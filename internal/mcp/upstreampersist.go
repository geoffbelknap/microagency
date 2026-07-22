package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"microagency/internal/auth"
	"microagency/internal/gateway"
	"microagency/internal/secretstore"
)

// Auth kinds for a persisted upstream. They tell ReloadUpstreams how to
// reconstruct the credential (if any) on restart.
const (
	authOAuth  = "oauth"  // refresh-token record in the secret store; rebuild a refreshing bearer
	authStatic = "static" // raw bearer token in the secret store; set Upstream.Token
	authNone   = "none"   // no credential (e.g. an upstream whose tools/list is public)
)

// upstreamReg is one persisted, NON-secret upstream registration. Any credential
// (an OAuth refresh token or a static bearer) lives in the secret store, never
// here; Auth records which kind so reload knows how to restore it.
type upstreamReg struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Discover bool   `json:"discover"`
	Auth     string `json:"auth,omitempty"`      // authOAuth|authStatic|authNone; "" = oauth (legacy)
	ReadOnly bool   `json:"read_only,omitempty"` // writes refused (least-privilege)
	Owner    string `json:"owner,omitempty"`     // principal subject this connection is scoped to; "" = shared
	Minimize string `json:"minimize,omitempty"`  // field-minimization policy JSON (type→action); "" = off
}

// authKind returns the registration's auth kind, treating a legacy empty value as
// OAuth (the only kind that existed before non-OAuth upstreams were persisted).
func (r upstreamReg) authKind() string {
	if r.Auth == "" {
		return authOAuth
	}
	return r.Auth
}

func (s *Server) registrationsPath() string { return filepath.Join(s.stateDir, "upstreams.json") }

// UpstreamRegistration is the non-secret identity (name + URL) of a persisted
// upstream. It's exported so out-of-server tooling — notably `microagency doctor`'s
// bypass check — can enumerate what microagency proxies without constructing a full
// Server. No credential is ever exposed here; those live only in the secret store.
type UpstreamRegistration struct {
	Name string
	URL  string
}

// ReadUpstreamRegistrations returns the persisted upstream registrations under
// stateDir (the same upstreams.json the server reloads on startup). It returns nil
// when the file is absent or unreadable — callers treat "no state" and "unreadable
// state" alike, since in both cases there's nothing to report on. Read-only: it
// never creates or mutates the file.
func ReadUpstreamRegistrations(stateDir string) []UpstreamRegistration {
	b, err := os.ReadFile(filepath.Join(stateDir, "upstreams.json"))
	if err != nil {
		return nil
	}
	var regs []upstreamReg
	if json.Unmarshal(b, &regs) != nil {
		return nil
	}
	out := make([]UpstreamRegistration, 0, len(regs))
	for _, r := range regs {
		out = append(out, UpstreamRegistration{Name: r.Name, URL: r.URL})
	}
	return out
}

func (s *Server) loadRegistrations() []upstreamReg {
	b, err := os.ReadFile(s.registrationsPath())
	if err != nil {
		return nil
	}
	var regs []upstreamReg
	_ = json.Unmarshal(b, &regs)
	return regs
}

// writeRegistrations persists regs atomically: write a sibling temp file, then
// rename it over upstreams.json so a crash mid-write can't leave a torn or empty
// registry. Callers hold persistMu (via updateRegistrations).
func (s *Server) writeRegistrations(regs []upstreamReg) {
	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		slog.Error("persist upstream registration failed", "err", err)
		return
	}
	b, _ := json.Marshal(regs)
	tmp, err := os.CreateTemp(s.stateDir, "upstreams-*.json.tmp")
	if err != nil {
		slog.Error("persist upstream registration failed", "err", err)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		slog.Error("persist upstream registration failed", "err", err)
		return
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		slog.Error("persist upstream registration failed", "err", err)
		return
	}
	if err := tmp.Close(); err != nil {
		slog.Error("persist upstream registration failed", "err", err)
		return
	}
	if err := os.Rename(tmpName, s.registrationsPath()); err != nil {
		slog.Error("persist upstream registration failed", "err", err)
	}
}

// updateRegistrations applies fn to the persisted registrations under persistMu
// and writes the result atomically when fn reports a change. Serializing the whole
// load-modify-write is what makes the six mutators below safe against concurrent
// admin handlers and the OAuth callback — an unlocked read-modify-write can drop a
// registration whose write interleaved with another. A no-op without a stateDir.
func (s *Server) updateRegistrations(fn func([]upstreamReg) ([]upstreamReg, bool)) {
	if s.stateDir == "" {
		return
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	next, changed := fn(s.loadRegistrations())
	if changed {
		s.writeRegistrations(next)
	}
}

// persistRegistration records (or updates) an upstream registration so it reloads
// across restarts. Best-effort; a no-op without a stateDir.
func (s *Server) persistRegistration(name, url string, discover bool, authKind, owner string) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		reg := upstreamReg{Name: name, URL: url, Discover: discover, Auth: authKind, Owner: owner}
		for i := range regs {
			if regs[i].Name == name {
				reg.ReadOnly = regs[i].ReadOnly // preserve an operator's read-only setting across re-registration
				if reg.Owner == "" {
					reg.Owner = regs[i].Owner // preserve owner scoping across re-registration (e.g. reauth)
				}
				regs[i] = reg
				return regs, true
			}
		}
		return append(regs, reg), true
	})
}

// persistOwner updates just the owner scoping of a persisted registration, so a
// reassignment survives restart independently of the add/enable path.
func (s *Server) persistOwner(name, owner string) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].Owner = owner
				return regs, true
			}
		}
		return regs, false
	})
}

// persistReadOnly updates just the read-only flag of a persisted registration, so
// the setting survives restart independently of the add/enable path.
func (s *Server) persistReadOnly(name string, ro bool) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].ReadOnly = ro
				return regs, true
			}
		}
		return regs, false
	})
}

// persistMinimize updates just the field-minimization policy of a persisted
// registration, so it survives restart independently of the add/enable path. An
// empty policy clears it.
func (s *Server) persistMinimize(name, policy string) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].Minimize = policy
				return regs, true
			}
		}
		return regs, false
	})
}

// markRegistrationEnabled flips a persisted registration's discover flag off, so an
// upstream the operator enabled reloads as enabled (invocable), not discovered. A
// no-op if the upstream was never persisted.
func (s *Server) markRegistrationEnabled(name string) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name && regs[i].Discover {
				regs[i].Discover = false
				return regs, true
			}
		}
		return regs, false
	})
}

// removeRegistration deletes an upstream's persisted registration and any stored
// credential, so a removed upstream stays gone across restarts. Best-effort.
func (s *Server) removeRegistration(ctx context.Context, name string) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		kept := make([]upstreamReg, 0, len(regs))
		for _, r := range regs {
			if r.Name != name {
				kept = append(kept, r)
			}
		}
		return kept, len(kept) != len(regs)
	})
	if s.secrets != nil {
		if err := s.secrets.Delete(ctx, tokenKey(name)); err != nil && err != secretstore.ErrNotFound {
			slog.Error("remove upstream secret failed", "upstream", name, "err", err)
		}
	}
}

// saveStaticToken stores a static bearer for an upstream in the secret store (never
// in the plaintext registration file), so it can be restored on restart.
func (s *Server) saveStaticToken(ctx context.Context, name, token string) {
	if s.secrets == nil {
		return
	}
	if err := s.secrets.Save(ctx, tokenKey(name), []byte(token)); err != nil {
		slog.Error("persist upstream token failed", "upstream", name, "err", err)
	}
}

// ReloadUpstreams re-adds persisted upstreams on startup so connections survive a
// restart with no re-login. It reconstructs each one's credential from its auth
// kind: an OAuth refresh token or a static bearer from the secret store, or none
// for a credential-free upstream. Per-upstream failures (e.g. a revoked token) are
// logged and skipped; the operator re-adds those from the console.
func (s *Server) ReloadUpstreams(ctx context.Context) {
	if s.stateDir == "" {
		return
	}
	for _, reg := range s.loadRegistrations() {
		u := &gateway.Upstream{Name: reg.Name, URL: reg.URL, Client: s.upstreamClient}
		switch reg.authKind() {
		case authNone:
			// No credential — reconnect as-is (its tools/list is reachable unauthenticated).
		case authStatic:
			if s.secrets == nil {
				slog.Warn("reload upstream skipped: no secret store", "upstream", reg.Name)
				continue
			}
			raw, err := s.secrets.Load(ctx, tokenKey(reg.Name))
			if err != nil {
				slog.Warn("reload upstream failed", "upstream", reg.Name, "err", err)
				continue
			}
			u.Token = string(raw)
		default: // authOAuth
			if s.secrets == nil {
				slog.Warn("reload upstream skipped: no secret store", "upstream", reg.Name)
				continue
			}
			raw, err := s.secrets.Load(ctx, tokenKey(reg.Name))
			if err != nil {
				if err != secretstore.ErrNotFound {
					slog.Warn("reload upstream failed", "upstream", reg.Name, "err", err)
				}
				continue
			}
			var rec auth.TokenRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				slog.Warn("reload upstream: bad token record", "upstream", reg.Name, "err", err)
				continue
			}
			u.Bearer = s.refreshingBearer(reg.Name, auth.TokenFromRecord(rec))
		}

		var opts []UpstreamOption
		if reg.Owner != "" {
			opts = append(opts, WithOwner(reg.Owner))
		}
		var aerr error
		if reg.Discover {
			aerr = s.DiscoverUpstream(ctx, u, opts...)
		} else {
			aerr = s.AddUpstream(ctx, u, opts...)
		}
		if aerr != nil {
			slog.Warn("reload upstream failed", "upstream", reg.Name, "err", aerr)
			continue
		}
		if reg.ReadOnly {
			_ = s.SetUpstreamReadOnly(reg.Name, true)
		}
		if reg.Minimize != "" {
			s.SetMinimizePolicy(reg.Name, []byte(reg.Minimize))
		}
		slog.Info("reloaded upstream", "upstream", reg.Name)
	}
}
