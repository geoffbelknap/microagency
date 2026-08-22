package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Owner    string `json:"owner,omitempty"`     // canonical principal key (issuer#subject) this connection is scoped to; "" = shared
	// AuditFullArgs opts this connection up to full argument capture in the
	// audit log on a multi-principal gateway (default there: structure + digest).
	AuditFullArgs bool             `json:"audit_full_args,omitempty"`
	Minimize      string           `json:"minimize,omitempty"`     // field-minimization policy JSON (type→action); "" = off
	SelfService   bool             `json:"self_service,omitempty"` // admitted from an operator-approved template
	Template      string           `json:"template,omitempty"`     // template id for self-service connections
	Revoked       bool             `json:"revoked,omitempty"`      // credential deleted; never reload as callable
	Grants        []OperationGrant `json:"grants,omitempty"`       // non-secret operator authority
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
// bypass check and its audit-capture posture line — can enumerate what microagency
// proxies without constructing a full Server. No credential is ever exposed here;
// those live only in the secret store.
type UpstreamRegistration struct {
	Name string
	URL  string
	// AuditFullArgs: this connection is opted up to full argument capture in the
	// audit log on a multi-principal gateway. Doctor discloses the opt-up.
	AuditFullArgs bool
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
		out = append(out, UpstreamRegistration{Name: r.Name, URL: r.URL, AuditFullArgs: r.AuditFullArgs})
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
func (s *Server) writeRegistrations(regs []upstreamReg) error {
	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(regs)
	tmp, err := os.CreateTemp(s.stateDir, "upstreams-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.registrationsPath()); err != nil {
		return err
	}
	dir, err := os.Open(s.stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
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
		if err := s.writeRegistrations(next); err != nil {
			slog.Error("persist upstream registration failed", "err", err)
		}
	}
}

func (s *Server) updateRegistrationsStrict(fn func([]upstreamReg) ([]upstreamReg, bool)) error {
	if s.stateDir == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	next, changed := fn(s.loadRegistrations())
	if !changed {
		return nil
	}
	return s.writeRegistrations(next)
}

// persistRegistration records (or updates) an upstream registration so it reloads
// across restarts. Best-effort; a no-op without a stateDir.
func (s *Server) persistRegistration(name, url string, discover bool, authKind, owner string) {
	s.persistRegistrationRecord(upstreamReg{Name: name, URL: url, Discover: discover, Auth: authKind, Owner: owner})
}

// persistRegistrationRecord records the full non-secret connection identity. It
// preserves operator policy fields across reauthorization while allowing a
// self-service callback to atomically bind owner + template metadata.
func (s *Server) persistRegistrationRecord(reg upstreamReg) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == reg.Name {
				reg.ReadOnly = regs[i].ReadOnly // preserve an operator's read-only setting across re-registration
				reg.AuditFullArgs = regs[i].AuditFullArgs
				reg.Minimize = regs[i].Minimize
				if len(reg.Grants) == 0 {
					reg.Grants = regs[i].Grants
				}
				if reg.Owner == "" {
					reg.Owner = regs[i].Owner // preserve owner scoping across re-registration (e.g. reauth)
				}
				if !reg.SelfService && regs[i].SelfService {
					reg.SelfService, reg.Template = true, regs[i].Template
				}
				regs[i] = reg
				return regs, true
			}
		}
		return append(regs, reg), true
	})
}

// persistDisabledStrict makes a registration reload as discovered/non-invocable
// and reports a durable-state failure to the operator.
func (s *Server) persistDisabledStrict(name string) error {
	return s.updateRegistrationsStrict(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].Discover = true
				return regs, true
			}
		}
		return regs, false
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

// persistAuditFullArgs updates just the audit-capture opt-up of a persisted
// registration, so the setting survives restart independently of the add/enable
// path — and stays readable by doctor's posture disclosure.
func (s *Server) persistAuditFullArgs(name string, on bool) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].AuditFullArgs = on
				return regs, true
			}
		}
		return regs, false
	})
}

func (s *Server) persistGrantsStrict(name string, grants []OperationGrant) error {
	found := false
	err := s.updateRegistrationsStrict(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				found = true
				regs[i].Grants = append([]OperationGrant(nil), grants...)
				return regs, true
			}
		}
		return regs, false
	})
	if err != nil {
		return err
	}
	if s.stateDir != "" && !found {
		return fmt.Errorf("persist grants: unknown upstream %q", name)
	}
	return nil
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
			if regs[i].Name == name && (regs[i].Discover || regs[i].Revoked) {
				regs[i].Discover = false
				regs[i].Revoked = false
				return regs, true
			}
		}
		return regs, false
	})
}

// removeRegistration deletes an upstream's persisted registration and any stored
// credential, so a removed upstream stays gone across restarts. Best-effort.
func (s *Server) removeRegistration(ctx context.Context, name string) {
	live, liveOK := s.snapshotUpstream(name)
	var removed *upstreamReg
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		kept := make([]upstreamReg, 0, len(regs))
		for _, r := range regs {
			if r.Name != name {
				kept = append(kept, r)
			} else {
				rc := r
				removed = &rc
			}
		}
		return kept, len(kept) != len(regs)
	})
	if s.secrets != nil {
		key := tokenKey(name)
		if removed != nil {
			key = credentialKeyForRegistration(*removed)
		} else if liveOK && live.selfService {
			key = selfServiceTokenKey(live.owner, name)
		}
		if err := s.secrets.Delete(ctx, key); err != nil && err != secretstore.ErrNotFound {
			slog.Error("remove upstream secret failed", "upstream", name, "err", err)
		}
	}
}

// revokeRegistration persists a fail-closed tombstone and deletes the durable
// credential. Even if deletion fails, restart still cannot reload the credential.
func (s *Server) revokeRegistration(ctx context.Context, name string) error {
	live, liveOK := s.snapshotUpstream(name)
	var found *upstreamReg
	persistErr := s.updateRegistrationsStrict(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].Revoked = true
				regs[i].Discover = true
				rc := regs[i]
				found = &rc
				return regs, true
			}
		}
		return regs, false
	})
	if found == nil && liveOK {
		found = &upstreamReg{Name: name, URL: live.conn.Endpoint(), Owner: live.owner, SelfService: live.selfService, Template: live.template, Revoked: true}
	}
	if found == nil {
		return fmt.Errorf("unknown upstream %q", name)
	}
	if s.secrets == nil {
		return persistErr
	}
	err := s.secrets.Delete(ctx, credentialKeyForRegistration(*found))
	if err != nil && err != secretstore.ErrNotFound {
		return errors.Join(persistErr, err)
	}
	return persistErr
}

// removeSelfServiceRegistration deletes a principal-owned registration and its
// credential with fail-closed ordering. Credential deletion is attempted even if
// the non-secret index write fails, so a restart cannot restore a callable grant.
func (s *Server) removeSelfServiceRegistration(ctx context.Context, name string, live upstream) error {
	var found bool
	persistErr := s.updateRegistrationsStrict(func(regs []upstreamReg) ([]upstreamReg, bool) {
		kept := make([]upstreamReg, 0, len(regs))
		for _, reg := range regs {
			if reg.Name == name {
				found = true
				continue
			}
			kept = append(kept, reg)
		}
		return kept, found
	})
	var secretErr error
	if s.secrets != nil {
		secretErr = s.secrets.Delete(ctx, selfServiceTokenKey(live.owner, name))
		if secretErr == secretstore.ErrNotFound {
			secretErr = nil
		}
	}
	return errors.Join(persistErr, secretErr)
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
		opts := []UpstreamOption{}
		if reg.Owner != "" {
			opts = append(opts, WithOwner(reg.Owner))
		}
		if reg.SelfService {
			opts = append(opts, WithSelfService(reg.Template))
		}
		if reg.Revoked {
			_ = s.registerUpstream(reg.Name, &upstream{conn: u, provenance: "preloaded"}, append(opts, WithRevoked())...)
			continue
		}
		switch reg.authKind() {
		case authNone:
			// No credential — reconnect as-is (its tools/list is reachable unauthenticated).
		case authStatic:
			if s.secrets == nil {
				slog.Warn("reload upstream skipped: no secret store", "upstream", reg.Name)
				continue
			}
			raw, err := s.secrets.Load(ctx, credentialKeyForRegistration(reg))
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
			raw, err := s.secrets.Load(ctx, credentialKeyForRegistration(reg))
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
			u.Bearer = s.refreshingBearerAtKey(reg.Name, credentialKeyForRegistration(reg), auth.TokenFromRecord(rec), 0, reg.SelfService)
		}
		var aerr error
		if reg.Discover {
			aerr = s.DiscoverUpstream(ctx, reg.Name, u, opts...)
		} else {
			aerr = s.AddUpstream(ctx, reg.Name, u, opts...)
		}
		if aerr != nil {
			slog.Warn("reload upstream failed", "upstream", reg.Name, "err", aerr)
			continue
		}
		if reg.ReadOnly {
			_ = s.SetUpstreamReadOnly(reg.Name, true)
		}
		if reg.AuditFullArgs {
			_ = s.SetUpstreamAuditFullArgs(reg.Name, true)
		}
		if len(reg.Grants) > 0 {
			if err := s.SetUpstreamGrants(reg.Name, reg.Grants); err != nil {
				_ = s.DisableUpstream(reg.Name)
				slog.Warn("reload upstream grants failed; connection disabled", "upstream", reg.Name, "err", err)
				continue
			}
		}
		if reg.Minimize != "" {
			s.SetMinimizePolicy(reg.Name, []byte(reg.Minimize))
		}
		slog.Info("reloaded upstream", "upstream", reg.Name)
	}
}
