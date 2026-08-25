package auth

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// persistedClient is the on-disk form of one dynamic client registration.
//
// Client registrations are otherwise memory-only, which breaks the authorize path
// across a restart: a client (e.g. Claude Code) caches its client_id, but a
// freshly-started server has an empty registry and rejects it with "unknown client
// or redirect_uri". The signing key and refresh tokens already persist so sessions
// survive restarts; persisting registrations closes the last gap. Registrations
// are non-secret (a public client_id + its own redirect URIs), so plain JSON at
// 0600 is sufficient — no secret store needed.
type persistedClient struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer,omitempty"`
	// CreatedAt and UsedAt persist unused-registration expiry across restarts.
	// Without them a restart would reset every registration's age and a
	// long-running gateway would never expire anything it had been restarted
	// through. A record written before these existed carries neither, and is
	// treated as an established client rather than expired on sight.
	CreatedAt time.Time `json:"created_at,omitzero"`
	UsedAt    time.Time `json:"used_at,omitzero"`
}

// LoadClients enables client-registration persistence at path and loads any
// registrations already stored there. Call once before serving. Best-effort on
// read: a missing or unreadable file simply starts empty.
func (s *AuthServer) LoadClients(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientsPath = path
	b, err := os.ReadFile(path)
	if err != nil {
		return // no file yet (or unreadable) — start empty, register will (re)create it
	}
	var pcs []persistedClient
	if err := json.Unmarshal(b, &pcs); err != nil {
		slog.Warn("load oauth clients failed", "err", err)
		return
	}
	for _, pc := range pcs {
		if pc.ClientID == "" || len(pc.RedirectURIs) == 0 || len(pc.RedirectURIs) > 8 {
			continue
		}
		// A public tunnel URL is the AS issuer. When an ephemeral URL changes,
		// registrations from the old issuer are not silently rebound to the new
		// public origin. Issuer-less records are a legacy local-only format.
		if pc.Issuer != s.issuer && !(pc.Issuer == "" && strings.HasPrefix(s.issuer, "http://")) {
			continue
		}
		valid := true
		for _, redirectURI := range pc.RedirectURIs {
			if !validRedirectURI(redirectURI, s.requireResource) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		s.clients[pc.ClientID] = clientReg{
			redirectURIs: pc.RedirectURIs, name: pc.Name,
			createdAt: pc.CreatedAt, usedAt: pc.UsedAt,
		}
	}
	// Registrations that expired while this gateway was down are dropped on the
	// way in, so a restart does not resurrect them for another full TTL.
	s.expireUnusedClientsLocked(time.Now(), s.effectiveRegistrationLimitsLocked().UnusedTTL)
}

// persistClientsLocked writes the current registrations to disk (0600, dir 0700).
// The caller must hold s.mu. Best-effort; a no-op without a configured path.
func (s *AuthServer) persistClientsLocked() {
	if s.clientsPath == "" {
		return
	}
	pcs := make([]persistedClient, 0, len(s.clients))
	for id, c := range s.clients {
		pcs = append(pcs, persistedClient{
			ClientID: id, RedirectURIs: c.redirectURIs, Name: c.name, Issuer: s.issuer,
			CreatedAt: c.createdAt, UsedAt: c.usedAt,
		})
	}
	if err := os.MkdirAll(filepath.Dir(s.clientsPath), 0o700); err != nil {
		slog.Error("persist oauth clients failed", "err", err)
		return
	}
	b, _ := json.Marshal(pcs)
	if err := os.WriteFile(s.clientsPath, b, 0o600); err != nil {
		slog.Error("persist oauth clients failed", "err", err)
	}
}
