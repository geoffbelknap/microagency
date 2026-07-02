package auth

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
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
		log.Printf("microagency: load oauth clients: %v", err)
		return
	}
	for _, pc := range pcs {
		s.clients[pc.ClientID] = clientReg{redirectURIs: pc.RedirectURIs, name: pc.Name}
	}
}

// persistClientsLocked writes the current registrations to disk (0600, dir 0700).
// The caller must hold s.mu. Best-effort; a no-op without a configured path.
func (s *AuthServer) persistClientsLocked() {
	if s.clientsPath == "" {
		return
	}
	pcs := make([]persistedClient, 0, len(s.clients))
	for id, c := range s.clients {
		pcs = append(pcs, persistedClient{ClientID: id, RedirectURIs: c.redirectURIs, Name: c.name})
	}
	if err := os.MkdirAll(filepath.Dir(s.clientsPath), 0o700); err != nil {
		log.Printf("microagency: persist oauth clients: %v", err)
		return
	}
	b, _ := json.Marshal(pcs)
	if err := os.WriteFile(s.clientsPath, b, 0o600); err != nil {
		log.Printf("microagency: persist oauth clients: %v", err)
	}
}
