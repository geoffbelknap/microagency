package auth

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// federatedRecord is the on-disk form of one federated identity: the provider
// subject that IS the principal, and the provider-verified email kept
// alongside for display and future per-user upstream delegation. Identity
// comparisons use the subject only — email can change at the provider while
// sub stays stable. Non-secret, so plain JSON at 0600 is sufficient.
type federatedRecord struct {
	Subject  string    `json:"subject"`
	Email    string    `json:"email,omitempty"`
	Issuer   string    `json:"issuer"`
	LastSeen time.Time `json:"last_seen"`
}

// LoadFederatedIdentities enables identity persistence at path and loads any
// records already stored there. Call once before serving, only in federated
// mode. Best-effort on read: a missing or unreadable file starts empty.
func (s *AuthServer) LoadFederatedIdentities(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identitiesPath = path
	b, err := os.ReadFile(path)
	if err != nil {
		return // no file yet — the first sign-in creates it
	}
	var recs []federatedRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		slog.Warn("load federated identities failed", "err", err)
		return
	}
	for _, rec := range recs {
		if rec.Subject == "" {
			continue
		}
		s.identities[rec.Subject] = rec
	}
}

// recordFederatedIdentity upserts the identity seen on a completed provider
// sign-in and persists the table.
func (s *AuthServer) recordFederatedIdentity(id *FederatedIdentity, issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[id.Subject] = federatedRecord{
		Subject: id.Subject, Email: id.Email, Issuer: issuer, LastSeen: time.Now().UTC(),
	}
	s.persistIdentitiesLocked()
}

// FederatedEmail returns the provider-verified email recorded for a federated
// subject, or "" when none is known.
func (s *AuthServer) FederatedEmail(subject string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identities[subject].Email
}

// persistIdentitiesLocked writes the identity table (0600, dir 0700), sorted
// for stable diffs. The caller must hold s.mu. Best-effort; a no-op without a
// configured path.
func (s *AuthServer) persistIdentitiesLocked() {
	if s.identitiesPath == "" {
		return
	}
	recs := make([]federatedRecord, 0, len(s.identities))
	for _, rec := range s.identities {
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Subject < recs[j].Subject })
	if err := os.MkdirAll(filepath.Dir(s.identitiesPath), 0o700); err != nil {
		slog.Error("persist federated identities failed", "err", err)
		return
	}
	b, _ := json.Marshal(recs)
	if err := os.WriteFile(s.identitiesPath, b, 0o600); err != nil {
		slog.Error("persist federated identities failed", "err", err)
	}
}
