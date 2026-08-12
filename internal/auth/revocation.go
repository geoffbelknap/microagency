package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RevocationList is the shared, persistent denylist for self-issued access and
// refresh token IDs. It is intentionally small: entries disappear after the
// token's own expiry, and only explicit revocations or consumed rotating refresh
// tokens are recorded.
type RevocationList struct {
	mu   sync.Mutex
	path string
	ids  map[string]time.Time
}

type persistedRevocation struct {
	ID     string    `json:"id"`
	Expiry time.Time `json:"expiry"`
}

// NewRevocationList loads a revocation list from path. An empty path creates an
// in-memory list for tests and ephemeral callers.
func NewRevocationList(path string) (*RevocationList, error) {
	r := &RevocationList{path: path, ids: make(map[string]time.Time)}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("read OAuth revocations: %w", err)
	}
	var entries []persistedRevocation
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("decode OAuth revocations: %w", err)
	}
	now := time.Now()
	for _, entry := range entries {
		if entry.ID != "" && entry.Expiry.After(now) {
			r.ids[entry.ID] = entry.Expiry
		}
	}
	return r, nil
}

// IsRevoked reports whether id is still denied.
func (r *RevocationList) IsRevoked(id string) bool {
	if r == nil || id == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	expiry, ok := r.ids[id]
	if ok && !expiry.After(time.Now()) {
		delete(r.ids, id)
		return false
	}
	return ok
}

// Revoke records id until expiry. Persistence failure is returned so callers
// can fail closed instead of claiming that a token was revoked when it was not.
func (r *RevocationList) Revoke(id string, expiry time.Time) error {
	if r == nil || id == "" || expiry.IsZero() {
		return fmt.Errorf("invalid OAuth token revocation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(time.Now())
	r.ids[id] = expiry
	if err := r.persistLocked(); err != nil {
		return err
	}
	return nil
}

// Consume atomically revokes a rotating refresh token. It returns false for a
// replay that was already consumed.
func (r *RevocationList) Consume(id string, expiry time.Time) (bool, error) {
	if r == nil || id == "" || expiry.IsZero() {
		return false, fmt.Errorf("invalid OAuth refresh token")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(time.Now())
	if _, exists := r.ids[id]; exists {
		return false, nil
	}
	r.ids[id] = expiry
	if err := r.persistLocked(); err != nil {
		return false, err
	}
	return true, nil
}

func (r *RevocationList) pruneLocked(now time.Time) {
	for id, expiry := range r.ids {
		if !expiry.After(now) {
			delete(r.ids, id)
		}
	}
}

func (r *RevocationList) persistLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create OAuth revocation directory: %w", err)
	}
	entries := make([]persistedRevocation, 0, len(r.ids))
	for id, expiry := range r.ids {
		entries = append(entries, persistedRevocation{ID: id, Expiry: expiry})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	b, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encode OAuth revocations: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".oauth-revocations-*")
	if err != nil {
		return fmt.Errorf("create OAuth revocation file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect OAuth revocation file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write OAuth revocations: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync OAuth revocations: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close OAuth revocations: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		return fmt.Errorf("replace OAuth revocations: %w", err)
	}
	dir, err := os.Open(filepath.Dir(r.path))
	if err != nil {
		return fmt.Errorf("open OAuth revocation directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync OAuth revocation directory: %w", err)
	}
	return nil
}
