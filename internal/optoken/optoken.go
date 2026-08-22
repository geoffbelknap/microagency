// Package optoken stores named operator tokens — the credentials that gate the
// operator surface (/admin and the console), never the agent-facing /mcp.
//
// Each token has a name, a role, a creation time, and an optional expiry. The
// token value itself is held only as a SHA-256 hash: the plaintext is returned
// once from Create/Rotate and never written to disk. The store is a single
// 0600 JSON file read on every authentication, so create, rotate, and revoke
// take effect on a running gateway immediately, with no restart or IPC.
package optoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Role is the authorization level an operator token carries.
type Role string

const (
	// RoleAdmin grants the full operator surface, including mutations and
	// out-of-band ref materialization.
	RoleAdmin Role = "admin"
	// RoleAuditor grants read-only observability: run listing, metrics, and
	// audit/decision-ledger verification. No mutations, no ref materialization.
	RoleAuditor Role = "auditor"
)

// ParseRole validates a role string from user input.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin, RoleAuditor:
		return Role(s), nil
	}
	return "", fmt.Errorf("unknown role %q (want admin or auditor)", s)
}

// LegacyName is the fixed audit attribution for the original single operator
// token (~/.microagency/token). Named tokens may not claim it, so an audit
// line reading LegacyName always means the break-glass credential.
const LegacyName = "legacy-operator-token"

// Token is one named operator credential's metadata. SHA256 is the hex SHA-256
// of the secret value; the value itself is never stored.
type Token struct {
	Name    string     `json:"name"`
	Role    Role       `json:"role"`
	SHA256  string     `json:"sha256"`
	Created time.Time  `json:"created"`
	Expires *time.Time `json:"expires,omitempty"`
}

// Expired reports whether the token's expiry (if any) has passed.
func (t Token) Expired(now time.Time) bool {
	return t.Expires != nil && now.After(*t.Expires)
}

// Store is a file-backed named-token store. Methods re-read the file on every
// call; writes are atomic (temp file + rename), so a concurrently running
// gateway observes either the old or the new token set, never a partial one.
type Store struct{ path string }

// NewStore returns a store backed by the given file path. The file need not
// exist yet; a missing file is an empty store.
func NewStore(path string) *Store { return &Store{path: path} }

// storeFile is the on-disk shape, versioned for future evolution.
type storeFile struct {
	Tokens []Token `json:"tokens"`
}

// nameRE bounds token names to a filesystem- and log-safe identifier.
var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidateName checks that a token name is usable: short, log-safe, and not
// the reserved legacy attribution name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid token name %q: use 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	if name == LegacyName {
		return fmt.Errorf("token name %q is reserved for the legacy operator token", name)
	}
	return nil
}

// List returns every stored token's metadata (never token values). A missing
// store file is an empty list.
func (s *Store) List() ([]Token, error) {
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	return f.Tokens, nil
}

// Create mints a new named token and returns its plaintext value — the only
// time the value exists outside the caller. The name must be unused.
func (s *Store) Create(name string, role Role, expires *time.Time) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if _, err := ParseRole(string(role)); err != nil {
		return "", err
	}
	f, err := s.read()
	if err != nil {
		return "", err
	}
	for _, t := range f.Tokens {
		if t.Name == name {
			return "", fmt.Errorf("an operator token named %q already exists", name)
		}
	}
	secret, err := mintSecret()
	if err != nil {
		return "", err
	}
	f.Tokens = append(f.Tokens, Token{
		Name: name, Role: role, SHA256: hashSecret(secret),
		Created: time.Now().UTC().Truncate(time.Second), Expires: expires,
	})
	if err := s.write(f); err != nil {
		return "", err
	}
	return secret, nil
}

// Rotate re-mints the named token's value, keeping its name and role. A nil
// expires keeps the stored expiry; rotating a token whose kept expiry has
// already passed is refused, so rotation never silently resurrects or ships a
// dead credential.
func (s *Store) Rotate(name string, expires *time.Time) (string, error) {
	f, err := s.read()
	if err != nil {
		return "", err
	}
	for i, t := range f.Tokens {
		if t.Name != name {
			continue
		}
		if expires == nil && t.Expired(time.Now()) {
			return "", fmt.Errorf("operator token %q expired %s; pass a new expiry to re-mint it", name, t.Expires.Format(time.RFC3339))
		}
		secret, err := mintSecret()
		if err != nil {
			return "", err
		}
		f.Tokens[i].SHA256 = hashSecret(secret)
		f.Tokens[i].Created = time.Now().UTC().Truncate(time.Second)
		if expires != nil {
			f.Tokens[i].Expires = expires
		}
		if err := s.write(f); err != nil {
			return "", err
		}
		return secret, nil
	}
	return "", fmt.Errorf("no operator token named %q", name)
}

// Revoke removes the named token. The next authentication attempt with its
// value fails.
func (s *Store) Revoke(name string) error {
	f, err := s.read()
	if err != nil {
		return err
	}
	kept := f.Tokens[:0]
	found := false
	for _, t := range f.Tokens {
		if t.Name == name {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		return fmt.Errorf("no operator token named %q", name)
	}
	f.Tokens = kept
	return s.write(f)
}

// Authenticate matches a presented bearer value against the stored tokens.
// The comparison is over SHA-256 hashes in constant time per entry, and every
// entry is compared so a match's position doesn't shorten the scan. An expired
// match fails. Read errors fail closed.
func (s *Store) Authenticate(presented string, now time.Time) (Token, bool) {
	if presented == "" {
		return Token{}, false
	}
	f, err := s.read()
	if err != nil {
		return Token{}, false
	}
	got := []byte(hashSecret(presented))
	var match *Token
	for i := range f.Tokens {
		if subtle.ConstantTimeCompare(got, []byte(f.Tokens[i].SHA256)) == 1 && match == nil {
			match = &f.Tokens[i]
		}
	}
	if match == nil || match.Expired(now) {
		return Token{}, false
	}
	return *match, true
}

func (s *Store) read() (storeFile, error) {
	var f storeFile
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("parse %s: %w", s.path, err)
	}
	return f, nil
}

// write persists atomically with 0600 hygiene: the temp file is created 0600
// in the same directory, then renamed over the store.
func (s *Store) write(f storeFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".operator-tokens-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func mintSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}
