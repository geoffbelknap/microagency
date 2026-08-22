package optoken

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "operator-tokens.json"))
}

func TestCreateAuthenticateRoundTrip(t *testing.T) {
	s := newTestStore(t)
	secret, err := s.Create("ops", RoleAdmin, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if secret == "" {
		t.Fatal("create returned an empty secret")
	}
	tok, ok := s.Authenticate(secret, time.Now())
	if !ok {
		t.Fatal("freshly created token did not authenticate")
	}
	if tok.Name != "ops" || tok.Role != RoleAdmin {
		t.Fatalf("authenticated as %q/%q, want ops/admin", tok.Name, tok.Role)
	}
	if _, ok := s.Authenticate(secret+"x", time.Now()); ok {
		t.Fatal("a wrong value authenticated")
	}
	if _, ok := s.Authenticate("", time.Now()); ok {
		t.Fatal("an empty value authenticated — empty must never mean no auth")
	}
}

func TestPlaintextNeverStored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-tokens.json")
	s := NewStore(path)
	secret, err := s.Create("ops", RoleAdmin, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatal("the plaintext token value was written to disk")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestDuplicateNameRefused(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Create("ops", RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("ops", RoleAuditor, nil); err == nil {
		t.Fatal("duplicate name was accepted")
	}
}

func TestNameValidation(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{"", "-lead", "has space", strings.Repeat("a", 65), LegacyName, "a/b"} {
		if _, err := s.Create(bad, RoleAdmin, nil); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
}

func TestBadRoleRefused(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Create("ops", Role("root"), nil); err == nil {
		t.Fatal("unknown role was accepted")
	}
}

func TestExpiry(t *testing.T) {
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	secret, err := s.Create("temp", RoleAuditor, &exp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate(secret, time.Now()); !ok {
		t.Fatal("unexpired token refused")
	}
	if _, ok := s.Authenticate(secret, exp.Add(time.Second)); ok {
		t.Fatal("expired token authenticated")
	}
}

func TestRotate(t *testing.T) {
	s := newTestStore(t)
	old, err := s.Create("ops", RoleAuditor, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Rotate("ops", nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if fresh == old {
		t.Fatal("rotate did not change the value")
	}
	if _, ok := s.Authenticate(old, time.Now()); ok {
		t.Fatal("old value still authenticates after rotate")
	}
	tok, ok := s.Authenticate(fresh, time.Now())
	if !ok {
		t.Fatal("rotated value refused")
	}
	if tok.Role != RoleAuditor {
		t.Fatalf("rotate changed the role to %q", tok.Role)
	}
	if _, err := s.Rotate("ghost", nil); err == nil {
		t.Fatal("rotating an unknown name succeeded")
	}
}

func TestRotateExpiredNeedsNewExpiry(t *testing.T) {
	s := newTestStore(t)
	past := time.Now().Add(-time.Hour)
	if _, err := s.Create("stale", RoleAdmin, &past); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate("stale", nil); err == nil {
		t.Fatal("rotating an expired token without a new expiry succeeded")
	}
	future := time.Now().Add(time.Hour)
	secret, err := s.Rotate("stale", &future)
	if err != nil {
		t.Fatalf("rotate with new expiry: %v", err)
	}
	if _, ok := s.Authenticate(secret, time.Now()); !ok {
		t.Fatal("re-minted token refused")
	}
}

func TestRevoke(t *testing.T) {
	s := newTestStore(t)
	secret, err := s.Create("ops", RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("ops"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := s.Authenticate(secret, time.Now()); ok {
		t.Fatal("revoked token still authenticates")
	}
	if err := s.Revoke("ops"); err == nil {
		t.Fatal("revoking an unknown name succeeded")
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("store still holds %d tokens after revoke", len(list))
	}
}

func TestListNeverReturnsValues(t *testing.T) {
	s := newTestStore(t)
	secret, err := s.Create("ops", RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "ops" {
		t.Fatalf("list = %+v", list)
	}
	if list[0].SHA256 == secret {
		t.Fatal("list exposed the plaintext value")
	}
}

func TestMissingFileIsEmptyStore(t *testing.T) {
	s := newTestStore(t)
	list, err := s.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("List on missing file = %v, %v", list, err)
	}
	if _, ok := s.Authenticate("anything", time.Now()); ok {
		t.Fatal("missing store authenticated a value")
	}
}
