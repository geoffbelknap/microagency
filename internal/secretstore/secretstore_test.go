package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func roundTrip(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Load(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("absent key: want ErrNotFound, got %v", err)
	}
	if err := s.Save(ctx, "up/supa", []byte(`{"refresh_token":"r1"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, "up/supa")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"refresh_token":"r1"}` {
		t.Fatalf("load = %s", got)
	}
	if err := s.Delete(ctx, "up/supa"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "up/supa"); err != ErrNotFound {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestFileStore(t *testing.T) {
	roundTrip(t, &File{Path: filepath.Join(t.TempDir(), "tokens.json")})
}

func TestEncryptedFileStoreRoundTripAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	key := bytes.Repeat([]byte{0x42}, 32)
	f, err := NewEncryptedFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind() != "encrypted-file" {
		t.Fatalf("kind = %q, want encrypted-file", f.Kind())
	}
	secret := `{"refresh_token":"sentinel-refresh","access_token":"sentinel-access"}`
	if err := f.Save(context.Background(), "up/example", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sentinel")) {
		t.Fatalf("plaintext secret appears in encrypted file: %s", raw)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}

	reopened, err := NewEncryptedFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Load(context.Background(), "up/example")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("restart load = %q, want %q", got, secret)
	}
}

func TestEncryptedFileMigratesPlaintextAtomically(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "upstream-tokens.json")
	secret := `{"refresh_token":"legacy-sentinel"}`
	legacy, _ := json.Marshal(map[string]string{"up/example": secret})
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "secret-store.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x37}, 32), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(stateDir, func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return ""
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind() != "encrypted-file" {
		t.Fatalf("kind = %q, want encrypted-file", s.Kind())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("legacy-sentinel")) {
		t.Fatalf("migration left plaintext in credential file: %s", raw)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("migrated mode = %04o, want 0600", got)
	}
	got, err := s.Load(context.Background(), "up/example")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("migrated value = %q, want %q", got, secret)
	}
	matches, err := filepath.Glob(path + "-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("migration left temporary files: %v", matches)
	}
}

func TestEncryptedFileRejectsWrongOrMissingKey(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	path := filepath.Join(stateDir, "upstream-tokens.json")
	f, err := NewEncryptedFile(path, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save(context.Background(), "up/example", []byte("sentinel")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedFile(path, bytes.Repeat([]byte{0x22}, 32)); err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("wrong key error = %v", err)
	}
	if _, err := Open(stateDir, func(string) string { return "" }, Options{AllowPlaintext: true}); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("missing key error = %v, want ErrKeyRequired", err)
	}
}

func TestEncryptedFileAtomicWriteKeepsPreviousStateOnRenameFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	f, err := NewEncryptedFile(path, bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.Save(ctx, "up/example", []byte("before")); err != nil {
		t.Fatal(err)
	}
	f.renameFn = func(string, string) error { return fmt.Errorf("simulated interrupted rename") }
	if err := f.Save(ctx, "up/example", []byte("after")); err == nil {
		t.Fatal("save succeeded despite interrupted rename")
	}
	f.renameFn = nil
	got, err := f.Load(ctx, "up/example")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Fatalf("value after interrupted write = %q, want previous value", got)
	}
}

func TestLoadFileKeyRequiresSeparateProtectedFile(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(stateDir, "key")
	if err := os.WriteFile(inside, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileKey(stateDir, inside); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("inside-state key error = %v", err)
	}
	weak := filepath.Join(root, "weak-key")
	if err := os.WriteFile(weak, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(weak, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileKey(stateDir, weak); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("weak key permissions error = %v", err)
	}
	missing := filepath.Join(root, "missing-key")
	if _, err := LoadFileKey(stateDir, missing); err == nil {
		t.Fatal("missing key file was accepted")
	}
}

// mockVault emulates the bits of OpenBao/Vault KV v2 we use.
func mockVault(t *testing.T) *Vault {
	t.Helper()
	store := map[string]string{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/data/"):
			var body struct {
				Data struct {
					V string `json:"v"`
				} `json:"data"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			store[after(r.URL.Path, "/data/")] = body.Data.V
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/data/"):
			v, ok := store[after(r.URL.Path, "/data/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"v": v}}})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/metadata/"):
			delete(store, after(r.URL.Path, "/metadata/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return &Vault{Addr: srv.URL, Token: "t", Mount: "secret", Prefix: "microagency", Client: srv.Client()}
}

func after(path, sep string) string {
	if i := strings.Index(path, sep); i >= 0 {
		return path[i+len(sep):]
	}
	return path
}

func TestVaultStore(t *testing.T) {
	roundTrip(t, mockVault(t))
}

func TestOpenPrefersVault(t *testing.T) {
	env := map[string]string{"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_TOKEN": "t"}
	s, err := Open(t.TempDir(), func(k string) string { return env[k] }, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind() != "vault" {
		t.Fatalf("with VAULT_* set, want vault, got %s", s.Kind())
	}
	s, err = Open(t.TempDir(), func(string) string { return "" }, Options{AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind() != "file" {
		t.Fatalf("without VAULT_*, want file, got %s", s.Kind())
	}
}

func TestOpenRejectsPartialVaultConfig(t *testing.T) {
	for _, env := range []map[string]string{
		{"VAULT_ADDR": "http://127.0.0.1:8200"},
		{"VAULT_TOKEN": "token"},
	} {
		if _, err := Open(t.TempDir(), func(name string) string { return env[name] }, Options{}); err == nil {
			t.Fatalf("partial Vault config was accepted: %#v", env)
		}
	}
}

// The unencrypted fallback is a downgrade, not a default. A vault that fails to
// come up must not be able to move credentials into the clear on its own; that
// takes an operator saying so.
func TestOpenRefusesPlaintextWithoutOptIn(t *testing.T) {
	withoutHostKeyring(t) // the host keyring, where there is one, encrypts instead
	dir := t.TempDir()
	if _, err := Open(dir, func(string) string { return "" }, Options{}); !errors.Is(err, ErrPlaintextNotAllowed) {
		t.Fatalf("plaintext fallback was selected without an opt-in: %v", err)
	}
	// Refusing must not leave the store behind as a side effect.
	if _, err := os.Stat(filepath.Join(dir, "upstream-tokens.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused start created the credential file anyway: %v", err)
	}
	s, err := Open(dir, func(string) string { return "" }, Options{AllowPlaintext: true})
	if err != nil {
		t.Fatalf("explicit opt-in was still refused: %v", err)
	}
	if s.Kind() != KindFile {
		t.Fatalf("kind = %q, want %q", s.Kind(), KindFile)
	}
}

// The ENCRYPTED file store is not a degradation, so it must keep working with
// no opt-in at all. Gating it would push operators toward the opt-in flag for a
// posture that never needed one.
func TestOpenAllowsEncryptedFileWithoutOptIn(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	keyPath := filepath.Join(root, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return ""
	}
	s, err := Open(stateDir, env, Options{})
	if err != nil {
		t.Fatalf("encrypted file store required an opt-in: %v", err)
	}
	if s.Kind() != KindEncryptedFile {
		t.Fatalf("kind = %q, want %q", s.Kind(), KindEncryptedFile)
	}
	if err := s.Save(context.Background(), "up/example", []byte("v")); err != nil {
		t.Fatal(err)
	}
}

// A store that IS encrypted but has lost its key setting must say so. The
// coarser "you did not opt in to plaintext" would send an operator to add the
// opt-in, which is the one action that must not fix this.
func TestOpenPrefersTheMissingKeyDiagnosisOverThePlaintextGate(t *testing.T) {
	stateDir := t.TempDir()
	store, err := NewEncryptedFile(filepath.Join(stateDir, "upstream-tokens.json"), bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "up/example", []byte("sentinel")); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{{}, {AllowPlaintext: true}} {
		if _, err := Open(stateDir, func(string) string { return "" }, opts); !errors.Is(err, ErrKeyRequired) {
			t.Fatalf("AllowPlaintext=%v: got %v, want ErrKeyRequired", opts.AllowPlaintext, err)
		}
	}
}

// The record exists so a diagnostic can report the store in effect. It must
// round-trip, and it must never be a place secrets end up.
func TestPostureRecordRoundTripsAndHoldsNoSecret(t *testing.T) {
	dir := t.TempDir()
	want := Posture{
		PID: 1234, Kind: KindFile, Effective: "unencrypted mode-0600 file",
		Configured: "external Vault/OpenBao (VAULT_ADDR)", Reason: "it did not answer", Degraded: true,
	}
	if err := SavePosture(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPosture(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != want.PID || got.Kind != want.Kind || got.Effective != want.Effective ||
		got.Configured != want.Configured || got.Reason != want.Reason || !got.Degraded {
		t.Fatalf("record round-trip lost fields: %+v", got)
	}
	if !got.Disagrees() {
		t.Fatal("a record naming two different stores must report a disagreement")
	}
	info, err := os.Stat(PosturePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("record permissions %04o are broader than the state directory's", info.Mode().Perm())
	}
	ClearPosture(dir)
	if _, err := LoadPosture(dir); err == nil {
		t.Fatal("a cleared record still loads")
	}
}
