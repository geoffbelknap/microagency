package baomanager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"microagency/internal/secretstore"
)

// TestRealLifecycle drives a real OpenBao on PATH end to end: start → init →
// unseal → KV v2 → Save/Load a secret → Stop. Gated so it stays out of normal CI.
func TestRealLifecycle(t *testing.T) {
	if os.Getenv("BAO_SMOKE") == "" {
		t.Skip("set BAO_SMOKE=1 (with bao on PATH) to run the real lifecycle")
	}
	dir := t.TempDir()
	ctx := context.Background()
	addr, token, err := Ensure(ctx, dir, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	defer Stop(dir)
	v := &secretstore.Vault{Addr: addr, Token: token, Mount: "secret", Prefix: "microagency", Client: http.DefaultClient}
	if err := v.Save(ctx, "smoke", []byte("hello")); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := v.Load(ctx, "smoke")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("load = %q", got)
	}
}

// mockBao emulates the sys endpoints Ensure drives.
func mockBao(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	initialized, sealed := false, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/sys/seal-status":
			json.NewEncoder(w).Encode(map[string]any{"initialized": initialized, "sealed": sealed})
		case "/v1/sys/init":
			initialized = true
			json.NewEncoder(w).Encode(map[string]any{"keys_base64": []string{"unseal-key-1"}, "root_token": "root-tok"})
		case "/v1/sys/unseal":
			sealed = false
			json.NewEncoder(w).Encode(map[string]any{"sealed": false})
		case "/v1/sys/mounts/secret":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInitStoresBootstrapAndUnseals(t *testing.T) {
	srv := mockBao(t)
	dir := t.TempDir()
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client()}

	tok, err := m.initOrUnseal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "root-tok" {
		t.Fatalf("root token = %q", tok)
	}
	bs, err := loadBootstrap(dir)
	if err != nil {
		t.Fatalf("bootstrap not saved: %v", err)
	}
	if bs.UnsealKey != "unseal-key-1" || bs.RootToken != "root-tok" {
		t.Fatalf("bootstrap = %+v", bs)
	}
	if err := m.ensureKVv2(context.Background(), tok); err != nil {
		t.Fatalf("ensure kv v2: %v", err)
	}
}

func TestUnsealsExistingFromBootstrap(t *testing.T) {
	srv := mockBao(t)
	dir := t.TempDir()
	// first run initializes + stores the bootstrap
	if _, err := (&Manager{Dir: dir, Addr: srv.URL, client: srv.Client()}).initOrUnseal(context.Background()); err != nil {
		t.Fatal(err)
	}
	// a "restart": initialized + sealed → unseal from the stored bootstrap (no re-init)
	srvReseal := reseal(t, srv.URL)
	m := &Manager{Dir: dir, Addr: srvReseal, client: http.DefaultClient}
	tok, err := m.initOrUnseal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "root-tok" {
		t.Fatalf("root token from bootstrap = %q", tok)
	}
}

// TestInitializedButBootstrapMissingResets is the fragility fix: when the vault is
// initialized but its bootstrap is gone (a torn write or an external delete), the
// vault is unrecoverable. initOrUnseal must reset it and come back usable, not fail
// forever (which strands OAuth tokens on the file store).
func TestInitializedButBootstrapMissingResets(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	initialized, sealed := true, true // the broken state: initialized, no bootstrap file
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/sys/seal-status":
			json.NewEncoder(w).Encode(map[string]any{"initialized": initialized, "sealed": sealed})
		case "/v1/sys/init":
			initialized, sealed = true, true
			json.NewEncoder(w).Encode(map[string]any{"keys_base64": []string{"unseal-key-1"}, "root_token": "root-tok"})
		case "/v1/sys/unseal":
			sealed = false
			json.NewEncoder(w).Encode(map[string]any{"sealed": false})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	// A real data dir stands in for the orphaned storage, so the reset archives it.
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "corrupt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	reset := false
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client(), reset: func(context.Context) error {
		reset = true
		mu.Lock()
		initialized, sealed = false, true // wiped storage → fresh, uninitialized
		mu.Unlock()
		return archiveBaoStorage(dir)
	}}

	tok, err := m.initOrUnseal(context.Background())
	if err != nil {
		t.Fatalf("expected recovery, got error: %v", err)
	}
	if !reset {
		t.Fatal("did not reset the unrecoverable vault")
	}
	if tok != "root-tok" {
		t.Fatalf("root token after reset = %q, want a freshly initialized one", tok)
	}
	if _, err := loadBootstrap(dir); err != nil {
		t.Fatalf("fresh bootstrap not saved after reset: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data.orphaned", "corrupt")); err != nil {
		t.Fatalf("orphaned storage was not archived: %v", err)
	}
}

// TestSaveBootstrapAtomic: the write leaves no temp file and round-trips.
func TestSaveBootstrapAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := saveBootstrap(dir, bootstrap{UnsealKey: "k", RootToken: "r"}); err != nil {
		t.Fatal(err)
	}
	got, err := loadBootstrap(dir)
	if err != nil || got.UnsealKey != "k" || got.RootToken != "r" {
		t.Fatalf("round trip: %+v err=%v", got, err)
	}
	if _, err := os.Stat(bootstrapPath(dir) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind (stat err = %v)", err)
	}
	// A second save replaces atomically.
	if err := saveBootstrap(dir, bootstrap{UnsealKey: "k2", RootToken: "r2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := loadBootstrap(dir); got.UnsealKey != "k2" {
		t.Fatalf("replace failed: %+v", got)
	}
}

// TestArchiveBaoStorage moves data aside, clears the bootstrap, and overwrites a
// prior archive rather than accumulating.
func TestArchiveBaoStorage(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "data", "f"), []byte("new"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "data.orphaned"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "data.orphaned", "old"), []byte("stale"), 0o600)
	_ = saveBootstrap(dir, bootstrap{UnsealKey: "k", RootToken: "r"})

	if err := archiveBaoStorage(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatal("data dir was not moved aside")
	}
	if _, err := os.Stat(filepath.Join(dir, "data.orphaned", "f")); err != nil {
		t.Fatalf("current data not archived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data.orphaned", "old")); !os.IsNotExist(err) {
		t.Fatal("prior archive was not overwritten")
	}
	if _, err := loadBootstrap(dir); err == nil {
		t.Fatal("bootstrap not cleared")
	}
}

// reseal returns a mock that reports initialized+sealed, then unseals on demand —
// modeling an existing Bao after a restart.
func reseal(t *testing.T, _ string) string {
	t.Helper()
	sealed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/seal-status":
			json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": sealed})
		case "/v1/sys/unseal":
			sealed = false
			json.NewEncoder(w).Encode(map[string]any{"sealed": false})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestResolveBinaryMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no bao/openbao
	if _, err := resolveBinary(); err == nil {
		t.Fatal("expected an error when bao is not installed")
	}
}
