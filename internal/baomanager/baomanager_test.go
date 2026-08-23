package baomanager

import (
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
	"time"

	"microagency/internal/secretstore"
)

func TestEnsureRejectsPartialExternalVaultConfig(t *testing.T) {
	for _, env := range []map[string]string{
		{"VAULT_ADDR": "https://vault.example:8200"},
		{"VAULT_TOKEN": "token"},
	} {
		_, _, err := Ensure(context.Background(), t.TempDir(), func(name string) string { return env[name] })
		if err == nil {
			t.Fatalf("partial external Vault config was accepted: %#v", env)
		}
	}
}

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
	Stop(dir)
	waitBaoStopped(t, addr)
}

// TestRealProtectedLifecycle proves the protected path against an actual Bao:
// no disk bootstrap, root retired, restart through the persisted protector
// locator, protector outage fails closed, and recovery preserves stored data.
func TestRealProtectedLifecycle(t *testing.T) {
	if os.Getenv("BAO_SMOKE") == "" {
		t.Skip("set BAO_SMOKE=1 (with bao on PATH) to run the real lifecycle")
	}
	dir := t.TempDir()
	helperDir := t.TempDir()
	store := filepath.Join(helperDir, "record")
	helper := filepath.Join(helperDir, "protector")
	script := fmt.Sprintf(`#!/bin/sh
store=%q
case "$1" in
  get) test -f "$store" || exit 3; cat "$store" ;;
  put) cat > "$store" ;;
  delete) rm -f "$store" ;;
  *) exit 2 ;;
esac
`, store)
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	env := func(name string) string {
		switch name {
		case ProtectorEnv:
			return "command"
		case ProtectorCommandEnv:
			return helper
		default:
			return ""
		}
	}
	ctx := context.Background()
	addr, token, err := Ensure(ctx, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(dir) })
	if _, err := os.Stat(bootstrapPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("protected lifecycle wrote bootstrap.json: %v", err)
	}
	record, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	var bs bootstrap
	if err := json.Unmarshal(record, &bs); err != nil {
		t.Fatal(err)
	}
	if bs.RootToken != "" || bs.RoleID == "" || bs.SecretID == "" {
		t.Fatalf("protected record retained root or lacks AppRole: %+v", bs)
	}
	v := &secretstore.Vault{Addr: addr, Token: token, Mount: "secret", Prefix: "microagency", Client: http.DefaultClient}
	if err := v.Save(ctx, "protected-smoke", []byte("survives")); err != nil {
		t.Fatal(err)
	}
	oldSecretID := bs.SecretID
	if err := RotateLogin(ctx, dir, func(string) string { return "" }); err != nil {
		t.Fatalf("rotate managed AppRole login: %v", err)
	}
	record, err = os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(record, &bs); err != nil {
		t.Fatal(err)
	}
	if bs.SecretID == "" || bs.SecretID == oldSecretID {
		t.Fatalf("AppRole SecretID did not rotate: %+v", bs)
	}
	probe := &Manager{Addr: addr, client: http.DefaultClient}
	if _, err := probe.loginAppRole(ctx, bs.RoleID, oldSecretID); err == nil {
		t.Fatal("previous AppRole SecretID still authenticated after rotation")
	}

	Stop(dir)
	waitBaoStopped(t, addr)
	// The manifest carries the helper path; shell configuration is not needed
	// for an unattended restart after the first protected start.
	addr, token, err = Ensure(ctx, dir, func(string) string { return "" })
	if err != nil {
		t.Fatalf("protected restart: %v", err)
	}
	v = &secretstore.Vault{Addr: addr, Token: token, Mount: "secret", Prefix: "microagency", Client: http.DefaultClient}
	if got, err := v.Load(ctx, "protected-smoke"); err != nil || string(got) != "survives" {
		t.Fatalf("load after protected restart = %q err=%v", got, err)
	}

	Stop(dir)
	waitBaoStopped(t, addr)
	backupHelper := helper + ".offline"
	if err := os.Rename(helper, backupHelper); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(ctx, dir, func(string) string { return "" }); err == nil || !FailClosed(err) {
		t.Fatalf("protector outage did not fail closed: %v", err)
	}
	if err := os.Rename(backupHelper, helper); err != nil {
		t.Fatal(err)
	}
	addr, token, err = Ensure(ctx, dir, func(string) string { return "" })
	if err != nil {
		t.Fatalf("restart after protector recovery: %v", err)
	}
	v = &secretstore.Vault{Addr: addr, Token: token, Mount: "secret", Prefix: "microagency", Client: http.DefaultClient}
	if got, err := v.Load(ctx, "protected-smoke"); err != nil || string(got) != "survives" {
		t.Fatalf("load after protector recovery = %q err=%v", got, err)
	}
}

func waitBaoStopped(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client := &http.Client{Timeout: 100 * time.Millisecond}
		resp, err := client.Get(addr + "/v1/sys/seal-status")
		if err != nil {
			return
		}
		_ = resp.Body.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("managed OpenBao did not stop")
}

// mockBao emulates the sys endpoints Ensure drives.
func mockBao(t *testing.T) (*httptest.Server, *bool) {
	t.Helper()
	var mu sync.Mutex
	initialized, sealed := false, true
	rootRevoked := false
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
		case "/v1/sys/policies/acl/microagency", "/v1/sys/auth/approle", "/v1/auth/approle/role/microagency":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/auth/approle/role/microagency/role-id":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"role_id": "role-1"}})
		case "/v1/auth/approle/role/microagency/secret-id":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"secret_id": "secret-1", "secret_id_accessor": "accessor-1"}})
		case "/v1/auth/approle/login":
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "service-tok", "lease_duration": 86400, "renewable": true}})
		case "/v1/auth/token/revoke-self":
			rootRevoked = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &rootRevoked
}

func TestInitRetiresRootAndStoresAppRole(t *testing.T) {
	srv, rootRevoked := mockBao(t)
	dir := t.TempDir()
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client()}

	tok, err := m.initOrUnseal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "service-tok" {
		t.Fatalf("operational token = %q", tok)
	}
	bs, err := loadBootstrap(dir)
	if err != nil {
		t.Fatalf("bootstrap not saved: %v", err)
	}
	if bs.UnsealKey != "unseal-key-1" || bs.RootToken != "" || bs.RoleID != "role-1" || bs.SecretID != "secret-1" {
		t.Fatalf("bootstrap = %+v", bs)
	}
	if !*rootRevoked {
		t.Fatal("initial root token was not revoked")
	}
}

func TestUnsealsExistingFromBootstrap(t *testing.T) {
	srv, _ := mockBao(t)
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
	if tok != "service-tok" {
		t.Fatalf("AppRole token from bootstrap = %q", tok)
	}
}

func TestRotateAppRoleCredentialCommitsBeforeRevokingOld(t *testing.T) {
	var destroyed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/role/microagency/secret-id":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"secret_id": "new-secret", "secret_id_accessor": "new-accessor"}})
		case "/v1/auth/approle/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["secret_id"] != "new-secret" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "new-token", "lease_duration": 86400, "renewable": true}})
		case "/v1/auth/approle/role/microagency/secret-id-accessor/destroy":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			destroyed = append(destroyed, body["secret_id_accessor"])
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	p := &memoryProtector{kind: "command", protected: true}
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client(), custody: protectedSelection(dir, p)}
	if err := m.saveBootstrap(context.Background(), bootstrap{
		UnsealKey: "unseal", RoleID: "role", SecretID: "old-secret", SecretAccessor: "old-accessor",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.rotateAppRoleCredential(context.Background(), "operational-token"); err != nil {
		t.Fatal(err)
	}
	bs, err := m.loadBootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bs.SecretID != "new-secret" || bs.SecretAccessor != "new-accessor" {
		t.Fatalf("rotated bootstrap = %+v", bs)
	}
	if len(destroyed) != 1 || destroyed[0] != "old-accessor" {
		t.Fatalf("destroyed accessors = %v", destroyed)
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
		case "/v1/sys/mounts/secret", "/v1/sys/policies/acl/microagency", "/v1/sys/auth/approle", "/v1/auth/approle/role/microagency":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/auth/approle/role/microagency/role-id":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"role_id": "role-1"}})
		case "/v1/auth/approle/role/microagency/secret-id":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"secret_id": "secret-1", "secret_id_accessor": "accessor-1"}})
		case "/v1/auth/approle/login":
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "service-tok", "lease_duration": 86400, "renewable": true}})
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
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
	if tok != "service-tok" {
		t.Fatalf("token after reset = %q, want a freshly authenticated AppRole token", tok)
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
		case "/v1/auth/approle/login":
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "service-tok", "lease_duration": 86400, "renewable": true}})
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

func TestStartRefusesReachableUnmanagedOpenBao(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client()}
	err := m.start()
	if err == nil {
		t.Fatal("reachable unmanaged OpenBao was accepted")
	}
	// A foreign listener on the managed port is its own recoverable condition,
	// not a generic outage: it must be identifiable by type so the caller can
	// name the port and say what to do, rather than surfacing a pid-file errno.
	if !IsStaleListener(err) {
		t.Fatalf("refusal is not typed as a stale listener: %v", err)
	}
	var stale *StaleListenerError
	if !errors.As(err, &stale) {
		t.Fatalf("no StaleListenerError in %v", err)
	}
	if stale.Addr != srv.URL || stale.Dir != dir || stale.Remediation() == "" {
		t.Fatalf("stale listener does not name the port, the state dir, and a next action: %+v", stale)
	}
	if !strings.Contains(err.Error(), "not the instance microagency manages") {
		t.Fatalf("refusal does not say the listener is not microagency's: %v", err)
	}

	// A recorded-but-dead instance is the same condition: whatever answers now
	// is not the one microagency started.
	if err := os.WriteFile(filepath.Join(dir, "bao.pid"), []byte("2147483646"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.start(); !IsStaleListener(err) {
		t.Fatalf("a dead recorded pid was not reported as a stale listener: %v", err)
	}
}

// ProbeManaged is what a diagnostic uses to answer "which store would a start
// actually use". It must observe, not act: no instance started, no vault
// initialized, nothing written.
func TestProbeManagedObservesWithoutActing(t *testing.T) {
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := ProbeManaged(dir, func(string) string { return "" })
	if p.Addr != ManagedAddr {
		t.Fatalf("probe addr = %q, want %q", p.Addr, ManagedAddr)
	}
	if p.Configured {
		t.Fatal("an empty state directory reported managed custody as configured")
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("probing created state: %d entries, was %d", len(after), len(before))
	}
}

// A foreign listener makes the managed store unusable, and the probe must say
// so with the typed condition — this is exactly the case where a diagnostic
// that reports the CONFIGURED store sends an operator to fix the wrong thing.
func TestProbeManagedReportsAStaleListener(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := &Manager{Dir: dir, Addr: srv.URL, client: srv.Client()}
	if !m.reachable() {
		t.Fatal("test listener is not reachable")
	}
	// Same adoption check ProbeManaged runs, against the test's own address.
	err := adoptManaged(dir, srv.URL)
	if !IsStaleListener(err) {
		t.Fatalf("a listener with no recorded instance was adopted: %v", err)
	}
	if !strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("the diagnosis does not name the port: %v", err)
	}
}
