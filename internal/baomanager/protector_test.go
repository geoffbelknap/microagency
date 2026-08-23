package baomanager

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
	"testing"
)

type memoryProtector struct {
	kind                 string
	protected            bool
	value                []byte
	loadErr, saveErr     error
	deleteErr            error
	deleted, corruptLoad bool
}

func (p *memoryProtector) Kind() string    { return p.kind }
func (p *memoryProtector) Protected() bool { return p.protected }
func (p *memoryProtector) Load(context.Context) ([]byte, error) {
	if p.loadErr != nil {
		return nil, p.loadErr
	}
	if p.value == nil {
		return nil, errBootstrapNotFound
	}
	out := append([]byte(nil), p.value...)
	if p.corruptLoad {
		out = append(out, 'x')
	}
	return out, nil
}
func (p *memoryProtector) Save(_ context.Context, value []byte) error {
	if p.saveErr != nil {
		return p.saveErr
	}
	p.value = append([]byte(nil), value...)
	p.deleted = false
	return nil
}
func (p *memoryProtector) Delete(context.Context) error {
	if p.deleteErr != nil {
		return p.deleteErr
	}
	p.value = nil
	p.deleted = true
	return nil
}

func protectedSelection(dir string, p protector) custodySelection {
	return custodySelection{
		dir:       dir,
		manifest:  custodyManifest{Format: custodyFormat, Kind: p.Kind(), ID: custodyID(dir), Command: "/test/helper"},
		protector: p,
	}
}

func TestProtectedBootstrapLeavesNoSecretInStateDirectory(t *testing.T) {
	dir := t.TempDir()
	p := &memoryProtector{kind: "command", protected: true}
	m := &Manager{Dir: dir, custody: protectedSelection(dir, p)}
	ctx := context.Background()
	if err := m.saveBootstrap(ctx, bootstrap{UnsealKey: "unseal", RootToken: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bootstrapPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("protected bootstrap was written under the state directory: %v", err)
	}
	manifest, err := loadCustodyManifest(dir)
	if err != nil || manifest.Kind != "command" {
		t.Fatalf("custody manifest = %+v err=%v", manifest, err)
	}
	if !bytes.Contains(p.value, []byte("root")) {
		t.Fatal("test protector did not receive the transitional record")
	}
	if err := m.saveBootstrap(ctx, bootstrap{UnsealKey: "unseal", RoleID: "role", SecretID: "secret"}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(p.value, []byte("root")) || bytes.Contains(p.value, []byte("root_token")) {
		t.Fatalf("retired root remained in protected record: %s", p.value)
	}
}

func TestProtectedCustodyPreflightDoesNotInitializeOverStaleOrUnavailableRecord(t *testing.T) {
	dir := t.TempDir()
	p := &memoryProtector{kind: "command", protected: true}
	m := &Manager{Dir: dir, custody: protectedSelection(dir, p)}
	if err := m.preflightProtectedCustody(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.value != nil || !p.deleted {
		t.Fatalf("preflight record was not removed: value=%q deleted=%v", p.value, p.deleted)
	}
	p.value = []byte(`{"unseal_key":"existing"}`)
	if err := m.preflightProtectedCustody(context.Background()); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("stale protected record was overwritten: %v", err)
	}
	if !bytes.Contains(p.value, []byte("existing")) {
		t.Fatalf("stale protected record changed: %q", p.value)
	}
	p.value = nil
	p.deleted = false
	p.saveErr = errors.New("kms unavailable")
	if err := m.preflightProtectedCustody(context.Background()); err == nil || !strings.Contains(err.Error(), "preflight protected bootstrap write") {
		t.Fatalf("unavailable protector passed preflight: %v", err)
	}
}

func TestProtectedBootstrapLossFailsClosedWithoutReset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/seal-status" {
			_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	reset := false
	p := &memoryProtector{kind: "command", protected: true, loadErr: errBootstrapNotFound}
	m := &Manager{
		Dir: t.TempDir(), Addr: srv.URL, client: srv.Client(), custody: protectedSelection(t.TempDir(), p),
		reset: func(context.Context) error { reset = true; return nil },
	}
	if _, err := m.initOrUnseal(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot be loaded") {
		t.Fatalf("protected loss did not fail closed: %v", err)
	}
	if reset {
		t.Fatal("protected bootstrap loss reset OpenBao storage")
	}
}

func TestLegacyBootstrapMigratesOnlyAfterProtectorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	legacy := bootstrap{UnsealKey: "unseal", RootToken: "root"}
	if err := saveBootstrap(dir, legacy); err != nil {
		t.Fatal(err)
	}
	p := &memoryProtector{kind: "command", protected: true}
	m := &Manager{Dir: dir, custody: protectedSelection(dir, p)}
	got, err := m.loadBootstrap(context.Background())
	if err != nil || got.RootToken != legacy.RootToken {
		t.Fatalf("migrated bootstrap = %+v err=%v", got, err)
	}
	if _, err := os.Stat(bootstrapPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("legacy disk copy remains after verified migration: %v", err)
	}
	if len(p.value) == 0 {
		t.Fatal("protector did not receive migrated bootstrap")
	}

	dir2 := t.TempDir()
	if err := saveBootstrap(dir2, legacy); err != nil {
		t.Fatal(err)
	}
	bad := &memoryProtector{kind: "command", protected: true, corruptLoad: true}
	m = &Manager{Dir: dir2, custody: protectedSelection(dir2, bad)}
	if _, err := m.loadBootstrap(context.Background()); err == nil || !strings.Contains(err.Error(), "round-trip mismatch") {
		t.Fatalf("corrupt protector migration was accepted: %v", err)
	}
	if _, err := os.Stat(bootstrapPath(dir2)); err != nil {
		t.Fatalf("failed migration removed the only good copy: %v", err)
	}
}

func TestCustodyMigrationCommitsBeforeDeletingSource(t *testing.T) {
	dir := t.TempDir()
	secret, _ := json.Marshal(bootstrap{UnsealKey: "unseal", RoleID: "role", SecretID: "secret"})
	source := &memoryProtector{kind: "file", value: secret}
	target := &memoryProtector{kind: "command", protected: true}
	targetManifest := custodyManifest{Format: custodyFormat, Kind: "command", ID: custodyID(dir), Command: "/test/helper"}
	if err := migrateCustodyRecord(context.Background(), dir, secret, source, targetManifest, target); err != nil {
		t.Fatal(err)
	}
	if !source.deleted || !bytes.Equal(target.value, secret) {
		t.Fatalf("source deleted=%v target=%q", source.deleted, target.value)
	}
	manifest, err := loadCustodyManifest(dir)
	if err != nil || manifest.Kind != "command" {
		t.Fatalf("committed manifest = %+v err=%v", manifest, err)
	}

	dir2 := t.TempDir()
	source = &memoryProtector{kind: "file", value: secret}
	target = &memoryProtector{kind: "command", protected: true, corruptLoad: true}
	if err := migrateCustodyRecord(context.Background(), dir2, secret, source, targetManifest, target); err == nil {
		t.Fatal("round-trip mismatch was accepted")
	}
	if source.deleted {
		t.Fatal("source was deleted before the target verified")
	}
	if _, err := os.Stat(custodyPath(dir2)); !os.IsNotExist(err) {
		t.Fatalf("failed migration committed a manifest: %v", err)
	}
}

func TestCommandProtectorMigrationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := saveBootstrap(dir, bootstrap{UnsealKey: "unseal", RoleID: "role", SecretID: "secret"}); err != nil {
		t.Fatal(err)
	}
	helperDir := t.TempDir()
	store := filepath.Join(helperDir, "protected-record")
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
	getenv := func(name string) string {
		if name == ProtectorCommandEnv {
			return helper
		}
		return ""
	}
	if err := MigrateCustody(context.Background(), dir, getenv, "command", false); err != nil {
		t.Fatalf("file to helper: %v", err)
	}
	if _, err := os.Stat(bootstrapPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("same-disk bootstrap remains after protected migration: %v", err)
	}
	if _, err := os.Stat(store); err != nil {
		t.Fatalf("helper did not retain the protected record: %v", err)
	}
	if err := MigrateCustody(context.Background(), dir, getenv, "file", true); err != nil {
		t.Fatalf("helper to acknowledged file: %v", err)
	}
	if _, err := loadBootstrap(dir); err != nil {
		t.Fatalf("degraded migration did not restore bootstrap.json: %v", err)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("old helper record remains after migration: %v", err)
	}
}

func TestInspectCustodyDistinguishesDegradedAndUnavailable(t *testing.T) {
	dir := t.TempDir()
	if err := saveBootstrap(dir, bootstrap{UnsealKey: "u", RoleID: "r", SecretID: "s"}); err != nil {
		t.Fatal(err)
	}
	posture := InspectCustody(context.Background(), dir, func(string) string { return "" })
	if posture.Protected || !posture.Available || posture.Kind != "file" || !strings.Contains(posture.Detail, "root retired") {
		t.Fatalf("file posture = %+v", posture)
	}

	dir = t.TempDir()
	manifest := custodyManifest{Format: custodyFormat, Kind: "command", ID: custodyID(dir), Command: filepath.Join(dir, "missing-helper")}
	if err := saveCustodyManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
	posture = InspectCustody(context.Background(), dir, func(string) string { return "" })
	if !posture.Protected || posture.Available || !strings.Contains(posture.Detail, "protector helper") {
		t.Fatalf("unavailable protected posture = %+v", posture)
	}
}

func TestProtectedErrorsAndDegradedMigrationGuard(t *testing.T) {
	base := errors.New("locked")
	if !FailClosed(&ProtectedError{Err: base}) || FailClosed(base) {
		t.Fatal("protected error classification is wrong")
	}
	if err := MigrateCustody(context.Background(), t.TempDir(), func(string) string { return "" }, "file", false); err == nil || !strings.Contains(err.Error(), "--allow-degraded") {
		t.Fatalf("degraded migration was not guarded: %v", err)
	}
}

func TestFreshProtectedSelectionPersistsFailClosedLocatorBeforeBaoStarts(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(t.TempDir(), "protector")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	getenv := func(name string) string {
		switch name {
		case ProtectorEnv:
			return "command"
		case ProtectorCommandEnv:
			return helper
		default:
			return ""
		}
	}
	if _, _, err := Ensure(context.Background(), dir, getenv); err == nil || !FailClosed(err) {
		t.Fatalf("fresh protected startup did not fail closed when Bao was missing: %v", err)
	}
	manifest, err := loadCustodyManifest(dir)
	if err != nil || manifest.Kind != "command" || manifest.Command != helper {
		t.Fatalf("fail-closed locator = %+v err=%v", manifest, err)
	}
}
