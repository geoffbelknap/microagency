package app

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"microagency/internal/secretstore"
)

// withLocalProtector points the credential store's data key at a helper script
// in a temp directory.
//
// Without it, a build with no opt-in resolves to whatever keyring the machine
// running the test happens to have: a developer desktop encrypts (and leaves a
// key in that developer's real keyring), while a headless build machine refuses.
// A test that takes a different code path in the two places is not testing the
// same thing in the two places, and the build machine is the one that catches
// regressions.
func withLocalProtector(t *testing.T) {
	t.Helper()
	dir := t.TempDir() // 0700, so it satisfies the helper's substitution checks
	key := filepath.Join(dir, "key")
	helper := filepath.Join(dir, "protector")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"  put) cat > " + key + " ;;\n" +
		"  get) [ -f " + key + " ] || exit 3; cat " + key + " ;;\n" +
		"  delete) rm -f " + key + " ;;\n" +
		"esac\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secretstore.ProtectorEnv, "command")
	t.Setenv(secretstore.ProtectorCommandEnv, helper)
}

// The default reduce engine is "the first one registered", so registration order
// must be deterministic (not Go map iteration) and must prefer jq. These pin both.
func TestOrderEngineNamesIsDeterministicAndJqFirst(t *testing.T) {
	// Input order must not affect the result: jq leads, the rest are alphabetical.
	want := []string{"jq", "html", "sql", "text"}
	for _, in := range [][]string{
		{"jq", "html", "sql", "text"},
		{"text", "sql", "html", "jq"},
		{"sql", "jq", "text", "html"},
	} {
		if got := orderEngineNames(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("orderEngineNames(%v) = %v, want %v", in, got, want)
		}
	}
}

// Without jq present, the order is simply alphabetical — still deterministic.
func TestOrderEngineNamesFallsBackToAlphabetical(t *testing.T) {
	got := orderEngineNames([]string{"text", "html", "sql"})
	want := []string{"html", "sql", "text"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderEngineNames without jq = %v, want %v", got, want)
	}
}

// BuildServer constructs a configured gateway from a plain Config — the importable
// seam an embedder/test/microplane uses instead of the CLI.
func TestBuildServerFromConfig(t *testing.T) {
	srv, err := BuildServer(Config{
		StateDir:       t.TempDir(),
		Version:        "test",
		MaxInlineBytes: 8192,
		WasmMaxMemMB:   512,
		BundledEngines: map[string][]byte{"jq": []byte("dummy-wasm"), "sql": []byte("dummy-wasm")},
		// No vault is configured here, so this build lands on the local file
		// store — which the gateway now refuses without an explicit opt-in.
		AllowPlaintextCredentials: true,
	})
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	if srv == nil {
		t.Fatal("nil server")
	}
	got := srv.EngineNames()
	if len(got) != 2 || got[0] != "jq" && got[1] != "jq" {
		t.Fatalf("engines not registered from Config: %v", got)
	}
}

// A bad --engine spec is returned as an error, not an os.Exit — the whole point of
// the importable seam. The store has to open for the build to reach engine
// parsing at all, so this names a protector: otherwise the credential gate
// returns first and the test passes without ever exercising what it describes.
func TestBuildServerReturnsErrorOnBadEngineSpec(t *testing.T) {
	withLocalProtector(t)
	_, err := BuildServer(Config{StateDir: t.TempDir(), EngineSpecs: []string{"noequals"}})
	if err == nil {
		t.Fatal("a malformed --engine spec must return an error, not exit")
	}
	if errors.Is(err, secretstore.ErrPlaintextNotAllowed) {
		t.Fatalf("the build stopped at the credential gate, so the engine spec was never parsed: %v", err)
	}
	if !strings.Contains(err.Error(), "noequals") {
		t.Fatalf("the error does not name the malformed spec: %v", err)
	}
}

// With a protector available and no opt-in, a build encrypts. It must never
// reach the unencrypted store, and the record it writes must name the protector
// holding the key.
func TestBuildServerEncryptsWithoutAnOptIn(t *testing.T) {
	withLocalProtector(t)
	dir := t.TempDir()
	if _, err := BuildServer(Config{
		StateDir:       dir,
		Version:        "test",
		MaxInlineBytes: 8192,
		WasmMaxMemMB:   512,
	}); err != nil {
		t.Fatalf("build refused with a reachable protector: %v", err)
	}
	p, err := secretstore.LoadPosture(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != secretstore.KindEncryptedFile {
		t.Fatalf("credentials did not land in the encrypted store with no opt-in: %+v", p)
	}
	if p.Degraded {
		t.Fatalf("an encrypted store was recorded as degraded: %+v", p)
	}
	if p.KeyCustody == "" || !p.KeyCreated {
		t.Fatalf("the record does not say who holds the key this build generated: %+v", p)
	}
}

// The refusal has to name what was unavailable and every way forward, or the
// operator is left with "it won't start" and no thread to pull.
func TestPlaintextRefusalNamesWhatWasTriedAndEveryWayForward(t *testing.T) {
	err := plaintextRefusal(Config{
		PreferredStore:            "external Vault/OpenBao (VAULT_ADDR)",
		PreferredStoreUnavailable: "it did not answer when the gateway started",
	})
	if !errors.Is(err, secretstore.ErrPlaintextNotAllowed) {
		t.Fatalf("refusal does not carry the sentinel: %v", err)
	}
	for _, want := range []string{
		"external Vault/OpenBao (VAULT_ADDR)",        // what was configured
		"it did not answer when the gateway started", // why it was unavailable
		"no OS keyring was available",                // why nothing else held a key
		secretstore.ProtectorEnv,                     // a KMS or secret-manager helper
		secretstore.FileKeyEnv,                       // a key the operator holds
		secretstore.AllowPlaintextEnv,                // how to accept it deliberately
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q is missing %q", err.Error(), want)
		}
	}
}

// Whatever store is opened, the gateway records it, so a diagnostic reports
// what is in effect instead of re-deriving it from configuration that may
// disagree.
func TestBuildServerRecordsTheStoreItActuallyOpened(t *testing.T) {
	dir := t.TempDir()
	if _, err := BuildServer(Config{
		StateDir:                  dir,
		Version:                   "test",
		MaxInlineBytes:            8192,
		WasmMaxMemMB:              512,
		AllowPlaintextCredentials: true,
		PreferredStore:            "external Vault/OpenBao (VAULT_ADDR)",
		PreferredStoreUnavailable: "it did not answer when the gateway started",
	}); err != nil {
		t.Fatal(err)
	}
	p, err := secretstore.LoadPosture(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != secretstore.KindFile || !p.Degraded {
		t.Fatalf("record does not describe the unencrypted store: %+v", p)
	}
	if !p.Disagrees() || p.Configured != "external Vault/OpenBao (VAULT_ADDR)" {
		t.Fatalf("record does not say the configured store is not the one in effect: %+v", p)
	}
	if p.Reason == "" {
		t.Fatalf("record does not say why the configured store was not used: %+v", p)
	}
	if p.PID != os.Getpid() {
		t.Fatalf("record pid = %d, want this process (%d)", p.PID, os.Getpid())
	}
}
