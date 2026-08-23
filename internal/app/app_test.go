package app

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"microagency/internal/secretstore"
)

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
// the importable seam.
func TestBuildServerReturnsErrorOnBadEngineSpec(t *testing.T) {
	if _, err := BuildServer(Config{StateDir: t.TempDir(), EngineSpecs: []string{"noequals"}}); err == nil {
		t.Fatal("a malformed --engine spec must return an error, not exit")
	}
}

// A vault that could not be reached must not silently become a plaintext file
// on disk. The refusal has to name what was unavailable and why, or the
// operator is left with "it won't start" and no thread to pull.
func TestBuildServerFailsClosedRatherThanDowngradingToPlaintext(t *testing.T) {
	_, err := BuildServer(Config{
		StateDir:                  t.TempDir(),
		Version:                   "test",
		MaxInlineBytes:            8192,
		WasmMaxMemMB:              512,
		PreferredStore:            "managed OpenBao",
		PreferredStoreUnavailable: "another process holds http://127.0.0.1:8200",
	})
	if !errors.Is(err, secretstore.ErrPlaintextNotAllowed) {
		t.Fatalf("build did not fail closed on the unencrypted fallback: %v", err)
	}
	for _, want := range []string{
		"managed OpenBao is unavailable",              // what was configured
		"another process holds http://127.0.0.1:8200", // why it was unavailable
		secretstore.FileKeyEnv,                        // how to encrypt instead
		secretstore.AllowPlaintextEnv,                 // how to accept it deliberately
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
		PreferredStore:            "managed OpenBao",
		PreferredStoreUnavailable: "another process holds http://127.0.0.1:8200",
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
	if !p.Disagrees() || p.Configured != "managed OpenBao" {
		t.Fatalf("record does not say the configured store is not the one in effect: %+v", p)
	}
	if p.Reason == "" {
		t.Fatalf("record does not say why the configured store was not used: %+v", p)
	}
	if p.PID != os.Getpid() {
		t.Fatalf("record pid = %d, want this process (%d)", p.PID, os.Getpid())
	}
}
