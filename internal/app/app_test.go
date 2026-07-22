package app

import (
	"reflect"
	"testing"
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
