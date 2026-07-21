package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/refstore"
)

// A ref is bound to the subject that created it: in a shared (--issuer) gateway,
// another principal that obtains the handle cannot reduce over it, and is refused
// with the SAME error as a genuinely unknown ref (no oracle that it exists).
func TestReduceRefBoundToCreatingPrincipal(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"x":1}]`, "alice") // owned by alice
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	args, _ := json.Marshal(map[string]any{"ref": string(ref), "query": "length"})

	// Bob (a different principal) is refused, indistinguishably from an unknown ref.
	out := s.reduce(withPrincipal("bob"), args)
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("another principal must not reduce over alice's ref")
	}
	if txt := errText(t, out); !strings.Contains(txt, "unknown reference") {
		t.Fatalf("cross-user reduce must look like an unknown ref (no ownership oracle): %q", txt)
	}

	// Alice (the creator) can reduce her own ref.
	if out := s.reduce(withPrincipal("alice"), args); out["isError"].(bool) {
		raw, _ := json.Marshal(out)
		t.Fatalf("the creating principal must be able to reduce its own ref: %s", raw)
	}
}

// The default single-principal deployment (no per-request principal → subject
// "local") is unaffected: a ref created as "local" reduces as "local".
func TestReduceRefLocalSubjectUnaffected(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[{"x":1}]`, "local")
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	args, _ := json.Marshal(map[string]any{"ref": string(ref), "query": "length"})

	if out := s.reduce(withPrincipal("local"), args); out["isError"].(bool) {
		raw, _ := json.Marshal(out)
		t.Fatalf("local subject must reduce a local-owned ref: %s", raw)
	}
}
