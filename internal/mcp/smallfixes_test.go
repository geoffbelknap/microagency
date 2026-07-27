package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"microagency/internal/budget"
	"microagency/internal/refstore"
)

// An object keyed by DATA (emails, ids) must not leak those keys in the preview —
// they're values, not a field schema. Report the count only.
func TestStructuralPreviewDataKeyedObjectHidesKeys(t *testing.T) {
	p := structuralPreview(`{"alice@example.com":{"n":1},"bob@example.com":{"n":2},"carol@example.com":{"n":3}}`)
	if p["kind"] != "object" {
		t.Fatalf("kind = %v, want object", p["kind"])
	}
	if _, hasKeys := p["keys"]; hasKeys {
		t.Fatalf("data-like keys must not be emitted: %v", p)
	}
	if p["key_count"] != 3 {
		t.Fatalf("key_count = %v, want 3", p["key_count"])
	}
	if b, _ := json.Marshal(p); strings.Contains(string(b), "@example.com") {
		t.Fatalf("preview leaked a data key: %s", b)
	}
}

// A normal record object still shows its field-name schema (regression guard).
func TestStructuralPreviewRecordShowsFieldNames(t *testing.T) {
	p := structuralPreview(`{"id":1,"name":"x","email":"secret@x.io"}`)
	ks, ok := p["keys"].([]string)
	if !ok || len(ks) != 3 {
		t.Fatalf("record schema should show keys, got %v", p)
	}
	if b, _ := json.Marshal(p); strings.Contains(string(b), "secret@x.io") {
		t.Fatalf("field-name preview leaked a value: %s", b)
	}
}

// reduce refuses query and code together rather than silently running the query.
func TestReduceRejectsQueryAndCode(t *testing.T) {
	store := refstore.NewMemStore()
	ref, _ := store.Put(`[1,2,3]`, "local")
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))

	args, _ := json.Marshal(map[string]any{"ref": string(ref), "query": "length", "code": "print(1)"})
	out := s.reduce(withPrincipal("local"), args)
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatal("reduce with both query and code must error")
	}
	if txt := errText(t, out); !strings.Contains(txt, "not both") {
		t.Fatalf("error should explain the query/code conflict: %q", txt)
	}
}

// putOAuthFlow sweeps abandoned (expired) flows, so a flow that's started and never
// completed doesn't linger forever.
func TestPutOAuthFlowSweepsExpired(t *testing.T) {
	s := NewServer(fakeRunner{})
	s.putOAuthFlow("stale", &oauthFlow{name: "old", expiry: time.Now().Add(-time.Hour)})
	s.putOAuthFlow("fresh", &oauthFlow{name: "new", expiry: time.Now().Add(time.Hour)})

	s.flows.mu.Lock()
	_, staleThere := s.flows.byState["stale"]
	_, freshThere := s.flows.byState["fresh"]
	n := len(s.flows.byState)
	s.flows.mu.Unlock()

	if staleThere {
		t.Fatal("the expired flow should have been swept on the next put")
	}
	if !freshThere || n != 1 {
		t.Fatalf("the fresh flow must remain (have %d flows)", n)
	}
}

// TestToolsListFollowsTheWorkflowOrder pins tools/list to find → call →
// reduce. The wire order led with reduce — the most advanced tool, the one
// least likely to be an agent's first step, carrying by far the largest
// description — and list order is a weak but real salience signal: a model
// skimming a tool list anchors on what it reads first. The README and the
// descriptions themselves teach find_tools → call_tool → reduce; the wire
// now agrees.
func TestToolsListFollowsTheWorkflowOrder(t *testing.T) {
	defs := toolDefs()
	var names []string
	for _, d := range defs {
		names = append(names, d["name"].(string))
	}
	want := []string{"find_tools", "call_tool", "reduce"}
	if len(names) != len(want) {
		t.Fatalf("tool count = %d, want %d: %v", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("tools/list order = %v, want %v", names, want)
		}
	}
}
