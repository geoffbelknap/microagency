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

	s.mu.Lock()
	_, staleThere := s.oauthFlows["stale"]
	_, freshThere := s.oauthFlows["fresh"]
	n := len(s.oauthFlows)
	s.mu.Unlock()

	if staleThere {
		t.Fatal("the expired flow should have been swept on the next put")
	}
	if !freshThere || n != 1 {
		t.Fatalf("the fresh flow must remain (have %d flows)", n)
	}
}
