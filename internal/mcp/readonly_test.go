package mcp

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

// A read-only upstream refuses its write tools at the invocation gate — no upstream
// call is made — while its read tools still work.
func TestReadOnlyRefusesWritesAllowsReads(t *testing.T) {
	s, hit := addGuarded(t, []upTool{{name: "get-thing"}, {name: "create-thing"}}, false)
	if err := s.SetUpstreamReadOnly("u", true); err != nil {
		t.Fatalf("set read-only: %v", err)
	}

	// Write refused, upstream never dialed.
	w := call(t, s, "call_tool", map[string]any{"name": "u__create-thing", "arguments": map[string]any{}})
	if e, _ := w["isError"].(bool); !e {
		t.Fatalf("write on a read-only upstream should be refused: %v", w)
	}
	if blob, _ := json.Marshal(w); !strings.Contains(string(blob), "READ-ONLY") {
		t.Fatalf("refusal should explain read-only: %s", blob)
	}
	if n := atomic.LoadInt32(hit); n != 0 {
		t.Fatalf("a refused write still reached the upstream %d time(s)", n)
	}

	// Read still works.
	r := call(t, s, "call_tool", map[string]any{"name": "u__get-thing", "arguments": map[string]any{}})
	if e, _ := r["isError"].(bool); e {
		t.Fatalf("read on a read-only upstream should work: %v", r)
	}
	if n := atomic.LoadInt32(hit); n != 1 {
		t.Fatalf("read did not reach upstream (hit=%d)", n)
	}
}

// find_tools marks a read-only upstream's write tools non-invocable, so the agent
// doesn't pick a tool the gate will refuse.
func TestReadOnlyFindToolsMarksWrites(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}, {name: "create-thing"}}, false)
	if err := s.SetUpstreamReadOnly("u", true); err != nil {
		t.Fatalf("set read-only: %v", err)
	}

	out := call(t, s, "find_tools", map[string]any{"query": "thing", "limit": 10})
	res := toolContentJSON(t, out)
	tools, _ := res["tools"].([]any)
	seen := map[string]map[string]any{}
	for _, ti := range tools {
		m, _ := ti.(map[string]any)
		name, _ := m["name"].(string)
		seen[name] = m
	}
	write := seen["u__create-thing"]
	if write == nil {
		t.Fatalf("write tool not in find_tools: %v", res)
	}
	if inv, _ := write["invocable"].(bool); inv {
		t.Fatalf("write on a read-only upstream must be marked non-invocable: %v", write)
	}
	if b, _ := write["read_only_blocked"].(bool); !b {
		t.Fatalf("write should carry read_only_blocked: %v", write)
	}
	read := seen["u__get-thing"]
	if inv, _ := read["invocable"].(bool); !inv {
		t.Fatalf("read tool must stay invocable: %v", read)
	}
}

// The read-only flag surfaces in the operator upstream list and errors on an unknown
// upstream.
func TestReadOnlyReflectedInUpstreamList(t *testing.T) {
	s, _ := addGuarded(t, []upTool{{name: "get-thing"}}, false)
	if err := s.SetUpstreamReadOnly("nope", true); err == nil {
		t.Fatal("setting read-only on an unknown upstream should error")
	}
	if err := s.SetUpstreamReadOnly("u", true); err != nil {
		t.Fatalf("set read-only: %v", err)
	}
	var found bool
	for _, u := range s.UpstreamList() {
		if u.Name == "u" {
			found = true
			if !u.ReadOnly {
				t.Fatal("upstream list should report read_only=true")
			}
		}
	}
	if !found {
		t.Fatal("upstream u missing from list")
	}
}
