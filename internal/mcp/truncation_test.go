package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

func TestTruncatedNotice(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		flag    bool
	}{
		{"truncated JSON (claims JSON, invalid)", `{"result":[{"id":"abc","name":"zon`, true},
		{"marker appended", `{"a":1} stuff --- TRUNCATED --- Response was ~27,449 tokens (limit: 6,000). Use narrower queries.`, true},
		{"valid JSON object", `{"a":1,"b":[1,2,3]}`, false},
		{"valid JSON array", `[{"mrn":"MRN1"},{"mrn":"MRN2"}]`, false},
		{"prose document", "Here is the result of view for the Page. Lots of real content follows.", false},
		{"doc mentioning the marker mid-content", `{"text":"The Cloudflare MCP appended --- TRUNCATED --- to the response. ` + strings.Repeat("More documentation about the incident. ", 40) + `"}`, false},
		{"marker in the tail", `{"result":"partial data...` + strings.Repeat("x", 100) + " --- TRUNCATED --- narrow your query.", true},
		// A COMPLETE JSON result whose own content ends with a marker phrase is data,
		// not a cut notice — it must not be discarded (regression for the false positive).
		{"valid JSON ending in a marker string", `[{"line":"connection reset"},{"line":"output truncated"}]`, false},
		{"valid JSON object with marker value", `{"log":"stream ended: response truncated"}`, false},
		{"empty", "", false},
	}
	for _, c := range cases {
		msg, got := truncatedNotice(c.payload)
		if got != c.flag {
			t.Errorf("%s: flagged=%v want %v (msg=%q)", c.name, got, c.flag, msg)
		}
		if got && msg == "" {
			t.Errorf("%s: flagged but empty message", c.name)
		}
	}
	// The marker's guidance is what gets surfaced.
	if msg, _ := truncatedNotice(`{"a":1 --- TRUNCATED --- Use more specific queries to reduce response size.`); !strings.Contains(msg, "specific queries") {
		t.Fatalf("marker tail should carry the upstream's guidance, got %q", msg)
	}
}

// textUpstream returns a fake MCP server whose tools/call hands back the given text
// as the single content block.
func textUpstream(t *testing.T, text string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get","description":"x","inputSchema":{}}]}}`)
		case "tools/call":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+strconv.Quote(text)+`}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
}

func truncTestServer(t *testing.T, up *httptest.Server, rs refstore.Store) *Server {
	t.Helper()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}
	return s
}

// The Cloudflare shape: a large JSON response cut mid-structure with a truncation
// marker. It must be surfaced inline as a notice — not parked behind a ref where the
// agent's reduce would hit a parse error.
func TestTruncatedPayloadSurfacedNotReffed(t *testing.T) {
	broken := `{"result":[` + strings.Repeat(`{"id":"zone","name":"example.com"},`, 200) +
		`{"id":"zone","na` + // cut mid-object
		"\n--- TRUNCATED --- Response was ~27,449 tokens (limit: 6,000). Use more specific queries to reduce response size."
	up := textUpstream(t, broken)
	defer up.Close()
	rs := refstore.NewMemStore()
	s := truncTestServer(t, up, rs)

	out := call(t, s, "call_tool", map[string]any{"name": "u__get", "arguments": map[string]any{}})
	inner := toolContentJSON(t, out)
	if tr, _ := inner["truncated"].(bool); !tr {
		t.Fatalf("truncated payload was not flagged: %v", inner)
	}
	if r, _ := inner["reffed"].(bool); r {
		t.Fatal("a truncation notice must not be reffed")
	}
	if notice, _ := inner["upstream_notice"].(string); !strings.Contains(notice, "specific queries") {
		t.Fatalf("the upstream's guidance was not surfaced: %q", notice)
	}
	// The broken 7KB blob must not have been parked as a ref.
	if blob, _ := json.Marshal(out); strings.Contains(string(blob), "example.com") {
		t.Fatal("the broken payload rode inline instead of just the notice")
	}
}

// A large, VALID result whose CONTENT ends with a truncation marker phrase (a log
// search returning a line that literally reads "output truncated") must still ref —
// the marker is data, not an appended cut notice, so it must not be discarded.
func TestValidJSONContainingMarkerStillReffed(t *testing.T) {
	valid := `[` + strings.Repeat(`{"line":"connection reset by peer"},`, 200) +
		`{"line":"upstream response: output truncated"}]`
	up := textUpstream(t, valid)
	defer up.Close()
	rs := refstore.NewMemStore()
	s := truncTestServer(t, up, rs)

	out := call(t, s, "call_tool", map[string]any{"name": "u__get", "arguments": map[string]any{}})
	inner := toolContentJSON(t, out)
	if tr, _ := inner["truncated"].(bool); tr {
		t.Fatalf("valid JSON containing a marker phrase was wrongly flagged as truncated: %v", inner)
	}
	if r, _ := inner["reffed"].(bool); !r {
		t.Fatalf("valid result containing a marker should still ref: %v", inner)
	}
}

// A large but VALID result still refs — the detector must not false-positive.
func TestLargeValidJSONStillReffed(t *testing.T) {
	valid := `[` + strings.Repeat(`{"mrn":"MRN0001"},`, 400) + `{"mrn":"LAST"}]`
	up := textUpstream(t, valid)
	defer up.Close()
	rs := refstore.NewMemStore()
	s := truncTestServer(t, up, rs)

	out := call(t, s, "call_tool", map[string]any{"name": "u__get", "arguments": map[string]any{}})
	inner := toolContentJSON(t, out)
	if tr, _ := inner["truncated"].(bool); tr {
		t.Fatalf("valid JSON was wrongly flagged as truncated: %v", inner)
	}
	if r, _ := inner["reffed"].(bool); !r {
		t.Fatalf("large valid result should ref: %v", inner)
	}
}
