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

// shadowUpstream returns an upstream whose tools/call result carries a COMPACT
// structuredContent alongside a LARGE content[].text — the Notion page-fetch shape
// that let a big result ride inline because resultPayload measured the small summary.
func shadowUpstream(t *testing.T, bigText string) *httptest.Server {
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
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"fetch","description":"x"}]}}`)
		case "tools/call":
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"summary":"short"},"content":[{"type":"text","text":`+strconv.Quote(bigText)+`}],"isError":false}}`)
		default:
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}))
}

// A large result must be reffed even when the upstream also sends a small
// structuredContent — the gate keys off the LARGER representation, not the summary —
// and the ref must hold the large content (lossless), not the summary.
func TestLargeResultReffedDespiteSmallStructuredContent(t *testing.T) {
	big := strings.Repeat("PAGEDATA ", 600) // ~5KB, well over the 2KB budget
	up := shadowUpstream(t, big)
	defer up.Close()

	rs := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "call_tool", map[string]any{"name": "u__fetch", "arguments": map[string]any{}})
	inner := toolContentJSON(t, out)
	if r, _ := inner["reffed"].(bool); !r {
		t.Fatalf("large result rode inline instead of reffing: %v", inner)
	}
	// The whole big payload must NOT be inline anywhere in the returned envelope.
	if blob, _ := json.Marshal(out); strings.Contains(string(blob), "PAGEDATA PAGEDATA") {
		t.Fatalf("large content leaked inline: %.100s", blob)
	}
	// The ref must hold the LARGE content (lossless), not the "short" summary.
	data, ok := rs.Get(refstore.Ref(inner["ref"].(string)))
	if !ok || !strings.Contains(data, "PAGEDATA") {
		t.Fatalf("ref does not hold the large content (ok=%v, %.80s)", ok, data)
	}
	if strings.TrimSpace(data) == `{"summary":"short"}` {
		t.Fatal("ref stored the structuredContent summary, dropping the real data")
	}
}

// A fetched document is prose whose body contains a small incidental JSON block (a
// Notion page's <properties>). The extractor must NOT grab that fragment and drop
// the KB of real content around it — resultPayload returns the whole text.
func TestResultPayloadKeepsProseWithIncidentalJSON(t *testing.T) {
	body := "Here is the result of view for the Page.\n" + strings.Repeat("real page content. ", 200) +
		"\n<properties>\n{\"Area\":\"Core\",\"Status\":\"Draft\"}\n</properties>\n" + strings.Repeat("more content. ", 200)
	res := map[string]any{"content": []any{map[string]any{"type": "text", "text": body}}}
	got := resultPayload(res)
	if !strings.Contains(got, "real page content") || !strings.Contains(got, "more content") {
		t.Fatalf("resultPayload dropped the page body: %.80s", got)
	}
	if len(got) < len(body)/2 {
		t.Fatalf("resultPayload returned the incidental JSON fragment, not the content (len=%d of %d)", len(got), len(body))
	}
}

// A genuinely small result (small on both representations) still inlines — the fix
// must not over-ref.
func TestSmallResultStillInlinesWithStructuredContent(t *testing.T) {
	up := shadowUpstream(t, "tiny")
	defer up.Close()

	rs := refstore.NewMemStore()
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 2048, Store: rs}),
		WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}
	out := call(t, s, "call_tool", map[string]any{"name": "u__fetch", "arguments": map[string]any{}})
	if r, _ := out["reffed"].(bool); r {
		t.Fatalf("a small result was needlessly reffed: %v", out)
	}
}
