package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/gateway"
)

func TestFindToolsRanksRelevant(t *testing.T) {
	ts := cannedUpstream(t) // exposes "search"
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	// A query about searching the corpus surfaces the upstream tool, ranked first,
	// WITH its schema so the agent can invoke it via call_tool.
	found := foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search the corpus"}))
	if len(found) == 0 || found[0].Name != "docs__search" {
		t.Fatalf("expected docs__search ranked first, got %v", found)
	}
	if found[0].InputSchema == nil {
		t.Fatal("find_tools must return the tool's inputSchema (for call_tool)")
	}

	// find_tools indexes only the aggregated upstreams — never the native tools
	// (those are already in tools/list) and never itself.
	for _, tl := range foundTools(t, call(t, s, "find_tools", map[string]any{"query": "reduce python find call source tools"})) {
		if tl.Name == "reduce" || tl.Name == "find_tools" || tl.Name == "call_tool" {
			t.Fatalf("find_tools returned native tool %q; it must index upstreams only", tl.Name)
		}
	}
}

func TestFindToolsRespectsLimit(t *testing.T) {
	// Two upstreams → two matching tools; the limit must cap results.
	a, b := cannedUpstream(t), cannedUpstream(t)
	defer a.Close()
	defer b.Close()
	s := newTestServer(t, fakeRunner{})
	for name, url := range map[string]string{"u1": a.URL, "u2": b.URL} {
		if err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: url}); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	if got := len(foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search corpus", "limit": 1}))); got != 1 {
		t.Fatalf("limit=1 returned %d tools", got)
	}
}

func TestFindToolsRanksByUsage(t *testing.T) {
	a, b := cannedUpstream(t), cannedUpstream(t)
	defer a.Close()
	defer b.Close()
	s := newTestServer(t, fakeRunner{})
	for name, url := range map[string]string{"u1": a.URL, "u2": b.URL} {
		if err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: url}); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	// u2__search gets invoked twice; u1__search not at all — same keyword score,
	// so usage must break the tie and rank u2__search first.
	call(t, s, "call_tool", map[string]any{"name": "u2__search", "arguments": map[string]any{"q": "x"}})
	call(t, s, "call_tool", map[string]any{"name": "u2__search", "arguments": map[string]any{"q": "x"}})

	found := foundTools(t, call(t, s, "find_tools", map[string]any{"query": "search the corpus"}))
	if len(found) < 2 || found[0].Name != "u2__search" {
		t.Fatalf("usage did not rank the more-used tool first: %v", found)
	}
}

type foundTool struct {
	Name        string `json:"name"`
	InputSchema any    `json:"inputSchema"`
	Enabled     bool   `json:"enabled"`
}

func foundTools(t *testing.T, out map[string]any) []foundTool {
	t.Helper()
	text := out["content"].([]map[string]any)[0]["text"].(string)
	var payload struct {
		Tools []foundTool `json:"tools"`
	}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("decode find_tools payload: %v (%s)", err, text)
	}
	return payload.Tools
}

// jsonStr renders s as a JSON string literal (safe for embedding in a hand-built body).
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// bigSchemaUpstream serves n tools that all match "widget", each with BOTH a verbose
// inputSchema and a multi-KB markdown description — the Notion shape (5–7KB
// descriptions, KB-scale schemas) that made a broad find_tools serialize to ~95KB.
// "verbose property description" marks a full schema; "FULLDESCRIPTION" marks a full
// (un-clipped) description.
func bigSchemaUpstream(t *testing.T, n int) *httptest.Server {
	t.Helper()
	var props []string
	for i := 0; i < 40; i++ {
		props = append(props, fmt.Sprintf(`"p_%d":{"type":"string","description":"a very long verbose property description repeated to bloat the schema well past any inline budget %s"}`, i, strings.Repeat("x", 200)))
	}
	schema := `{"type":"object","required":["p_0"],"properties":{` + strings.Join(props, ",") + `}}`
	bigDesc := "FULLDESCRIPTION " + strings.Repeat("this tool has a very long markdown description like Notion's. ", 90) // ~5KB
	var tools []string
	for i := 0; i < n; i++ {
		desc := fmt.Sprintf("manage widget number %d. %s", i, bigDesc)
		if i == 0 {
			desc = "manage widget alphaonly. " + bigDesc // a unique term so a narrow query selects exactly this tool
		}
		tools = append(tools, fmt.Sprintf(`{"name":"widget_%d","description":%s,"inputSchema":%s}`, i, jsonStr(desc), schema))
	}
	list := `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Join(tools, ",") + `]}}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "tools/list" {
			io.WriteString(w, list)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
}

// A broad find_tools over a verbose upstream must stay within budget: the top hit
// keeps its full schema, the tail gets summarized, and the whole response is bounded
// — instead of the ~100KB unbounded dump that tripped the model's context cap.
func TestFindToolsBoundsOversizedMenu(t *testing.T) {
	up := bigSchemaUpstream(t, 30)
	defer up.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "find_tools", map[string]any{"query": "widget", "limit": 30})

	res := toolContentJSON(t, out)
	tools, _ := res["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("no tools returned")
	}

	// The core property: the whole response is bounded. A naive dump of 30 tools with
	// ~5KB descriptions + KB schemas is ~200KB; the bounded menu is a fraction of that,
	// regardless of upstream verbosity.
	blob, _ := json.Marshal(out)
	if len(blob) > findToolsHardMax+8<<10 {
		t.Fatalf("find_tools output = %d bytes, not bounded (hard max %d)", len(blob), findToolsHardMax)
	}

	// Both heavy fields are capped: only a bounded prefix keeps the full description
	// AND the full schema.
	var fullDescs, fullSchemas int
	for _, ti := range tools {
		m, _ := ti.(map[string]any)
		if d, _ := m["description"].(string); strings.Contains(d, "FULLDESCRIPTION") && !strings.Contains(d, "[truncated]") {
			fullDescs++
		}
		if sb, _ := json.Marshal(m["inputSchema"]); strings.Contains(string(sb), "verbose property description") {
			fullSchemas++
		}
	}
	if fullDescs == 0 || fullSchemas == 0 {
		t.Fatalf("no full detail returned — menu unusable (fullDescs=%d fullSchemas=%d)", fullDescs, fullSchemas)
	}
	if fullDescs > 3 || fullSchemas > 3 {
		t.Fatalf("heavy fields not capped: %d full descriptions, %d full schemas of %d", fullDescs, fullSchemas, len(tools))
	}

	// Top hit is full on both fields.
	top, _ := tools[0].(map[string]any)
	if d, _ := top["description"].(string); !strings.Contains(d, "FULLDESCRIPTION") || strings.Contains(d, "[truncated]") {
		t.Fatalf("top hit lost its full description: %.80s", d)
	}
	if topSchema, _ := json.Marshal(top["inputSchema"]); !strings.Contains(string(topSchema), "verbose property description") {
		t.Fatalf("top hit lost its full inputSchema: %s", topSchema)
	}
	if _, trunc := top["truncated"]; trunc {
		t.Fatal("top hit must never be summarized")
	}

	// The summarized tail: description clipped, schema digested to param names only.
	var sawTruncated bool
	for _, ti := range tools {
		m, _ := ti.(map[string]any)
		if t2, _ := m["truncated"].(bool); !t2 {
			continue
		}
		sawTruncated = true
		if d, _ := m["description"].(string); !strings.Contains(d, "[truncated]") {
			t.Fatalf("summarized entry kept its full description: %.80s", d)
		}
		dig, _ := m["inputSchema"].(map[string]any)
		if s2, _ := dig["summarized"].(bool); !s2 {
			t.Fatalf("truncated entry missing schema digest: %v", m["inputSchema"])
		}
		if sb, _ := json.Marshal(dig); strings.Contains(string(sb), "verbose property description") {
			t.Fatal("summarized schema still carries full property descriptions")
		}
	}
	if !sawTruncated {
		t.Fatal("expected the tail of a verbose menu to be summarized")
	}
	if res["note"] == nil {
		t.Fatal("truncated menu must carry a follow-up note")
	}
}

// A narrow query (few matches) returns full schemas — the escape hatch the
// truncation note points to.
func TestFindToolsNarrowQueryKeepsFullSchema(t *testing.T) {
	up := bigSchemaUpstream(t, 30)
	defer up.Close()

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: &http.Client{}}); err != nil {
		t.Fatalf("add upstream: %v", err)
	}

	out := call(t, s, "find_tools", map[string]any{"query": "alphaonly", "limit": 3})
	res := toolContentJSON(t, out)
	tools, _ := res["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected exactly one match for the unique term, got %d", len(tools))
	}
	top, _ := tools[0].(map[string]any)
	if got := top["name"]; got != "u__widget_0" {
		t.Fatalf("expected u__widget_0 as the sole hit, got %v", got)
	}
	if topSchema, _ := json.Marshal(top["inputSchema"]); !strings.Contains(string(topSchema), "verbose property description") {
		t.Fatalf("narrow query did not return the full schema: %s", topSchema)
	}
}
