package main

import (
	"os"
	"path/filepath"
	"testing"

	"microagency/internal/mcp"
)

// writeFile is a tiny helper for the hermetic config fixtures below.
func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseClientMCPServers(t *testing.T) {
	// ~/.claude.json shape: per-project mcpServers under projects.<dir>, plus a
	// top-level block. stdio servers (command/args, no url) must be ignored.
	claudeJSON := `{
		"mcpServers": {"global-http": {"type": "http", "url": "https://global.example/mcp"}},
		"projects": {
			"/home/me/proj": {
				"mcpServers": {
					"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"},
					"local-cli": {"command": "some-bin", "args": ["--stdio"]}
				}
			},
			"/home/me/other": {"mcpServers": {"linear": {"url": "https://mcp.linear.app/mcp"}}}
		}
	}`
	got := parseClientMCPServers([]byte(claudeJSON), "/home/me/.claude.json")
	byName := map[string]clientMCPServer{}
	for _, s := range got {
		byName[s.Name] = s
	}
	for _, want := range []string{"global-http", "github", "linear"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected direct server %q to be parsed, got %+v", want, got)
		}
	}
	if _, ok := byName["local-cli"]; ok {
		t.Errorf("stdio server (no url) should be ignored, but was parsed")
	}
	if byName["github"].ConfigPath != "/home/me/.claude.json" {
		t.Errorf("ConfigPath not propagated: %+v", byName["github"])
	}
}

func TestParseClientMCPServers_ProjectMCPJSON(t *testing.T) {
	// Project-level .mcp.json shape: a top-level mcpServers map, no projects wrapper.
	body := `{"mcpServers": {"jira": {"type": "http", "url": "https://jira.example/mcp"}}}`
	got := parseClientMCPServers([]byte(body), ".mcp.json")
	if len(got) != 1 || got[0].Name != "jira" {
		t.Fatalf("expected one jira server, got %+v", got)
	}
}

func TestParseClientMCPServers_Malformed(t *testing.T) {
	// Defensive parsing: garbage or unexpected shapes yield nothing, never a panic.
	for _, in := range []string{``, `not json`, `[]`, `{"mcpServers": "nope"}`, `{"projects": 5}`, `{"mcpServers": {"x": 7}}`} {
		if got := parseClientMCPServers([]byte(in), "cfg"); got != nil {
			t.Errorf("parseClientMCPServers(%q) = %+v, want nil", in, got)
		}
	}
}

func TestNormalizeMCPURL(t *testing.T) {
	cases := []struct{ a, b string }{
		{"https://mcp.linear.app/mcp", "https://mcp.linear.app/mcp/"}, // trailing slash
		{"https://Host.Example/MCP", "https://host.example/MCP"},      // host case only (path preserved)
		{"HTTPS://host.example/mcp", "https://host.example/mcp"},      // scheme case
		{"https://host.example/mcp#frag", "https://host.example/mcp"}, // fragment stripped
	}
	for _, c := range cases {
		if normalizeMCPURL(c.a) != normalizeMCPURL(c.b) {
			t.Errorf("normalizeMCPURL(%q)=%q != normalizeMCPURL(%q)=%q", c.a, normalizeMCPURL(c.a), c.b, normalizeMCPURL(c.b))
		}
	}
	// Distinct paths must NOT collapse together.
	if normalizeMCPURL("https://host/mcp") == normalizeMCPURL("https://host/other") {
		t.Error("distinct paths should not normalize equal")
	}
}

func TestDetectBypasses_Overlap(t *testing.T) {
	upstreams := []mcp.UpstreamRegistration{
		{Name: "linear", URL: "https://mcp.linear.app/mcp"},
		{Name: "github", URL: "https://api.githubcopilot.com/mcp/"},
	}
	client := []clientMCPServer{
		// Same URL as the "linear" upstream but formatted differently (trailing slash).
		{Name: "linear-direct", URL: "https://mcp.linear.app/mcp/", ConfigPath: "/h/.claude.json"},
		// Something else entirely — must not warn.
		{Name: "notion", URL: "https://mcp.notion.com/mcp", ConfigPath: "/h/.claude.json"},
	}
	warnings := detectBypasses(upstreams, client)
	if len(warnings) != 1 {
		t.Fatalf("expected exactly 1 bypass warning, got %d: %+v", len(warnings), warnings)
	}
	w := warnings[0]
	if w.UpstreamName != "linear" || w.ClientName != "linear-direct" || w.ConfigPath != "/h/.claude.json" {
		t.Errorf("unexpected warning contents: %+v", w)
	}
	if w.URL != "https://mcp.linear.app/mcp" {
		t.Errorf("warning should carry the upstream's registered URL, got %q", w.URL)
	}
}

func TestDetectBypasses_NoOverlap(t *testing.T) {
	upstreams := []mcp.UpstreamRegistration{{Name: "linear", URL: "https://mcp.linear.app/mcp"}}
	client := []clientMCPServer{
		// microagency's OWN entry — points at the local gateway, not an upstream URL.
		{Name: "microagency", URL: "http://127.0.0.1:8765/mcp", ConfigPath: "/h/.claude.json"},
		{Name: "notion", URL: "https://mcp.notion.com/mcp", ConfigPath: "/h/.claude.json"},
	}
	if got := detectBypasses(upstreams, client); len(got) != 0 {
		t.Fatalf("expected no bypass warnings, got %+v", got)
	}
}

// TestGatherAndDetect_EndToEnd wires the real file-reading path against fixtures in a
// temp dir — no real home dir or cwd dependence — and asserts the overlap surfaces.
func TestGatherAndDetect_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	claudePath := writeFile(t, dir, ".claude.json", `{
		"projects": {"/p": {"mcpServers": {
			"linear-direct": {"type": "http", "url": "https://mcp.linear.app/mcp"},
			"cli-tool": {"command": "x"}
		}}}
	}`)
	mcpJSONPath := writeFile(t, dir, ".mcp.json", `{"mcpServers": {"jira": {"url": "https://jira.example/mcp"}}}`)
	missing := filepath.Join(dir, "does-not-exist.json")

	servers := gatherClientServers([]string{claudePath, mcpJSONPath, missing})
	upstreams := []mcp.UpstreamRegistration{
		{Name: "linear", URL: "https://mcp.linear.app/mcp/"}, // overlaps linear-direct
		{Name: "safe", URL: "https://safe.example/mcp"},      // no overlap
	}
	warnings := detectBypasses(upstreams, servers)
	if len(warnings) != 1 || warnings[0].UpstreamName != "linear" {
		t.Fatalf("expected 1 warning for 'linear', got %+v", warnings)
	}
}

// TestReadUpstreamRegistrations_RoundTrip verifies the exported reader used by
// doctor parses the persisted upstreams.json, and tolerates a missing file.
func TestReadUpstreamRegistrations_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if got := mcp.ReadUpstreamRegistrations(dir); got != nil {
		t.Fatalf("no file should read as nil, got %+v", got)
	}
	writeFile(t, dir, "upstreams.json", `[{"name":"linear","url":"https://mcp.linear.app/mcp"},{"name":"gh","url":"https://api.githubcopilot.com/mcp/"}]`)
	got := mcp.ReadUpstreamRegistrations(dir)
	if len(got) != 2 || got[0].Name != "linear" || got[1].URL != "https://api.githubcopilot.com/mcp/" {
		t.Fatalf("unexpected registrations: %+v", got)
	}
}
