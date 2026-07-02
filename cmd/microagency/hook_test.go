package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHostsFromToolInput(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
		want  []string
	}{
		{"bash single url", "Bash", `{"command":"curl https://mcp.supabase.com/mcp -d x"}`, []string{"mcp.supabase.com"}},
		{"bash strips port + case", "Bash", `{"command":"curl HTTPS://API.Example.com:8443/v1"}`, []string{"api.example.com"}},
		{"bash strips userinfo", "Bash", `{"command":"curl https://user:pw@host.example.com/x"}`, []string{"host.example.com"}},
		{"bash multiple + dedup", "Bash", `{"command":"curl https://a.example.com/1 && wget https://b.example.com/2 https://a.example.com/3"}`, []string{"a.example.com", "b.example.com"}},
		{"webfetch url", "WebFetch", `{"url":"https://app.notion.com/v1/pages"}`, []string{"app.notion.com"}},
		{"non-network tool ignored", "Read", `{"file_path":"https://x.example.com/nope"}`, nil},
		{"bash no url", "Bash", `{"command":"ls -la && echo hi"}`, nil},
		{"malformed input", "Bash", `not json`, nil},
	}
	for _, c := range cases {
		got := hostsFromToolInput(c.tool, json.RawMessage(c.input))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestGovernedMatches(t *testing.T) {
	governed := map[string]bool{"mcp.supabase.com": true, "db.example.com": true}
	if got := governedMatches([]string{"mcp.supabase.com", "google.com"}, governed); len(got) != 1 || got[0] != "mcp.supabase.com" {
		t.Fatalf("expected only the governed host, got %v", got)
	}
	if got := governedMatches([]string{"google.com", "github.com"}, governed); got != nil {
		t.Fatalf("no governed host should match, got %v", got)
	}
	// dedup
	if got := governedMatches([]string{"db.example.com", "db.example.com"}, governed); len(got) != 1 {
		t.Fatalf("duplicates should collapse, got %v", got)
	}
}

// The guard is fail-open: with no reachable policy (governed set empty), no warning
// is written even when the command targets a plausible host.
func TestEgressGuardFailsOpenWithoutPolicy(t *testing.T) {
	// Ensure no token/policy is reachable: point at a dead admin addr.
	t.Setenv("MICROAGENCY_ADMIN_ADDR", "127.0.0.1:0")
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"curl https://mcp.supabase.com/mcp"}}`)
	var out, errw bytes.Buffer
	egressGuard(in, &out, &errw)
	if out.Len() != 0 || errw.Len() != 0 {
		t.Fatalf("guard must stay silent when the policy is unreachable (fail-open); out=%q err=%q", out.String(), errw.String())
	}
}

// A non-network tool never triggers the guard regardless of policy.
func TestEgressGuardIgnoresNonNetworkTools(t *testing.T) {
	in := strings.NewReader(`{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}`)
	var out, errw bytes.Buffer
	egressGuard(in, &out, &errw)
	if out.Len() != 0 || errw.Len() != 0 {
		t.Fatalf("non-network tool must not warn; out=%q err=%q", out.String(), errw.String())
	}
}

func TestPrintHookInstallShowsCommand(t *testing.T) {
	var b bytes.Buffer
	printHookInstall(&b)
	s := b.String()
	if !strings.Contains(s, "hook egress-guard") || !strings.Contains(s, "PreToolUse") || !strings.Contains(s, "Bash|WebFetch") {
		t.Fatalf("install help missing key parts:\n%s", s)
	}
}
