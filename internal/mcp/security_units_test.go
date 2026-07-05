package mcp

import "testing"

// A resource indicator that is a URL on a DIFFERENT origin than the upstream is
// rejected; the upstream's own origin and a host-less audience identifier are allowed.
func TestResourceAllowedForUpstream(t *testing.T) {
	const up = "https://mcp.example.com/mcp"
	cases := []struct {
		resource string
		want     bool
	}{
		{"https://mcp.example.com/mcp", true},       // exact
		{"https://mcp.example.com", true},           // same origin, different path
		{"microagency", true},                       // bare audience identifier (no host)
		{"", true},                                  // empty parses to no host → allowed (caller fills it)
		{"https://victim.example.com/api", false},   // cross-origin URL — the attack
		{"http://mcp.example.com/mcp", false},       // scheme mismatch
		{"https://mcp.example.com.evil.com", false}, // look-alike host
	}
	for _, c := range cases {
		if got := resourceAllowedForUpstream(c.resource, up); got != c.want {
			t.Errorf("resourceAllowedForUpstream(%q) = %v, want %v", c.resource, got, c.want)
		}
	}
}

// Scope sanitization drops any advertised scope carrying characters outside the RFC
// 6749 scope-token set — so a scope smuggling markup for the console picker never
// reaches the browser.
func TestSanitizeScopes(t *testing.T) {
	in := []string{
		"read:files",
		"write:files",
		`"><img src=x onerror=alert(1)>`, // XSS payload — has space + quote
		"",                               // empty
		"has space",                      // space is not a scope-token char
		"tab\tinside",                    // control char
	}
	got := sanitizeScopes(in)
	want := []string{"read:files", "write:files"}
	if len(got) != len(want) {
		t.Fatalf("sanitizeScopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sanitizeScopes = %v, want %v", got, want)
		}
	}
}
