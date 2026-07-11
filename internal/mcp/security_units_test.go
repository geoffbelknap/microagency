package mcp

import "testing"

// A non-empty resource indicator must be an absolute URL on the upstream's origin.
// Host-less, opaque, and cross-origin values are rejected so attacker-controlled
// protected-resource metadata cannot select a token audience unrelated to the upstream.
func TestResourceAllowedForUpstream(t *testing.T) {
	const up = "https://mcp.example.com/mcp"
	cases := []struct {
		resource string
		want     bool
	}{
		{"https://mcp.example.com/mcp", true},       // exact
		{"https://mcp.example.com", true},           // same origin, different path
		{"", true},                                  // empty is allowed only because the caller fills it
		{"microagency", false},                      // bare audience identifier
		{"urn:example:resource", false},             // opaque absolute URI with no host
		{"/mcp", false},                             // relative URL
		{"https://victim.example.com/api", false},   // cross-origin URL — the attack
		{"http://mcp.example.com/mcp", false},       // same host, different scheme
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
