package mcp

import (
	"reflect"
	"testing"

	"microagency/internal/gateway"
)

// putUp registers an upstream directly (no live dial) so the policy test is
// hermetic — it never opens a socket.
func putUp(s *Server, name, url string, enabled bool) {
	_ = s.registerUpstream(name, &upstream{
		conn:       &gateway.Upstream{Name: name, URL: url},
		enabled:    enabled,
		provenance: "catalog",
	})
}

// EgressPolicy is the single source of truth: the deduped, sorted set of the host
// of every ENABLED upstream's URL.
func TestEgressPolicyUnion(t *testing.T) {
	s := NewServer(nil)

	putUp(s, "github", "https://api.github.com/mcp", true)      // enabled → host governed
	putUp(s, "slack", "https://slack.example.com:8443/x", true) // enabled, port stripped
	putUp(s, "notion", "https://notion.example.com/mcp", false) // discovered → excluded

	got := s.EgressPolicy()
	want := []string{
		"api.github.com",
		"slack.example.com",
	}
	if !reflect.DeepEqual(got.Hosts, want) {
		t.Fatalf("hosts mismatch:\n got %v\nwant %v", got.Hosts, want)
	}
	// A discovered (not enabled) upstream contributes nothing.
	for _, h := range got.Hosts {
		if h == "notion.example.com" {
			t.Fatalf("discovered upstream host leaked into policy: %v", got.Hosts)
		}
	}
	// Provenance is recorded per host.
	if c := got.Contributors["api.github.com"]; len(c) != 1 || c[0].Kind != "upstream" || c[0].Name != "github" {
		t.Fatalf("api.github.com contributor wrong: %+v", c)
	}
}

// Duplicate hosts — the same host arriving from multiple enabled upstreams —
// collapse to a single allowlist entry, with every contributor recorded.
func TestEgressPolicyDedup(t *testing.T) {
	s := NewServer(nil)
	putUp(s, "up-a", "https://shared.example.com/mcp", true)
	putUp(s, "up-b", "https://shared.example.com/other", true)

	got := s.EgressPolicy()
	want := []string{"shared.example.com"}
	if !reflect.DeepEqual(got.Hosts, want) {
		t.Fatalf("duplicate hosts did not collapse: got %v want %v", got.Hosts, want)
	}
	c := got.Contributors["shared.example.com"]
	if len(c) != 2 {
		t.Fatalf("want 2 contributors for shared host, got %d: %+v", len(c), c)
	}
	// Deterministic ordering: by name.
	want2 := []EgressContributor{
		{Kind: "upstream", Name: "up-a"},
		{Kind: "upstream", Name: "up-b"},
	}
	if !reflect.DeepEqual(c, want2) {
		t.Fatalf("contributor order wrong: %+v", c)
	}
}

// An unparseable / hostless upstream URL is skipped, not emitted — a malformed
// registration can never widen the allowlist with a bogus entry.
func TestEgressPolicySkipsBadUpstreamURL(t *testing.T) {
	s := NewServer(nil)

	putUp(s, "bad", "://not a url", true)    // parse error → skipped
	putUp(s, "empty", "mcp-tool-name", true) // parses but no host → skipped
	putUp(s, "ok", "https://ok.example.com", true)

	got := s.EgressPolicy()
	want := []string{"ok.example.com"}
	if !reflect.DeepEqual(got.Hosts, want) {
		t.Fatalf("bad upstream URLs not skipped: got %v want %v", got.Hosts, want)
	}
}

// An empty gateway (no upstreams) yields an empty — not nil-panicking — policy.
func TestEgressPolicyEmpty(t *testing.T) {
	s := NewServer(nil)
	got := s.EgressPolicy()
	if len(got.Hosts) != 0 {
		t.Fatalf("empty gateway should have no governed hosts: %v", got.Hosts)
	}
}
