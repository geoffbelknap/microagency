package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"microagency/internal/gateway"
)

// The suggester recognizes sensitive field types from tool names and input
// property names, mapping each to a sensible default action.
func TestSuggestMinimizePolicy(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "get_accounts", InputSchema: json.RawMessage(`{"type":"object","properties":{"account_number":{"type":"string"}}}`)},
		{Name: "place_order", InputSchema: json.RawMessage(`{"type":"object","properties":{"card_number":{"type":"string"},"customer_email":{"type":"string"}}}`)},
		{Name: "kyc", InputSchema: json.RawMessage(`{"type":"object","properties":{"ssn":{"type":"string"}}}`)},
	}
	got := suggestMinimizePolicy(tools)
	want := map[string]string{
		"account": "tokenize",
		"card":    "tokenize",
		"email":   "redact",
		"ssn":     "alert",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

// A schema with no sensitive signals yields no suggestion.
func TestSuggestMinimizePolicyEmpty(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "search", InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"number"}}}`)},
	}
	if got := suggestMinimizePolicy(tools); len(got) != 0 {
		t.Fatalf("expected no suggestion, got %v", got)
	}
}

// The suggestion is exposed via UpstreamList only until a policy is set; setting
// one suppresses the suggestion in favor of the active policy.
func TestUpstreamListSurfacesSuggestionUntilPolicySet(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	ts := upstreamEchoingCard(t, new(string)) // advertises an "acct" tool → account signal
	defer ts.Close()
	if err := s.AddUpstream(context.Background(), &gateway.Upstream{Name: "acme", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	find := func() UpstreamInfo {
		for _, u := range s.UpstreamList() {
			if u.Name == "acme" {
				return u
			}
		}
		t.Fatal("upstream not found")
		return UpstreamInfo{}
	}

	u := find()
	if len(u.MinimizeSuggested) == 0 {
		t.Fatal("expected a suggestion auto-detected from the tool schema")
	}
	if len(u.Minimize) != 0 {
		t.Fatal("no active policy is set yet")
	}

	s.SetMinimizePolicy("acme", []byte(`{"account":"tokenize"}`))
	u = find()
	if len(u.MinimizeSuggested) != 0 {
		t.Fatalf("suggestion must be suppressed once a policy is set, got %s", u.MinimizeSuggested)
	}
	if len(u.Minimize) == 0 {
		t.Fatal("active policy should be surfaced")
	}
}
