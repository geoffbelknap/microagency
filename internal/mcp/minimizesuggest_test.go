package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"microagency/internal/gateway"
)

// Sensitive VALUE fields are recognized and mapped to a sensible action.
func TestSuggestMinimizePolicyValues(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "get_portfolio", InputSchema: json.RawMessage(`{"type":"object","properties":{"account_number":{"type":"string"}}}`)},
		{Name: "place_order", InputSchema: json.RawMessage(`{"type":"object","properties":{"card_number":{"type":"string"},"customer_email":{"type":"string"}}}`)},
		{Name: "kyc", InputSchema: json.RawMessage(`{"type":"object","properties":{"ssn":{"type":"string"},"billing_address":{"type":"string"}}}`)},
	}
	want := map[string]string{"account": "tokenize", "card": "tokenize", "email": "redact", "ssn": "alert", "address": "redact"}
	assertPolicy(t, suggestMinimizePolicy(tools), want)
}

// Reference keys and same-looking non-PII fields must NOT be flagged: account_id is
// a tenant key (Cloudflare), ip_address is a network address (security tools), and
// "dashboard" merely contains "card". None are sensitive values.
func TestSuggestMinimizePolicyNoFalsePositives(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "cf_execute", InputSchema: json.RawMessage(`{"type":"object","properties":{"account_id":{"type":"string"},"code":{"type":"string"}}}`)},
		{Name: "get_sensor", InputSchema: json.RawMessage(`{"type":"object","properties":{"ip_address":{"type":"string"},"mac_address":{"type":"string"}}}`)},
		{Name: "open_dashboard", InputSchema: json.RawMessage(`{"type":"object","properties":{"country_code":{"type":"string"}}}`)},
	}
	if got := suggestMinimizePolicy(tools); len(got) != 0 {
		t.Fatalf("no sensitive VALUE present — expected no suggestion, got %v", got)
	}
}

// An arbitrary-output tool (free query/SQL/search) can return any PII regardless of
// its input schema, so a starter output-scrub policy is suggested — catching the
// Notion/Supabase shape the input-name scan misses.
func TestSuggestMinimizePolicyUnboundedOutput(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "execute_sql", InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"project_id":{"type":"string"}}}`)},
	}
	assertPolicy(t, suggestMinimizePolicy(tools), unboundedOutputDefault)
}

// A tool with neither sensitive fields nor a free-query input yields nothing.
func TestSuggestMinimizePolicyEmpty(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "list_items", InputSchema: json.RawMessage(`{"type":"object","properties":{"limit":{"type":"number"},"cursor":{"type":"string"}}}`)},
	}
	if got := suggestMinimizePolicy(tools); len(got) != 0 {
		t.Fatalf("expected no suggestion, got %v", got)
	}
}

// The server's own prose is a first-class signal: a field described as "the
// customer's email address" or a tool that "returns social security numbers" is
// detected even when the field NAME gives nothing away.
func TestSuggestFromDescriptions(t *testing.T) {
	tools := []gateway.Tool{
		{
			Name:        "lookup",
			Description: "Returns the member's social security number and date of birth.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"the customer's email address"},"x":{"type":"string","description":"an opaque handle"}}}`),
		},
	}
	assertPolicy(t, suggestMinimizePolicy(tools), map[string]string{
		"ssn":   "alert",
		"dob":   "alert",
		"email": "redact",
	})
}

// A negated mention must not trigger a suggestion — "does not return" is the
// opposite of a signal. Only the unbounded-output signal (from "search") fires.
func TestSuggestProseNegationGuard(t *testing.T) {
	tools := []gateway.Tool{
		{Name: "safe_search", Description: "A privacy-safe search that does not return social security numbers or email addresses.", InputSchema: json.RawMessage(`{"type":"object","properties":{"term":{"type":"string","description":"free text; without any phone number"}}}`)},
	}
	assertPolicy(t, suggestMinimizePolicy(tools), unboundedOutputDefault)
}

// The expanded vocabulary is suggested from field names — credentials, a personal
// name, a bare phone, a CVV — while DB keys (primary_key/public_key) and generic
// name-like fields (table_name) are NOT.
func TestSuggestSecretNameAndLoosenedFields(t *testing.T) {
	got := suggestMinimizePolicy([]gateway.Tool{
		{Name: "get_events", InputSchema: json.RawMessage(`{"type":"object","properties":{"api_key":{"type":"string"},"bearer_token":{"type":"string"},"private_key_pem":{"type":"string"},"full_name":{"type":"string"},"phone":{"type":"string"},"card_cvv":{"type":"string"},"zip":{"type":"string"}}}`)},
	})
	for _, ty := range []string{"secret", "name", "phone", "card", "address"} {
		if got[ty] == "" {
			t.Errorf("expected %q to be suggested, got %v", ty, got)
		}
	}
	if got["secret"] != "redact" {
		t.Errorf("secret should default to redact, got %q", got["secret"])
	}
	// DB keys and generic *_name fields must not be flagged.
	safe := suggestMinimizePolicy([]gateway.Tool{
		{Name: "list_things", InputSchema: json.RawMessage(`{"type":"object","properties":{"primary_key":{"type":"string"},"public_key":{"type":"string"},"table_name":{"type":"string"},"tool_name":{"type":"string"}}}`)},
	})
	if len(safe) != 0 {
		t.Fatalf("DB keys / *_name fields must not be flagged: %v", safe)
	}
}

func assertPolicy(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
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
