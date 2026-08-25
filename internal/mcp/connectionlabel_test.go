package mcp

import (
	"strings"
	"testing"
)

// A label is text an attacker may influence that lands in a model's context, so
// the charset is an allow-list and everything outside it is REFUSED — never
// trimmed, substituted, or quietly rewritten into something acceptable.
func TestConnectionLabelCharset(t *testing.T) {
	accepted := []string{
		"",                                 // clears the label
		"production",                       // the ordinary case
		"prod",                             //
		"Acme EU",                          // interior single space
		"staging-2",                        // hyphen and digit
		"db_read.only",                     // the whole punctuation set
		"a",                                // one character
		strings.Repeat("x", 32),            // exactly at the cap
		"production eu west 1 replica set", // a realistic long name
	}
	for _, label := range accepted {
		got, err := validateConnectionLabel(label)
		if err != nil {
			t.Fatalf("label %q must be accepted: %v", label, err)
		}
		if got != label {
			t.Fatalf("a valid label must be returned byte-for-byte: set %q, got %q", label, got)
		}
	}

	refused := []struct {
		name, label, wantReason string
	}{
		{"newline", "prod\nstaging", "line break"},
		{"carriage return", "prod\rstaging", "line break"},
		{"tab", "prod\tstaging", "tab"},
		{"nul", "prod\x00staging", "control character"},
		{"bell", "prod\astaging", "control character"},
		{"escape", "prod\x1b[31m", "control character"},
		{"delete", "prod\x7f", "control character"},
		{"zero-width space", "prod\u200bstaging", "zero-width or bidirectional"},
		{"zero-width joiner", "prod\u200dstaging", "zero-width or bidirectional"},
		{"right-to-left override", "prod\u202estaging", "zero-width or bidirectional"},
		{"left-to-right isolate", "prod\u2066staging", "zero-width or bidirectional"},
		{"cyrillic homoglyph", "prоduction", "non-ASCII"},
		{"emoji", "prod \U0001f525", "non-ASCII"},
		{"over the cap", strings.Repeat("x", 33), "the limit is 32"},
		{"far over the cap", strings.Repeat("x", 5000), "the limit is 32"},
		{"leading space", " prod", "leading or trailing space"},
		{"trailing space", "prod ", "leading or trailing space"},
		{"repeated spaces", "prod  db", "repeated spaces"},
		{"namespace separator", "prod__search", "separates a connection"},
		{"punctuation only", "---", "no letter or digit"},
		{"angle brackets", "<prod>", "limited to"},
		{"quote", `prod"`, "limited to"},
		{"backslash", `prod\`, "limited to"},
		{"colon", "prod:db", "limited to"},
		{"invalid utf-8", "prod\xff", "valid UTF-8"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateConnectionLabel(tc.label)
			if err == nil {
				t.Fatalf("label %q must be refused; got %q", tc.label, got)
			}
			if got != "" {
				t.Fatalf("a refused label must return nothing, never a rewritten value: %q", got)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("refusal must say %q: %v", tc.wantReason, err)
			}
		})
	}
}

// A refusal message is itself text that reaches a log and a caller, so it must
// not carry the raw control characters or the unbounded input it is rejecting.
func TestConnectionLabelRefusalDoesNotEchoRawHazards(t *testing.T) {
	for _, label := range []string{"prod\nstaging", "prod\x00x", "prod\u202estaging", strings.Repeat("x", 5000)} {
		_, err := validateConnectionLabel(label)
		if err == nil {
			t.Fatalf("expected %q to be refused", label)
		}
		msg := err.Error()
		if strings.ContainsAny(msg, "\n\r\t\x00\u202e") {
			t.Fatalf("refusal must not echo raw control or formatting characters: %q", msg)
		}
		if len(msg) > 200 {
			t.Fatalf("refusal must stay bounded regardless of input size: %d bytes", len(msg))
		}
	}
}

// The mutator is the enforcement point every write surface goes through, so an
// invalid label must never reach a connection record.
func TestSetUpstreamLabelRefusesInvalidLabels(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111")
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "prod\nstaging"); err == nil {
		t.Fatal("SetUpstreamLabel must refuse a label containing a line break")
	}
	for _, info := range s.UpstreamList() {
		if info.Label != "" {
			t.Fatalf("a refused label must not be stored: %q", info.Label)
		}
	}
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "production"); err != nil {
		t.Fatalf("a valid label must be accepted: %v", err)
	}
	if err := s.SetUpstreamLabel("no-such-connection", "production"); err == nil {
		t.Fatal("labelling an unknown connection must fail")
	}
	// "" clears it — the reverse of every create.
	if err := s.SetUpstreamLabel("supabase-aaaa1111", ""); err != nil {
		t.Fatalf("clearing a label must be allowed: %v", err)
	}
	for _, info := range s.UpstreamList() {
		if info.Label != "" {
			t.Fatalf("label was not cleared: %q", info.Label)
		}
	}
}
