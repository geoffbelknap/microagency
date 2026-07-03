package mcp

import (
	"encoding/json"
	"sort"
	"strings"

	"microagency/internal/gateway"
)

// This is discovery-time auto-detection for field minimization: a static scan of an
// upstream's advertised tool SCHEMAS (tool names and input property names — never
// any data) that proposes a minimization policy for the sensitive field types it
// recognizes. The proposal is surfaced to the operator to accept or edit; it is
// never applied on its own (the operator makes the call — an adjustable suggestion,
// not a silent default).

// sensitiveHint maps field-name signals to a suggested (type, action). Action
// defaults by sensitivity: financial identifiers → tokenize (keep utility for the
// model while holding the raw value), contact PII → redact, high-sensitivity
// identifiers → alert (leave in place but flag the detection).
type sensitiveHint struct {
	needles []string
	typ     string
	action  string
}

var sensitiveHints = []sensitiveHint{
	{[]string{"ssn", "social_security", "socialsecurity"}, "ssn", "alert"},
	{[]string{"dob", "date_of_birth", "birthdate", "birth_date"}, "dob", "alert"},
	{[]string{"account", "acct", "iban", "routing"}, "account", "tokenize"},
	{[]string{"card", "pan", "creditcard", "credit_card", "cardnumber"}, "card", "tokenize"},
	{[]string{"email"}, "email", "redact"},
	{[]string{"phone", "mobile"}, "phone", "redact"},
	{[]string{"address", "street", "postal", "zipcode", "zip_code"}, "address", "redact"},
}

// suggestMinimizePolicy scans the tool schemas for sensitive-field signals and
// returns a suggested type→action policy. It reads tool names and input property
// names only — no descriptions (prose is noisy) and never any data. Empty when
// nothing recognizable is found.
func suggestMinimizePolicy(tools []gateway.Tool) map[string]string {
	pol := map[string]string{}
	consider := func(s string) {
		low := strings.ToLower(s)
		for _, h := range sensitiveHints {
			if _, done := pol[h.typ]; done {
				continue
			}
			for _, n := range h.needles {
				if strings.Contains(low, n) {
					pol[h.typ] = h.action
					break
				}
			}
		}
	}
	for _, t := range tools {
		consider(t.Name)
		for _, k := range schemaPropertyNames(t.InputSchema) {
			consider(k)
		}
	}
	return pol
}

// schemaPropertyNames returns the top-level property names of a JSON Schema object.
func schemaPropertyNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	out := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
