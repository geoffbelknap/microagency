package mcp

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"microagency/internal/gateway"
)

// This is discovery-time auto-detection for field minimization: a static scan of an
// upstream's advertised tool SCHEMAS (tool names and input property names — never
// any data) that proposes a minimization policy for the sensitive field types it
// recognizes. The proposal is surfaced to the operator to accept or edit; it is
// never applied on its own.
//
// Matching is token-based, not substring-based, and distinguishes a sensitive VALUE
// from a mere reference key. "account_number" is a value; "account_id" is a tenant
// key — the same substring, opposite sensitivity — so a raw contains() would fire on
// Cloudflare's account_id or a security tool's ip_address. Tokenizing on separators
// and camelCase and matching whole words fixes both.
//
// The input-schema scan can't see sensitivity that lives only in RESULTS, so it is
// paired with an unbounded-output heuristic: a tool whose input is a free query /
// SQL / search returns arbitrary content, so a starter output-scrub policy is
// suggested for it regardless of its input field names (catches Notion, Supabase).

// fieldTokens splits a field or tool name into a set of lowercased whole-word
// tokens, on separators and camelCase boundaries: "account_id" → {account, id},
// "ipAddress" → {ip, address}, "get_accounts" → {get, accounts}.
func fieldTokens(s string) map[string]bool {
	set := map[string]bool{}
	var cur strings.Builder
	rs := []rune(s)
	flush := func() {
		if cur.Len() > 0 {
			set[strings.ToLower(cur.String())] = true
			cur.Reset()
		}
	}
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.' || r == '/' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return set
}

func hasAny(t map[string]bool, words ...string) bool {
	for _, w := range words {
		if t[w] {
			return true
		}
	}
	return false
}

// fieldSignal maps a token rule to a suggested (type, action). match reports whether
// the sensitive VALUE (not a reference key) is present in a name's tokens.
type fieldSignal struct {
	typ    string
	action string
	match  func(t map[string]bool) bool
}

var fieldSignals = []fieldSignal{
	{"ssn", "alert", func(t map[string]bool) bool { return t["ssn"] || (t["social"] && t["security"]) }},
	{"dob", "alert", func(t map[string]bool) bool { return t["dob"] || t["birthdate"] || (t["birth"] && t["date"]) }},
	// account NUMBER, not account_id / account_name — the id is a reference key.
	{"account", "tokenize", func(t map[string]bool) bool {
		return (hasAny(t, "account", "acct") && hasAny(t, "number", "no", "num", "nbr")) || t["iban"] || (t["routing"] && t["number"])
	}},
	{"card", "tokenize", func(t map[string]bool) bool {
		return (t["card"] && t["number"]) || (t["credit"] && t["card"]) || (t["debit"] && t["card"])
	}},
	{"email", "redact", func(t map[string]bool) bool { return t["email"] }},
	{"phone", "redact", func(t map[string]bool) bool {
		return (t["phone"] && t["number"]) || t["telephone"] || (t["mobile"] && t["number"]) || t["msisdn"]
	}},
	// postal address, not ip / mac / email address.
	{"address", "redact", func(t map[string]bool) bool {
		return (t["address"] && hasAny(t, "street", "postal", "mailing", "billing", "shipping", "home")) ||
			t["street"] || t["postal"] || t["zipcode"] || (t["zip"] && t["code"])
	}},
}

// unboundedInputTokens flag a tool that returns ARBITRARY content — a free query,
// SQL, or search — so its results can hold any PII regardless of the input schema.
var unboundedInputTokens = map[string]bool{"query": true, "sql": true, "lcql": true, "search": true, "q": true}

// unboundedOutputDefault is the starter policy suggested for arbitrary-output tools,
// limited to what the bundled content detector can actually enforce on free text.
var unboundedOutputDefault = map[string]string{"email": "redact", "ssn": "alert", "card": "tokenize"}

// suggestMinimizePolicy returns a suggested type→action policy from the tool schemas.
// Empty when nothing recognizable is found.
func suggestMinimizePolicy(tools []gateway.Tool) map[string]string {
	pol := map[string]string{}
	unbounded := false
	scan := func(name string) {
		t := fieldTokens(name)
		for _, sig := range fieldSignals {
			if _, done := pol[sig.typ]; done {
				continue
			}
			if sig.match(t) {
				pol[sig.typ] = sig.action
			}
		}
		for w := range t {
			if unboundedInputTokens[w] {
				unbounded = true
			}
		}
	}
	for _, tl := range tools {
		scan(tl.Name)
		for _, k := range schemaPropertyNames(tl.InputSchema) {
			scan(k)
		}
	}
	if unbounded {
		for typ, act := range unboundedOutputDefault {
			if _, ok := pol[typ]; !ok {
				pol[typ] = act
			}
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
