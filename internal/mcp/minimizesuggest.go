package mcp

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"microagency/internal/gateway"
)

// This is discovery-time auto-detection for field minimization: a static scan of an
// upstream's advertised tool SCHEMAS that proposes a minimization policy. It reads
// three things, all metadata, never any data:
//
//   - field NAMES (tokenized), to spot sensitive VALUE fields vs reference keys
//     (account_number ✓ but account_id ✗; billing_address ✓ but ip_address ✗);
//   - field and tool DESCRIPTIONS (the server's own prose — "brokerage account
//     number", "the user's email"), which say what a field IS far more reliably
//     than its name, in any phrasing, for any vendor; and
//   - an unbounded-output signal (a free query/sql/search input returns arbitrary
//     content the schema can't describe).
//
// TRUST AND VERIFY. A description is DATA from an untrusted external source (ASK
// tenet 24), so it drives a SUGGESTION the operator confirms — never enforcement on
// its own. The deterministic content detectors in the module are the backstop a
// lying server can't evade for formatted PII, and the operator is the final check.

// fieldTokens splits a field or tool name into a set of lowercased whole-word
// tokens, on separators and camelCase boundaries: "account_id" → {account, id},
// "ipAddress" → {ip, address}.
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

// fieldSignal maps a token rule to a suggested (type, action) — the sensitive VALUE
// (not a reference key) in a field NAME.
type fieldSignal struct {
	typ    string
	action string
	match  func(t map[string]bool) bool
}

// fieldSignals mirrors the redactor's typeForTokens (minimizers/redactor/main.go) —
// keep the two in sync.
var fieldSignals = []fieldSignal{
	{"secret", "redact", func(t map[string]bool) bool {
		return t["password"] || t["passwd"] || t["pwd"] || t["passphrase"] || t["secret"] ||
			t["apikey"] || (t["api"] && t["key"]) || (t["private"] && t["key"]) || (t["access"] && t["key"]) ||
			t["credential"] || t["credentials"] ||
			(hasAny(t, "bearer", "access", "refresh", "session", "auth", "id") && t["token"]) ||
			(t["auth"] && t["cookie"]) || (t["mfa"] && hasAny(t, "seed", "secret", "code"))
	}},
	{"health", "redact", func(t map[string]bool) bool {
		return t["mrn"] || (t["medical"] && t["record"]) || t["diagnosis"] || t["diagnoses"] || t["icd"] ||
			t["medication"] || t["medications"] || t["prescription"] || t["rx"] ||
			(t["mental"] && t["health"]) || t["cpt"] || t["npi"] ||
			(hasAny(t, "clinical", "provider", "medical", "patient", "encounter", "physician", "doctor") && t["notes"]) ||
			(t["insurance"] && hasAny(t, "member", "policy", "claim")) ||
			t["allergy"] || t["allergies"] || t["immunization"] || t["vaccine"] || t["prognosis"]
	}},
	{"ssn", "alert", func(t map[string]bool) bool { return t["ssn"] || (t["social"] && t["security"]) }},
	{"dob", "alert", func(t map[string]bool) bool { return t["dob"] || t["birthdate"] || (t["birth"] && t["date"]) }},
	{"account", "tokenize", func(t map[string]bool) bool {
		return (hasAny(t, "account", "acct") && hasAny(t, "number", "no", "num", "nbr")) || t["iban"] || (t["routing"] && t["number"])
	}},
	{"card", "tokenize", func(t map[string]bool) bool {
		return (t["card"] && hasAny(t, "number", "cvv", "cvc", "exp", "expiry", "expiration")) || (t["credit"] && t["card"]) || (t["debit"] && t["card"]) ||
			t["cvv"] || t["cvc"] || (t["security"] && t["code"])
	}},
	{"email", "redact", func(t map[string]bool) bool { return t["email"] }},
	{"phone", "redact", func(t map[string]bool) bool {
		return t["phone"] || t["telephone"] || t["msisdn"] || t["fax"] || (t["mobile"] && t["number"])
	}},
	{"address", "redact", func(t map[string]bool) bool {
		return (t["address"] && hasAny(t, "street", "postal", "mailing", "billing", "shipping", "home", "residential", "physical")) ||
			t["street"] || t["postal"] || t["postcode"] || t["zipcode"] || t["zip"]
	}},
	{"name", "redact", func(t map[string]bool) bool {
		return (hasAny(t, "full", "first", "last", "given", "family", "middle", "maiden", "customer", "patient", "contact", "person", "user", "legal", "display") && t["name"]) ||
			t["fullname"] || t["surname"]
	}},
}

// phraseSignal maps natural-language phrases to a suggested (type, action) — the
// "trust the server's prose" step. Phrases are specific enough that a plain match is
// meaningful (unlike a bare token): "social security" isn't "security", "billing
// address" isn't "ip address".
type phraseSignal struct {
	typ     string
	action  string
	phrases []string
}

var phraseSignals = []phraseSignal{
	{"secret", "redact", []string{"api key", "secret key", "access token", "bearer token", "refresh token", "session token", "private key", "client secret", "credential", "password", "passphrase", "auth cookie"}},
	{"health", "redact", []string{"medical record", "diagnosis", "diagnoses", "medication", "prescription", "mental health", "clinical notes", "health record", "protected health", "patient record", "medical history"}},
	{"ssn", "alert", []string{"social security", "social-security"}},
	{"dob", "alert", []string{"date of birth", "birth date", "birthdate", "born on"}},
	{"account", "tokenize", []string{"account number", "bank account", "brokerage account", "routing number", "iban"}},
	{"card", "tokenize", []string{"credit card", "debit card", "payment card", "card number", "security code", "card expiration"}},
	{"email", "redact", []string{"email address", "e-mail", "email"}},
	{"phone", "redact", []string{"phone number", "telephone", "mobile number", "cell phone"}},
	{"address", "redact", []string{"mailing address", "street address", "home address", "billing address", "shipping address", "postal address", "residential address", "physical address"}},
	{"name", "redact", []string{"full name", "first name", "last name", "person's name", "customer name", "legal name"}},
}

// classifyProse is the "trust the prose" classifier: a natural-language blob in, the
// sensitive types it names out. Phrase matching with a light negation guard for now.
// This is the SEAM a model classifier can replace — same signature — if phrases
// aren't enough.
var classifyProse = func(text string) map[string]string {
	low := strings.ToLower(text)
	out := map[string]string{}
	for _, sig := range phraseSignals {
		for _, p := range sig.phrases {
			if phraseHit(low, p) {
				out[sig.typ] = sig.action
				break
			}
		}
	}
	return out
}

// phraseHit reports whether phrase appears in low (already lowercased) not directly
// negated — so "does not return social security numbers" doesn't suggest ssn.
func phraseHit(low, phrase string) bool {
	from := 0
	for {
		i := strings.Index(low[from:], phrase)
		if i < 0 {
			return false
		}
		at := from + i
		start := at - 24
		if start < 0 {
			start = 0
		}
		if !hasNegation(low[start:at]) {
			return true
		}
		from = at + len(phrase)
	}
}

func hasNegation(window string) bool {
	for _, n := range []string{"no ", "not ", "n't", "without", "never", "exclude", "doesn", "don't"} {
		if strings.Contains(window, n) {
			return true
		}
	}
	return false
}

// unboundedInputTokens flag a tool that returns ARBITRARY content — a free query,
// SQL, or search — so its results can hold any PII regardless of the input schema.
var unboundedInputTokens = map[string]bool{"query": true, "sql": true, "lcql": true, "search": true, "q": true}

// unboundedOutputDefault is the starter policy suggested for arbitrary-output tools,
// limited to what the bundled content detector can actually enforce on free text.
var unboundedOutputDefault = map[string]string{"email": "redact", "ssn": "alert", "card": "tokenize", "secret": "redact"}

// suggestMinimizePolicy returns a suggested type→action policy from the tool
// schemas. Empty when nothing recognizable is found.
func suggestMinimizePolicy(tools []gateway.Tool) map[string]string {
	pol := map[string]string{}
	unbounded := false
	merge := func(m map[string]string) {
		for k, v := range m {
			if _, ok := pol[k]; !ok {
				pol[k] = v
			}
		}
	}
	scanName := func(name string) {
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
		scanName(tl.Name)                    // field NAME tokens (+ unbounded)
		merge(classifyProse(tl.Description)) // TRUST the tool's prose
		for _, f := range schemaProperties(tl.InputSchema) {
			scanName(f.name)
			merge(classifyProse(f.description)) // TRUST the field's prose
		}
	}
	if unbounded {
		merge(unboundedOutputDefault)
	}
	return pol
}

// schemaProp is one JSON-Schema property: its name and its self-description.
type schemaProp struct {
	name        string
	description string
}

// schemaProperties returns the top-level properties of a JSON Schema object, name +
// description, sorted by name.
func schemaProperties(raw json.RawMessage) []schemaProp {
	if len(raw) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	out := make([]schemaProp, 0, len(s.Properties))
	for k, v := range s.Properties {
		out = append(out, schemaProp{name: k, description: v.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
