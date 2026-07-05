// Command redactor is the default field-minimizer module: a wasip1 program that
// reads a minimize request JSON on stdin and writes a result JSON on stdout,
// applying a type→action mapping (the "policy") to sensitive values it finds.
//
// It detects two ways, and both run:
//
//   - by CONTENT — email / SSN / credit-card values, recognized by their format
//     (regex + Luhn) wherever they appear, even in free text; and
//   - by FIELD NAME — the value of any field whose NAME says what it is
//     ("account_number", "billing_address"), even when the value has no format a
//     content detector could catch (an account number is just an opaque string).
//     This is the "trust the declaration, apply the rule" half: the schema/field
//     tells us the value is sensitive; content patterns remain the backstop for
//     fields the server DIDN'T declare.
//
// The sandbox denies it network and host access, so even an untrusted detector
// cannot leak what it sees. Built with: GOOS=wasip1 GOARCH=wasm go build.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type wireIn struct {
	Payload   string          `json:"payload"`
	Upstream  string          `json:"upstream,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Direction string          `json:"direction,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	// Salt is a per-scan secret the host supplies (never shown to the model) so
	// tokenized placeholders are a keyed hash of the value, not an unsalted digest an
	// authenticated agent could brute-force for low-entropy values (SSNs, known
	// cards). It stays host-side; only the placeholder crosses into model context.
	Salt string `json:"salt,omitempty"`
}

type token struct {
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
	Type        string `json:"type,omitempty"`
	Path        string `json:"path,omitempty"`
}

type alert struct {
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Path     string `json:"path,omitempty"`
	Note     string `json:"note,omitempty"`
}

type wireOut struct {
	Transformed *string `json:"transformed"`
	Tokens      []token `json:"tokens,omitempty"`
	Alerts      []alert `json:"alerts,omitempty"`
	// Protected is the count of field values actually hidden this scan (redacted or
	// tokenized). It's how the gateway shows minimization impact — the work that
	// leaves no token/alert behind and would otherwise be invisible.
	Protected int `json:"protected,omitempty"`
}

// acc accumulates the tokens/alerts produced during a scan, plus the request
// context the module carries.
type acc struct {
	policy    map[string]string
	upstream  string
	salt      string // per-scan secret keying placeholder derivation (see wireIn.Salt)
	tokens    []token
	alerts    []alert
	protected int // values redacted or tokenized (hidden from the model)
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	var in wireIn
	if err := json.Unmarshal(raw, &in); err != nil {
		os.Exit(1)
	}
	payload, err := base64.StdEncoding.DecodeString(in.Payload)
	if err != nil {
		os.Exit(1)
	}
	a := &acc{policy: map[string]string{}, upstream: in.Upstream, salt: in.Salt}
	if len(in.Policy) > 0 {
		_ = json.Unmarshal(in.Policy, &a.policy) // unknown types default to pass
	}

	var out string
	// Structured path: if the payload is JSON, walk it so field NAMES are visible;
	// otherwise treat it as free text and rely on content patterns alone. Decode with
	// UseNumber so numeric values keep their exact literal — a card or account number
	// stored as a JSON number must be enforceable by field name, not silently skipped
	// or mangled through float64.
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&v); err == nil && decodedFully(dec) {
		v = a.walk(v, "")
		b, _ := json.Marshal(v)
		out = string(b)
	} else {
		out = a.scanText(string(payload), "")
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(out)) // ABI: transformed is base64
	enc := wireOut{Transformed: &b64, Tokens: a.tokens, Alerts: a.alerts, Protected: a.protected}
	b, err := json.Marshal(enc)
	if err != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(b)
}

// decodedFully reports whether the decoder consumed the whole payload as a single
// JSON value (only trailing whitespace left) — matching json.Unmarshal's rejection
// of trailing garbage, so a non-JSON payload still falls through to content scanning.
func decodedFully(dec *json.Decoder) bool {
	_, err := dec.Token()
	return err == io.EOF
}

// walk recurses the decoded JSON, replacing sensitive values in place. key is the
// field name the current value sits under (the field-NAME signal).
//
// Field-name and content detection BOTH run: a field name that declares a type is
// acted on, and — unless the whole value was hidden (redact/tokenize) — the value is
// still content-scanned so a lying field name (e.g. an alert-only "ssn" field
// carrying an email or card) can't smuggle other PII past the boundary.
func (a *acc) walk(v interface{}, key string) interface{} {
	switch val := v.(type) {
	case string:
		if typ := fieldType(key); typ != "" {
			switch a.policy[typ] {
			case "redact", "tokenize":
				// The whole value is replaced, so any embedded PII goes with it.
				return a.apply(typ, a.policy[typ], val)
			case "alert":
				// Record the field-declared signal, but the value stays model-visible —
				// so still content-scan it for OTHER embedded PII (skip re-detecting typ).
				a.apply(typ, "alert", val)
				return a.scanEmbeddedOrText(val, key, typ)
			}
			// "pass"/unknown: fall through to a full content scan (the backstop still runs).
		}
		return a.scanEmbeddedOrText(val, key, "")
	case json.Number:
		// A sensitive value stored as a JSON number (a card or account number) is
		// enforced by its field name, and content-scanned as a backstop; if nothing
		// fires it stays a number.
		skip := ""
		if typ := fieldType(key); typ != "" {
			switch a.policy[typ] {
			case "redact", "tokenize":
				return a.apply(typ, a.policy[typ], val.String())
			case "alert":
				a.apply(typ, "alert", val.String())
				skip = typ
			}
		}
		if scanned := a.scanText(val.String(), skip); scanned != val.String() {
			return scanned
		}
		return val
	case map[string]interface{}:
		for k, vv := range val {
			val[k] = a.walk(vv, k)
		}
		return val
	case []interface{}:
		for i, vv := range val {
			val[i] = a.walk(vv, key) // elements inherit the array's field name
		}
		return val
	default:
		return v
	}
}

// scanEmbeddedOrText content-scans a free-text string value. It first splices out any
// embedded JSON — a double-encoded payload, or rows an MCP wrapped in prose +
// <untrusted-data> tags (Supabase, Cloudflare, …) — and walks it so nested field
// names are enforced, re-splicing it into the surrounding text (itself content-
// scanned). skipType, when set, is a type already acted on by the field name, so the
// content pass doesn't flag it twice.
func (a *acc) scanEmbeddedOrText(val, key, skipType string) string {
	if s, e, ok := embeddedJSON(val); ok {
		var inner interface{}
		d := json.NewDecoder(bytes.NewReader([]byte(val[s:e])))
		d.UseNumber()
		if d.Decode(&inner) == nil {
			inner = a.walk(inner, key)
			if b, err := json.Marshal(inner); err == nil {
				return a.scanText(val[:s], skipType) + string(b) + a.scanText(val[e:], skipType)
			}
		}
	}
	return a.scanText(val, skipType)
}

// embeddedJSON returns the [start,end) span of the first balanced JSON object or
// array in s, tracking string literals so braces inside strings don't miscount.
// This lets the structured walk reach rows an MCP wrapped in prose ("Below is the
// result…<untrusted-data>[…]</untrusted-data>"). ok=false when none is found.
func embeddedJSON(s string) (int, int, bool) {
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return 0, 0, false
	}
	open := s[start]
	closeCh := byte('}')
	if open == '[' {
		closeCh = ']'
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return start, i + 1, true
			}
		}
	}
	return 0, 0, false
}

// apply performs one action on a whole value (the field-name path), recording the
// token/alert.
func (a *acc) apply(typ, action, value string) string {
	switch action {
	case "redact":
		a.protected++
		return mask(typ, value)
	case "tokenize":
		a.protected++
		ph := a.placeholder(typ, value)
		a.tokens = append(a.tokens, token{Placeholder: ph, Value: value, Type: typ})
		return ph
	case "alert":
		a.alerts = append(a.alerts, alert{Type: typ, Severity: "high", Note: "field-declared " + typ + " in " + a.upstream})
		return value
	default:
		return value
	}
}

// --- content detection (by value format) ---

type detector struct {
	typ   string
	re    *regexp.Regexp
	valid func(string) bool
}

var detectors = []detector{
	{typ: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
	{typ: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{typ: "card", re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), valid: luhn},
	// Secrets by VALUE — high-precision shapes only, so we don't flag every hash or
	// base64 blob: PEM private keys, JWTs, and well-known key prefixes. The PEM match
	// spans the WHOLE block (header, base64 body, footer) — matching only the header
	// would leave the key material in the output.
	{typ: "secret", re: regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)},
	{typ: "secret", re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)}, // JWT
	{typ: "secret", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},                                              // AWS access key id
	{typ: "secret", re: regexp.MustCompile(`\b(?:sk|rk|pk)_[A-Za-z0-9]{16,}`)},                               // stripe/openai-style
	{typ: "secret", re: regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}`)},                                        // github PAT
	{typ: "secret", re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},                                  // slack
}

type hit struct {
	start, end int
	typ, val   string
}

// scanText applies the content detectors to a string, honoring the policy, and
// returns the transformed string. skipType, when set, is a type already acted on by
// the caller (the field-name path) so it isn't detected — and re-alerted — twice.
func (a *acc) scanText(text, skipType string) string {
	var hits []hit
	for _, d := range detectors {
		if skipType != "" && d.typ == skipType {
			continue
		}
		for _, idx := range d.re.FindAllStringIndex(text, -1) {
			val := text[idx[0]:idx[1]]
			if d.valid != nil && !d.valid(val) {
				continue
			}
			hits = append(hits, hit{start: idx[0], end: idx[1], typ: d.typ, val: val})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})

	var b strings.Builder
	lastEnd := 0
	for _, h := range hits {
		if h.start < lastEnd {
			continue
		}
		b.WriteString(text[lastEnd:h.start])
		b.WriteString(a.apply(h.typ, action(a.policy, h.typ), h.val))
		lastEnd = h.end
	}
	b.WriteString(text[lastEnd:])
	return b.String()
}

func action(policy map[string]string, typ string) string {
	if act, ok := policy[typ]; ok {
		return act
	}
	return "pass"
}

// --- field NAME → sensitive type (mirrors internal/mcp/minimizesuggest.go) ---

// fieldType returns the sensitive type a field NAME declares, distinguishing a
// sensitive VALUE from a reference key (account_number ✓, account_id ✗) and a
// postal address from a network one (billing_address ✓, ip_address ✗). "" if none.
func fieldType(name string) string {
	if name == "" {
		return ""
	}
	return typeForTokens(fieldTokens(name))
}

// typeForTokens is the shared field-name classification (kept identical to the
// suggester's rules in internal/mcp/minimizesuggest.go).
func typeForTokens(t map[string]bool) string {
	switch {
	// Credentials/secrets — a key, token, or password, distinguished from a DB key
	// (primary_key / foreign_key / public_key never match).
	case t["password"] || t["passwd"] || t["pwd"] || t["passphrase"] || t["secret"] ||
		t["apikey"] || (t["api"] && t["key"]) || (t["private"] && t["key"]) || (t["access"] && t["key"]) ||
		t["credential"] || t["credentials"] ||
		(has(t, "bearer", "access", "refresh", "session", "auth", "id") && t["token"]) ||
		(t["auth"] && t["cookie"]) || (t["mfa"] && has(t, "seed", "secret", "code")):
		return "secret"
	// Protected health information (PHI) — clinical fields with no content format,
	// so the field name is the only signal.
	case t["mrn"] || (t["medical"] && t["record"]) || t["diagnosis"] || t["diagnoses"] || t["icd"] ||
		t["medication"] || t["medications"] || t["prescription"] || t["rx"] ||
		(t["mental"] && t["health"]) || t["cpt"] || t["npi"] ||
		(has(t, "clinical", "provider", "medical", "patient", "encounter", "physician", "doctor") && t["notes"]) ||
		(t["insurance"] && has(t, "member", "policy", "claim")) ||
		t["allergy"] || t["allergies"] || t["immunization"] || t["vaccine"] || t["prognosis"]:
		return "health"
	case t["ssn"] || (t["social"] && t["security"]):
		return "ssn"
	case t["dob"] || t["birthdate"] || (t["birth"] && t["date"]):
		return "dob"
	case (has(t, "account", "acct") && has(t, "number", "no", "num", "nbr")) || t["iban"] || (t["routing"] && t["number"]):
		return "account"
	case (t["card"] && has(t, "number", "cvv", "cvc", "exp", "expiry", "expiration")) || (t["credit"] && t["card"]) || (t["debit"] && t["card"]) ||
		t["cvv"] || t["cvc"] || (t["security"] && t["code"]):
		return "card"
	case t["email"]:
		return "email"
	case t["phone"] || t["telephone"] || t["msisdn"] || t["fax"] || (t["mobile"] && t["number"]):
		return "phone"
	case (t["address"] && has(t, "street", "postal", "mailing", "billing", "shipping", "home", "residential", "physical")) ||
		t["street"] || t["postal"] || t["postcode"] || t["zipcode"] || t["zip"]:
		return "address"
	// Personal name — paired with a person qualifier so table_name / file_name /
	// tool_name never match.
	case (has(t, "full", "first", "last", "given", "family", "middle", "maiden", "customer", "patient", "contact", "person", "user", "legal", "display") && t["name"]) ||
		t["fullname"] || t["surname"]:
		return "name"
	}
	return ""
}

func has(t map[string]bool, words ...string) bool {
	for _, w := range words {
		if t[w] {
			return true
		}
	}
	return false
}

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

// --- transforms ---

// placeholder derives the opaque token that stands in for a value. It is a KEYED
// hash (HMAC-SHA256 under the host-supplied per-scan salt), so an agent that sees a
// placeholder cannot brute-force a low-entropy value (an SSN, a known test card) by
// hashing candidates — it doesn't hold the salt. Deterministic within a scan, so
// repeated occurrences of one value collapse to one placeholder/token.
func (a *acc) placeholder(typ, val string) string {
	mac := hmac.New(sha256.New, []byte(a.salt))
	mac.Write([]byte(typ + ":" + val))
	return "[[mtok_" + hex.EncodeToString(mac.Sum(nil))[:16] + "]]"
}

func mask(typ, val string) string {
	switch typ {
	case "email":
		return "[redacted:email]"
	case "card", "ssn", "account", "phone":
		digits := onlyDigits(val)
		if len(digits) >= 4 {
			return "[redacted:" + typ + " ••" + digits[len(digits)-4:] + "]"
		}
	}
	return "[redacted:" + typ + "]"
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(s string) bool {
	digits := onlyDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
