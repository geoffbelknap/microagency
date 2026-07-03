// Command redactor is the default field-minimizer module: a wasip1 program that
// reads a minimize request JSON on stdin and writes a result JSON on stdout,
// applying a type→action mapping (the "policy") to sensitive values it detects.
//
// It is deliberately small — the MVP detector for checksummed/patterned types —
// and stands in as the reference implementation of the minimize module ABI. Real
// deployments drop in their own module against the same ABI; the sandbox denies it
// network and host access, so even an untrusted detector cannot leak what it sees.
//
// Built into a module at test/release time with: GOOS=wasip1 GOARCH=wasm go build.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type wireIn struct {
	Payload   string          `json:"payload"`
	Upstream  string          `json:"upstream,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Direction string          `json:"direction,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
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
}

// detector is one type's matcher. valid, when set, is an extra check on the raw
// match (e.g. Luhn) to cut false positives.
type detector struct {
	typ   string
	re    *regexp.Regexp
	valid func(string) bool
}

var detectors = []detector{
	{typ: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
	{typ: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{typ: "card", re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), valid: luhn},
}

type hit struct {
	start, end int
	typ, val   string
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
	policy := map[string]string{}
	if len(in.Policy) > 0 {
		_ = json.Unmarshal(in.Policy, &policy) // best-effort; unknown types default to pass
	}
	text := string(payload)

	// Collect matches across all detectors, then drop overlaps (earliest wins) so a
	// value is never transformed twice.
	var hits []hit
	for _, d := range detectors {
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
		return hits[i].end > hits[j].end // prefer the longer match at the same start
	})

	var (
		b       strings.Builder
		tokens  []token
		alerts  []alert
		lastEnd int
	)
	for _, h := range hits {
		if h.start < lastEnd {
			continue // overlaps a match we already handled
		}
		b.WriteString(text[lastEnd:h.start])
		switch action(policy, h.typ) {
		case "redact":
			b.WriteString(mask(h.typ, h.val))
		case "tokenize":
			ph := placeholder(h.typ, h.val)
			b.WriteString(ph)
			tokens = append(tokens, token{Placeholder: ph, Value: h.val, Type: h.typ})
		case "alert":
			b.WriteString(h.val) // value stays; the operator is notified
			alerts = append(alerts, alert{Type: h.typ, Severity: "high", Note: "detected " + h.typ + " in " + in.Upstream + " result"})
		default: // pass
			b.WriteString(h.val)
		}
		lastEnd = h.end
	}
	b.WriteString(text[lastEnd:])

	transformed := base64.StdEncoding.EncodeToString([]byte(b.String()))
	out := wireOut{Transformed: &transformed, Tokens: tokens, Alerts: alerts}
	enc, err := json.Marshal(out)
	if err != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(enc)
}

func action(policy map[string]string, typ string) string {
	if a, ok := policy[typ]; ok {
		return a
	}
	return "pass"
}

// placeholder is a deterministic, unguessable-enough handle for a value: same
// value → same token (so repeats correlate within a payload), no host entropy
// needed (wasip1-friendly). The [[ ]] delimiters are JSON-safe — unlike < >, Go's
// JSON encoder does not escape them — so the placeholder survives the model
// echoing it back verbatim, which is what makes the resolve-on-return path work.
func placeholder(typ, val string) string {
	sum := sha256.Sum256([]byte(typ + ":" + val))
	return "[[mtok_" + hex.EncodeToString(sum[:])[:10] + "]]"
}

// mask redacts a value while keeping a small tail where it aids the operator.
func mask(typ, val string) string {
	switch typ {
	case "email":
		return "[redacted:email]"
	case "card", "ssn":
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

// luhn reports whether the digits of s pass the Luhn checksum — the standard
// filter that keeps a 16-digit order id from being mistaken for a card number.
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
