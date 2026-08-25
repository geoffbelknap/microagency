package mcp

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A connection label is a short human-meaningful name for one connection —
// "production", "staging", "acme-eu" — that the owner (or, for a shared
// connection, the operator) attaches so an agent can tell two otherwise
// identical connections apart.
//
// A label is ATTACKER-INFLUENCEABLE TEXT THAT LANDS IN A MODEL'S CONTEXT. It is
// rendered as its own field in the tool view, never concatenated into a
// description, so it cannot terminate or extend surrounding prose; and it is
// held to an identifier's charset rather than a string's, so it cannot smuggle
// line breaks, invisible characters, or reordering marks into that context.
//
// The charset is deliberately the same shape as the one sanitizeName enforces on
// upstream names, with one difference that matters: sanitizeName REWRITES a name
// it cannot express, because a registry entry the operator did not author has to
// be admitted somehow. A label is authored by the person setting it, so a label
// that cannot be expressed is REFUSED and the author told why. Silently rewriting
// it would hand back a label that is not the one they read back later, which is
// exactly the confusion labels exist to remove.
const (
	// maxConnectionLabelRunes keeps a label a name, not a sentence. Long enough
	// for "production (eu-west)" and short enough that it cannot become prose.
	maxConnectionLabelRunes = 32
	// connectionLabelPunctuation is the entire punctuation set a label may use,
	// beyond letters, digits, and single interior spaces.
	connectionLabelPunctuation = "-_."
	// connectionLabelCharset describes the charset in the refusal message.
	connectionLabelCharset = "letters, digits, spaces, and the characters - _ ."
)

// validateConnectionLabel checks a caller-supplied label and returns it
// unchanged, or reports why it cannot be a label. The empty string is valid and
// means "no label" — that is how a label is cleared.
//
// The returned label is byte-for-byte what was supplied: this function never
// normalizes, trims, or substitutes. Every rule below is a refusal.
func validateConnectionLabel(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	// Reject malformed UTF-8 before anything inspects runes, so no later rule
	// silently reasons over U+FFFD replacements it did not receive.
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("label is not valid UTF-8")
	}
	// Length first, so a refusal for any later rule can safely quote the input:
	// nothing longer than the cap is ever echoed back into a log or a context.
	if n := utf8.RuneCountInString(raw); n > maxConnectionLabelRunes {
		return "", fmt.Errorf("label is %d characters; the limit is %d", n, maxConnectionLabelRunes)
	}
	for i, r := range raw {
		if err := checkLabelRune(r, i); err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(raw, " ") || strings.HasSuffix(raw, " ") {
		return "", fmt.Errorf("label %q has a leading or trailing space; labels are not trimmed for you, so the label you set is the label you read back", raw)
	}
	if strings.Contains(raw, "  ") {
		return "", fmt.Errorf("label %q contains repeated spaces; use single spaces between words", raw)
	}
	// "__" is the separator between a connection name and a tool name in every
	// namespaced tool the agent sees. A label carrying it could be read as a
	// qualified tool name, which is the one shape a disambiguating field must
	// never take.
	if strings.Contains(raw, nsSep) {
		return "", fmt.Errorf("label %q contains %q, which separates a connection from a tool name", raw, nsSep)
	}
	if !strings.ContainsFunc(raw, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	}) {
		return "", fmt.Errorf("label %q has no letter or digit; a label has to be readable as a name", raw)
	}
	return raw, nil
}

// checkLabelRune admits one rune of a label, naming the specific hazard when it
// refuses. Every branch below refuses; the ASCII allow-list at the end is what
// actually decides, and the branches before it exist only so the author is told
// which invisible thing they pasted rather than "invalid character".
func checkLabelRune(r rune, offset int) error {
	switch {
	case r == '\n' || r == '\r':
		return fmt.Errorf("label contains a line break at byte %d; a label is one line", offset)
	case r == '\t':
		return fmt.Errorf("label contains a tab at byte %d", offset)
	case r < 0x20 || r == 0x7f:
		return fmt.Errorf("label contains the control character U+%04X at byte %d", r, offset)
	case unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Join_Control, r) || unicode.Is(unicode.Cf, r):
		// Zero-width joiners and bidirectional overrides reorder or hide text
		// where it is rendered without changing the bytes stored. In a field the
		// model reads to choose between two connections, that is the whole attack.
		return fmt.Errorf("label contains the zero-width or bidirectional formatting character U+%04X at byte %d", r, offset)
	case r > unicode.MaxASCII:
		// Non-ASCII letters are refused rather than admitted-and-checked. Confusable
		// scripts make "prоduction" (Cyrillic о) and "production" different labels
		// that read identically, and a disambiguator that can be impersonated
		// disambiguates nothing. This is a real limitation for non-Latin names; it
		// is the conservative side of a security trade, not an oversight.
		return fmt.Errorf("label contains the non-ASCII character U+%04X at byte %d; labels are limited to %s", r, offset, connectionLabelCharset)
	case r == ' ':
		return nil
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return nil
	case strings.ContainsRune(connectionLabelPunctuation, r):
		return nil
	}
	return fmt.Errorf("label contains %q at byte %d; labels are limited to %s", r, offset, connectionLabelCharset)
}
