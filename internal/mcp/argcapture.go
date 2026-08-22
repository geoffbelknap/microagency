package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Argument capture for proxy audit records.
//
// A single-principal gateway records full tool arguments: the operator reading
// the log is the same person whose calls produced it. On a multi-principal
// gateway the log concentrates every caller's raw arguments into one
// operator-readable file, so non-governed proxy records capture the argument
// STRUCTURE (keys and value types), byte counts, and a SHA-256 digest of the
// canonicalized arguments instead of the values. The digest keeps records
// provable: anyone holding a claimed argument set can canonicalize it, hash it,
// and check the result against the signed chain. A connection can be opted back
// up to full capture per connection (SetUpstreamAuditFullArgs); doctor and the
// upstream list disclose that posture.

// Capture markers recorded in runRecord.ArgsCapture. The empty value means the
// record predates capture modes or was written by a single-principal gateway
// (full arguments, or a governed record's deliberate blank).
const (
	argsCaptureStructure = "structure" // shape + digest, no values
	argsCaptureFull      = "full"      // full values via explicit per-connection opt-up
)

// argsSHA256 returns the lowercase hex SHA-256 of the canonicalized arguments.
// Arguments that don't parse as JSON are hashed as their exact raw bytes.
func argsSHA256(raw json.RawMessage) string {
	sum := sha256.Sum256(canonicalJSON(raw))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON re-serializes one JSON value deterministically: object keys
// sorted, no insignificant whitespace, number literals preserved as sent, and
// minimal string escaping (no HTML escaping). Input that is not exactly one
// JSON value is returned unchanged, so the digest is still defined over the
// exact bytes.
func canonicalJSON(raw json.RawMessage) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	if dec.More() { // trailing data — not one canonical value
		return raw
	}
	var buf bytes.Buffer
	writeCanonical(&buf, v)
	return buf.Bytes()
}

func writeCanonical(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			writeCanonical(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, e)
		}
		buf.WriteByte(']')
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		buf.WriteString(string(t))
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	default: // nil
		buf.WriteString("null")
	}
}

// writeCanonicalString appends s as a JSON string without HTML escaping, so the
// canonical form matches what standard JSON tools produce for &, <, and >.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)           // a string encode cannot fail
	buf.Truncate(buf.Len() - 1) // Encode appends a newline
}

// maxShapeDepth bounds shape recursion so a deeply nested argument document
// can't produce an unbounded audit record. Below the cap, containers collapse
// to a count descriptor.
const maxShapeDepth = 8

// argShape returns a values-free structural mirror of JSON tool arguments:
// object keys and nesting preserved, every value replaced by its type and — for
// strings — its byte count. Object keys are emitted only when they look like a
// fixed field schema (fieldNameKeys); an object keyed by data (emails, ids)
// collapses to a key count so the shape can't leak values through keys. Arrays
// carry the first element's shape plus a count. Non-JSON arguments report size
// only; empty arguments return nil.
func argShape(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return mustShapeJSON(fmt.Sprintf("opaque(%dB)", len(raw)))
	}
	return mustShapeJSON(shapeOf(v, 0))
}

func shapeOf(v any, depth int) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if depth >= maxShapeDepth || !fieldNameKeys(keys) {
			return fmt.Sprintf("object(%d keys)", len(t))
		}
		out := make(map[string]any, len(keys))
		for _, k := range keys {
			out[k] = shapeOf(t[k], depth+1)
		}
		return out
	case []any:
		if len(t) == 0 {
			return []any{}
		}
		if depth >= maxShapeDepth {
			return fmt.Sprintf("array(%d)", len(t))
		}
		first := shapeOf(t[0], depth+1)
		if len(t) == 1 {
			return []any{first}
		}
		return []any{first, fmt.Sprintf("+%d more", len(t)-1)}
	case string:
		return fmt.Sprintf("string(%dB)", len(t))
	case json.Number:
		return "number"
	case bool:
		return "bool"
	default:
		return "null"
	}
}

func mustShapeJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil { // shapes are built from strings/maps/slices only
		return nil
	}
	return b
}
