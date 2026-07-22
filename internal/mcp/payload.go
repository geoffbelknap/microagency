package mcp

// This file holds the upstream-result NORMALIZATION helpers — pure functions that
// turn an upstream MCP tool result into the bytes/shape the gateway parks, inlines,
// or previews. They were split out of gateway.go (which owns registry CRUD and the
// invocation gate) so this subtle, comment-heavy shaping logic lives on its own and
// is easy to test and evolve. No behavior change from the move.

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// resultPayload extracts the DATA an MCP tool result carries — the bare rows, so a
// reduce queries the array directly. It prefers structuredContent (already parsed),
// else pulls the JSON out of the text content (many data tools wrap rows in a
// human-readable preamble and XPIA "untrusted-data" tags). Falls back to the whole
// result. This is what the budget gate measures and what reduce queries.
// truncationMarkers are the machine-generated "I cut this off" strings some
// upstreams append when a response exceeds their output cap. Matched
// case-insensitively; the dash/bracket wrapping keeps them specific enough not to
// fire on prose that merely uses the word "truncated".
var truncationMarkers = []string{"--- truncated", "truncated ---", "[truncated", "response truncated", "output truncated"}

// offloadURL returns the URL an upstream substituted for a large payload — an
// off-platform "your data is at this link" pointer — or "" if the payload isn't
// one. payload is the EXTRACTED result data (resultPayload output), since upstreams
// wrap results in an MCP content text block and the offload fields live inside it.
// It matches only unambiguous offload field names (not a generic "url"/"link" a
// tool might legitimately return as data), so a match means "the real payload lives
// out-of-band," which the proxy then rehydrates rather than leak.
func offloadURL(payload string) string {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return ""
	}
	for _, k := range []string{"resource_link", "download_url", "artifact_url", "signed_url"} {
		if v, ok := m[k].(string); ok && (strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")) {
			return v
		}
	}
	return ""
}

// rehydratedResult wraps a small rehydrated offload payload as a tool result (the
// large case returns a ref instead). Parses JSON when possible so the agent gets
// structure, not a blob.
func rehydratedResult(payload string) map[string]any {
	var v any
	if json.Unmarshal([]byte(payload), &v) == nil {
		return toolResult(map[string]any{"rehydrated_from_offload": true, "data": v})
	}
	return toolResult(map[string]any{"rehydrated_from_offload": true, "data": payload})
}

// hostOf returns the host[:port] of a URL, for the egress record. "" on parse error.
func hostFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return ""
}

func resultIsError(result map[string]any) bool {
	e, _ := result["isError"].(bool)
	return e
}

// truncatedNotice reports whether payload is a truncation/notice rather than the
// clean data the ref/reduce path assumes, returning the message to surface. It fires
// on (a) a known truncation marker in the tail, or (b) a payload that CLAIMS to be
// JSON (starts with { or [) but does not parse — a response cut mid-structure.
//
// Well-formed JSON is exempt first: a complete JSON result is data even when a
// string value inside it ends with a phrase like "...output truncated" (a
// log-search hit, say), so the marker there is content, not an appended cut notice
// — flagging it would DISCARD a valid result. A genuine truncation cut mid-structure
// won't parse (or has the marker appended after the close, which also won't parse),
// so it still falls to the branches below. A non-JSON prose document with no marker
// is likewise never flagged, so real documents ref normally.
func truncatedNotice(payload string) (string, bool) {
	if tr := strings.TrimSpace(payload); len(tr) > 0 && (tr[0] == '{' || tr[0] == '[') && json.Valid([]byte(tr)) {
		return "", false
	}
	low := strings.ToLower(payload)
	for _, m := range truncationMarkers {
		// A real truncation marker is APPENDED at the END of the payload. A document
		// that merely MENTIONS the marker (e.g. a backlog page documenting the
		// Cloudflare incident) has it mid-content — so only treat it as truncation
		// when it sits in the tail. Use the last occurrence + a tight tail window.
		// (This runs before the generic invalid-JSON message so the upstream's own
		// guidance is surfaced even for JSON cut mid-structure with a marker.)
		if i := strings.LastIndex(low, m); i >= 0 && len(payload)-i <= 512 {
			return truncationTail(payload, i), true
		}
	}
	if tr := strings.TrimSpace(payload); len(tr) > 0 && (tr[0] == '{' || tr[0] == '[') {
		return "the upstream returned malformed or truncated JSON (it did not parse)", true
	}
	return "", false
}

// truncationTail returns the marker's line plus a bounded amount of following text
// (the upstream's guidance), so a huge truncated blob doesn't ride inline behind the
// small notice.
func truncationTail(payload string, at int) string {
	start := strings.LastIndexByte(payload[:at], '\n') + 1
	tail := strings.TrimSpace(payload[start:])
	if len(tail) > 500 {
		tail = tail[:500]
	}
	return tail
}

// truncatedResult surfaces an upstream truncation notice inline (small, actionable)
// instead of parking a broken payload behind a reference.
func truncatedResult(msg string) map[string]any {
	return toolResult(map[string]any{
		"truncated":       true,
		"upstream_notice": msg,
		"note":            "The upstream truncated or malformed this result, so microagency did not park it as a reference (reduce would fail to parse it). Request less data — narrow the query or add a limit — and retry.",
	})
}

func resultPayload(result map[string]any) string {
	if sc, ok := result["structuredContent"]; ok {
		if b, err := json.Marshal(sc); err == nil && len(b) > 2 { // not null/"" /{}
			return string(b)
		}
	}
	if content, ok := result["content"].([]any); ok {
		var sb strings.Builder
		for _, c := range content {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := m["type"].(string); t == "text" {
				if txt, _ := m["text"].(string); txt != "" {
					sb.WriteString(txt)
				}
			}
		}
		if sb.Len() > 0 {
			return unwrapData(sb.String())
		}
	}
	b, _ := json.Marshal(result)
	return string(b)
}

func unwrapData(s string) string {
	out := extractJSON(s)
	if len(s)-len(out) > maxUnwrapFraming {
		return s // extraction discarded more than framing — that text WAS the payload
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &obj) != nil {
		return out // not an object (already a bare array, or plain text)
	}
	best := ""
	for _, v := range obj {
		var str string
		if json.Unmarshal(v, &str) != nil {
			continue // field value isn't a string
		}
		inner := extractJSON(str)
		if inner == str || !json.Valid([]byte(inner)) {
			continue // string holds no embedded JSON
		}
		if len(str)-len(inner) > maxUnwrapFraming {
			continue // the field's text is content, not framing around the JSON
		}
		if strings.HasPrefix(inner, "[") {
			return inner // the rows array — done
		}
		if best == "" {
			best = inner
		}
	}
	if best != "" {
		return best
	}
	return out
}

// extractJSON returns the outermost balanced JSON array/object embedded in s
// (skipping any preamble/wrapper), or s unchanged if none parses. String-aware so
// brackets inside string values don't throw off the balance.
func extractJSON(s string) string {
	start := strings.IndexAny(s, "[{")
	if start < 0 {
		return s
	}
	open := s[start]
	close := byte(']')
	if open == '{' {
		close = '}'
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
		case close:
			if depth--; depth == 0 {
				if cand := s[start : i+1]; json.Valid([]byte(cand)) {
					return cand
				}
				return s
			}
		}
	}
	return s
}

// structuralPreview returns a STRUCTURE-ONLY glimpse of a reffed payload — its shape,
// field names, and counts — so the agent can often decide its next step without a
// reduce round-trip. It never includes VALUES: the whole point of a ref is to keep
// the raw (often sensitive) data OUT of context, so leaking even a sample row would
// defeat minimization. A JSON array reports its count + the first item's field names
// (the row schema); an object reports its keys; anything else reports size only.
func structuralPreview(payload string) map[string]any {
	tr := strings.TrimSpace(payload)
	if len(tr) == 0 {
		return nil
	}
	switch tr[0] {
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal([]byte(tr), &arr) == nil {
			p := map[string]any{"kind": "array", "count": len(arr)}
			if len(arr) > 0 {
				if ks, _, ok := objectShape(arr[0]); ok && fieldNameKeys(ks) {
					p["item_keys"] = capKeys(ks)
				}
			}
			return p
		}
	case '{':
		if ks, total, ok := objectShape(json.RawMessage(tr)); ok {
			if fieldNameKeys(ks) {
				return map[string]any{"kind": "object", "keys": capKeys(ks)}
			}
			// The keys look like DATA (emails, ids, …), not a fixed field schema —
			// e.g. {"alice@example.com": {...}} — so emitting them would leak values
			// the ref model keeps out of context. Report shape (count) only.
			return map[string]any{"kind": "object", "key_count": total}
		}
	}
	return map[string]any{"kind": "text", "chars": len(payload), "lines": strings.Count(payload, "\n") + 1}
}

// objectShape returns a JSON object's sorted top-level keys and their count, or
// ok=false if raw isn't an object.
func objectShape(raw json.RawMessage) (keys []string, total int, ok bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, 0, false
	}
	keys = make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, len(m), true
}

// fieldNameKeys reports whether keys look like a fixed FIELD SCHEMA (safe to show
// in a values-free preview) rather than data used as map keys. A record schema is
// a small set of identifier-like names; an object keyed by data (emails, UUIDs)
// has many keys and/or keys with value-like characters (@, spaces, …), which would
// leak content. Heuristic — conservative: any doubt falls back to count-only.
func fieldNameKeys(keys []string) bool {
	if len(keys) == 0 || len(keys) > 25 { // records rarely exceed ~25 fields; data-maps do
		return false
	}
	for _, k := range keys {
		if !isFieldName(k) {
			return false
		}
	}
	return true
}

func isFieldName(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '$') {
			return false
		}
	}
	return true
}

func capKeys(ks []string) []string {
	if len(ks) > 50 {
		return ks[:50]
	}
	return ks
}
