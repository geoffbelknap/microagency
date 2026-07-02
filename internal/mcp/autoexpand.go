package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"

	"microagency/internal/gateway"
)

// This file implements schema auto-expansion around call_tool. find_tools summarizes
// verbose tools (Notion ships 5–7KB markdown descriptions), so an agent may pick a
// tool having seen only a param-name digest and then call it under-informed. Two
// tiers recover the full spec — which microagency never discarded; it lives in the
// upstream record and is only projected away in the find_tools OUTPUT:
//
//   Tier 1 (writes, pre-egress): validate the arguments against the retained schema
//     BEFORE dialing. A structural gap on a write fails CLOSED — no malformed
//     mutation reaches the upstream — and the full description + inputSchema is
//     returned so the retry is informed.
//   Tier 2 (all tools, on error): if the upstream rejects the call, append the full
//     description + inputSchema to the error, so a retry after a semantic failure
//     (e.g. a bad DSL string the JSON schema can't express) is informed.
//
// Reads skip Tier 1: they have no side effect, so letting the upstream judge and
// attaching the spec on error (Tier 2) is enough — and it avoids ever hard-blocking
// a read on a false-positive.

// findTool returns the upstream's advertised tool by its un-namespaced name.
func findTool(tools []gateway.Tool, name string) (gateway.Tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return gateway.Tool{}, false
}

var readVerbs = map[string]bool{
	"search": true, "query": true, "fetch": true, "get": true, "list": true,
	"read": true, "describe": true, "export": true, "find": true, "lookup": true,
	"count": true, "resolve": true, "check": true, "status": true, "view": true,
}

var writeVerbs = map[string]bool{
	"create": true, "update": true, "delete": true, "remove": true, "add": true,
	"set": true, "put": true, "patch": true, "move": true, "duplicate": true,
	"write": true, "insert": true, "upsert": true, "archive": true, "restore": true,
	"send": true, "post": true, "modify": true, "rename": true, "copy": true,
}

// isWriteTool decides whether a tool mutates state, so the pre-egress guard knows
// whether to fail closed. The MCP readOnlyHint is authoritative when present; absent
// it falls back to the action verb in the name, and — critically — defaults to WRITE
// when nothing is conclusive, so an unclassifiable tool is guarded rather than
// silently allowed to receive a malformed mutation. A mutation verb wins over a read
// verb (e.g. "create-view" contains both "create" and "view").
func isWriteTool(t gateway.Tool) bool {
	if t.Annotations != nil && t.Annotations.ReadOnlyHint != nil {
		return !*t.Annotations.ReadOnlyHint
	}
	hasWrite, hasRead := false, false
	for _, tok := range tokenize(t.Name) {
		if writeVerbs[tok] {
			hasWrite = true
		}
		if readVerbs[tok] {
			hasRead = true
		}
	}
	if hasWrite {
		return true
	}
	if hasRead {
		return false
	}
	return true // unclassifiable → guard it
}

// schemaGaps reports the structural reasons args fails schema, conservatively: it
// flags only unambiguous, agent-fixable violations — a missing required field, or a
// value whose JSON kind can't be what the schema declares (object/array vs scalar).
// It deliberately does NOT police scalar-vs-scalar types (coercion-prone) or unknown
// fields, to avoid false positives that would hard-block a valid write into a loop.
// An empty/absent/non-object schema, or unparseable schema, yields no gaps (allow).
func schemaGaps(schema, args json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}
	var sc struct {
		Type       string `json:"type"`
		Required   []string
		Properties map[string]struct {
			Type json.RawMessage `json:"type"`
		}
	}
	if err := json.Unmarshal(schema, &sc); err != nil {
		return nil // can't understand the schema → don't block
	}
	if sc.Type != "" && sc.Type != "object" {
		return nil // not an object schema → nothing structural to check here
	}

	var a map[string]json.RawMessage
	trimmed := bytes.TrimSpace(args)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		a = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(trimmed, &a); err != nil {
		if len(sc.Properties) > 0 || len(sc.Required) > 0 {
			return []string{"arguments must be a JSON object"}
		}
		return nil
	}

	var gaps []string
	for _, r := range sc.Required {
		if _, ok := a[r]; !ok {
			gaps = append(gaps, "missing required field: "+r)
		}
	}
	for name, val := range a {
		p, ok := sc.Properties[name]
		if !ok {
			continue
		}
		if want := singleType(p.Type); want != "" && !kindCompatible(want, val) {
			gaps = append(gaps, fmt.Sprintf("field %q must be %s", name, want))
		}
	}
	return gaps
}

// singleType returns the lone declared JSON type, or "" if the type is a union
// (["string","null"]) or absent — cases too ambiguous to police.
func singleType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// kindCompatible enforces only the high-confidence structural distinction: a
// declared object/array must be given an object/array, and a declared scalar must
// not be given an object/array. Scalar-vs-scalar (string/number coercion) is left
// alone. A null/empty value is never flagged.
func kindCompatible(want string, val json.RawMessage) bool {
	v := bytes.TrimSpace(val)
	if len(v) == 0 || string(v) == "null" {
		return true
	}
	isObj, isArr := v[0] == '{', v[0] == '['
	switch want {
	case "object":
		return isObj
	case "array":
		return isArr
	case "string", "number", "integer", "boolean":
		return !isObj && !isArr
	}
	return true
}

// schemaBlockResult is the Tier-1 fail-closed response: an isError result carrying
// the specific problems plus the full description + inputSchema, so the agent can
// fix the arguments and retry. No mutation was sent upstream.
func schemaBlockResult(fqName string, spec gateway.Tool, gaps []string) map[string]any {
	b, _ := json.Marshal(map[string]any{
		"microagency_block": "This write was blocked BEFORE execution: its arguments do not satisfy the tool's schema (you may have selected it from a summarized find_tools entry without its full spec). No mutation was sent. Fix the arguments per the full inputSchema below, then call again.",
		"tool":              fqName,
		"problems":          gaps,
		"description":       spec.Description,
		"inputSchema":       spec.InputSchema,
	})
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": true,
	}
}

// attachToolSpec is the Tier-2 augmentation: it appends the tool's full description
// and inputSchema to an upstream ERROR result, so a retry after a failure the schema
// couldn't have prevented (e.g. a malformed DSL string) is informed. Stateless — the
// full spec is always held server-side — so it simply always attaches on error.
func attachToolSpec(result map[string]any, fqName string, spec gateway.Tool) map[string]any {
	b, _ := json.Marshal(map[string]any{
		"microagency_note": "The call failed. If you chose this tool from a summarized find_tools entry, you may have lacked its full spec. Its full description and inputSchema follow; correct the arguments and retry.",
		"tool":             fqName,
		"description":      spec.Description,
		"inputSchema":      spec.InputSchema,
	})
	block := map[string]any{"type": "text", "text": string(b)}
	switch c := result["content"].(type) {
	case []any:
		result["content"] = append(c, block)
	case []map[string]any:
		nc := make([]any, 0, len(c)+1)
		for _, m := range c {
			nc = append(nc, m)
		}
		result["content"] = append(nc, block)
	default:
		result["content"] = []any{block}
	}
	return result
}
