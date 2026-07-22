package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// find_tools is the one data path that must stay inline — reffing the menu would
// force a reduce hop just to read tool names — so instead of gating the whole
// result we bound it here. Verbose upstreams blow this open in two ways: multi-KB
// inputSchemas AND multi-KB markdown descriptions (Notion tools average 5–7KB of
// description each). A broad query over them serialized to ~95KB and tripped the
// model's context cap — the exact thing find_tools exists to prevent. So we bound
// the whole entry, trimming whichever field is heavy:
//
//   - full description + inputSchema are kept while the menu is under findToolsFullBudget,
//   - beyond that, entries are summarized (description clipped, schema digested),
//   - and once even summarized entries would pass findToolsHardMax, the tail is dropped
//     with a count — an absolute ceiling regardless of how many verbose tools match.
//
// The top hit is always returned in full so the best match is immediately usable,
// and a narrow query (few matches) returns full detail — the escape hatch the note
// points to.
const (
	findToolsFullBudget = 8 << 10  // keep full description+schema until the menu reaches this
	findToolsHardMax    = 36 << 10 // absolute ceiling; drop the tail beyond it
	findToolsDescRunes  = 180      // clipped-description length for summarized entries
)

// findTools is the discover half of the off-context tool surface: the aggregated
// upstream tools are kept OUT of tools/list, so an agent searches this index and
// pulls only the relevant few — with their schemas — then invokes them via
// call_tool. It ranks the indexed tools by keyword overlap over name and
// description. Keyword match keeps it dependency-free; an embedding ranker can
// replace the scorer later behind this same tool, without changing the surface.
func (s *Server) findTools(ctx context.Context, args json.RawMessage) map[string]any {
	var in struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	_ = json.Unmarshal(args, &in)
	limit := in.Limit
	if limit <= 0 {
		limit = 10 // default
	}
	if limit > 50 {
		limit = 50 // clamp to the max, rather than snapping back to the default
	}
	terms := tokenize(in.Query)

	type scored struct {
		tool  map[string]any
		score int
		usage int
	}
	var hits []scored
	// The index is scoped to the caller: shared connections + the caller's own.
	for _, t := range s.indexedTools(principalOf(ctx).Subject) {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		score := matchScore(terms, name, desc)
		if score > 0 {
			usage, _ := t["usage"].(int)
			hits = append(hits, scored{tool: t, score: score, usage: usage})
		}
	}
	// Keyword relevance is primary; usage (how often a tool has actually been
	// invoked) breaks ties, so popular, proven tools surface first. This is the
	// free-signal precursor to a heavier embedding ranker.
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].usage > hits[j].usage
	})

	if limit > len(hits) {
		limit = len(hits)
	}
	out := make([]map[string]any, 0, limit)
	total, summarized, omitted := 0, 0, 0
	for i := 0; i < limit; i++ {
		h := hits[i]
		desc, _ := h.tool["description"].(string)
		schema, _ := h.tool["inputSchema"].(json.RawMessage)
		// name/enabled/provenance/usage are always inline — that's what the agent picks
		// from. description and inputSchema are the heavy fields, so they're what we trim.
		entry := map[string]any{
			"name":        h.tool["name"],
			"enabled":     h.tool["enabled"], // invocable now, or must be enabled first
			"provenance":  h.tool["provenance"],
			"usage":       h.tool["usage"],
			"description": desc,
			"inputSchema": schema,
		}
		if v, ok := h.tool["invocable"]; ok {
			entry["invocable"] = v // false → a write on a read-only upstream; don't call it
		}
		if v, ok := h.tool["read_only_blocked"]; ok {
			entry["read_only_blocked"] = v
		}
		full := marshalLen(entry)
		// The top hit is always full so the best match is immediately usable; others
		// stay full only while the menu is under budget.
		if i == 0 || total+full <= findToolsFullBudget {
			total += full
			out = append(out, entry)
			continue
		}
		// Over the full budget. Beyond the absolute ceiling, drop the rest rather than
		// keep appending — a hard bound no matter how many verbose tools matched.
		if total >= findToolsHardMax {
			omitted = limit - i
			break
		}
		entry["description"] = clip(desc, findToolsDescRunes)
		entry["inputSchema"] = schemaDigest(schema)
		entry["truncated"] = true
		total += marshalLen(entry)
		out = append(out, entry)
		summarized++
	}
	result := map[string]any{"tools": out}
	if summarized > 0 || omitted > 0 {
		// Self-describing overflow: tell the agent how to recover any full detail.
		note := "Some results were summarized to stay within budget."
		if omitted > 0 {
			note = fmt.Sprintf("%d lower-ranked result(s) were omitted and %d summarized to stay within budget.", omitted, summarized)
		}
		result["note"] = note + " Narrow your query, or call find_tools with a tool's exact name for its full description and inputSchema."
	}
	return toolResult(result)
}

// marshalLen is the serialized byte size of v, used to track the running menu size.
func marshalLen(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// clip shortens s to at most max runes (never splitting a multibyte rune), marking
// that detail was dropped. Rune-based so a UTF-8 description isn't corrupted mid-cut.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + " …[truncated]"
}

// schemaDigest compresses an inputSchema to just what an agent needs to decide
// whether a tool fits — its parameter names and which are required — without the
// full (potentially multi-KB) property definitions. The full schema is one narrow
// find_tools call away.
func schemaDigest(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var sc struct {
		Type       string                     `json:"type"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &sc); err != nil {
		return map[string]any{"note": "schema summarized; call find_tools with this tool's exact name for the full inputSchema"}
	}
	props := make([]string, 0, len(sc.Properties))
	for k := range sc.Properties {
		props = append(props, k)
	}
	sort.Strings(props)
	digest := map[string]any{"properties": props, "summarized": true}
	if sc.Type != "" {
		digest["type"] = sc.Type
	}
	if len(sc.Required) > 0 {
		digest["required"] = sc.Required
	}
	return digest
}

// tokenize lowercases and splits a query into alphanumeric terms.
func tokenize(q string) []string {
	return strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
}

// matchScore counts term hits in name (weighted) and description.
func matchScore(terms []string, name, desc string) int {
	n, d := strings.ToLower(name), strings.ToLower(desc)
	score := 0
	for _, t := range terms {
		if strings.Contains(n, t) {
			score += 2
		}
		if strings.Contains(d, t) {
			score++
		}
	}
	return score
}
