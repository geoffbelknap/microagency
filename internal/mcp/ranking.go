package mcp

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"unicode"
)

const (
	bm25K1         = 1.2
	bm25B          = 0.75
	exactRankScore = 1_000_000
)

// rankedTool is an internal ranking result. explanation contains only query
// terms and numeric factors; it never copies a description, schema, or example.
type rankedTool struct {
	tool        map[string]any
	score       float64
	usage       int
	explanation rankExplanation
}

type rankExplanation struct {
	Exact        bool     `json:"exact"`
	Score        float64  `json:"score"`
	MatchedTerms []string `json:"matched_terms,omitempty"`
	Usage        int      `json:"usage"`
}

// ToolRankInfo is the operator-only explanation shape. It contains no tool
// descriptions, schemas, arguments, or example values.
type ToolRankInfo struct {
	Name         string   `json:"name"`
	Score        float64  `json:"score"`
	Exact        bool     `json:"exact"`
	MatchedTerms []string `json:"matched_terms,omitempty"`
	Usage        int      `json:"usage"`
}

// RankTools explains the local rank for one caller-scoped index without storing
// the query or exposing the protected metadata used to build the score. The
// caller is identified by canonical principal key (issuer#subject).
func (s *Server) RankTools(callerKey, query string, limit int) []ToolRankInfo {
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	ranked := rankIndexedTools(query, s.indexedTools(callerKey))
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := make([]ToolRankInfo, 0, len(ranked))
	for _, hit := range ranked {
		name, _ := hit.tool["name"].(string)
		out = append(out, ToolRankInfo{
			Name: name, Score: hit.explanation.Score, Exact: hit.explanation.Exact,
			MatchedTerms: hit.explanation.MatchedTerms, Usage: hit.explanation.Usage,
		})
	}
	return out
}

type lexicalDocument struct {
	tool   map[string]any
	terms  map[string]float64
	length float64
}

// lexicalAliases is deliberately small and generic. It expands caller intent for
// ranking only; aliases are never presented as authoritative tool metadata.
var lexicalAliases = map[string][]string{
	"add":        {"create"},
	"calendar":   {"event"},
	"contact":    {"customer"},
	"create":     {"add"},
	"customer":   {"contact"},
	"delete":     {"remove"},
	"doc":        {"document"},
	"document":   {"doc", "page"},
	"edit":       {"update"},
	"email":      {"message"},
	"event":      {"calendar", "meeting"},
	"find":       {"lookup", "search"},
	"issue":      {"ticket"},
	"list":       {"find", "search"},
	"lookup":     {"find", "search"},
	"meeting":    {"event"},
	"message":    {"email"},
	"page":       {"document"},
	"remove":     {"delete"},
	"repo":       {"repository"},
	"repository": {"repo"},
	"reschedule": {"update"},
	"search":     {"find", "lookup"},
	"ticket":     {"issue"},
	"update":     {"edit"},
}

// rankIndexedTools applies an exact-name override, then a local BM25 lexical
// score over names, descriptions, and schema property names. It is rebuilt from
// the caller-scoped snapshot each time, so catalog updates cannot leave a stale
// cached index and catalog text never leaves the gateway.
func rankIndexedTools(query string, indexed []map[string]any) []rankedTool {
	q := queryTerms(query)
	exactQuery := strings.TrimSpace(query)
	if len(q) == 0 && exactQuery == "" {
		return nil
	}
	docs := make([]lexicalDocument, 0, len(indexed))
	df := map[string]int{}
	var totalLength float64
	for _, tool := range indexed {
		doc := buildLexicalDocument(tool)
		for term := range doc.terms {
			df[term]++
		}
		docs = append(docs, doc)
		totalLength += doc.length
	}
	if len(docs) == 0 {
		return nil
	}
	avgLength := totalLength / float64(len(docs))
	if avgLength == 0 {
		avgLength = 1
	}

	hits := make([]rankedTool, 0, len(docs))
	for _, doc := range docs {
		name, _ := doc.tool["name"].(string)
		exact := strings.EqualFold(exactQuery, name)
		score := 0.0
		matched := make([]string, 0, len(q))
		for term, queryWeight := range q {
			tf := doc.terms[term]
			if tf == 0 {
				continue
			}
			matched = append(matched, term)
			idf := math.Log(1 + (float64(len(docs)-df[term])+0.5)/(float64(df[term])+0.5))
			denom := tf + bm25K1*(1-bm25B+bm25B*doc.length/avgLength)
			score += queryWeight * idf * (tf * (bm25K1 + 1) / denom)
		}
		if exact {
			score += exactRankScore
		}
		if score <= 0 {
			continue
		}
		sort.Strings(matched)
		usage, _ := doc.tool["usage"].(int)
		hits = append(hits, rankedTool{
			tool: doc.tool, score: score, usage: usage,
			explanation: rankExplanation{Exact: exact, Score: roundedScore(score), MatchedTerms: matched, Usage: usage},
		})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		if hits[i].usage != hits[j].usage {
			return hits[i].usage > hits[j].usage
		}
		left, _ := hits[i].tool["name"].(string)
		right, _ := hits[j].tool["name"].(string)
		return left < right
	})
	return hits
}

func buildLexicalDocument(tool map[string]any) lexicalDocument {
	terms := map[string]float64{}
	add := func(text string, weight float64) {
		for _, term := range lexicalTokens(text) {
			terms[term] += weight
		}
	}
	name, _ := tool["name"].(string)
	desc, _ := tool["description"].(string)
	add(name, 3)
	add(desc, 1)
	if raw, _ := tool["inputSchema"].(json.RawMessage); len(raw) > 0 {
		var schema struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if json.Unmarshal(raw, &schema) == nil {
			for property := range schema.Properties {
				add(property, 1.5)
			}
			for _, required := range schema.Required {
				add(required, 0.5)
			}
		}
	}
	length := 0.0
	for _, count := range terms {
		length += count
	}
	return lexicalDocument{tool: tool, terms: terms, length: length}
}

func queryTerms(query string) map[string]float64 {
	out := map[string]float64{}
	for _, term := range lexicalTokens(query) {
		if out[term] < 1 {
			out[term] = 1
		}
		for _, alias := range lexicalAliases[term] {
			for _, expanded := range lexicalTokens(alias) {
				if out[expanded] < 0.85 {
					out[expanded] = 0.85
				}
			}
		}
	}
	return out
}

// lexicalTokens splits separators and camelCase, then adds a conservative stem
// beside each original token. Keeping the original avoids an aggressive stem
// turning one product term into another.
func lexicalTokens(text string) []string {
	var spaced strings.Builder
	var prev rune
	for _, r := range text {
		if unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)) {
			spaced.WriteByte(' ')
		}
		spaced.WriteRune(r)
		prev = r
	}
	raw := tokenize(spaced.String())
	out := make([]string, 0, len(raw)*2)
	seen := map[string]bool{}
	for _, term := range raw {
		for _, candidate := range []string{term, stemTerm(term)} {
			if len(candidate) < 2 || seen[candidate] {
				continue
			}
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	return out
}

func stemTerm(term string) string {
	switch {
	case len(term) > 4 && strings.HasSuffix(term, "ies"):
		return strings.TrimSuffix(term, "ies") + "y"
	case len(term) > 5 && (strings.HasSuffix(term, "ches") || strings.HasSuffix(term, "shes") || strings.HasSuffix(term, "xes") || strings.HasSuffix(term, "zes") || strings.HasSuffix(term, "oes")):
		return term[:len(term)-2]
	case len(term) > 5 && strings.HasSuffix(term, "ing"):
		return strings.TrimSuffix(term, "ing")
	case len(term) > 4 && strings.HasSuffix(term, "ed"):
		return strings.TrimSuffix(term, "ed")
	case len(term) > 3 && strings.HasSuffix(term, "s") && !strings.HasSuffix(term, "ss"):
		return strings.TrimSuffix(term, "s")
	default:
		return term
	}
}

func roundedScore(score float64) float64 { return math.Round(score*1_000_000) / 1_000_000 }

// legacyRankIndexedTools preserves the previous scorer for the checked-in
// evaluation baseline. Production discovery uses rankIndexedTools.
func legacyRankIndexedTools(query string, indexed []map[string]any) []rankedTool {
	terms := tokenize(query)
	var hits []rankedTool
	for _, tool := range indexed {
		name, _ := tool["name"].(string)
		desc, _ := tool["description"].(string)
		score := matchScore(terms, name, desc)
		if score > 0 {
			usage, _ := tool["usage"].(int)
			hits = append(hits, rankedTool{tool: tool, score: float64(score), usage: usage})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].usage > hits[j].usage
	})
	return hits
}
