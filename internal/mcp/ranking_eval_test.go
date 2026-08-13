package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"
)

type rankingEvalFixture struct {
	Version        int                   `json:"version"`
	Tools          []rankingFixtureTool  `json:"tools"`
	GeneratedTools []rankingGeneratedSet `json:"generated_tools"`
	Queries        []rankingFixtureQuery `json:"queries"`
}

type rankingFixtureTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Owner       string          `json:"owner"`
	Examples    []string        `json:"examples"`
}

type rankingGeneratedSet struct {
	Prefix      string          `json:"prefix"`
	Count       int             `json:"count"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type rankingFixtureQuery struct {
	ID               string   `json:"id"`
	Query            string   `json:"query"`
	Subject          string   `json:"subject"`
	Relevant         []string `json:"relevant"`
	Absent           []string `json:"absent"`
	ExpectedRequired []string `json:"expected_required"`
	ExpectEmpty      bool     `json:"expect_empty"`
}

type rankingEvalReport struct {
	RecallAt5        float64 `json:"recall_at_5"`
	MRR              float64 `json:"mrr"`
	ResultBytes      int     `json:"result_bytes"`
	FollowUpCalls    int     `json:"follow_up_discovery_calls"`
	ArgumentValidity float64 `json:"argument_validity"`
	LatencyMicros    int64   `json:"latency_micros"`
}

type rankingFunction func(string, []map[string]any) []rankedTool

func TestToolRankingEval(t *testing.T) {
	fixture := loadRankingFixture(t)
	legacy := evaluateRanking(t, fixture, "legacy", legacyRankIndexedTools, false)
	bm25 := evaluateRanking(t, fixture, "bm25", rankIndexedTools, false)
	examples := evaluateRanking(t, fixture, "bm25+examples", rankIndexedTools, true)

	if bm25.RecallAt5 < legacy.RecallAt5 || bm25.MRR <= legacy.MRR+0.05 {
		t.Fatalf("local ranker did not materially improve quality: legacy=%+v bm25=%+v", legacy, bm25)
	}
	if bm25.MRR < 0.90 || bm25.ArgumentValidity < 0.90 {
		t.Fatalf("local ranker missed the quality floor: %+v", bm25)
	}
	if bm25.ResultBytes > findToolsHardMax {
		t.Fatalf("ranked result fixture = %d bytes, cap = %d", bm25.ResultBytes, findToolsHardMax)
	}
	// BM25 is intentionally more work than substring counting, but this fixture is
	// a large catalog and the absolute local cost must stay negligible.
	if enforceRankingEvalLatency && bm25.LatencyMicros > 100_000 {
		t.Fatalf("local ranker latency materially regressed: %+v", bm25)
	}

	report, _ := json.Marshal(map[string]any{
		"catalog_tools":                    len(expandRankingTools(fixture)),
		"queries":                          len(fixture.Queries),
		"legacy":                           legacy,
		"bm25":                             bm25,
		"with_examples":                    examples,
		"examples_mrr_delta":               examples.MRR - bm25.MRR,
		"examples_argument_validity_delta": examples.ArgumentValidity - bm25.ArgumentValidity,
	})
	t.Logf("tool-ranking baseline: %s", report)
}

func loadRankingFixture(t *testing.T) rankingEvalFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/tool_ranking_eval.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture rankingEvalFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Tools) == 0 || len(fixture.Queries) == 0 {
		t.Fatalf("incomplete ranking fixture: %+v", fixture)
	}
	return fixture
}

func expandRankingTools(fixture rankingEvalFixture) []rankingFixtureTool {
	tools := append([]rankingFixtureTool(nil), fixture.Tools...)
	for _, generated := range fixture.GeneratedTools {
		for i := 0; i < generated.Count; i++ {
			tools = append(tools, rankingFixtureTool{
				Name: generated.Prefix + generatedIndex(i), Description: generated.Description,
				InputSchema: generated.InputSchema,
			})
		}
	}
	return tools
}

func generatedIndex(i int) string { return fmt.Sprintf("%03d", i) }

func evaluateRanking(t *testing.T, fixture rankingEvalFixture, label string, rank rankingFunction, includeExamples bool) rankingEvalReport {
	t.Helper()
	tools := expandRankingTools(fixture)
	var report rankingEvalReport
	var reciprocalRank, argumentPass float64
	qualityQueries := 0
	start := time.Now()
	for _, query := range fixture.Queries {
		index := make([]map[string]any, 0, len(tools))
		byName := map[string]rankingFixtureTool{}
		for _, tool := range tools {
			if tool.Owner != "" && tool.Owner != query.Subject {
				continue
			}
			description := tool.Description
			if includeExamples {
				for _, example := range tool.Examples {
					description += " " + example
				}
			}
			index = append(index, map[string]any{
				"name": tool.Name, "description": description,
				"inputSchema": tool.InputSchema, "usage": 0,
			})
			byName[tool.Name] = tool
		}
		ranked := rank(query.Query, index)
		if query.ExpectEmpty {
			if len(ranked) != 0 {
				t.Errorf("%s: malformed query returned %q", query.ID, ranked[0].tool["name"])
			}
			continue
		}
		for _, absent := range query.Absent {
			for _, hit := range ranked {
				if hit.tool["name"] == absent {
					t.Errorf("%s: owner-scoped tool %q leaked into rank", query.ID, absent)
				}
			}
		}
		if len(query.Relevant) == 0 {
			continue
		}
		qualityQueries++
		rankPosition := 0
		for i, hit := range ranked {
			name, _ := hit.tool["name"].(string)
			if containsString(query.Relevant, name) {
				rankPosition = i + 1
				break
			}
		}
		if rankPosition > 0 && rankPosition <= 5 {
			report.RecallAt5++
		}
		if rankPosition > 0 {
			reciprocalRank += 1 / float64(rankPosition)
		}
		if rankPosition == 1 {
			if requiredSchemaContains(byName[query.Relevant[0]].InputSchema, query.ExpectedRequired) {
				argumentPass++
			}
		} else {
			report.FollowUpCalls++
			top := "<none>"
			if len(ranked) > 0 {
				top, _ = ranked[0].tool["name"].(string)
			}
			t.Logf("%s/%s: relevant rank=%d top=%s", label, query.ID, rankPosition, top)
		}
		report.ResultBytes += rankedResultBytes(ranked, 5)
	}
	report.LatencyMicros = time.Since(start).Microseconds()
	if qualityQueries > 0 {
		report.RecallAt5 /= float64(qualityQueries)
		report.MRR = reciprocalRank / float64(qualityQueries)
		report.ArgumentValidity = argumentPass / float64(qualityQueries)
	}
	return report
}

func rankedResultBytes(ranked []rankedTool, limit int) int {
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	tools := make([]map[string]any, 0, len(ranked))
	for _, hit := range ranked {
		tools = append(tools, hit.tool)
	}
	return marshalLen(toolResult(map[string]any{"tools": tools}))
}

func requiredSchemaContains(raw json.RawMessage, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if json.Unmarshal(raw, &schema) != nil {
		return false
	}
	sort.Strings(schema.Required)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	return len(schema.Required) == len(want) && containsAll(schema.Required, want)
}

func containsAll(have, want []string) bool {
	for _, value := range want {
		if !containsString(have, value) {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
