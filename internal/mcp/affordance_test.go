package mcp

import (
	"strings"
	"testing"
)

// The credential-less long tail (exact arithmetic, date/timezone math, unit
// conversions, hashing/encoding, parsing, and bulk fetches) has no credential to
// gate on, so routing can only be ENCOURAGED via the tool copy. These assertions
// pin that steer into the reduce description so it can't silently regress.
// Advisory text only — no behavior is exercised.

// steerCues are the off-context-computation signals the affordance copy must carry.
var steerCues = []string{"arithmetic", "date", "timezone", "unit", "hashing", "parsing", "off-context"}

func toolDescByName(t *testing.T, name string) string {
	t.Helper()
	for _, td := range toolDefs() {
		if td["name"] == name {
			return td["description"].(string)
		}
	}
	t.Fatalf("tool %q not found in toolDefs()", name)
	return ""
}

func TestReduceDescriptionSteersExactComputationOffContext(t *testing.T) {
	desc := toolDescByName(t, "reduce")
	for _, cue := range steerCues {
		if !strings.Contains(strings.ToLower(desc), cue) {
			t.Errorf("reduce description missing steer cue %q: %s", cue, desc)
		}
	}
}
