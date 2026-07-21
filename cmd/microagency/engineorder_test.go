package main

import (
	"reflect"
	"testing"
)

// The default reduce engine is "the first one registered", so registration order
// must be deterministic (not Go map iteration) and must prefer jq. These pin both.
func TestOrderEngineNamesIsDeterministicAndJqFirst(t *testing.T) {
	// Input order must not affect the result: jq leads, the rest are alphabetical.
	want := []string{"jq", "html", "sql", "text"}
	for _, in := range [][]string{
		{"jq", "html", "sql", "text"},
		{"text", "sql", "html", "jq"},
		{"sql", "jq", "text", "html"},
	} {
		if got := orderEngineNames(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("orderEngineNames(%v) = %v, want %v", in, got, want)
		}
	}
}

// Without jq present, the order is simply alphabetical — still deterministic.
func TestOrderEngineNamesFallsBackToAlphabetical(t *testing.T) {
	got := orderEngineNames([]string{"text", "html", "sql"})
	want := []string{"html", "sql", "text"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderEngineNames without jq = %v, want %v", got, want)
	}
}
