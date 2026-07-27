package wasmexec

import (
	"context"
	"errors"
	"testing"
)

// TestEnginesRejectBadQueriesWithExitTwo guards the contract the gateway's
// agent-facing advice is derived from.
//
// Every bundled engine exits 2 when it rejects the query and 1 when the data or
// I/O is the problem. The gateway reads the failure class from that code: a
// rejected query is reported as something to correct, a data failure keeps the
// "run it as code instead" steer. An engine that drifts from the convention
// would silently start sending agents the wrong advice — telling them to
// escalate a typo to the microVM, or to rewrite a query when the data was at
// fault — with nothing else to catch it, because the stderr that would say so is
// deliberately withheld.
//
// Each case builds the real module, so this is the convention as shipped rather
// than as documented.
func TestEnginesRejectBadQueriesWithExitTwo(t *testing.T) {
	tests := []struct {
		engine string
		dir    string
		query  string
		data   string
	}{
		{engine: "jq", dir: "../../engines/jq", query: "this is not valid jq |||", data: `[1,2]`},
		{engine: "sql", dir: "../../engines/sql", query: "NOT A SELECT AT ALL", data: `[{"a":1}]`},
		{engine: "text", dir: "../../engines/text", query: "[unclosed", data: "a line\n"},
		{engine: "html", dir: "../../engines/html", query: ">>>bad selector", data: "<p>hi</p>"},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			eng := SandboxEngine{Module: buildWasip1(t, tt.dir)}
			_, err := eng.Run(context.Background(), tt.query, []byte(tt.data))
			if err == nil {
				t.Fatalf("%s accepted a malformed query", tt.engine)
			}
			var exitErr *ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("%s: want *ExitError, got %T: %v", tt.engine, err, err)
			}
			if !exitErr.BadQuery() {
				t.Errorf("%s exited %d for a malformed query, want 2 so the gateway reports it as one to correct",
					tt.engine, exitErr.ExitCode)
			}
		})
	}
}

// TestDataFailureIsNotAQueryRejection is the other side of the convention. A
// valid query over unusable data must not classify as a rejected query, or the
// agent would be told to fix a query that is already correct.
func TestDataFailureIsNotAQueryRejection(t *testing.T) {
	eng := SandboxEngine{Module: buildWasip1(t, "../../engines/jq")}
	_, err := eng.Run(context.Background(), ".[0]", []byte("this is not json at all"))
	if err == nil {
		t.Fatal("jq accepted non-JSON input")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("want *ExitError, got %T: %v", err, err)
	}
	if exitErr.BadQuery() {
		t.Errorf("a data failure exited %d and classified as a query rejection; the query was valid",
			exitErr.ExitCode)
	}
}
