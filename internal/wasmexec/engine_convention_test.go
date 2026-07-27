package wasmexec

import (
	"context"
	"errors"
	"strings"
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

// TestBadQueryStderrNamesTheQueryNotTheData extends the convention with the
// property the gateway now RELIES on: at exit 2 the diagnostic is built from
// the query text alone, because every engine exits 2 before its first stdin
// read. The gateway returns that diagnostic to the caller as their own text;
// this test plants a sentinel in the data and requires it absent from every
// bad-query diagnostic, so an engine that starts reading data before parsing
// fails here rather than leaking through the returned message.
func TestBadQueryStderrNamesTheQueryNotTheData(t *testing.T) {
	const sentinel = "SECRET-ROW-VALUE-9f2c"
	tests := []struct {
		engine string
		dir    string
		query  string
		data   string
	}{
		{engine: "jq", dir: "../../engines/jq", query: "this is not valid jq |||", data: `["` + sentinel + `"]`},
		{engine: "sql", dir: "../../engines/sql", query: "NOT A SELECT AT ALL", data: `[{"a":"` + sentinel + `"}]`},
		{engine: "text", dir: "../../engines/text", query: "[unclosed", data: sentinel + "\n"},
		{engine: "html", dir: "../../engines/html", query: ">>>bad selector", data: "<p>" + sentinel + "</p>"},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			eng := SandboxEngine{Module: buildWasip1(t, tt.dir)}
			_, err := eng.Run(context.Background(), tt.query, []byte(tt.data))
			var exitErr *ExitError
			if !errors.As(err, &exitErr) || !exitErr.BadQuery() {
				t.Fatalf("%s: expected a bad-query rejection, got %v", tt.engine, err)
			}
			if exitErr.Stderr == "" {
				t.Errorf("%s produced no diagnostic; the caller is back to fixing the query blind", tt.engine)
			}
			if strings.Contains(exitErr.Stderr, sentinel) {
				t.Errorf("%s: bad-query diagnostic contains data: %q", tt.engine, exitErr.Stderr)
			}
		})
	}
}
