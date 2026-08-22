package wasmexec

import (
	"strings"
	"testing"
)

// TestBadQueryFollowsTheEngineConvention pins the exit-code contract every
// bundled engine implements: 2 when the query itself is rejected, 1 when the
// data or I/O is the problem. The gateway reads the class from this, so an
// engine that drifts from the convention silently changes what an agent is told.
func TestBadQueryFollowsTheEngineConvention(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		exitCode int
		want     bool
	}{
		{"query rejected", 2, true},
		{"data or I/O failure", 1, false},
		{"unexpected code is not a query rejection", 3, false},
		{"success is never a failure class", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := &ExitError{ExitCode: tt.exitCode, Stderr: "jq: parse query: unexpected token"}
			if got := err.BadQuery(); got != tt.want {
				t.Errorf("BadQuery() for exit %d = %v, want %v", tt.exitCode, got, tt.want)
			}
		})
	}
}

// TestErrorTextNeverCarriesStderr is the disclosure boundary. The class is safe
// to surface — it is derived from the module's exit path, and describes text the
// caller wrote and already holds. The stderr is not: an engine failing part-way
// through a document can quote the data it was processing, and that must never
// ride an error message back into a model's context.
func TestErrorTextNeverCarriesStderr(t *testing.T) {
	t.Parallel()
	secret := "row 42: customer=alice@example.com balance=91231.55"
	for _, code := range []int{1, 2} {
		err := &ExitError{ExitCode: code, Stderr: "jq: " + secret}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("exit %d: Error() leaked the module's stderr: %q", code, err.Error())
		}
		// The operator's copy is still on the struct — withheld from the message,
		// not discarded.
		if !strings.Contains(err.Stderr, secret) {
			t.Errorf("exit %d: Stderr was discarded; the operator needs it", code)
		}
	}
}
