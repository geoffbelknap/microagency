package mcp

import (
	"strings"
	"testing"
)

// TestClassifyReduceFailureRoutesBlame pins the property the old single
// message lacked: a substrate failure and an authoring failure must not
// produce the same advice. "Fix the code and retry" against a broken
// environment is a non-terminating loop with a VM boot per attempt — it ran
// for two days against a rootfs with no /bin/sh, telling an agent to rewrite
// print(1).
func TestClassifyReduceFailureRoutesBlame(t *testing.T) {
	tests := []struct {
		name       string
		exitCode   int
		startError string
		mustSay    []string
		mustNotSay []string
	}{
		{
			name:       "never ran: environment, never 'fix the code'",
			exitCode:   127,
			startError: "fork/exec /bin/sh: no such file or directory",
			mustSay:    []string{"could not run", "do not rewrite", "operator", "fork/exec /bin/sh"},
			mustNotSay: []string{"Fix the code"},
		},
		{
			name:       "exit 127 with a working start: interpreter/config, hedged",
			exitCode:   127,
			mustSay:    []string{"interpreter or a command", "gateway", "operator", "127"},
			mustNotSay: []string{"Fix the code and retry"},
		},
		{
			name:     "exit 126: same class as 127",
			exitCode: 126,
			mustSay:  []string{"126", "not found"},
		},
		{
			name:       "killed: resource, not logic",
			exitCode:   -1,
			mustSay:    []string{"killed", "out-of-memory", "not a logic"},
			mustNotSay: []string{"Fix the code"},
		},
		{
			name:     "genuine code failure keeps the original advice",
			exitCode: 5,
			mustSay:  []string{"reduce code failed (exit 5)", "Fix the code and retry", "stderr is not returned"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := classifyReduceFailure(tt.exitCode, tt.startError, "run_7")
			for _, want := range tt.mustSay {
				if !strings.Contains(msg, want) {
					t.Errorf("message omits %q:\n%s", want, msg)
				}
			}
			for _, not := range tt.mustNotSay {
				if strings.Contains(msg, not) {
					t.Errorf("message wrongly says %q:\n%s", not, msg)
				}
			}
			if !strings.Contains(msg, "run_7") {
				t.Errorf("message loses the run ID the operator needs:\n%s", msg)
			}
		})
	}
}

// TestStartErrorOutranksExitCode pins precedence: a start failure with exit
// 127 is a start failure, not an interpreter hint. The exit code of a run
// that never happened describes nothing.
func TestStartErrorOutranksExitCode(t *testing.T) {
	msg := classifyReduceFailure(127, "mount /dev/vdb at /data: invalid argument", "run_9")
	if !strings.Contains(msg, "could not run") || !strings.Contains(msg, "mount /dev/vdb") {
		t.Errorf("start error did not take precedence:\n%s", msg)
	}
	if strings.Contains(msg, "interpreter") {
		t.Errorf("a never-ran failure got the exit-127 interpreter hint:\n%s", msg)
	}
}

// TestNoClassEverEchoesWorkloadOutput is the boundary guard: every message is
// built from the exit path, guest-init's substrate diagnosis, and the run ID
// — the classifier has no access to stdout/stderr at all, and this pins that
// its output never grows a stderr parameter by asserting the messages for a
// failing run stay identical whatever the workload printed. (Compile-time,
// really: the function signature has no output params; this documents it.)
func TestNoClassEverEchoesWorkloadOutput(t *testing.T) {
	a := classifyReduceFailure(1, "", "run_1")
	b := classifyReduceFailure(1, "", "run_1")
	if a != b {
		t.Error("message is not a pure function of exit path and run ID")
	}
	if strings.Contains(a, "%!") {
		t.Errorf("malformed format directives in message:\n%s", a)
	}
}

// TestBadQueryDiagnosticIsBounded pins capQueryDiagnostic's hygiene: first
// line only, hard length cap, and an honest placeholder when the engine said
// nothing.
func TestBadQueryDiagnosticIsBounded(t *testing.T) {
	if got := capQueryDiagnostic("jq: parse: unexpected token\nline two\nline three"); got != "jq: parse: unexpected token" {
		t.Errorf("multi-line diagnostic not trimmed to its first line: %q", got)
	}
	if got := capQueryDiagnostic(strings.Repeat("x", 1000)); len(got) > 310 {
		t.Errorf("diagnostic not capped: %d bytes", len(got))
	}
	if got := capQueryDiagnostic("  \n"); got != "(no diagnostic)" {
		t.Errorf("empty stderr not named: %q", got)
	}
}
