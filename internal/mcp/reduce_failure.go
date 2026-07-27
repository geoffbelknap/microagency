package mcp

import (
	"fmt"
	"strings"
)

// classifyReduceFailure writes the failure message for a reduce(code) run that
// did not succeed, routed by WHO can fix it.
//
// One message used to cover every non-zero exit: "reduce code failed … Fix
// the code and retry." When the substrate was broken — a poisoned rootfs
// with no /bin/sh — that advice was a non-terminating loop with a VM boot
// per attempt: the agent rewrote correct code indefinitely, and the one fact
// that would end it (the environment is broken; get the operator) was
// captured nowhere the agent could see. The message read as authoritative,
// which made it worse: a well-behaved agent had no reason to doubt it.
//
// Classification uses only the exit path and guest-init's own start
// diagnosis — never the workload's output — so the operator-only stderr
// boundary is unchanged. startError is substrate-generated text (a failed
// mount, a failed exec) and cannot echo the referenced data.
func classifyReduceFailure(exitCode int, startError, runID string) string {
	switch {
	case startError != "":
		// The code never ran. Nothing the agent writes can change this.
		return fmt.Sprintf("reduce could not run your code — the sandbox failed before the code started (%s). "+
			"This is an environment problem, not a code bug: do not rewrite the code. "+
			"Ask the operator to check run %s (/admin/runs).", startError, runID)
	case exitCode == 126 || exitCode == 127:
		// The shell ran but the interpreter (or a command) was missing or not
		// executable. The workload image is gateway configuration — unless
		// the code exits 126/127 itself, which the hedge covers.
		return fmt.Sprintf("reduce code failed (exit %d), which usually means the interpreter or a command "+
			"was not found in the workload image. Unless your code exits %d deliberately, this is gateway "+
			"configuration, not a code bug — ask the operator to check run %s (/admin/runs) before rewriting anything.",
			exitCode, exitCode, runID)
	case exitCode < 0:
		// No exit status: the runner was killed (signal, out-of-memory).
		return fmt.Sprintf("reduce code was killed before completing (signal or out-of-memory), not a logic "+
			"error. Retry, reduce the input or memory the code uses, or ask the operator to check run %s "+
			"(/admin/runs).", runID)
	default:
		// A genuine non-zero exit from code that ran. Content-free by
		// design: a traceback (or stray print to stderr) over /app/input can
		// echo the exact bytes the ref model keeps off-context, so stderr
		// stays in the operator's audit record.
		return fmt.Sprintf("reduce code failed (exit %d). The guest's stderr is not returned here (it can "+
			"echo the referenced data); the operator can read it in the audit log (run %s, /admin/runs). "+
			"Fix the code and retry — the inputs are unchanged.", exitCode, runID)
	}
}

// capQueryDiagnostic bounds a compile/parse diagnostic for the agent-facing
// message: first lines, modest length. The diagnostic is safe to return only
// because every engine exits 2 before reading input (see the bad-query branch
// in runReduce); this cap is about message hygiene, not privacy.
func capQueryDiagnostic(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return "(no diagnostic)"
	}
	if i := strings.IndexByte(stderr, '\n'); i >= 0 {
		stderr = stderr[:i]
	}
	const maxLen = 300
	if len(stderr) > maxLen {
		stderr = stderr[:maxLen] + "…"
	}
	return stderr
}
