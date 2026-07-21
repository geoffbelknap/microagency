// Package router is the deterministic control plane: it validates a request,
// runs the caller's code in a deny-all-egress compute-only sandbox via
// the SandboxProvider seam over an optional Input payload, and passes the result
// through the budget gate before it can reach the model. It does NOT import
// microagent — all microVM specifics live behind the sandbox seam.
package router

import (
	"context"
	"errors"
	"strings"
	"time"

	"microagency/internal/budget"
	"microagency/internal/refstore"
	"microagency/internal/sandbox"
)

// Request is a unit of work submitted to the router. Code is caller-authored
// Python, run compute-only (deny-all egress) over zero or more Input
// payload files made available to the guest at their Paths.
type Request struct {
	Name   string
	Code   string
	Inputs []sandbox.Input // optional payload files (e.g. /app/input, or /app/input_1..N)
	// Owner is the subject the result ref is bound to, so only that principal can
	// reduce over it later. "" for a single-principal deployment.
	Owner string
}

// maxStderrBytes caps how many bytes of stderr are retained in a Decision.
// Stderr is OPERATOR-BOUND diagnostics (recorded in the run's audit record,
// never returned to the model), so the cap bounds the audit record — anything
// beyond it is replaced with a truncation notice.
const maxStderrBytes = 4096

// CapStderr bounds operator-bound guest diagnostics (stderr, console logs) to
// maxStderrBytes before they are recorded in an audit record, replacing the
// excess with a truncation notice.
func CapStderr(s string) string {
	if len(s) > maxStderrBytes {
		return s[:maxStderrBytes] + "\n...[stderr truncated]"
	}
	return s
}

// Decision is what the router returns. Exactly one of Inline (Reffed=false) or
// Ref+Summary (Reffed=true) carries the result; the rest is execution metadata.
type Decision struct {
	Reffed   bool
	Inline   string
	Ref      refstore.Ref
	Summary  refstore.Summary
	ExitCode int
	// Stderr is the guest's captured stderr — OPERATOR-BOUND diagnostics for the
	// run's audit record (bounded by maxStderrBytes). It must never be returned
	// to the model: a traceback or stray print over the input can echo the exact
	// bytes the ref model keeps off-context.
	Stderr string
	// InputBytes is the size of the data the execution consumed, when known — the
	// wasm path sets it to the host-fetched bytes, so impact instrumentation can
	// measure how much data the query kept out of the model's context. The microVM
	// path fetches inside the guest, so it leaves this 0 (not observable).
	InputBytes int
	Audit      []sandbox.AuditEvent
	// AuditErr is non-nil if the egress audit could not be read; Audit may
	// then be empty/incomplete.
	AuditErr error
}

// Router wires a SandboxProvider and a budget Gate together.
type Router struct {
	Provider sandbox.Provider
	Gate     budget.Gate
	Image    string
	CodePath string        // guest path for the script, e.g. "/app/run.py"
	Timeout  time.Duration // per-run sandbox timeout
}

// Run validates the request, executes it in the sandbox, and budget-gates the
// stdout result.
func (r Router) Run(ctx context.Context, req Request) (Decision, error) {
	if strings.TrimSpace(req.Code) == "" {
		return Decision{}, errors.New("router: empty code")
	}
	if req.Name == "" {
		return Decision{}, errors.New("router: empty name")
	}

	res, err := r.Provider.Run(ctx, sandbox.Spec{
		Name:     req.Name,
		Image:    r.Image,
		Code:     req.Code,
		CodePath: r.CodePath,
		Command:  "python " + r.CodePath,
		Inputs:   req.Inputs,
		Timeout:  r.Timeout,
	})
	if err != nil {
		return Decision{}, err
	}

	out := r.Gate.Apply(res.Stdout, req.Owner)
	return Decision{
		Reffed:   out.Reffed,
		Inline:   out.Inline,
		Ref:      out.Ref,
		Summary:  out.Summary,
		ExitCode: res.ExitCode,
		Stderr:   CapStderr(res.Stderr),
		Audit:    res.Audit,
		AuditErr: res.AuditErr,
	}, nil
}
