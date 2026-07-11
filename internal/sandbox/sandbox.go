// Package sandbox is the execution seam: "run this code in an isolated,
// deny-all-egress compute-only sandbox; give me its output and the
// egress audit." MicroagentProvider is the v1 implementation over microagent; a
// pooled or WASM provider can replace it behind the Provider interface without
// the router knowing. This is the ONLY microagency package that imports microagent.
package sandbox

import (
	"context"
	"fmt"
	"time"
)

// Spec describes one isolated execution. The provider always enforces strict
// egress with no allowlist — deny-all, compute-only; callers no longer supply an
// egress allowlist or a cred-swap config.
type Spec struct {
	Name     string        // workspace name (must be non-empty)
	Image    string        // OCI image ref
	Code     string        // script source, written into the guest
	CodePath string        // absolute guest path for the script
	Command  string        // exec command, e.g. "python /app/run.py"
	Inputs   []Input       // optional payload files made available to the guest (read-only)
	Timeout  time.Duration // 0 uses the provider default
}

// Input is a read-only payload file made available to the guest at Path — a
// compute input (e.g. a reduce over one or more stored references). It never
// leaves the sandbox.
type Input struct {
	Data []byte
	Path string // absolute guest path, e.g. /app/input or /app/input_1
}

// AuditEvent is one egress decision recorded by the mediator.
type AuditEvent struct {
	Event  string // e.g. "egress_allow", "egress_dns_deny"
	Host   string // populated for host-keyed events (allows); may be empty for DNS denies
	Dst    string // raw destination (IP:port or qname) recorded for deny events
	Reason string // human-readable denial reason from the mediator, if present
}

// Result is the outcome of a sandboxed run.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Audit    []AuditEvent
	// AuditErr is non-nil if the egress audit could not be read after an
	// otherwise-successful run; Audit may then be empty/incomplete.
	AuditErr error
}

// GuestFailureError reports a run whose guest never delivered a result (boot,
// exec, or result-channel failure). SerialLog carries the VM console log for the
// OPERATOR's audit surface only — the guest tees its command output to the
// console, so the serial log can echo the input data; Error() deliberately
// excludes it so guest output never rides an error message back into the
// model's context.
type GuestFailureError struct {
	Name      string
	SerialLog string
}

func (e *GuestFailureError) Error() string {
	return fmt.Sprintf("sandbox: %q: no guest result (serial log withheld from this message; captured for the operator)", e.Name)
}

// Provider runs a Spec in an isolated sandbox.
type Provider interface {
	Run(ctx context.Context, spec Spec) (Result, error)
}
