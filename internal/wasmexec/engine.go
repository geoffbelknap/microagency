// Package wasmexec runs a declarative query in a wasip1 wasm engine over
// in-memory bytes — pure compute, no network, no credentials. It backs the
// reduce tool: a query plus a payload go in, a computed summary comes out.
package wasmexec

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/geoffbelknap/microagent/pkg/sandbox"
)

// Engine is the wasm compute engine: pure compute over bytes, no creds, no
// network. It runs a declarative query over in-memory data and returns a summary.
type Engine interface {
	Run(ctx context.Context, query string, data []byte) (summary []byte, err error)
}

// SandboxEngine runs a consumer-supplied wasip1 query module via microagent's
// pkg/sandbox. It pipes the host-fetched data to the module's stdin and the
// query as argv[1], and returns the module's stdout as the summary. The module
// is pure compute — no network, no credentials (the host already did the
// cred-blind fetch); the substrate is engine-agnostic, so Module is whatever
// wasm-native engine the consumer supplies.
//
// This satisfies the Engine seam with a real wasm substrate. The query LANGUAGE
// is the module's concern: a row-counter takes a keyword, a SQL engine takes
// SQL. Picking the production engine (a wasip1 build — DuckDB-wasm is Emscripten
// and will not load) is a separate step; the wiring here is engine-agnostic.
type SandboxEngine struct {
	// Module is the wasip1 query-engine module binary.
	Module []byte
	// Timeout bounds a single execution (0 = the caller's ctx only).
	Timeout time.Duration
	// MaxMemoryPages caps guest linear memory (0 = wazero's default ceiling).
	MaxMemoryPages uint32
}

// ExitError reports a non-zero engine module exit. Stderr carries the module's
// captured stderr for the OPERATOR's audit surface only — an engine's runtime
// error (e.g. jq failing mid-document) can echo the referenced data it was
// processing, so Error() deliberately excludes it: guest output must never ride
// an error message back into the model's context.
type ExitError struct {
	ExitCode int
	Stderr   string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("wasmexec: engine module exited %d (stderr withheld from this message; captured for the operator)", e.ExitCode)
}

// Run satisfies Engine: query → argv[1], data → stdin, stdout → summary. A
// non-zero module exit is an error (the summary is not trustworthy) — an
// *ExitError carrying the module's stderr for the operator's audit record.
func (e SandboxEngine) Run(ctx context.Context, query string, data []byte) ([]byte, error) {
	res, err := sandbox.Run(ctx, sandbox.Config{
		Module: e.Module,
		Args:   []string{query},
		Stdin:  bytes.NewReader(data),
		Limits: sandbox.Limits{Timeout: e.Timeout, MaxMemoryPages: e.MaxMemoryPages},
	})
	if err != nil {
		return nil, fmt.Errorf("wasmexec: sandbox: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, &ExitError{ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return []byte(res.Stdout), nil
}
