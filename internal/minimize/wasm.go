package minimize

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/geoffbelknap/microagent/pkg/sandbox"
)

// WasmModule is a minimizer backed by a wasip1 module, run through a warm cluster
// of sandboxed instances. sandbox.Compile pays the compilation cost once; each
// Scan borrows a slot from a bounded semaphore and does a cheap
// instantiate-run-discard on a fresh, isolated guest (safe to run concurrently).
// The guest has no network and no host filesystem, so a module physically cannot
// exfiltrate the very data it inspects — which is what makes running an untrusted
// third-party detector over sensitive fields safe.
type WasmModule struct {
	name    string
	rt      *sandbox.Runtime
	sem     chan struct{} // warm cluster: caps concurrent live guest instances
	timeout time.Duration
	maxMem  uint32
}

// Options configures a WasmModule's warm cluster and per-scan bounds.
type Options struct {
	// Instances is the warm-cluster size: the max number of guest instances live
	// at once. 0 → GOMAXPROCS. Every tool result crosses this boundary, so a small
	// warm cluster keeps per-scan latency low without unbounded concurrency.
	Instances int
	// Timeout bounds a single scan (0 = the caller's ctx only).
	Timeout time.Duration
	// MaxMemoryPages caps each guest's linear memory (0 = wazero's default).
	MaxMemoryPages uint32
}

// LoadWasm compiles a wasip1 minimizer module once and returns it ready to scan,
// with a warm cluster of Instances sandboxed guests. The caller owns it and must
// Close it.
func LoadWasm(ctx context.Context, name string, module []byte, opts Options) (*WasmModule, error) {
	rt, err := sandbox.Compile(ctx, module, sandbox.RuntimeOptions{MaxMemoryPages: opts.MaxMemoryPages})
	if err != nil {
		return nil, fmt.Errorf("minimize: compile %q: %w", name, err)
	}
	n := opts.Instances
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	sem := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		sem <- struct{}{} // a token in the channel == a free instance slot
	}
	return &WasmModule{name: name, rt: rt, sem: sem, timeout: opts.Timeout, maxMem: opts.MaxMemoryPages}, nil
}

func (m *WasmModule) Name() string { return m.name }

// Close releases the compiled runtime.
func (m *WasmModule) Close(ctx context.Context) error { return m.rt.Close(ctx) }

// wireIn / wireOut are the module ABI: one JSON object in on stdin, one out on
// stdout. Payload and Transformed are base64 so any bytes survive the JSON hop.
type wireIn struct {
	Payload   string          `json:"payload"`
	Upstream  string          `json:"upstream,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Direction string          `json:"direction,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
}

type wireOut struct {
	// Transformed is the base64 payload to forward. A nil field (absent from the
	// JSON) means "unchanged" — a detect-only module need not echo the payload.
	Transformed *string `json:"transformed"`
	Tokens      []Token `json:"tokens,omitempty"`
	Alerts      []Alert `json:"alerts,omitempty"`
}

// Scan runs the module over one payload. It borrows a warm slot (bounding
// concurrency), pipes the request JSON to the guest's stdin, and parses the
// guest's stdout. Any failure returns an error and no payload — the caller must
// fail closed.
func (m *WasmModule) Scan(ctx context.Context, in ScanInput) (ScanResult, error) {
	select {
	case <-m.sem:
		defer func() { m.sem <- struct{}{} }()
	case <-ctx.Done():
		return ScanResult{}, ctx.Err()
	}

	var policy json.RawMessage
	if len(in.Policy) > 0 {
		policy = json.RawMessage(in.Policy)
	}
	reqBytes, err := json.Marshal(wireIn{
		Payload:   base64.StdEncoding.EncodeToString(in.Payload),
		Upstream:  in.Upstream,
		Tool:      in.Tool,
		Direction: string(in.Direction),
		Policy:    policy,
	})
	if err != nil {
		return ScanResult{}, fmt.Errorf("minimize: module %q: encode request: %w", m.name, err)
	}

	res, err := m.rt.Run(ctx, sandbox.Config{
		Stdin:  bytes.NewReader(reqBytes),
		Limits: sandbox.Limits{Timeout: m.timeout, MaxMemoryPages: m.maxMem},
	})
	if err != nil {
		return ScanResult{}, fmt.Errorf("minimize: module %q: %w", m.name, err)
	}
	if res.ExitCode != 0 {
		return ScanResult{}, fmt.Errorf("minimize: module %q exited %d", m.name, res.ExitCode)
	}

	var out wireOut
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		return ScanResult{}, fmt.Errorf("minimize: module %q: decode output: %w", m.name, err)
	}
	transformed := in.Payload
	if out.Transformed != nil {
		b, err := base64.StdEncoding.DecodeString(*out.Transformed)
		if err != nil {
			return ScanResult{}, fmt.Errorf("minimize: module %q: decode transformed: %w", m.name, err)
		}
		transformed = b
	}
	return ScanResult{Transformed: transformed, Tokens: out.Tokens, Alerts: out.Alerts}, nil
}

// compile-time check
var _ Module = (*WasmModule)(nil)
