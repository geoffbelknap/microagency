// Package mcp serves the microagency tool surface to any MCP client over stdio
// JSON-RPC 2.0 (newline-delimited). It wraps the router behind the Runner
// interface so handlers are unit-testable without a microVM. No external MCP
// library — the wire protocol is small and implemented here, mirroring
// microagent's own stdio server.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"microagency/internal/budget"
	"microagency/internal/router"
	"microagency/internal/safedial"
	"microagency/internal/sandbox"
	"microagency/internal/secretstore"
	"microagency/internal/wasmexec"
)

// Runner executes a router request. *router.Router satisfies it; tests use a fake.
type Runner interface {
	Run(ctx context.Context, req router.Request) (router.Decision, error)
}

// Server is the MCP stdio server.
type Server struct {
	runner Runner

	// version is the build's release version (main.version via -ldflags), surfaced
	// in /admin/infra and the MCP serverInfo. "" for a plain `go build`.
	version string

	// wasm holds the reduce substrate's engines by name (e.g. jq, sql, text, html).
	// A declarative reduction is computed in the selected engine instead of running
	// Python in a microVM. Empty = the declarative reduce path is off. The agent
	// never selects the SUBSTRATE; it may name a query LANGUAGE (engine), which the
	// router resolves.
	wasm        map[string]wasmexec.Engine
	wasmDefault string

	// upstreamClient fetches user-supplied upstream MCP URLs (the SSRF vector).
	// Defaults to an SSRF-guarded client that refuses internal/metadata addresses.
	upstreamClient *http.Client

	// secrets persists acquired credentials (upstream OAuth refresh tokens) in
	// OpenBao/Vault or a 0600 file. nil = not persisted (in-memory only).
	secrets secretstore.Store
	// stateDir holds non-secret persisted state (the upstream registrations index),
	// so OAuth upstreams survive a restart. "" = not persisted.
	stateDir string

	// budget is the shared context-byte gate + refstore the run substrates use, so
	// the proxy path minimizes (reference-by-default) and reffed proxy results are
	// reducible off-context. Zero value = no gate (proxy results pass through).
	budget budget.Gate

	// inflight decouples a slow READ's execution from the caller's request context
	// (a client cancel no longer aborts near-done work) and single-flights identical
	// calls. Writes never use it — a slow write must fail visibly, not commit after
	// the caller gave up.
	inflight *inflight

	mu         sync.Mutex
	auditMu    sync.Mutex // serializes audit appends (the hash chain must not fork)
	auditHash  string     // last written chain hash; "" before the first chained line
	seq        int
	runs       map[string]runRecord
	upstreams  map[string]*upstream  // aggregated MCP servers (enabled or discovered), by name
	toolUsage  map[string]int        // per-tool invocation counts, a find_tools ranking signal
	oauthFlows map[string]*oauthFlow // pending console OAuth-add flows, keyed by state
}

// Option configures a Server.
type Option func(*Server)

// runRecord is the routing outcome retained for the audit log and explain-by-run.
type runRecord struct {
	// Kind is "reduce" (an off-context reduction over a ref) or "proxy" (an
	// aggregated upstream MCP tool call). Proxy records carry Upstream/Tool/Args;
	// a reduce carries the ref it reduced in SourceID.
	Kind     string `json:"kind,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	Upstream string `json:"upstream,omitempty"` // proxy: the aggregated MCP name
	Tool     string `json:"tool,omitempty"`     // proxy: the upstream tool name
	Args     string `json:"args,omitempty"`     // proxy: the full call arguments (no redaction — audit means audit)
	User     string `json:"user,omitempty"`     // the OAuth sub that ran it
	Session  string `json:"session,omitempty"`  // per-run SPIFFE identity
	// Impact instrumentation: which substrate ran it, which engine (wasm only),
	// how long it took, the bytes fetched (input) and returned to the model
	// (output). InputBytes/OutputBytes give the data-minimization ratio.
	Substrate   string `json:"substrate,omitempty"` // "wasm" | "microvm"
	Engine      string `json:"engine,omitempty"`    // wasm engine name
	LatencyMs   int64  `json:"latency_ms"`
	InputBytes  int    `json:"input_bytes"`
	OutputBytes int    `json:"output_bytes"`
	Reffed      bool   `json:"reffed"`
	Ref         string `json:"ref,omitempty"`
	Bytes       int    `json:"bytes"`
	ExitCode    int    `json:"exit_code"`
	// Stderr is the guest's captured stderr (or console log on a guest failure),
	// bounded — OPERATOR-BOUND diagnostics surfaced via /admin/runs. It is never
	// part of the agent-facing tool result: guest output over the input can echo
	// the exact bytes the ref model keeps off-context.
	Stderr    string               `json:"stderr,omitempty"`
	Audit     []sandbox.AuditEvent `json:"audit,omitempty"`
	AuditErr  string               `json:"audit_err,omitempty"`
	Timestamp time.Time            `json:"timestamp,omitempty"`
}

func NewServer(r Runner, opts ...Option) *Server {
	s := &Server{
		runner:     r,
		runs:       map[string]runRecord{},
		toolUsage:  map[string]int{},
		oauthFlows: map[string]*oauthFlow{},
		inflight:   newInflight(),
		// SSRF-guarded; short dial (10s) but a generous request timeout (5m) so slow
		// upstream tools — e.g. a security query that computes before its first byte —
		// aren't killed mid-flight.
		upstreamClient: safedial.GuardedClient(0, 0),
	}
	for _, o := range opts {
		o(s)
	}
	s.loadAudit() // replay the persisted audit log so the operator's history survives restarts
	return s
}

// WithSecretStore installs the store that persists acquired credentials (upstream
// OAuth refresh tokens) — OpenBao/Vault when configured, else a 0600 file.
func WithSecretStore(s2 secretstore.Store) Option { return func(s *Server) { s.secrets = s2 } }

// WithStateDir sets the directory for non-secret persisted state (the upstream
// registrations index), so OAuth upstreams reload across restarts.
func WithStateDir(dir string) Option { return func(s *Server) { s.stateDir = dir } }

// WithBudgetGate installs the shared context-byte gate + refstore (the same one
// the run substrates use) so the proxy path can minimize and reduce off-context.
func WithBudgetGate(g budget.Gate) Option { return func(s *Server) { s.budget = g } }

// WithUpstreamClient overrides the HTTP client used to fetch user-supplied
// upstream MCP URLs. Production keeps the SSRF-guarded default; tests inject a
// plain client to reach loopback mocks.
func WithUpstreamClient(c *http.Client) Option { return func(s *Server) { s.upstreamClient = c } }

// WithVersion sets the build's release version, reported in /admin/infra and the
// MCP serverInfo.
func WithVersion(v string) Option { return func(s *Server) { s.version = v } }

// WithWasmEngine registers a named engine for the declarative wasm-compute
// substrate (e.g. "jq", "text", "html"). A reduce query is routed to the
// selected engine — computed in wasm over the referenced bytes — instead of
// running Python in a microVM. The first engine registered is the default (used
// when neither the request nor the source names one). Repeatable. Without any, a
// declarative reduce is refused.
func WithWasmEngine(name string, e wasmexec.Engine) Option {
	return func(s *Server) {
		if s.wasm == nil {
			s.wasm = map[string]wasmexec.Engine{}
		}
		s.wasm[name] = e
		if s.wasmDefault == "" {
			s.wasmDefault = name
		}
	}
}

// EngineNames returns the configured declarative engine names, sorted.
func (s *Server) EngineNames() []string { return s.wasmEngineNames() }

// wasmEngineNames returns the configured engine names, sorted, for error messages.
func (s *Server) wasmEngineNames() []string {
	names := make([]string, 0, len(s.wasm))
	for n := range s.wasm {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// --- JSON-RPC envelope types ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC from in and writes responses to out.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	enc := json.NewEncoder(out) // Encode appends a newline → one response per line
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if resp, write := s.Handle(ctx, line); write {
				if werr := enc.Encode(resp); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// Handle processes one JSON-RPC message line. The second return is false for
// notifications (no id), which get no response. Exported for tests.
func (s *Server) Handle(ctx context.Context, line []byte) (rpcResponse, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}}, true
	}
	if req.ID == nil { // notification
		return rpcResponse{}, false
	}
	switch req.Method {
	case "initialize":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: initializeResult(s.version)}, true
	case "tools/list":
		// Lean by design: only microagency's own tools. Aggregated upstream tools
		// are NOT listed here — they'd flood the model's context — they live behind
		// find_tools (discover) + call_tool (invoke).
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": toolDefs()}}, true
	case "tools/call":
		return s.handleToolCall(ctx, req), true
	case "ping":
		// Standard MCP keep-alive: respond promptly with an empty result.
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}, true
	case "resources/list":
		// We expose no resources; answer empty rather than error so liberal
		// clients that probe regardless don't surface a warning.
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"resources": []any{}}}, true
	case "prompts/list":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"prompts": []any{}}}, true
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}}, true
	}
}

func initializeResult(version string) map[string]any {
	if version == "" {
		version = "dev"
	}
	return map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "microagency", "version": version},
	}
}

// nextRunID returns a deterministic run id and reserves it.
func (s *Server) nextRunID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("run_%d", s.seq)
}

func (s *Server) putRun(id string, rec runRecord) {
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	s.mu.Lock()
	s.runs[id] = rec
	s.mu.Unlock()
	s.appendAudit(id, rec) // durable, append-only — the audit outlives the process
}

func (s *Server) getRun(id string) (runRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.runs[id]
	return rec, ok
}
