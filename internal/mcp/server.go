// Package mcp serves the microagency tool surface to any MCP client over stdio
// JSON-RPC 2.0 (newline-delimited). It wraps the router behind the Runner
// interface so handlers are unit-testable without a microVM. No external MCP
// library — the wire protocol is small and implemented here, mirroring
// microagent's own stdio server.
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"microagency/internal/budget"
	"microagency/internal/minimize"
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

	// consoleAddr is where the operator surface (/console) is bound, reported in
	// /admin/infra so the header can show where the console is reachable. "" for a
	// plain `go build` / tests, where the browser falls back to its own location.
	consoleAddr string

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
	// OpenBao/Vault, an encrypted file with a separately held key, or an explicit
	// degraded mode-0600 plaintext fallback. nil = not persisted (in-memory only).
	secrets secretstore.Store
	// stateDir holds non-secret persisted state (the upstream registrations index),
	// so OAuth upstreams survive a restart. "" = not persisted.
	stateDir string

	// budget is the shared context-byte gate + refstore the run substrates use, so
	// the proxy path minimizes (reference-by-default) and reffed proxy results are
	// reducible off-context. Zero value = no gate (proxy results pass through).
	budget budget.Gate

	// minimizer is the field-level minimization pass applied to inline proxy results
	// before they enter model context (redact/tokenize/alert on sensitive values),
	// the fine-grained complement to reference-by-default. nil = off. tokens holds
	// the placeholder→value bindings for tokenized fields, resolved back on the way
	// to the upstream. (The per-upstream minimize policy lives in reg.policies.)
	minimizer minimize.Module
	tokens    minimize.TokenStore
	// tokenSalt keys placeholder derivation in the minimizer (a per-session secret,
	// never exposed to the model) so tokenized low-entropy values can't be brute-
	// forced from their placeholders. Set when a minimizer is installed.
	tokenSalt string

	// inflight decouples a slow READ's execution from the caller's request context
	// (a client cancel no longer aborts near-done work) and single-flights identical
	// calls. Writes never use it — a slow write must fail visibly, not commit after
	// the caller gave up.
	inflight *inflight

	// persistMu serializes the read-modify-write of upstreams.json so concurrent
	// admin handlers and the OAuth callback can't interleave and lose a persisted
	// registration. It guards on-disk state only, independent of the in-memory stores.
	persistMu sync.Mutex

	// auditSigner, when set, signs each audit line's chain hash (ES256) so the log
	// is unforgeable without the private key and verifiable offline from the public
	// key. Nil = integrity-only chain (detects accidental corruption and naive edits,
	// but a key-less attacker who recomputes hashes is not stopped).
	auditSigner auditSigner

	// Audit-write state, guarded by auditMu (the hash chain must not fork).
	auditMu         sync.Mutex
	auditHash       string // last written chain hash; "" before the first chained line
	auditChained    int    // count of chained lines written/loaded (the log's height)
	auditAnchoredAt int    // auditChained at the last out-of-band anchor save

	// Privileged decisions use a separate fail-closed stream. Its lock covers
	// both the chain head and finite grant-budget reservation, so concurrent
	// calls cannot each spend the same last unit.
	decisionMu       sync.Mutex
	decisionHash     string
	decisionSequence int64
	decisionUsage    map[string]*grantUsage
	decisionAppend   func(string, []byte) error
	decisionLoadErr  string
	highAssurance    bool

	// multiPrincipal records whether the agent-facing surface authenticates more
	// than one distinct principal (an external issuer today). On a multi-principal
	// gateway, non-governed proxy audit records capture argument structure and a
	// digest instead of values (see argcapture.go), unless a connection is opted
	// up to full capture. Set once at wiring time, before the server serves.
	multiPrincipal bool

	// Three concern-scoped stores, each with its OWN mutex — previously one shared
	// mutex guarded runs, upstreams, tool usage, OAuth flows, and minimize policies
	// alike. Splitting them cuts the blast radius (a change to run tracking can't
	// affect the registry) and the contention (recording a run no longer blocks a
	// find_tools index read). No critical section spans two of them.
	reg   registry         // aggregated upstreams + tool usage + per-upstream minimize policy
	rs    runStore         // the bounded recent-run window + all-time counters + run-id seq
	flows oauthFlowStore   // pending console OAuth-add flows
	self  selfServiceStore // operator-approved templates + bounded per-principal start rates
}

// registry holds the aggregated-MCP index and its per-upstream configuration.
type registry struct {
	mu            sync.Mutex
	conns         map[string]*upstream // aggregated MCP servers (enabled or discovered), by name
	usage         map[string]int       // per-tool invocation counts, a find_tools ranking signal
	policies      map[string][]byte    // per-upstream field-minimization policy JSON; nil = passthrough
	secureDefault bool                 // protect detected sensitive fields by default (operator opts down)
}

// runStore holds the bounded recent-run window (the durable audit log on disk is
// the complete record) plus the all-time counters that survive window eviction.
type runStore struct {
	mu      sync.Mutex
	seq     int
	byID    map[string]runRecord // the recent window, by run id
	order   []string             // insertion order, so the oldest is evicted at maxKept
	maxKept int                  // window cap (0 = unbounded)
	total   int                  // all-time run count, for Metrics.TotalRuns
	impact  Impact               // all-time cumulative impact
	context ContextCost          // all-time stage/context counters; rebuilt from audit
}

// oauthFlowStore holds pending console OAuth-add flows, keyed by state.
type oauthFlowStore struct {
	mu      sync.Mutex
	byState map[string]*oauthFlow
}

// defaultMaxRuns bounds the in-memory recent-run window. The complete history
// lives in the durable audit log; this is what /admin/runs and the by-substrate
// metrics breakdown scan, so it must stay bounded.
const defaultMaxRuns = 5000

// Option configures a Server.
type Option func(*Server)

// runRecord is the routing outcome retained for the audit log and explain-by-run.
type runRecord struct {
	// Kind is "discovery" (find_tools), "reduce" (an off-context reduction over
	// a ref), or "proxy" (an aggregated upstream MCP tool call). Proxy records
	// carry Upstream/Tool/Args; a reduce carries the ref it reduced in SourceID.
	Kind   string `json:"kind,omitempty"`
	TaskID string `json:"task_id,omitempty"` // bounded opaque correlation id; never a metric label
	// ParentRunID correlates a discovery/invocation performed inside a governed
	// reduce program to the outer microVM run. Delivery="program" means the
	// response went to that sandbox, not directly into model context.
	ParentRunID      string `json:"parent_run_id,omitempty"`
	Delivery         string `json:"delivery,omitempty"`
	ProgramRequestID string `json:"program_request_id,omitempty"`
	SourceID         string `json:"source_id,omitempty"`
	Upstream         string `json:"upstream,omitempty"` // proxy: the aggregated MCP name
	Tool             string `json:"tool,omitempty"`     // proxy: the upstream tool name
	// Args is the full call arguments. Captured verbatim on single-principal
	// gateways (the operator reading the log made the calls); on a
	// multi-principal gateway it is captured only for connections explicitly
	// opted up — everything else records ArgsShape/ArgsSHA256 instead, so one
	// operator-readable file doesn't concentrate every caller's raw arguments.
	Args string `json:"args,omitempty"`
	// ArgsCapture marks how arguments were captured: "" (full capture, or a
	// governed record's deliberate blank), "structure" (shape + digest, no
	// values), or "full" (multi-principal connection explicitly opted up).
	ArgsCapture string `json:"args_capture,omitempty"`
	// ArgsShape is the values-free structural mirror of the arguments (keys,
	// types, string byte counts); ArgsSHA256 is the hex SHA-256 of the
	// canonicalized arguments, so a claimed argument set stays verifiable
	// against the signed chain. Both set only under "structure" capture.
	ArgsShape   json.RawMessage `json:"args_shape,omitempty"`
	ArgsSHA256  string          `json:"args_sha256,omitempty"`
	User        string          `json:"user,omitempty"`     // the OAuth sub that ran it
	Campaign    string          `json:"campaign,omitempty"` // signed caller campaign claim
	GrantID     string          `json:"grant_id,omitempty"`
	GrantDigest string          `json:"grant_digest,omitempty"`
	Effect      string          `json:"effect,omitempty"`
	ResourceIDs []string        `json:"resource_ids,omitempty"`
	Session     string          `json:"session,omitempty"` // per-run SPIFFE identity
	// Impact instrumentation: which substrate ran it, which engine (wasm only),
	// how long it took, the bytes fetched (input) and returned to the model
	// (output). InputBytes/OutputBytes give the data-minimization ratio.
	Substrate   string `json:"substrate,omitempty"` // "wasm" | "microvm"
	Engine      string `json:"engine,omitempty"`    // wasm engine name
	LatencyMs   int64  `json:"latency_ms"`
	InputBytes  int    `json:"input_bytes"`
	OutputBytes int    `json:"output_bytes"`
	// RawBytes is the upstream/reducer output before parking or minimization.
	// ParkedBytes is the payload retained behind a reference. MinimizedBytes is
	// the non-negative serialized-byte reduction from field minimization. None
	// stores the payload itself.
	RawBytes       int `json:"raw_bytes,omitempty"`
	ParkedBytes    int `json:"parked_bytes,omitempty"`
	MinimizedBytes int `json:"minimized_bytes,omitempty"`
	// ContextMeasured distinguishes new exact context-byte records from older
	// audit lines whose OutputBytes meant raw tool output. It prevents an upgrade
	// from relabeling historical raw bytes as model-context bytes.
	ContextMeasured bool `json:"context_measured,omitempty"`
	// Discovery detail counts describe the bounded find_tools response without
	// retaining its query, schemas, descriptions, or result.
	FullSchemaEntries   int  `json:"full_schema_entries,omitempty"`
	SchemaDigestEntries int  `json:"schema_digest_entries,omitempty"`
	SummarizedEntries   int  `json:"summarized_entries,omitempty"`
	OmittedEntries      int  `json:"omitted_entries,omitempty"`
	ExactSchemaLookup   bool `json:"exact_schema_lookup,omitempty"`
	// A fused invocation records the declarative transform without retaining its
	// query or source result. The digest, engine, byte counts, latency, and status
	// are sufficient to reconstruct the governed chain.
	FusedInvocation      bool   `json:"fused_invocation,omitempty"`
	TransformEngine      string `json:"transform_engine,omitempty"`
	TransformQuerySHA256 string `json:"transform_query_sha256,omitempty"`
	TransformInputBytes  int    `json:"transform_input_bytes,omitempty"`
	TransformOutputBytes int    `json:"transform_output_bytes,omitempty"`
	TransformLatencyMs   int64  `json:"transform_latency_ms,omitempty"`
	TransformStatus      string `json:"transform_status,omitempty"`
	// Program* summarizes the bounded broker attached to an outer reduce run.
	// Child calls carry ParentRunID/ProgramRequestID instead.
	ProgramTools  []string `json:"program_tools,omitempty"`
	ProgramCalls  int      `json:"program_calls,omitempty"`
	ProgramBytes  int      `json:"program_bytes,omitempty"`
	ProgramStatus string   `json:"program_status,omitempty"`
	Reffed        bool     `json:"reffed"`
	Ref           string   `json:"ref,omitempty"`
	Bytes         int      `json:"bytes"`
	// Protected is the count of sensitive field values minimized (redacted or
	// tokenized) on this proxy call — the field-level minimization impact.
	Protected int `json:"protected,omitempty"`
	ExitCode  int `json:"exit_code"`
	// StartError is the guest's own diagnosis when the code never ran (failed
	// mount, unresolvable command, failed exec) — substrate text, never
	// workload output. It also shapes the agent-facing message: a run with
	// StartError set is classified as an environment failure, not a code bug.
	StartError string `json:"start_error,omitempty"`
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
		runner:        r,
		reg:           registry{conns: map[string]*upstream{}, usage: map[string]int{}, policies: map[string][]byte{}},
		rs:            runStore{byID: map[string]runRecord{}, maxKept: defaultMaxRuns},
		flows:         oauthFlowStore{byState: map[string]*oauthFlow{}},
		self:          newSelfServiceStore(),
		inflight:      newInflight(),
		decisionUsage: map[string]*grantUsage{},
		// SSRF-guarded; short dial (10s) but a generous request timeout (5m) so slow
		// upstream tools — e.g. a security query that computes before its first byte —
		// aren't killed mid-flight.
		upstreamClient: safedial.GuardedClient(0, 0),
	}
	for _, o := range opts {
		o(s)
	}
	s.loadConnectionTemplates()
	s.loadAudit() // replay the persisted audit log so the operator's history survives restarts
	s.loadDecisionLedger()
	return s
}

// WithHighAssuranceMultiUser requires an exact operation grant for every
// invocation and rejects implicit shared credential or writable authority.
func WithHighAssuranceMultiUser(enabled bool) Option {
	return func(s *Server) { s.highAssurance = enabled }
}

// SetMultiPrincipalAuth records whether the agent-facing surface authenticates
// more than one distinct principal, from the wired Authenticator's declared
// capability (Authenticator.MultiPrincipal) — never from comparing mode
// strings. Call at wiring time, before the server serves requests. It selects
// audit argument capture: multi-principal deployments record structure + digest
// for non-opted-up connections (see argcapture.go).
func (s *Server) SetMultiPrincipalAuth(on bool) { s.multiPrincipal = on }

// multiPrincipalAudit reports whether audit records must default to
// structure-only argument capture. High-assurance mode implies a shared
// multi-principal deployment even if a custom embedder forgot the wiring call.
func (s *Server) multiPrincipalAudit() bool { return s.multiPrincipal || s.highAssurance }

// withDecisionLedgerAppender is a narrow test seam for induced durable-write
// failures. Production always uses an append+fsync implementation.
func withDecisionLedgerAppender(appendLine func(string, []byte) error) Option {
	return func(s *Server) { s.decisionAppend = appendLine }
}

// WithSecretStore installs the store that persists acquired credentials (upstream
// OAuth refresh tokens).
func WithSecretStore(s2 secretstore.Store) Option { return func(s *Server) { s.secrets = s2 } }

// WithStateDir sets the directory for non-secret persisted state (the upstream
// registrations index), so OAuth upstreams reload across restarts.
func WithStateDir(dir string) Option { return func(s *Server) { s.stateDir = dir } }

// WithMaxRuns bounds the in-memory recent-run window (0 = unbounded). The durable
// audit log keeps the complete history regardless; this caps what /admin/runs and
// the metrics breakdown scan. Applied before the audit replay, so a restart honors
// it too.
func WithMaxRuns(n int) Option { return func(s *Server) { s.rs.maxKept = n } }

// auditSigner signs and verifies audit-chain hashes. *auth.Signer (ES256/P-256)
// satisfies it; kept as a narrow interface so the audit log doesn't import auth
// and tests can inject a stub.
type auditSigner interface {
	SignBytes(data []byte) ([]byte, error)
	VerifyBytes(data, sig []byte) bool
}

// WithAuditSigner makes the audit chain signed (and offline-verifiable): every
// appended line is signed over its hash, and VerifyAuditLog checks those
// signatures. Without it the chain is integrity-only.
func WithAuditSigner(signer auditSigner) Option {
	return func(s *Server) { s.auditSigner = signer }
}

// auditVerify returns the signature verifier for VerifyAuditLog, or nil when no
// signer is configured (chain-linkage checks only).
func (s *Server) auditVerify() func(hash, sig []byte) bool {
	if s.auditSigner == nil {
		return nil
	}
	return s.auditSigner.VerifyBytes
}

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

// WithMinimizer installs the field-level minimization pass (a minimize.Module —
// typically a warm-pool wasm minimizer) and the store for its tokenized-field
// bindings. Without it, the proxy path is unchanged. Per-upstream policy is set
// with SetMinimizePolicy; an upstream with no policy passes through untouched.
func WithMinimizer(m minimize.Module, tokens minimize.TokenStore) Option {
	return func(s *Server) { s.minimizer = m; s.tokens = tokens; s.tokenSalt = newTokenSalt() }
}

// newTokenSalt returns a per-session secret used to key placeholder derivation. It
// stays in memory and is never persisted or returned to the model. On the vanishing
// chance the OS RNG fails, we return "" — placeholders are still per-session stable,
// just not salted; the token store's scope check remains the primary defense.
func newTokenSalt() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// WithSecureDefault turns on secure-by-default minimization: an upstream with no
// explicit policy is protected by defaultMinimizePolicy (the operator opts down),
// instead of passing through. No effect without a minimizer installed.
func WithSecureDefault(on bool) Option { return func(s *Server) { s.reg.secureDefault = on } }

// WithConsoleAddr records where the operator console is bound (e.g.
// "127.0.0.1:8765"), reported in /admin/infra so the header shows the actual
// bind rather than a hardcoded label.
func WithConsoleAddr(addr string) Option { return func(s *Server) { s.consoleAddr = addr } }

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
	s.rs.mu.Lock()
	defer s.rs.mu.Unlock()
	s.rs.seq++
	return fmt.Sprintf("run_%d", s.rs.seq)
}

func (s *Server) putRun(id string, rec runRecord) {
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	s.rs.mu.Lock()
	s.addRunLocked(id, rec)
	s.rs.mu.Unlock()
	s.appendAudit(id, rec) // durable, append-only — the audit outlives the process
}

// addRunLocked records a run in the bounded in-memory window and folds it into the
// all-time cumulative counters, evicting the oldest window entry past maxRuns. The
// cumulative impact/total are accumulated on first insert (so they stay complete
// even after the window evicts a run), and recomputed from the durable log on
// restart via loadAudit. Caller holds s.rs.mu.
func (s *Server) addRunLocked(id string, rec runRecord) {
	if _, exists := s.rs.byID[id]; !exists {
		s.rs.order = append(s.rs.order, id)
		s.rs.total++
		s.accumulateImpactLocked(rec)
	}
	s.rs.byID[id] = rec
	for s.rs.maxKept > 0 && len(s.rs.order) > s.rs.maxKept {
		oldest := s.rs.order[0]
		s.rs.order = s.rs.order[1:]
		delete(s.rs.byID, oldest)
	}
}

// accumulateImpactLocked folds one run into the all-time impact totals, mirroring
// the per-run logic in Metrics so the cumulative figures match a full scan. Caller
// holds s.rs.mu.
func (s *Server) accumulateImpactLocked(rec runRecord) {
	if rec.Kind == "materialize" { // operator out-of-band pull, not a model-context call
		return
	}
	s.rs.impact.Calls++
	if rec.Reffed {
		s.rs.impact.Parked++
		parked := rec.ParkedBytes
		if parked == 0 { // backward-compatible replay of older audit records
			parked = rec.Bytes
		}
		s.rs.impact.BytesKeptOut += int64(parked)
	}
	// A reference handle and preview still enter context on newly measured
	// records. Preserve the old inline-only interpretation when replaying audit
	// lines written before ContextMeasured existed.
	if rec.ContextMeasured || !rec.Reffed {
		s.rs.impact.BytesToContext += int64(rec.OutputBytes)
	}
	s.rs.impact.FieldsProtected += rec.Protected
	s.accumulateContextLocked(rec)
}

func (s *Server) getRun(id string) (runRecord, bool) {
	s.rs.mu.Lock()
	defer s.rs.mu.Unlock()
	rec, ok := s.rs.byID[id]
	return rec, ok
}
