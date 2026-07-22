package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/sandbox"
)

// maxOffloadBytes bounds how much microagency rehydrates from an upstream offload
// URL before the budget gate takes over. Bounded, per ASK tenet 8.
const maxOffloadBytes = 64 << 20 // 64 MiB

// nsSep separates an upstream's name from its tool name in the index:
// "<upstream>__<tool>". Tool names don't normally contain it, so it round-trips.
const nsSep = "__"

// upstreamConn is the transport-agnostic seam the gateway stores and calls. The
// concrete HTTP client (*gateway.Upstream) satisfies it today; a stdio or
// WebSocket transport can be added by implementing this interface, without
// touching the storage, invocation, enable/rebind/refresh, or health machinery
// that only ever talks to this seam. (Onboarding still constructs the concrete
// HTTP client explicitly — new transports add their own onboarding path and reuse
// everything below.)
type upstreamConn interface {
	Initialize(ctx context.Context) error
	ListTools(ctx context.Context) ([]gateway.Tool, error)
	CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error)
	Probe(ctx context.Context) (string, error)
	Endpoint() string // the upstream address (for display + egress accounting)
}

// upstream is one registered MCP server in the index. ENABLED means it's
// connected and its tools are invocable; otherwise it's DISCOVERED — metadata the
// agent can find but NOT call until the operator enables it. This is the
// discovery/invocation gate: the index may be broader than what's invocable, but
// call_tool only runs enabled upstreams (ASK: trust is explicit, never
// self-elevated).
type upstream struct {
	conn       upstreamConn   // connection (any transport; HTTP today)
	tools      []gateway.Tool // advertised tools (un-namespaced)
	enabled    bool           // connected → invocable
	provenance string         // "preloaded" | "catalog" | "discovered"
	// readOnly restricts this upstream to its READ tools: write/destructive tools
	// (isWriteTool) are refused at the invocation gate and marked non-invocable in
	// find_tools. Least-privilege at onboarding — an operator opts a connection down
	// to reads so an org-scoped OAuth grant (e.g. Supabase across all projects) can't
	// be used to mutate through microagency.
	readOnly bool
	// owner scopes this connection to ONE authenticated principal (by subject).
	// "" = shared: every authenticated user of this gateway may find and invoke it.
	// Non-empty: the connection — and the credential it holds — is invisible and
	// uninvocable to every other principal, enforced at find_tools and at the
	// invocation gate. This is what keeps one user's OAuth grant from being
	// exercised by another user of a shared (--issuer) deployment.
	owner string
	// minimizeSuggested is the minimization policy auto-detected from this upstream's
	// tool schemas, computed ONCE when tools are (re)loaded and cached here. Computing
	// it lazily in UpstreamList would rescan attacker-controlled tool metadata on every
	// /admin request under the lock — a DoS vector — so it is done at discovery instead.
	minimizeSuggested json.RawMessage
	// lastOK/lastErr track the most recent invocation's outcome so the operator can
	// see a dead or erroring upstream instead of discovering it one failed call at a
	// time. Mutated under s.mu, like the other record fields.
	lastOK    time.Time
	lastErr   string
	lastErrAt time.Time
}

// recordUpstreamHealth stamps the outcome of the most recent call to name, for
// operator visibility (UpstreamList). A client cancellation is not a failure and
// isn't recorded here.
func (s *Server) recordUpstreamHealth(name string, callErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.upstreams[name]
	if !ok {
		return
	}
	if callErr != nil {
		rec.lastErr, rec.lastErrAt = callErr.Error(), time.Now()
	} else {
		rec.lastOK = time.Now()
	}
}

// suggestionFor computes the cached minimization suggestion for a tool set. Done at
// tool-(re)load time, off the admin read path, so a huge or repeated upstream tool
// list can't drive repeated scans. nil when nothing is recognizable.
func suggestionFor(tools []gateway.Tool) json.RawMessage {
	sug := suggestMinimizePolicy(tools)
	if len(sug) == 0 {
		return nil
	}
	if b, err := json.Marshal(sug); err == nil {
		return b
	}
	return nil
}

// UpstreamOption customizes a registration at add/discover time, applied inside
// the same lock acquisition that registers the record — scoping is never applied
// "shortly after" registration, so there is no window where an owned connection
// is visible as shared.
type UpstreamOption func(*upstream)

// WithOwner scopes the connection to the principal with the given subject.
func WithOwner(subject string) UpstreamOption { return func(u *upstream) { u.owner = subject } }

// registerUpstream atomically registers rec under name, failing if the name is
// already taken. The existence check and the write happen under ONE lock
// acquisition — two concurrent adds of the same name can't both pass a separate
// check and silently overwrite each other.
func (s *Server) registerUpstream(name string, u *upstream, opts ...UpstreamOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upstreams == nil {
		s.upstreams = map[string]*upstream{}
	}
	if _, ok := s.upstreams[name]; ok {
		return fmt.Errorf("gateway: upstream %q already registered", name)
	}
	for _, opt := range opts {
		opt(u)
	}
	s.upstreams[name] = u
	return nil
}

func (s *Server) hasUpstream(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.upstreams[name]
	return ok
}

// snapshotUpstream returns a consistent copy of the named record's fields, taken
// under the lock. s.mu guards the map AND the record fields — Enable/Rebind/
// SetUpstreamReadOnly mutate records in place under the lock — so readers must
// never hold a bare *upstream across unlocked work. The copy is safe to use
// lock-free: conn is immutable once wired, and tools is only ever replaced
// wholesale, never mutated in place.
func (s *Server) snapshotUpstream(name string) (upstream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.upstreams[name]
	if !ok {
		return upstream{}, false
	}
	return *rec, true
}

// AddUpstream connects to an upstream, lists its tools, and registers it ENABLED
// (preloaded — operator-trusted, invocable). Failure to reach it is returned
// (fail-loud at wiring time), never a silent drop.
func (s *Server) AddUpstream(ctx context.Context, name string, conn upstreamConn, opts ...UpstreamOption) error {
	if name == "" || strings.Contains(name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", name, nsSep)
	}
	if s.hasUpstream(name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: upstream %q already registered", name)
	}
	_ = conn.Initialize(ctx) // best-effort; some servers don't require it before tools/list
	tools, err := conn.ListTools(ctx)
	if err != nil {
		return err
	}
	return s.registerUpstream(name, &upstream{conn: conn, tools: tools, enabled: true, provenance: "preloaded", minimizeSuggested: suggestionFor(tools)}, opts...)
}

// AddDiscovered registers an upstream's tools WITHOUT connecting — discovered
// metadata (a catalog entry or pre-discovery). The tools enter the index and are
// findable, but call_tool refuses them until EnableUpstream connects it. The
// connection config is retained so enabling is a one-step operator action.
func (s *Server) AddDiscovered(name string, conn upstreamConn, tools []gateway.Tool, provenance string, opts ...UpstreamOption) error {
	if name == "" || strings.Contains(name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", name, nsSep)
	}
	if provenance == "" {
		provenance = "discovered"
	}
	return s.registerUpstream(name, &upstream{conn: conn, tools: tools, enabled: false, provenance: provenance, minimizeSuggested: suggestionFor(tools)}, opts...)
}

// DiscoverUpstream connects once to fetch an upstream's tool metadata and
// registers it DISCOVERED (not enabled): the agent can find its tools but not
// invoke them until EnableUpstream authorizes it. (A catalog feed would instead
// call AddDiscovered with metadata it already holds, without connecting.)
func (s *Server) DiscoverUpstream(ctx context.Context, name string, conn upstreamConn, opts ...UpstreamOption) error {
	if name == "" || strings.Contains(name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", name, nsSep)
	}
	if s.hasUpstream(name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: upstream %q already registered", name)
	}
	_ = conn.Initialize(ctx)
	tools, err := conn.ListTools(ctx)
	if err != nil {
		return err
	}
	return s.registerUpstream(name, &upstream{conn: conn, tools: tools, enabled: false, provenance: "discovered", minimizeSuggested: suggestionFor(tools)}, opts...)
}

// EnableUpstream connects a discovered upstream — verifying it's reachable and
// refreshing its tools — and flips it to enabled (invocable). This is the
// explicit operator trust grant: discovery never auto-enables.
func (s *Server) EnableUpstream(ctx context.Context, name string) error {
	rec, ok := s.snapshotUpstream(name)
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	if rec.enabled {
		return nil
	}
	_ = rec.conn.Initialize(ctx)
	tools, err := rec.conn.ListTools(ctx)
	if err != nil {
		return err
	}
	sug := suggestionFor(tools) // compute off the lock (scans tool metadata)
	// Commit under the lock, re-validating against the live record: the upstream
	// may have been removed or rebound to a new connection while we were on the
	// network — enabling with tools listed from a stale connection would be wrong.
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.upstreams[name]
	if !ok {
		return fmt.Errorf("gateway: upstream %q was removed while enabling", name)
	}
	if cur.conn != rec.conn {
		return fmt.Errorf("gateway: upstream %q changed while enabling; retry", name)
	}
	cur.tools = tools
	cur.minimizeSuggested = sug
	cur.enabled = true
	return nil
}

// RebindUpstream swaps a registered upstream's connection — for re-auth with a new
// token or scope — refreshing its tools while preserving its enabled state and
// provenance. Errors if the upstream is unknown or the new connection is
// unreachable (leaving the old connection in place).
func (s *Server) RebindUpstream(ctx context.Context, name string, conn upstreamConn) error {
	if !s.hasUpstream(name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	_ = conn.Initialize(ctx)
	tools, err := conn.ListTools(ctx)
	if err != nil {
		return err
	}
	sug := suggestionFor(tools) // compute off the lock (scans tool metadata)
	// Commit under the lock against the live record — it may have been removed
	// while we were verifying the new connection.
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.upstreams[name]
	if !ok {
		return fmt.Errorf("gateway: upstream %q was removed while rebinding", name)
	}
	rec.conn = conn
	rec.tools = tools
	rec.minimizeSuggested = sug
	return nil
}

// RefreshUpstream re-lists a registered upstream's tools, updating the index so
// find_tools serves current schemas and the pre-egress write guard validates
// against them. An upstream's advertised tool set can change after it was first
// added — tools added or removed, schemas revised — and nothing re-listed it
// short of a rebind; a stale index hides added tools (and, being spec-less, treats
// them as writes) and keeps a removed tool looking invocable. Preserves the
// connection, enabled state, and provenance. Errors if the upstream is unknown or
// unreachable (leaving the current tools in place).
func (s *Server) RefreshUpstream(ctx context.Context, name string) error {
	rec, ok := s.snapshotUpstream(name)
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	_ = rec.conn.Initialize(ctx)
	tools, err := rec.conn.ListTools(ctx)
	if err != nil {
		return err
	}
	sug := suggestionFor(tools) // compute off the lock (scans tool metadata)
	// Commit under the lock, re-validating against the live record: it may have been
	// removed or rebound to a new connection while we were on the network.
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.upstreams[name]
	if !ok {
		return fmt.Errorf("gateway: upstream %q was removed while refreshing", name)
	}
	if cur.conn != rec.conn {
		return fmt.Errorf("gateway: upstream %q changed while refreshing; retry", name)
	}
	cur.tools = tools
	cur.minimizeSuggested = sug
	return nil
}

// UpstreamInfo is an operator-facing view of one registered upstream (no token).
type UpstreamInfo struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	State      string `json:"state"`           // "enabled" | "discovered"
	Provenance string `json:"provenance"`      // preloaded | catalog | discovered
	ReadOnly   bool   `json:"read_only"`       // writes refused (least-privilege)
	Owner      string `json:"owner,omitempty"` // principal subject this connection is scoped to; "" = shared
	Tools      int    `json:"tools"`           // count of advertised tools (shown per connection in the console)
	// Minimize is the field-minimization policy set for this upstream (type→action
	// JSON), or empty when none is configured. Shown/edited in the console.
	Minimize json.RawMessage `json:"minimize,omitempty"`
	// MinimizeSuggested is a policy auto-detected from this upstream's tool schemas,
	// surfaced only when no policy is set yet, so the console can offer it for the
	// operator to accept or edit. Never applied on its own.
	MinimizeSuggested json.RawMessage `json:"minimize_suggested,omitempty"`
	// MinimizeEffective is the policy ACTUALLY applied — the explicit one, or the
	// secure default when none is set. The console pre-fills the editor from this and
	// shows the "protected" chip when it's non-empty.
	MinimizeEffective json.RawMessage `json:"minimize_effective,omitempty"`
	// Health: the outcome of the most recent invocation, so a dead or erroring
	// upstream is visible in the console without waiting for the next per-call error.
	LastOK      string `json:"last_ok,omitempty"`       // RFC3339 of the last successful call
	LastError   string `json:"last_error,omitempty"`    // message of the last failed call
	LastErrorAt string `json:"last_error_at,omitempty"` // RFC3339 of the last failed call
}

// SetUpstreamOwner scopes (or, with "", un-scopes) a registered connection to one
// principal's subject. Errors if the upstream is unknown.
func (s *Server) SetUpstreamOwner(name, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.upstreams[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.owner = owner
	return nil
}

// SetUpstreamReadOnly toggles an upstream's read-only restriction. Errors if the
// upstream is unknown.
func (s *Server) SetUpstreamReadOnly(name string, ro bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.upstreams[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.readOnly = ro
	return nil
}

// UpstreamList returns the registered upstreams (enabled and discovered), sorted.
func (s *Server) UpstreamList() []UpstreamInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]UpstreamInfo, 0, len(s.upstreams))
	for name, rec := range s.upstreams {
		state := "discovered"
		if rec.enabled {
			state = "enabled"
		}
		explicit, hasExplicit := s.minimizePolicies[name]
		effective := explicit
		if !hasExplicit && s.secureDefault {
			effective = defaultMinimizePolicyJSON // secure-by-default
		}
		info := UpstreamInfo{Name: name, URL: rec.conn.Endpoint(), State: state, Provenance: rec.provenance, ReadOnly: rec.readOnly, Owner: rec.owner, Tools: len(rec.tools),
			Minimize: json.RawMessage(explicit), MinimizeEffective: json.RawMessage(effective)}
		if !rec.lastOK.IsZero() {
			info.LastOK = rec.lastOK.Format(time.RFC3339)
		}
		if rec.lastErr != "" {
			info.LastError = rec.lastErr
			info.LastErrorAt = rec.lastErrAt.Format(time.RFC3339)
		}
		// Surface the schema-derived suggestion only when nothing is protecting the
		// upstream (secure-default off and no explicit policy) — never applied on its
		// own. Read from the cache computed at tool-load time; UpstreamList must not
		// rescan attacker-controlled tool metadata on every admin request (a DoS vector).
		if len(effective) == 0 && len(rec.minimizeSuggested) > 0 {
			info.MinimizeSuggested = rec.minimizeSuggested
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RemoveUpstream deregisters an upstream (enabled or discovered), dropping its
// tools from the index.
func (s *Server) RemoveUpstream(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[name]; !ok {
		return false
	}
	delete(s.upstreams, name)
	return true
}

// indexedTools returns the searchable index FOR ONE PRINCIPAL: every registered
// upstream's tools the subject may see — shared connections plus the ones owned
// by that subject — namespaced and tagged with enabled (invocable) + provenance.
// Kept OUT of tools/list so the model's context isn't flooded with the whole
// catalog. An owned connection never appears in another principal's index; the
// invocation gate enforces the same boundary, so this filter is minimization,
// not the only line of defense.
func (s *Server) indexedTools(subject string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for name, rec := range s.upstreams {
		if rec.owner != "" && rec.owner != subject {
			continue
		}
		for _, t := range rec.tools {
			full := name + nsSep + t.Name
			// A write tool on a read-only upstream is findable but NOT invocable, so
			// the agent doesn't pick a tool the gate will refuse.
			invocable := rec.enabled
			m := map[string]any{
				"name":        full,
				"description": t.Description,
				"inputSchema": t.InputSchema,
				"enabled":     rec.enabled,
				"provenance":  rec.provenance,
				"usage":       s.toolUsage[full],
			}
			if rec.enabled && rec.readOnly && isWriteTool(t) {
				invocable = false
				m["read_only_blocked"] = true // the upstream is read-only; this write is refused
			}
			m["invocable"] = invocable
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	return out
}

// invokeUpstream runs an aggregated upstream tool call: it applies the
// pre-invocation gates (unknown/owner/disabled — no call, so no audit record),
// then hands off to proxyCall and records the single outcome. Every path through
// proxyCall returns a proxyOutcome, so recording happens in exactly one place —
// a new early return can't silently skip the audit log.
func (s *Server) invokeUpstream(ctx context.Context, name string, args json.RawMessage) (map[string]any, bool) {
	upName, tool, found := strings.Cut(name, nsSep)
	if !found {
		return nil, false
	}
	// A consistent SNAPSHOT of the record, not the live pointer: the gate below
	// reads enabled/readOnly/tools/conn across the whole (network-bound) call, and
	// an operator Enable/Rebind/SetUpstreamReadOnly mutates the live record under
	// the lock — reading it lock-free would race and could skip the read-only gate
	// or call through a half-swapped connection.
	rec, ok := s.snapshotUpstream(upName)
	if !ok {
		return toolError("unknown tool %q; discover tools with find_tools", name), true
	}
	// Ownership gate: a connection scoped to one principal is INVISIBLE to every
	// other — same error as an unregistered tool, so a probing caller can't even
	// learn the connection exists, let alone exercise its credential.
	if rec.owner != "" && rec.owner != principalOf(ctx).Subject {
		return toolError("unknown tool %q; discover tools with find_tools", name), true
	}
	if !rec.enabled {
		return toolError("tool %q is discovered but not enabled; ask the operator to enable upstream %q", name, upName), true
	}
	// Restore any tokenized-field placeholders the model authored back to their real
	// values before this call is dialed (the return path for field minimization).
	// Scoped to this caller and THIS upstream: a placeholder from another upstream (or
	// another principal) stays inert, so a secret tokenized out of upstream X can't be
	// replayed by handing its placeholder to a different upstream. No-op unless a
	// minimizer previously tokenized a value the model is now echoing back here.
	args = s.resolveOutbound(ctx, upName, args)
	runID := s.nextRunID()
	start := time.Now()
	out := s.proxyCall(ctx, runID, start, upName, tool, name, rec, args)
	// THE single audit record: every proxyCall outcome — refusal, error, ref,
	// inline, or success — lands here, so "every outcome is audited" is structural.
	s.recordProxy(ctx, runID, upName, tool, args, out.outBytes, start, out.err, out.outcome, out.egressHost, out.protected, out.extra...)
	return out.result, true
}

// proxyOutcome bundles a proxied call's result with everything recordProxy needs.
// proxyCall returns it on every path, so the single recordProxy in invokeUpstream
// can't be bypassed by a new early return.
type proxyOutcome struct {
	result     map[string]any
	outBytes   int
	err        error
	outcome    budget.Outcome
	egressHost string // "" when no egress reached the upstream (a pre-dial refusal)
	protected  int
	extra      []sandbox.AuditEvent
}

// proxyCall dials the upstream (after the read-only and pre-egress write gates),
// then shapes the result — offload rehydration, truncation notice,
// reference-by-default parking, or field minimization — returning a proxyOutcome
// for each path. It performs the side effects that belong to a call (health,
// usage), but never records the audit line itself; that is invokeUpstream's job.
func (s *Server) proxyCall(ctx context.Context, runID string, start time.Time, upName, tool, name string, rec upstream, args json.RawMessage) proxyOutcome {
	upHost := hostFromURL(rec.conn.Endpoint()) // the egress target for calls that reach the upstream
	spec, haveSpec := findTool(rec.tools, tool)
	// Read-only gate: a read-only upstream refuses writes (and unclassifiable tools,
	// which default to write). Enforced OUTSIDE the agent, at the single invocation
	// gate — the agent can't widen it. No egress happened, so egressHost stays "".
	if rec.readOnly && (!haveSpec || isWriteTool(spec)) {
		return proxyOutcome{
			result: toolError("upstream %q is READ-ONLY; the write/destructive tool %q is refused. Ask the operator to allow writes on this upstream if this is intended.", upName, name),
			err:    fmt.Errorf("read-only upstream: write refused"),
		}
	}
	// Tier 1 — pre-egress write guard. If this is a write and its arguments don't
	// satisfy the tool's retained schema, fail CLOSED: no malformed mutation is sent,
	// and the agent gets the full spec to retry. Reads skip this — Tier 2 covers them.
	if haveSpec && isWriteTool(spec) {
		if gaps := schemaGaps(spec.InputSchema, args); len(gaps) > 0 {
			return proxyOutcome{
				result: schemaBlockResult(name, spec, gaps),
				err:    fmt.Errorf("pre-egress schema block: %s", strings.Join(gaps, "; ")),
			}
		}
	}
	// Reads run through the in-flight cache (a client-timeout cancel won't abort
	// near-done work, and identical concurrent reads share one execution); writes and
	// unclassifiable tools run under the caller context (a cancel aborts, nothing
	// commits in the background after the client stopped waiting).
	var res json.RawMessage
	var err error
	if !haveSpec || isWriteTool(spec) {
		res, err = rec.conn.CallTool(ctx, tool, args)
	} else {
		var canceled bool
		res, err, canceled = s.inflight.do(ctx, inflightKey(upName, tool, args), func(c context.Context) (json.RawMessage, error) {
			return rec.conn.CallTool(c, tool, args)
		})
		if canceled {
			return proxyOutcome{result: toolError("upstream %q: still running after the client stopped waiting; the call was not aborted — retry to collect the result", upName), err: err, egressHost: upHost}
		}
	}
	s.recordUpstreamHealth(upName, err) // last-call health, for the operator view
	if err != nil {
		return proxyOutcome{result: toolError("upstream %q: %v", upName, err), outBytes: len(res), err: err, egressHost: upHost}
	}
	var passthrough map[string]any
	if uerr := json.Unmarshal(res, &passthrough); uerr != nil {
		return proxyOutcome{result: toolError("upstream %q: malformed result: %v", upName, uerr), outBytes: len(res), err: uerr, egressHost: upHost}
	}
	s.bumpUsage(name) // a successful call — a find_tools ranking signal
	// Reference-by-default: a large result is held off-context as a handle the agent
	// reduces, not flooded into context. Errors and small results pass through inline.
	if s.budget.Store != nil && !resultIsError(passthrough) {
		payload, rehydrated := resultPayload(passthrough), false
		// Offload neutralization: some upstreams return an off-platform URL in place
		// of a large payload. That pointer defeats cred-blindness and minimization —
		// fetch it host-side and treat the bytes as the real result; the agent never
		// sees the URL.
		if link := offloadURL(payload); link != "" {
			data, ferr := s.fetchOffload(ctx, link)
			if ferr != nil {
				return proxyOutcome{result: toolError("upstream %q returned an off-platform result link microagency could not retrieve (%v); the raw URL is withheld", upName, ferr), err: fmt.Errorf("offload rehydrate: %w", ferr), egressHost: upHost}
			}
			payload, rehydrated = string(data), true
		}
		// A truncated / malformed payload is a NOTICE, not data — surface it inline so
		// the agent reads the guidance instead of parking broken bytes behind a ref.
		if notice, ok := truncatedNotice(payload); ok {
			return proxyOutcome{result: truncatedResult(notice), outBytes: len(notice), egressHost: upHost}
		}
		// Gate on the LARGER of the extracted payload and the full upstream result, so
		// a compact structuredContent beside a large content[].text can't ride inline.
		if len(payload) > s.budget.MaxBytes || (!rehydrated && len(res) > s.budget.MaxBytes) {
			stored := payload
			if !rehydrated && len(payload) < len(res)/2 {
				stored = string(res) // extraction dropped data — ref the full result instead
			}
			ref, sum := s.budget.Store.Put(stored, principalOf(ctx).Subject)
			return proxyOutcome{result: s.refHandleResult(ref, sum, name), outBytes: sum.Bytes, outcome: budget.Outcome{Reffed: true, Ref: ref, Summary: sum}, egressHost: upHost}
		}
		if rehydrated { // small enough to inline, but return the DATA, never the offload URL
			return proxyOutcome{result: rehydratedResult(payload), outBytes: len(payload), egressHost: upHost}
		}
	}
	// Tier 2 — on an upstream tool error, append the tool's full description +
	// inputSchema so a retry is informed (a semantic failure the JSON schema can't
	// express). Applies to reads and writes.
	if resultIsError(passthrough) && haveSpec {
		passthrough = attachToolSpec(passthrough, name, spec)
	}
	// Field-level minimization: scrub sensitive VALUES out of a small inline result
	// before it enters model context. No-op unless a minimizer and policy are
	// configured for this upstream. Fails closed.
	scrubbed, alerts, protected, merr := s.scrubInbound(ctx, upName, tool, passthrough)
	if merr != nil {
		return proxyOutcome{result: toolError("upstream %q: field minimization failed; result withheld", upName), err: fmt.Errorf("minimize: %w", merr), egressHost: upHost}
	}
	return proxyOutcome{result: scrubbed, outBytes: len(res), egressHost: upHost, protected: protected, extra: minimizeAlertEvents(alerts)}
}

// fetchOffload retrieves an upstream offload URL host-side through the SSRF-guarded
// upstream client (so the bytes stay off the agent and internal addresses are
// refused), bounded by maxOffloadBytes, transparently decompressing a gzip export.
func (s *Server) fetchOffload(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxOffloadBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxOffloadBytes {
		return nil, fmt.Errorf("offload exceeds the %d MiB cap", maxOffloadBytes>>20)
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b { // gzip magic (e.g. *.json.gz)
		zr, zerr := gzip.NewReader(bytes.NewReader(data))
		if zerr != nil {
			return nil, zerr
		}
		defer func() { _ = zr.Close() }()
		un, zerr := io.ReadAll(io.LimitReader(zr, maxOffloadBytes+1))
		if zerr != nil {
			return nil, zerr
		}
		if int64(len(un)) > maxOffloadBytes {
			return nil, fmt.Errorf("decompressed offload exceeds the %d MiB cap", maxOffloadBytes>>20)
		}
		data = un
	}
	return data, nil
}

// recordProxy writes an audit record for one aggregated-MCP tool call, so the
// proxy path shows up in /admin/runs and /admin/metrics exactly like a run. The
// full arguments are recorded (no redaction — audit means audit).
// egressHost is the upstream host this call reached (mediated, cred-blind), or ""
// when the call was refused BEFORE any egress (read-only gate, pre-egress schema
// block). When set, it's recorded as an egress_allow event so the console and the
// audit chain show the gateway's outbound call, not "no egress".
func (s *Server) recordProxy(ctx context.Context, runID, upstream, tool string, args json.RawMessage, outBytes int, start time.Time, callErr error, out budget.Outcome, egressHost string, protected int, extra ...sandbox.AuditEvent) {
	exit, auditErr := 0, ""
	if callErr != nil {
		exit, auditErr = 1, callErr.Error()
	}
	var audit []sandbox.AuditEvent
	if egressHost != "" {
		audit = append(audit, sandbox.AuditEvent{Event: "egress_allow", Host: egressHost})
	}
	audit = append(audit, extra...) // e.g. minimize_alert events from field minimization
	s.putRun(runID, runRecord{
		Kind: "proxy", Upstream: upstream, Tool: tool, Args: string(args),
		User:        principalOf(ctx).Subject,
		InputBytes:  len(args), // the tool arguments are the call's input payload
		OutputBytes: outBytes, Bytes: outBytes,
		LatencyMs: time.Since(start).Milliseconds(),
		Reffed:    out.Reffed, Ref: string(out.Ref),
		Protected: protected,
		ExitCode:  exit, AuditErr: auditErr, Audit: audit,
	})
}

// unwrapData digs through common wrappers to the bare rows. It pulls the outermost
// JSON out of any preamble, then — for tools (e.g. Supabase) that return the rows
// as a JSON-encoded STRING inside a field, like {"result":"...<untrusted-data>[…]…"}
// — digs one level into that string to the array. Prefers an array payload.
// maxUnwrapFraming bounds how much surrounding text unwrapData will strip to reach
// an embedded JSON payload. Stripping a short preamble + XPIA tags around a rows
// array is the intent; discarding KILOBYTES means the "surrounding text" was itself
// the real content (a fetched document whose prose merely contains an incidental
// JSON block — e.g. a Notion page's <properties> block), so the strip is refused and
// the full text is kept. Erring toward NOT stripping loses at most some reduce
// tidiness; erring the other way silently drops the actual data.
const maxUnwrapFraming = 512

// refHandleResult is what the agent receives when a proxied result is held off
// context: the handle + size + how to reduce it. Never the raw data.
func (s *Server) refHandleResult(ref refstore.Ref, sum refstore.Summary, toolName string) map[string]any {
	out := map[string]any{
		"reffed": true,
		"ref":    string(ref),
		"bytes":  sum.Bytes,
		"note": fmt.Sprintf("%s returned %d bytes, held off-context as %s. A structural preview is included so you may not need to reduce at all. To read it off-context: "+
			"reduce(ref=%q, query=<jq/sql/... query>, engine=<engine>) for a declarative reduction, or "+
			"reduce(ref=%q, code=<python that reads /app/input>) for arbitrary logic.",
			toolName, sum.Bytes, ref, ref, ref),
	}
	if p := s.refPreview(ref); p != nil {
		out["preview"] = p
	}
	return toolResult(out)
}

// refPreview computes the structural preview of a stored ref's payload.
func (s *Server) refPreview(ref refstore.Ref) map[string]any {
	if s.budget.Store == nil {
		return nil
	}
	if data, _, ok := s.budget.Store.Get(ref); ok { // preview is gateway-internal; owner enforced at reduce
		return structuralPreview(data)
	}
	return nil
}

// bumpUsage records one successful invocation of a tool, by namespaced name.
func (s *Server) bumpUsage(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toolUsage == nil {
		s.toolUsage = map[string]int{}
	}
	s.toolUsage[name]++
}

// callTool is the invoke half of the off-context tool surface: a tool discovered
// via find_tools isn't in tools/list, so the agent reaches it here by name +
// arguments. The discovery/invocation gate is enforced in invokeUpstream.
func (s *Server) callTool(ctx context.Context, args json.RawMessage) map[string]any {
	var in struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.Name == "" {
		return toolError("call_tool requires a tool name; discover tools with find_tools")
	}
	if res, ok := s.invokeUpstream(ctx, in.Name, in.Arguments); ok {
		return res
	}
	return toolError("unknown tool %q; discover tools with find_tools", in.Name)
}
