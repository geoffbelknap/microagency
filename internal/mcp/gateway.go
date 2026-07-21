package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// upstream is one registered MCP server in the index. ENABLED means it's
// connected and its tools are invocable; otherwise it's DISCOVERED — metadata the
// agent can find but NOT call until the operator enables it. This is the
// discovery/invocation gate: the index may be broader than what's invocable, but
// call_tool only runs enabled upstreams (ASK: trust is explicit, never
// self-elevated).
type upstream struct {
	conn       *gateway.Upstream // connection config (URL, token, client)
	tools      []gateway.Tool    // advertised tools (un-namespaced)
	enabled    bool              // connected → invocable
	provenance string            // "preloaded" | "catalog" | "discovered"
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
func (s *Server) AddUpstream(ctx context.Context, u *gateway.Upstream, opts ...UpstreamOption) error {
	if u.Name == "" || strings.Contains(u.Name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", u.Name, nsSep)
	}
	if s.hasUpstream(u.Name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: upstream %q already registered", u.Name)
	}
	_ = u.Initialize(ctx) // best-effort; some servers don't require it before tools/list
	tools, err := u.ListTools(ctx)
	if err != nil {
		return err
	}
	return s.registerUpstream(u.Name, &upstream{conn: u, tools: tools, enabled: true, provenance: "preloaded", minimizeSuggested: suggestionFor(tools)}, opts...)
}

// AddDiscovered registers an upstream's tools WITHOUT connecting — discovered
// metadata (a catalog entry or pre-discovery). The tools enter the index and are
// findable, but call_tool refuses them until EnableUpstream connects it. The
// connection config is retained so enabling is a one-step operator action.
func (s *Server) AddDiscovered(u *gateway.Upstream, tools []gateway.Tool, provenance string, opts ...UpstreamOption) error {
	if u.Name == "" || strings.Contains(u.Name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", u.Name, nsSep)
	}
	if provenance == "" {
		provenance = "discovered"
	}
	return s.registerUpstream(u.Name, &upstream{conn: u, tools: tools, enabled: false, provenance: provenance, minimizeSuggested: suggestionFor(tools)}, opts...)
}

// DiscoverUpstream connects once to fetch an upstream's tool metadata and
// registers it DISCOVERED (not enabled): the agent can find its tools but not
// invoke them until EnableUpstream authorizes it. (A catalog feed would instead
// call AddDiscovered with metadata it already holds, without connecting.)
func (s *Server) DiscoverUpstream(ctx context.Context, u *gateway.Upstream, opts ...UpstreamOption) error {
	if u.Name == "" || strings.Contains(u.Name, nsSep) {
		return fmt.Errorf("gateway: upstream name %q must be non-empty and not contain %q", u.Name, nsSep)
	}
	if s.hasUpstream(u.Name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: upstream %q already registered", u.Name)
	}
	_ = u.Initialize(ctx)
	tools, err := u.ListTools(ctx)
	if err != nil {
		return err
	}
	return s.registerUpstream(u.Name, &upstream{conn: u, tools: tools, enabled: false, provenance: "discovered", minimizeSuggested: suggestionFor(tools)}, opts...)
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
func (s *Server) RebindUpstream(ctx context.Context, name string, u *gateway.Upstream) error {
	if !s.hasUpstream(name) { // fast-fail before the network round-trip
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	_ = u.Initialize(ctx)
	tools, err := u.ListTools(ctx)
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
	rec.conn = u
	rec.tools = tools
	rec.minimizeSuggested = sug
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
		info := UpstreamInfo{Name: name, URL: rec.conn.URL, State: state, Provenance: rec.provenance, ReadOnly: rec.readOnly, Owner: rec.owner, Tools: len(rec.tools),
			Minimize: json.RawMessage(explicit), MinimizeEffective: json.RawMessage(effective)}
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

// invokeUpstream resolves a namespaced tool, GATES on enabled, and proxies to the
// upstream. ok is false only when the name isn't namespaced (so the caller can
// fall back to "unknown tool"); a disabled or unknown-upstream tool returns a tool
// error with ok=true. This is the single invocation gate both call_tool and a
// direct namespaced call go through.
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
	upHost := hostFromURL(rec.conn.URL) // the egress target for calls that reach the upstream
	// Tier 1 — pre-egress write guard. If this is a write and its arguments don't
	// satisfy the tool's retained schema, fail CLOSED: no malformed mutation is sent,
	// and the agent gets the full spec to retry (it may have seen only a find_tools
	// digest). Reads skip this — Tier 2 covers them after the fact, without ever
	// hard-blocking on a false positive.
	spec, haveSpec := findTool(rec.tools, tool)
	// Read-only gate: a read-only upstream refuses writes (and unclassifiable tools,
	// which default to write). Enforced OUTSIDE the agent, at the single invocation
	// gate — the agent can't widen it.
	if rec.readOnly && (!haveSpec || isWriteTool(spec)) {
		s.recordProxy(ctx, runID, upName, tool, args, 0, start, fmt.Errorf("read-only upstream: write refused"), budget.Outcome{}, "", 0)
		return toolError("upstream %q is READ-ONLY; the write/destructive tool %q is refused. Ask the operator to allow writes on this upstream if this is intended.", upName, name), true
	}
	if haveSpec && isWriteTool(spec) {
		if gaps := schemaGaps(spec.InputSchema, args); len(gaps) > 0 {
			s.recordProxy(ctx, runID, upName, tool, args, 0, start, fmt.Errorf("pre-egress schema block: %s", strings.Join(gaps, "; ")), budget.Outcome{}, "", 0)
			return schemaBlockResult(name, spec, gaps), true
		}
	}
	// Reads run through the in-flight cache: a slow read is decoupled from the
	// caller's request context (a client-timeout cancel won't abort near-done work,
	// and an identical retry collects the cached result), and identical concurrent
	// reads share one execution. Writes — and unclassifiable tools, defaulted to
	// write — run under the caller context: a cancel aborts, and nothing continues in
	// the background that could commit after the client stopped waiting.
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
			s.recordProxy(ctx, runID, upName, tool, args, 0, start, err, budget.Outcome{}, upHost, 0)
			return toolError("upstream %q: still running after the client stopped waiting; the call was not aborted — retry to collect the result", upName), true
		}
	}
	if err != nil {
		s.recordProxy(ctx, runID, upName, tool, args, len(res), start, err, budget.Outcome{}, upHost, 0)
		return toolError("upstream %q: %v", upName, err), true
	}
	var passthrough map[string]any
	if err := json.Unmarshal(res, &passthrough); err != nil {
		s.recordProxy(ctx, runID, upName, tool, args, len(res), start, err, budget.Outcome{}, upHost, 0)
		return toolError("upstream %q: malformed result: %v", upName, err), true
	}
	s.bumpUsage(name) // a successful call — a find_tools ranking signal
	// Reference-by-default: a large result is held off-context as a handle the agent
	// reduces, not flooded into context. Errors and small results pass through inline.
	if s.budget.Store != nil && !resultIsError(passthrough) {
		payload, rehydrated := resultPayload(passthrough), false
		// Offload neutralization: some upstreams return an off-platform URL in place
		// of a large payload (e.g. LimaCharlie exporting to a public GCS bucket). That
		// pointer defeats cred-blindness and minimization — the real bytes never enter
		// the governed pipeline, and a bare public URL is an unmediated egress
		// capability handed to the agent. Fetch it host-side and treat the bytes as the
		// real result; the agent never sees the URL. The offload fields live in the
		// extracted payload (upstreams wrap results in an MCP content text block).
		if link := offloadURL(payload); link != "" {
			data, ferr := s.fetchOffload(ctx, link)
			if ferr != nil {
				s.recordProxy(ctx, runID, upName, tool, args, 0, start, fmt.Errorf("offload rehydrate: %w", ferr), budget.Outcome{}, upHost, 0)
				return toolError("upstream %q returned an off-platform result link microagency could not retrieve (%v); the raw URL is withheld", upName, ferr), true
			}
			payload, rehydrated = string(data), true
		}
		// A truncated / malformed payload is a NOTICE, not data. Some upstreams cut a
		// too-large response mid-structure and append a "narrow your query" marker
		// (Cloudflare's MCP does). Parking that behind a ref buries the guidance: the
		// agent's reduce then fails to PARSE the broken bytes instead of reading the
		// message. Surface the notice inline instead. Only fires when the payload
		// claims to be JSON but doesn't parse, or carries a truncation marker — a real
		// prose document (which doesn't claim to be JSON) still refs normally.
		if notice, ok := truncatedNotice(payload); ok {
			s.recordProxy(ctx, runID, upName, tool, args, len(notice), start, nil, budget.Outcome{}, upHost, 0)
			return truncatedResult(notice), true
		}
		// Gate on the LARGER of the extracted payload and the full upstream result.
		// The inline path returns the whole passthrough (len(res) bytes); resultPayload
		// can extract LESS than that (a compact structuredContent beside a large
		// content[].text — Notion page fetches), so measuring only the extraction let
		// large results ride inline, defeating reference-by-default. A rehydrated
		// result replaces the passthrough, so it's measured by its own size, not res.
		if len(payload) > s.budget.MaxBytes || (!rehydrated && len(res) > s.budget.MaxBytes) {
			// Store the extracted payload when it kept the bulk (clean data for reduce);
			// if the extraction is a small fraction of the full result, the extraction
			// dropped data — ref the full result instead so nothing is lost behind the ref.
			stored := payload
			if !rehydrated && len(payload) < len(res)/2 {
				stored = string(res)
			}
			ref, sum := s.budget.Store.Put(stored, principalOf(ctx).Subject)
			s.recordProxy(ctx, runID, upName, tool, args, sum.Bytes, start, nil, budget.Outcome{Reffed: true, Ref: ref, Summary: sum}, upHost, 0)
			return s.refHandleResult(ref, sum, name), true
		}
		if rehydrated { // small enough to inline, but return the DATA, never the offload URL
			s.recordProxy(ctx, runID, upName, tool, args, len(payload), start, nil, budget.Outcome{}, upHost, 0)
			return rehydratedResult(payload), true
		}
	}
	// Tier 2 — on an upstream tool error, append the tool's full description +
	// inputSchema so a retry is informed (the failure may be a semantic one the JSON
	// schema can't express, e.g. a malformed DSL string). Applies to reads and writes.
	if resultIsError(passthrough) && haveSpec {
		passthrough = attachToolSpec(passthrough, name, spec)
	}
	// Field-level minimization: scrub sensitive VALUES out of a small inline result
	// before it enters model context — the fine-grained complement to
	// reference-by-default (which only parks LARGE results). No-op unless a minimizer
	// and a policy are configured for this upstream. Fails closed: a minimizer error
	// withholds the result rather than emit it un-minimized.
	scrubbed, alerts, protected, merr := s.scrubInbound(ctx, upName, tool, passthrough)
	if merr != nil {
		s.recordProxy(ctx, runID, upName, tool, args, 0, start, fmt.Errorf("minimize: %w", merr), budget.Outcome{}, upHost, 0)
		return toolError("upstream %q: field minimization failed; result withheld", upName), true
	}
	s.recordProxy(ctx, runID, upName, tool, args, len(res), start, nil, budget.Outcome{}, upHost, protected, minimizeAlertEvents(alerts)...)
	return scrubbed, true
}

// offloadURL returns the URL an upstream substituted for a large payload — an
// off-platform "your data is at this link" pointer — or "" if the payload isn't
// one. payload is the EXTRACTED result data (resultPayload output), since upstreams
// wrap results in an MCP content text block and the offload fields live inside it.
// It matches only unambiguous offload field names (not a generic "url"/"link" a
// tool might legitimately return as data), so a match means "the real payload lives
// out-of-band," which the proxy then rehydrates rather than leak.
func offloadURL(payload string) string {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return ""
	}
	for _, k := range []string{"resource_link", "download_url", "artifact_url", "signed_url"} {
		if v, ok := m[k].(string); ok && (strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")) {
			return v
		}
	}
	return ""
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

// rehydratedResult wraps a small rehydrated offload payload as a tool result (the
// large case returns a ref instead). Parses JSON when possible so the agent gets
// structure, not a blob.
func rehydratedResult(payload string) map[string]any {
	var v any
	if json.Unmarshal([]byte(payload), &v) == nil {
		return toolResult(map[string]any{"rehydrated_from_offload": true, "data": v})
	}
	return toolResult(map[string]any{"rehydrated_from_offload": true, "data": payload})
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

// hostOf returns the host[:port] of a URL, for the egress record. "" on parse error.
func hostFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return ""
}

func resultIsError(result map[string]any) bool {
	e, _ := result["isError"].(bool)
	return e
}

// resultPayload extracts the DATA an MCP tool result carries — the bare rows, so a
// reduce queries the array directly. It prefers structuredContent (already parsed),
// else pulls the JSON out of the text content (many data tools wrap rows in a
// human-readable preamble and XPIA "untrusted-data" tags). Falls back to the whole
// result. This is what the budget gate measures and what reduce queries.
// truncationMarkers are the machine-generated "I cut this off" strings some
// upstreams append when a response exceeds their output cap. Matched
// case-insensitively; the dash/bracket wrapping keeps them specific enough not to
// fire on prose that merely uses the word "truncated".
var truncationMarkers = []string{"--- truncated", "truncated ---", "[truncated", "response truncated", "output truncated"}

// truncatedNotice reports whether payload is a truncation/notice rather than the
// clean data the ref/reduce path assumes, returning the message to surface. It fires
// on (a) a known truncation marker in the tail, or (b) a payload that CLAIMS to be
// JSON (starts with { or [) but does not parse — a response cut mid-structure.
//
// Well-formed JSON is exempt first: a complete JSON result is data even when a
// string value inside it ends with a phrase like "...output truncated" (a
// log-search hit, say), so the marker there is content, not an appended cut notice
// — flagging it would DISCARD a valid result. A genuine truncation cut mid-structure
// won't parse (or has the marker appended after the close, which also won't parse),
// so it still falls to the branches below. A non-JSON prose document with no marker
// is likewise never flagged, so real documents ref normally.
func truncatedNotice(payload string) (string, bool) {
	if tr := strings.TrimSpace(payload); len(tr) > 0 && (tr[0] == '{' || tr[0] == '[') && json.Valid([]byte(tr)) {
		return "", false
	}
	low := strings.ToLower(payload)
	for _, m := range truncationMarkers {
		// A real truncation marker is APPENDED at the END of the payload. A document
		// that merely MENTIONS the marker (e.g. a backlog page documenting the
		// Cloudflare incident) has it mid-content — so only treat it as truncation
		// when it sits in the tail. Use the last occurrence + a tight tail window.
		// (This runs before the generic invalid-JSON message so the upstream's own
		// guidance is surfaced even for JSON cut mid-structure with a marker.)
		if i := strings.LastIndex(low, m); i >= 0 && len(payload)-i <= 512 {
			return truncationTail(payload, i), true
		}
	}
	if tr := strings.TrimSpace(payload); len(tr) > 0 && (tr[0] == '{' || tr[0] == '[') {
		return "the upstream returned malformed or truncated JSON (it did not parse)", true
	}
	return "", false
}

// truncationTail returns the marker's line plus a bounded amount of following text
// (the upstream's guidance), so a huge truncated blob doesn't ride inline behind the
// small notice.
func truncationTail(payload string, at int) string {
	start := strings.LastIndexByte(payload[:at], '\n') + 1
	tail := strings.TrimSpace(payload[start:])
	if len(tail) > 500 {
		tail = tail[:500]
	}
	return tail
}

// truncatedResult surfaces an upstream truncation notice inline (small, actionable)
// instead of parking a broken payload behind a reference.
func truncatedResult(msg string) map[string]any {
	return toolResult(map[string]any{
		"truncated":       true,
		"upstream_notice": msg,
		"note":            "The upstream truncated or malformed this result, so microagency did not park it as a reference (reduce would fail to parse it). Request less data — narrow the query or add a limit — and retry.",
	})
}

func resultPayload(result map[string]any) string {
	if sc, ok := result["structuredContent"]; ok {
		if b, err := json.Marshal(sc); err == nil && len(b) > 2 { // not null/"" /{}
			return string(b)
		}
	}
	if content, ok := result["content"].([]any); ok {
		var sb strings.Builder
		for _, c := range content {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := m["type"].(string); t == "text" {
				if txt, _ := m["text"].(string); txt != "" {
					sb.WriteString(txt)
				}
			}
		}
		if sb.Len() > 0 {
			return unwrapData(sb.String())
		}
	}
	b, _ := json.Marshal(result)
	return string(b)
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

func unwrapData(s string) string {
	out := extractJSON(s)
	if len(s)-len(out) > maxUnwrapFraming {
		return s // extraction discarded more than framing — that text WAS the payload
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &obj) != nil {
		return out // not an object (already a bare array, or plain text)
	}
	best := ""
	for _, v := range obj {
		var str string
		if json.Unmarshal(v, &str) != nil {
			continue // field value isn't a string
		}
		inner := extractJSON(str)
		if inner == str || !json.Valid([]byte(inner)) {
			continue // string holds no embedded JSON
		}
		if len(str)-len(inner) > maxUnwrapFraming {
			continue // the field's text is content, not framing around the JSON
		}
		if strings.HasPrefix(inner, "[") {
			return inner // the rows array — done
		}
		if best == "" {
			best = inner
		}
	}
	if best != "" {
		return best
	}
	return out
}

// extractJSON returns the outermost balanced JSON array/object embedded in s
// (skipping any preamble/wrapper), or s unchanged if none parses. String-aware so
// brackets inside string values don't throw off the balance.
func extractJSON(s string) string {
	start := strings.IndexAny(s, "[{")
	if start < 0 {
		return s
	}
	open := s[start]
	close := byte(']')
	if open == '{' {
		close = '}'
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case close:
			if depth--; depth == 0 {
				if cand := s[start : i+1]; json.Valid([]byte(cand)) {
					return cand
				}
				return s
			}
		}
	}
	return s
}

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

// structuralPreview returns a STRUCTURE-ONLY glimpse of a reffed payload — its shape,
// field names, and counts — so the agent can often decide its next step without a
// reduce round-trip. It never includes VALUES: the whole point of a ref is to keep
// the raw (often sensitive) data OUT of context, so leaking even a sample row would
// defeat minimization. A JSON array reports its count + the first item's field names
// (the row schema); an object reports its keys; anything else reports size only.
func structuralPreview(payload string) map[string]any {
	tr := strings.TrimSpace(payload)
	if len(tr) == 0 {
		return nil
	}
	switch tr[0] {
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal([]byte(tr), &arr) == nil {
			p := map[string]any{"kind": "array", "count": len(arr)}
			if len(arr) > 0 {
				if ks := jsonKeys(arr[0]); ks != nil {
					p["item_keys"] = ks
				}
			}
			return p
		}
	case '{':
		if ks := jsonKeys(json.RawMessage(tr)); ks != nil {
			return map[string]any{"kind": "object", "keys": ks}
		}
	}
	return map[string]any{"kind": "text", "chars": len(payload), "lines": strings.Count(payload, "\n") + 1}
}

// jsonKeys returns the sorted top-level field names of a JSON object (schema, not
// values), capped so the preview stays small. Returns nil if raw isn't an object.
func jsonKeys(raw json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	if len(ks) > 50 {
		ks = ks[:50]
	}
	return ks
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
