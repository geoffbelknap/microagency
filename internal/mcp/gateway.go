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

	"microagency/internal/auth"
	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/safedial"
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
	// privateDestination is set when the operator declared this connection's own
	// endpoint reachable even though it is loopback or otherwise private — a
	// sidecar connector, or an internal MCP server beside the gateway. It is
	// operator-only: a principal-created connection can never carry it, so the
	// SSRF guard still covers every URL that came from a user.
	privateDestination bool
	// auditFullArgs opts this connection up to FULL argument capture in the
	// audit log on a multi-principal gateway, where the default is structure +
	// digest (see argcapture.go). Inert on single-principal deployments, which
	// always capture full arguments. Disclosed in UpstreamList and by doctor.
	auditFullArgs bool
	// grants are immutable, operator-owned semantic capabilities. An empty set
	// preserves the standard connection posture; high-assurance mode requires a
	// matching grant and therefore treats empty as deny-all.
	grants []OperationGrant
	// owner scopes this connection to ONE authenticated principal, by canonical
	// identity key (auth.PrincipalKey — issuer#subject, never a bare subject).
	// "" = shared: every authenticated user of this gateway may find and invoke it.
	// Non-empty: the connection — and the credential it holds — is invisible and
	// uninvocable to every other principal, enforced at find_tools and at the
	// invocation gate. This is what keeps one user's OAuth grant from being
	// exercised by another user of a shared (--issuer) deployment, including a
	// caller whose token asserts the same subject under a different issuer.
	owner string
	// selfService marks a principal-created connection. Its ownership is immutable:
	// an operator may disable, revoke, or delete it, but cannot transfer an OAuth
	// grant to a different identity. template records which approved template
	// admitted it. revoked keeps the record visible to the operator while making it
	// absent from every agent index and impossible to invoke.
	selfService bool
	template    string
	revoked     bool
	// label is a short human-meaningful name for THIS connection — "production",
	// "staging" — surfaced as its own field in the agent's view of every tool the
	// connection exposes. It is what makes two connections instantiated from one
	// template choosable on purpose rather than by coin flip (see ambiguity.go).
	// Held to an identifier's charset by validateConnectionLabel, because it is
	// caller-supplied text that lands in a model's context.
	label string
	// delegation, when set, makes this a google-dwd connection: per call, the
	// source derives a short-lived upstream token acting as the CALLER's
	// provider-verified email, so the provider's own ACLs trim results.
	// Callers with no verified email cannot see or invoke the connection.
	delegation *auth.DelegatedTokenSource
	// authGeneration changes on operator revocation. Self-service refresh writers
	// and reauthorization callbacks may commit only against the generation they
	// started from, so an in-flight operation cannot resurrect a revoked grant.
	authGeneration uint64
	// minimizeSuggested is the minimization policy auto-detected from this upstream's
	// tool schemas, computed ONCE when tools are (re)loaded and cached here. Computing
	// it lazily in UpstreamList would rescan attacker-controlled tool metadata on every
	// /admin request under the lock — a DoS vector — so it is done at discovery instead.
	minimizeSuggested json.RawMessage
	// lastOK/lastErr track the most recent invocation's outcome so the operator can
	// see a dead or erroring upstream instead of discovering it one failed call at a
	// time. Mutated under s.reg.mu, like the other record fields.
	lastOK    time.Time
	lastErr   string
	lastErrAt time.Time
}

// recordUpstreamHealth stamps the outcome of the most recent call to name, for
// operator visibility (UpstreamList). A client cancellation is not a failure and
// isn't recorded here.
func (s *Server) recordUpstreamHealth(name string, callErr error) {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
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

// WithOwner scopes the connection to the principal with the given canonical
// identity key (auth.PrincipalKey — issuer#subject).
func WithOwner(key string) UpstreamOption { return func(u *upstream) { u.owner = key } }

// WithSelfService marks a connection as created by its owning principal from an
// operator-approved template.
func WithSelfService(template string) UpstreamOption {
	return func(u *upstream) { u.selfService, u.template = true, template }
}

// WithPrivateDestination permits this connection to dial its own endpoint when
// that endpoint is private. Only the operator admin path may set it; see
// registerUpstream, which refuses it together with WithSelfService.
func WithPrivateDestination() UpstreamOption {
	return func(u *upstream) { u.privateDestination = true }
}

// WithRevoked restores a persisted revoked record without restoring a credential.
func WithRevoked() UpstreamOption { return func(u *upstream) { u.revoked = true } }

// WithLabel names the connection for the humans and agents that read its tools.
// The label must already have passed validateConnectionLabel; registration paths
// that accept caller input validate before constructing the option.
func WithLabel(label string) UpstreamOption { return func(u *upstream) { u.label = label } }

// registerUpstream atomically registers rec under name, failing if the name is
// already taken. The existence check and the write happen under ONE lock
// acquisition — two concurrent adds of the same name can't both pass a separate
// check and silently overwrite each other.
func (s *Server) registerUpstream(name string, u *upstream, opts ...UpstreamOption) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	if s.reg.conns == nil {
		s.reg.conns = map[string]*upstream{}
	}
	if _, ok := s.reg.conns[name]; ok {
		return fmt.Errorf("gateway: upstream %q already registered", name)
	}
	for _, opt := range opts {
		opt(u)
	}
	// A private destination is operator authority. Refuse the combination at
	// REGISTRATION rather than at dial time, so no self-service path — template,
	// reauthorize, or a future one — can admit a principal-supplied URL that
	// reaches inside the deployment's own network.
	if u.privateDestination && u.selfService {
		return fmt.Errorf("gateway: upstream %q: a self-service connection may not declare a private destination", name)
	}
	if u.enabled && !u.revoked {
		if err := s.validateMediationEndpoint(u.conn.Endpoint()); err != nil {
			return fmt.Errorf("gateway: enforced mediation refuses upstream %q: %w", name, err)
		}
	}
	s.reg.conns[name] = u
	return nil
}

func (s *Server) hasUpstream(name string) bool {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	_, ok := s.reg.conns[name]
	return ok
}

// snapshotUpstream returns a consistent copy of the named record's fields, taken
// under the lock. s.reg.mu guards the map AND the record fields — Enable/Rebind/
// SetUpstreamReadOnly mutate records in place under the lock — so readers must
// never hold a bare *upstream across unlocked work. The copy is safe to use
// lock-free: conn is immutable once wired, and tools is only ever replaced
// wholesale, never mutated in place.
func (s *Server) snapshotUpstream(name string) (upstream, bool) {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
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
	if rec.revoked {
		return fmt.Errorf("gateway: upstream %q is revoked; reauthorize it before enabling", name)
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
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	cur, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: upstream %q was removed while enabling", name)
	}
	if cur.conn != rec.conn {
		return fmt.Errorf("gateway: upstream %q changed while enabling; retry", name)
	}
	if err := s.validateMediationEndpoint(cur.conn.Endpoint()); err != nil {
		return fmt.Errorf("gateway: enforced mediation refuses upstream %q: %w", name, err)
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
	return s.rebindUpstream(ctx, name, conn, nil)
}

func (s *Server) rebindUpstream(ctx context.Context, name string, conn upstreamConn, expectedGeneration *uint64) error {
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
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: upstream %q was removed while rebinding", name)
	}
	if expectedGeneration != nil && rec.authGeneration != *expectedGeneration {
		return fmt.Errorf("gateway: upstream %q authorization changed while rebinding; start again", name)
	}
	if err := s.validateMediationEndpoint(conn.Endpoint()); err != nil {
		return fmt.Errorf("gateway: enforced mediation refuses upstream %q: %w", name, err)
	}
	rec.conn = conn
	rec.tools = tools
	rec.minimizeSuggested = sug
	if rec.revoked {
		rec.enabled = true
	}
	rec.revoked = false
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
	if rec.revoked {
		return fmt.Errorf("gateway: upstream %q is revoked; reauthorize it before refreshing", name)
	}
	_ = rec.conn.Initialize(ctx)
	tools, err := rec.conn.ListTools(ctx)
	if err != nil {
		return err
	}
	sug := suggestionFor(tools) // compute off the lock (scans tool metadata)
	// Commit under the lock, re-validating against the live record: it may have been
	// removed or rebound to a new connection while we were on the network.
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	cur, ok := s.reg.conns[name]
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
	State      string `json:"state"`      // "enabled" | "discovered"
	Provenance string `json:"provenance"` // preloaded | catalog | discovered
	ReadOnly   bool   `json:"read_only"`  // writes refused (least-privilege)
	// PrivateDestination reports an operator-declared connection whose own
	// endpoint is private (a sidecar or an internal server beside the gateway).
	PrivateDestination bool   `json:"private_destination,omitempty"`
	Owner              string `json:"owner,omitempty"` // canonical principal key (issuer#subject) this connection is scoped to; "" = shared
	// AuditFullArgs: this connection is opted up to full argument capture in the
	// audit log on a multi-principal gateway (default there: structure + digest).
	AuditFullArgs bool   `json:"audit_full_args,omitempty"`
	SelfService   bool   `json:"self_service,omitempty"`
	Template      string `json:"template,omitempty"`
	Revoked       bool   `json:"revoked,omitempty"`
	// Label is the connection's human-meaningful name, or empty when unset.
	Label        string   `json:"label,omitempty"`
	Tools        int      `json:"tools"` // count of advertised tools (shown per connection in the console)
	GrantCount   int      `json:"grant_count,omitempty"`
	GrantDigests []string `json:"grant_digests,omitempty"`
	// Strategy is how a calling principal maps to upstream authority: static,
	// per-user-oauth, or google-dwd. Delegation carries a google-dwd
	// connection's non-secret config; the key itself is never exposed.
	Strategy   string          `json:"strategy"`
	Delegation *DelegationInfo `json:"delegation,omitempty"`
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

// SetUpstreamOwner scopes (or, with "", un-scopes) a registered connection to
// one principal's canonical identity key (auth.PrincipalKey — issuer#subject).
// A bare subject is refused: it matches no authenticated caller, so accepting
// it would silently scope the connection to nobody. Errors if the upstream is
// unknown.
func (s *Server) SetUpstreamOwner(name, owner string) error {
	if owner != "" {
		if _, _, err := auth.SplitPrincipalKey(owner); err != nil {
			return fmt.Errorf("gateway: owner: %w", err)
		}
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	if rec.selfService && owner != rec.owner {
		return fmt.Errorf("gateway: self-service upstream %q ownership is immutable; revoke or delete it instead", name)
	}
	rec.owner = owner
	return nil
}

// SetUpstreamLabel sets (or, with "", clears) a connection's human-meaningful
// label. The label is REFUSED rather than rewritten when it cannot be expressed
// in the label charset, so the label an author sets is the label they read back.
// Errors if the upstream is unknown.
func (s *Server) SetUpstreamLabel(name, label string) error {
	checked, err := validateConnectionLabel(label)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.label = checked
	return nil
}

// DisableUpstream makes a connection non-invocable while retaining its indexed
// metadata and credential. Revoked connections remain revoked. A delegated
// connection's derived-token cache is dropped, so no derived credential
// outlives the decision inside the gateway.
func (s *Server) DisableUpstream(name string) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.enabled = false
	if rec.delegation != nil {
		rec.delegation.DropCache()
	}
	return nil
}

// RevokeUpstream makes a connection invisible and non-invocable immediately. The
// caller separately deletes its durable credential before reporting success. A
// delegated connection's derived-token cache is dropped as well.
func (s *Server) RevokeUpstream(name string) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.enabled = false
	rec.revoked = true
	rec.authGeneration++
	if rec.delegation != nil {
		rec.delegation.DropCache()
	}
	return nil
}

// SetUpstreamReadOnly toggles an upstream's read-only restriction. Errors if the
// upstream is unknown.
func (s *Server) SetUpstreamReadOnly(name string, ro bool) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.readOnly = ro
	return nil
}

// SetUpstreamAuditFullArgs toggles a connection's opt-up to full argument
// capture in the audit log on a multi-principal gateway (the default there is
// structure + digest). Errors if the upstream is unknown.
func (s *Server) SetUpstreamAuditFullArgs(name string, on bool) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.auditFullArgs = on
	return nil
}

// SetUpstreamGrants atomically replaces an upstream's operation authority.
// Definitions are validated before the live record changes; duplicate IDs or
// duplicate principal/campaign/tool tuples are refused as ambiguous.
func (s *Server) SetUpstreamGrants(name string, grants []OperationGrant) error {
	validated := make([]OperationGrant, len(grants))
	seenID, seenTuple := map[string]bool{}, map[string]bool{}
	for i, grant := range grants {
		var err error
		validated[i], err = validateOperationGrant(grant, name)
		if err != nil {
			return fmt.Errorf("grant %d: %w", i+1, err)
		}
		tuple := validated[i].Principal + "\x00" + validated[i].Campaign + "\x00" + validated[i].Tool
		if seenID[validated[i].ID] || seenTuple[tuple] {
			return fmt.Errorf("grant %d duplicates an id or principal/campaign/operation tuple", i+1)
		}
		seenID[validated[i].ID], seenTuple[tuple] = true, true
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	rec.grants = validated
	return nil
}

// matchingGrant selects the grant bound to the caller's canonical identity key
// (issuer#subject), campaign, and exact tool. Grants store the composite key,
// so a grant written for one issuer's subject never matches the same subject
// asserted by another issuer.
func matchingGrant(rec upstream, callerKey, campaign, tool string) (OperationGrant, bool) {
	for _, grant := range rec.grants {
		if grant.Principal == callerKey && grant.Campaign == campaign && grant.Tool == tool {
			return grant, true
		}
	}
	return OperationGrant{}, false
}

// UpstreamList returns the registered upstreams (enabled and discovered), sorted.
func (s *Server) UpstreamList() []UpstreamInfo {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	out := make([]UpstreamInfo, 0, len(s.reg.conns))
	for name, rec := range s.reg.conns {
		state := "discovered"
		if rec.enabled {
			state = "enabled"
		}
		if rec.revoked {
			state = "revoked"
		}
		explicit, hasExplicit := s.reg.policies[name]
		effective := explicit
		if !hasExplicit && s.reg.secureDefault {
			effective = defaultMinimizePolicyJSON // secure-by-default
		}
		info := UpstreamInfo{Name: name, URL: rec.conn.Endpoint(), State: state, Provenance: rec.provenance, ReadOnly: rec.readOnly, PrivateDestination: rec.privateDestination, Owner: rec.owner, AuditFullArgs: rec.auditFullArgs, SelfService: rec.selfService, Template: rec.template, Revoked: rec.revoked, Label: rec.label, Tools: len(rec.tools), GrantCount: len(rec.grants), GrantDigests: sortedGrantDigests(rec.grants),
			Strategy: StrategyStatic, Minimize: json.RawMessage(explicit), MinimizeEffective: json.RawMessage(effective)}
		switch {
		case rec.delegation != nil:
			info.Strategy = StrategyGoogleDWD
			info.Delegation = &DelegationInfo{
				ClientEmail: rec.delegation.ClientEmail(), TokenEndpoint: rec.delegation.TokenEndpoint(),
				Scopes: rec.delegation.Scopes(), KeyConfigured: true,
				DiscoverySubject: rec.delegation.DiscoverySubject(),
			}
		case rec.selfService:
			info.Strategy = StrategyPerUserOAuth
		}
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
// tools from the index — and, for a delegated connection, its derived-token
// cache.
func (s *Server) RemoveUpstream(name string) bool {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return false
	}
	if rec.delegation != nil {
		rec.delegation.DropCache()
	}
	delete(s.reg.conns, name)
	return true
}

// indexedTools returns the searchable index FOR ONE PRINCIPAL, identified by
// canonical identity key: every registered upstream's tools that caller may
// see — shared connections plus the ones owned by that key — namespaced and
// tagged with enabled (invocable) + provenance. Kept OUT of tools/list so the
// model's context isn't flooded with the whole catalog. An owned connection
// never appears in another principal's index; the invocation gate enforces the
// same boundary, so this filter is minimization, not the only line of defense.
func (s *Server) indexedTools(callerKey string) []map[string]any {
	return s.indexedToolsFor(callerKey, "local")
}

func (s *Server) indexedToolsFor(callerKey, campaign string) []map[string]any {
	// Resolved before the lock: whether this caller has a provider-verified
	// email — the identity delegated (google-dwd) connections act as.
	delegationSubject := s.delegationSubjectForKey(callerKey)
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	var out []map[string]any
	// groups collects, per (template, upstream tool name), the entries a caller
	// would have to choose between. Grouping happens here, where the connection
	// record is in hand, so find_tools can warn about a tie at DISCOVERY time —
	// before the agent spends a call and meets the refusal.
	groups := map[string][]*indexCandidate{}
	for name, rec := range s.reg.conns {
		if !connectionVisibleTo(rec, callerKey, delegationSubject) {
			continue
		}
		for _, t := range rec.tools {
			if !s.toolIndexable(rec, t, callerKey, campaign) {
				continue
			}
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
				"usage":       s.reg.usage[full],
			}
			if rec.enabled && rec.readOnly && isWriteTool(t) {
				invocable = false
				m["read_only_blocked"] = true // the upstream is read-only; this write is refused
			}
			m["invocable"] = invocable
			// The label is its OWN field. It is never folded into the description,
			// because caller-supplied text that can extend or terminate surrounding
			// prose in the model's context is the thing a label must not be.
			if rec.label != "" {
				m["label"] = rec.label
			}
			if rec.template != "" && invocable {
				key := rec.template + "\x00" + t.Name
				groups[key] = append(groups[key], &indexCandidate{entry: m, label: rec.label})
			}
			out = append(out, m)
		}
	}
	markAmbiguousCandidates(groups)
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
	principal, campaign := callerKey(ctx), campaignOf(ctx)
	deny := func(connection, grantID, digest, reason string) (map[string]any, bool) {
		ledgerErr := s.refuseDecision(principal, campaign, connection, tool, grantID, digest, reason)
		s.recordGovernedDenial(ctx, connection, tool, grantID, digest, reason, ledgerErr)
		// One stable response covers an unknown connection, another principal's
		// hidden connection, an adjacent operation, and a malformed argument. The
		// operator ledger keeps the reason without becoming a caller oracle.
		return toolError("tool %q is not authorized for this caller", name), true
	}
	// A consistent SNAPSHOT of the record, not the live pointer: the gate below
	// reads enabled/readOnly/tools/conn across the whole (network-bound) call, and
	// an operator Enable/Rebind/SetUpstreamReadOnly mutates the live record under
	// the lock — reading it lock-free would race and could skip the read-only gate
	// or call through a half-swapped connection.
	rec, ok := s.snapshotUpstream(upName)
	if !ok {
		if s.highAssurance {
			return deny(upName, "", "", "connection or operation is not granted")
		}
		return toolError("unknown tool %q; discover tools with find_tools", name), true
	}
	governed := s.highAssurance || len(rec.grants) > 0
	grant, hasGrant := matchingGrant(rec, principal, campaign, tool)
	grantID, digest := "", ""
	if hasGrant {
		grantID = grant.ID
		digest, _ = grantDigest(grant)
	}
	// Ownership gate: a connection scoped to one principal is INVISIBLE to every
	// other — same error as an unregistered tool, so a probing caller can't even
	// learn the connection exists, let alone exercise its credential. Compared by
	// canonical identity key, so the same subject under a different issuer is
	// "every other", not the owner.
	if rec.owner != "" && rec.owner != principal {
		if governed {
			return deny(upName, grantID, digest, "caller does not own the connection")
		}
		return toolError("unknown tool %q; discover tools with find_tools", name), true
	}
	if rec.revoked {
		if governed {
			return deny(upName, grantID, digest, "connection authority is revoked")
		}
		return toolError("unknown tool %q; discover tools with find_tools", name), true
	}
	if !rec.enabled {
		if governed {
			return deny(upName, grantID, digest, "connection is not enabled")
		}
		return toolError("tool %q is discovered but not enabled; ask the operator to enable upstream %q", name, upName), true
	}
	// Ambiguity gate. A governed connection is exempt on BOTH branches: with a
	// matching grant the operator named this connection exactly, so no guess was
	// made; without one the governed denial below owns the response, and it must
	// stay opaque — naming sibling connections to an ungranted caller would turn
	// this refusal into the disclosure oracle the governed path exists to avoid.
	if !governed {
		if peers := s.indistinguishablePeers(principal, campaign, upName, rec, tool); len(peers) > 0 && !labelDistinguishes(rec.label, peers) {
			return ambiguousCallRefusal(name, upName, rec.template, tool, rec.label, rec.owner != "", peers), true
		}
	}
	// Restore any tokenized-field placeholders the model authored back to their real
	// values before this call is dialed (the return path for field minimization).
	// Scoped to this caller and THIS upstream: a placeholder from another upstream (or
	// another principal) stays inert, so a secret tokenized out of upstream X can't be
	// replayed by handing its placeholder to a different upstream. No-op unless a
	// minimizer previously tokenized a value the model is now echoing back here.
	args = s.resolveOutbound(ctx, upName, args)
	var evaluated *evaluatedGrant
	if governed {
		if !hasGrant {
			return deny(upName, "", "", "exact operation grant is absent")
		}
		if s.highAssurance && !grant.HighAssurance {
			return deny(upName, grantID, digest, "grant is not marked high assurance")
		}
		if rec.owner == "" && !grant.AllowShared {
			return deny(upName, grantID, digest, "shared connection credential is not explicitly granted")
		}
		spec, haveSpec := findTool(rec.tools, tool)
		if !haveSpec || (isHighAssuranceWriteTool(spec) && grant.Effect != effectWrite) || (!isHighAssuranceWriteTool(spec) && grant.Effect != effectRead) {
			return deny(upName, grantID, digest, "operation effect disagrees with retained tool authority")
		}
		if rec.readOnly && grant.Effect == effectWrite {
			return deny(upName, grantID, digest, "connection is read-only")
		}
		if policy := programPolicyOf(ctx); policy != nil {
			if _, allowed := policy.allowed[name]; !allowed || grant.Effect != effectRead {
				return deny(upName, grantID, digest, "governed program authority does not include the operation")
			}
		}
		if grant.Effect == effectWrite && len(grant.Resources) == 0 {
			return deny(upName, grantID, digest, "write operation has no explicit resource namespace")
		}
		if rec.owner == "" && grant.Effect == effectWrite {
			for _, resource := range grant.Resources {
				if !resource.SharedWritable {
					return deny(upName, grantID, digest, "shared writable namespace is not explicitly granted")
				}
			}
		}
		checked, err := evaluateOperationGrant(grant, principal, campaign, tool, args, time.Now())
		if err != nil {
			return deny(upName, grantID, digest, err.Error())
		}
		if err := s.authorizeDecision(checked, len(args), time.Now()); err != nil {
			s.recordGovernedDenial(ctx, upName, tool, grantID, digest, "decision ledger or budget refused crossing", err)
			return toolError("tool %q is not authorized for this caller", name), true
		}
		evaluated = &checked
	}
	// Delegated (google-dwd) connection: resolve the caller's provider-verified
	// email — the identity the upstream call will act as. A caller with none is
	// refused BEFORE any egress or token derivation, with an audited record; no
	// fallback identity is ever substituted. The resolved pair rides the
	// context so the connection's bearer derives for exactly this caller.
	delegated := ""
	if rec.delegation != nil {
		delegated = s.delegationSubject(ctx)
		if delegated == "" {
			runID := s.nextRunID()
			start := time.Now()
			out := proxyOutcome{
				result: toolError("upstream %q maps each caller to their own provider identity, and no provider-verified email is recorded for this caller, so the call is refused. Sign in through the gateway's federated sign-in (or ask the operator to enable it), then retry.", upName),
				err:    fmt.Errorf("delegated call without a provider-verified caller identity"),
			}
			s.recordProxy(ctx, runID, upName, tool, args, marshalLen(out.result), start, out, evaluated, rec.auditFullArgs, "")
			return out.result, true
		}
		ctx = withDelegatedCall(ctx, principal, delegated)
	}
	runID := s.nextRunID()
	start := time.Now()
	out := s.proxyCall(ctx, runID, start, upName, tool, name, rec, args, evaluated)
	// THE single audit record: every proxyCall outcome — refusal, error, ref,
	// inline, or success — lands here, so "every outcome is audited" is structural.
	// Delegated calls record the derived subject beside the caller identity.
	s.recordProxy(ctx, runID, upName, tool, args, marshalLen(out.result), start, out, evaluated, rec.auditFullArgs, delegated)
	return out.result, true
}

func (s *Server) recordGovernedDenial(ctx context.Context, upstream, tool, grantID, digest, reason string, ledgerErr error) {
	if ledgerErr != nil {
		reason += "; decision record: " + ledgerErr.Error()
	}
	s.putRun(s.nextRunID(), runRecord{
		Kind: "decision", Upstream: upstream, Tool: tool, User: callerKey(ctx),
		Campaign: campaignOf(ctx), GrantID: grantID, GrantDigest: digest,
		ExitCode: 1, AuditErr: reason,
	})
}

// proxyOutcome bundles a proxied call's result with everything recordProxy needs.
// proxyCall returns it on every path, so the single recordProxy in invokeUpstream
// can't be bypassed by a new early return.
type proxyOutcome struct {
	result               map[string]any
	rawBytes             int
	minimizedBytes       int
	err                  error
	outcome              budget.Outcome
	egressHost           string // "" when no egress reached the upstream (a pre-dial refusal)
	protected            int
	extra                []sandbox.AuditEvent
	transformRan         bool
	transformInputBytes  int
	transformOutputBytes int
	transformLatencyMs   int64
	transformStatus      string
}

// proxyCall dials the upstream (after the read-only and pre-egress write gates),
// then shapes the result — offload rehydration, truncation notice,
// reference-by-default parking, or field minimization — returning a proxyOutcome
// for each path. It performs the side effects that belong to a call (health,
// usage), but never records the audit line itself; that is invokeUpstream's job.
func (s *Server) proxyCall(ctx context.Context, runID string, start time.Time, upName, tool, name string, rec upstream, args json.RawMessage, evaluated *evaluatedGrant) proxyOutcome {
	upHost := hostFromURL(rec.conn.Endpoint()) // the egress target for calls that reach the upstream
	spec, haveSpec := findTool(rec.tools, tool)
	// A governed reduce program carries an exact, immutable per-run allowlist and
	// is read-only even when the underlying connection permits writes. Enforce
	// both properties inside the ordinary proxy path so the same owner/enable,
	// schema, credential, transport, result, and audit machinery remains the
	// single invocation path. State is reclassified on every call, closing the
	// validation-to-invocation race if an upstream refresh changes annotations.
	if policy := programPolicyOf(ctx); policy != nil {
		if _, allowed := policy.allowed[name]; !allowed {
			return proxyOutcome{
				result: toolError("tool %q is not granted to this governed program", name),
				err:    fmt.Errorf("governed program allowlist refused tool"),
			}
		}
		if !haveSpec || isWriteTool(spec) {
			return proxyOutcome{
				result: toolError("governed programs are read-only; tool %q is write/destructive or unclassifiable", name),
				err:    fmt.Errorf("governed program read-only policy refused tool"),
			}
		}
	}
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
	// near-done work, and identical concurrent reads share one execution — per
	// caller: the cache key carries the caller's identity, so callers never share
	// a cached result); writes and unclassifiable tools run under the caller
	// context (a cancel aborts, nothing commits in the background after the
	// client stopped waiting). Upstream session state is scoped to the caller
	// too, and the in-flight runner detaches from the caller context, so the
	// session scope — and, on a delegated connection, the caller's resolved
	// delegation identity — is re-attached inside the detached run.
	caller := callerKey(ctx)
	delegatedCaller, delegatedSubject := delegatedCallFrom(ctx)
	var res json.RawMessage
	var err error
	if !haveSpec || isWriteTool(spec) {
		res, err = rec.conn.CallTool(gateway.WithSessionScope(ctx, caller), tool, args)
	} else {
		var canceled bool
		res, err, canceled = s.inflight.do(ctx, inflightKey(caller, upName, tool, args), func(c context.Context) (json.RawMessage, error) {
			c = gateway.WithSessionScope(c, caller)
			if delegatedSubject != "" {
				c = withDelegatedCall(c, delegatedCaller, delegatedSubject)
			}
			return rec.conn.CallTool(c, tool, args)
		})
		if canceled {
			return proxyOutcome{result: toolError("upstream %q: still running after the client stopped waiting; the call was not aborted — retry to collect the result", upName), err: err, egressHost: upHost}
		}
	}
	s.recordUpstreamHealth(upName, err) // last-call health, for the operator view
	if err != nil {
		return proxyOutcome{result: toolError("upstream %q: %v", upName, err), rawBytes: len(res), err: err, egressHost: upHost}
	}
	if evaluated != nil && int64(len(res)) > evaluated.Grant.MaxResponseBytes {
		return proxyOutcome{
			result:   toolError("upstream %q response exceeded its operation grant and was withheld", upName),
			rawBytes: len(res), err: fmt.Errorf("operation grant response byte bound exceeded"), egressHost: upHost,
		}
	}
	var passthrough map[string]any
	if uerr := json.Unmarshal(res, &passthrough); uerr != nil {
		return proxyOutcome{result: toolError("upstream %q: malformed result: %v", upName, uerr), rawBytes: len(res), err: uerr, egressHost: upHost}
	}
	s.bumpUsage(name) // a successful call — a find_tools ranking signal
	if transform := transformOf(ctx); transform != nil && !resultIsError(passthrough) {
		return s.fusedProxyResult(ctx, runID, upName, tool, name, transform, passthrough, res, upHost, evaluated)
	}
	// Reference-by-default: a large result is held off-context as a handle the agent
	// reduces, not flooded into context. Errors and small results pass through inline.
	if s.budget.Store != nil && !resultIsError(passthrough) {
		payload, rehydrated := resultPayload(passthrough), false
		// Offload neutralization: some upstreams return an off-platform URL in place
		// of a large payload. That pointer defeats cred-blindness and minimization —
		// fetch it host-side and treat the bytes as the real result; the agent never
		// sees the URL.
		if link := offloadURL(payload); link != "" {
			data, ferr := s.fetchOffload(ctx, link, evaluated)
			if ferr != nil {
				return proxyOutcome{result: toolError("upstream %q returned an off-platform result link microagency could not retrieve (%v); the raw URL is withheld", upName, ferr), err: fmt.Errorf("offload rehydrate: %w", ferr), egressHost: upHost}
			}
			payload, rehydrated = string(data), true
		}
		// A truncated / malformed payload is a NOTICE, not data — surface it inline so
		// the agent reads the guidance instead of parking broken bytes behind a ref.
		if notice, ok := truncatedNotice(payload); ok {
			return proxyOutcome{result: truncatedResult(notice), rawBytes: len(res), egressHost: upHost}
		}
		// Gate on the LARGER of the extracted payload and the full upstream result, so
		// a compact structuredContent beside a large content[].text can't ride inline.
		if len(payload) > s.budget.MaxBytes || (!rehydrated && len(res) > s.budget.MaxBytes) {
			stored := payload
			if !rehydrated && len(payload) < len(res)/2 {
				stored = string(res) // extraction dropped data — ref the full result instead
			}
			ref, sum := s.budget.Store.Put(stored, caller)
			return proxyOutcome{result: s.refHandleResult(ref, sum, name, caller), rawBytes: max(len(res), len(stored)), outcome: budget.Outcome{Reffed: true, Ref: ref, Summary: sum}, egressHost: upHost}
		}
		if rehydrated { // small enough to inline, but return the DATA, never the offload URL
			return proxyOutcome{result: rehydratedResult(payload), rawBytes: len(payload), egressHost: upHost}
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
	preMinimizeBytes := marshalLen(passthrough)
	scrubbed, alerts, protected, merr := s.scrubInbound(ctx, upName, tool, passthrough)
	if merr != nil {
		return proxyOutcome{result: toolError("upstream %q: field minimization failed; result withheld", upName), rawBytes: len(res), err: fmt.Errorf("minimize: %w", merr), egressHost: upHost}
	}
	minimizedBytes := preMinimizeBytes - marshalLen(scrubbed)
	if minimizedBytes < 0 {
		minimizedBytes = 0
	}
	return proxyOutcome{result: scrubbed, rawBytes: len(res), minimizedBytes: minimizedBytes, egressHost: upHost, protected: protected, extra: minimizeAlertEvents(alerts)}
}

// fetchOffload retrieves an upstream offload URL host-side through the SSRF-guarded
// upstream client (so the bytes stay off the agent and internal addresses are
// refused), bounded by maxOffloadBytes, transparently decompressing a gzip export.
func (s *Server) fetchOffload(ctx context.Context, rawURL string, evaluated *evaluatedGrant) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	client := s.httpClient()
	if evaluated != nil {
		target, ok := findURLTarget(evaluated.Grant.URLTargets, "offload")
		if !ok {
			return nil, fmt.Errorf("operation grant does not authorize response offload retrieval")
		}
		if err := validateGrantedURL(rawURL, target); err != nil {
			return nil, err
		}
		initialOrigin, _ := parseGrantOrigin(req.URL.Scheme + "://" + req.URL.Host)
		client = safedial.GuardedClientForPolicy(0, 0, func(next *url.URL) error {
			if err := validateGrantedURL(next.String(), target); err != nil {
				return err
			}
			if !target.Redirect {
				nextOrigin, _ := parseGrantOrigin(next.Scheme + "://" + next.Host)
				if nextOrigin != initialOrigin {
					return fmt.Errorf("offload redirect is not granted")
				}
			}
			return nil
		})
	}
	resp, err := client.Do(req)
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
// proxy path shows up in /admin/runs and /admin/metrics exactly like a run.
// On a single-principal gateway the full arguments are recorded (no redaction —
// the operator reading the log made the calls). On a multi-principal gateway
// the record carries argument structure + digest instead, unless the connection
// is opted up to full capture (fullCapture); see argcapture.go.
// egressHost is the upstream host this call reached (mediated, cred-blind), or ""
// when the call was refused BEFORE any egress (read-only gate, pre-egress schema
// block). When set, it's recorded as an egress_allow event so the console and the
// audit chain show the gateway's outbound call, not "no egress".
// delegated is the provider identity a google-dwd call acted as (the derived
// subject), recorded beside the caller identity; "" on every other call.
func (s *Server) recordProxy(ctx context.Context, runID, upstream, tool string, args json.RawMessage, contextBytes int, start time.Time, out proxyOutcome, evaluated *evaluatedGrant, fullCapture bool, delegated string) {
	exit, auditErr := 0, ""
	if out.err != nil {
		exit, auditErr = 1, out.err.Error()
	}
	var audit []sandbox.AuditEvent
	if out.egressHost != "" {
		audit = append(audit, sandbox.AuditEvent{Event: "egress_allow", Host: out.egressHost})
	}
	audit = append(audit, out.extra...) // e.g. minimize_alert events from field minimization
	parkedBytes := 0
	if out.outcome.Reffed {
		parkedBytes = out.outcome.Summary.Bytes
	}
	transform := transformOf(ctx)
	transformEngine, transformQuerySHA256, transformStatus := "", "", out.transformStatus
	if transform != nil {
		transformEngine = transform.Engine
		transformQuerySHA256 = transformDigest(transform.Query)
		if transformStatus == "" {
			transformStatus = "not_run"
		}
	}
	substrate, engine := "", ""
	if out.transformRan {
		substrate, engine = "wasm", transformEngine
	}
	parentRun, delivery, requestID := programAuditContext(ctx)
	if delivery == "program" {
		contextBytes = 0 // the raw/intermediate response went to the sandbox only
	}
	recordedArgs, capture := string(args), ""
	var argsShape json.RawMessage
	argsDigest := ""
	switch {
	case s.multiPrincipalAudit() && !fullCapture:
		// Multi-principal gateway: keep every caller's argument VALUES out of the
		// shared operator-readable log; keep the record provable via the shape and
		// the canonicalized-argument digest.
		recordedArgs, capture = "", argsCaptureStructure
		argsShape, argsDigest = argShape(args), argsSHA256(args)
	case s.multiPrincipalAudit() && evaluated == nil:
		capture = argsCaptureFull // this connection is explicitly opted up
	}
	if evaluated != nil {
		// Governed records carry opaque resource identifiers instead of raw
		// object arguments, so a fleet correlator does not need payload access.
		// This blank wins over a full-capture opt-up.
		recordedArgs = ""
	}
	record := runRecord{
		Kind: "proxy", TaskID: taskIDOf(ctx), Upstream: upstream, Tool: tool, Args: recordedArgs,
		ArgsCapture: capture, ArgsShape: argsShape, ArgsSHA256: argsDigest,
		ParentRunID: parentRun, Delivery: delivery, ProgramRequestID: requestID,
		User: callerKey(ctx), Campaign: campaignOf(ctx), DelegatedIdentity: delegated,
		InputBytes:      len(args), // the tool arguments are the call's input payload
		RawBytes:        out.rawBytes,
		ParkedBytes:     parkedBytes,
		MinimizedBytes:  out.minimizedBytes,
		OutputBytes:     contextBytes,
		ContextMeasured: true,
		Bytes:           parkedBytes,
		LatencyMs:       time.Since(start).Milliseconds(),
		Substrate:       substrate, Engine: engine,
		FusedInvocation: out.transformRan,
		TransformEngine: transformEngine, TransformQuerySHA256: transformQuerySHA256,
		TransformInputBytes: out.transformInputBytes, TransformOutputBytes: out.transformOutputBytes,
		TransformLatencyMs: out.transformLatencyMs, TransformStatus: transformStatus,
		Reffed: out.outcome.Reffed, Ref: string(out.outcome.Ref),
		Protected: out.protected,
		ExitCode:  exit, AuditErr: auditErr, Audit: audit,
	}
	if evaluated != nil {
		record.GrantID, record.GrantDigest, record.Effect = evaluated.Grant.ID, evaluated.Digest, evaluated.Grant.Effect
		record.ResourceIDs = append([]string(nil), evaluated.ResourceIDs...)
	}
	s.putRun(runID, record)
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
// context: the handle + size + how to reduce it. Never the raw data. owner is
// the caller the ref was just stored for; the preview is bound to it.
func (s *Server) refHandleResult(ref refstore.Ref, sum refstore.Summary, toolName, owner string) map[string]any {
	out := map[string]any{
		"reffed": true,
		"ref":    string(ref),
		"bytes":  sum.Bytes,
		"note": fmt.Sprintf("%s returned %d bytes, held off-context as %s. A structural preview is included so you may not need to reduce at all. To read it off-context: "+
			"reduce(ref=%q, query=<jq/sql/... query>, engine=<engine>) for a declarative reduction, or "+
			"reduce(ref=%q, code=<python that reads /app/input>) for arbitrary logic.",
			toolName, sum.Bytes, ref, ref, ref),
	}
	if p := s.refPreview(ref, owner); p != nil {
		out["preview"] = p
	}
	return toolResult(out)
}

// refPreview computes the structural preview of a stored ref's payload, and
// only for the ref's owner. Every current caller passes a ref it just created
// for that same owner, but the check lives HERE so a future call site cannot
// leak a preview of another principal's data by handle.
func (s *Server) refPreview(ref refstore.Ref, owner string) map[string]any {
	if s.budget.Store == nil {
		return nil
	}
	if data, got, ok := s.budget.Store.Get(ref); ok && got == owner {
		return structuralPreview(data)
	}
	return nil
}

// bumpUsage records one successful invocation of a tool, by namespaced name.
func (s *Server) bumpUsage(name string) {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	if s.reg.usage == nil {
		s.reg.usage = map[string]int{}
	}
	s.reg.usage[name]++
}

// callTool is the invoke half of the off-context tool surface: a tool discovered
// via find_tools isn't in tools/list, so the agent reaches it here by name +
// arguments. The discovery/invocation gate is enforced in invokeUpstream.
func (s *Server) callTool(ctx context.Context, args json.RawMessage) map[string]any {
	var in struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Transform json.RawMessage `json:"transform"`
		TaskID    string          `json:"task_id"`
	}
	if err := json.Unmarshal(args, &in); err != nil || in.Name == "" {
		return toolError("call_tool requires a tool name; discover tools with find_tools")
	}
	taskID, err := validateTaskID(in.TaskID)
	if err != nil {
		return toolError("call_tool: %v", err)
	}
	transform, err := s.parseTransform(in.Transform)
	if err != nil {
		return toolError("call_tool: %v", err)
	}
	ctx = withTaskID(ctx, taskID)
	ctx = withTransform(ctx, transform)
	if res, ok := s.invokeUpstream(ctx, in.Name, in.Arguments); ok {
		return res
	}
	return toolError("unknown tool %q; discover tools with find_tools", in.Name)
}
