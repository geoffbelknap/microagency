package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"microagency/internal/auth"
	"microagency/internal/catalog"
	"microagency/internal/gateway"
	"microagency/internal/optoken"
	"microagency/internal/refstore"
	"microagency/internal/safedial"
	"microagency/internal/sandbox"
)

// RunInfo is an operator-facing view of one recorded run, including its egress
// audit — the observability surface (what the agent reached, and what was denied).
type RunInfo struct {
	RunID            string `json:"run_id"`
	Kind             string `json:"kind,omitempty"`
	TaskID           string `json:"task_id,omitempty"`
	ParentRunID      string `json:"parent_run_id,omitempty"`
	Delivery         string `json:"delivery,omitempty"`
	ProgramRequestID string `json:"program_request_id,omitempty"`
	SourceID         string `json:"source_id,omitempty"`
	Upstream         string `json:"upstream,omitempty"`
	Tool             string `json:"tool,omitempty"`
	Args             string `json:"args,omitempty"`
	// ArgsCapture/ArgsShape/ArgsSHA256 mirror the audit record's argument
	// capture: on a multi-principal gateway, non-opted-up connections record
	// structure + digest here instead of Args (see argcapture.go).
	ArgsCapture          string          `json:"args_capture,omitempty"`
	ArgsShape            json.RawMessage `json:"args_shape,omitempty"`
	ArgsSHA256           string          `json:"args_sha256,omitempty"`
	User                 string          `json:"user,omitempty"`
	Reason               string          `json:"reason,omitempty"`
	DelegatedIdentity    string          `json:"delegated_identity,omitempty"`
	Campaign             string          `json:"campaign,omitempty"`
	GrantID              string          `json:"grant_id,omitempty"`
	GrantDigest          string          `json:"grant_digest,omitempty"`
	Effect               string          `json:"effect,omitempty"`
	ResourceIDs          []string        `json:"resource_ids,omitempty"`
	Session              string          `json:"session,omitempty"`
	Substrate            string          `json:"substrate,omitempty"`
	Engine               string          `json:"engine,omitempty"`
	LatencyMs            int64           `json:"latency_ms"`
	InputBytes           int             `json:"input_bytes"`
	OutputBytes          int             `json:"output_bytes"`
	RawBytes             int             `json:"raw_bytes,omitempty"`
	ParkedBytes          int             `json:"parked_bytes,omitempty"`
	MinimizedBytes       int             `json:"minimized_bytes,omitempty"`
	ContextMeasured      bool            `json:"context_measured,omitempty"`
	FullSchemaEntries    int             `json:"full_schema_entries,omitempty"`
	SchemaDigestEntries  int             `json:"schema_digest_entries,omitempty"`
	SummarizedEntries    int             `json:"summarized_entries,omitempty"`
	OmittedEntries       int             `json:"omitted_entries,omitempty"`
	ExactSchemaLookup    bool            `json:"exact_schema_lookup,omitempty"`
	FusedInvocation      bool            `json:"fused_invocation,omitempty"`
	TransformEngine      string          `json:"transform_engine,omitempty"`
	TransformQuerySHA256 string          `json:"transform_query_sha256,omitempty"`
	TransformInputBytes  int             `json:"transform_input_bytes,omitempty"`
	TransformOutputBytes int             `json:"transform_output_bytes,omitempty"`
	TransformLatencyMs   int64           `json:"transform_latency_ms,omitempty"`
	TransformStatus      string          `json:"transform_status,omitempty"`
	ProgramTools         []string        `json:"program_tools,omitempty"`
	ProgramCalls         int             `json:"program_calls,omitempty"`
	ProgramBytes         int             `json:"program_bytes,omitempty"`
	ProgramStatus        string          `json:"program_status,omitempty"`
	Reffed               bool            `json:"reffed"`
	Ref                  string          `json:"ref,omitempty"`
	Bytes                int             `json:"bytes"`
	Protected            int             `json:"protected,omitempty"` // sensitive field values minimized on this call
	ExitCode             int             `json:"exit_code"`
	// Stderr is the guest's captured stderr (bounded) — operator-only diagnostics.
	// It is deliberately absent from the agent-facing tool result, which can only
	// point here.
	Stderr    string               `json:"stderr,omitempty"`
	Audit     []sandbox.AuditEvent `json:"audit,omitempty"`
	AuditErr  string               `json:"audit_err,omitempty"`
	Timestamp string               `json:"timestamp,omitempty"`
}

// RunLog returns every recorded run (with its egress audit), ordered by run id.
func (s *Server) RunLog() []RunInfo {
	s.rs.mu.Lock()
	defer s.rs.mu.Unlock()
	out := make([]RunInfo, 0, len(s.rs.byID))
	for id, rec := range s.rs.byID {
		ts := ""
		if !rec.Timestamp.IsZero() {
			ts = rec.Timestamp.Format(time.RFC3339)
		}
		out = append(out, RunInfo{
			RunID: id, Kind: rec.Kind, TaskID: rec.TaskID, ParentRunID: rec.ParentRunID,
			Delivery: rec.Delivery, ProgramRequestID: rec.ProgramRequestID, SourceID: rec.SourceID,
			Upstream: rec.Upstream, Tool: rec.Tool, Args: rec.Args,
			ArgsCapture: rec.ArgsCapture, ArgsShape: rec.ArgsShape, ArgsSHA256: rec.ArgsSHA256,
			User: rec.User, Reason: rec.Reason, DelegatedIdentity: rec.DelegatedIdentity, Campaign: rec.Campaign, GrantID: rec.GrantID, GrantDigest: rec.GrantDigest,
			Effect: rec.Effect, ResourceIDs: append([]string(nil), rec.ResourceIDs...), Session: rec.Session,
			Substrate: rec.Substrate, Engine: rec.Engine, LatencyMs: rec.LatencyMs,
			InputBytes: rec.InputBytes, OutputBytes: rec.OutputBytes,
			RawBytes: rec.RawBytes, ParkedBytes: rec.ParkedBytes, MinimizedBytes: rec.MinimizedBytes,
			ContextMeasured:   rec.ContextMeasured,
			FullSchemaEntries: rec.FullSchemaEntries, SchemaDigestEntries: rec.SchemaDigestEntries,
			SummarizedEntries: rec.SummarizedEntries, OmittedEntries: rec.OmittedEntries,
			ExactSchemaLookup: rec.ExactSchemaLookup, FusedInvocation: rec.FusedInvocation,
			TransformEngine: rec.TransformEngine, TransformQuerySHA256: rec.TransformQuerySHA256,
			TransformInputBytes: rec.TransformInputBytes, TransformOutputBytes: rec.TransformOutputBytes,
			TransformLatencyMs: rec.TransformLatencyMs, TransformStatus: rec.TransformStatus,
			ProgramTools: rec.ProgramTools, ProgramCalls: rec.ProgramCalls, ProgramBytes: rec.ProgramBytes, ProgramStatus: rec.ProgramStatus,
			Reffed: rec.Reffed, Ref: rec.Ref,
			Bytes: rec.Bytes, Protected: rec.Protected, ExitCode: rec.ExitCode, Stderr: rec.Stderr, Audit: rec.Audit, AuditErr: rec.AuditErr,
			Timestamp: ts,
		})
	}
	// Newest first (run ids are monotonic), so the console shows recent activity on top.
	sort.Slice(out, func(i, j int) bool { return runSeq(out[i].RunID) > runSeq(out[j].RunID) })
	return out
}

// OperatorAuth authenticates the operator surface (/admin + the console's data
// API). Two credential kinds are accepted: the legacy single token from
// ~/.microagency/token (full admin, break-glass), and named tokens from the
// operator-token store, each carrying a role and optional expiry. With neither
// configured every request is refused — an unconfigured operator plane is
// closed, not open.
type OperatorAuth struct {
	// LegacyToken is the original single full-admin bearer; "" means the
	// legacy credential path is disabled, never that auth is skipped.
	LegacyToken string
	// Tokens is the named operator-token store; nil disables named tokens.
	Tokens *optoken.Store
}

// authenticate resolves a request to an operator identity: the acting token's
// name and role. Comparisons are constant-time; an empty bearer never matches.
func (a OperatorAuth) authenticate(r *http.Request) (name string, role optoken.Role, ok bool) {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		return "", "", false
	}
	if a.LegacyToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(a.LegacyToken)) == 1 {
		return optoken.LegacyName, optoken.RoleAdmin, true
	}
	if a.Tokens != nil {
		if t, ok := a.Tokens.Authenticate(got, time.Now()); ok {
			return t.Name, t.Role, true
		}
	}
	return "", "", false
}

// operatorActorKey carries the authenticated operator token's name in the
// request context, so handlers attribute admin actions to the acting token.
type operatorActorKey struct{}

// operatorActor returns the acting operator token's name set by the guard.
func operatorActor(r *http.Request) string {
	if v, ok := r.Context().Value(operatorActorKey{}).(string); ok && v != "" {
		return v
	}
	return "operator"
}

// AdminHandler is the operator-facing management API: read sources/runs/
// upstreams (the console's data backbone + observability surface) and manage
// sources and upstreams. Every route authenticates; most require the admin
// role, and a small read-only observability set (runs, metrics, audit and
// decision-ledger verification) also admits the auditor role.
func (s *Server) AdminHandler(opAuth OperatorAuth) http.Handler {
	mux := http.NewServeMux()
	g := func(h http.HandlerFunc) http.HandlerFunc { return s.operatorGuard(opAuth, true, h) }
	ro := func(h http.HandlerFunc) http.HandlerFunc { return s.operatorGuard(opAuth, false, h) }
	mux.HandleFunc("GET /admin/runs", ro(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.RunLog()) }))
	mux.HandleFunc("GET /admin/audit/verify", ro(func(w http.ResponseWriter, _ *http.Request) {
		v, err := s.VerifyAudit()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}))
	mux.HandleFunc("GET /admin/decisions/verify", ro(func(w http.ResponseWriter, r *http.Request) {
		v := s.VerifyDecisionLedger(r.Context())
		status := http.StatusOK
		if !v.Intact || v.Error != "" {
			status = http.StatusConflict
		}
		writeJSON(w, status, v)
	}))
	mux.HandleFunc("GET /admin/refs/{ref}", g(s.adminMaterializeRef))
	mux.HandleFunc("GET /admin/metrics", ro(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Metrics()) }))
	mux.HandleFunc("GET /admin/metrics/prometheus", ro(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", PrometheusContentType)
		_, _ = w.Write([]byte(s.Metrics().Prometheus()))
	}))
	mux.HandleFunc("GET /admin/tools/rank", g(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		// The subject parameter takes a canonical principal key (issuer#subject);
		// the default is the local operator's key.
		subject := q.Get("subject")
		if subject == "" {
			subject = auth.PrincipalKey(auth.LocalIssuer, "local")
		}
		writeJSON(w, http.StatusOK, s.RankTools(subject, q.Get("q"), limit))
	}))
	mux.HandleFunc("GET /admin/infra", g(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.InfraStatus(r.Context())) }))
	mux.HandleFunc("GET /admin/upstreams", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.UpstreamList()) }))
	mux.HandleFunc("GET /admin/egress-policy", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.EgressPolicy()) }))
	mux.HandleFunc("GET /admin/mediation", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.MediationStatus()) }))
	mux.HandleFunc("GET /admin/mediation/denials", g(func(w http.ResponseWriter, _ *http.Request) {
		denials, err := s.MediationDenials()
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, denials)
	}))
	mux.HandleFunc("POST /admin/upstreams", g(s.adminAddUpstream))
	// The OAuth callback is a browser redirect from the upstream — no operator token;
	// it is protected by the unguessable state + PKCE, not the admin bearer.
	mux.HandleFunc("GET /admin/oauth/callback", s.adminOAuthCallback)
	mux.HandleFunc("POST /admin/upstreams/{name}/enable", g(s.adminEnableUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/disable", g(s.adminDisableUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/revoke", g(s.adminRevokeUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/refresh", g(s.adminRefreshUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/reauth", g(s.adminReauthUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/read-only", g(s.adminSetReadOnly))
	mux.HandleFunc("POST /admin/upstreams/{name}/audit-capture", g(s.adminSetAuditCapture))
	mux.HandleFunc("POST /admin/upstreams/{name}/grants", g(s.adminSetGrants))
	mux.HandleFunc("POST /admin/upstreams/{name}/minimize", g(s.adminSetMinimize))
	mux.HandleFunc("POST /admin/upstreams/{name}/owner", g(s.adminSetOwner))
	mux.HandleFunc("POST /admin/upstreams/{name}/delegation", g(s.adminUpdateDelegation))
	mux.HandleFunc("GET /admin/oauth-scopes", g(s.adminOAuthScopes))
	mux.HandleFunc("GET /admin/provider-params", g(s.adminProviderParams))
	mux.HandleFunc("GET /admin/registry", g(s.adminRegistrySearch))
	mux.HandleFunc("POST /admin/registry/import", g(s.adminRegistryImport))
	mux.HandleFunc("GET /admin/connection-templates", g(s.adminListConnectionTemplates))
	mux.HandleFunc("POST /admin/connection-templates", g(s.adminPutConnectionTemplate))
	mux.HandleFunc("DELETE /admin/connection-templates/{id}", g(s.adminDeleteConnectionTemplate))
	mux.HandleFunc("DELETE /admin/upstreams/{name}", g(s.adminDeleteUpstream))
	return mux
}

// maxMaterializeReason bounds the operator-supplied reason so one request
// can't bloat the audit log.
const maxMaterializeReason = 512

// adminMaterializeRef delivers the actual data behind a reference to the
// authorized operator — the out-of-band channel that lets a human retrieve PII a
// run kept off the model's context. It NEVER passes through the agent: it
// requires the admin role, an explicit ?reason=, and the retrieval is itself
// audited under the acting token's name (ASK tenets 2 and 13 — every access to
// the data leaves a trace, and the trace says who and why).
func (s *Server) adminMaterializeRef(w http.ResponseWriter, r *http.Request) {
	if s.budget.Store == nil {
		http.Error(w, "references are not enabled", http.StatusNotFound)
		return
	}
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		http.Error(w, "materializing parked data requires a reason: repeat the request with ?reason=<why>; it is recorded in the audit log", http.StatusBadRequest)
		return
	}
	if len(reason) > maxMaterializeReason {
		http.Error(w, fmt.Sprintf("reason is too long (%d bytes; max %d)", len(reason), maxMaterializeReason), http.StatusBadRequest)
		return
	}
	ref := r.PathValue("ref")
	// The admin operator may materialize ANY ref out-of-band; owner binding
	// gates the AGENT's reduce path, not the operator.
	payload, _, ok := s.budget.Store.Get(refstore.Ref(ref))
	if !ok {
		http.Error(w, "unknown reference", http.StatusNotFound)
		return
	}
	s.putRun(s.nextRunID(), runRecord{
		Kind: "materialize", SourceID: ref, User: operatorActor(r), Reason: reason,
		OutputBytes: len(payload), Bytes: len(payload),
	})
	name := strings.Trim(ref, "<>")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".txt"))
	_, _ = io.WriteString(w, payload)
}

// operatorGuard authenticates every operator route and enforces the role gate.
// requireAdmin routes refuse auditor tokens; the guard then stamps the acting
// token's name into the request context for audit attribution. There is no
// unauthenticated branch: a deployment with no operator credential configured
// refuses every request rather than waving them through.
func (s *Server) operatorGuard(opAuth OperatorAuth, requireAdmin bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, role, ok := opAuth.authenticate(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if requireAdmin && role != optoken.RoleAdmin {
			http.Error(w, fmt.Sprintf("forbidden: operator token %q has the read-only auditor role; this operation requires an admin token", name), http.StatusForbidden)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), operatorActorKey{}, name)))
	}
}

func (s *Server) adminAddUpstream(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Token    string `json:"token"`
		Scope    string `json:"scope"`     // OAuth scopes to request (space-separated); operator-chosen, least-privilege
		Discover bool   `json:"discover"`  // register DISCOVERED (findable, not invocable) instead of enabled
		ReadOnly bool   `json:"read_only"` // expose only READ tools; refuse writes (least-privilege at onboarding)
		// AllowPrivateDestination declares this connection's own endpoint reachable
		// even when it is loopback or otherwise private — a sidecar connector, or an
		// internal MCP server beside the gateway. Operator-only: this surface is the
		// only one that accepts it, and the metadata addresses stay refused regardless.
		AllowPrivateDestination bool `json:"allow_private_destination"`
		// Owner scopes the connection to ONE authenticated principal, by canonical
		// identity key (issuer#subject): only that caller can find or invoke it.
		// "" = shared with every authenticated user of this gateway.
		Owner string `json:"owner"`
		// ScopeParams narrows the upstream connection AT THE PROVIDER: operator-approved
		// values for a known provider's curated scoping knobs (e.g. Supabase project_ref,
		// read_only), appended to the MCP URL as query params before registration. Distinct
		// from ReadOnly, which gates write tools at our boundary after the fact.
		ScopeParams map[string]string `json:"scope_params"`
		// ClientID/ClientSecret let the operator supply a pre-registered OAuth client for
		// an authorization server that doesn't offer dynamic client registration (Google,
		// most enterprise IdPs). When set, they seed the stored client and skip DCR.
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		// Strategy selects how a calling principal maps to upstream authority.
		// "" and "static" are today's shared-credential behavior. "google-dwd"
		// requires Delegation (non-secret config) and ServiceAccountKey (the
		// provider's JSON key document, stored only in the secret store).
		// "per-user-oauth" is refused here: those connections are created by
		// each user from an operator-approved connection template.
		Strategy          string             `json:"strategy"`
		Delegation        *DelegationSummary `json:"delegation"`
		ServiceAccountKey string             `json:"service_account_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	// A non-canonical owner (e.g. a bare token subject) matches no authenticated
	// caller; refuse it here so the operator learns immediately instead of
	// shipping a connection nobody can reach.
	if in.Owner != "" {
		if _, _, err := auth.SplitPrincipalKey(in.Owner); err != nil {
			http.Error(w, "owner: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	// Apply provider scoping at add-time: bake the operator's chosen knobs into the
	// URL so every downstream use (OAuth probe, registration, persistence) targets
	// the narrowed connection. A non-catalog URL or empty values leaves it untouched.
	scopedURL, serr := ScopedURL(in.URL, in.ScopeParams)
	if serr != nil {
		http.Error(w, "invalid scope params: "+serr.Error(), http.StatusBadRequest)
		return
	}
	in.URL = scopedURL
	// Credential-strategy dispatch. Contradictory inputs are invalid
	// configuration and fail closed, naming both sides.
	switch in.Strategy {
	case "", StrategyStatic:
		if in.Delegation != nil || in.ServiceAccountKey != "" {
			http.Error(w, "delegation config and service_account_key require strategy \"google-dwd\"; set it, or drop them", http.StatusBadRequest)
			return
		}
	case StrategyGoogleDWD:
		if in.Token != "" {
			http.Error(w, "token and strategy \"google-dwd\" are mutually exclusive: a delegated connection derives a per-caller credential and cannot also hold a static bearer; drop one of them", http.StatusBadRequest)
			return
		}
		state, code, err := s.addDelegatedUpstream(r.Context(), in.Name, in.URL, in.Discover, in.ReadOnly, in.AllowPrivateDestination, in.Owner, in.Delegation, in.ServiceAccountKey)
		if err != nil {
			http.Error(w, err.Error(), code)
			return
		}
		rec, _ := s.snapshotUpstream(in.Name)
		resp := map[string]any{"name": in.Name, "state": state, "read_only": in.ReadOnly, "owner": in.Owner, "strategy": StrategyGoogleDWD}
		if rec.delegation != nil {
			resp["delegation"] = DelegationInfo{
				ClientEmail: rec.delegation.ClientEmail(), TokenEndpoint: rec.delegation.TokenEndpoint(),
				Scopes: rec.delegation.Scopes(), KeyConfigured: true,
			}
		}
		writeJSON(w, http.StatusCreated, resp)
		return
	case StrategyPerUserOAuth:
		http.Error(w, "per-user-oauth connections are created by each user from an operator-approved connection template (POST /admin/connection-templates), not on this surface", http.StatusBadRequest)
		return
	default:
		http.Error(w, "unknown credential strategy "+strconv.Quote(in.Strategy)+"; one of: static, per-user-oauth, google-dwd", http.StatusBadRequest)
		return
	}
	client := s.upstreamClient
	if in.AllowPrivateDestination {
		dest, derr := safedial.ParseDestination(in.URL)
		if derr != nil {
			http.Error(w, derr.Error(), http.StatusBadRequest)
			return
		}
		client = safedial.GuardedClientForDestination(0, 0, dest)
	}
	u := &gateway.Upstream{Name: in.Name, URL: in.URL, Token: in.Token, Client: client}
	// No static token → probe for OAuth. If the upstream requires it, start the web
	// flow and return an authorize URL for the operator's browser to visit (no PAT).
	if in.Token == "" {
		if rm, perr := u.Probe(r.Context()); perr == nil && rm != "" {
			authURL, aerr := s.startUpstreamOAuth(r.Context(), in.Name, in.URL, in.Discover, false, in.ReadOnly, in.Owner, in.Scope, rm, callbackURL(r), in.ClientID, in.ClientSecret)
			if aerr != nil {
				http.Error(w, aerr.Error(), http.StatusBadGateway)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "authorization_required", "authorize_url": authURL})
			return
		}
	}
	var opts []UpstreamOption
	if in.Owner != "" {
		opts = append(opts, WithOwner(in.Owner))
	}
	if in.AllowPrivateDestination {
		opts = append(opts, WithPrivateDestination())
	}
	var err error
	state := "enabled"
	if in.Discover {
		err, state = s.DiscoverUpstream(r.Context(), in.Name, u, opts...), "discovered"
	} else {
		err = s.AddUpstream(r.Context(), in.Name, u, opts...)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Persist so the upstream reloads across restarts. A static token is held in the
	// secret store (never the plaintext registration); a tokenless upstream records
	// no credential. (The OAuth path persists from its callback, above.)
	authKind := authNone
	if in.Token != "" {
		authKind = authStatic
		s.saveStaticToken(r.Context(), in.Name, in.Token)
	}
	s.persistRegistrationRecord(upstreamReg{
		Name: in.Name, URL: in.URL, Discover: in.Discover, Auth: authKind,
		Owner: in.Owner, PrivateDestination: in.AllowPrivateDestination,
	})
	if in.ReadOnly {
		_ = s.SetUpstreamReadOnly(in.Name, true)
		s.persistReadOnly(in.Name, true)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": in.Name, "state": state, "read_only": in.ReadOnly, "owner": in.Owner})
}

// adminSetOwner scopes (or, with "", un-scopes) a connection to one principal's
// canonical identity key (issuer#subject). Operator-plane: assigning ownership
// is a trust decision, so it lives behind the operator token like every other
// grant.
func (s *Server) adminSetOwner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if in.Owner != "" {
		if _, _, err := auth.SplitPrincipalKey(in.Owner); err != nil {
			http.Error(w, "owner: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.SetUpstreamOwner(name, in.Owner); err != nil {
		status := http.StatusNotFound
		if strings.Contains(err.Error(), "ownership is immutable") {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.persistOwner(name, in.Owner)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "owner": in.Owner})
}

// adminSetReadOnly toggles an upstream's read-only restriction (writes refused).
func (s *Server) adminSetReadOnly(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		ReadOnly bool `json:"read_only"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.SetUpstreamReadOnly(name, in.ReadOnly); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.persistReadOnly(name, in.ReadOnly)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "read_only": in.ReadOnly})
}

// adminSetAuditCapture opts a connection up to (or back down from) FULL
// argument capture in the audit log on a multi-principal gateway, where the
// default is structure + digest. Operator-plane: widening what the shared log
// retains is a trust decision, so it lives behind the operator token. The
// posture is disclosed in the upstream list and by `microagency doctor`.
func (s *Server) adminSetAuditCapture(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		FullArgs bool `json:"full_args"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.SetUpstreamAuditFullArgs(name, in.FullArgs); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.persistAuditFullArgs(name, in.FullArgs)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "audit_full_args": in.FullArgs})
}

func (s *Server) adminSetGrants(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Grants []OperationGrant `json:"grants"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		http.Error(w, "invalid grant body", http.StatusBadRequest)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		http.Error(w, "invalid grant body", http.StatusBadRequest)
		return
	}
	if err := s.SetUpstreamGrants(name, in.Grants); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.persistGrantsStrict(name, in.Grants); err != nil {
		_ = s.DisableUpstream(name)
		http.Error(w, "grants applied fail-closed but durable persistence failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "grant_count": len(in.Grants), "grant_digests": sortedGrantDigests(in.Grants),
	})
}

// adminSetMinimize sets an upstream's field-minimization policy — opaque
// module-defined JSON (a type→action map, e.g. {"account":"tokenize"}). With
// secure-by-default, three inputs are distinct: a null/absent policy RESETS to the
// secure default; an empty object {} is an explicit OPT-OUT (passthrough); any
// other object is the explicit policy. Persisted so config survives across builds.
func (s *Server) adminSetMinimize(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(string(in.Policy))
	if raw == "" || raw == "null" {
		// reset → the secure default (or passthrough if secure-default is off)
		s.SetMinimizePolicy(name, nil)
		s.persistMinimize(name, "")
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "minimize": nil, "reset": true})
		return
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		http.Error(w, "policy must be a JSON object (e.g. {\"account\":\"tokenize\"}), or null to reset", http.StatusBadRequest)
		return
	}
	s.SetMinimizePolicy(name, []byte(raw)) // explicit — {} is a real opt-out
	s.persistMinimize(name, raw)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "minimize": obj})
}

// adminEnableUpstream is the explicit operator trust grant: it connects a
// discovered upstream and makes its tools invocable.
func (s *Server) adminEnableUpstream(w http.ResponseWriter, r *http.Request) {
	if err := s.EnableUpstream(r.Context(), r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.markRegistrationEnabled(r.PathValue("name")) // reload enabled, not discovered
	writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "state": "enabled"})
}

// adminRefreshUpstream re-lists an upstream's tools so the index reflects the
// upstream's current tool set (added/removed tools, revised schemas).
func (s *Server) adminRefreshUpstream(w http.ResponseWriter, r *http.Request) {
	if err := s.RefreshUpstream(r.Context(), r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "state": "refreshed"})
}

// adminOAuthScopes probes a URL and reports whether it's OAuth-protected and which
// scopes it advertises — so the console can render a scope picker (checkboxes)
// instead of asking the operator to type scope strings. Query: ?url=<mcp url>.
func (s *Server) adminOAuthScopes(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	u := &gateway.Upstream{URL: target, Client: s.upstreamClient}
	rm, perr := u.Probe(r.Context())
	if perr != nil || rm == "" {
		writeJSON(w, http.StatusOK, map[string]any{"oauth": false, "scopes": []string{}})
		return
	}
	meta, err := auth.DiscoverAS(r.Context(), s.httpClient(), rm)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"oauth": true, "scopes": []string{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"oauth": true, "scopes": sanitizeScopes(meta.ScopesSupported)})
}

// sanitizeScopes drops any advertised scope that isn't a well-formed OAuth scope
// token (RFC 6749 §3.3: visible ASCII except space, double-quote, and backslash).
// The upstream's metadata is attacker-controlled; this keeps a malicious scope value
// (e.g. one carrying markup for the console's scope picker) from ever reaching the
// browser, complementing the console's own output escaping.
func sanitizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if sc != "" && isScopeToken(sc) {
			out = append(out, sc)
		}
	}
	return out
}

func isScopeToken(s string) bool {
	for _, r := range s {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// adminProviderParams reports the curated scoping knobs for the known provider a
// URL matches — so the console can render "limit this connection" fields (a text
// box per string param, a checkbox per bool param) at add-time. A URL matching no
// known provider returns an empty param set. Query: ?url=<mcp url>.
func (s *Server) adminProviderParams(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	prov, ok := providerForURL(target)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"provider": "", "params": []ProviderParam{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": prov.Name, "params": prov.Params})
}

// adminRegistrySearch browses an MCP registry (default: the official MCP registry)
// and returns servers the operator can add — the live-registry feed that lets the
// index get AHEAD of manual wiring. Read-only: it changes no state. Query:
// ?q=<search>&limit=<N>&url=<registry base, optional>.
func (s *Server) adminRegistrySearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	servers, err := catalog.LoadRegistry(r.Context(), s.httpClient(), q.Get("url"), q.Get("q"), limit)
	if err != nil {
		http.Error(w, "registry: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers, "count": len(servers)})
}

// adminRegistryImport bulk-registers registry servers into the index as DISCOVERED
// (findable, but NOT invocable until the operator enables each — the gate stays on
// EnableUpstream). Registry entries carry no tools; enabling a server fetches its
// real tools. Already-registered upstreams are skipped, so import is idempotent.
// Body: {"q":"...","limit":N,"url":"..."} (all optional).
func (s *Server) adminRegistryImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Q     string `json:"q"`
		Limit int    `json:"limit"`
		URL   string `json:"url"`
	}
	// Empty body is valid (import a default page); ignore decode errors on it.
	_ = json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in)
	servers, err := catalog.LoadRegistry(r.Context(), s.httpClient(), in.URL, in.Q, in.Limit)
	if err != nil {
		http.Error(w, "registry: "+err.Error(), http.StatusBadGateway)
		return
	}
	existing := map[string]bool{}
	for _, up := range s.UpstreamList() {
		existing[up.Name] = true
	}
	imported, skipped := 0, 0
	for _, sv := range servers {
		if existing[sv.Name] {
			skipped++
			continue
		}
		u := &gateway.Upstream{Name: sv.Name, URL: sv.URL, Client: s.upstreamClient}
		if err := s.AddDiscovered(sv.Name, u, sv.Tools, "catalog"); err != nil {
			skipped++
			continue
		}
		existing[sv.Name] = true
		imported++
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "skipped": skipped, "found": len(servers)})
}

// adminReauthUpstream re-runs the OAuth flow for an already-registered upstream —
// to refresh a revoked/expired grant or to change the requested scopes. It returns
// an authorize URL; the callback rebinds the new token onto the existing upstream
// (see RebindUpstream) without re-adding it. Body: optional {"scope": "..."}.
func (s *Server) adminReauthUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Scope string `json:"scope"`
	}
	// Body is optional (empty = no scope change request); ignore decode errors on an empty body.
	_ = json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in)

	var url, state string
	var selfService bool
	for _, up := range s.UpstreamList() {
		if up.Name == name {
			url, state, selfService = up.URL, up.State, up.SelfService
			break
		}
	}
	if url == "" {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	if selfService {
		http.Error(w, "self-service connections must be reauthorized by their owning principal", http.StatusConflict)
		return
	}
	u := &gateway.Upstream{Name: name, URL: url, Client: s.upstreamClient}
	rm, perr := u.Probe(r.Context())
	if perr != nil || rm == "" {
		http.Error(w, "upstream does not advertise OAuth", http.StatusBadRequest)
		return
	}
	// Reauth reuses the client already stored for this AS (from the original add), so
	// no supplied creds are needed here.
	authURL, aerr := s.startUpstreamOAuth(r.Context(), name, url, state == "discovered", true, false, "", in.Scope, rm, callbackURL(r), "", "")
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "authorization_required", "authorize_url": authURL})
}

func (s *Server) adminDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	record, _ := s.snapshotUpstream(name)
	if record.conn == nil {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	s.cancelOAuthFlows(func(flow *oauthFlow) bool { return flow.name == name })
	if record.selfService {
		_ = s.RevokeUpstream(name)
		if err := s.removeSelfServiceRegistration(r.Context(), name, record); err != nil {
			http.Error(w, "connection disabled, but durable deletion failed: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		s.deleteSelfServiceClientIfUnused(r.Context(), record.owner, record.template, record.conn.Endpoint())
	} else {
		s.removeRegistration(r.Context(), name) // stay gone across restarts
	}
	_ = s.RemoveUpstream(name)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
