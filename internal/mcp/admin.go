package mcp

import (
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
	"microagency/internal/refstore"
	"microagency/internal/sandbox"
)

// RunInfo is an operator-facing view of one recorded run, including its egress
// audit — the observability surface (what the agent reached, and what was denied).
type RunInfo struct {
	RunID       string `json:"run_id"`
	Kind        string `json:"kind,omitempty"`
	SourceID    string `json:"source_id,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Args        string `json:"args,omitempty"`
	User        string `json:"user,omitempty"`
	Session     string `json:"session,omitempty"`
	Substrate   string `json:"substrate,omitempty"`
	Engine      string `json:"engine,omitempty"`
	LatencyMs   int64  `json:"latency_ms"`
	InputBytes  int    `json:"input_bytes"`
	OutputBytes int    `json:"output_bytes"`
	Reffed      bool   `json:"reffed"`
	Ref         string `json:"ref,omitempty"`
	Bytes       int    `json:"bytes"`
	ExitCode    int    `json:"exit_code"`
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
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RunInfo, 0, len(s.runs))
	for id, rec := range s.runs {
		ts := ""
		if !rec.Timestamp.IsZero() {
			ts = rec.Timestamp.Format(time.RFC3339)
		}
		out = append(out, RunInfo{
			RunID: id, Kind: rec.Kind, SourceID: rec.SourceID,
			Upstream: rec.Upstream, Tool: rec.Tool, Args: rec.Args,
			User: rec.User, Session: rec.Session,
			Substrate: rec.Substrate, Engine: rec.Engine, LatencyMs: rec.LatencyMs,
			InputBytes: rec.InputBytes, OutputBytes: rec.OutputBytes,
			Reffed: rec.Reffed, Ref: rec.Ref,
			Bytes: rec.Bytes, ExitCode: rec.ExitCode, Stderr: rec.Stderr, Audit: rec.Audit, AuditErr: rec.AuditErr,
			Timestamp: ts,
		})
	}
	// Newest first (run ids are monotonic), so the console shows recent activity on top.
	sort.Slice(out, func(i, j int) bool { return runSeq(out[i].RunID) > runSeq(out[j].RunID) })
	return out
}

// AdminHandler is the operator-facing management API: read sources/runs/
// upstreams (the console's data backbone + observability surface) and manage
// sources and upstreams. A non-empty token is required (operator audience).
func (s *Server) AdminHandler(token string) http.Handler {
	mux := http.NewServeMux()
	g := func(h http.HandlerFunc) http.HandlerFunc { return s.adminGuard(token, h) }
	mux.HandleFunc("GET /admin/runs", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.RunLog()) }))
	mux.HandleFunc("GET /admin/audit/verify", g(func(w http.ResponseWriter, _ *http.Request) {
		v, err := VerifyAuditLog(s.auditPath())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}))
	mux.HandleFunc("GET /admin/refs/{ref}", g(s.adminMaterializeRef))
	mux.HandleFunc("GET /admin/metrics", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Metrics()) }))
	mux.HandleFunc("GET /admin/infra", g(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.InfraStatus(r.Context())) }))
	mux.HandleFunc("GET /admin/upstreams", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.UpstreamList()) }))
	mux.HandleFunc("GET /admin/egress-policy", g(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.EgressPolicy()) }))
	mux.HandleFunc("POST /admin/upstreams", g(s.adminAddUpstream))
	// The OAuth callback is a browser redirect from the upstream — no operator token;
	// it is protected by the unguessable state + PKCE, not the admin bearer.
	mux.HandleFunc("GET /admin/oauth/callback", s.adminOAuthCallback)
	mux.HandleFunc("POST /admin/upstreams/{name}/enable", g(s.adminEnableUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/reauth", g(s.adminReauthUpstream))
	mux.HandleFunc("POST /admin/upstreams/{name}/read-only", g(s.adminSetReadOnly))
	mux.HandleFunc("POST /admin/upstreams/{name}/owner", g(s.adminSetOwner))
	mux.HandleFunc("GET /admin/oauth-scopes", g(s.adminOAuthScopes))
	mux.HandleFunc("GET /admin/provider-params", g(s.adminProviderParams))
	mux.HandleFunc("GET /admin/registry", g(s.adminRegistrySearch))
	mux.HandleFunc("POST /admin/registry/import", g(s.adminRegistryImport))
	mux.HandleFunc("DELETE /admin/upstreams/{name}", g(s.adminDeleteUpstream))
	return mux
}

// adminMaterializeRef delivers the actual data behind a reference to the
// authorized operator — the out-of-band channel that lets a human retrieve PII a
// run kept off the model's context. It NEVER passes through the agent: it's
// gated by the operator token and the retrieval is itself audited (ASK tenets 2
// and 13 — every access to the data leaves a trace).
func (s *Server) adminMaterializeRef(w http.ResponseWriter, r *http.Request) {
	if s.budget.Store == nil {
		http.Error(w, "references are not enabled", http.StatusNotFound)
		return
	}
	ref := r.PathValue("ref")
	payload, ok := s.budget.Store.Get(refstore.Ref(ref))
	if !ok {
		http.Error(w, "unknown reference", http.StatusNotFound)
		return
	}
	s.putRun(s.nextRunID(), runRecord{
		Kind: "materialize", SourceID: ref, User: "operator",
		OutputBytes: len(payload), Bytes: len(payload),
	})
	name := strings.Trim(ref, "<>")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".txt"))
	_, _ = io.WriteString(w, payload)
}

// adminGuard enforces the operator bearer token (constant-time) on every route.
func (s *Server) adminGuard(token string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, r)
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
		// Owner scopes the connection to ONE authenticated principal (by token
		// subject): only that user can find or invoke it. "" = shared with every
		// authenticated user of this gateway.
		Owner string `json:"owner"`
		// ScopeParams narrows the upstream connection AT THE PROVIDER: operator-approved
		// values for a known provider's curated scoping knobs (e.g. Supabase project_ref,
		// read_only), appended to the MCP URL as query params before registration. Distinct
		// from ReadOnly, which gates write tools at our boundary after the fact.
		ScopeParams map[string]string `json:"scope_params"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
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
	u := &gateway.Upstream{Name: in.Name, URL: in.URL, Token: in.Token, Client: s.upstreamClient}
	// No static token → probe for OAuth. If the upstream requires it, start the web
	// flow and return an authorize URL for the operator's browser to visit (no PAT).
	if in.Token == "" {
		if rm, perr := u.Probe(r.Context()); perr == nil && rm != "" {
			authURL, aerr := s.startUpstreamOAuth(r.Context(), in.Name, in.URL, in.Discover, false, in.ReadOnly, in.Owner, in.Scope, rm, callbackURL(r))
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
	var err error
	state := "enabled"
	if in.Discover {
		err, state = s.DiscoverUpstream(r.Context(), u, opts...), "discovered"
	} else {
		err = s.AddUpstream(r.Context(), u, opts...)
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
	s.persistRegistration(in.Name, in.URL, in.Discover, authKind, in.Owner)
	if in.ReadOnly {
		_ = s.SetUpstreamReadOnly(in.Name, true)
		s.persistReadOnly(in.Name, true)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": in.Name, "state": state, "read_only": in.ReadOnly, "owner": in.Owner})
}

// adminSetOwner scopes (or, with "", un-scopes) a connection to one principal's
// subject. Operator-plane: assigning ownership is a trust decision, so it lives
// behind the operator token like every other grant.
func (s *Server) adminSetOwner(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.SetUpstreamOwner(name, in.Owner); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
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
	writeJSON(w, http.StatusOK, map[string]any{"oauth": true, "scopes": meta.ScopesSupported})
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
		if err := s.AddDiscovered(u, sv.Tools, "catalog"); err != nil {
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
	for _, up := range s.UpstreamList() {
		if up.Name == name {
			url, state = up.URL, up.State
			break
		}
	}
	if url == "" {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	u := &gateway.Upstream{Name: name, URL: url, Client: s.upstreamClient}
	rm, perr := u.Probe(r.Context())
	if perr != nil || rm == "" {
		http.Error(w, "upstream does not advertise OAuth", http.StatusBadRequest)
		return
	}
	authURL, aerr := s.startUpstreamOAuth(r.Context(), name, url, state == "discovered", true, false, "", in.Scope, rm, callbackURL(r))
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "authorization_required", "authorize_url": authURL})
}

func (s *Server) adminDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	if !s.RemoveUpstream(r.PathValue("name")) {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	s.removeRegistration(r.Context(), r.PathValue("name")) // stay gone across restarts
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
