package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"microagency/internal/gateway"
	"microagency/internal/secretstore"
)

const (
	maxConnectionTemplates       = 64
	maxSelfServiceConnections    = 1024
	defaultConnectionsPerUser    = 4
	maxConnectionsPerUser        = 16
	maxPendingConnectionsPerUser = 4
	maxPendingConnectionsGlobal  = 256
	maxConnectionStartsPerHour   = 10
	maxRateTrackedPrincipals     = 4096
)

// ConnectionTemplate is an operator-approved upstream shape a principal may
// instantiate with their own OAuth grant. It contains no credential. The URL,
// scopes, provider parameters, read-only posture, and quota are all operator
// bounds; a user can only narrow them.
type ConnectionTemplate struct {
	ID               string   `json:"id"`
	DisplayName      string   `json:"display_name"`
	URL              string   `json:"url"`
	AllowedScopes    []string `json:"allowed_scopes,omitempty"`
	DefaultScopes    []string `json:"default_scopes,omitempty"`
	AllowedParams    []string `json:"allowed_params,omitempty"`
	ReadOnly         bool     `json:"read_only"`
	MaxPerUser       int      `json:"max_per_user"`
	Disabled         bool     `json:"disabled,omitempty"`
	ClientConfigured bool     `json:"client_configured,omitempty"`
}

type startWindow struct {
	Since time.Time
	Count int
}

type pendingConnection struct {
	Owner, Template string
	Expiry          time.Time
}

type selfServiceStore struct {
	adminMu   sync.Mutex // serializes template + template-client mutations
	mu        sync.Mutex
	templates map[string]ConnectionTemplate
	versions  map[string]uint64
	starts    map[string]startWindow
	pending   map[string]pendingConnection
}

func newSelfServiceStore() selfServiceStore {
	return selfServiceStore{
		templates: map[string]ConnectionTemplate{},
		versions:  map[string]uint64{},
		starts:    map[string]startWindow{},
		pending:   map[string]pendingConnection{},
	}
}

func (s *Server) connectionTemplatesPath() string {
	return filepath.Join(s.stateDir, "connection-templates.json")
}

func (s *Server) loadConnectionTemplates() {
	if s.stateDir == "" {
		return
	}
	b, err := os.ReadFile(s.connectionTemplatesPath())
	if err != nil {
		return
	}
	var templates []ConnectionTemplate
	if json.Unmarshal(b, &templates) != nil {
		return
	}
	s.self.mu.Lock()
	defer s.self.mu.Unlock()
	for _, template := range templates {
		if normalizeConnectionTemplate(&template) == nil {
			s.self.templates[template.ID] = template
			s.self.versions[template.ID] = 1
		}
	}
}

func (s *Server) writeConnectionTemplatesLocked() error {
	if s.stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		return err
	}
	templates := make([]ConnectionTemplate, 0, len(s.self.templates))
	for _, template := range s.self.templates {
		templates = append(templates, template)
	}
	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	b, err := json.Marshal(templates)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.stateDir, ".connection-templates-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.connectionTemplatesPath()); err != nil {
		return err
	}
	dir, err := os.Open(s.stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func normalizeConnectionTemplate(template *ConnectionTemplate) error {
	template.ID = strings.TrimSpace(template.ID)
	if len(template.ID) == 0 || len(template.ID) > 48 {
		return errors.New("template id must be 1-48 characters")
	}
	for _, c := range template.ID {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return errors.New("template id may contain only lowercase letters, digits, and hyphens")
		}
	}
	template.DisplayName = strings.TrimSpace(template.DisplayName)
	if template.DisplayName == "" {
		template.DisplayName = template.ID
	}
	if len(template.DisplayName) > 120 || len(template.URL) > 4096 {
		return errors.New("template display name or URL is too long")
	}
	u, err := url.Parse(strings.TrimSpace(template.URL))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("template URL must be an absolute upstream URL without userinfo or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return errors.New("template URL must use HTTPS (loopback HTTP is allowed for local development)")
	}
	template.URL = u.String()
	allowed, err := normalizeScopes(template.AllowedScopes)
	if err != nil {
		return fmt.Errorf("allowed scopes: %w", err)
	}
	defaults, err := normalizeScopes(template.DefaultScopes)
	if err != nil {
		return fmt.Errorf("default scopes: %w", err)
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = true
	}
	for _, scope := range defaults {
		if !allowedSet[scope] {
			return fmt.Errorf("default scope %q is not operator-allowed", scope)
		}
	}
	template.AllowedScopes, template.DefaultScopes = allowed, defaults
	if len(template.AllowedParams) > 8 {
		return errors.New("at most 8 provider parameters may be allowed")
	}
	provider, known := providerForURL(template.URL)
	knownParams := map[string]bool{}
	for _, param := range provider.Params {
		knownParams[param.Name] = true
	}
	seen := map[string]bool{}
	params := make([]string, 0, len(template.AllowedParams))
	for _, param := range template.AllowedParams {
		param = strings.TrimSpace(param)
		if param == "" || seen[param] || !known || !knownParams[param] {
			return fmt.Errorf("provider parameter %q is not a curated parameter for this URL", param)
		}
		seen[param] = true
		params = append(params, param)
	}
	sort.Strings(params)
	template.AllowedParams = params
	if template.MaxPerUser == 0 {
		template.MaxPerUser = defaultConnectionsPerUser
	}
	if template.MaxPerUser < 1 || template.MaxPerUser > maxConnectionsPerUser {
		return fmt.Errorf("max_per_user must be between 1 and %d", maxConnectionsPerUser)
	}
	return nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) > 32 {
		return nil, errors.New("at most 32 scopes are allowed")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > 256 {
			return nil, errors.New("scope is empty or too long")
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return nil, fmt.Errorf("scope %q is malformed", scope)
			}
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// opaquePrincipal derives the secret-path segment for one caller from the
// canonical principal key (issuer#subject). Hashing the composite key keeps
// raw identities out of secret paths AND keeps two issuers' identical subjects
// on different paths — a bare-subject digest would collide them.
func opaquePrincipal(key string) string {
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

func selfServiceTokenKey(owner, name string) string {
	return "self-service/subjects/" + opaquePrincipal(owner) + "/upstreams/" + name + "/token"
}

func selfServiceClientKey(owner, template, upstreamURL string) string {
	sum := sha256.Sum256([]byte(upstreamURL))
	return "self-service/subjects/" + opaquePrincipal(owner) + "/clients/" + template + "/" + base64.RawURLEncoding.EncodeToString(sum[:12])
}

func templateClientKey(template string) string {
	return "self-service/templates/" + template + "/client"
}

func credentialKeyForRegistration(reg upstreamReg) string {
	if reg.strategyKind() == StrategyGoogleDWD {
		return DelegationKeyKey(reg.Name)
	}
	if reg.SelfService && reg.Owner != "" {
		return selfServiceTokenKey(reg.Owner, reg.Name)
	}
	return tokenKey(reg.Name)
}

func (s *Server) recordConnectionEvent(owner, name, action string) {
	s.putRun(s.nextRunID(), runRecord{Kind: "connection", Upstream: name, Tool: action, User: owner})
}

func (s *Server) reserveConnectionStart(owner, template string, maxPerUser, existingForTemplate, existingGlobal int, reauth bool) (string, error) {
	if owner == "" || len(owner) > 1024 || strings.ContainsRune(owner, '\x00') {
		return "", errors.New("authenticated principal identity is missing or too long")
	}
	s.self.mu.Lock()
	defer s.self.mu.Unlock()
	now := time.Now()
	for subject, rate := range s.self.starts {
		if now.Sub(rate.Since) >= time.Hour {
			delete(s.self.starts, subject)
		}
	}
	for id, pending := range s.self.pending {
		if now.After(pending.Expiry) {
			delete(s.self.pending, id)
		}
	}
	window := s.self.starts[owner]
	if window.Since.IsZero() && len(s.self.starts) >= maxRateTrackedPrincipals {
		return "", errors.New("gateway connection authorization rate capacity reached")
	}
	if window.Since.IsZero() || now.Sub(window.Since) >= time.Hour {
		window = startWindow{Since: now}
	}
	if window.Count >= maxConnectionStartsPerHour {
		return "", errors.New("connection authorization rate limit reached; try again later")
	}
	pendingUser, pendingTemplate := 0, 0
	for _, pending := range s.self.pending {
		if pending.Owner == owner {
			pendingUser++
			if pending.Template == template {
				pendingTemplate++
			}
		}
	}
	if pendingUser >= maxPendingConnectionsPerUser || len(s.self.pending) >= maxPendingConnectionsGlobal {
		return "", errors.New("too many connection authorizations are pending")
	}
	if !reauth {
		if existingForTemplate+pendingTemplate >= maxPerUser {
			return "", errors.New("connection quota reached for this template")
		}
		if existingGlobal+len(s.self.pending) >= maxSelfServiceConnections {
			return "", errors.New("gateway self-service connection quota reached")
		}
	}
	id := randomConnectionSuffix(18)
	s.self.pending[id] = pendingConnection{Owner: owner, Template: template, Expiry: now.Add(10 * time.Minute)}
	window.Count++
	s.self.starts[owner] = window
	return id, nil
}

func (s *Server) releaseConnectionStart(id string) {
	if id == "" {
		return
	}
	s.self.mu.Lock()
	delete(s.self.pending, id)
	s.self.mu.Unlock()
}

func (s *Server) selfServiceCounts(owner, template string) (perTemplate, global int) {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	for _, connection := range s.reg.conns {
		if !connection.selfService {
			continue
		}
		global++
		if connection.owner == owner && connection.template == template {
			perTemplate++
		}
	}
	return perTemplate, global
}

func randomConnectionSuffix(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (s *Server) connectionTemplate(id string, includeDisabled bool) (ConnectionTemplate, bool) {
	template, _, ok := s.connectionTemplateWithVersion(id, includeDisabled)
	return template, ok
}

func (s *Server) connectionTemplateWithVersion(id string, includeDisabled bool) (ConnectionTemplate, uint64, bool) {
	s.self.mu.Lock()
	defer s.self.mu.Unlock()
	template, ok := s.self.templates[id]
	if !ok || (template.Disabled && !includeDisabled) {
		return ConnectionTemplate{}, 0, false
	}
	return template, s.self.versions[id], true
}

// commitSelfServiceOAuth performs the network-bound tool load first, then commits
// under the template and registry locks. The template version and connection auth
// generation are checked in the same critical section as registration/rebind, so
// a concurrent operator policy edit or revocation wins without a visibility gap.
func (s *Server) commitSelfServiceOAuth(ctx context.Context, flow *oauthFlow, conn upstreamConn) error {
	_ = conn.Initialize(ctx)
	tools, err := conn.ListTools(ctx)
	if err != nil {
		return err
	}
	suggestion := suggestionFor(tools)
	s.self.mu.Lock()
	defer s.self.mu.Unlock()
	template, ok := s.self.templates[flow.template]
	if !ok || template.Disabled || s.self.versions[flow.template] != flow.templateVersion {
		return errors.New("connection template changed while authorization was in progress; start again")
	}
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	if flow.reauth {
		record, ok := s.reg.conns[flow.name]
		if !ok || !record.selfService || record.owner != flow.owner || record.template != flow.template {
			return fmt.Errorf("gateway: unknown upstream %q", flow.name)
		}
		if record.authGeneration != flow.authGeneration {
			return fmt.Errorf("gateway: upstream %q authorization changed while rebinding; start again", flow.name)
		}
		record.conn = conn
		record.tools = tools
		record.minimizeSuggested = suggestion
		if record.revoked {
			record.enabled = true
		}
		record.revoked = false
		return nil
	}
	if _, exists := s.reg.conns[flow.name]; exists {
		return fmt.Errorf("gateway: upstream %q already registered", flow.name)
	}
	provenance := "preloaded"
	if flow.discover {
		provenance = "discovered"
	}
	s.reg.conns[flow.name] = &upstream{
		conn: conn, tools: tools, enabled: !flow.discover, provenance: provenance,
		readOnly: flow.readOnly, owner: flow.owner, selfService: true,
		template: flow.template, label: flow.label, authGeneration: flow.authGeneration,
		minimizeSuggested: suggestion,
	}
	return nil
}

func (s *Server) listConnectionTemplates(includeDisabled bool) []ConnectionTemplate {
	s.self.mu.Lock()
	defer s.self.mu.Unlock()
	out := make([]ConnectionTemplate, 0, len(s.self.templates))
	for _, template := range s.self.templates {
		if !template.Disabled || includeDisabled {
			out = append(out, template)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) adminListConnectionTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.listConnectionTemplates(true))
}

func (s *Server) adminPutConnectionTemplate(w http.ResponseWriter, r *http.Request) {
	s.self.adminMu.Lock()
	defer s.self.adminMu.Unlock()
	var in struct {
		ConnectionTemplate
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
		ClearClient  bool    `json:"clear_client"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	template := in.ConnectionTemplate
	template.ClientConfigured = false // derived from the secret store, never caller-controlled
	if err := normalizeConnectionTemplate(&template); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if (in.ClientID != nil || in.ClientSecret != nil) && (in.ClientID == nil || strings.TrimSpace(*in.ClientID) == "") {
		http.Error(w, "client_id is required when configuring a template OAuth client", http.StatusBadRequest)
		return
	}
	if in.ClearClient && in.ClientID != nil {
		http.Error(w, "clear_client and client_id are mutually exclusive", http.StatusBadRequest)
		return
	}
	if in.ClientID != nil && len(*in.ClientID) > 512 || in.ClientSecret != nil && len(*in.ClientSecret) > 4096 {
		http.Error(w, "template OAuth client value is too long", http.StatusBadRequest)
		return
	}
	existingTemplate, existed := s.connectionTemplate(template.ID, true)
	s.self.mu.Lock()
	atTemplateLimit := !existed && len(s.self.templates) >= maxConnectionTemplates
	s.self.mu.Unlock()
	if atTemplateLimit {
		http.Error(w, "connection template quota reached", http.StatusConflict)
		return
	}
	clientMutated := in.ClientID != nil || in.ClearClient
	var previousClient []byte
	previousClientExists := false
	if clientMutated && s.secrets != nil {
		var loadErr error
		previousClient, loadErr = s.secrets.Load(r.Context(), templateClientKey(template.ID))
		switch {
		case loadErr == nil:
			previousClientExists = true
		case errors.Is(loadErr, secretstore.ErrNotFound):
			previousClient = nil
		default:
			http.Error(w, "read existing template OAuth client: "+loadErr.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	if in.ClientID != nil {
		if s.secrets == nil {
			http.Error(w, "a secret store is required for a template OAuth client", http.StatusServiceUnavailable)
			return
		}
		secret := ""
		if in.ClientSecret != nil {
			secret = *in.ClientSecret
		}
		b, _ := json.Marshal(storedClient{ClientID: strings.TrimSpace(*in.ClientID), ClientSecret: secret})
		if err := s.secrets.Save(r.Context(), templateClientKey(template.ID), b); err != nil {
			http.Error(w, "store template OAuth client: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		template.ClientConfigured = true
	} else if in.ClearClient {
		if s.secrets != nil {
			if err := s.secrets.Delete(r.Context(), templateClientKey(template.ID)); err != nil && err != secretstore.ErrNotFound {
				http.Error(w, "delete template OAuth client: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		template.ClientConfigured = false
	} else if existed {
		template.ClientConfigured = existingTemplate.ClientConfigured
	}
	s.self.mu.Lock()
	previous, existed := s.self.templates[template.ID]
	s.self.templates[template.ID] = template
	err := s.writeConnectionTemplatesLocked()
	if err != nil {
		if existed {
			s.self.templates[template.ID] = previous
		} else {
			delete(s.self.templates, template.ID)
		}
	} else {
		s.self.versions[template.ID]++
		if s.self.versions[template.ID] == 0 {
			s.self.versions[template.ID] = 1
		}
	}
	s.self.mu.Unlock()
	if err != nil {
		if clientMutated && s.secrets != nil {
			var rollbackErr error
			if previousClientExists {
				rollbackErr = s.secrets.Save(r.Context(), templateClientKey(template.ID), previousClient)
			} else {
				rollbackErr = s.secrets.Delete(r.Context(), templateClientKey(template.ID))
				if rollbackErr == secretstore.ErrNotFound {
					rollbackErr = nil
				}
			}
			err = errors.Join(err, rollbackErr)
		}
		http.Error(w, "persist connection template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Any template edit can narrow its URL, scopes, parameters, or client. Cancel
	// old pending flows so callbacks cannot complete under superseded policy.
	s.cancelOAuthFlows(func(flow *oauthFlow) bool { return flow.selfService && flow.template == template.ID })
	writeJSON(w, http.StatusOK, template)
}

func (s *Server) adminDeleteConnectionTemplate(w http.ResponseWriter, r *http.Request) {
	s.self.adminMu.Lock()
	defer s.self.adminMu.Unlock()
	id := r.PathValue("id")
	s.self.mu.Lock()
	template, ok := s.self.templates[id]
	if !ok {
		s.self.mu.Unlock()
		http.Error(w, "unknown connection template", http.StatusNotFound)
		return
	}
	delete(s.self.templates, id)
	previousVersion := s.self.versions[id]
	delete(s.self.versions, id)
	err := s.writeConnectionTemplatesLocked()
	if err != nil {
		s.self.templates[id] = template
		s.self.versions[id] = previousVersion
	}
	s.self.mu.Unlock()
	if err != nil {
		http.Error(w, "persist connection templates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.cancelOAuthFlows(func(flow *oauthFlow) bool { return flow.selfService && flow.template == id })
	if s.secrets != nil {
		if err := s.secrets.Delete(r.Context(), templateClientKey(id)); err != nil && err != secretstore.ErrNotFound {
			http.Error(w, "delete template OAuth client: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminDisableUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.DisableUpstream(name); err != nil {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	if err := s.persistDisabledStrict(name); err != nil {
		http.Error(w, "connection disabled, but durable state failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "state": "discovered"})
}

func (s *Server) adminRevokeUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.cancelOAuthFlows(func(flow *oauthFlow) bool { return flow.name == name })
	if err := s.RevokeUpstream(name); err != nil {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	if err := s.revokeRegistration(r.Context(), name); err != nil {
		http.Error(w, "credential revocation failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.recordConnectionEvent(operatorActor(r), name, "revoked")
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "state": "revoked"})
}

// UserConnectionsHandler serves the principal-authenticated self-service
// management plane. It adds HTTP routes beside /mcp; it does not add MCP tools.
func (s *Server) UserConnectionsHandler(a Authenticator, callbackBase, resourceMetadata string) (http.Handler, error) {
	u, err := url.Parse(strings.TrimSuffix(callbackBase, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("self-service callback base must be an absolute origin")
	}
	callback := strings.TrimSuffix(u.String(), "/") + "/connections/oauth/callback"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		s.completeUpstreamOAuth(w, r, true)
	})
	g := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			principal, err := a.Authenticate(r)
			if err != nil {
				metadata := resourceMetadata
				if metadata == "" {
					metadata = "/.well-known/oauth-protected-resource"
				}
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadata+`"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
		}
	}
	mux.HandleFunc("GET /connections/templates", g(s.userListConnectionTemplates))
	mux.HandleFunc("GET /connections", g(s.userListConnections))
	mux.HandleFunc("POST /connections", g(func(w http.ResponseWriter, r *http.Request) { s.userStartConnection(w, r, callback) }))
	mux.HandleFunc("PATCH /connections/{name}", g(s.userSetConnectionLabel))
	mux.HandleFunc("POST /connections/{name}/refresh", g(s.userRefreshConnection))
	mux.HandleFunc("POST /connections/{name}/reauthorize", g(func(w http.ResponseWriter, r *http.Request) { s.userReauthorizeConnection(w, r, callback) }))
	mux.HandleFunc("DELETE /connections/{name}", g(s.userDeleteConnection))
	return mux, nil
}

// userConnectionTemplate is the published shape of a template. It carries the
// template itself plus the curated provider parameters resolved for its URL, so
// a client can render a labelled field per parameter instead of guessing what
// "project_ref" means. Params is exactly AllowedParams — the operator's choice —
// expanded with each one's description and kind. It never carries a credential:
// a template's configured OAuth client is a bool, and the client_id and secret
// live only in the secret store.
type userConnectionTemplate struct {
	ConnectionTemplate
	Params []ProviderParam `json:"params,omitempty"`
}

// templateParams resolves the operator-allowed parameter names to the curated
// catalog entries for the template's URL, in catalog order. Names the catalog
// no longer declares are dropped rather than rendered without meaning.
func templateParams(template ConnectionTemplate) []ProviderParam {
	if len(template.AllowedParams) == 0 {
		return nil
	}
	provider, ok := providerForURL(template.URL)
	if !ok {
		return nil
	}
	allowed := make(map[string]bool, len(template.AllowedParams))
	for _, name := range template.AllowedParams {
		allowed[name] = true
	}
	out := make([]ProviderParam, 0, len(template.AllowedParams))
	for _, param := range provider.Params {
		if allowed[param.Name] {
			out = append(out, param)
		}
	}
	return out
}

func (s *Server) userListConnectionTemplates(w http.ResponseWriter, _ *http.Request) {
	templates := s.listConnectionTemplates(false)
	out := make([]userConnectionTemplate, 0, len(templates))
	for _, template := range templates {
		out = append(out, userConnectionTemplate{ConnectionTemplate: template, Params: templateParams(template)})
	}
	writeJSON(w, http.StatusOK, out)
}

type userConnectionInfo struct {
	Name string `json:"name"`
	// Label is the caller's own human-meaningful name for this connection, or
	// empty when it has none. It is what the caller's agent sees beside every
	// tool this connection exposes.
	Label    string `json:"label,omitempty"`
	Template string `json:"template"`
	URL      string `json:"url"`
	State    string `json:"state"`
	ReadOnly bool   `json:"read_only"`
	Tools    int    `json:"tools"`
	// LastOK is the RFC 3339 time of this connection's last successful call, or
	// empty when it has not been used since the gateway started. It is the
	// caller's own usage, on the caller's own connection.
	LastOK string `json:"last_ok,omitempty"`
}

func (s *Server) userListConnections(w http.ResponseWriter, r *http.Request) {
	owner := callerKey(r.Context())
	all := s.UpstreamList()
	out := make([]userConnectionInfo, 0, len(all))
	for _, connection := range all {
		if connection.SelfService && connection.Owner == owner {
			out = append(out, userConnectionInfo{
				Name: connection.Name, Label: connection.Label, Template: connection.Template, URL: connection.URL,
				State: connection.State, ReadOnly: connection.ReadOnly,
				Tools: connection.Tools, LastOK: connection.LastOK,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func requestedTemplateScopes(template ConnectionTemplate, requested []string) (string, error) {
	if len(requested) == 0 {
		requested = template.DefaultScopes
	}
	normalized, err := normalizeScopes(requested)
	if err != nil {
		return "", err
	}
	allowed := map[string]bool{}
	for _, scope := range template.AllowedScopes {
		allowed[scope] = true
	}
	for _, scope := range normalized {
		if !allowed[scope] {
			return "", fmt.Errorf("scope %q is not allowed by the connection template", scope)
		}
	}
	return strings.Join(normalized, " "), nil
}

func scopedTemplateURL(template ConnectionTemplate, values map[string]string) (string, error) {
	if len(values) > len(template.AllowedParams) || len(values) > 8 {
		return "", errors.New("too many provider parameters")
	}
	allowed := map[string]bool{}
	for _, name := range template.AllowedParams {
		allowed[name] = true
	}
	for name := range values {
		if !allowed[name] {
			return "", fmt.Errorf("provider parameter %q is not allowed by the connection template", name)
		}
		if len(values[name]) > 2048 {
			return "", fmt.Errorf("provider parameter %q is too long", name)
		}
	}
	return ScopedURL(template.URL, values)
}

func templateMatchesConnection(definition ConnectionTemplate, connectionURL string) bool {
	template, err1 := url.Parse(definition.URL)
	connection, err2 := url.Parse(connectionURL)
	if err1 != nil || err2 != nil {
		return false
	}
	for _, param := range definition.AllowedParams {
		tq, cq := template.Query(), connection.Query()
		tq.Del(param)
		cq.Del(param)
		template.RawQuery, connection.RawQuery = tq.Encode(), cq.Encode()
	}
	return template.String() == connection.String()
}

func (s *Server) templateClient(ctx context.Context, template ConnectionTemplate) (string, string, error) {
	if !template.ClientConfigured {
		return "", "", nil
	}
	if s.secrets == nil {
		return "", "", errors.New("template OAuth client store is unavailable")
	}
	raw, err := s.secrets.Load(ctx, templateClientKey(template.ID))
	if err != nil {
		return "", "", err
	}
	var client storedClient
	if err := json.Unmarshal(raw, &client); err != nil || client.ClientID == "" {
		return "", "", errors.New("template OAuth client record is invalid")
	}
	return client.ClientID, client.ClientSecret, nil
}

func (s *Server) userStartConnection(w http.ResponseWriter, r *http.Request, callback string) {
	var in struct {
		Template string            `json:"template"`
		Scopes   []string          `json:"scopes"`
		Params   map[string]string `json:"params"`
		Label    string            `json:"label"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Naming the connection at creation closes the window in which a second
	// connection from the same template exists and neither can be told apart.
	label, err := validateConnectionLabel(in.Label)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	template, templateVersion, ok := s.connectionTemplateWithVersion(in.Template, false)
	if !ok {
		http.Error(w, "unknown connection template", http.StatusNotFound)
		return
	}
	scope, err := requestedTemplateScopes(template, in.Scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstreamURL, err := scopedTemplateURL(template, in.Params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	owner := callerKey(r.Context())
	perTemplate, global := s.selfServiceCounts(owner, template.ID)
	reservation, err := s.reserveConnectionStart(owner, template.ID, template.MaxPerUser, perTemplate, global, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	keepReservation := false
	defer func() {
		if !keepReservation {
			s.releaseConnectionStart(reservation)
		}
	}()
	name := template.ID + "-" + randomConnectionSuffix(9)
	u := &gateway.Upstream{Name: name, URL: upstreamURL, Client: s.upstreamClient}
	metadata, err := u.Probe(r.Context())
	if err != nil || metadata == "" {
		http.Error(w, "upstream does not advertise OAuth", http.StatusBadGateway)
		return
	}
	clientID, clientSecret, err := s.templateClient(r.Context(), template)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	authorizeURL, err := s.startUpstreamOAuth(r.Context(), name, upstreamURL, false, false, template.ReadOnly, owner, scope, metadata, callback, clientID, clientSecret,
		withSelfServiceOAuth(template.ID, templateVersion, selfServiceTokenKey(owner, name), selfServiceClientKey(owner, template.ID, upstreamURL), 0),
		withConnectionLabel(label),
		withConnectionReservation(reservation))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	keepReservation = true
	s.recordConnectionEvent(owner, name, "authorization_started")
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "authorization_required", "name": name, "authorize_url": authorizeURL})
}

// userSetConnectionLabel names one of the caller's OWN connections. A label on an
// owned connection reaches only that principal's agent context, which is why the
// principal sets it here rather than asking the operator; a label on a shared
// connection reaches every admitted caller and is set on the operator surface
// instead.
//
// An invalid label is refused with the reason, never trimmed or rewritten into
// something acceptable. Sending {"label":""} clears it.
func (s *Server) userSetConnectionLabel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	owner := callerKey(r.Context())
	if _, ok := s.ownedSelfServiceConnection(r.Context(), name); !ok {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	var in struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	label, err := validateConnectionLabel(in.Label)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.SetUpstreamLabel(name, label); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.persistLabel(name, label)
	s.recordConnectionEvent(owner, name, "labelled")
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "label": label})
}

func (s *Server) ownedSelfServiceConnection(ctx context.Context, name string) (upstream, bool) {
	record, ok := s.snapshotUpstream(name)
	if !ok || !record.selfService || record.owner != callerKey(ctx) {
		return upstream{}, false
	}
	return record, true
}

func (s *Server) userRefreshConnection(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	owner := callerKey(r.Context())
	if _, ok := s.ownedSelfServiceConnection(r.Context(), name); !ok {
		s.recordConnectionEvent(owner, "", "refresh_denied")
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	if err := s.RefreshUpstream(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.recordConnectionEvent(owner, name, "refreshed")
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "status": "refreshed"})
}

func (s *Server) userReauthorizeConnection(w http.ResponseWriter, r *http.Request, callback string) {
	name := r.PathValue("name")
	owner := callerKey(r.Context())
	record, ok := s.ownedSelfServiceConnection(r.Context(), name)
	if !ok {
		s.recordConnectionEvent(owner, "", "reauthorize_denied")
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	template, templateVersion, ok := s.connectionTemplateWithVersion(record.template, false)
	if !ok {
		http.Error(w, "connection template is disabled or removed", http.StatusForbidden)
		return
	}
	if !templateMatchesConnection(template, record.conn.Endpoint()) {
		http.Error(w, "connection template endpoint changed; delete and recreate this connection", http.StatusConflict)
		return
	}
	var in struct {
		Scopes []string `json:"scopes"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in)
	scope, err := requestedTemplateScopes(template, in.Scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	perTemplate, global := s.selfServiceCounts(owner, template.ID)
	reservation, err := s.reserveConnectionStart(owner, template.ID, template.MaxPerUser, perTemplate, global, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	keepReservation := false
	defer func() {
		if !keepReservation {
			s.releaseConnectionStart(reservation)
		}
	}()
	u := &gateway.Upstream{Name: name, URL: record.conn.Endpoint(), Client: s.upstreamClient}
	metadata, err := u.Probe(r.Context())
	if err != nil || metadata == "" {
		http.Error(w, "upstream does not advertise OAuth", http.StatusBadGateway)
		return
	}
	clientID, clientSecret, err := s.templateClient(r.Context(), template)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	discover := !record.enabled && !record.revoked
	authorizeURL, err := s.startUpstreamOAuth(r.Context(), name, record.conn.Endpoint(), discover, true, record.readOnly, owner, scope, metadata, callback, clientID, clientSecret,
		withSelfServiceOAuth(template.ID, templateVersion, selfServiceTokenKey(owner, name), selfServiceClientKey(owner, template.ID, record.conn.Endpoint()), record.authGeneration),
		withConnectionReservation(reservation))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	keepReservation = true
	s.recordConnectionEvent(owner, name, "reauthorization_started")
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "authorization_required", "name": name, "authorize_url": authorizeURL})
}

func (s *Server) userDeleteConnection(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	owner := callerKey(r.Context())
	record, ok := s.ownedSelfServiceConnection(r.Context(), name)
	if !ok {
		s.recordConnectionEvent(owner, "", "delete_denied")
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	s.cancelOAuthFlows(func(flow *oauthFlow) bool { return flow.name == name })
	if err := s.RevokeUpstream(name); err != nil {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	if err := s.removeSelfServiceRegistration(r.Context(), name, record); err != nil {
		http.Error(w, "connection disabled, but durable deletion failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_ = s.RemoveUpstream(name)
	s.deleteSelfServiceClientIfUnused(r.Context(), owner, record.template, record.conn.Endpoint())
	s.recordConnectionEvent(owner, name, "deleted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteSelfServiceClientIfUnused(ctx context.Context, owner, template, upstreamURL string) {
	for _, reg := range s.loadRegistrations() {
		if reg.SelfService && reg.Owner == owner && reg.Template == template {
			return
		}
	}
	s.flows.mu.Lock()
	for _, flow := range s.flows.byState {
		if flow.selfService && flow.owner == owner && flow.template == template && time.Now().Before(flow.expiry) {
			s.flows.mu.Unlock()
			return
		}
	}
	s.flows.mu.Unlock()
	if s.secrets != nil {
		_ = s.secrets.Delete(ctx, selfServiceClientKey(owner, template, upstreamURL))
	}
}
