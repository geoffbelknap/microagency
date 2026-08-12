package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"microagency/internal/authui"
)

const (
	// refreshTTL is how long a refresh token stays valid. It's a stateless signed
	// JWT, so the operator's session survives microagency restarts (no re-auth on
	// every rebuild) without any server-side state to persist.
	refreshTTL = 30 * 24 * time.Hour
	// refreshAudienceSuffix binds a refresh token to a distinct audience so it can
	// never be replayed as an access token (or vice versa).
	refreshAudienceSuffix = "#refresh"
)

// AuthServer is a self-contained, single-user OAuth 2.1 authorization server: open
// dynamic client registration, authorization-code + PKCE with a one-click consent
// page, and refresh tokens. It mints ES256 access tokens via the Signer that the
// resource server (same process) validates. Single-user collapses the hard parts —
// there is one principal ("operator"), so "login" is the single Approve click.
type AuthServer struct {
	signer    *Signer
	issuer    string        // our own URL, e.g. http://127.0.0.1:8765
	audience  string        // this resource's identifier
	accessTTL time.Duration // access-token lifetime

	mu          sync.Mutex
	clients     map[string]clientReg // client_id -> registration
	codes       map[string]authCode  // auth code -> pending grant (single-use, short TTL)
	pending     map[string]authCode  // public flow waiting for approval on the loopback listener
	clientsPath string               // if set, client registrations persist here across restarts

	resource        string
	approvalBase    string
	revocations     *RevocationList
	requireState    bool
	requireResource bool

	// Subject is the `sub` this single-user AS stamps on the tokens it issues — the
	// one local principal. Defaults to "operator"; main sets it to the OS user so
	// runs are attributed to the real human, matching the console header. When
	// microagency grows multi-principal, this stops being a single fixed value.
	Subject string
}

type clientReg struct {
	redirectURIs []string
	name         string
}

type authCode struct {
	clientID      string
	redirectURI   string
	codeChallenge string
	subject       string
	scope         string
	state         string
	resource      string
	expiry        time.Time
}

// NewAuthServer builds an AS that issues for audience, identified by issuer (our
// own URL). accessTTL defaults to 1h.
func NewAuthServer(signer *Signer, issuer, audience string, accessTTL time.Duration) *AuthServer {
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	revocations, _ := NewRevocationList("")
	return &AuthServer{
		signer: signer, issuer: issuer, audience: audience, accessTTL: accessTTL,
		clients: map[string]clientReg{}, codes: map[string]authCode{}, pending: map[string]authCode{},
		resource: audience, revocations: revocations,
		Subject: "operator",
	}
}

// ConfigurePublicFlow binds authorization requests to resource and moves the
// human consent decision to approvalBase, which must be an HTTP loopback origin
// served by the separate operator listener. The operator credential therefore
// never crosses the public tunnel.
func (s *AuthServer) ConfigurePublicFlow(resource, approvalBase string, revocations *RevocationList) error {
	u, err := url.Parse(approvalBase)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("public OAuth approval URL must be a loopback HTTP origin")
	}
	if strings.TrimSpace(resource) == "" {
		return fmt.Errorf("public OAuth resource must be non-empty")
	}
	if revocations == nil {
		return fmt.Errorf("public OAuth revocation list is required")
	}
	s.resource = resource
	s.approvalBase = strings.TrimSuffix(approvalBase, "/")
	s.revocations = revocations
	s.requireState = true
	s.requireResource = true
	return nil
}

// Revocations returns the list shared with the built-in resource server.
func (s *AuthServer) Revocations() *RevocationList { return s.revocations }

// Register mounts the AS routes onto mux. The protected-resource metadata
// (/.well-known/oauth-protected-resource) is served separately by the caller.
func (s *AuthServer) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("/oauth/register", s.register)
	mux.HandleFunc("/oauth/authorize", s.authorize)
	mux.HandleFunc("/oauth/token", s.token)
	mux.HandleFunc("/oauth/revoke", s.revoke)
	mux.HandleFunc("/oauth/jwks", s.jwks)
}

// RegisterOperator mounts the public flow's consent page on the loopback-only
// operator mux. It never mounts on the tunneled mux.
func (s *AuthServer) RegisterOperator(mux *http.ServeMux) {
	if s.approvalBase != "" {
		mux.HandleFunc("/oauth/consent", s.operatorConsent)
	}
}

func (s *AuthServer) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + "/oauth/authorize",
		"token_endpoint":                                 s.issuer + "/oauth/token",
		"revocation_endpoint":                            s.issuer + "/oauth/revoke",
		"registration_endpoint":                          s.issuer + "/oauth/register",
		"jwks_uri":                                       s.issuer + "/oauth/jwks",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"}, // public clients (PKCE)
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               []string{"mcp"},
	})
}

// register is open dynamic client registration (RFC 7591). Single user, loopback —
// there is nothing to vet; we hand back a client_id bound to the redirect URIs.
func (s *AuthServer) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var in struct {
		RedirectURIs      []string `json:"redirect_uris"`
		ClientName        string   `json:"client_name"`
		TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
		GrantTypes        []string `json:"grant_types"`
		ResponseTypes     []string `json:"response_types"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&in); err != nil || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	if err := ensureJSONEOF(dec); err != nil || len(in.ClientName) > 200 ||
		(in.TokenEndpointAuth != "" && in.TokenEndpointAuth != "none") ||
		!onlySupported(in.GrantTypes, "authorization_code", "refresh_token") ||
		!onlySupported(in.ResponseTypes, "code") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	seen := make(map[string]bool, len(in.RedirectURIs))
	for _, redirectURI := range in.RedirectURIs {
		if !validRedirectURI(redirectURI, s.requireResource) || seen[redirectURI] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
			return
		}
		seen[redirectURI] = true
	}
	id := randToken(16)
	s.mu.Lock()
	if len(s.clients) >= 4096 {
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	s.clients[id] = clientReg{redirectURIs: in.RedirectURIs, name: firstNonBlank(in.ClientName, "an MCP client")}
	s.persistClientsLocked() // survive restart, so the client's cached client_id stays known
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"redirect_uris":              in.RedirectURIs,
		"client_name":                in.ClientName,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
	})
}

// authorize renders the one-click consent page (GET) and issues an auth code on
// approval (POST). An unregistered client or mismatched redirect_uri is a hard 400
// — we never redirect to an unvetted URI.
func (s *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		q = r.Form
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	state := q.Get("state")
	scope := firstNonBlank(q.Get("scope"), "mcp")
	resource := q.Get("resource")

	s.mu.Lock()
	client, known := s.clients[clientID]
	s.mu.Unlock()
	if !known || !contains(client.redirectURIs, redirectURI) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || !validPKCEChallenge(challenge) || q.Get("code_challenge_method") != "S256" ||
		scope != "mcp" || (s.requireState && state == "") || (s.requireResource && resource != s.resource) {
		s.redirectErr(w, r, redirectURI, state, "invalid_request")
		return
	}
	if s.approvalBase != "" {
		if r.Method != http.MethodGet {
			http.Error(w, "public consent is decided on the operator listener", http.StatusMethodNotAllowed)
			return
		}
		requestID := randToken(24)
		s.mu.Lock()
		s.prunePendingLocked(time.Now())
		s.pending[requestID] = authCode{
			clientID: clientID, redirectURI: redirectURI, codeChallenge: challenge,
			subject: s.currentSubjectLocked(), scope: scope, state: state,
			resource: resource, expiry: time.Now().Add(5 * time.Minute),
		}
		s.mu.Unlock()
		u := s.approvalBase + "/oauth/consent?request=" + url.QueryEscape(requestID)
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		authui.WriteConsent(w, client.name, redirectURI, map[string]string{
			"response_type": "code", "client_id": clientID, "redirect_uri": redirectURI,
			"code_challenge": challenge, "code_challenge_method": "S256", "state": state, "scope": scope,
		})
		return
	}
	// POST = the consent decision.
	if q.Get("approve") != "yes" {
		s.redirectErr(w, r, redirectURI, state, "access_denied")
		return
	}
	code := randToken(24)
	s.mu.Lock()
	s.codes[code] = authCode{
		clientID: clientID, redirectURI: redirectURI, codeChallenge: challenge,
		subject: s.currentSubjectLocked(), scope: scope, resource: resource, expiry: time.Now().Add(60 * time.Second),
	}
	s.mu.Unlock()
	s.redirectAuthorizationResult(w, r, redirectURI, state, "code", code)
}

// operatorConsent is deliberately reachable only on the separate loopback
// listener. The public authorization endpoint redirects the operator's browser
// here, proving local presence without asking for or transmitting the operator
// bearer through the tunnel.
func (s *AuthServer) operatorConsent(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRemote(r.RemoteAddr) {
		http.Error(w, "loopback only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid consent", http.StatusBadRequest)
			return
		}
		requestID = r.Form.Get("request")
	}

	s.mu.Lock()
	s.prunePendingLocked(time.Now())
	pending, ok := s.pending[requestID]
	client := s.clients[pending.clientID]
	if r.Method == http.MethodPost && ok {
		delete(s.pending, requestID)
	}
	s.mu.Unlock()
	if !ok || requestID == "" {
		authui.WriteMessage(w, "This authorization request is missing, expired, or was already used.")
		return
	}
	if r.Method == http.MethodGet {
		authui.WriteConsent(w, client.name, pending.redirectURI, map[string]string{"request": requestID})
		return
	}
	if r.Form.Get("approve") != "yes" {
		s.redirectErr(w, r, pending.redirectURI, pending.state, "access_denied")
		return
	}
	code := randToken(24)
	pending.expiry = time.Now().Add(60 * time.Second)
	s.mu.Lock()
	s.codes[code] = pending
	s.mu.Unlock()
	s.redirectAuthorizationResult(w, r, pending.redirectURI, pending.state, "code", code)
}

func (s *AuthServer) currentSubjectLocked() string {
	if s.Subject == "" {
		return "operator"
	}
	return s.Subject
}

func (s *AuthServer) prunePendingLocked(now time.Time) {
	for id, pending := range s.pending {
		if !pending.expiry.After(now) {
			delete(s.pending, id)
		}
	}
}

// token exchanges an auth code (verifying PKCE) or a refresh token for a fresh
// ES256 access token.
func (s *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	f := r.Form
	w.Header().Set("Cache-Control", "no-store")
	switch f.Get("grant_type") {
	case "authorization_code":
		s.grantCode(w, f)
	case "refresh_token":
		s.grantRefresh(w, f)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (s *AuthServer) grantCode(w http.ResponseWriter, f url.Values) {
	code := f.Get("code")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code) // single-use, even on failure
	s.mu.Unlock()
	if !ok || time.Now().After(ac.expiry) || !validPKCEVerifier(f.Get("code_verifier")) ||
		ac.clientID != f.Get("client_id") || ac.redirectURI != f.Get("redirect_uri") ||
		pkceS256(f.Get("code_verifier")) != ac.codeChallenge ||
		(ac.resource != "" && f.Get("resource") != ac.resource) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	s.issueTokens(w, ac.subject, ac.scope, ac.clientID)
}

func (s *AuthServer) grantRefresh(w http.ResponseWriter, f url.Values) {
	_, scope, clientID, tokenID, expiry, ok := s.parseRefreshGrant(f.Get("refresh_token"))
	requestedClientID := f.Get("client_id")
	if clientID == "" && !s.requireResource {
		// Upgrade path for refresh tokens minted before client binding and jti
		// were added. A successful refresh replaces the legacy token with a
		// bound, rotating token. Public OAuth never accepts this legacy form.
		clientID = requestedClientID
	}
	if !ok || clientID == "" || clientID != requestedClientID || (s.requireResource && tokenID == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if tokenID != "" {
		consumed, err := s.revocations.Consume(tokenID, expiry)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		if !consumed {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
	}
	// Single-user AS: the identity is always the current local principal, not the
	// subject baked into an older refresh token. Re-stamp s.Subject so an upgraded
	// binary (e.g. one that now attributes to the real OS user instead of the
	// legacy "operator") corrects the attribution WITHOUT forcing re-consent. The
	// refresh token still had to be one we signed — it proves the session, the
	// identity is ours to set. This changes when microagency grows multi-principal.
	s.mu.Lock()
	subject := s.Subject
	s.mu.Unlock()
	if subject == "" {
		subject = "operator"
	}
	s.issueTokens(w, subject, scope, clientID)
}

// parseRefresh verifies a refresh JWT this server signed and bound to the refresh
// audience. The grant rides in the token; the persistent revocation list records
// only consumed token IDs, so sessions and replay protection survive restarts.
func (s *AuthServer) parseRefresh(raw string) (subject, scope string, ok bool) {
	subject, scope, _, _, _, ok = s.parseRefreshGrant(raw)
	return subject, scope, ok
}

func (s *AuthServer) parseRefreshGrant(raw string) (subject, scope, clientID, tokenID string, expiry time.Time, ok bool) {
	if raw == "" {
		return "", "", "", "", time.Time{}, false
	}
	claims, valid := s.parseOwnedToken(raw, s.audience+refreshAudienceSuffix)
	if !valid {
		return "", "", "", "", time.Time{}, false
	}
	subject, _ = claims["sub"].(string)
	scope, _ = claims["scope"].(string)
	clientID, _ = claims["client_id"].(string)
	tokenID, _ = claims["jti"].(string)
	exp, _ := claims.GetExpirationTime()
	if exp != nil {
		expiry = exp.Time
	}
	if subject == "" || expiry.IsZero() || s.revocations.IsRevoked(tokenID) {
		return "", "", "", "", time.Time{}, false
	}
	return subject, scope, clientID, tokenID, expiry, true
}

// revoke implements RFC 7009 for self-issued access and refresh tokens. The
// response is deliberately 200 for unknown/invalid tokens to avoid an oracle.
func (s *AuthServer) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	f := r.Form
	raw := f.Get("token")
	claims, ok := s.parseOwnedToken(raw, s.audience)
	if !ok {
		claims, ok = s.parseOwnedToken(raw, s.audience+refreshAudienceSuffix)
	}
	if ok {
		id, _ := claims["jti"].(string)
		exp, _ := claims.GetExpirationTime()
		if id != "" && exp != nil {
			if err := s.revocations.Revoke(id, exp.Time); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
				return
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *AuthServer) parseOwnedToken(raw, audience string) (jwt.MapClaims, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	tok, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return s.signer.PublicKey(), nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, false
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	return claims, ok
}

func (s *AuthServer) issueTokens(w http.ResponseWriter, subject, scope, clientID string) {
	access, err := s.signer.Mint(s.issuer, s.audience, subject, strings.Fields(scope), s.accessTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Refresh token: a JWT bound to the refresh audience (never usable as an access
	// token). Stateless, so it outlives restarts.
	rt, err := s.signer.mint(s.issuer, s.audience+refreshAudienceSuffix, subject, strings.Fields(scope), refreshTTL, map[string]any{"client_id": clientID})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.accessTTL.Seconds()),
		"refresh_token": rt,
		"scope":         scope,
	})
}

// jwks publishes the signer's public key (so AS metadata's jwks_uri resolves; the
// resource server validates locally, so it isn't load-bearing).
func (s *AuthServer) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pub := s.signer.PublicKey()
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.signer.KID(),
		"x": b64Coord(pub.X.Bytes()), "y": b64Coord(pub.Y.Bytes()),
	}}})
}

// --- helpers ---

func (s *AuthServer) redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	s.redirectAuthorizationResult(w, r, redirectURI, state, "error", code)
}

func (s *AuthServer) redirectAuthorizationResult(w http.ResponseWriter, r *http.Request, redirectURI, state, key, value string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, value, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set(key, value)
	q.Set("iss", s.issuer)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("extra JSON value")
		}
		return err
	}
	return nil
}

func onlySupported(got []string, allowed ...string) bool {
	if len(got) == 0 {
		return true
	}
	for _, value := range got {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func validRedirectURI(raw string, public bool) bool {
	if len(raw) == 0 || len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		return u.Host != "" && isLoopbackHost(u.Hostname())
	default:
		// Private-use callback schemes remain available to local clients. The
		// public AS accepts only HTTPS or loopback HTTP redirects.
		return !public && u.Scheme != "file" && (u.Host != "" || u.Path != "")
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return isLoopbackHost(host)
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) < 43 || len(challenge) > 128 {
		return false
	}
	for _, c := range challenge {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

func pkceS256(verifier string) string {
	if verifier == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error()) // unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64Coord left-pads an EC coordinate to the P-256 field size (32 bytes) before
// base64url, as required for JWK x/y.
func b64Coord(b []byte) string {
	const size = 32
	if len(b) < size {
		p := make([]byte, size)
		copy(p[size-len(b):], b)
		b = p
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonBlank(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
