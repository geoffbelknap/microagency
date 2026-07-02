package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	clientsPath string               // if set, client registrations persist here across restarts
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
	expiry        time.Time
}

// NewAuthServer builds an AS that issues for audience, identified by issuer (our
// own URL). accessTTL defaults to 1h.
func NewAuthServer(signer *Signer, issuer, audience string, accessTTL time.Duration) *AuthServer {
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	return &AuthServer{
		signer: signer, issuer: issuer, audience: audience, accessTTL: accessTTL,
		clients: map[string]clientReg{}, codes: map[string]authCode{},
	}
}

// Register mounts the AS routes onto mux. The protected-resource metadata
// (/.well-known/oauth-protected-resource) is served separately by the caller.
func (s *AuthServer) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("/oauth/register", s.register)
	mux.HandleFunc("/oauth/authorize", s.authorize)
	mux.HandleFunc("/oauth/token", s.token)
	mux.HandleFunc("/oauth/jwks", s.jwks)
}

func (s *AuthServer) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth/authorize",
		"token_endpoint":                        s.issuer + "/oauth/token",
		"registration_endpoint":                 s.issuer + "/oauth/register",
		"jwks_uri":                              s.issuer + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"}, // public clients (PKCE)
		"scopes_supported":                      []string{"mcp"},
	})
}

// register is open dynamic client registration (RFC 7591). Single user, loopback —
// there is nothing to vet; we hand back a client_id bound to the redirect URIs.
func (s *AuthServer) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	id := randToken(16)
	s.mu.Lock()
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
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		q = mustParseForm(r)
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	state := q.Get("state")
	scope := firstNonBlank(q.Get("scope"), "mcp")

	s.mu.Lock()
	client, known := s.clients[clientID]
	s.mu.Unlock()
	if !known || !contains(client.redirectURIs, redirectURI) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || challenge == "" || q.Get("code_challenge_method") != "S256" {
		redirectErr(w, r, redirectURI, state, "invalid_request")
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
		redirectErr(w, r, redirectURI, state, "access_denied")
		return
	}
	code := randToken(24)
	s.mu.Lock()
	s.codes[code] = authCode{
		clientID: clientID, redirectURI: redirectURI, codeChallenge: challenge,
		subject: "operator", scope: scope, expiry: time.Now().Add(60 * time.Second),
	}
	s.mu.Unlock()
	u, _ := url.Parse(redirectURI)
	rq := u.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token exchanges an auth code (verifying PKCE) or a refresh token for a fresh
// ES256 access token.
func (s *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f := mustParseForm(r)
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
	if !ok || time.Now().After(ac.expiry) ||
		ac.clientID != f.Get("client_id") || ac.redirectURI != f.Get("redirect_uri") ||
		pkceS256(f.Get("code_verifier")) != ac.codeChallenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	s.issueTokens(w, ac.subject, ac.scope)
}

func (s *AuthServer) grantRefresh(w http.ResponseWriter, f url.Values) {
	subject, scope, ok := s.parseRefresh(f.Get("refresh_token"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	s.issueTokens(w, subject, scope)
}

// parseRefresh verifies a stateless refresh token (a JWT this server signed, bound
// to the refresh audience) and returns its subject + scope. Stateless is the whole
// point: the grant rides in the token and the signing key persists, so the session
// survives a restart with no server-side map to forget.
func (s *AuthServer) parseRefresh(raw string) (subject, scope string, ok bool) {
	if raw == "" {
		return "", "", false
	}
	tok, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return s.signer.PublicKey(), nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience+refreshAudienceSuffix))
	if err != nil || !tok.Valid {
		return "", "", false
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	subject, _ = claims["sub"].(string)
	scope, _ = claims["scope"].(string)
	return subject, scope, subject != ""
}

func (s *AuthServer) issueTokens(w http.ResponseWriter, subject, scope string) {
	access, err := s.signer.Mint(s.issuer, s.audience, subject, strings.Fields(scope), s.accessTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Refresh token: a JWT bound to the refresh audience (never usable as an access
	// token). Stateless, so it outlives restarts.
	rt, err := s.signer.Mint(s.issuer, s.audience+refreshAudienceSuffix, subject, strings.Fields(scope), refreshTTL)
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
func (s *AuthServer) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.signer.PublicKey()
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.signer.KID(),
		"x": b64Coord(pub.X.Bytes()), "y": b64Coord(pub.Y.Bytes()),
	}}})
}

// --- helpers ---

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
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

func mustParseForm(r *http.Request) url.Values {
	_ = r.ParseForm()
	return r.Form
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
