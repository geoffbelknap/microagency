package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stubProvider is a minimal OIDC identity provider: discovery, an authorize
// endpoint that auto-approves as a configurable identity, a token endpoint
// that validates client credentials + PKCE and returns a signed ID token, and
// an ES256 JWKS.
type stubProvider struct {
	ts           *httptest.Server
	priv         *ecdsa.PrivateKey
	clientID     string
	clientSecret string

	mu         sync.Mutex
	codes      map[string]stubCode
	sub        string
	email      string
	verified   bool
	hd         string
	wrongNonce bool
}

type stubCode struct {
	redirectURI string
	nonce       string
	challenge   string
	sub, email  string
	verified    bool
	hd          string
}

func newStubProvider(t *testing.T) *stubProvider {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &stubProvider{
		priv: priv, clientID: "gw-client", clientSecret: "gw-secret",
		codes: map[string]stubCode{},
		sub:   "user-alpha", email: "alpha@corp.example", verified: true, hd: "corp.example",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                 p.ts.URL,
			"authorization_endpoint": p.ts.URL + "/authorize",
			"token_endpoint":         p.ts.URL + "/token",
			"jwks_uri":               p.ts.URL + "/jwks",
		})
	})
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := p.priv.PublicKey
		writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "stub-1",
			"x": b64Coord(pub.X.Bytes()), "y": b64Coord(pub.Y.Bytes()),
		}}})
	})
	p.ts = httptest.NewServer(mux)
	t.Cleanup(p.ts.Close)
	return p
}

func (p *stubProvider) setUser(sub, email string, verified bool, hd string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sub, p.email, p.verified, p.hd = sub, email, verified, hd
}

func (p *stubProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.clientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := randToken(16)
	p.mu.Lock()
	p.codes[code] = stubCode{
		redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		sub: p.sub, email: p.email, verified: p.verified, hd: p.hd,
	}
	p.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	dest := u.Query()
	dest.Set("code", code)
	dest.Set("state", q.Get("state"))
	u.RawQuery = dest.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *stubProvider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.Form
	if f.Get("client_id") != p.clientID || f.Get("client_secret") != p.clientSecret {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	sc, ok := p.codes[f.Get("code")]
	delete(p.codes, f.Get("code"))
	tamper := p.wrongNonce
	p.wrongNonce = false
	p.mu.Unlock()
	if !ok || sc.redirectURI != f.Get("redirect_uri") || pkceS256(f.Get("code_verifier")) != sc.challenge {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	nonce := sc.nonce
	if tamper {
		nonce = "not-the-nonce"
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": p.ts.URL, "aud": p.clientID, "sub": sc.sub,
		"email": sc.email, "email_verified": sc.verified, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if sc.hd != "" {
		claims["hd"] = sc.hd
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "stub-1"
	signed, err := tok.SignedString(p.priv)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token": "opaque-provider-token", "token_type": "Bearer", "expires_in": 300,
		"id_token": signed,
	})
}

// newFederatedAS builds an AuthServer federated to a stub provider.
func newFederatedAS(t *testing.T, hostedDomain string) (*httptest.Server, *AuthServer, *stubProvider, *http.Client) {
	t.Helper()
	provider := newStubProvider(t)
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	var as *AuthServer
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	as = NewAuthServer(signer, ts.URL, testAud, time.Hour, nil)
	fed, err := DiscoverFederation(context.Background(), FederationConfig{
		Issuer: provider.ts.URL, ClientID: provider.clientID, ClientSecret: provider.clientSecret,
		HostedDomain: hostedDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	as.ConfigureFederation(fed)
	as.Register(mux)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return ts, as, provider, c
}

// federatedSignIn walks the whole browser round-trip for one MCP-client
// authorization: authorize → provider redirect → provider auto-approval →
// gateway callback. It returns the final response (normally the redirect back
// to the MCP client with a code).
func federatedSignIn(t *testing.T, ts *httptest.Server, c *http.Client, clientID, challenge string) *http.Response {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"client-state"}, "scope": {"mcp"},
	}
	r1, err := c.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize = %d, want provider redirect 303", r1.StatusCode)
	}
	providerURL := r1.Header.Get("Location")
	r2, err := c.Get(providerURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusFound {
		t.Fatalf("provider authorize = %d, want 302 back to gateway", r2.StatusCode)
	}
	r3, err := c.Get(r2.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return r3
}

func TestFederatedFullFlow(t *testing.T) {
	ts, as, provider, c := newFederatedAS(t, "")
	provider.setUser("user-alpha", "alpha@corp.example", true, "corp.example")
	clientID := registerClient(t, ts, c)
	verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
	final := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d, want 302 to the MCP client", final.StatusCode)
	}
	loc, err := url.Parse(final.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), testRedirect) {
		t.Fatalf("callback redirected to %q, want the client redirect_uri", final.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "client-state" {
		t.Fatalf("client state = %q, want the original state", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code for the MCP client")
	}

	status, tokens := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange = %d (%v)", status, tokens)
	}
	rs := &ResourceServer{Issuer: ts.URL, Audience: testAud, Keys: as.signer.KeySet()}
	p, err := rs.Validate(context.Background(), tokens["access_token"].(string))
	if err != nil {
		t.Fatalf("minted token invalid: %v", err)
	}
	if p.Subject != "user-alpha" {
		t.Fatalf("token subject = %q, want the provider sub user-alpha", p.Subject)
	}
	if p.Issuer != ts.URL {
		t.Fatalf("token issuer = %q, want the gateway %q — the gateway stays the AS", p.Issuer, ts.URL)
	}
	if got := PrincipalKey(p.Issuer, p.Subject); got != PrincipalKey(ts.URL, "user-alpha") {
		t.Fatalf("principal key = %q", got)
	}
	if email := as.FederatedEmail("user-alpha"); email != "alpha@corp.example" {
		t.Fatalf("recorded email = %q, want the verified provider email", email)
	}
}

func TestFederatedHostedDomainRefused(t *testing.T) {
	ts, as, provider, c := newFederatedAS(t, "corp.example")
	provider.setUser("outsider", "someone@other.example", true, "other.example")
	clientID := registerClient(t, ts, c)
	final := federatedSignIn(t, ts, c, clientID, pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890"))
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode == http.StatusFound {
		t.Fatalf("hd-mismatched sign-in redirected with a code: %q", final.Header.Get("Location"))
	}
	as.mu.Lock()
	nCodes := len(as.codes)
	as.mu.Unlock()
	if nCodes != 0 {
		t.Fatalf("hd-mismatched sign-in left %d minted codes, want 0", nCodes)
	}
	if as.FederatedEmail("outsider") != "" {
		t.Fatal("hd-mismatched identity was recorded")
	}
}

func TestFederatedNonceMismatchRefused(t *testing.T) {
	ts, as, provider, c := newFederatedAS(t, "")
	provider.mu.Lock()
	provider.wrongNonce = true
	provider.mu.Unlock()
	clientID := registerClient(t, ts, c)
	final := federatedSignIn(t, ts, c, clientID, pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890"))
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode == http.StatusFound {
		t.Fatal("nonce-mismatched sign-in minted a code")
	}
	as.mu.Lock()
	nCodes := len(as.codes)
	as.mu.Unlock()
	if nCodes != 0 {
		t.Fatalf("nonce mismatch left %d minted codes, want 0", nCodes)
	}
}

func TestFederatedStateMismatchRefused(t *testing.T) {
	ts, _, provider, c := newFederatedAS(t, "")
	clientID := registerClient(t, ts, c)
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge":        {pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890")},
		"code_challenge_method": {"S256"}, "state": {"client-state"}, "scope": {"mcp"},
	}
	r1, err := c.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	providerURL := r1.Header.Get("Location")
	r2, err := c.Get(providerURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	cb, err := url.Parse(r2.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	// Same code, forged state: nothing pending matches, so no code is minted.
	forged := cb.Query()
	forged.Set("state", "forged-state-value")
	cb.RawQuery = forged.Encode()
	r3, err := c.Get(cb.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = r3.Body.Close()
	if r3.StatusCode == http.StatusFound {
		t.Fatal("forged-state callback minted a code")
	}

	_ = provider // identity irrelevant: the callback never reaches the exchange
}

// Two people signing in through the same federated gateway are two different
// principals: distinct subs, distinct canonical identity keys.
func TestFederatedDistinctPrincipals(t *testing.T) {
	ts, as, provider, c := newFederatedAS(t, "")
	clientID := registerClient(t, ts, c)
	rs := &ResourceServer{Issuer: ts.URL, Audience: testAud, Keys: as.signer.KeySet()}

	subjectFor := func(user, email string) (*Principal, string) {
		t.Helper()
		provider.setUser(user, email, true, "")
		verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
		final := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
		defer func() { _ = final.Body.Close() }()
		loc, _ := url.Parse(final.Header.Get("Location"))
		status, tokens := postForm(t, c, ts.URL+"/oauth/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
			"client_id": {clientID}, "redirect_uri": {testRedirect}, "code_verifier": {verifier},
		})
		if status != http.StatusOK {
			t.Fatalf("token exchange for %s = %d", user, status)
		}
		p, err := rs.Validate(context.Background(), tokens["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		refresh, _ := tokens["refresh_token"].(string)
		return p, refresh
	}

	alpha, _ := subjectFor("user-alpha", "alpha@corp.example")
	beta, betaRefresh := subjectFor("user-beta", "beta@corp.example")
	if alpha.Subject != "user-alpha" || beta.Subject != "user-beta" {
		t.Fatalf("subjects = %q, %q", alpha.Subject, beta.Subject)
	}
	if alpha.Key() == beta.Key() {
		t.Fatalf("two provider accounts share one principal key %q", alpha.Key())
	}

	// Refresh continues under the token's own subject — no re-contacting the
	// provider, no collapsing onto the local single-user principal.
	status, refreshed := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {betaRefresh}, "client_id": {clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("federated refresh = %d (%v)", status, refreshed)
	}
	p, err := rs.Validate(context.Background(), refreshed["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "user-beta" {
		t.Fatalf("refreshed subject = %q, want user-beta", p.Subject)
	}
}

// The local and operator consent surfaces cannot approve a federated grant:
// sign-in happens at the identity provider, nowhere else.
func TestFederatedConsentSurfacesRefuse(t *testing.T) {
	ts, _, _, c := newFederatedAS(t, "")
	resp, err := c.PostForm(ts.URL+"/oauth/authorize", url.Values{"request": {"anything"}, "approve": {"yes"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("federated consent POST = %d, want 405", resp.StatusCode)
	}
}

// An unverified provider email is not recorded.
func TestFederatedUnverifiedEmailNotRecorded(t *testing.T) {
	ts, as, provider, c := newFederatedAS(t, "")
	provider.setUser("user-unverified", "spoof@corp.example", false, "")
	clientID := registerClient(t, ts, c)
	final := federatedSignIn(t, ts, c, clientID, pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890"))
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		t.Fatalf("sign-in = %d, want success (email verification gates recording, not sign-in)", final.StatusCode)
	}
	if got := as.FederatedEmail("user-unverified"); got != "" {
		t.Fatalf("unverified email %q was recorded", got)
	}
}

// Discovery fails closed on an issuer mismatch between the configured issuer
// and the discovery document.
func TestFederationDiscoveryIssuerMismatch(t *testing.T) {
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                 "https://accounts.google.com",
			"authorization_endpoint": ts.URL + "/authorize",
			"token_endpoint":         ts.URL + "/token",
			"jwks_uri":               ts.URL + "/jwks",
		})
	})
	_, err := DiscoverFederation(context.Background(), FederationConfig{
		Issuer: ts.URL, ClientID: "x", ClientSecret: "y",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("issuer-mismatched discovery err = %v, want mismatch refusal", err)
	}
}

// Federated identities persist across a restart.
func TestFederatedIdentityPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sso-identities.json")
	signer, err := LoadOrCreateSigner(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	as.LoadFederatedIdentities(path)
	as.recordFederatedIdentity(&FederatedIdentity{Subject: "user-alpha", Email: "alpha@corp.example"}, "https://idp.example")

	restarted := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	restarted.LoadFederatedIdentities(path)
	if got := restarted.FederatedEmail("user-alpha"); got != "alpha@corp.example" {
		t.Fatalf("after restart email = %q", got)
	}
	var recs []map[string]any
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &recs) != nil || len(recs) != 1 {
		t.Fatalf("persisted file unreadable: %v %s", err, b)
	}
}
