package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"microagency/internal/auth"
	"microagency/internal/mcp"
	"microagency/internal/secretstore"
)

func TestParseUpOptionsSSOFlags(t *testing.T) {
	o, err := parseUpOptions([]string{
		"--public", "--sso-issuer", "https://accounts.google.com",
		"--sso-client-id", "gw-client", "--sso-hd", "corp.example",
		"--sso-client-secret-file", "/run/secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.ssoIssuer != "https://accounts.google.com" || o.ssoClientID != "gw-client" ||
		o.ssoHD != "corp.example" || o.ssoClientSecretFile != "/run/secret" {
		t.Fatalf("parsed options = %+v", o)
	}

	refused := []struct {
		name string
		args []string
		want string // remediation substring
	}{
		{"client-id without issuer", []string{"--sso-client-id", "x"}, "--sso-issuer"},
		{"secret-file without issuer", []string{"--sso-client-secret-file", "/p"}, "--sso-issuer"},
		{"hd without issuer", []string{"--sso-hd", "corp.example"}, "--sso-issuer"},
		{"issuer without client-id", []string{"--sso-issuer", "https://idp.example"}, "--sso-client-id"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseUpOptions(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestSSOFlagExclusivity(t *testing.T) {
	sso := func(cfg httpConfig) httpConfig {
		cfg.ssoIssuer, cfg.ssoClientID = "https://idp.example", "gw-client"
		return cfg
	}
	refused := []struct {
		name string
		cfg  httpConfig
		want string
	}{
		{"sso with external issuer", sso(httpConfig{addr: "127.0.0.1:8765", issuer: "https://as.example"}), "mutually exclusive"},
		{"sso with static bearer", sso(httpConfig{addr: "127.0.0.1:8765", token: "tok"}), "mutually exclusive"},
		{"sso with --single-user", sso(httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", singleUser: true}), "mutually exclusive"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHTTPConfig(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}

	// Federation is the multi-user posture, so the public single-user gate does
	// not fire: a tunnel plus --sso-issuer starts without --single-user.
	accepted := []httpConfig{
		sso(httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare"}),
		sso(httpConfig{addr: "127.0.0.1:8765"}), // local federation needs no tunnel
	}
	for _, cfg := range accepted {
		if err := validateHTTPConfig(cfg); err != nil {
			t.Fatalf("safe config rejected: %+v: %v", cfg, err)
		}
	}
}

// The public-tunnel refusal points multi-user operators at federation.
func TestPublicGateNamesFederationRemediation(t *testing.T) {
	err := validateHTTPConfig(httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare"})
	if err == nil || !strings.Contains(err.Error(), "--sso-issuer") {
		t.Fatalf("refusal %v does not offer --sso-issuer", err)
	}
}

func TestUpHelpListsSSOFlags(t *testing.T) {
	stdout, _, _ := runHelpHelper(t, "up", "--help")
	for _, want := range []string{"--sso-issuer <url>", "--sso-client-id <id>", "--sso-client-secret-file <path>", "--sso-hd <domain>"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("up --help is missing %q:\n%s", want, stdout)
		}
	}
}

func TestResolveSSOClientSecret(t *testing.T) {
	dir := t.TempDir()
	store, err := secretstore.Open(dir, func(string) string { return "" }, secretstore.Options{AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := httpConfig{ssoIssuer: "https://idp.example", ssoClientID: "gw-client"}
	ctx := context.Background()

	// No secret anywhere: the error names both supply paths.
	t.Setenv(ssoClientSecretEnv, "")
	if _, err := resolveSSOClientSecret(ctx, store, cfg); err == nil ||
		!strings.Contains(err.Error(), ssoClientSecretEnv) || !strings.Contains(err.Error(), "--sso-client-secret-file") {
		t.Fatalf("missing-secret err = %v", err)
	}

	// Supplied via env: stored, then read back with no env on the next start.
	t.Setenv(ssoClientSecretEnv, "s3cret")
	if got, err := resolveSSOClientSecret(ctx, store, cfg); err != nil || got != "s3cret" {
		t.Fatalf("env secret = %q, %v", got, err)
	}
	t.Setenv(ssoClientSecretEnv, "")
	if got, err := resolveSSOClientSecret(ctx, store, cfg); err != nil || got != "s3cret" {
		t.Fatalf("stored secret = %q, %v", got, err)
	}

	// A different client id cannot silently reuse the stored secret.
	changed := cfg
	changed.ssoClientID = "another-client"
	if _, err := resolveSSOClientSecret(ctx, store, changed); err == nil || !strings.Contains(err.Error(), "gw-client") {
		t.Fatalf("client-change err = %v", err)
	}

	// Two live sources at once is invalid configuration, naming both.
	t.Setenv(ssoClientSecretEnv, "s3cret")
	file := writeFile(t, dir, "sso-secret", "other\n")
	both := cfg
	both.ssoClientSecretFile = file
	if _, err := resolveSSOClientSecret(ctx, store, both); err == nil ||
		!strings.Contains(err.Error(), ssoClientSecretEnv) || !strings.Contains(err.Error(), "--sso-client-secret-file") {
		t.Fatalf("dual-source err = %v", err)
	}

	// File alone works and trims the trailing newline.
	t.Setenv(ssoClientSecretEnv, "")
	if got, err := resolveSSOClientSecret(ctx, store, both); err != nil || got != "other" {
		t.Fatalf("file secret = %q, %v", got, err)
	}
}

// --- stub OIDC provider (discovery + authorize + token + ES256 JWKS) --------

type testOIDCProvider struct {
	ts   *httptest.Server
	priv *ecdsa.PrivateKey

	mu    sync.Mutex
	codes map[string]testOIDCCode
	sub   string
	email string
	hd    string
}

type testOIDCCode struct {
	redirectURI, nonce, challenge string
	sub, email, hd                string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testOIDCProvider{priv: priv, codes: map[string]testOIDCCode{}, sub: "user-alpha", email: "alpha@corp.example"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.ts.URL,
			"authorization_endpoint": p.ts.URL + "/authorize",
			"token_endpoint":         p.ts.URL + "/token",
			"jwks_uri":               p.ts.URL + "/jwks",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")
		p.mu.Lock()
		p.codes[code] = testOIDCCode{
			redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
			sub: p.sub, email: p.email, hd: p.hd,
		}
		p.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		dest := u.Query()
		dest.Set("code", code)
		dest.Set("state", q.Get("state"))
		u.RawQuery = dest.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.Form
		if f.Get("client_id") != "gw-client" || f.Get("client_secret") != "gw-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		sc, ok := p.codes[f.Get("code")]
		delete(p.codes, f.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || sc.redirectURI != f.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != sc.challenge {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{
			"iss": p.ts.URL, "aud": "gw-client", "sub": sc.sub,
			"email": sc.email, "email_verified": true, "nonce": sc.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		if sc.hd != "" {
			claims["hd"] = sc.hd
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["kid"] = "stub-1"
		signed, err := tok.SignedString(p.priv)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque", "token_type": "Bearer", "expires_in": 300, "id_token": signed,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := p.priv.PublicKey
		pad := func(i *big.Int) string {
			b := make([]byte, 32)
			i.FillBytes(b)
			return base64.RawURLEncoding.EncodeToString(b)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "stub-1",
			"x": pad(pub.X), "y": pad(pub.Y),
		}}})
	})
	p.ts = httptest.NewServer(mux)
	t.Cleanup(p.ts.Close)
	return p
}

// The whole federated flow through the real muxes: DCR, authorize redirecting
// to the provider, the provider callback completing the grant, and a token
// whose subject is the provider's sub — proving the cmd wiring end to end,
// including the env-supplied client secret landing in the secret store.
func TestLocalFederatedFlowThroughMuxes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ssoClientSecretEnv, "gw-secret")
	provider := newTestOIDCProvider(t)

	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", authDir: t.TempDir(),
		ssoIssuer: provider.ts.URL, ssoClientID: "gw-client",
		// A dedicated tenant: the issuer is the membership boundary, which is
		// the declaration this flow test models.
		ssoAnyAccount: true,
	}
	mcpMux, _, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-local" {
		t.Fatalf("mode = %q", mode)
	}
	gw := httptest.NewServer(mcpMux)
	t.Cleanup(gw.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Dynamic client registration, as an MCP client does it.
	regBody := strings.NewReader(`{"redirect_uris":["http://127.0.0.1:7777/cb"],"client_name":"t"}`)
	regResp, err := c.Post(gw.URL+"/oauth/register", "application/json", regBody)
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	_ = regResp.Body.Close()

	verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {"http://127.0.0.1:7777/cb"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"client-state"}, "scope": {"mcp"},
	}
	r1, err := c.Get(gw.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusSeeOther || !strings.HasPrefix(r1.Header.Get("Location"), provider.ts.URL) {
		t.Fatalf("authorize = %d -> %q, want provider redirect", r1.StatusCode, r1.Header.Get("Location"))
	}
	r2, err := c.Get(r1.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	back, err := url.Parse(r2.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	// The provider redirects to the gateway's advertised origin; route the
	// browser hop to the test listener serving the same mux.
	r3, err := c.Get(gw.URL + back.Path + "?" + back.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	_ = r3.Body.Close()
	if r3.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d, want client redirect", r3.StatusCode)
	}
	clientLoc, _ := url.Parse(r3.Header.Get("Location"))
	code := clientLoc.Query().Get("code")
	if code == "" || clientLoc.Query().Get("state") != "client-state" {
		t.Fatalf("client redirect = %q", r3.Header.Get("Location"))
	}

	tokResp, err := c.PostForm(gw.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {reg.ClientID},
		"redirect_uri": {"http://127.0.0.1:7777/cb"}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	_ = tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token exchange = %d", tokResp.StatusCode)
	}
	parts := strings.Split(tokens.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "user-alpha" {
		t.Fatalf("token sub = %q, want the provider sub", claims.Sub)
	}
	if claims.Iss != "http://127.0.0.1:8765" {
		t.Fatalf("token iss = %q, want the gateway issuer — the gateway stays the AS", claims.Iss)
	}

	// No consent surface can approve a federated grant.
	consent, err := c.PostForm(gw.URL+"/oauth/authorize", url.Values{"request": {"x"}, "approve": {"yes"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = consent.Body.Close()
	if consent.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("federated consent POST = %d, want 405", consent.StatusCode)
	}
}

// In federated tunnel mode the operator listener carries no consent page:
// sign-in happens at the provider, and the operator mux must not offer a
// surface that could approve a grant.
func TestFederatedTunnelMountsNoOperatorConsent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ssoClientSecretEnv, "gw-secret")
	provider := newTestOIDCProvider(t)

	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "cloudflare", publicURL: "https://gateway.example",
		authDir: t.TempDir(), ssoIssuer: provider.ts.URL, ssoClientID: "gw-client",
	}
	mcpMux, adminMux, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-tunnel" || adminMux == mcpMux {
		t.Fatalf("mode/split = %q/%v", mode, adminMux != mcpMux)
	}
	rec := httptest.NewRecorder()
	adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/consent?request=x", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("operator consent in federated mode = %d, want 404", rec.Code)
	}
	// The provider callback is on the tunneled mux, where the provider's
	// browser redirect can reach it.
	cb := httptest.NewRecorder()
	mcpMux.ServeHTTP(cb, httptest.NewRequest(http.MethodGet, "/oauth/sso/callback?state=unknown", nil))
	if cb.Code != http.StatusOK {
		t.Fatalf("callback with unknown state = %d, want the notice page", cb.Code)
	}
}

func TestRecordAuthPostureSSOFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "cloudflare", publicURL: "https://gateway.example",
		ssoIssuer: "https://idp.example", ssoHD: "corp.example",
	}
	if _, err := recordAuthPostureAt(cfg, "oauth-tunnel", path); err != nil {
		t.Fatal(err)
	}
	posture, err := readAuthPosture(path)
	if err != nil {
		t.Fatal(err)
	}
	if posture.SSOIssuer != "https://idp.example" || posture.SSOHostedDomain != "corp.example" {
		t.Fatalf("posture = %+v", posture)
	}
}

func TestDoctorReportsFederatedPosture(t *testing.T) {
	dir := t.TempDir()
	b, _ := json.Marshal(authPosture{
		Mode: "oauth-tunnel", Issuer: "https://gateway.example", Resource: "https://gateway.example/mcp",
		Audience: "https://gateway.example/mcp", Tunnel: "cloudflare",
		SSOIssuer: "https://idp.example", SSOHostedDomain: "corp.example",
	})
	path := writeFile(t, dir, "auth-posture.json", string(b))
	var out strings.Builder
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{})
	for _, want := range []string{
		"federated to https://idp.example",
		"audience        accounts with hd=corp.example",
		"multi-user — each provider account is a distinct principal",
		"audit capture",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("federated doctor page is missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "single-user") {
		t.Errorf("federated doctor page still claims single-user:\n%s", out.String())
	}

	// A dedicated tenant reads as the deliberate declaration it is, naming the
	// flag that made it, rather than as a missing bound.
	b, _ = json.Marshal(authPosture{
		Mode: "oauth-local", Issuer: "http://127.0.0.1:8765",
		SSOIssuer: "https://idp.example", SSOAnyAccount: true,
	})
	path = writeFile(t, dir, "auth-posture.json", string(b))
	out.Reset()
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{})
	if !strings.Contains(out.String(), "audience        any account at https://idp.example (--sso-any-account") {
		t.Errorf("dedicated-tenant audience line missing:\n%s", out.String())
	}

	// Rules alone bound the audience, and the page counts them without naming
	// anyone: a diagnostic page is not a roster.
	b, _ = json.Marshal(authPosture{Mode: "oauth-local", Issuer: "http://127.0.0.1:8765", SSOIssuer: "https://idp.example"})
	path = writeFile(t, dir, "auth-posture.json", string(b))
	out.Reset()
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{Groups: 2, Identities: 1})
	if !strings.Contains(out.String(), "audience        accounts matching 2 groups + 1 identity") {
		t.Errorf("rule-bounded audience line missing:\n%s", out.String())
	}

	// A federated gateway with every bound removed cannot serve anyone. That is
	// fail-closed, and it is still a broken deployment the page must report.
	out.Reset()
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{})
	if !strings.Contains(out.String(), "⚠ none declared") {
		t.Errorf("undeclared audience is not flagged:\n%s", out.String())
	}
}

// setUser selects the identity the provider asserts on the next sign-in.
func (p *testOIDCProvider) setUser(sub, email string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sub, p.email = sub, email
}
