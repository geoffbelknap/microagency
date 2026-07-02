package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// A path-bearing issuer (e.g. Robinhood's .../mcp/trading) must be discovered via
// RFC 8414 path INSERTION first; the old path-append form is only a last-resort
// fallback. A root issuer collapses to the plain well-known.
func TestASMetadataURLsPathInsertion(t *testing.T) {
	got := asMetadataURLs("https://agent.robinhood.com/mcp/trading")
	want := []string{
		"https://agent.robinhood.com/.well-known/oauth-authorization-server/mcp/trading",
		"https://agent.robinhood.com/.well-known/openid-configuration/mcp/trading",
		"https://agent.robinhood.com/mcp/trading/.well-known/openid-configuration",
		"https://agent.robinhood.com/mcp/trading/.well-known/oauth-authorization-server",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}

	root := asMetadataURLs("https://as.example.com/")
	if len(root) == 0 || root[0] != "https://as.example.com/.well-known/oauth-authorization-server" {
		t.Fatalf("root issuer first candidate = %v, want the plain well-known", root)
	}
}

// DiscoverAS must fall through a 404 on the append form and succeed on the
// path-insertion location — the exact Robinhood shape.
func TestDiscoverASFallsThroughToPathInsertion(t *testing.T) {
	var ts *httptest.Server // captured by the handlers; ts.URL is set before any request
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_servers":["` + ts.URL + `/mcp/trading"],"scopes_supported":["internal"]}`))
	})
	// Only the RFC 8414 path-insertion location serves the AS metadata — the append
	// form (.../mcp/trading/.well-known/...) 404s, so discovery must fall through.
	mux.HandleFunc("/.well-known/oauth-authorization-server/mcp/trading", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + ts.URL + `/mcp/trading","authorization_endpoint":"` + ts.URL + `/authorize","token_endpoint":"` + ts.URL + `/token"}`))
	})
	ts = httptest.NewServer(mux)
	defer ts.Close()

	meta, err := DiscoverAS(context.Background(), ts.Client(), ts.URL+"/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("DiscoverAS should have found the path-insertion metadata: %v", err)
	}
	if meta.TokenEndpoint != ts.URL+"/token" || meta.AuthorizationEndpoint != ts.URL+"/authorize" {
		t.Fatalf("wrong endpoints: %+v", meta)
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "internal" {
		t.Fatalf("scopes should fall back to the resource's: %+v", meta.ScopesSupported)
	}
}

// approveAndCode POSTs the authorize params with approve=yes (simulating the
// operator clicking Approve) and returns the issued auth code from the redirect.
func approveAndCode(t *testing.T, c *http.Client, authURL string) string {
	t.Helper()
	u, _ := url.Parse(authURL)
	form := u.Query()
	form.Set("approve", "yes")
	r, err := c.PostForm(u.Scheme+"://"+u.Host+u.Path, form)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusFound {
		t.Fatalf("approve POST = %d", r.StatusCode)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	return code
}

// TestOAuthClientFullFlowAgainstOwnAS exercises microagency's OAuth *client* against
// microagency's own *server* — discovery, DCR, PKCE, code exchange, refresh — so the
// loop closes and both sides are proven together.
func TestOAuthClientFullFlowAgainstOwnAS(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	// Unstarted so we can set issuer = the real listen addr before serving.
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()
	mux := http.NewServeMux()
	NewAuthServer(signer, issuer, "microagency", time.Hour).Register(mux)
	mux.Handle("/.well-known/oauth-protected-resource", ProtectedResourceMetadata("microagency", issuer))
	ts.Config.Handler = mux
	ts.Start()
	defer ts.Close()

	ctx := context.Background()
	const redirectURI = "http://127.0.0.1:9999/cb"
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. discover the AS from the resource's protected-resource metadata
	meta, err := DiscoverAS(ctx, noRedirect, issuer+"/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.TokenEndpoint == "" || meta.RegistrationEndpoint == "" || meta.AuthorizationEndpoint == "" {
		t.Fatalf("incomplete AS metadata: %+v", meta)
	}

	// 2. dynamic client registration
	clientID, clientSecret, err := RegisterClient(ctx, noRedirect, meta.RegistrationEndpoint, redirectURI, "microagency")
	if err != nil {
		t.Fatalf("DCR: %v", err)
	}

	// 3. PKCE + authorize, with the operator approving the consent
	p := NewPKCE()
	code := approveAndCode(t, noRedirect, AuthorizeURL(meta, clientID, redirectURI, p, "mcp", "st8"))

	// 4. exchange the code for tokens microagency will hold (cred-blind)
	tok, err := ExchangeCode(ctx, noRedirect, meta, clientID, clientSecret, redirectURI, code, p)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}

	// the token validates against the upstream's resource server
	rs := &ResourceServer{Issuer: issuer, Audience: "microagency", Keys: signer.KeySet()}
	if _, err := rs.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("access token invalid: %v", err)
	}

	// 5. refresh yields a fresh, valid access token (no re-login)
	if err := tok.Refresh(ctx, noRedirect); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := rs.Validate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("refreshed token invalid: %v", err)
	}
}

// TestRefreshTokenSurvivesRestart: a refresh token minted before a restart must
// still work after one (stateless JWT + persisted signer), so the operator isn't
// forced to re-auth on every rebuild. And an access token must never be accepted
// as a refresh token (audience binding).
func TestRefreshTokenSurvivesRestart(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	const issuer, aud = "http://127.0.0.1:8765", "microagency"
	rt, err := signer.Mint(issuer, aud+refreshAudienceSuffix, "operator", []string{"mcp"}, refreshTTL)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a restart: a brand-new AuthServer (empty maps) with the SAME signer.
	as2 := NewAuthServer(signer, issuer, aud, time.Hour)
	sub, scope, ok := as2.parseRefresh(rt)
	if !ok {
		t.Fatal("refresh token rejected after restart — the session would force re-auth")
	}
	if sub != "operator" || scope != "mcp" {
		t.Fatalf("grant lost across restart: sub=%q scope=%q", sub, scope)
	}
	access, _ := signer.Mint(issuer, aud, "operator", []string{"mcp"}, time.Hour)
	if _, _, ok := as2.parseRefresh(access); ok {
		t.Fatal("an access token was accepted as a refresh token — audience binding is broken")
	}
}

// TestTokenRecordPersistsAccessToken: the record round-trips the access token and
// its expiry, so a reload can reuse a still-valid token instead of forcing a
// refresh (which would rotate the refresh token on every restart).
func TestTokenRecordPersistsAccessToken(t *testing.T) {
	exp := time.Now().Add(time.Hour).Round(time.Second)
	orig := &UpstreamToken{
		AccessToken: "at", RefreshToken: "rt", Expiry: exp,
		tokenEndpoint: "https://as/token", clientID: "cid", clientSecret: "sec",
	}
	back := TokenFromRecord(orig.Record())
	if back.AccessToken != "at" || back.RefreshToken != "rt" || !back.Expiry.Equal(exp) {
		t.Fatalf("round trip dropped access token/expiry: %+v", back)
	}
	if back.tokenEndpoint != "https://as/token" || back.clientID != "cid" || back.clientSecret != "sec" {
		t.Fatalf("round trip dropped refresh params: %+v", back)
	}
}

// TestReloadWithValidAccessTokenDoesNotRefresh is the core of the fix: a token
// reloaded from persistence with a still-valid access token must be used as-is,
// with NO call to the token endpoint. Otherwise every restart refreshes, which
// rotates the refresh token and eventually trips "reuse detected".
func TestReloadWithValidAccessTokenDoesNotRefresh(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "token endpoint must not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tok := TokenFromRecord(TokenRecord{
		AccessToken: "still-valid", RefreshToken: "rt",
		Expiry: time.Now().Add(time.Hour), TokenEndpoint: srv.URL,
	})
	got, err := RefreshingBearer(tok, srv.Client(), nil)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "still-valid" {
		t.Fatalf("bearer = %q, want the persisted access token", got)
	}
	if hits != 0 {
		t.Fatalf("token endpoint was called %d time(s) — a restart refreshed and rotated the refresh token", hits)
	}
}

// TestReloadWithExpiredAccessTokenRefreshes: once the persisted access token is
// past expiry, the next call refreshes normally and hands the rotated refresh
// token to onRefresh for persistence.
func TestReloadWithExpiredAccessTokenRefreshes(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fresh","expires_in":3600,"refresh_token":"rt2"}`))
	}))
	defer srv.Close()

	tok := TokenFromRecord(TokenRecord{
		AccessToken: "stale", RefreshToken: "rt1",
		Expiry: time.Now().Add(-time.Minute), TokenEndpoint: srv.URL,
	})
	var saved *UpstreamToken
	got, err := RefreshingBearer(tok, srv.Client(), func(u *UpstreamToken) { saved = u })(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "fresh" {
		t.Fatalf("bearer = %q, want the refreshed token", got)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt1" {
		t.Fatalf("refresh sent the wrong grant: %v", form)
	}
	if saved == nil || saved.RefreshToken != "rt2" {
		t.Fatalf("rotated refresh token not handed to onRefresh for persistence: %+v", saved)
	}
}

func TestOAuthClientRefuses401(t *testing.T) {
	// A DCR endpoint that rejects → a clear error, not a panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, _, err := RegisterClient(context.Background(), srv.Client(), srv.URL, "http://127.0.0.1/cb", "x"); err == nil {
		t.Fatal("expected DCR error on 401")
	}
}

// TestExchangeSendsClientSecret: a confidential AS (Supabase) requires
// client_secret at the token endpoint — exchange and refresh must include it.
func TestExchangeSendsClientSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "sek" {
			http.Error(w, `{"message":"Required parameter: client_secret"}`, http.StatusUnprocessableEntity)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600}`))
	}))
	defer srv.Close()

	meta := &ASMetadata{TokenEndpoint: srv.URL}
	tok, err := ExchangeCode(context.Background(), srv.Client(), meta, "cid", "sek", "http://cb", "code", NewPKCE())
	if err != nil {
		t.Fatalf("exchange with client_secret failed: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Fatalf("no access token: %+v", tok)
	}
	if err := tok.Refresh(context.Background(), srv.Client()); err != nil {
		t.Fatalf("refresh must also send client_secret: %v", err)
	}
}
