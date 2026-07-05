package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Metadata discovery is defined by the issuer's URL SHAPE, not any one provider.
// RFC 8414/9728 insert the well-known segment after the host and keep the path
// suffix; a root issuer has a single canonical location.
func TestWellKnownCandidates(t *testing.T) {
	cases := []struct {
		name, base, wk string
		want           []string
	}{
		{
			name: "path issuer inserts then appends",
			base: "https://host.example/a/b", wk: "oauth-authorization-server",
			want: []string{
				"https://host.example/.well-known/oauth-authorization-server/a/b",
				"https://host.example/a/b/.well-known/oauth-authorization-server",
			},
		},
		{
			name: "root issuer has one location",
			base: "https://host.example", wk: "oauth-authorization-server",
			want: []string{"https://host.example/.well-known/oauth-authorization-server"},
		},
		{
			name: "trailing slash is a root issuer",
			base: "https://host.example/", wk: "oauth-protected-resource",
			want: []string{"https://host.example/.well-known/oauth-protected-resource"},
		},
	}
	for _, c := range cases {
		got := WellKnownCandidates(c.base, c.wk)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("%s[%d]: got %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
}

// asMetadataURLs tries insertion forms before legacy appends, oauth before oidc,
// for any path-bearing issuer.
func TestASMetadataURLsOrdering(t *testing.T) {
	got := asMetadataURLs("https://host.example/a/b")
	want := []string{
		"https://host.example/.well-known/oauth-authorization-server/a/b", // oauth insertion
		"https://host.example/.well-known/openid-configuration/a/b",       // oidc insertion
		"https://host.example/a/b/.well-known/oauth-authorization-server", // oauth append
		"https://host.example/a/b/.well-known/openid-configuration",       // oidc append
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A path-bearing issuer whose AS metadata is served only at the insertion location
// must be discovered by falling through the append form's 404. Also verifies the
// RFC 8707 resource indicator is captured from the protected-resource metadata.
func TestDiscoverASPathAwareWithResourceIndicator(t *testing.T) {
	var ts *httptest.Server // captured by handlers; ts.URL is set before any request
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_servers":["` + ts.URL + `/a/b"],"scopes_supported":["s"],"resource":"` + ts.URL + `/a/b"}`))
	})
	// Only the insertion location serves AS metadata; the append form 404s.
	mux.HandleFunc("/.well-known/oauth-authorization-server/a/b", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + ts.URL + `/a/b","authorization_endpoint":"` + ts.URL + `/authorize","token_endpoint":"` + ts.URL + `/token"}`))
	})
	ts = httptest.NewServer(mux)
	defer ts.Close()

	meta, err := DiscoverAS(context.Background(), ts.Client(), ts.URL+"/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("DiscoverAS should have found the insertion metadata: %v", err)
	}
	if meta.TokenEndpoint != ts.URL+"/token" || meta.AuthorizationEndpoint != ts.URL+"/authorize" {
		t.Fatalf("wrong endpoints: %+v", meta)
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "s" {
		t.Fatalf("scopes should fall back to the resource's: %+v", meta.ScopesSupported)
	}
	if meta.Resource != ts.URL+"/a/b" {
		t.Fatalf("resource indicator = %q, want the PR metadata's resource", meta.Resource)
	}
}

// AS metadata whose issuer does NOT match the authorization-server URL it was fetched
// from is rejected (RFC 8414 §3.3). Otherwise a malicious upstream could serve its
// own AS document while claiming issuer = a legitimate provider, causing that
// provider's stored client_secret to be sent to the attacker's token endpoint.
func TestDiscoverASRejectsIssuerMismatch(t *testing.T) {
	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_servers":["` + ts.URL + `"],"resource":"` + ts.URL + `"}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		// issuer claims a different provider than the AS URL microagency fetched from.
		_, _ = w.Write([]byte(`{"issuer":"https://accounts.google.com","authorization_endpoint":"` + ts.URL + `/authorize","token_endpoint":"` + ts.URL + `/token"}`))
	})
	ts = httptest.NewServer(mux)
	defer ts.Close()

	if _, err := DiscoverAS(context.Background(), ts.Client(), ts.URL+"/.well-known/oauth-protected-resource"); err == nil {
		t.Fatal("expected DiscoverAS to reject metadata whose issuer != authorization server URL")
	}
}

// sameIssuer compares issuer identifiers per RFC 8414: trailing-slash and case
// insensitive on scheme/host, exact on path.
func TestSameIssuer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://as.example", "https://as.example/", true},
		{"https://AS.example", "https://as.example", true},
		{"https://as.example/a/b", "https://as.example/a/b", true},
		{"https://as.example", "https://evil.example", false},
		{"https://as.example/a", "https://as.example/b", false},
		{"not a url", "https://as.example", false},
	}
	for _, c := range cases {
		if got := sameIssuer(c.a, c.b); got != c.want {
			t.Errorf("sameIssuer(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The RFC 8707 resource indicator is sent on the authorize request when present,
// and omitted when not — no vendor assumptions.
func TestAuthorizeURLResourceIndicator(t *testing.T) {
	base := &ASMetadata{AuthorizationEndpoint: "https://as.example/authorize"}
	if got := AuthorizeURL(base, "cid", "https://cb", NewPKCE(), "", "st"); strings.Contains(got, "resource=") {
		t.Errorf("no resource indicator should be sent when unset: %s", got)
	}
	base.Resource = "https://mcp.example/a/b"
	got := AuthorizeURL(base, "cid", "https://cb", NewPKCE(), "", "st")
	if !strings.Contains(got, "resource=https%3A%2F%2Fmcp.example%2Fa%2Fb") {
		t.Errorf("authorize URL must carry the resource indicator: %s", got)
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
