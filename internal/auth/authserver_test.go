package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	testIss      = "http://127.0.0.1:8765"
	testAud      = "microagency"
	testRedirect = "http://127.0.0.1:9999/callback"
)

func newTestAS(t *testing.T) (*httptest.Server, *http.Client, *Signer) {
	t.Helper()
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	NewAuthServer(signer, testIss, testAud, time.Hour, nil).Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	// Don't auto-follow redirects so we can read the auth code out of Location.
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return ts, c, signer
}

func registerClient(t *testing.T, ts *httptest.Server, c *http.Client) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{testRedirect}, "client_name": "Cursor"})
	r, err := c.Post(ts.URL+"/oauth/register", "application/json", bytes.NewReader(body))
	if err != nil || r.StatusCode != http.StatusCreated {
		t.Fatalf("register: %v status=%v", err, r.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(r.Body).Decode(&reg)
	if reg.ClientID == "" {
		t.Fatal("register returned no client_id")
	}
	return reg.ClientID
}

// consentRequestRE extracts the single-use request ID that binds the consent
// POST to the pending grant the rendered page belongs to.
var consentRequestRE = regexp.MustCompile(`name="request" value="([^"]+)"`)

// browserConsent does what a real browser does: GET the consent page, read the
// request ID out of the form, and POST the decision bound to it.
func browserConsent(c *http.Client, authURL, decision string) (*http.Response, error) {
	page, err := c.Get(authURL)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if err != nil {
		return nil, err
	}
	if page.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consent GET status %d", page.StatusCode)
	}
	m := consentRequestRE.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("consent page has no request binding")
	}
	u, err := url.Parse(authURL)
	if err != nil {
		return nil, err
	}
	return c.PostForm(u.Scheme+"://"+u.Host+u.Path,
		url.Values{"request": {string(m[1])}, "approve": {decision}})
}

// approve runs the browser consent flow for the given client/challenge and
// returns the issued auth code from the redirect.
func approve(t *testing.T, ts *httptest.Server, c *http.Client, clientID, challenge string) string {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"}, "scope": {"mcp"},
	}
	pr, err := browserConsent(c, ts.URL+"/oauth/authorize?"+q.Encode(), "yes")
	if err != nil || pr.StatusCode != http.StatusFound {
		t.Fatalf("approve POST: %v status=%v", err, pr.StatusCode)
	}
	loc, _ := url.Parse(pr.Header.Get("Location"))
	if loc.Query().Get("state") != "xyz" {
		t.Fatal("state not echoed back")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	return code
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) (int, map[string]any) {
	t.Helper()
	r, err := c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	return r.StatusCode, body
}

func TestAuthServerFullFlow(t *testing.T) {
	ts, c, signer := newTestAS(t)
	clientID := registerClient(t, ts, c)

	verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
	code := approve(t, ts, c, clientID, pkceS256(verifier))

	tokForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}
	status, tok := postForm(t, c, ts.URL+"/oauth/token", tokForm)
	if status != http.StatusOK {
		t.Fatalf("token exchange = %d (%v)", status, tok)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	if access == "" || refresh == "" || tok["token_type"] != "Bearer" {
		t.Fatalf("bad token response: %v", tok)
	}

	// The issued access token validates through the resource server.
	rs := &ResourceServer{Issuer: testIss, Audience: testAud, Keys: signer.KeySet()}
	p, err := rs.Validate(context.Background(), access)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if p.Subject != "operator" {
		t.Fatalf("subject = %q", p.Subject)
	}

	// The auth code is single-use.
	if status, _ := postForm(t, c, ts.URL+"/oauth/token", tokForm); status == http.StatusOK {
		t.Fatal("auth code was accepted twice")
	}

	// Refresh yields a fresh, valid access token.
	status, rf := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh = %d (%v)", status, rf)
	}
	if _, err := rs.Validate(context.Background(), rf["access_token"].(string)); err != nil {
		t.Fatalf("refreshed token invalid: %v", err)
	}
}

// A refresh honors the subject baked into the presented token. When the local
// principal changes between issue and refresh, the session no longer belongs to
// that identity, so the refresh is refused (forcing re-consent) rather than
// silently rebound to the new subject.
func TestRefreshRefusedOnSubjectChange(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, nil) // Subject defaults to "operator"
	mux := http.NewServeMux()
	as.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	clientID := registerClient(t, ts, c)
	verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
	code := approve(t, ts, c, clientID, pkceS256(verifier))
	_, tok := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh token")
	}

	// Same subject: the refresh succeeds and honors the token's own sub.
	status, rf := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("same-subject refresh = %d (%v)", status, rf)
	}
	rotated, _ := rf["refresh_token"].(string)
	rs := &ResourceServer{Issuer: testIss, Audience: testAud, Keys: signer.KeySet()}
	p, err := rs.Validate(context.Background(), rf["access_token"].(string))
	if err != nil {
		t.Fatalf("refreshed token invalid: %v", err)
	}
	if p.Subject != "operator" {
		t.Fatalf("refresh should honor the token subject; got %q, want operator", p.Subject)
	}

	// The local principal changes (upgraded binary, reconfigured Subject).
	as.Subject = "alice"

	// The rotated token still carries sub=operator, which no longer matches the
	// server. The refresh is refused, and the client must re-consent.
	status, body := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated}, "client_id": {clientID},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("subject-changed refresh = %d (%v), want 400 invalid_grant", status, body)
	}
}

// A refresh token minted before client binding and jti existed (the legacy
// form) is refused outright in local mode — it is unrotatable and, lacking a
// jti, unrevocable.
func TestRefreshRejectsLegacyFormat(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	mux := http.NewServeMux()
	as.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// A legacy refresh JWT: correct audience and subject, but no client_id and
	// no jti — exactly what older builds minted.
	legacy, err := signer.mint(testIss, testAud+refreshAudienceSuffix, "operator", []string{"mcp"}, refreshTTL, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, body := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {legacy}, "client_id": {""},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("legacy refresh = %d (%v), want 400 invalid_grant", status, body)
	}
}

func TestAuthServerRejectsBadPKCE(t *testing.T) {
	ts, c, _ := newTestAS(t)
	clientID := registerClient(t, ts, c)
	code := approve(t, ts, c, clientID, pkceS256("the-real-verifier-aaaaaaaaaaaaaaaaaaaa"))

	// Exchange with the WRONG verifier → invalid_grant.
	status, body := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {"a-different-verifier-bbbbbbbbbbbbbbbbbbbb"},
	})
	if status == http.StatusOK {
		t.Fatal("token issued despite PKCE mismatch")
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant", body["error"])
	}
}

func TestAuthServerRejectsUnknownClient(t *testing.T) {
	ts, c, _ := newTestAS(t)
	// Unknown client_id must be a hard 400 — never a redirect to an unvetted URI.
	r, _ := c.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=nope&redirect_uri=" +
		url.QueryEscape(testRedirect) + "&code_challenge=x&code_challenge_method=S256")
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown client = %d, want 400", r.StatusCode)
	}
}

// A page in the operator's browser can register a client (open DCR) and fire a
// form POST at the loopback listener. Consent must refuse anything a browser
// labels cross-site, and must never accept authorize parameters over POST.
func TestLocalConsentRefusesCrossSiteForgery(t *testing.T) {
	ts, c, _ := newTestAS(t)
	clientID := registerClient(t, ts, c)
	challenge := pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890")
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"}, "scope": {"mcp"},
	}

	// The old CSRF shape: POST the authorize parameters with approve=yes.
	// It must not mint a code.
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("approve", "yes")
	old, err := c.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Body.Close()
	if old.StatusCode == http.StatusFound || old.Header.Get("Location") != "" {
		t.Fatalf("parameter-carrying consent POST minted a code: %d %q", old.StatusCode, old.Header.Get("Location"))
	}

	// Get a REAL pending request ID, then forge the approval the way a browser
	// fires it from another site. Every labeled-cross-site shape is refused.
	page, err := c.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	m := consentRequestRE.FindSubmatch(body)
	if m == nil {
		t.Fatal("consent page has no request binding")
	}
	decision := url.Values{"request": {string(m[1])}, "approve": {"yes"}}
	postDecision := func(headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/oauth/authorize", strings.NewReader(decision.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	for _, forged := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://attacker.example"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "cross-site", "Origin": "https://attacker.example"},
	} {
		if resp := postDecision(forged); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("forged consent POST %v = %d, want 403", forged, resp.StatusCode)
		}
	}

	// The refusals fire before the pending lookup, so the legitimate
	// same-origin approval with the same request ID still succeeds.
	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": ts.URL}
	approved := postDecision(sameOrigin)
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("legitimate same-origin approval = %d, want 302", approved.StatusCode)
	}
	loc, _ := url.Parse(approved.Header.Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatal("no code after legitimate approval")
	}

	// The request ID is single-use: replaying the approval mints nothing.
	if replay := postDecision(sameOrigin); replay.StatusCode == http.StatusFound {
		t.Fatal("request ID replay minted a second code")
	}
}

// A dynamic client registration must survive a restart: a second AuthServer that
// loads the same clients file recognizes a client_id registered against the first,
// so the authorize path doesn't 400 "unknown client" (which would force a re-auth).
func TestClientRegistrationPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	signer, err := LoadOrCreateSigner(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	clientsPath := filepath.Join(dir, "oauth-clients.json")

	// First server: register a client (persists to clientsPath).
	as1 := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	as1.LoadClients(clientsPath)
	mux1 := http.NewServeMux()
	as1.Register(mux1)
	ts1 := httptest.NewServer(mux1)
	defer ts1.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientID := registerClient(t, ts1, c)

	// "Restart": a fresh AuthServer (empty in-memory map) loading the same file.
	as2 := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	as2.LoadClients(clientsPath)
	mux2 := http.NewServeMux()
	as2.Register(mux2)
	ts2 := httptest.NewServer(mux2)
	defer ts2.Close()

	// The reloaded server must recognize the client on /authorize (consent page, 200)
	// rather than reject it as unknown (400).
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge":        {pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890")},
		"code_challenge_method": {"S256"}, "state": {"s"}, "scope": {"mcp"},
	}
	r, err := c.Get(ts2.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("reloaded server rejected persisted client: authorize = %d, want 200", r.StatusCode)
	}
}

// The AS and the resource server share one file-backed revocation list in every
// mode: POST /oauth/revoke kills the access token on the resource surface
// immediately, and a consumed refresh token stays refused after a restart.
func TestRevocationSharedWithResourceServerAndPersists(t *testing.T) {
	dir := t.TempDir()
	signer, err := LoadOrCreateSigner(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	revocationsPath := filepath.Join(dir, "oauth-revocations.json")
	revocations, err := NewRevocationList(revocationsPath)
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, revocations)
	mux := http.NewServeMux()
	as.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	clientID := registerClient(t, ts, c)
	verifier := "a-sufficiently-long-pkce-code-verifier-1234567890"
	code := approve(t, ts, c, clientID, pkceS256(verifier))
	status, tok := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange = %d (%v)", status, tok)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)

	// Resource server wired the way local mode wires it: SAME list, jti required.
	rs := &ResourceServer{
		Issuer: testIss, Audience: testAud, Keys: signer.KeySet(),
		Revocations: revocations, RequireTokenID: true,
	}
	if _, err := rs.Validate(context.Background(), access); err != nil {
		t.Fatalf("validate access token: %v", err)
	}

	// Revoking via the AS endpoint must take effect on the resource server at once.
	revokeResp, err := c.PostForm(ts.URL+"/oauth/revoke", url.Values{"token": {access}})
	if err != nil {
		t.Fatal(err)
	}
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", revokeResp.StatusCode)
	}
	if _, err := rs.Validate(context.Background(), access); err == nil {
		t.Fatal("revoked access token still validates on the resource server")
	}

	// Rotate the refresh token; its jti is consumed into the shared list.
	if status, body := postForm(t, c, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	}); status != http.StatusOK {
		t.Fatalf("refresh = %d (%v)", status, body)
	}

	// "Restart": a fresh AS loading a fresh list from the same file. Replaying the
	// consumed refresh token must still be refused.
	reloaded, err := NewRevocationList(revocationsPath)
	if err != nil {
		t.Fatal(err)
	}
	as2 := NewAuthServer(signer, testIss, testAud, time.Hour, reloaded)
	mux2 := http.NewServeMux()
	as2.Register(mux2)
	ts2 := httptest.NewServer(mux2)
	t.Cleanup(ts2.Close)
	if status, _ := postForm(t, c, ts2.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	}); status != http.StatusBadRequest {
		t.Fatalf("consumed refresh token replay after restart = %d, want 400", status)
	}
}

func TestPublicClientRegistrationDoesNotRebindToChangedIssuer(t *testing.T) {
	dir := t.TempDir()
	signer, err := LoadOrCreateSigner(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	clientsPath := filepath.Join(dir, "oauth-clients.json")
	as1 := NewAuthServer(signer, "https://first.example", "https://first.example/mcp", time.Hour, nil)
	as1.LoadClients(clientsPath)
	mux1 := http.NewServeMux()
	as1.Register(mux1)
	ts1 := httptest.NewServer(mux1)
	defer ts1.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientID := registerClient(t, ts1, c)

	as2 := NewAuthServer(signer, "https://second.example", "https://second.example/mcp", time.Hour, nil)
	as2.LoadClients(clientsPath)
	mux2 := http.NewServeMux()
	as2.Register(mux2)
	rec := httptest.NewRecorder()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge":        {pkceS256("a-sufficiently-long-pkce-code-verifier-1234567890")},
		"code_challenge_method": {"S256"}, "state": {"s"}, "scope": {"mcp"},
	}
	mux2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("registration from old issuer was rebound: status=%d", rec.Code)
	}
}
