package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	NewAuthServer(signer, testIss, testAud, time.Hour).Register(mux)
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

// approve runs GET+POST /authorize for the given client/challenge and returns the
// issued auth code from the redirect.
func approve(t *testing.T, ts *httptest.Server, c *http.Client, clientID, challenge string) string {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"}, "scope": {"mcp"},
	}
	gr, err := c.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil || gr.StatusCode != http.StatusOK {
		t.Fatalf("consent GET: %v status=%v", err, gr.StatusCode)
	}
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("approve", "yes")
	pr, err := c.PostForm(ts.URL+"/oauth/authorize", form)
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
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh = %d (%v)", status, rf)
	}
	if _, err := rs.Validate(context.Background(), rf["access_token"].(string)); err != nil {
		t.Fatalf("refreshed token invalid: %v", err)
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
	as1 := NewAuthServer(signer, testIss, testAud, time.Hour)
	as1.LoadClients(clientsPath)
	mux1 := http.NewServeMux()
	as1.Register(mux1)
	ts1 := httptest.NewServer(mux1)
	defer ts1.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientID := registerClient(t, ts1, c)

	// "Restart": a fresh AuthServer (empty in-memory map) loading the same file.
	as2 := NewAuthServer(signer, testIss, testAud, time.Hour)
	as2.LoadClients(clientsPath)
	mux2 := http.NewServeMux()
	as2.Register(mux2)
	ts2 := httptest.NewServer(mux2)
	defer ts2.Close()

	// The reloaded server must recognize the client on /authorize (consent page, 200)
	// rather than reject it as unknown (400).
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"}, "state": {"s"}, "scope": {"mcp"},
	}
	r, err := c.Get(ts2.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("reloaded server rejected persisted client: authorize = %d, want 200", r.StatusCode)
	}
}
