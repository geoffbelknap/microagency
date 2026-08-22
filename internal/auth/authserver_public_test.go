package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	publicIssuer   = "https://gateway.example"
	publicResource = "https://gateway.example/mcp"
	publicRedirect = "https://client.example/oauth/callback"
)

func newPublicTestAS(t *testing.T) (*AuthServer, *httptest.Server, *httptest.Server, *http.Client, *Signer) {
	t.Helper()
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "oauth-key"))
	if err != nil {
		t.Fatal(err)
	}
	revocations, err := NewRevocationList(filepath.Join(t.TempDir(), "oauth-revocations.json"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, publicIssuer, publicResource, time.Hour, revocations)
	adminMux := http.NewServeMux()
	admin := httptest.NewServer(adminMux)
	t.Cleanup(admin.Close)
	if err := as.ConfigurePublicFlow(publicResource, admin.URL); err != nil {
		t.Fatal(err)
	}
	as.RegisterOperator(adminMux)
	publicMux := http.NewServeMux()
	as.Register(publicMux)
	public := httptest.NewServer(publicMux)
	t.Cleanup(public.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return as, public, admin, client, signer
}

func registerPublicClient(t *testing.T, public *httptest.Server, client *http.Client, redirect string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{redirect},
		"client_name":                "Remote MCP client",
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
	resp, err := client.Post(public.URL+"/oauth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ClientID == "" {
		t.Fatalf("register response = %+v err=%v", out, err)
	}
	return out.ClientID
}

func TestPublicAuthFlowRequiresLoopbackConsentAndBindsResource(t *testing.T) {
	as, public, admin, client, signer := newPublicTestAS(t)
	clientID := registerPublicClient(t, public, client, publicRedirect)
	p := NewPKCE()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {publicRedirect},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"state-sentinel"},
		"scope":                 {"mcp"},
		"resource":              {publicResource},
	}
	authResp, err := client.Get(public.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize = %d, want loopback redirect", authResp.StatusCode)
	}
	consentURL, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil || consentURL.Host != strings.TrimPrefix(admin.URL, "http://") || consentURL.Path != "/oauth/consent" {
		t.Fatalf("consent redirect = %q, want operator listener %s", authResp.Header.Get("Location"), admin.URL)
	}

	consentResp, err := client.Get(consentURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("loopback consent = %d", consentResp.StatusCode)
	}

	approveResp, err := client.PostForm(consentURL.String(), url.Values{
		"request": {consentURL.Query().Get("request")},
		"approve": {"yes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusFound {
		t.Fatalf("approve = %d", approveResp.StatusCode)
	}
	callback, _ := url.Parse(approveResp.Header.Get("Location"))
	if callback.Scheme+"://"+callback.Host+callback.Path != publicRedirect ||
		callback.Query().Get("state") != "state-sentinel" || callback.Query().Get("iss") != publicIssuer {
		t.Fatalf("callback = %s", callback)
	}
	code := callback.Query().Get("code")
	status, token := postForm(t, client, public.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {publicRedirect}, "code_verifier": {p.Verifier}, "resource": {publicResource},
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange = %d (%v)", status, token)
	}
	access := token["access_token"].(string)
	refresh := token["refresh_token"].(string)
	rs := &ResourceServer{
		Issuer: publicIssuer, Audience: publicResource, Keys: signer.KeySet(),
		Revocations: as.Revocations(), RequireTokenID: true,
	}
	if _, err := rs.Validate(context.Background(), access); err != nil {
		t.Fatalf("validate public access token: %v", err)
	}
	if _, err := (&ResourceServer{Issuer: "https://other.example", Audience: publicResource, Keys: signer.KeySet()}).Validate(context.Background(), access); err == nil {
		t.Fatal("public access token validated for the wrong issuer")
	}
	if _, err := (&ResourceServer{Issuer: publicIssuer, Audience: "https://other.example/mcp", Keys: signer.KeySet()}).Validate(context.Background(), access); err == nil {
		t.Fatal("public access token validated for the wrong audience")
	}
	if status, _ := postForm(t, client, public.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"other-client"},
	}); status != http.StatusBadRequest {
		t.Fatalf("refresh token accepted for wrong client: status=%d", status)
	}
	status, rotated := postForm(t, client, public.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	})
	if status != http.StatusOK || rotated["refresh_token"] == "" {
		t.Fatalf("refresh rotation = %d (%v)", status, rotated)
	}
	if status, _ := postForm(t, client, public.URL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
	}); status != http.StatusBadRequest {
		t.Fatalf("refresh replay = %d, want 400", status)
	}
	revokeResp, err := client.PostForm(public.URL+"/oauth/revoke", url.Values{"token": {access}})
	if err != nil {
		t.Fatal(err)
	}
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", revokeResp.StatusCode)
	}
	if _, err := rs.Validate(context.Background(), access); err == nil {
		t.Fatal("revoked access token still validates")
	}

	// The consent handler exists only on the loopback operator mux.
	rec := httptest.NewRecorder()
	public.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/consent", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("public /oauth/consent = %d, want 404", rec.Code)
	}
}

func TestPublicAuthRejectsStateResourcePKCEAndReplay(t *testing.T) {
	_, public, _, client, _ := newPublicTestAS(t)
	clientID := registerPublicClient(t, public, client, publicRedirect)
	p := NewPKCE()
	base := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {publicRedirect},
		"code_challenge": {p.Challenge}, "code_challenge_method": {"S256"},
		"state": {"s"}, "scope": {"mcp"}, "resource": {publicResource},
	}
	for _, mutation := range []func(url.Values){
		func(q url.Values) { q.Del("state") },
		func(q url.Values) { q.Set("resource", "https://other.example/mcp") },
		func(q url.Values) { q.Set("code_challenge", "too-short") },
	} {
		q := cloneValues(base)
		mutation(q)
		resp, err := client.Get(public.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "error=invalid_request") {
			t.Fatalf("negative authorize = %d location=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	mismatch := cloneValues(base)
	mismatch.Set("redirect_uri", "https://attacker.example/callback")
	resp, err := client.Get(public.URL + "/oauth/authorize?" + mismatch.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered redirect was followed: status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = client.PostForm(public.URL+"/oauth/authorize", base)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("public consent POST = %d, want 405", resp.StatusCode)
	}
}

func TestPublicDynamicRegistrationRejectsUnsafeRedirects(t *testing.T) {
	_, public, _, client, _ := newPublicTestAS(t)
	for _, redirect := range []string{
		"http://client.example/callback",
		"https://user:pass@client.example/callback",
		"https://client.example/callback#fragment",
		"file:///tmp/callback",
	} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}})
		resp, err := client.Post(public.URL+"/oauth/register", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("redirect %q registration = %d, want 400", redirect, resp.StatusCode)
		}
	}
	registerPublicClient(t, public, client, "http://127.0.0.1:49152/callback")
}

func TestRefreshRotationAndRevocationPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oauth-revocations.json")
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	if consumed, err := list.Consume("refresh-id", expiry); err != nil || !consumed {
		t.Fatalf("first consume = %v, %v", consumed, err)
	}
	if consumed, err := list.Consume("refresh-id", expiry); err != nil || consumed {
		t.Fatalf("replay consume = %v, %v", consumed, err)
	}
	reloaded, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.IsRevoked("refresh-id") {
		t.Fatal("revocation did not survive reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("revocation file mode = %o, want 600", info.Mode().Perm())
	}
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
