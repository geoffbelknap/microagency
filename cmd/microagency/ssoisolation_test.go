package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"microagency/internal/auth"
	"microagency/internal/gateway"
	"microagency/internal/mcp"
)

// A shared gateway is only worth running if the people sharing it cannot reach
// each other's data. Admitting two people through one consumer identity
// provider is exactly the case where that is easy to get wrong: they arrive at
// the same issuer, over the same tunnel, with tokens minted by the same
// authorization server, and nothing about the provider distinguishes them the
// way a corporate directory would.
//
// The isolation mechanisms are keyed on the canonical principal, so they should
// hold as soon as two admitted people are distinct principals. "Should" is not
// evidence. This test signs two audience-admitted accounts in through one stub
// provider and then walks the whole boundary: distinct principals, connection
// ownership on both discovery and invocation, parked-data ownership, and audit
// attribution.
func TestTwoAdmittedIdentitiesCannotReachEachOthersData(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ssoClientSecretEnv, "gw-secret")
	provider := newTestOIDCProvider(t)
	authDir := t.TempDir()

	// The operator admits two named people on a provider that asserts no
	// hosted domain and no groups — the no-directory case that audience rules
	// exist for. Both are admitted by the same operator, through the same
	// mechanism, so nothing but the identity itself separates them.
	rules := auth.NewAudienceRules(auth.AudienceRulesPath(authDir))
	for _, address := range []string{"alpha@personal.example", "beta@personal.example"} {
		if _, err := rules.Add(auth.AudienceRule{Kind: auth.AudienceEmail, Value: address}); err != nil {
			t.Fatal(err)
		}
	}

	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", authDir: authDir,
		ssoIssuer: provider.ts.URL, ssoClientID: "gw-client",
	}
	if err := validateFederationAudience(cfg, rules.Summary()); err != nil {
		t.Fatalf("audience rules should declare the audience: %v", err)
	}
	mcpMux, _, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-local" {
		t.Fatalf("mode = %q", mode)
	}
	gw := httptest.NewServer(mcpMux)
	defer gw.Close()

	// --- both admitted accounts sign in, and become distinct principals ------

	alphaToken := federatedAccessToken(t, gw, provider, "user-alpha", "alpha@personal.example")
	betaToken := federatedAccessToken(t, gw, provider, "user-beta", "beta@personal.example")

	const gatewayIssuer = "http://127.0.0.1:8765"
	alphaKey := auth.PrincipalKey(gatewayIssuer, "user-alpha")
	betaKey := auth.PrincipalKey(gatewayIssuer, "user-beta")
	if alphaKey == betaKey {
		t.Fatal("the two accounts produced the same principal key")
	}
	for _, tc := range []struct{ token, wantSub string }{
		{alphaToken, "user-alpha"},
		{betaToken, "user-beta"},
	} {
		if got := tokenSubject(t, tc.token); got != tc.wantSub {
			t.Fatalf("access token sub = %q, want %q — each account must be its own principal", got, tc.wantSub)
		}
	}

	// --- a connection owned by one is invisible and uninvocable to the other -

	upstream := bulkUpstream(t)
	defer upstream.Close()
	if err := srv.AddUpstream(context.Background(), "docs",
		&gateway.Upstream{Name: "docs", URL: upstream.URL}, mcp.WithOwner(alphaKey)); err != nil {
		t.Fatal(err)
	}

	if found := findToolNames(t, gw, alphaToken, "search"); !found["docs__search"] {
		t.Fatalf("the owner cannot find their own connection: %v", found)
	}
	if found := findToolNames(t, gw, betaToken, "search"); found["docs__search"] {
		t.Fatalf("another principal's owned connection appeared in find_tools: %v", found)
	}

	// The refusal must not double as an existence oracle: invoking a connection
	// owned by someone else has to look exactly like invoking a tool that was
	// never registered at all.
	refusedOwned := callToolText(t, gw, betaToken, "docs__search", map[string]any{"q": "x"})
	refusedUnknown := callToolText(t, gw, betaToken, "nosuch__tool", map[string]any{"q": "x"})
	if !refusedOwned.isError || !refusedUnknown.isError {
		t.Fatalf("expected both calls to error; owned=%v unknown=%v", refusedOwned, refusedUnknown)
	}
	// The messages echo the name they were given, as every refusal here does,
	// so compare them with the name factored out: what must not differ is the
	// refusal itself.
	ownedShape := strings.ReplaceAll(refusedOwned.text, "docs__search", "NAME")
	unknownShape := strings.ReplaceAll(refusedUnknown.text, "nosuch__tool", "NAME")
	if ownedShape != unknownShape {
		t.Errorf("owned-connection refusal differs from unknown-tool refusal, which leaks that the connection exists:\n owned:   %s\n unknown: %s",
			refusedOwned.text, refusedUnknown.text)
	}
	if !strings.Contains(refusedOwned.text, "unknown tool") {
		t.Errorf("refusal text = %q, want the unknown-tool wording", refusedOwned.text)
	}

	// --- parked data is bound to the principal that created it --------------

	answer := callToolText(t, gw, alphaToken, "docs__search", map[string]any{"q": "everything"})
	if answer.isError {
		t.Fatalf("owner's own call failed: %s", answer.text)
	}
	ref := extractRef(answer.text)
	if ref == "" {
		t.Fatalf("expected the large result to park as a reference, got: %s", truncate(answer.text))
	}

	// The handle is not authority. Beta holds it and still cannot read it, with
	// the same wording as a handle that never existed.
	betaReduce := reduceText(t, gw, betaToken, ref)
	if !strings.Contains(betaReduce, "unknown reference") {
		t.Errorf("another principal reduced over parked data with only the handle: %s", truncate(betaReduce))
	}
	// The same handle in the creator's hands gets past the ownership check.
	// (What it does next depends on which query engines are built, which is not
	// what this test is about — only that the ownership gate does not fire.)
	alphaReduce := reduceText(t, gw, alphaToken, ref)
	if strings.Contains(alphaReduce, "unknown reference") {
		t.Errorf("the creating principal was refused its own reference: %s", truncate(alphaReduce))
	}

	// --- the audit log attributes each action to the right principal ---------

	var alphaProxy, betaProxy int
	var wrongUser []string
	for _, rec := range srv.RunLog() {
		switch rec.User {
		case alphaKey:
			if rec.Kind == "proxy" && rec.Upstream == "docs" {
				alphaProxy++
			}
		case betaKey:
			if rec.Kind == "proxy" && rec.Upstream == "docs" {
				betaProxy++
			}
		default:
			// A client registration precedes sign-in and has no principal by
			// definition — it is the one unauthenticated event on this surface.
			// Attribution is about what a signed-in caller did.
			if rec.Kind == "client" {
				continue
			}
			wrongUser = append(wrongUser, fmt.Sprintf("%s/%s", rec.Kind, rec.User))
		}
	}
	if alphaProxy == 0 {
		t.Error("the owner's upstream call is not attributed to them in the audit log")
	}
	if betaProxy != 0 {
		t.Errorf("a refused caller was recorded as having proxied to the owned connection (%d records)", betaProxy)
	}
	if len(wrongUser) > 0 {
		t.Errorf("audit records attributed to neither signed-in principal: %v", wrongUser)
	}

	// Both principals appear in the log under their own key, so attribution
	// distinguishes them rather than collapsing them onto one federated caller.
	users := map[string]bool{}
	for _, rec := range srv.RunLog() {
		users[rec.User] = true
	}
	if !users[alphaKey] || !users[betaKey] {
		t.Errorf("audit log does not carry both principals separately: %v", users)
	}
}

// TestRefusedAccountNeverBecomesAPrincipal is the other half of the boundary:
// an account the audience does not admit must not reach the agent surface at
// all. Refusing at sign-in and refusing after admission are very different
// postures — the second one leaves a real principal with a real audit trail
// and a tool surface that merely happens to be empty today.
func TestRefusedAccountNeverBecomesAPrincipal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(ssoClientSecretEnv, "gw-secret")
	provider := newTestOIDCProvider(t)
	authDir := t.TempDir()

	rules := auth.NewAudienceRules(auth.AudienceRulesPath(authDir))
	if _, err := rules.Add(auth.AudienceRule{Kind: auth.AudienceEmail, Value: "alpha@personal.example"}); err != nil {
		t.Fatal(err)
	}

	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", authDir: authDir,
		ssoIssuer: provider.ts.URL, ssoClientID: "gw-client",
	}
	mcpMux, _, _, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(mcpMux)
	defer gw.Close()

	clientID := registerMCPClient(t, gw)
	provider.setUser("user-beta", "beta@personal.example")
	final := driveFederatedSignIn(t, gw, provider, clientID, pkceVerifier)
	defer func() { _ = final.Body.Close() }()

	if final.StatusCode != http.StatusOK {
		t.Fatalf("refused sign-in = %d, want the 200 notice page", final.StatusCode)
	}
	if loc := final.Header.Get("Location"); loc != "" {
		t.Fatalf("refused sign-in redirected to %q; no authorization code may be issued", loc)
	}
	body, err := io.ReadAll(final.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "not one this gateway admits") {
		t.Errorf("refusal page did not explain the refusal:\n%s", body)
	}
	// Nothing was minted, so nothing can be presented to the agent surface. The
	// client registration that opened the flow is recorded and carries no
	// principal, which is exactly what a refused sign-in should leave behind:
	// evidence that something tried, and no attributed activity.
	for _, rec := range srv.RunLog() {
		if rec.Kind == "client" {
			if rec.User != "" {
				t.Errorf("a client registration was attributed to a principal: %+v", rec)
			}
			continue
		}
		t.Errorf("a refused account produced audit activity: %+v", rec)
	}
}

// --- helpers ----------------------------------------------------------------

const pkceVerifier = "a-sufficiently-long-pkce-code-verifier-1234567890"

// bulkUpstream is a minimal MCP-over-HTTP server whose one tool returns a
// result far larger than the test gateway's inline ceiling, so the answer parks
// as a reference instead of entering context.
func bulkUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	rows := make([]map[string]string, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, map[string]string{
			"id": fmt.Sprintf("row-%03d", i), "note": "a private record belonging to the connection owner",
		})
	}
	bulk, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(string(bulk))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"search the corpus","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}}`)
		case "tools/call":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+string(payload)+`}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`)
		}
	}))
}

// registerMCPClient runs dynamic client registration and returns the client id.
func registerMCPClient(t *testing.T, gw *httptest.Server) string {
	t.Helper()
	resp, err := http.Post(gw.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"client_name":"test-client","redirect_uris":["http://127.0.0.1:7777/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.ClientID == "" {
		t.Fatal("dynamic client registration returned no client id")
	}
	return reg.ClientID
}

// driveFederatedSignIn walks one browser round-trip: authorize → provider →
// gateway callback. It returns the callback's response, which is either the
// redirect back to the MCP client with a code, or the refusal notice page.
func driveFederatedSignIn(t *testing.T, gw *httptest.Server, provider *testOIDCProvider, clientID, verifier string) *http.Response {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:7777/cb"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"client-state"}, "scope": {"mcp"},
	}
	r1, err := c.Get(gw.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize = %d, want a redirect to the provider", r1.StatusCode)
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
	return r3
}

// federatedAccessToken signs one identity in and exchanges the resulting code
// for a gateway access token.
func federatedAccessToken(t *testing.T, gw *httptest.Server, provider *testOIDCProvider, sub, email string) string {
	t.Helper()
	clientID := registerMCPClient(t, gw)
	provider.setUser(sub, email)
	final := driveFederatedSignIn(t, gw, provider, clientID, pkceVerifier)
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		t.Fatalf("sign-in for %s = %d, want the redirect back to the MCP client", sub, final.StatusCode)
	}
	loc, err := url.Parse(final.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("sign-in for %s returned no authorization code", sub)
	}
	resp, err := http.PostForm(gw.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"http://127.0.0.1:7777/cb"}, "code_verifier": {pkceVerifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token exchange for %s = %d", sub, resp.StatusCode)
	}
	return tokens.AccessToken
}

// tokenSubject decodes the `sub` an access token carries.
func tokenSubject(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Sub
}

// mcpToolCall posts one JSON-RPC tools/call to the agent surface as `token`.
func mcpToolCall(t *testing.T, gw *httptest.Server, token, tool string, args map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s = %d: %s", tool, resp.StatusCode, raw)
	}
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Result
}

type toolReply struct {
	isError bool
	text    string
}

func resultText(result map[string]any) toolReply {
	reply := toolReply{}
	if v, ok := result["isError"].(bool); ok {
		reply.isError = v
	}
	content, _ := result["content"].([]any)
	var b strings.Builder
	for _, item := range content {
		entry, _ := item.(map[string]any)
		if text, ok := entry["text"].(string); ok {
			b.WriteString(text)
		}
	}
	reply.text = b.String()
	return reply
}

func callToolText(t *testing.T, gw *httptest.Server, token, tool string, args map[string]any) toolReply {
	t.Helper()
	return resultText(mcpToolCall(t, gw, token, "call_tool", map[string]any{"name": tool, "arguments": args}))
}

func reduceText(t *testing.T, gw *httptest.Server, token, ref string) string {
	t.Helper()
	return resultText(mcpToolCall(t, gw, token, "reduce", map[string]any{"ref": ref, "query": ".[0]"})).text
}

// findToolNames returns the namespaced tool names one principal can discover.
func findToolNames(t *testing.T, gw *httptest.Server, token, query string) map[string]bool {
	t.Helper()
	reply := resultText(mcpToolCall(t, gw, token, "find_tools", map[string]any{"query": query}))
	names := map[string]bool{}
	for _, candidate := range []string{"docs__search"} {
		if strings.Contains(reply.text, candidate) {
			names[candidate] = true
		}
	}
	return names
}

// extractRef pulls the first ref handle out of a tool result. The handle is
// quoted inside a JSON envelope, so it is matched on the identifier itself
// rather than on the surrounding angle brackets, which may arrive escaped.
var refPattern = regexp.MustCompile(`ref_[A-Za-z0-9_-]+`)

func extractRef(text string) string {
	m := refPattern.FindString(text)
	if m == "" {
		return ""
	}
	return "<" + m + ">"
}

func truncate(s string) string {
	if len(s) <= 300 {
		return s
	}
	return s[:300] + "…"
}
