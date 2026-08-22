package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"microagency/internal/auth"
	"microagency/internal/gateway"
)

// --- stubs -----------------------------------------------------------------

// delegationSAKey builds a provider-shaped service-account key document and
// returns it with its public key.
func delegationSAKey(t *testing.T, email, tokenURI string) (string, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	doc, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": email,
		"private_key":  string(pemKey),
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(doc), &priv.PublicKey
}

// delegationProvider is a stub token endpoint that VALIDATES each assertion —
// RS256 signature against the service account's registered public key, issuer,
// audience, sub and scope presence — and returns short-lived tokens embedding
// the delegated subject.
type delegationProvider struct {
	ts *httptest.Server

	mu        sync.Mutex
	pub       *rsa.PublicKey
	issuer    string
	exchanges int
	subjects  []string
	scopes    []string
}

func newDelegationProvider(t *testing.T) *delegationProvider {
	t.Helper()
	p := &delegationProvider{}
	p.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		pub, issuer := p.pub, p.issuer
		p.mu.Unlock()
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(r.Form.Get("assertion"), claims,
			func(*jwt.Token) (any, error) { return pub, nil },
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer(issuer),
			jwt.WithAudience(p.ts.URL),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			http.Error(w, "invalid assertion: "+err.Error(), http.StatusUnauthorized)
			return
		}
		sub, _ := claims["sub"].(string)
		scope, _ := claims["scope"].(string)
		if sub == "" || scope == "" {
			http.Error(w, "assertion missing sub or scope", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.exchanges++
		n := p.exchanges
		p.subjects = append(p.subjects, sub)
		p.scopes = append(p.scopes, scope)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("derived-for-%s-%d", sub, n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(p.ts.Close)
	return p
}

func (p *delegationProvider) registerKey(t *testing.T, email string) string {
	t.Helper()
	doc, pub := delegationSAKey(t, email, p.ts.URL)
	p.mu.Lock()
	p.pub, p.issuer = pub, email
	p.mu.Unlock()
	return doc
}

func (p *delegationProvider) exchangeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exchanges
}

// delegationUpstream is a canned MCP server recording, per tools/call, the
// Authorization bearer and Mcp-Session-Id presented — the two things that must
// never cross principals. tools/list is served unauthenticated (wiring-time
// calls carry no caller identity by design).
type delegationUpstream struct {
	ts *httptest.Server

	mu          sync.Mutex
	initializes int
	bearers     []string
	sessions    []string
}

func newDelegationUpstream(t *testing.T) *delegationUpstream {
	t.Helper()
	u := &delegationUpstream{}
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			u.mu.Lock()
			u.initializes++
			id := fmt.Sprintf("sess-%d", u.initializes)
			u.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		case "tools/list":
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"read the corpus","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}},"annotations":{"readOnlyHint":true}}]}}`)
		case "tools/call":
			u.mu.Lock()
			u.bearers = append(u.bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			u.sessions = append(u.sessions, r.Header.Get("Mcp-Session-Id"))
			u.mu.Unlock()
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"row"}],"isError":false}}`)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(u.ts.Close)
	return u
}

func (u *delegationUpstream) calls() (bearers, sessions []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bearers...), append([]string(nil), u.sessions...)
}

// newDelegatedServer wires a test server with one google-dwd connection and a
// verified-email table, the way main wires it under federated sign-in.
func newDelegatedServer(t *testing.T, provider *delegationProvider, up *delegationUpstream, emails map[string]string, opts ...Option) *Server {
	t.Helper()
	saKey := provider.registerKey(t, "delegate@project.example")
	s := newTestServer(t, fakeRunner{}, append(opts,
		WithStateDir(t.TempDir()),
		WithUpstreamClient(&http.Client{}),
		WithSecretStore(openTestSecretStore(t, t.TempDir())))...)
	s.SetDelegatedEmailLookup(func(subject string) string { return emails[subject] })
	cfg := &DelegationSummary{Scopes: []string{"https://provider.example/auth/data.readonly"}}
	if _, code, err := s.addDelegatedUpstream(context.Background(), "docs", up.ts.URL, false, false, "", cfg, saKey); err != nil {
		t.Fatalf("add delegated upstream (%d): %v", code, err)
	}
	return s
}

func callToolHTTPArgs(t *testing.T, h http.Handler, bearer, tool, args string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_tool","arguments":{"name":"` + tool + `","arguments":` + args + `}}}`
	rec := postJSONRPC(t, h, bearer, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("call_tool status = %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Result
}

// --- tests -----------------------------------------------------------------

// The flagship boundary proof: on one shared google-dwd connection, each
// federated principal gets a DERIVED credential acting as their own verified
// email AND their own upstream session — neither is ever reused across
// principals — while one principal's repeat call reuses their cached token.
func TestDelegatedConnectionPerPrincipalCredentialAndSession(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	emails := map[string]string{"alice": "alice@corp.example", "bob": "bob@corp.example"}
	s := newDelegatedServer(t, provider, up, emails)
	h := s.HTTPHandlerAuth(issuerBearerAuth{})
	const issuer = "https://gateway.test"

	for _, c := range []struct{ user, args string }{
		{"alice", `{"q":"a1"}`}, {"bob", `{"q":"b1"}`}, {"alice", `{"q":"a2"}`},
	} {
		out := callToolHTTPArgs(t, h, issuer+"|"+c.user, "docs__search", c.args)
		if isErr, _ := out["isError"].(bool); isErr {
			t.Fatalf("%s call errored: %v", c.user, out)
		}
	}

	bearers, sessions := up.calls()
	if len(bearers) != 3 {
		t.Fatalf("upstream saw %d calls, want 3", len(bearers))
	}
	alice1, bob, alice2 := 0, 1, 2
	// Each derived credential embeds ITS caller's verified email — the stub
	// provider validated the assertion's sub before minting it.
	if !strings.Contains(bearers[alice1], "alice@corp.example") || !strings.Contains(bearers[bob], "bob@corp.example") {
		t.Fatalf("derived tokens are not bound to their callers: %v", bearers)
	}
	if bearers[alice1] == bearers[bob] {
		t.Fatal("two principals shared one derived credential")
	}
	if bearers[alice1] != bearers[alice2] {
		t.Fatalf("one principal's cached credential must be reused within expiry: %q vs %q", bearers[alice1], bearers[alice2])
	}
	if got := provider.exchangeCount(); got != 2 {
		t.Fatalf("token endpoint saw %d exchanges, want 2 (alice's second call is a cache hit)", got)
	}
	// Upstream sessions are per principal too: distinct across callers, stable
	// for one caller.
	if sessions[alice1] == "" || sessions[bob] == "" {
		t.Fatalf("delegated calls must carry a session id: %v", sessions)
	}
	if sessions[alice1] == sessions[bob] {
		t.Fatalf("two principals shared one upstream session: %q", sessions[alice1])
	}
	if sessions[alice1] != sessions[alice2] {
		t.Fatalf("one principal's session must be stable: %q vs %q", sessions[alice1], sessions[alice2])
	}
}

// A caller with no provider-verified email cannot use a delegated connection:
// find_tools hides it, and a direct call fails closed BEFORE any egress, with
// an audited refusal. No fallback identity is ever substituted.
func TestDelegatedConnectionFailsClosedWithoutEmailMapping(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	emails := map[string]string{"alice": "alice@corp.example"} // carol is unmapped
	s := newDelegatedServer(t, provider, up, emails)
	h := s.HTTPHandlerAuth(issuerBearerAuth{})
	const issuer = "https://gateway.test"

	// find_tools: hidden from carol, visible to alice.
	if got := len(s.indexedTools(auth.PrincipalKey(issuer, "carol"))); got != 0 {
		t.Fatalf("unmapped caller must not see the delegated connection; got %d tools", got)
	}
	if got := len(s.indexedTools(auth.PrincipalKey(issuer, "alice"))); got != 1 {
		t.Fatalf("mapped caller must see the delegated connection; got %d tools", got)
	}

	out := callToolHTTPArgs(t, h, issuer+"|carol", "docs__search", `{"q":"x"}`)
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatalf("unmapped caller's delegated call must fail closed: %v", out)
	}
	if raw, _ := json.Marshal(out); !strings.Contains(string(raw), "provider-verified") {
		t.Fatalf("refusal must name the missing verified identity: %s", raw)
	}
	if bearers, _ := up.calls(); len(bearers) != 0 {
		t.Fatalf("a refused delegated call must not reach the upstream; saw %d calls", len(bearers))
	}
	if got := provider.exchangeCount(); got != 0 {
		t.Fatalf("a refused delegated call must not derive a token; saw %d exchanges", got)
	}
	// The refusal is audited.
	var refusal *RunInfo
	for _, r := range s.RunLog() {
		if r.Kind == "proxy" && r.ExitCode != 0 {
			rec := r
			refusal = &rec
		}
	}
	if refusal == nil {
		t.Fatal("refused delegated call left no audit record")
	}
	if refusal.User != auth.PrincipalKey(issuer, "carol") || refusal.DelegatedIdentity != "" {
		t.Fatalf("refusal record wrong: user=%q delegated=%q", refusal.User, refusal.DelegatedIdentity)
	}
}

// Without any email lookup wired (a non-federated deployment), a delegated
// connection is hidden from every caller and every call fails closed.
func TestDelegatedConnectionRequiresFederationWiring(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	s := newDelegatedServer(t, provider, up, nil)
	s.SetDelegatedEmailLookup(nil)
	if got := len(s.indexedTools(pk("alice"))); got != 0 {
		t.Fatalf("with no email lookup every caller must be unmapped; got %d tools", got)
	}
	out, handled := s.invokeUpstream(withPrincipal("alice"), "docs__search", json.RawMessage(`{"q":"x"}`))
	if !handled || !out["isError"].(bool) {
		t.Fatalf("delegated call without federation must fail closed: %v", out)
	}
}

// Every delegated proxy record carries BOTH identities: the caller's canonical
// key and the delegated identity the upstream saw.
func TestDelegatedAuditRecordsBothIdentities(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	s := newDelegatedServer(t, provider, up, map[string]string{"alice": "alice@corp.example"})

	out, handled := s.invokeUpstream(withPrincipal("alice"), "docs__search", json.RawMessage(`{"q":"x"}`))
	if !handled || out["isError"].(bool) {
		t.Fatalf("delegated call failed: %v", out)
	}
	var proxy *RunInfo
	for _, r := range s.RunLog() {
		if r.Kind == "proxy" {
			rec := r
			proxy = &rec
		}
	}
	if proxy == nil {
		t.Fatal("no proxy audit record")
	}
	if proxy.User != pk("alice") {
		t.Fatalf("caller identity = %q, want %q", proxy.User, pk("alice"))
	}
	if proxy.DelegatedIdentity != "alice@corp.example" {
		t.Fatalf("delegated identity = %q, want the derived subject", proxy.DelegatedIdentity)
	}
}

// Disabling a delegated connection quarantines it at the normal gate and drops
// the derivation cache: after re-enable, the next call derives fresh instead
// of replaying a token cached before the disable.
func TestDelegatedDisableDropsDerivationCache(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	s := newDelegatedServer(t, provider, up, map[string]string{"alice": "alice@corp.example"})
	ctx := withPrincipal("alice")

	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"1"}`)); out["isError"].(bool) {
		t.Fatalf("warm-up call failed: %v", out)
	}
	if err := s.DisableUpstream("docs"); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"2"}`)); !out["isError"].(bool) {
		t.Fatalf("disabled delegated connection must refuse: %v", out)
	}
	if err := s.EnableUpstream(context.Background(), "docs"); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"3"}`)); out["isError"].(bool) {
		t.Fatalf("re-enabled call failed: %v", out)
	}
	if got := provider.exchangeCount(); got != 2 {
		t.Fatalf("token endpoint saw %d exchanges, want 2 (cache dropped on disable)", got)
	}
}

// Revoking a delegated connection deletes the stored service-account key and
// refuses further calls like an unregistered tool.
func TestDelegatedRevokeDeletesKeyAndRefuses(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	s := newDelegatedServer(t, provider, up, map[string]string{"alice": "alice@corp.example"})
	ctx := withPrincipal("alice")

	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"1"}`)); out["isError"].(bool) {
		t.Fatalf("warm-up call failed: %v", out)
	}
	if err := s.RevokeUpstream("docs"); err != nil {
		t.Fatal(err)
	}
	if err := s.revokeRegistration(context.Background(), "docs"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.secrets.Load(context.Background(), DelegationKeyKey("docs")); err == nil {
		t.Fatal("revocation must delete the stored service-account key")
	}
	out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"2"}`))
	if !out["isError"].(bool) {
		t.Fatalf("revoked delegated connection must refuse: %v", out)
	}
}

// A delegated connection reloads across restart from the non-secret registry
// plus the stored key — and refuses to reload when the key is gone.
func TestDelegatedReloadAcrossRestart(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	stateDir, secretDir := t.TempDir(), t.TempDir()
	emails := map[string]string{"alice": "alice@corp.example"}

	saKey := provider.registerKey(t, "delegate@project.example")
	s1 := newTestServer(t, fakeRunner{}, WithStateDir(stateDir), WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, secretDir)))
	cfg := &DelegationSummary{Scopes: []string{"https://provider.example/auth/data.readonly"}}
	if _, code, err := s1.addDelegatedUpstream(context.Background(), "docs", up.ts.URL, false, false, "", cfg, saKey); err != nil {
		t.Fatalf("add delegated upstream (%d): %v", code, err)
	}

	s2 := newTestServer(t, fakeRunner{}, WithStateDir(stateDir), WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, secretDir)))
	s2.SetDelegatedEmailLookup(func(subject string) string { return emails[subject] })
	s2.ReloadUpstreams(context.Background())
	out, handled := s2.invokeUpstream(withPrincipal("alice"), "docs__search", json.RawMessage(`{"q":"x"}`))
	if !handled || out["isError"].(bool) {
		t.Fatalf("reloaded delegated call failed: %v", out)
	}
	bearers, _ := up.calls()
	if len(bearers) == 0 || !strings.Contains(bearers[len(bearers)-1], "alice@corp.example") {
		t.Fatalf("reloaded connection did not derive for the caller: %v", bearers)
	}

	// Key gone: the connection must not reload as callable.
	if err := s2.secrets.Delete(context.Background(), DelegationKeyKey("docs")); err != nil {
		t.Fatal(err)
	}
	s3 := newTestServer(t, fakeRunner{}, WithStateDir(stateDir), WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, secretDir)))
	s3.SetDelegatedEmailLookup(func(subject string) string { return emails[subject] })
	s3.ReloadUpstreams(context.Background())
	if s3.hasUpstream("docs") {
		t.Fatal("a delegated connection with no stored key must not reload")
	}
}

// The admin surface: adding a google-dwd connection stores the key ONLY in the
// secret store, persists only non-secret config, and never echoes key
// material. Invalid combinations fail closed.
func TestAdminAddDelegatedConnection(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	saKey := provider.registerKey(t, "delegate@project.example")
	stateDir := t.TempDir()
	s := newTestServer(t, fakeRunner{}, WithStateDir(stateDir), WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, t.TempDir())))
	h := s.AdminHandler(OperatorAuth{LegacyToken: "optok"})

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/upstreams", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer optok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	keyJSON, _ := json.Marshal(saKey)
	body := fmt.Sprintf(`{"name":"docs","url":%q,"strategy":"google-dwd","delegation":{"scopes":["https://provider.example/auth/data.readonly"]},"service_account_key":%s}`, up.ts.URL, keyJSON)
	rec := post(body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("response echoed key material")
	}
	if !strings.Contains(rec.Body.String(), `"key_configured":true`) {
		t.Fatalf("response must report key_configured: %s", rec.Body)
	}
	// The registry holds strategy + non-secret config, never the key.
	regs := s.loadRegistrations()
	if len(regs) != 1 || regs[0].strategyKind() != StrategyGoogleDWD || regs[0].Delegation == nil {
		t.Fatalf("registry = %+v", regs)
	}
	if regs[0].Delegation.ClientEmail != "delegate@project.example" {
		t.Fatalf("client email not resolved from the key: %+v", regs[0].Delegation)
	}
	if raw, err := json.Marshal(regs); err != nil || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("registry contains key material")
	}
	if _, err := s.secrets.Load(context.Background(), DelegationKeyKey("docs")); err != nil {
		t.Fatalf("key not in the secret store: %v", err)
	}
	// The operator listing shows the strategy and config, key_configured only.
	list := s.UpstreamList()
	if len(list) != 1 || list[0].Strategy != StrategyGoogleDWD || list[0].Delegation == nil || !list[0].Delegation.KeyConfigured {
		t.Fatalf("upstream list = %+v", list)
	}

	refused := []struct{ name, body string }{
		{"missing key", fmt.Sprintf(`{"name":"d2","url":%q,"strategy":"google-dwd","delegation":{"scopes":["s"]}}`, up.ts.URL)},
		{"missing scopes", fmt.Sprintf(`{"name":"d3","url":%q,"strategy":"google-dwd","service_account_key":%s}`, up.ts.URL, keyJSON)},
		{"static token alongside", fmt.Sprintf(`{"name":"d4","url":%q,"strategy":"google-dwd","token":"tok","delegation":{"scopes":["s"]},"service_account_key":%s}`, up.ts.URL, keyJSON)},
		{"per-user-oauth on admin surface", fmt.Sprintf(`{"name":"d5","url":%q,"strategy":"per-user-oauth"}`, up.ts.URL)},
		{"unknown strategy", fmt.Sprintf(`{"name":"d6","url":%q,"strategy":"acme"}`, up.ts.URL)},
		{"delegation without strategy", fmt.Sprintf(`{"name":"d7","url":%q,"delegation":{"scopes":["s"]}}`, up.ts.URL)},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400: %s", tc.name, rec.Code, rec.Body)
			}
		})
	}
}

// Key rotation through the admin surface: the new key serves subsequent
// derivations, the response reports key_configured without echoing material,
// and the old derivation cache is dropped.
func TestAdminRotateDelegatedKey(t *testing.T) {
	provider := newDelegationProvider(t)
	up := newDelegationUpstream(t)
	s := newDelegatedServer(t, provider, up, map[string]string{"alice": "alice@corp.example"})
	h := s.AdminHandler(OperatorAuth{LegacyToken: "optok"})
	ctx := withPrincipal("alice")

	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"1"}`)); out["isError"].(bool) {
		t.Fatalf("warm-up call failed: %v", out)
	}

	// Rotate to a fresh key; the stub provider now trusts only the new one.
	newKey := provider.registerKey(t, "delegate@project.example")
	keyJSON, _ := json.Marshal(newKey)
	req := httptest.NewRequest(http.MethodPost, "/admin/upstreams/docs/delegation",
		strings.NewReader(fmt.Sprintf(`{"service_account_key":%s}`, keyJSON)))
	req.Header.Set("Authorization", "Bearer optok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("rotation response echoed key material")
	}

	// The next call derives under the NEW key (the old cached token is gone;
	// the stub validates the assertion against the new public key).
	if out, _ := s.invokeUpstream(ctx, "docs__search", json.RawMessage(`{"q":"2"}`)); out["isError"].(bool) {
		t.Fatalf("post-rotation call failed: %v", out)
	}
	if got := provider.exchangeCount(); got != 2 {
		t.Fatalf("token endpoint saw %d exchanges, want 2 (fresh derivation after rotation)", got)
	}
}

// The strategy vocabulary is visible per connection: self-service connections
// report per-user-oauth, ordinary connections static, without any behavior
// change to either.
func TestStrategyVocabularyOnExistingConnections(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUpstream(context.Background(), "mine", &gateway.Upstream{Name: "mine", URL: ts.URL}, WithOwner(pk("alice")), WithSelfService("tpl")); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, info := range s.UpstreamList() {
		got[info.Name] = info.Strategy
	}
	if got["docs"] != StrategyStatic || got["mine"] != StrategyPerUserOAuth {
		t.Fatalf("strategies = %v", got)
	}
}
