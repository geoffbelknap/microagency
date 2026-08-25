package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
	"microagency/internal/secretstore"
)

type bearerSubjectAuth struct{}

func (bearerSubjectAuth) MultiPrincipal() bool { return true } // any bearer becomes its own subject

func (bearerSubjectAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	subject := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subject == "" || subject == r.Header.Get("Authorization") {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{Subject: subject, Issuer: testIssuer, Scopes: []string{"mcp"}}, nil
}

type selfServiceFixture struct {
	server      *Server
	admin       http.Handler
	users       *httptest.Server
	secrets     secretstore.Store
	upstreamURL string
	stateDir    string
	calls       *atomic.Int64
}

func newSelfServiceFixture(t *testing.T, maxPerUser int) *selfServiceFixture {
	t.Helper()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "upstream-as-key"))
	if err != nil {
		t.Fatal(err)
	}
	as := httptest.NewUnstartedServer(nil)
	asURL := "http://" + as.Listener.Addr().String()
	asMux := http.NewServeMux()
	auth.NewAuthServer(signer, asURL, "upstream", time.Hour, nil).Register(asMux)
	var upstreamResource string
	asMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"resource": upstreamResource, "authorization_servers": []string{asURL}})
	})
	as.Config.Handler = asMux
	as.Start()
	t.Cleanup(as.Close)

	calls := &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+asURL+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "tools/list") {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"query","description":"query documents","inputSchema":{"type":"object"}}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	}))
	t.Cleanup(upstream.Close)
	upstreamResource = upstream.URL

	stateDir := t.TempDir()
	secrets := openTestSecretStore(t, stateDir)
	refs := refstore.NewMemStore()
	server := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}), WithSecretStore(secrets), WithStateDir(stateDir), WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: refs}), WithWasmEngine("jq", fakeEngine{}))
	users := httptest.NewUnstartedServer(nil)
	base := "http://" + users.Listener.Addr().String()
	handler, err := server.UserConnectionsHandler(bearerSubjectAuth{}, base, "https://gateway.example/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	users.Config.Handler = handler
	users.Start()
	t.Cleanup(users.Close)

	admin := server.AdminHandler(OperatorAuth{LegacyToken: "operator"})
	template, _ := json.Marshal(map[string]any{
		"id": "documents", "display_name": "Documents", "url": upstream.URL,
		"allowed_scopes": []string{"mcp"}, "default_scopes": []string{"mcp"},
		"read_only": true, "max_per_user": maxPerUser,
	})
	rec := adminReq(t, admin, http.MethodPost, "/admin/connection-templates", "operator", string(template))
	if rec.Code != http.StatusOK {
		t.Fatalf("create template: %d %s", rec.Code, rec.Body.String())
	}
	return &selfServiceFixture{server: server, admin: admin, users: users, secrets: secrets, upstreamURL: upstream.URL, stateDir: stateDir, calls: calls}
}

func userRequest(t *testing.T, client *http.Client, method, rawURL, subject string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "" {
		req.Header.Set("Authorization", "Bearer "+subject)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func authorizeSelfServiceConnection(t *testing.T, fixture *selfServiceFixture, subject string) string {
	t.Helper()
	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", subject, map[string]any{"template": "documents"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("start %s connection: %d %s", subject, resp.StatusCode, body)
	}
	var started struct {
		Name         string `json:"name"`
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	if started.Name == "" || started.AuthorizeURL == "" {
		t.Fatalf("incomplete authorization response: %+v", started)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	approved := approveAtAS(t, noRedirect, started.AuthorizeURL)
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("approve = %d, want 302", approved.StatusCode)
	}
	callback, err := http.Get(approved.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Body.Close()
	callbackBody, _ := io.ReadAll(callback.Body)
	if callback.StatusCode != http.StatusOK {
		t.Fatalf("callback = %d: %s", callback.StatusCode, callbackBody)
	}
	if !strings.Contains(string(callbackBody), "Connected "+started.Name) {
		t.Fatalf("authorization did not register connection: %s", callbackBody)
	}
	return started.Name
}

func listUserConnections(t *testing.T, fixture *selfServiceFixture, subject string) []userConnectionInfo {
	t.Helper()
	resp := userRequest(t, http.DefaultClient, http.MethodGet, fixture.users.URL+"/connections", subject, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list connections = %d", resp.StatusCode)
	}
	var out []userConnectionInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSelfServiceConnectionsArePrincipalIsolated(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	aliceName := authorizeSelfServiceConnection(t, fixture, "alice")
	bobName := authorizeSelfServiceConnection(t, fixture, "bob")
	if aliceName == bobName {
		t.Fatal("server-generated connection names collided")
	}

	aliceList := listUserConnections(t, fixture, "alice")
	bobList := listUserConnections(t, fixture, "bob")
	if len(aliceList) != 1 || aliceList[0].Name != aliceName || len(bobList) != 1 || bobList[0].Name != bobName {
		t.Fatalf("principal lists crossed: alice=%+v bob=%+v", aliceList, bobList)
	}
	if renamed := listUserConnections(t, fixture, "alice-renamed"); len(renamed) != 0 {
		t.Fatalf("changed identity inherited old resources: %+v", renamed)
	}

	aliceTools, bobTools := fixture.server.indexedTools(pk("alice")), fixture.server.indexedTools(pk("bob"))
	aliceJSON, _ := json.Marshal(aliceTools)
	bobJSON, _ := json.Marshal(bobTools)
	if !strings.Contains(string(aliceJSON), aliceName+nsSep+"query") || strings.Contains(string(aliceJSON), bobName+nsSep+"query") {
		t.Fatalf("Alice tool view crossed: %s", aliceJSON)
	}
	if !strings.Contains(string(bobJSON), bobName+nsSep+"query") || strings.Contains(string(bobJSON), aliceName+nsSep+"query") {
		t.Fatalf("Bob tool view crossed: %s", bobJSON)
	}

	before := fixture.calls.Load()
	if out, _ := fixture.server.invokeUpstream(withPrincipal("bob"), aliceName+nsSep+"query", json.RawMessage(`{}`)); !out["isError"].(bool) || !strings.Contains(errText(t, out), "unknown tool") {
		t.Fatalf("Bob invoked Alice's connection: %+v", out)
	}
	if fixture.calls.Load() != before {
		t.Fatal("cross-user invocation reached the upstream or refreshed its token")
	}
	for _, action := range []struct {
		method, path string
	}{
		{http.MethodPost, "/connections/" + aliceName + "/refresh"},
		{http.MethodPost, "/connections/" + aliceName + "/reauthorize"},
		{http.MethodDelete, "/connections/" + aliceName},
	} {
		resp := userRequest(t, http.DefaultClient, action.method, fixture.users.URL+action.path, "bob", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Bob %s Alice connection = %d, want indistinguishable 404", action.path, resp.StatusCode)
		}
	}

	ref, _ := fixture.server.budget.Store.Put(`[{"private":true}]`, pk("alice"))
	args, _ := json.Marshal(map[string]any{"ref": string(ref), "query": "length"})
	if out := fixture.server.reduce(withPrincipal("bob"), args); !out["isError"].(bool) || !strings.Contains(errText(t, out), "unknown reference") {
		t.Fatalf("Bob reduced Alice's reference: %+v", out)
	}

	aliceTokenKey := selfServiceTokenKey(pk("alice"), aliceName)
	bobTokenKey := selfServiceTokenKey(pk("bob"), bobName)
	if aliceTokenKey == bobTokenKey {
		t.Fatal("principal credential keys collided")
	}
	if _, err := fixture.secrets.Load(context.Background(), aliceTokenKey); err != nil {
		t.Fatalf("Alice token missing: %v", err)
	}
	if _, err := fixture.secrets.Load(context.Background(), bobTokenKey); err != nil {
		t.Fatalf("Bob token missing: %v", err)
	}
	if _, err := fixture.secrets.Load(context.Background(), tokenKey(aliceName)); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("self-service token was written to the shared key: %v", err)
	}
	aliceClientKey := selfServiceClientKey(pk("alice"), "documents", fixture.upstreamURL)
	bobClientKey := selfServiceClientKey(pk("bob"), "documents", fixture.upstreamURL)
	if aliceClientKey == bobClientKey {
		t.Fatal("principal DCR keys collided")
	}
	var aliceClient, bobClient storedClient
	aliceRaw, err := fixture.secrets.Load(context.Background(), aliceClientKey)
	if err != nil {
		t.Fatal(err)
	}
	bobRaw, err := fixture.secrets.Load(context.Background(), bobClientKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(aliceRaw, &aliceClient)
	_ = json.Unmarshal(bobRaw, &bobClient)
	if aliceClient.ClientID == "" || bobClient.ClientID == "" || aliceClient.ClientID == bobClient.ClientID {
		t.Fatalf("DCR registrations were not principal-bound: alice=%q bob=%q", aliceClient.ClientID, bobClient.ClientID)
	}

	restarted := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, fixture.stateDir)), WithStateDir(fixture.stateDir))
	restarted.ReloadUpstreams(context.Background())
	if aliceView, _ := json.Marshal(restarted.indexedTools(pk("alice"))); !strings.Contains(string(aliceView), aliceName+nsSep+"query") || strings.Contains(string(aliceView), bobName+nsSep+"query") {
		t.Fatalf("restart lost Alice isolation: %s", aliceView)
	}
	if bobView, _ := json.Marshal(restarted.indexedTools(pk("bob"))); !strings.Contains(string(bobView), bobName+nsSep+"query") || strings.Contains(string(bobView), aliceName+nsSep+"query") {
		t.Fatalf("restart lost Bob isolation: %s", bobView)
	}

	shared := &gateway.Upstream{Name: "shared", URL: fixture.upstreamURL, Token: "operator-token", Client: &http.Client{}}
	if err := fixture.server.AddUpstream(context.Background(), "shared", shared); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"alice", "bob"} {
		view, _ := json.Marshal(fixture.server.indexedTools(pk(subject)))
		if !strings.Contains(string(view), "shared__query") {
			t.Fatalf("shared operator connection missing for %s: %s", subject, view)
		}
	}
	var aliceAuthorized, bobAuthorized, bobDenied bool
	for _, event := range fixture.server.RunLog() {
		if event.Kind != "connection" {
			continue
		}
		switch {
		case event.User == pk("alice") && event.Upstream == aliceName && event.Tool == "authorized":
			aliceAuthorized = true
		case event.User == pk("bob") && event.Upstream == bobName && event.Tool == "authorized":
			bobAuthorized = true
		case event.User == pk("bob") && event.Upstream == "" && event.Tool == "delete_denied":
			bobDenied = true
		}
	}
	if !aliceAuthorized || !bobAuthorized || !bobDenied {
		t.Fatalf("connection audit attribution incomplete: alice=%v bob=%v denied=%v", aliceAuthorized, bobAuthorized, bobDenied)
	}

	admin := adminReq(t, fixture.admin, http.MethodGet, "/admin/upstreams", "operator", "")
	if !strings.Contains(admin.Body.String(), `"owner":"`+pk("alice")+`"`) || !strings.Contains(admin.Body.String(), `"owner":"`+pk("bob")+`"`) {
		t.Fatalf("operator view omitted ownership: %s", admin.Body.String())
	}
	deletedByOperator := adminReq(t, fixture.admin, http.MethodDelete, "/admin/upstreams/"+bobName, "operator", "")
	if deletedByOperator.Code != http.StatusNoContent {
		t.Fatalf("operator delete self-service connection: %d %s", deletedByOperator.Code, deletedByOperator.Body.String())
	}
	if _, err := fixture.secrets.Load(context.Background(), bobTokenKey); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("operator delete retained Bob credential: %v", err)
	}
}

func TestSelfServiceQuotaAndRevocation(t *testing.T) {
	fixture := newSelfServiceFixture(t, 1)

	first := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice", map[string]any{"template": "documents"})
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first authorization = %d", first.StatusCode)
	}
	var pending struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	_ = json.NewDecoder(first.Body).Decode(&pending)
	first.Body.Close()
	second := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice", map[string]any{"template": "documents"})
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("parallel quota bypass = %d, want 429", second.StatusCode)
	}

	// Cancel the first pending flow by disabling the template, then restore it.
	disabled := adminReq(t, fixture.admin, http.MethodPost, "/admin/connection-templates", "operator", `{"id":"documents","display_name":"Documents","url":"`+fixture.upstreamURL+`","allowed_scopes":["mcp"],"default_scopes":["mcp"],"read_only":true,"max_per_user":1,"disabled":true}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable template: %d %s", disabled.Code, disabled.Body.String())
	}
	callback, err := url.Parse(pending.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") == "" {
		t.Fatal("authorization state missing")
	}
	enabled := adminReq(t, fixture.admin, http.MethodPost, "/admin/connection-templates", "operator", `{"id":"documents","display_name":"Documents","url":"`+fixture.upstreamURL+`","allowed_scopes":["mcp"],"default_scopes":["mcp"],"read_only":true,"max_per_user":1}`)
	if enabled.Code != http.StatusOK {
		t.Fatalf("restore template: %d %s", enabled.Code, enabled.Body.String())
	}

	name := authorizeSelfServiceConnection(t, fixture, "alice")
	overQuota := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice", map[string]any{"template": "documents"})
	overQuota.Body.Close()
	if overQuota.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("completed connection quota bypass = %d, want 429", overQuota.StatusCode)
	}
	disable := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/disable", "operator", "")
	if disable.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", disable.Code, disable.Body.String())
	}
	if out, _ := fixture.server.invokeUpstream(withPrincipal("alice"), name+nsSep+"query", json.RawMessage(`{}`)); !out["isError"].(bool) || !strings.Contains(errText(t, out), "not enabled") {
		t.Fatalf("disabled connection remained callable: %+v", out)
	}
	if enable := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/enable", "operator", ""); enable.Code != http.StatusOK {
		t.Fatalf("enable after disable: %d %s", enable.Code, enable.Body.String())
	}

	revoke := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/revoke", "operator", "")
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoke.Code, revoke.Body.String())
	}
	if _, err := fixture.secrets.Load(context.Background(), selfServiceTokenKey(pk("alice"), name)); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("revoked credential remains: %v", err)
	}
	if tools, _ := json.Marshal(fixture.server.indexedTools(pk("alice"))); strings.Contains(string(tools), name+nsSep) {
		t.Fatalf("revoked connection remains discoverable: %s", tools)
	}
	before := fixture.calls.Load()
	if out, _ := fixture.server.invokeUpstream(withPrincipal("alice"), name+nsSep+"query", json.RawMessage(`{}`)); !out["isError"].(bool) {
		t.Fatalf("revoked connection remained callable: %+v", out)
	}
	if fixture.calls.Load() != before {
		t.Fatal("revoked call reached upstream")
	}
	refresh := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections/"+name+"/refresh", "alice", nil)
	refresh.Body.Close()
	if refresh.StatusCode != http.StatusBadGateway {
		t.Fatalf("revoked refresh = %d, want refusal", refresh.StatusCode)
	}
	if enable := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/enable", "operator", ""); enable.Code != http.StatusBadGateway {
		t.Fatalf("operator re-enabled revoked credential = %d", enable.Code)
	}
	if reauth := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/reauth", "operator", "{}"); reauth.Code != http.StatusConflict {
		t.Fatalf("operator rebound user credential = %d", reauth.Code)
	}
	if owner := adminReq(t, fixture.admin, http.MethodPost, "/admin/upstreams/"+name+"/owner", "operator", `{"owner":"`+pk("bob")+`"}`); owner.Code != http.StatusConflict {
		t.Fatalf("operator transferred user grant = %d", owner.Code)
	}
	restarted := NewServer(fakeRunner{}, WithUpstreamClient(&http.Client{}), WithSecretStore(openTestSecretStore(t, fixture.stateDir)), WithStateDir(fixture.stateDir))
	restarted.ReloadUpstreams(context.Background())
	if view, _ := json.Marshal(restarted.indexedTools(pk("alice"))); strings.Contains(string(view), name+nsSep) {
		t.Fatalf("revoked credential became discoverable after restart: %s", view)
	}
	foundRevoked := false
	for _, connection := range restarted.UpstreamList() {
		if connection.Name == name && connection.Revoked && connection.State == "revoked" {
			foundRevoked = true
		}
	}
	if !foundRevoked {
		t.Fatal("restart did not retain the operator-visible revocation tombstone")
	}

	deleted := userRequest(t, http.DefaultClient, http.MethodDelete, fixture.users.URL+"/connections/"+name, "alice", nil)
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("owner delete = %d", deleted.StatusCode)
	}
	if _, err := fixture.secrets.Load(context.Background(), selfServiceClientKey(pk("alice"), "documents", fixture.upstreamURL)); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("last-connection DCR record remains after delete: %v", err)
	}
}

func TestConnectionTemplateValidationAndSecretCustody(t *testing.T) {
	stateDir := t.TempDir()
	store := openTestSecretStore(t, stateDir)
	server := NewServer(fakeRunner{}, WithStateDir(stateDir), WithSecretStore(store))
	admin := server.AdminHandler(OperatorAuth{LegacyToken: "operator"})
	bad := adminReq(t, admin, http.MethodPost, "/admin/connection-templates", "operator", `{"id":"bad","url":"http://metadata.google.internal/mcp"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("insecure remote template accepted: %d", bad.Code)
	}
	configured := adminReq(t, admin, http.MethodPost, "/admin/connection-templates", "operator", `{"id":"safe","url":"https://mcp.example.com/mcp","allowed_scopes":["read"],"default_scopes":["read"],"client_id":"public-id","client_secret":"private-secret"}`)
	if configured.Code != http.StatusOK {
		t.Fatalf("configure template client: %d %s", configured.Code, configured.Body.String())
	}
	if strings.Contains(configured.Body.String(), "public-id") || strings.Contains(configured.Body.String(), "private-secret") {
		t.Fatalf("template response exposed OAuth client: %s", configured.Body.String())
	}
	state, err := os.ReadFile(filepath.Join(stateDir, "connection-templates.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "public-id") || strings.Contains(string(state), "private-secret") {
		t.Fatalf("non-secret template state exposed OAuth client: %s", state)
	}
	raw, err := store.Load(context.Background(), templateClientKey("safe"))
	if err != nil || !strings.Contains(string(raw), "private-secret") {
		t.Fatalf("template client not held in secret store: %v %s", err, raw)
	}
	info, err := os.Stat(filepath.Join(stateDir, "connection-templates.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("template state mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestConnectionStartRateBound(t *testing.T) {
	server := NewServer(fakeRunner{})
	for i := 0; i < maxConnectionStartsPerHour; i++ {
		reservation, err := server.reserveConnectionStart("alice", "docs", 1, 1, 1, true)
		if err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
		server.releaseConnectionStart(reservation)
	}
	if _, err := server.reserveConnectionStart("alice", "docs", 1, 1, 1, true); err == nil {
		t.Fatal("hourly connection authorization rate limit was not enforced")
	}
}

func TestConnectionTemplateBoundsUserScopesAndParams(t *testing.T) {
	template := ConnectionTemplate{
		ID: "supabase", URL: "https://mcp.supabase.com/mcp",
		AllowedScopes: []string{"projects:read"}, DefaultScopes: []string{"projects:read"},
		AllowedParams: []string{"project_ref"},
	}
	if err := normalizeConnectionTemplate(&template); err != nil {
		t.Fatal(err)
	}
	if _, err := requestedTemplateScopes(template, []string{"projects:write"}); err == nil {
		t.Fatal("user widened operator-approved OAuth scopes")
	}
	scoped, err := scopedTemplateURL(template, map[string]string{"project_ref": "project-a"})
	if err != nil || !strings.Contains(scoped, "project_ref=project-a") {
		t.Fatalf("approved provider parameter was not applied: %q %v", scoped, err)
	}
	if _, err := scopedTemplateURL(template, map[string]string{"features": "database"}); err == nil {
		t.Fatal("user supplied a provider parameter outside the template")
	}
}

func TestTemplateVersionBlocksStaleAuthorizationCommit(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	_, version, ok := fixture.server.connectionTemplateWithVersion("documents", false)
	if !ok {
		t.Fatal("template missing")
	}
	updated := adminReq(t, fixture.admin, http.MethodPost, "/admin/connection-templates", "operator", `{"id":"documents","display_name":"Documents v2","url":"`+fixture.upstreamURL+`","allowed_scopes":["mcp"],"default_scopes":["mcp"],"read_only":true,"max_per_user":2}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update template: %d %s", updated.Code, updated.Body.String())
	}
	flow := &oauthFlow{name: "documents-stale", url: fixture.upstreamURL, owner: "alice", selfService: true, template: "documents", templateVersion: version, readOnly: true}
	conn := &gateway.Upstream{Name: flow.name, URL: flow.url, Token: "access", Client: &http.Client{}}
	if err := fixture.server.commitSelfServiceOAuth(context.Background(), flow, conn); err == nil {
		t.Fatal("authorization admitted under a superseded template version")
	}
	if fixture.server.hasUpstream(flow.name) {
		t.Fatal("stale authorization became visible in the tool registry")
	}
}

func TestUserConnectionRoutesRequirePrincipal(t *testing.T) {
	server := NewServer(fakeRunner{})
	handler, err := server.UserConnectionsHandler(bearerSubjectAuth{}, "https://gateway.example", "https://gateway.example/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/connections/templates", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("unauthenticated template list = %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// The provider callback cannot be bearer-gated, but forged state is inert.
	req = httptest.NewRequest(http.MethodGet, "/connections/oauth/callback?state=forged&code=x", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(server.UpstreamList()) != 0 {
		t.Fatalf("forged unauthenticated callback changed state: %d %+v", rec.Code, server.UpstreamList())
	}
}

func TestRevocationGenerationBlocksStaleRebindAndTokenWrite(t *testing.T) {
	upstream := cannedUpstream(t)
	defer upstream.Close()
	stateDir := t.TempDir()
	store := openTestSecretStore(t, stateDir)
	server := NewServer(fakeRunner{}, WithUpstreamClient(upstream.Client()), WithSecretStore(store), WithStateDir(stateDir))
	connection := &gateway.Upstream{Name: "private", URL: upstream.URL, Token: "access", Client: upstream.Client()}
	if err := server.AddUpstream(context.Background(), "private", connection, WithOwner("alice"), WithSelfService("documents")); err != nil {
		t.Fatal(err)
	}
	server.persistRegistrationRecord(upstreamReg{Name: "private", URL: upstream.URL, Auth: authOAuth, Owner: "alice", SelfService: true, Template: "documents"})
	if err := server.RevokeUpstream("private"); err != nil {
		t.Fatal(err)
	}
	staleGeneration := uint64(0)
	if err := server.rebindUpstream(context.Background(), "private", connection, &staleGeneration); err == nil {
		t.Fatal("a callback from before revocation rebound the connection")
	}
	token := auth.TokenFromRecord(auth.TokenRecord{AccessToken: "access", RefreshToken: "refresh", TokenEndpoint: "https://issuer.example/token"})
	key := selfServiceTokenKey("alice", "private")
	server.saveUpstreamTokenAtKey("private", key, token, staleGeneration, true)
	if _, err := store.Load(context.Background(), key); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("a stale refresh persisted after revocation: %v", err)
	}
	if record, ok := server.snapshotUpstream("private"); !ok || !record.revoked || record.enabled {
		t.Fatalf("stale operations changed revoked posture: %+v %v", record, ok)
	}
}

func TestPrincipalTokenRotationPersistsDuringReloadBeforeRegistration(t *testing.T) {
	stateDir := t.TempDir()
	store := openTestSecretStore(t, stateDir)
	server := NewServer(fakeRunner{}, WithSecretStore(store), WithStateDir(stateDir))
	server.persistRegistrationRecord(upstreamReg{Name: "private", URL: "https://mcp.example.com", Auth: authOAuth, Owner: "alice", SelfService: true, Template: "documents"})
	token := auth.TokenFromRecord(auth.TokenRecord{AccessToken: "new-access", RefreshToken: "new-refresh", TokenEndpoint: "https://issuer.example/token"})
	key := selfServiceTokenKey("alice", "private")
	server.saveUpstreamTokenAtKey("private", key, token, 0, true)
	raw, err := store.Load(context.Background(), key)
	if err != nil || !strings.Contains(string(raw), "new-refresh") {
		t.Fatalf("startup rotation was not persisted before in-memory registration: %v %s", err, raw)
	}
	server.updateRegistrations(func(registrations []upstreamReg) ([]upstreamReg, bool) { return nil, true })
	server.saveUpstreamTokenAtKey("private", key, auth.TokenFromRecord(auth.TokenRecord{RefreshToken: "stale"}), 0, true)
	raw, err = store.Load(context.Background(), key)
	if err != nil || strings.Contains(string(raw), "stale") {
		t.Fatalf("removed durable registration accepted a stale token write: %v %s", err, raw)
	}
}

func listUserTemplates(t *testing.T, fixture *selfServiceFixture, subject string) []userConnectionTemplate {
	t.Helper()
	resp := userRequest(t, http.DefaultClient, http.MethodGet, fixture.users.URL+"/connections/templates", subject, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list templates = %d", resp.StatusCode)
	}
	var out []userConnectionTemplate
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A user choosing provider parameters needs to know what each one means, so the
// published template carries the curated catalog entry for every parameter the
// operator allowed — and nothing beyond it. The operator's OAuth client for the
// template stays a bool: the client_id and secret are only ever in the secret
// store.
func TestUserTemplatesCarryCuratedParamsAndNoClientSecret(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	template, _ := json.Marshal(map[string]any{
		"id": "supabase", "display_name": "Supabase", "url": "https://mcp.supabase.com/mcp",
		"allowed_scopes": []string{"mcp"}, "default_scopes": []string{"mcp"},
		"allowed_params": []string{"read_only", "project_ref"},
		"read_only":      true, "max_per_user": 1,
		"client_id": "public-client", "client_secret": "s3cret",
	})
	if rec := adminReq(t, fixture.admin, http.MethodPost, "/admin/connection-templates", "operator", string(template)); rec.Code != http.StatusOK {
		t.Fatalf("create template: %d %s", rec.Code, rec.Body.String())
	}

	published := listUserTemplates(t, fixture, "alice")
	var supabase *userConnectionTemplate
	for i := range published {
		if published[i].ID == "supabase" {
			supabase = &published[i]
		}
	}
	if supabase == nil {
		t.Fatal("published template missing from the user template list")
	}
	if len(supabase.Params) != 2 {
		t.Fatalf("params = %+v, want the two allowed parameters", supabase.Params)
	}
	// Catalog order, not the operator's request order: the surface renders the
	// provider's own ordering.
	if supabase.Params[0].Name != "project_ref" || supabase.Params[1].Name != "read_only" {
		t.Errorf("params not in catalog order: %+v", supabase.Params)
	}
	if supabase.Params[0].Kind != ParamString || supabase.Params[1].Kind != ParamBool {
		t.Errorf("parameter kinds not published: %+v", supabase.Params)
	}
	for _, param := range supabase.Params {
		if param.Description == "" {
			t.Errorf("parameter %q published without its description", param.Name)
		}
	}
	if !supabase.ClientConfigured {
		t.Error("client_configured should report that the operator configured a client")
	}
	raw, _ := json.Marshal(supabase)
	for _, secret := range []string{"s3cret", "public-client", "client_secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("template response leaked OAuth client material %q: %s", secret, raw)
		}
	}
}

// templateParams publishes only what the operator allowed AND the catalog still
// declares. A parameter the catalog dropped is omitted rather than rendered with
// no meaning, and an unknown provider publishes none at all.
func TestTemplateParamsAreBoundedByOperatorAndCatalog(t *testing.T) {
	supabase := ConnectionTemplate{URL: "https://mcp.supabase.com/mcp", AllowedParams: []string{"read_only"}}
	if got := templateParams(supabase); len(got) != 1 || got[0].Name != "read_only" {
		t.Fatalf("templateParams = %+v, want just read_only", got)
	}
	stale := ConnectionTemplate{URL: "https://mcp.supabase.com/mcp", AllowedParams: []string{"no_such_param"}}
	if got := templateParams(stale); len(got) != 0 {
		t.Fatalf("templateParams published an uncurated parameter: %+v", got)
	}
	unknown := ConnectionTemplate{URL: "https://mcp.example.com/mcp", AllowedParams: []string{"read_only"}}
	if got := templateParams(unknown); len(got) != 0 {
		t.Fatalf("templateParams published parameters for an unknown provider: %+v", got)
	}
}

// The connection list is what a user manages their own connections from, so it
// carries the target it points at and when it last worked — and still only ever
// the caller's own connections.
func TestUserConnectionListCarriesTargetAndLastUse(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	name := authorizeSelfServiceConnection(t, fixture, "alice")

	listed := listUserConnections(t, fixture, "alice")
	if len(listed) != 1 {
		t.Fatalf("connections = %+v, want one", listed)
	}
	if listed[0].URL != fixture.upstreamURL {
		t.Errorf("url = %q, want the connection's target %q", listed[0].URL, fixture.upstreamURL)
	}
	if listed[0].LastOK != "" {
		t.Errorf("last_ok = %q on a connection that has never been called", listed[0].LastOK)
	}

	if out, _ := fixture.server.invokeUpstream(withPrincipal("alice"), name+nsSep+"query", json.RawMessage(`{}`)); out["isError"] == true {
		t.Fatalf("call through the connection failed: %+v", out)
	}
	after := listUserConnections(t, fixture, "alice")
	if len(after) != 1 || after[0].LastOK == "" {
		t.Fatalf("last_ok not reported after a successful call: %+v", after)
	}
	if _, err := time.Parse(time.RFC3339, after[0].LastOK); err != nil {
		t.Errorf("last_ok is not RFC 3339: %q", after[0].LastOK)
	}
	if other := listUserConnections(t, fixture, "bob"); len(other) != 0 {
		t.Fatalf("another principal saw the connection: %+v", other)
	}
}

// A principal labels their OWN connection through the self-service plane. The
// label is what makes two connections from one template choosable on purpose, so
// it has to survive the round trip to the listing and the tool view — and an
// invalid label has to be refused at the write, not sanitized into the record.
func TestSelfServiceConnectionLabelling(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	name := authorizeSelfServiceConnection(t, fixture, "alice")

	label := func(subject, connection, value string) *http.Response {
		return userRequest(t, http.DefaultClient, http.MethodPatch,
			fixture.users.URL+"/connections/"+connection, subject, map[string]any{"label": value})
	}

	resp := label("alice", name, "production")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("label own connection = %d: %s", resp.StatusCode, body)
	}
	listed := listUserConnections(t, fixture, "alice")
	if len(listed) != 1 || listed[0].Label != "production" {
		t.Fatalf("label must appear in the owner's listing: %+v", listed)
	}

	// Refused at the write surface, with the reason — never trimmed into shape.
	for _, bad := range []string{"prod\nstaging", strings.Repeat("x", 33), " prod", "prоduction"} {
		resp := label("alice", name, bad)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("label %q must be refused with 400; got %d %s", bad, resp.StatusCode, body)
		}
	}
	if listed := listUserConnections(t, fixture, "alice"); listed[0].Label != "production" {
		t.Fatalf("a refused label must leave the stored one intact: %+v", listed)
	}

	// Another principal cannot label a connection they do not own, and learns
	// nothing about it beyond the not-found every unknown name gets.
	resp = label("bob", name, "mine-now")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("labelling another principal's connection must 404; got %d %s", resp.StatusCode, body)
	}
	if listed := listUserConnections(t, fixture, "alice"); listed[0].Label != "production" {
		t.Fatalf("another principal must not change the owner's label: %+v", listed)
	}

	// Clearing is the reverse of setting.
	resp = label("alice", name, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clearing a label = %d", resp.StatusCode)
	}
	if listed := listUserConnections(t, fixture, "alice"); listed[0].Label != "" {
		t.Fatalf("label was not cleared: %+v", listed)
	}
}

// A label set when the connection is created closes the window in which a second
// connection from the same template exists and neither can be told apart. It must
// also survive a restart, or the gateway comes back with both twins unnamed.
func TestSelfServiceLabelAtCreationSurvivesReload(t *testing.T) {
	fixture := newSelfServiceFixture(t, 2)
	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", "alice",
		map[string]any{"template": "documents", "label": "prod\nstaging"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an invalid label must be refused before any connection is started; got %d %s", resp.StatusCode, body)
	}

	name := authorizeSelfServiceConnectionLabelled(t, fixture, "alice", "production")
	listed := listUserConnections(t, fixture, "alice")
	if len(listed) != 1 || listed[0].Label != "production" {
		t.Fatalf("a label set at creation must be stored: %+v", listed)
	}

	persisted := persistedLabel(t, fixture.stateDir, name)
	if persisted != "production" {
		t.Fatalf("label must be persisted for reload; got %q", persisted)
	}
}

// authorizeSelfServiceConnectionLabelled runs the self-service OAuth flow with a
// label supplied at creation and returns the connection name.
func authorizeSelfServiceConnectionLabelled(t *testing.T, fixture *selfServiceFixture, subject, label string) string {
	t.Helper()
	resp := userRequest(t, http.DefaultClient, http.MethodPost, fixture.users.URL+"/connections", subject,
		map[string]any{"template": "documents", "label": label})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("start labelled connection: %d %s", resp.StatusCode, body)
	}
	var started struct {
		Name         string `json:"name"`
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	approved := approveAtAS(t, noRedirect, started.AuthorizeURL)
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("approve = %d, want 302", approved.StatusCode)
	}
	callback, err := http.Get(approved.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Body.Close()
	if callback.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(callback.Body)
		t.Fatalf("callback = %d: %s", callback.StatusCode, body)
	}
	return started.Name
}

// persistedLabel reads one connection's stored label straight out of the state
// file, proving the label is durable rather than only in memory.
func persistedLabel(t *testing.T, stateDir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, "upstreams.json"))
	if err != nil {
		t.Fatal(err)
	}
	var regs []upstreamReg
	if err := json.Unmarshal(raw, &regs); err != nil {
		t.Fatal(err)
	}
	for _, reg := range regs {
		if reg.Name == name {
			return reg.Label
		}
	}
	t.Fatalf("no persisted registration for %q", name)
	return ""
}
