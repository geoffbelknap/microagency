package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/gateway"
)

func withCampaign(sub, campaign string) context.Context {
	return context.WithValue(context.Background(), principalKey, &auth.Principal{Subject: sub, Issuer: testIssuer, Campaign: campaign})
}

func newGovernedTestServer(t *testing.T, tools []upTool, appendLine func(string, []byte) error, shared bool) (*Server, *int32) {
	t.Helper()
	var hit int32
	up := guardUpstream(t, tools, false, &hit)
	t.Cleanup(up.Close)
	dir := t.TempDir()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatal(err)
	}
	opts := []Option{
		WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)), WithAuditSigner(signer),
		WithHighAssuranceMultiUser(true), WithUpstreamClient(up.Client()),
	}
	if appendLine != nil {
		opts = append(opts, withDecisionLedgerAppender(appendLine))
	}
	s := NewServer(fakeRunner{}, opts...)
	var upstreamOpts []UpstreamOption
	if !shared {
		upstreamOpts = append(upstreamOpts, WithOwner(pk("alice")))
	}
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: up.Client()}, upstreamOpts...); err != nil {
		t.Fatal(err)
	}
	return s, &hit
}

func readGrant(tool string) OperationGrant {
	return OperationGrant{
		Version: grantVersion, ID: "read-repo", Connection: "u", Tool: tool, Effect: effectRead,
		Principal: pk("alice"), Campaign: "campaign-a", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Arguments:   []ArgumentGrant{{Pointer: "/repo", Required: true, Values: []string{"org/repo"}}},
		Resources:   []ResourceGrant{{Kind: "repository", Namespace: "github", Argument: "/repo"}},
		MaxRequests: 4, MaxBytes: 8192, MaxResponseBytes: 1024,
		Rate: RateGrant{Requests: 4, WindowS: 60}, HighAssurance: true,
	}
}

func TestHighAssuranceExactReadCannotReachAdjacentOperations(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}, {name: "create-repo"}, {name: "fetch-url"}}, nil, false)
	if err := s.SetUpstreamGrants("u", []OperationGrant{readGrant("get-repo")}); err != nil {
		t.Fatal(err)
	}
	ctx := withCampaign("alice", "campaign-a")
	allowed, _ := s.invokeUpstream(ctx, "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
	if allowed["isError"].(bool) {
		t.Fatalf("granted read failed: %v", allowed)
	}
	for _, adjacent := range []string{"create-repo", "fetch-url", "delete-repo"} {
		out, _ := s.invokeUpstream(ctx, "u__"+adjacent, json.RawMessage(`{"repo":"org/repo"}`))
		if !out["isError"].(bool) || !strings.Contains(errText(t, out), "not authorized") {
			t.Fatalf("adjacent operation %s was not uniformly refused: %v", adjacent, out)
		}
	}
	if got := atomic.LoadInt32(hit); got != 1 {
		t.Fatalf("adjacent operation crossed the gateway: upstream hits=%d", got)
	}
}

func TestHighAssuranceReadGrantDoesNotTrustRelabeledWriteTool(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "create-repo", readOnly: ptrBool(true)}}, nil, false)
	grant := readGrant("create-repo")
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	out, _ := s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__create-repo", json.RawMessage(`{"repo":"org/repo"}`))
	if !out["isError"].(bool) || atomic.LoadInt32(hit) != 0 {
		t.Fatalf("read grant trusted a relabeled write tool: out=%v hits=%d", out, atomic.LoadInt32(hit))
	}
	indexed, _ := json.Marshal(s.indexedToolsFor(pk("alice"), "campaign-a"))
	if strings.Contains(string(indexed), "create-repo") {
		t.Fatalf("relabeled write tool remained discoverable under a read grant: %s", indexed)
	}
}

func TestGrantRejectsArgumentSmugglingAndAlternateURLs(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "fetch-url", readOnly: ptrBool(true)}}, nil, false)
	grant := readGrant("fetch-url")
	grant.ID = "fetch-approved"
	grant.Arguments = []ArgumentGrant{{Pointer: "/url", Required: true, URLTarget: "fixture"}}
	grant.Resources = []ResourceGrant{{Kind: "url", Namespace: "fixture-fetch", Argument: "/url"}}
	grant.URLTargets = []URLTargetGrant{{ID: "fixture", Origins: []string{"https://fixture.example"}, Paths: []string{"/approved"}}}
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	ctx := withCampaign("alice", "campaign-a")
	allowed, _ := s.invokeUpstream(ctx, "u__fetch-url", json.RawMessage(`{"url":"https://fixture.example/approved/item"}`))
	if allowed["isError"].(bool) {
		t.Fatalf("approved URL failed: %v", allowed)
	}
	denied := []string{
		`{"url":"https://fixture.example/approved/item","webhook":"https://evil.example"}`,
		`{"url":"https://evil.example/approved/item"}`,
		`{"url":"https://203.0.113.8/approved/item"}`,
		`{"url":"https://fixture.example/approved/%2e%2e/admin"}`,
		`{"url":"https://fixture.example/approved/item?url=https%3A%2F%2Fevil.example"}`,
		`{"url":"https://user@fixture.example/approved/item"}`,
		`{"url":"https://fixture.example/approved/item","url":"https://evil.example/approved/item"}`,
	}
	for _, args := range denied {
		out, _ := s.invokeUpstream(ctx, "u__fetch-url", json.RawMessage(args))
		if !out["isError"].(bool) {
			t.Fatalf("ungranted argument form crossed: %s", args)
		}
	}
	if got := atomic.LoadInt32(hit); got != 1 {
		t.Fatalf("denied URL form reached the upstream: hits=%d", got)
	}
}

func TestGrantURLQueryMustMatchExactCanonicalAllowlist(t *testing.T) {
	grant := readGrant("fetch-url")
	grant.Arguments = []ArgumentGrant{{Pointer: "/url", Required: true, URLTarget: "fixture"}}
	grant.Resources = []ResourceGrant{{Kind: "url", Namespace: "fixture-fetch", Argument: "/url"}}
	grant.URLTargets = []URLTargetGrant{{
		ID: "fixture", Origins: []string{"https://fixture.example"}, Paths: []string{"/approved"},
		Query: map[string][]string{"version": {"1"}},
	}}
	checked, err := validateOperationGrant(grant, "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluateOperationGrant(checked, pk("alice"), "campaign-a", "fetch-url", json.RawMessage(`{"url":"https://fixture.example/approved?version=1"}`), time.Now()); err != nil {
		t.Fatalf("exact query was denied: %v", err)
	}
	for _, raw := range []string{
		`{"url":"https://fixture.example/approved"}`,
		`{"url":"https://fixture.example/approved?version=2"}`,
		`{"url":"https://fixture.example/approved?version=1&next=https%3A%2F%2Fevil.example"}`,
	} {
		if _, err := evaluateOperationGrant(checked, pk("alice"), "campaign-a", "fetch-url", json.RawMessage(raw), time.Now()); err == nil {
			t.Fatalf("non-exact URL query was accepted: %s", raw)
		}
	}
}

func TestOperationGrantJSONRejectsUnknownAndDuplicateFields(t *testing.T) {
	valid, err := json.Marshal(readGrant("get-repo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		append(valid[:len(valid)-1], []byte(`,"max_requsets":99}`)...),
		append(valid[:len(valid)-1], []byte(`,"tool":"create-repo"}`)...),
		[]byte(strings.Replace(string(valid), `"required":true`, `"required":true,"unexpected":true`, 1)),
	} {
		var grant OperationGrant
		if err := json.Unmarshal(raw, &grant); err == nil {
			t.Fatalf("ambiguous grant JSON was accepted: %s", raw)
		}
	}
}

func TestGrantBudgetsRejectOverflowAndImpossibleReservation(t *testing.T) {
	for _, mutate := range []func(*OperationGrant){
		func(g *OperationGrant) { g.MaxRequests = maxGrantRequests + 1 },
		func(g *OperationGrant) { g.MaxBytes = maxGrantBytes + 1 },
		func(g *OperationGrant) { g.MaxResponseBytes = g.MaxBytes },
		func(g *OperationGrant) { g.Rate.WindowS = maxGrantRateWindow + 1 },
	} {
		grant := readGrant("get-repo")
		mutate(&grant)
		if _, err := validateOperationGrant(grant, "u"); err == nil {
			t.Fatalf("unbounded grant was accepted: %+v", grant)
		}
	}
}

func TestOpaqueResourceIDsArePrincipalScopedUnlessSharedWritable(t *testing.T) {
	alice := opaqueResourceID("alice", "campaign-a", "object", "mailbox", "same")
	bob := opaqueResourceID("bob", "campaign-a", "object", "mailbox", "same")
	if alice == bob {
		t.Fatal("private resource ID created a cross-principal correlation channel")
	}
	sharedA := opaqueResourceID("shared-writable", "campaign-a", "object", "mailbox", "same")
	sharedB := opaqueResourceID("shared-writable", "campaign-a", "object", "mailbox", "same")
	if sharedA != sharedB {
		t.Fatal("explicit shared-writable resource did not retain one audit identity")
	}
}

func TestSharedWritableNamespaceRequiresExplicitOptIn(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "create-object"}}, nil, true)
	grant := OperationGrant{
		Version: grantVersion, ID: "write-object", Connection: "u", Tool: "create-object", Effect: effectWrite,
		Principal: pk("alice"), Campaign: "campaign-a", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Arguments:   []ArgumentGrant{{Pointer: "/object", Required: true, Pattern: `[a-z0-9-]+`, MaxBytes: 64}},
		Resources:   []ResourceGrant{{Kind: "object", Namespace: "mailbox", Argument: "/object"}},
		MaxRequests: 2, MaxBytes: 4096, MaxResponseBytes: 1024,
		Rate: RateGrant{Requests: 2, WindowS: 60}, HighAssurance: true,
	}
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	ctx := withCampaign("alice", "campaign-a")
	if out, _ := s.invokeUpstream(ctx, "u__create-object", json.RawMessage(`{"object":"message-a"}`)); !out["isError"].(bool) {
		t.Fatal("implicit shared credential/namespace was accepted")
	}
	if atomic.LoadInt32(hit) != 0 {
		t.Fatal("undeclared shared namespace reached the upstream")
	}
	grant.AllowShared = true
	grant.Resources[0].SharedWritable = true
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(ctx, "u__create-object", json.RawMessage(`{"object":"message-a"}`)); out["isError"].(bool) {
		t.Fatalf("explicit shared namespace failed: %v", out)
	}
	if out, _ := s.invokeUpstream(withCampaign("bob", "campaign-a"), "u__create-object", json.RawMessage(`{"object":"message-a"}`)); !out["isError"].(bool) {
		t.Fatal("another principal exercised Alice's shared writable grant")
	}
	if atomic.LoadInt32(hit) != 1 {
		t.Fatalf("cross-principal call crossed: hits=%d", atomic.LoadInt32(hit))
	}
}

func TestDecisionLedgerFailureBlocksCrossing(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, func(string, []byte) error {
		return errors.New("induced ledger failure")
	}, false)
	if err := s.SetUpstreamGrants("u", []OperationGrant{readGrant("get-repo")}); err != nil {
		t.Fatal(err)
	}
	out, _ := s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
	if !out["isError"].(bool) || atomic.LoadInt32(hit) != 0 {
		t.Fatalf("ledger failure did not fail closed: out=%v hit=%d", out, atomic.LoadInt32(hit))
	}
}

func TestDecisionLedgerIsSignedAnchoredPrivateAndBudgeted(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, nil, false)
	grant := readGrant("get-repo")
	grant.MaxRequests = 1
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	ctx := withCampaign("alice", "campaign-a")
	for i := 0; i < 2; i++ {
		_, _ = s.invokeUpstream(ctx, "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
	}
	if atomic.LoadInt32(hit) != 1 {
		t.Fatalf("request budget did not stop the second crossing: hits=%d", atomic.LoadInt32(hit))
	}
	verification := s.VerifyDecisionLedger(context.Background())
	if !verification.Intact || !verification.Anchored || verification.Records != 2 || verification.Error != "" {
		t.Fatalf("decision ledger verification = %+v", verification)
	}
	raw, err := os.ReadFile(s.decisionLedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "org/repo") || !strings.Contains(string(raw), `"resource_ids":["res_`) {
		t.Fatalf("ledger exposed raw object identity or omitted opaque identity: %s", raw)
	}
	if !strings.Contains(string(raw), `"principal":"`+pk("alice")+`"`) || !strings.Contains(string(raw), `"campaign":"campaign-a"`) || !strings.Contains(string(raw), `"grant_id":"read-repo"`) || !strings.Contains(string(raw), `"operation":"get-repo"`) || !strings.Contains(string(raw), `"reason":"request budget exhausted"`) {
		t.Fatalf("ledger denial attribution is incomplete: %s", raw)
	}
	runs := s.RunLog()
	var found bool
	for _, run := range runs {
		if run.Kind == "proxy" && run.Campaign == "campaign-a" && run.GrantID == "read-repo" && len(run.ResourceIDs) == 1 && run.Args == "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ordinary audit omitted campaign/grant/resource correlation: %+v", runs)
	}
	if err := os.Remove(s.decisionLedgerPath()); err != nil {
		t.Fatal(err)
	}
	if after := s.VerifyDecisionLedger(context.Background()); after.Intact || after.Error == "" {
		t.Fatalf("signed anchor did not detect whole-ledger truncation: %+v", after)
	}
}

func TestDecisionLedgerEnforcesRateAndByteBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*OperationGrant)
		reason string
	}{
		{
			name: "rate", reason: "rate budget exhausted",
			mutate: func(grant *OperationGrant) {
				grant.MaxRequests = 2
				grant.Rate = RateGrant{Requests: 1, WindowS: 3600}
			},
		},
		{
			name: "bytes", reason: "byte budget exhausted",
			mutate: func(grant *OperationGrant) {
				grant.MaxRequests = 2
				grant.MaxBytes = 1100
				grant.MaxResponseBytes = 1024
				grant.Rate = RateGrant{Requests: 2, WindowS: 60}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, nil, false)
			grant := readGrant("get-repo")
			tc.mutate(&grant)
			if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				_, _ = s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
			}
			if atomic.LoadInt32(hit) != 1 {
				t.Fatalf("%s budget allowed extra crossing: hits=%d", tc.name, atomic.LoadInt32(hit))
			}
			raw, err := os.ReadFile(s.decisionLedgerPath())
			if err != nil || !strings.Contains(string(raw), tc.reason) {
				t.Fatalf("%s refusal reason missing: err=%v ledger=%s", tc.name, err, raw)
			}
		})
	}
}

func TestGrantExpiryAndSignedCampaignAreRecheckedAtInvocation(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, nil, false)
	grant := readGrant("get-repo")
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(withCampaign("alice", "campaign-b"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`)); !out["isError"].(bool) {
		t.Fatal("caller selected authority from another signed campaign")
	}
	grant.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`)); !out["isError"].(bool) {
		t.Fatal("expired grant remained invocable")
	}
	if atomic.LoadInt32(hit) != 0 {
		t.Fatalf("campaign or expiry denial reached upstream: hits=%d", atomic.LoadInt32(hit))
	}
}

func TestGrantedResponseByteCeilingWithholdsOversizeResult(t *testing.T) {
	s, hit := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, nil, false)
	grant := readGrant("get-repo")
	grant.MaxResponseBytes = 1
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	out, _ := s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
	if !out["isError"].(bool) || !strings.Contains(errText(t, out), "withheld") || atomic.LoadInt32(hit) != 1 {
		t.Fatalf("oversize governed response was not withheld: out=%v hits=%d", out, atomic.LoadInt32(hit))
	}
}

func TestHighAssuranceIndexExposesOnlyCurrentCallerGrant(t *testing.T) {
	s, _ := newGovernedTestServer(t, []upTool{{name: "get-repo"}, {name: "create-repo"}}, nil, false)
	if err := s.SetUpstreamGrants("u", []OperationGrant{readGrant("get-repo")}); err != nil {
		t.Fatal(err)
	}
	alice, _ := json.Marshal(s.indexedToolsFor(pk("alice"), "campaign-a"))
	bob, _ := json.Marshal(s.indexedToolsFor(pk("bob"), "campaign-a"))
	if !strings.Contains(string(alice), "u__get-repo") || strings.Contains(string(alice), "create-repo") || strings.Contains(string(bob), "u__") {
		t.Fatalf("grant-filtered index: alice=%s bob=%s", alice, bob)
	}
}

func TestOperationGrantsPersistAndReload(t *testing.T) {
	var hit int32
	up := guardUpstream(t, []upTool{{name: "get-repo"}}, false, &hit)
	defer up.Close()
	dir := t.TempDir()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatal(err)
	}
	newServer := func() *Server {
		return NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)),
			WithAuditSigner(signer), WithHighAssuranceMultiUser(true), WithUpstreamClient(up.Client()))
	}
	s := newServer()
	if err := s.AddUpstream(context.Background(), "u", &gateway.Upstream{Name: "u", URL: up.URL, Client: up.Client()}, WithOwner(pk("alice"))); err != nil {
		t.Fatal(err)
	}
	s.persistRegistration("u", up.URL, false, authNone, pk("alice"))
	grant := readGrant("get-repo")
	grant.MaxRequests = 1
	if err := s.SetUpstreamGrants("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if err := s.persistGrantsStrict("u", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`)); out["isError"].(bool) {
		t.Fatalf("initial persisted grant call failed: %v", out)
	}

	restarted := newServer()
	restarted.ReloadUpstreams(context.Background())
	if got := restarted.UpstreamList(); len(got) != 1 || got[0].GrantCount != 1 || len(got[0].GrantDigests) != 1 {
		t.Fatalf("reloaded grant metadata = %+v", got)
	}
	out, _ := restarted.invokeUpstream(withCampaign("alice", "campaign-a"), "u__get-repo", json.RawMessage(`{"repo":"org/repo"}`))
	if !out["isError"].(bool) || atomic.LoadInt32(&hit) != 1 {
		t.Fatalf("reloaded grant budget was reset: out=%v hits=%d", out, atomic.LoadInt32(&hit))
	}
}

func TestAdminGrantRouteIsStrictAndPersists(t *testing.T) {
	s, _ := newGovernedTestServer(t, []upTool{{name: "get-repo"}}, nil, false)
	upstreams := s.UpstreamList()
	if len(upstreams) != 1 {
		t.Fatalf("upstreams = %+v", upstreams)
	}
	s.persistRegistration("u", upstreams[0].URL, false, authNone, pk("alice"))
	grant := readGrant("get-repo")
	body, err := json.Marshal(map[string]any{"grants": []OperationGrant{grant}})
	if err != nil {
		t.Fatal(err)
	}
	handler := s.AdminHandler(OperatorAuth{LegacyToken: "operator-token"})
	if rec := adminReq(t, handler, "POST", "/admin/upstreams/u/grants", "operator-token", string(body)); rec.Code != 200 {
		t.Fatalf("set grants: status=%d body=%s", rec.Code, rec.Body)
	}
	persisted, err := os.ReadFile(s.registrationsPath())
	if err != nil || !strings.Contains(string(persisted), `"id":"read-repo"`) {
		t.Fatalf("grant was not persisted: err=%v body=%s", err, persisted)
	}
	invalid := strings.Replace(string(body), `"required":true`, `"required":true,"unexpected":true`, 1)
	if rec := adminReq(t, handler, "POST", "/admin/upstreams/u/grants", "operator-token", invalid); rec.Code != 400 {
		t.Fatalf("nested unknown field accepted: status=%d body=%s", rec.Code, rec.Body)
	}
}
