package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/gateway"
)

// twinFixture stands up connections that are identical by construction: the same
// template, the same upstream, and therefore the same tool with the same schema.
// This is what a template with max_per_user above one produces — one project for
// production, one for staging — and the state the disambiguation gate exists for.
func twinFixture(t *testing.T, template string, names ...string) *Server {
	t.Helper()
	up := cannedUpstream(t)
	t.Cleanup(up.Close)
	s := newTestServer(t, fakeRunner{})
	for _, name := range names {
		err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: up.URL},
			WithOwner(pk("alice")), WithSelfService(template))
		if err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	return s
}

// callAs invokes one namespaced tool as sub and returns the result, plus the
// refusal text when the result is an error (empty otherwise).
func callAs(t *testing.T, s *Server, sub, tool string) (map[string]any, string) {
	t.Helper()
	out, ok := s.invokeUpstream(withPrincipal(sub), tool, json.RawMessage(`{"q":"x"}`))
	if !ok {
		t.Fatalf("invokeUpstream did not handle %q", tool)
	}
	if isErr, _ := out["isError"].(bool); !isErr {
		return out, ""
	}
	return out, errText(t, out)
}

// Two connections from one template, neither labelled, are indistinguishable to
// the caller: the call is refused rather than run against a coin-flip upstream,
// and the refusal names both siblings so the caller can act on it.
func TestAmbiguousSameTemplateCallIsRefused(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")

	out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search")
	if out["isError"] != true {
		t.Fatalf("an indistinguishable call must be refused, not guessed: %v", out)
	}
	for _, want := range []string{"ambiguous", "supabase-aaaa1111", "supabase-bbbb2222", "supabase", "search", "label"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("refusal must mention %q: %q", want, txt)
		}
	}
	// The sibling is refused the same way — neither is the "right" one to guess.
	if out, _ := callAs(t, s, "alice", "supabase-bbbb2222__search"); out["isError"] != true {
		t.Fatalf("both siblings must be refused, not just one: %v", out)
	}
}

// Distinct labels are the remedy the refusal names, so they must actually lift it.
func TestDistinctLabelsResolveAmbiguity(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "production"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpstreamLabel("supabase-bbbb2222", "staging"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"supabase-aaaa1111__search", "supabase-bbbb2222__search"} {
		out, txt := callAs(t, s, "alice", name)
		if isErr, _ := out["isError"].(bool); isErr {
			t.Fatalf("a labelled connection must be callable: %s -> %q", name, txt)
		}
	}
}

// A label only disambiguates the connection that carries it. Labelling one of two
// siblings makes THAT one a deliberate choice; the unlabelled one is still a
// guess, so it stays refused.
func TestOneSidedLabelResolvesOnlyTheLabelledConnection(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "production"); err != nil {
		t.Fatal(err)
	}
	if out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search"); out["isError"] == true {
		t.Fatalf("the labelled connection is a deliberate choice and must run: %q", txt)
	}
	out, txt := callAs(t, s, "alice", "supabase-bbbb2222__search")
	if out["isError"] != true {
		t.Fatalf("the unlabelled sibling is still a guess and must be refused: %v", out)
	}
	if !strings.Contains(txt, "carries no label") {
		t.Fatalf("refusal must say this connection has no label: %q", txt)
	}
}

// Labels that differ only by case are two spellings of one word. They do not tell
// two connections apart for a reader, so they do not lift the refusal either.
func TestLabelsThatMatchDoNotDisambiguate(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "prod"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpstreamLabel("supabase-bbbb2222", "PROD"); err != nil {
		t.Fatal(err)
	}
	out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search")
	if out["isError"] != true {
		t.Fatalf("labels that read the same must not disambiguate: %v", out)
	}
	if !strings.Contains(txt, `labelled "prod"`) {
		t.Fatalf("refusal must say the labels collide: %q", txt)
	}
}

// The ordinary case: one connection from a template is never ambiguous.
func TestSingleConnectionIsNeverAmbiguous(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111")
	if out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search"); out["isError"] == true {
		t.Fatalf("a lone connection must be callable: %q", txt)
	}
}

// Two connections from DIFFERENT templates are not twins. Their descriptions and
// schemas differ, so the ranker and the agent can tell them apart, and refusing
// them would be a false gate on the ordinary multi-provider case.
func TestCrossProviderCollisionIsNotRefused(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	s := newTestServer(t, fakeRunner{})
	for _, c := range []struct{ name, template string }{
		{"supabase-aaaa1111", "supabase"},
		{"postgres-bbbb2222", "postgres"},
	} {
		err := s.AddUpstream(context.Background(), c.name, &gateway.Upstream{Name: c.name, URL: up.URL},
			WithOwner(pk("alice")), WithSelfService(c.template))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"supabase-aaaa1111__search", "postgres-bbbb2222__search"} {
		if out, txt := callAs(t, s, "alice", name); out["isError"] == true {
			t.Fatalf("different templates are distinguishable and must not be refused: %s -> %q", name, txt)
		}
	}
	// Neither is marked at discovery time either.
	indexed, _ := json.Marshal(s.indexedTools(pk("alice")))
	if strings.Contains(string(indexed), "ambiguous") {
		t.Fatalf("cross-provider tools must not be marked ambiguous: %s", indexed)
	}
}

// Operator-registered connections carry no template. They have operator-chosen
// names and are not the accidental twins this gate exists for.
func TestOperatorRegisteredConnectionsAreNotTwins(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	s := newTestServer(t, fakeRunner{})
	for _, name := range []string{"docs-a", "docs-b"} {
		if err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: up.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if out, txt := callAs(t, s, "alice", "docs-a__search"); out["isError"] == true {
		t.Fatalf("operator-registered connections must not be refused: %q", txt)
	}
}

// A sibling nobody can invoke is not an alternative the caller might have meant.
// Disabling one twin makes the other unambiguous, so the gate stays narrow.
func TestDisabledSiblingDoesNotMakeACallAmbiguous(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")
	if err := s.DisableUpstream("supabase-bbbb2222"); err != nil {
		t.Fatal(err)
	}
	if out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search"); out["isError"] == true {
		t.Fatalf("a disabled sibling is not a real alternative: %q", txt)
	}
}

// Another principal's connection is not visible to this caller, so it cannot make
// this caller's call ambiguous — and naming it would be a disclosure oracle.
func TestOtherPrincipalsTwinIsNotASibling(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	s := newTestServer(t, fakeRunner{})
	for _, c := range []struct{ name, owner string }{
		{"supabase-aaaa1111", "alice"},
		{"supabase-bbbb2222", "bob"},
	} {
		err := s.AddUpstream(context.Background(), c.name, &gateway.Upstream{Name: c.name, URL: up.URL},
			WithOwner(pk(c.owner)), WithSelfService("supabase"))
		if err != nil {
			t.Fatal(err)
		}
	}
	out, txt := callAs(t, s, "alice", "supabase-aaaa1111__search")
	if out["isError"] == true {
		t.Fatalf("another principal's connection must not make this call ambiguous: %q", txt)
	}
	if strings.Contains(txt, "supabase-bbbb2222") {
		t.Fatalf("a refusal must never name a connection this caller cannot see: %q", txt)
	}
}

// find_tools marks tied candidates so the agent learns about the tie at discovery
// time, and stops marking them once labels tell them apart.
func TestFindToolsMarksAndUnmarksTiedCandidates(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111", "supabase-bbbb2222")

	var found struct {
		Tools []map[string]any `json:"tools"`
		Note  string           `json:"note"`
	}
	discover := func() {
		t.Helper()
		out := s.findTools(withPrincipal("alice"), json.RawMessage(`{"query":"search"}`))
		found.Tools, found.Note = nil, ""
		if err := json.Unmarshal([]byte(out["content"].([]map[string]any)[0]["text"].(string)), &found); err != nil {
			t.Fatal(err)
		}
	}
	discover()
	if len(found.Tools) != 2 {
		t.Fatalf("expected both twins in the index; got %d", len(found.Tools))
	}
	for _, tool := range found.Tools {
		if tool["ambiguous"] != true {
			t.Fatalf("a tied candidate must be marked at discovery time: %v", tool)
		}
	}
	if !strings.Contains(found.Note, "ambiguous") || !strings.Contains(found.Note, "label") {
		t.Fatalf("note must explain the tie and the remedy: %q", found.Note)
	}

	if err := s.SetUpstreamLabel("supabase-aaaa1111", "production"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpstreamLabel("supabase-bbbb2222", "staging"); err != nil {
		t.Fatal(err)
	}
	discover()
	labels := map[string]bool{}
	for _, tool := range found.Tools {
		if _, marked := tool["ambiguous"]; marked {
			t.Fatalf("labelled candidates must no longer be marked ambiguous: %v", tool)
		}
		label, _ := tool["label"].(string)
		labels[label] = true
	}
	if !labels["production"] || !labels["staging"] {
		t.Fatalf("each label must reach the agent's view of its tools: %v", labels)
	}
	if strings.Contains(found.Note, "ambiguous") {
		t.Fatalf("the tie note must clear once labels resolve it: %q", found.Note)
	}
}

// The label is its own field in the tool view. It must never be folded into the
// description, where it could terminate or extend prose the model reads.
func TestLabelIsAStructuredFieldNotDescriptionProse(t *testing.T) {
	s := twinFixture(t, "supabase", "supabase-aaaa1111")
	if err := s.SetUpstreamLabel("supabase-aaaa1111", "production"); err != nil {
		t.Fatal(err)
	}
	indexed := s.indexedTools(pk("alice"))
	if len(indexed) != 1 {
		t.Fatalf("expected one indexed tool; got %d", len(indexed))
	}
	if indexed[0]["label"] != "production" {
		t.Fatalf("label must be its own field: %v", indexed[0])
	}
	if desc := indexed[0]["description"].(string); strings.Contains(desc, "production") {
		t.Fatalf("label must never be concatenated into the description: %q", desc)
	}
}

// A call authorized by an operation grant is not a guess: the operator named the
// connection exactly, so the ambiguity gate does not apply.
func TestMatchingGrantExemptsAnOtherwiseAmbiguousCall(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)), WithAuditSigner(signer))
	for _, name := range []string{"supabase-aaaa1111", "supabase-bbbb2222"} {
		err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: up.URL},
			WithOwner(pk("alice")), WithSelfService("supabase"))
		if err != nil {
			t.Fatal(err)
		}
	}
	grant := OperationGrant{
		Version: grantVersion, ID: "read-one", Connection: "supabase-aaaa1111", Tool: "search", Effect: effectRead,
		Principal: pk("alice"), Campaign: "campaign-a", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Arguments:   []ArgumentGrant{{Pointer: "/q", Required: true, Values: []string{"x"}}},
		Resources:   []ResourceGrant{{Kind: "corpus", Namespace: "supabase", Argument: "/q"}},
		MaxRequests: 4, MaxBytes: 8192, MaxResponseBytes: 4096,
		Rate: RateGrant{Requests: 4, WindowS: 60}, HighAssurance: true,
	}
	if err := s.SetUpstreamGrants("supabase-aaaa1111", []OperationGrant{grant}); err != nil {
		t.Fatalf("set grants: %v", err)
	}
	out, ok := s.invokeUpstream(withCampaign("alice", "campaign-a"), "supabase-aaaa1111__search", json.RawMessage(`{"q":"x"}`))
	if !ok {
		t.Fatal("invokeUpstream did not handle the granted call")
	}
	if out["isError"] == true {
		t.Fatalf("a call under a matching grant names its connection exactly and must run: %v", out)
	}
}

// An ungranted caller on a governed connection gets the governed denial, which
// must stay opaque. The ambiguity refusal names sibling connections, so it must
// never be what an ungranted caller sees.
func TestGovernedDenialNeverLeaksSiblingsToAnUngrantedCaller(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)), WithAuditSigner(signer))
	for _, name := range []string{"supabase-aaaa1111", "supabase-bbbb2222"} {
		err := s.AddUpstream(context.Background(), name, &gateway.Upstream{Name: name, URL: up.URL},
			WithOwner(pk("alice")), WithSelfService("supabase"))
		if err != nil {
			t.Fatal(err)
		}
	}
	grant := OperationGrant{
		Version: grantVersion, ID: "read-one", Connection: "supabase-aaaa1111", Tool: "search", Effect: effectRead,
		Principal: pk("alice"), Campaign: "campaign-a", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Arguments:   []ArgumentGrant{{Pointer: "/q", Required: true, Values: []string{"x"}}},
		Resources:   []ResourceGrant{{Kind: "corpus", Namespace: "supabase", Argument: "/q"}},
		MaxRequests: 4, MaxBytes: 8192, MaxResponseBytes: 4096,
		Rate: RateGrant{Requests: 4, WindowS: 60}, HighAssurance: true,
	}
	if err := s.SetUpstreamGrants("supabase-aaaa1111", []OperationGrant{grant}); err != nil {
		t.Fatal(err)
	}
	// Same principal, WRONG campaign: no grant matches.
	out, _ := s.invokeUpstream(withCampaign("alice", "campaign-b"), "supabase-aaaa1111__search", json.RawMessage(`{"q":"x"}`))
	txt := errText(t, out)
	if out["isError"] != true || !strings.Contains(txt, "not authorized") {
		t.Fatalf("an ungranted governed call must get the governed denial: %q", txt)
	}
	if strings.Contains(txt, "supabase-bbbb2222") || strings.Contains(txt, "ambiguous") {
		t.Fatalf("the governed denial must not disclose siblings: %q", txt)
	}
}

// A label on a SHARED connection reaches every admitted caller's context, so it
// is set on the operator surface. The charset rules are the same ones the
// self-service surface enforces — there is one definition of a safe label.
func TestAdminSetsLabelOnASharedConnection(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)))
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: up.URL}); err != nil {
		t.Fatal(err)
	}
	admin := s.AdminHandler(OperatorAuth{LegacyToken: "operator"})

	if rec := adminReq(t, admin, "POST", "/admin/upstreams/docs/label", "operator", `{"label":"corporate wiki"}`); rec.Code != 200 {
		t.Fatalf("set label = %d %s", rec.Code, rec.Body.String())
	}
	labelOf := func(name string) string {
		t.Helper()
		for _, info := range s.UpstreamList() {
			if info.Name == name {
				return info.Label
			}
		}
		t.Fatalf("no connection %q", name)
		return ""
	}
	if got := labelOf("docs"); got != "corporate wiki" {
		t.Fatalf("label not stored: %q", got)
	}
	// Every caller of a shared connection sees the label beside its tools.
	for _, subject := range []string{"alice", "bob"} {
		view, _ := json.Marshal(s.indexedTools(pk(subject)))
		if !strings.Contains(string(view), `"label":"corporate wiki"`) {
			t.Fatalf("shared label missing for %s: %s", subject, view)
		}
	}
	for _, bad := range []string{`{"label":"wiki\nprod"}`, `{"label":"wiki\u200bprod"}`, `{"label":"` + strings.Repeat("x", 33) + `"}`} {
		if rec := adminReq(t, admin, "POST", "/admin/upstreams/docs/label", "operator", bad); rec.Code != 400 {
			t.Fatalf("body %s must be refused with 400; got %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	if got := labelOf("docs"); got != "corporate wiki" {
		t.Fatalf("a refused label must leave the stored one intact: %q", got)
	}
	if rec := adminReq(t, admin, "POST", "/admin/upstreams/nope/label", "operator", `{"label":"x"}`); rec.Code != 404 {
		t.Fatalf("labelling an unknown connection = %d", rec.Code)
	}
	if rec := adminReq(t, admin, "POST", "/admin/upstreams/docs/label", "", `{"label":"x"}`); rec.Code == 200 {
		t.Fatal("labelling must require the operator token")
	}
}

// A label is the thing an agent is told to choose by, so losing it on restart
// would silently put two connections back into a tie.
func TestLabelSurvivesRestart(t *testing.T) {
	up := cannedUpstream(t)
	defer up.Close()
	dir := t.TempDir()
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)), WithUpstreamClient(up.Client()))
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: up.URL, Client: up.Client()}); err != nil {
		t.Fatal(err)
	}
	s.persistRegistration("docs", up.URL, false, authNone, "")
	if err := s.SetUpstreamLabel("docs", "corporate wiki"); err != nil {
		t.Fatal(err)
	}
	s.persistLabel("docs", "corporate wiki")

	restarted := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(openTestSecretStore(t, dir)), WithUpstreamClient(up.Client()))
	restarted.ReloadUpstreams(context.Background())
	found := false
	for _, info := range restarted.UpstreamList() {
		if info.Name == "docs" {
			found = true
			if info.Label != "corporate wiki" {
				t.Fatalf("label did not survive restart: %q", info.Label)
			}
		}
	}
	if !found {
		t.Fatal("connection did not reload")
	}
}
