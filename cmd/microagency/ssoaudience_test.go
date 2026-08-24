package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/auth"
	"microagency/internal/mcp"
)

// TestFederationRefusesAnUndeclaredAudience is the start gate. Federating to a
// provider says how people prove who they are; it does not say which of that
// provider's accounts belong on this gateway. Left unanswered on a shared
// provider, every account in the world at that provider becomes a principal.
func TestFederationRefusesAnUndeclaredAudience(t *testing.T) {
	base := httpConfig{addr: "127.0.0.1:8765", ssoIssuer: "https://accounts.google.com", ssoClientID: "gw"}
	err := validateFederationAudience(base, auth.AudienceSummary{})
	if err == nil {
		t.Fatal("federation with no declared audience started; it must refuse")
	}
	// The refusal has to be usable, which means naming every way out — not just
	// the one that happens to be listed first.
	for _, want := range []string{
		"--sso-any-account",
		"--sso-hd",
		"sso-audience allow group:",
		"sso-audience allow email:",
		"dedicated tenant",
		"https://accounts.google.com",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%s", want, err)
		}
	}
}

// Each way of declaring the audience is sufficient on its own.
func TestDeclaredAudiencesStart(t *testing.T) {
	base := httpConfig{addr: "127.0.0.1:8765", ssoIssuer: "https://idp.example", ssoClientID: "gw"}
	for _, tc := range []struct {
		name  string
		cfg   httpConfig
		rules auth.AudienceSummary
	}{
		{"dedicated tenant", withAnyAccount(base), auth.AudienceSummary{}},
		{"hosted domain", withHD(base, "corp.example"), auth.AudienceSummary{}},
		{"a group rule", base, auth.AudienceSummary{Groups: 1}},
		{"an identity rule", base, auth.AudienceSummary{Identities: 1}},
		{"domain and rules together", withHD(base, "corp.example"), auth.AudienceSummary{Groups: 1}},
	} {
		if err := validateFederationAudience(tc.cfg, tc.rules); err != nil {
			t.Errorf("%s should start: %v", tc.name, err)
		}
	}
	// Without federation there is no audience to declare.
	if err := validateFederationAudience(httpConfig{addr: "127.0.0.1:8765"}, auth.AudienceSummary{}); err != nil {
		t.Errorf("a non-federated start should be unaffected: %v", err)
	}
}

func withAnyAccount(cfg httpConfig) httpConfig { cfg.ssoAnyAccount = true; return cfg }
func withHD(cfg httpConfig, hd string) httpConfig {
	cfg.ssoHD = hd
	return cfg
}

func TestSSOAudienceFlagExclusivity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     httpConfig
		wantSub string
	}{
		{
			"any-account without federation",
			httpConfig{addr: "127.0.0.1:8765", ssoAnyAccount: true},
			"needs --sso-issuer",
		},
		{
			"groups-claim without federation",
			httpConfig{addr: "127.0.0.1:8765", ssoGroupsClaim: "roles"},
			"needs --sso-issuer",
		},
		{
			"any-account contradicts a hosted domain",
			httpConfig{addr: "127.0.0.1:8765", ssoIssuer: "https://idp.example", ssoAnyAccount: true, ssoHD: "corp.example"},
			"they disagree",
		},
	} {
		err := validateHTTPConfig(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: error = %v, want one containing %q", tc.name, err, tc.wantSub)
		}
	}
}

func TestParseUpOptionsAudienceFlags(t *testing.T) {
	o, err := parseUpOptions([]string{
		"--sso-issuer", "https://idp.example", "--sso-client-id", "gw",
		"--sso-any-account", "--sso-groups-claim", "roles",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !o.ssoAnyAccount || o.ssoGroupsClaim != "roles" {
		t.Fatalf("parsed options = %+v, want ssoAnyAccount and the named groups claim", o)
	}
}

func TestUpHelpExplainsAudienceDeclaration(t *testing.T) {
	var out strings.Builder
	upHelp(&out)
	for _, want := range []string{"--sso-any-account", "dedicated", "sso-audience", "--sso-groups-claim"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("up --help does not mention %q:\n%s", want, out.String())
		}
	}
}

// TestSSOAudienceCLIRoundTrip exercises the operator command. It edits the file
// directly, which is what makes a first federated start possible: the gateway
// refuses to run until the audience is declared, so a rule has to be addable
// while nothing is listening.
func TestSSOAudienceCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	rules := ssoAudienceRules("")
	if got := ssoAudienceRulesPath(""); got != filepath.Join(dir, ".microagency", auth.AudienceRulesFile) {
		t.Fatalf("rule path = %q, want it under the state directory", got)
	}

	var out strings.Builder
	if err := runSSOAudienceList(rules, nil, &out); err != nil {
		t.Fatal(err)
	}
	// The empty state must not be read as "nobody can sign in": a hosted domain
	// or a dedicated-tenant declaration may bound the audience instead.
	if !strings.Contains(out.String(), "No audience rules.") || !strings.Contains(out.String(), "--sso-hd") {
		t.Errorf("empty listing does not explain what empty means:\n%s", out.String())
	}

	out.Reset()
	if err := runSSOAudienceAllow(rules, []string{"group:Engineering", "--note", "platform team"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Allowed group:engineering") {
		t.Errorf("allow output = %q", out.String())
	}

	out.Reset()
	if err := runSSOAudienceAllow(rules, []string{"email:Person@Example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	// An email rule is only as good as the provider's verification, and that is
	// worth saying at the moment the operator adds one.
	if !strings.Contains(out.String(), "verified") {
		t.Errorf("allow output for an email rule should mention verification: %q", out.String())
	}

	out.Reset()
	if err := runSSOAudienceList(rules, nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"group", "engineering", "person@example.com", "platform team", "both must pass"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("listing is missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := runSSOAudienceRemove(rules, []string{"email:person@example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSSOAudienceRemove(rules, []string{"group:engineering"}, &out); err != nil {
		t.Fatal(err)
	}
	// Emptying the rule set can leave a running gateway admitting nobody. Say so
	// when it happens rather than leaving it for the next doctor run.
	if !strings.Contains(out.String(), "No audience rules remain") {
		t.Errorf("removing the last rule did not warn:\n%s", out.String())
	}
	if err := runSSOAudienceRemove(rules, []string{"group:engineering"}, &out); err == nil {
		t.Error("removing an absent rule should report that it was not there")
	}
}

func TestSSOAudienceCLIRejectsBadInput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rules := ssoAudienceRules("")
	var out strings.Builder
	for _, args := range [][]string{
		{"engineering"},             // no kind
		{"team:engineering"},        // unknown kind
		{"email:example.com"},       // a domain, not an address
		{"group:x", "--bogus", "y"}, // unknown flag
		{"group:x", "group:y"},      // two rules in one call
	} {
		if err := runSSOAudienceAllow(rules, args, &out); err == nil {
			t.Errorf("allow %v should have failed", args)
		}
	}
}

// TestSSOAudienceHelpDoesNotAct pins the safety-flag rule for the new command.
func TestSSOAudienceHelpDoesNotAct(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rules := ssoAudienceRules("")
	var out strings.Builder
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		if err := runSSOAudienceAllow(rules, args, &out); err != nil {
			t.Fatalf("allow %v: %v", args, err)
		}
		if err := runSSOAudienceRemove(rules, args, &out); err != nil {
			t.Fatalf("remove %v: %v", args, err)
		}
	}
	if got := rules.Summary().Total(); got != 0 {
		t.Errorf("help paths changed state: %d rules exist", got)
	}
}

// TestAdminAudienceAPI is the operator API surface, following the same shape as
// the connection-template routes it sits beside.
func TestAdminAudienceAPI(t *testing.T) {
	srv := testServer(t, "127.0.0.1:8766")
	h := srv.AdminHandler(mcp.OperatorAuth{LegacyToken: "op-tok"})

	adminDo := func(method, path, body string, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Audience rules are operator policy; an unauthenticated request never sees
	// them and never changes them.
	if rec := adminDo(http.MethodGet, "/admin/sso-audience", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list = %d, want 401", rec.Code)
	}
	if rec := adminDo(http.MethodPost, "/admin/sso-audience", `{"kind":"group","value":"x"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated add = %d, want 401", rec.Code)
	}

	rec := adminDo(http.MethodGet, "/admin/sso-audience", "", "op-tok")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q, want 200 []", rec.Code, rec.Body.String())
	}

	rec = adminDo(http.MethodPost, "/admin/sso-audience", `{"kind":"group","value":"Engineering","note":"platform"}`, "op-tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("add = %d: %s", rec.Code, rec.Body)
	}
	var stored auth.AudienceRule
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Kind != auth.AudienceGroup || stored.Value != "engineering" {
		t.Fatalf("stored rule = %+v, want a normalized group rule", stored)
	}
	if stored.Added.IsZero() {
		t.Error("the gateway must stamp the admission time")
	}

	if rec := adminDo(http.MethodPost, "/admin/sso-audience", `{"kind":"team","value":"x"}`, "op-tok"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown rule kind = %d, want 400", rec.Code)
	}

	// A rule added through the API is visible to the sign-in path immediately —
	// the same file, read through, with no restart in between.
	if got := srv.AudienceRules().Summary(); got.Groups != 1 {
		t.Fatalf("the running gateway does not see the new rule: %+v", got)
	}

	if rec := adminDo(http.MethodDelete, "/admin/sso-audience/group:engineering", "", "op-tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body)
	}
	if rec := adminDo(http.MethodDelete, "/admin/sso-audience/group:engineering", "", "op-tok"); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", rec.Code)
	}
	if got := srv.AudienceRules().Summary().Total(); got != 0 {
		t.Fatalf("rule survived deletion: %d remain", got)
	}
}

// TestStartupBannerStatesTheAudience: an operator reads the banner to confirm
// what they just started. "Who can sign in" is the fact most worth confirming,
// so it appears for every posture rather than only when a bound is configured.
func TestStartupBannerStatesTheAudience(t *testing.T) {
	dir := t.TempDir()
	base := httpConfig{addr: "127.0.0.1:8765", ssoIssuer: "https://idp.example", authDir: dir}

	for _, tc := range []struct {
		name string
		cfg  httpConfig
		want string
	}{
		{"dedicated tenant", withAnyAccount(base), "Admits         any account at https://idp.example"},
		{"hosted domain", withHD(base, "corp.example"), "Admits         accounts with hd=corp.example"},
	} {
		var out strings.Builder
		writeSSOPosture(&out, tc.cfg)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s banner missing %q:\n%s", tc.name, tc.want, out.String())
		}
	}

	// Rules bound the audience without naming anyone on a shared terminal.
	rules := auth.NewAudienceRules(auth.AudienceRulesPath(dir))
	if _, err := rules.Add(auth.AudienceRule{Kind: auth.AudienceGroup, Value: "engineering"}); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Add(auth.AudienceRule{Kind: auth.AudienceEmail, Value: "person@example.com"}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	writeSSOPosture(&out, base)
	if !strings.Contains(out.String(), "Admits         accounts matching 1 group + 1 identity") {
		t.Errorf("rule-bounded banner is wrong:\n%s", out.String())
	}
	if strings.Contains(out.String(), "person@example.com") {
		t.Errorf("the banner printed a rule value; it must count, not enumerate:\n%s", out.String())
	}

	// Both bounds together read as both applying, not as one replacing the other.
	out.Reset()
	writeSSOPosture(&out, withHD(base, "corp.example"))
	if !strings.Contains(out.String(), "accounts with hd=corp.example that also match") {
		t.Errorf("composed banner does not show both bounds:\n%s", out.String())
	}
}

// TestFederatedPostureLabelsAreUnique guards a collision that is easy to
// reintroduce. A tunnelled gateway already reports an "audience" — the OAuth
// protected-resource identifier clients must request — and federated sign-in
// reports who may sign in. Two adjacent lines sharing one label while meaning
// different things is worse than either wording alone, so the sign-in bound is
// labelled "admits" and the page is checked for duplicate labels.
func TestFederatedPostureLabelsAreUnique(t *testing.T) {
	b, err := json.Marshal(authPosture{
		Mode: "oauth-tunnel", Issuer: "https://gateway.example",
		Resource: "https://gateway.example/mcp", Audience: "https://gateway.example/mcp",
		Tunnel: "cloudflare", TunnelMode: "named", TunnelName: "gw",
		SSOIssuer: "https://idp.example", SSOHostedDomain: "corp.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{Groups: 1})

	seen := map[string]int{}
	for _, line := range strings.Split(out.String(), "\n") {
		// Indented label lines carry a label column then the value; a
		// continuation line is blank in that column.
		trimmed := strings.TrimLeft(line, " ")
		if line == trimmed || trimmed == "" {
			continue
		}
		fields := strings.SplitN(trimmed, "  ", 2)
		if len(fields) != 2 || strings.TrimSpace(fields[1]) == "" {
			continue
		}
		seen[strings.TrimSpace(fields[0])]++
	}
	for label, n := range seen {
		if n > 1 {
			t.Errorf("label %q renders %d times on one page; two meanings under one label is unreadable:\n%s", label, n, out.String())
		}
	}
	// The two facts that previously collided must both still be present.
	for _, want := range []string{"audience        https://gateway.example/mcp", "admits          accounts with hd=corp.example"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("page is missing %q:\n%s", want, out.String())
		}
	}
}
