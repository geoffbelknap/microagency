package auth

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAudienceRule(t *testing.T) {
	for _, tc := range []struct {
		spec       string
		wantKind   string
		wantValue  string
		wantErrSub string
	}{
		{spec: "group:Engineering", wantKind: AudienceGroup, wantValue: "engineering"},
		{spec: "email:Alpha@Corp.Example", wantKind: AudienceEmail, wantValue: "alpha@corp.example"},
		{spec: "subject:User-Alpha", wantKind: AudienceSubject, wantValue: "User-Alpha"},
		{spec: "engineering", wantErrSub: "kind:value"},
		{spec: "team:engineering", wantErrSub: "unknown audience rule kind"},
		{spec: "email:corp.example", wantErrSub: "--sso-hd"},
		{spec: "email:@corp.example", wantErrSub: "--sso-hd"},
		{spec: "group:", wantErrSub: "needs a value"},
	} {
		rule, err := ParseAudienceRule(tc.spec)
		if tc.wantErrSub != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("ParseAudienceRule(%q) error = %v, want one containing %q", tc.spec, err, tc.wantErrSub)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAudienceRule(%q) = %v", tc.spec, err)
			continue
		}
		if rule.Kind != tc.wantKind || rule.Value != tc.wantValue {
			t.Errorf("ParseAudienceRule(%q) = %s:%s, want %s:%s", tc.spec, rule.Kind, rule.Value, tc.wantKind, tc.wantValue)
		}
	}
}

// TestAudienceRulesPersistAndReadThrough asserts the property the whole design
// leans on: every read goes to the file, so a rule written by one holder of the
// path is visible to another with no restart and no cache to invalidate. The
// admin API and an offline edit are exactly two such holders.
func TestAudienceRulesPersistAndReadThrough(t *testing.T) {
	dir := t.TempDir()
	writer := NewAudienceRules(AudienceRulesPath(dir))
	reader := NewAudienceRules(AudienceRulesPath(dir))

	if got := reader.Summary().Total(); got != 0 {
		t.Fatalf("fresh rule set has %d rules, want 0", got)
	}
	if _, err := writer.Add(AudienceRule{Kind: AudienceGroup, Value: "engineering"}); err != nil {
		t.Fatal(err)
	}
	if got := reader.Summary(); got.Groups != 1 || got.Identities != 0 {
		t.Fatalf("after add, reader summary = %+v, want 1 group", got)
	}

	info, err := os.Stat(AudienceRulesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("rule file mode = %o, want 600", perm)
	}

	removed, err := writer.Remove("group:Engineering") // id parsing normalizes
	if err != nil || !removed {
		t.Fatalf("Remove = %v, %v; want true, nil", removed, err)
	}
	if got := reader.Summary().Total(); got != 0 {
		t.Errorf("after remove, reader sees %d rules, want 0", got)
	}
	removed, err = writer.Remove("group:engineering")
	if err != nil || removed {
		t.Errorf("second Remove = %v, %v; want false, nil (idempotent)", removed, err)
	}
}

func TestAudienceRulesAddIsIdempotentAndKeepsAdmissionTime(t *testing.T) {
	rules := NewAudienceRules(AudienceRulesPath(t.TempDir()))
	first, err := rules.Add(AudienceRule{Kind: AudienceEmail, Value: "alpha@corp.example", Note: "first"})
	if err != nil {
		t.Fatal(err)
	}
	first.Added = first.Added.Add(-time.Hour) // prove the stored value is reused, not the supplied one
	second, err := rules.Add(AudienceRule{Kind: AudienceEmail, Value: "ALPHA@corp.example", Note: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if got := rules.Summary().Total(); got != 1 {
		t.Errorf("re-adding the same identity produced %d rules, want 1", got)
	}
	if second.Note != "second" {
		t.Errorf("note = %q, want the updated %q", second.Note, "second")
	}
	if second.Added.Equal(first.Added) {
		t.Error("re-add reset the admission time to the caller's value; it must keep the original")
	}
}

// TestAudienceRulesDropUnusableRecords asserts that a record which could never
// match is not counted as a bound. A malformed rule sitting in the file looking
// like protection, while the audience is actually unbounded, is the failure
// this guards.
func TestAudienceRulesDropUnusableRecords(t *testing.T) {
	dir := t.TempDir()
	path := AudienceRulesPath(dir)
	body := `[{"kind":"group","value":"engineering"},{"kind":"team","value":"ops"},{"kind":"email","value":"corp.example"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := NewAudienceRules(path)
	got, err := rules.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID() != "group:engineering" {
		t.Fatalf("List() = %+v, want only group:engineering", got)
	}
}

func TestAudienceRulePredicates(t *testing.T) {
	rules := NewAudienceRules(AudienceRulesPath(t.TempDir()))
	for _, spec := range []string{"group:engineering", "email:alpha@corp.example", "subject:user-gamma"} {
		rule, err := ParseAudienceRule(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rules.Add(rule); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		id   *FederatedIdentity
		want bool
	}{
		{"verified email matches", &FederatedIdentity{Subject: "s1", Email: "alpha@corp.example"}, true},
		{"email match is case-insensitive", &FederatedIdentity{Subject: "s1", Email: "ALPHA@CORP.EXAMPLE"}, true},
		{"subject matches", &FederatedIdentity{Subject: "user-gamma"}, true},
		{"group matches", &FederatedIdentity{Subject: "s2", Groups: []string{"sales", "Engineering"}}, true},
		{"nothing matches", &FederatedIdentity{Subject: "s3", Email: "beta@corp.example"}, false},
		{"empty identity matches nothing", &FederatedIdentity{}, false},
		{"nil identity matches nothing", nil, false},
	} {
		if got := rules.Permits(tc.id); got != tc.want {
			t.Errorf("%s: Permits = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestUnverifiedEmailCannotMatchAnEmailRule pins the fail-closed edge: an email
// rule names a person, and a provider that has not verified the address has not
// established that the signer is that person.
func TestUnverifiedEmailCannotMatchAnEmailRule(t *testing.T) {
	rules := NewAudienceRules(AudienceRulesPath(t.TempDir()))
	if _, err := rules.Add(AudienceRule{Kind: AudienceEmail, Value: "alpha@corp.example"}); err != nil {
		t.Fatal(err)
	}
	// validateIDToken leaves Email empty unless email_verified was true, so an
	// unverified sign-in reaches the rule set with no address to match.
	if rules.Permits(&FederatedIdentity{Subject: "user-alpha", Email: ""}) {
		t.Error("an identity with no verified email matched an email rule")
	}
}

func TestInertAudienceRules(t *testing.T) {
	if got := InertAudienceRules(true, AudienceSummary{Groups: 2}); got != "2 groups" {
		t.Errorf("InertAudienceRules = %q, want the inert rules named", got)
	}
	if got := InertAudienceRules(false, AudienceSummary{Groups: 2}); got != "" {
		t.Errorf("rules that DO apply were reported inert: %q", got)
	}
	if got := InertAudienceRules(true, AudienceSummary{}); got != "" {
		t.Errorf("no rules configured, yet reported inert: %q", got)
	}
}

func TestDescribeAudience(t *testing.T) {
	const issuer = "https://okta.example.com"
	for _, tc := range []struct {
		name       string
		hd         string
		anyAccount bool
		rules      AudienceSummary
		want       string
	}{
		{"dedicated tenant", "", true, AudienceSummary{}, "any account at " + issuer},
		{"hosted domain", "corp.example", false, AudienceSummary{}, "accounts with hd=corp.example"},
		{"rules only", "", false, AudienceSummary{Groups: 2, Identities: 1}, "accounts matching 2 groups + 1 identity"},
		{"both", "corp.example", false, AudienceSummary{Groups: 1}, "accounts with hd=corp.example that also match 1 group"},
		{"undeclared", "", false, AudienceSummary{}, "UNDECLARED — no account can sign in"},
	} {
		if got := DescribeAudience(issuer, tc.hd, tc.anyAccount, tc.rules); got != tc.want {
			t.Errorf("%s: DescribeAudience = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestFederationPermitsComposesBounds asserts the composition contract: a
// hosted domain and a rule set may both be configured, and then both must pass.
// The hosted domain is enforced earlier in validateIDToken, so what is checked
// here is that a configured rule set does not stop applying just because a
// domain is also required.
func TestFederationPermitsComposesBounds(t *testing.T) {
	inDomain := &FederatedIdentity{Subject: "user-alpha", Email: "alpha@corp.example", HostedDomain: "corp.example"}
	outsideRules := &FederatedIdentity{Subject: "user-beta", Email: "beta@corp.example", HostedDomain: "corp.example"}
	rules := NewAudienceRules(AudienceRulesPath(t.TempDir()))
	if _, err := rules.Add(AudienceRule{Kind: AudienceEmail, Value: "alpha@corp.example"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name              string
		cfg               FederationConfig
		wantIn, wantOther bool
	}{
		{"domain only admits both", FederationConfig{HostedDomain: "corp.example"}, true, true},
		{"rules only admit the named one", FederationConfig{Audience: rules}, true, false},
		{"domain and rules both apply", FederationConfig{HostedDomain: "corp.example", Audience: rules}, true, false},
		{"any-account overrides both", FederationConfig{HostedDomain: "corp.example", Audience: rules, AnyAccount: true}, true, true},
		{"nothing declared admits nobody", FederationConfig{}, false, false},
	} {
		f := &Federation{cfg: tc.cfg}
		if got := f.Permits(inDomain); got != tc.wantIn {
			t.Errorf("%s: Permits(named) = %v, want %v", tc.name, got, tc.wantIn)
		}
		if got := f.Permits(outsideRules); got != tc.wantOther {
			t.Errorf("%s: Permits(unnamed) = %v, want %v", tc.name, got, tc.wantOther)
		}
	}
}

// TestFederatedGroupRuleAdmitsAndRefuses drives the whole browser round-trip
// twice against one provider: a member of the permitted group signs in, and a
// non-member is refused. The refusal must happen at the door — the response is
// the notice page, not a redirect carrying an authorization code.
func TestFederatedGroupRuleAdmitsAndRefuses(t *testing.T) {
	rules := testAudienceRules(t, AudienceRule{Kind: AudienceGroup, Value: "engineering"})
	ts, _, provider, c := newFederatedASWith(t, FederationConfig{Audience: rules})
	clientID := registerClient(t, ts, c)
	verifier := randToken(32)

	provider.setUser("user-alpha", "alpha@personal.example", true, "")
	provider.setGroups("engineering", "everyone")
	resp := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("group member callback = %d, want 302 back to the MCP client", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("group member got no authorization code: %s", resp.Header.Get("Location"))
	}

	provider.setUser("user-beta", "beta@personal.example", true, "")
	provider.setGroups("everyone")
	refused := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = refused.Body.Close() }()
	assertRefusedAtTheDoor(t, refused)
}

// TestFederatedIdentityRuleRefusesUnlistedAccount is the no-directory case: two
// people on a shared consumer provider, one named and one not. The unnamed one
// authenticates perfectly well at the provider and still must not become a
// principal.
func TestFederatedIdentityRuleRefusesUnlistedAccount(t *testing.T) {
	rules := testAudienceRules(t, AudienceRule{Kind: AudienceEmail, Value: "alpha@personal.example"})
	ts, as, provider, c := newFederatedASWith(t, FederationConfig{Audience: rules})
	clientID := registerClient(t, ts, c)
	verifier := randToken(32)

	provider.setUser("user-beta", "beta@personal.example", true, "")
	refused := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = refused.Body.Close() }()
	assertRefusedAtTheDoor(t, refused)

	// A refused sign-in leaves no trace of the account as a known identity: it
	// never became a principal, so it must not appear in the identity table.
	if email := as.FederatedEmail("user-beta"); email != "" {
		t.Errorf("refused account was recorded as a federated identity (email %q)", email)
	}

	provider.setUser("user-alpha", "alpha@personal.example", true, "")
	admitted := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = admitted.Body.Close() }()
	if admitted.StatusCode != http.StatusFound {
		t.Fatalf("named account callback = %d, want 302 back to the MCP client", admitted.StatusCode)
	}
	if as.FederatedEmail("user-alpha") != "alpha@personal.example" {
		t.Errorf("admitted account was not recorded: %q", as.FederatedEmail("user-alpha"))
	}
}

// TestFederatedAudienceComposesWithHostedDomain drives the composed posture end
// to end: the right domain is not enough on its own once rules are configured.
func TestFederatedAudienceComposesWithHostedDomain(t *testing.T) {
	rules := testAudienceRules(t, AudienceRule{Kind: AudienceSubject, Value: "user-alpha"})
	ts, _, provider, c := newFederatedASWith(t, FederationConfig{HostedDomain: "corp.example", Audience: rules})
	clientID := registerClient(t, ts, c)
	verifier := randToken(32)

	// In the domain, but not named by a rule.
	provider.setUser("user-beta", "beta@corp.example", true, "corp.example")
	refused := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = refused.Body.Close() }()
	assertRefusedAtTheDoor(t, refused)

	// Named by a rule, but outside the domain: the domain refusal fires first,
	// and it is a different message because it names a different remedy.
	provider.setUser("user-alpha", "alpha@other.example", true, "other.example")
	wrongDomain := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = wrongDomain.Body.Close() }()
	body := readBody(t, wrongDomain)
	if !strings.Contains(body, "not in the required domain") {
		t.Errorf("out-of-domain sign-in did not get the hosted-domain refusal:\n%s", body)
	}

	// Both bounds satisfied.
	provider.setUser("user-alpha", "alpha@corp.example", true, "corp.example")
	admitted := federatedSignIn(t, ts, c, clientID, pkceS256(verifier))
	defer func() { _ = admitted.Body.Close() }()
	if admitted.StatusCode != http.StatusFound {
		t.Fatalf("in-domain named account = %d, want 302 back to the MCP client", admitted.StatusCode)
	}
}

// TestFederatedUndeclaredAudienceAdmitsNobody is the second line of the same
// defence as the startup refusal: if a federation somehow reaches serving with
// no audience declared, it admits nobody rather than everybody.
func TestFederatedUndeclaredAudienceAdmitsNobody(t *testing.T) {
	ts, _, provider, c := newFederatedASWith(t, FederationConfig{})
	clientID := registerClient(t, ts, c)
	provider.setUser("user-alpha", "alpha@corp.example", true, "corp.example")
	refused := federatedSignIn(t, ts, c, clientID, pkceS256(randToken(32)))
	defer func() { _ = refused.Body.Close() }()
	assertRefusedAtTheDoor(t, refused)
}

func TestErrIdentityNotPermittedIsDistinctFromHostedDomain(t *testing.T) {
	if errors.Is(ErrIdentityNotPermitted, ErrHostedDomainRefused) {
		t.Error("the audience refusal and the hosted-domain refusal must stay distinguishable")
	}
}

// assertRefusedAtTheDoor asserts that a sign-in ended on the notice page with no
// authorization code — the caller never became a principal.
func assertRefusedAtTheDoor(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refused sign-in = %d, want the 200 notice page", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("refused sign-in redirected to %q; it must not hand back a code", loc)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "not one this gateway admits") {
		t.Errorf("refusal page did not carry the audience message:\n%s", body)
	}
	if !strings.Contains(body, "operator") {
		t.Errorf("refusal page does not name who can fix it:\n%s", body)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAudienceRulesPathEmptyStateDir(t *testing.T) {
	if got := AudienceRulesPath(""); got != "" {
		t.Errorf("AudienceRulesPath(\"\") = %q, want empty", got)
	}
	if got := AudienceRulesPath("/state"); got != filepath.Join("/state", AudienceRulesFile) {
		t.Errorf("AudienceRulesPath = %q", got)
	}
	// A rule set with no path is inert rather than a nil-pointer hazard.
	var nilRules *AudienceRules
	if nilRules.Summary().Total() != 0 || nilRules.Permits(&FederatedIdentity{Subject: "x"}) {
		t.Error("a nil rule set must be empty and permit nobody")
	}
	if _, err := nilRules.Add(AudienceRule{Kind: AudienceGroup, Value: "x"}); err == nil {
		t.Error("adding to a rule set with no file should fail rather than silently vanish")
	}
}
