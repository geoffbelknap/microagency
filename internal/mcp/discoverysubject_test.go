package mcp

import (
	"context"
	"strings"
	"testing"

	"microagency/internal/auth"
)

func discoverySource(t *testing.T, provider *delegationProvider, subject string) *auth.DelegatedTokenSource {
	t.Helper()
	saKey := provider.registerKey(t, "delegate@project.example")
	src, err := buildDelegatedSource(DelegationSummary{
		ClientEmail:      "delegate@project.example",
		TokenEndpoint:    provider.ts.URL,
		Scopes:           []string{"https://provider.example/auth/data.readonly"},
		DiscoverySubject: subject,
	}, []byte(saKey))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// A wiring call carries no caller. With a discovery subject declared it must
// authenticate as that subject, so an upstream that authenticates tools/list
// can be registered at all.
func TestWiringCallActsAsDiscoverySubject(t *testing.T) {
	provider := newDelegationProvider(t)
	src := discoverySource(t, provider, "operator@example.com")

	token, err := delegatedBearer(src, src.DiscoverySubject())(context.Background())
	if err != nil {
		t.Fatalf("wiring call failed to derive a discovery token: %v", err)
	}
	if token == "" {
		t.Fatal("wiring call produced no token despite a declared discovery subject")
	}
	if got := provider.seenSubjects(); len(got) != 1 || got[0] != "operator@example.com" {
		t.Fatalf("provider saw subjects %v, want [operator@example.com]", got)
	}
}

// Without a declared subject the previous behavior stands: unauthenticated
// rather than acting as anyone.
func TestWiringCallWithoutDiscoverySubjectStaysUnauthenticated(t *testing.T) {
	provider := newDelegationProvider(t)
	src := discoverySource(t, provider, "")

	token, err := delegatedBearer(src, src.DiscoverySubject())(context.Background())
	if err != nil {
		t.Fatalf("wiring call errored instead of going unauthenticated: %v", err)
	}
	if token != "" {
		t.Fatalf("wiring call produced token %q with no discovery subject declared", token)
	}
}

// The load-bearing invariant: a real caller is served its OWN subject, never
// the discovery one. invokeUpstream refuses a caller with no verified email
// before the bearer is reached, so the discovery path is unreachable for a
// caller — this pins that a caller-carrying context derives for the caller.
func TestDiscoverySubjectNeverSubstitutesForACaller(t *testing.T) {
	provider := newDelegationProvider(t)
	src := discoverySource(t, provider, "operator@example.com")
	bearer := delegatedBearer(src, src.DiscoverySubject())

	if _, err := bearer(withDelegatedCall(context.Background(), "https://idp#u1", "alice@example.com")); err != nil {
		t.Fatalf("caller-scoped derivation failed: %v", err)
	}
	if got := provider.seenSubjects(); len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("provider saw subjects %v; a caller must never be served the discovery subject", got)
	}
}

func TestDiscoverySubjectRoundTripsThroughSummary(t *testing.T) {
	provider := newDelegationProvider(t)
	src := discoverySource(t, provider, "operator@example.com")
	if got := resolvedDelegationSummary(src).DiscoverySubject; got != "operator@example.com" {
		t.Fatalf("DiscoverySubject = %q, want operator@example.com", got)
	}
}

func TestDiscoverySubjectMustBeAProviderIdentity(t *testing.T) {
	provider := newDelegationProvider(t)
	saKey := provider.registerKey(t, "delegate@project.example")
	_, err := buildDelegatedSource(DelegationSummary{
		ClientEmail:      "delegate@project.example",
		TokenEndpoint:    provider.ts.URL,
		Scopes:           []string{"scope"},
		DiscoverySubject: "not-an-email",
	}, []byte(saKey))
	if err == nil || !strings.Contains(err.Error(), "provider identity") {
		t.Fatalf("want a provider-identity refusal, got %v", err)
	}
}

// An operator must be able to see what a connection was configured with,
// without reading the registry file off disk.
func TestUpstreamListingReportsDiscoverySubject(t *testing.T) {
	provider := newDelegationProvider(t)
	src := discoverySource(t, provider, "operator@example.com")
	s := newTestServer(t, fakeRunner{})
	if err := s.registerUpstream("docs", &upstream{
		conn: &fakeConn{endpoint: "https://upstream.example/mcp"}, enabled: true,
	}, WithDelegation(src)); err != nil {
		t.Fatal(err)
	}
	for _, info := range s.UpstreamList() {
		if info.Name == "docs" {
			if info.Delegation == nil || info.Delegation.DiscoverySubject != "operator@example.com" {
				t.Fatalf("listing did not report the discovery subject: %+v", info.Delegation)
			}
			return
		}
	}
	t.Fatal("connection missing from the listing")
}
