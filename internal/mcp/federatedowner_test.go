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

// Federated sign-in mints gateway tokens whose subject is the identity
// provider's `sub`, all under the gateway's one issuer. Two provider accounts
// must therefore be two principals with separate connection ownership: an
// owner-scoped connection is invocable and findable only by the account it is
// scoped to, through the public HTTP surface with full JWT validation.
func TestFederatedSubjectsOwnSeparateConnections(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})

	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	const gatewayIssuer = "https://gateway.test"
	rs := &auth.ResourceServer{Issuer: gatewayIssuer, Audience: "mcp-aud", Keys: signer.KeySet()}
	// Federated built-in OAuth is a multi-principal surface.
	authn := OAuthAuthenticator(rs, "mcp", true)

	// The operator scopes a connection to alpha's canonical identity: the
	// gateway issuer plus the provider sub — exactly what federated tokens carry.
	ownerKey := auth.PrincipalKey(gatewayIssuer, "user-alpha")
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}, WithOwner(ownerKey)); err != nil {
		t.Fatalf("add owned upstream: %v", err)
	}
	h := s.HTTPHandlerAuth(authn)

	mint := func(sub string) string {
		t.Helper()
		tok, err := signer.Mint(gatewayIssuer, "mcp-aud", sub, []string{"mcp"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	// Alpha invokes the owned connection normally.
	out := callToolHTTP(t, h, mint("user-alpha"), "docs__search")
	if isErr, _ := out["isError"].(bool); isErr {
		t.Fatalf("the owning account must be able to invoke: %v", out)
	}
	// Beta — another account at the same provider, same gateway issuer — is
	// refused indistinguishably from an unregistered tool.
	out = callToolHTTP(t, h, mint("user-beta"), "docs__search")
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatalf("another provider account must not invoke an owned connection: %v", out)
	}
	if raw, _ := json.Marshal(out); !strings.Contains(string(raw), "unknown tool") {
		t.Fatalf("refusal must look like an unregistered tool: %s", raw)
	}

	// Discovery follows the same boundary.
	if got := len(s.indexedTools(auth.PrincipalKey(gatewayIssuer, "user-alpha"))); got != 1 {
		t.Fatalf("owner must see the owned connection; got %d tools", got)
	}
	if got := len(s.indexedTools(auth.PrincipalKey(gatewayIssuer, "user-beta"))); got != 0 {
		t.Fatalf("another account must see nothing; got %d tools", got)
	}
}
