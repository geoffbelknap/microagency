package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/refstore"
)

// issuerBearerAuth authenticates a bearer of the form "issuer|subject" into a
// principal under that issuer — a stand-in for two OAuth resource servers whose
// validated tokens assert the same `sub`.
type issuerBearerAuth struct{}

func (issuerBearerAuth) MultiPrincipal() bool { return true } // attests arbitrary issuer+subject pairs

func (issuerBearerAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	issuer, subject, ok := strings.Cut(raw, "|")
	if !ok || issuer == "" || subject == "" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{Subject: subject, Issuer: issuer, Scopes: []string{"mcp"}}, nil
}

func callToolHTTP(t *testing.T, h http.Handler, bearer, tool string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_tool","arguments":{"name":"` + tool + `","arguments":{"q":"x"}}}}`
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

// The identity boundary is (issuer, subject), not the bare token subject: a
// caller whose token asserts the SAME `sub` under a DIFFERENT issuer is a
// different principal. An owner-scoped connection stays invisible and
// uninvocable to the other issuer's caller through the public HTTP surface,
// with the same error as an unregistered tool.
func TestSameSubjectDifferentIssuerIsADifferentCaller(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	s := newTestServer(t, fakeRunner{})
	const issuerA, issuerB = "https://issuer-a.test", "https://issuer-b.test"
	ownerKey := auth.PrincipalKey(issuerA, "alice")
	if err := s.AddUpstream(context.Background(), "docs", &gateway.Upstream{Name: "docs", URL: ts.URL}, WithOwner(ownerKey)); err != nil {
		t.Fatalf("add owned upstream: %v", err)
	}
	h := s.HTTPHandlerAuth(issuerBearerAuth{})

	// The owning caller (issuer A) invokes normally.
	out := callToolHTTP(t, h, issuerA+"|alice", "docs__search")
	if isErr, _ := out["isError"].(bool); isErr {
		t.Fatalf("the owner must be able to invoke: %v", out)
	}
	// The same subject under issuer B is refused, indistinguishably from an
	// unregistered tool.
	out = callToolHTTP(t, h, issuerB+"|alice", "docs__search")
	if isErr, _ := out["isError"].(bool); !isErr {
		t.Fatalf("same sub under another issuer must not invoke an owned connection: %v", out)
	}
	if raw, _ := json.Marshal(out); !strings.Contains(string(raw), "unknown tool") {
		t.Fatalf("refusal must look like an unregistered tool: %s", raw)
	}

	// find_tools scoping follows the same boundary.
	if got := len(s.indexedTools(auth.PrincipalKey(issuerA, "alice"))); got != 1 {
		t.Fatalf("owner must see the owned connection; got %d tools", got)
	}
	if got := len(s.indexedTools(auth.PrincipalKey(issuerB, "alice"))); got != 0 {
		t.Fatalf("same sub under another issuer must see nothing; got %d tools", got)
	}
}

// A ref created by (issuer A, alice) is not readable by (issuer B, alice): the
// composite key, not the bare subject, owns stored results.
func TestRefOwnershipIsIssuerScoped(t *testing.T) {
	store := refstore.NewMemStore()
	const issuerA, issuerB = "https://issuer-a.test", "https://issuer-b.test"
	ref, _ := store.Put(`[{"x":1}]`, auth.PrincipalKey(issuerA, "alice"))
	s := newTestServer(t, fakeRunner{},
		WithBudgetGate(budget.Gate{MaxBytes: 4096, Store: store}),
		WithWasmEngine("jq", fakeEngine{}))
	args, _ := json.Marshal(map[string]any{"ref": string(ref), "query": "length"})

	ctxB := context.WithValue(context.Background(), principalKey, &auth.Principal{Subject: "alice", Issuer: issuerB})
	if out := s.reduce(ctxB, args); !out["isError"].(bool) || !strings.Contains(errText(t, out), "unknown reference") {
		t.Fatalf("same sub under another issuer must be refused like an unknown ref: %v", out)
	}
	ctxA := context.WithValue(context.Background(), principalKey, &auth.Principal{Subject: "alice", Issuer: issuerA})
	if out := s.reduce(ctxA, args); out["isError"].(bool) {
		t.Fatalf("the creating (issuer, subject) must reduce its own ref: %v", out)
	}
}

// Self-service secret paths derive from the composite key: identical subjects
// under two issuers never share a credential path.
func TestSecretPathsAreIssuerScoped(t *testing.T) {
	a := selfServiceTokenKey(auth.PrincipalKey("https://issuer-a.test", "alice"), "conn")
	b := selfServiceTokenKey(auth.PrincipalKey("https://issuer-b.test", "alice"), "conn")
	if a == b {
		t.Fatal("secret paths collided across issuers for the same subject")
	}
}

// A grant names the composite identity; the same subject under another issuer
// does not match it, and a bare-subject grant is rejected outright.
func TestGrantsBindToIssuerAndSubject(t *testing.T) {
	grant := readGrant("get-repo")
	if _, err := validateOperationGrant(grant, "u"); err != nil {
		t.Fatalf("composite-principal grant must validate: %v", err)
	}
	if _, err := evaluateOperationGrant(grant, auth.PrincipalKey("https://issuer-b.test", "alice"), "campaign-a", "get-repo", json.RawMessage(`{"repo":"org/repo"}`), time.Now()); err == nil {
		t.Fatal("same sub under another issuer must not match the grant")
	}
	if _, err := evaluateOperationGrant(grant, pk("alice"), "campaign-a", "get-repo", json.RawMessage(`{"repo":"org/repo"}`), time.Now()); err != nil {
		t.Fatalf("the granted (issuer, subject) must match: %v", err)
	}
	bare := grant
	bare.Principal = "alice"
	if _, err := validateOperationGrant(bare, "u"); err == nil || !strings.Contains(err.Error(), "canonical issuer#subject") {
		t.Fatalf("bare-subject grant must be rejected: %v", err)
	}
}
