package mcp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/budget"
	"microagency/internal/optoken"
	"microagency/internal/refstore"
)

func operatorReq(t *testing.T, h http.Handler, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestUnconfiguredOperatorPlaneRefusesEverything kills the old empty-token
// bypass: adminGuard used to skip authentication entirely when the configured
// token was "". No credential configured must mean no access, not open access.
func TestUnconfiguredOperatorPlaneRefusesEverything(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.AdminHandler(OperatorAuth{})
	for _, bearer := range []string{"", "guess"} {
		if rec := operatorReq(t, h, http.MethodGet, "/admin/runs", bearer); rec.Code != http.StatusUnauthorized {
			t.Errorf("bearer %q on unconfigured plane = %d, want 401", bearer, rec.Code)
		}
	}
	if rec := operatorReq(t, h, http.MethodPost, "/admin/upstreams", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("mutation on unconfigured plane = %d, want 401", rec.Code)
	}
}

func newTokenStore(t *testing.T) *optoken.Store {
	t.Helper()
	return optoken.NewStore(filepath.Join(t.TempDir(), "operator-tokens.json"))
}

// TestAuditorRoleIsReadOnly pins the auditor contract: the observability set
// answers, and every mutation or parked-data materialization refuses with 403.
func TestAuditorRoleIsReadOnly(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	store := newTokenStore(t)
	secret, err := store.Create("audit-ro", optoken.RoleAuditor, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.AdminHandler(OperatorAuth{Tokens: store})

	for _, path := range []string{"/admin/runs", "/admin/metrics", "/admin/metrics/prometheus"} {
		if rec := operatorReq(t, h, http.MethodGet, path, secret); rec.Code != http.StatusOK {
			t.Errorf("auditor GET %s = %d, want 200", path, rec.Code)
		}
	}
	// Verification endpoints must pass authorization for an auditor; their
	// status then reflects ledger state, never the role.
	for _, path := range []string{"/admin/audit/verify", "/admin/decisions/verify"} {
		if rec := operatorReq(t, h, http.MethodGet, path, secret); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("auditor GET %s = %d, want authorized", path, rec.Code)
		}
	}
	denied := []struct{ method, path string }{
		{http.MethodPost, "/admin/upstreams"},
		{http.MethodPost, "/admin/upstreams/x/disable"},
		{http.MethodDelete, "/admin/upstreams/x"},
		{http.MethodGet, "/admin/upstreams"},
		{http.MethodGet, "/admin/refs/x"},
	}
	for _, d := range denied {
		rec := operatorReq(t, h, d.method, d.path, secret)
		if rec.Code != http.StatusForbidden {
			t.Errorf("auditor %s %s = %d, want 403", d.method, d.path, rec.Code)
		}
		if d.path == "/admin/refs/x" && !strings.Contains(rec.Body.String(), "auditor") {
			t.Errorf("refusal does not name the role: %q", rec.Body.String())
		}
	}
}

// TestAdminTokenMaterializesWithNameAndReason pins the materialization
// contract: admin role required, explicit reason required, and the audit
// record carries the acting token's name plus the reason.
func TestAdminTokenMaterializesWithNameAndReason(t *testing.T) {
	rs := refstore.NewMemStore()
	ref, _ := rs.Put("203.0.113.9\n", "local")
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 1, Store: rs}))
	store := newTokenStore(t)
	secret, err := store.Create("ops-alice", optoken.RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.AdminHandler(OperatorAuth{Tokens: store})

	if rec := operatorReq(t, h, http.MethodGet, "/admin/refs/"+string(ref), secret); rec.Code != http.StatusBadRequest {
		t.Fatalf("materialize without reason = %d, want 400", rec.Code)
	}
	rec := operatorReq(t, h, http.MethodGet, "/admin/refs/"+string(ref)+"?reason=support+ticket+7", secret)
	if rec.Code != http.StatusOK {
		t.Fatalf("materialize with reason = %d: %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, r := range s.RunLog() {
		if r.Kind == "materialize" {
			found = true
			if r.User != "ops-alice" {
				t.Errorf("audit actor = %q, want the acting token name", r.User)
			}
			if r.Reason != "support ticket 7" {
				t.Errorf("audit reason = %q", r.Reason)
			}
		}
	}
	if !found {
		t.Fatal("no materialize audit record")
	}
}

// TestLegacyTokenIsBreakGlassAdmin: the original single token keeps full
// admin access and audits under its fixed recognizable name.
func TestLegacyTokenIsBreakGlassAdmin(t *testing.T) {
	rs := refstore.NewMemStore()
	ref, _ := rs.Put("data", "local")
	s := newTestServer(t, fakeRunner{}, WithBudgetGate(budget.Gate{MaxBytes: 1, Store: rs}))
	h := s.AdminHandler(OperatorAuth{LegacyToken: "op-legacy"})

	if rec := operatorReq(t, h, http.MethodGet, "/admin/runs", "op-legacy"); rec.Code != http.StatusOK {
		t.Fatalf("legacy token GET /admin/runs = %d", rec.Code)
	}
	rec := operatorReq(t, h, http.MethodGet, "/admin/refs/"+string(ref)+"?reason=drill", "op-legacy")
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy materialize = %d", rec.Code)
	}
	for _, r := range s.RunLog() {
		if r.Kind == "materialize" && r.User != optoken.LegacyName {
			t.Errorf("legacy actor = %q, want %q", r.User, optoken.LegacyName)
		}
	}
}

// TestRevocationAndExpiryTakeEffectWithoutRestart: the guard reads the store
// per request, so a revoke or a passed expiry bites on the very next call.
func TestRevocationAndExpiryTakeEffectWithoutRestart(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	store := newTokenStore(t)
	secret, err := store.Create("shortlived", optoken.RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.AdminHandler(OperatorAuth{Tokens: store})

	if rec := operatorReq(t, h, http.MethodGet, "/admin/runs", secret); rec.Code != http.StatusOK {
		t.Fatalf("fresh token = %d", rec.Code)
	}
	if err := store.Revoke("shortlived"); err != nil {
		t.Fatal(err)
	}
	if rec := operatorReq(t, h, http.MethodGet, "/admin/runs", secret); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d, want 401 on the next request", rec.Code)
	}

	past := time.Now().Add(-time.Minute)
	expired, err := store.Create("expired", optoken.RoleAdmin, &past)
	if err != nil {
		t.Fatal(err)
	}
	if rec := operatorReq(t, h, http.MethodGet, "/admin/runs", expired); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d, want 401", rec.Code)
	}
}
