package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func adminGET(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminTokenEnforced(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.AdminHandler("tok")
	if rec := adminGET(t, h, "/admin/upstreams", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := adminGET(t, h, "/admin/upstreams", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
}

func TestAdminUpstreamSSRFGuard(t *testing.T) {
	s := newTestServer(t, fakeRunner{}) // default: SSRF-guarded upstream client
	h := s.AdminHandler("tok")
	// An upstream pointed at the cloud-metadata address must be refused, not
	// fetched — the dial guard fires before any request leaves.
	rec := adminReq(t, h, "POST", "/admin/upstreams", "tok",
		`{"name":"evil","url":"http://169.254.169.254/latest/meta-data/"}`)
	if rec.Code == http.StatusCreated {
		t.Fatalf("SSRF: upstream to a metadata address was accepted: %s", rec.Body)
	}
}

func TestAdminMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	// /admin/runs is GET-only.
	req := httptest.NewRequest(http.MethodPost, "/admin/runs", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.AdminHandler("tok").ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /admin/runs status = %d, want 405", rec.Code)
	}
}

func adminReq(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminUpstreamCRUD(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	// The admin upstream-add path is SSRF-guarded by default; inject a plain
	// client so the test's loopback mock is reachable.
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(ts.Client()))
	h := s.AdminHandler("tok")
	// The upstream tool is kept out of tools/list; it's discoverable via find_tools.
	discoverable := func() bool {
		out := call(t, s, "find_tools", map[string]any{"query": "search the corpus"})
		b, _ := json.Marshal(out)
		return strings.Contains(string(b), "docs__search")
	}

	if rec := adminReq(t, h, "POST", "/admin/upstreams", "tok",
		`{"name":"docs","url":"`+ts.URL+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("add upstream: %d (%s)", rec.Code, rec.Body)
	}
	if rec := adminReq(t, h, "GET", "/admin/upstreams", "tok", ""); !strings.Contains(rec.Body.String(), `"name":"docs"`) {
		t.Fatalf("upstream not listed: %s", rec.Body)
	}
	if !discoverable() {
		t.Fatal("aggregated upstream tool not discoverable via find_tools after add")
	}
	// delete removes the upstream and drops it from the index.
	if rec := adminReq(t, h, "DELETE", "/admin/upstreams/docs", "tok", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete upstream: %d", rec.Code)
	}
	if discoverable() {
		t.Fatal("aggregated tool still discoverable after upstream delete")
	}
}
