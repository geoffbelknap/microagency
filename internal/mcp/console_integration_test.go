package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"microagency/internal/console"
)

// The console's operator affordances must match the admin API: every action the
// page wires a button to actually exists and works. This drives the exact HTTP
// calls the buttons issue — enable a discovered upstream, scope it to a user,
// verify the audit chain — against a live handler. It lives in the mcp package
// (which serves /admin) and imports internal/console for the page.
func TestConsoleAffordancesMatchAdminAPI(t *testing.T) {
	// The page carries the affordances.
	s := newTestServer(t, fakeRunner{}, WithStateDir(t.TempDir()), WithUpstreamClient(&http.Client{}))
	page := httptest.NewRecorder()
	console.Handler("").ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/console", nil))
	body := page.Body.String()
	for _, want := range []string{"/enable", "/owner", "/admin/audit/verify", "Scope to user", "Verify audit chain"} {
		if !strings.Contains(body, want) {
			t.Fatalf("console page missing affordance %q", want)
		}
	}

	// ...and the endpoints they call behave.
	up := cannedUpstream(t)
	defer up.Close()
	admin := httptest.NewServer(s.AdminHandler("op"))
	defer admin.Close()
	call := func(method, path, payload string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, admin.URL+path, strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer op")
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		_, _ = io.Copy(&sb, resp.Body)
		return resp.StatusCode, sb.String()
	}

	if code, out := call(http.MethodPost, "/admin/upstreams", `{"name":"docs","url":"`+up.URL+`","discover":true}`); code != http.StatusCreated {
		t.Fatalf("add discovered: %d %s", code, out)
	}
	// enable — the button the discovered state renders.
	if code, out := call(http.MethodPost, "/admin/upstreams/docs/enable", ""); code != http.StatusOK {
		t.Fatalf("enable: %d %s", code, out)
	}
	// owner — the scope-to-user modal's POST.
	if code, out := call(http.MethodPost, "/admin/upstreams/docs/owner", `{"owner":"alice"}`); code != http.StatusOK {
		t.Fatalf("set owner: %d %s", code, out)
	}
	if code, out := call(http.MethodGet, "/admin/upstreams", ""); code != http.StatusOK || !strings.Contains(out, `"owner":"alice"`) || !strings.Contains(out, `"state":"enabled"`) {
		t.Fatalf("list after enable+scope: %d %s", code, out)
	}
	// verify — the audit-chain button's GET.
	if code, out := call(http.MethodGet, "/admin/audit/verify", ""); code != http.StatusOK || !strings.Contains(out, `"intact":true`) {
		t.Fatalf("audit verify: %d %s", code, out)
	}
}
