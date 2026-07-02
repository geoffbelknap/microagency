package mcp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestProviderForURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string // expected provider name, "" for no match
		wantHit bool
	}{
		{"supabase https", "https://mcp.supabase.com/mcp", "Supabase", true},
		{"supabase with port", "https://mcp.supabase.com:443/mcp", "Supabase", true},
		{"supabase case-insensitive host", "https://MCP.Supabase.COM/mcp", "Supabase", true},
		{"supabase with existing query", "https://mcp.supabase.com/mcp?foo=1", "Supabase", true},
		{"unknown host", "https://mcp.example.com/mcp", "", false},
		{"empty", "", "", false},
		{"no host", "/just/a/path", "", false},
		{"garbage", "://::::", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := providerForURL(tc.url)
			if ok != tc.wantHit {
				t.Fatalf("providerForURL(%q) hit = %v, want %v", tc.url, ok, tc.wantHit)
			}
			if ok && p.Name != tc.want {
				t.Fatalf("providerForURL(%q) = %q, want %q", tc.url, p.Name, tc.want)
			}
		})
	}
}

// queryOf parses a URL and returns its query values (fatal on parse error).
func queryOf(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}

func TestScopedURL_AppendsProviderParams(t *testing.T) {
	got, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{
		"project_ref": "abcd1234",
		"read_only":   "true",
	})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	q := queryOf(t, got)
	if q.Get("project_ref") != "abcd1234" {
		t.Errorf("project_ref = %q, want abcd1234", q.Get("project_ref"))
	}
	if q.Get("read_only") != "true" {
		t.Errorf("read_only = %q, want true", q.Get("read_only"))
	}
}

func TestScopedURL_PreservesExistingQueryNoDuplicates(t *testing.T) {
	got, err := ScopedURL("https://mcp.supabase.com/mcp?foo=1&project_ref=OLD", map[string]string{
		"project_ref": "NEW",
	})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}
	q := u.Query()
	// Pre-existing unrelated param survives.
	if q.Get("foo") != "1" {
		t.Errorf("existing foo lost: %q", q.Get("foo"))
	}
	// Operator value replaces the existing key — exactly one, not duplicated.
	if vals := q["project_ref"]; len(vals) != 1 || vals[0] != "NEW" {
		t.Errorf("project_ref = %v, want single [NEW]", vals)
	}
}

func TestScopedURL_BoolHandling(t *testing.T) {
	// Truthy variants normalize to "true".
	for _, v := range []string{"true", "1", "TRUE", "t"} {
		got, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{"read_only": v})
		if err != nil {
			t.Fatalf("ScopedURL(read_only=%q): %v", v, err)
		}
		if q := queryOf(t, got); q.Get("read_only") != "true" {
			t.Errorf("read_only=%q normalized to %q, want true", v, q.Get("read_only"))
		}
	}
	// Falsy normalizes to "false" and is still explicit.
	got, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{"read_only": "false"})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	if q := queryOf(t, got); q.Get("read_only") != "false" {
		t.Errorf("read_only=false normalized to %q, want false", q.Get("read_only"))
	}
	// A non-boolean value for a bool knob is rejected defensively.
	if _, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{"read_only": "yesnt"}); err == nil {
		t.Error("expected error for non-boolean read_only, got nil")
	}
}

func TestScopedURL_BlankStringSkipped(t *testing.T) {
	got, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{
		"project_ref": "   ", // whitespace-only → operator left it blank
		"features":    "database,docs",
	})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	q := queryOf(t, got)
	if q.Has("project_ref") {
		t.Errorf("blank project_ref should be omitted, got %q", q.Get("project_ref"))
	}
	if q.Get("features") != "database,docs" {
		t.Errorf("features = %q, want database,docs", q.Get("features"))
	}
}

func TestScopedURL_UnknownKeysIgnored(t *testing.T) {
	// A key the provider does not declare must never be smuggled onto the URL.
	got, err := ScopedURL("https://mcp.supabase.com/mcp", map[string]string{
		"project_ref": "abc",
		"admin":       "true", // not a declared Supabase knob
	})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	q := queryOf(t, got)
	if q.Has("admin") {
		t.Errorf("undeclared param 'admin' was applied: %q", q.Get("admin"))
	}
	if q.Get("project_ref") != "abc" {
		t.Errorf("project_ref = %q, want abc", q.Get("project_ref"))
	}
}

func TestScopedURL_NonCatalogUntouched(t *testing.T) {
	in := "https://mcp.example.com/mcp?keep=1"
	got, err := ScopedURL(in, map[string]string{"project_ref": "abc", "read_only": "true"})
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	if got != in {
		t.Errorf("non-catalog URL changed: got %q, want %q", got, in)
	}
}

func TestScopedURL_NoValuesUntouched(t *testing.T) {
	in := "https://mcp.supabase.com/mcp?keep=1"
	got, err := ScopedURL(in, nil)
	if err != nil {
		t.Fatalf("ScopedURL: %v", err)
	}
	if got != in {
		t.Errorf("empty values changed URL: got %q, want %q", got, in)
	}
}

func TestAdminProviderParamsEndpoint(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.AdminHandler("tok")

	// Known provider → its curated knobs.
	rec := adminReq(t, h, "GET", "/admin/provider-params?url="+url.QueryEscape("https://mcp.supabase.com/mcp"), "tok", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}
	var got struct {
		Provider string          `json:"provider"`
		Params   []ProviderParam `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Provider != "Supabase" || len(got.Params) == 0 {
		t.Fatalf("supabase params missing: %+v", got)
	}
	var haveProjectRef, haveReadOnly bool
	for _, p := range got.Params {
		switch p.Name {
		case "project_ref":
			haveProjectRef = p.Kind == ParamString
		case "read_only":
			haveReadOnly = p.Kind == ParamBool
		}
	}
	if !haveProjectRef || !haveReadOnly {
		t.Fatalf("expected project_ref(string) + read_only(bool), got %+v", got.Params)
	}

	// Unknown provider → empty set, still 200.
	rec = adminReq(t, h, "GET", "/admin/provider-params?url="+url.QueryEscape("https://mcp.example.com/mcp"), "tok", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"provider":""`) {
		t.Fatalf("unknown provider: %d %s", rec.Code, rec.Body)
	}

	// Missing url → 400.
	if rec := adminReq(t, h, "GET", "/admin/provider-params", "tok", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing url: %d, want 400", rec.Code)
	}
}

// TestAdminAddUpstreamAppliesScopeParams drives the full add handler and confirms
// operator-chosen scoping knobs are baked into the registered upstream's URL. The
// canned upstream is loopback, so a temporary catalog entry matching its host is
// registered for the duration of the test (restored on cleanup).
func TestAdminAddUpstreamAppliesScopeParams(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()

	host, err := hostOf(ts.URL)
	if err != nil {
		t.Fatalf("parse test url: %v", err)
	}
	restore := providerCatalog
	providerCatalog = append([]Provider{{
		Name: "TestProvider",
		Host: host,
		Params: []ProviderParam{
			{Name: "project_ref", Kind: ParamString},
			{Name: "read_only", Kind: ParamBool},
		},
	}}, providerCatalog...)
	t.Cleanup(func() { providerCatalog = restore })

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(ts.Client()))
	h := s.AdminHandler("tok")

	body := `{"name":"scoped","url":"` + ts.URL + `","scope_params":{"project_ref":"proj123","read_only":"true"}}`
	if rec := adminReq(t, h, "POST", "/admin/upstreams", "tok", body); rec.Code != http.StatusCreated {
		t.Fatalf("add upstream: %d (%s)", rec.Code, rec.Body)
	}

	var registered string
	for _, u := range s.UpstreamList() {
		if u.Name == "scoped" {
			registered = u.URL
		}
	}
	if registered == "" {
		t.Fatal("upstream not registered")
	}
	q := queryOf(t, registered)
	if q.Get("project_ref") != "proj123" {
		t.Errorf("registered URL missing project_ref: %q", registered)
	}
	if q.Get("read_only") != "true" {
		t.Errorf("registered URL missing read_only: %q", registered)
	}
}

// TestAdminAddUpstreamRejectsBadScopeParam confirms a malformed bool is a 400, not
// a silently-dropped param.
func TestAdminAddUpstreamRejectsBadScopeParam(t *testing.T) {
	ts := cannedUpstream(t)
	defer ts.Close()
	host, err := hostOf(ts.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	restore := providerCatalog
	providerCatalog = append([]Provider{{
		Name: "TestProvider", Host: host,
		Params: []ProviderParam{{Name: "read_only", Kind: ParamBool}},
	}}, providerCatalog...)
	t.Cleanup(func() { providerCatalog = restore })

	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(ts.Client()))
	h := s.AdminHandler("tok")
	body := `{"name":"bad","url":"` + ts.URL + `","scope_params":{"read_only":"maybe"}}`
	if rec := adminReq(t, h, "POST", "/admin/upstreams", "tok", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad scope param: %d, want 400 (%s)", rec.Code, rec.Body)
	}
}

func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}
