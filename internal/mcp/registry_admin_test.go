package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeMCPRegistry serves one page of the official-registry GET /v0/servers shape:
// a remote server (importable) and a package-only server (skipped).
func fakeMCPRegistry() *httptest.Server {
	body := `{"servers":[
      {"server":{"name":"io.github.acme/db","description":"Query databases","remotes":[{"type":"streamable-http","url":"https://db.acme.dev/mcp"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}},
      {"server":{"name":"pkg.only/thing","description":"stdio","packages":[{"registry":"npm"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}}
    ],"metadata":{"nextCursor":""}}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func TestAdminRegistrySearch(t *testing.T) {
	reg := fakeMCPRegistry()
	defer reg.Close()
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	h := s.AdminHandler("tok")

	rec := adminGET(t, h, "/admin/registry?url="+reg.URL+"&limit=50", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Servers []struct {
			Name, URL, Description string
		} `json:"servers"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || len(out.Servers) != 1 {
		t.Fatalf("want 1 remote server (package-only skipped), got %+v", out)
	}
	if out.Servers[0].Name != "io.github.acme-db" || out.Servers[0].URL != "https://db.acme.dev/mcp" {
		t.Fatalf("unexpected mapped server: %+v", out.Servers[0])
	}
}

func TestAdminRegistryImportIsGatedAndIdempotent(t *testing.T) {
	reg := fakeMCPRegistry()
	defer reg.Close()
	s := newTestServer(t, fakeRunner{}, WithUpstreamClient(&http.Client{}))
	h := s.AdminHandler("tok")

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/registry/import", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := post(`{"url":"` + reg.URL + `","limit":50}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var first struct{ Imported, Skipped, Found int }
	_ = json.Unmarshal(rec.Body.Bytes(), &first)
	if first.Imported != 1 {
		t.Fatalf("expected 1 imported, got %+v", first)
	}

	// The imported server is DISCOVERED (gated), not enabled, provenance=catalog.
	up := s.UpstreamList()
	var found *UpstreamInfo
	for i := range up {
		if up[i].Name == "io.github.acme-db" {
			found = &up[i]
		}
	}
	if found == nil {
		t.Fatalf("imported server not in the upstream index: %+v", up)
	}
	if found.State != "discovered" || found.Provenance != "catalog" {
		t.Fatalf("imported server must be gated+catalog, got state=%q provenance=%q", found.State, found.Provenance)
	}

	// Re-import is idempotent: the existing entry is skipped, not duplicated.
	rec2 := post(`{"url":"` + reg.URL + `","limit":50}`)
	var second struct{ Imported, Skipped, Found int }
	_ = json.Unmarshal(rec2.Body.Bytes(), &second)
	if second.Imported != 0 || second.Skipped != 1 {
		t.Fatalf("re-import should skip the existing server, got %+v", second)
	}
}
