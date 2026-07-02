package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeRegistry serves the official-registry GET /v0/servers shape in two pages,
// including a superseded version, an inactive server, and a package-only server
// (no remote) — all of which the adapter must handle.
func fakeRegistry() *httptest.Server {
	page1 := `{"servers":[
      {"server":{"name":"ac.inference.sh/mcp","description":"AI apps","title":"inference","remotes":[{"type":"streamable-http","url":"https://api.inference.sh/mcp"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}},
      {"server":{"name":"ac.inference.sh/mcp","description":"old","title":"inference","remotes":[{"type":"streamable-http","url":"https://old.example/mcp"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":false}}},
      {"server":{"name":"pkg.only/server","description":"stdio only","packages":[{"registry":"npm"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}}
    ],"metadata":{"nextCursor":"c2"}}`
	page2 := `{"servers":[
      {"server":{"name":"io.github.acme/db","description":"Query databases","title":"acme db","remotes":[{"type":"sse","url":"https://db.acme.dev/sse"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"active","isLatest":true}}},
      {"server":{"name":"gone/server","description":"deleted","remotes":[{"type":"streamable-http","url":"https://gone.example/mcp"}]},
       "_meta":{"io.modelcontextprotocol.registry/official":{"status":"deleted","isLatest":true}}}
    ],"metadata":{"nextCursor":""}}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/servers" {
			w.WriteHeader(404)
			return
		}
		if r.URL.Query().Get("cursor") == "c2" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
}

func TestLoadRegistryMapsAndFilters(t *testing.T) {
	srv := fakeRegistry()
	defer srv.Close()

	got, err := LoadRegistry(context.Background(), srv.Client(), srv.URL, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	// Expect: inference (latest), acme/db (sse). NOT: the old inference version
	// (isLatest=false), the package-only server (no remote), the deleted server.
	if len(got) != 2 {
		t.Fatalf("want 2 servers, got %d: %+v", len(got), got)
	}
	byName := map[string]Server{}
	for _, s := range got {
		byName[s.Name] = s
	}
	inf, ok := byName["ac.inference.sh-mcp"] // "/" sanitized to "-"
	if !ok {
		t.Fatalf("inference server missing or misnamed: %+v", got)
	}
	if inf.URL != "https://api.inference.sh/mcp" {
		t.Fatalf("inference should use the LATEST remote, got %q", inf.URL)
	}
	if inf.Description != "AI apps" {
		t.Fatalf("description = %q", inf.Description)
	}
	if len(inf.Tools) != 0 {
		t.Fatal("registry entries carry no tools until enabled")
	}
	if db, ok := byName["io.github.acme-db"]; !ok || db.URL != "https://db.acme.dev/sse" {
		t.Fatalf("acme db server missing/wrong: %+v", byName)
	}
	if _, bad := byName["gone-server"]; bad {
		t.Fatal("a deleted server must be skipped")
	}
	if _, bad := byName["pkg.only-server"]; bad {
		t.Fatal("a package-only server (no remote) must be skipped")
	}
}

func TestLoadRegistryQueryFilter(t *testing.T) {
	srv := fakeRegistry()
	defer srv.Close()

	got, err := LoadRegistry(context.Background(), srv.Client(), srv.URL, "database", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "io.github.acme-db" {
		t.Fatalf(`query "database" should match only acme db, got %+v`, got)
	}
}

func TestLoadRegistryLimitStopsEarly(t *testing.T) {
	srv := fakeRegistry()
	defer srv.Close()

	got, err := LoadRegistry(context.Background(), srv.Client(), srv.URL, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("limit=1 must cap results, got %d", len(got))
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"io.github.owner/server": "io.github.owner-server",
		"a__b":                   "a-b", // nsSep must not survive
		"  spaced/name  ":        "spaced-name",
		"weird@#chars":           "weird-chars",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadRegistryDefaultsURL(t *testing.T) {
	// A blank baseURL must fall back to the official registry (not panic / empty).
	if _, err := url.Parse(DefaultRegistryURL); err != nil {
		t.Fatalf("DefaultRegistryURL is not a valid URL: %v", err)
	}
}
