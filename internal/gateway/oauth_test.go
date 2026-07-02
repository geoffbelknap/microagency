package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamCarriesSessionID(t *testing.T) {
	var toolsListSession string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), `"initialize"`):
			w.Header().Set("Mcp-Session-Id", "sess-123")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		case strings.Contains(string(body), "tools/list"):
			toolsListSession = r.Header.Get("Mcp-Session-Id")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
		default: // notifications/initialized
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	u := &Upstream{Name: "x", URL: srv.URL}
	if err := u.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := u.ListTools(context.Background()); err != nil {
		t.Fatal(err)
	}
	if toolsListSession != "sess-123" {
		t.Fatalf("tools/list did not echo the session id from initialize: %q", toolsListSession)
	}
}

func TestUpstreamBearerTakesPrecedence(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	u := &Upstream{
		Name: "x", URL: srv.URL, Token: "static",
		Bearer: func(context.Context) (string, error) { return "dynamic", nil },
	}
	if err := u.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer dynamic" {
		t.Fatalf("auth = %q, want the dynamic bearer to win over the static token", gotAuth)
	}
}

func TestUpstreamParsesSSEResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "tools/list") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"q\"}]}}\n\n")
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	tools, err := (&Upstream{Name: "x", URL: srv.URL}).ListTools(context.Background())
	if err != nil {
		t.Fatalf("SSE tools/list: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "q" {
		t.Fatalf("tools = %+v", tools)
	}
}

func TestUpstreamLargeSSEResponse(t *testing.T) {
	// ~10 MB result full of quotes + backslashes — over the old 8 MB read cap that
	// truncated or cut mid-escape. The whole body must reassemble and decode.
	big := strings.Repeat(`row "a\b" `, 1<<20)
	msg, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"content": []map[string]any{{"type": "text", "text": big}}},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: "))
		_, _ = w.Write(msg)
		_, _ = w.Write([]byte("\n\n"))
	}))
	defer srv.Close()

	res, err := (&Upstream{Name: "x", URL: srv.URL}).CallTool(context.Background(), "q", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("large SSE result with escapes must parse, got: %v", err)
	}
	if !strings.Contains(string(res), `"content"`) {
		t.Fatal("parsed result missing content")
	}
}

func TestUpstreamProbeDetectsOAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://as.example/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rm, err := (&Upstream{Name: "x", URL: srv.URL}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rm != "https://as.example/.well-known/oauth-protected-resource" {
		t.Fatalf("probe rm = %q", rm)
	}
}

func TestUpstreamProbeNoOAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	rm, err := (&Upstream{Name: "x", URL: srv.URL}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rm != "" {
		t.Fatalf("expected no OAuth, got rm = %q", rm)
	}
}

func TestResourceMetadataFromWWWAuth(t *testing.T) {
	const mcp = "https://mcp.example.com/mcp"
	cases := []struct{ name, www, want string }{
		{"relative", `Bearer resource_metadata="/.well-known/oauth-protected-resource"`, "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{"absolute", `Bearer resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"`, "https://auth.example.com/.well-known/oauth-protected-resource"},
		{"absent-returns-empty", "", ""}, // no header value → caller derives (path-aware) instead
		{"no-resource-param", `Bearer realm="x"`, ""},
	}
	for _, c := range cases {
		if got := resourceMetadataFromWWWAuth(mcp, c.www); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A resource served under a path (e.g. /mcp/trading) publishes its RFC 9728
// metadata at the INSERTION location (<origin>/.well-known/oauth-protected-
// resource/mcp/trading), not by appending after the path. Probe must find it there
// even though the root location 404s — the sibling of the AS-discovery fix.
func TestUpstreamProbePathAwareResourceMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/trading", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)) // public initialize, no challenge
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp/trading", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"x","authorization_servers":["https://as.example"]}`))
	})
	// The root location deliberately 404s (default ServeMux behavior), so a
	// root-only probe would miss OAuth entirely.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rm, err := (&Upstream{Name: "rh", URL: srv.URL + "/mcp/trading"}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := srv.URL + "/.well-known/oauth-protected-resource/mcp/trading"; rm != want {
		t.Fatalf("probe rm = %q, want the insertion location %q", rm, want)
	}
}

// A LimaCharlie-style upstream: public initialize/tools-list (no 401 challenge)
// but advertises OAuth via RFC 9728 protected-resource metadata. Probe must fall
// back to that metadata and report OAuth is available.
func TestUpstreamProbeDetectsOAuthViaWellKnown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"resource":"x","authorization_servers":["https://as.example"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)) // public, no challenge
	}))
	defer srv.Close()

	rm, err := (&Upstream{Name: "lc", URL: srv.URL}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := srv.URL + "/.well-known/oauth-protected-resource"; rm != want {
		t.Fatalf("probe rm = %q, want %q", rm, want)
	}
}

// A public upstream with no OAuth metadata (well-known 404s) must report no OAuth.
func TestUpstreamProbeNoOAuthWhenWellKnownAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	rm, err := (&Upstream{Name: "x", URL: srv.URL}).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rm != "" {
		t.Fatalf("expected no OAuth, got rm = %q", rm)
	}
}
