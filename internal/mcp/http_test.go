package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postJSONRPC(t *testing.T, h http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHTTPToolsList(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.HTTPHandler("")
	rec := postJSONRPC(t, h, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var resp struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Result.Tools) != 3 {
		t.Fatalf("want 3 native tools over HTTP, got %d", len(resp.Result.Tools))
	}
}

func TestHTTPRejectsGET(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	s.HTTPHandler("").ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}

func TestHTTPTokenEnforced(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	h := s.HTTPHandler("s3cr3t-token")
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	if rec := postJSONRPC(t, h, "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := postJSONRPC(t, h, "wrong", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
	if rec := postJSONRPC(t, h, "s3cr3t-token", body); rec.Code != http.StatusOK {
		t.Fatalf("correct token: status = %d, want 200", rec.Code)
	}
}

func TestHTTPNotificationAccepted(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	rec := postJSONRPC(t, s.HTTPHandler(""), "", `{"jsonrpc":"2.0","method":"initialized"}`) // no id
	if rec.Code != http.StatusAccepted {
		t.Fatalf("notification status = %d, want 202", rec.Code)
	}
}
