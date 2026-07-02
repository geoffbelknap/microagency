package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtectedResourceMetadata(t *testing.T) {
	h := ProtectedResourceMetadata("microagency", "https://as.example.com")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Resource != "microagency" || len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://as.example.com" {
		t.Fatalf("metadata wrong: %+v", doc)
	}

	prec := httptest.NewRecorder()
	h.ServeHTTP(prec, httptest.NewRequest(http.MethodPost, "/x", nil))
	if prec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", prec.Code)
	}
}
