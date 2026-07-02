package secretstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func roundTrip(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Load(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("absent key: want ErrNotFound, got %v", err)
	}
	if err := s.Save(ctx, "up/supa", []byte(`{"refresh_token":"r1"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, "up/supa")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"refresh_token":"r1"}` {
		t.Fatalf("load = %s", got)
	}
	if err := s.Delete(ctx, "up/supa"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "up/supa"); err != ErrNotFound {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestFileStore(t *testing.T) {
	roundTrip(t, &File{Path: filepath.Join(t.TempDir(), "tokens.json")})
}

// mockVault emulates the bits of OpenBao/Vault KV v2 we use.
func mockVault(t *testing.T) *Vault {
	t.Helper()
	store := map[string]string{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/data/"):
			var body struct {
				Data struct {
					V string `json:"v"`
				} `json:"data"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			store[after(r.URL.Path, "/data/")] = body.Data.V
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/data/"):
			v, ok := store[after(r.URL.Path, "/data/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"v": v}}})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/metadata/"):
			delete(store, after(r.URL.Path, "/metadata/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return &Vault{Addr: srv.URL, Token: "t", Mount: "secret", Prefix: "microagency", Client: srv.Client()}
}

func after(path, sep string) string {
	if i := strings.Index(path, sep); i >= 0 {
		return path[i+len(sep):]
	}
	return path
}

func TestVaultStore(t *testing.T) {
	roundTrip(t, mockVault(t))
}

func TestOpenPrefersVault(t *testing.T) {
	env := map[string]string{"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_TOKEN": "t"}
	s := Open(t.TempDir(), func(k string) string { return env[k] }, nil)
	if s.Kind() != "vault" {
		t.Fatalf("with VAULT_* set, want vault, got %s", s.Kind())
	}
	s = Open(t.TempDir(), func(string) string { return "" }, nil)
	if s.Kind() != "file" {
		t.Fatalf("without VAULT_*, want file, got %s", s.Kind())
	}
}
