package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"microagency/internal/auth"
)

// TestHTTPOAuthMode drives the /mcp surface behind the OAuth resource server:
// no token and a bad token are 401 (with a metadata hint), a valid token is 200.
func TestHTTPOAuthMode(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/jwks"})
		case "/jwks":
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
				{"kty": "RSA", "kid": "k1", "n": n, "e": e},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()

	ks, err := auth.NewJWKSFromIssuer(context.Background(), issuer.URL, issuer.Client())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	rs := &auth.ResourceServer{Issuer: issuer.URL, Audience: "microagency", Keys: ks}
	h := newTestServer(t, fakeRunner{}).HTTPHandlerAuth(OAuthAuthenticator(rs, ""))

	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(key)
		return s
	}
	post := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec.Code)
	} else if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("401 missing resource_metadata hint: %q", rec.Header().Get("WWW-Authenticate"))
	}
	if rec := post("garbage"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d, want 401", rec.Code)
	}
	valid := sign(jwt.MapClaims{
		"iss": issuer.URL, "aud": "microagency", "sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if rec := post(valid); rec.Code != http.StatusOK {
		t.Fatalf("valid token: %d (%s)", rec.Code, rec.Body)
	}
}

// With a required scope configured, a valid token that wasn't granted it is
// refused — indistinguishably from any other auth failure — and a token carrying
// it passes. Scope enforcement is real, not decorative.
func TestHTTPOAuthRequiredScope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/jwks"})
		case "/jwks":
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
				{"kty": "RSA", "kid": "k1", "n": n, "e": e},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()

	ks, err := auth.NewJWKSFromIssuer(context.Background(), issuer.URL, issuer.Client())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	rs := &auth.ResourceServer{Issuer: issuer.URL, Audience: "microagency", Keys: ks}
	h := newTestServer(t, fakeRunner{}).HTTPHandlerAuth(OAuthAuthenticator(rs, "mcp"))

	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(key)
		return s
	}
	post := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	base := jwt.MapClaims{"iss": issuer.URL, "aud": "microagency", "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}

	noScope := jwt.MapClaims{}
	for k, v := range base {
		noScope[k] = v
	}
	if rec := post(sign(noScope)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token without the required scope: %d, want 401", rec.Code)
	}

	wrong := jwt.MapClaims{"scope": "email profile"}
	for k, v := range base {
		wrong[k] = v
	}
	if rec := post(sign(wrong)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token with other scopes only: %d, want 401", rec.Code)
	}

	granted := jwt.MapClaims{"scope": "email mcp"}
	for k, v := range base {
		granted[k] = v
	}
	if rec := post(sign(granted)); rec.Code != http.StatusOK {
		t.Fatalf("token granted the scope: %d (%s)", rec.Code, rec.Body)
	}
}
