package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func rsaJWK(kid string, pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// TestJWKSEndToEnd discovers a JWKS from a mock issuer and validates a token
// signed by its key — the production key-resolution path.
func TestJWKSEndToEnd(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk{rsaJWK("k1", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	ctx := context.Background()

	ks, err := NewJWKSFromIssuer(ctx, ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	rs := &ResourceServer{Issuer: ts.URL, Audience: "microagency", Keys: ks}

	claims := jwt.MapClaims{
		"iss": ts.URL, "aud": "microagency", "sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	p, err := rs.Validate(ctx, signRS256(t, key, "k1", claims))
	if err != nil {
		t.Fatalf("validate via JWKS: %v", err)
	}
	if p.Subject != "u1" {
		t.Fatalf("subject = %q", p.Subject)
	}

	// A token whose kid isn't in the JWKS is rejected.
	if _, err := rs.Validate(ctx, signRS256(t, key, "absent-kid", claims)); err == nil {
		t.Fatal("expected rejection for an unknown kid")
	}
}
