package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// staticKeySet returns a fixed public key, optionally pinned to a kid.
type staticKeySet struct {
	pub crypto.PublicKey
	kid string
}

func (s staticKeySet) Key(_ context.Context, kid string) (crypto.PublicKey, error) {
	if s.kid != "" && kid != s.kid {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return s.pub, nil
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   "https://as.example.com",
		"aud":   "microagency",
		"sub":   "user-123",
		"scope": "mcp:run mcp:describe",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
}

func newRS(t *testing.T, key *rsa.PrivateKey) *ResourceServer {
	return &ResourceServer{
		Issuer:   "https://as.example.com",
		Audience: "microagency",
		Keys:     staticKeySet{pub: key.Public(), kid: "k1"},
	}
}

func TestValidateAccepts(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs := newRS(t, key)

	p, err := rs.Validate(context.Background(), signRS256(t, key, "k1", baseClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if p.Subject != "user-123" {
		t.Fatalf("subject = %q", p.Subject)
	}
	if !p.HasScope("mcp:run") || !p.HasScope("mcp:describe") || p.HasScope("admin") {
		t.Fatalf("scopes wrong: %v", p.Scopes)
	}
	if p.Expiry.Before(time.Now()) {
		t.Fatalf("expiry not parsed: %v", p.Expiry)
	}
}

func TestValidateRejects(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs := newRS(t, key)
	ctx := context.Background()

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"wrong audience", signRS256(t, key, "k1", withClaim(baseClaims(), "aud", "someone-else"))},
		{"wrong issuer", signRS256(t, key, "k1", withClaim(baseClaims(), "iss", "https://evil.example"))},
		{"expired", signRS256(t, key, "k1", withClaim(baseClaims(), "exp", time.Now().Add(-time.Hour).Unix()))},
		{"no expiry", signRS256(t, key, "k1", withoutClaim(baseClaims(), "exp"))},
		{"missing sub", signRS256(t, key, "k1", withoutClaim(baseClaims(), "sub"))},
		{"bad signature", signRS256(t, other, "k1", baseClaims())}, // signed by a key the set doesn't hold
		{"unknown kid", signRS256(t, key, "k-unknown", baseClaims())},
		{"symmetric alg (HS256)", signHS256(t, baseClaims())},
		{"garbage", "not-a-jwt"},
	}
	for _, c := range cases {
		if _, err := rs.Validate(ctx, c.token); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		} else if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: error should wrap ErrUnauthenticated, got %v", c.name, err)
		}
	}
}

func TestValidateScopeFormats(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs := newRS(t, key)

	// `scp` array instead of the space-delimited `scope` string.
	claims := withoutClaim(baseClaims(), "scope")
	claims["scp"] = []any{"a", "b"}
	p, err := rs.Validate(context.Background(), signRS256(t, key, "k1", claims))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !p.HasScope("a") || !p.HasScope("b") {
		t.Fatalf("scp array not parsed: %v", p.Scopes)
	}
}

func signHS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	return s
}

func withClaim(c jwt.MapClaims, k string, v any) jwt.MapClaims {
	out := jwt.MapClaims{}
	for kk, vv := range c {
		out[kk] = vv
	}
	out[k] = v
	return out
}

func withoutClaim(c jwt.MapClaims, k string) jwt.MapClaims {
	out := jwt.MapClaims{}
	for kk, vv := range c {
		if kk != k {
			out[kk] = vv
		}
	}
	return out
}
