package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer self-issues ES256 JWT access tokens and exposes the matching KeySet, so
// microagency can be its own authorization server validated by its own
// ResourceServer — the resource-server half (Validate/OAuthAuthenticator) is
// reused unchanged. The private key is generated once and persisted (0600), so
// tokens minted before a restart still validate after it.
type Signer struct {
	priv *ecdsa.PrivateKey
	kid  string
}

// LoadOrCreateSigner loads the ES256 (P-256) key at path, or generates and
// persists one (PEM, 0600, dir 0700) if absent.
func LoadOrCreateSigner(path string) (*Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("signer key %q: not PEM", path)
		}
		priv, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signer key %q: %w", path, err)
		}
		return newSigner(priv)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return newSigner(priv)
}

func newSigner(priv *ecdsa.PrivateKey) (*Signer, error) {
	// kid = base64url(sha256(SPKI)[:8]) — stable across restarts, collision-resistant.
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Signer{priv: priv, kid: base64.RawURLEncoding.EncodeToString(sum[:8])}, nil
}

// Mint issues a signed ES256 access token for subject with the given scopes,
// valid for ttl. iss is the authorization-server identifier (our own URL); aud is
// this resource's identifier (binding the token to us — RFC 8707).
func (s *Signer) Mint(iss, aud, sub string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   sub,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"scope": strings.Join(scopes, " "),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.priv)
}

// KeySet resolves this signer's public key, so a ResourceServer validates tokens
// this Signer minted with no network fetch.
func (s *Signer) KeySet() KeySet { return localKeySet{kid: s.kid, pub: &s.priv.PublicKey} }

// KID is the key id stamped in minted tokens' headers (and published in JWKS).
func (s *Signer) KID() string { return s.kid }

// PublicKey is the verification key, for publishing JWKS / AS metadata.
func (s *Signer) PublicKey() *ecdsa.PublicKey { return &s.priv.PublicKey }

// SignBytes signs an arbitrary message with the ES256 private key (ASN.1 ECDSA
// over SHA-256 of data), for uses beyond JWTs — the audit chain signs each line's
// hash so a record can't be forged or edited without this key, and the log stays
// verifiable offline by anyone holding only the public key.
func (s *Signer) SignBytes(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.priv, h[:])
}

// VerifyBytes reports whether sig is a valid SignBytes signature over data under
// this signer's public key.
func (s *Signer) VerifyBytes(data, sig []byte) bool {
	h := sha256.Sum256(data)
	return ecdsa.VerifyASN1(&s.priv.PublicKey, h[:], sig)
}

type localKeySet struct {
	kid string
	pub crypto.PublicKey
}

func (k localKeySet) Key(_ context.Context, kid string) (crypto.PublicKey, error) {
	if kid != "" && kid != k.kid {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return k.pub, nil
}
