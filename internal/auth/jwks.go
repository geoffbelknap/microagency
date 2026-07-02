package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKSKeySet resolves signing keys from a remote JWKS (RFC 7517), discovered
// from the issuer's OIDC metadata or pointed at directly. Keys are cached by kid
// and refreshed on a cache miss (rate-limited, so an unknown-kid flood can't be
// turned into a fetch flood).
type JWKSKeySet struct {
	URL        string
	Client     *http.Client
	MinRefresh time.Duration // minimum interval between refreshes; default 1m

	mu       sync.RWMutex
	keys     map[string]crypto.PublicKey
	lastLoad time.Time
}

// NewJWKSFromIssuer discovers the JWKS URL from the issuer's OIDC metadata
// ({issuer}/.well-known/openid-configuration) and returns a key set for it.
func NewJWKSFromIssuer(ctx context.Context, issuer string, client *http.Client) (*JWKSKeySet, error) {
	if client == nil {
		client = http.DefaultClient
	}
	meta := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, client, meta, &doc); err != nil {
		return nil, fmt.Errorf("auth: discover issuer metadata: %w", err)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("auth: issuer %q has no jwks_uri", issuer)
	}
	return &JWKSKeySet{URL: doc.JWKSURI, Client: client}, nil
}

// Key returns the public key for kid, refreshing the JWKS on a miss.
func (j *JWKSKeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if k := j.cached(kid); k != nil {
		return k, nil
	}
	if err := j.refresh(ctx); err != nil {
		return nil, err
	}
	if k := j.cached(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("auth: no signing key for kid %q", kid)
}

func (j *JWKSKeySet) cached(kid string) crypto.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keys[kid]
}

func (j *JWKSKeySet) refresh(ctx context.Context) error {
	min := j.MinRefresh
	if min <= 0 {
		min = time.Minute
	}
	j.mu.Lock()
	if !j.lastLoad.IsZero() && time.Since(j.lastLoad) < min {
		j.mu.Unlock()
		return nil // rate-limited; the cache miss will surface as no-key
	}
	j.mu.Unlock()

	client := j.Client
	if client == nil {
		client = http.DefaultClient
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := getJSON(ctx, client, j.URL, &set); err != nil {
		return fmt.Errorf("auth: fetch jwks: %w", err)
	}
	parsed := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil || k.Kid == "" {
			continue // skip unusable keys rather than fail the whole set
		}
		parsed[k.Kid] = pub
	}
	j.mu.Lock()
	j.keys = parsed
	j.lastLoad = time.Now()
	j.mu.Unlock()
	return nil
}

// jwk is the subset of a JSON Web Key we verify with (RSA and EC public keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // RSA modulus
	E   string `json:"e"` // RSA exponent
	Crv string `json:"crv"`
	X   string `json:"x"` // EC
	Y   string `json:"y"`
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported crv %q", crv)
	}
}

func b64uint(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: http %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
