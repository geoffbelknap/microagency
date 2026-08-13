// Package auth contains microagency's OAuth 2.1 authorization- and resource-
// server components. The built-in single-user server issues audience-bound
// tokens only after local operator consent; shared deployments can instead
// validate tokens from an external issuer.
//
// The validator does the security-critical, bounded job — verify a JWT's
// signature against the issuer's keys, and its issuer, audience, and expiry —
// using a vetted JWT library with only asymmetric algorithms permitted (no
// HMAC, no `none`, no alg-confusion).
package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// asymmetricAlgs is the closed set of permitted signing algorithms. Symmetric
// (HS*) and `none` are excluded by construction, which is the standard defense
// against algorithm-confusion attacks against a JWKS-fed verifier.
var asymmetricAlgs = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
}

// KeySet resolves the public verification key for a token's `kid`. Production
// uses a JWKS-backed implementation that fetches the issuer's keys; tests inject
// a static key.
type KeySet interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// Principal is the authenticated caller extracted from a validated token. The
// Subject is the user identity — it becomes the scope key, the audit subject,
// and the join to that user's connected upstreams.
type Principal struct {
	Subject string
	// Campaign is an immutable correlation/authority claim from the signed
	// access token. The MCP request body cannot select or widen it.
	Campaign string
	Scopes   []string
	Issuer   string
	Expiry   time.Time
}

// HasScope reports whether the principal was granted scope s.
func (p *Principal) HasScope(s string) bool {
	for _, have := range p.Scopes {
		if have == s {
			return true
		}
	}
	return false
}

// ResourceServer validates JWT access tokens minted for this resource.
type ResourceServer struct {
	// Issuer is the expected `iss` (the authorization server).
	Issuer string
	// Audience is the expected `aud` — this resource's identifier. Binding the
	// token to our audience (RFC 8707) is what stops a token minted for another
	// resource from being replayed here.
	Audience string
	// Keys resolves the issuer's signing keys.
	Keys KeySet
	// Leeway tolerates small clock skew on exp/nbf/iat. Default 30s.
	Leeway time.Duration
	// Revocations is consulted after signature, issuer, audience, and expiry
	// validation. Built-in OAuth supplies the same list used by its token and
	// revocation endpoints; external issuers normally leave it nil.
	Revocations *RevocationList
	// RequireTokenID rejects a token without jti. Built-in OAuth enables this so
	// every access token can be revoked; external issuers may omit jti.
	RequireTokenID bool
}

// ErrUnauthenticated is returned (wrapped) for any token that fails validation,
// so callers can map every failure mode to a single 401 without leaking which
// check failed.
var ErrUnauthenticated = errors.New("unauthenticated")

// Validate parses and verifies a raw bearer token and returns the Principal.
// Every failure wraps ErrUnauthenticated.
func (rs *ResourceServer) Validate(ctx context.Context, raw string) (*Principal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty token", ErrUnauthenticated)
	}
	if rs.Keys == nil {
		return nil, fmt.Errorf("%w: no key set configured", ErrUnauthenticated)
	}
	leeway := rs.Leeway
	if leeway <= 0 {
		leeway = 30 * time.Second
	}

	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return rs.Keys.Key(ctx, kid)
	}
	parsed, err := jwt.Parse(raw, keyFunc,
		jwt.WithValidMethods(asymmetricAlgs),
		jwt.WithIssuer(rs.Issuer),
		jwt.WithAudience(rs.Audience),
		jwt.WithLeeway(leeway),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("%w: invalid claims", ErrUnauthenticated)
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return nil, fmt.Errorf("%w: token missing sub", ErrUnauthenticated)
	}
	jti, _ := claims["jti"].(string)
	if rs.RequireTokenID && strings.TrimSpace(jti) == "" {
		return nil, fmt.Errorf("%w: token missing jti", ErrUnauthenticated)
	}
	if rs.Revocations != nil && rs.Revocations.IsRevoked(jti) {
		return nil, fmt.Errorf("%w: token revoked", ErrUnauthenticated)
	}

	p := &Principal{Subject: sub, Issuer: rs.Issuer, Scopes: parseScopes(claims)}
	if campaign, _ := claims["campaign"].(string); strings.TrimSpace(campaign) != "" {
		p.Campaign = strings.TrimSpace(campaign)
	} else if campaign, _ := claims["campaign_id"].(string); strings.TrimSpace(campaign) != "" {
		p.Campaign = strings.TrimSpace(campaign)
	}
	if exp, e := claims.GetExpirationTime(); e == nil && exp != nil {
		p.Expiry = exp.Time
	}
	return p, nil
}

// parseScopes reads OAuth scopes: the space-delimited `scope` string (RFC 6749)
// or an `scp` array (some issuers).
func parseScopes(claims jwt.MapClaims) []string {
	if s, ok := claims["scope"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.Fields(s)
	}
	if arr, ok := claims["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
