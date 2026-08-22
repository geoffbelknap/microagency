package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrHostedDomainRefused reports a fully validated sign-in from an account
// outside the required hosted domain. The identity is real; the policy refuses
// it. Callers show a policy message rather than a validation error.
var ErrHostedDomainRefused = errors.New("account is not in the required hosted domain")

// This is SSO federation for the built-in authorization server: the gateway
// stays the AS toward MCP clients (dynamic registration, PKCE, token minting
// are unchanged), and only the human-authentication step is delegated to an
// upstream OIDC identity provider. Delegating the whole AS role directly to a
// provider like Google does not work for MCP clients — its access tokens are
// opaque to a third-party resource server, ID tokens are audience-bound to one
// client, and there is no open dynamic client registration — so the provider
// authenticates the person and the gateway mints the tokens.

// FederationConfig configures delegation of the human-authentication step to
// an upstream OIDC identity provider.
type FederationConfig struct {
	// Issuer is the provider's OIDC issuer URL, e.g. https://accounts.google.com.
	Issuer string
	// ClientID is the OAuth client the operator registered at the provider for
	// this gateway.
	ClientID string
	// ClientSecret authenticates the gateway at the provider's token endpoint.
	// The caller retrieves it from the secret store; it never appears in argv.
	ClientSecret string
	// HostedDomain, when set, requires the ID token's `hd` claim to equal it.
	// Enforced server-side on every sign-in; an account outside the domain is
	// refused before any gateway token exists.
	HostedDomain string
	// HTTPClient is used for discovery, JWKS fetches, and the code exchange.
	// nil means http.DefaultClient.
	HTTPClient *http.Client
}

// Federation is a discovered, ready-to-use identity provider binding.
type Federation struct {
	cfg                   FederationConfig
	authorizationEndpoint string
	tokenEndpoint         string
	keys                  *JWKSKeySet
}

// FederatedIdentity is the validated outcome of one provider sign-in.
type FederatedIdentity struct {
	// Subject is the provider's stable `sub` claim — the principal identity.
	Subject string
	// Email is the provider-verified email address, empty unless the ID token
	// carried email_verified=true. Display and future per-user delegation use
	// it; identity comparisons never do.
	Email string
	// HostedDomain is the ID token's `hd` claim, if any.
	HostedDomain string
}

// DiscoverFederation resolves the provider's endpoints from its OIDC discovery
// document and prepares JWKS-based ID-token validation. The document's issuer
// must match the configured issuer (fail-closed), and every endpoint must be
// HTTPS or loopback HTTP.
func DiscoverFederation(ctx context.Context, cfg FederationConfig) (*Federation, error) {
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("sso federation needs an issuer and a client id")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, fmt.Errorf("sso federation needs the provider client secret")
	}
	if err := checkFederationEndpoint("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	meta := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	if err := getJSON(ctx, hc, meta, &doc); err != nil {
		return nil, fmt.Errorf("sso issuer discovery: %w", err)
	}
	if !sameIssuer(doc.Issuer, cfg.Issuer) {
		return nil, fmt.Errorf("sso issuer discovery: document issuer %q does not match configured issuer %q", doc.Issuer, cfg.Issuer)
	}
	for name, u := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		if err := checkFederationEndpoint(name, u); err != nil {
			return nil, err
		}
	}
	return &Federation{
		cfg:                   cfg,
		authorizationEndpoint: doc.AuthorizationEndpoint,
		tokenEndpoint:         doc.TokenEndpoint,
		keys:                  &JWKSKeySet{URL: doc.JWKSURI, Client: hc},
	}, nil
}

// checkFederationEndpoint requires an absolute HTTPS URL, or loopback HTTP for
// a local test provider. The code exchange sends the client secret to the
// token endpoint, so a plaintext non-loopback URL is refused outright.
func checkFederationEndpoint(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("sso %s %q must be an absolute URL", name, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("sso %s %q must use HTTPS (plain HTTP is allowed only on loopback)", name, raw)
	default:
		return fmt.Errorf("sso %s %q must use HTTPS", name, raw)
	}
}

// Issuer returns the provider's issuer URL.
func (f *Federation) Issuer() string { return f.cfg.Issuer }

// HostedDomain returns the required `hd` claim, or "" when not enforced.
func (f *Federation) HostedDomain() string { return f.cfg.HostedDomain }

// AuthorizeURL builds the provider authorization request for one pending
// gateway authorization: state carries the single-use request ID that binds
// the provider round-trip to the pending grant, nonce binds the ID token to
// it, and PKCE binds the code to this server's exchange.
func (f *Federation) AuthorizeURL(redirectURI, state, nonce, codeChallenge string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	if f.cfg.HostedDomain != "" {
		// Provider-side account picker hint only; the hd claim is enforced
		// server-side in Exchange regardless.
		q.Set("hd", f.cfg.HostedDomain)
	}
	sep := "?"
	if strings.Contains(f.authorizationEndpoint, "?") {
		sep = "&"
	}
	return f.authorizationEndpoint + sep + q.Encode()
}

// Exchange swaps the provider's authorization code for tokens and validates
// the ID token: provider signature via JWKS, issuer, audience = our client id,
// expiry, and the nonce bound to the pending request. When a hosted domain is
// configured, an ID token without that exact `hd` claim is refused — no
// gateway token is minted for it.
func (f *Federation) Exchange(ctx context.Context, code, redirectURI, codeVerifier, nonce string) (*FederatedIdentity, error) {
	hc := f.cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {f.cfg.ClientID},
		"client_secret": {f.cfg.ClientSecret},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sso token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso token exchange: provider returned http %d", resp.StatusCode)
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("sso token exchange: %w", err)
	}
	if out.IDToken == "" {
		return nil, fmt.Errorf("sso token exchange: provider returned no id_token")
	}
	return f.validateIDToken(ctx, out.IDToken, nonce)
}

func (f *Federation) validateIDToken(ctx context.Context, raw, nonce string) (*FederatedIdentity, error) {
	keyFunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return f.keys.Key(ctx, kid)
	}
	parsed, err := jwt.Parse(raw, keyFunc,
		jwt.WithValidMethods(asymmetricAlgs),
		jwt.WithIssuer(f.cfg.Issuer),
		jwt.WithAudience(f.cfg.ClientID),
		jwt.WithLeeway(30*time.Second),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("sso id token invalid: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("sso id token invalid: unreadable claims")
	}
	gotNonce, _ := claims["nonce"].(string)
	if nonce == "" || gotNonce != nonce {
		return nil, fmt.Errorf("sso id token invalid: nonce mismatch")
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return nil, fmt.Errorf("sso id token invalid: missing sub")
	}
	hd, _ := claims["hd"].(string)
	if f.cfg.HostedDomain != "" && hd != f.cfg.HostedDomain {
		return nil, fmt.Errorf("sso sign-in for %q: %w", f.cfg.HostedDomain, ErrHostedDomainRefused)
	}
	id := &FederatedIdentity{Subject: sub, HostedDomain: hd}
	if verified, _ := claims["email_verified"].(bool); verified {
		id.Email, _ = claims["email"].(string)
	}
	return id, nil
}
