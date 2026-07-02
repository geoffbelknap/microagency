package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This is the OAuth 2.1 CLIENT side: it lets microagency obtain a short-lived,
// refreshable token from an upstream MCP's authorization server (via Dynamic
// Client Registration + authorization-code + PKCE) instead of holding a static
// Personal Access Token. microagency holds the token cred-blind and never exposes
// it to the agent. (The server side — microagency's own AS — is in authserver.go.)

// ASMetadata is the subset of RFC 8414 authorization-server metadata we use.
type ASMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"` // advertised scopes, for an operator scope picker
}

// DiscoverAS finds the authorization server protecting an MCP resource: fetch the
// resource's protected-resource metadata (RFC 9728), then the AS metadata
// (RFC 8414). resourceMetadataURL is the absolute /.well-known/oauth-protected-
// resource URL (from the upstream's 401 WWW-Authenticate, or derived from its URL).
func DiscoverAS(ctx context.Context, hc *http.Client, resourceMetadataURL string) (*ASMetadata, error) {
	var pr struct {
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	if err := getJSON(ctx, hc, resourceMetadataURL, &pr); err != nil {
		return nil, fmt.Errorf("protected-resource metadata: %w", err)
	}
	if len(pr.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization_servers in resource metadata")
	}
	meta, err := discoverASMetadata(ctx, hc, pr.AuthorizationServers[0])
	if err != nil {
		return nil, err
	}
	if len(meta.ScopesSupported) == 0 {
		meta.ScopesSupported = pr.ScopesSupported // fall back to the resource's advertised scopes
	}
	return meta, nil
}

// discoverASMetadata fetches an authorization server's RFC 8414 metadata, trying
// each well-known location in spec-preferred order until one yields a document
// with the endpoints we need. The first non-404 with valid endpoints wins.
func discoverASMetadata(ctx context.Context, hc *http.Client, issuer string) (*ASMetadata, error) {
	var lastErr error
	for _, candidate := range asMetadataURLs(issuer) {
		var m ASMetadata
		if err := getJSON(ctx, hc, candidate, &m); err != nil {
			lastErr = err
			continue
		}
		if m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" {
			lastErr = fmt.Errorf("%s: metadata missing authorization/token endpoints", candidate)
			continue
		}
		return &m, nil
	}
	return nil, fmt.Errorf("authorization-server metadata: %w", lastErr)
}

// asMetadataURLs returns the candidate metadata URLs for an issuer, in the order
// an MCP client should try them. RFC 8414 §3.1 INSERTS the well-known segment
// after the host and keeps the issuer's path suffix — appending it after the path
// (the old behavior) 404s on any issuer with a path, e.g. .../mcp/trading. When
// the issuer has no path, insert and append coincide. We also try the OpenID
// Connect discovery locations, since some providers only serve those.
func asMetadataURLs(issuer string) []string {
	issuer = strings.TrimRight(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return []string{issuer + "/.well-known/oauth-authorization-server"}
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimRight(u.Path, "/") // "" for a root issuer, else "/mcp/trading"
	if path == "" {
		return []string{
			origin + "/.well-known/oauth-authorization-server",
			origin + "/.well-known/openid-configuration",
		}
	}
	return []string{
		origin + "/.well-known/oauth-authorization-server" + path, // RFC 8414 path insertion (correct)
		origin + "/.well-known/openid-configuration" + path,       // OIDC path insertion
		issuer + "/.well-known/openid-configuration",              // OIDC path append (legacy)
		issuer + "/.well-known/oauth-authorization-server",        // append (some servers; old behavior)
	}
}

// RegisterClient performs Dynamic Client Registration (RFC 7591) and returns the
// issued client_id. redirectURI is microagency's loopback callback. We register as
// a public client (PKCE, no secret).
// We prefer PKCE (public client), but some authorization servers (e.g. Supabase)
// always issue a confidential client and require its client_secret at the token
// endpoint — so we capture and use whatever they return.
func RegisterClient(ctx context.Context, hc *http.Client, registrationEndpoint, redirectURI, clientName string) (clientID, clientSecret string, err error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":   clientName,
		"redirect_uris": []string{redirectURI},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("dynamic client registration: http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.ClientID == "" {
		return "", "", fmt.Errorf("dynamic client registration: no client_id returned")
	}
	return out.ClientID, out.ClientSecret, nil
}

// PKCE is a code verifier and its S256 challenge (RFC 7636).
type PKCE struct{ Verifier, Challenge string }

// NewPKCE generates a PKCE pair (43-char base64url verifier).
func NewPKCE() PKCE {
	v := randToken(32)
	return PKCE{Verifier: v, Challenge: pkceS256(v)}
}

// AuthorizeURL builds the authorization request the operator's browser opens to
// log in at the upstream and consent.
func AuthorizeURL(meta *ASMetadata, clientID, redirectURI string, p PKCE, scope, state string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + q.Encode()
}

// UpstreamToken is an OAuth token microagency holds for an upstream — short-lived,
// refreshable, and never exposed to the agent.
type UpstreamToken struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time

	tokenEndpoint string
	clientID      string
	clientSecret  string
}

// ExchangeCode swaps an authorization code (+ PKCE verifier) for tokens.
func ExchangeCode(ctx context.Context, hc *http.Client, meta *ASMetadata, clientID, clientSecret, redirectURI, code string, p PKCE) (*UpstreamToken, error) {
	return postToken(ctx, hc, meta.TokenEndpoint, clientID, clientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {p.Verifier},
	})
}

// Expired reports whether the access token is past (or within 30s of) expiry.
func (t *UpstreamToken) Expired() bool {
	return !t.Expiry.IsZero() && time.Now().After(t.Expiry.Add(-30*time.Second))
}

// Refresh obtains a fresh access token using the refresh token, mutating t.
func (t *UpstreamToken) Refresh(ctx context.Context, hc *http.Client) error {
	if t.RefreshToken == "" {
		return fmt.Errorf("no refresh token")
	}
	nt, err := postToken(ctx, hc, t.tokenEndpoint, t.clientID, t.clientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
		"client_id":     {t.clientID},
	})
	if err != nil {
		return err
	}
	t.AccessToken, t.Expiry = nt.AccessToken, nt.Expiry
	if nt.RefreshToken != "" {
		t.RefreshToken = nt.RefreshToken // honor rotation
	}
	return nil
}

// RefreshingBearer returns a thread-safe bearer source that yields the access
// token, refreshing it first if it's missing or expired. After a refresh it calls
// onRefresh (if non-nil) so the rotated token can be persisted. Wire it into
// gateway.Upstream.Bearer so every upstream call uses a fresh, cred-blind token.
func RefreshingBearer(tok *UpstreamToken, hc *http.Client, onRefresh func(*UpstreamToken)) func(context.Context) (string, error) {
	var mu sync.Mutex
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if tok.AccessToken == "" || tok.Expired() {
			if err := tok.Refresh(ctx, hc); err != nil {
				return "", err
			}
			if onRefresh != nil {
				onRefresh(tok)
			}
		}
		return tok.AccessToken, nil
	}
}

// TokenRecord is the persistable form of an UpstreamToken: the refresh token,
// what's needed to refresh it, and the current access token + expiry. Persisting
// the access token is deliberate. Without it, every restart reconnects with no
// access token and is forced to refresh, and each refresh rotates the refresh
// token at providers that rotate (Notion, Google, …). Under frequent restarts
// that spends a rotation on every start and widens the window where a process
// dies after the provider rotated but before we persisted the new token — which
// strands the credential and surfaces as "refresh token reuse detected". Keeping
// a valid access token lets a restart reconnect without refreshing at all. It
// lives in the same store as the (more sensitive) refresh token, so it adds no
// new exposure class.
type TokenRecord struct {
	RefreshToken  string    `json:"refresh_token"`
	TokenEndpoint string    `json:"token_endpoint"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	AccessToken   string    `json:"access_token,omitempty"`
	Expiry        time.Time `json:"expiry,omitempty"`
}

// Record returns the persistable form of t.
func (t *UpstreamToken) Record() TokenRecord {
	return TokenRecord{
		RefreshToken: t.RefreshToken, TokenEndpoint: t.tokenEndpoint,
		ClientID: t.clientID, ClientSecret: t.clientSecret,
		AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
}

// TokenFromRecord rebuilds an UpstreamToken from a persisted record. If the record
// carries a still-valid access token, RefreshingBearer uses it as-is and does not
// refresh (so a restart doesn't rotate the refresh token); once it expires, the
// next call refreshes normally.
func TokenFromRecord(r TokenRecord) *UpstreamToken {
	return &UpstreamToken{
		AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, Expiry: r.Expiry,
		tokenEndpoint: r.TokenEndpoint, clientID: r.ClientID, clientSecret: r.ClientSecret,
	}
}

func postToken(ctx context.Context, hc *http.Client, tokenEndpoint, clientID, clientSecret string, form url.Values) (*UpstreamToken, error) {
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint: http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint: no access_token")
	}
	t := &UpstreamToken{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, tokenEndpoint: tokenEndpoint, clientID: clientID, clientSecret: clientSecret}
	if out.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return t, nil
}
