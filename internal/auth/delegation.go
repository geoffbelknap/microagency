package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This is per-caller credential delegation for a shared upstream connection:
// the gateway holds ONE provider credential (a service-account key) and, per
// call, derives a short-lived access token that acts as the CALLING user at
// the provider. The invariant the whole mechanism exists for: the gateway
// reaches the provider as the mapped per-user identity, so the provider's own
// ACLs trim what comes back — it never queries broadly under a powerful
// credential and filters afterwards. The profile implemented is the RFC 7523
// JWT-bearer authorization grant as Google uses it for domain-wide delegation:
// a signed assertion (iss = the service account, sub = the user being acted
// for, scope = the connection's configured scopes, aud = the token endpoint)
// exchanged for a user-scoped access token.

// delegationAssertionTTL bounds the signed assertion's validity. Short: the
// assertion is minted immediately before its one exchange.
const delegationAssertionTTL = 5 * time.Minute

// delegationExpirySkew derives a fresh token this long before the cached one
// expires, so a token is never attached moments before it dies in flight.
const delegationExpirySkew = 30 * time.Second

// maxDelegatedTokens bounds the per-caller derived-token cache. When the cap
// is reached an arbitrary other entry is evicted; that caller simply derives
// again on its next call.
const maxDelegatedTokens = 512

// ServiceAccountKey is the parsed form of a provider service-account key file
// (the JSON document the provider issues). Only the fields delegation needs
// are read; the raw document stays in the secret store.
type ServiceAccountKey struct {
	ClientEmail  string // the service account's identity (assertion issuer)
	TokenURI     string // the provider token endpoint the key names, if any
	PrivateKeyID string // key id stamped into the assertion header
	Key          *rsa.PrivateKey
}

// ParseServiceAccountKey parses a provider service-account key JSON document
// (type "service_account": client_email + PEM private_key, optionally
// private_key_id and token_uri). Anything else is refused — a wrong file
// pasted here must fail loudly, not sign garbage.
func ParseServiceAccountKey(raw []byte) (*ServiceAccountKey, error) {
	var doc struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("service account key: not a JSON key file: %w", err)
	}
	if doc.Type != "service_account" {
		return nil, fmt.Errorf("service account key: document type %q is not \"service_account\"", doc.Type)
	}
	if strings.TrimSpace(doc.ClientEmail) == "" {
		return nil, errors.New("service account key: missing client_email")
	}
	block, _ := pem.Decode([]byte(doc.PrivateKey))
	if block == nil {
		return nil, errors.New("service account key: private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service account key: private_key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("service account key: private_key is %T, not RSA", parsed)
	}
	return &ServiceAccountKey{
		ClientEmail:  doc.ClientEmail,
		TokenURI:     doc.TokenURI,
		PrivateKeyID: doc.PrivateKeyID,
		Key:          rsaKey,
	}, nil
}

// DelegationConfig is the non-secret configuration of one delegated
// connection: which service account signs, where assertions are exchanged,
// and which scopes every derived token carries.
type DelegationConfig struct {
	// ClientEmail is the service account's identity — the assertion's issuer.
	ClientEmail string
	// TokenEndpoint receives the assertion exchange and is the assertion's
	// audience. HTTPS, or loopback HTTP for a local test provider.
	TokenEndpoint string
	// Scopes are the OAuth scopes every derived token is limited to.
	Scopes []string
	// HTTPClient performs the exchange. The token endpoint is
	// operator-configured infrastructure (like the SSO issuer), not an
	// untrusted upstream URL. nil means http.DefaultClient.
	HTTPClient *http.Client
}

// CheckDelegationEndpoint validates a delegation token endpoint: an absolute
// HTTPS URL, or loopback HTTP for a local test provider. The exchange posts a
// signed assertion there, so a plaintext non-loopback endpoint is refused.
func CheckDelegationEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("delegation token endpoint %q must be an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("delegation token endpoint %q must use HTTPS (plain HTTP is allowed only on loopback)", raw)
	default:
		return fmt.Errorf("delegation token endpoint %q must use HTTPS", raw)
	}
}

// DelegatedTokenSource derives and caches per-caller access tokens for one
// delegated connection. Derived tokens are cached per (caller identity key,
// delegation subject, scopes) until shortly before expiry, and concurrent
// derivations for the same key share one exchange.
type DelegatedTokenSource struct {
	cfg   DelegationConfig
	key   *rsa.PrivateKey
	keyID string
	scope string // the joined scope string every assertion carries

	mu       sync.Mutex
	cache    map[string]delegatedToken
	inflight map[string]*delegationCall
}

type delegatedToken struct {
	token  string
	expiry time.Time
}

type delegationCall struct {
	done  chan struct{}
	token string
	err   error
}

// NewDelegatedTokenSource builds the token source for one connection from its
// non-secret config and the service-account key. Config fields left empty are
// filled from the key document; a non-empty ClientEmail must match the key's,
// so a rotated key cannot silently change the acting service account.
func NewDelegatedTokenSource(cfg DelegationConfig, sa *ServiceAccountKey) (*DelegatedTokenSource, error) {
	if sa == nil || sa.Key == nil {
		return nil, errors.New("delegation: a service account key is required")
	}
	if cfg.ClientEmail == "" {
		cfg.ClientEmail = sa.ClientEmail
	}
	if cfg.ClientEmail != sa.ClientEmail {
		return nil, fmt.Errorf("delegation: configured client email %q does not match the stored key's %q", cfg.ClientEmail, sa.ClientEmail)
	}
	if cfg.TokenEndpoint == "" {
		cfg.TokenEndpoint = sa.TokenURI
	}
	if err := CheckDelegationEndpoint(cfg.TokenEndpoint); err != nil {
		return nil, err
	}
	if len(cfg.Scopes) == 0 {
		return nil, errors.New("delegation: at least one scope is required — a derived token's authority must be explicit")
	}
	scopes := append([]string(nil), cfg.Scopes...)
	sort.Strings(scopes)
	return &DelegatedTokenSource{
		cfg: cfg, key: sa.Key, keyID: sa.PrivateKeyID,
		scope:    strings.Join(scopes, " "),
		cache:    map[string]delegatedToken{},
		inflight: map[string]*delegationCall{},
	}, nil
}

// ClientEmail returns the acting service account's identity.
func (d *DelegatedTokenSource) ClientEmail() string { return d.cfg.ClientEmail }

// TokenEndpoint returns the endpoint assertions are exchanged at.
func (d *DelegatedTokenSource) TokenEndpoint() string { return d.cfg.TokenEndpoint }

// Scopes returns the scopes every derived token carries.
func (d *DelegatedTokenSource) Scopes() []string { return append([]string(nil), d.cfg.Scopes...) }

// Token returns an access token acting as subject (the caller's
// provider-verified identity), deriving one if the cache holds no live token
// for (callerKey, subject, scopes). callerKey is the caller's canonical
// identity key; it partitions the cache so no derived token is ever attached
// to another principal's call, even if two principals mapped to one subject.
func (d *DelegatedTokenSource) Token(ctx context.Context, callerKey, subject string) (string, error) {
	if callerKey == "" || subject == "" {
		return "", errors.New("delegation: a caller identity and delegation subject are required")
	}
	key := callerKey + "\x00" + subject + "\x00" + d.scope

	d.mu.Lock()
	if cached, ok := d.cache[key]; ok && time.Now().Before(cached.expiry.Add(-delegationExpirySkew)) {
		d.mu.Unlock()
		return cached.token, nil
	}
	if call, ok := d.inflight[key]; ok { // single-flight: join the derivation in progress
		d.mu.Unlock()
		select {
		case <-call.done:
			return call.token, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	call := &delegationCall{done: make(chan struct{})}
	d.inflight[key] = call
	d.mu.Unlock()

	token, expiry, err := d.derive(ctx, subject)
	call.token, call.err = token, err
	d.mu.Lock()
	delete(d.inflight, key)
	if err == nil {
		d.roomForTokenLocked(key)
		d.cache[key] = delegatedToken{token: token, expiry: expiry}
	}
	d.mu.Unlock()
	close(call.done)
	return token, err
}

// DropCache discards every cached derived token. Called when the connection is
// disabled or revoked, so no derived credential outlives the decision inside
// the gateway. (Tokens already issued by the provider expire on their own
// short lifetime; the provider owns their revocation.)
func (d *DelegatedTokenSource) DropCache() {
	d.mu.Lock()
	d.cache = map[string]delegatedToken{}
	d.mu.Unlock()
}

// roomForTokenLocked makes room for a new cache entry under the
// maxDelegatedTokens bound by dropping an arbitrary other entry. Caller holds
// d.mu.
func (d *DelegatedTokenSource) roomForTokenLocked(key string) {
	if _, ok := d.cache[key]; ok || len(d.cache) < maxDelegatedTokens {
		return
	}
	for k := range d.cache {
		if k != key {
			delete(d.cache, k)
			return
		}
	}
}

// derive signs one assertion for subject and exchanges it. The assertion is
// the whole authorization: the provider verifies the signature against the
// service account's registered key and applies its own delegation policy for
// (service account, subject, scopes).
func (d *DelegatedTokenSource) derive(ctx context.Context, subject string) (string, time.Time, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   d.cfg.ClientEmail,
		"sub":   subject,
		"aud":   d.cfg.TokenEndpoint,
		"scope": d.scope,
		"iat":   now.Unix(),
		"exp":   now.Add(delegationAssertionTTL).Unix(),
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if d.keyID != "" {
		assertion.Header["kid"] = d.keyID
	}
	signed, err := assertion.SignedString(d.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("delegation: sign assertion: %w", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signed},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := d.cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("delegation: token exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("delegation: token exchange: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("delegation: token exchange: provider returned http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("delegation: token exchange: decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, errors.New("delegation: token exchange: provider returned no access_token")
	}
	expiry := now.Add(delegationAssertionTTL) // conservative default when the provider omits expires_in
	if out.ExpiresIn > 0 {
		expiry = now.Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return out.AccessToken, expiry, nil
}
