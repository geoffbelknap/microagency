package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"microagency/internal/mcp"
)

const externalIssuerKid = "external-test-key"

// newExternalIssuer runs a minimal external authorization server: OIDC
// discovery plus a JWKS for one generated ES256 key, the way a real issuer
// would serve them.
func newExternalIssuer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": ts.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "EC", "crv": "P-256", "kid": externalIssuerKid, "alg": "ES256", "use": "sig",
				"x": b64(pub.X.FillBytes(make([]byte, 32))),
				"y": b64(pub.Y.FillBytes(make([]byte, 32))),
			}},
		})
	})
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, key
}

// mintExternalToken signs an access token the way the external issuer would
// for a client that requested the given resource indicator (RFC 8707).
func mintExternalToken(t *testing.T, key *ecdsa.PrivateKey, issuer, aud string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuer, "aud": aud, "sub": "alice", "scope": "mcp",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = externalIssuerKid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// discoverAdvertisedResource does what a real MCP client does: hit /mcp
// unauthenticated, follow the WWW-Authenticate resource_metadata pointer, and
// read the advertised resource identifier from the RFC 9728 document.
func discoverAdvertisedResource(t *testing.T, mux *http.ServeMux) (resource string, issuers []string) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp = %d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	_, rest, ok := strings.Cut(challenge, `resource_metadata="`)
	if !ok {
		t.Fatalf("401 challenge %q carries no resource_metadata pointer", challenge)
	}
	metadataURL, _, ok := strings.Cut(rest, `"`)
	if !ok {
		t.Fatalf("unterminated resource_metadata in challenge %q", challenge)
	}
	u, err := url.Parse(metadataURL)
	if err != nil {
		t.Fatalf("resource_metadata %q: %v", metadataURL, err)
	}
	metaRec := httptest.NewRecorder()
	mux.ServeHTTP(metaRec, httptest.NewRequest(http.MethodGet, u.Path, nil))
	if metaRec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", u.Path, metaRec.Code)
	}
	var metadata struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(metaRec.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata.Resource, metadata.AuthorizationServers
}

// TestTunnelExternalIssuerAdvertisedResourceValidates asserts the contract a
// discovering client depends on: a token minted for exactly the resource the
// RFC 9728 metadata advertises authenticates /mcp, and a token for any other
// audience does not. Before this contract held, the tunneled external-issuer
// mode advertised the public /mcp URL while validating a different audience,
// so every client that followed discovery got a 401.
func TestTunnelExternalIssuerAdvertisedResourceValidates(t *testing.T) {
	issuer, key := newExternalIssuer(t)
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "cloudflare",
		publicURL: "https://gateway.example", issuer: issuer.URL,
	}
	mcpMux, _, mode, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "oauth-external" {
		t.Fatalf("mode = %q, want oauth-external", mode)
	}

	resource, issuers := discoverAdvertisedResource(t, mcpMux)
	if resource != "https://gateway.example/mcp" {
		t.Fatalf("advertised resource = %q, want the public /mcp URL", resource)
	}
	if len(issuers) != 1 || issuers[0] != issuer.URL {
		t.Fatalf("advertised authorization servers = %v, want [%s]", issuers, issuer.URL)
	}

	// The token a discovering client obtains — audience exactly as advertised.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mintExternalToken(t, key, issuer.URL, resource))
	mcpMux.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("token minted for the advertised resource did not authenticate /mcp")
	}

	// Any other audience keeps failing: the replay defense is intact.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mintExternalToken(t, key, issuer.URL, "microagency"))
	mcpMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token for a different audience = %d, want 401", rec.Code)
	}
}

// TestTunnelExternalIssuerExplicitAudienceIsAdvertised asserts the override
// case stays self-consistent: an explicit --audience changes the validated
// audience and the advertised resource together.
func TestTunnelExternalIssuerExplicitAudienceIsAdvertised(t *testing.T) {
	issuer, key := newExternalIssuer(t)
	srv := testServer(t, "127.0.0.1:8766")
	cfg := httpConfig{
		addr: "127.0.0.1:8765", tunnel: "ngrok",
		publicURL: "https://gateway.example", issuer: issuer.URL,
		audience: "urn:example:mcp",
	}
	mcpMux, _, _, _, err := buildMuxes(srv, cfg, mcp.OperatorAuth{LegacyToken: "op-tok"})
	if err != nil {
		t.Fatal(err)
	}

	resource, _ := discoverAdvertisedResource(t, mcpMux)
	if resource != "urn:example:mcp" {
		t.Fatalf("advertised resource = %q, want the explicit audience", resource)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mintExternalToken(t, key, issuer.URL, resource))
	mcpMux.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("token minted for the advertised explicit audience did not authenticate /mcp")
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mintExternalToken(t, key, issuer.URL, "https://gateway.example/mcp"))
	mcpMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token for the unadvertised URL audience = %d, want 401", rec.Code)
	}
}
