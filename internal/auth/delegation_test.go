package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testServiceAccountKey builds a provider-shaped service-account key JSON
// document and returns it with its public key for assertion verification.
func testServiceAccountKey(t *testing.T, tokenURI string) ([]byte, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	doc, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   "delegate@project.example",
		"private_key":    string(pemKey),
		"private_key_id": "sa-key-1",
		"token_uri":      tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc, &priv.PublicKey
}

// stubTokenEndpoint is a provider token endpoint that VALIDATES each
// assertion — signature against the service account's public key, issuer,
// audience, subject presence, scope — and returns a short-lived token that
// embeds the delegated subject, so callers can prove which identity each
// derived token acts as.
type stubTokenEndpoint struct {
	ts  *httptest.Server
	pub *rsa.PublicKey

	mu         sync.Mutex
	exchanges  int
	lastScope  string
	lastSub    string
	wantIssuer string
	expiresIn  int
	gate       chan struct{} // when set, each exchange blocks until it closes
}

func newStubTokenEndpoint(t *testing.T) *stubTokenEndpoint {
	t.Helper()
	p := &stubTokenEndpoint{wantIssuer: "delegate@project.example", expiresIn: 3600}
	p.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		gate := p.gate
		p.mu.Unlock()
		if gate != nil {
			<-gate
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(r.Form.Get("assertion"), claims,
			func(*jwt.Token) (any, error) { return p.pub, nil },
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer(p.wantIssuer),
			jwt.WithAudience(p.ts.URL),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			http.Error(w, "invalid assertion: "+err.Error(), http.StatusUnauthorized)
			return
		}
		sub, _ := claims["sub"].(string)
		scope, _ := claims["scope"].(string)
		if sub == "" || scope == "" {
			http.Error(w, "assertion missing sub or scope", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.exchanges++
		n := p.exchanges
		p.lastSub, p.lastScope = sub, scope
		expires := p.expiresIn
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("derived-for-%s-%d", sub, n),
			"token_type":   "Bearer",
			"expires_in":   expires,
		})
	}))
	t.Cleanup(p.ts.Close)
	return p
}

func newTestSource(t *testing.T, p *stubTokenEndpoint, scopes ...string) *DelegatedTokenSource {
	t.Helper()
	doc, pub := testServiceAccountKey(t, p.ts.URL)
	p.pub = pub
	sa, err := ParseServiceAccountKey(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) == 0 {
		scopes = []string{"https://provider.example/auth/data.readonly"}
	}
	src, err := NewDelegatedTokenSource(DelegationConfig{Scopes: scopes}, sa)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// A derived token acts as the delegated subject: the provider validates the
// assertion's signature, issuer, audience, and scope, and the token it
// returns is bound to the asserted sub. Distinct callers derive DISTINCT
// tokens; one caller's repeat within expiry is served from cache.
func TestDelegatedTokenPerCaller(t *testing.T) {
	p := newStubTokenEndpoint(t)
	src := newTestSource(t, p)
	ctx := context.Background()

	alice1, err := src.Token(ctx, "iss#alice", "alice@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(alice1, "alice@corp.example") {
		t.Fatalf("token %q is not bound to alice's identity", alice1)
	}
	bob, err := src.Token(ctx, "iss#bob", "bob@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bob, "bob@corp.example") {
		t.Fatalf("token %q is not bound to bob's identity", bob)
	}
	if alice1 == bob {
		t.Fatal("two callers received one derived token")
	}
	alice2, err := src.Token(ctx, "iss#alice", "alice@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if alice2 != alice1 {
		t.Fatalf("cache miss within expiry: %q vs %q", alice1, alice2)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exchanges != 2 {
		t.Fatalf("provider saw %d exchanges, want 2 (alice cached)", p.exchanges)
	}
	if p.lastScope != "https://provider.example/auth/data.readonly" {
		t.Fatalf("assertion scope = %q", p.lastScope)
	}
}

// An expired cache entry is re-derived rather than attached.
func TestDelegatedTokenExpiryRederives(t *testing.T) {
	p := newStubTokenEndpoint(t)
	p.expiresIn = 1 // expires inside the skew window → immediately stale
	src := newTestSource(t, p)
	ctx := context.Background()
	if _, err := src.Token(ctx, "iss#alice", "alice@corp.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Token(ctx, "iss#alice", "alice@corp.example"); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exchanges != 2 {
		t.Fatalf("provider saw %d exchanges, want 2 (stale entry re-derived)", p.exchanges)
	}
}

// Concurrent derivations for one caller share a single exchange.
func TestDelegatedTokenSingleFlight(t *testing.T) {
	p := newStubTokenEndpoint(t)
	release := make(chan struct{})
	p.mu.Lock()
	p.gate = release
	p.mu.Unlock()
	src := newTestSource(t, p)
	ctx := context.Background()

	var wg sync.WaitGroup
	tokens := make([]string, 8)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], _ = src.Token(ctx, "iss#alice", "alice@corp.example")
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let the goroutines pile onto the in-flight call
	close(release)
	wg.Wait()
	for _, tok := range tokens {
		if tok == "" || tok != tokens[0] {
			t.Fatalf("concurrent callers diverged: %v", tokens)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exchanges != 1 {
		t.Fatalf("provider saw %d exchanges, want 1 (single-flight)", p.exchanges)
	}
}

// DropCache forces the next call to derive fresh tokens.
func TestDelegatedTokenDropCache(t *testing.T) {
	p := newStubTokenEndpoint(t)
	src := newTestSource(t, p)
	ctx := context.Background()
	first, err := src.Token(ctx, "iss#alice", "alice@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	src.DropCache()
	second, err := src.Token(ctx, "iss#alice", "alice@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("token survived DropCache")
	}
}

// A provider refusal surfaces as an error, never as an empty bearer.
func TestDelegatedTokenProviderRefusal(t *testing.T) {
	p := newStubTokenEndpoint(t)
	p.wantIssuer = "someone-else@project.example" // provider-side policy mismatch
	src := newTestSource(t, p)
	if _, err := src.Token(context.Background(), "iss#alice", "alice@corp.example"); err == nil {
		t.Fatal("refused exchange returned no error")
	}
}

// Fail-closed inputs: no subject or caller identity means no token.
func TestDelegatedTokenRequiresIdentity(t *testing.T) {
	p := newStubTokenEndpoint(t)
	src := newTestSource(t, p)
	if _, err := src.Token(context.Background(), "iss#alice", ""); err == nil {
		t.Fatal("empty subject derived a token")
	}
	if _, err := src.Token(context.Background(), "", "alice@corp.example"); err == nil {
		t.Fatal("empty caller key derived a token")
	}
}

func TestParseServiceAccountKeyRefusesWrongDocuments(t *testing.T) {
	if _, err := ParseServiceAccountKey([]byte(`{"type":"authorized_user"}`)); err == nil {
		t.Fatal("non-service-account document accepted")
	}
	if _, err := ParseServiceAccountKey([]byte(`not json`)); err == nil {
		t.Fatal("non-JSON accepted")
	}
	if _, err := ParseServiceAccountKey([]byte(`{"type":"service_account","client_email":"a@b","private_key":"not pem"}`)); err == nil {
		t.Fatal("non-PEM key accepted")
	}
}

func TestNewDelegatedTokenSourceValidation(t *testing.T) {
	doc, _ := testServiceAccountKey(t, "https://provider.example/token")
	sa, err := ParseServiceAccountKey(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDelegatedTokenSource(DelegationConfig{Scopes: nil, TokenEndpoint: "https://provider.example/token"}, sa); err == nil {
		t.Fatal("empty scopes accepted")
	}
	if _, err := NewDelegatedTokenSource(DelegationConfig{Scopes: []string{"s"}, TokenEndpoint: "http://provider.example/token"}, sa); err == nil {
		t.Fatal("plaintext non-loopback token endpoint accepted")
	}
	if _, err := NewDelegatedTokenSource(DelegationConfig{Scopes: []string{"s"}, ClientEmail: "other@project.example"}, sa); err == nil {
		t.Fatal("client email disagreeing with the key accepted")
	}
	src, err := NewDelegatedTokenSource(DelegationConfig{Scopes: []string{"s"}}, sa)
	if err != nil {
		t.Fatal(err)
	}
	if src.ClientEmail() != "delegate@project.example" || src.TokenEndpoint() != "https://provider.example/token" {
		t.Fatalf("defaults not filled from the key: %q %q", src.ClientEmail(), src.TokenEndpoint())
	}
}
