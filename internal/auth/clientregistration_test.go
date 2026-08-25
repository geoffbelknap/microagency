package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// boundedAS builds an authorization server with an explicit registration
// posture and returns it alongside its test server and the events it recorded.
func boundedAS(t *testing.T, mode RegistrationMode, limits RegistrationLimits) (*AuthServer, *httptest.Server, *[]RegistrationEvent, *sync.Mutex) {
	t.Helper()
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	as.SetClientRegistration(mode, limits)
	var mu sync.Mutex
	events := []RegistrationEvent{}
	as.SetRegistrationRecorder(func(e RegistrationEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	})
	mux := http.NewServeMux()
	as.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return as, ts, &events, &mu
}

func tryRegister(t *testing.T, ts *httptest.Server) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{testRedirect}, "client_name": "Cursor"})
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.ClientID
}

func outcomes(events *[]RegistrationEvent, mu *sync.Mutex) []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(*events))
	for _, e := range *events {
		out = append(out, e.Outcome)
	}
	return out
}

// The default posture still registers clients. Dynamic registration is how a
// remote MCP client connects without an operator provisioning it, so bounding
// it must not mean breaking it.
func TestBoundedRegistrationStillRegisters(t *testing.T) {
	_, ts, events, mu := boundedAS(t, RegistrationBounded, RegistrationLimits{})
	status, clientID := tryRegister(t, ts)
	if status != http.StatusCreated || clientID == "" {
		t.Fatalf("register = %d, client_id %q", status, clientID)
	}
	if got := outcomes(events, mu); len(got) != 1 || got[0] != RegistrationAccepted {
		t.Errorf("recorded %v, want one %q", got, RegistrationAccepted)
	}
}

// An operator who provisions clients can refuse registration entirely. The
// endpoint refuses, and the metadata stops advertising it so a client learns it
// must be provisioned rather than discovering it by being refused.
func TestRegistrationOffRefusesAndIsNotAdvertised(t *testing.T) {
	_, ts, events, mu := boundedAS(t, RegistrationOff, RegistrationLimits{})
	status, clientID := tryRegister(t, ts)
	if status != http.StatusForbidden {
		t.Errorf("register = %d, want 403", status)
	}
	if clientID != "" {
		t.Errorf("a refusing gateway minted client_id %q", clientID)
	}
	if got := outcomes(events, mu); len(got) != 1 || got[0] != RegistrationRefusedDisabled {
		t.Errorf("recorded %v, want one %q", got, RegistrationRefusedDisabled)
	}

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if _, advertised := meta["registration_endpoint"]; advertised {
		t.Error("a gateway that refuses registration still advertises a registration endpoint")
	}
	// Discovery itself must keep working: a client still has to find where to
	// authenticate, which is what RFC 8414 metadata is for.
	for _, required := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if meta[required] == nil {
			t.Errorf("metadata dropped %q; discovery must keep working", required)
		}
	}
}

// One source cannot register without limit. This is the bound that matters on a
// directly-reachable bind, where callers are distinguishable.
func TestRegistrationIsRateLimitedPerSource(t *testing.T) {
	_, ts, events, mu := boundedAS(t, RegistrationBounded, RegistrationLimits{PerSourcePerHour: 3, PerHour: 100})
	for i := range 3 {
		if status, _ := tryRegister(t, ts); status != http.StatusCreated {
			t.Fatalf("registration %d = %d, want 201", i+1, status)
		}
	}
	if status, clientID := tryRegister(t, ts); status != http.StatusTooManyRequests || clientID != "" {
		t.Fatalf("over-limit registration = %d, client_id %q; want 429 and no client", status, clientID)
	}
	// Refusals are recorded once per source per window, not once per attempt:
	// an endpoint that logged every refusal would hand an attacker an unbounded
	// append to the audit log simply by being refused repeatedly.
	for range 20 {
		tryRegister(t, ts)
	}
	refusals := 0
	for _, outcome := range outcomes(events, mu) {
		if outcome == RegistrationRefusedRate {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("recorded %d rate refusals; repeated refusals must not grow the audit log", refusals)
	}
}

// Behind a tunnel every caller arrives from the tunnel process, so the
// per-source bound stops separating anyone. The global bound is what still
// holds there, and it must hold independently.
func TestRegistrationIsRateLimitedGlobally(t *testing.T) {
	_, ts, _, _ := boundedAS(t, RegistrationBounded, RegistrationLimits{PerSourcePerHour: 1000, PerHour: 2})
	for i := range 2 {
		if status, _ := tryRegister(t, ts); status != http.StatusCreated {
			t.Fatalf("registration %d = %d, want 201", i+1, status)
		}
	}
	if status, _ := tryRegister(t, ts); status != http.StatusTooManyRequests {
		t.Errorf("global limit not enforced: %d", status)
	}
}

// The number of registrations that may exist at once is capped, so a gateway
// left running cannot accumulate records without bound.
func TestRegistrationIsCapped(t *testing.T) {
	as, ts, events, mu := boundedAS(t, RegistrationBounded, RegistrationLimits{MaxClients: 2, PerSourcePerHour: 100, PerHour: 100})
	for i := range 2 {
		if status, _ := tryRegister(t, ts); status != http.StatusCreated {
			t.Fatalf("registration %d = %d", i+1, status)
		}
	}
	if status, _ := tryRegister(t, ts); status != http.StatusTooManyRequests {
		t.Errorf("capacity cap not enforced: %d", status)
	}
	as.mu.Lock()
	held := len(as.clients)
	as.mu.Unlock()
	if held != 2 {
		t.Errorf("held %d registrations past a cap of 2", held)
	}
	found := false
	for _, outcome := range outcomes(events, mu) {
		if outcome == RegistrationRefusedCapacity {
			found = true
		}
	}
	if !found {
		t.Errorf("capacity refusal was not recorded: %v", outcomes(events, mu))
	}
}

// A registration nobody came back for expires. One that completed a flow does
// not: it belongs to a client someone actually connected, and expiring it would
// break that client's cached client_id for nothing.
func TestUnusedRegistrationsExpireAndUsedOnesDoNot(t *testing.T) {
	as, ts, _, _ := boundedAS(t, RegistrationBounded, RegistrationLimits{UnusedTTL: time.Hour, PerSourcePerHour: 100, PerHour: 100})
	_, abandoned := tryRegister(t, ts)
	_, connected := tryRegister(t, ts)
	if abandoned == "" || connected == "" {
		t.Fatal("registration did not return a client_id")
	}

	as.mu.Lock()
	as.markClientUsedLocked(connected)
	// Age both registrations past the TTL. Only the unused one should go.
	for id, client := range as.clients {
		client.createdAt = time.Now().Add(-2 * time.Hour)
		as.clients[id] = client
	}
	as.expireUnusedClientsLocked(time.Now(), time.Hour)
	_, abandonedHeld := as.clients[abandoned]
	_, connectedHeld := as.clients[connected]
	as.mu.Unlock()

	if abandonedHeld {
		t.Error("a registration that never completed a flow outlived its TTL")
	}
	if !connectedHeld {
		t.Error("a registration that completed a flow was expired; a connected client would lose its client_id")
	}
}

// Completing the real flow is what marks a registration used. The state that
// drives expiry has to be set by the flow itself, not by a test hook.
func TestCompletingAFlowMarksARegistrationUsed(t *testing.T) {
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	as := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	mux := http.NewServeMux()
	as.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	clientID := registerClient(t, ts, client)
	as.mu.Lock()
	before := as.clients[clientID]
	as.mu.Unlock()
	if !before.usedAt.IsZero() {
		t.Fatal("a fresh registration is already marked used")
	}

	verifier := pkceVerifierForTest
	code := approve(t, ts, client, clientID, pkceS256(verifier))
	status, tok := postForm(t, client, ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if status != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("token exchange = %d (%v)", status, tok)
	}

	as.mu.Lock()
	after := as.clients[clientID]
	as.mu.Unlock()
	if after.usedAt.IsZero() {
		t.Error("completing a flow did not mark the registration used; a connected client would be expired as abandoned")
	}
}

const pkceVerifierForTest = "a-sufficiently-long-pkce-code-verifier-1234567890"

// Expiry survives a restart. Without persisted times a restart would reset every
// registration's age, and a gateway restarted often would never expire anything.
func TestUnusedExpirySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oauth-clients.json")
	signer, err := LoadOrCreateSigner(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	first := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	first.SetClientRegistration(RegistrationBounded, RegistrationLimits{UnusedTTL: time.Hour})
	first.LoadClients(path)
	first.mu.Lock()
	first.clients["stale"] = clientReg{redirectURIs: []string{testRedirect}, name: "gone", createdAt: time.Now().Add(-2 * time.Hour)}
	first.clients["fresh"] = clientReg{redirectURIs: []string{testRedirect}, name: "here", createdAt: time.Now()}
	first.persistClientsLocked()
	first.mu.Unlock()

	restarted := NewAuthServer(signer, testIss, testAud, time.Hour, nil)
	restarted.SetClientRegistration(RegistrationBounded, RegistrationLimits{UnusedTTL: time.Hour})
	restarted.LoadClients(path)
	restarted.mu.Lock()
	_, staleHeld := restarted.clients["stale"]
	_, freshHeld := restarted.clients["fresh"]
	restarted.mu.Unlock()
	if staleHeld {
		t.Error("a registration that expired while the gateway was down came back")
	}
	if !freshHeld {
		t.Error("restart expired a registration that was still within its TTL")
	}
}

// The audit record identifies the client and distinguishes sources without the
// log accumulating the addresses of everyone who reached the endpoint.
func TestRegistrationRecordNamesTheClientAndNotTheAddress(t *testing.T) {
	_, ts, events, mu := boundedAS(t, RegistrationBounded, RegistrationLimits{})
	_, clientID := tryRegister(t, ts)
	mu.Lock()
	defer mu.Unlock()
	if len(*events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(*events))
	}
	event := (*events)[0]
	if event.ClientID != clientID {
		t.Errorf("record names client %q, want %q", event.ClientID, clientID)
	}
	if event.SourceDigest == "" {
		t.Error("record carries no source digest; growth cannot be attributed to one source or many")
	}
	if strings.Contains(event.SourceDigest, "127.0.0.1") {
		t.Errorf("record carries a raw address: %q", event.SourceDigest)
	}
}

// The mode name an operator types is validated, and an unknown one is refused
// rather than quietly falling back to the permissive default.
func TestParseRegistrationMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want RegistrationMode
		bad  bool
	}{
		{"", RegistrationBounded, false},
		{"bounded", RegistrationBounded, false},
		{"off", RegistrationOff, false},
		{"OFF", RegistrationOff, false},
		{"open", "", true},
		{"disabled", "", true},
	} {
		got, err := ParseRegistrationMode(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseRegistrationMode(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseRegistrationMode(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

// Both postures state what they are, with the bound named rather than implied.
func TestRegistrationPostureDescribesItself(t *testing.T) {
	limits := DefaultRegistrationLimits()
	bounded := RegistrationBounded.Describe(limits)
	for _, want := range []string{"bounded", "per source", "expire"} {
		if !strings.Contains(bounded, want) {
			t.Errorf("bounded posture %q does not state %q", bounded, want)
		}
	}
	off := RegistrationOff.Describe(limits)
	for _, want := range []string{"off", "operator"} {
		if !strings.Contains(off, want) {
			t.Errorf("off posture %q does not state %q", off, want)
		}
	}
}
