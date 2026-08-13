package safedial

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsInternal(t *testing.T) {
	internal := []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254",                       // cloud metadata (link-local)
		"fe80::1",                               // link-local v6
		"10.1.2.3", "172.16.5.4", "192.168.1.1", // RFC1918
		"fd00::1",    // ULA
		"100.64.0.1", // CGNAT
		"0.0.0.0",    // unspecified
		"224.0.0.1",  // multicast
	}
	for _, s := range internal {
		if !isInternal(net.ParseIP(s)) {
			t.Errorf("%s should be internal", s)
		}
	}
	external := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"}
	for _, s := range external {
		if isInternal(net.ParseIP(s)) {
			t.Errorf("%s should be external", s)
		}
	}
	if !isInternal(nil) {
		t.Error("nil IP must fail closed (internal)")
	}
}

// TestGuardedClientRefusesLoopback proves the dial guard blocks a real loopback
// connection — the SSRF property — even against a server that is up.
func TestGuardedClientRefusesLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ts.Close()

	_, err := GuardedClient(2*time.Second, 2*time.Second).Get(ts.URL) // ts.URL is on 127.0.0.1
	if err == nil {
		t.Fatal("guarded client reached a loopback address — SSRF guard did not fire")
	}
}

// TestGuardedClientSeparatesDialAndRequestTimeouts locks in the fix: the overall
// request / response-header bound must be the REQUEST timeout, not the short dial
// timeout — otherwise a slow-to-first-byte upstream (a security query that computes
// before responding) is killed mid-flight.
func TestGuardedClientSeparatesDialAndRequestTimeouts(t *testing.T) {
	c := GuardedClient(3*time.Second, 90*time.Second)
	if c.Timeout != 90*time.Second {
		t.Fatalf("client Timeout = %v, want request timeout 90s", c.Timeout)
	}
	guarded, ok := c.Transport.(targetTransport)
	if !ok {
		t.Fatal("transport is not targetTransport")
	}
	tr, ok := guarded.base.(*http.Transport)
	if !ok {
		t.Fatal("base transport is not *http.Transport")
	}
	if tr.ResponseHeaderTimeout != 90*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want the request timeout (90s), not the dial timeout", tr.ResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout != 3*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want the dial timeout (3s)", tr.TLSHandshakeTimeout)
	}
	// Defaults: dial 10s, request 5m.
	d := GuardedClient(0, 0)
	if d.Timeout != 5*time.Minute {
		t.Fatalf("default request timeout = %v, want 5m", d.Timeout)
	}
}

func TestGuardedClientDisablesEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9999")
	_ = os.Getenv("HTTPS_PROXY") // document that the configured value is live
	guarded := GuardedClient(time.Second, time.Second).Transport.(targetTransport)
	tr := guarded.base.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("untrusted target client inherited an environment proxy")
	}
}

func TestGuardedClientChecksInitialAndRedirectTargets(t *testing.T) {
	var checked []string
	client := GuardedClientForPolicy(time.Second, time.Second, func(target *url.URL) error {
		checked = append(checked, target.String())
		if !strings.HasPrefix(target.Host, "allowed.example") {
			return &url.Error{Op: "authorize", URL: target.String(), Err: errDenied{}}
		}
		return nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://denied.example/start", nil)
	if _, err := client.Do(req); err == nil || len(checked) != 1 {
		t.Fatalf("initial target policy: checks=%v err=%v", checked, err)
	}
	redirect, _ := http.NewRequest(http.MethodGet, "https://denied.example/redirect", nil)
	first, _ := http.NewRequest(http.MethodGet, "https://allowed.example/start", nil)
	if err := client.CheckRedirect(redirect, []*http.Request{first}); err == nil {
		t.Fatal("redirect target escaped the URL policy")
	}
}

type errDenied struct{}

func (errDenied) Error() string { return "denied" }

func TestGuardedClientDefaultRedirectsStayOnOrigin(t *testing.T) {
	client := GuardedClient(time.Second, time.Second)
	first, _ := http.NewRequest(http.MethodGet, "https://api.example/start", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://api.example/next", nil)
	if err := client.CheckRedirect(same, []*http.Request{first}); err != nil {
		t.Fatalf("same-origin redirect denied: %v", err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://cdn.example/next", nil)
	if err := client.CheckRedirect(other, []*http.Request{first}); err == nil {
		t.Fatal("cross-origin redirect allowed without explicit policy")
	}
}
