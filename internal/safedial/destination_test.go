package safedial

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDestinationRefusesMetadataAddresses(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254/mcp",
		"http://[fd00:ec2::254]/mcp",
		"http://169.254.170.2/mcp", // ECS task metadata, also link-local
	} {
		if _, err := ParseDestination(raw); err == nil {
			t.Fatalf("ParseDestination(%q) = nil error, want refusal", raw)
		}
	}
}

func TestParseDestinationDefaultsPortByScheme(t *testing.T) {
	d, err := ParseDestination("https://connector.internal/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if d.port != "443" {
		t.Fatalf("port = %q, want 443", d.port)
	}
	if d, err = ParseDestination("http://connector.internal/mcp"); err != nil || d.port != "80" {
		t.Fatalf("port = %q err = %v, want 80", d.port, err)
	}
}

// A loopback connector is exactly the operator-declared case this exists for.
func TestGuardedClientForDestinationReachesDeclaredLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dest, err := ParseDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := GuardedClientForDestination(0, 0, dest).Get(srv.URL)
	if err != nil {
		t.Fatalf("declared destination refused: %v", err)
	}
	resp.Body.Close()

	// The stock guard must still refuse the same address.
	if _, err := GuardedClient(0, 0).Get(srv.URL); err == nil {
		t.Fatal("GuardedClient reached loopback; the SSRF guard is not intact")
	}
}

// The permission is scoped to the declared destination, not to private space.
func TestGuardedClientForDestinationRefusesOtherPrivateAddresses(t *testing.T) {
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer declared.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer other.Close()

	dest, err := ParseDestination(declared.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GuardedClientForDestination(0, 0, dest).Get(other.URL); err == nil {
		t.Fatal("a second private address was reachable; the permission is not destination-scoped")
	}
}

func TestGuardedClientForDestinationRefusesMetadataEvenWhenDeclaredElsewhere(t *testing.T) {
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer declared.Close()
	dest, err := ParseDestination(declared.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = GuardedClientForDestination(0, 0, dest).Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("cloud metadata was reachable from a client with a private destination")
	}
	if !strings.Contains(err.Error(), "never a permitted destination") &&
		!strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
}

// A redirect must not carry the permission to a different private address.
func TestGuardedClientForDestinationRefusesRedirectToOtherPrivateAddress(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	}))
	defer redirector.Close()

	dest, err := ParseDestination(redirector.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GuardedClientForDestination(0, 0, dest).Get(redirector.URL); err == nil {
		t.Fatal("redirect to a different private address was followed")
	}
}

func TestAlwaysRefusedCoversNilAndMetadata(t *testing.T) {
	if !alwaysRefused(nil) {
		t.Fatal("nil IP must fail closed")
	}
	if !alwaysRefused(net.ParseIP("169.254.169.254")) {
		t.Fatal("IMDS address must always be refused")
	}
	if alwaysRefused(net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback must be declarable, not always refused")
	}
	if alwaysRefused(net.ParseIP("10.1.2.3")) {
		t.Fatal("RFC1918 must be declarable, not always refused")
	}
}
