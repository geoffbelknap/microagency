package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private destination is operator authority. The combination must be refused
// at registration, so no self-service path can admit a principal-supplied URL
// that reaches inside the deployment's own network.
func TestSelfServiceCannotDeclarePrivateDestination(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	err := s.registerUpstream("sneaky", &upstream{
		conn:    &fakeConn{endpoint: "http://127.0.0.1:9999/mcp"},
		enabled: true,
	}, WithSelfService("supabase"), WithPrivateDestination())
	if err == nil {
		t.Fatal("a self-service connection was allowed to declare a private destination")
	}
	if !strings.Contains(err.Error(), "self-service") {
		t.Fatalf("refusal should name the reason, got: %v", err)
	}
	if _, ok := s.reg.conns["sneaky"]; ok {
		t.Fatal("the refused connection was registered anyway")
	}
}

func TestOperatorMayDeclarePrivateDestination(t *testing.T) {
	s := newTestServer(t, fakeRunner{})
	if err := s.registerUpstream("sidecar", &upstream{
		conn:    &fakeConn{endpoint: "http://127.0.0.1:9999/mcp"},
		enabled: true,
	}, WithPrivateDestination()); err != nil {
		t.Fatalf("operator registration refused: %v", err)
	}
	rec, ok := s.reg.conns["sidecar"]
	if !ok || !rec.privateDestination {
		t.Fatal("private destination was not recorded on the registration")
	}
	var found bool
	for _, info := range s.UpstreamList() {
		if info.Name == "sidecar" {
			found = info.PrivateDestination
		}
	}
	if !found {
		t.Fatal("UpstreamList does not disclose the private destination")
	}
}

// The declaration must survive a restart: an operator who declared a sidecar
// reachable should not find it silently unreachable after a bounce.
func TestPrivateDestinationRoundTripsThroughPersistence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "upstreams.json"), []byte(
		`[{"name":"sidecar","url":"http://127.0.0.1:8795/mcp","private_destination":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	regs := ReadUpstreamRegistrations(dir)
	if len(regs) != 1 {
		t.Fatalf("got %d registrations, want 1", len(regs))
	}
	if !regs[0].PrivateDestination {
		t.Fatal("private destination did not survive the persisted round trip")
	}
}
