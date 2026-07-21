package mcp

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"microagency/internal/auth"
)

// failingSecrets is a secret store whose Save always errors, to exercise the
// persist-failure logging on the OAuth client path.
type failingSecrets struct{}

func (failingSecrets) Save(context.Context, string, []byte) error { return fmt.Errorf("disk full") }
func (failingSecrets) Load(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("not found")
}
func (failingSecrets) Delete(context.Context, string) error { return nil }
func (failingSecrets) Kind() string                         { return "file" }

// A failed persist of the OAuth client must be logged, not swallowed — otherwise a
// registered/supplied client silently fails to survive a restart.
func TestLoadOrRegisterClientLogsSaveFailure(t *testing.T) {
	srv := NewServer(fakeRunner{}, WithSecretStore(failingSecrets{}))

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	id, sec, err := srv.loadOrRegisterClient(
		context.Background(),
		&auth.ASMetadata{Issuer: "https://as.example"},
		"http://127.0.0.1/callback",
		"supplied-id", "supplied-secret",
	)
	// The supplied client is still USED this session (the save failure is non-fatal).
	if err != nil || id != "supplied-id" || sec != "supplied-secret" {
		t.Fatalf("supplied client must be used despite a save failure: id=%q sec=%q err=%v", id, sec, err)
	}
	if !strings.Contains(buf.String(), "persist OAuth client") {
		t.Fatalf("the persist failure was not logged: %q", buf.String())
	}
}
