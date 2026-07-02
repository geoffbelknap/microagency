package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSignerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-key")
	s, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}

	const iss, aud, sub = "http://127.0.0.1:8765", "microagency", "operator"
	tok, err := s.Mint(iss, aud, sub, []string{"mcp"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// The existing ResourceServer validates a self-issued token unchanged.
	rs := &ResourceServer{Issuer: iss, Audience: aud, Keys: s.KeySet()}
	p, err := rs.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.Subject != sub {
		t.Fatalf("subject = %q, want %q", p.Subject, sub)
	}
	if !p.HasScope("mcp") {
		t.Fatalf("scope missing: %v", p.Scopes)
	}
}

func TestSignerPersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-key")
	s, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	const iss, aud = "http://127.0.0.1:8765", "microagency"
	tok, _ := s.Mint(iss, aud, "operator", nil, time.Minute)

	// A "restart" reloads the persisted key — same kid, and a token minted before
	// the restart still validates.
	s2, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.KID() != s.KID() {
		t.Fatalf("kid changed on reload: %s vs %s", s2.KID(), s.KID())
	}
	rs := &ResourceServer{Issuer: iss, Audience: aud, Keys: s2.KeySet()}
	if _, err := rs.Validate(context.Background(), tok); err != nil {
		t.Fatalf("pre-restart token rejected after reload: %v", err)
	}
}

func TestSignerAudienceBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-key")
	s, _ := LoadOrCreateSigner(path)
	const iss = "http://127.0.0.1:8765"
	tok, _ := s.Mint(iss, "microagency", "operator", nil, time.Minute)

	// A token bound to our audience must not validate for another resource.
	rs := &ResourceServer{Issuer: iss, Audience: "some-other-resource", Keys: s.KeySet()}
	if _, err := rs.Validate(context.Background(), tok); err == nil {
		t.Fatal("token accepted for the wrong audience (replay not blocked)")
	}
}
