package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/auth"
	"microagency/internal/secretstore"
)

func TestReportAuthPostureNamesPublicIssuerResourceAndConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	posture := authPosture{
		Mode: "oauth-tunnel", Tunnel: "cloudflare",
		Issuer: "https://gateway.example", Resource: "https://gateway.example/mcp",
		Audience:  "https://gateway.example/mcp",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{})
	for _, want := range []string{"built-in OAuth", "cloudflare", posture.Issuer, posture.Resource, posture.Audience, "loopback operator listener"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("auth posture %q is missing %q", out.String(), want)
		}
	}
}

// On a multi-user posture (external issuer), doctor states what the shared
// audit log retains, and a full-capture opt-up never passes silently.
func TestReportAuthPostureDisclosesAuditCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	posture := authPosture{
		Mode: "oauth-external", Issuer: "https://as.example",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	reportAuthPostureAt(&out, path, nil, auth.AudienceSummary{})
	if !strings.Contains(out.String(), "structure + digest") {
		t.Fatalf("default multi-user capture posture is not stated: %q", out.String())
	}
	if strings.Contains(out.String(), "⚠") {
		t.Fatalf("the safe default should not warn: %q", out.String())
	}

	out.Reset()
	reportAuthPostureAt(&out, path, []string{"github", "slack"}, auth.AudienceSummary{})
	for _, want := range []string{"⚠", "FULL arguments", "github, slack"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("opt-up disclosure %q is missing %q", out.String(), want)
		}
	}
}

// doctor reports the secret-store posture so "where are my credentials" has an
// answer. An external Vault/OpenBao (VAULT_ADDR) is named explicitly — and only
// after it answers, because a configured address is not a reachable one.
func TestReportSecretPostureExternalVault(t *testing.T) {
	env := map[string]string{"VAULT_ADDR": "https://vault.example:8200", "VAULT_TOKEN": "token"}
	getenv := func(name string) string { return env[name] }

	var buf bytes.Buffer
	reportSecretPostureWith(&buf, getenv, t.TempDir(), 0, vaultReachable)
	got := buf.String()
	if !strings.Contains(got, "✓ external Vault/OpenBao") || !strings.Contains(got, "vault.example") {
		t.Fatalf("posture should name the external Vault: %q", got)
	}
	if !strings.Contains(got, "verified") {
		t.Fatalf("a healthy external store must say it was verified, not assumed: %q", got)
	}

	// The genuine disagreement: the operator configured a store, and it is not
	// answering. Reporting a green line here is the false verdict this avoids.
	buf.Reset()
	reportSecretPostureWith(&buf, getenv, t.TempDir(), 0, vaultUnreachable)
	got = buf.String()
	for _, want := range []string{"✗ external Vault/OpenBao", "did not answer", "connection refused", "fix:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("unreachable external Vault posture %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "✓") {
		t.Fatalf("a store that did not answer must never read as healthy: %q", got)
	}
}

// vaultReachable / vaultUnreachable stand in for the network read so no test
// reaches a real address.
func vaultReachable(context.Context, func(string) string) error { return nil }

func vaultUnreachable(context.Context, func(string) string) error {
	return errors.New("dial tcp 127.0.0.1:8200: connection refused")
}

// The unencrypted store is a posture the operator opted into, never one doctor
// discovers for them, and it is never green.
func TestReportSecretPostureNamesPlaintextOptIn(t *testing.T) {
	env := func(name string) string {
		if name == secretstore.AllowPlaintextEnv {
			return "1"
		}
		return ""
	}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, env, t.TempDir(), 0, vaultReachable)
	got := buf.String()
	if !strings.Contains(got, "⚠") || !strings.Contains(got, "NOT encrypted at rest") {
		t.Fatalf("opted-in plaintext posture is not explicit: %q", got)
	}
	if strings.Contains(got, "✓") {
		t.Fatalf("an unencrypted store must never read as healthy: %q", got)
	}
	if !strings.Contains(got, "keyring") {
		t.Fatalf("the page should say what would encrypt this instead: %q", got)
	}
}

// A host that can hold no data key outside the state directory refuses, and the
// page names every way forward that does not need a keyring. It must never
// suggest a key beside the ciphertext.
func TestNoKeyringRefusalNamesEveryWayForward(t *testing.T) {
	ls := noProtectorAvailable(secretstore.AutoProtector{
		Kind:  "secret-service",
		Label: "Linux Secret Service",
		Detail: "linux Secret Service protector requires secret-tool " +
			"(libsecret-tools/libsecret)",
	})
	var buf bytes.Buffer
	renderLocalStore(&buf, ls)
	got := buf.String()
	for _, want := range []string{
		"✗",
		"secret-tool",                   // why
		secretstore.ProtectorEnv,        // a KMS or secret-manager helper
		secretstore.FileKeyEnv,          // a key the operator holds
		"--allow-plaintext-credentials", // the explicit downgrade
		"Linux Secret Service",          // repair the keyring
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("no-keyring refusal %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "✓") {
		t.Fatalf("a host with no usable store must never read as healthy: %q", got)
	}
}

// The defect this pins: a gateway running healthily with its key file exported
// into its OWN environment was reported as broken by a doctor run from a shell
// that did not export the same variable. Doctor cannot see that key, but "I
// cannot verify this" is not "your store is broken", and the page must name the
// remedy for both readings.
func TestEncryptedStoreWithNoKeyHereReadsAsUnverifiedNotBroken(t *testing.T) {
	var buf bytes.Buffer
	renderLocalStore(&buf, encryptedStoreNoKeyHere())
	got := buf.String()
	if !strings.Contains(got, "⚠") {
		t.Fatalf("an unverifiable key is not a failure: %q", got)
	}
	if strings.Contains(got, "✗") {
		t.Fatalf("a healthy deployment must not be reported as broken: %q", got)
	}
	for _, want := range []string{
		"encrypted",            // what was verified
		"export the same",      // remedy 1: give doctor the same variable
		secretstore.FileKeyEnv, //
		"secret-store migrate", // remedy 2: move it where doctor can follow
		"THIS environment",     // whose start would refuse
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("unverified-key posture %q is missing %q", got, want)
		}
	}
}

// A running gateway is the authority on which store it opened; the record it
// wrote beats anything inferred from configuration. It is trusted only while
// its pid is the live gateway.
func TestReportSecretPostureTrustsTheRunningGatewaysRecord(t *testing.T) {
	stateDir := t.TempDir()
	recorded := secretstore.Posture{
		PID: 4242, Kind: secretstore.KindFile,
		Effective:  "unencrypted mode-0600 plaintext file under ~/.microagency",
		Configured: "external Vault/OpenBao (VAULT_ADDR)",
		Reason:     "it did not answer when the gateway started",
		Degraded:   true,
	}
	if err := secretstore.SavePosture(stateDir, recorded); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	// A probe that would claim a perfectly healthy store must not override what
	// the running gateway actually opened.
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 4242, vaultReachable)
	got := buf.String()
	for _, want := range []string{"NOT the one holding credentials", recorded.Configured, "pid 4242", recorded.Reason} {
		if !strings.Contains(got, want) {
			t.Fatalf("live posture %q is missing %q", got, want)
		}
	}

	// A record left by an exited gateway describes a run that has ended.
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 99, vaultReachable)
	if strings.Contains(buf.String(), "pid 4242") {
		t.Fatalf("a stale record was reported as the live posture: %q", buf.String())
	}
}

// The running gateway's healthy record names the protector holding its key: an
// operator whose keyring is locked after a reboot needs to know which one.
func TestLivePostureNamesTheProtectorHoldingTheKey(t *testing.T) {
	stateDir := t.TempDir()
	if err := secretstore.SavePosture(stateDir, secretstore.Posture{
		PID: 7, Kind: secretstore.KindEncryptedFile,
		Effective:  "AES-256-GCM file store (data key: Linux Secret Service)",
		KeyCustody: "secret-service",
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 7, vaultReachable)
	got := buf.String()
	if !strings.Contains(got, "✓") || !strings.Contains(got, "Linux Secret Service") {
		t.Fatalf("live posture should name the protector: %q", got)
	}
}
