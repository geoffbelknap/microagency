package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microagency/internal/baomanager"
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
	reportAuthPostureAt(&out, path, nil)
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
	reportAuthPostureAt(&out, path, nil)
	if !strings.Contains(out.String(), "structure + digest") {
		t.Fatalf("default multi-user capture posture is not stated: %q", out.String())
	}
	if strings.Contains(out.String(), "⚠") {
		t.Fatalf("the safe default should not warn: %q", out.String())
	}

	out.Reset()
	reportAuthPostureAt(&out, path, []string{"github", "slack"})
	for _, want := range []string{"⚠", "FULL arguments", "github, slack"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("opt-up disclosure %q is missing %q", out.String(), want)
		}
	}
}

// doctor reports the secret-store posture so "where are my credentials" has an
// answer. An external Vault/OpenBao (VAULT_ADDR) is named explicitly.
func TestReportSecretPostureExternalVault(t *testing.T) {
	env := map[string]string{"VAULT_ADDR": "https://vault.example:8200", "VAULT_TOKEN": "token"}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(name string) string { return env[name] }, t.TempDir(), 0, noManagedBao)
	if !strings.Contains(buf.String(), "external Vault/OpenBao") || !strings.Contains(buf.String(), "vault.example") {
		t.Fatalf("posture should name the external Vault: %q", buf.String())
	}
}

func TestReportSecretPostureDistinguishesManagedCustody(t *testing.T) {
	stateDir := t.TempDir()
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 0, baoBinaryOnPath)
	if !strings.Contains(buf.String(), "same-disk degraded bootstrap custody") || !strings.Contains(buf.String(), "MICROAGENCY_OPENBAO_PROTECTOR") {
		t.Fatalf("managed degraded posture is not explicit: %q", buf.String())
	}

	baoDir := filepath.Join(stateDir, "openbao")
	if err := os.MkdirAll(baoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "protector")
	script := "#!/bin/sh\nif [ \"$1\" = get ]; then printf '%s' '{\"unseal_key\":\"u\",\"role_id\":\"r\",\"secret_id\":\"s\"}'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"format":"microagency-openbao-custody-v1","kind":"command","id":"test","command":"` + helper + `"}`
	if err := os.WriteFile(filepath.Join(baoDir, "custody.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 0, baoBinaryOnPath)
	if !strings.Contains(buf.String(), "managed protected OpenBao") || !strings.Contains(buf.String(), "external protector helper") || !strings.Contains(buf.String(), "root retired") {
		t.Fatalf("managed protected posture is not explicit: %q", buf.String())
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 0, noManagedBao)
	if !strings.Contains(buf.String(), "OpenBao binary unavailable") || !strings.Contains(buf.String(), "startup will fail closed") {
		t.Fatalf("protected posture disappeared when the binary was unavailable: %q", buf.String())
	}
}

// probeStub fixes the parts of the managed-instance probe that need a live host
// (is a binary installed, is anything listening) while still resolving "is
// managed custody configured" from the state directory, which does not.
func probeStub(p baomanager.ManagedProbe) managedProbeFunc {
	return func(dir string, getenv func(string) string) baomanager.ManagedProbe {
		out := p
		out.Configured = out.Configured || baomanager.ManagedConfigured(dir, getenv)
		return out
	}
}

// noManagedBao: nothing managed configured, no OpenBao binary.
var noManagedBao = probeStub(baomanager.ManagedProbe{Addr: baomanager.ManagedAddr})

// baoBinaryOnPath: an OpenBao binary is installed, nothing is running yet.
var baoBinaryOnPath = probeStub(baomanager.ManagedProbe{Addr: baomanager.ManagedAddr, Binary: true})

func TestReportSecretPostureNamesPlaintextFallback(t *testing.T) {
	// Without an opt-in the unencrypted fallback is not a posture the gateway
	// will adopt, so the page says a start refuses rather than describing it as
	// the store in use.
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, t.TempDir(), 0, noManagedBao)
	got := buf.String()
	if !strings.Contains(got, "plaintext") || !strings.Contains(got, "will refuse") || strings.Contains(got, "fine for single-user") {
		t.Fatalf("fallback posture is not explicit: %q", got)
	}
	if !strings.Contains(got, "--allow-plaintext-credentials") {
		t.Fatalf("the refusal does not name the opt-in: %q", got)
	}

	// With the opt-in it is a real, degraded posture — and still never green.
	buf.Reset()
	env := func(name string) string {
		if name == secretstore.AllowPlaintextEnv {
			return "1"
		}
		return ""
	}
	reportSecretPostureWith(&buf, env, t.TempDir(), 0, noManagedBao)
	got = buf.String()
	if !strings.Contains(got, "⚠") || !strings.Contains(got, "NOT encrypted at rest") {
		t.Fatalf("opted-in plaintext posture is not explicit: %q", got)
	}
	if strings.Contains(got, "✓") {
		t.Fatalf("an unencrypted store must never read as healthy: %q", got)
	}
}

// The defect this pins: configuration named one store and a different one held
// the credentials, and doctor reported the configured one. An operator who
// believes their secrets are in a vault when they are in a file remediates the
// wrong thing, so the page must name the store actually in effect.
func TestReportSecretPostureNamesEffectiveStoreWhenManagedOpenBaoCannotBeUsed(t *testing.T) {
	stateDir := t.TempDir()
	baoDir := filepath.Join(stateDir, "openbao")
	if err := os.MkdirAll(filepath.Join(baoDir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baoDir, "data", "core"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Managed OpenBao is configured and installed, but the port is held by a
	// process microagency did not start, so a start never reaches its own
	// instance.
	stale := &baomanager.StaleListenerError{
		Addr: baomanager.ManagedAddr, Dir: baoDir,
		Detail: "microagency has no managed instance recorded here",
	}
	probe := probeStub(baomanager.ManagedProbe{
		Addr: baomanager.ManagedAddr, Configured: true, Binary: true, Running: true, Err: stale,
	})

	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 0, probe)
	got := buf.String()
	for _, want := range []string{
		"managed OpenBao is configured but CANNOT be used", // what was configured
		"in effect:",           // what actually holds credentials
		"plaintext",            // named, not left as "a fallback"
		baomanager.ManagedAddr, // why the first failed
		"not the instance microagency manages",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("posture %q is missing %q", got, want)
		}
	}
	// The store that is NOT in effect must not be presented as the one holding
	// credentials, in either posture.
	if strings.Contains(got, "✓ managed") || strings.Contains(got, "⚠ managed OpenBao with same-disk") {
		t.Fatalf("doctor still reports the configured managed store as the store in effect: %q", got)
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
		Configured: "managed OpenBao",
		Reason:     "another process holds " + baomanager.ManagedAddr,
		Degraded:   true,
	}
	if err := secretstore.SavePosture(stateDir, recorded); err != nil {
		t.Fatal(err)
	}
	// A probe that would claim a perfectly healthy managed store must not
	// override what the running gateway actually opened.
	healthy := probeStub(baomanager.ManagedProbe{
		Addr: baomanager.ManagedAddr, Configured: true, Binary: true, Running: true, Adopted: true,
	})

	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 4242, healthy)
	got := buf.String()
	for _, want := range []string{"NOT the one holding credentials", "managed OpenBao", "pid 4242", recorded.Reason} {
		if !strings.Contains(got, want) {
			t.Fatalf("live posture %q is missing %q", got, want)
		}
	}

	// A record left by an exited gateway describes a run that has ended.
	buf.Reset()
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 99, healthy)
	if strings.Contains(buf.String(), "pid 4242") {
		t.Fatalf("a stale record was reported as the live posture: %q", buf.String())
	}
}

func TestReportSecretPostureValidatesEncryptedFallback(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	keyPath := filepath.Join(root, "key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(name string) string {
		if name == secretstore.FileKeyEnv {
			return keyPath
		}
		return ""
	}
	var buf bytes.Buffer
	reportSecretPostureWith(&buf, env, stateDir, 0, noManagedBao)
	if !strings.Contains(buf.String(), "AES-256-GCM") || !strings.Contains(buf.String(), "separately supplied") {
		t.Fatalf("encrypted posture is not explicit: %q", buf.String())
	}

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, env, stateDir, 0, noManagedBao)
	if !strings.Contains(buf.String(), "misconfigured") || !strings.Contains(buf.String(), "fail closed") {
		t.Fatalf("invalid key posture is not explicit: %q", buf.String())
	}
}

func TestReportSecretPostureRejectsMissingOrWrongExistingFileKey(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	store, err := secretstore.NewEncryptedFile(filepath.Join(stateDir, "upstream-tokens.json"), bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "up/example", []byte("sentinel")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	reportSecretPostureWith(&buf, func(string) string { return "" }, stateDir, 0, noManagedBao)
	if !strings.Contains(buf.String(), "exists") || !strings.Contains(buf.String(), "not configured") || !strings.Contains(buf.String(), "fail closed") {
		t.Fatalf("missing existing-file key posture is not explicit: %q", buf.String())
	}

	wrongKeyPath := filepath.Join(root, "wrong-key")
	if err := os.WriteFile(wrongKeyPath, bytes.Repeat([]byte{0x22}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reportSecretPostureWith(&buf, func(name string) string {
		if name == secretstore.FileKeyEnv {
			return wrongKeyPath
		}
		return ""
	}, stateDir, 0, noManagedBao)
	if !strings.Contains(buf.String(), "wrong key") || !strings.Contains(buf.String(), "misconfigured") {
		t.Fatalf("wrong existing-file key posture is not explicit: %q", buf.String())
	}
}

func TestReportSecretPostureRejectsPartialVaultConfig(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"VAULT_ADDR": "https://vault.example:8200"}, "VAULT_TOKEN is missing"},
		{map[string]string{"VAULT_TOKEN": "token"}, "VAULT_ADDR is missing"},
	} {
		var buf bytes.Buffer
		reportSecretPostureWith(&buf, func(name string) string { return tc.env[name] }, t.TempDir(), 0, noManagedBao)
		if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), "fail closed") {
			t.Fatalf("partial Vault config is not explicit: %q", buf.String())
		}
	}
}

// The closing sentence answers for the whole page: a dead server can never
// sit above an ending that reads green, and only the fully healthy page may
// claim "ready".
func TestClosingVerdictGatesOnWholePage(t *testing.T) {
	healthy := "reduce(code) is verified end to end (booted and ran)"
	tests := []struct {
		name           string
		serverUp       bool
		bypassWarnings int
		runtimeHealthy bool
		mediationReady bool
		tunnelOK       bool
		wantContains   string
		wantNotReady   bool
	}{
		{"all green claims ready", true, 0, true, true, true, "microagency is ready", false},
		{"dead server never reads green", false, 0, true, true, true, "The gateway is not ready", true},
		{"dead tunnel blocks the ready claim", true, 0, true, true, false, "tunnel process has exited", true},
		{"back door blocks the ready claim", true, 1, true, true, true, "reachable around the gateway", true},
		{"multiple back doors are counted", true, 3, true, true, true, "3 upstreams", true},
		{"unhealthy runtime blocks the ready claim", true, 0, false, true, true, "The server is running, but", true},
		{"degraded mediation blocks ready", true, 0, true, false, true, "mediation is degraded", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := closingVerdict(tt.serverUp, tt.bypassWarnings, tt.runtimeHealthy, healthy, tt.mediationReady, "enforced workspace mediation is degraded",
				tt.tunnelOK, "the tunnel process has exited so the public URL is unreachable — restart with `microagency restart`")
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("verdict %q should contain %q", got, tt.wantContains)
			}
			if tt.wantNotReady && strings.Contains(got, "microagency is ready") {
				t.Errorf("page with a failing check claims ready: %q", got)
			}
		})
	}
}

// A passing lookup line carries no path; the failing line names where the
// lookup went, which is the remediation detail someone actually needs.
func TestPathWhenMissing(t *testing.T) {
	if got := pathWhenMissing(true, "/opt/supervisor"); got != "" {
		t.Errorf("healthy line leaks a path: %q", got)
	}
	if got := pathWhenMissing(false, "/opt/supervisor"); !strings.Contains(got, "/opt/supervisor") {
		t.Errorf("failing line should name the expected path: %q", got)
	}
	if got := pathWhenMissing(false, ""); got != "" {
		t.Errorf("no path known should stay empty: %q", got)
	}
}
