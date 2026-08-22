package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/secretstore"
)

// delegatedRegistry writes an upstreams.json holding one google-dwd
// connection into dir and returns the state dir.
func delegatedRegistry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	regs := []map[string]any{{
		"name": "drive", "url": "https://mcp.example.com/mcp",
		"strategy": "google-dwd",
		"delegation": map[string]any{
			"client_email":   "delegate@project.example",
			"token_endpoint": "https://provider.example/token",
			"scopes":         []string{"https://provider.example/auth/data.readonly"},
		},
	}}
	b, err := json.Marshal(regs)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "upstreams.json", string(b))
	return dir
}

// Doctor reports each delegated connection and verifies both prerequisites:
// key material in the secret store and federated sign-in for verified emails.
func TestDoctorReportsDelegatedConnections(t *testing.T) {
	dir := delegatedRegistry(t)
	store, err := secretstore.Open(dir, func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "delegation/upstreams/drive/key", []byte(`{"type":"service_account"}`)); err != nil {
		t.Fatal(err)
	}
	posture, _ := json.Marshal(authPosture{Mode: "oauth-tunnel", SSOIssuer: "https://idp.example"})
	posturePath := writeFile(t, dir, "auth-posture.json", string(posture))

	var out strings.Builder
	reportDelegatedConnectionsAt(&out, dir, posturePath)
	for _, want := range []string{
		"delegated access",
		"✓ key present (acting service account delegate@project.example, 1 scopes)",
		"email mapping   ✓ federated sign-in (https://idp.example)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("delegated doctor section is missing %q:\n%s", want, out.String())
		}
	}
}

// A missing key and an absent federated sign-in are failures with
// remediation, never silence.
func TestDoctorDelegatedPrerequisitesMissing(t *testing.T) {
	dir := delegatedRegistry(t)
	var out strings.Builder
	reportDelegatedConnectionsAt(&out, dir, filepath.Join(dir, "no-posture.json"))
	for _, want := range []string{
		"✗ service-account key missing",
		"POST /admin/upstreams/drive/delegation",
		"✗ no federated sign-in",
		"--sso-issuer",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("failing delegated section is missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "✓ key present") {
		t.Errorf("missing key rendered as present:\n%s", out.String())
	}
}

// No delegated connections: the section does not render (like the federated
// sign-in lines, which render only under an SSO posture).
func TestDoctorDelegatedSectionAbsentWithoutDelegatedConnections(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "upstreams.json", `[{"name":"docs","url":"https://docs.example/mcp"}]`)
	var out strings.Builder
	reportDelegatedConnectionsAt(&out, dir, filepath.Join(dir, "no-posture.json"))
	if out.Len() != 0 {
		t.Fatalf("section rendered with no delegated connections:\n%s", out.String())
	}
}
