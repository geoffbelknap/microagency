package main

import (
	"bytes"
	"strings"
	"testing"
)

// doctor reports the secret-store posture so "where are my credentials" has an
// answer. An external Vault/OpenBao (VAULT_ADDR) is named explicitly.
func TestReportSecretPostureExternalVault(t *testing.T) {
	t.Setenv("VAULT_ADDR", "https://vault.example:8200")
	var buf bytes.Buffer
	reportSecretPosture(&buf)
	if !strings.Contains(buf.String(), "external Vault/OpenBao") || !strings.Contains(buf.String(), "vault.example") {
		t.Fatalf("posture should name the external Vault: %q", buf.String())
	}
}
