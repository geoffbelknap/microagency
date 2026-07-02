package main

import (
	"os"
	"path/filepath"
	"testing"
)

// seedState writes a representative ~/.microagency layout into dir.
func seedState(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "refs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "openbao"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"audit.jsonl":        "run1\nrun2\n",
		"refs/ref_abc.enc":   "encrypted",
		"refs.key":           "0123456789abcdef",
		"microagency.log":    "some log lines\n",
		"upstreams.json":     `{"conn":"notion"}`,
		"token":              "operator-token",
		"oauth-clients.json": "{}",
		"openbao/vault.db":   "secrets",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Tier 1 removes data + history and truncates the log, but keeps connections,
// credentials, and the operator token — so the operator doesn't have to re-auth.
func TestDoPurgeTier1KeepsAuthAndConnections(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)

	if err := doPurge(dir, false); err != nil {
		t.Fatalf("doPurge: %v", err)
	}

	// gone: the data
	for _, p := range []string{"audit.jsonl", "refs", "refs.key"} {
		if fileExists(filepath.Join(dir, p)) {
			t.Errorf("%s should have been removed", p)
		}
	}
	// truncated, not removed: the log path stays valid for the next start
	if b, err := os.ReadFile(filepath.Join(dir, "microagency.log")); err != nil {
		t.Errorf("log should still exist: %v", err)
	} else if len(b) != 0 {
		t.Errorf("log should be truncated, got %d bytes", len(b))
	}
	// kept: connections, credentials, auth
	for _, p := range []string{"upstreams.json", "token", "oauth-clients.json", "openbao/vault.db"} {
		if !fileExists(filepath.Join(dir, p)) {
			t.Errorf("%s must be kept by a Tier-1 purge", p)
		}
	}
}

// --full removes the entire directory.
func TestDoPurgeFullRemovesEverything(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)

	if err := doPurge(dir, true); err != nil {
		t.Fatalf("doPurge full: %v", err)
	}
	if fileExists(dir) {
		t.Fatalf("the whole dir should be gone, %s still exists", dir)
	}
}

// A purge over an already-clean dir is not an error (missing files are fine).
func TestDoPurgeTier1Idempotent(t *testing.T) {
	dir := t.TempDir() // empty
	if err := doPurge(dir, false); err != nil {
		t.Fatalf("purge of empty dir should be a no-op, got %v", err)
	}
}
