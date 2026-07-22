package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/auth"
	"microagency/internal/secretstore"
)

func anchoredServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	secrets := secretstore.Open(dir, func(string) string { return "" }, nil) // file secret store
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithSecretStore(secrets), WithAuditSigner(signer))
	return s, dir
}

// The out-of-band anchor catches a wholesale tail truncation that the in-file
// chain can't: a validly-signed prefix shorter than the anchor was truncated.
func TestAuditAnchorDetectsTailTruncation(t *testing.T) {
	s, dir := anchoredServer(t)
	// Enough runs to cross the anchor threshold (so a head anchor is persisted).
	for i := 0; i < auditAnchorEvery+5; i++ {
		s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t"})
	}

	// The intact, signed log verifies AND reports it's anchored.
	if v, err := s.VerifyAudit(); err != nil || !v.Intact || !v.Anchored {
		t.Fatalf("intact anchored log: %+v err=%v", v, err)
	}

	// Truncate the log well below the anchored height (drop to 10 lines).
	path := filepath.Join(dir, "audit.jsonl")
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) <= 10 {
		t.Fatalf("expected a long log, got %d lines", len(lines))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines[:10], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The remaining 10 lines are each still validly signed and chained — the in-file
	// walk alone would call this intact — but the anchor catches the truncation.
	if v, err := VerifyAuditLog(path, s.auditVerify()); err != nil || !v.Intact {
		t.Fatalf("the truncated prefix is still internally valid (expected): %+v err=%v", v, err)
	}
	v, _ := s.VerifyAudit()
	if v.Intact || !strings.Contains(v.Detail, "truncated") {
		t.Fatalf("the anchor must catch the tail truncation: %+v", v)
	}
}

// A forged anchor (bad signature) is ignored, so an attacker can't inject a
// lowered anchor to hide a truncation — lowering it needs a valid signature.
func TestAuditAnchorRejectsForgedAnchor(t *testing.T) {
	s, _ := anchoredServer(t)
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t"})

	forged, _ := json.Marshal(AuditAnchor{Chained: 1, Head: "deadbeef", Sig: "00"})
	if err := s.secrets.Save(context.Background(), auditAnchorKey, forged); err != nil {
		t.Fatal(err)
	}
	if s.loadAuditAnchor() != nil {
		t.Fatal("an anchor with an invalid signature must be ignored, not trusted")
	}
}
