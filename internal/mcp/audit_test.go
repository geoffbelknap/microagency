package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAuditLogPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	// session 1: record a proxied call and a reduce
	s1 := newTestServer(t, fakeRunner{}, WithStateDir(dir))
	s1.putRun(s1.nextRunID(), runRecord{Kind: "proxy", Upstream: "supabase", Tool: "execute_sql", Args: "select 1"})
	s1.putRun(s1.nextRunID(), runRecord{Kind: "reduce", SourceID: "demo"})
	if got := len(s1.RunLog()); got != 2 {
		t.Fatalf("session 1: got %d runs, want 2", got)
	}

	// "restart": a fresh Server over the same state dir replays the persisted log
	s2 := newTestServer(t, fakeRunner{}, WithStateDir(dir))
	log := s2.RunLog()
	if len(log) != 2 {
		t.Fatalf("audit history lost across restart: got %d runs, want 2", len(log))
	}
	if log[0].Upstream != "supabase" && log[1].Upstream != "supabase" {
		t.Fatalf("persisted proxy record missing its detail: %+v", log)
	}
	// new run ids continue past the restored history (no collision)
	if id := s2.nextRunID(); id != "run_3" {
		t.Fatalf("run-id counter not restored: next = %q, want run_3", id)
	}
}

// The chain makes tampering DETECTABLE: an intact log verifies; editing a line
// in place or deleting one breaks verification at that line.
func TestAuditChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(fakeRunner{}, WithStateDir(dir))
	for i := 0; i < 3; i++ {
		s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t", Args: `{"i":` + strconv.Itoa(i) + `}`})
	}
	path := filepath.Join(dir, "audit.jsonl")

	v, err := VerifyAuditLog(path, nil)
	if err != nil || !v.Intact || v.Lines != 3 || v.Chained != 3 {
		t.Fatalf("fresh log must verify intact: %+v err=%v", v, err)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	// Edit line 2 in place (change the recorded args, keep its hash).
	edited := append([]string{}, lines...)
	edited[1] = strings.Replace(edited[1], `\"i\":1`, `\"i\":9`, 1)
	if edited[1] == lines[1] {
		t.Fatal("test setup: edit did not change the line")
	}
	os.WriteFile(path, []byte(strings.Join(edited, "\n")+"\n"), 0o600)
	if v, _ := VerifyAuditLog(path, nil); v.Intact || v.BreakAt != 2 {
		t.Fatalf("in-place edit must break verification at line 2: %+v", v)
	}

	// Delete line 2 entirely — line 3 no longer links to line 1.
	os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if v, _ := VerifyAuditLog(path, nil); v.Intact || v.BreakAt != 2 {
		t.Fatalf("deleting a line must break the chain at line 2: %+v", v)
	}
}

// A restarted server resumes the chain from the last persisted link — the log
// stays verifiable across restarts.
func TestAuditChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(fakeRunner{}, WithStateDir(dir))
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "a"})

	s2 := NewServer(fakeRunner{}, WithStateDir(dir))
	s2.putRun(s2.nextRunID(), runRecord{Kind: "proxy", Tool: "b"})

	v, err := VerifyAuditLog(filepath.Join(dir, "audit.jsonl"), nil)
	if err != nil || !v.Intact || v.Chained != 2 {
		t.Fatalf("chain must continue across restart: %+v err=%v", v, err)
	}
}

// Lines written before the chain existed (no hash field) are tolerated: the log
// verifies, with only the chained suffix counted.
func TestAuditChainToleratesLegacyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	legacy, _ := json.Marshal(auditLine{RunID: "run_1", Rec: runRecord{Kind: "proxy", Tool: "old"}})
	legacy2, _ := json.Marshal(auditLine{RunID: "run_2", Rec: runRecord{Kind: "proxy", Tool: "old2"}})
	os.WriteFile(path, []byte(string(legacy)+"\n"+string(legacy2)+"\n"), 0o600)

	s := NewServer(fakeRunner{}, WithStateDir(dir)) // loads legacy history
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "new"})

	v, err := VerifyAuditLog(path, nil)
	if err != nil || !v.Intact {
		t.Fatalf("legacy prefix must not fail verification: %+v err=%v", v, err)
	}
	if v.Lines != 3 || v.Chained != 1 {
		t.Fatalf("lines=%d chained=%d, want 3/1", v.Lines, v.Chained)
	}
}
