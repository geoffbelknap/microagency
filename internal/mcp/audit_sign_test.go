package mcp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"microagency/internal/auth"
)

func newSignedAuditServer(t *testing.T, dir string, n int) (*auth.Signer, string) {
	t.Helper()
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithAuditSigner(signer))
	for i := 0; i < n; i++ {
		s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "t", Args: `{"i":` + strconv.Itoa(i) + `}`})
	}
	return signer, filepath.Join(dir, "audit.jsonl")
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// A signed chain verifies intact, and every line is counted as signed.
func TestAuditSignedChainVerifies(t *testing.T) {
	dir := t.TempDir()
	signer, path := newSignedAuditServer(t, dir, 3)
	v, err := VerifyAuditLog(path, signer.VerifyBytes)
	if err != nil || !v.Intact || v.Chained != 3 || v.Signed != 3 {
		t.Fatalf("signed chain must verify intact and signed: %+v err=%v", v, err)
	}
}

// THE tamper-evidence property: an attacker edits a record and recomputes its
// chain hash (public, keyless) so chain-only verification passes — but cannot
// re-sign it, so signature verification catches the forgery. This is exactly the
// gap keyless chaining left open.
func TestAuditRewrittenRecordFailsSignatureButPassesChainOnly(t *testing.T) {
	dir := t.TempDir()
	signer, path := newSignedAuditServer(t, dir, 3)
	lines := readLines(t, path)

	// Rewrite the LAST line's record (no successor whose Prev would break), recompute
	// its chain hash correctly, and keep the now-stale signature — what a key-less
	// attacker can do.
	var last auditLine
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("unmarshal last line: %v", err)
	}
	last.Rec.Args = `{"i":999}`                            // the tamper
	last.Hash = chainHash(last.Prev, last.RunID, last.Rec) // recompute the public hash
	forged, _ := json.Marshal(last)
	lines[len(lines)-1] = string(forged)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	// Chain-only verification is FOOLED (the hash was recomputed to match).
	if v, _ := VerifyAuditLog(path, nil); !v.Intact {
		t.Fatalf("chain-only verify should pass on a recomputed hash (that's the weakness): %+v", v)
	}
	// Signature verification CATCHES it (the signature can't be recomputed).
	v, _ := VerifyAuditLog(path, signer.VerifyBytes)
	if v.Intact || v.BreakAt != len(lines) || !strings.Contains(v.Detail, "signature") {
		t.Fatalf("signature verify must reject the forged record: %+v", v)
	}
}

// A forged record appended with the hash/sig fields omitted (the exploit the old
// verifier allowed by skipping hash-less lines) is rejected once the chain has
// begun — with or without a signature verifier.
func TestAuditForgedUnchainedAppendRejected(t *testing.T) {
	dir := t.TempDir()
	signer, path := newSignedAuditServer(t, dir, 2)

	forged, _ := json.Marshal(auditLine{RunID: "run_99", Rec: runRecord{Kind: "proxy", Tool: "forged"}})
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write(append(forged, '\n'))
	f.Close()

	for _, verify := range []func(_, _ []byte) bool{nil, signer.VerifyBytes} {
		v, _ := VerifyAuditLog(path, verify)
		if v.Intact || v.BreakAt != 3 {
			t.Fatalf("forged unchained append must break at line 3 (verify=%v): %+v", verify != nil, v)
		}
	}
}

// Downgrade attempt: stripping the signature off a line after signing began is a
// break — an attacker can't quietly drop signatures to dodge signature checks.
func TestAuditStrippedSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	signer, path := newSignedAuditServer(t, dir, 2)
	lines := readLines(t, path)

	var last auditLine
	json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	last.Sig = "" // strip the signature, leaving the (valid) chain hash
	stripped, _ := json.Marshal(last)
	lines[len(lines)-1] = string(stripped)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	v, _ := VerifyAuditLog(path, signer.VerifyBytes)
	if v.Intact || !strings.Contains(v.Detail, "unsigned") {
		t.Fatalf("stripped signature must be rejected: %+v", v)
	}
}

// A signer whose key differs from the one that signed the log rejects it — the
// log is bound to its signing key, so offline verification needs the right key.
func TestAuditWrongKeyRejects(t *testing.T) {
	dir := t.TempDir()
	_, path := newSignedAuditServer(t, dir, 2)
	other, _ := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "other-key"))
	v, _ := VerifyAuditLog(path, other.VerifyBytes)
	if v.Intact || !strings.Contains(v.Detail, "signature") {
		t.Fatalf("a different key must fail verification: %+v", v)
	}
}

// Upgrade path: a log that already has chained-but-UNSIGNED lines (written before
// signing was enabled) still verifies once signing begins — the unsigned lines are
// tolerated as a leading prefix, and signed lines are checked from there on.
func TestAuditUnsignedPrefixThenSignedVerifies(t *testing.T) {
	dir := t.TempDir()
	// Before the upgrade: an unsigned server writes a chained line.
	NewServer(fakeRunner{}, WithStateDir(dir)).putRun("run_1", runRecord{Kind: "proxy", Tool: "old"})
	// After the upgrade: a signed server over the same dir appends signed lines.
	signer, err := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "audit-key"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	s := NewServer(fakeRunner{}, WithStateDir(dir), WithAuditSigner(signer))
	s.putRun(s.nextRunID(), runRecord{Kind: "proxy", Tool: "new"})

	v, err := VerifyAuditLog(filepath.Join(dir, "audit.jsonl"), signer.VerifyBytes)
	if err != nil || !v.Intact || v.Chained != 2 || v.Signed != 1 {
		t.Fatalf("unsigned prefix + signed suffix must verify: %+v err=%v", v, err)
	}
}

// Sanity: SignBytes/VerifyBytes round-trip and reject altered data.
func TestSignerSignVerifyRoundTrip(t *testing.T) {
	signer, _ := auth.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k"))
	sig, err := signer.SignBytes([]byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !signer.VerifyBytes([]byte("hello"), sig) {
		t.Fatal("valid signature must verify")
	}
	if signer.VerifyBytes([]byte("hell0"), sig) {
		t.Fatal("altered data must not verify")
	}
	bad, _ := hex.DecodeString("deadbeef")
	if signer.VerifyBytes([]byte("hello"), bad) {
		t.Fatal("garbage signature must not verify")
	}
}
