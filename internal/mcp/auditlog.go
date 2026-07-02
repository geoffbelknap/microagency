package mcp

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The run/audit log persists to an append-only JSONL file under the state dir, so
// the operator's audit history (every run and proxied call) survives restarts —
// an audit that evaporates on restart isn't an audit. Append-only by design
// (ASK tenet 10: constraint/run history is immutable and complete).

type auditLine struct {
	RunID string    `json:"run_id"`
	Rec   runRecord `json:"rec"`
	// Prev/Hash chain the log: Hash = sha256(Prev || canonical(RunID+Rec)). Editing,
	// reordering, or deleting any line breaks every hash after it, so tampering is
	// DETECTABLE (tenet 10's "immutable" made checkable, not just asserted). The
	// chain can't stop a same-privilege attacker from truncating the tail wholesale —
	// that requires an external anchor — but it turns silent surgery into a visible
	// break, verified by VerifyAuditLog and GET /admin/audit/verify.
	Prev string `json:"prev,omitempty"`
	Hash string `json:"hash,omitempty"`
}

// chainHash computes one line's chained hash from its predecessor's.
func chainHash(prev, runID string, rec runRecord) string {
	b, _ := json.Marshal(auditLine{RunID: runID, Rec: rec})
	h := sha256.Sum256(append([]byte(prev+"\x00"), b...))
	return hex.EncodeToString(h[:])
}

func (s *Server) auditPath() string {
	if s.stateDir == "" {
		return "" // no state dir (e.g. tests) → in-memory only
	}
	return filepath.Join(s.stateDir, "audit.jsonl")
}

// appendAudit writes one record to the append-only log, chained to its
// predecessor. Best-effort: a write failure is logged, never fatal — a failed
// audit write must not block the agent — but the chain makes the resulting gap
// visible to verification instead of silent. Appends serialize on auditMu so
// concurrent runs can't interleave and fork the chain.
func (s *Server) appendAudit(id string, rec runRecord) {
	path := s.auditPath()
	if path == "" {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("microagency: audit log: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	line := auditLine{RunID: id, Rec: rec, Prev: s.auditHash, Hash: chainHash(s.auditHash, id, rec)}
	b, _ := json.Marshal(line)
	if _, err := f.Write(append(b, '\n')); err != nil {
		log.Printf("microagency: audit log: %v", err)
		return
	}
	s.auditHash = line.Hash
}

// loadAudit replays the persisted log into s.runs and restores the run-id counter
// past the highest seen id, so new run ids don't collide with history.
func (s *Server) loadAudit() {
	path := s.auditPath()
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return // no history yet
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	maxSeq, malformed := 0, 0
	for sc.Scan() {
		var line auditLine
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.RunID == "" {
			malformed++ // surfaced (and located) by VerifyAuditLog; counted here so it's never silent
			continue
		}
		s.runs[line.RunID] = line.Rec
		if line.Hash != "" {
			s.auditHash = line.Hash // resume the chain from the last written link
		}
		if n := runSeq(line.RunID); n > maxSeq {
			maxSeq = n
		}
	}
	if malformed > 0 {
		log.Printf("microagency: audit log: %d malformed line(s) skipped — run /admin/audit/verify", malformed)
	}
	s.seq = maxSeq
}

// AuditVerification is the outcome of walking the audit chain.
type AuditVerification struct {
	Lines    int    `json:"lines"`              // total lines examined
	Chained  int    `json:"chained"`            // lines carrying chain hashes (legacy lines predate the chain)
	Intact   bool   `json:"intact"`             // every chained line links to its predecessor
	BreakAt  int    `json:"break_at,omitempty"` // 1-based line number of the first break
	Detail   string `json:"detail,omitempty"`   // what broke there
}

// VerifyAuditLog walks the persisted chain and reports the first break, if any.
// Lines written before the chain existed (no hash) are reported but not failed.
func VerifyAuditLog(path string) (AuditVerification, error) {
	v := AuditVerification{Intact: true}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil // no log yet — vacuously intact
		}
		return v, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	prev := ""
	for sc.Scan() {
		v.Lines++
		var line auditLine
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.RunID == "" {
			v.Intact, v.BreakAt, v.Detail = false, v.Lines, "malformed line"
			return v, nil
		}
		if line.Hash == "" {
			continue // pre-chain legacy line
		}
		v.Chained++
		if line.Prev != prev {
			v.Intact, v.BreakAt, v.Detail = false, v.Lines, fmt.Sprintf("chain break: prev=%.12s… want %.12s…", line.Prev, prev)
			return v, nil
		}
		if chainHash(line.Prev, line.RunID, line.Rec) != line.Hash {
			v.Intact, v.BreakAt, v.Detail = false, v.Lines, "record does not match its hash (edited in place)"
			return v, nil
		}
		prev = line.Hash
	}
	return v, sc.Err()
}

func runSeq(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "run_"))
	return n
}
