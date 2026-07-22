package mcp

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
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
	// reordering, or deleting any line breaks every hash after it. Sig is an ES256
	// signature over Hash (hex), present when an audit signer is configured: it makes
	// the chain UNFORGEABLE — a key-less attacker who can write the file cannot
	// recompute a valid record, because Hash alone is public and recomputable but the
	// signature over it is not. It also makes the log verifiable OFFLINE by anyone
	// holding only the public key. The residual the chain still can't stop is
	// wholesale tail truncation (deleting the last N lines leaves a valid prefix) —
	// that requires an external high-water anchor. Verified by VerifyAuditLog and
	// GET /admin/audit/verify.
	Prev string `json:"prev,omitempty"`
	Hash string `json:"hash,omitempty"`
	Sig  string `json:"sig,omitempty"`
}

// chainHash computes one line's chained hash from its predecessor's. It hashes
// only RunID+Rec (Prev/Hash/Sig are omitempty and absent here), so the signature
// over Hash below binds the record and its chain position without self-reference.
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
		slog.Error("audit log write failed", "err", err)
		return
	}
	defer func() { _ = f.Close() }()
	line := auditLine{RunID: id, Rec: rec, Prev: s.auditHash, Hash: chainHash(s.auditHash, id, rec)}
	if s.auditSigner != nil {
		if sig, err := s.auditSigner.SignBytes([]byte(line.Hash)); err == nil {
			line.Sig = hex.EncodeToString(sig)
		} else {
			slog.Warn("audit log sign failed; line unsigned", "err", err) // verification flags the gap
		}
	}
	b, _ := json.Marshal(line)
	if _, err := f.Write(append(b, '\n')); err != nil {
		slog.Error("audit log write failed", "err", err)
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
	// Replays run before the server serves, so no concurrency — but addRunLocked
	// mutates the same fields putRun does, so hold mu for the invariant. Every line
	// folds into the all-time cumulative totals; only the last maxRuns stay in the
	// in-memory window, so replaying a huge log doesn't reload it all into memory.
	s.mu.Lock()
	for sc.Scan() {
		var line auditLine
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.RunID == "" {
			malformed++ // surfaced (and located) by VerifyAuditLog; counted here so it's never silent
			continue
		}
		s.addRunLocked(line.RunID, line.Rec)
		if line.Hash != "" {
			s.auditHash = line.Hash // resume the chain from the last written link
		}
		if n := runSeq(line.RunID); n > maxSeq {
			maxSeq = n
		}
	}
	s.mu.Unlock()
	if malformed > 0 {
		slog.Warn("audit log has malformed lines; run /admin/audit/verify", "count", malformed)
	}
	s.seq = maxSeq
}

// AuditVerification is the outcome of walking the audit chain.
type AuditVerification struct {
	Lines   int    `json:"lines"`              // total lines examined
	Chained int    `json:"chained"`            // lines carrying chain hashes (legacy lines predate the chain)
	Signed  int    `json:"signed"`             // chained lines carrying a signature
	Intact  bool   `json:"intact"`             // chain links, and every signature (if a verifier was supplied) checks out
	BreakAt int    `json:"break_at,omitempty"` // 1-based line number of the first break
	Detail  string `json:"detail,omitempty"`   // what broke there
}

// VerifyAuditLog walks the persisted chain and reports the first break, if any.
// When verify is non-nil, each signed line's ES256 signature is checked against
// its hash, so an attacker who rewrites a record (and recomputes its public hash)
// is still caught for lacking a valid signature; pass nil to check chain linkage
// only.
//
// Two legacy prefixes are tolerated so upgrades don't false-alarm on old history:
// lines predating the chain (no hash) and chained lines predating signing (no
// sig) are accepted ONLY as a leading run. Once a chained line has been seen, a
// later hash-less line is a break (this closes the hole where forged records were
// appended with the hash fields omitted and silently accepted); once a signed
// line has been seen, a later unsigned line is a break.
func VerifyAuditLog(path string, verify func(hash, sig []byte) bool) (AuditVerification, error) {
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
	fail := func(detail string) { v.Intact, v.BreakAt, v.Detail = false, v.Lines, detail }
	prev := ""
	seenChained, seenSigned := false, false
	for sc.Scan() {
		v.Lines++
		var line auditLine
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.RunID == "" {
			fail("malformed line")
			return v, nil
		}
		if line.Hash == "" {
			if seenChained {
				fail("unchained line after chained history (inserted or forged)")
				return v, nil
			}
			continue // pre-chain legacy prefix line
		}
		seenChained = true
		v.Chained++
		if line.Prev != prev {
			fail(fmt.Sprintf("chain break: prev=%.12s… want %.12s…", line.Prev, prev))
			return v, nil
		}
		if chainHash(line.Prev, line.RunID, line.Rec) != line.Hash {
			fail("record does not match its hash (edited in place)")
			return v, nil
		}
		if line.Sig != "" {
			v.Signed++
			if verify != nil {
				sig, err := hex.DecodeString(line.Sig)
				if err != nil || !verify([]byte(line.Hash), sig) {
					fail("invalid signature (forged or edited)")
					return v, nil
				}
			}
			seenSigned = true
		} else if seenSigned {
			fail("unsigned line after signed history (signature stripped or forged)")
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
