package mcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"microagency/internal/secretstore"
)

const decisionAnchorKey = "decision-ledger-anchor"

type decisionRecord struct {
	Timestamp      time.Time `json:"timestamp"`
	Principal      string    `json:"principal"`
	Campaign       string    `json:"campaign"`
	GrantID        string    `json:"grant_id,omitempty"`
	GrantDigest    string    `json:"grant_digest,omitempty"`
	Connection     string    `json:"connection,omitempty"`
	Operation      string    `json:"operation"`
	Effect         string    `json:"effect,omitempty"`
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason"`
	RequestBytes   int64     `json:"request_bytes,omitempty"`
	ReservedBytes  int64     `json:"reserved_bytes,omitempty"`
	ResourceIDs    []string  `json:"resource_ids,omitempty"`
	SharedWritable []string  `json:"shared_writable_ids,omitempty"`
}

type decisionLine struct {
	Sequence int64          `json:"sequence"`
	Record   decisionRecord `json:"record"`
	Prev     string         `json:"prev,omitempty"`
	Hash     string         `json:"hash"`
	Sig      string         `json:"sig"`
}

type decisionAnchor struct {
	Sequence int64  `json:"sequence"`
	Head     string `json:"head"`
	Sig      string `json:"sig"`
}

type grantUsage struct {
	Requests int64
	Bytes    int64
	Times    []time.Time
}

func decisionHash(prev string, sequence int64, record decisionRecord) string {
	b, _ := json.Marshal(struct {
		Sequence int64          `json:"sequence"`
		Record   decisionRecord `json:"record"`
	}{sequence, record})
	sum := sha256.Sum256(append([]byte(prev+"\x00"), b...))
	return hex.EncodeToString(sum[:])
}

func (s *Server) decisionLedgerPath() string {
	if s.stateDir == "" {
		return ""
	}
	return filepath.Join(s.stateDir, "decision-ledger.jsonl")
}

func defaultDecisionAppend(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// authorizeDecision reserves finite grant budgets and fsyncs the signed
// authorization record before the upstream call can begin. Any signer, ledger,
// or anchor failure refuses the crossing.
func (s *Server) authorizeDecision(evaluated evaluatedGrant, argsBytes int, now time.Time) error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	usage := s.decisionUsage[evaluated.Digest]
	if usage == nil {
		usage = &grantUsage{}
	}
	reserved := int64(argsBytes) + evaluated.Grant.MaxResponseBytes
	if usage.Requests+1 > evaluated.Grant.MaxRequests {
		return s.refuseDecisionLocked(evaluated.Grant.Principal, evaluated.Grant.Campaign, evaluated.Grant.Connection, evaluated.Grant.Tool, evaluated.Grant.ID, evaluated.Digest, "request budget exhausted", now)
	}
	if usage.Bytes+reserved > evaluated.Grant.MaxBytes {
		return s.refuseDecisionLocked(evaluated.Grant.Principal, evaluated.Grant.Campaign, evaluated.Grant.Connection, evaluated.Grant.Tool, evaluated.Grant.ID, evaluated.Digest, "byte budget exhausted", now)
	}
	window := time.Duration(evaluated.Grant.Rate.WindowS) * time.Second
	cutoff := now.Add(-window)
	kept := usage.Times[:0]
	for _, at := range usage.Times {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	usage.Times = kept
	if int64(len(usage.Times))+1 > evaluated.Grant.Rate.Requests {
		return s.refuseDecisionLocked(evaluated.Grant.Principal, evaluated.Grant.Campaign, evaluated.Grant.Connection, evaluated.Grant.Tool, evaluated.Grant.ID, evaluated.Digest, "rate budget exhausted", now)
	}
	record := decisionRecord{
		Timestamp: now.UTC(), Principal: evaluated.Grant.Principal, Campaign: evaluated.Grant.Campaign,
		GrantID: evaluated.Grant.ID, GrantDigest: evaluated.Digest, Connection: evaluated.Grant.Connection,
		Operation: evaluated.Grant.Tool, Effect: evaluated.Grant.Effect, Decision: "authorized", Reason: "grant matched",
		RequestBytes: int64(argsBytes), ReservedBytes: reserved,
		ResourceIDs: append([]string(nil), evaluated.ResourceIDs...), SharedWritable: append([]string(nil), evaluated.SharedWritableID...),
	}
	if err := s.appendDecisionLocked(record); err != nil {
		return fmt.Errorf("decision ledger unavailable: %w", err)
	}
	usage.Requests++
	usage.Bytes += reserved
	usage.Times = append(usage.Times, now)
	s.decisionUsage[evaluated.Digest] = usage
	return nil
}

func (s *Server) refuseDecision(principal, campaign, connection, operation, grantID, digest, reason string) error {
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	return s.refuseDecisionLocked(principal, campaign, connection, operation, grantID, digest, reason, time.Now())
}

func (s *Server) refuseDecisionLocked(principal, campaign, connection, operation, grantID, digest, reason string, now time.Time) error {
	record := decisionRecord{
		Timestamp: now.UTC(), Principal: principal, Campaign: campaign, GrantID: grantID,
		GrantDigest: digest, Connection: connection, Operation: operation,
		Decision: "refused", Reason: reason,
	}
	if err := s.appendDecisionLocked(record); err != nil {
		return fmt.Errorf("record refusal: %w", err)
	}
	return errors.New(reason)
}

func (s *Server) appendDecisionLocked(record decisionRecord) error {
	if s.decisionLoadErr != "" {
		return fmt.Errorf("existing decision ledger is not trusted: %s", s.decisionLoadErr)
	}
	if s.decisionLedgerPath() == "" {
		return fmt.Errorf("state directory is not configured")
	}
	if s.auditSigner == nil {
		return fmt.Errorf("decision ledger signer is not configured")
	}
	if s.secrets == nil {
		return fmt.Errorf("decision ledger anchor store is not configured")
	}
	sequence := s.decisionSequence + 1
	hash := decisionHash(s.decisionHash, sequence, record)
	sig, err := s.auditSigner.SignBytes([]byte(hash))
	if err != nil {
		return fmt.Errorf("sign decision: %w", err)
	}
	line := decisionLine{Sequence: sequence, Record: record, Prev: s.decisionHash, Hash: hash, Sig: hex.EncodeToString(sig)}
	b, err := json.Marshal(line)
	if err != nil {
		return err
	}
	appendLine := s.decisionAppend
	if appendLine == nil {
		appendLine = defaultDecisionAppend
	}
	if err := appendLine(s.decisionLedgerPath(), b); err != nil {
		return fmt.Errorf("append and fsync decision: %w", err)
	}
	s.decisionSequence, s.decisionHash = sequence, hash
	anchor := decisionAnchor{Sequence: sequence, Head: hash}
	anchorInput, _ := json.Marshal(struct {
		Sequence int64  `json:"sequence"`
		Head     string `json:"head"`
	}{sequence, hash})
	anchorSig, err := s.auditSigner.SignBytes(anchorInput)
	if err != nil {
		return fmt.Errorf("sign decision anchor: %w", err)
	}
	anchor.Sig = hex.EncodeToString(anchorSig)
	anchorRaw, _ := json.Marshal(anchor)
	if err := s.secrets.Save(context.Background(), decisionAnchorKey, anchorRaw); err != nil {
		return fmt.Errorf("persist decision anchor: %w", err)
	}
	return nil
}

func (s *Server) loadDecisionLedger() {
	path := s.decisionLedgerPath()
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && s.secrets != nil {
			if _, anchorErr := s.secrets.Load(context.Background(), decisionAnchorKey); anchorErr == nil {
				s.decisionLoadErr = "ledger is missing but an anchor exists"
			} else if !errors.Is(anchorErr, secretstore.ErrNotFound) {
				s.decisionLoadErr = "decision anchor could not be read"
			}
		}
		return
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	var prev string
	var sequence int64
	usage := map[string]*grantUsage{}
	for scanner.Scan() {
		var line decisionLine
		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Sequence != sequence+1 || line.Prev != prev || line.Hash != decisionHash(prev, line.Sequence, line.Record) {
			s.decisionLoadErr = "decision chain is malformed"
			return
		}
		if s.auditSigner == nil {
			s.decisionLoadErr = "decision signer is unavailable"
			return
		}
		sig, err := hex.DecodeString(line.Sig)
		if err != nil || !s.auditSigner.VerifyBytes([]byte(line.Hash), sig) {
			s.decisionLoadErr = "decision signature is invalid"
			return
		}
		prev, sequence = line.Hash, line.Sequence
		if line.Record.Decision == "authorized" && line.Record.GrantDigest != "" {
			u := usage[line.Record.GrantDigest]
			if u == nil {
				u = &grantUsage{}
				usage[line.Record.GrantDigest] = u
			}
			u.Requests++
			u.Bytes += line.Record.ReservedBytes
			u.Times = append(u.Times, line.Record.Timestamp)
		}
	}
	if err := scanner.Err(); err != nil {
		s.decisionLoadErr = err.Error()
		return
	}
	s.decisionHash, s.decisionSequence, s.decisionUsage = prev, sequence, usage
	if sequence == 0 {
		return
	}
	if s.secrets == nil {
		s.decisionLoadErr = "decision anchor store is unavailable"
		return
	}
	raw, err := s.secrets.Load(context.Background(), decisionAnchorKey)
	if err != nil {
		s.decisionLoadErr = "decision anchor is unavailable"
		return
	}
	var anchor decisionAnchor
	if json.Unmarshal(raw, &anchor) != nil {
		s.decisionLoadErr = "decision anchor is malformed"
		return
	}
	input, _ := json.Marshal(struct {
		Sequence int64  `json:"sequence"`
		Head     string `json:"head"`
	}{anchor.Sequence, anchor.Head})
	anchorSig, err := hex.DecodeString(anchor.Sig)
	if err != nil || !s.auditSigner.VerifyBytes(input, anchorSig) || anchor.Sequence != sequence || anchor.Head != prev {
		s.decisionLoadErr = "decision ledger does not match its signed anchor"
	}
}

type DecisionVerification struct {
	Intact   bool   `json:"intact"`
	Records  int64  `json:"records"`
	Head     string `json:"head,omitempty"`
	Anchored bool   `json:"anchored"`
	Error    string `json:"error,omitempty"`
}

func (s *Server) VerifyDecisionLedger(ctx context.Context) DecisionVerification {
	verification := DecisionVerification{Intact: true}
	f, err := os.Open(s.decisionLedgerPath())
	if err != nil {
		if os.IsNotExist(err) {
			if s.secrets != nil {
				if _, anchorErr := s.secrets.Load(ctx, decisionAnchorKey); anchorErr == nil {
					return DecisionVerification{Error: "decision ledger is missing but its anchor exists"}
				} else if !errors.Is(anchorErr, secretstore.ErrNotFound) {
					return DecisionVerification{Error: "decision anchor is unavailable"}
				}
			}
			return verification
		}
		return DecisionVerification{Error: err.Error()}
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	var prev string
	for scanner.Scan() {
		var line decisionLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil || line.Sequence != verification.Records+1 || line.Prev != prev || line.Hash != decisionHash(prev, line.Sequence, line.Record) {
			return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision chain is malformed"}
		}
		sig, err := hex.DecodeString(line.Sig)
		if err != nil || s.auditSigner == nil || !s.auditSigner.VerifyBytes([]byte(line.Hash), sig) {
			return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision signature is invalid"}
		}
		verification.Records, prev = line.Sequence, line.Hash
	}
	if err := scanner.Err(); err != nil {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: err.Error()}
	}
	verification.Head = prev
	if s.secrets == nil {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision anchor store is unavailable"}
	}
	raw, err := s.secrets.Load(ctx, decisionAnchorKey)
	if err != nil {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision anchor is unavailable"}
	}
	var anchor decisionAnchor
	if json.Unmarshal(raw, &anchor) != nil {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision anchor is malformed"}
	}
	input, _ := json.Marshal(struct {
		Sequence int64  `json:"sequence"`
		Head     string `json:"head"`
	}{anchor.Sequence, anchor.Head})
	sig, err := hex.DecodeString(anchor.Sig)
	if err != nil || s.auditSigner == nil || !s.auditSigner.VerifyBytes(input, sig) {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision anchor signature is invalid"}
	}
	if anchor.Sequence != verification.Records || anchor.Head != verification.Head {
		return DecisionVerification{Records: verification.Records, Head: prev, Error: "decision ledger does not match its anchor"}
	}
	verification.Anchored = true
	return verification
}

func sortedGrantDigests(grants []OperationGrant) []string {
	var out []string
	for _, grant := range grants {
		if digest, err := grantDigest(grant); err == nil {
			out = append(out, digest)
		}
	}
	sort.Strings(out)
	return out
}
