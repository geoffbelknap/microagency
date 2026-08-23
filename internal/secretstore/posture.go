package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PostureFile is the non-secret record of the credential store a gateway
// actually opened.
const PostureFile = "credential-store.json"

// Posture is what the gateway resolved at startup, written where a diagnostic
// can read it. A store is chosen from configuration plus what the host will
// actually allow, and those two can disagree — an operator who is told the
// configured store when a different one holds the credentials will remediate
// the wrong thing. Recording the resolved store makes `doctor` able to report
// what is in effect instead of inferring what should be.
//
// Nothing here is secret: a pid, a store kind, and the phrases an operator
// reads. The pid is recorded so a file left behind by an exited gateway is
// never mistaken for the live one.
type Posture struct {
	PID  int    `json:"pid"`
	Kind string `json:"kind"` // vault | encrypted-file | file
	// Effective describes the store holding credentials right now.
	Effective string `json:"effective"`
	// Configured is the store the deployment asked for, recorded only when it
	// is not the one in effect.
	Configured string `json:"configured,omitempty"`
	// Reason says why Configured is not in effect.
	Reason string `json:"reason,omitempty"`
	// Degraded marks a store that protects credentials less than the
	// deployment's configuration intends.
	Degraded bool   `json:"degraded,omitempty"`
	Recorded string `json:"recorded"`
}

// Disagrees reports whether the configured store is not the one in effect.
func (p Posture) Disagrees() bool {
	return p.Configured != "" && p.Configured != p.Effective
}

// PosturePath is where the record lives under a state directory.
func PosturePath(stateDir string) string { return filepath.Join(stateDir, PostureFile) }

// SavePosture records the resolved store. It is written 0600 for consistency
// with the rest of the state directory, not because it holds anything secret.
func SavePosture(stateDir string, p Posture) error {
	if p.Recorded == "" {
		p.Recorded = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(PosturePath(stateDir), b, 0o600)
}

// LoadPosture reads the record. A caller must check PID against the running
// gateway before trusting it; a record whose pid is not the live gateway
// describes a run that has ended.
func LoadPosture(stateDir string) (Posture, error) {
	var p Posture
	b, err := os.ReadFile(PosturePath(stateDir))
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("secretstore: decode credential-store record: %w", err)
	}
	if p.Kind == "" {
		return p, errors.New("secretstore: credential-store record names no store")
	}
	return p, nil
}

// ClearPosture removes the record (used when the gateway stops).
func ClearPosture(stateDir string) {
	_ = os.Remove(PosturePath(stateDir))
}
