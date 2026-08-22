package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"microagency/internal/tunnel"
)

// tunnelState is the on-disk record of the tunnel subprocess this server run
// started — public identifiers only. It exists so `microagency doctor` can
// answer "is the public URL actually being served" from outside the server
// process: the pid is probed live, and a recorded exit carries the child's
// exit state.
type tunnelState struct {
	Provider  string `json:"provider"`
	Mode      string `json:"mode"` // "quick" or "named"
	Name      string `json:"name,omitempty"`
	URL       string `json:"url,omitempty"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	ExitedAt  string `json:"exited_at,omitempty"`
	ExitError string `json:"exit_error,omitempty"`
}

func tunnelStatePath() string { return filepath.Join(microagencyDir(), "tunnel-state.json") }

// tunnelMode names the two tunnel contracts: a quick tunnel's URL is assigned
// per run, a named tunnel's URL is operator-declared and stable.
func tunnelMode(cfg httpConfig) string {
	if cfg.tunnelName != "" {
		return "named"
	}
	return "quick"
}

func newTunnelState(cfg httpConfig, pid int) tunnelState {
	return tunnelState{
		Provider:  cfg.tunnel,
		Mode:      tunnelMode(cfg),
		Name:      cfg.tunnelName,
		URL:       cfg.publicURL,
		PID:       pid,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func writeTunnelState(path string, st tunnelState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readTunnelState(path string) (tunnelState, error) {
	var st tunnelState
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

// markTunnelExited records the child's death on the state file, so doctor can
// report why the public URL stopped serving even after the pid is long gone.
func markTunnelExited(path string, exitErr error) {
	st, err := readTunnelState(path)
	if err != nil {
		return
	}
	st.ExitedAt = time.Now().UTC().Format(time.RFC3339)
	if exitErr != nil {
		st.ExitError = exitErr.Error()
	}
	_ = writeTunnelState(path, st)
}

// watchTunnel is the death watch for the tunnel subprocess: tunnel start used
// to be fire-and-forget, so a dead provider left the server up, the public URL
// unreachable, and nothing anywhere saying so. A requested Close (shutdown) is
// not a death and passes silently; anything else logs loudly with the child's
// last output and lands in the state file for doctor.
func watchTunnel(t *tunnel.Tunnel, statePath string) {
	<-t.Done()
	if t.Stopped() {
		return
	}
	slog.Error("tunnel process exited — the public URL is no longer being served; restart with `microagency restart`",
		"pid", t.Pid(), "err", t.ExitError(), "last_output", strings.Join(t.Tail(), " | "))
	markTunnelExited(statePath, t.ExitError())
}

// processAlive reports whether pid is a live process we could signal. Signal 0
// probes existence without touching the target.
func processAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}
