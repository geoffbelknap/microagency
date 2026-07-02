// Package baomanager makes OpenBao a managed dependency: microagency runs its own
// dedicated OpenBao instance, initializes and unseals it, and reports the address +
// token to use. The bootstrap (a single unseal key + the root token) is stored in a
// 0600 file for now — keychain/KMS auto-unseal is the hardening follow-up; the file
// posture is stated plainly so it isn't theater-by-omission.
package baomanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Manager supervises one OpenBao instance under Dir.
type Manager struct {
	Dir    string // e.g. ~/.microagency/openbao
	Addr   string // http://127.0.0.1:8200
	binary string
	client *http.Client
	// reset resets the storage to a fresh, uninitialized state. nil = the default
	// (stop bao, archive the orphaned data, restart fresh); tests inject a stub.
	reset func(context.Context) error
}

type bootstrap struct {
	UnsealKey string `json:"unseal_key"`
	RootToken string `json:"root_token"`
}

// Ensure brings OpenBao up and returns the address + token microagency should use.
// If VAULT_ADDR is already set (an external Bao the operator runs), it returns that
// and manages nothing. Otherwise it resolves the bao binary, starts a dedicated
// server, initializes-or-unseals it, ensures a KV v2 mount, and returns its address
// + root token.
func Ensure(ctx context.Context, dir string, getenv func(string) string) (addr, token string, err error) {
	if a := getenv("VAULT_ADDR"); a != "" {
		return a, getenv("VAULT_TOKEN"), nil
	}
	bin, err := resolveBinary()
	if err != nil {
		return "", "", err
	}
	m := &Manager{
		Dir: dir, Addr: "http://127.0.0.1:8200", binary: bin,
		client: &http.Client{Timeout: 10 * time.Second},
	}
	if err := m.start(); err != nil {
		return "", "", err
	}
	if err := m.waitReachable(ctx); err != nil {
		return "", "", err
	}
	tok, err := m.initOrUnseal(ctx)
	if err != nil {
		return "", "", err
	}
	if err := m.ensureKVv2(ctx, tok); err != nil {
		return "", "", err
	}
	return m.Addr, tok, nil
}

// Stop terminates the managed OpenBao recorded in the pid file (used by `down`).
func Stop(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "bao.pid"))
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	_ = os.Remove(filepath.Join(dir, "bao.pid"))
}

func resolveBinary() (string, error) {
	for _, name := range []string{"bao", "openbao"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("openbao not found on PATH — install it (e.g. `brew install openbao`)")
}

const configTmpl = `storage "file" { path = "%s/data" }
listener "tcp" { address = "127.0.0.1:8200" tls_disable = 1 }
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
`

// start launches `bao server` as a detached, supervised subprocess — unless an
// instance is already reachable at Addr (idempotent across restarts).
func (m *Manager) start() error {
	if m.reachable() {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(m.Dir, "data"), 0o700); err != nil {
		return err
	}
	cfg := filepath.Join(m.Dir, "bao.hcl")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(configTmpl, m.Dir)), 0o600); err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(m.Dir, "bao.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	cmd := exec.Command(m.binary, "server", "-config="+cfg)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start openbao: %w", err)
	}
	return os.WriteFile(filepath.Join(m.Dir, "bao.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
}

func (m *Manager) reachable() bool {
	resp, err := m.client.Get(m.Addr + "/v1/sys/seal-status")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

func (m *Manager) waitReachable(ctx context.Context) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m.reachable() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("openbao did not become reachable at %s — see %s/bao.log", m.Addr, m.Dir)
}

type sealStatus struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

func (m *Manager) sealStatus(ctx context.Context) (sealStatus, error) {
	var st sealStatus
	err := m.do(ctx, http.MethodGet, "/v1/sys/seal-status", "", nil, &st)
	return st, err
}

// initOrUnseal initializes a fresh Bao (storing the bootstrap) or unseals an
// existing one from the stored bootstrap, returning the root token.
func (m *Manager) initOrUnseal(ctx context.Context) (string, error) {
	st, err := m.sealStatus(ctx)
	if err != nil {
		return "", err
	}
	// Initialized, but the bootstrap (the only copy of the unseal key + root token)
	// is gone: the vault can never be unsealed again, so its contents are lost no
	// matter what we do. Rather than fail every start forever — which silently drops
	// microagency to the file store and strands the OAuth tokens there — reset the
	// vault to a fresh, usable state. Upstream connections held in the old vault must
	// be re-authorized afterward. This turns a permanent brick into a one-time reset.
	if st.Initialized {
		if _, lerr := loadBootstrap(m.Dir); lerr != nil {
			log.Printf("microagency: OpenBao is initialized but its bootstrap is missing — the vault is unrecoverable; resetting it fresh (re-authorize upstream connections afterward)")
			if rerr := m.resetStorage(ctx); rerr != nil {
				return "", fmt.Errorf("reset unrecoverable openbao: %w", rerr)
			}
			if st, err = m.sealStatus(ctx); err != nil {
				return "", err
			}
		}
	}
	if !st.Initialized {
		var out struct {
			KeysB64   []string `json:"keys_base64"`
			RootToken string   `json:"root_token"`
		}
		if err := m.do(ctx, http.MethodPut, "/v1/sys/init", "", map[string]int{"secret_shares": 1, "secret_threshold": 1}, &out); err != nil {
			return "", fmt.Errorf("openbao init: %w", err)
		}
		if len(out.KeysB64) == 0 || out.RootToken == "" {
			return "", fmt.Errorf("openbao init returned no key/token")
		}
		bs := bootstrap{UnsealKey: out.KeysB64[0], RootToken: out.RootToken}
		if err := saveBootstrap(m.Dir, bs); err != nil {
			return "", err
		}
		if err := m.unseal(ctx, bs.UnsealKey); err != nil {
			return "", err
		}
		return bs.RootToken, nil
	}
	bs, err := loadBootstrap(m.Dir)
	if err != nil {
		return "", fmt.Errorf("openbao is initialized but the bootstrap is missing (%s): %w", m.Dir, err)
	}
	if st.Sealed {
		if err := m.unseal(ctx, bs.UnsealKey); err != nil {
			return "", err
		}
	}
	return bs.RootToken, nil
}

func (m *Manager) unseal(ctx context.Context, key string) error {
	return m.do(ctx, http.MethodPut, "/v1/sys/unseal", "", map[string]string{"key": key}, nil)
}

// resetStorage discards an unrecoverable vault and brings OpenBao back up fresh.
// The unseal key is gone, so the old data is inaccessible anyway; it is archived
// (data.orphaned) rather than deleted, in case an operator wants to inspect it.
func (m *Manager) resetStorage(ctx context.Context) error {
	if m.reset != nil {
		return m.reset(ctx)
	}
	Stop(m.Dir) // stop the running bao so its storage files are released
	// Wait (bounded) for the old process to exit and release the port before touching
	// the storage and starting fresh. If it never goes down — e.g. a foreign bao we
	// don't own is bound to this address — give up rather than spin forever.
	deadline := time.Now().Add(10 * time.Second)
	for m.reachable() {
		if time.Now().After(deadline) {
			return fmt.Errorf("openbao at %s did not stop for reset (a bao we don't manage may be bound here)", m.Addr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := archiveBaoStorage(m.Dir); err != nil {
		return err
	}
	if err := m.start(); err != nil {
		return err
	}
	return m.waitReachable(ctx)
}

// archiveBaoStorage moves the orphaned storage aside (keeping only the most recent
// archive) and clears any partial bootstrap, so the next start initializes clean.
func archiveBaoStorage(dir string) error {
	data := filepath.Join(dir, "data")
	orphan := filepath.Join(dir, "data.orphaned")
	_ = os.RemoveAll(orphan)
	if err := os.Rename(data, orphan); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("archive orphaned openbao storage: %w", err)
	}
	_ = os.Remove(bootstrapPath(dir))
	return nil
}

// ensureKVv2 enables the KV v2 secrets engine at secret/ (idempotent — an
// already-existing mount is fine).
func (m *Manager) ensureKVv2(ctx context.Context, token string) error {
	body := map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}
	err := m.do(ctx, http.MethodPost, "/v1/sys/mounts/secret", token, body, nil)
	// Idempotent: after the first run secret/ is already mounted — OpenBao reports
	// "path is already in use at secret/" (or "existing mount"), which is fine.
	if err != nil {
		if e := err.Error(); strings.Contains(e, "in use") || strings.Contains(e, "existing mount") {
			return nil
		}
	}
	return err
}

func (m *Manager) do(ctx context.Context, method, path, token string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.Addr+path, r)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("openbao %s %s: http %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func bootstrapPath(dir string) string { return filepath.Join(dir, "bootstrap.json") }

// saveBootstrap writes the bootstrap atomically: a temp file, fsync'd, then
// renamed over the target. Without this, a plain write interrupted by a kill
// (dev churn, a brew replace) can leave an empty or partial bootstrap.json while
// the vault is already initialized — the exact unrecoverable state resetStorage
// exists to heal. Atomic replace means the file is always either the old contents
// or the complete new ones, never a torn middle.
func saveBootstrap(dir string, bs bootstrap) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(bs)
	tmp := bootstrapPath(dir) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, bootstrapPath(dir))
}

func loadBootstrap(dir string) (bootstrap, error) {
	var bs bootstrap
	b, err := os.ReadFile(bootstrapPath(dir))
	if err != nil {
		return bs, err
	}
	return bs, json.Unmarshal(b, &bs)
}
