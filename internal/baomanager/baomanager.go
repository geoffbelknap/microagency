// Package baomanager makes OpenBao a managed dependency: microagency runs its own
// dedicated OpenBao instance, initializes and unseals it, and reports the address +
// token to use. Protected custody keeps bootstrap material in an OS keyring or an
// operator helper; the compatibility file posture remains explicit and degraded.
package baomanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	Dir     string // e.g. ~/.microagency/openbao
	Addr    string // http://127.0.0.1:8200
	binary  string
	client  *http.Client
	custody custodySelection
	// tokenLease is populated by AppRole login. The periodic token is renewed in
	// place, so callers can keep the returned token string for the process life.
	tokenLease time.Duration
	// reset resets the storage to a fresh, uninitialized state. nil = the default
	// (stop bao, archive the orphaned data, restart fresh); tests inject a stub.
	reset func(context.Context) error
}

type bootstrap struct {
	UnsealKey      string `json:"unseal_key,omitempty"`
	RecoveryKey    string `json:"recovery_key,omitempty"`
	RootToken      string `json:"root_token,omitempty"` // legacy/transitional only; revoked after AppRole setup
	RoleID         string `json:"role_id,omitempty"`
	SecretID       string `json:"secret_id,omitempty"`
	SecretAccessor string `json:"secret_id_accessor,omitempty"`
}

// Ensure brings OpenBao up and returns the address + token microagency should use.
// If VAULT_ADDR is already set (an external Bao the operator runs), it returns that
// and manages nothing. Otherwise it resolves the bao binary, starts a dedicated
// server, initializes-or-unseals it, retires the initial root to a narrow AppRole,
// and returns its address plus a renewable periodic token.
func Ensure(ctx context.Context, dir string, getenv func(string) string) (addr, token string, err error) {
	if a := getenv("VAULT_ADDR"); a != "" {
		token := getenv("VAULT_TOKEN")
		if token == "" {
			return "", "", fmt.Errorf("VAULT_ADDR is set but VAULT_TOKEN is missing")
		}
		return a, token, nil
	}
	if getenv("VAULT_TOKEN") != "" {
		return "", "", fmt.Errorf("VAULT_TOKEN is set but VAULT_ADDR is missing")
	}
	sel, err := selectCustody(dir, getenv)
	if err != nil {
		if protectedRequested(dir, getenv) {
			return "", "", &ProtectedError{Err: err}
		}
		return "", "", err
	}
	if sel.manifest.Protected() {
		if _, statErr := os.Stat(custodyPath(dir)); os.IsNotExist(statErr) {
			// Persist the non-secret locator before OpenBao can initialize. If the
			// first protected write then fails, every later start still knows it
			// must fail closed rather than reset or select a disk fallback.
			if err := saveCustodyManifest(dir, sel.manifest); err != nil {
				return "", "", &ProtectedError{Err: fmt.Errorf("persist protected custody metadata: %w", err)}
			}
		}
	}
	fail := func(err error) (string, string, error) {
		if err != nil && sel.manifest.Protected() {
			err = &ProtectedError{Err: err}
		}
		return "", "", err
	}
	bin, err := resolveBinary()
	if err != nil {
		return fail(err)
	}
	m := &Manager{
		Dir: dir, Addr: ManagedAddr, binary: bin,
		client: &http.Client{Timeout: 10 * time.Second}, custody: sel,
	}
	if err := m.start(); err != nil {
		return fail(err)
	}
	if err := m.waitReachable(ctx); err != nil {
		return fail(err)
	}
	tok, err := m.initOrUnseal(ctx)
	if err != nil {
		return fail(err)
	}
	m.startTokenRenewal(ctx, tok)
	return m.Addr, tok, nil
}

// RotateLogin replaces the persistent AppRole SecretID through the current
// narrow operational token. The new credential is login-tested and durably
// protected before the old accessor is destroyed.
func RotateLogin(ctx context.Context, dir string, getenv func(string) string) error {
	if getenv("VAULT_ADDR") != "" || getenv("VAULT_TOKEN") != "" {
		return errors.New("openbao login rotation applies only to the managed store, not external Vault/OpenBao")
	}
	addr, token, err := Ensure(ctx, dir, getenv)
	if err != nil {
		return err
	}
	sel, err := selectCustody(dir, getenv)
	if err != nil {
		if protectedRequested(dir, getenv) {
			return &ProtectedError{Err: err}
		}
		return err
	}
	m := &Manager{Dir: dir, Addr: addr, client: &http.Client{Timeout: 10 * time.Second}, custody: sel}
	if err := m.rotateAppRoleCredential(ctx, token); err != nil && sel.manifest.Protected() {
		return &ProtectedError{Err: err}
	} else {
		return err
	}
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

// Available reports whether an OpenBao/Vault binary is on PATH, so `doctor` can
// tell the operator which secret-store posture `up` would use.
func Available() bool {
	_, err := resolveBinary()
	return err == nil
}

// ManagedAddr is the loopback address the managed instance binds.
const ManagedAddr = "http://127.0.0.1:8200"

// StaleListenerError reports that something already answers on the managed
// OpenBao address but is not the instance microagency recorded. It is a
// distinct, recoverable condition rather than a generic outage: the managed
// store is unusable only until the port is freed, and adopting whatever is
// listening would hand the gateway's credentials to a process it does not
// manage.
type StaleListenerError struct {
	Addr   string // where the foreign listener answers
	Dir    string // the managed state directory whose instance was expected
	Detail string // what made the listener unrecognizable
}

func (e *StaleListenerError) Error() string {
	return fmt.Sprintf("another process is already serving OpenBao at %s and it is not the instance microagency manages under %s (%s)",
		e.Addr, e.Dir, e.Detail)
}

// Remediation is the operator's next action for a stale listener.
func (e *StaleListenerError) Remediation() string {
	return fmt.Sprintf("stop whatever holds %s (it was not started by microagency), then start microagency again", e.Addr)
}

// IsStaleListener reports whether err is the "someone else holds the managed
// OpenBao port" condition, which has its own diagnosis and remediation.
func IsStaleListener(err error) bool {
	var stale *StaleListenerError
	return errors.As(err, &stale)
}

// adoptManaged reports whether the OpenBao answering at addr is the instance
// microagency started. Both startup (through start) and the read-only probe
// call it, so what doctor reports and what `up` does cannot drift.
func adoptManaged(dir, addr string) error {
	pid, err := managedPID(dir)
	if err != nil {
		detail := "microagency has no managed instance recorded here"
		if !errors.Is(err, os.ErrNotExist) {
			detail = "microagency's record of its managed instance is unreadable: " + err.Error()
		}
		return &StaleListenerError{Addr: addr, Dir: dir, Detail: detail}
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return &StaleListenerError{Addr: addr, Dir: dir,
			Detail: fmt.Sprintf("microagency's managed instance (pid %d) is no longer running", pid)}
	}
	return nil
}

// ManagedProbe is the read-only answer to "which credential store would a start
// right now actually use". It starts nothing, initializes nothing, and writes
// nothing, so `doctor` can call it. Running+Adopted is an observation; a probe
// that finds nothing bound reports Running=false, and whether `up` could then
// start an instance is a prediction the caller must present as one.
type ManagedProbe struct {
	Addr       string // the managed loopback address
	Configured bool   // managed custody exists, or a protector was selected
	Binary     bool   // an OpenBao binary is on PATH
	Running    bool   // something answers at Addr
	Adopted    bool   // ...and it is the instance recorded under the state dir
	Err        error  // why the managed store cannot be used right now
}

// ProbeManaged inspects the managed instance without touching it.
func ProbeManaged(dir string, getenv func(string) string) ManagedProbe {
	p := ManagedProbe{Addr: ManagedAddr, Configured: ManagedConfigured(dir, getenv), Binary: Available()}
	m := &Manager{Dir: dir, Addr: ManagedAddr, client: &http.Client{Timeout: 2 * time.Second}}
	p.Running = m.reachable()
	switch {
	case p.Running:
		if err := adoptManaged(dir, ManagedAddr); err != nil {
			p.Err = err
			return p
		}
		p.Adopted = true
	case !p.Binary:
		p.Err = errors.New("openbao is not on PATH — install it (e.g. `brew install openbao`)")
	}
	return p
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
		return adoptManaged(m.Dir, m.Addr)
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

func managedPID(dir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, "bao.pid"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, errors.New("managed pid file is invalid")
	}
	return pid, nil
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

// initOrUnseal initializes a fresh Bao or unseals an existing one. The initial
// root token exists only long enough to provision a narrow AppRole; it is then
// revoked and removed from the protected record.
func (m *Manager) initOrUnseal(ctx context.Context) (string, error) {
	st, err := m.sealStatus(ctx)
	if err != nil {
		return "", err
	}
	var bs bootstrap
	if st.Initialized {
		if bs, err = m.loadBootstrap(ctx); err != nil {
			if m.custody.protector != nil && m.custody.protector.Protected() {
				return "", fmt.Errorf("managed OpenBao is initialized but its protected bootstrap cannot be loaded: %w", err)
			}
			slog.Warn("OpenBao bootstrap missing; resetting vault fresh (re-authorize upstream connections afterward)")
			if rerr := m.resetStorage(ctx); rerr != nil {
				return "", fmt.Errorf("reset unrecoverable openbao: %w", rerr)
			}
			if st, err = m.sealStatus(ctx); err != nil {
				return "", err
			}
		}
	}
	if !st.Initialized {
		if err := m.preflightProtectedCustody(ctx); err != nil {
			return "", err
		}
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
		bs = bootstrap{UnsealKey: out.KeysB64[0], RootToken: out.RootToken}
		if err := m.saveBootstrap(ctx, bs); err != nil {
			return "", err
		}
		if err := m.unseal(ctx, bs.UnsealKey); err != nil {
			return "", err
		}
		return m.operationalToken(ctx, bs)
	}
	if st.Sealed {
		if bs.UnsealKey == "" {
			return "", errors.New("managed OpenBao is sealed but its protected record has no unseal key")
		}
		if err := m.unseal(ctx, bs.UnsealKey); err != nil {
			return "", err
		}
	}
	return m.operationalToken(ctx, bs)
}

func (m *Manager) preflightProtectedCustody(ctx context.Context) error {
	selection := m.custodySelection()
	if !selection.protector.Protected() {
		return nil
	}
	if _, err := selection.protector.Load(ctx); err == nil {
		return errors.New("protected bootstrap already exists for an uninitialized OpenBao; restore the matching data or purge the stale protected record")
	} else if !errors.Is(err, errBootstrapNotFound) {
		return fmt.Errorf("preflight protected bootstrap read: %w", err)
	}
	probe := []byte(`{"format":"microagency-openbao-protector-preflight"}`)
	if err := selection.protector.Save(ctx, probe); err != nil {
		return fmt.Errorf("preflight protected bootstrap write: %w", err)
	}
	got, err := selection.protector.Load(ctx)
	if err != nil || !bytes.Equal(got, probe) {
		_ = selection.protector.Delete(ctx)
		if err != nil {
			return fmt.Errorf("preflight protected bootstrap verification: %w", err)
		}
		return errors.New("preflight protected bootstrap verification: round-trip mismatch")
	}
	if err := selection.protector.Delete(ctx); err != nil {
		return fmt.Errorf("preflight protected bootstrap cleanup: %w", err)
	}
	return nil
}

func (m *Manager) unseal(ctx context.Context, key string) error {
	return m.do(ctx, http.MethodPut, "/v1/sys/unseal", "", map[string]string{"key": key}, nil)
}

const managedPolicy = `path "secret/data/microagency/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "secret/metadata/microagency/*" {
  capabilities = ["read", "list", "delete"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/approle/role/microagency/secret-id" {
  capabilities = ["update"]
}
path "auth/approle/role/microagency/secret-id-accessor/destroy" {
  capabilities = ["update"]
}`

// operationalToken migrates a legacy root-token bootstrap once, or logs in
// through the already-provisioned AppRole. Root is never returned to the
// gateway and is revoked before startup completes.
func (m *Manager) operationalToken(ctx context.Context, bs bootstrap) (string, error) {
	if bs.RoleID == "" || bs.SecretID == "" {
		if bs.RootToken == "" {
			return "", errors.New("managed OpenBao bootstrap has neither AppRole credentials nor a transitional root token")
		}
		if err := m.ensureKVv2(ctx, bs.RootToken); err != nil {
			return "", fmt.Errorf("prepare managed KV mount: %w", err)
		}
		roleID, secretID, accessor, err := m.provisionAppRole(ctx, bs.RootToken)
		if err != nil {
			return "", err
		}
		bs.RoleID, bs.SecretID, bs.SecretAccessor = roleID, secretID, accessor
		// Keep the root token only until the AppRole record has round-tripped
		// through its protector. A failed revoke can then be retried safely.
		if err := m.saveBootstrap(ctx, bs); err != nil {
			return "", fmt.Errorf("save AppRole bootstrap before root revocation: %w", err)
		}
	}

	login, err := m.loginAppRole(ctx, bs.RoleID, bs.SecretID)
	if err != nil {
		return "", fmt.Errorf("managed OpenBao AppRole login: %w", err)
	}
	m.tokenLease = time.Duration(login.LeaseDuration) * time.Second
	if bs.RootToken != "" {
		err := m.do(ctx, http.MethodPost, "/v1/auth/token/revoke-self", bs.RootToken, nil, nil)
		// If a prior run revoked root and crashed before pruning the protected
		// record, OpenBao reports the old credential as forbidden. AppRole login
		// above proves the replacement path is usable, so pruning is safe.
		if err != nil && !hasHTTPStatus(err, http.StatusForbidden) {
			return "", fmt.Errorf("revoke initial OpenBao root token: %w", err)
		}
		bs.RootToken = ""
		if err := m.saveBootstrap(ctx, bs); err != nil {
			return "", fmt.Errorf("remove revoked root token from protected bootstrap: %w", err)
		}
	}
	return login.Token, nil
}

func (m *Manager) provisionAppRole(ctx context.Context, root string) (roleID, secretID, accessor string, err error) {
	if err := m.do(ctx, http.MethodPut, "/v1/sys/policies/acl/microagency", root, map[string]string{"policy": managedPolicy}, nil); err != nil {
		return "", "", "", fmt.Errorf("install managed OpenBao policy: %w", err)
	}
	err = m.do(ctx, http.MethodPost, "/v1/sys/auth/approle", root, map[string]any{
		"type":        "approle",
		"description": "microagency managed credential-store login",
	}, nil)
	if err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "path is already in use") && !strings.Contains(msg, "existing mount") {
			return "", "", "", fmt.Errorf("enable managed OpenBao AppRole: %w", err)
		}
	}
	if err := m.do(ctx, http.MethodPost, "/v1/auth/approle/role/microagency", root, map[string]any{
		"bind_secret_id":          true,
		"secret_id_num_uses":      0,
		"secret_id_ttl":           "0",
		"token_no_default_policy": true,
		"token_period":            "24h",
		"token_policies":          []string{"microagency"},
		"token_type":              "service",
	}, nil); err != nil {
		return "", "", "", fmt.Errorf("configure managed OpenBao AppRole: %w", err)
	}
	var role struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := m.do(ctx, http.MethodGet, "/v1/auth/approle/role/microagency/role-id", root, nil, &role); err != nil {
		return "", "", "", fmt.Errorf("read managed OpenBao AppRole ID: %w", err)
	}
	secretID, accessor, err = m.createAppRoleSecret(ctx, root)
	if err != nil {
		return "", "", "", err
	}
	if role.Data.RoleID == "" || secretID == "" {
		return "", "", "", errors.New("managed OpenBao AppRole returned incomplete credentials")
	}
	return role.Data.RoleID, secretID, accessor, nil
}

func (m *Manager) createAppRoleSecret(ctx context.Context, token string) (secretID, accessor string, err error) {
	var secret struct {
		Data struct {
			SecretID string `json:"secret_id"`
			Accessor string `json:"secret_id_accessor"`
		} `json:"data"`
	}
	if err := m.do(ctx, http.MethodPost, "/v1/auth/approle/role/microagency/secret-id", token, nil, &secret); err != nil {
		return "", "", fmt.Errorf("create managed OpenBao AppRole secret: %w", err)
	}
	if secret.Data.SecretID == "" || secret.Data.Accessor == "" {
		return "", "", errors.New("managed OpenBao AppRole returned an incomplete secret ID")
	}
	return secret.Data.SecretID, secret.Data.Accessor, nil
}

type appRoleLogin struct {
	Token         string
	LeaseDuration int
}

func (m *Manager) loginAppRole(ctx context.Context, roleID, secretID string) (appRoleLogin, error) {
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := m.do(ctx, http.MethodPost, "/v1/auth/approle/login", "", map[string]string{
		"role_id": roleID, "secret_id": secretID,
	}, &out); err != nil {
		return appRoleLogin{}, err
	}
	if out.Auth.ClientToken == "" || !out.Auth.Renewable || out.Auth.LeaseDuration <= 0 {
		return appRoleLogin{}, errors.New("AppRole did not return a renewable periodic token")
	}
	return appRoleLogin{Token: out.Auth.ClientToken, LeaseDuration: out.Auth.LeaseDuration}, nil
}

func (m *Manager) rotateAppRoleCredential(ctx context.Context, token string) error {
	bs, err := m.loadBootstrap(ctx)
	if err != nil {
		return fmt.Errorf("load managed OpenBao login bootstrap: %w", err)
	}
	if bs.RoleID == "" || bs.SecretID == "" {
		return errors.New("managed OpenBao AppRole is not provisioned")
	}
	newSecret, newAccessor, err := m.createAppRoleSecret(ctx, token)
	if err != nil {
		return err
	}
	cleanupNew := func() {
		_ = m.do(context.Background(), http.MethodPost, "/v1/auth/approle/role/microagency/secret-id-accessor/destroy", token, map[string]string{"secret_id_accessor": newAccessor}, nil)
	}
	if _, err := m.loginAppRole(ctx, bs.RoleID, newSecret); err != nil {
		cleanupNew()
		return fmt.Errorf("verify rotated managed OpenBao login: %w", err)
	}
	oldAccessor := bs.SecretAccessor
	bs.SecretID, bs.SecretAccessor = newSecret, newAccessor
	if err := m.saveBootstrap(ctx, bs); err != nil {
		cleanupNew()
		return fmt.Errorf("save rotated managed OpenBao login: %w", err)
	}
	if oldAccessor != "" {
		if err := m.do(ctx, http.MethodPost, "/v1/auth/approle/role/microagency/secret-id-accessor/destroy", token, map[string]string{"secret_id_accessor": oldAccessor}, nil); err != nil {
			return fmt.Errorf("login rotation committed, but the previous SecretID accessor could not be destroyed: %w", err)
		}
	}
	return nil
}

func (m *Manager) startTokenRenewal(ctx context.Context, token string) {
	if token == "" || m.tokenLease <= 0 {
		return
	}
	go func() {
		lease := m.tokenLease
		delay := renewalDelay(lease)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				var out struct {
					Auth struct {
						LeaseDuration int `json:"lease_duration"`
					} `json:"auth"`
				}
				if err := m.do(context.Background(), http.MethodPost, "/v1/auth/token/renew-self", token, nil, &out); err != nil {
					slog.Error("managed OpenBao token renewal failed; restore service before the current lease expires", "err", err)
					delay = time.Minute
					if lease < 3*time.Minute {
						delay = lease / 4
					}
				} else {
					if out.Auth.LeaseDuration > 0 {
						lease = time.Duration(out.Auth.LeaseDuration) * time.Second
					}
					delay = renewalDelay(lease)
				}
				timer.Reset(delay)
			}
		}
	}()
}

func renewalDelay(lease time.Duration) time.Duration {
	delay := lease / 3
	if delay < time.Minute {
		delay = time.Minute
	}
	return delay
}

func (m *Manager) custodySelection() custodySelection {
	if m.custody.protector != nil {
		return m.custody
	}
	manifest := custodyManifest{Format: custodyFormat, Kind: "file", ID: custodyID(m.Dir)}
	return custodySelection{dir: m.Dir, manifest: manifest, protector: &fileProtector{dir: m.Dir}}
}

func (m *Manager) saveBootstrap(ctx context.Context, bs bootstrap) error {
	b, err := json.Marshal(bs)
	if err != nil {
		return err
	}
	return saveProtectedRecord(ctx, m.custodySelection(), b)
}

func (m *Manager) loadBootstrap(ctx context.Context) (bootstrap, error) {
	var bs bootstrap
	selection := m.custodySelection()
	b, err := selection.protector.Load(ctx)
	if errors.Is(err, errBootstrapNotFound) && selection.protector.Protected() {
		// Explicitly selecting protected custody on a legacy installation is a
		// one-way, verified migration. The disk copy is removed only after the
		// protector round-trip and custody manifest both succeed.
		legacy, legacyErr := os.ReadFile(bootstrapPath(m.Dir))
		if legacyErr == nil {
			if err := json.Unmarshal(legacy, &bs); err != nil {
				return bs, fmt.Errorf("legacy OpenBao bootstrap is invalid: %w", err)
			}
			if err := saveProtectedRecord(ctx, selection, legacy); err != nil {
				return bs, fmt.Errorf("migrate OpenBao bootstrap to %s: %w", protectorLabel(selection.manifest.Kind), err)
			}
			return bs, nil
		}
	}
	if err != nil {
		return bs, err
	}
	if err := json.Unmarshal(b, &bs); err != nil {
		return bs, fmt.Errorf("decode managed OpenBao bootstrap: %w", err)
	}
	return bs, nil
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
	_ = os.Remove(custodyPath(dir))
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
		return &baoHTTPError{Method: method, Path: path, Status: resp.StatusCode, Detail: strings.TrimSpace(string(data))}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

type baoHTTPError struct {
	Method, Path string
	Status       int
	Detail       string
}

func (e *baoHTTPError) Error() string {
	return fmt.Sprintf("openbao %s %s: http %d: %s", e.Method, e.Path, e.Status, e.Detail)
}

func hasHTTPStatus(err error, status int) bool {
	var httpErr *baoHTTPError
	return errors.As(err, &httpErr) && httpErr.Status == status
}

func bootstrapPath(dir string) string { return filepath.Join(dir, "bootstrap.json") }

// saveBootstrap writes the bootstrap atomically: a temp file, fsync'd, then
// renamed over the target. Without this, a plain write interrupted by a kill
// (dev churn, a brew replace) can leave an empty or partial bootstrap.json while
// the vault is already initialized — the exact unrecoverable state resetStorage
// exists to heal. Atomic replace means the file is always either the old contents
// or the complete new ones, never a torn middle.
func saveBootstrap(dir string, bs bootstrap) error {
	b, err := json.Marshal(bs)
	if err != nil {
		return err
	}
	return writeAtomic(bootstrapPath(dir), b, 0o600)
}

func loadBootstrap(dir string) (bootstrap, error) {
	var bs bootstrap
	b, err := os.ReadFile(bootstrapPath(dir))
	if err != nil {
		return bs, err
	}
	return bs, json.Unmarshal(b, &bs)
}
