package baomanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// ProtectorEnv selects custody for the managed OpenBao bootstrap. The empty
	// value retains the compatibility file posture; protected custody is always
	// explicit so a headless host never silently depends on a locked keyring.
	ProtectorEnv = "MICROAGENCY_OPENBAO_PROTECTOR"
	// ProtectorCommandEnv names the absolute helper used by the command
	// protector. The helper protocol is documented in docs/operations.md.
	ProtectorCommandEnv = "MICROAGENCY_OPENBAO_PROTECTOR_COMMAND"

	custodyFormat = "microagency-openbao-custody-v1"
	keychainSvc   = "microagency.openbao"
)

var errBootstrapNotFound = errors.New("managed OpenBao bootstrap not found")

// ProtectedError marks a managed-store failure that must not fall through to
// another credential store. Once protected custody is selected, an unavailable
// protector is an outage, not permission to create a second store on disk.
type ProtectedError struct{ Err error }

func (e *ProtectedError) Error() string { return "protected OpenBao custody: " + e.Err.Error() }
func (e *ProtectedError) Unwrap() error { return e.Err }

// FailClosed reports whether startup must stop instead of evaluating a local
// credential-store fallback.
func FailClosed(err error) bool {
	var protected *ProtectedError
	return errors.As(err, &protected)
}

type protector interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
	Delete(context.Context) error
	Kind() string
	Protected() bool
}

type custodyManifest struct {
	Format  string `json:"format"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Command string `json:"command,omitempty"`
}

func (m custodyManifest) protected() bool { return m.Kind != "file" }

type custodySelection struct {
	dir       string
	manifest  custodyManifest
	protector protector
}

type fileProtector struct{ dir string }

func (p *fileProtector) Kind() string    { return "file" }
func (p *fileProtector) Protected() bool { return false }
func (p *fileProtector) Delete(context.Context) error {
	err := os.Remove(bootstrapPath(p.dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (p *fileProtector) Load(context.Context) ([]byte, error) {
	b, err := os.ReadFile(bootstrapPath(p.dir))
	if os.IsNotExist(err) {
		return nil, errBootstrapNotFound
	}
	return b, err
}
func (p *fileProtector) Save(_ context.Context, b []byte) error {
	return writeAtomic(bootstrapPath(p.dir), b, 0o600)
}

type commandResult struct {
	stdout, stderr []byte
	exitCode       int
}

type commandRunner func(context.Context, []byte, string, ...string) commandResult

func runCommand(ctx context.Context, stdin []byte, name string, args ...string) commandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{W: &stdout, N: 1 << 20}
	cmd.Stderr = &limitedWriter{W: &stderr, N: 16 << 10}
	err := cmd.Run()
	if err == nil {
		return commandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	}
	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	return commandResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), exitCode: code}
}

type limitedWriter struct {
	W io.Writer
	N int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.N <= 0 {
		return n, nil
	}
	if int64(len(p)) > w.N {
		p = p[:w.N]
	}
	written, err := w.W.Write(p)
	w.N -= int64(written)
	if err != nil {
		return written, err
	}
	return n, nil
}

type osKeyringProtector struct {
	kind, binary, account string
	run                   commandRunner
}

func (p *osKeyringProtector) Kind() string    { return p.kind }
func (p *osKeyringProtector) Protected() bool { return true }

func (p *osKeyringProtector) Load(ctx context.Context) ([]byte, error) {
	var r commandResult
	switch p.kind {
	case "keychain":
		r = p.run(ctx, nil, p.binary, "find-generic-password", "-s", keychainSvc, "-a", p.account, "-w")
		if r.exitCode != 0 {
			msg := strings.ToLower(string(r.stderr))
			if r.exitCode == 44 || strings.Contains(msg, "could not be found") {
				return nil, errBootstrapNotFound
			}
			return nil, fmt.Errorf("macOS Keychain read failed (security exit %d); unlock the login keychain and retry", r.exitCode)
		}
	case "secret-service":
		r = p.run(ctx, nil, p.binary, "lookup", "application", "microagency", "purpose", "openbao-bootstrap", "instance", p.account)
		if r.exitCode != 0 {
			if r.exitCode == 1 && len(bytes.TrimSpace(r.stderr)) == 0 {
				return nil, errBootstrapNotFound
			}
			return nil, fmt.Errorf("linux Secret Service read failed (secret-tool exit %d); ensure the user session D-Bus and unlocked login collection are available", r.exitCode)
		}
	default:
		return nil, fmt.Errorf("unsupported OS protector %q", p.kind)
	}
	return bytes.TrimSpace(r.stdout), nil
}

func (p *osKeyringProtector) Save(ctx context.Context, secret []byte) error {
	var r commandResult
	switch p.kind {
	case "keychain":
		// security(1) is the stable, rebuild-safe Keychain identity available to
		// unsigned Homebrew binaries. It necessarily receives the value as an
		// argument; the docs call out that same-user process-list tradeoff.
		r = p.run(ctx, nil, p.binary, "add-generic-password", "-U", "-s", keychainSvc, "-a", p.account, "-w", string(secret))
	case "secret-service":
		r = p.run(ctx, secret, p.binary, "store", "--label=microagency managed OpenBao bootstrap", "application", "microagency", "purpose", "openbao-bootstrap", "instance", p.account)
	default:
		return fmt.Errorf("unsupported OS protector %q", p.kind)
	}
	if r.exitCode != 0 {
		return fmt.Errorf("%s write failed (exit %d); the protector must be available and unlocked", protectorLabel(p.kind), r.exitCode)
	}
	return nil
}

func (p *osKeyringProtector) Delete(ctx context.Context) error {
	var r commandResult
	switch p.kind {
	case "keychain":
		r = p.run(ctx, nil, p.binary, "delete-generic-password", "-s", keychainSvc, "-a", p.account)
		if r.exitCode == 44 || strings.Contains(strings.ToLower(string(r.stderr)), "could not be found") {
			return nil
		}
	case "secret-service":
		r = p.run(ctx, nil, p.binary, "clear", "application", "microagency", "purpose", "openbao-bootstrap", "instance", p.account)
		if r.exitCode == 1 && len(bytes.TrimSpace(r.stderr)) == 0 {
			return nil
		}
	}
	if r.exitCode != 0 {
		return fmt.Errorf("%s delete failed (exit %d)", protectorLabel(p.kind), r.exitCode)
	}
	return nil
}

type helperProtector struct {
	binary, id string
	run        commandRunner
}

func (p *helperProtector) Kind() string    { return "command" }
func (p *helperProtector) Protected() bool { return true }
func (p *helperProtector) Load(ctx context.Context) ([]byte, error) {
	r := p.run(ctx, nil, p.binary, "get", p.id)
	if r.exitCode == 3 {
		return nil, errBootstrapNotFound
	}
	if r.exitCode != 0 {
		return nil, fmt.Errorf("protector helper read failed (exit %d); restore its KMS/secret-manager access and retry", r.exitCode)
	}
	return bytes.TrimSpace(r.stdout), nil
}
func (p *helperProtector) Save(ctx context.Context, secret []byte) error {
	r := p.run(ctx, secret, p.binary, "put", p.id)
	if r.exitCode != 0 {
		return fmt.Errorf("protector helper write failed (exit %d)", r.exitCode)
	}
	return nil
}
func (p *helperProtector) Delete(ctx context.Context) error {
	r := p.run(ctx, nil, p.binary, "delete", p.id)
	if r.exitCode != 0 && r.exitCode != 3 {
		return fmt.Errorf("protector helper delete failed (exit %d)", r.exitCode)
	}
	return nil
}

func protectorLabel(kind string) string {
	switch kind {
	case "keychain":
		return "macOS Keychain"
	case "secret-service":
		return "Linux Secret Service"
	case "command":
		return "external protector helper"
	default:
		return "same-disk file"
	}
}

func canonicalProtectorKind(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "file":
		return "file", nil
	case "keychain", "macos-keychain":
		return "keychain", nil
	case "secret-service", "linux-secret-service", "keyring":
		return "secret-service", nil
	case "command", "kms", "helper":
		return "command", nil
	default:
		return "", fmt.Errorf("unknown %s value %q (use file, keychain, secret-service, or command)", ProtectorEnv, raw)
	}
}

func custodyID(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:12])
}

func newProtector(dir string, manifest custodyManifest, getenv func(string) string, runner commandRunner) (protector, error) {
	if runner == nil {
		runner = runCommand
	}
	switch manifest.Kind {
	case "file":
		return &fileProtector{dir: dir}, nil
	case "keychain":
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("macOS Keychain protector requires darwin, current host is %s", runtime.GOOS)
		}
		binary := "/usr/bin/security"
		if st, err := os.Stat(binary); err != nil || !st.Mode().IsRegular() {
			return nil, errors.New("macOS Keychain protector requires /usr/bin/security")
		}
		return &osKeyringProtector{kind: manifest.Kind, binary: binary, account: manifest.ID, run: runner}, nil
	case "secret-service":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("linux Secret Service protector requires linux, current host is %s", runtime.GOOS)
		}
		binary, err := exec.LookPath("secret-tool")
		if err != nil {
			return nil, errors.New("linux Secret Service protector requires secret-tool (libsecret-tools/libsecret)")
		}
		return &osKeyringProtector{kind: manifest.Kind, binary: binary, account: manifest.ID, run: runner}, nil
	case "command":
		path := strings.TrimSpace(manifest.Command)
		if path == "" {
			path = strings.TrimSpace(getenv(ProtectorCommandEnv))
		}
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%s must be an absolute executable path", ProtectorCommandEnv)
		}
		linkInfo, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("protector helper %s: %w", path, err)
		}
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("protector helper %s must not be a symbolic link", path)
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("protector helper %s: %w", path, err)
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			return nil, fmt.Errorf("protector helper %s is not executable", path)
		}
		if st.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("protector helper %s is writable by group or other users", path)
		}
		if parent, parentErr := os.Stat(filepath.Dir(path)); parentErr != nil || parent.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("protector helper directory %s must not be writable by group or other users", filepath.Dir(path))
		}
		return &helperProtector{binary: path, id: manifest.ID, run: runner}, nil
	default:
		return nil, fmt.Errorf("unsupported protector kind %q", manifest.Kind)
	}
}

func selectCustody(dir string, getenv func(string) string) (custodySelection, error) {
	manifest, err := loadCustodyManifest(dir)
	if err == nil {
		p, perr := newProtector(dir, manifest, getenv, nil)
		return custodySelection{dir: dir, manifest: manifest, protector: p}, perr
	}
	if !os.IsNotExist(err) {
		return custodySelection{}, err
	}
	kind, err := canonicalProtectorKind(getenv(ProtectorEnv))
	if err != nil {
		return custodySelection{}, err
	}
	manifest = custodyManifest{Format: custodyFormat, Kind: kind, ID: custodyID(dir)}
	if kind == "command" {
		manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
	}
	p, err := newProtector(dir, manifest, getenv, nil)
	return custodySelection{dir: dir, manifest: manifest, protector: p}, err
}

func protectedRequested(dir string, getenv func(string) string) bool {
	if manifest, err := loadCustodyManifest(dir); err == nil {
		return manifest.protected()
	}
	if _, err := os.Stat(custodyPath(dir)); err == nil {
		// A corrupt custody manifest must never authorize a downgrade; its kind
		// cannot be trusted until the operator repairs or restores it.
		return true
	}
	kind, err := canonicalProtectorKind(getenv(ProtectorEnv))
	return err == nil && kind != "file"
}

// ManagedConfigured reports whether this state directory already has managed
// OpenBao custody or the operator explicitly selected a protector. It lets
// doctor describe that posture even when the OpenBao binary itself is missing.
func ManagedConfigured(dir string, getenv func(string) string) bool {
	if _, err := loadCustodyManifest(dir); err == nil {
		return true
	}
	if _, err := os.Stat(custodyPath(dir)); err == nil {
		return true
	}
	if strings.TrimSpace(getenv(ProtectorEnv)) != "" {
		return true
	}
	if _, err := os.Stat(bootstrapPath(dir)); err == nil {
		return true
	}
	return dirHasEntries(filepath.Join(dir, "data"))
}

func custodyPath(dir string) string { return filepath.Join(dir, "custody.json") }

func loadCustodyManifest(dir string) (custodyManifest, error) {
	var manifest custodyManifest
	b, err := os.ReadFile(custodyPath(dir))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return manifest, fmt.Errorf("read managed OpenBao custody metadata: %w", err)
	}
	if manifest.Format != custodyFormat || manifest.ID == "" {
		return manifest, errors.New("managed OpenBao custody metadata has an unsupported or incomplete format")
	}
	kind, err := canonicalProtectorKind(manifest.Kind)
	if err != nil {
		return manifest, err
	}
	if kind != manifest.Kind {
		return manifest, errors.New("managed OpenBao custody metadata uses a non-canonical protector kind")
	}
	return manifest, nil
}

func saveCustodyManifest(dir string, manifest custodyManifest) error {
	manifest.Format = custodyFormat
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeAtomic(custodyPath(dir), b, 0o600)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if _, err := f.Write(b); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func saveProtectedRecord(ctx context.Context, selection custodySelection, b []byte) error {
	if err := selection.protector.Save(ctx, b); err != nil {
		return err
	}
	got, err := selection.protector.Load(ctx)
	if err != nil {
		return fmt.Errorf("verify protector write: %w", err)
	}
	if !bytes.Equal(got, b) {
		return errors.New("verify protector write: round-trip mismatch")
	}
	if err := saveCustodyManifest(selection.dir, selection.manifest); err != nil {
		return err
	}
	if selection.protector.Protected() {
		_ = os.Remove(bootstrapPath(selection.dir))
		_ = os.Remove(bootstrapPath(selection.dir) + ".tmp")
	}
	return nil
}

// CustodyPosture is the non-secret managed-store state rendered by doctor.
type CustodyPosture struct {
	Kind, Label, Detail  string
	Protected, Available bool
}

// InspectCustody validates the configured protector without printing or
// returning bootstrap material.
func InspectCustody(ctx context.Context, dir string, getenv func(string) string) CustodyPosture {
	kind, _ := canonicalProtectorKind(getenv(ProtectorEnv))
	if manifest, err := loadCustodyManifest(dir); err == nil {
		kind = manifest.Kind
	}
	posture := CustodyPosture{Kind: kind, Label: protectorLabel(kind), Protected: kind != "file", Available: true}
	selection, err := selectCustody(dir, getenv)
	if err != nil {
		if _, statErr := os.Stat(custodyPath(dir)); statErr == nil {
			posture.Protected = true
			posture.Label = "custody metadata"
		}
		posture.Available = false
		posture.Detail = err.Error()
		return posture
	}
	b, err := selection.protector.Load(ctx)
	if errors.Is(err, errBootstrapNotFound) {
		if selection.protector.Protected() {
			if legacy, legacyErr := os.ReadFile(bootstrapPath(dir)); legacyErr == nil {
				if json.Valid(legacy) {
					posture.Detail = "configured; legacy bootstrap will migrate on next startup"
					return posture
				}
			}
		}
		if dirHasEntries(filepath.Join(dir, "data")) {
			posture.Available = false
			posture.Detail = "OpenBao data exists but the bootstrap is unavailable; restore the protector before startup"
			return posture
		}
		posture.Detail = "configured; bootstrap will be created on first startup"
		return posture
	}
	if err != nil {
		posture.Available = false
		posture.Detail = err.Error()
		return posture
	}
	var bs bootstrap
	if err := json.Unmarshal(b, &bs); err != nil {
		posture.Available = false
		posture.Detail = "bootstrap record is invalid: " + err.Error()
		return posture
	}
	if bs.RootToken != "" {
		posture.Detail = "legacy root bootstrap will be retired to a narrow AppRole on next startup"
	} else {
		posture.Detail = "root retired; renewable narrow AppRole configured"
	}
	return posture
}

func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// MigrateCustody verifies the target protector before atomically switching the
// non-secret manifest, then removes the old copy. Moving back to the same-disk
// file posture requires an explicit allowDegraded acknowledgement.
func MigrateCustody(ctx context.Context, dir string, getenv func(string) string, target string, allowDegraded bool) error {
	targetKind, err := canonicalProtectorKind(target)
	if err != nil {
		return err
	}
	if targetKind == "file" && !allowDegraded {
		return errors.New("refusing to move protected OpenBao custody onto the same disk without --allow-degraded")
	}
	sourceManifest, err := loadCustodyManifest(dir)
	if os.IsNotExist(err) {
		sourceManifest = custodyManifest{Format: custodyFormat, Kind: "file", ID: custodyID(dir)}
	} else if err != nil {
		return err
	}
	targetCommand := strings.TrimSpace(getenv(ProtectorCommandEnv))
	sameCommand := sourceManifest.Kind == "command" && targetKind == "command" && targetCommand != "" && filepath.Clean(targetCommand) != filepath.Clean(sourceManifest.Command)
	if sourceManifest.Kind == targetKind && !sameCommand {
		return fmt.Errorf("managed OpenBao already uses %s custody", protectorLabel(targetKind))
	}
	source, err := newProtector(dir, sourceManifest, func(name string) string {
		if name == ProtectorCommandEnv && sourceManifest.Command != "" {
			return sourceManifest.Command
		}
		return getenv(name)
	}, nil)
	if err != nil {
		return fmt.Errorf("open current protector: %w", err)
	}
	secret, err := source.Load(ctx)
	if err != nil {
		return fmt.Errorf("load current protected bootstrap: %w", err)
	}
	var bs bootstrap
	if err := json.Unmarshal(secret, &bs); err != nil {
		return fmt.Errorf("current protected bootstrap is invalid: %w", err)
	}
	targetManifest := custodyManifest{Format: custodyFormat, Kind: targetKind, ID: sourceManifest.ID}
	if targetKind == "command" {
		targetManifest.Command = targetCommand
	}
	targetProtector, err := newProtector(dir, targetManifest, getenv, nil)
	if err != nil {
		return fmt.Errorf("open target protector: %w", err)
	}
	return migrateCustodyRecord(ctx, dir, secret, sourceManifest, source, targetManifest, targetProtector)
}

func migrateCustodyRecord(ctx context.Context, dir string, secret []byte, sourceManifest custodyManifest, source protector, targetManifest custodyManifest, targetProtector protector) error {
	if err := targetProtector.Save(ctx, secret); err != nil {
		return fmt.Errorf("write target protector: %w", err)
	}
	got, err := targetProtector.Load(ctx)
	if err != nil || !bytes.Equal(got, secret) {
		_ = targetProtector.Delete(ctx)
		if err != nil {
			return fmt.Errorf("verify target protector: %w", err)
		}
		return errors.New("verify target protector: round-trip mismatch")
	}
	if err := saveCustodyManifest(dir, targetManifest); err != nil {
		_ = targetProtector.Delete(ctx)
		return fmt.Errorf("commit custody migration: %w", err)
	}
	if err := source.Delete(ctx); err != nil {
		return fmt.Errorf("custody migration committed, but the old %s copy could not be deleted: %w", protectorLabel(sourceManifest.Kind), err)
	}
	return nil
}

// DeleteCustody removes the out-of-directory protected record before a full
// purge removes the manifest needed to locate it.
func DeleteCustody(ctx context.Context, dir string, getenv func(string) string) error {
	manifest, err := loadCustodyManifest(dir)
	if os.IsNotExist(err) {
		kind, kindErr := canonicalProtectorKind(getenv(ProtectorEnv))
		if kindErr != nil || kind == "file" {
			return kindErr
		}
		manifest = custodyManifest{Format: custodyFormat, Kind: kind, ID: custodyID(dir)}
		if kind == "command" {
			manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
		}
		err = nil
	}
	if err != nil {
		return err
	}
	if !manifest.protected() {
		return nil
	}
	p, err := newProtector(dir, manifest, func(name string) string {
		if name == ProtectorCommandEnv && manifest.Command != "" {
			return manifest.Command
		}
		return getenv(name)
	}, nil)
	if err != nil {
		return err
	}
	return p.Delete(ctx)
}
