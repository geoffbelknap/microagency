// Package custody holds the protectors that keep a small piece of key material
// out of the gateway's state directory: the macOS Keychain, the Linux Secret
// Service, an operator helper backed by a KMS or secret manager, or — the
// compatibility posture — a file the consumer owns.
//
// Two things inside microagency need exactly this. The managed OpenBao
// bootstrap record has to survive a restart without sitting beside the data it
// unseals, and the encrypted credential store's data key has to be reachable at
// startup without an operator hand-placing it. Both get the same protector
// choices, the same fail-closed behavior when a selected protector cannot be
// reached, and the same verified copy-then-switch migration.
//
// Nothing here decides *what* the material is. A consumer supplies a Records
// value naming its locator file, its format tag, the settings that select a
// protector, and the keyring identifiers its material uses; the protectors move
// opaque bytes.
package custody

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

// Protector kinds.
const (
	// KindFile is the compatibility posture: the consumer keeps the material in
	// a file it owns. It is the only kind that is not Protected.
	KindFile = "file"
	// KindKeychain is the macOS login Keychain, reached through /usr/bin/security.
	KindKeychain = "keychain"
	// KindSecretService is the Linux user Secret Service, reached through secret-tool.
	KindSecretService = "secret-service"
	// KindCommand is an operator helper, typically fronting a KMS or secret manager.
	KindCommand = "command"
)

// ErrNotFound means the protector answered and holds no record. It is distinct
// from an unavailable protector: "there is nothing here yet" permits creating
// the material, and "I cannot reach the protector" never does.
var ErrNotFound = errors.New("custody: no protected record")

// secretServiceApp is the fixed `application` attribute every microagency
// record carries in the Linux Secret Service, so `purpose` alone separates one
// consumer's material from another's.
const secretServiceApp = "microagency"

// Protector reads, writes, and removes one opaque record.
type Protector interface {
	Load(context.Context) ([]byte, error) // ErrNotFound when the protector holds nothing
	Save(context.Context, []byte) error
	Delete(context.Context) error
	Kind() string
	Protected() bool // false only for KindFile
}

// Purpose fixes the identifiers one consumer's material uses inside an OS
// keyring. Two consumers on the same host must not collide, and the values are
// a compatibility surface: changing one orphans every existing record.
type Purpose struct {
	KeychainService string // macOS generic-password service name
	Attribute       string // Linux Secret Service `purpose` attribute value
	Label           string // Linux Secret Service label shown to the user
}

// Records is one consumer's custody configuration.
type Records struct {
	// Path is the non-secret locator file recording which protector holds the
	// material. It lives in the consumer's state directory; the material does not.
	Path string
	// Format tags the locator so another consumer's file is never adopted.
	Format string
	// Noun names the material in operator-facing text ("managed OpenBao custody").
	Noun string
	// KindEnv and CommandEnv are the settings that select a protector.
	KindEnv, CommandEnv string
	// Purpose fixes the keyring identifiers for this material.
	Purpose Purpose
	// Runner overrides process execution. Tests set it; production leaves it nil.
	Runner Runner
}

// Manifest is the non-secret locator: which protector holds the record, and
// under what opaque id. It never contains the material itself.
type Manifest struct {
	Format  string `json:"format"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Command string `json:"command,omitempty"`
}

// Protected reports whether the manifest names an out-of-directory protector.
func (m Manifest) Protected() bool { return m.Kind != KindFile }

// ID derives a stable opaque record id from a state directory. It is a digest,
// not the path: the id travels to a keyring and a helper's provider, and those
// have no business learning the operator's directory layout.
func ID(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:12])
}

// CanonicalKind maps an operator-supplied value to a protector kind. An empty
// value is the compatibility file posture: protected custody is always explicit,
// so a headless host never silently depends on a locked keyring.
func CanonicalKind(raw, envName string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", KindFile:
		return KindFile, nil
	case KindKeychain, "macos-keychain":
		return KindKeychain, nil
	case KindSecretService, "linux-secret-service", "keyring":
		return KindSecretService, nil
	case KindCommand, "kms", "helper":
		return KindCommand, nil
	default:
		return "", fmt.Errorf("unknown %s value %q (use file, keychain, secret-service, or command)", envName, raw)
	}
}

// Label returns the operator-facing name for a protector kind.
func Label(kind string) string {
	switch kind {
	case KindKeychain:
		return "macOS Keychain"
	case KindSecretService:
		return "Linux Secret Service"
	case KindCommand:
		return "external protector helper"
	default:
		return "same-disk file"
	}
}

// Kind returns the protector kind the environment selects.
func (r Records) Kind(getenv func(string) string) (string, error) {
	return CanonicalKind(getenv(r.KindEnv), r.KindEnv)
}

// LoadManifest reads the locator. A missing file returns an error satisfying
// os.IsNotExist, which callers treat as "not configured yet"; anything else is
// a corrupt locator and must not be repaired by guessing.
func (r Records) LoadManifest() (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(r.Path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("read %s metadata: %w", r.Noun, err)
	}
	if m.Format != r.Format || m.ID == "" {
		return m, fmt.Errorf("%s metadata has an unsupported or incomplete format", r.Noun)
	}
	kind, err := CanonicalKind(m.Kind, r.KindEnv)
	if err != nil {
		return m, err
	}
	if kind != m.Kind {
		return m, fmt.Errorf("%s metadata uses a non-canonical protector kind", r.Noun)
	}
	return m, nil
}

// SaveManifest writes the locator atomically.
func (r Records) SaveManifest(m Manifest) error {
	m.Format = r.Format
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return WriteAtomic(r.Path, b, 0o600)
}

// DeleteManifest removes the locator. A missing file is not an error.
func (r Records) DeleteManifest() error {
	if err := os.Remove(r.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Exists reports whether a locator file is present, readable or not. A corrupt
// locator must never authorize a downgrade, so callers use this to tell "no
// custody configured" from "custody configured but unreadable".
func (r Records) Exists() bool {
	_, err := os.Stat(r.Path)
	return err == nil
}

// New builds the protector a manifest names. file supplies the KindFile
// protector: what a same-disk posture means belongs to the consumer, since one
// keeps a JSON record beside its data and another points at an operator's key
// file outside the state directory.
func (r Records) New(m Manifest, getenv func(string) string, file Protector) (Protector, error) {
	runner := r.Runner
	if runner == nil {
		runner = Run
	}
	switch m.Kind {
	case KindFile:
		if file == nil {
			return nil, fmt.Errorf("%s has no same-disk protector", r.Noun)
		}
		return file, nil
	case KindKeychain:
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("macOS Keychain protector requires darwin, current host is %s", runtime.GOOS)
		}
		binary := "/usr/bin/security"
		if st, err := os.Stat(binary); err != nil || !st.Mode().IsRegular() {
			return nil, errors.New("macOS Keychain protector requires /usr/bin/security")
		}
		return &keyringProtector{kind: m.Kind, binary: binary, account: m.ID, purpose: r.Purpose, run: runner}, nil
	case KindSecretService:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("linux Secret Service protector requires linux, current host is %s", runtime.GOOS)
		}
		binary, err := exec.LookPath("secret-tool")
		if err != nil {
			return nil, errors.New("linux Secret Service protector requires secret-tool (libsecret-tools/libsecret)")
		}
		return &keyringProtector{kind: m.Kind, binary: binary, account: m.ID, purpose: r.Purpose, run: runner}, nil
	case KindCommand:
		path := strings.TrimSpace(m.Command)
		if path == "" {
			path = strings.TrimSpace(getenv(r.CommandEnv))
		}
		if err := checkHelper(path, r.CommandEnv); err != nil {
			return nil, err
		}
		return &helperProtector{binary: path, id: m.ID, run: runner}, nil
	default:
		return nil, fmt.Errorf("unsupported protector kind %q", m.Kind)
	}
}

// checkHelper enforces substitution resistance before the helper is ever run:
// an absolute non-symlink executable that neither group nor other users can
// replace, in a directory they cannot replace it through.
func checkHelper(path, commandEnv string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute executable path", commandEnv)
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("protector helper %s: %w", path, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("protector helper %s must not be a symbolic link", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("protector helper %s: %w", path, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("protector helper %s is not executable", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("protector helper %s is writable by group or other users", path)
	}
	if parent, parentErr := os.Stat(filepath.Dir(path)); parentErr != nil || parent.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("protector helper directory %s must not be writable by group or other users", filepath.Dir(path))
	}
	return nil
}

// --- OS keyrings ---

type keyringProtector struct {
	kind, binary, account string
	purpose               Purpose
	run                   Runner
}

func (p *keyringProtector) Kind() string    { return p.kind }
func (p *keyringProtector) Protected() bool { return true }

func (p *keyringProtector) attrs() []string {
	return []string{"application", secretServiceApp, "purpose", p.purpose.Attribute, "instance", p.account}
}

func (p *keyringProtector) Load(ctx context.Context) ([]byte, error) {
	var r Result
	switch p.kind {
	case KindKeychain:
		r = p.run(ctx, nil, p.binary, "find-generic-password", "-s", p.purpose.KeychainService, "-a", p.account, "-w")
		if r.ExitCode != 0 {
			msg := strings.ToLower(string(r.Stderr))
			if r.ExitCode == 44 || strings.Contains(msg, "could not be found") {
				return nil, ErrNotFound
			}
			return nil, fmt.Errorf("macOS Keychain read failed (security exit %d); unlock the login keychain and retry", r.ExitCode)
		}
	case KindSecretService:
		r = p.run(ctx, nil, p.binary, append([]string{"lookup"}, p.attrs()...)...)
		if r.ExitCode != 0 {
			if r.ExitCode == 1 && len(bytes.TrimSpace(r.Stderr)) == 0 {
				return nil, ErrNotFound
			}
			return nil, fmt.Errorf("linux Secret Service read failed (secret-tool exit %d); ensure the user session D-Bus and unlocked login collection are available", r.ExitCode)
		}
	default:
		return nil, fmt.Errorf("unsupported OS protector %q", p.kind)
	}
	return bytes.TrimSpace(r.Stdout), nil
}

func (p *keyringProtector) Save(ctx context.Context, secret []byte) error {
	var r Result
	switch p.kind {
	case KindKeychain:
		// security(1) is the stable, rebuild-safe Keychain identity available to
		// unsigned Homebrew binaries. It necessarily receives the value as an
		// argument; the docs call out that same-user process-list tradeoff.
		r = p.run(ctx, nil, p.binary, "add-generic-password", "-U", "-s", p.purpose.KeychainService, "-a", p.account, "-w", string(secret))
	case KindSecretService:
		r = p.run(ctx, secret, p.binary, append([]string{"store", "--label=" + p.purpose.Label}, p.attrs()...)...)
	default:
		return fmt.Errorf("unsupported OS protector %q", p.kind)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("%s write failed (exit %d); the protector must be available and unlocked", Label(p.kind), r.ExitCode)
	}
	return nil
}

func (p *keyringProtector) Delete(ctx context.Context) error {
	var r Result
	switch p.kind {
	case KindKeychain:
		r = p.run(ctx, nil, p.binary, "delete-generic-password", "-s", p.purpose.KeychainService, "-a", p.account)
		if r.ExitCode == 44 || strings.Contains(strings.ToLower(string(r.Stderr)), "could not be found") {
			return nil
		}
	case KindSecretService:
		r = p.run(ctx, nil, p.binary, append([]string{"clear"}, p.attrs()...)...)
		if r.ExitCode == 1 && len(bytes.TrimSpace(r.Stderr)) == 0 {
			return nil
		}
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("%s delete failed (exit %d)", Label(p.kind), r.ExitCode)
	}
	return nil
}

// --- operator helper ---

type helperProtector struct {
	binary, id string
	run        Runner
}

func (p *helperProtector) Kind() string    { return KindCommand }
func (p *helperProtector) Protected() bool { return true }

func (p *helperProtector) Load(ctx context.Context) ([]byte, error) {
	r := p.run(ctx, nil, p.binary, "get", p.id)
	if r.ExitCode == 3 {
		return nil, ErrNotFound
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("protector helper read failed (exit %d); restore its KMS/secret-manager access and retry", r.ExitCode)
	}
	return bytes.TrimSpace(r.Stdout), nil
}

func (p *helperProtector) Save(ctx context.Context, secret []byte) error {
	r := p.run(ctx, secret, p.binary, "put", p.id)
	if r.ExitCode != 0 {
		return fmt.Errorf("protector helper write failed (exit %d)", r.ExitCode)
	}
	return nil
}

func (p *helperProtector) Delete(ctx context.Context) error {
	r := p.run(ctx, nil, p.binary, "delete", p.id)
	if r.ExitCode != 0 && r.ExitCode != 3 {
		return fmt.Errorf("protector helper delete failed (exit %d)", r.ExitCode)
	}
	return nil
}

// --- process execution ---

// Result is one helper or keyring-tool invocation's outcome.
type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// Runner executes a protector tool. Output is bounded: a helper that floods
// stdout must not be able to grow the gateway's memory.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) Result

// Run is the production Runner.
func Run(ctx context.Context, stdin []byte, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{W: &stdout, N: 1 << 20}
	cmd.Stderr = &limitedWriter{W: &stderr, N: 16 << 10}
	err := cmd.Run()
	if err == nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	}
	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: code}
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

// --- shared write discipline ---

// SaveVerified writes the record and reads it back before the caller treats it
// as durable. A protector that accepts a write and returns something else on
// the next read is the failure that leaves material unrecoverable, and it is
// only detectable here.
func SaveVerified(ctx context.Context, p Protector, record []byte) error {
	if err := p.Save(ctx, record); err != nil {
		return err
	}
	got, err := p.Load(ctx)
	if err != nil {
		return fmt.Errorf("verify protector write: %w", err)
	}
	if !bytes.Equal(got, record) {
		return errors.New("verify protector write: round-trip mismatch")
	}
	return nil
}

// Transfer moves a record from one protector to another: write the target,
// verify the round-trip, commit the locator, then delete the source copy. Every
// failure before commit leaves the source authoritative and the target cleaned
// up, so an interrupted migration is never a half-moved record. A failure
// *after* commit is reported as committed-with-cleanup-outstanding rather than
// rolled back, because the locator already names the target.
func Transfer(ctx context.Context, record []byte, source, target Protector, commit func() error) error {
	if err := target.Save(ctx, record); err != nil {
		return fmt.Errorf("write target protector: %w", err)
	}
	got, err := target.Load(ctx)
	if err != nil || !bytes.Equal(got, record) {
		_ = target.Delete(ctx)
		if err != nil {
			return fmt.Errorf("verify target protector: %w", err)
		}
		return errors.New("verify target protector: round-trip mismatch")
	}
	if err := commit(); err != nil {
		_ = target.Delete(ctx)
		return fmt.Errorf("commit custody migration: %w", err)
	}
	if err := source.Delete(ctx); err != nil {
		return fmt.Errorf("custody migration committed, but the old %s copy could not be deleted: %w", Label(source.Kind()), err)
	}
	return nil
}

// WriteAtomic replaces path with b through a sibling temporary file and a
// rename, then fsyncs the directory. A locator that is half-written after a
// crash would point at neither protector.
func WriteAtomic(path string, b []byte, mode os.FileMode) error {
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
