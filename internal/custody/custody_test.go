package custody

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type memProtector struct {
	kind        string
	protected   bool
	value       []byte
	corruptLoad bool
	saveErr     error
	deleted     bool
}

func (p *memProtector) Kind() string    { return p.kind }
func (p *memProtector) Protected() bool { return p.protected }
func (p *memProtector) Load(context.Context) ([]byte, error) {
	if p.value == nil {
		return nil, ErrNotFound
	}
	out := append([]byte(nil), p.value...)
	if p.corruptLoad {
		out = append(out, 'x')
	}
	return out, nil
}
func (p *memProtector) Save(_ context.Context, v []byte) error {
	if p.saveErr != nil {
		return p.saveErr
	}
	p.value = append([]byte(nil), v...)
	p.deleted = false
	return nil
}
func (p *memProtector) Delete(context.Context) error {
	p.value, p.deleted = nil, true
	return nil
}

// TestProtectorCommandProtocols pins the wire contract each protector speaks —
// including that the value reaches Secret Service and the helper only on stdin,
// where another process on the host cannot read it out of the process list.
func TestProtectorCommandProtocols(t *testing.T) {
	ctx := context.Background()
	secret := []byte(`{"unseal_key":"not-on-disk"}`)
	var calls []struct {
		stdin []byte
		name  string
		args  []string
	}
	runner := func(_ context.Context, stdin []byte, name string, args ...string) Result {
		calls = append(calls, struct {
			stdin []byte
			name  string
			args  []string
		}{append([]byte(nil), stdin...), name, append([]string(nil), args...)})
		if slices.Contains(args, "get") || slices.Contains(args, "lookup") || slices.Contains(args, "find-generic-password") {
			return Result{Stdout: append(secret, '\n')}
		}
		return Result{}
	}
	purpose := Purpose{KeychainService: "microagency.test", Attribute: "test-material", Label: "microagency test"}

	linux := &keyringProtector{kind: KindSecretService, binary: "/usr/bin/secret-tool", account: "instance", purpose: purpose, run: runner}
	if err := linux.Save(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(calls[0].stdin, secret) || strings.Contains(strings.Join(calls[0].args, " "), string(secret)) {
		t.Fatalf("Secret Service did not receive the value only on stdin: %+v", calls[0])
	}
	if !slices.Contains(calls[0].args, "test-material") {
		t.Fatalf("Secret Service call did not carry the purpose attribute: %+v", calls[0].args)
	}
	if got, err := linux.Load(ctx); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Secret Service load = %q err=%v", got, err)
	}

	calls = nil
	helper := &helperProtector{binary: "/usr/local/bin/protect", id: "instance", run: runner}
	if err := helper.Save(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(calls[0].stdin, secret) || strings.Contains(strings.Join(calls[0].args, " "), string(secret)) {
		t.Fatalf("helper did not receive the value only on stdin: %+v", calls[0])
	}
	if got, err := helper.Load(ctx); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("helper load = %q err=%v", got, err)
	}

	calls = nil
	mac := &keyringProtector{kind: KindKeychain, binary: "/usr/bin/security", account: "instance", purpose: purpose, run: runner}
	if err := mac.Save(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(calls[0].args, string(secret)) {
		t.Fatal("security(1) compatibility path did not receive the Keychain value")
	}
	if !slices.Contains(calls[0].args, "microagency.test") {
		t.Fatalf("Keychain call did not carry the service name: %+v", calls[0].args)
	}
}

// TestPurposesDoNotCollide is the property that lets two consumers share one
// keyring: distinct service names and attributes, so neither can read or
// overwrite the other's record. It is what makes Purpose a contract rather
// than a label, and it has to hold before a second consumer exists, not after
// one has already overwritten the first one's key.
func TestPurposesDoNotCollide(t *testing.T) {
	ctx := context.Background()
	var seen []string
	runner := func(_ context.Context, _ []byte, _ string, args ...string) Result {
		seen = append(seen, strings.Join(args, " "))
		return Result{}
	}
	a := &keyringProtector{kind: KindSecretService, binary: "/x", account: "same-id",
		purpose: Purpose{Attribute: "secretstore-data-key"}, run: runner}
	b := &keyringProtector{kind: KindSecretService, binary: "/x", account: "same-id",
		purpose: Purpose{Attribute: "some-other-material"}, run: runner}
	_ = a.Save(ctx, []byte("a"))
	_ = b.Save(ctx, []byte("b"))
	if seen[0] == seen[1] {
		t.Fatalf("two purposes addressed the same keyring record: %q", seen[0])
	}
}

func TestTransferCommitsBeforeDeletingSource(t *testing.T) {
	ctx := context.Background()
	record := []byte("the-record")
	source := &memProtector{kind: KindFile, value: record}
	target := &memProtector{kind: KindCommand, protected: true}
	committed := false
	if err := Transfer(ctx, record, source, target, func() error { committed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !committed || !source.deleted || !bytes.Equal(target.value, record) {
		t.Fatalf("committed=%v source.deleted=%v target=%q", committed, source.deleted, target.value)
	}

	source = &memProtector{kind: KindFile, value: record}
	bad := &memProtector{kind: KindCommand, protected: true, corruptLoad: true}
	if err := Transfer(ctx, record, source, bad, func() error { t.Fatal("committed over a bad target"); return nil }); err == nil {
		t.Fatal("round-trip mismatch was accepted")
	}
	if source.deleted {
		t.Fatal("source was deleted before the target verified")
	}

	source = &memProtector{kind: KindFile, value: record}
	target = &memProtector{kind: KindCommand, protected: true}
	if err := Transfer(ctx, record, source, target, func() error { return errors.New("disk full") }); err == nil {
		t.Fatal("a failed commit was accepted")
	}
	if source.deleted {
		t.Fatal("source was deleted after a failed commit")
	}
	if target.value != nil {
		t.Fatal("target copy survived a failed commit")
	}
}

func TestSaveVerifiedRejectsAProtectorThatDoesNotReadBack(t *testing.T) {
	ctx := context.Background()
	if err := SaveVerified(ctx, &memProtector{kind: KindCommand, protected: true}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	err := SaveVerified(ctx, &memProtector{kind: KindCommand, protected: true, corruptLoad: true}, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "round-trip mismatch") {
		t.Fatalf("unverifiable write accepted: %v", err)
	}
}

func TestManifestRoundTripAndFormatIsolation(t *testing.T) {
	dir := t.TempDir()
	a := Records{Path: filepath.Join(dir, "custody.json"), Format: "format-a", Noun: "thing A", KindEnv: "A_ENV"}
	if err := a.SaveManifest(Manifest{Kind: KindCommand, ID: ID(dir), Command: "/opt/helper"}); err != nil {
		t.Fatal(err)
	}
	got, err := a.LoadManifest()
	if err != nil || got.Kind != KindCommand || got.Command != "/opt/helper" || got.Format != "format-a" {
		t.Fatalf("manifest = %+v err=%v", got, err)
	}
	if !got.Protected() {
		t.Fatal("command custody reported unprotected")
	}

	// A second consumer must not adopt the first's locator as its own.
	b := Records{Path: a.Path, Format: "format-b", Noun: "thing B", KindEnv: "B_ENV"}
	if _, err := b.LoadManifest(); err == nil {
		t.Fatal("a foreign locator format was accepted")
	}

	if !a.Exists() {
		t.Fatal("Exists did not see a written locator")
	}
	if err := a.DeleteManifest(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LoadManifest(); !os.IsNotExist(err) {
		t.Fatalf("after delete: %v", err)
	}
	if err := a.DeleteManifest(); err != nil {
		t.Fatalf("deleting an absent locator: %v", err)
	}
}

func TestCanonicalKindNamesTheSettingItRejects(t *testing.T) {
	for _, raw := range []string{"", "file"} {
		if k, err := CanonicalKind(raw, "SOME_ENV"); err != nil || k != KindFile {
			t.Fatalf("CanonicalKind(%q) = %q, %v", raw, k, err)
		}
	}
	for raw, want := range map[string]string{
		"keychain": KindKeychain, "macos-keychain": KindKeychain,
		"secret-service": KindSecretService, "keyring": KindSecretService,
		"command": KindCommand, "kms": KindCommand, " KMS ": KindCommand,
	} {
		if k, err := CanonicalKind(raw, "SOME_ENV"); err != nil || k != want {
			t.Fatalf("CanonicalKind(%q) = %q, %v; want %q", raw, k, err, want)
		}
	}
	_, err := CanonicalKind("vault", "SOME_ENV")
	if err == nil || !strings.Contains(err.Error(), "SOME_ENV") {
		t.Fatalf("rejection did not name the setting: %v", err)
	}
}

// TestHelperMustNotBeSubstitutable is the reason the command protector checks
// the filesystem before it ever runs: anything another user can replace is a
// path to the material, not a protector for it.
func TestHelperMustNotBeSubstitutable(t *testing.T) {
	dir := t.TempDir()
	recs := Records{Path: filepath.Join(dir, "c.json"), Format: "f", Noun: "n", KindEnv: "K", CommandEnv: "CMD"}
	manifest := Manifest{Format: "f", Kind: KindCommand, ID: "id"}
	getenv := func(string) string { return "" }

	helper := filepath.Join(dir, "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest.Command = helper
	if _, err := recs.New(manifest, getenv, nil); err != nil {
		t.Fatalf("a private executable helper was rejected: %v", err)
	}

	manifest.Command = "relative/helper"
	if _, err := recs.New(manifest, getenv, nil); err == nil || !strings.Contains(err.Error(), "CMD") {
		t.Fatalf("relative helper: %v", err)
	}

	worldWritable := filepath.Join(dir, "loose")
	if err := os.WriteFile(worldWritable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil { // explicit: umask would strip this
		t.Fatal(err)
	}
	manifest.Command = worldWritable
	if _, err := recs.New(manifest, getenv, nil); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("world-writable helper: %v", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(helper, link); err != nil {
		t.Fatal(err)
	}
	manifest.Command = link
	if _, err := recs.New(manifest, getenv, nil); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlinked helper: %v", err)
	}

	manifest.Command = filepath.Join(dir, "absent")
	if _, err := recs.New(manifest, getenv, nil); err == nil {
		t.Fatal("a missing helper was accepted")
	}
}

func TestIDIsAStableDigestNotThePath(t *testing.T) {
	dir := t.TempDir()
	if a, b := ID(dir), ID(dir); a != b {
		t.Fatalf("ID is not stable: %q vs %q", a, b)
	}
	if strings.Contains(ID(dir), filepath.Base(dir)) {
		t.Fatal("the record id leaks the operator's directory layout")
	}
	if ID(dir) == ID(t.TempDir()) {
		t.Fatal("two directories share one record id")
	}
}

func TestWriteAtomicReplacesInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "file")
	if err := WriteAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "second" {
		t.Fatalf("read = %q err=%v", b, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v err=%v", st.Mode().Perm(), err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file remained: %v", err)
	}
}

func TestBoundedOutputCannotGrowUnbounded(t *testing.T) {
	var buf bytes.Buffer
	w := &limitedWriter{W: &buf, N: 8}
	n, err := w.Write(bytes.Repeat([]byte("x"), 100))
	if err != nil || n != 100 {
		t.Fatalf("write = %d, %v (the writer must not stall the child process)", n, err)
	}
	if buf.Len() != 8 {
		t.Fatalf("captured %d bytes, want 8", buf.Len())
	}
}
