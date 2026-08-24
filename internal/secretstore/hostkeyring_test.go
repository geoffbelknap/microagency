package secretstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"microagency/internal/custody"
)

// The zero-configuration path is what every standalone install takes, so it has
// to be covered on a build machine with no desktop keyring. These tests supply a
// stand-in protector for that reason: what is under test is microagency's
// selection, creation, recording, and refusal logic, none of which is a property
// of Keychain or the Secret Service. The real backends are exercised by
// TestZeroConfigurationOnTheRealHostKeyring below, and by custody's own tests.

// fakeProtector is a protected protector with no host behind it. It answers the
// same three ways a real keyring does: with the record, with "nothing stored
// yet", or with a failure.
type fakeProtector struct {
	kind    string
	value   []byte
	failure error
	saves   int
}

func (p *fakeProtector) Kind() string    { return p.kind }
func (p *fakeProtector) Protected() bool { return true }

func (p *fakeProtector) Load(context.Context) ([]byte, error) {
	if p.failure != nil {
		return nil, p.failure
	}
	if p.value == nil {
		return nil, custody.ErrNotFound
	}
	return bytes.Clone(p.value), nil
}

func (p *fakeProtector) Save(_ context.Context, record []byte) error {
	if p.failure != nil {
		return p.failure
	}
	p.value = bytes.Clone(record)
	p.saves++
	return nil
}

func (p *fakeProtector) Delete(context.Context) error {
	if p.failure != nil {
		return p.failure
	}
	p.value = nil
	return nil
}

// withHostKeyring puts an empty, reachable stand-in where the host keyring would
// be, and returns it so a test can see what was stored through it.
func withHostKeyring(t *testing.T) *fakeProtector {
	t.Helper()
	requireHostKeyringConcept(t)
	fake := &fakeProtector{}
	prev := newProtector
	newProtector = func(records custody.Records, m custody.Manifest, getenv func(string) string, file custody.Protector) (custody.Protector, error) {
		// The operator's own key file is plain filesystem work and behaves the
		// same everywhere, so it stays real: a test about precedence should be
		// comparing against the actual key-file protector, not a second fake.
		if m.Kind == custody.KindFile {
			return records.New(m, getenv, file)
		}
		fake.kind = m.Kind
		return fake, nil
	}
	t.Cleanup(func() { newProtector = prev })
	return fake
}

// withoutHostKeyring makes the host keyring answer as unreachable — no keyring
// tool installed, no session bus, a locked collection. All three arrive here as
// a construction failure, which is what a headless machine actually produces.
func withoutHostKeyring(t *testing.T) {
	t.Helper()
	prev := newProtector
	newProtector = func(records custody.Records, m custody.Manifest, getenv func(string) string, file custody.Protector) (custody.Protector, error) {
		if m.Kind == custody.KindFile {
			return records.New(m, getenv, file)
		}
		return nil, errors.New("linux Secret Service protector requires secret-tool (libsecret-tools/libsecret)")
	}
	t.Cleanup(func() { newProtector = prev })
}

// requireHostKeyringConcept fails rather than skips on a platform where
// microagency names no default keyring at all. Linux and macOS both do, and they
// are what this ships on; anywhere else the stand-in would never be reached and
// a silent skip would hide that the test proved nothing.
func requireHostKeyringConcept(t *testing.T) {
	t.Helper()
	if autoProtectorKind() == "" {
		t.Fatalf("no default host keyring is defined for %s, so the zero-configuration path cannot be exercised here", runtime.GOOS)
	}
}

// The zero-configuration install: no VAULT_ADDR, no protector setting, no key
// file. The store must come up encrypted, under a key the host keyring holds,
// and the locator must record that so the next start does not re-decide.
func TestZeroConfigurationEncryptsUnderTheHostKeyring(t *testing.T) {
	fake := withHostKeyring(t)
	dir := t.TempDir()
	none := func(string) string { return "" }

	store, err := Open(dir, none, Options{})
	if err != nil {
		t.Fatalf("zero-configuration start refused: %v", err)
	}
	if store.Kind() != KindEncryptedFile {
		t.Fatalf("kind = %q, want %q", store.Kind(), KindEncryptedFile)
	}
	f := store.(*File)
	if f.KeyCustody() == custody.KindFile || f.KeyCustody() == "" {
		t.Fatalf("data key custody = %q, want a protected one", f.KeyCustody())
	}
	if !f.KeyCreated() {
		t.Fatal("the first start did not report generating the data key")
	}
	if fake.saves == 0 || len(fake.value) == 0 {
		t.Fatal("nothing was stored through the protector")
	}
	if err := store.Save(context.Background(), "probe", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// The key is the protector's, not the state directory's. A copy of the
	// directory alone must not be able to open this store.
	if bytes.Contains(readFile(t, StorePath(dir)), fake.value) {
		t.Fatal("the data key was written into the state directory beside the ciphertext")
	}

	// The second start retrieves the same key through the recorded locator and
	// reads back what the first one wrote.
	again, err := Open(dir, none, Options{})
	if err != nil {
		t.Fatalf("second zero-configuration start refused: %v", err)
	}
	if again.(*File).KeyCreated() {
		t.Fatal("a later start reported generating the key again")
	}
	got, err := again.Load(context.Background(), "probe")
	if err != nil || string(got) != "v" {
		t.Fatalf("second start could not read the first start's data: %q %v", got, err)
	}
}

// A host that offers no usable keyring must still reach the plaintext gate, and
// must not write a key beside the ciphertext to avoid refusing.
func TestNoUsableHostKeyringRefusesRatherThanKeyingBesideTheData(t *testing.T) {
	withoutHostKeyring(t)
	dir := t.TempDir()
	none := func(string) string { return "" }

	if _, err := Open(dir, none, Options{}); !errors.Is(err, ErrPlaintextNotAllowed) {
		t.Fatalf("want ErrPlaintextNotAllowed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, CustodyFile)); !os.IsNotExist(err) {
		t.Fatalf("a refused start recorded a locator anyway: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused start left state behind: %v", entries)
	}

	auto := InspectAutoProtector(context.Background(), dir, none)
	if auto.Available {
		t.Fatalf("keyring reported available with nothing behind it: %+v", auto)
	}
	if auto.Detail == "" {
		t.Fatal("an unavailable keyring must say why")
	}
}

// Auto-selection is what happens when the operator has said nothing. Every
// explicit choice outranks it, and an already-encrypted store is never re-keyed
// under a keyring on the strength of a setting that went missing.
func TestHostKeyringNeverOverridesAnExplicitChoice(t *testing.T) {
	t.Run("plaintext opt-in", func(t *testing.T) {
		fake := withHostKeyring(t)
		store, err := Open(t.TempDir(), func(string) string { return "" }, Options{AllowPlaintext: true})
		if err != nil {
			t.Fatal(err)
		}
		if store.Kind() != KindFile {
			t.Fatalf("the explicit unencrypted opt-in was overridden: kind = %q", store.Kind())
		}
		if fake.saves != 0 {
			t.Fatal("a key was put in the keyring for a deployment that opted out of encryption")
		}
	})

	t.Run("operator key file", func(t *testing.T) {
		fake := withHostKeyring(t)
		keyFile := writeKeyFile(t, bytes.Repeat([]byte{7}, 32))
		env := func(name string) string {
			if name == FileKeyEnv {
				return keyFile
			}
			return ""
		}
		store, err := Open(t.TempDir(), env, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := store.(*File).KeyCustody(); got != custody.KindFile {
			t.Fatalf("the operator's key file was overridden: custody = %q", got)
		}
		if fake.saves != 0 {
			t.Fatal("a second key was put in the keyring beside the operator's own")
		}
	})

	t.Run("already-encrypted store with no setting", func(t *testing.T) {
		fake := withHostKeyring(t)
		dir := t.TempDir()
		keyFile := writeKeyFile(t, bytes.Repeat([]byte{9}, 32))
		withKey := func(name string) string {
			if name == FileKeyEnv {
				return keyFile
			}
			return ""
		}
		store, err := Open(dir, withKey, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(context.Background(), "probe", []byte("v")); err != nil {
			t.Fatal(err)
		}
		// The setting disappears. Minting a keyring key here would leave the
		// existing credentials permanently unreadable.
		if _, err := Open(dir, func(string) string { return "" }, Options{}); err == nil {
			t.Fatal("an encrypted store was re-keyed under the host keyring")
		}
		if fake.saves != 0 {
			t.Fatal("a key was minted over ciphertext it cannot open")
		}
	})
}

// The locator is what `purge --full` follows to delete the data key out of the
// keyring. A protector that already holds the key — a rebuilt state directory
// around a keyring that kept its record — must still leave one behind, or the
// key outlives every trace of the gateway that created it.
func TestProtectedCustodyAlwaysLeavesALocator(t *testing.T) {
	withHostKeyring(t)
	none := func(string) string { return "" }

	dir := t.TempDir()
	if _, err := Open(dir, none, Options{}); err != nil {
		t.Fatal(err)
	}
	locator := filepath.Join(dir, CustodyFile)
	if _, err := os.Stat(locator); err != nil {
		t.Fatalf("first start recorded no locator: %v", err)
	}

	// The state directory is rebuilt while the keyring keeps its record.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, none, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(locator); err != nil {
		t.Fatalf("a start that found an existing key recorded no locator: %v", err)
	}
}

// TestZeroConfigurationOnTheRealHostKeyring runs the same path against the
// keyring this machine actually has. It is the only test in this file that needs
// one; the others prove the same behavior with a stand-in, so a machine without
// a keyring still gets the coverage.
func TestZeroConfigurationOnTheRealHostKeyring(t *testing.T) {
	dir := t.TempDir()
	none := func(string) string { return "" }
	ctx := context.Background()

	if auto := InspectAutoProtector(ctx, dir, none); !auto.Available {
		t.Skipf("no reachable host keyring here (%s: %s); the stand-in tests in this file cover the same path",
			CustodyLabel(autoProtectorKind()), auto.Detail)
	}
	// Whatever this leaves in a real keyring is removed again, pass or fail.
	t.Cleanup(func() {
		if err := DeleteKeyCustody(context.Background(), dir, none); err != nil {
			t.Errorf("could not remove the data key this test put in the host keyring: %v", err)
		}
	})

	store, err := Open(dir, none, Options{})
	if err != nil {
		t.Fatalf("zero-configuration start refused with a reachable keyring: %v", err)
	}
	if store.Kind() != KindEncryptedFile {
		t.Fatalf("kind = %q, want %q", store.Kind(), KindEncryptedFile)
	}
	if err := store.Save(ctx, "probe", []byte("v")); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, none, Options{})
	if err != nil {
		t.Fatalf("second start refused: %v", err)
	}
	got, err := again.Load(ctx, "probe")
	if err != nil || string(got) != "v" {
		t.Fatalf("the real keyring did not return a key that reopens the store: %q %v", got, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
