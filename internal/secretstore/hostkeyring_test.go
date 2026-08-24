package secretstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"microagency/internal/custody"
)

// withoutHostKeyring makes this host's own keyring answer as unreachable, so a
// test that is about the refusal path gets the refusal on every machine — a
// developer laptop with an unlocked login keyring included.
func withoutHostKeyring(t *testing.T) {
	t.Helper()
	prev := hostRunner
	hostRunner = func(context.Context, []byte, string, ...string) custody.Result {
		return custody.Result{ExitCode: 1, Stderr: []byte("no session bus")}
	}
	t.Cleanup(func() { hostRunner = prev })
}

// withHostKeyring makes this host's own keyring answer as an empty, reachable
// one, so the auto-selected posture is exercised on every machine.
func withHostKeyring(t *testing.T) *map[string][]byte {
	t.Helper()
	stored := map[string][]byte{}
	prev := hostRunner
	hostRunner = func(_ context.Context, stdin []byte, _ string, args ...string) custody.Result {
		switch {
		case len(args) > 0 && (args[0] == "store" || args[0] == "add-generic-password"):
			stored["k"] = stdin
			return custody.Result{}
		case len(args) > 0 && (args[0] == "lookup" || args[0] == "find-generic-password"):
			v, ok := stored["k"]
			if !ok {
				return custody.Result{ExitCode: 1} // secret-tool "absent" shape
			}
			return custody.Result{Stdout: v}
		default:
			return custody.Result{}
		}
	}
	t.Cleanup(func() { hostRunner = prev })
	return &stored
}

// A host that offers no usable keyring must still reach the plaintext gate, and
// must not write a key beside the ciphertext to avoid it.
func TestNoUsableHostKeyringRefusesRatherThanKeyingBesideTheData(t *testing.T) {
	withoutHostKeyring(t)
	dir := t.TempDir()
	if _, err := Open(dir, func(string) string { return "" }, Options{}); err == nil {
		t.Fatal("a host with no usable keyring started anyway")
	}
	auto := InspectAutoProtector(context.Background(), dir, func(string) string { return "" })
	if auto.Available {
		t.Fatalf("keyring reported available with no runner behind it: %+v", auto)
	}
	if auto.Detail == "" {
		t.Fatal("an unavailable keyring must say why")
	}
}

// The zero-configuration install: no VAULT_ADDR, no protector setting, no key
// file. The store must come up encrypted, under a key the host keyring holds,
// and the locator must record that so the next start does not re-decide.
func TestZeroConfigurationEncryptsUnderTheHostKeyring(t *testing.T) {
	withHostKeyring(t)
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
	if err := store.Save(context.Background(), "probe", []byte("v")); err != nil {
		t.Fatal(err)
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

// Auto-selection is what happens when the operator has said nothing. Every
// explicit choice outranks it, and an already-encrypted store is never re-keyed
// under a keyring on the strength of a setting that went missing.
func TestHostKeyringNeverOverridesAnExplicitChoice(t *testing.T) {
	withHostKeyring(t)

	t.Run("plaintext opt-in", func(t *testing.T) {
		store, err := Open(t.TempDir(), func(string) string { return "" }, Options{AllowPlaintext: true})
		if err != nil {
			t.Fatal(err)
		}
		if store.Kind() != KindFile {
			t.Fatalf("the explicit unencrypted opt-in was overridden: kind = %q", store.Kind())
		}
	})

	t.Run("operator key file", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := writeKeyFile(t, bytes.Repeat([]byte{7}, 32))
		env := func(name string) string {
			if name == FileKeyEnv {
				return keyFile
			}
			return ""
		}
		store, err := Open(dir, env, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := store.(*File).KeyCustody(); got != custody.KindFile {
			t.Fatalf("the operator's key file was overridden: custody = %q", got)
		}
	})

	t.Run("already-encrypted store with no setting", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := writeKeyFile(t, bytes.Repeat([]byte{7}, 32))
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
