package secretstore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/custody"
)

// stubHelper writes a `command` protector helper backed by a file, matching the
// documented get/put/delete protocol including exit 3 for an absent record.
func stubHelper(t *testing.T, record string) (helper string, getenv func(string) string) {
	t.Helper()
	helperDir := t.TempDir()
	helper = filepath.Join(helperDir, "protector")
	script := fmt.Sprintf(`#!/bin/sh
store=%q
case "$1" in
  get) test -f "$store" || exit 3; cat "$store" ;;
  put) cat > "$store" ;;
  delete) rm -f "$store" ;;
  *) exit 2 ;;
esac
`, record)
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return helper, func(name string) string {
		switch name {
		case ProtectorEnv:
			return "command"
		case ProtectorCommandEnv:
			return helper
		default:
			return ""
		}
	}
}

func writeKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret-store.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestProtectorCreatesThenReusesTheDataKey is the whole feature in one test: a
// first start mints a key nobody placed, and every later start opens the SAME
// store with the key the protector returns.
func TestProtectorCreatesThenReusesTheDataKey(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, getenv := stubHelper(t, recordPath)
	ctx := context.Background()

	store, err := Open(dir, getenv, Options{})
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if store.Kind() != KindEncryptedFile {
		t.Fatalf("kind = %q, want %q", store.Kind(), KindEncryptedFile)
	}
	if kc := store.(*File).KeyCustody(); kc != custody.KindCommand {
		t.Fatalf("key custody = %q, want command", kc)
	}
	if err := store.Save(ctx, "up/example", []byte(`{"refresh_token":"sentinel"}`)); err != nil {
		t.Fatal(err)
	}

	// The key is with the protector, and nothing under the state directory
	// carries it: a copy of ~/.microagency alone must not decrypt.
	record, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("the protector holds no record: %v", err)
	}
	if _, err := parseDataKey(record); err != nil {
		t.Fatalf("the protector's record is not a usable data key: %v", err)
	}
	blob, err := os.ReadFile(StorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "sentinel") {
		t.Fatal("credentials are in the clear on disk")
	}
	if strings.Contains(string(blob), strings.TrimSpace(string(record))) {
		t.Fatal("the data key is stored beside the ciphertext it protects")
	}

	// A later start retrieves the same key and reads the same store back.
	again, err := Open(dir, getenv, Options{})
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	got, err := again.Load(ctx, "up/example")
	if err != nil || string(got) != `{"refresh_token":"sentinel"}` {
		t.Fatalf("restart load = %s err=%v", got, err)
	}
}

// TestUnavailableProtectorFailsClosed: the protector is the whole reason the
// store is encrypted, so losing it must stop startup — not quietly produce a
// second store the operator does not know about.
func TestUnavailableProtectorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	helper, getenv := stubHelper(t, recordPath)

	store, err := Open(dir, getenv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "up/example", []byte(`{"refresh_token":"sentinel"}`)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(StorePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	// The helper now fails every request, as a KMS outage or a denied identity would.
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Even with the plaintext opt-in, which must not rescue a failed protector.
	_, err = Open(dir, getenv, Options{AllowPlaintext: true})
	if !errors.Is(err, ErrProtectorUnavailable) {
		t.Fatalf("unavailable protector did not fail closed: %v", err)
	}
	if errors.Is(err, ErrPlaintextNotAllowed) {
		t.Fatal("an unavailable protector was reported as a plaintext-gate decision")
	}
	after, err := os.ReadFile(StorePath(dir))
	if err != nil || string(after) != string(before) {
		t.Fatal("a failed open modified the credential store")
	}

	posture := InspectKeyCustody(context.Background(), dir, getenv)
	if posture.Available {
		t.Fatalf("doctor reported an unreachable protector as available: %+v", posture)
	}
	if posture.Kind != custody.KindCommand {
		t.Fatalf("doctor did not name the protector: %+v", posture)
	}
}

// TestProtectorWithNoKeyRefusesToReKeyAnEncryptedStore: minting a fresh key
// over existing ciphertext would make the store permanently unreadable, and the
// failure would read as "wrong key" rather than "your protector lost its record".
func TestProtectorWithNoKeyRefusesToReKeyAnEncryptedStore(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, getenv := stubHelper(t, recordPath)

	store, err := Open(dir, getenv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), "up/example", []byte(`{"refresh_token":"sentinel"}`)); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(StorePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	// The protector answers, but its record is gone (restored from a backup that
	// predates the key, or deleted by mistake).
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir, getenv, Options{})
	if !errors.Is(err, ErrProtectorUnavailable) || !strings.Contains(err.Error(), "already encrypted") {
		t.Fatalf("a missing record re-keyed a live store: %v", err)
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatal("a new key was written despite the refusal")
	}
	now, err := os.ReadFile(StorePath(dir))
	if err != nil || string(now) != string(ciphertext) {
		t.Fatal("the refusal rewrote the credential store")
	}
}

// TestKeyFileBehaviorIsUnchanged: the setting a live deployment already depends
// on keeps opening its existing store with no operator action.
func TestKeyFileBehaviorIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyPath := writeKeyFile(t, key)
	ctx := context.Background()

	// A store created the old way, before any of this existed.
	pre, err := NewEncryptedFile(StorePath(dir), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pre.Save(ctx, "up/example", []byte(`{"refresh_token":"sentinel"}`)); err != nil {
		t.Fatal(err)
	}

	getenv := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return ""
	}
	store, err := Open(dir, getenv, Options{})
	if err != nil {
		t.Fatalf("the existing key-file store did not open: %v", err)
	}
	got, err := store.Load(ctx, "up/example")
	if err != nil || string(got) != `{"refresh_token":"sentinel"}` {
		t.Fatalf("load = %s err=%v", got, err)
	}
	if store.Kind() != KindEncryptedFile {
		t.Fatalf("kind = %q", store.Kind())
	}
	if kc := store.(*File).KeyCustody(); kc != custody.KindFile {
		t.Fatalf("key custody = %q, want file", kc)
	}
	// No locator appears: MICROAGENCY_SECRET_KEY_FILE is the record, and a new
	// file in the state directory would be a change this deployment never made.
	if _, err := os.Stat(filepath.Join(dir, CustodyFile)); !os.IsNotExist(err) {
		t.Fatalf("the key-file posture wrote a custody locator: %v", err)
	}

	// A missing key file still reports the setting, and never mints a key.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir, getenv, Options{AllowPlaintext: true})
	if err == nil || !strings.Contains(err.Error(), FileKeyEnv) {
		t.Fatalf("a missing key file did not name the setting: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("microagency created a key file it does not own")
	}
}

// TestConflictingCustodyRefusesRatherThanGuesses. Two settings that name
// different keys is invalid configuration: the store opens under exactly one of
// them, and picking wrong is indistinguishable from corruption.
func TestConflictingCustodyRefusesRatherThanGuesses(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, base := stubHelper(t, recordPath)

	if _, err := Open(dir, base, Options{}); err != nil {
		t.Fatal(err)
	}
	protectorKey, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}

	other := make([]byte, 32)
	other[0] = 0xAA
	withKeyFile := func(path string) func(string) string {
		return func(name string) string {
			if name == FileKeyEnv {
				return path
			}
			return base(name)
		}
	}

	_, err = Open(dir, withKeyFile(writeKeyFile(t, other)), Options{})
	if !errors.Is(err, ErrCustodyConflict) {
		t.Fatalf("disagreeing custody settings were not refused: %v", err)
	}
	if !strings.Contains(err.Error(), FileKeyEnv) {
		t.Fatalf("the refusal did not name both settings: %v", err)
	}

	// Agreeing settings are not a conflict: that is a migration whose old
	// setting is still exported, and refusing it would strand the operator.
	same, err := parseDataKey(protectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, withKeyFile(writeKeyFile(t, same)), Options{}); err != nil {
		t.Fatalf("agreeing custody settings were refused: %v", err)
	}

	// A recorded locator disagreeing with the environment is refused too.
	envKeychain := func(name string) string {
		if name == ProtectorEnv {
			return "keychain"
		}
		return base(name)
	}
	_, err = Open(dir, envKeychain, Options{})
	if !errors.Is(err, ErrCustodyConflict) || !strings.Contains(err.Error(), ProtectorEnv) {
		t.Fatalf("a locator/environment disagreement was not refused: %v", err)
	}
}

// TestNoCustodyConfiguredStillReachesThePlaintextGate: adding protectors must
// not change what a deployment that configures none of this does.
func TestNoCustodyConfiguredStillReachesThePlaintextGate(t *testing.T) {
	dir := t.TempDir()
	none := func(string) string { return "" }
	if _, err := Open(dir, none, Options{}); !errors.Is(err, ErrPlaintextNotAllowed) {
		t.Fatalf("want ErrPlaintextNotAllowed, got %v", err)
	}
	store, err := Open(dir, none, Options{AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if store.Kind() != KindFile {
		t.Fatalf("kind = %q, want %q", store.Kind(), KindFile)
	}
	if kc := store.(*File).KeyCustody(); kc != "" {
		t.Fatalf("an unencrypted store claimed key custody %q", kc)
	}
	if posture := InspectKeyCustody(context.Background(), dir, none); posture.Kind != "" {
		t.Fatalf("doctor invented custody where none is configured: %+v", posture)
	}
}

// TestFileProtectorRequiresItsKeyFile: explicit configuration that cannot work
// fails closed instead of sliding into the plaintext gate.
func TestFileProtectorRequiresItsKeyFile(t *testing.T) {
	getenv := func(name string) string {
		if name == ProtectorEnv {
			return "file"
		}
		return ""
	}
	_, err := Open(t.TempDir(), getenv, Options{AllowPlaintext: true})
	if err == nil || !strings.Contains(err.Error(), FileKeyEnv) {
		t.Fatalf("want a refusal naming %s, got %v", FileKeyEnv, err)
	}
}

// TestMigrateMovesCustodyWithoutRewritingTheStore. The ciphertext is untouched,
// so an interrupted migration leaves a store that still opens under the key the
// operator already has.
func TestMigrateMovesCustodyWithoutRewritingTheStore(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	key := make([]byte, 32)
	key[3] = 0x7F
	keyPath := writeKeyFile(t, key)
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	helper, helperEnv := stubHelper(t, recordPath)

	fileEnv := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return ""
	}
	store, err := Open(dir, fileEnv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "up/example", []byte(`{"refresh_token":"sentinel"}`)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(StorePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	migrateEnv := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return helperEnv(name)
	}
	if err := MigrateKeyCustody(ctx, dir, migrateEnv, "command", false); err != nil {
		t.Fatalf("migrate to command: %v", err)
	}
	after, err := os.ReadFile(StorePath(dir))
	if err != nil || string(after) != string(before) {
		t.Fatal("migration rewrote the credential store")
	}
	// The key file is left in place as the operator's backup — microagency did
	// not create it and does not delete it.
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("migration deleted the operator's key file: %v", err)
	}
	record, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := parseDataKey(record)
	if err != nil || string(moved) != string(key) {
		t.Fatal("the protector did not receive the same data key")
	}

	// The store opens through the protector alone, with the key-file setting gone.
	reopened, err := Open(dir, helperEnv, Options{})
	if err != nil {
		t.Fatalf("post-migration open: %v", err)
	}
	got, err := reopened.Load(ctx, "up/example")
	if err != nil || string(got) != `{"refresh_token":"sentinel"}` {
		t.Fatalf("post-migration load = %s err=%v", got, err)
	}

	// Migrating to the same protector is a no-op the command names, not a
	// silently repeated move.
	if err := MigrateKeyCustody(ctx, dir, helperEnv, "command", false); err == nil || !strings.Contains(err.Error(), "already uses") {
		t.Fatalf("re-migrating to the same protector: %v", err)
	}

	// Going back to a key file writes the key to disk, so it is gated.
	if err := MigrateKeyCustody(ctx, dir, migrateEnv, "file", false); err == nil || !strings.Contains(err.Error(), "--allow-degraded") {
		t.Fatalf("degraded migration was not gated: %v", err)
	}
	if err := MigrateKeyCustody(ctx, dir, migrateEnv, "file", true); err != nil {
		t.Fatalf("acknowledged degraded migration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, CustodyFile)); !os.IsNotExist(err) {
		t.Fatalf("a stale locator survived the move back to a key file: %v", err)
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatal("the old protected record was not deleted after the move")
	}
	backAgain, err := Open(dir, fileEnv, Options{})
	if err != nil {
		t.Fatalf("open after moving back to the key file: %v", err)
	}
	if got, err := backAgain.Load(ctx, "up/example"); err != nil || string(got) != `{"refresh_token":"sentinel"}` {
		t.Fatalf("load after moving back = %s err=%v", got, err)
	}
	_ = helper
}

// TestMigrateRefusesToOverwriteADifferentKeyFile: the destination may be some
// other store's only key, and overwriting it is unrecoverable.
func TestMigrateRefusesToOverwriteADifferentKeyFile(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, helperEnv := stubHelper(t, recordPath)
	if _, err := Open(dir, helperEnv, Options{}); err != nil {
		t.Fatal(err)
	}
	unrelated := make([]byte, 32)
	unrelated[0] = 0x99
	keyPath := writeKeyFile(t, unrelated)
	getenv := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return helperEnv(name)
	}
	err := MigrateKeyCustody(context.Background(), dir, getenv, "file", true)
	if err == nil || !strings.Contains(err.Error(), "already holds a different key") {
		t.Fatalf("migration overwrote an unrelated key file: %v", err)
	}
	b, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, _ := parseDataKey(b); string(got) != string(unrelated) {
		t.Fatal("the unrelated key file was modified")
	}
}

// TestDeleteKeyCustodyReversesTheCreate. Purge must not strand a record in a
// keyring or KMS by removing the locator that finds it.
func TestDeleteKeyCustodyReversesTheCreate(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, getenv := stubHelper(t, recordPath)
	ctx := context.Background()
	if _, err := Open(dir, getenv, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatal(err)
	}
	if err := DeleteKeyCustody(ctx, dir, getenv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatal("the protected data key survived a purge")
	}
	// The operator's key file is never deleted by this path.
	keyPath := writeKeyFile(t, make([]byte, 32))
	fileEnv := func(name string) string {
		if name == FileKeyEnv {
			return keyPath
		}
		return ""
	}
	if err := DeleteKeyCustody(ctx, t.TempDir(), fileEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("purge deleted the operator's key file: %v", err)
	}
}

// TestInspectKeyCustodyDoesNotCreateAnything: doctor must report what a start
// WOULD do, never do it. A probe that mints the key makes its own page green.
func TestInspectKeyCustodyDoesNotCreateAnything(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "protected-record")
	_, getenv := stubHelper(t, recordPath)
	ctx := context.Background()

	posture := InspectKeyCustody(ctx, dir, getenv)
	if !posture.Available || posture.Present {
		t.Fatalf("a reachable, empty protector = %+v", posture)
	}
	if !strings.Contains(posture.Detail, "first startup") {
		t.Fatalf("detail = %q", posture.Detail)
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatal("the probe created the data key")
	}
	if _, err := os.Stat(filepath.Join(dir, CustodyFile)); !os.IsNotExist(err) {
		t.Fatal("the probe wrote a custody locator")
	}

	if _, err := Open(dir, getenv, Options{}); err != nil {
		t.Fatal(err)
	}
	posture = InspectKeyCustody(ctx, dir, getenv)
	if !posture.Available || !posture.Present || posture.Label == "" {
		t.Fatalf("after first start = %+v", posture)
	}
}

// TestPostureNamesTheProtector: "encrypted" alone does not tell an operator
// what must be unlocked for the gateway to come back after a reboot.
func TestPostureNamesTheProtector(t *testing.T) {
	if got := DescribeStore(KindEncryptedFile, custody.KindKeychain); !strings.Contains(got, "macOS Keychain") {
		t.Fatalf("DescribeStore = %q", got)
	}
	if got := DescribeStore(KindEncryptedFile, custody.KindFile); got != Describe(KindEncryptedFile) {
		t.Fatalf("the key-file posture changed wording: %q", got)
	}
	if got := DescribeStore(KindVault, ""); got != Describe(KindVault) {
		t.Fatalf("DescribeStore(vault) = %q", got)
	}
	if got := CustodyLabel(custody.KindFile); !strings.Contains(got, FileKeyEnv) {
		t.Fatalf("the key-file label does not name its setting: %q", got)
	}
}

func TestParseDataKeyAcceptsRawAndBase64(t *testing.T) {
	key := make([]byte, 32)
	key[31] = 9
	for _, in := range [][]byte{
		key,
		[]byte(base64.StdEncoding.EncodeToString(key)),
		[]byte(base64.RawStdEncoding.EncodeToString(key) + "\n"),
	} {
		got, err := parseDataKey(in)
		if err != nil || string(got) != string(key) {
			t.Fatalf("parseDataKey(%q) err=%v", in, err)
		}
	}
	if _, err := parseDataKey([]byte("short")); err == nil {
		t.Fatal("a short key was accepted")
	}
}
