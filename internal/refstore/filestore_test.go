package refstore

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A failed ref write must be LOGGED (not swallowed): otherwise Put hands back a
// live-looking handle whose Get later fails with "unknown reference" — a confusing
// failure at a distance.
func TestFileStorePutLogsWriteError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a write-permission failure can't be forced as root")
	}
	dir := filepath.Join(t.TempDir(), "refs")
	fs, err := NewFileStore(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	// Make the store directory read+execute but not writable, so mintLocked can still
	// stat (the ref file is absent → IsNotExist → mint proceeds) but writeLocked's
	// WriteFile fails deterministically.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	ref, _ := fs.Put("payload that can't be written", "")
	if _, _, ok := fs.Get(ref); ok {
		t.Fatal("Get should fail after the write failed")
	}
	if !strings.Contains(buf.String(), "persist ref") {
		t.Fatalf("write failure was not logged: %q", buf.String())
	}
}

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func TestFileStoreRoundTripAndEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "SENSITIVE-mrn-1234-and-a-failed-login-ip-10.0.0.9"
	ref, sum := s.Put(secret, "carol")
	if sum.Bytes != len(secret) {
		t.Fatalf("summary bytes = %d, want %d", sum.Bytes, len(secret))
	}
	got, owner, ok := s.Get(ref)
	if !ok || got != secret {
		t.Fatalf("round-trip failed: %q ok=%v", got, ok)
	}
	if owner != "carol" {
		t.Fatalf("owner did not round-trip: %q, want carol", owner)
	}
	// Nothing on disk may contain the plaintext — it's encrypted at rest.
	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Fatal("nothing persisted")
	}
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if bytes.Contains(b, []byte("SENSITIVE")) || bytes.Contains(b, []byte("10.0.0.9")) {
			t.Fatalf("plaintext found on disk in %s", f.Name())
		}
	}
}

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewFileStore(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := s1.Put("survive the restart", "")

	// Reopen the same dir with the same key — the ref resolves, and new handles
	// don't collide with persisted ones.
	s2, err := NewFileStore(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _, ok := s2.Get(ref)
	if !ok || got != "survive the restart" {
		t.Fatalf("ref did not survive reopen: %q ok=%v", got, ok)
	}
	if ref2, _ := s2.Put("second", ""); ref2 == ref {
		t.Fatalf("ref seq collided across reopen: %s", ref2)
	}
}

func TestFileStoreWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s1, _ := NewFileStore(dir, testKey(), 0, 0)
	ref, _ := s1.Put("secret", "")

	other := make([]byte, 32) // all zeros — different key
	s2, err := NewFileStore(dir, other, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s2.Get(ref); ok {
		t.Fatal("a wrong key must not decrypt the payload")
	}
}

func TestFileStoreTTLExpires(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir, testKey(), time.Hour, 0)
	base := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return base }
	ref, _ := s.Put("temp", "")
	if _, _, ok := s.Get(ref); !ok {
		t.Fatal("should be present within TTL")
	}
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, _, ok := s.Get(ref); ok {
		t.Fatal("should be gone past TTL")
	}
}

func TestFileStoreMaxEntriesEvictsOldest(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir, testKey(), 0, 2)
	base := time.Unix(1_000_000, 0)
	tick := 0
	s.now = func() time.Time { return base.Add(time.Duration(tick) * time.Second) }

	tick = 0
	r1, _ := s.Put("one", "")
	tick = 1
	r2, _ := s.Put("two", "")
	tick = 2
	r3, _ := s.Put("three", "") // cap is 2 → the oldest (r1) is evicted

	if _, _, ok := s.Get(r1); ok {
		t.Fatal("oldest entry should have been evicted at the cap")
	}
	if _, _, ok := s.Get(r2); !ok {
		t.Fatal("r2 should remain")
	}
	if _, _, ok := s.Get(r3); !ok {
		t.Fatal("r3 (newest) should remain")
	}
}

func TestFileStoreRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir, testKey(), 0, 0)
	// base62-only tokens: anything with a path separator, "..", brackets, or an
	// empty token must be rejected by refToken before it can touch the filesystem.
	for _, bad := range []Ref{"<ref_../../etc/passwd>", "../../etc/passwd", "<ref_>", "<ref_a/b>", "<ref_..>", "<ref_a.b>", "ref_abc"} {
		if _, ok := refToken(bad); ok {
			t.Fatalf("malicious/invalid ref %q should be rejected by refToken", bad)
		}
		if _, _, ok := s.Get(bad); ok {
			t.Fatalf("malicious/invalid ref %q should not resolve", bad)
		}
	}
}
