package refstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileStore is a persisted, ENCRYPTED-at-rest Store: reffed payloads survive a
// restart, so <ref_> handles (and reduce / GET /admin/refs/{ref}) keep working
// across `microagency down`/`up`. A ref holds the RAW data reference-by-default
// exists to keep out of context (often PII), so persistence is a new at-rest
// liability handled two ways: every payload is AES-256-GCM encrypted with an
// operator-held key, and retention is BOUNDED (ASK tenet 8) — a TTL plus a
// max-entry cap, swept lazily on write. Safe for concurrent use.
type FileStore struct {
	dir        string
	aead       cipher.AEAD
	ttl        time.Duration
	maxEntries int

	mu    sync.Mutex
	now   func() time.Time // injectable for tests
	newID func() Ref       // injectable for tests; defaults to randRef
}

// NewFileStore opens (creating if needed) a 0700 directory-backed store encrypted
// with key (must be 16/24/32 bytes; 32 → AES-256). ttl<=0 disables expiry;
// maxEntries<=0 disables the cap. Handles are random, so nothing needs to resume
// from disk — a fresh handle can't collide with a persisted one.
func NewFileStore(dir string, key []byte, ttl time.Duration, maxEntries int) (*FileStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("refstore: key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir, aead: aead, ttl: ttl, maxEntries: maxEntries, now: time.Now, newID: randRef}, nil
}

func (s *FileStore) Put(payload, owner string) (Ref, Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, name := s.mintLocked()
	if name != "" {
		if err := s.writeLocked(name, owner, payload); err != nil {
			// Put's signature can't return this, but a silent failure hands back a
			// live-looking ref whose Get later fails with "unknown reference" — a
			// confusing failure at a distance. Surface it here, at the source.
			slog.Error("persist ref failed", "ref", ref, "err", err)
		}
	}
	s.sweepLocked() // after the write, so the cap counts the new entry (never evicts it — it's newest)
	return ref, Summary{Bytes: len(payload)}
}

// mintLocked returns a fresh handle whose backing file doesn't already exist, so a
// repeated id source (a deterministic test generator) can't overwrite a stored ref.
func (s *FileStore) mintLocked() (Ref, string) {
	for {
		ref := s.newID()
		name, ok := safeRefFile(ref)
		if !ok {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.dir, name)); os.IsNotExist(err) {
			return ref, name
		}
	}
}

func (s *FileStore) Get(ref Ref) (string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := safeRefFile(ref)
	if !ok {
		return "", "", false
	}
	path := filepath.Join(s.dir, name)
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8+s.aead.NonceSize() {
		return "", "", false
	}
	created := int64(binary.BigEndian.Uint64(data[:8]))
	if s.ttl > 0 && s.now().UnixNano()-created > int64(s.ttl) {
		_ = os.Remove(path) // expired — drop it
		return "", "", false
	}
	nonce := data[8 : 8+s.aead.NonceSize()]
	pt, err := s.aead.Open(nil, nonce, data[8+s.aead.NonceSize():], nil)
	if err != nil {
		return "", "", false // tampered / wrong key
	}
	owner, payload, ok := unframeOwner(pt)
	if !ok {
		return "", "", false // unframed (e.g. a pre-owner record) — treat as absent
	}
	return payload, owner, true
}

// writeLocked encrypts the owner-framed payload and writes it 0600 as: created(8,
// big-endian unixnano) || nonce || ciphertext. created is cleartext (not sensitive)
// so TTL can be checked without decrypting; the owner is INSIDE the ciphertext, so
// file access alone doesn't reveal who owns each ref.
func (s *FileStore) writeLocked(name, owner, payload string) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, frameOwner(owner, payload), nil)
	buf := make([]byte, 8+len(nonce)+len(ct))
	binary.BigEndian.PutUint64(buf[:8], uint64(s.now().UnixNano()))
	copy(buf[8:], nonce)
	copy(buf[8+len(nonce):], ct)
	return os.WriteFile(filepath.Join(s.dir, name), buf, 0o600)
}

// frameOwner prefixes the plaintext with a 2-byte big-endian owner length + the
// owner bytes, so Get can split the creating subject back out from the payload.
// Owner subjects are short identifiers, well within 2 bytes.
func frameOwner(owner, payload string) []byte {
	if len(owner) > 0xffff {
		owner = owner[:0xffff]
	}
	buf := make([]byte, 2+len(owner)+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(owner)))
	copy(buf[2:], owner)
	copy(buf[2+len(owner):], payload)
	return buf
}

func unframeOwner(pt []byte) (owner, payload string, ok bool) {
	if len(pt) < 2 {
		return "", "", false
	}
	n := int(binary.BigEndian.Uint16(pt[:2]))
	if 2+n > len(pt) {
		return "", "", false
	}
	return string(pt[2 : 2+n]), string(pt[2+n:]), true
}

// sweepLocked drops expired entries and, if over the cap, the oldest — bounding
// retention (ASK tenet 8).
func (s *FileStore) sweepLocked() {
	if s.ttl <= 0 && s.maxEntries <= 0 {
		return
	}
	entries, _ := os.ReadDir(s.dir)
	type item struct {
		name    string
		created int64
	}
	var live []item
	now := s.now().UnixNano()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		created, ok := readCreated(path)
		if !ok {
			continue
		}
		if s.ttl > 0 && now-created > int64(s.ttl) {
			_ = os.Remove(path)
			continue
		}
		live = append(live, item{e.Name(), created})
	}
	if s.maxEntries > 0 && len(live) > s.maxEntries {
		sort.Slice(live, func(i, j int) bool { return live[i].created < live[j].created })
		for _, it := range live[:len(live)-s.maxEntries] {
			_ = os.Remove(filepath.Join(s.dir, it.name))
		}
	}
}

// safeRefFile maps a "<ref_TOKEN>" handle to its "ref_TOKEN.enc" filename via the
// shared base62 validator, rejecting any other shape — so a caller-supplied ref
// can never carry a path separator or ".." and escape the store directory.
func safeRefFile(ref Ref) (string, bool) {
	tok, ok := refToken(ref)
	if !ok {
		return "", false
	}
	return "ref_" + tok + ".enc", true
}

func readCreated(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	var b [8]byte
	if _, err := f.Read(b[:]); err != nil {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(b[:])), true
}
