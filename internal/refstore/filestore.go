package refstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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


	mu  sync.Mutex
	seq int
	now func() time.Time // injectable for tests
}

// NewFileStore opens (creating if needed) a 0700 directory-backed store encrypted
// with key (must be 16/24/32 bytes; 32 → AES-256). ttl<=0 disables expiry;
// maxEntries<=0 disables the cap. It resumes the ref sequence from existing files so
// handles minted after a restart never collide with persisted ones.
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
	fs := &FileStore{dir: dir, aead: aead, ttl: ttl, maxEntries: maxEntries, now: time.Now}
	fs.mu.Lock()
	fs.seq = fs.maxSeqLocked()
	fs.mu.Unlock()
	return fs, nil
}

func (s *FileStore) Put(payload string) (Ref, Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	ref := Ref(fmt.Sprintf("<ref_%d>", s.seq))
	if name, ok := safeRefFile(ref); ok {
		_ = s.writeLocked(name, payload)
	}
	s.sweepLocked() // after the write, so the cap counts the new entry (never evicts it — it's newest)
	return ref, Summary{Bytes: len(payload)}
}

func (s *FileStore) Get(ref Ref) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := safeRefFile(ref)
	if !ok {
		return "", false
	}
	path := filepath.Join(s.dir, name)
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8+s.aead.NonceSize() {
		return "", false
	}
	created := int64(binary.BigEndian.Uint64(data[:8]))
	if s.ttl > 0 && s.now().UnixNano()-created > int64(s.ttl) {
		_ = os.Remove(path) // expired — drop it
		return "", false
	}
	nonce := data[8 : 8+s.aead.NonceSize()]
	pt, err := s.aead.Open(nil, nonce, data[8+s.aead.NonceSize():], nil)
	if err != nil {
		return "", false // tampered / wrong key
	}
	return string(pt), true
}

// writeLocked encrypts payload and writes it 0600 as: created(8, big-endian unixnano)
// || nonce || ciphertext. created is cleartext (not sensitive) so TTL can be checked
// without decrypting.
func (s *FileStore) writeLocked(name, payload string) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, []byte(payload), nil)
	buf := make([]byte, 8+len(nonce)+len(ct))
	binary.BigEndian.PutUint64(buf[:8], uint64(s.now().UnixNano()))
	copy(buf[8:], nonce)
	copy(buf[8+len(nonce):], ct)
	return os.WriteFile(filepath.Join(s.dir, name), buf, 0o600)
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

// maxSeqLocked returns the highest ref number persisted, so Put resumes from there.
func (s *FileStore) maxSeqLocked() int {
	entries, _ := os.ReadDir(s.dir)
	max := 0
	for _, e := range entries {
		if n, ok := seqOfFile(e.Name()); ok && n > max {
			max = n
		}
	}
	return max
}

// safeRefFile maps a "<ref_N>" handle to its "ref_N.enc" filename, rejecting any
// other shape — so a caller-supplied ref can never escape the store directory.
func safeRefFile(ref Ref) (string, bool) {
	s := string(ref)
	if !strings.HasPrefix(s, "<ref_") || !strings.HasSuffix(s, ">") {
		return "", false
	}
	num := s[len("<ref_") : len(s)-1]
	if num == "" {
		return "", false
	}
	if _, err := strconv.Atoi(num); err != nil {
		return "", false
	}
	return "ref_" + num + ".enc", true
}

func seqOfFile(name string) (int, bool) {
	if !strings.HasPrefix(name, "ref_") || !strings.HasSuffix(name, ".enc") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "ref_"), ".enc"))
	if err != nil {
		return 0, false
	}
	return n, true
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
