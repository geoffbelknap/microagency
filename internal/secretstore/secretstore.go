// Package secretstore persists the small secrets microagency *acquires* — OAuth
// refresh-token records for aggregated upstreams — in OpenBao/Vault (KV v2) when
// configured, otherwise in a local file. The local file is encrypted whenever a
// data-key protector supplies its key: an OS keyring, an operator helper
// fronting a KMS, or a key file the operator places. Without one it is an
// explicitly degraded, mode-0600 plaintext fallback. When a vault is present
// microagency holds no durable secret itself; it reads the refresh token only to
// mint a fresh access token. (This is the write side; microagent's secret
// resolver is the read side for operator-placed `vault:` refs.)
package secretstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"microagency/internal/custody"
)

const (
	// FileKeyEnv names the operator-supplied key-file setting for the encrypted
	// fallback. The key file must live outside microagency's state directory so
	// copying that directory alone never copies both ciphertext and key.
	FileKeyEnv = "MICROAGENCY_SECRET_KEY_FILE"

	// AllowPlaintextEnv opts in to the unencrypted mode-0600 fallback for
	// deployments that start the gateway from a unit file rather than a
	// terminal. `up --allow-plaintext-credentials` is the flag form.
	AllowPlaintextEnv = "MICROAGENCY_ALLOW_PLAINTEXT_CREDENTIALS"

	fileFormat = "microagency-secretstore-v1"
	fileCipher = "AES-256-GCM"

	// storeFileName is the file fallback's name under the state directory.
	storeFileName = "upstream-tokens.json"
)

// StorePath is where the file fallback lives under a state directory.
func StorePath(stateDir string) string { return filepath.Join(stateDir, storeFileName) }

// ErrNotFound is returned by Load when the key is absent.
var ErrNotFound = errors.New("secretstore: not found")

// ErrKeyRequired means an encrypted fallback exists but no decryption key was
// configured. It is deliberately distinct from ErrNotFound: startup must not
// silently replace an encrypted posture with plaintext after a restart.
var ErrKeyRequired = errors.New("secretstore: encrypted file exists but no key is configured")

// ErrPlaintextNotAllowed means resolution landed on the unencrypted fallback
// and the operator did not opt in. Storing upstream credentials in the clear is
// a downgrade, not a default, so it is a decision an operator makes out loud
// rather than one a failed vault makes for them.
var ErrPlaintextNotAllowed = errors.New("secretstore: the unencrypted credential fallback requires an explicit operator opt-in")

// Store kinds, as returned by Store.Kind.
const (
	KindVault         = "vault"
	KindEncryptedFile = "encrypted-file"
	KindFile          = "file"
)

// Options control how Open resolves the store.
type Options struct {
	// AllowPlaintext permits the unencrypted mode-0600 fallback. A caller that
	// will PERSIST credentials sets it only on an explicit operator opt-in;
	// without it Open returns ErrPlaintextNotAllowed rather than writing
	// upstream credentials to disk in the clear. The encrypted file store is
	// not a downgrade and needs no opt-in.
	AllowPlaintext bool
	// Client overrides the HTTP client used for a Vault/OpenBao store.
	Client *http.Client
}

// Describe returns the operator-facing phrase for a store kind.
func Describe(kind string) string {
	switch kind {
	case KindVault:
		return "OpenBao/Vault"
	case KindEncryptedFile:
		return "AES-256-GCM file store with a separately supplied key"
	case KindFile:
		return "unencrypted mode-0600 file in the state directory"
	default:
		return "unknown credential store"
	}
}

// DescribeStore is Describe, naming the data-key protector when one supplies
// the key. "Encrypted" is only half the answer an operator needs: the other
// half is what has to be available and unlocked for the store to open at all.
func DescribeStore(kind, keyCustody string) string {
	if kind != KindEncryptedFile || keyCustody == "" || keyCustody == custody.KindFile {
		return Describe(kind)
	}
	return "AES-256-GCM file store (data key: " + custody.Label(keyCustody) + ")"
}

// Store persists secret blobs by key.
type Store interface {
	Save(ctx context.Context, key string, value []byte) error
	Load(ctx context.Context, key string) ([]byte, error) // ErrNotFound if absent
	Delete(ctx context.Context, key string) error
	Kind() string // "vault" | "encrypted-file" | "file"
}

// Open returns a Vault-backed store when VAULT_ADDR + VAULT_TOKEN are set (the
// preferred path). Otherwise it opens the file fallback, encrypting it whenever
// a data-key protector supplies the AES-256-GCM key: an OS keyring, an operator
// helper fronting a KMS, or MICROAGENCY_SECRET_KEY_FILE. Existing plaintext
// fallback state is migrated atomically when encryption is enabled. Landing on
// the unencrypted fallback requires opts.AllowPlaintext.
//
// A protector that is configured and cannot supply the key fails the open. It
// never degrades to another store: creating a second credential store beside
// one the operator believes is authoritative is the failure that goes unnoticed
// precisely because everything keeps working.
func Open(dir string, getenv func(string) string, opts Options) (Store, error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	addr, tok := strings.TrimSpace(getenv("VAULT_ADDR")), strings.TrimSpace(getenv("VAULT_TOKEN"))
	if (addr == "") != (tok == "") {
		return nil, errors.New("secretstore: VAULT_ADDR and VAULT_TOKEN must be configured together")
	}
	if addr != "" {
		mount := getenv("VAULT_MOUNT")
		if mount == "" {
			mount = "secret" // OpenBao/Vault dev default KV v2 mount
		}
		return &Vault{Addr: addr, Token: tok, Mount: mount, Prefix: "microagency", Client: client}, nil
	}
	path := StorePath(dir)
	if err := protectExistingFile(path); err != nil {
		return nil, err
	}
	src, err := resolveKeySource(dir, getenv)
	if err != nil {
		return nil, err
	}
	if src != nil {
		ctx, cancel := context.WithTimeout(context.Background(), dataKeyTimeout)
		defer cancel()
		key, err := src.dataKey(ctx, path)
		if err != nil {
			return nil, err
		}
		f, err := NewEncryptedFile(path, key)
		if err != nil {
			return nil, err
		}
		f.keyCustody = src.manifest.Kind
		return f, nil
	}
	f := &File{Path: path}
	// Validate existing state now, rather than discovering after startup that an
	// encrypted store cannot be opened because its key setting disappeared. This
	// runs before the opt-in gate so a store that is actually encrypted reports
	// the missing key, never the coarser "you did not opt in to plaintext".
	if _, _, err := f.read(); err != nil {
		return nil, err
	}
	if !opts.AllowPlaintext {
		return nil, ErrPlaintextNotAllowed
	}
	return f, nil
}

// --- Vault / OpenBao (KV v2) ---

type Vault struct {
	Addr, Token, Mount, Prefix string
	Client                     *http.Client
}

func (v *Vault) Kind() string { return "vault" }

func (v *Vault) dataURL(key string) string {
	return strings.TrimRight(v.Addr, "/") + "/v1/" + v.Mount + "/data/" + v.Prefix + "/" + key
}
func (v *Vault) metaURL(key string) string {
	return strings.TrimRight(v.Addr, "/") + "/v1/" + v.Mount + "/metadata/" + v.Prefix + "/" + key
}

func (v *Vault) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return v.Client.Do(req)
}

func (v *Vault) Save(ctx context.Context, key string, value []byte) error {
	body, _ := json.Marshal(map[string]any{"data": map[string]string{"v": string(value)}})
	resp, err := v.do(ctx, http.MethodPost, v.dataURL(key), body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("vault save %q: http %d: %s", key, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (v *Vault) Load(ctx context.Context, key string) ([]byte, error) {
	resp, err := v.do(ctx, http.MethodGet, v.dataURL(key), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("vault load %q: http %d: %s", key, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Data struct {
			Data struct {
				V string `json:"v"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Data.Data.V == "" {
		return nil, ErrNotFound
	}
	return []byte(out.Data.Data.V), nil
}

func (v *Vault) Delete(ctx context.Context, key string) error {
	resp, err := v.do(ctx, http.MethodDelete, v.metaURL(key), nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// --- File fallback ---

type fileEnvelope struct {
	Format     string `json:"format"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type File struct {
	Path string

	mu         sync.Mutex
	aead       cipher.AEAD
	keyCustody string                     // protector kind supplying the data key
	renameFn   func(string, string) error // test seam for interrupted atomic writes
}

func (f *File) Kind() string {
	if f.aead != nil {
		return "encrypted-file"
	}
	return "file"
}

// KeyCustody names the protector supplying an encrypted store's data key
// ("file", "keychain", "secret-service", "command"), or "" when the store is
// not encrypted. Reporting the store kind alone would tell an operator their
// credentials are encrypted without saying what they must keep available to
// read them back.
func (f *File) KeyCustody() string {
	if f.aead == nil {
		return ""
	}
	return f.keyCustody
}

// NewEncryptedFile opens an AES-256-GCM file store. If path contains the legacy
// plaintext JSON map, it is encrypted to a sibling temporary file and atomically
// renamed over the original before this function returns.
func NewEncryptedFile(path string, key []byte) (*File, error) {
	aead, err := newFileAEAD(key)
	if err != nil {
		return nil, err
	}
	if err := protectExistingFile(path); err != nil {
		return nil, err
	}
	f := &File{Path: path, aead: aead}
	m, legacy, err := f.read()
	if err != nil {
		return nil, err
	}
	if legacy {
		if err := f.write(m); err != nil {
			return nil, fmt.Errorf("secretstore: migrate plaintext fallback: %w", err)
		}
	}
	return f, nil
}

func newFileAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretstore: encrypted file key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretstore: encrypted file key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretstore: encrypted file cipher: %w", err)
	}
	return aead, nil
}

// InspectFile reports "absent", "file", or "encrypted-file" without modifying
// path. When an encrypted file exists, key must decrypt it successfully. This is
// the read-only posture probe used by doctor; it never returns stored values.
func InspectFile(path string, key []byte) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", fmt.Errorf("secretstore: inspect fallback file: %w", err)
	}
	if len(b) == 0 {
		return "file", nil
	}
	var marker struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(b, &marker); err != nil {
		return "", fmt.Errorf("secretstore: inspect fallback file: %w", err)
	}
	if marker.Format == "" {
		var legacy map[string]string
		if err := json.Unmarshal(b, &legacy); err != nil {
			return "", fmt.Errorf("secretstore: inspect fallback file: %w", err)
		}
		return "file", nil
	}
	if len(key) == 0 {
		return "encrypted-file", ErrKeyRequired
	}
	aead, err := newFileAEAD(key)
	if err != nil {
		return "encrypted-file", err
	}
	f := &File{Path: path, aead: aead}
	if _, legacy, err := f.read(); err != nil {
		return "encrypted-file", err
	} else if legacy {
		return "file", nil
	}
	return "encrypted-file", nil
}

func protectExistingFile(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("secretstore: inspect fallback file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("secretstore: fallback path must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secretstore: protect fallback file: %w", err)
		}
	}
	return nil
}

// LoadFileKey validates and reads the operator-held key for the encrypted file
// fallback. The key may be 32 raw bytes or base64 text encoding 32 bytes. It must
// be a mode-0600-or-stronger regular file outside stateDir.
func LoadFileKey(stateDir, path string) ([]byte, error) {
	if insidePath(stateDir, path) {
		return nil, fmt.Errorf("secretstore: %s must point outside the microagency state directory", FileKeyEnv)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secretstore: read %s: %w", FileKeyEnv, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secretstore: %s must name a regular file", FileKeyEnv)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secretstore: %s permissions %04o are too broad; require 0600 or stronger", FileKeyEnv, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secretstore: read %s: %w", FileKeyEnv, err)
	}
	key, err := parseDataKey(b)
	if err != nil {
		return nil, fmt.Errorf("secretstore: %s must contain 32 raw bytes or their base64 encoding", FileKeyEnv)
	}
	return key, nil
}

func insidePath(stateDir, path string) bool {
	base, err1 := filepath.Abs(stateDir)
	target, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return true // fail closed when containment cannot be established
	}
	if pathWithin(base, target) {
		return true
	}
	// Resolve symlinks when both paths exist. This also rejects a key whose
	// apparent location is outside the state directory but whose target is in it.
	resolvedBase, baseErr := filepath.EvalSymlinks(base)
	resolvedTarget, targetErr := filepath.EvalSymlinks(target)
	return baseErr == nil && targetErr == nil && pathWithin(resolvedBase, resolvedTarget)
}

func pathWithin(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return true
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// read returns legacy=true only when an encrypted File read a plaintext map that
// must be migrated. An unencrypted File refuses an encrypted envelope so losing
// the key configuration can never silently downgrade the existing store.
func (f *File) read() (m map[string]string, legacy bool, err error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(b) == 0 {
		return map[string]string{}, false, nil
	}

	var marker struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(b, &marker); err != nil {
		return nil, false, err
	}
	if marker.Format != "" {
		if f.aead == nil {
			return nil, false, ErrKeyRequired
		}
		var env fileEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			return nil, false, err
		}
		if env.Format != fileFormat || env.Cipher != fileCipher {
			return nil, false, fmt.Errorf("secretstore: unsupported encrypted file format %q cipher %q", env.Format, env.Cipher)
		}
		nonce, err := base64.RawStdEncoding.DecodeString(env.Nonce)
		if err != nil || len(nonce) != f.aead.NonceSize() {
			return nil, false, errors.New("secretstore: invalid encrypted file nonce")
		}
		ct, err := base64.RawStdEncoding.DecodeString(env.Ciphertext)
		if err != nil {
			return nil, false, errors.New("secretstore: invalid encrypted file ciphertext")
		}
		plaintext, err := f.aead.Open(nil, nonce, ct, []byte(fileFormat))
		if err != nil {
			return nil, false, errors.New("secretstore: decrypt encrypted file: wrong key or corrupted data")
		}
		m := map[string]string{}
		if err := json.Unmarshal(plaintext, &m); err != nil {
			return nil, false, fmt.Errorf("secretstore: decode encrypted file: %w", err)
		}
		return m, false, nil
	}

	m = map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false, err
	}
	return m, f.aead != nil, nil
}

func (f *File) write(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if f.aead != nil {
		nonce := make([]byte, f.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		env := fileEnvelope{
			Format: fileFormat,
			Cipher: fileCipher,
			Nonce:  base64.RawStdEncoding.EncodeToString(nonce),
			Ciphertext: base64.RawStdEncoding.EncodeToString(
				f.aead.Seal(nil, nonce, b, []byte(fileFormat))),
		}
		b, err = json.Marshal(env)
		if err != nil {
			return err
		}
	}
	return f.atomicWrite(b)
}

func (f *File) atomicWrite(b []byte) error {
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, filepath.Base(f.Path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	rename := os.Rename
	if f.renameFn != nil {
		rename = f.renameFn
	}
	if err := rename(tmpName, f.Path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (f *File) Save(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, _, err := f.read()
	if err != nil {
		return err
	}
	m[key] = string(value)
	return f.write(m)
}

func (f *File) Load(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, _, err := f.read()
	if err != nil {
		return nil, err
	}
	v, ok := m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return []byte(v), nil
}

func (f *File) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, _, err := f.read()
	if err != nil {
		return err
	}
	delete(m, key)
	return f.write(m)
}
