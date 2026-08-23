package secretstore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"microagency/internal/custody"
)

const (
	// ProtectorEnv selects who holds the encrypted file store's AES-256-GCM data
	// key: `keychain`, `secret-service`, `command` (an operator helper, typically
	// fronting a KMS), or `file` — which is MICROAGENCY_SECRET_KEY_FILE by
	// another name. Empty keeps the key-file behavior exactly as it was.
	ProtectorEnv = "MICROAGENCY_SECRET_PROTECTOR"
	// ProtectorCommandEnv names the absolute helper the `command` protector runs.
	ProtectorCommandEnv = "MICROAGENCY_SECRET_PROTECTOR_COMMAND"

	// CustodyFile is the non-secret locator naming the protector that holds the
	// data key. It records no key material — only which protector to ask.
	CustodyFile = "credential-key-custody.json"

	keyCustodyFormat = "microagency-secretstore-custody-v1"

	// dataKeyTimeout bounds one protector round-trip. A keyring waiting on an
	// unlock prompt that never comes, or a helper wedged against an unreachable
	// KMS, would otherwise hang startup with no output at all — which is a worse
	// failure than refusing, because nothing tells the operator to go look.
	dataKeyTimeout = 30 * time.Second
)

// ErrProtectorUnavailable means a data-key protector was selected and could not
// supply the key. It never permits another store: falling back would create a
// second credential store beside one the operator believes is authoritative,
// which is the silent downgrade the explicit plaintext gate exists to prevent.
var ErrProtectorUnavailable = errors.New("secretstore: the configured data-key protector is unavailable")

// ErrCustodyConflict means a key file and a protector are both configured and
// do not hold the same data key. Startup refuses rather than picking one: the
// store opens under exactly one key, and guessing wrong reads as corruption.
var ErrCustodyConflict = errors.New("secretstore: the configured data-key custody settings disagree")

// keyRecords describes where this state directory's data-key locator lives and
// which keyring identifiers its record uses. The format tag, Keychain service,
// and Secret Service attribute are a compatibility surface: changing one
// orphans every existing record.
func keyRecords(stateDir string) custody.Records {
	return custody.Records{
		Path:       filepath.Join(stateDir, CustodyFile),
		Format:     keyCustodyFormat,
		Noun:       "credential-store key custody",
		KindEnv:    ProtectorEnv,
		CommandEnv: ProtectorCommandEnv,
		Purpose: custody.Purpose{
			KeychainService: "microagency.secretstore",
			Attribute:       "secretstore-data-key",
			Label:           "microagency credential store data key",
		},
	}
}

// keyFileProtector is the `file` protector: the operator's own key file, named
// by MICROAGENCY_SECRET_KEY_FILE. It is a protector in the same sense as the
// others — it answers "give me the data key" — but the operator, not
// microagency, decides that file exists.
type keyFileProtector struct {
	stateDir, path string
}

func (p *keyFileProtector) Kind() string    { return custody.KindFile }
func (p *keyFileProtector) Protected() bool { return false }

// Load deliberately never reports custody.ErrNotFound. A missing key file is an
// operator-visible misconfiguration with its own message, not an invitation to
// mint a key: microagency has never created this file and must not start.
//
// It returns the same encoded record every other protector returns, so custody
// transfers compare like with like. A key file may hold raw bytes or base64;
// what leaves a protector is always the canonical encoding.
func (p *keyFileProtector) Load(context.Context) ([]byte, error) {
	if p.path == "" {
		return nil, fmt.Errorf("secretstore: %s=file requires %s to name the key file", ProtectorEnv, FileKeyEnv)
	}
	key, err := LoadFileKey(p.stateDir, p.path)
	if err != nil {
		return nil, err
	}
	return encodeDataKey(key), nil
}

// Save writes the key file only when it is absent or already holds this key.
// Overwriting a key file that holds something else would destroy the operator's
// only copy of a key some other store may still be encrypted under.
func (p *keyFileProtector) Save(_ context.Context, record []byte) error {
	if p.path == "" {
		return fmt.Errorf("secretstore: %s must name the key file to write", FileKeyEnv)
	}
	key, err := parseDataKey(record)
	if err != nil {
		return fmt.Errorf("secretstore: %s: %w", FileKeyEnv, err)
	}
	if insidePath(p.stateDir, p.path) {
		return fmt.Errorf("secretstore: %s must point outside the microagency state directory", FileKeyEnv)
	}
	if existing, err := LoadFileKey(p.stateDir, p.path); err == nil {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil
		}
		return fmt.Errorf("secretstore: %s already holds a different key; move it aside before migrating custody to it", p.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return custody.WriteAtomic(p.path, append(encodeDataKey(key), '\n'), 0o600)
}

// Delete leaves the operator's key file in place. It is the documented backup
// for an encrypted store, microagency did not create it, and removing it would
// make a custody migration irreversible at the moment it is least proven.
func (p *keyFileProtector) Delete(context.Context) error { return nil }

// keySource is the resolved answer to "who supplies this store's data key".
type keySource struct {
	records   custody.Records
	manifest  custody.Manifest
	protector custody.Protector
	stateDir  string
	keyFile   string
}

func (s *keySource) label() string { return CustodyLabel(s.manifest.Kind) }

// CustodyLabel names a data-key protector for operators. The file posture gets
// its own phrase: unlike material that sits beside what it protects, this key
// file is required to live outside the state directory, so calling it
// "same-disk" would describe the opposite of what it is.
func CustodyLabel(kind string) string {
	if kind == custody.KindFile {
		return "key file at $" + FileKeyEnv
	}
	return custody.Label(kind)
}

// resolveKeySource decides which protector supplies the data key. It returns
// (nil, nil) when nothing selects one, which leaves the plaintext gate to
// decide — the behavior of every deployment that configures neither setting.
func resolveKeySource(stateDir string, getenv func(string) string) (*keySource, error) {
	records := keyRecords(stateDir)
	keyFile := strings.TrimSpace(getenv(FileKeyEnv))
	envKind := strings.TrimSpace(getenv(ProtectorEnv))

	manifest, err := records.LoadManifest()
	switch {
	case err == nil:
		// A recorded locator is the authority: it says who actually holds the
		// key. The environment may agree with it, but a disagreement is the
		// operator having moved custody in one place and not the other.
		if envKind != "" {
			kind, kindErr := custody.CanonicalKind(envKind, ProtectorEnv)
			if kindErr != nil {
				return nil, kindErr
			}
			if kind != manifest.Kind {
				return nil, fmt.Errorf("%w: %s=%s but the recorded data-key custody is %s; run `microagency secret-store migrate --to %s` to move it, or restore the setting",
					ErrCustodyConflict, ProtectorEnv, kind, manifest.Kind, kind)
			}
		}
	case os.IsNotExist(err):
		if envKind == "" && keyFile == "" {
			return nil, nil // no data key configured; the plaintext gate decides
		}
		kind, kindErr := custody.CanonicalKind(envKind, ProtectorEnv)
		if kindErr != nil {
			return nil, kindErr
		}
		if kind == custody.KindFile && keyFile == "" {
			return nil, fmt.Errorf("secretstore: %s=file requires %s to name the key file", ProtectorEnv, FileKeyEnv)
		}
		manifest = custody.Manifest{Format: keyCustodyFormat, Kind: kind, ID: custody.ID(stateDir)}
		if kind == custody.KindCommand {
			manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
		}
	default:
		// A locator that exists but cannot be read names a protector we can no
		// longer identify. Guessing `file` would look for a key that may not
		// exist; guessing a keyring would mint a second one over live
		// ciphertext. Neither is recoverable, so refuse and keep the file.
		return nil, fmt.Errorf("%w: %v", ErrProtectorUnavailable, err)
	}

	p, err := records.New(manifest, getenv, &keyFileProtector{stateDir: stateDir, path: keyFile})
	if err != nil {
		if manifest.Protected() {
			return nil, fmt.Errorf("%w: %s: %v", ErrProtectorUnavailable, custody.Label(manifest.Kind), err)
		}
		return nil, err
	}
	return &keySource{records: records, manifest: manifest, protector: p, stateDir: stateDir, keyFile: keyFile}, nil
}

// dataKey returns the store's data key, creating one on first use. storePath is
// consulted only to refuse minting a key over ciphertext that key cannot open.
func (s *keySource) dataKey(ctx context.Context, storePath string) ([]byte, error) {
	record, err := s.protector.Load(ctx)
	switch {
	case err == nil:
		key, decErr := parseDataKey(record)
		if decErr != nil {
			if !s.protector.Protected() {
				return nil, decErr
			}
			return nil, fmt.Errorf("%w: %s holds an unusable data key: %v", ErrProtectorUnavailable, s.label(), decErr)
		}
		if err := s.reconcile(key); err != nil {
			return nil, err
		}
		return key, nil
	case errors.Is(err, custody.ErrNotFound):
		return s.create(ctx, storePath)
	default:
		if !s.protector.Protected() {
			// The key file's own error already names the setting and the fix.
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrProtectorUnavailable, s.label(), err)
	}
}

// reconcile refuses to start when a protector and a key file are both
// configured and hold different keys. Equal keys are not a conflict: that is
// simply a migration whose old setting is still exported.
func (s *keySource) reconcile(key []byte) error {
	if !s.protector.Protected() || s.keyFile == "" {
		return nil
	}
	fileKey, err := LoadFileKey(s.stateDir, s.keyFile)
	if err != nil {
		return fmt.Errorf("%w: %s supplies the data key but %s is also set and cannot be read (%v); unset whichever no longer applies",
			ErrCustodyConflict, s.label(), FileKeyEnv, err)
	}
	if subtle.ConstantTimeCompare(fileKey, key) != 1 {
		return fmt.Errorf("%w: %s and %s hold different data keys; unset whichever is stale rather than letting startup guess which one opens the store",
			ErrCustodyConflict, s.label(), FileKeyEnv)
	}
	return nil
}

// create mints the data key on first use.
func (s *keySource) create(ctx context.Context, storePath string) ([]byte, error) {
	// A protector holding nothing must never mint a key over ciphertext that key
	// cannot open: the store would be permanently unreadable, and the failure
	// would read as "wrong key" rather than "your protector lost its record".
	kind, inspectErr := InspectFile(storePath, nil)
	if inspectErr != nil && !errors.Is(inspectErr, ErrKeyRequired) {
		return nil, inspectErr
	}
	if kind == KindEncryptedFile {
		return nil, fmt.Errorf("%w: %s holds no data key but the credential store is already encrypted; restore the protector's record from backup rather than re-keying",
			ErrProtectorUnavailable, s.label())
	}
	if s.keyFile != "" {
		return nil, fmt.Errorf("%w: %s holds no data key and %s is also set; unset one, or run `microagency secret-store migrate --to %s` to move the key file's key under the protector",
			ErrCustodyConflict, s.label(), FileKeyEnv, s.manifest.Kind)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secretstore: generate data key: %w", err)
	}
	if err := custody.SaveVerified(ctx, s.protector, encodeDataKey(key)); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrProtectorUnavailable, s.label(), err)
	}
	// Record the locator only after the protector has proven it can return the
	// key. A locator written first would point at a record that does not exist.
	if err := s.records.SaveManifest(s.manifest); err != nil {
		return nil, fmt.Errorf("secretstore: record data-key custody: %w", err)
	}
	return key, nil
}

// encodeDataKey renders the key for a protector. Keyrings and helpers carry
// text far more reliably than 32 arbitrary bytes, several of which are not
// valid UTF-8 and one of which is NUL.
func encodeDataKey(key []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(key))
}

// parseDataKey accepts 32 raw bytes or their base64 encoding, matching what an
// operator may have put in a key file by hand.
func parseDataKey(b []byte) ([]byte, error) {
	if len(b) == 32 {
		return b, nil
	}
	encoded := strings.TrimSpace(string(b))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if key, err := enc.DecodeString(encoded); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, errors.New("expected 32 raw bytes or their base64 encoding")
}

// KeyCustodyPosture is the non-secret data-key custody state doctor renders. It
// never carries key material.
type KeyCustodyPosture struct {
	// Kind is the protector kind, or "" when nothing selects one.
	Kind string
	// Label is the operator-facing protector name.
	Label string
	// Protected is false for the key-file posture.
	Protected bool
	// Available reports that the protector answered. A protector that could not
	// be reached is never rendered as healthy — the key it holds is unverified,
	// and startup will fail closed.
	Available bool
	// Present reports that the protector holds a data key today.
	Present bool
	// Detail explains Available/Present in the operator's terms.
	Detail string
}

// InspectKeyCustody probes the configured data-key protector read-only. It
// never creates a key, never writes a locator, and never returns key material —
// running it must not change what a later startup would do.
func InspectKeyCustody(ctx context.Context, stateDir string, getenv func(string) string) KeyCustodyPosture {
	src, err := resolveKeySource(stateDir, getenv)
	if err != nil {
		kind, _ := custody.CanonicalKind(getenv(ProtectorEnv), ProtectorEnv)
		if m, mErr := keyRecords(stateDir).LoadManifest(); mErr == nil {
			kind = m.Kind
		}
		return KeyCustodyPosture{Kind: kind, Label: CustodyLabel(kind), Protected: kind != custody.KindFile, Detail: err.Error()}
	}
	if src == nil {
		return KeyCustodyPosture{}
	}
	posture := KeyCustodyPosture{
		Kind:      src.manifest.Kind,
		Label:     src.label(),
		Protected: src.manifest.Protected(),
	}
	storePath := StorePath(stateDir)
	record, err := src.protector.Load(ctx)
	switch {
	case err == nil:
		key, parseErr := parseDataKey(record)
		if parseErr != nil {
			posture.Detail = fmt.Sprintf("the protector holds an unusable data key: %v", parseErr)
			return posture
		}
		if err := src.reconcile(key); err != nil {
			posture.Detail = err.Error()
			return posture
		}
		// Holding a key is not the claim doctor is making. The claim is that the
		// store opens, and a key that does not decrypt the existing ciphertext
		// would pass every check above while failing the only one that matters.
		if _, err := InspectFile(storePath, key); err != nil {
			posture.Detail = err.Error()
			return posture
		}
		posture.Available, posture.Present = true, true
		posture.Detail = "the data key opens the credential store"
	case errors.Is(err, custody.ErrNotFound):
		// The protector answered, so it is reachable; it simply holds nothing yet.
		if kind, _ := InspectFile(storePath, nil); kind == KindEncryptedFile {
			posture.Detail = "the credential store is encrypted but the protector holds no data key; restore its record from backup"
			return posture
		}
		posture.Available = true
		posture.Detail = "the data key will be created on first startup"
	default:
		posture.Detail = err.Error()
	}
	return posture
}

// DeleteKeyCustody removes the out-of-directory data-key record before a full
// purge removes the locator needed to find it. The operator's own key file is
// left alone: microagency did not create it, and it may still be the backup for
// a store copied elsewhere. Every create this package performs has a delete
// that reverses it; this is that delete.
func DeleteKeyCustody(ctx context.Context, stateDir string, getenv func(string) string) error {
	records := keyRecords(stateDir)
	manifest, err := records.LoadManifest()
	if os.IsNotExist(err) {
		kind, kindErr := custody.CanonicalKind(getenv(ProtectorEnv), ProtectorEnv)
		if kindErr != nil || kind == custody.KindFile {
			return kindErr
		}
		manifest = custody.Manifest{Format: keyCustodyFormat, Kind: kind, ID: custody.ID(stateDir)}
		if kind == custody.KindCommand {
			manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
		}
	} else if err != nil {
		return err
	}
	if !manifest.Protected() {
		return nil
	}
	p, err := records.New(manifest, func(name string) string {
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

// MigrateKeyCustody moves the credential store's data key from the protector
// holding it to target, verifying the target before committing. The store's
// ciphertext is never rewritten: the same key simply gains a new custodian, so
// an interrupted migration leaves a store that still opens under the old one.
//
// Moving to the key-file posture requires allowDegraded, because it writes the
// key back onto the same host as a file the operator must then protect.
func MigrateKeyCustody(ctx context.Context, stateDir string, getenv func(string) string, target string, allowDegraded bool) error {
	targetKind, err := custody.CanonicalKind(target, ProtectorEnv)
	if err != nil {
		return err
	}
	keyFile := strings.TrimSpace(getenv(FileKeyEnv))
	if targetKind == custody.KindFile {
		if !allowDegraded {
			return errors.New("refusing to write the credential store's data key back to a key file without --allow-degraded")
		}
		if keyFile == "" {
			return fmt.Errorf("migrating to file custody requires %s to name the destination key file", FileKeyEnv)
		}
	}

	records := keyRecords(stateDir)
	sourceManifest, err := records.LoadManifest()
	if os.IsNotExist(err) {
		// No locator: the key file is what holds the key today. That is the
		// posture every deployment predating protector custody is in.
		if keyFile == "" {
			return fmt.Errorf("no data-key custody to migrate: set %s or %s first", FileKeyEnv, ProtectorEnv)
		}
		sourceManifest = custody.Manifest{Format: keyCustodyFormat, Kind: custody.KindFile, ID: custody.ID(stateDir)}
	} else if err != nil {
		return err
	}

	targetCommand := strings.TrimSpace(getenv(ProtectorCommandEnv))
	newHelper := sourceManifest.Kind == custody.KindCommand && targetKind == custody.KindCommand &&
		targetCommand != "" && filepath.Clean(targetCommand) != filepath.Clean(sourceManifest.Command)
	if sourceManifest.Kind == targetKind && !newHelper {
		return fmt.Errorf("the credential store's data key already uses %s custody", custody.Label(targetKind))
	}

	file := &keyFileProtector{stateDir: stateDir, path: keyFile}
	source, err := records.New(sourceManifest, func(name string) string {
		if name == ProtectorCommandEnv && sourceManifest.Command != "" {
			return sourceManifest.Command
		}
		return getenv(name)
	}, file)
	if err != nil {
		return fmt.Errorf("open current protector: %w", err)
	}
	record, err := source.Load(ctx)
	if err != nil {
		return fmt.Errorf("load the current data key: %w", err)
	}
	key, err := parseDataKey(record)
	if err != nil {
		return fmt.Errorf("the current data key is unusable: %w", err)
	}

	targetManifest := custody.Manifest{Format: keyCustodyFormat, Kind: targetKind, ID: sourceManifest.ID}
	if targetKind == custody.KindCommand {
		targetManifest.Command = targetCommand
	}
	targetProtector, err := records.New(targetManifest, getenv, file)
	if err != nil {
		return fmt.Errorf("open target protector: %w", err)
	}
	commit := func() error {
		if targetKind == custody.KindFile {
			// The key file needs no locator: MICROAGENCY_SECRET_KEY_FILE is the
			// record. Leaving a stale one behind would name a protector that no
			// longer holds the key.
			return records.DeleteManifest()
		}
		return records.SaveManifest(targetManifest)
	}
	if err := custody.Transfer(ctx, encodeDataKey(key), source, targetProtector, commit); err != nil {
		return err
	}
	return nil
}
