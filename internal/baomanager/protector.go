package baomanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"microagency/internal/custody"
)

const (
	// ProtectorEnv selects custody for the managed OpenBao bootstrap. The empty
	// value retains the compatibility file posture; protected custody is always
	// explicit so a headless host never silently depends on a locked keyring.
	ProtectorEnv = "MICROAGENCY_OPENBAO_PROTECTOR"
	// ProtectorCommandEnv names the absolute helper used by the command
	// protector. The helper protocol is documented in docs/operations.md.
	ProtectorCommandEnv = "MICROAGENCY_OPENBAO_PROTECTOR_COMMAND"

	custodyFormat = "microagency-openbao-custody-v1"
	keychainSvc   = "microagency.openbao"
)

// Local names for the shared custody vocabulary, so the rest of this package
// (and the OpenBao-specific tests) read in OpenBao's terms.
type (
	protector       = custody.Protector
	custodyManifest = custody.Manifest
)

// errBootstrapNotFound is the local name for "the protector holds nothing yet".
var errBootstrapNotFound = custody.ErrNotFound

// ProtectedError marks a managed-store failure that must not fall through to
// another credential store. Once protected custody is selected, an unavailable
// protector is an outage, not permission to create a second store on disk.
type ProtectedError struct{ Err error }

func (e *ProtectedError) Error() string { return "protected OpenBao custody: " + e.Err.Error() }
func (e *ProtectedError) Unwrap() error { return e.Err }

// FailClosed reports whether startup must stop instead of evaluating a local
// credential-store fallback.
func FailClosed(err error) bool {
	var protected *ProtectedError
	return errors.As(err, &protected)
}

// records describes where the managed-OpenBao bootstrap custody locator lives
// and which keyring identifiers its record uses. The format tag, service name,
// and attribute value are a compatibility surface: changing one orphans every
// existing installation's record.
func records(dir string) custody.Records {
	return custody.Records{
		Path:       custodyPath(dir),
		Format:     custodyFormat,
		Noun:       "managed OpenBao custody",
		KindEnv:    ProtectorEnv,
		CommandEnv: ProtectorCommandEnv,
		Purpose: custody.Purpose{
			KeychainService: keychainSvc,
			Attribute:       "openbao-bootstrap",
			Label:           "microagency managed OpenBao bootstrap",
		},
	}
}

type custodySelection struct {
	dir       string
	manifest  custody.Manifest
	protector custody.Protector
}

// fileProtector is the compatibility posture: the bootstrap record sits beside
// OpenBao's data under the state directory.
type fileProtector struct{ dir string }

func (p *fileProtector) Kind() string    { return custody.KindFile }
func (p *fileProtector) Protected() bool { return false }
func (p *fileProtector) Delete(context.Context) error {
	err := os.Remove(bootstrapPath(p.dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (p *fileProtector) Load(context.Context) ([]byte, error) {
	b, err := os.ReadFile(bootstrapPath(p.dir))
	if os.IsNotExist(err) {
		return nil, custody.ErrNotFound
	}
	return b, err
}
func (p *fileProtector) Save(_ context.Context, b []byte) error {
	return custody.WriteAtomic(bootstrapPath(p.dir), b, 0o600)
}

func protectorLabel(kind string) string { return custody.Label(kind) }

func canonicalProtectorKind(raw string) (string, error) {
	return custody.CanonicalKind(raw, ProtectorEnv)
}

func custodyID(dir string) string { return custody.ID(dir) }

func newProtector(dir string, manifest custody.Manifest, getenv func(string) string) (custody.Protector, error) {
	return records(dir).New(manifest, getenv, &fileProtector{dir: dir})
}

func selectCustody(dir string, getenv func(string) string) (custodySelection, error) {
	manifest, err := loadCustodyManifest(dir)
	if err == nil {
		p, perr := newProtector(dir, manifest, getenv)
		return custodySelection{dir: dir, manifest: manifest, protector: p}, perr
	}
	if !os.IsNotExist(err) {
		return custodySelection{}, err
	}
	kind, err := canonicalProtectorKind(getenv(ProtectorEnv))
	if err != nil {
		return custodySelection{}, err
	}
	manifest = custody.Manifest{Format: custodyFormat, Kind: kind, ID: custodyID(dir)}
	if kind == custody.KindCommand {
		manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
	}
	p, err := newProtector(dir, manifest, getenv)
	return custodySelection{dir: dir, manifest: manifest, protector: p}, err
}

func protectedRequested(dir string, getenv func(string) string) bool {
	if manifest, err := loadCustodyManifest(dir); err == nil {
		return manifest.Protected()
	}
	if records(dir).Exists() {
		// A corrupt custody manifest must never authorize a downgrade; its kind
		// cannot be trusted until the operator repairs or restores it.
		return true
	}
	kind, err := canonicalProtectorKind(getenv(ProtectorEnv))
	return err == nil && kind != custody.KindFile
}

// ManagedConfigured reports whether this state directory already has managed
// OpenBao custody or the operator explicitly selected a protector. It lets
// doctor describe that posture even when the OpenBao binary itself is missing.
func ManagedConfigured(dir string, getenv func(string) string) bool {
	if _, err := loadCustodyManifest(dir); err == nil {
		return true
	}
	if records(dir).Exists() {
		return true
	}
	if strings.TrimSpace(getenv(ProtectorEnv)) != "" {
		return true
	}
	if _, err := os.Stat(bootstrapPath(dir)); err == nil {
		return true
	}
	return dirHasEntries(filepath.Join(dir, "data"))
}

func custodyPath(dir string) string { return filepath.Join(dir, "custody.json") }

func loadCustodyManifest(dir string) (custody.Manifest, error) {
	return records(dir).LoadManifest()
}

func saveCustodyManifest(dir string, manifest custody.Manifest) error {
	return records(dir).SaveManifest(manifest)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	return custody.WriteAtomic(path, b, mode)
}

func saveProtectedRecord(ctx context.Context, selection custodySelection, b []byte) error {
	if err := custody.SaveVerified(ctx, selection.protector, b); err != nil {
		return err
	}
	if err := saveCustodyManifest(selection.dir, selection.manifest); err != nil {
		return err
	}
	if selection.protector.Protected() {
		_ = os.Remove(bootstrapPath(selection.dir))
		_ = os.Remove(bootstrapPath(selection.dir) + ".tmp")
	}
	return nil
}

// CustodyPosture is the non-secret managed-store state rendered by doctor.
type CustodyPosture struct {
	Kind, Label, Detail  string
	Protected, Available bool
}

// InspectCustody validates the configured protector without printing or
// returning bootstrap material.
func InspectCustody(ctx context.Context, dir string, getenv func(string) string) CustodyPosture {
	kind, _ := canonicalProtectorKind(getenv(ProtectorEnv))
	if manifest, err := loadCustodyManifest(dir); err == nil {
		kind = manifest.Kind
	}
	posture := CustodyPosture{Kind: kind, Label: protectorLabel(kind), Protected: kind != custody.KindFile, Available: true}
	selection, err := selectCustody(dir, getenv)
	if err != nil {
		if records(dir).Exists() {
			posture.Protected = true
			posture.Label = "custody metadata"
		}
		posture.Available = false
		posture.Detail = err.Error()
		return posture
	}
	b, err := selection.protector.Load(ctx)
	if errors.Is(err, errBootstrapNotFound) {
		if selection.protector.Protected() {
			if legacy, legacyErr := os.ReadFile(bootstrapPath(dir)); legacyErr == nil {
				if json.Valid(legacy) {
					posture.Detail = "configured; legacy bootstrap will migrate on next startup"
					return posture
				}
			}
		}
		if dirHasEntries(filepath.Join(dir, "data")) {
			posture.Available = false
			posture.Detail = "OpenBao data exists but the bootstrap is unavailable; restore the protector before startup"
			return posture
		}
		posture.Detail = "configured; bootstrap will be created on first startup"
		return posture
	}
	if err != nil {
		posture.Available = false
		posture.Detail = err.Error()
		return posture
	}
	var bs bootstrap
	if err := json.Unmarshal(b, &bs); err != nil {
		posture.Available = false
		posture.Detail = "bootstrap record is invalid: " + err.Error()
		return posture
	}
	if bs.RootToken != "" {
		posture.Detail = "legacy root bootstrap will be retired to a narrow AppRole on next startup"
	} else {
		posture.Detail = "root retired; renewable narrow AppRole configured"
	}
	return posture
}

func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// MigrateCustody verifies the target protector before atomically switching the
// non-secret manifest, then removes the old copy. Moving back to the same-disk
// file posture requires an explicit allowDegraded acknowledgement.
func MigrateCustody(ctx context.Context, dir string, getenv func(string) string, target string, allowDegraded bool) error {
	targetKind, err := canonicalProtectorKind(target)
	if err != nil {
		return err
	}
	if targetKind == custody.KindFile && !allowDegraded {
		return errors.New("refusing to move protected OpenBao custody onto the same disk without --allow-degraded")
	}
	sourceManifest, err := loadCustodyManifest(dir)
	if os.IsNotExist(err) {
		sourceManifest = custody.Manifest{Format: custodyFormat, Kind: custody.KindFile, ID: custodyID(dir)}
	} else if err != nil {
		return err
	}
	targetCommand := strings.TrimSpace(getenv(ProtectorCommandEnv))
	sameCommand := sourceManifest.Kind == custody.KindCommand && targetKind == custody.KindCommand && targetCommand != "" && filepath.Clean(targetCommand) != filepath.Clean(sourceManifest.Command)
	if sourceManifest.Kind == targetKind && !sameCommand {
		return fmt.Errorf("managed OpenBao already uses %s custody", protectorLabel(targetKind))
	}
	source, err := newProtector(dir, sourceManifest, func(name string) string {
		if name == ProtectorCommandEnv && sourceManifest.Command != "" {
			return sourceManifest.Command
		}
		return getenv(name)
	})
	if err != nil {
		return fmt.Errorf("open current protector: %w", err)
	}
	secret, err := source.Load(ctx)
	if err != nil {
		return fmt.Errorf("load current protected bootstrap: %w", err)
	}
	var bs bootstrap
	if err := json.Unmarshal(secret, &bs); err != nil {
		return fmt.Errorf("current protected bootstrap is invalid: %w", err)
	}
	targetManifest := custody.Manifest{Format: custodyFormat, Kind: targetKind, ID: sourceManifest.ID}
	if targetKind == custody.KindCommand {
		targetManifest.Command = targetCommand
	}
	targetProtector, err := newProtector(dir, targetManifest, getenv)
	if err != nil {
		return fmt.Errorf("open target protector: %w", err)
	}
	return migrateCustodyRecord(ctx, dir, secret, source, targetManifest, targetProtector)
}

func migrateCustodyRecord(ctx context.Context, dir string, secret []byte, source custody.Protector, targetManifest custody.Manifest, targetProtector custody.Protector) error {
	return custody.Transfer(ctx, secret, source, targetProtector, func() error {
		return saveCustodyManifest(dir, targetManifest)
	})
}

// DeleteCustody removes the out-of-directory protected record before a full
// purge removes the manifest needed to locate it.
func DeleteCustody(ctx context.Context, dir string, getenv func(string) string) error {
	manifest, err := loadCustodyManifest(dir)
	if os.IsNotExist(err) {
		kind, kindErr := canonicalProtectorKind(getenv(ProtectorEnv))
		if kindErr != nil || kind == custody.KindFile {
			return kindErr
		}
		manifest = custody.Manifest{Format: custodyFormat, Kind: kind, ID: custodyID(dir)}
		if kind == custody.KindCommand {
			manifest.Command = strings.TrimSpace(getenv(ProtectorCommandEnv))
		}
		err = nil
	}
	if err != nil {
		return err
	}
	if !manifest.Protected() {
		return nil
	}
	p, err := newProtector(dir, manifest, func(name string) string {
		if name == ProtectorCommandEnv && manifest.Command != "" {
			return manifest.Command
		}
		return getenv(name)
	})
	if err != nil {
		return err
	}
	return p.Delete(ctx)
}
