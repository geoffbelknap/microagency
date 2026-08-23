// Package app wires a configured microagency gateway (an *mcp.Server with its
// reduce substrates, refstore, minimizers, and signed audit chain) from a plain
// Config. It exists so the CLI is not the only way to construct the server: an
// embedder, a test harness, or a sibling service (e.g. microplane) can call
// BuildServer without re-deriving the ~90 lines of wiring that used to live in
// package main. The CLI (cmd/microagency) now just parses flags into a Config and
// calls in here.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"microagency/internal/auth"
	"microagency/internal/budget"
	"microagency/internal/mcp"
	"microagency/internal/minimize"
	"microagency/internal/refstore"
	"microagency/internal/router"
	"microagency/internal/sandbox"
	"microagency/internal/secretstore"
	"microagency/internal/wasmexec"
)

// Config is the full set of inputs needed to build a gateway server. Paths derive
// from StateDir (the ~/.microagency dir in the CLI). The bundled engine/minimizer
// modules are passed in as bytes so this package carries no embed of its own — the
// binary that has them (the CLI) supplies them.
type Config struct {
	StateDir               string            // holds secrets, refs, the audit key (0700)
	Version                string            // build version, surfaced in serverInfo/infra
	ConsoleAddr            string            // where the operator console is bound (for infra display)
	MaxInlineBytes         int               // results larger than this return as a <ref_>
	WasmMaxMemMB           int               // per-wasm-run memory ceiling
	PersistRefs            bool              // persist reffed payloads (encrypted, TTL'd) across restart
	ReduceEnginesOnly      bool              // disable the microVM code path (wasm engines only)
	HighAssuranceMultiUser bool              // exact operation grants + fail-closed decision ledger
	EngineSpecs            []string          // extra `name=path` query engines to load/override
	BundledEngines         map[string][]byte // embedded query-engine modules by name
	BundledMinimizers      map[string][]byte // embedded field-minimizer modules by name

	// AllowPlaintextCredentials opts in to the unencrypted mode-0600 credential
	// fallback. Without it, a build that would land there fails closed instead
	// of persisting upstream credentials in the clear.
	AllowPlaintextCredentials bool
	// PreferredStore names the store the caller tried before this build (e.g.
	// "managed OpenBao"), and PreferredStoreUnavailable says why it could not
	// be used. Both feed the credential-store record and the fail-closed error,
	// so an operator is told what was unavailable rather than only what was
	// refused. Empty when nothing was tried first.
	PreferredStore, PreferredStoreUnavailable string
}

// BuildServer constructs the gateway server from cfg. Unlike the old package-main
// wiring it returns an error rather than calling a fatal()/os.Exit, so an embedder
// decides how to handle a failure.
func BuildServer(cfg Config) (*mcp.Server, error) {
	// One refstore backs the budget gate for both substrates AND the proxy path, so
	// a reffed result is resolvable regardless of which produced it. In-memory and
	// BOUNDED by default (24h TTL, 10k entries) so a long-lived gateway can't grow
	// until it OOMs; --persist-refs swaps in an encrypted, TTL'd file store.
	var store refstore.Store = refstore.NewBoundedMemStore(24*time.Hour, 10000)
	if cfg.PersistRefs {
		if fs, err := openPersistedRefs(cfg.StateDir); err != nil {
			slog.Warn("--persist-refs unavailable; using in-memory refs", "err", err)
		} else {
			store = fs
			slog.Info("refs persisted (encrypted, 24h TTL)", "dir", filepath.Join(cfg.StateDir, "refs"))
		}
	}
	gate := budget.Gate{MaxBytes: cfg.MaxInlineBytes, Store: store}

	// The microVM reduce path (arbitrary code) needs nested virtualization; where
	// there is none, disable it and keep only the in-process wasm engines.
	var provider sandbox.Provider = sandbox.MicroagentProvider{}
	if cfg.ReduceEnginesOnly {
		provider = sandbox.UnavailableProvider{Reason: "microagency is running with --reduce-engines-only (no microVM sandbox)"}
		slog.Info("microVM reduce disabled (--reduce-engines-only); wasm engines only")
	}
	rt := router.Router{
		Provider: provider,
		Gate:     gate,
		Image:    sandbox.ReduceImage,
		CodePath: sandbox.ReduceCodePath,
		Timeout:  6 * time.Minute,
	}

	// Acquired secrets (upstream OAuth refresh tokens) persist in OpenBao/Vault when
	// VAULT_ADDR + VAULT_TOKEN are set. The file fallback is encrypted under a data
	// key a protector supplies — an OS keyring, a KMS-backed helper, or an operator
	// key file; the unencrypted form is a downgrade and needs
	// AllowPlaintextCredentials, so a vault outage cannot quietly move credentials
	// into the clear.
	secStore, err := secretstore.Open(cfg.StateDir, os.Getenv, secretstore.Options{
		AllowPlaintext: cfg.AllowPlaintextCredentials,
		Client:         http.DefaultClient,
	})
	if err != nil {
		if errors.Is(err, secretstore.ErrPlaintextNotAllowed) {
			return nil, plaintextRefusal(cfg)
		}
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	// Record what was actually opened, so `doctor` and the startup banner report
	// the store in effect rather than the one the configuration asks for. A
	// silent downgrade is the failure this closes: everything keeps working, so
	// nothing prompts the second look that would find the credentials in the
	// clear.
	posture := resolvedPosture(cfg, secStore.Kind(), keyCustodyOf(secStore))
	if err := secretstore.SavePosture(cfg.StateDir, posture); err != nil {
		slog.Warn("could not record the credential-store posture", "err", err)
	}
	switch {
	case posture.Disagrees():
		slog.Warn("credential store in effect is not the one configured",
			"in_effect", posture.Effective, "configured", posture.Configured, "reason", posture.Reason)
	case posture.Degraded:
		slog.Warn("credential store is degraded", "in_effect", posture.Effective,
			"encrypt_with", secretstore.ProtectorEnv+" or "+secretstore.FileKeyEnv)
	default:
		slog.Info("credential store selected", "backend", posture.Effective)
	}
	opts := []mcp.Option{
		mcp.WithSecretStore(secStore),
		mcp.WithStateDir(cfg.StateDir),
		mcp.WithBudgetGate(gate),
		mcp.WithVersion(cfg.Version),
		mcp.WithConsoleAddr(cfg.ConsoleAddr),
		mcp.WithHighAssuranceMultiUser(cfg.HighAssuranceMultiUser),
	}
	// Sign the audit chain (ES256). Best-effort: if the key can't be loaded, the
	// chain stays integrity-only rather than blocking startup.
	if signer, err := auth.LoadOrCreateSigner(filepath.Join(cfg.StateDir, "audit-key")); err == nil {
		opts = append(opts, mcp.WithAuditSigner(signer))
	} else {
		slog.Warn("audit signing disabled; chain is integrity-only", "err", err)
	}

	// Query engines back reduce's declarative path. Bundled modules register first,
	// in a deterministic order (jq default when present); each `--engine name=path`
	// adds or overrides one.
	addEngine := func(name string, mod []byte) {
		opts = append(opts, mcp.WithWasmEngine(name, wasmexec.SandboxEngine{
			Module:         mod,
			Timeout:        2 * time.Minute,
			MaxMemoryPages: uint32(cfg.WasmMaxMemMB) * 16, // 64 KiB pages → MiB
		}))
	}
	names := make([]string, 0, len(cfg.BundledEngines))
	for name := range cfg.BundledEngines {
		names = append(names, name)
	}
	for _, name := range orderEngineNames(names) {
		addEngine(name, cfg.BundledEngines[name])
	}
	for _, spec := range cfg.EngineSpecs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("--engine expects name=path, got %q", spec)
		}
		mod, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read engine %q: %w", path, err)
		}
		addEngine(name, mod)
	}

	// Field minimizers: bundled wasip1 modules that redact/tokenize sensitive field
	// values at the egress-to-model boundary. Installed as an ordered pipeline;
	// per-upstream policy decides what fires (no policy → nothing changes).
	if mods := cfg.BundledMinimizers; len(mods) > 0 {
		mnames := make([]string, 0, len(mods))
		for n := range mods {
			mnames = append(mnames, n)
		}
		sort.Strings(mnames)
		var chain []minimize.Module
		for _, n := range mnames {
			m, err := minimize.LoadWasm(context.Background(), n, mods[n], minimize.Options{
				Timeout:        30 * time.Second,
				MaxMemoryPages: uint32(cfg.WasmMaxMemMB) * 16,
			})
			if err != nil {
				slog.Warn("minimizer unavailable", "minimizer", n, "err", err)
				continue
			}
			chain = append(chain, m)
		}
		if len(chain) > 0 {
			opts = append(opts,
				mcp.WithMinimizer(minimize.Pipeline{Modules: chain}, minimize.NewMemTokenStore()),
				mcp.WithSecureDefault(true)) // protect detected sensitive fields by default; operator opts down
		}
	}
	return mcp.NewServer(rt, opts...), nil
}

// keyCustodyOf reports which protector supplies an encrypted store's data key.
// Only the file store has one; a vault holds no local key.
func keyCustodyOf(store secretstore.Store) string {
	if c, ok := store.(interface{ KeyCustody() string }); ok {
		return c.KeyCustody()
	}
	return ""
}

// resolvedPosture turns the store that was actually opened, plus what the
// caller tried first, into the non-secret record `doctor` reads.
func resolvedPosture(cfg Config, kind, keyCustody string) secretstore.Posture {
	effective := secretstore.DescribeStore(kind, keyCustody)
	if kind == secretstore.KindVault {
		// A vault store is reached either through a managed instance the caller
		// brought up or through an operator-run one; only the caller knows
		// which, and "OpenBao/Vault" alone would not tell an operator where to
		// look.
		effective = "external Vault/OpenBao (VAULT_ADDR)"
		if cfg.PreferredStore != "" {
			effective = cfg.PreferredStore
		}
	}
	p := secretstore.Posture{
		PID:        os.Getpid(),
		Kind:       kind,
		Effective:  effective,
		KeyCustody: keyCustody,
		Degraded:   kind == secretstore.KindFile,
	}
	if cfg.PreferredStore != "" && cfg.PreferredStore != effective {
		p.Configured, p.Reason = cfg.PreferredStore, cfg.PreferredStoreUnavailable
	}
	return p
}

// plaintextRefusal explains a fail-closed startup in terms of what was
// unavailable, not only what was refused. Consumers with their own vocabulary
// (the CLI has a flag; an embedder has neither) override the wording; the
// sentinel stays wrapped so they can still branch on it.
func plaintextRefusal(cfg Config) error {
	msg := "refusing to persist upstream credentials in the unencrypted mode-0600 fallback"
	if cfg.PreferredStore != "" {
		msg += fmt.Sprintf(": %s is unavailable", cfg.PreferredStore)
		if cfg.PreferredStoreUnavailable != "" {
			msg += fmt.Sprintf(" (%s)", cfg.PreferredStoreUnavailable)
		}
	}
	msg += fmt.Sprintf("; restore that store, encrypt the fallback with %s or %s, or opt in with %s=1",
		secretstore.ProtectorEnv, secretstore.FileKeyEnv, secretstore.AllowPlaintextEnv)
	return fmt.Errorf("%s: %w", msg, secretstore.ErrPlaintextNotAllowed)
}

// orderEngineNames returns bundled engine names in a deterministic registration
// order: jq first (the preferred default — the first engine registered becomes the
// default), then the rest alphabetically. A stable order keeps the default from
// flipping between restarts under Go's randomized map iteration.
func orderEngineNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Slice(out, func(i, j int) bool {
		if (out[i] == "jq") != (out[j] == "jq") {
			return out[i] == "jq"
		}
		return out[i] < out[j]
	})
	return out
}

// openPersistedRefs builds an encrypted, TTL'd file-backed refstore under
// stateDir. The AES-256 key is generated once and persisted 0600.
func openPersistedRefs(stateDir string) (refstore.Store, error) {
	key, err := loadOrCreateRefsKey(filepath.Join(stateDir, "refs.key"))
	if err != nil {
		return nil, err
	}
	return refstore.NewFileStore(filepath.Join(stateDir, "refs"), key, 24*time.Hour, 10000)
}

// loadOrCreateRefsKey reads the 32-byte refs encryption key, minting and
// persisting one (0600) if absent.
func loadOrCreateRefsKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
