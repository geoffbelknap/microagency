package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/geoffbelknap/microagent/pkg/workspace"
)

// MicroagentProvider runs a Spec as a microagent microVM. It always enforces
// deny-all egress (broker mode with a locked, empty allowlist); the caller
// cannot disable it. StateDir defaults to workspace.DefaultOptions().StateDir.
type MicroagentProvider struct {
	StateDir string // optional override; "" uses the workspace default
}

func (p MicroagentProvider) Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Name == "" {
		return Result{}, fmt.Errorf("sandbox: spec.Name must be non-empty")
	}
	if spec.Command == "" {
		return Result{}, fmt.Errorf("sandbox: spec.Command must be non-empty")
	}

	// Write the script to a host temp file for injection into the guest.
	dir, err := os.MkdirTemp("", "microagency-sandbox-*")
	if err != nil {
		return Result{}, fmt.Errorf("sandbox: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	codeFile := filepath.Join(dir, "run.py")
	if err := os.WriteFile(codeFile, []byte(spec.Code), 0o644); err != nil {
		return Result{}, fmt.Errorf("sandbox: write code: %w", err)
	}

	opts := workspace.DefaultOptions()
	if p.StateDir != "" {
		opts.StateDir = p.StateDir
	}
	stateDir := opts.StateDir
	// Cache the base image's unpacked layers so repeated boots don't re-pull from
	// the registry every time (which hits Docker Hub rate limits). The microagent
	// builder only consults its base-stage cache when this env var is set; default
	// it here, leaving any operator override in place. First boot populates it;
	// subsequent boots are fully offline.
	if os.Getenv("MICROAGENT_ROOTFS_BASE_CACHE_DIR") == "" {
		_ = os.Setenv("MICROAGENT_ROOTFS_BASE_CACHE_DIR", filepath.Join(stateDir, "build", "base-cache"))
	}
	opts.Name = spec.Name
	opts.ImageRef = spec.Image
	opts.Keep = true // retain per-workspace state so we can read the egress audit
	if spec.Timeout > 0 {
		opts.Timeout = spec.Timeout
	} else {
		opts.Timeout = 6 * time.Minute
	}
	// microagent resolves its own guest binaries (relative to the installed
	// microagent, not our binary) — we don't reach into its install layout.
	// Deny-all egress for compute-only reduce: mitm mode transparently
	// mediates ALL egress (arbitrary reduce code won't cooperate with a
	// forward proxy), and a LOCKED, empty allowlist reaches no destination
	// while auditing every attempt. This is strict's faithful successor
	// after the egress vocabulary change (strict → mitm + locked allowlist;
	// broker is a cooperative forward proxy and would not intercept a direct
	// connection). Callers cannot disable it.
	opts.EgressMode = "mitm"
	opts.EgressAllowlistLocked = true
	opts.Files = []workspace.File{{SourcePath: codeFile, Path: spec.CodePath}}
	// Optional input payloads (e.g. a reduce over one or more stored references):
	// inject each as a guest file the script reads. They never leave the sandbox.
	for i, in := range spec.Inputs {
		if len(in.Data) == 0 || in.Path == "" {
			continue
		}
		inputFile := filepath.Join(dir, fmt.Sprintf("input_%d", i))
		if err := os.WriteFile(inputFile, in.Data, 0o644); err != nil {
			return Result{}, fmt.Errorf("sandbox: write input %d: %w", i, err)
		}
		opts.Files = append(opts.Files, workspace.File{SourcePath: inputFile, Path: in.Path})
	}
	opts.ExecCommand = spec.Command

	// Reset only this workspace's state dir (append-only audit would otherwise
	// accumulate). Never touch anything else under StateDir (image cache).
	_ = os.RemoveAll(filepath.Join(stateDir, spec.Name))

	res, err := workspace.Run(ctx, opts)
	if err != nil {
		return Result{}, fmt.Errorf("sandbox: run %q: %w", spec.Name, err)
	}
	if res.Result == nil {
		// The serial log tees guest command output, which can echo the input data —
		// return it as a typed error so callers can route it to the operator's audit
		// surface instead of an agent-facing message.
		return Result{}, &GuestFailureError{Name: spec.Name, SerialLog: res.SerialLog}
	}

	out := Result{
		Stdout:   res.Result.Stdout,
		Stderr:   res.Result.Stderr,
		ExitCode: res.Result.ExitCode,
	}
	events, aerr := workspace.ReadEgressAudit(stateDir, spec.Name)
	if aerr != nil {
		out.AuditErr = aerr
	} else {
		for _, e := range events {
			out.Audit = append(out.Audit, AuditEvent{
				Event:  e.Event,
				Host:   e.Host,
				Dst:    e.Dst,
				Reason: e.Reason,
			})
		}
	}
	return out, nil
}
