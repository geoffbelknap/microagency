package sandbox

import (
	"context"
	"time"

	"github.com/geoffbelknap/microagent/pkg/diagnostics"
)

// Health is a snapshot of microVM-runtime readiness — what `microagency doctor`
// reports so a missing/unhealthy install is visible up front, not a cryptic
// failure mid-run (e.g. "copy init binary: no such file").
type Health struct {
	Backend         string
	Architecture    string
	Virtualization  bool
	SupervisorPath  string
	SupervisorReady bool
	GuestInitPath   string
	GuestInitReady  bool
	Version         string
	KVM             bool
	Vsock           bool
	ProbeError      string // non-empty if the host probe itself failed
}

// Usable reports whether the microVM (code) substrate can actually run:
// virtualization plus both host binaries present.
func (h Health) Usable() bool {
	return h.Virtualization && h.SupervisorReady && h.GuestInitReady
}

// Probed reports whether the host probe returned data. When false (with a
// ProbeError), readiness is UNKNOWN — distinct from a definitive "not usable".
func (h Health) Probed() bool {
	return h.Backend != "" || h.SupervisorPath != "" || h.GuestInitPath != ""
}

// InspectRuntime probes the host microVM runtime via microagent (best-effort,
// time-bounded). It never panics: a probe failure lands in ProbeError, so the
// doctor can report "not usable" cleanly instead of crashing.
//
// This issues a host-support probe (diagnostics.Check sends a "host" command to
// the supervisor and augments the result), NOT a workspace "inspect" lifecycle
// command — the latter operates on a (here non-existent) workspace and never
// populates resp.Host, which left the doctor permanently reporting "could not
// probe" even on a healthy install.
func InspectRuntime(ctx context.Context) Health {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Empty Options: diagnostics.Check defaults the backend/arch to this host's
	// and resolves the supervisor binary from PATH (microagent's install layout).
	resp, err := diagnostics.Check(ctx, diagnostics.Options{})
	h := Health{}
	if resp.Host != nil {
		host := resp.Host
		h.Backend = host.Backend
		h.Architecture = host.Architecture
		h.Virtualization = host.VirtualizationSupported
		h.SupervisorPath = host.SupervisorPath
		h.SupervisorReady = host.SupervisorAvailable
		h.GuestInitPath = host.GuestInitPath
		h.GuestInitReady = host.GuestInitAvailable
		h.Version = host.BinaryVersion
		h.KVM = host.KVMAvailable
		h.Vsock = host.VsockAvailable
	}
	// The apple-vf host probe does not report guest-init (only the firecracker
	// and hyper-v probes do), yet reduce(code) needs it on every
	// backend. Resolve it ourselves when the probe left it blank, using the same
	// PATH-aware lookup microagent uses at launch (it finds the binary via the
	// installed `microagent`, not microagency's own layout) so the doctor's
	// guest-init line matches what a real run would resolve.
	if h.GuestInitPath == "" && h.Backend != "" {
		path, gerr := diagnostics.ResolveGuestInitPath(diagnostics.Options{Arch: h.Architecture})
		if gerr == nil {
			h.GuestInitPath = path
			h.GuestInitReady = true
		}
	}
	if err != nil {
		h.ProbeError = err.Error()
	}
	return h
}
