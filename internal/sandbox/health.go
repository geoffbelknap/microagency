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
	Issues          string // definitive problems the probe reported alongside its data
	ProbeError      string // non-empty if the host probe itself failed (returned no data)
}

// Usable reports whether the microVM (code) substrate can actually run:
// virtualization plus both host binaries present, established by a probe that
// itself succeeded and reported no issues.
//
// ProbeError is part of the condition deliberately. It used to be rendered to
// the operator and then ignored here, so a probe error and a healthy verdict
// printed together — doctor asserted "reduce(code) will work" directly beneath
// the reason it could not establish that. A failed probe means the readiness
// flags below were never confirmed, so nothing may be claimed from them.
//
// Issues is part of the condition for the opposite reason: the probe's issue
// list covers prerequisites this struct has no flag for (kernel artifacts,
// user networking). A host failing only one of those would show every flag
// green, and dropping Issues from the condition would print "reduce(code)
// will work" over the probe's own list of reasons it will not.
func (h Health) Usable() bool {
	return h.ProbeError == "" && h.Issues == "" && h.Virtualization && h.SupervisorReady && h.GuestInitReady
}

// Unknown reports whether readiness could not be established at all: the probe
// returned no data. This is distinct from a definitive "not usable" — the
// substrate may well work — and callers must not collapse the two in either
// direction. Telling an operator their host is broken when it was never
// inspected is one failure; the shipped converse was the other: every probe
// that returned data alongside an error landed here, so a host with no
// supervisor, no guest-init, and no firecracker read as "may still be fine"
// and the NOT-usable verdict — the only one that names the install fix — was
// unreachable.
func (h Health) Unknown() bool {
	return h.ProbeError != "" || !h.Probed()
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
		// The probe reports two different failures through one error return,
		// and they must not share a field. Data plus an error means the probe
		// worked and is listing what is definitively wrong with the host —
		// diagnostics.Check errors whenever ANY issue exists. No data means
		// the probe itself failed and nothing was established. Mapping both
		// to ProbeError made every broken host read as "unknown, may still be
		// fine" and left the NOT-usable verdict unreachable.
		if resp.Host != nil {
			h.Issues = err.Error()
		} else {
			h.ProbeError = err.Error()
		}
	}
	return h
}
