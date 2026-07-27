package sandbox

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// ready is a Health with every prerequisite confirmed and a clean probe.
func ready() Health {
	return Health{
		Backend:         "linux-kvm",
		Architecture:    "amd64",
		Virtualization:  true,
		SupervisorPath:  "/opt/bin/microagent-firecracker-supervisor",
		SupervisorReady: true,
		GuestInitPath:   "/opt/libexec/microagent-guestinit-amd64",
		GuestInitReady:  true,
		KVM:             true,
		Vsock:           true,
	}
}

// TestProbeErrorIsNeverHealthy is the regression test for a verdict that
// contradicted its own evidence. doctor rendered the probe error and then
// asserted "microVM runtime is healthy — reduce(code) will work" directly
// beneath it, because Usable consulted only the readiness flags — flags a
// failed probe never confirmed.
func TestProbeErrorIsNeverHealthy(t *testing.T) {
	h := ready()
	h.ProbeError = "firecracker binary not found"

	if h.Usable() {
		t.Error("Usable() is true alongside a probe error; a failed probe confirms nothing")
	}
	if !h.Unknown() {
		t.Error("Unknown() is false alongside a probe error; readiness was never established")
	}
}

// TestCleanProbeWithPrerequisitesIsHealthy keeps the positive case working, so
// the fix cannot be "always report unknown".
func TestCleanProbeWithPrerequisitesIsHealthy(t *testing.T) {
	h := ready()
	if !h.Usable() {
		t.Error("Usable() is false for a clean probe with every prerequisite met")
	}
	if h.Unknown() {
		t.Error("Unknown() is true for a clean, fully-probed host")
	}
}

// TestUnknownIsDistinctFromNotUsable pins the three-way split. Collapsing
// unknown into not-usable tells an operator their host is broken when the truth
// is that it was never inspected; collapsing it into healthy is the bug above.
func TestUnknownIsDistinctFromNotUsable(t *testing.T) {
	tests := []struct {
		name        string
		health      Health
		wantUsable  bool
		wantUnknown bool
	}{
		{
			name:        "clean probe, prerequisites met",
			health:      ready(),
			wantUsable:  true,
			wantUnknown: false,
		},
		{
			name: "probed, a prerequisite genuinely missing",
			health: func() Health {
				h := ready()
				h.SupervisorReady = false
				return h
			}(),
			wantUsable:  false,
			wantUnknown: false, // definitively not usable, not unknown
		},
		{
			// An error alongside data is the probe LISTING what is wrong, not
			// failing — diagnostics.Check errors whenever any issue exists.
			// This used to land in ProbeError, which made every broken host
			// read as unknown and left the NOT-usable verdict unreachable.
			name: "probe returned its issue list alongside its data",
			health: func() Health {
				h := ready()
				h.SupervisorReady = false
				h.GuestInitReady = false
				h.Issues = "supervisor not found; guest-init not found; firecracker binary not found"
				return h
			}(),
			wantUsable:  false,
			wantUnknown: false, // definitive: the fix is an install, not a re-probe
		},
		{
			name:        "probe returned nothing at all",
			health:      Health{ProbeError: "probe timed out"},
			wantUsable:  false,
			wantUnknown: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.health.Usable(); got != tt.wantUsable {
				t.Errorf("Usable() = %v, want %v", got, tt.wantUsable)
			}
			if got := tt.health.Unknown(); got != tt.wantUnknown {
				t.Errorf("Unknown() = %v, want %v", got, tt.wantUnknown)
			}
		})
	}
}

// TestIssuesAloneAreNotUsable is the false-green guard for the Issues field.
// The probe's issue list covers prerequisites Health has no flag for (kernel
// artifacts, user networking), so a host failing only one of those shows every
// flag green. Dropping Issues from Usable() would print "reduce(code) will
// work" directly above the probe's own list of reasons it will not.
func TestIssuesAloneAreNotUsable(t *testing.T) {
	h := ready()
	h.Issues = "kernel: no installed kernel for linux-kvm/amd64"

	if h.Usable() {
		t.Error("Usable() is true alongside a definitive issues list")
	}
	if h.Unknown() {
		t.Error("Unknown() is true for a probe that returned data; the issues are definitive")
	}
}

// TestBrokenHostIsDefinitivelyNotUsable drives the real InspectRuntime against
// a host with no microagent install in sight, which is the state a fresh
// operator machine is in.
//
// This is the test the unit truth table could not stand in for. The table pins
// "probed, prerequisite missing → not usable, not unknown", but the shipped
// InspectRuntime could never produce that state: diagnostics.Check returns a
// non-nil error whenever ANY issue exists, and mapping every error to
// ProbeError collapsed "definitively broken" into "never inspected". A host
// with no supervisor, no guest-init, and no firecracker printed "⚠ may still
// be fine — verify with a quick reduce(code=…)" — advice to verify with the
// very thing that cannot run — and the ✗ verdict naming the install fix was
// unreachable. The unit table stayed green throughout, which is how it
// shipped.
func TestBrokenHostIsDefinitivelyNotUsable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("probe semantics under test are the linux ones")
	}
	// An empty PATH removes the microagent install layout regardless of what
	// this machine has; the probe should still return host data (KVM, vsock,
	// virtualization are read directly) alongside its issue list.
	t.Setenv("PATH", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h := InspectRuntime(ctx)

	if !h.Probed() {
		t.Fatalf("probe returned no data at all; cannot assert the definitive branch: %+v", h)
	}
	if h.Usable() {
		t.Errorf("Usable() with no supervisor on PATH: %+v", h)
	}
	if h.Unknown() {
		t.Errorf("a probe that returned data reads as unknown; the NOT-usable verdict is unreachable again: %+v", h)
	}
	if h.Issues == "" {
		t.Errorf("no issues recorded for a host with no install: %+v", h)
	}
}
