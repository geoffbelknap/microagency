package sandbox

import "testing"

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
			name: "probe returned an error alongside its data",
			health: func() Health {
				h := ready()
				h.ProbeError = "firecracker binary not found"
				return h
			}(),
			wantUsable:  false,
			wantUnknown: true,
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
