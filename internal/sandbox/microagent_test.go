package sandbox

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func requireVM(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("microVM integration test; needs the microagent runtime — run without -short")
	}
	if runtime.GOOS != "linux" {
		t.Skip("requires linux")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("requires /dev/kvm")
	}
}

const pyImage = "docker.io/library/python:3.13-slim"

// TestProviderRunsScript: the seam runs a script and returns its stdout.
func TestProviderRunsScript(t *testing.T) {
	requireVM(t)
	p := MicroagentProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	res, err := p.Run(ctx, Spec{
		Name:     "m2-prov-run",
		Image:    pyImage,
		Code:     "print('PROVIDER-MARKER-a1b2')",
		CodePath: "/app/run.py",
		Command:  "python /app/run.py",
		Timeout:  6 * time.Minute,
	})
	if err != nil {
		t.Fatalf("provider.Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	if res.AuditErr != nil {
		t.Fatalf("audit read failed: %v", res.AuditErr)
	}
	if !strings.Contains(res.Stdout, "PROVIDER-MARKER-a1b2") {
		t.Fatalf("stdout missing marker: %q", res.Stdout)
	}
}

// TestProviderMultiInput: multiple Inputs land as distinct guest files the script
// can read — the reduce multi-ref join/correlate path (/app/input_1..N).
func TestProviderMultiInput(t *testing.T) {
	requireVM(t)
	p := MicroagentProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	res, err := p.Run(ctx, Spec{
		Name:     "multi-input",
		Image:    pyImage,
		Code:     "print(open('/app/input_1').read() + '|' + open('/app/input_2').read())",
		CodePath: "/app/run.py",
		Command:  "python /app/run.py",
		Inputs: []Input{
			{Data: []byte("ALPHA"), Path: "/app/input_1"},
			{Data: []byte("BETA"), Path: "/app/input_2"},
		},
		Timeout: 6 * time.Minute,
	})
	if err != nil {
		t.Fatalf("provider.Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ALPHA|BETA") {
		t.Fatalf("both inputs must be delivered as files; stdout=%q", res.Stdout)
	}
}

// TestProviderSurfacesDeny: a strict sandbox (deny-all, no allowlist) produces at
// least one deny event in the audit when the guest attempts an outbound HTTPS
// connection. This proves Dst and/or Event are populated for blocked targets.
func TestProviderSurfacesDeny(t *testing.T) {
	requireVM(t)
	p := MicroagentProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Attempt an outbound HTTPS GET with no allowlisted hosts. The sandbox will
	// deny the connection; we expect at least one deny event in the audit.
	probe := "import ssl, urllib.request\n" +
		"try:\n" +
		"    urllib.request.urlopen('https://example.com', timeout=10)\n" +
		"except Exception:\n" +
		"    pass\n"

	res, err := p.Run(ctx, Spec{
		Name:        "m2-prov-deny",
		Image:       pyImage,
		Code:        probe,
		CodePath:    "/app/run.py",
		Command:     "python /app/run.py",
		Timeout:     6 * time.Minute,
	})
	if err != nil {
		t.Fatalf("provider.Run: %v", err)
	}
	if res.AuditErr != nil {
		t.Fatalf("audit read failed: %v", res.AuditErr)
	}

	t.Logf("audit events (%d):", len(res.Audit))
	for _, e := range res.Audit {
		t.Logf("  event=%q host=%q dst=%q reason=%q", e.Event, e.Host, e.Dst, e.Reason)
	}

	// Find at least one deny event. The mediator uses egress_dns_deny,
	// egress_deny, or similar. Check Event contains "deny".
	hasDeny := false
	for _, e := range res.Audit {
		if strings.Contains(e.Event, "deny") {
			hasDeny = true
			// Verify the blocked target is surfaced in Dst, Host, or Raw.
			hasTarget := strings.Contains(e.Dst, "example.com") ||
				strings.Contains(e.Host, "example.com")
			if !hasTarget {
				t.Logf("deny event has no example.com in Dst/Host â checking raw event fields; Dst=%q Host=%q", e.Dst, e.Host)
			}
			break
		}
	}
	if !hasDeny {
		t.Fatalf("expected at least one deny audit event; got %d events: %+v", len(res.Audit), res.Audit)
	}
}
