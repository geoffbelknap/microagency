package router

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"microagency/internal/budget"
	"microagency/internal/refstore"
	"microagency/internal/sandbox"
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

func newRouter(maxBytes int) (Router, *refstore.MemStore) {
	store := refstore.NewMemStore()
	return Router{
		Provider: sandbox.MicroagentProvider{},
		Gate:     budget.Gate{MaxBytes: maxBytes, Store: store},
		Image:    "docker.io/library/python:3.13-slim",
		CodePath: "/app/run.py",
		Timeout:  6 * time.Minute,
	}, store
}

// fakeProvider implements sandbox.Provider and returns a canned Result.
type fakeProvider struct{ result sandbox.Result }

func (f fakeProvider) Run(_ context.Context, _ sandbox.Spec) (sandbox.Result, error) {
	return f.result, nil
}

// TestRouterPropagatesAuditErrAndCapsStderr verifies two properties without a VM:
//  1. AuditErr from the sandbox is surfaced on Decision.AuditErr.
//  2. Stderr longer than maxStderrBytes is truncated with a notice; shorter stderr passes through unchanged.
//
// Decision.Stderr is OPERATOR-BOUND: the mcp layer records it in the run's audit
// record (surfaced via /admin/runs) and never returns it in the agent-facing tool
// result — the cap here bounds that audit record.
func TestRouterPropagatesAuditErrAndCapsStderr(t *testing.T) {
	sentinelErr := errors.New("audit read failed: disk full")

	bigStderr := strings.Repeat("E", maxStderrBytes+500)
	smallStderr := "just a warning"

	cases := []struct {
		name          string
		stderr        string
		wantTruncated bool
	}{
		{"big-stderr", bigStderr, true},
		{"small-stderr", smallStderr, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := refstore.NewMemStore()
			r := Router{
				Provider: fakeProvider{result: sandbox.Result{
					Stdout:   "ok",
					Stderr:   tc.stderr,
					ExitCode: 0,
					AuditErr: sentinelErr,
				}},
				Gate:     budget.Gate{MaxBytes: 4096, Store: store},
				CodePath: "/app/run.py",
			}
			dec, err := r.Run(context.Background(), Request{
				Name: "fake-run",
				Code: "print('ok')",
			})
			if err != nil {
				t.Fatalf("router.Run: %v", err)
			}
			// AuditErr must be propagated.
			if dec.AuditErr != sentinelErr {
				t.Fatalf("AuditErr = %v, want %v", dec.AuditErr, sentinelErr)
			}
			if tc.wantTruncated {
				if len(dec.Stderr) > maxStderrBytes+len("\n...[stderr truncated]") {
					t.Fatalf("Stderr not truncated: len=%d", len(dec.Stderr))
				}
				if !strings.HasSuffix(dec.Stderr, "\n...[stderr truncated]") {
					t.Fatalf("Stderr missing truncation suffix: %q", dec.Stderr[len(dec.Stderr)-40:])
				}
				// Must start with the first maxStderrBytes of the original.
				if dec.Stderr[:maxStderrBytes] != tc.stderr[:maxStderrBytes] {
					t.Fatal("Stderr prefix does not match original")
				}
			} else {
				if dec.Stderr != tc.stderr {
					t.Fatalf("small Stderr modified: got %q, want %q", dec.Stderr, tc.stderr)
				}
			}
		})
	}
}

// TestRouterRejectsEmptyCode is a pure-validation unit test (no VM).
func TestRouterRejectsEmptyCode(t *testing.T) {
	r, _ := newRouter(2048)
	if _, err := r.Run(context.Background(), Request{Name: "x", Code: "   "}); err == nil {
		t.Fatal("expected error for empty code")
	}
}

// TestRouterRejectsEmptyName is a pure-validation unit test (no VM).
func TestRouterRejectsEmptyName(t *testing.T) {
	r, _ := newRouter(2048)
	if _, err := r.Run(context.Background(), Request{Name: "", Code: "print(1)"}); err == nil {
		t.Fatal("expected error for empty name")
	}
}

// TestRouterSurfacesUnavailableProvider: with the microVM path disabled
// (--reduce-engines-only), a code reduce through the router fails with a
// clear ErrProviderUnavailable rather than silently succeeding. No VM.
func TestRouterSurfacesUnavailableProvider(t *testing.T) {
	r := Router{
		Provider: sandbox.UnavailableProvider{Reason: "engines-only"},
		Gate:     budget.Gate{MaxBytes: 4096, Store: refstore.NewMemStore()},
		CodePath: "/app/run.py",
	}
	_, err := r.Run(context.Background(), Request{Name: "x", Code: "print(1)"})
	if err == nil {
		t.Fatal("expected an error when the microVM provider is unavailable")
	}
	if !errors.Is(err, sandbox.ErrProviderUnavailable) {
		t.Fatalf("error should wrap ErrProviderUnavailable, got %v", err)
	}
}

// TestRouterInlineSmallResult: a small result comes back inline.
func TestRouterInlineSmallResult(t *testing.T) {
	requireVM(t)
	r, _ := newRouter(2048)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	dec, err := r.Run(ctx, Request{
		Name: "m2-router-small",
		Code: "print('SMALL-RESULT-OK')",
	})
	if err != nil {
		t.Fatalf("router.Run: %v", err)
	}
	if dec.Reffed {
		t.Fatalf("small result was reffed; summary=%+v", dec.Summary)
	}
	if !strings.Contains(dec.Inline, "SMALL-RESULT-OK") {
		t.Fatalf("inline missing marker: %q", dec.Inline)
	}
}

// TestRouterRefsLargeResult: an over-budget result is stored behind a ref and
// only {ref, summary} is returned â the payload never comes inline (S4),
// proven end-to-end through a real sandbox.
func TestRouterRefsLargeResult(t *testing.T) {
	requireVM(t)
	r, store := newRouter(512) // small budget
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Emit ~5000 bytes from the guest â well over the 512-byte budget.
	dec, err := r.Run(ctx, Request{
		Name: "m2-router-large",
		Code: "print('R' * 5000)",
	})
	if err != nil {
		t.Fatalf("router.Run: %v", err)
	}
	if !dec.Reffed {
		t.Fatal("over-budget result was returned inline (S4 violation)")
	}
	if dec.Inline != "" {
		t.Fatalf("over-budget Inline must be empty, got %d bytes", len(dec.Inline))
	}
	if dec.Ref == "" {
		t.Fatal("over-budget Ref is empty")
	}
	if dec.Summary.Bytes < 5000 {
		t.Fatalf("summary bytes = %d, want >= 5000", dec.Summary.Bytes)
	}
	// The full payload is retrievable from the store but never reached the caller.
	full, _, ok := store.Get(dec.Ref)
	if !ok || !strings.Contains(full, strings.Repeat("R", 5000)) {
		t.Fatalf("stored payload not retrievable/complete via %q (ok=%v)", dec.Ref, ok)
	}
}
