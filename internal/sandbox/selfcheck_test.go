package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geoffbelknap/microagent/pkg/workspace"
)

// TestSelfCheckPassesOnAHealthyHost is the positive control, and it also pins
// the cleanup contract: a passing probe leaves no workspace record and no
// state directory behind, so doctor can run forever without accreting state.
func TestSelfCheckPassesOnAHealthyHost(t *testing.T) {
	requireVM(t)
	sc := SelfCheck(context.Background(), ReduceImage, ReduceCodePath, 2*time.Minute)
	if !sc.OK {
		t.Fatalf("self-check failed on a healthy host: %+v", sc)
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{
		filepath.Join(home, ".microagent", "workspaces", selfCheckName),
		filepath.Join(home, ".microagent", selfCheckName),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("passing self-check left %s behind (err=%v)", p, err)
		}
	}
}

// TestSelfCheckCatchesAPoisonedRootfs reproduces the incident the self-check
// exists for, end to end.
//
// A base-stage cache entry with a valid completion marker over a gutted tree
// — no /bin — produced a rootfs whose guest exited 1 with nothing on any
// stream, for two days, behind a doctor verdict that said reduce(code) would
// work. This test manufactures that exact cache state (healthy entry copied,
// base/ gutted to usr/ plus the stage marker so restore accepts it), points
// the builder at it, and requires the self-check to fail with the guest's own
// start diagnosis rather than pass, time out, or blame the code.
func TestSelfCheckCatchesAPoisonedRootfs(t *testing.T) {
	requireVM(t)
	home, _ := os.UserHomeDir()
	healthy := filepath.Join(home, ".microagent", "build", "base-cache")
	entries, err := os.ReadDir(healthy)
	if err != nil || len(entries) == 0 {
		t.Skipf("no healthy base cache to poison a copy of: %v", err)
	}

	poisoned := t.TempDir()
	for _, e := range entries {
		src := filepath.Join(healthy, e.Name())
		dst := filepath.Join(poisoned, e.Name())
		if out, cpErr := exec.Command("cp", "-a", src, dst).CombinedOutput(); cpErr != nil {
			t.Fatalf("copy cache entry: %v: %s", cpErr, out)
		}
		base := filepath.Join(dst, "base")
		// Gut the tree the way an interrupted pre-atomic save did, keeping
		// the two files that make the entry LOOK valid: metadata.json and
		// the stage marker.
		baseEntries, _ := os.ReadDir(base)
		for _, be := range baseEntries {
			if be.Name() == "usr" || strings.HasPrefix(be.Name(), ".microagent-rootfs-metadata") {
				continue
			}
			if err := os.RemoveAll(filepath.Join(base, be.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("MICROAGENT_ROOTFS_BASE_CACHE_DIR", poisoned)

	sc := SelfCheck(context.Background(), ReduceImage, ReduceCodePath, 2*time.Minute)

	if sc.OK {
		t.Fatal("self-check passed against a rootfs with no /bin — the verdict is unearned again")
	}
	if sc.TimedOut {
		t.Fatalf("self-check timed out instead of diagnosing: %+v", sc)
	}
	if !strings.Contains(sc.Detail, "could not start") {
		t.Errorf("failure not classified as a start failure: %q", sc.Detail)
	}
	if !strings.Contains(sc.Detail, "fork/exec") {
		t.Errorf("the guest's own diagnosis is missing from the detail: %q", sc.Detail)
	}
	if !sc.Kept {
		t.Error("failed probe workspace was not kept for inspection")
	}
	// Clean the kept workspace so the test leaves nothing behind.
	cleanupWorkspace(context.Background(), workspace.DefaultOptions(), selfCheckName)
}
