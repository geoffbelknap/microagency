package main

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// TestRunningPID covers the single-instance guard: it must report a live daemon,
// ignore (and clean up) a stale or garbage pid file, and report nothing when no
// file exists. This is what stops two instances from sharing one OAuth token
// store and rotating each other's refresh tokens into "reuse detected".
func TestRunningPID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(microagencyDir(), 0o700); err != nil {
		t.Fatal(err)
	}

	// No pid file → not running.
	if got := runningPID(); got != 0 {
		t.Fatalf("no pid file: runningPID = %d, want 0", got)
	}

	// A live pid (this test process) → reported.
	writePID(t, os.Getpid())
	if got := runningPID(); got != os.Getpid() {
		t.Fatalf("live pid: runningPID = %d, want %d", got, os.Getpid())
	}

	// A stale pid (a process that has exited) → 0, and the file is cleaned up.
	writePID(t, reapedPID(t))
	if got := runningPID(); got != 0 {
		t.Fatalf("stale pid: runningPID = %d, want 0", got)
	}
	if _, err := os.Stat(pidPath()); !os.IsNotExist(err) {
		t.Fatalf("stale pid file was not removed (stat err = %v)", err)
	}

	// A garbage pid file → 0, and cleaned up.
	if err := os.WriteFile(pidPath(), []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runningPID(); got != 0 {
		t.Fatalf("garbage pid: runningPID = %d, want 0", got)
	}
}

func writePID(t *testing.T, pid int) {
	t.Helper()
	if err := os.WriteFile(pidPath(), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// reapedPID starts a trivial process, waits for it to exit, and returns its now-
// dead pid — a pid that is guaranteed not to be running for the test's duration.
func reapedPID(t *testing.T) int {
	t.Helper()
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no `true` binary to produce a reaped pid")
	}
	c := exec.Command(bin)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	_ = c.Wait()
	return pid
}
