package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// standInServer is a real sleeping process recorded as the running server, plus
// a channel closed once it has exited and been reaped. Reaping matters: a
// SIGTERMed child stays in the process table as a zombie until its parent waits
// on it, and kill(pid, 0) still succeeds against a zombie — so process death
// has to be observed through Wait, not through a liveness probe.
type standInServer struct {
	pid     int
	pidFile string
	exited  chan struct{}
}

// running reports whether the stand-in is still alive, allowing grace for the
// asynchronous delivery of a signal that should kill it.
func (s *standInServer) running(grace time.Duration) bool {
	select {
	case <-s.exited:
		return false
	case <-time.After(grace):
		return true
	}
}

// stageStandInServer points microagencyDir() at a temp HOME and records a live
// child process as the running server, so runDown has something genuine to
// stop. Without a live process runningPID() returns 0 and every assertion below
// would pass vacuously.
func stageStandInServer(t *testing.T) *standInServer {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".microagency")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("start stand-in server process: %v", err)
	}

	s := &standInServer{
		pid:     child.Process.Pid,
		pidFile: filepath.Join(dir, "microagency.pid"),
		exited:  make(chan struct{}),
	}
	go func() {
		_ = child.Wait() // reap, then report the exit
		close(s.exited)
	}()
	t.Cleanup(func() {
		_ = child.Process.Kill()
		<-s.exited
	})

	if err := os.WriteFile(s.pidFile, []byte(strconv.Itoa(s.pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runningPID(); got != s.pid {
		t.Fatalf("runningPID() = %d, want the staged child %d", got, s.pid)
	}
	return s
}

// TestDownHelpDoesNotStopTheServer is the conformance test for the rule that a
// flag meaning "explain yourself" never acts. runDown used to receive no
// arguments at all, so `microagency down --help` fell straight through to the
// shutdown path: a user asking for help stopped their own gateway and
// disconnected every MCP client attached to it.
func TestDownHelpDoesNotStopTheServer(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "help"} {
		t.Run(flag, func(t *testing.T) {
			s := stageStandInServer(t)

			runDown([]string{flag})

			if !s.running(100 * time.Millisecond) {
				t.Errorf("runDown(%q) stopped the running server; --help must never act", flag)
			}
			if _, err := os.Stat(s.pidFile); err != nil {
				t.Errorf("runDown(%q) removed the pid file (%v); --help must not touch state", flag, err)
			}
		})
	}
}

// TestDownStopsTheServer is the positive control for the test above. Without
// it, a runDown that returned early for every input would satisfy the --help
// assertions while being entirely broken.
func TestDownStopsTheServer(t *testing.T) {
	s := stageStandInServer(t)

	runDown(nil)

	if s.running(2 * time.Second) {
		t.Errorf("runDown(nil) left the server running (pid %d); it must stop it", s.pid)
	}
	if _, err := os.Stat(s.pidFile); !os.IsNotExist(err) {
		t.Errorf("runDown(nil) left the pid file in place (err=%v); it must remove it", err)
	}
}

// TestDoctorHelpReturnsWithoutProbing covers the read-only half of the same
// bug: runDoctor also discarded its arguments. It has no destructive side
// effect, so the observable is that --help returns instead of running the full
// host probe, which shells out to the microagent runtime and takes seconds.
func TestDoctorHelpReturnsWithoutProbing(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "help"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())

			done := make(chan struct{})
			go func() {
				defer close(done)
				runDoctor([]string{flag})
			}()

			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("runDoctor(%q) did not return promptly; --help must not run the host probe", flag)
			}
		})
	}
}
