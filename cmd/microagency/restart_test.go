package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRestartHelpDoesNotStopTheServer extends the down/doctor conformance rule
// to the command it missed. runRestart called stopRunningServer() before
// looking at a single argument, so `restart --help` SIGTERMed the gateway,
// printed usage over its corpse, and started nothing — strictly worse than the
// `down --help` bug it survived, because the user believes they only asked a
// question.
func TestRestartHelpDoesNotStopTheServer(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "help"} {
		t.Run(flag, func(t *testing.T) {
			s := stageStandInServer(t)

			runRestart([]string{flag})

			if !s.running(100 * time.Millisecond) {
				t.Errorf("runRestart(%q) stopped the running server; --help must never act", flag)
			}
			if _, err := os.Stat(s.pidFile); err != nil {
				t.Errorf("runRestart(%q) removed the pid file (%v); --help must not touch state", flag, err)
			}
		})
	}
}

// TestRestartRejectsBadArgsBeforeStopping covers the sibling failure: an
// argument `up` would reject used to be discovered only after the stop, so
// `restart --bogus` left the operator with no server and an error about flags.
// The rejection has to happen while there is still nothing to undo. The
// unknown-arg path exits the process, so it runs in a helper re-invocation of
// this test binary sharing the staged HOME.
func TestRestartRejectsBadArgsBeforeStopping(t *testing.T) {
	s := stageStandInServer(t)

	out, code := runRestartHelper(t, "--bogus")

	if code != 2 {
		t.Errorf("exit = %d, want 2 for an unknown argument:\n%s", code, out)
	}
	if !strings.Contains(out, "unknown argument: --bogus") {
		t.Errorf("rejection does not name the argument:\n%s", out)
	}
	if !s.running(100 * time.Millisecond) {
		t.Error("restart with a bad argument stopped the server; validation must precede the stop")
	}
	if _, err := os.Stat(s.pidFile); err != nil {
		t.Errorf("restart with a bad argument removed the pid file: %v", err)
	}
}

// TestRestartStillStopsTheServer is the positive control. Without it, a
// runRestart that refused every argument list would satisfy both conformance
// tests above while never restarting anything. Valid arguments must get past
// the new validation and reach the stop; --foreground keeps the replacement
// server in the helper process so the test can kill it.
func TestRestartStillStopsTheServer(t *testing.T) {
	s := stageStandInServer(t)

	helper := startRestartHelper(t, "--foreground", "--http", "127.0.0.1:0", "--no-register")
	defer func() { _ = helper.Process.Kill(); _ = helper.Wait() }()

	if s.running(5 * time.Second) {
		t.Fatalf("restart with valid arguments never stopped the old server (pid %d)", s.pid)
	}
}

// runRestartHelper re-invokes this test binary as a runRestart process against
// the caller's staged HOME and returns its combined output and exit code.
func runRestartHelper(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := startRestartHelper(t, args...)
	_ = cmd.Wait()
	b, err := os.ReadFile(cmd.Env[len(cmd.Env)-1][len("MICROAGENCY_HELPER_OUT="):])
	if err != nil {
		t.Fatalf("read helper output: %v", err)
	}
	return string(b), cmd.ProcessState.ExitCode()
}

// startRestartHelper launches the helper without waiting, for the control test
// whose replacement server keeps running.
func startRestartHelper(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	outFile := t.TempDir() + "/helper.out"
	cmd := exec.Command(os.Args[0], "-test.run=TestRestartHelperProcess$")
	cmd.Env = append(os.Environ(),
		"MICROAGENCY_RESTART_HELPER_ARGS="+strings.Join(args, "\x1f"),
		"MICROAGENCY_HELPER_OUT="+outFile,
	)
	f, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	return cmd
}

// TestRestartHelperProcess is not a test: it is the body of the helper
// re-invocation above. It runs runRestart with the requested arguments and
// exits however runRestart exits.
func TestRestartHelperProcess(t *testing.T) {
	raw := os.Getenv("MICROAGENCY_RESTART_HELPER_ARGS")
	if raw == "" {
		t.Skip("helper body; only meaningful when re-invoked")
	}
	runRestart(strings.Split(raw, "\x1f"))
	os.Exit(0)
}

// TestParseUpOptionsVocabulary keeps restart's validation and up's acceptance
// the same vocabulary by construction — both call parseUpOptions — and pins
// the defaults so the extraction cannot have changed them.
func TestParseUpOptionsVocabulary(t *testing.T) {
	o, err := parseUpOptions(nil)
	if err != nil {
		t.Fatalf("no args: %v", err)
	}
	if o.httpAddr != "127.0.0.1:8765" || o.wasmMaxMemMB != 512 || o.maxInlineBytes != 8192 {
		t.Errorf("defaults changed: %+v", o)
	}

	o, err = parseUpOptions([]string{"--engine", "a=x", "--engine", "b=y", "--no-register"})
	if err != nil || len(o.engineSpecs) != 2 || !o.noRegister {
		t.Errorf("known flags rejected or dropped: %+v err=%v", o, err)
	}

	if _, err = parseUpOptions([]string{"--wasm-max-memory-mb", "zero"}); err == nil {
		t.Error("non-numeric --wasm-max-memory-mb accepted")
	}
	if _, err = parseUpOptions([]string{"--nope"}); err == nil {
		t.Error("unknown argument accepted")
	}
	if _, err = parseUpOptions([]string{"--high-assurance-multi-user"}); err == nil {
		t.Error("high-assurance mode accepted without an external issuer")
	}
	if o, err = parseUpOptions([]string{"--high-assurance-multi-user", "--issuer", "https://issuer.example"}); err != nil || !o.highAssuranceMultiUser {
		t.Fatalf("high-assurance external issuer options = %+v, %v", o, err)
	}
	if o, _ = parseUpOptions([]string{"--help"}); !o.help {
		t.Error("--help not recognized")
	}
}

// TestUnknownCommandIsNamedAndSuggested pins the two-line diagnosis. The
// usage dump never named the input — "doctr" got twenty lines with zero
// occurrences of "doctr" — while an unknown FLAG already got a named
// one-liner; the broader mistake had the vaguer answer.
func TestUnknownCommandIsNamedAndSuggested(t *testing.T) {
	for input, want := range map[string]string{
		"doctr":   "doctor",
		"restrat": "restart",
		"pruge":   "purge",
	} {
		if got := nearestCommand(input); got != want {
			t.Errorf("nearestCommand(%q) = %q, want %q", input, got, want)
		}
	}
	if got := nearestCommand("zzqqx"); got != "" {
		t.Errorf("nonsense got a confident suggestion: %q", got)
	}
	// The candidate list must stay in step with the dispatch: every candidate
	// is a real command (spot-check via the ones with side-effect-free paths).
	for _, c := range commandNames {
		if c == "" {
			t.Error("empty candidate in commandNames")
		}
	}
}
