package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runHelpHelper re-invokes this test binary as a full microagency dispatch
// with the given argv, returning stdout, stderr, and the exit code. Help
// behavior is a process-level contract (stream + exit code), so it has to be
// observed from outside the process.
func runHelpHelper(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelpHelperProcess$")
	cmd.Env = append(os.Environ(),
		"HOME="+t.TempDir(),
		"MICROAGENCY_HELP_HELPER=1",
		"MICROAGENCY_HELP_HELPER_ARGS="+strings.Join(args, "\x1f"),
	)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	return stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()
}

// TestHelpHelperProcess is the body of the re-invocation above, not a test.
func TestHelpHelperProcess(t *testing.T) {
	if os.Getenv("MICROAGENCY_HELP_HELPER") == "" {
		t.Skip("helper body; only meaningful when re-invoked")
	}
	os.Args = []string{"microagency"}
	if raw := os.Getenv("MICROAGENCY_HELP_HELPER_ARGS"); raw != "" {
		os.Args = append(os.Args, strings.Split(raw, "\x1f")...)
	}
	main()
	os.Exit(0)
}

// TestHelpIsOneContractEverywhere pins the property the surface used to lack:
// --help always explains, on stdout, exit 0, with nothing on stderr — for
// every command. Before this, help behaved three ways: purge/down/doctor
// answered (on stderr), up dumped the global usage, and hook called the
// question an error ("unknown hook \"--help\"", exit 2). A script cannot
// tell an answer from a complaint unless the stream and the exit code say
// which one it got.
func TestHelpIsOneContractEverywhere(t *testing.T) {
	commands := [][]string{
		{"help"},
		{"up", "--help"},
		{"down", "--help"},
		{"restart", "--help"},
		{"purge", "--help"},
		{"doctor", "--help"},
		{"hook", "--help"},
		{"mediation", "--help"},
		{"token", "--help"},
		{"token", "create", "--help"},
	}
	for _, argv := range commands {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			stdout, stderr, code := runHelpHelper(t, argv...)

			if code != 0 {
				t.Errorf("exit = %d, want 0: asking for help is not a mistake\nstderr:\n%s", code, stderr)
			}
			if !strings.Contains(stdout, "usage") {
				t.Errorf("help did not land on stdout:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			if stderr != "" {
				t.Errorf("help wrote to stderr:\n%s", stderr)
			}
		})
	}
}

// TestUpHelpIsUpsOwn pins the split that ended the last ambiguity: `up --help`
// answers with up's contract, not the global command list — which was
// byte-identical to what a typo produced, so the output could not say whether
// the user asked a question or made a mistake. The global list stays reachable
// as `microagency help`.
func TestUpHelpIsUpsOwn(t *testing.T) {
	stdout, _, _ := runHelpHelper(t, "up", "--help")
	if !strings.Contains(stdout, "usage: microagency up [flags]") {
		t.Errorf("up --help lost its own usage line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--http <addr>") {
		t.Errorf("up --help lost the flag list:\n%s", stdout)
	}
	if strings.Contains(stdout, "microagency purge") {
		t.Errorf("up --help still dumps the global command list:\n%s", stdout)
	}

	stdout, _, _ = runHelpHelper(t, "help")
	for _, cmd := range []string{"microagency up", "microagency down", "microagency doctor", "microagency hook", "microagency mediation", "microagency token"} {
		if !strings.Contains(stdout, cmd) {
			t.Errorf("global help lost %q:\n%s", cmd, stdout)
		}
	}
}

// TestMistakesStayOnStderrExitTwo is the control: the failure paths that share
// text with help (no arguments, unknown command) must keep the failure
// contract, or the stream/exit distinction above means nothing.
func TestMistakesStayOnStderrExitTwo(t *testing.T) {
	for _, argv := range [][]string{{}, {"doctr"}, {"hook", "bogus"}, {"token", "bogus"}} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			stdout, stderr, code := runHelpHelper(t, argv...)

			if code != 2 {
				t.Errorf("exit = %d, want 2 for a mistake", code)
			}
			if stderr == "" {
				t.Error("mistake produced nothing on stderr")
			}
			if stdout != "" {
				t.Errorf("mistake wrote to stdout, where scripts read answers:\n%s", stdout)
			}
		})
	}
}
