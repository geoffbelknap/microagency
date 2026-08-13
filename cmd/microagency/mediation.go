package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/geoffbelknap/microagent/pkg/workspace"

	"microagency/internal/mcp"
	"microagency/internal/mediation"
)

func runMediation(args []string) {
	if len(args) == 0 {
		mediationHelp(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "-h", "--help", "help":
		mediationHelp(os.Stdout)
	case "enforce":
		runMediationEnforce(args[1:])
	case "status":
		runMediationStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown mediation command %q (want enforce|status)\n", args[0])
		os.Exit(2)
	}
}

func mediationHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency mediation enforce --workspace <name> --gateway <url> [--state-dir <dir>]")
	fmt.Fprintln(w, "  microagency mediation status [--json]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  enforce binds a stopped microagent workspace to gateway-only locked egress.")
	fmt.Fprintln(w, "  Local-host and unbound clients remain advisory/uncovered.")
}

func runMediationEnforce(args []string) {
	var name, gatewayURL, stateDir string
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "-h" || args[i] == "--help" || args[i] == "help"):
			mediationHelp(os.Stdout)
			return
		case args[i] == "--workspace" && i+1 < len(args):
			name = args[i+1]
			i++
		case args[i] == "--gateway" && i+1 < len(args):
			gatewayURL = args[i+1]
			i++
		case args[i] == "--state-dir" && i+1 < len(args):
			stateDir = args[i+1]
			i++
		default:
			fmt.Fprintf(os.Stderr, "unknown or incomplete argument: %s\n", args[i])
			os.Exit(2)
		}
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(gatewayURL) == "" {
		fmt.Fprintln(os.Stderr, "--workspace and --gateway are required")
		os.Exit(2)
	}
	if pid := runningPID(); pid != 0 {
		fmt.Fprintf(os.Stderr, "microagency is running (pid %d); run `microagency down` before changing the enforcement binding\n", pid)
		os.Exit(1)
	}
	if stateDir == "" {
		stateDir = workspace.DefaultOptions().StateDir
	}

	// Refuse the unsafe shared-host topology before changing the workspace.
	// Registration persistence is read while the gateway is stopped, so this
	// check and the subsequent binding publication cannot race an add/rebind.
	probe, err := mediation.NewBinding(stateDir, name, gatewayURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "microagency mediation:", err)
		os.Exit(1)
	}
	for _, up := range mcp.ReadUpstreamRegistrations(microagencyDir()) {
		if err := mediation.ValidateUpstream(probe, up.URL); err != nil {
			fmt.Fprintf(os.Stderr, "microagency mediation: existing upstream %q is incompatible: %v\n", up.Name, err)
			os.Exit(1)
		}
	}
	binding, err := mediation.Enforce(microagencyDir(), stateDir, name, gatewayURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "microagency mediation:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "enforced workspace %s: only %s is reachable directly\n", binding.Workspace, binding.GatewayHost)
	fmt.Fprintln(os.Stdout, "Start the workspace normally; use `microagency doctor` to verify the active posture.")
}

func runMediationStatus(args []string) {
	jsonOutput := false
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		case "-h", "--help", "help":
			mediationHelp(os.Stdout)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", arg)
			os.Exit(2)
		}
	}
	status := mediation.Inspect(microagencyDir())
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(status)
		return
	}
	fmt.Fprintf(os.Stdout, "%s: %s\n", status.Mode, status.State)
	if status.Workspace != "" {
		fmt.Fprintf(os.Stdout, "  workspace  %s (%s)\n", status.Workspace, status.WorkspaceState)
		fmt.Fprintf(os.Stdout, "  gateway    %s\n", status.GatewayURL)
	}
	if status.Reason != "" {
		fmt.Fprintf(os.Stdout, "  %s\n", status.Reason)
	}
	if len(status.Uncovered) > 0 {
		fmt.Fprintf(os.Stdout, "  uncovered: %s\n", strings.Join(status.Uncovered, ", "))
	}
}
