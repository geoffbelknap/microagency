package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"microagency/internal/baomanager"
	"microagency/internal/mcp"
	"microagency/internal/sandbox"
)

// runDoctor reports the health of the things `up` depends on — the wasm engines
// (always available, in-process) and the microVM runtime (the code substrate) —
// so an unhealthy install is visible up front with a fix, not a cryptic failure
// mid-run.
func runDoctor() {
	out := os.Stderr
	fmt.Fprintln(out, "microagency doctor")

	// The two questions a first-run operator most often has: is the server up, and
	// where do my credentials actually live.
	if pid := runningPID(); pid != 0 {
		fmt.Fprintf(out, "\n  server            ✓ running (pid %d)\n", pid)
	} else {
		fmt.Fprintf(out, "\n  server            ✗ not running — start it with `microagency up`\n")
	}
	reportSecretPosture(out)

	// query engines — the WebAssembly modules that run reduce's declarative
	// query path (filter / count / extract) in-process, no VM.
	var names []string
	for n := range bundledEngines() {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(out, "\n  query engines     %s\n", join(names))
	fmt.Fprintln(out, "                    (WebAssembly, in-process; always available — reduce uses these for query work, no VM)")

	// microVM runtime — the code substrate: reduce(code).
	h := sandbox.InspectRuntime(context.Background())
	fmt.Fprintf(out, "\n  microVM runtime   backend=%s arch=%s\n", dash(h.Backend), dash(h.Architecture))
	fmt.Fprintf(out, "    virtualization  %s\n", mark(h.Virtualization))
	fmt.Fprintf(out, "    supervisor      %s  %s\n", mark(h.SupervisorReady), h.SupervisorPath)
	fmt.Fprintf(out, "    guest-init      %s  %s\n", mark(h.GuestInitReady), h.GuestInitPath)
	if runtime.GOOS == "linux" {
		fmt.Fprintf(out, "    kvm / vsock     %s / %s\n", mark(h.KVM), mark(h.Vsock))
	}
	if h.Version != "" {
		fmt.Fprintf(out, "    version         %s\n", h.Version)
	}
	if h.ProbeError != "" {
		fmt.Fprintf(out, "    probe error     %s\n", h.ProbeError)
	}

	// Enforcement hygiene: warn about any upstream reachable BOTH through microagency
	// AND directly from the local client (a back door around the governed well).
	reportBypasses(out)

	fmt.Fprintln(out)
	if h.Usable() {
		fmt.Fprintln(out, "  ✓ microVM runtime is healthy — reduce(code) will work.")
		return
	}
	if !h.Probed() {
		fmt.Fprintln(out, "  ⚠ could not probe the microVM runtime — it may still be fine.")
		fmt.Fprintln(out, "    Verify with a quick reduce(code=…) (it reads /app/input).")
		fmt.Fprintln(out, "    The query engines above work regardless.")
		return
	}
	fmt.Fprintln(out, "  ✗ microVM runtime is NOT usable — reduce(code) will fail.")
	fmt.Fprintln(out, "    The query engines above still work without it (no VM needed).")
	fmt.Fprintln(out, "    Install the microagent runtime:")
	fmt.Fprintln(out, "      brew install geoffbelknap/tap/microagent")
	fmt.Fprintln(out, "    or from a microagent source checkout:")
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(out, "      make signed-supervisor && make install")
		fmt.Fprintln(out, "      (macOS uses Apple Virtualization; the supervisor must be code-signed)")
	} else {
		fmt.Fprintln(out, "      make install")
	}
	fmt.Fprintln(out, "    Then `microagency doctor` again — microagency finds the binaries via the")
	fmt.Fprintln(out, "    installed `microagent` on PATH (it does not manage them itself).")
}

// reportBypasses prints the enforcement-hygiene bypass check: for each upstream
// microagency proxies, it warns when the SAME MCP server URL is also configured as a
// DIRECT MCP server in the local client config — a connection the client can use
// without going through microagency, i.e. a back door around the governed well.
//
// Advisory only: it reads config, never writes it, and it can only see LOCAL client
// config on this machine. A separate or remote client holding its own token to the
// same upstream is invisible here — this raises hygiene, it does not enforce.
func reportBypasses(out *os.File) {
	upstreams := mcp.ReadUpstreamRegistrations(microagencyDir())
	if len(upstreams) == 0 {
		return // nothing proxied yet — nothing to bypass
	}
	warnings := detectBypasses(upstreams, gatherClientServers(clientConfigPaths()))
	fmt.Fprintf(out, "\n  bypass check      %s\n", bypassStatus(len(warnings)))
	if len(warnings) == 0 {
		fmt.Fprintln(out, "                    (no upstream is also a DIRECT MCP server in the local client config;")
		fmt.Fprintln(out, "                     note: only local config is visible — a separate/remote client isn't)")
		return
	}
	for _, w := range warnings {
		fmt.Fprintf(out, "    ⚠ upstream %q (%s) is ALSO directly connected as %q in %s\n",
			w.UpstreamName, w.URL, w.ClientName, w.ConfigPath)
		fmt.Fprintln(out, "      that's a back door around microagency — remove the direct entry so every call goes through the gateway.")
	}
}

// reportSecretPosture tells the operator where upstream credentials are held —
// the posture `up` selects — so "where are my secrets" has an answer up front.
func reportSecretPosture(out io.Writer) {
	switch {
	case os.Getenv("VAULT_ADDR") != "":
		fmt.Fprintf(out, "  secret store      ✓ external Vault/OpenBao (VAULT_ADDR=%s)\n", os.Getenv("VAULT_ADDR"))
	case baomanager.Available():
		fmt.Fprintln(out, "  secret store      ✓ managed OpenBao (loopback 127.0.0.1:8200)")
	default:
		fmt.Fprintln(out, "  secret store      ⚠ encrypted file store under ~/.microagency")
		fmt.Fprintln(out, "                    (no OpenBao/Vault found — fine for single-user; install openbao or set VAULT_ADDR for hosted/multi-user)")
	}
}

// bypassStatus renders the one-line status marker for the bypass check.
func bypassStatus(n int) string {
	if n == 0 {
		return "✓ no direct back doors in local client config"
	}
	if n == 1 {
		return "⚠ 1 upstream also reachable directly (back door)"
	}
	return fmt.Sprintf("⚠ %d upstreams also reachable directly (back doors)", n)
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func join(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
