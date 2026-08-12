package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"microagency/internal/baomanager"
	"microagency/internal/mcp"
	"microagency/internal/sandbox"
	"microagency/internal/secretstore"
)

// runDoctor reports the health of the things `up` depends on — the wasm engines
// (always available, in-process) and the microVM runtime (the code substrate) —
// so an unhealthy install is visible up front with a fix, not a cryptic failure
// mid-run.
func runDoctor(args []string) {
	// --help must never act. doctor is read-only, so running it on --help was
	// harmless, but the same discarded-argument bug made `down --help` stop
	// the server; both commands now parse before doing anything.
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stdout, "usage: microagency doctor")
			fmt.Fprintln(os.Stdout, "  check runtime + engine health (server, secret store, query engines,")
			fmt.Fprintln(os.Stdout, "  microVM runtime, enforcement-hygiene bypasses)")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", a)
			os.Exit(2)
		}
	}

	out := os.Stderr
	fmt.Fprintln(out, "microagency doctor")

	// The two questions a first-run operator most often has: is the server up, and
	// where do my credentials actually live.
	pid := runningPID()
	if pid != 0 {
		fmt.Fprintf(out, "\n  server            ✓ running (pid %d)\n", pid)
	} else {
		fmt.Fprintf(out, "\n  server            ✗ not running — start it with `microagency up`\n")
	}
	reportSecretPosture(out)
	reportAuthPosture(out)

	// query engines — the WebAssembly modules that run reduce's declarative
	// query path (filter / count / extract) in-process, no VM.
	var names []string
	for n := range bundledEngines() {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(out, "\n  query engines     %s\n", join(names))
	fmt.Fprintln(out, "                    (WebAssembly, in-process; always available — reduce uses these for query work, no VM)")

	// microVM runtime — the code substrate: reduce(code). A passing line
	// carries no path — the path is remediation detail, and it returns on the
	// failing line where someone actually needs to know where the lookup went.
	h := sandbox.InspectRuntime(context.Background())
	fmt.Fprintf(out, "\n  microVM runtime   backend=%s arch=%s\n", dash(h.Backend), dash(h.Architecture))
	fmt.Fprintf(out, "    virtualization  %s\n", mark(h.Virtualization))
	fmt.Fprintf(out, "    supervisor      %s%s\n", mark(h.SupervisorReady), pathWhenMissing(h.SupervisorReady, h.SupervisorPath))
	fmt.Fprintf(out, "    guest-init      %s%s\n", mark(h.GuestInitReady), pathWhenMissing(h.GuestInitReady, h.GuestInitPath))
	if runtime.GOOS == "linux" {
		fmt.Fprintf(out, "    kvm / vsock     %s / %s\n", mark(h.KVM), mark(h.Vsock))
	}
	if h.Version != "" {
		fmt.Fprintf(out, "    version         %s\n", h.Version)
	}
	if h.Issues != "" {
		fmt.Fprintf(out, "    issues          %s\n", h.Issues)
	}
	if h.ProbeError != "" {
		fmt.Fprintf(out, "    probe error     %s\n", h.ProbeError)
	}

	// Enforcement hygiene: warn about any upstream reachable BOTH through microagency
	// AND directly from the local client (a back door around the governed well).
	bypassWarnings := reportBypasses(out)

	fmt.Fprintln(out)
	runtimeHealthy := false
	var runtimeClause string
	switch {
	case h.Usable():
		// Prerequisites alone earned a healthy verdict once, and it was false
		// for two days: every prerequisite present, every reduce failing on a
		// poisoned rootfs. The claim is now gated on the whole path it
		// promises — boot the real image, run real code, see the output come
		// back — per the verdict rule that a capability claim covers every
		// step or is not made.
		fmt.Fprint(out, "    end-to-end      running a probe reduce(code)…")
		sc := sandbox.SelfCheck(context.Background(), sandbox.ReduceImage, sandbox.ReduceCodePath, 30*time.Second)
		switch {
		case sc.OK:
			fmt.Fprintln(out, " ok")
			runtimeHealthy = true
			runtimeClause = "reduce(code) is verified end to end (booted and ran)"
		case sc.TimedOut:
			fmt.Fprintln(out, " timed out")
			fmt.Fprintln(out, "  ⚠ prerequisites are present, but the end-to-end probe did not finish in 30s.")
			fmt.Fprintln(out, "    A cold image cache pulls the workload image on first use, which can take")
			fmt.Fprintln(out, "    longer than the probe allows. Run a reduce(code=…) once to confirm and warm it.")
			runtimeClause = "the end-to-end reduce(code) probe timed out (likely a cold image cache)"
		default:
			fmt.Fprintln(out, " FAILED")
			fmt.Fprintf(out, "  ✗ prerequisites are present but reduce(code) fails end to end: %s\n", sc.Detail)
			if sc.Kept {
				fmt.Fprintln(out, "    The failed workspace is kept for inspection: `microagent result m2-doctor-selfcheck`,")
				fmt.Fprintln(out, "    `microagent logs m2-doctor-selfcheck`.")
			}
			runtimeClause = "reduce(code) fails end to end; the query engines work regardless"
		}
	case h.Unknown():
		fmt.Fprintln(out, "  ⚠ could not establish microVM runtime readiness — it may still be fine.")
		fmt.Fprintln(out, "    Verify with a quick reduce(code=…) (it reads /app/input).")
		runtimeClause = "microVM runtime readiness could not be established; the query engines work regardless"
	default:
		fmt.Fprintln(out, "  ✗ microVM runtime is NOT usable — reduce(code) will fail.")
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
		runtimeClause = "reduce(code) will fail until the microVM runtime is installed; the query engines work regardless"
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, closingVerdict(pid != 0, bypassWarnings, runtimeHealthy, runtimeClause))
}

func reportAuthPosture(out io.Writer) {
	reportAuthPostureAt(out, authPosturePath())
}

func reportAuthPostureAt(out io.Writer, path string) {
	posture, err := readAuthPosture(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(out, "  public auth      ⚠ unreadable posture: %v\n", err)
		}
		return
	}
	switch posture.Mode {
	case "oauth-tunnel":
		fmt.Fprintf(out, "  public auth      built-in OAuth (%s)\n", dash(posture.Tunnel))
		fmt.Fprintf(out, "    issuer          %s\n", dash(posture.Issuer))
		fmt.Fprintf(out, "    resource        %s\n", dash(posture.Resource))
		fmt.Fprintf(out, "    audience        %s\n", dash(posture.Audience))
		fmt.Fprintln(out, "    consent         loopback operator listener")
	case "oauth-external":
		fmt.Fprintf(out, "  public auth      external OAuth (issuer %s)\n", dash(posture.Issuer))
		if posture.Resource != "" {
			fmt.Fprintf(out, "    resource        %s\n", posture.Resource)
		}
		if posture.Audience != "" {
			fmt.Fprintf(out, "    audience        %s\n", posture.Audience)
		}
	case "bearer":
		fmt.Fprintln(out, "  public auth      static bearer compatibility mode")
	case "oauth-local":
		fmt.Fprintln(out, "  public auth      local built-in OAuth")
	default:
		fmt.Fprintf(out, "  public auth      ⚠ unknown posture %q\n", posture.Mode)
	}
}

// closingVerdict composes the page's rollup sentence, gated on everything the
// page reported: the server, the bypass check, and the runtime clause from the
// end-to-end probe. It exists so a dead server can never sit above an ending
// that reads green — the closing sentence answers for the whole page or it
// does not claim readiness.
func closingVerdict(serverUp bool, bypassWarnings int, runtimeHealthy bool, runtimeClause string) string {
	switch {
	case !serverUp:
		return fmt.Sprintf("The gateway is not ready: the server is not running (start it with `microagency up`), and %s.", runtimeClause)
	case bypassWarnings == 1:
		return fmt.Sprintf("The server is running and %s, but one upstream is reachable around the gateway — remove the direct entry above so every call is governed and audited.", runtimeClause)
	case bypassWarnings > 1:
		return fmt.Sprintf("The server is running and %s, but %d upstreams are reachable around the gateway — remove the direct entries above so every call is governed and audited.", runtimeClause, bypassWarnings)
	case runtimeHealthy:
		return fmt.Sprintf("microagency is ready: the server is running, and %s.", runtimeClause)
	default:
		return fmt.Sprintf("The server is running, but %s.", runtimeClause)
	}
}

// pathWhenMissing returns the remediation detail for a failed lookup line: the
// path the lookup went through. Healthy lines stay path-free.
func pathWhenMissing(ok bool, path string) string {
	if ok || strings.TrimSpace(path) == "" {
		return ""
	}
	return "  not found (expected at " + path + ")"
}

// reportBypasses prints the enforcement-hygiene bypass check: for each upstream
// microagency proxies, it warns when the SAME MCP server URL is also configured as a
// DIRECT MCP server in the local client config — a connection the client can use
// without going through microagency, i.e. a back door around the governed well.
//
// Advisory only: it reads config, never writes it, and it can only see LOCAL client
// config on this machine. A separate or remote client holding its own token to the
// same upstream is invisible here — this raises hygiene, it does not enforce.
func reportBypasses(out *os.File) int {
	upstreams := mcp.ReadUpstreamRegistrations(microagencyDir())
	if len(upstreams) == 0 {
		// Not applicable is a rendered state: an absent line is
		// indistinguishable from a check that was forgotten.
		fmt.Fprintln(out, "\n  bypass check      — not applicable (no upstreams proxied yet)")
		return 0
	}
	warnings := detectBypasses(upstreams, gatherClientServers(clientConfigPaths()))
	fmt.Fprintf(out, "\n  bypass check      %s\n", bypassStatus(len(warnings)))
	if len(warnings) == 0 {
		fmt.Fprintln(out, "                    (no upstream is also a DIRECT MCP server in the local client config;")
		fmt.Fprintln(out, "                     note: only local config is visible — a separate/remote client isn't)")
		return 0
	}
	for _, w := range warnings {
		fmt.Fprintf(out, "    ⚠ upstream %q (%s) is ALSO directly connected as %q in %s\n",
			w.UpstreamName, w.URL, w.ClientName, w.ConfigPath)
		fmt.Fprintln(out, "      that's a back door around microagency — remove the direct entry so every call goes through the gateway.")
	}
	return len(warnings)
}

// reportSecretPosture tells the operator where upstream credentials are held —
// the posture `up` selects — so "where are my secrets" has an answer up front.
func reportSecretPosture(out io.Writer) {
	reportSecretPostureWith(out, os.Getenv, baomanager.Available, microagencyDir())
}

func reportSecretPostureWith(out io.Writer, getenv func(string) string, baoAvailable func() bool, stateDir string) {
	addr, token := getenv("VAULT_ADDR"), getenv("VAULT_TOKEN")
	switch {
	case addr != "" && token == "":
		fmt.Fprintln(out, "  secret store      ✗ VAULT_ADDR is set but VAULT_TOKEN is missing")
		fmt.Fprintln(out, "                    (startup will fail closed; provide the token or unset VAULT_ADDR)")
	case addr == "" && token != "":
		fmt.Fprintln(out, "  secret store      ✗ VAULT_TOKEN is set but VAULT_ADDR is missing")
		fmt.Fprintln(out, "                    (startup will fail closed; provide the address or unset VAULT_TOKEN)")
	case addr != "":
		fmt.Fprintf(out, "  secret store      ✓ external Vault/OpenBao (VAULT_ADDR=%s)\n", addr)
	case baoAvailable():
		fmt.Fprintln(out, "  secret store      ✓ managed OpenBao (loopback 127.0.0.1:8200)")
	case strings.TrimSpace(getenv(secretstore.FileKeyEnv)) != "":
		keyPath := strings.TrimSpace(getenv(secretstore.FileKeyEnv))
		key, err := secretstore.LoadFileKey(stateDir, keyPath)
		if err == nil {
			_, err = secretstore.InspectFile(filepath.Join(stateDir, "upstream-tokens.json"), key)
		}
		if err != nil {
			fmt.Fprintf(out, "  secret store      ✗ encrypted file store is misconfigured: %v\n", err)
			fmt.Fprintln(out, "                    (startup will fail closed; fix or unset MICROAGENCY_SECRET_KEY_FILE)")
			return
		}
		fmt.Fprintln(out, "  secret store      ✓ AES-256-GCM file store with a separately supplied key")
		fmt.Fprintf(out, "                    (key: %s; credentials: %s)\n", keyPath, filepath.Join(stateDir, "upstream-tokens.json"))
	default:
		kind, err := secretstore.InspectFile(filepath.Join(stateDir, "upstream-tokens.json"), nil)
		if errors.Is(err, secretstore.ErrKeyRequired) || kind == "encrypted-file" {
			fmt.Fprintln(out, "  secret store      ✗ encrypted file store exists but MICROAGENCY_SECRET_KEY_FILE is not configured")
			fmt.Fprintln(out, "                    (startup will fail closed; restore the separately held key setting)")
			return
		}
		if err != nil {
			fmt.Fprintf(out, "  secret store      ✗ local credential store cannot be read: %v\n", err)
			fmt.Fprintln(out, "                    (startup will fail closed; repair or restore the credential store)")
			return
		}
		fmt.Fprintln(out, "  secret store      ⚠ degraded mode-0600 plaintext file under ~/.microagency")
		fmt.Fprintln(out, "                    (credentials stay out of the agent, but are not encrypted at rest;")
		fmt.Fprintln(out, "                     install OpenBao or configure MICROAGENCY_SECRET_KEY_FILE)")
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
