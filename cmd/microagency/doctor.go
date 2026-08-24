package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"microagency/internal/auth"
	"microagency/internal/mcp"
	"microagency/internal/mediation"
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
			fmt.Fprintln(os.Stdout, "  check runtime + engine health (server, secret store, public auth + tunnel,")
			fmt.Fprintln(os.Stdout, "  delegated connections, query engines, microVM runtime, enforcement-hygiene bypasses)")
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
	reportDelegatedConnections(out)
	reportPrivateDestinations(out)
	tunnelOK, tunnelClause := reportTunnelHealth(out, pid != 0)

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
	mediationReady, mediationClause := reportMediation(out, mediation.Inspect(microagencyDir()))

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
	fmt.Fprintln(out, closingVerdict(pid != 0, bypassWarnings, runtimeHealthy, runtimeClause, mediationReady, mediationClause, tunnelOK, tunnelClause))
}

func reportAuthPosture(out io.Writer) {
	reportAuthPostureAt(out, authPosturePath(), optedUpConnections(mcp.ReadUpstreamRegistrations(microagencyDir())), ssoAudienceRules("").Summary())
}

func reportDelegatedConnections(out io.Writer) {
	reportDelegatedConnectionsAt(out, microagencyDir(), authPosturePath())
}

// reportPrivateDestinations lists connections the operator declared reachable at
// a private address. Reaching inside the deployment's own network is authority
// worth seeing in the posture, so it is stated rather than left silent. Nothing
// is printed when no connection carries the declaration.
func reportPrivateDestinations(out io.Writer) {
	reportPrivateDestinationsAt(out, microagencyDir())
}

func reportPrivateDestinationsAt(out io.Writer, stateDir string) {
	var private []mcp.UpstreamRegistration
	for _, reg := range mcp.ReadUpstreamRegistrations(stateDir) {
		if reg.PrivateDestination {
			private = append(private, reg)
		}
	}
	if len(private) == 0 {
		return
	}
	fmt.Fprintln(out, "  private upstreams operator-declared endpoints inside this deployment's network")
	for _, reg := range private {
		fmt.Fprintf(out, "    %-15s %s\n", reg.Name, reg.URL)
	}
	fmt.Fprintln(out, "                    (self-service connections can never reach a private address;")
	fmt.Fprintln(out, "                     cloud-metadata addresses stay refused for these too)")
}

// reportDelegatedConnectionsAt renders each delegated (google-dwd) connection
// and the two prerequisites every delegated call needs: the service-account
// key in the secret store, and federated sign-in recording callers' verified
// emails. Rendered only when a delegated connection exists; a secret store
// that cannot be opened reports the key as unverified, never as present.
func reportDelegatedConnectionsAt(out io.Writer, stateDir, posturePath string) {
	var delegated []mcp.UpstreamRegistration
	for _, reg := range mcp.ReadUpstreamRegistrations(stateDir) {
		if reg.Strategy == mcp.StrategyGoogleDWD {
			delegated = append(delegated, reg)
		}
	}
	if len(delegated) == 0 {
		return
	}
	fmt.Fprintln(out, "  delegated access  per-caller upstream identity (google-dwd)")
	// AllowPlaintext here is a read: doctor inspects whatever store already
	// exists to answer "is the key present". The opt-in gates a gateway that
	// would PERSIST credentials in the clear, and refusing to look would only
	// cost this check its answer.
	store, storeErr := secretstore.Open(stateDir, os.Getenv, secretstore.Options{AllowPlaintext: true})
	for _, reg := range delegated {
		email := ""
		scopes := 0
		if reg.Delegation != nil {
			email, scopes = reg.Delegation.ClientEmail, len(reg.Delegation.Scopes)
		}
		switch {
		case storeErr != nil:
			fmt.Fprintf(out, "    %-15s ⚠ key unverified — the secret store could not be opened: %v\n", reg.Name, storeErr)
		default:
			if _, err := store.Load(context.Background(), mcp.DelegationKeyKey(reg.Name)); err != nil {
				fmt.Fprintf(out, "    %-15s ✗ service-account key missing — delegated calls will fail;\n", reg.Name)
				fmt.Fprintf(out, "                    re-add it: POST /admin/upstreams/%s/delegation with service_account_key\n", reg.Name)
			} else {
				fmt.Fprintf(out, "    %-15s ✓ key present (acting service account %s, %d scopes)\n", reg.Name, dash(email), scopes)
			}
		}
	}
	posture, err := readAuthPosture(posturePath)
	if err == nil && posture.SSOIssuer != "" {
		fmt.Fprintf(out, "    email mapping   ✓ federated sign-in (%s) records callers' verified emails\n", posture.SSOIssuer)
	} else {
		fmt.Fprintln(out, "    email mapping   ✗ no federated sign-in — no caller has a provider-verified email, so")
		fmt.Fprintln(out, "                    every delegated call will refuse; start with --sso-issuer to enable it")
	}
}

// optedUpConnections returns the names of persisted connections opted up to
// full audit argument capture, sorted, for the posture disclosure below.
func optedUpConnections(regs []mcp.UpstreamRegistration) []string {
	var names []string
	for _, reg := range regs {
		if reg.AuditFullArgs {
			names = append(names, reg.Name)
		}
	}
	sort.Strings(names)
	return names
}

func reportAuthPostureAt(out io.Writer, path string, optedUp []string, audienceRules auth.AudienceSummary) {
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
		reportTunnelStability(out, posture)
		if posture.SSOIssuer != "" {
			reportFederatedSignIn(out, posture, optedUp, audienceRules)
			break
		}
		fmt.Fprintln(out, "    consent         loopback operator listener")
		fmt.Fprintln(out, "    posture         single-user (--single-user) — every remote client authenticates as the")
		fmt.Fprintln(out, "                    local operator; several people need federated sign-in (--sso-issuer)")
		fmt.Fprintln(out, "                    or an external issuer (--issuer)")
	case "oauth-external":
		fmt.Fprintf(out, "  public auth      external OAuth (issuer %s)\n", dash(posture.Issuer))
		if posture.Resource != "" {
			fmt.Fprintf(out, "    resource        %s\n", posture.Resource)
		}
		if posture.Audience != "" {
			fmt.Fprintf(out, "    audience        %s\n", posture.Audience)
		}
		reportTunnelStability(out, posture)
		// Multi-user deployment: say what the shared audit log retains. The
		// default keeps callers' argument values out of the operator-readable
		// file; a per-connection opt-up widens that, so it never passes silently.
		if len(optedUp) == 0 {
			fmt.Fprintln(out, "    audit capture   argument structure + digest (callers' argument values stay out of the shared log)")
		} else {
			fmt.Fprintf(out, "    audit capture   ⚠ FULL arguments for: %s (operator opt-up; other connections record structure + digest)\n", strings.Join(optedUp, ", "))
		}
	case "bearer":
		fmt.Fprintln(out, "  public auth      static bearer compatibility mode")
	case "oauth-local":
		fmt.Fprintln(out, "  public auth      local built-in OAuth")
		if posture.SSOIssuer != "" {
			reportFederatedSignIn(out, posture, optedUp, audienceRules)
		}
	default:
		fmt.Fprintf(out, "  public auth      ⚠ unknown posture %q\n", posture.Mode)
	}
	// A lifted loopback floor never passes silently: keep the exposure visible
	// on every doctor run for as long as the posture holds.
	if posture.RemoteAdmin != "" {
		fmt.Fprintf(out, "  operator surface ⚠ /admin + /console reachable beyond loopback on %s (--allow-remote-admin)\n", posture.RemoteAdmin)
		fmt.Fprintln(out, "                    (cleartext HTTP, operator token only — front it with TLS, or bind")
		fmt.Fprintln(out, "                     loopback and use SSH forwarding)")
	}
}

// reportFederatedSignIn renders the federated posture: the identity provider
// people sign in at, who that provider's accounts are narrowed to, the
// multi-user posture, and what the shared audit log retains of callers'
// arguments.
//
// The audience line is always present. "Which accounts can reach this gateway"
// is the question a federated deployment most needs answered, and answering it
// only when a bound happens to be configured would make the widest posture the
// quietest one.
func reportFederatedSignIn(out io.Writer, posture authPosture, optedUp []string, audienceRules auth.AudienceSummary) {
	fmt.Fprintf(out, "    sign-in         federated to %s\n", posture.SSOIssuer)
	audience := auth.DescribeAudience(posture.SSOIssuer, posture.SSOHostedDomain, posture.SSOAnyAccount, audienceRules)
	switch {
	case posture.SSOAnyAccount:
		fmt.Fprintf(out, "    audience        %s (--sso-any-account: the issuer is the membership boundary)\n", audience)
		if inert := auth.InertAudienceRules(true, audienceRules); inert != "" {
			fmt.Fprintf(out, "                    ⚠ %s configured but not applied — every account at the issuer is admitted\n", inert)
		}
	case audienceRules.Unreadable:
		// Sign-in fails closed here, so the page must not render the hosted
		// domain alone as though it were still the whole audience.
		fmt.Fprintf(out, "    audience        ⚠ %s\n", audience)
		fmt.Fprintf(out, "                    repair or remove %s\n", ssoAudienceRulesPath(""))
	case posture.SSOHostedDomain == "" && audienceRules.Total() == 0:
		// Reachable only by removing every rule from a running gateway that had
		// no other bound: a start in this state is refused. Nobody can sign in,
		// which is fail-closed but is still a broken deployment to report.
		fmt.Fprintln(out, "    audience        ⚠ none declared — no account can sign in until a bound is restored")
		fmt.Fprintln(out, "                    add --sso-hd <domain>, --sso-any-account, or `microagency sso-audience allow ...`")
	default:
		fmt.Fprintf(out, "    audience        %s\n", audience)
	}
	fmt.Fprintln(out, "    posture         multi-user — each provider account is a distinct principal")
	if len(optedUp) == 0 {
		fmt.Fprintln(out, "    audit capture   argument structure + digest (callers' argument values stay out of the shared log)")
	} else {
		fmt.Fprintf(out, "    audit capture   ⚠ FULL arguments for: %s (operator opt-up; other connections record structure + digest)\n", strings.Join(optedUp, ", "))
	}
}

// reportTunnelStability names the URL contract the recorded tunnel mode
// carries: a named tunnel keeps its issuer across restarts, a quick tunnel
// does not — which decides whether issued tokens survive a restart.
func reportTunnelStability(out io.Writer, posture authPosture) {
	switch posture.TunnelMode {
	case "named":
		fmt.Fprintf(out, "    url stability   stable — named tunnel %q keeps the issuer across restarts (tokens survive)\n", posture.TunnelName)
	case "quick":
		fmt.Fprintln(out, "    url stability   quick tunnel — the URL changes on restart, invalidating issued tokens")
	}
}

func reportTunnelHealth(out io.Writer, serverUp bool) (bool, string) {
	return reportTunnelHealthAt(out, tunnelStatePath(), serverUp, processAlive)
}

// reportTunnelHealthAt answers "is the public URL actually being served" from
// the tunnel-state record the server wrote when it started its tunnel child.
// A dead child under a live server is the alarm case: clients still hold the
// public URL, and nothing behind it is listening.
func reportTunnelHealthAt(out io.Writer, path string, serverUp bool, alive func(int) bool) (ok bool, clause string) {
	st, err := readTunnelState(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, "" // no tunnel in this deployment — nothing to check
		}
		fmt.Fprintf(out, "  tunnel            ⚠ state unreadable: %v\n", err)
		fmt.Fprintln(out, "                    (tunnel liveness is unknown; restart with `microagency restart` to rewrite it)")
		return false, "tunnel liveness is unknown because its state record is unreadable"
	}
	desc := st.Provider
	switch st.Mode {
	case "named":
		desc = fmt.Sprintf("%s (named tunnel %q)", st.Provider, st.Name)
	case "quick":
		desc = st.Provider + " (quick tunnel)"
	}
	const restartHint = "the public URL is unreachable — restart with `microagency restart`"
	switch {
	case !serverUp:
		fmt.Fprintf(out, "  tunnel            — not running: %s starts and stops with the server\n", desc)
		return true, "" // the dead server already fails the verdict
	case st.ExitedAt != "":
		fmt.Fprintf(out, "  tunnel            ✗ %s exited — %s is not being served\n", desc, dash(st.URL))
		if st.ExitError != "" {
			fmt.Fprintf(out, "                    (%s; restart with `microagency restart`)\n", st.ExitError)
		} else {
			fmt.Fprintln(out, "                    (restart with `microagency restart`)")
		}
		return false, "the tunnel process has exited so " + restartHint
	case !alive(st.PID):
		fmt.Fprintf(out, "  tunnel            ✗ %s process (pid %d) is gone — %s is not being served\n", desc, st.PID, dash(st.URL))
		fmt.Fprintln(out, "                    (restart with `microagency restart`)")
		return false, "the tunnel process is gone so " + restartHint
	default:
		fmt.Fprintf(out, "  tunnel            ✓ %s running (pid %d), serving %s\n", desc, st.PID, dash(st.URL))
		return true, ""
	}
}

// closingVerdict composes the page's rollup sentence, gated on everything the
// page reported: the server, the tunnel child, the bypass check, and the
// runtime clause from the end-to-end probe. It exists so a dead server can
// never sit above an ending that reads green — the closing sentence answers
// for the whole page or it does not claim readiness.
func closingVerdict(serverUp bool, bypassWarnings int, runtimeHealthy bool, runtimeClause string, mediationReady bool, mediationClause string, tunnelOK bool, tunnelClause string) string {
	switch {
	case !serverUp:
		return fmt.Sprintf("The gateway is not ready: the server is not running (start it with `microagency up`), %s, and %s.", runtimeClause, mediationClause)
	case !tunnelOK:
		return fmt.Sprintf("The server is running and %s, but %s.", runtimeClause, tunnelClause)
	case bypassWarnings == 1:
		return fmt.Sprintf("The server is running and %s, but one upstream is reachable around the gateway — remove the direct entry above so every call is governed and audited.", runtimeClause)
	case bypassWarnings > 1:
		return fmt.Sprintf("The server is running and %s, but %d upstreams are reachable around the gateway — remove the direct entries above so every call is governed and audited.", runtimeClause, bypassWarnings)
	case !mediationReady:
		return fmt.Sprintf("The server is running and %s, but %s.", runtimeClause, mediationClause)
	case runtimeHealthy:
		return fmt.Sprintf("microagency is ready: the server is running, %s, and %s.", runtimeClause, mediationClause)
	default:
		return fmt.Sprintf("The server is running, but %s; %s.", runtimeClause, mediationClause)
	}
}

func reportMediation(out io.Writer, status mediation.Status) (bool, string) {
	fmt.Fprintf(out, "\n  direct mediation %s (%s)\n", status.Mode, status.State)
	if status.Workspace != "" {
		fmt.Fprintf(out, "    workspace       %s (%s)\n", status.Workspace, dash(status.WorkspaceState))
		fmt.Fprintf(out, "    gateway         %s\n", status.GatewayURL)
	}
	if status.Reason != "" {
		fmt.Fprintf(out, "    detail          %s\n", status.Reason)
	}
	if len(status.Uncovered) > 0 {
		fmt.Fprintf(out, "    uncovered       %s\n", strings.Join(status.Uncovered, ", "))
	}
	switch status.State {
	case "enforced":
		return true, "direct upstreams are denied in the bound workspace"
	case "configured":
		return true, "the bound workspace policy is configured and fails closed when started"
	case "advisory":
		return true, "direct-upstream checks are advisory for local and unbound clients"
	default:
		return false, "enforced workspace mediation is " + status.State
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
// so "where are my secrets" has an answer up front.
//
// While a gateway runs it reports the store in EFFECT — the record that gateway
// wrote when it opened one — not the store this shell's configuration asks for.
// The two agree right up until something goes wrong, which is exactly when this
// line gets read, and an operator told the configured store will go and fix the
// wrong thing. With no gateway running it resolves the same way a start would,
// and probes what it resolves to rather than assuming a configured store is a
// reachable one.
func reportSecretPosture(out io.Writer) {
	reportSecretPostureWith(out, os.Getenv, microagencyDir(), runningPID(), probeVault)
}

// vaultProbeFunc reads one key from the configured external Vault/OpenBao. It is
// injected so tests never reach the network.
type vaultProbeFunc func(ctx context.Context, getenv func(string) string) error

// probeVault performs the read a start would perform. ErrNotFound is the healthy
// answer: the store answered and holds no such key.
func probeVault(ctx context.Context, getenv func(string) string) error {
	v := secretstore.VaultFromEnv(getenv, &http.Client{Timeout: 5 * time.Second})
	if _, err := v.Load(ctx, "doctor-probe/__unused__"); err != nil && !errors.Is(err, secretstore.ErrNotFound) {
		return err
	}
	return nil
}

func reportSecretPostureWith(out io.Writer, getenv func(string) string, stateDir string, gatewayPID int, probe vaultProbeFunc) {
	if p, ok := livePosture(stateDir, gatewayPID); ok {
		renderLivePosture(out, p)
		return
	}
	renderResolvedPosture(out, getenv, stateDir, probe)
}

// livePosture returns the record a RUNNING gateway wrote when it opened its
// store. A running gateway is the authority on which store holds its
// credentials; anything derived from configuration is second-hand. The pid must
// match the live gateway, so a record left behind by an exited one is never
// mistaken for the current posture.
func livePosture(stateDir string, gatewayPID int) (secretstore.Posture, bool) {
	if gatewayPID == 0 {
		return secretstore.Posture{}, false
	}
	p, err := secretstore.LoadPosture(stateDir)
	if err != nil || p.PID != gatewayPID {
		return secretstore.Posture{}, false
	}
	return p, true
}

func renderLivePosture(out io.Writer, p secretstore.Posture) {
	if p.Disagrees() {
		// Severity follows the store that actually holds the credentials, not
		// the fact of the disagreement. Credentials safely encrypted in a store
		// nobody configured is worth a warning; credentials in the clear is a
		// failure. Ranking both the same trains operators to skip the line.
		glyph := "⚠"
		if p.Degraded {
			glyph = "✗"
		}
		fmt.Fprintf(out, "  secret store      %s the configured store is NOT the one holding credentials\n", glyph)
		fmt.Fprintf(out, "                    configured: %s\n", p.Configured)
		fmt.Fprintf(out, "                    in effect:  %s (running gateway, pid %d)\n", p.Effective, p.PID)
		if p.Reason != "" {
			fmt.Fprintf(out, "                    why:        %s\n", p.Reason)
		}
		fmt.Fprintln(out, "                    fix:        restore the configured store, then `microagency restart`")
		if p.Degraded {
			fmt.Fprintln(out, "                    until then credentials are NOT encrypted at rest")
		}
		return
	}
	glyph := "✓"
	if p.Degraded {
		glyph = "⚠"
	}
	fmt.Fprintf(out, "  secret store      %s %s\n", glyph, p.Effective)
	fmt.Fprintf(out, "                    (in effect in the running gateway, pid %d)\n", p.PID)
	if p.KeyCustody != "" {
		fmt.Fprintf(out, "                    (data key held by: %s)\n", secretstore.CustodyLabel(p.KeyCustody))
	}
	if p.Degraded {
		fmt.Fprintln(out, "                    (credentials stay out of the agent, but are NOT encrypted at rest;")
		fmt.Fprintln(out, "                     set "+secretstore.ProtectorEnv+" or "+secretstore.FileKeyEnv+" and restart)")
	}
}

// renderResolvedPosture answers "which store would a start right now use" by
// resolving the same way `up` does, and probing what it resolves to rather than
// trusting that a configured store is a reachable one.
func renderResolvedPosture(out io.Writer, getenv func(string) string, stateDir string, probe vaultProbeFunc) {
	addr, token := getenv("VAULT_ADDR"), getenv("VAULT_TOKEN")
	switch {
	case addr != "" && token == "":
		fmt.Fprintln(out, "  secret store      ✗ VAULT_ADDR is set but VAULT_TOKEN is missing")
		fmt.Fprintln(out, "                    (startup will fail closed; provide the token or unset VAULT_ADDR)")
		return
	case addr == "" && token != "":
		fmt.Fprintln(out, "  secret store      ✗ VAULT_TOKEN is set but VAULT_ADDR is missing")
		fmt.Fprintln(out, "                    (startup will fail closed; provide the address or unset VAULT_TOKEN)")
		return
	case addr != "":
		renderExternalVault(out, getenv, addr, probe)
		return
	}
	renderLocalStore(out, inspectLocalStore(getenv, stateDir))
}

// renderExternalVault reports the configured external store only after it
// answers. A configured address is not a reachable one, and a start would keep
// using it either way — so a green line here that nobody verified is exactly
// the claim an operator would act on and should not.
func renderExternalVault(out io.Writer, getenv func(string) string, addr string, probe vaultProbeFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probe(ctx, getenv); err != nil {
		fmt.Fprintf(out, "  secret store      ✗ external Vault/OpenBao (VAULT_ADDR=%s) did not answer\n", addr)
		fmt.Fprintf(out, "                    why:        %v\n", err)
		fmt.Fprintln(out, "                    fix:        start it, or correct VAULT_ADDR/VAULT_TOKEN, then `microagency restart`")
		fmt.Fprintln(out, "                    (a start still uses it; every credential read would fail until it answers)")
		return
	}
	fmt.Fprintf(out, "  secret store      ✓ external Vault/OpenBao (VAULT_ADDR=%s)\n", addr)
	fmt.Fprintln(out, "                    (verified: it answered a read on microagency's KV v2 path)")
}

// localStore is the file-backed store this state directory would use, resolved
// by inspecting the files rather than reading intent from configuration.
type localStore struct {
	glyph  string
	head   string
	detail []string
}

func inspectLocalStore(getenv func(string) string, stateDir string) localStore {
	ctx := context.Background()
	path := secretstore.StorePath(stateDir)
	// A data-key protector is probed read-only: doctor must not create the key a
	// start would create, or a green page here would be the thing that made it green.
	if kc := secretstore.InspectKeyCustody(ctx, stateDir, getenv); kc.Kind != "" {
		return renderKeyCustody(kc, getenv, path)
	}
	kind, err := secretstore.InspectFile(path, nil)
	if errors.Is(err, secretstore.ErrKeyRequired) || kind == secretstore.KindEncryptedFile {
		return encryptedStoreNoKeyHere()
	}
	if err != nil {
		return localStore{"✗", fmt.Sprintf("local credential store cannot be read: %v", err),
			[]string{"startup will fail closed; repair or restore the credential store"}}
	}
	// The opt-in outranks the host keyring, exactly as a start resolves it, so
	// the probe below never runs for a deployment that already chose this.
	if secretstore.AllowPlaintextConfigured(getenv) {
		return localStore{"⚠", "unencrypted mode-0600 plaintext file under ~/.microagency",
			[]string{
				"(opted in with " + secretstore.AllowPlaintextEnv + "; credentials stay out of the agent,",
				" but are NOT encrypted at rest — unset it to let this host's keyring hold a data",
				" key instead, or set " + secretstore.ProtectorEnv + " / " + secretstore.FileKeyEnv + ")",
			}}
	}
	// Nothing is configured and no protector is recorded, so a start would look
	// for this host's own keyring. Report what that probe found, not what the
	// absence of configuration implies.
	return noProtectorAvailable(secretstore.InspectAutoProtector(ctx, stateDir, getenv))
}

// noProtectorAvailable is the host that can hold no data key outside its own
// state directory. Every way forward is named, and a key file *inside* the
// state directory is not among them: a key sitting beside the ciphertext it
// opens protects nothing, so microagency will not write one and does not
// suggest it.
func noProtectorAvailable(auto secretstore.AutoProtector) localStore {
	detail := []string{"why:        " + auto.Detail}
	detail = append(detail,
		"fix:        set "+secretstore.ProtectorEnv+"=command with a KMS or secret-manager helper,",
		"            or point "+secretstore.FileKeyEnv+" at a key you hold outside ~/.microagency,")
	if auto.Kind != "" {
		detail = append(detail, "            or make this host's "+auto.Label+" reachable,")
	}
	detail = append(detail,
		"            or accept the unencrypted mode-0600 file with",
		"            `microagency up --allow-plaintext-credentials`")
	return localStore{"✗", "no data key can be held outside the state directory, so no store is usable", detail}
}

// encryptedStoreNoKeyHere is the store that is demonstrably encrypted while
// nothing in THIS environment says which key opens it.
//
// The usual cause is not a fault. A gateway started with a key file exported
// into its own environment is perfectly healthy; doctor run from a shell that
// does not export the same variable simply cannot see the key. Doctor cannot
// tell that apart from a setting that is genuinely gone, so it reports what it
// verified — the store is encrypted, and this environment cannot open it — and
// names the remedy for each reading rather than calling a working deployment
// broken.
func encryptedStoreNoKeyHere() localStore {
	return localStore{"⚠", "AES-256-GCM file store — its data key is not reachable from this shell",
		[]string{
			"the credential file is encrypted, so a key opens it somewhere; " + secretstore.FileKeyEnv,
			"is unset here and no protector is recorded, so doctor could not verify it",
			"fix:        if the gateway runs with " + secretstore.FileKeyEnv + " set, export the same",
			"            value for doctor too; otherwise move the key to a protector with",
			"            `microagency secret-store migrate --to keychain|secret-service|command`,",
			"            which records a locator doctor follows with no environment at all",
			"(a start from THIS environment would refuse rather than open the store)",
		}}
}

// renderKeyCustody turns the data-key custody probe into a check line. An
// unreachable protector is never rendered healthy: what is known is that a
// start right now would refuse, and the operator needs told which provider to
// restore, not reassured that the store is "encrypted".
func renderKeyCustody(kc secretstore.KeyCustodyPosture, getenv func(string) string, path string) localStore {
	if !kc.Protected {
		// The operator key file keeps its own wording: it is the same posture,
		// the same setting, and the same remediation it has always had.
		if !kc.Available {
			return localStore{"✗", fmt.Sprintf("encrypted file store is misconfigured: %s", kc.Detail),
				[]string{"startup will fail closed; fix or unset " + secretstore.FileKeyEnv}}
		}
		return localStore{"✓", "AES-256-GCM file store with a separately supplied key",
			[]string{fmt.Sprintf("(key: %s; credentials: %s)", strings.TrimSpace(getenv(secretstore.FileKeyEnv)), path)}}
	}
	head := fmt.Sprintf("AES-256-GCM file store (data key: %s)", kc.Label)
	if !kc.Available {
		// The store may well be intact; what is known is that a start right now
		// would refuse. Claiming the protector "did not answer" would be wrong
		// for a custody disagreement, where it answered and the settings did not
		// agree — so state the consequence and let Detail carry the cause.
		return localStore{"✗", head + " — UNVERIFIED",
			[]string{kc.Detail, "startup will fail closed until this is resolved"}}
	}
	return localStore{"✓", head, []string{fmt.Sprintf("(%s; credentials: %s)", kc.Detail, path)}}
}

func renderLocalStore(out io.Writer, ls localStore) {
	fmt.Fprintf(out, "  secret store      %s %s\n", ls.glyph, ls.head)
	for _, d := range ls.detail {
		fmt.Fprintf(out, "                    %s\n", d)
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
