// Command microagency brings up the microagency MCP tool surface.
//
// Usage:
//
//	microagency up                            (HTTP server; connects your agent)
//	microagency up --stdio                    (serve over stdin/stdout, client-spawned)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"microagency/internal/auth"
	"microagency/internal/baomanager"
	"microagency/internal/budget"
	"microagency/internal/gateway"
	"microagency/internal/mcp"
	"microagency/internal/minimize"
	"microagency/internal/refstore"
	"microagency/internal/router"
	"microagency/internal/sandbox"
	"microagency/internal/secretstore"
	"microagency/internal/tunnel"
	"microagency/internal/wasmexec"
)

// Build stamp, set via -ldflags at release time (GoReleaser). "dev" for a plain
// `go build`; the binary also carries the VCS revision via debug.ReadBuildInfo.
var (
	version = "dev"
	commit  = ""
)

func main() {
	gateway.ClientVersion = version // identify the real build to upstream MCP servers
	args := os.Args[1:]
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
	case "version", "--version", "-v":
		printVersion()
	case "up":
		run(args[1:])
	case "down":
		runDown()
	case "restart":
		runRestart(args[1:])
	case "purge":
		runPurge(args[1:])
	case "doctor":
		runDoctor()
	case "hook":
		runHook(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

// localSubject is the identity the built-in single-user OAuth server stamps on
// issued tokens (so runs attribute to the real human, matching the console
// header). The OS user, falling back to $USER then "operator".
func localSubject() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return "operator"
}

func printVersion() {
	if commit != "" {
		fmt.Printf("microagency %s (%s)\n", version, commit)
		return
	}
	fmt.Printf("microagency %s\n", version)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  microagency up [flags]    start the MCP server (runs in the background)")
	fmt.Fprintln(os.Stderr, "  microagency down          stop the background server")
	fmt.Fprintln(os.Stderr, "  microagency restart [flags]  restart the background server (keeps OpenBao up)")
	fmt.Fprintln(os.Stderr, "  microagency purge [--full] delete your data (--full wipes everything; both confirm)")
	fmt.Fprintln(os.Stderr, "  microagency doctor        check runtime + engine health")
	fmt.Fprintln(os.Stderr, "  microagency hook install  print the Claude Code egress-guard hook setup")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  up flags:")
	fmt.Fprintln(os.Stderr, "    --http <addr>         bind address (default 127.0.0.1:8765)")
	fmt.Fprintln(os.Stderr, "    --public              expose a public URL via a tunnel (web apps)")
	fmt.Fprintln(os.Stderr, "    --foreground          run attached instead of backgrounding")
	fmt.Fprintln(os.Stderr, "    --stdio               serve over stdin/stdout (client-spawned)")
	fmt.Fprintln(os.Stderr, "    --no-register         don't auto-register with Claude Code")
	fmt.Fprintln(os.Stderr, "    --token <tok>         use a static bearer instead of OAuth")
	fmt.Fprintln(os.Stderr, "    --issuer/--audience   external OAuth resource-server mode")
	fmt.Fprintln(os.Stderr, "    --require-scope <s>   with --issuer: refuse tokens not granted this OAuth scope")
	fmt.Fprintln(os.Stderr, "    --admin-addr <addr>   bind /admin + /console on a separate listener")
	fmt.Fprintln(os.Stderr, "                          (defaults to "+defaultAdminAddr+" when a tunnel is used)")
	fmt.Fprintln(os.Stderr, "    --engine name=path    add a query engine (a wasip1 module)")
	fmt.Fprintln(os.Stderr, "    --max-inline-bytes N  results larger than N bytes return as a reference (default 8192)")
	fmt.Fprintln(os.Stderr, "    --persist-refs        keep reffed data across restart (encrypted at rest, 24h TTL)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Add MCP servers from the console (http://<addr>/console), not here.")
}

// run starts the server. That's all it does — adding upstream MCPs is the
// console's job (/admin), not a startup flag. The HTTP server runs in
// the BACKGROUND by default (`up` returns the terminal; stop with `microagency
// down`); --stdio serves over stdin/stdout for a client that spawns the binary.
func run(args []string) {
	httpAddr, token := "127.0.0.1:8765", ""
	issuer, audience, tunnelProvider, adminAddr := "", "", "", ""
	requireScope := ""
	wasmMaxMemMB := 512 // per-wasm-run memory ceiling (ASK tenet 8 — bounded ops)
	// Results larger than this come back as a reference, not raw data. 8 KiB (not 2
	// KiB): real API responses cluster just over 2 KB, so a low bar parked ordinary
	// small answers behind a reduce round-trip; genuinely large data (documents, row
	// dumps) still parks. The ref now carries a structural preview, so even parked
	// results often need no reduce.
	maxInlineBytes := 8192
	stdio, public, noRegister, foreground := false, false, false, false
	persistRefs := false // opt-in: persist reffed payloads (encrypted, TTL'd) so refs survive restart
	var engineSpecs []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--http" && i+1 < len(args):
			httpAddr = args[i+1]
			i++
		case args[i] == "--token" && i+1 < len(args):
			token = args[i+1]
			i++
		case args[i] == "--issuer" && i+1 < len(args):
			issuer = args[i+1]
			i++
		case args[i] == "--require-scope" && i+1 < len(args):
			requireScope = args[i+1]
			i++
		case args[i] == "--audience" && i+1 < len(args):
			audience = args[i+1]
			i++
		case args[i] == "--tunnel" && i+1 < len(args):
			tunnelProvider = args[i+1]
			i++
		case args[i] == "--admin-addr" && i+1 < len(args):
			adminAddr = args[i+1] // bind /admin + /console on their own listener
			i++
		case args[i] == "--engine" && i+1 < len(args):
			engineSpecs = append(engineSpecs, args[i+1]) // name=path; repeatable
			i++
		case args[i] == "--wasm-max-memory-mb" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "--wasm-max-memory-mb must be a positive integer, got %q\n", args[i+1])
				os.Exit(2)
			}
			wasmMaxMemMB = n
			i++
		case args[i] == "--max-inline-bytes" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "--max-inline-bytes must be a positive integer, got %q\n", args[i+1])
				os.Exit(2)
			}
			maxInlineBytes = n
			i++
		case args[i] == "--stdio":
			stdio = true
		case args[i] == "--public":
			public = true
		case args[i] == "--persist-refs":
			persistRefs = true
		case args[i] == "--no-register":
			noRegister = true
		case args[i] == "--foreground":
			foreground = true // run attached (don't background) — for debugging
		case args[i] == "-h" || args[i] == "--help" || args[i] == "help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", args[i])
			os.Exit(2)
		}
	}

	if public && tunnelProvider == "" {
		tunnelProvider = "cloudflare"
	}
	cfg := httpConfig{
		addr: httpAddr, adminAddr: adminAddr,
		issuer: issuer, audience: audience, requireScope: requireScope,
		tunnel: tunnelProvider, noRegister: noRegister,
	}

	// Background by default: the parent spawns a detached child (MICROAGENCY_DAEMON=1)
	// and returns the terminal. stdio is always foreground (it IS the client's pipe).
	if !stdio && !foreground && os.Getenv("MICROAGENCY_DAEMON") != "1" {
		daemonize(cfg)
		return
	}

	// A foreground start shares the same token store as any running daemon; refuse
	// rather than let two instances rotate the same OAuth tokens against each other.
	// (The daemon child carries MICROAGENCY_DAEMON=1 and its own pid, so it skips this.)
	if !stdio && os.Getenv("MICROAGENCY_DAEMON") != "1" {
		if pid := runningPID(); pid != 0 {
			fmt.Fprintf(os.Stderr, "microagency is already running in the background (pid %d). Run `microagency down` first.\n", pid)
			os.Exit(1)
		}
	}

	// OpenBao is a managed dependency: bring up microagency's own instance (or use
	// an external one via VAULT_ADDR) and point the secret store at it. stdio
	// doesn't aggregate upstreams, so it skips this. If Bao can't come up, fall back
	// to the local file store rather than failing the whole server.
	if !stdio {
		if addr, vaultTok, err := baomanager.Ensure(context.Background(), filepath.Join(microagencyDir(), "openbao"), os.Getenv); err != nil {
			log.Printf("microagency: OpenBao unavailable (%v) — using the local file store", err)
		} else {
			_ = os.Setenv("VAULT_ADDR", addr)
			_ = os.Setenv("VAULT_TOKEN", vaultTok)
		}
	}

	srv := buildServer(engineSpecs, wasmMaxMemMB, maxInlineBytes, persistRefs, consoleAddr(cfg))

	if stdio {
		if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Reconnect upstreams added in a previous run (OAuth tokens from the secret
	// store), so they survive a restart with no re-login.
	srv.ReloadUpstreams(context.Background())

	if token == "" {
		token = os.Getenv("MICROAGENCY_TOKEN")
	}
	cfg.token = token
	serveHTTP(srv, cfg)
}

// pidPath is the background server's pid file.
func pidPath() string { return filepath.Join(microagencyDir(), "microagency.pid") }

// runningPID returns the pid of a live background microagency, or 0 if none is
// running. A pid file pointing at a dead process (a crashed or brew-replaced
// daemon) is stale and removed, so it never blocks a fresh start. This is what
// keeps two instances from sharing one OAuth token store — the failure mode that
// rotates a refresh token out from under the other and trips "reuse detected".
func runningPID() int {
	b, err := os.ReadFile(pidPath())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || syscall.Kill(pid, 0) != nil {
		_ = os.Remove(pidPath()) // stale
		return 0
	}
	return pid
}

// daemonize re-execs microagency as a detached background server (the child sees
// MICROAGENCY_DAEMON=1), records its pid, and returns the terminal. The child's
// output goes to ~/.microagency/microagency.log.
func daemonize(cfg httpConfig) {
	if pid := runningPID(); pid != 0 {
		fmt.Fprintf(os.Stderr, "microagency is already running (pid %d). Run `microagency down` first, or `--foreground` to run attached.\n", pid)
		os.Exit(1)
	}
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("microagency: %v", err)
	}
	dir := microagencyDir()
	_ = os.MkdirAll(dir, 0o700)
	logPath := filepath.Join(dir, "microagency.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("microagency: open log: %v", err)
	}
	defer func() { _ = logf.Close() }()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "MICROAGENCY_DAEMON=1")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from the terminal
	if err := cmd.Start(); err != nil {
		log.Fatalf("microagency: start: %v", err)
	}
	pid := cmd.Process.Pid
	_ = os.WriteFile(pidPath(), []byte(strconv.Itoa(pid)), 0o600)

	// Give it a moment to bind; surface an immediate exit (e.g. port in use).
	time.Sleep(700 * time.Millisecond)
	if syscall.Kill(pid, 0) != nil {
		fmt.Fprintf(os.Stderr, "microagency: server exited on startup — see %s\n", logPath)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\n  microagency is up in the background (pid %d).\n\n", pid)
	fmt.Fprintf(os.Stderr, "    MCP endpoint   http://%s/mcp   (in Claude Code: /mcp → Authenticate)\n", cfg.addr)
	fmt.Fprintf(os.Stderr, "    Console        http://%s/console\n", consoleAddr(cfg))
	if cfg.tunnel != "" {
		fmt.Fprintf(os.Stderr, "    Tunnel         public URL appears in the logs — it exposes /mcp only; the console stays loopback\n")
	}
	fmt.Fprintf(os.Stderr, "    Logs           %s\n", logPath)
	fmt.Fprintf(os.Stderr, "    Stop           microagency down\n\n")
	upgradeNudge()
}

// upgradeNudge prints a one-line hint if the Homebrew tap has a newer build than
// the one running. Best-effort and unobtrusive: the server is already up by the
// time this runs, it uses a short timeout and fails silently (offline, blocked,
// parse miss), and it's skipped for `go build` binaries or when
// MICROAGENCY_NO_UPDATE_CHECK is set. The tap formula's version is exactly what
// `brew upgrade` would install, so it's the authoritative comparison — and it
// keys off the running channel (stable vs latest) to name the right formula.
func upgradeNudge() {
	if version == "dev" || version == "" || os.Getenv("MICROAGENCY_NO_UPDATE_CHECK") != "" {
		return
	}
	formula := "microagency"
	if strings.Contains(version, "-latest.") {
		formula = "microagency-latest"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://raw.githubusercontent.com/geoffbelknap/homebrew-tap/main/" + formula + ".rb")
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if latest := parseFormulaVersion(string(body)); latest != "" && latest != version {
		fmt.Fprintf(os.Stderr, "    Update         %s available — run: brew upgrade %s\n\n", latest, formula)
	}
}

// parseFormulaVersion pulls the value out of a Homebrew formula's `version "X"`
// line; "" if not found.
func parseFormulaVersion(formula string) string {
	const marker = `version "`
	i := strings.Index(formula, marker)
	if i < 0 {
		return ""
	}
	rest := formula[i+len(marker):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

// runDown stops the background server and the managed OpenBao.
func runDown() {
	if pid := runningPID(); pid != 0 {
		if kerr := syscall.Kill(pid, syscall.SIGTERM); kerr != nil {
			fmt.Fprintf(os.Stderr, "microagency: stop pid %d: %v\n", pid, kerr)
		} else {
			fmt.Fprintf(os.Stderr, "microagency: stopped (pid %d)\n", pid)
		}
		_ = os.Remove(pidPath())
	} else {
		fmt.Fprintln(os.Stderr, "microagency: not running")
	}
	baomanager.Stop(filepath.Join(microagencyDir(), "openbao")) // also stop managed OpenBao
}

// runRestart stops a running background server and starts a fresh one with the
// given up-flags. It deliberately leaves the managed OpenBao running — a restart
// shouldn't churn the secret store (that churn is part of what strands OAuth
// tokens), so only the server process is cycled. If nothing is running, it's just
// a start.
func runRestart(args []string) {
	if pid := stopRunningServer(); pid != 0 {
		fmt.Fprintf(os.Stderr, "microagency: stopped (pid %d)\n", pid)
	}
	// Re-exec as `up`, not `restart`. run() backgrounds by re-running os.Args[1:];
	// if that still said "restart", the daemon child would run restart again, find
	// its own freshly-written pid in the pid file, and SIGTERM itself. Rewrite argv
	// to the up form so the child serves instead of killing itself.
	os.Args = append([]string{os.Args[0], "up"}, args...)
	run(args)
}

// stopRunningServer SIGTERMs a running background server and waits for it to exit
// (so a follow-up start can bind the port, or files can be removed without the
// process rewriting them). Returns the pid it stopped, or 0 if nothing was up.
func stopRunningServer() int {
	pid := runningPID()
	if pid == 0 {
		return 0
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	// runningPID clears the stale pid file once the process is gone.
	for i := 0; i < 50 && runningPID() != 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return pid
}

// runPurge deletes the operator's data. The default (Tier 1) removes parked data
// and run/audit history but keeps connections, credentials, and the operator
// token — no re-auth. --full removes the entire ~/.microagency (re-auth after).
// Both confirm first (skip with --yes) and stop the server so it can't hold stale
// state in memory or re-append to the audit log after the wipe.
func runPurge(args []string) {
	full, yes := false, false
	for _, a := range args {
		switch a {
		case "--full":
			full = true
		case "--yes", "-y":
			yes = true
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stderr, "usage: microagency purge [--full] [--yes]")
			fmt.Fprintln(os.Stderr, "  (default) delete parked data (refs) + run/audit history; keep connections & auth")
			fmt.Fprintln(os.Stderr, "  --full    delete EVERYTHING under ~/.microagency (re-authenticate afterward)")
			fmt.Fprintln(os.Stderr, "  --yes,-y  skip the confirmation prompt")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", a)
			os.Exit(2)
		}
	}
	dir := microagencyDir()
	if full {
		fmt.Fprintf(os.Stderr, "This PERMANENTLY deletes the entire %s directory:\n", dir)
		fmt.Fprintln(os.Stderr, "  • parked data (refs) and all run/audit history")
		fmt.Fprintln(os.Stderr, "  • stored upstream credentials — you will re-authenticate every connection")
		fmt.Fprintln(os.Stderr, "  • the operator token and local OAuth keys — Claude Code will re-consent")
	} else {
		fmt.Fprintln(os.Stderr, "This permanently deletes your data:")
		fmt.Fprintf(os.Stderr, "  • %s   (run/audit history, incl. args + stderr)\n", filepath.Join(dir, "audit.jsonl"))
		fmt.Fprintf(os.Stderr, "  • %s/       (parked reference payloads)\n", filepath.Join(dir, "refs"))
		fmt.Fprintf(os.Stderr, "  • %s   (the refs encryption key)\n", filepath.Join(dir, "refs.key"))
		fmt.Fprintln(os.Stderr, "Connections, credentials, and the operator token are KEPT — no re-auth.")
	}
	if !yes && !confirmPurge() {
		fmt.Fprintln(os.Stderr, "microagency: purge cancelled")
		return
	}
	if pid := stopRunningServer(); pid != 0 {
		fmt.Fprintf(os.Stderr, "microagency: stopped (pid %d)\n", pid)
	}
	if full {
		baomanager.Stop(filepath.Join(dir, "openbao")) // release the storage dir before removing it
	}
	if err := doPurge(dir, full); err != nil {
		fmt.Fprintf(os.Stderr, "microagency: purge: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "microagency: purge complete")
	fmt.Fprintln(os.Stderr, "Start fresh with: microagency up")
}

// confirmPurge reads a yes/no from stdin; only an explicit y/yes proceeds.
func confirmPurge() bool {
	fmt.Fprint(os.Stderr, "Continue? [y/N]: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// doPurge removes the on-disk state. full → the whole dir; otherwise the data
// files only (missing files are not an error), truncating the log (kept as a
// valid path for the next start). Best-effort: it removes everything it can and
// reports what it couldn't, rather than stopping at the first error.
func doPurge(dir string, full bool) error {
	if full {
		return os.RemoveAll(dir)
	}
	var errs []string
	for _, p := range []string{
		filepath.Join(dir, "audit.jsonl"),
		filepath.Join(dir, "refs"),
		filepath.Join(dir, "refs.key"),
	} {
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p, err))
		}
	}
	if logPath := filepath.Join(dir, "microagency.log"); fileExists(logPath) {
		if err := os.Truncate(logPath, 0); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", logPath, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func microagencyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return os.TempDir()
	}
	return filepath.Join(home, ".microagency")
}

type httpConfig struct {
	addr, adminAddr, token, issuer, audience, tunnel string
	requireScope                                     string // with --issuer: OAuth scope a token must carry to reach /mcp
	noRegister                                       bool
}

// defaultAdminAddr is where the operator surface (/admin + /console) binds when a
// tunnel is requested without an explicit --admin-addr. A tunnel proxies the
// ENTIRE origin, so leaving the operator surface on the tunneled mux would make
// it publicly network-reachable (token-gated, but exposed). One port above the
// default MCP bind (8765), so the pair reads as one install.
const defaultAdminAddr = "127.0.0.1:8766"

// effectiveAdminAddr decides where the operator surface binds. An explicit
// --admin-addr always wins (even one equal to the MCP bind — the operator opted
// in to sharing that listener). With a tunnel and no --admin-addr, the operator
// surface defaults to its own loopback listener so the tunnel exposes only the
// agent plane. "" means the operator surface shares the agent listener.
func effectiveAdminAddr(cfg httpConfig) string {
	if cfg.adminAddr != "" {
		return cfg.adminAddr
	}
	if cfg.tunnel != "" {
		return defaultAdminAddr
	}
	return ""
}

// consoleAddr is the address the operator opens the console on.
func consoleAddr(cfg httpConfig) string {
	if a := effectiveAdminAddr(cfg); a != "" {
		return a
	}
	return cfg.addr
}

// buildMuxes constructs the agent-plane mux (everything cfg.addr — and any
// tunnel in front of it — serves: /mcp plus the OAuth discovery/authorization
// endpoints its auth mode needs) and the operator mux (/admin + /console).
// When effectiveAdminAddr puts the operator surface on its own listener, the
// two muxes are distinct and the agent plane cannot route to the operator
// surface at all; otherwise both share one mux. mode and bearer feed the
// connect banner.
func buildMuxes(srv *mcp.Server, cfg httpConfig, operatorToken string) (mcpMux, adminMux *http.ServeMux, mode, bearer string) {
	audience := cfg.audience
	if audience == "" {
		audience = "microagency"
	}

	mcpMux = http.NewServeMux()
	switch {
	case cfg.issuer != "":
		// External OAuth resource server — issuance is hosted elsewhere.
		ks, err := auth.NewJWKSFromIssuer(context.Background(), cfg.issuer, nil)
		if err != nil {
			log.Fatalf("microagency: discover issuer %q: %v", cfg.issuer, err)
		}
		rs := &auth.ResourceServer{Issuer: cfg.issuer, Audience: audience, Keys: ks}
		mcpMux.Handle("/mcp", srv.HTTPHandlerAuth(mcp.OAuthAuthenticator(rs, cfg.requireScope)))
		mcpMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata(audience, cfg.issuer))
		mode = "oauth-external"
	case cfg.token != "" || cfg.tunnel != "":
		// Static bearer: explicit --token, or a tunnel (a web connector UI needs a
		// pasteable token; OAuth-over-tunnel needs a public issuer — a follow-up).
		bearer = cfg.token
		if bearer == "" {
			bearer = operatorToken
		}
		mcpMux.Handle("/mcp", srv.HTTPHandler(bearer))
		mode = "bearer"
	default:
		// DEFAULT: the built-in single-user OAuth 2.1 server. microagency is its own
		// authorization server AND resource server, pointing at itself.
		signer, err := auth.LoadOrCreateSigner(oauthKeyPath())
		if err != nil {
			log.Fatalf("microagency: oauth key: %v", err)
		}
		issuer := "http://" + cfg.addr
		// 2h access tokens: long enough that a working session never re-auths
		// interactively (refresh is silent), short enough that a leaked bearer has a
		// bounded life. (Was 12h — a long-lived bearer with no revocation path.)
		as := auth.NewAuthServer(signer, issuer, audience, 2*time.Hour)
		as.Subject = localSubject() // attribute runs to the real OS user, not a generic "operator"
		as.LoadClients(oauthClientsPath()) // remember DCR client_ids across restarts (no re-auth)
		as.Register(mcpMux)
		rs := &auth.ResourceServer{Issuer: issuer, Audience: audience, Keys: signer.KeySet()}
		// The built-in AS always grants "mcp", so requiring it costs nothing and
		// makes scope enforcement real instead of decorative.
		mcpMux.Handle("/mcp", srv.HTTPHandlerAuth(mcp.OAuthAuthenticator(rs, "mcp")))
		mcpMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata(audience, issuer))
		mode = "oauth-local"
	}

	// The operator surface binds a SEPARATE listener whenever effectiveAdminAddr
	// says so (explicit --admin-addr, or the loopback default under a tunnel), so
	// it stays unreachable from the public /mcp bind.
	adminMux = mcpMux
	if a := effectiveAdminAddr(cfg); a != "" && a != cfg.addr {
		adminMux = http.NewServeMux()
	}
	adminMux.Handle("/admin/", srv.AdminHandler(operatorToken))
	adminMux.Handle("/console", srv.ConsoleHandler(operatorToken))
	return mcpMux, adminMux, mode, bearer
}

// serveHTTP runs the agent surface (/mcp) and operator surface (/admin +
// /console), then connects the user. /mcp is always authenticated (it proxies the
// credential pile). DEFAULT is the built-in single-user OAuth 2.1 server — paste
// the URL, approve once, no token handed over. --token forces a static bearer (for
// clients that can't do OAuth); --issuer uses an external authorization server.
// /admin + /console always sit behind a persistent operator token.
func serveHTTP(srv *mcp.Server, cfg httpConfig) {
	operatorToken, opTokenFile := persistentToken()

	mcpMux, adminMux, mode, bearer := buildMuxes(srv, cfg, operatorToken)
	if adminMux != mcpMux {
		adminAddr := effectiveAdminAddr(cfg)
		go func() {
			if err := http.ListenAndServe(adminAddr, adminMux); err != nil {
				log.Fatalf("microagency: admin listener %s: %v", adminAddr, err)
			}
		}()
	}

	announce(srv, cfg, mode, bearer, opTokenFile)

	// A tunnel exposes the loopback bind publicly so a web app can reach it. We run
	// the user's installed provider; we never operate a tunnel ourselves.
	if cfg.tunnel != "" {
		tun, err := tunnel.Start(context.Background(), cfg.tunnel, cfg.addr, 45*time.Second)
		if err != nil {
			log.Fatalf("microagency: %v", err)
		}
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
			_ = tun.Close()
			os.Exit(0)
		}()
		fmt.Fprintf(os.Stderr, "  Public URL     %s/mcp  (paste into a web app's connector)\n\n", tun.PublicURL)
	}

	if err := http.ListenAndServe(cfg.addr, mcpMux); err != nil {
		fmt.Fprintf(os.Stderr, "microagency: %v\n", err)
		os.Exit(1)
	}
}

// announce connects the user to the running server. For OAuth the client runs the
// login flow, so we hand over no token — we auto-register just the URL with Claude
// Code (no token in argv either) and the client opens the one-click approve page.
// For bearer the token reaches Claude Code via the subprocess, never the shell.
func announce(srv *mcp.Server, cfg httpConfig, mode, bearer, opTokenFile string) {
	url := "http://" + cfg.addr + "/mcp"

	// Auto-register with Claude Code — a side effect that runs regardless of whether
	// we print the banner (OAuth registers the URL only; bearer includes the token).
	regToken := ""
	if mode == "bearer" {
		regToken = bearer
	}
	registered := !cfg.noRegister && claudeAvailable() && registerClaude(url, regToken)

	// The detached daemon child writes only structured, timestamped log lines — the
	// parent already printed the connect banner to the terminal. Don't dump the
	// human banner into the log.
	if os.Getenv("MICROAGENCY_DAEMON") == "1" {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  microagency is up — %s\n\n", url)
	switch mode {
	case "oauth-local", "oauth-external":
		if registered {
			fmt.Fprintf(os.Stderr, "  Connect        Added to Claude Code (this project). In Claude Code, run /mcp → Authenticate.\n")
			fmt.Fprintf(os.Stderr, "                 Any other client: paste %s and approve once.\n", url)
		} else {
			fmt.Fprintf(os.Stderr, "  Connect        Paste %s into any MCP client; it will prompt you to approve once.\n", url)
		}
		if mode == "oauth-external" {
			fmt.Fprintf(os.Stderr, "  Auth           OAuth (issuer %s)\n", cfg.issuer)
		}
	case "bearer":
		manualFile := opTokenFile
		if cfg.token != "" {
			manualFile = "" // explicit --token: the user knows it; don't point at the wrong file
		}
		if registered {
			fmt.Fprintf(os.Stderr, "  Connected      Claude Code (project scope). Remove with: claude mcp remove microagency\n")
		} else {
			printManualConnect(url, manualFile)
		}
		if cfg.tunnel != "" && manualFile != "" {
			fmt.Fprintf(os.Stderr, "  Public note    a web connector UI needs the token: cat %s\n", opTokenFile)
		}
	}
	fmt.Fprintf(os.Stderr, "  Console        http://%s/console   (operator token: cat %s)\n", consoleAddr(cfg), opTokenFile)
	if cfg.tunnel != "" && consoleAddr(cfg) != cfg.addr {
		fmt.Fprintf(os.Stderr, "                 loopback-only — the tunnel exposes /mcp, never the operator surface\n")
	}
	if engines := srv.EngineNames(); len(engines) > 0 {
		fmt.Fprintf(os.Stderr, "  Query engines  %s\n", strings.Join(engines, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "  Query engines  none — run `make engines` to enable\n")
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// printManualConnect prints a connect command that reads the token from its 0600
// file via $(cat …), so the secret never lands in shell history.
func printManualConnect(url, tokenFile string) {
	if tokenFile != "" {
		fmt.Fprintf(os.Stderr, "  Connect        claude mcp add --transport http microagency %s \\\n", url)
		fmt.Fprintf(os.Stderr, "                   --header \"Authorization: Bearer $(cat %s)\"\n", tokenFile)
		fmt.Fprintf(os.Stderr, "  Any client     point it at %s with that bearer header\n", url)
		return
	}
	fmt.Fprintf(os.Stderr, "  Connect        point your client at %s with header Authorization: Bearer <token>\n", url)
}

func claudeAvailable() bool {
	_, err := exec.LookPath("claude")
	return err == nil
}

// registerClaude adds this server to Claude Code at project (local) scope. With a
// token it's passed via the subprocess (never the shell); with token=="" (OAuth)
// only the URL is registered and the client runs the login flow itself.
//
// In OAuth mode, removing an existing entry would make Claude Code discard the
// tokens cached against it, forcing a re-login on every restart. So when the entry
// already exists with the same URL and we have no token to re-supply, we leave it
// untouched — the persistent signing key means the cached token still validates.
// We only remove-then-add when the URL changed, the entry is missing, or a static
// token needs re-supplying (that path never triggers a re-auth).
func registerClaude(url, token string) bool {
	if token == "" && claudeRegisteredURL() == url {
		return true // already registered at this URL; don't disturb the cached OAuth token
	}
	_ = exec.Command("claude", "mcp", "remove", "microagency", "-s", "local").Run()
	args := []string{"mcp", "add", "--transport", "http", "microagency", url, "-s", "local"}
	if token != "" {
		args = append(args, "--header", "Authorization: Bearer "+token)
	}
	return exec.Command("claude", args...).Run() == nil
}

// claudeRegisteredURL returns the URL Claude Code currently has registered for the
// microagency server at local scope, or "" if it isn't registered. It parses the
// "URL:" line of `claude mcp get`, which exits non-zero when the entry is absent.
func claudeRegisteredURL() string {
	out, err := exec.Command("claude", "mcp", "get", "microagency").Output()
	if err != nil {
		return ""
	}
	return parseRegisteredURL(out)
}

// parseRegisteredURL extracts the URL from `claude mcp get` output (the value of
// its "URL:" line), or "" if there isn't one.
func parseRegisteredURL(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if _, rest, ok := strings.Cut(strings.TrimSpace(line), "URL:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// oauthKeyPath is where the local OAuth signing key lives (0600), so issued tokens
// survive restarts.
func oauthKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "microagency-oauth-key")
	}
	return filepath.Join(home, ".microagency", "oauth-key")
}

// oauthClientsPath is where dynamic client registrations persist (0600), so a
// client's cached client_id stays known across restarts (no spurious re-auth).
func oauthClientsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "microagency-oauth-clients")
	}
	return filepath.Join(home, ".microagency", "oauth-clients.json")
}

// persistentToken reads-or-mints a stable bearer token at ~/.microagency/token
// (0600), so the client config and any auto-registration survive restarts. file is
// "" only when there is no home directory.
func persistentToken() (token, file string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return randomToken(), ""
	}
	file = filepath.Join(home, ".microagency", "token")
	if b, err := os.ReadFile(file); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, file
		}
	}
	t := randomToken()
	_ = os.MkdirAll(filepath.Dir(file), 0o700)
	_ = os.WriteFile(file, []byte(t), 0o600)
	return t, file
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("microagency: generate token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// buildServer wires the MCP gateway: the refstore-backed budget gate, the reduce
// substrate (wasm engines + a microVM router), and the upstream secret store.
// openPersistedRefs builds an encrypted, TTL'd file-backed refstore. The AES-256 key
// is a 0600 file under the state dir (generated on first use) — a local at-rest key
// for a single-user install; a KMS/Vault-held key is the hardening path.
func openPersistedRefs() (refstore.Store, error) {
	key, err := loadOrCreateRefsKey(filepath.Join(microagencyDir(), "refs.key"))
	if err != nil {
		return nil, err
	}
	return refstore.NewFileStore(filepath.Join(microagencyDir(), "refs"), key, 24*time.Hour, 10000)
}

// loadOrCreateRefsKey reads the 32-byte refs encryption key, minting and persisting
// one (0600) on first use.
func loadOrCreateRefsKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func buildServer(engineSpecs []string, wasmMaxMemMB, maxInlineBytes int, persistRefs bool, consoleAddr string) *mcp.Server {
	// One refstore backs the budget gate for both substrates AND the proxy path, so
	// a reffed result is resolvable regardless of which produced it. maxInlineBytes
	// (operator-set via --max-inline-bytes) is the single context budget everywhere.
	// In-memory by default; --persist-refs swaps in an encrypted, TTL'd file store so
	// <ref_> handles survive a restart (opt-in — it's a new at-rest liability).
	var store refstore.Store = refstore.NewMemStore()
	if persistRefs {
		if fs, err := openPersistedRefs(); err != nil {
			log.Printf("microagency: --persist-refs unavailable (%v) — using in-memory refs", err)
		} else {
			store = fs
			log.Printf("microagency: refs persisted (encrypted, 24h TTL) under %s", filepath.Join(microagencyDir(), "refs"))
		}
	}
	gate := budget.Gate{MaxBytes: maxInlineBytes, Store: store}
	rt := router.Router{
		Provider: sandbox.MicroagentProvider{},
		Gate:     gate,
		Image:    "docker.io/library/python:3.13-slim",
		CodePath: "/app/run.py",
		Timeout:  6 * time.Minute,
	}
	// Acquired secrets (upstream OAuth refresh tokens) persist in OpenBao/Vault when
	// VAULT_ADDR + VAULT_TOKEN are set, else a 0600 file under ~/.microagency.
	secStore := secretstore.Open(microagencyDir(), os.Getenv, http.DefaultClient)
	// Hand the store + gate to the Server so the PROXY path (aggregated MCP tool
	// calls) goes through reference-by-default minimization and the reffed results
	// are reducible off-context.
	opts := []mcp.Option{mcp.WithSecretStore(secStore), mcp.WithStateDir(microagencyDir()), mcp.WithBudgetGate(gate), mcp.WithVersion(version), mcp.WithConsoleAddr(consoleAddr)}
	// The wasm engines back reduce (a declarative reduction over a ref is computed
	// in the selected engine instead of running Python in a microVM). The engines
	// BUNDLED into the binary are registered automatically; each `--engine name=path`
	// adds or overrides one. All engines share the budget gate.
	addEngine := func(name string, mod []byte) {
		opts = append(opts, mcp.WithWasmEngine(name, wasmexec.SandboxEngine{
			Module:         mod,
			Timeout:        2 * time.Minute,
			MaxMemoryPages: uint32(wasmMaxMemMB) * 16, // 64 KiB pages → MiB
		}))
	}
	for name, mod := range bundledEngines() {
		addEngine(name, mod)
	}
	for _, spec := range engineSpecs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || name == "" || path == "" {
			log.Fatalf("microagency: --engine expects name=path, got %q", spec)
		}
		mod, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("microagency: read engine %q: %v", path, err)
		}
		addEngine(name, mod)
	}
	// Field minimizers: bundled wasip1 modules that redact/tokenize/alert on
	// sensitive FIELD values at the egress-to-model boundary (the fine-grained
	// complement to reference-by-default). Loaded into a warm cluster and installed
	// as an ordered pipeline; per-upstream policy (set from the console) decides what
	// actually fires — with no policy for an upstream, nothing changes.
	if mods := bundledMinimizers(); len(mods) > 0 {
		names := make([]string, 0, len(mods))
		for n := range mods {
			names = append(names, n)
		}
		sort.Strings(names)
		var chain []minimize.Module
		for _, n := range names {
			m, err := minimize.LoadWasm(context.Background(), n, mods[n], minimize.Options{
				Timeout:        30 * time.Second,
				MaxMemoryPages: uint32(wasmMaxMemMB) * 16,
			})
			if err != nil {
				log.Printf("microagency: minimizer %q unavailable: %v", n, err)
				continue
			}
			chain = append(chain, m)
		}
		if len(chain) > 0 {
			opts = append(opts, mcp.WithMinimizer(minimize.Pipeline{Modules: chain}, minimize.NewMemTokenStore()))
		}
	}
	return mcp.NewServer(rt, opts...)
}
