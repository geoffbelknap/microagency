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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"microagency/internal/app"
	"microagency/internal/auth"
	"microagency/internal/baomanager"
	"microagency/internal/console"
	"microagency/internal/gateway"
	"microagency/internal/mcp"
	"microagency/internal/optoken"
	"microagency/internal/portal"
	"microagency/internal/secretstore"
	"microagency/internal/tunnel"
)

// Build stamp, set via -ldflags at release time (GoReleaser). "dev" for a plain
// `go build`; the binary also carries the VCS revision via debug.ReadBuildInfo.
var (
	version = "dev"
	commit  = ""
)

// setupLogging routes structured logs (slog) to stderr — which the daemon parent
// redirects to ~/.microagency/microagency.log. Level from MICROAGENCY_LOG_LEVEL
// (debug|info|warn|error), default info.
func setupLogging() {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("MICROAGENCY_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

// fatal logs a structured error and exits non-zero — the slog replacement for the
// startup log.Fatalf sites (a running server logs and recovers; startup can't).
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func main() {
	setupLogging()
	gateway.ClientVersion = version // identify the real build to upstream MCP servers
	args := os.Args[1:]
	if len(args) < 1 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(os.Stdout)
	case "version", "--version", "-v":
		printVersion()
	case "up":
		run(args[1:])
	case "down":
		runDown(args[1:])
	case "restart":
		runRestart(args[1:])
	case "purge":
		runPurge(args[1:])
	case "doctor":
		runDoctor(args[1:])
	case "openbao":
		runOpenBao(args[1:])
	case "secret-store":
		runSecretStore(args[1:])
	case "hook":
		runHook(args[1:])
	case "mediation":
		runMediation(args[1:])
	case "token":
		runToken(args[1:])
	default:
		// The usage dump never named the input, so "doctr" got 20 lines with
		// zero occurrences of "doctr" and no suggestion — while an unknown
		// FLAG already got a named one-liner. Echo it, suggest the near miss
		// from the same switch above, and point at help.
		if near := nearestCommand(args[0]); near != "" {
			fmt.Fprintf(os.Stderr, "microagency: unknown command %q (did you mean %q?)\n", args[0], near)
		} else {
			fmt.Fprintf(os.Stderr, "microagency: unknown command %q\n", args[0])
		}
		fmt.Fprintln(os.Stderr, "Run 'microagency help' for the command list.")
		os.Exit(2)
	}
}

// commandNames is the dispatch set above, for suggestions — keep in step with
// the switch.
var commandNames = []string{"help", "version", "up", "down", "restart", "purge", "doctor", "secret-store", "openbao", "hook", "mediation", "token"}

// nearestCommand suggests the closest command: edit distance ≤ 2, or a
// unique 3+ character prefix. Nonsense gets no confident wrong guess.
func nearestCommand(input string) string {
	best, bestDist := "", 3
	for _, c := range commandNames {
		if d := editDistance(input, c); d < bestDist {
			best, bestDist = c, d
		}
		if len(input) >= 3 && strings.HasPrefix(c, input) && bestDist > 1 {
			best, bestDist = c, 1
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev = cur
	}
	return prev[len(b)]
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

// usage writes the whole surface: the command list plus up's flags, which
// dominate the CLI. Help paths pass stdout; failure paths pass stderr, so a
// script capturing output never confuses an answer with a complaint.
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency up [flags]    start the MCP server (runs in the background)")
	fmt.Fprintln(w, "  microagency down          stop the background server")
	fmt.Fprintln(w, "  microagency restart [flags]  restart the background server (keeps OpenBao up)")
	fmt.Fprintln(w, "  microagency purge [--full] delete your data (--full wipes everything; both confirm)")
	fmt.Fprintln(w, "  microagency doctor        check runtime + engine health")
	fmt.Fprintln(w, "  microagency secret-store  inspect or migrate credential-store data-key custody")
	fmt.Fprintln(w, "  microagency openbao       inspect or migrate managed OpenBao custody")
	fmt.Fprintln(w, "  microagency hook install  print the Claude Code egress-guard hook setup")
	fmt.Fprintln(w, "  microagency mediation     configure or inspect enforced workspace mediation")
	fmt.Fprintln(w, "  microagency token         manage named operator tokens for /admin and the console")
	fmt.Fprintln(w, "")
	upFlags(w)
}

// upHelp answers `up --help` with up's own contract instead of the global
// dump. Before the split, up was the one command whose --help produced the
// full command list — the same bytes a typo produced — so "did I ask a
// question or make a mistake" was unanswerable from the output.
func upHelp(w io.Writer) {
	fmt.Fprintln(w, "usage: microagency up [flags]")
	fmt.Fprintln(w, "  start the MCP server (runs in the background; stop with `microagency down`)")
	fmt.Fprintln(w, "")
	upFlags(w)
}

func upFlags(w io.Writer) {
	fmt.Fprintln(w, "  up flags:")
	fmt.Fprintln(w, "    --http <addr>         bind address (default 127.0.0.1:8765)")
	fmt.Fprintln(w, "    --public              expose built-in OAuth + /mcp via Cloudflare")
	fmt.Fprintln(w, "    --tunnel <provider>   tunnel provider: cloudflare (default with --public) or ngrok")
	fmt.Fprintln(w, "    --tunnel-name <name>  run a named Cloudflare tunnel you created (stable URL; tokens survive restarts)")
	fmt.Fprintln(w, "    --tunnel-url <url>    the named tunnel's public https:// origin (required with --tunnel-name)")
	fmt.Fprintln(w, "    --single-user         acknowledge that the public built-in OAuth serves ONE person:")
	fmt.Fprintln(w, "                          every remote client authenticates as you (required with a tunnel")
	fmt.Fprintln(w, "                          unless --issuer, --sso-issuer, or --token selects another auth mode)")
	fmt.Fprintln(w, "    --sso-issuer <url>    federate built-in OAuth sign-in to an OIDC identity provider")
	fmt.Fprintln(w, "                          (e.g. https://accounts.google.com); each person becomes a distinct principal")
	fmt.Fprintln(w, "    --sso-client-id <id>  the OAuth client registered at the SSO provider for this gateway")
	fmt.Fprintln(w, "    --sso-client-secret-file <path>  file holding that client's secret (or set")
	fmt.Fprintln(w, "                          "+ssoClientSecretEnv+" once; stored in the secret store, never argv)")
	fmt.Fprintln(w, "    --sso-hd <domain>     require the provider's hd (hosted domain) claim to equal <domain>")
	fmt.Fprintln(w, "    --foreground          run attached instead of backgrounding")
	fmt.Fprintln(w, "    --stdio               serve over stdin/stdout (client-spawned)")
	fmt.Fprintln(w, "    --no-register         don't auto-register with Claude Code")
	fmt.Fprintln(w, "    --token <tok>         use a static bearer instead of OAuth (compatibility)")
	fmt.Fprintln(w, "    --issuer/--audience   external OAuth resource-server mode")
	fmt.Fprintln(w, "    --require-scope <s>   with --issuer: refuse tokens not granted this OAuth scope")
	fmt.Fprintln(w, "    --high-assurance-multi-user  require exact principal/campaign operation grants (external issuer)")
	fmt.Fprintln(w, "    --admin-addr <addr>   bind /admin + /console on a separate listener")
	fmt.Fprintln(w, "                          (defaults to "+defaultAdminAddr+" when a tunnel is used)")
	fmt.Fprintln(w, "    --allow-remote-admin  serve /admin + /console on a non-loopback bind (cleartext HTTP,")
	fmt.Fprintln(w, "                          operator token only — required when --http or --admin-addr leaves")
	fmt.Fprintln(w, "                          loopback; prefer a loopback bind reached over SSH forwarding)")
	fmt.Fprintln(w, "    --allow-plaintext-credentials  keep upstream credentials in the UNENCRYPTED")
	fmt.Fprintln(w, "                          mode-0600 file store when no vault is reachable (or set")
	fmt.Fprintln(w, "                          "+secretstore.AllowPlaintextEnv+"=1). Without it,")
	fmt.Fprintln(w, "                          a start that would land there refuses. Encrypting the")
	fmt.Fprintln(w, "                          fallback with "+secretstore.ProtectorEnv+" or")
	fmt.Fprintln(w, "                          "+secretstore.FileKeyEnv+" needs no opt-in.")
	fmt.Fprintln(w, "    --engine name=path    add a query engine (a wasip1 module)")
	fmt.Fprintln(w, "    --max-inline-bytes N  results larger than N bytes return as a reference (default 8192)")
	fmt.Fprintln(w, "    --persist-refs        keep reffed data across restart (encrypted at rest, 24h TTL)")
	fmt.Fprintln(w, "    --reduce-engines-only disable the microVM reduce path (wasm engines only; for hosts without nested virt)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Add MCP servers from the console (http://<addr>/console), not here.")
}

// run starts the server. That's all it does — adding upstream MCPs is the
// console's job (/admin), not a startup flag. The HTTP server runs in
// the BACKGROUND by default (`up` returns the terminal; stop with `microagency
// down`); --stdio serves over stdin/stdout for a client that spawns the binary.
// upOptions is `up`'s argument list in parsed form, split from acting on it
// so restart can validate arguments while there is still nothing to undo.
type upOptions struct {
	httpAddr, token                     string
	issuer, audience, tunnel, adminAddr string
	tunnelName, tunnelURL               string
	requireScope                        string
	wasmMaxMemMB                        int // per-wasm-run memory ceiling (ASK tenet 8 — bounded ops)
	// Results larger than maxInlineBytes come back as a reference, not raw
	// data. 8 KiB (not 2 KiB): real API responses cluster just over 2 KB, so a
	// low bar parked ordinary small answers behind a reduce round-trip;
	// genuinely large data (documents, row dumps) still parks. The ref now
	// carries a structural preview, so even parked results often need no
	// reduce.
	maxInlineBytes                        int
	stdio, public, noRegister, foreground bool
	persistRefs                           bool // opt-in: persist reffed payloads (encrypted, TTL'd) so refs survive restart
	// reduceEnginesOnly disables the microVM reduce path (arbitrary-code
	// reduce), leaving only the in-process wasm engines. Required where there
	// is no nested virtualization to run a microVM in — e.g. microagency
	// itself running inside a microVM.
	reduceEnginesOnly      bool
	highAssuranceMultiUser bool
	// singleUser acknowledges that a public tunnel in front of the built-in
	// OAuth server serves exactly one person — the local operator. Without it,
	// a tunnel with built-in OAuth refuses to start (see validateHTTPConfig).
	singleUser bool
	// allowRemoteAdmin acknowledges serving the operator surface (/admin +
	// /console) on a non-loopback bind. Without it, such a bind refuses to
	// start (see validateHTTPConfig).
	allowRemoteAdmin bool
	// allowPlaintextCredentials acknowledges keeping upstream credentials in the
	// unencrypted mode-0600 file store. Without it — or MICROAGENCY_ALLOW_
	// PLAINTEXT_CREDENTIALS — a start that would land there refuses, so an
	// unreachable OpenBao cannot silently move credentials into the clear.
	allowPlaintextCredentials bool
	// SSO federation: the built-in OAuth server stays the authorization server
	// toward MCP clients, but sign-in is delegated to this OIDC provider, so
	// each person is a distinct principal. The client secret never rides argv:
	// it arrives via MICROAGENCY_SSO_CLIENT_SECRET or --sso-client-secret-file
	// and lives in the secret store.
	ssoIssuer, ssoClientID, ssoClientSecretFile, ssoHD string
	engineSpecs                                        []string
	help                                               bool
}

func parseUpOptions(args []string) (upOptions, error) {
	o := upOptions{httpAddr: "127.0.0.1:8765", wasmMaxMemMB: 512, maxInlineBytes: 8192}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--http" && i+1 < len(args):
			o.httpAddr = args[i+1]
			i++
		case args[i] == "--token" && i+1 < len(args):
			o.token = args[i+1]
			i++
		case args[i] == "--issuer" && i+1 < len(args):
			o.issuer = args[i+1]
			i++
		case args[i] == "--require-scope" && i+1 < len(args):
			o.requireScope = args[i+1]
			i++
		case args[i] == "--audience" && i+1 < len(args):
			o.audience = args[i+1]
			i++
		case args[i] == "--tunnel" && i+1 < len(args):
			o.tunnel = args[i+1]
			i++
		case args[i] == "--tunnel-name" && i+1 < len(args):
			o.tunnelName = args[i+1]
			i++
		case args[i] == "--tunnel-url" && i+1 < len(args):
			o.tunnelURL = args[i+1]
			i++
		case args[i] == "--admin-addr" && i+1 < len(args):
			o.adminAddr = args[i+1] // bind /admin + /console on their own listener
			i++
		case args[i] == "--sso-issuer" && i+1 < len(args):
			o.ssoIssuer = args[i+1]
			i++
		case args[i] == "--sso-client-id" && i+1 < len(args):
			o.ssoClientID = args[i+1]
			i++
		case args[i] == "--sso-client-secret-file" && i+1 < len(args):
			o.ssoClientSecretFile = args[i+1]
			i++
		case args[i] == "--sso-hd" && i+1 < len(args):
			o.ssoHD = args[i+1]
			i++
		case args[i] == "--engine" && i+1 < len(args):
			o.engineSpecs = append(o.engineSpecs, args[i+1]) // name=path; repeatable
			i++
		case args[i] == "--wasm-max-memory-mb" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return o, fmt.Errorf("--wasm-max-memory-mb must be a positive integer, got %q", args[i+1])
			}
			o.wasmMaxMemMB = n
			i++
		case args[i] == "--max-inline-bytes" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return o, fmt.Errorf("--max-inline-bytes must be a positive integer, got %q", args[i+1])
			}
			o.maxInlineBytes = n
			i++
		case args[i] == "--stdio":
			o.stdio = true
		case args[i] == "--public":
			o.public = true
		case args[i] == "--persist-refs":
			o.persistRefs = true
		case args[i] == "--reduce-engines-only":
			o.reduceEnginesOnly = true
		case args[i] == "--high-assurance-multi-user":
			o.highAssuranceMultiUser = true
		case args[i] == "--single-user":
			o.singleUser = true
		case args[i] == "--allow-remote-admin":
			o.allowRemoteAdmin = true
		case args[i] == "--allow-plaintext-credentials":
			o.allowPlaintextCredentials = true
		case args[i] == "--no-register":
			o.noRegister = true
		case args[i] == "--foreground":
			o.foreground = true // run attached (don't background) — for debugging
		case args[i] == "-h" || args[i] == "--help" || args[i] == "help":
			o.help = true
			return o, nil
		default:
			return o, fmt.Errorf("unknown argument: %s", args[i])
		}
	}
	if o.highAssuranceMultiUser && o.issuer == "" {
		return o, fmt.Errorf("--high-assurance-multi-user requires --issuer with a signed campaign or campaign_id claim")
	}
	// SSO federation is one contract: the issuer names the provider and the
	// client id names this gateway's registration there. The secret-file and
	// hosted-domain flags refine that contract and mean nothing without it.
	if o.ssoIssuer == "" {
		switch {
		case o.ssoClientID != "":
			return o, fmt.Errorf("--sso-client-id requires --sso-issuer (the OIDC provider it registers with)")
		case o.ssoClientSecretFile != "":
			return o, fmt.Errorf("--sso-client-secret-file requires --sso-issuer (the OIDC provider the secret belongs to)")
		case o.ssoHD != "":
			return o, fmt.Errorf("--sso-hd requires --sso-issuer (the OIDC provider that asserts the hd claim)")
		}
	} else if o.ssoClientID == "" {
		return o, fmt.Errorf("--sso-issuer requires --sso-client-id (the OAuth client registered at the provider)")
	}
	// A named tunnel is one contract with two halves: the tunnel to run and the
	// stable origin it serves. Half a contract fails closed with both named.
	if (o.tunnelName == "") != (o.tunnelURL == "") {
		return o, fmt.Errorf("--tunnel-name and --tunnel-url must be set together (the name picks the tunnel to run; the URL is its public origin)")
	}
	if o.tunnelName != "" {
		if o.tunnel != "" && o.tunnel != "cloudflare" {
			return o, fmt.Errorf("--tunnel-name works with --tunnel cloudflare only (got --tunnel %s)", o.tunnel)
		}
		normalized, err := normalizeTunnelURL(o.tunnelURL)
		if err != nil {
			return o, err
		}
		o.tunnelURL = normalized
	}
	return o, nil
}

// normalizeTunnelURL validates the operator-declared public origin for a named
// tunnel. It becomes the OAuth issuer and resource base, so anything beyond a
// plain https:// origin — a path, query, fragment, or embedded credentials —
// would corrupt every derived endpoint. The returned form has no trailing
// slash.
func normalizeTunnelURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("--tunnel-url must be a plain https:// origin like https://mcp.example.com, got %q", raw)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func run(args []string) {
	o, err := parseUpOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if o.help {
		upHelp(os.Stdout)
		return
	}
	httpAddr, token := o.httpAddr, o.token
	issuer, audience, tunnelProvider, adminAddr := o.issuer, o.audience, o.tunnel, o.adminAddr
	requireScope := o.requireScope
	stdio, public, noRegister, foreground := o.stdio, o.public, o.noRegister, o.foreground

	if (public || o.tunnelName != "") && tunnelProvider == "" {
		tunnelProvider = "cloudflare"
	}
	if token == "" {
		token = os.Getenv("MICROAGENCY_TOKEN")
	}
	cfg := httpConfig{
		addr: httpAddr, adminAddr: adminAddr, token: token,
		issuer: issuer, audience: audience, requireScope: requireScope,
		tunnel: tunnelProvider, tunnelName: o.tunnelName, tunnelURL: o.tunnelURL,
		noRegister: noRegister, singleUser: o.singleUser, allowRemoteAdmin: o.allowRemoteAdmin,
		ssoIssuer: o.ssoIssuer, ssoClientID: o.ssoClientID,
		ssoClientSecretFile: o.ssoClientSecretFile, ssoHD: o.ssoHD,
	}
	if err := validateHTTPConfig(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
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
	// doesn't aggregate upstreams, so it skips this. If Bao can't come up, the
	// server builder selects the configured local posture: operator-key encrypted,
	// or — only on an explicit opt-in — the unencrypted mode-0600 fallback.
	cred := credentialIntent{allowPlaintext: o.allowPlaintextCredentials || envEnabled(os.Getenv(secretstore.AllowPlaintextEnv))}
	if !stdio {
		cred.preferred = "managed OpenBao"
		if os.Getenv("VAULT_ADDR") != "" {
			cred.preferred = "external Vault/OpenBao (VAULT_ADDR)"
		}
		addr, vaultTok, err := baomanager.Ensure(context.Background(), filepath.Join(microagencyDir(), "openbao"), os.Getenv)
		switch {
		case err == nil:
			_ = os.Setenv("VAULT_ADDR", addr)
			_ = os.Setenv("VAULT_TOKEN", vaultTok)
		case baomanager.FailClosed(err):
			fatal("managed OpenBao protected custody is unavailable; refusing a credential-store downgrade", "err", err)
		default:
			cred.unavailable = credentialStoreUnavailable(err)
			reportOpenBaoUnavailable(err)
		}
	}

	srv := buildServer(o, consoleAddr(cfg), cred)

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
		fatal("resolve executable", "err", err)
	}
	dir := microagencyDir()
	_ = os.MkdirAll(dir, 0o700)
	logPath := filepath.Join(dir, "microagency.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fatal("open log file", "err", err)
	}
	defer func() { _ = logf.Close() }()
	// Where this run's output starts, so a child that exits on startup can have
	// its own reason shown here rather than in a log file nobody opens.
	logStart, _ := logf.Seek(0, io.SeekEnd)

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "MICROAGENCY_DAEMON=1")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from the terminal
	if err := cmd.Start(); err != nil {
		fatal("start daemon", "err", err)
	}
	pid := cmd.Process.Pid
	_ = os.WriteFile(pidPath(), []byte(strconv.Itoa(pid)), 0o600)

	// Give it a moment to bind; surface an immediate exit (a port already in
	// use, a credential store the gateway refuses to open).
	time.Sleep(700 * time.Millisecond)
	if childExited(pid) {
		fmt.Fprintf(os.Stderr, "microagency: server exited on startup — see %s\n", logPath)
		writeChildOutput(os.Stderr, logPath, logStart)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\n  microagency is up in the background (pid %d).\n\n", pid)
	fmt.Fprintf(os.Stderr, "    MCP endpoint   http://%s/mcp   (in Claude Code: /mcp → Authenticate)\n", cfg.addr)
	if servesPortal(cfg) {
		fmt.Fprintf(os.Stderr, "    Account portal http://%s%s\n", cfg.addr, portal.Path)
	}
	fmt.Fprintf(os.Stderr, "    Console        http://%s/console\n", consoleAddr(cfg))
	if ra := remoteAdminAddr(cfg); ra != "" {
		fmt.Fprintf(os.Stderr, "    WARNING        /admin + /console are reachable beyond loopback on %s (--allow-remote-admin)\n", ra)
		fmt.Fprintln(os.Stderr, "                   cleartext HTTP, operator token only — front it with TLS, or bind loopback and use SSH forwarding")
	}
	if cfg.tunnel != "" {
		if cfg.tunnelName != "" {
			fmt.Fprintf(os.Stderr, "    Tunnel         %s (named tunnel %q, stable across restarts) — exposes /mcp only; the console stays loopback\n", cfg.tunnelURL, cfg.tunnelName)
		} else {
			fmt.Fprintf(os.Stderr, "    Tunnel         public URL appears in the logs — it exposes /mcp only; the console stays loopback\n")
		}
		switch {
		case cfg.issuer != "":
			fmt.Fprintf(os.Stderr, "    Public auth    external OAuth (%s)\n", cfg.issuer)
		case cfg.token != "":
			fmt.Fprintln(os.Stderr, "    Public auth    explicit static bearer")
		case cfg.ssoIssuer != "":
			fmt.Fprintf(os.Stderr, "    Public auth    built-in OAuth, sign-in federated to %s\n", cfg.ssoIssuer)
			if cfg.ssoHD != "" {
				fmt.Fprintf(os.Stderr, "                   accounts must carry hd=%s; each person is a distinct principal\n", cfg.ssoHD)
			} else {
				fmt.Fprintln(os.Stderr, "                   each person signs in at the provider and is a distinct principal")
			}
		default:
			fmt.Fprintf(os.Stderr, "    Public auth    built-in OAuth, single-user — every remote client authenticates as %q\n", localSubject())
			fmt.Fprintln(os.Stderr, "                   consent stays on the loopback operator listener")
		}
	}
	startupCredentialLine(os.Stderr, microagencyDir(), pid, 2*time.Second)
	fmt.Fprintf(os.Stderr, "    Logs           %s\n", logPath)
	fmt.Fprintf(os.Stderr, "    Stop           microagency down\n\n")
	upgradeNudge()
}

// childExited reports whether the daemon child is already gone. A plain
// `kill(pid, 0)` is not enough: an unreaped child is a zombie, which still
// accepts signal 0, so a start that refused in under a second was reported as
// "up in the background". Reaping without blocking answers the real question.
func childExited(pid int) bool {
	var ws syscall.WaitStatus
	reaped, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
	if err == nil && reaped == pid {
		return true
	}
	return syscall.Kill(pid, 0) != nil
}

// writeChildOutput replays what the child wrote before exiting. Pointing at a
// log file costs the operator a second command to learn something already
// written; a refusal that explains itself should reach the terminal that asked.
func writeChildOutput(w io.Writer, logPath string, from int64) {
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return
	}
	// Bounded: a crash loop can write a lot, and the log stays authoritative.
	b, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil || len(b) == 0 {
		return
	}
	fmt.Fprintln(w)
	_, _ = w.Write(b)
}

// startupCredentialLine prints where this gateway's credentials actually
// landed. A store downgrade that reaches only the log file is a downgrade
// nobody reads: the gateway starts, every call keeps working, and nothing
// prompts the second look that would find the credentials in the clear. The
// child records the store as it opens it, so the parent reports that record
// rather than re-deriving an answer that could differ from the child's.
func startupCredentialLine(w io.Writer, stateDir string, pid int, wait time.Duration) {
	deadline := time.Now().Add(wait)
	for {
		if p, err := secretstore.LoadPosture(stateDir); err == nil && p.PID == pid {
			switch {
			case p.Disagrees():
				fmt.Fprintf(w, "    Credentials    ⚠ %s\n", p.Effective)
				fmt.Fprintf(w, "                   NOT the configured %s", p.Configured)
				if p.Reason != "" {
					fmt.Fprintf(w, " — %s", p.Reason)
				}
				fmt.Fprintln(w, "")
				fmt.Fprintln(w, "                   run `microagency doctor` for the full posture")
			case p.Degraded:
				fmt.Fprintf(w, "    Credentials    ⚠ %s (NOT encrypted at rest)\n", p.Effective)
			default:
				fmt.Fprintf(w, "    Credentials    %s\n", p.Effective)
			}
			return
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(w, "    Credentials    still resolving — `microagency doctor` reports the store in effect")
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
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
func runDown(args []string) {
	// --help must never act. Parse arguments before touching the running
	// server: this used to discard args entirely, so `down --help` stopped
	// the gateway instead of explaining it.
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stdout, "usage: microagency down")
			fmt.Fprintln(os.Stdout, "  stop the background server (and any managed OpenBao)")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", a)
			os.Exit(2)
		}
	}
	if pid := runningPID(); pid != 0 {
		if kerr := syscall.Kill(pid, syscall.SIGTERM); kerr != nil {
			fmt.Fprintf(os.Stderr, "microagency: stop pid %d: %v\n", pid, kerr)
		} else {
			fmt.Fprintf(os.Stderr, "microagency: stopped (pid %d)\n", pid)
		}
		_ = os.Remove(pidPath())
		// The credential-store record describes a gateway that is now gone; a
		// record outliving its run is exactly the stale state that makes a
		// diagnostic lie.
		secretstore.ClearPosture(microagencyDir())
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
	// Parse before acting. restart used to stop the server first and look at
	// its arguments never: `restart --help` killed the gateway and printed
	// usage over its corpse, and `restart --bogus` killed it and started
	// nothing. Validation has to finish while there is still nothing to undo.
	o, err := parseUpOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "the server was not stopped")
		os.Exit(2)
	}
	if o.help {
		fmt.Fprintln(os.Stdout, "usage: microagency restart [up flags]")
		fmt.Fprintln(os.Stdout, "  stop the background server, then start a fresh one with the given flags")
		fmt.Fprintln(os.Stdout, "  (managed OpenBao keeps running; see `microagency up --help` for the flags)")
		return
	}
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
			fmt.Fprintln(os.Stdout, "usage: microagency purge [--full] [--yes]")
			fmt.Fprintln(os.Stdout, "  (default) delete parked data (refs) + run/audit history; keep connections & auth")
			fmt.Fprintln(os.Stdout, "  --full    delete EVERYTHING under ~/.microagency (re-authenticate afterward)")
			fmt.Fprintln(os.Stdout, "  --yes,-y  skip the confirmation prompt")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown argument: %s\n", a)
			os.Exit(2)
		}
	}
	dir := microagencyDir()
	if full {
		// A full purge recursively removes `dir`. microagencyDir() falls back to
		// os.TempDir() when the home directory can't be resolved (HOME unset) — deleting
		// that would wipe an unrelated directory the user pointed TMPDIR at. Require a
		// resolvable, correctly-named state dir before doing anything destructive.
		if err := verifyFullPurgeTarget(dir); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: refusing --full purge: %v\n", err)
			os.Exit(1)
		}
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
		if err := baomanager.DeleteCustody(context.Background(), filepath.Join(dir, "openbao"), os.Getenv); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: purge: protected OpenBao bootstrap was not deleted: %v\n", err)
			fmt.Fprintln(os.Stderr, "The state directory was kept so the protector record can still be located; restore protector access and retry.")
			os.Exit(1)
		}
		// The credential store's data key lives outside this directory too, and
		// the locator that finds it lives inside. Delete the record first, or
		// removing the directory strands it in the keyring or KMS forever.
		if err := secretstore.DeleteKeyCustody(context.Background(), dir, os.Getenv); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: purge: the protected credential-store data key was not deleted: %v\n", err)
			fmt.Fprintln(os.Stderr, "The state directory was kept so the protector record can still be located; restore protector access and retry.")
			os.Exit(1)
		}
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

// verifyFullPurgeTarget guards the recursive `purge --full` deletion. It fails closed
// unless the home directory resolves AND the target is exactly the "~/.microagency"
// state dir — so an unset HOME (which makes microagencyDir fall back to os.TempDir())
// or any unexpected path can never be handed to os.RemoveAll.
func verifyFullPurgeTarget(dir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory could not be resolved (is $HOME set?); resolve it and retry")
	}
	want := filepath.Join(home, ".microagency")
	if filepath.Clean(dir) != filepath.Clean(want) {
		return fmt.Errorf("target %q is not the expected state directory %q", dir, want)
	}
	return nil
}

type httpConfig struct {
	addr, adminAddr, token, issuer, audience, tunnel string
	tunnelName                                       string // named-tunnel mode: the operator-created tunnel to run
	tunnelURL                                        string // named-tunnel mode: the operator-declared stable https origin
	publicURL                                        string // scraped from a quick tunnel or declared via --tunnel-url, never from request headers
	authDir                                          string // test-only override; production uses ~/.microagency
	requireScope                                     string // with --issuer: OAuth scope a token must carry to reach /mcp
	ssoIssuer                                        string // federate built-in OAuth sign-in to this OIDC provider
	ssoClientID                                      string // the gateway's OAuth client at the SSO provider
	ssoClientSecretFile                              string // file holding that client's secret (stored in the secret store)
	ssoHD                                            string // required hd (hosted domain) claim, enforced server-side
	noRegister                                       bool
	singleUser                                       bool // explicit acknowledgment that public built-in OAuth serves one person
	allowRemoteAdmin                                 bool // explicit acknowledgment of a non-loopback operator surface
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

// remoteAdminAddr returns the address on which the operator surface (/admin +
// /console) would be reachable beyond loopback, or "" while it stays local.
// With no separate operator listener the agent bind serves the operator
// surface too, so its host decides. An address that does not parse is left to
// fail at bind time, exactly as it does today.
func remoteAdminAddr(cfg httpConfig) string {
	addr := effectiveAdminAddr(cfg)
	if addr == "" {
		addr = cfg.addr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if !loopbackHost(host) {
		return addr
	}
	return ""
}

// validateRemoteAdminToken refuses an operator surface beyond loopback that
// no credential could authenticate: an empty legacy token disables that
// credential path (never auth itself), so with no named operator tokens
// either, every /admin request would be refused — a misconfiguration to
// surface at startup, not from remote 401s. The shipped CLI always mints the
// legacy token, so this guards the invariant against regressions in how the
// credentials are sourced.
func validateRemoteAdminToken(cfg httpConfig, opAuth mcp.OperatorAuth) error {
	ra := remoteAdminAddr(cfg)
	if ra == "" || strings.TrimSpace(opAuth.LegacyToken) != "" {
		return nil
	}
	if opAuth.Tokens != nil {
		if named, err := opAuth.Tokens.List(); err == nil && len(named) > 0 {
			return nil // named operator tokens still authenticate the surface
		}
	}
	return fmt.Errorf("the operator surface on %s is reachable beyond loopback with no credential that could authenticate it (empty legacy token, no named operator tokens), so every /admin request would be refused.\n"+
		"  Restore the legacy token file (~/.microagency/token), or create a named token: microagency token create <name> --role admin", ra)
}

func validateHTTPConfig(cfg httpConfig) error {
	// SSO federation keeps the built-in OAuth server; --issuer replaces it and
	// --token bypasses OAuth entirely, so combining them cannot mean anything.
	if cfg.ssoIssuer != "" && cfg.issuer != "" {
		return fmt.Errorf("--sso-issuer and --issuer are mutually exclusive: --sso-issuer federates the built-in OAuth server's sign-in, --issuer replaces the built-in server with an external one; drop one of them")
	}
	if cfg.ssoIssuer != "" && cfg.token != "" {
		return fmt.Errorf("--sso-issuer and --token are mutually exclusive: --token selects static bearer mode, which does not use the built-in OAuth server; drop one of them")
	}
	if cfg.ssoIssuer != "" && cfg.singleUser {
		return fmt.Errorf("--sso-issuer and --single-user are mutually exclusive: federated sign-in makes each person a distinct principal, which is exactly what --single-user disclaims; drop one of them")
	}
	if cfg.tunnel == "" {
		if cfg.singleUser {
			return fmt.Errorf("--single-user only applies to a public tunnel; add --public or --tunnel, or drop the flag")
		}
		ra := remoteAdminAddr(cfg)
		if ra != "" && !cfg.allowRemoteAdmin {
			flag := "--http"
			if effectiveAdminAddr(cfg) != "" {
				flag = "--admin-addr"
			}
			// The operator surface holds credential custody and out-of-band data
			// materialization behind one bearer compare, over cleartext HTTP.
			// Leaving loopback with it must be chosen, not defaulted into.
			return fmt.Errorf("refusing to serve /admin and /console beyond loopback: %s %s exposes the operator surface (credential custody, parked-data retrieval) over cleartext HTTP, gated only by the operator token.\n"+
				"  Keeping it local: bind a loopback address (the default) and reach it over SSH port forwarding.\n"+
				"  Exposing it deliberately: add --allow-remote-admin to accept that posture", flag, ra)
		}
		if cfg.allowRemoteAdmin && ra == "" {
			return fmt.Errorf("--allow-remote-admin only applies when --http or --admin-addr binds the operator surface beyond loopback; drop the flag or change the bind")
		}
		return nil
	}
	if cfg.allowRemoteAdmin {
		return fmt.Errorf("--allow-remote-admin does not apply with a public tunnel: the tunnel keeps the operator surface loopback-only; drop the flag")
	}
	if cfg.singleUser && cfg.issuer != "" {
		return fmt.Errorf("--single-user and --issuer are mutually exclusive: --single-user acknowledges the single-user built-in OAuth server, --issuer replaces it with an external one; drop one of them")
	}
	if cfg.singleUser && cfg.token != "" {
		return fmt.Errorf("--single-user and --token are mutually exclusive: --token selects static bearer mode, which does not use the built-in OAuth server; drop one of them")
	}
	agentHost, _, err := net.SplitHostPort(cfg.addr)
	if err != nil || !loopbackHost(agentHost) {
		return fmt.Errorf("a public tunnel requires --http to use a loopback address")
	}
	adminAddr := effectiveAdminAddr(cfg)
	adminHost, _, err := net.SplitHostPort(adminAddr)
	if err != nil || !loopbackHost(adminHost) {
		return fmt.Errorf("a public tunnel requires the operator listener to use a loopback --admin-addr")
	}
	if canonicalListenAddr(adminAddr) == canonicalListenAddr(cfg.addr) {
		return fmt.Errorf("a public tunnel requires a separate operator listener; --admin-addr cannot equal --http")
	}
	// Public exposure of the built-in OAuth server is never silent. Without
	// federation the built-in server identifies exactly one person — every token
	// it issues carries the local operator's identity — so several humans
	// connecting through the tunnel would merge into one caller: shared
	// connections, shared credentials, shared parked data. That posture must be
	// chosen, not defaulted into. Federated sign-in (--sso-issuer) is the
	// multi-user remedy: each person authenticates at the identity provider and
	// becomes a distinct principal, so no acknowledgment is needed.
	if cfg.issuer == "" && cfg.token == "" && cfg.ssoIssuer == "" && !cfg.singleUser {
		return fmt.Errorf("a public tunnel with built-in OAuth is single-user: every token it issues authenticates as %q, so different people connecting would be indistinguishable and would share connections, credentials, and parked data.\n"+
			"  Serving only yourself: add --single-user to accept that posture.\n"+
			"  Serving several people: federate sign-in to an identity provider with --sso-issuer <url>,\n"+
			"  or validate an external authorization server's tokens with --issuer <url>", localSubject())
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func canonicalListenAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func validatePublicTunnelURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("tunnel returned an invalid public HTTPS origin")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("tunnel returned a public URL with an unexpected path")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// consoleAddr is the address the operator opens the console on.
func consoleAddr(cfg httpConfig) string {
	if a := effectiveAdminAddr(cfg); a != "" {
		return a
	}
	return cfg.addr
}

// servesPortal reports whether this configuration mounts the account portal. It
// tracks the condition in buildMuxes: the portal signs users in against the
// built-in authorization server, which runs only when issuance has not been
// handed to an external issuer or replaced by a static bearer.
func servesPortal(cfg httpConfig) bool { return cfg.issuer == "" && cfg.token == "" }

// buildMuxes constructs the agent-plane mux (everything cfg.addr — and any
// tunnel in front of it — serves: /mcp plus the OAuth discovery/authorization
// endpoints its auth mode needs) and the operator mux (/admin + /console).
// When effectiveAdminAddr puts the operator surface on its own listener, the
// two muxes are distinct and the agent plane cannot route to the operator
// surface at all; otherwise both share one mux. mode and bearer feed the
// connect banner.
func buildMuxes(srv *mcp.Server, cfg httpConfig, opAuth mcp.OperatorAuth) (mcpMux, adminMux *http.ServeMux, mode, bearer string, err error) {
	// The default audience over a tunnel is the public /mcp URL for every OAuth
	// mode, external issuer included. The advertised RFC 9728 resource and the
	// validated audience must be the same value: a client follows the metadata,
	// requests a token for that resource indicator (RFC 8707), and presents it
	// here — advertising one identifier while validating another guarantees a
	// 401 for every client that does discovery correctly.
	audience := cfg.audience
	if audience == "" {
		if cfg.tunnel != "" && cfg.token == "" {
			audience = strings.TrimSuffix(cfg.publicURL, "/") + "/mcp"
		} else {
			audience = "microagency"
		}
	}

	mcpMux = http.NewServeMux()
	var builtInAS *auth.AuthServer
	var connectionAuth mcp.Authenticator
	var connectionBase, connectionMetadata string
	switch {
	case cfg.issuer != "":
		// External OAuth resource server — issuance is hosted elsewhere.
		ks, err := auth.NewJWKSFromIssuer(context.Background(), cfg.issuer, nil)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("discover issuer %q: %w", cfg.issuer, err)
		}
		rs := &auth.ResourceServer{Issuer: cfg.issuer, Audience: audience, Keys: ks}
		if cfg.tunnel != "" {
			publicIssuer, err := validatePublicTunnelURL(cfg.publicURL)
			if err != nil {
				return nil, nil, "", "", err
			}
			// Advertise exactly what the resource server validates. The default
			// audience is this tunnel's /mcp URL; an explicit --audience changes
			// the advertised resource with it, like the non-tunnel branch below.
			resource := audience
			metadataURL := publicIssuer + "/.well-known/oauth-protected-resource/mcp"
			// An external issuer attests arbitrary subjects — a multi-principal surface.
			connectionAuth = mcp.OAuthAuthenticator(rs, cfg.requireScope, true)
			connectionBase, connectionMetadata = publicIssuer, metadataURL
			mcpMux.Handle("/mcp", srv.HTTPHandlerAuthMetadata(connectionAuth, metadataURL))
			mcpMux.Handle("/.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadata(resource, cfg.issuer))
		} else {
			connectionAuth = mcp.OAuthAuthenticator(rs, cfg.requireScope, true)
			connectionBase, connectionMetadata = "http://"+cfg.addr, "/.well-known/oauth-protected-resource"
			mcpMux.Handle("/mcp", srv.HTTPHandlerAuth(connectionAuth))
			mcpMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata(audience, cfg.issuer))
		}
		mode = "oauth-external"
	case cfg.token != "":
		// Explicit compatibility mode for clients that cannot complete OAuth.
		bearer = cfg.token
		mcpMux.Handle("/mcp", srv.HTTPHandler(bearer))
		mode = "bearer"
	case cfg.tunnel != "":
		publicIssuer, err := validatePublicTunnelURL(cfg.publicURL)
		if err != nil {
			return nil, nil, "", "", err
		}
		publicResource := publicIssuer + "/mcp"
		signer, err := auth.LoadOrCreateSigner(oauthKeyPathFor(cfg.authDir))
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("load OAuth key: %w", err)
		}
		revocations, err := auth.NewRevocationList(oauthRevocationsPathFor(cfg.authDir))
		if err != nil {
			return nil, nil, "", "", err
		}
		builtInAS = auth.NewAuthServer(signer, publicIssuer, audience, 2*time.Hour, revocations)
		builtInAS.Subject = localSubject()
		approvalBase := "http://" + effectiveAdminAddr(cfg)
		if err := builtInAS.ConfigurePublicFlow(publicResource, approvalBase); err != nil {
			return nil, nil, "", "", err
		}
		federated, err := configureBuiltInFederation(builtInAS, srv, cfg)
		if err != nil {
			return nil, nil, "", "", err
		}
		builtInAS.LoadClients(oauthClientsPathFor(cfg.authDir))
		builtInAS.Register(mcpMux)
		rs := &auth.ResourceServer{
			Issuer: publicIssuer, Audience: audience, Keys: signer.KeySet(),
			Revocations: revocations, RequireTokenID: true,
		}
		metadataURL := publicIssuer + "/.well-known/oauth-protected-resource/mcp"
		// Without federation the built-in AS mints tokens for the one local
		// operator subject; federated sign-in makes each provider account a
		// distinct principal.
		connectionAuth = mcp.OAuthAuthenticator(rs, "mcp", federated)
		connectionBase, connectionMetadata = publicIssuer, metadataURL
		mcpMux.Handle("/mcp", srv.HTTPHandlerAuthMetadata(connectionAuth, metadataURL))
		mcpMux.Handle("/.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadata(publicResource, publicIssuer))
		mode = "oauth-tunnel"
	default:
		// DEFAULT: the built-in single-user OAuth 2.1 server. microagency is its own
		// authorization server AND resource server, pointing at itself.
		signer, err := auth.LoadOrCreateSigner(oauthKeyPathFor(cfg.authDir))
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("load OAuth key: %w", err)
		}
		issuer := "http://" + cfg.addr
		revocations, err := auth.NewRevocationList(oauthRevocationsPathFor(cfg.authDir))
		if err != nil {
			return nil, nil, "", "", err
		}
		// 2h access tokens: long enough that a working session never re-auths
		// interactively (refresh is silent), short enough that a leaked bearer has a
		// bounded life. (Was 12h — a long-lived bearer with no revocation path.)
		// The AS and the resource server share ONE file-backed revocation list, so
		// POST /oauth/revoke takes effect on /mcp immediately and consumed refresh
		// tokens stay refused across restarts — same wiring as the tunnel mode.
		builtInAS = auth.NewAuthServer(signer, issuer, audience, 2*time.Hour, revocations)
		builtInAS.Subject = localSubject() // attribute runs to the real OS user, not a generic "operator"
		federated, err := configureBuiltInFederation(builtInAS, srv, cfg)
		if err != nil {
			return nil, nil, "", "", err
		}
		builtInAS.LoadClients(oauthClientsPathFor(cfg.authDir)) // remember DCR client_ids across restarts (no re-auth)
		builtInAS.Register(mcpMux)
		rs := &auth.ResourceServer{
			Issuer: issuer, Audience: audience, Keys: signer.KeySet(),
			Revocations: revocations, RequireTokenID: true,
		}
		// The built-in AS always grants "mcp", so requiring it costs nothing and
		// makes scope enforcement real instead of decorative. Single-principal
		// unless federated: with --sso-issuer each provider account is a
		// distinct principal.
		connectionAuth = mcp.OAuthAuthenticator(rs, "mcp", federated)
		connectionBase, connectionMetadata = issuer, "/.well-known/oauth-protected-resource"
		mcpMux.Handle("/mcp", srv.HTTPHandlerAuth(connectionAuth))
		mcpMux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadata(audience, issuer))
		mode = "oauth-local"
	}
	if connectionAuth != nil {
		// Copy the authenticator's declared capability onto the server: it selects
		// audit argument capture (structure + digest when multi-principal). Static
		// bearer and stdio never reach here and keep the single-principal default.
		srv.SetMultiPrincipalAuth(connectionAuth.MultiPrincipal())
		connections, err := srv.UserConnectionsHandler(connectionAuth, connectionBase, connectionMetadata)
		if err != nil {
			return nil, nil, "", "", err
		}
		mcpMux.Handle("/connections", connections)
		mcpMux.Handle("/connections/", connections)
		// The account portal is a browser client of the routes just mounted. It
		// signs in against the gateway's own authorization server, so it is served
		// only when this process runs one: with --issuer, issuance and its consent
		// screens belong to the operator's identity provider, and there is no
		// registration endpoint here for a browser to obtain a client from.
		if builtInAS != nil {
			mcpMux.Handle(portal.Path, portal.Handler(portal.Config{
				ResourceMetadata: connectionMetadata,
				Version:          version,
			}))
		}
	}

	// The operator surface binds a SEPARATE listener whenever effectiveAdminAddr
	// says so (explicit --admin-addr, or the loopback default under a tunnel), so
	// it stays unreachable from the public /mcp bind.
	adminMux = mcpMux
	if a := effectiveAdminAddr(cfg); a != "" && a != cfg.addr {
		adminMux = http.NewServeMux()
	}
	if builtInAS != nil && mode == "oauth-tunnel" {
		builtInAS.RegisterOperator(adminMux)
	}
	adminMux.Handle("/admin/", srv.AdminHandler(opAuth))
	// The console self-authenticates on loopback with the legacy operator token
	// (full admin — the console is a management UI).
	adminMux.Handle("/console", console.Handler(opAuth.LegacyToken))
	return mcpMux, adminMux, mode, bearer, nil
}

// serveHTTP runs the agent surface (/mcp) and operator surface (/admin +
// /console), then connects the user. /mcp is always authenticated (it proxies the
// credential pile). DEFAULT is the built-in single-user OAuth 2.1 server — paste
// the URL, approve once, no token handed over. --token forces a static bearer (for
// clients that can't do OAuth); --issuer uses an external authorization server.
// /admin + /console always sit behind a persistent operator token.
func buildServer(o upOptions, consoleAddr string, cred credentialIntent) *mcp.Server {
	srv, err := app.BuildServer(app.Config{
		StateDir:                  microagencyDir(),
		Version:                   version,
		ConsoleAddr:               consoleAddr,
		MaxInlineBytes:            o.maxInlineBytes,
		WasmMaxMemMB:              o.wasmMaxMemMB,
		PersistRefs:               o.persistRefs,
		ReduceEnginesOnly:         o.reduceEnginesOnly,
		HighAssuranceMultiUser:    o.highAssuranceMultiUser,
		EngineSpecs:               o.engineSpecs,
		BundledEngines:            bundledEngines(),
		BundledMinimizers:         bundledMinimizers(),
		AllowPlaintextCredentials: cred.allowPlaintext,
		PreferredStore:            cred.preferred,
		PreferredStoreUnavailable: cred.unavailable,
	})
	if err != nil {
		if errors.Is(err, secretstore.ErrPlaintextNotAllowed) {
			refusePlaintextCredentials(os.Stderr, cred)
		}
		fatal("build server", "err", err)
	}
	return srv
}

// credentialIntent is what `up` aimed at for credential custody before the
// server was built: the store it tried, why that store was unavailable, and
// whether the operator opted in to the unencrypted fallback.
type credentialIntent struct {
	preferred      string
	unavailable    string
	allowPlaintext bool
}

// envEnabled reads an opt-in environment variable. Anything but an explicit
// off-value enables, so a unit file that sets the variable at all is honored.
func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// reportOpenBaoUnavailable diagnoses why the managed store could not be used.
// A stale listener on the managed port is its own recoverable condition — some
// other process answers there, so microagency's own instance was never reached
// — and it gets a named diagnosis and remediation instead of a pid-file errno
// buried inside a generic unavailability warning.
func reportOpenBaoUnavailable(err error) {
	var stale *baomanager.StaleListenerError
	if errors.As(err, &stale) {
		slog.Warn("managed OpenBao is unavailable: its port is held by another process",
			"addr", stale.Addr, "detail", stale.Detail, "remediation", stale.Remediation())
		return
	}
	slog.Warn("OpenBao unavailable; evaluating the configured local credential-store fallback", "err", err)
}

// credentialStoreUnavailable is the short phrase recorded in the credential
// store posture and quoted in the fail-closed refusal.
func credentialStoreUnavailable(err error) string {
	var stale *baomanager.StaleListenerError
	if errors.As(err, &stale) {
		return fmt.Sprintf("another process holds %s, so microagency's own instance was never reached", stale.Addr)
	}
	return err.Error()
}

// refusePlaintextCredentials states the fail-closed refusal in the CLI's own
// vocabulary: what was unavailable, what the gateway will not do about it, and
// every way forward. Exits non-zero — this is an operational failure, not a
// usage error.
func refusePlaintextCredentials(w io.Writer, cred credentialIntent) {
	fmt.Fprintln(w, "microagency: refusing to start — upstream credentials would be stored UNENCRYPTED.")
	switch {
	case cred.preferred != "" && cred.unavailable != "":
		fmt.Fprintf(w, "  %s is unavailable: %s\n", cred.preferred, cred.unavailable)
	case cred.preferred != "":
		fmt.Fprintf(w, "  %s is unavailable.\n", cred.preferred)
	}
	fmt.Fprintf(w, "  The only store left is the mode-0600 file at %s,\n", filepath.Join(microagencyDir(), "upstream-tokens.json"))
	fmt.Fprintln(w, "  which is not encrypted at rest. Every upstream credential the gateway holds")
	fmt.Fprintln(w, "  would sit there in the clear.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Choose one:")
	fmt.Fprintln(w, "    - restore the store named above, then start again")
	fmt.Fprintf(w, "    - encrypt the fallback with a data-key protector: set %s to\n", secretstore.ProtectorEnv)
	fmt.Fprintln(w, "      keychain, secret-service, or command, then start again")
	fmt.Fprintf(w, "    - encrypt the fallback with your own key file: point %s at a\n", secretstore.FileKeyEnv)
	fmt.Fprintf(w, "      separately held 32-byte key outside %s, then start again\n", microagencyDir())
	fmt.Fprintln(w, "    - accept unencrypted credentials, knowing what that means:")
	fmt.Fprintf(w, "      `microagency up --allow-plaintext-credentials` (or %s=1)\n", secretstore.AllowPlaintextEnv)
	os.Exit(1)
}

func serveHTTP(srv *mcp.Server, cfg httpConfig) {
	operatorToken, opTokenFile := persistentToken()
	opAuth := mcp.OperatorAuth{LegacyToken: operatorToken, Tokens: optoken.NewStore(operatorTokensPath())}
	if err := validateRemoteAdminToken(cfg, opAuth); err != nil {
		fatal("refusing an unauthenticatable operator surface beyond loopback", "err", err)
	}
	mcpListener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		fatal("bind MCP listener", "addr", cfg.addr, "err", err)
	}
	var adminListener net.Listener
	adminAddr := effectiveAdminAddr(cfg)
	if adminAddr != "" && adminAddr != cfg.addr {
		adminListener, err = net.Listen("tcp", adminAddr)
		if err != nil {
			_ = mcpListener.Close()
			fatal("bind operator listener", "addr", adminAddr, "err", err)
		}
	}
	closeListeners := func() {
		_ = mcpListener.Close()
		if adminListener != nil {
			_ = adminListener.Close()
		}
	}

	// Establish the public origin before building OAuth metadata. A quick tunnel
	// reports its assigned origin on stdout; a named tunnel serves the origin the
	// operator declared with --tunnel-url. Either way that exact HTTPS origin,
	// not Host/Forwarded headers, becomes the issuer and default resource
	// identifier for the lifetime of this process.
	var tun *tunnel.Tunnel
	switch {
	case cfg.tunnel != "" && cfg.tunnelName != "":
		t, err := tunnel.StartNamed(context.Background(), cfg.tunnel, cfg.tunnelName, cfg.addr, 3*time.Second)
		if err != nil {
			closeListeners()
			fatal("start named tunnel", "err", err)
		}
		tun = t
		cfg.publicURL = cfg.tunnelURL // operator-declared; validated at parse time
	case cfg.tunnel != "":
		t, err := tunnel.Start(context.Background(), cfg.tunnel, cfg.addr, 45*time.Second)
		if err != nil {
			closeListeners()
			fatal("start tunnel", "err", err)
		}
		publicURL, err := validatePublicTunnelURL(t.PublicURL)
		if err != nil {
			_ = t.Close()
			closeListeners()
			fatal("validate tunnel URL", "err", err)
		}
		tun = t
		cfg.publicURL = publicURL
	}
	if tun != nil {
		defer func() { _ = tun.Close() }()
		if err := writeTunnelState(tunnelStatePath(), newTunnelState(cfg, tun.Pid())); err != nil {
			slog.Warn("tunnel state not recorded; doctor cannot see tunnel liveness", "err", err)
		}
		go watchTunnel(tun, tunnelStatePath())
	} else {
		// No tunnel this run: drop any record from a previous one so doctor
		// reports the deployment that exists, not the one that used to.
		_ = os.Remove(tunnelStatePath())
	}

	mcpMux, adminMux, mode, bearer, err := buildMuxes(srv, cfg, opAuth)
	if err != nil {
		if tun != nil {
			_ = tun.Close()
		}
		closeListeners()
		fatal("configure HTTP authentication", "err", err)
	}
	changedOrigin, err := recordAuthPosture(cfg, mode)
	if err != nil {
		if tun != nil {
			_ = tun.Close()
		}
		closeListeners()
		fatal("record authentication posture", "err", err)
	}

	mcpSrv := newHTTPServer(cfg.addr, mcpMux)
	var adminSrv *http.Server
	if adminMux != mcpMux {
		adminSrv = newHTTPServer(adminAddr, adminMux)
		go func() {
			if err := adminSrv.Serve(adminListener); err != nil && err != http.ErrServerClosed {
				slog.Error("admin listener failed", "addr", adminSrv.Addr, "err", err)
			}
		}()
	}

	if cfg.publicURL != "" {
		endpoint := strings.TrimSuffix(cfg.publicURL, "/") + "/mcp"
		audience := firstNonEmpty(cfg.audience, endpoint)
		resource := endpoint
		if mode == "oauth-external" {
			resource = audience // the metadata advertises exactly what is validated
		}
		slog.Info("public MCP endpoint ready", "url", endpoint, "auth", mode, "resource", resource, "audience", audience, "operator_addr", consoleAddr(cfg), "issuer_changed", changedOrigin)
	}
	announce(srv, cfg, mode, bearer, opTokenFile, changedOrigin)

	// Graceful shutdown: on SIGINT/SIGTERM (what `microagency down` sends) stop
	// accepting, drain in-flight calls and their audit appends within a bounded
	// window, and close the tunnel — instead of the old os.Exit(0) that dropped
	// requests and half-written audit lines mid-flight.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		if tun != nil {
			_ = tun.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if adminSrv != nil {
			_ = adminSrv.Shutdown(ctx)
		}
		_ = mcpSrv.Shutdown(ctx) // unblocks ListenAndServe below → clean return
	}()

	if err := mcpSrv.Serve(mcpListener); err != nil && err != http.ErrServerClosed {
		if tun != nil {
			_ = tun.Close()
		}
		if adminListener != nil {
			_ = adminListener.Close()
		}
		fmt.Fprintf(os.Stderr, "microagency: %v\n", err)
		os.Exit(1)
	}
}

// shutdownGrace bounds how long a SIGTERM drain waits for in-flight requests
// before the process exits. `microagency down` doesn't block on it, so it can be
// generous enough to let a normal call finish without stalling shutdown for a
// long-running reduce.
const shutdownGrace = 10 * time.Second

// newHTTPServer builds a listener with timeouts instead of the bare
// http.ListenAndServe. ReadHeaderTimeout is the slowloris defense on the public
// tunneled bind; IdleTimeout reaps idle keep-alives. Read/WriteTimeout are
// deliberately unset — a reduce or a slow upstream tool can legitimately stream
// for minutes (the upstream client caps at 5m), and a write deadline would sever
// those mid-response.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// announce connects the user to the running server. For OAuth the client runs the
// login flow, so we hand over no token — we auto-register just the URL with Claude
// Code (no token in argv either) and the client opens the one-click approve page.
// For bearer the token reaches Claude Code via the subprocess, never the shell.
func announce(srv *mcp.Server, cfg httpConfig, mode, bearer, opTokenFile string, changedOrigin bool) {
	endpoint := "http://" + cfg.addr + "/mcp"
	if cfg.publicURL != "" {
		endpoint = strings.TrimSuffix(cfg.publicURL, "/") + "/mcp"
	}

	// Auto-register with Claude Code — a side effect that runs regardless of whether
	// we print the banner (OAuth registers the URL only; bearer includes the token).
	regToken := ""
	if mode == "bearer" {
		regToken = bearer
	}
	registered := !cfg.noRegister && claudeAvailable() && registerClaude(endpoint, regToken)

	// The detached daemon child writes only structured, timestamped log lines — the
	// parent already printed the connect banner to the terminal. Don't dump the
	// human banner into the log.
	if os.Getenv("MICROAGENCY_DAEMON") == "1" {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  microagency is up — %s\n\n", endpoint)
	switch mode {
	case "oauth-local", "oauth-external", "oauth-tunnel":
		if registered {
			fmt.Fprintf(os.Stderr, "  Connect        Added to Claude Code (this project). In Claude Code, run /mcp → Authenticate.\n")
			fmt.Fprintf(os.Stderr, "                 Any other client: paste %s and approve once.\n", endpoint)
		} else {
			fmt.Fprintf(os.Stderr, "  Connect        Paste %s into any MCP client; it will prompt you to approve once.\n", endpoint)
		}
		switch mode {
		case "oauth-external":
			fmt.Fprintf(os.Stderr, "  Auth           OAuth (issuer %s)\n", cfg.issuer)
			if cfg.publicURL != "" {
				fmt.Fprintf(os.Stderr, "  Audience       %s (advertised as the protected-resource identifier)\n", firstNonEmpty(cfg.audience, endpoint))
			}
		case "oauth-local":
			if cfg.ssoIssuer != "" {
				printSSOPosture(cfg)
			}
		case "oauth-tunnel":
			if cfg.ssoIssuer != "" {
				printSSOPosture(cfg)
			} else {
				fmt.Fprintf(os.Stderr, "  Auth           Built-in OAuth over %s; consent is approved only on %s\n", cfg.tunnel, consoleAddr(cfg))
				fmt.Fprintf(os.Stderr, "  Posture        single-user — every remote client authenticates as %q (several people need --sso-issuer or --issuer)\n", localSubject())
			}
			fmt.Fprintf(os.Stderr, "  Audience       %s\n", firstNonEmpty(cfg.audience, endpoint))
			switch {
			case changedOrigin:
				fmt.Fprintln(os.Stderr, "  URL changed    prior tunnel tokens are invalid; reconnect clients at this URL")
			case cfg.tunnelName != "":
				fmt.Fprintf(os.Stderr, "  URL            stable — named tunnel %q keeps this URL across restarts (tokens survive)\n", cfg.tunnelName)
			default:
				fmt.Fprintln(os.Stderr, "  URL            quick tunnel — the URL changes on restart, invalidating issued tokens")
			}
		}
	case "bearer":
		if registered {
			fmt.Fprintf(os.Stderr, "  Connected      Claude Code (project scope). Remove with: claude mcp remove microagency\n")
		} else {
			printManualConnect(endpoint)
		}
	}
	if servesPortal(cfg) {
		fmt.Fprintf(os.Stderr, "  Account portal %s   (each signed-in user connects their own providers here)\n",
			strings.TrimSuffix(endpoint, "/mcp")+portal.Path)
	}
	fmt.Fprintf(os.Stderr, "  Console        http://%s/console   (operator token: cat %s)\n", consoleAddr(cfg), opTokenFile)
	if cfg.tunnel != "" && consoleAddr(cfg) != cfg.addr {
		fmt.Fprintf(os.Stderr, "                 loopback-only — the tunnel exposes /mcp, never the operator surface\n")
	}
	if ra := remoteAdminAddr(cfg); ra != "" {
		fmt.Fprintf(os.Stderr, "  WARNING        /admin + /console are reachable beyond loopback on %s (--allow-remote-admin)\n", ra)
		fmt.Fprintln(os.Stderr, "                 cleartext HTTP, operator token only — front it with TLS, or bind loopback and use SSH forwarding")
	}
	if engines := srv.EngineNames(); len(engines) > 0 {
		fmt.Fprintf(os.Stderr, "  Query engines  %s\n", strings.Join(engines, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "  Query engines  none — run `make engines` to enable\n")
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// printManualConnect gives clients without auto-registration the endpoint shape
// without printing the bearer value.
func printManualConnect(url string) {
	fmt.Fprintf(os.Stderr, "  Connect        point your client at %s with header Authorization: Bearer <token>\n", url)
}

// printSSOPosture describes federated built-in OAuth: where people sign in,
// and that each provider account is its own principal.
func printSSOPosture(cfg httpConfig) {
	fmt.Fprintf(os.Stderr, "  Auth           Built-in OAuth; sign-in federated to %s\n", cfg.ssoIssuer)
	if cfg.ssoHD != "" {
		fmt.Fprintf(os.Stderr, "  Posture        multi-user — each provider account is a distinct principal (hd=%s required)\n", cfg.ssoHD)
	} else {
		fmt.Fprintln(os.Stderr, "  Posture        multi-user — each provider account is a distinct principal")
	}
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

func oauthKeyPathFor(dir string) string {
	if dir != "" {
		return filepath.Join(dir, "oauth-key")
	}
	return oauthKeyPath()
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

func oauthClientsPathFor(dir string) string {
	if dir != "" {
		return filepath.Join(dir, "oauth-clients.json")
	}
	return oauthClientsPath()
}

// oauthRevocationsPath persists revoked self-issued access token IDs and
// consumed rotating refresh token IDs until their natural expiry.
func oauthRevocationsPath() string {
	return filepath.Join(microagencyDir(), "oauth-revocations.json")
}

func oauthRevocationsPathFor(dir string) string {
	if dir != "" {
		return filepath.Join(dir, "oauth-revocations.json")
	}
	return oauthRevocationsPath()
}

type authPosture struct {
	Mode     string `json:"mode"`
	Issuer   string `json:"issuer,omitempty"`
	Resource string `json:"resource,omitempty"`
	Audience string `json:"audience,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
	// TunnelMode records URL stability: "named" tunnels keep their issuer
	// across restarts (tokens survive); "quick" tunnels get a fresh one.
	TunnelMode string `json:"tunnel_mode,omitempty"`
	TunnelName string `json:"tunnel_name,omitempty"`
	// RemoteAdmin records the non-loopback address serving /admin + /console
	// when the operator lifted the loopback floor with --allow-remote-admin,
	// so doctor can keep the exposure visible. Empty while the surface is local.
	RemoteAdmin string `json:"remote_admin_addr,omitempty"`
	// SSOIssuer records federated sign-in: the built-in server still mints the
	// tokens (Issuer above), but people authenticate at this OIDC provider and
	// each provider account is a distinct principal.
	SSOIssuer       string `json:"sso_issuer,omitempty"`
	SSOHostedDomain string `json:"sso_hosted_domain,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}

func authPosturePath() string { return filepath.Join(microagencyDir(), "auth-posture.json") }

func readAuthPosture(path string) (authPosture, error) {
	var posture authPosture
	b, err := os.ReadFile(path)
	if err != nil {
		return posture, err
	}
	if err := json.Unmarshal(b, &posture); err != nil {
		return posture, err
	}
	return posture, nil
}

// recordAuthPosture stores only public identifiers. It reports whether a
// built-in tunnel issuer changed since the prior run so startup can make the
// resulting client reauthorization explicit.
func recordAuthPosture(cfg httpConfig, mode string) (bool, error) {
	return recordAuthPostureAt(cfg, mode, authPosturePath())
}

func recordAuthPostureAt(cfg httpConfig, mode, path string) (bool, error) {
	issuer := cfg.issuer
	resource, audience := "", cfg.audience
	if mode == "oauth-tunnel" {
		issuer = cfg.publicURL
		resource = strings.TrimSuffix(cfg.publicURL, "/") + "/mcp"
		if audience == "" {
			audience = resource
		}
	} else if mode == "oauth-local" {
		issuer = "http://" + cfg.addr
		resource = "http://" + cfg.addr + "/mcp"
		if audience == "" {
			audience = "microagency"
		}
	} else if mode == "oauth-external" && cfg.publicURL != "" {
		// The advertised resource is the validated audience (default: the public
		// /mcp URL), so doctor shows the identifier clients actually request.
		if audience == "" {
			audience = strings.TrimSuffix(cfg.publicURL, "/") + "/mcp"
		}
		resource = audience
	}
	var previous authPosture
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &previous)
	}
	posture := authPosture{
		Mode: mode, Issuer: issuer, Resource: resource, Audience: audience, Tunnel: cfg.tunnel,
		SSOIssuer: cfg.ssoIssuer, SSOHostedDomain: cfg.ssoHD,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if cfg.tunnel != "" {
		posture.TunnelMode = tunnelMode(cfg)
		posture.TunnelName = cfg.tunnelName
	}
	posture.RemoteAdmin = remoteAdminAddr(cfg)
	b, err := json.Marshal(posture)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return false, err
	}
	changed := mode == "oauth-tunnel" && previous.Mode == "oauth-tunnel" && previous.Issuer != "" && previous.Issuer != issuer
	return changed, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// persistentToken reads-or-mints a stable bearer token at ~/.microagency/token
// (0600), so the client config and any auto-registration survive restarts. file is
// "" only when there is no home directory.
// persistentToken is the LEGACY operator token: a full-admin break-glass
// credential gating /admin + /console, and the value the loopback console
// self-authenticates with. Named tokens (`microagency token`) are the managed
// alternative with roles and expiry; admin actions with this one audit under
// the fixed name optoken.LegacyName. It never authenticates the agent-facing
// /mcp surface.
func persistentToken() (token, file string) { return persistentTokenAt("token") }

// persistentTokenAt reads (or mints and 0600-persists) a random token in
// ~/.microagency/<name>, so it survives restarts. A missing home dir falls back
// to an ephemeral token (no file).
func persistentTokenAt(name string) (token, file string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return randomToken(), ""
	}
	file = filepath.Join(home, ".microagency", name)
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
		fatal("generate token", "err", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
