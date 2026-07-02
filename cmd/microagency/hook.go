package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// runHook dispatches microagency's Claude Code hook integrations.
//
//	microagency hook egress-guard   a PreToolUse hook (reads the tool call on stdin)
//	microagency hook install        print the settings.json snippet to enable it
func runHook(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: microagency hook <egress-guard|install>")
		os.Exit(2)
	}
	switch args[0] {
	case "egress-guard":
		egressGuard(os.Stdin, os.Stdout, os.Stderr)
	case "install":
		printHookInstall(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown hook %q (want egress-guard|install)\n", args[0])
		os.Exit(2)
	}
}

// egressGuard is a Claude Code PreToolUse hook. It reads the tool-call JSON on
// stdin, and if the call would reach a microagency-GOVERNED host DIRECTLY (a Bash
// command or WebFetch whose URL targets a host in GET /admin/egress-policy), it
// WARNS — steering the agent back through the gateway (call_tool), the governed
// well. This is enforcement hygiene from OUTSIDE the agent (ASK tenet 1), a first
// layer under the network-level containment epic.
//
// Warn-first and FAIL-OPEN by design: it never blocks the call, and every failure
// path (microagency down, no operator token, unparseable input) exits silently — the
// hook can never break the agent's workflow. It is a nudge, NOT complete mediation: a
// determined agent can evade command-string inspection; only network-level egress
// mediation is complete.
func egressGuard(in io.Reader, out, errw io.Writer) {
	data, err := io.ReadAll(io.LimitReader(in, 1<<20))
	if err != nil {
		return
	}
	var ev struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return
	}
	hosts := hostsFromToolInput(ev.ToolName, ev.ToolInput)
	if len(hosts) == 0 {
		return
	}
	governed := fetchGovernedHosts()
	if len(governed) == 0 {
		return
	}
	hit := governedMatches(hosts, governed)
	if len(hit) == 0 {
		return
	}
	msg := fmt.Sprintf("microagency: this %s reaches %s directly, but microagency already connects there. Use call_tool instead so the call is audited and the credentials never leave the gateway.",
		strings.ToLower(ev.ToolName), strings.Join(hit, ", "))
	// Human-visible warning + a non-blocking steer injected for the agent. Exit 0:
	// the call still proceeds (warn-first).
	fmt.Fprintf(errw, "⚠ %s\n", msg)
	_ = json.NewEncoder(out).Encode(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PreToolUse",
			"additionalContext": "⚠ " + msg,
		},
	})
}

// urlHostRe captures the host[:port] of an http(s) URL anywhere in a string
// (case-insensitive scheme — a command may write HTTPS://).
var urlHostRe = regexp.MustCompile(`(?i)https?://([^/\s"'` + "`" + `)>\],]+)`)

// hostsFromToolInput extracts the hostnames a tool call would reach: every http(s)
// URL host in a Bash command, or the WebFetch url. Other tools contribute none.
// Detection is URL-based (deliberately conservative — a false negative is a missed
// nudge, not a broken command).
func hostsFromToolInput(toolName string, input json.RawMessage) []string {
	var m map[string]any
	if json.Unmarshal(input, &m) != nil {
		return nil
	}
	var text string
	switch toolName {
	case "Bash":
		text, _ = m["command"].(string)
	case "WebFetch":
		text, _ = m["url"].(string)
	default:
		return nil
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, mt := range urlHostRe.FindAllStringSubmatch(text, -1) {
		if h := normalizeHost(mt[1]); h != "" && !seen[h] {
			out = append(out, h)
			seen[h] = true
		}
	}
	return out
}

// normalizeHost reduces a host[:port] (optionally with userinfo@) to a bare
// lower-cased hostname — matching how the egress policy stores hosts (url.Hostname()).
func normalizeHost(hostport string) string {
	hp := strings.TrimSpace(hostport)
	if i := strings.LastIndex(hp, "@"); i >= 0 {
		hp = hp[i+1:]
	}
	if h, _, err := net.SplitHostPort(hp); err == nil {
		hp = h
	}
	return strings.ToLower(hp)
}

// governedMatches returns the deduped subset of hosts that are in the governed set.
func governedMatches(hosts []string, governed map[string]bool) []string {
	var hit []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if governed[h] && !seen[h] {
			hit = append(hit, h)
			seen[h] = true
		}
	}
	return hit
}

// fetchGovernedHosts reads microagency's egress policy (the source-of-truth set of
// governed data hosts). Best-effort: returns nil on any error so the guard fails open.
func fetchGovernedHosts() map[string]bool {
	addr := os.Getenv("MICROAGENCY_ADMIN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8765"
	}
	token := readOperatorToken()
	if token == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/admin/egress-policy", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var pol struct {
		Hosts []string `json:"hosts"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pol) != nil {
		return nil
	}
	set := make(map[string]bool, len(pol.Hosts))
	for _, h := range pol.Hosts {
		set[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return set
}

func readOperatorToken() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".microagency", "token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// printHookInstall shows the Claude Code settings.json snippet that wires the guard
// as a PreToolUse hook on Bash and WebFetch.
func printHookInstall(w io.Writer) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "microagency"
	}
	fmt.Fprintf(w, `Add this to your Claude Code settings.json (~/.claude/settings.json) to enable
the warn-first egress guard on Bash and WebFetch:

{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|WebFetch",
        "hooks": [
          { "type": "command", "command": %q }
        ]
      }
    ]
  }
}

It warns (never blocks) when a command would directly reach a host that's
connected through microagency, steering the agent to call_tool instead. Fails open: if microagency
isn't running or has no token, the guard stays silent. Set MICROAGENCY_ADMIN_ADDR
if your /admin listener isn't on 127.0.0.1:8765.
`, exe+" hook egress-guard")
}
