// Package tunnel orchestrates a user-installed tunnel CLI (cloudflared, ngrok, …)
// to expose a loopback-bound microagency publicly, so the remote-MCP-in-Claude
// case is one command. microagency does NOT bundle or operate a tunnel — it runs
// the provider the user already has and scrapes the public URL from its output.
// This keeps reachability provider-agnostic (any tunnel works against the
// loopback port) and out of our operational surface.
package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"time"
)

// provider describes how to launch a tunnel CLI for a local address and how to
// recognize the public URL it prints.
type provider struct {
	command func(localAddr string) (name string, args []string)
	urlRE   *regexp.Regexp
}

var providers = map[string]provider{
	// Cloudflare quick tunnel: ephemeral *.trycloudflare.com URL, no account.
	"cloudflare": {
		command: func(addr string) (string, []string) {
			return "cloudflared", []string{"tunnel", "--url", "http://" + addr}
		},
		urlRE: regexp.MustCompile(`https://[a-zA-Z0-9][a-zA-Z0-9-]*\.trycloudflare\.com`),
	},
	"ngrok": {
		command: func(addr string) (string, []string) {
			_, port, _ := net.SplitHostPort(addr)
			return "ngrok", []string{"http", port, "--log", "stdout"}
		},
		urlRE: regexp.MustCompile(`https://[a-zA-Z0-9][a-zA-Z0-9-]*\.ngrok[a-z0-9.-]*`),
	},
}

// Providers lists the supported provider names.
func Providers() []string { return []string{"cloudflare", "ngrok"} }

// Tunnel is a running tunnel subprocess exposing a local address publicly.
type Tunnel struct {
	cmd       *exec.Cmd
	PublicURL string
}

// Start launches the named provider to expose localAddr and returns once the
// public URL is parsed (or it times out / the CLI is missing).
func Start(ctx context.Context, name, localAddr string, timeout time.Duration) (*Tunnel, error) {
	p, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("tunnel: unknown provider %q (have %v)", name, Providers())
	}
	cmdName, args := p.command(localAddr)
	return start(ctx, cmdName, args, p.urlRE, timeout)
}

func start(ctx context.Context, name string, args []string, re *regexp.Regexp, timeout time.Duration) (*Tunnel, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cmd := exec.CommandContext(ctx, name, args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, fmt.Errorf("tunnel: cannot start %q — is it installed and on PATH? (%w)", name, err)
	}
	_ = pw.Close() // the child holds its own write end; closing ours lets us see EOF

	urlCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if m := re.FindString(sc.Text()); m != "" {
				select {
				case urlCh <- m:
				default:
				}
			}
		}
		_ = pr.Close()
	}()

	select {
	case url := <-urlCh:
		return &Tunnel{cmd: cmd, PublicURL: url}, nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("tunnel: %q did not report a public URL within %s", name, timeout)
	}
}

// Close terminates the tunnel subprocess.
func (t *Tunnel) Close() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	_ = t.cmd.Process.Kill()
	_, _ = t.cmd.Process.Wait()
	return nil
}
