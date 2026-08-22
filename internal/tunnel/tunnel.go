// Package tunnel orchestrates a user-installed tunnel CLI (cloudflared, ngrok, …)
// to expose a loopback-bound microagency publicly, so the remote-MCP-in-Claude
// case is one command. microagency does NOT bundle or operate a tunnel — it runs
// the provider the user already has. Quick tunnels scrape the assigned URL from
// the provider's output; named tunnels print no URL, so the operator supplies
// the stable public origin and Start's job is just to run and watch the child.
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
	"strings"
	"sync"
	"sync/atomic"
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
	// --no-autoupdate keeps the child we monitor from replacing itself
	// mid-flight: an autoupdate restart would read as a tunnel death.
	"cloudflare": {
		command: func(addr string) (string, []string) {
			return "cloudflared", []string{"tunnel", "--no-autoupdate", "--url", "http://" + addr}
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

// tailLines bounds how much recent child output a Tunnel retains for
// diagnostics. Enough to carry a provider's error context, small enough to
// never be a payload.
const tailLines = 20

// Tunnel is a running tunnel subprocess exposing a local address publicly.
type Tunnel struct {
	cmd *exec.Cmd
	// PublicURL is the origin scraped from a quick tunnel's output. Named
	// tunnels leave it empty — the operator declares the stable origin.
	PublicURL string

	done    chan struct{} // closed once the child has exited and been reaped
	stopped atomic.Bool   // set by Close: the exit was requested, not a death

	mu      sync.Mutex
	exitErr error
	tail    []string
}

// Start launches the named provider as a quick tunnel exposing localAddr and
// returns once the public URL is parsed (or the child dies, the wait times
// out, or the CLI is missing).
func Start(ctx context.Context, name, localAddr string, timeout time.Duration) (*Tunnel, error) {
	p, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("tunnel: unknown provider %q (have %v)", name, Providers())
	}
	cmdName, args := p.command(localAddr)
	return startQuick(ctx, cmdName, args, p.urlRE, timeout)
}

// StartNamed runs an operator-created named Cloudflare tunnel. There is no URL
// to scrape — `cloudflared tunnel run` prints none — so the caller supplies the
// stable public origin out of band and this only launches and watches the
// child. --url points the tunnel at localAddr, overriding any ingress rules in
// the operator's cloudflared config, so the declared origin always fronts this
// server. grace is how long a clean start must survive: config errors (unknown
// tunnel name, missing credentials) exit within it and fail startup instead of
// surfacing as a dead public URL later.
func StartNamed(ctx context.Context, providerName, tunnelName, localAddr string, grace time.Duration) (*Tunnel, error) {
	if providerName != "cloudflare" {
		return nil, fmt.Errorf("tunnel: named tunnels are supported with provider \"cloudflare\" only (got %q)", providerName)
	}
	if tunnelName == "" {
		return nil, fmt.Errorf("tunnel: a named tunnel needs a name")
	}
	if grace <= 0 {
		grace = 3 * time.Second
	}
	args := []string{"tunnel", "--no-autoupdate", "run", "--url", "http://" + localAddr, tunnelName}
	t, _, err := launch(ctx, "cloudflared", args, nil)
	if err != nil {
		return nil, err
	}
	select {
	case <-t.done:
		return nil, fmt.Errorf("tunnel: cloudflared exited while starting named tunnel %q: %v%s", tunnelName, t.ExitError(), t.tailSuffix())
	case <-time.After(grace):
		return t, nil
	}
}

func startQuick(ctx context.Context, name string, args []string, re *regexp.Regexp, timeout time.Duration) (*Tunnel, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	t, urlCh, err := launch(ctx, name, args, re)
	if err != nil {
		return nil, err
	}
	select {
	case url := <-urlCh:
		t.PublicURL = url
		return t, nil
	case <-t.done:
		return nil, fmt.Errorf("tunnel: %q exited before reporting a public URL: %v%s", name, t.ExitError(), t.tailSuffix())
	case <-time.After(timeout):
		_ = t.Close()
		return nil, fmt.Errorf("tunnel: %q did not report a public URL within %s", name, timeout)
	}
}

// launch starts the child, drains its combined output (keeping a bounded tail,
// and matching re into the returned channel when non-nil), and reaps it in the
// background so an exit is observable via Done — never a zombie.
func launch(ctx context.Context, name string, args []string, re *regexp.Regexp) (*Tunnel, <-chan string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, nil, fmt.Errorf("tunnel: cannot start %q — is it installed and on PATH? (%w)", name, err)
	}
	_ = pw.Close() // the child holds its own write end; closing ours lets us see EOF

	t := &Tunnel{cmd: cmd, done: make(chan struct{})}
	urlCh := make(chan string, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			t.mu.Lock()
			t.tail = append(t.tail, line)
			if len(t.tail) > tailLines {
				t.tail = t.tail[1:]
			}
			t.mu.Unlock()
			if re != nil {
				if m := re.FindString(line); m != "" {
					select {
					case urlCh <- m:
					default:
					}
				}
			}
		}
		_ = pr.Close()
	}()
	go func() {
		err := cmd.Wait()
		// Let the scanner catch the child's last words before Done fires, but
		// bounded: an orphaned grandchild could hold the pipe open forever.
		select {
		case <-scanDone:
		case <-time.After(500 * time.Millisecond):
		}
		t.mu.Lock()
		t.exitErr = err
		t.mu.Unlock()
		close(t.done)
	}()
	return t, urlCh, nil
}

// Done is closed once the tunnel subprocess has exited (for any reason,
// including Close).
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Stopped reports whether Close asked the child to exit — distinguishing a
// requested shutdown from a death nobody wanted.
func (t *Tunnel) Stopped() bool { return t.stopped.Load() }

// ExitError returns the child's exit error (nil for a clean exit). Meaningful
// only after Done is closed.
func (t *Tunnel) ExitError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.exitErr
}

// Tail returns the most recent lines of the child's output, for diagnostics.
func (t *Tunnel) Tail() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.tail...)
}

// Pid returns the tunnel subprocess pid, or 0 if it never started.
func (t *Tunnel) Pid() int {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return 0
	}
	return t.cmd.Process.Pid
}

// tailSuffix renders the last few output lines for an error message — enough
// to say why the provider quit without dumping a log.
func (t *Tunnel) tailSuffix() string {
	lines := t.Tail()
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	if len(lines) == 0 {
		return ""
	}
	return " — last output: " + strings.Join(lines, " | ")
}

// Close terminates the tunnel subprocess and waits for it to be reaped.
func (t *Tunnel) Close() error {
	if t == nil || t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	t.stopped.Store(true)
	_ = t.cmd.Process.Kill()
	<-t.done
	return nil
}
