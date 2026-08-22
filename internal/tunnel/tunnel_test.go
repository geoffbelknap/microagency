package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStartScrapesURL(t *testing.T) {
	re := regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	// A stand-in tunnel: print a URL to stderr (like cloudflared) then stay alive.
	tun, err := startQuick(context.Background(), "sh",
		[]string{"-c", "echo 'INF |  https://happy-tree-1234.trycloudflare.com  |' >&2; sleep 5"},
		re, 5*time.Second)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = tun.Close() }()
	if tun.PublicURL != "https://happy-tree-1234.trycloudflare.com" {
		t.Fatalf("public URL = %q", tun.PublicURL)
	}
}

func TestStartTimeout(t *testing.T) {
	if _, err := startQuick(context.Background(), "sh", []string{"-c", "echo nope; sleep 5"},
		regexp.MustCompile(`never-matches`), 300*time.Millisecond); err == nil {
		t.Fatal("expected a timeout error when no URL appears")
	}
}

// A child that dies before printing a URL fails immediately with its last
// words, instead of burning the whole timeout on a corpse.
func TestStartFailsFastWhenChildDies(t *testing.T) {
	start := time.Now()
	_, err := startQuick(context.Background(), "sh",
		[]string{"-c", "echo 'no cert found'; exit 1"},
		regexp.MustCompile(`never-matches`), 30*time.Second)
	if err == nil {
		t.Fatal("expected an error when the child exits before a URL")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("early exit took the full timeout path: %v", time.Since(start))
	}
	if !strings.Contains(err.Error(), "no cert found") {
		t.Fatalf("error does not carry the child's output: %v", err)
	}
}

func TestStartMissingBinary(t *testing.T) {
	if _, err := startQuick(context.Background(), "definitely-not-a-real-binary-xyz", nil,
		regexp.MustCompile("x"), time.Second); err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

func TestUnknownProvider(t *testing.T) {
	if _, err := Start(context.Background(), "nope", "127.0.0.1:1", time.Second); err == nil {
		t.Fatal("expected an unknown-provider error")
	}
}

func TestProviderRegexes(t *testing.T) {
	if providers["cloudflare"].urlRE.FindString("INF |  https://abc-def-12.trycloudflare.com  |") == "" {
		t.Fatal("cloudflare regex did not match sample output")
	}
	if providers["ngrok"].urlRE.FindString(`msg="started tunnel" url=https://1234.ngrok-free.app`) == "" {
		t.Fatal("ngrok regex did not match sample output")
	}
}

// stubCloudflared installs a fake cloudflared on PATH whose behavior is the
// given shell script body, and returns the file its argv is recorded to.
func stubCloudflared(t *testing.T, body string) (argvFile string) {
	t.Helper()
	dir := t.TempDir()
	argvFile = filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s ' \"$@\" > " + argvFile + "\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cloudflared"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvFile
}

func TestStartNamedRunsTheOperatorsTunnel(t *testing.T) {
	argvFile := stubCloudflared(t, "echo 'INF Registered tunnel connection'; sleep 5")
	tun, err := StartNamed(context.Background(), "cloudflare", "my-gateway", "127.0.0.1:8765", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	defer func() { _ = tun.Close() }()
	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	// The tunnel must be pointed at OUR listener (--url overrides ingress
	// config), and run the operator's named tunnel.
	for _, want := range []string{"tunnel", "run", "--url http://127.0.0.1:8765", "my-gateway"} {
		if !strings.Contains(string(argv), want) {
			t.Fatalf("cloudflared argv %q is missing %q", argv, want)
		}
	}
	if tun.PublicURL != "" {
		t.Fatalf("named tunnel invented a public URL: %q", tun.PublicURL)
	}
	select {
	case <-tun.Done():
		t.Fatal("named tunnel reported exit while the child is alive")
	default:
	}
}

// A named tunnel that dies inside the startup grace window (unknown tunnel,
// missing credentials) fails start with the provider's own words.
func TestStartNamedSurfacesEarlyExit(t *testing.T) {
	stubCloudflared(t, "echo \"tunnel credentials file not found\" >&2; exit 1")
	_, err := StartNamed(context.Background(), "cloudflare", "my-gateway", "127.0.0.1:8765", 2*time.Second)
	if err == nil {
		t.Fatal("expected an error when cloudflared exits during startup")
	}
	if !strings.Contains(err.Error(), "credentials file not found") {
		t.Fatalf("error does not carry cloudflared's output: %v", err)
	}
}

func TestStartNamedRejectsOtherProviders(t *testing.T) {
	if _, err := StartNamed(context.Background(), "ngrok", "my-gateway", "127.0.0.1:8765", time.Second); err == nil {
		t.Fatal("expected an error for a non-cloudflare named tunnel")
	}
}

// The child is monitored, not fire-and-forgotten: an exit after startup is
// observable through Done, carries the exit state, and is distinguishable
// from a requested Close.
func TestDoneReportsChildDeath(t *testing.T) {
	stubCloudflared(t, "sleep 0.2; echo 'connection lost' >&2; exit 3")
	tun, err := StartNamed(context.Background(), "cloudflare", "my-gateway", "127.0.0.1:8765", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("child exit was never observed")
	}
	if tun.Stopped() {
		t.Fatal("an uncommanded death reads as a requested stop")
	}
	if tun.ExitError() == nil {
		t.Fatal("a non-zero exit lost its exit error")
	}
	// The scanner drains the pipe independently of the reaper; give the last
	// line a moment to land in the tail.
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(strings.Join(tun.Tail(), "\n"), "connection lost") {
		if time.Now().After(deadline) {
			t.Fatalf("tail lost the child's last words: %q", tun.Tail())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCloseIsARequestedStop(t *testing.T) {
	tun, err := startQuick(context.Background(), "sh",
		[]string{"-c", "echo https://x.trycloudflare.com; sleep 30"},
		regexp.MustCompile(`https://[a-z0-9.-]+`), 5*time.Second)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-tun.Done():
	default:
		t.Fatal("Close returned before the child was reaped")
	}
	if !tun.Stopped() {
		t.Fatal("Close did not mark the stop as requested")
	}
}
