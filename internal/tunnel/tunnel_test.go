package tunnel

import (
	"context"
	"regexp"
	"testing"
	"time"
)

func TestStartScrapesURL(t *testing.T) {
	re := regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	// A stand-in tunnel: print a URL to stderr (like cloudflared) then stay alive.
	tun, err := start(context.Background(), "sh",
		[]string{"-c", "echo 'INF |  https://happy-tree-1234.trycloudflare.com  |' >&2; sleep 5"},
		re, 5*time.Second)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tun.Close()
	if tun.PublicURL != "https://happy-tree-1234.trycloudflare.com" {
		t.Fatalf("public URL = %q", tun.PublicURL)
	}
}

func TestStartTimeout(t *testing.T) {
	if _, err := start(context.Background(), "sh", []string{"-c", "echo nope; sleep 5"},
		regexp.MustCompile(`never-matches`), 300*time.Millisecond); err == nil {
		t.Fatal("expected a timeout error when no URL appears")
	}
}

func TestStartMissingBinary(t *testing.T) {
	if _, err := start(context.Background(), "definitely-not-a-real-binary-xyz", nil,
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
