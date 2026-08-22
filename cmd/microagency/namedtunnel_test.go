package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUpOptionsNamedTunnelFlags(t *testing.T) {
	o, err := parseUpOptions([]string{"--tunnel-name", "my-gateway", "--tunnel-url", "https://mcp.example.com/"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.tunnelName != "my-gateway" {
		t.Fatalf("tunnelName = %q", o.tunnelName)
	}
	if o.tunnelURL != "https://mcp.example.com" {
		t.Fatalf("tunnelURL not normalized: %q", o.tunnelURL)
	}
}

// The two halves of the named-tunnel contract fail closed together, with both
// flags named — half a contract must not silently pick a default for the
// other half.
func TestParseUpOptionsNamedTunnelNeedsBothFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--tunnel-name", "my-gateway"},
		{"--tunnel-url", "https://mcp.example.com"},
	} {
		_, err := parseUpOptions(args)
		if err == nil {
			t.Fatalf("half a named-tunnel config accepted: %v", args)
		}
		if !strings.Contains(err.Error(), "--tunnel-name") || !strings.Contains(err.Error(), "--tunnel-url") {
			t.Fatalf("error does not name both flags: %v", err)
		}
	}
}

// The declared URL becomes the OAuth issuer, so anything beyond a plain
// https:// origin is rejected at parse time — before restart stops anything.
func TestParseUpOptionsRejectsUnsafeTunnelURL(t *testing.T) {
	for _, raw := range []string{
		"http://mcp.example.com",
		"https://user:pass@mcp.example.com",
		"https://mcp.example.com/path",
		"https://mcp.example.com?x=1",
		"https://mcp.example.com#frag",
		"mcp.example.com",
		"",
	} {
		if _, err := parseUpOptions([]string{"--tunnel-name", "n", "--tunnel-url", raw}); err == nil {
			t.Fatalf("unsafe --tunnel-url accepted: %q", raw)
		}
	}
}

func TestParseUpOptionsNamedTunnelIsCloudflareOnly(t *testing.T) {
	_, err := parseUpOptions([]string{"--tunnel", "ngrok", "--tunnel-name", "n", "--tunnel-url", "https://mcp.example.com"})
	if err == nil || !strings.Contains(err.Error(), "cloudflare") {
		t.Fatalf("ngrok named tunnel accepted or unhelpful error: %v", err)
	}
	if _, err := parseUpOptions([]string{"--tunnel", "cloudflare", "--tunnel-name", "n", "--tunnel-url", "https://mcp.example.com"}); err != nil {
		t.Fatalf("explicit cloudflare rejected: %v", err)
	}
}

// A named tunnel's issuer is stable, so a restart with the same declared URL
// must not report the origin as changed — issued tokens stay valid.
func TestRecordAuthPostureNamedTunnelIsStableAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-posture.json")
	cfg := httpConfig{tunnel: "cloudflare", tunnelName: "my-gateway", tunnelURL: "https://mcp.example.com", publicURL: "https://mcp.example.com"}
	if changed, err := recordAuthPostureAt(cfg, "oauth-tunnel", path); err != nil || changed {
		t.Fatalf("first run: changed %v, err %v", changed, err)
	}
	if changed, err := recordAuthPostureAt(cfg, "oauth-tunnel", path); err != nil || changed {
		t.Fatalf("restart with the same URL flagged a change: changed %v, err %v", changed, err)
	}
	posture, err := readAuthPosture(path)
	if err != nil {
		t.Fatal(err)
	}
	if posture.TunnelMode != "named" || posture.TunnelName != "my-gateway" {
		t.Fatalf("posture lost the tunnel mode: %+v", posture)
	}

	// Moving from a quick tunnel's origin to a named one IS a change: tokens
	// issued for the old origin are dead and the operator should hear it.
	quick := httpConfig{tunnel: "cloudflare", publicURL: "https://random.trycloudflare.com"}
	if _, err := recordAuthPostureAt(quick, "oauth-tunnel", path); err != nil {
		t.Fatal(err)
	}
	if changed, err := recordAuthPostureAt(cfg, "oauth-tunnel", path); err != nil || !changed {
		t.Fatalf("quick→named origin change not reported: changed %v, err %v", changed, err)
	}
}

func TestReportAuthPostureNamesURLStability(t *testing.T) {
	var out bytes.Buffer
	reportTunnelStability(&out, authPosture{TunnelMode: "named", TunnelName: "my-gateway"})
	if !strings.Contains(out.String(), "stable") || !strings.Contains(out.String(), "my-gateway") {
		t.Fatalf("named stability line: %q", out.String())
	}
	out.Reset()
	reportTunnelStability(&out, authPosture{TunnelMode: "quick"})
	if !strings.Contains(out.String(), "changes on restart") {
		t.Fatalf("quick stability line: %q", out.String())
	}
	out.Reset()
	reportTunnelStability(&out, authPosture{})
	if out.String() != "" {
		t.Fatalf("posture without a tunnel printed a stability line: %q", out.String())
	}
}

func TestTunnelStateRoundTripAndExitRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnel-state.json")
	cfg := httpConfig{tunnel: "cloudflare", tunnelName: "my-gateway", tunnelURL: "https://mcp.example.com", publicURL: "https://mcp.example.com"}
	if err := writeTunnelState(path, newTunnelState(cfg, 4242)); err != nil {
		t.Fatal(err)
	}
	st, err := readTunnelState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Provider != "cloudflare" || st.Mode != "named" || st.Name != "my-gateway" || st.PID != 4242 || st.URL != "https://mcp.example.com" {
		t.Fatalf("state round trip = %+v", st)
	}
	markTunnelExited(path, errors.New("exit status 1"))
	st, err = readTunnelState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExitedAt == "" || st.ExitError != "exit status 1" {
		t.Fatalf("exit not recorded: %+v", st)
	}
}

func TestReportTunnelHealthAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel-state.json")
	cfg := httpConfig{tunnel: "cloudflare", tunnelName: "my-gateway", tunnelURL: "https://mcp.example.com", publicURL: "https://mcp.example.com"}
	aliveYes := func(int) bool { return true }
	aliveNo := func(int) bool { return false }

	t.Run("no tunnel configured is silent and healthy", func(t *testing.T) {
		var out bytes.Buffer
		ok, clause := reportTunnelHealthAt(&out, filepath.Join(dir, "absent.json"), true, aliveYes)
		if !ok || clause != "" || out.String() != "" {
			t.Fatalf("ok=%v clause=%q out=%q", ok, clause, out.String())
		}
	})

	if err := writeTunnelState(path, newTunnelState(cfg, 4242)); err != nil {
		t.Fatal(err)
	}

	t.Run("live child reads green with mode, pid, and URL", func(t *testing.T) {
		var out bytes.Buffer
		ok, clause := reportTunnelHealthAt(&out, path, true, aliveYes)
		if !ok || clause != "" {
			t.Fatalf("ok=%v clause=%q", ok, clause)
		}
		for _, want := range []string{"✓", "named tunnel \"my-gateway\"", "4242", "https://mcp.example.com"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("healthy line %q is missing %q", out.String(), want)
			}
		}
	})

	t.Run("server down renders not-running, not a false alarm", func(t *testing.T) {
		var out bytes.Buffer
		ok, _ := reportTunnelHealthAt(&out, path, false, aliveNo)
		if !ok {
			t.Fatal("a stopped server must not double-fail the verdict on its tunnel")
		}
		if !strings.Contains(out.String(), "starts and stops with the server") {
			t.Fatalf("not-running state is not rendered: %q", out.String())
		}
	})

	t.Run("gone pid under a live server is the alarm case", func(t *testing.T) {
		var out bytes.Buffer
		ok, clause := reportTunnelHealthAt(&out, path, true, aliveNo)
		if ok || clause == "" {
			t.Fatalf("dead tunnel read healthy: clause=%q", clause)
		}
		for _, want := range []string{"✗", "not being served", "microagency restart"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("alarm line %q is missing %q", out.String(), want)
			}
		}
	})

	t.Run("recorded exit carries the exit error", func(t *testing.T) {
		markTunnelExited(path, errors.New("exit status 1"))
		var out bytes.Buffer
		ok, _ := reportTunnelHealthAt(&out, path, true, aliveYes)
		if ok {
			t.Fatal("recorded exit read healthy")
		}
		if !strings.Contains(out.String(), "exit status 1") {
			t.Fatalf("exit detail lost: %q", out.String())
		}
	})
}

// The new flags are part of up's help contract: --tunnel existed but was
// absent from the flag listing, so the provider switch was undiscoverable.
func TestUpHelpListsTunnelFlags(t *testing.T) {
	stdout, _, _ := runHelpHelper(t, "up", "--help")
	for _, want := range []string{"--tunnel <provider>", "--tunnel-name <name>", "--tunnel-url <url>"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("up --help is missing %q:\n%s", want, stdout)
		}
	}
}
