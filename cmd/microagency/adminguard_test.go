package main

import (
	"path/filepath"
	"strings"
	"testing"

	"microagency/internal/mcp"
	"microagency/internal/optoken"
)

// TestNonLoopbackAdminRequiresExplicitOptIn asserts the operator surface never
// leaves loopback silently: a bind that would serve /admin + /console beyond
// loopback refuses to start unless --allow-remote-admin accepts that posture.
func TestNonLoopbackAdminRequiresExplicitOptIn(t *testing.T) {
	refused := []struct {
		name string
		cfg  httpConfig
		want string // substring the refusal must carry
	}{
		{"shared all-interfaces bind", httpConfig{addr: "0.0.0.0:8765"}, "--allow-remote-admin"},
		{"shared all-interfaces bind names the flag that binds it", httpConfig{addr: "0.0.0.0:8765"}, "--http"},
		{"shared empty-host bind (all interfaces)", httpConfig{addr: ":8765"}, "--allow-remote-admin"},
		{"shared LAN bind", httpConfig{addr: "192.168.1.10:8765"}, "--allow-remote-admin"},
		{"non-loopback --admin-addr", httpConfig{addr: "127.0.0.1:8765", adminAddr: "0.0.0.0:8766"}, "--admin-addr"},
		{"opt-in without exposure is contradictory", httpConfig{addr: "127.0.0.1:8765", allowRemoteAdmin: true}, "only applies"},
		{"opt-in with a tunnel is contradictory", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare", singleUser: true, allowRemoteAdmin: true}, "loopback-only"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHTTPConfig(tc.cfg)
			if err == nil {
				t.Fatalf("config accepted, want refusal: %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
	accepted := []struct {
		name string
		cfg  httpConfig
	}{
		{"loopback default", httpConfig{addr: "127.0.0.1:8765"}},
		{"localhost bind", httpConfig{addr: "localhost:8765"}},
		{"ipv6 loopback bind", httpConfig{addr: "[::1]:8765"}},
		{"acknowledged all-interfaces bind", httpConfig{addr: "0.0.0.0:8765", allowRemoteAdmin: true}},
		{"acknowledged non-loopback --admin-addr", httpConfig{addr: "127.0.0.1:8765", adminAddr: "0.0.0.0:8766", allowRemoteAdmin: true}},
		{"non-loopback agent plane with loopback operator listener", httpConfig{addr: "0.0.0.0:8765", adminAddr: "127.0.0.1:8766"}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHTTPConfig(tc.cfg); err != nil {
				t.Fatalf("safe config rejected: %+v: %v", tc.cfg, err)
			}
		})
	}
}

// TestRemoteAdminRefusesUnauthenticatableSurface asserts the second floor
// under the exposed operator surface: beyond loopback, a deployment with no
// operator credential at all — empty legacy token, no named tokens — refuses
// to serve rather than expose a plane where every request is a 401.
func TestRemoteAdminRefusesUnauthenticatableSurface(t *testing.T) {
	remote := httpConfig{addr: "0.0.0.0:8765", allowRemoteAdmin: true}
	none := mcp.OperatorAuth{Tokens: optoken.NewStore(filepath.Join(t.TempDir(), "operator-tokens.json"))}
	if err := validateRemoteAdminToken(remote, none); err == nil {
		t.Fatal("credential-less operator surface accepted beyond loopback")
	}
	blank := none
	blank.LegacyToken = "   "
	if err := validateRemoteAdminToken(remote, blank); err == nil {
		t.Fatal("blank legacy token with no named tokens accepted beyond loopback")
	}
	legacy := none
	legacy.LegacyToken = "op-tok"
	if err := validateRemoteAdminToken(remote, legacy); err != nil {
		t.Fatalf("legacy operator token rejected: %v", err)
	}
	// A named operator token alone keeps the surface authenticatable: an empty
	// legacy token disables that credential path, not authentication.
	namedStore := optoken.NewStore(filepath.Join(t.TempDir(), "operator-tokens.json"))
	if _, err := namedStore.Create("ops", optoken.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	named := mcp.OperatorAuth{Tokens: namedStore}
	if err := validateRemoteAdminToken(remote, named); err != nil {
		t.Fatalf("named-token-only deployment rejected: %v", err)
	}
	// Loopback keeps today's behavior: no credential is tolerated locally.
	local := httpConfig{addr: "127.0.0.1:8765"}
	if err := validateRemoteAdminToken(local, none); err != nil {
		t.Fatalf("loopback behavior changed: %v", err)
	}
}

func TestRemoteAdminAddr(t *testing.T) {
	cases := []struct {
		name string
		cfg  httpConfig
		want string
	}{
		{"loopback shared", httpConfig{addr: "127.0.0.1:8765"}, ""},
		{"all-interfaces shared", httpConfig{addr: "0.0.0.0:8765"}, "0.0.0.0:8765"},
		{"empty-host shared", httpConfig{addr: ":8765"}, ":8765"},
		{"remote agent plane, loopback admin", httpConfig{addr: "0.0.0.0:8765", adminAddr: "127.0.0.1:8766"}, ""},
		{"loopback agent plane, remote admin", httpConfig{addr: "127.0.0.1:8765", adminAddr: "10.0.0.5:8766"}, "10.0.0.5:8766"},
		{"tunnel default keeps admin loopback", httpConfig{addr: "127.0.0.1:8765", tunnel: "cloudflare"}, ""},
		{"unparseable addr is left for bind to reject", httpConfig{addr: "not-an-addr"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := remoteAdminAddr(tc.cfg); got != tc.want {
				t.Fatalf("remoteAdminAddr(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestParseUpOptionsAllowRemoteAdmin(t *testing.T) {
	o, err := parseUpOptions([]string{"--http", "0.0.0.0:8765", "--allow-remote-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if o.httpAddr != "0.0.0.0:8765" || !o.allowRemoteAdmin {
		t.Fatalf("parsed options = %+v, want httpAddr and allowRemoteAdmin set", o)
	}
}
