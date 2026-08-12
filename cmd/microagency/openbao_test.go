package main

import (
	"bytes"
	"strings"
	"testing"

	"microagency/internal/baomanager"
)

func TestParseOpenBaoCommand(t *testing.T) {
	cases := []struct {
		args           []string
		action, target string
		allowDegraded  bool
		wantErr        string
	}{
		{args: nil, action: "status"},
		{args: []string{"status"}, action: "status"},
		{args: []string{"rotate-login"}, action: "rotate-login"},
		{args: []string{"migrate", "--to", "keychain"}, action: "migrate", target: "keychain"},
		{args: []string{"migrate", "--to", "file", "--allow-degraded"}, action: "migrate", target: "file", allowDegraded: true},
		{args: []string{"migrate"}, wantErr: "requires --to"},
		{args: []string{"migrate", "--to"}, wantErr: "--to requires"},
		{args: []string{"reset"}, wantErr: "unknown openbao action"},
	}
	for _, tc := range cases {
		got, err := parseOpenBaoCommand(tc.args)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseOpenBaoCommand(%q) error = %v, want %q", tc.args, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got.action != tc.action || got.target != tc.target || got.allowDegraded != tc.allowDegraded {
			t.Fatalf("parseOpenBaoCommand(%q) = %+v err=%v", tc.args, got, err)
		}
	}
}

func TestRenderOpenBaoPostureDistinguishesProtectedAndDegraded(t *testing.T) {
	var out bytes.Buffer
	renderOpenBaoPosture(&out, baomanager.CustodyPosture{
		Kind: "keychain", Label: "macOS Keychain", Protected: true, Available: true, Detail: "root retired",
	})
	if !strings.Contains(out.String(), "✓ protected") || !strings.Contains(out.String(), "macOS Keychain") || !strings.Contains(out.String(), "root retired") {
		t.Fatalf("protected posture = %q", out.String())
	}
	out.Reset()
	renderOpenBaoPosture(&out, baomanager.CustodyPosture{
		Kind: "file", Label: "same-disk file", Available: true,
	})
	if !strings.Contains(out.String(), "⚠ same-disk degraded") {
		t.Fatalf("degraded posture = %q", out.String())
	}
	out.Reset()
	renderOpenBaoPosture(&out, baomanager.CustodyPosture{
		Kind: "command", Label: "external protector helper", Protected: true, Detail: "KMS unavailable",
	})
	if !strings.Contains(out.String(), "✗ protected") || !strings.Contains(out.String(), "KMS unavailable") {
		t.Fatalf("unavailable posture = %q", out.String())
	}
}
