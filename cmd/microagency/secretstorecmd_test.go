package main

import (
	"bytes"
	"strings"
	"testing"

	"microagency/internal/secretstore"
)

func TestParseSecretStoreCommand(t *testing.T) {
	if cmd, err := parseSecretStoreCommand(nil); err != nil || cmd.action != "status" {
		t.Fatalf("default action = %+v err=%v", cmd, err)
	}
	cmd, err := parseSecretStoreCommand([]string{"migrate", "--to", "keychain"})
	if err != nil || cmd.action != "migrate" || cmd.target != "keychain" || cmd.allowDegraded {
		t.Fatalf("migrate = %+v err=%v", cmd, err)
	}
	if cmd, err := parseSecretStoreCommand([]string{"migrate", "--to", "file", "--allow-degraded"}); err != nil || !cmd.allowDegraded {
		t.Fatalf("allow-degraded = %+v err=%v", cmd, err)
	}
	// A missing required argument states the requirement; it does not act.
	if _, err := parseSecretStoreCommand([]string{"migrate"}); err == nil || !strings.Contains(err.Error(), "--to") {
		t.Fatalf("migrate without --to: %v", err)
	}
	if _, err := parseSecretStoreCommand([]string{"migrate", "--to"}); err == nil {
		t.Fatal("--to with no value was accepted")
	}
	// Unknown arguments are rejected, never ignored.
	if _, err := parseSecretStoreCommand([]string{"migrate", "--to", "keychain", "--force"}); err == nil {
		t.Fatal("an unknown argument was ignored")
	}
	if _, err := parseSecretStoreCommand([]string{"rotate"}); err == nil || !strings.Contains(err.Error(), "rotate") {
		t.Fatal("an unknown action was not echoed back")
	}
	if _, err := parseSecretStoreCommand([]string{"status", "extra"}); err == nil {
		t.Fatal("status took an argument")
	}
	for _, args := range [][]string{{"--help"}, {"migrate", "-h"}, {"status", "--help"}} {
		cmd, err := parseSecretStoreCommand(args)
		if err != nil || !cmd.help {
			t.Fatalf("%v: help = %+v err=%v", args, cmd, err)
		}
	}
}

func TestRenderKeyCustodyPostureDistinguishesTheThreeStates(t *testing.T) {
	var buf bytes.Buffer
	renderKeyCustodyPosture(&buf, secretstore.KeyCustodyPosture{})
	if !strings.Contains(buf.String(), "no protector configured") || !strings.Contains(buf.String(), secretstore.ProtectorEnv) {
		t.Fatalf("unconfigured state does not name the action: %q", buf.String())
	}

	buf.Reset()
	renderKeyCustodyPosture(&buf, secretstore.KeyCustodyPosture{
		Kind: "command", Label: "external protector helper", Protected: true,
		Available: true, Present: true, Detail: "the data key opens the credential store",
	})
	if !strings.Contains(buf.String(), "✓") || !strings.Contains(buf.String(), "protected") {
		t.Fatalf("healthy state = %q", buf.String())
	}

	buf.Reset()
	renderKeyCustodyPosture(&buf, secretstore.KeyCustodyPosture{
		Kind: "command", Label: "external protector helper", Protected: true,
		Detail: "protector helper read failed (exit 1)",
	})
	out := buf.String()
	if strings.Contains(out, "✓") || !strings.Contains(out, "✗") || !strings.Contains(out, "exit 1") {
		t.Fatalf("unavailable state = %q", out)
	}
}
