package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"microagency/internal/secretstore"
)

type secretStoreCommand struct {
	action        string
	target        string
	allowDegraded bool
	help          bool
}

func parseSecretStoreCommand(args []string) (secretStoreCommand, error) {
	cmd := secretStoreCommand{action: "status"}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd.action = args[0]
		args = args[1:]
	}
	switch cmd.action {
	case "status":
		for _, arg := range args {
			if arg == "-h" || arg == "--help" || arg == "help" {
				cmd.help = true
				continue
			}
			return cmd, fmt.Errorf("%s takes no arguments, got %q", cmd.action, arg)
		}
	case "migrate":
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-h", "--help", "help":
				cmd.help = true
			case "--allow-degraded":
				cmd.allowDegraded = true
			case "--to":
				i++
				if i >= len(args) {
					return cmd, errors.New("--to requires file, keychain, secret-service, or command")
				}
				cmd.target = args[i]
			default:
				return cmd, fmt.Errorf("unknown secret-store migrate argument %q", args[i])
			}
		}
		if !cmd.help && cmd.target == "" {
			return cmd, errors.New("secret-store migrate requires --to")
		}
	default:
		return cmd, fmt.Errorf("unknown secret-store action %q", cmd.action)
	}
	return cmd, nil
}

func secretStoreHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency secret-store status")
	fmt.Fprintln(w, "  microagency secret-store migrate --to <keychain|secret-service|command|file> [--allow-degraded]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Who holds the encrypted credential store's data key:")
	fmt.Fprintln(w, "  keychain       macOS login Keychain")
	fmt.Fprintln(w, "  secret-service Linux user Secret Service/keyring")
	fmt.Fprintln(w, "  command        operator helper at $"+secretstore.ProtectorCommandEnv)
	fmt.Fprintln(w, "  file           a key file you place at $"+secretstore.FileKeyEnv)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "migrate moves the SAME data key to another protector and verifies the new copy")
	fmt.Fprintln(w, "before switching. Stored credentials are never re-encrypted, so the store keeps")
	fmt.Fprintln(w, "opening throughout. Moving to file writes that key back to disk as a file you")
	fmt.Fprintln(w, "must then protect, so it requires --allow-degraded. Your existing key file is")
	fmt.Fprintln(w, "left in place when migrating away from it — keep it as the backup, or remove it")
	fmt.Fprintln(w, "yourself once the new protector is proven.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Stop the gateway (`microagency down`) before migrating.")
}

func renderKeyCustodyPosture(w io.Writer, posture secretstore.KeyCustodyPosture) {
	if posture.Kind == "" {
		fmt.Fprintln(w, "credential-store data key  — no protector configured")
		fmt.Fprintln(w, "  set "+secretstore.ProtectorEnv+" (keychain, secret-service, or command)")
		fmt.Fprintln(w, "  or "+secretstore.FileKeyEnv+" to encrypt the credential store")
		return
	}
	mark := "✓"
	if !posture.Available {
		mark = "✗"
	}
	mode := "protected"
	if !posture.Protected {
		mode = "operator-held"
	}
	fmt.Fprintf(w, "credential-store data key  %s %s (%s)\n", mark, mode, posture.Label)
	if posture.Detail != "" {
		fmt.Fprintf(w, "  %s\n", posture.Detail)
	}
}

func runSecretStore(args []string) {
	cmd, err := parseSecretStoreCommand(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "microagency: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'microagency secret-store --help' for usage.")
		os.Exit(2)
	}
	if cmd.help {
		secretStoreHelp(os.Stdout)
		return
	}
	dir := microagencyDir()
	ctx := context.Background()
	switch cmd.action {
	case "status":
		posture := secretstore.InspectKeyCustody(ctx, dir, os.Getenv)
		renderKeyCustodyPosture(os.Stdout, posture)
		if posture.Kind != "" && !posture.Available {
			os.Exit(1)
		}
	case "migrate":
		// A running gateway holds the store open under the current key. Migrating
		// underneath it would leave the process and the locator disagreeing about
		// who holds the key until the next restart.
		if pid := runningPID(); pid != 0 {
			fmt.Fprintf(os.Stderr, "microagency is running (pid %d); run `microagency down` before migrating the data key.\n", pid)
			os.Exit(1)
		}
		if err := secretstore.MigrateKeyCustody(ctx, dir, os.Getenv, cmd.target, cmd.allowDegraded); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: credential-store key migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "microagency: credential-store data key migrated")
		renderKeyCustodyPosture(os.Stdout, secretstore.InspectKeyCustody(ctx, dir, os.Getenv))
	}
}
