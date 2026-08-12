package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"microagency/internal/baomanager"
)

type openBaoCommand struct {
	action        string
	target        string
	allowDegraded bool
	help          bool
}

func parseOpenBaoCommand(args []string) (openBaoCommand, error) {
	cmd := openBaoCommand{action: "status"}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd.action = args[0]
		args = args[1:]
	}
	switch cmd.action {
	case "status", "rotate-login":
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
				return cmd, fmt.Errorf("unknown openbao migrate argument %q", args[i])
			}
		}
		if !cmd.help && cmd.target == "" {
			return cmd, errors.New("openbao migrate requires --to")
		}
	default:
		return cmd, fmt.Errorf("unknown openbao action %q", cmd.action)
	}
	return cmd, nil
}

func openBaoHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency openbao status")
	fmt.Fprintln(w, "  microagency openbao rotate-login")
	fmt.Fprintln(w, "  microagency openbao migrate --to <keychain|secret-service|command|file> [--allow-degraded]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Protected providers:")
	fmt.Fprintln(w, "  keychain       macOS login Keychain")
	fmt.Fprintln(w, "  secret-service Linux user Secret Service/keyring")
	fmt.Fprintln(w, "  command        operator helper at $MICROAGENCY_OPENBAO_PROTECTOR_COMMAND")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Moving to file custody requires --allow-degraded because bootstrap material")
	fmt.Fprintln(w, "will again live beside OpenBao's data under ~/.microagency.")
}

func renderOpenBaoPosture(w io.Writer, posture baomanager.CustodyPosture) {
	mark := "✓"
	if !posture.Available {
		mark = "✗"
	} else if !posture.Protected {
		mark = "⚠"
	}
	mode := "protected"
	if !posture.Protected {
		mode = "same-disk degraded"
	}
	fmt.Fprintf(w, "managed OpenBao custody  %s %s (%s)\n", mark, mode, posture.Label)
	if posture.Detail != "" {
		fmt.Fprintf(w, "  %s\n", posture.Detail)
	}
}

func runOpenBao(args []string) {
	cmd, err := parseOpenBaoCommand(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "microagency: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'microagency openbao --help' for usage.")
		os.Exit(2)
	}
	if cmd.help {
		openBaoHelp(os.Stdout)
		return
	}
	dir := filepath.Join(microagencyDir(), "openbao")
	switch cmd.action {
	case "status":
		posture := baomanager.InspectCustody(context.Background(), dir, os.Getenv)
		renderOpenBaoPosture(os.Stdout, posture)
		if !posture.Available {
			os.Exit(1)
		}
	case "migrate":
		if err := baomanager.MigrateCustody(context.Background(), dir, os.Getenv, cmd.target, cmd.allowDegraded); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: OpenBao custody migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "microagency: OpenBao custody migration complete")
		renderOpenBaoPosture(os.Stdout, baomanager.InspectCustody(context.Background(), dir, os.Getenv))
	case "rotate-login":
		if err := baomanager.RotateLogin(context.Background(), dir, os.Getenv); err != nil {
			fmt.Fprintf(os.Stderr, "microagency: managed OpenBao login rotation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "microagency: managed OpenBao login rotated; the previous SecretID was revoked")
	}
}
