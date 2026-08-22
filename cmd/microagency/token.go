// The token command manages named operator tokens: the credentials that gate
// the operator surface (/admin + the console). They never authenticate the
// agent-facing /mcp endpoint — that surface has its own OAuth/bearer modes.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"microagency/internal/optoken"
)

// operatorTokensPath is the named operator-token store (0600; values hashed).
func operatorTokensPath() string {
	return filepath.Join(microagencyDir(), "operator-tokens.json")
}

func runToken(args []string) {
	if len(args) == 0 {
		tokenHelp(os.Stderr)
		os.Exit(2)
	}
	store := optoken.NewStore(operatorTokensPath())
	var err error
	switch args[0] {
	case "-h", "--help", "help":
		tokenHelp(os.Stdout)
	case "create":
		err = runTokenCreate(store, args[1:], os.Stdout, os.Stderr)
	case "list":
		err = runTokenList(store, args[1:], os.Stdout)
	case "rotate":
		err = runTokenRotate(store, args[1:], os.Stdout, os.Stderr)
	case "revoke":
		err = runTokenRevoke(store, args[1:], os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "unknown token command %q (want create|list|rotate|revoke)\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "microagency token:", err)
		os.Exit(1)
	}
}

func tokenHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency token create <name> --role admin|auditor [--expires <dur>]")
	fmt.Fprintln(w, "  microagency token list")
	fmt.Fprintln(w, "  microagency token rotate <name> [--expires <dur>]")
	fmt.Fprintln(w, "  microagency token revoke <name>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Operator tokens gate /admin and the console — never the agent-facing /mcp.")
	fmt.Fprintln(w, "  admin grants the full operator surface; auditor is read-only (run listing,")
	fmt.Fprintln(w, "  metrics, audit verification — no mutations, no parked-data materialization).")
	fmt.Fprintln(w, "  create and rotate print the token value once, on stdout; only a hash is stored.")
	fmt.Fprintln(w, "  list never shows values. revoke removes a token; rotate keeps name and role.")
	fmt.Fprintln(w, "  --expires takes a Go duration (72h) or days (30d). No expiry means no expiry.")
	fmt.Fprintln(w, "  A running gateway picks up every change immediately (no restart).")
}

// tokenNameAndFlags parses "<name> [flags...]" for create/rotate/revoke,
// answering --help without acting and rejecting unknown arguments.
func tokenNameAndFlags(args []string, allowRole bool) (name, role, expires string, helped bool, err error) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-h" || args[i] == "--help" || args[i] == "help":
			return "", "", "", true, nil
		case allowRole && args[i] == "--role" && i+1 < len(args):
			role = args[i+1]
			i++
		case args[i] == "--expires" && i+1 < len(args):
			expires = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-") && name == "":
			name = args[i]
		default:
			return "", "", "", false, fmt.Errorf("unknown or incomplete argument: %s", args[i])
		}
	}
	if name == "" {
		return "", "", "", false, fmt.Errorf("a token name is required")
	}
	return name, role, expires, false, nil
}

// parseExpires turns a --expires value into an absolute UTC time: a Go
// duration ("72h", "45m") or whole days ("30d"). "" means no expiry (nil).
func parseExpires(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("--expires takes a positive duration like 72h or 30d, got %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("--expires takes a positive duration like 72h or 30d, got %q", s)
		}
	}
	t := time.Now().Add(d).UTC().Truncate(time.Second)
	return &t, nil
}

// runTokenCreate mints a named token. The value goes to stdout alone (so a
// script can capture exactly the secret); everything human goes to stderr.
func runTokenCreate(store *optoken.Store, args []string, stdout, stderr io.Writer) error {
	name, roleStr, expiresStr, helped, err := tokenNameAndFlags(args, true)
	if helped {
		tokenHelp(stdout)
		return nil
	}
	if err != nil {
		return err
	}
	if roleStr == "" {
		return fmt.Errorf("--role is required: admin (full operator surface) or auditor (read-only)")
	}
	role, err := optoken.ParseRole(roleStr)
	if err != nil {
		return err
	}
	expires, err := parseExpires(expiresStr)
	if err != nil {
		return err
	}
	secret, err := store.Create(name, role, expires)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("%v; rotate it instead: microagency token rotate %s", err, name)
		}
		return err
	}
	when := "no expiry"
	if expires != nil {
		when = "expires " + expires.Format(time.RFC3339)
	}
	fmt.Fprintf(stderr, "Operator token %q created (role %s, %s).\n", name, role, when)
	fmt.Fprintln(stderr, "The value below is shown once and stored only as a hash — save it now.")
	fmt.Fprintln(stdout, secret)
	return nil
}

func runTokenList(store *optoken.Store, args []string, stdout io.Writer) error {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			tokenHelp(stdout)
			return nil
		default:
			return fmt.Errorf("unknown argument: %s", a)
		}
	}
	tokens, err := store.List()
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Fprintln(stdout, "No named operator tokens.")
		fmt.Fprintln(stdout, "Create one with: microagency token create <name> --role admin|auditor")
	} else {
		tw := tabwriter.NewWriter(stdout, 2, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tROLE\tCREATED\tEXPIRES")
		now := time.Now()
		for _, t := range tokens {
			exp := "never"
			if t.Expires != nil {
				exp = t.Expires.Format(time.RFC3339)
				if t.Expired(now) {
					exp += " (expired)"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Role, t.Created.Format(time.RFC3339), exp)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if legacy, _ := persistentTokenFileIfPresent(); legacy != "" {
		fmt.Fprintf(stdout, "Legacy operator token present (%s): full admin; audits as %q.\n", legacy, optoken.LegacyName)
	}
	return nil
}

// persistentTokenFileIfPresent reports the legacy token file's path if it
// exists with content, without minting one.
func persistentTokenFileIfPresent() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	file := filepath.Join(home, ".microagency", "token")
	b, err := os.ReadFile(file)
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return "", err
	}
	return file, nil
}

func runTokenRotate(store *optoken.Store, args []string, stdout, stderr io.Writer) error {
	name, _, expiresStr, helped, err := tokenNameAndFlags(args, false)
	if helped {
		tokenHelp(stdout)
		return nil
	}
	if err != nil {
		return err
	}
	expires, err := parseExpires(expiresStr)
	if err != nil {
		return err
	}
	secret, err := store.Rotate(name, expires)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Operator token %q rotated; the previous value no longer authenticates.\n", name)
	fmt.Fprintln(stderr, "The new value below is shown once and stored only as a hash — save it now.")
	fmt.Fprintln(stdout, secret)
	return nil
}

func runTokenRevoke(store *optoken.Store, args []string, stderr io.Writer) error {
	name, _, expiresStr, helped, err := tokenNameAndFlags(args, false)
	if helped {
		tokenHelp(os.Stdout)
		return nil
	}
	if err != nil {
		return err
	}
	if expiresStr != "" {
		return fmt.Errorf("revoke takes no --expires")
	}
	if err := store.Revoke(name); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Operator token %q revoked; it no longer authenticates.\n", name)
	return nil
}
