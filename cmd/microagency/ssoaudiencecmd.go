// The sso-audience command manages who may sign in through federated sign-in.
// It edits the rule file directly, so it works whether or not the gateway is
// running — which matters, because a federated gateway refuses to start until
// its audience is declared, and rules are one of the ways to declare it.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"microagency/internal/auth"
)

func runSSOAudience(args []string) {
	if len(args) == 0 {
		ssoAudienceHelp(os.Stderr)
		os.Exit(2)
	}
	rules := ssoAudienceRules("")
	var err error
	switch args[0] {
	case "-h", "--help", "help":
		ssoAudienceHelp(os.Stdout)
	case "list":
		err = runSSOAudienceList(rules, args[1:], os.Stdout)
	case "allow":
		err = runSSOAudienceAllow(rules, args[1:], os.Stdout)
	case "remove":
		err = runSSOAudienceRemove(rules, args[1:], os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown sso-audience command %q (want list|allow|remove)\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "microagency sso-audience:", err)
		os.Exit(1)
	}
}

func ssoAudienceHelp(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  microagency sso-audience list")
	fmt.Fprintln(w, "  microagency sso-audience allow <rule> [--note <text>]")
	fmt.Fprintln(w, "  microagency sso-audience remove <rule>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  A rule is kind:value, and any one matching rule admits the account:")
	fmt.Fprintln(w, "    group:<name>       a group the provider asserts in its "+auth.DefaultGroupsClaim+" claim")
	fmt.Fprintln(w, "                       (--sso-groups-claim names a different claim)")
	fmt.Fprintln(w, "    email:<address>    a provider-VERIFIED email address; an unverified one never matches")
	fmt.Fprintln(w, "    subject:<sub>      the provider's stable subject, for an account whose address may change")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Rules are one way to declare the audience of federated sign-in. `up --sso-hd`")
	fmt.Fprintln(w, "  bounds it to one hosted domain, and `up --sso-any-account` declares every account")
	fmt.Fprintln(w, "  at the issuer to be in it. Configure a domain and rules together and BOTH must")
	fmt.Fprintln(w, "  pass. Reach for rules when the provider asserts a group, or — as a last resort,")
	fmt.Fprintln(w, "  where it asserts nothing usable — to name people individually.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Rules hold no secret. A running gateway picks up every change immediately")
	fmt.Fprintln(w, "  (no restart), and so does the operator API at /admin/sso-audience.")
}

// ssoAudienceArgs parses "<rule> [--note <text>]", answering --help without
// acting and rejecting unknown arguments.
func ssoAudienceArgs(args []string, allowNote bool, stdout io.Writer) (spec, note string, helped bool, err error) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-h" || args[i] == "--help" || args[i] == "help":
			ssoAudienceHelp(stdout)
			return "", "", true, nil
		case allowNote && args[i] == "--note" && i+1 < len(args):
			note = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-") && spec == "":
			spec = args[i]
		default:
			return "", "", false, fmt.Errorf("unknown argument: %s", args[i])
		}
	}
	if spec == "" {
		return "", "", false, fmt.Errorf("name a rule as kind:value, e.g. group:engineering or email:person@example.com")
	}
	return spec, note, false, nil
}

func runSSOAudienceAllow(rules *auth.AudienceRules, args []string, stdout io.Writer) error {
	spec, note, helped, err := ssoAudienceArgs(args, true, stdout)
	if err != nil || helped {
		return err
	}
	rule, err := auth.ParseAudienceRule(spec)
	if err != nil {
		return err
	}
	rule.Note = note
	stored, err := rules.Add(rule)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Allowed %s.\n", stored.ID())
	if stored.Kind == auth.AudienceEmail {
		fmt.Fprintln(stdout, "The provider must mark this address verified; an unverified claim never matches.")
	}
	return nil
}

func runSSOAudienceRemove(rules *auth.AudienceRules, args []string, stdout io.Writer) error {
	spec, _, helped, err := ssoAudienceArgs(args, false, stdout)
	if err != nil || helped {
		return err
	}
	removed, err := rules.Remove(spec)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("no audience rule %q; list them with: microagency sso-audience list", spec)
	}
	rule, _ := auth.ParseAudienceRule(spec)
	fmt.Fprintf(stdout, "Removed %s.\n", rule.ID())
	// Removing the last rule can leave a running gateway admitting nobody, and
	// that is worth saying at the moment it happens rather than at the next
	// doctor run.
	if rules.Summary().Total() == 0 {
		fmt.Fprintln(stdout, "No audience rules remain. If no --sso-hd or --sso-any-account bounds sign-in,")
		fmt.Fprintln(stdout, "no account can sign in until a bound is restored.")
	}
	return nil
}

func runSSOAudienceList(rules *auth.AudienceRules, args []string, stdout io.Writer) error {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			ssoAudienceHelp(stdout)
			return nil
		default:
			return fmt.Errorf("unknown argument: %s", a)
		}
	}
	list, err := rules.List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		// Empty here does not mean "nobody can sign in" — a hosted domain or a
		// dedicated-tenant declaration may bound the audience instead — so the
		// empty state says what it does and does not mean.
		fmt.Fprintln(stdout, "No audience rules.")
		fmt.Fprintln(stdout, "Sign-in is then bounded by `up --sso-hd` or `up --sso-any-account`; with neither, a federated start refuses.")
		fmt.Fprintln(stdout, "Add one with: microagency sso-audience allow group:<name>")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tVALUE\tADDED\tNOTE")
	for _, rule := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", rule.Kind, rule.Value, rule.Added.Format(time.RFC3339), rule.Note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nAny one matching rule admits an account (%s).\n", rules.Summary())
	fmt.Fprintln(stdout, "A configured --sso-hd applies as well: both must pass.")
	return nil
}
