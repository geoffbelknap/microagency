package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// A federated gateway has to answer one question before it can serve anyone:
// who may sign in? The provider authenticates the person, but "authenticated
// somewhere" is not "belongs here". A dedicated tenant — a company's own Okta,
// Entra, or Keycloak — answers it by construction: everyone who can
// authenticate there is in the organisation, so the issuer IS the boundary. A
// shared provider like accounts.google.com serves the whole internet and
// answers nothing, so the audience has to be narrowed by a claim the provider
// asserts (a hosted domain, a group) or, when it asserts nothing usable, by
// naming the people.
//
// The gateway cannot tell those two kinds of issuer apart by inspection, so it
// does not try. It requires the operator to state the audience, and states it
// back on every surface that describes the deployment.

// ErrIdentityNotPermitted reports a fully validated sign-in from an account
// outside the gateway's declared audience. The identity is real and the
// provider vouched for it; the gateway's audience refuses it. Callers show a
// policy message rather than a validation error, exactly as they do for
// ErrHostedDomainRefused.
var ErrIdentityNotPermitted = errors.New("account is outside the gateway's declared audience")

// Audience rule kinds. A rule is one predicate over a validated identity; an
// identity is admitted when any single rule matches.
const (
	// AudienceGroup matches a value the provider asserts in its groups claim.
	// This is the predicate to reach for on a shared issuer that publishes
	// organisation or group membership.
	AudienceGroup = "group"
	// AudienceEmail matches the provider-verified email address, compared
	// case-insensitively. Only an address the provider marked verified can
	// match: an unverified claim never becomes a principal.
	AudienceEmail = "email"
	// AudienceSubject matches the provider's stable `sub` claim exactly. Use it
	// where an address may change but the account must not.
	AudienceSubject = "subject"
)

// maxAudienceRules bounds the rule file so one operator mistake cannot grow an
// unbounded document that every sign-in has to read.
const maxAudienceRules = 512

// AudienceRule is one operator-authored predicate over a validated federated
// identity. It holds no secret: a group name, an email address, or a provider
// subject, all of which the operator already knows.
type AudienceRule struct {
	Kind  string    `json:"kind"`
	Value string    `json:"value"`
	Note  string    `json:"note,omitempty"`
	Added time.Time `json:"added"`
}

// ID is the stable handle for one rule — the kind and value that define it.
// Removing a rule names this, so removal is idempotent and does not depend on
// list position.
func (r AudienceRule) ID() string { return r.Kind + ":" + r.Value }

// normalizeAudienceRule validates and canonicalizes one rule in place. It is
// the single funnel for both the admin API and the on-disk load, so a record
// that could never match is refused at the door rather than sitting in the file
// looking like protection.
func normalizeAudienceRule(rule *AudienceRule) error {
	rule.Kind = strings.ToLower(strings.TrimSpace(rule.Kind))
	rule.Value = strings.TrimSpace(rule.Value)
	rule.Note = strings.TrimSpace(rule.Note)
	if len(rule.Note) > 256 {
		return errors.New("rule note must be 256 characters or fewer")
	}
	if rule.Value == "" {
		return fmt.Errorf("an audience rule needs a value, e.g. %s:%s", AudienceGroup, "engineering")
	}
	if len(rule.Value) > 320 {
		return errors.New("rule value must be 320 characters or fewer")
	}
	switch rule.Kind {
	case AudienceGroup:
		// Group names are compared case-insensitively: providers spell the same
		// group inconsistently across their console and their claims, and an
		// operator should not have to guess which spelling the token carries.
		rule.Value = strings.ToLower(rule.Value)
	case AudienceEmail:
		if !strings.Contains(rule.Value, "@") || strings.HasPrefix(rule.Value, "@") || strings.HasSuffix(rule.Value, "@") {
			return fmt.Errorf("email rule %q must be a full address; to admit a whole domain use --sso-hd", rule.Value)
		}
		rule.Value = strings.ToLower(rule.Value)
	case AudienceSubject:
		// A subject is an opaque provider identifier. Case may be significant,
		// so it is compared exactly.
	case "":
		return fmt.Errorf("an audience rule needs a kind: %s, %s, or %s", AudienceGroup, AudienceEmail, AudienceSubject)
	default:
		return fmt.Errorf("unknown audience rule kind %q: use %s, %s, or %s", rule.Kind, AudienceGroup, AudienceEmail, AudienceSubject)
	}
	if rule.Added.IsZero() {
		rule.Added = time.Now().UTC()
	}
	return nil
}

// ParseAudienceRule reads the `kind:value` form an operator types on a command
// line or passes as a rule id.
func ParseAudienceRule(spec string) (AudienceRule, error) {
	kind, value, ok := strings.Cut(spec, ":")
	if !ok {
		return AudienceRule{}, fmt.Errorf("%q is not an audience rule: write it as kind:value, e.g. %s:engineering or %s:person@example.com", spec, AudienceGroup, AudienceEmail)
	}
	rule := AudienceRule{Kind: kind, Value: value}
	if err := normalizeAudienceRule(&rule); err != nil {
		return AudienceRule{}, err
	}
	return rule, nil
}

// AudienceRules is the operator-managed rule set, backed by a JSON file that
// holds no secret.
//
// Every read goes to the file. The rule set is consulted once per interactive
// sign-in — a browser round-trip — so the cost is irrelevant, and reading
// through means the running gateway, the admin API, and an offline edit all
// see the same rules with no restart and no cache to go stale. Writes land
// atomically (temp file, fsync, rename), so a concurrent read never observes a
// half-written document.
type AudienceRules struct {
	mu   sync.Mutex
	path string
}

// AudienceRulesFile is the state-directory file holding the rule set. It is a
// fixed name so the running gateway, the admin API, and an offline edit all
// address the same document without being wired to each other.
const AudienceRulesFile = "sso-audience.json"

// AudienceRulesPath locates the rule set inside a state directory. An empty
// state directory yields an empty path, which is an inert rule set.
func AudienceRulesPath(stateDir string) string {
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, AudienceRulesFile)
}

// NewAudienceRules binds a rule set to its file. The file need not exist yet;
// an absent file is an empty rule set.
func NewAudienceRules(path string) *AudienceRules {
	return &AudienceRules{path: path}
}

// Path reports the file backing this rule set.
func (a *AudienceRules) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

// List returns the rules, sorted by kind then value so the operator surface and
// the file agree on order.
func (a *AudienceRules) List() ([]AudienceRule, error) {
	if a == nil || a.path == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.loadLocked()
}

func (a *AudienceRules) loadLocked() ([]AudienceRule, error) {
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var raw []AudienceRule
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("read audience rules %s: %w", a.path, err)
	}
	rules := make([]AudienceRule, 0, len(raw))
	seen := map[string]bool{}
	for _, rule := range raw {
		// A record that cannot be normalized could never match anything, so it
		// is dropped rather than counted as an audience bound it is not.
		if normalizeAudienceRule(&rule) != nil || seen[rule.ID()] {
			continue
		}
		seen[rule.ID()] = true
		rules = append(rules, rule)
	}
	sortAudienceRules(rules)
	return rules, nil
}

func sortAudienceRules(rules []AudienceRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Kind != rules[j].Kind {
			return rules[i].Kind < rules[j].Kind
		}
		return rules[i].Value < rules[j].Value
	})
}

// Add stores one rule, replacing any rule with the same kind and value. It
// returns the normalized rule as stored.
func (a *AudienceRules) Add(rule AudienceRule) (AudienceRule, error) {
	if a == nil || a.path == "" {
		return AudienceRule{}, errors.New("no state directory is configured to hold audience rules")
	}
	if err := normalizeAudienceRule(&rule); err != nil {
		return AudienceRule{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rules, err := a.loadLocked()
	if err != nil {
		return AudienceRule{}, err
	}
	replaced := false
	for i := range rules {
		if rules[i].ID() == rule.ID() {
			rule.Added = rules[i].Added // keep the original admission time
			rules[i] = rule
			replaced = true
			break
		}
	}
	if !replaced {
		if len(rules) >= maxAudienceRules {
			return AudienceRule{}, fmt.Errorf("audience rule quota reached (%d)", maxAudienceRules)
		}
		rules = append(rules, rule)
	}
	sortAudienceRules(rules)
	if err := a.writeLocked(rules); err != nil {
		return AudienceRule{}, err
	}
	return rule, nil
}

// Remove deletes the rule with this id (`kind:value`). It reports whether a
// rule was there to remove.
func (a *AudienceRules) Remove(id string) (bool, error) {
	if a == nil || a.path == "" {
		return false, nil
	}
	rule, err := ParseAudienceRule(id)
	if err != nil {
		return false, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rules, err := a.loadLocked()
	if err != nil {
		return false, err
	}
	kept := make([]AudienceRule, 0, len(rules))
	for _, existing := range rules {
		if existing.ID() == rule.ID() {
			continue
		}
		kept = append(kept, existing)
	}
	if len(kept) == len(rules) {
		return false, nil
	}
	if err := a.writeLocked(kept); err != nil {
		return false, err
	}
	return true, nil
}

// writeLocked persists the rule set atomically: a temp file in the same
// directory, fsynced and renamed over the target, then the directory fsynced.
// A reader therefore sees either the old document or the new one.
func (a *AudienceRules) writeLocked(rules []AudienceRule) error {
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sso-audience-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, a.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// AudienceSummary counts the rule set by kind. It carries no rule values, so it
// is safe to render on a banner or a diagnostic page: an operator learns how
// the audience is bounded without the page listing who is in it.
type AudienceSummary struct {
	Groups     int `json:"groups"`
	Identities int `json:"identities"`
	// Unreadable records that the rule file exists but could not be parsed.
	// Sign-in fails closed in that state, so every surface describing the
	// audience has to say so rather than render the remaining bounds as if
	// they were the whole story.
	Unreadable bool `json:"unreadable,omitempty"`
}

// Total reports how many rules bound the audience.
func (s AudienceSummary) Total() int { return s.Groups + s.Identities }

// String renders the summary for a human, pluralized and omitting kinds that
// have no rules: "2 groups", "1 identity", "2 groups + 1 identity".
func (s AudienceSummary) String() string {
	if s.Unreadable {
		return "an unreadable rule set"
	}
	var parts []string
	if s.Groups > 0 {
		parts = append(parts, plural(s.Groups, "group", "groups"))
	}
	if s.Identities > 0 {
		parts = append(parts, plural(s.Identities, "identity", "identities"))
	}
	if len(parts) == 0 {
		return "no rules"
	}
	return strings.Join(parts, " + ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Summary counts the rules by kind. An unreadable file counts as no rules,
// which keeps the audience bounded: with nothing else declared, a start refuses
// and a sign-in is refused, rather than a damaged file quietly admitting
// everyone.
func (a *AudienceRules) Summary() AudienceSummary {
	rules, err := a.List()
	if err != nil {
		return AudienceSummary{Unreadable: true}
	}
	var s AudienceSummary
	for _, rule := range rules {
		switch rule.Kind {
		case AudienceGroup:
			s.Groups++
		default:
			s.Identities++
		}
	}
	return s
}

// Match reports whether any rule matches this validated identity, how many
// rules were considered, and any error reading them.
//
// The count and the error are returned separately on purpose. An unreadable
// rule set is not an empty one, and a caller that cannot tell them apart will
// treat "I could not read the bounds" as "there are no bounds" — which widens
// the audience at exactly the moment the operator can least see it.
func (a *AudienceRules) Match(id *FederatedIdentity) (matched bool, count int, err error) {
	if a == nil || id == nil {
		return false, 0, nil
	}
	rules, err := a.List()
	if err != nil {
		return false, 0, err
	}
	for _, rule := range rules {
		if rule.matches(id) {
			return true, len(rules), nil
		}
	}
	return false, len(rules), nil
}

// Permits reports whether any rule matches this validated identity. An empty
// rule set matches nothing — it is the caller's job to know whether the
// audience is bounded some other way.
func (a *AudienceRules) Permits(id *FederatedIdentity) bool {
	matched, _, err := a.Match(id)
	return matched && err == nil
}

func (r AudienceRule) matches(id *FederatedIdentity) bool {
	switch r.Kind {
	case AudienceSubject:
		return id.Subject != "" && id.Subject == r.Value
	case AudienceEmail:
		// id.Email is populated only when the provider marked it verified, so an
		// unverified address cannot match a rule.
		return id.Email != "" && strings.EqualFold(id.Email, r.Value)
	case AudienceGroup:
		for _, group := range id.Groups {
			if strings.EqualFold(group, r.Value) {
				return true
			}
		}
	}
	return false
}
