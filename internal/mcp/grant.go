package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	grantVersion             = "microagency.grant/v1"
	effectRead               = "read"
	effectWrite              = "write"
	maxGrantEntries          = 256
	maxGrantRequests         = 1_000_000
	maxGrantBytes      int64 = 1 << 40
	maxGrantRateWindow       = 365 * 24 * 60 * 60
)

// OperationGrant is operator-owned authority for one exact MCP operation. It
// lives beside a connection, never in agent arguments, and is evaluated again
// at the last invocation gate before any upstream call.
type OperationGrant struct {
	Version     string           `json:"version"`
	ID          string           `json:"id"`
	Connection  string           `json:"connection"`
	Tool        string           `json:"tool"`
	Effect      string           `json:"effect"`
	Principal   string           `json:"principal"`
	Campaign    string           `json:"campaign"`
	ExpiresAt   string           `json:"expires_at"`
	Arguments   []ArgumentGrant  `json:"arguments,omitempty"`
	Resources   []ResourceGrant  `json:"resources,omitempty"`
	URLTargets  []URLTargetGrant `json:"url_targets,omitempty"`
	MaxRequests int64            `json:"max_requests"`
	MaxBytes    int64            `json:"max_bytes"`
	// MaxResponseBytes is reserved before crossing. Reserving the declared
	// response ceiling, rather than trying to charge bytes after release, keeps
	// the aggregate byte budget fail-closed.
	MaxResponseBytes int64             `json:"max_response_bytes"`
	Rate             RateGrant         `json:"rate"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	AllowShared      bool              `json:"allow_shared_credential,omitempty"`
	HighAssurance    bool              `json:"high_assurance,omitempty"`
}

// UnmarshalJSON keeps authority documents closed to schema drift. A misspelled
// or future field cannot silently disappear while the rest of a grant becomes
// live, and duplicate object keys cannot be interpreted differently by another
// JSON implementation.
func (g *OperationGrant) UnmarshalJSON(raw []byte) error {
	type grantWire OperationGrant
	var decoded grantWire
	if err := decodeStrictGrantJSON(raw, &decoded); err != nil {
		return err
	}
	*g = OperationGrant(decoded)
	return nil
}

type ArgumentGrant struct {
	Pointer   string   `json:"pointer"`
	Required  bool     `json:"required,omitempty"`
	Values    []string `json:"values,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	MaxBytes  int      `json:"max_bytes,omitempty"`
	URLTarget string   `json:"url_target,omitempty"`
}

func (g *ArgumentGrant) UnmarshalJSON(raw []byte) error {
	type argumentWire ArgumentGrant
	var decoded argumentWire
	if err := decodeStrictGrantJSON(raw, &decoded); err != nil {
		return err
	}
	*g = ArgumentGrant(decoded)
	return nil
}

// ResourceGrant binds a privacy-preserving namespace to a JSON argument. A
// shared writable namespace is never inferred: it requires SharedWritable and
// an explicit principal/campaign owner in the surrounding grant.
type ResourceGrant struct {
	Kind           string `json:"kind"`
	Namespace      string `json:"namespace"`
	Argument       string `json:"argument,omitempty"`
	Value          string `json:"value,omitempty"`
	SharedWritable bool   `json:"shared_writable,omitempty"`
}

func (g *ResourceGrant) UnmarshalJSON(raw []byte) error {
	type resourceWire ResourceGrant
	var decoded resourceWire
	if err := decodeStrictGrantJSON(raw, &decoded); err != nil {
		return err
	}
	*g = ResourceGrant(decoded)
	return nil
}

type URLTargetGrant struct {
	ID       string              `json:"id"`
	Origins  []string            `json:"origins"`
	Paths    []string            `json:"paths,omitempty"`
	Query    map[string][]string `json:"query,omitempty"`
	Redirect bool                `json:"redirect,omitempty"`
}

func (g *URLTargetGrant) UnmarshalJSON(raw []byte) error {
	type targetWire URLTargetGrant
	var decoded targetWire
	if err := decodeStrictGrantJSON(raw, &decoded); err != nil {
		return err
	}
	*g = URLTargetGrant(decoded)
	return nil
}

type RateGrant struct {
	Requests int64 `json:"requests"`
	WindowS  int64 `json:"window_seconds"`
}

func (g *RateGrant) UnmarshalJSON(raw []byte) error {
	type rateWire RateGrant
	var decoded rateWire
	if err := decodeStrictGrantJSON(raw, &decoded); err != nil {
		return err
	}
	*g = RateGrant(decoded)
	return nil
}

type evaluatedGrant struct {
	Grant            OperationGrant
	Digest           string
	ResourceIDs      []string
	SharedWritableID []string
}

func validateOperationGrant(grant OperationGrant, connection string) (OperationGrant, error) {
	if grant.Version != grantVersion {
		return OperationGrant{}, fmt.Errorf("grant.version: got %q, want %q", grant.Version, grantVersion)
	}
	grant.ID = strings.TrimSpace(grant.ID)
	grant.Connection = strings.TrimSpace(grant.Connection)
	grant.Tool = strings.TrimSpace(grant.Tool)
	grant.Principal = strings.TrimSpace(grant.Principal)
	grant.Campaign = strings.TrimSpace(grant.Campaign)
	if grant.ID == "" || grant.Connection == "" || grant.Tool == "" {
		return OperationGrant{}, fmt.Errorf("grant requires id, connection, and exact tool")
	}
	if grant.Connection != connection {
		return OperationGrant{}, fmt.Errorf("grant connection %q does not match %q", grant.Connection, connection)
	}
	if grant.Effect != effectRead && grant.Effect != effectWrite {
		return OperationGrant{}, fmt.Errorf("grant.effect must be read or write")
	}
	if grant.Principal == "" || grant.Campaign == "" {
		return OperationGrant{}, fmt.Errorf("grant requires principal and campaign ownership")
	}
	expiry, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil || expiry.IsZero() {
		return OperationGrant{}, fmt.Errorf("grant.expires_at must be RFC3339")
	}
	if grant.MaxRequests <= 0 || grant.MaxBytes <= 0 || grant.MaxResponseBytes <= 0 || grant.Rate.Requests <= 0 || grant.Rate.WindowS <= 0 {
		return OperationGrant{}, fmt.Errorf("grant requires finite positive request, byte, and rate budgets")
	}
	if grant.MaxRequests > maxGrantRequests || grant.Rate.Requests > maxGrantRequests || grant.MaxBytes > maxGrantBytes || grant.MaxResponseBytes >= grant.MaxBytes || grant.Rate.WindowS > maxGrantRateWindow {
		return OperationGrant{}, fmt.Errorf("grant budget exceeds its bounded range or cannot reserve one response")
	}
	if len(grant.Arguments) > maxGrantEntries || len(grant.Resources) > maxGrantEntries || len(grant.URLTargets) > maxGrantEntries || len(grant.Metadata) > maxGrantEntries {
		return OperationGrant{}, fmt.Errorf("grant exceeds the %d-entry configuration bound", maxGrantEntries)
	}
	seenArgs := map[string]bool{}
	for i, rule := range grant.Arguments {
		if err := validatePointer(rule.Pointer); err != nil {
			return OperationGrant{}, fmt.Errorf("grant.arguments[%d]: %w", i, err)
		}
		if seenArgs[rule.Pointer] {
			return OperationGrant{}, fmt.Errorf("grant.arguments[%d] duplicates pointer %q", i, rule.Pointer)
		}
		seenArgs[rule.Pointer] = true
		if len(rule.Values) == 0 && rule.Pattern == "" && rule.URLTarget == "" {
			return OperationGrant{}, fmt.Errorf("grant.arguments[%d] must constrain values, a pattern, or a URL target", i)
		}
		if rule.Pattern != "" {
			if rule.MaxBytes <= 0 {
				return OperationGrant{}, fmt.Errorf("grant.arguments[%d] pattern requires max_bytes", i)
			}
			if _, err := regexp.Compile("^(?:" + rule.Pattern + ")$"); err != nil {
				return OperationGrant{}, fmt.Errorf("grant.arguments[%d] pattern: %w", i, err)
			}
		}
	}
	targets := map[string]bool{}
	for i, target := range grant.URLTargets {
		if target.ID == "" || targets[target.ID] || len(target.Origins) == 0 {
			return OperationGrant{}, fmt.Errorf("grant.url_targets[%d] requires a unique id and origins", i)
		}
		targets[target.ID] = true
		for _, origin := range target.Origins {
			if _, err := parseGrantOrigin(origin); err != nil {
				return OperationGrant{}, fmt.Errorf("grant.url_targets[%d]: %w", i, err)
			}
		}
		for _, prefix := range target.Paths {
			lower := strings.ToLower(prefix)
			if !strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "//") ||
				strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") ||
				strings.Contains(lower, "%5c") || pathpkg.Clean(prefix) != prefix {
				return OperationGrant{}, fmt.Errorf("grant.url_targets[%d] has an invalid path prefix", i)
			}
		}
		for key := range target.Query {
			if strings.TrimSpace(key) == "" {
				return OperationGrant{}, fmt.Errorf("grant.url_targets[%d] has an empty query key", i)
			}
		}
	}
	for i, rule := range grant.Arguments {
		if rule.URLTarget != "" && !targets[rule.URLTarget] {
			return OperationGrant{}, fmt.Errorf("grant.arguments[%d] names unknown URL target %q", i, rule.URLTarget)
		}
	}
	seenResources := map[string]bool{}
	for i, resource := range grant.Resources {
		resource.Kind = strings.TrimSpace(resource.Kind)
		resource.Namespace = strings.TrimSpace(resource.Namespace)
		if resource.Kind == "" || resource.Namespace == "" || (resource.Argument == "" && resource.Value == "") || (resource.Argument != "" && resource.Value != "") {
			return OperationGrant{}, fmt.Errorf("grant.resources[%d] requires kind, namespace, and exactly one of argument or value", i)
		}
		if resource.Argument != "" {
			if err := validatePointer(resource.Argument); err != nil {
				return OperationGrant{}, fmt.Errorf("grant.resources[%d]: %w", i, err)
			}
		}
		key := resource.Kind + "\x00" + resource.Namespace
		if seenResources[key] {
			return OperationGrant{}, fmt.Errorf("grant.resources[%d] duplicates a resource namespace", i)
		}
		seenResources[key] = true
		grant.Resources[i] = resource
	}
	return grant, nil
}

func evaluateOperationGrant(grant OperationGrant, principal, campaign, tool string, args json.RawMessage, now time.Time) (evaluatedGrant, error) {
	if principal != grant.Principal || campaign == "" || campaign != grant.Campaign {
		return evaluatedGrant{}, fmt.Errorf("caller authority does not match grant ownership")
	}
	if tool != grant.Tool {
		return evaluatedGrant{}, fmt.Errorf("operation is not granted")
	}
	expiry, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
	if !now.Before(expiry) {
		return evaluatedGrant{}, fmt.Errorf("grant expired")
	}
	var document any
	if !json.Valid(args) {
		return evaluatedGrant{}, fmt.Errorf("arguments are not valid JSON")
	}
	if err := rejectDuplicateJSONKeys(args); err != nil {
		return evaluatedGrant{}, fmt.Errorf("arguments are ambiguous: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(args)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return evaluatedGrant{}, fmt.Errorf("arguments are not valid JSON")
	}
	if err := rejectUngovernedArguments(document, grant); err != nil {
		return evaluatedGrant{}, err
	}
	for _, rule := range grant.Arguments {
		value, ok := pointerValue(document, rule.Pointer)
		if !ok {
			if rule.Required {
				return evaluatedGrant{}, fmt.Errorf("required argument is absent")
			}
			continue
		}
		if err := validateArgumentValue(value, rule, grant.URLTargets); err != nil {
			return evaluatedGrant{}, err
		}
	}
	var resources, shared []string
	for _, resource := range grant.Resources {
		value := resource.Value
		if resource.Argument != "" {
			raw, ok := pointerValue(document, resource.Argument)
			if !ok {
				return evaluatedGrant{}, fmt.Errorf("resource argument is absent")
			}
			var okString bool
			value, okString = scalarString(raw)
			if !okString || value == "" {
				return evaluatedGrant{}, fmt.Errorf("resource argument must be a non-empty scalar")
			}
		}
		privacyOwner := grant.Principal
		if resource.SharedWritable {
			privacyOwner = "shared-writable"
		}
		id := opaqueResourceID(privacyOwner, grant.Campaign, resource.Kind, resource.Namespace, value)
		resources = append(resources, id)
		if grant.Effect == effectWrite && resource.SharedWritable {
			shared = append(shared, id)
		}
	}
	digest, err := grantDigest(grant)
	if err != nil {
		return evaluatedGrant{}, err
	}
	sort.Strings(resources)
	sort.Strings(shared)
	return evaluatedGrant{Grant: grant, Digest: digest, ResourceIDs: resources, SharedWritableID: shared}, nil
}

func validatePointer(pointer string) error {
	if pointer == "" || !strings.HasPrefix(pointer, "/") || strings.Contains(pointer, "//") {
		return fmt.Errorf("argument pointer %q must be a non-empty JSON pointer", pointer)
	}
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		for i := 0; i < len(token); i++ {
			if token[i] == '~' && (i+1 >= len(token) || (token[i+1] != '0' && token[i+1] != '1')) {
				return fmt.Errorf("argument pointer %q has invalid escaping", pointer)
			}
		}
	}
	return nil
}

func rejectUngovernedArguments(document any, grant OperationGrant) error {
	allowed := map[string]bool{}
	for _, rule := range grant.Arguments {
		allowed[rule.Pointer] = true
	}
	for _, resource := range grant.Resources {
		if resource.Argument != "" {
			allowed[resource.Argument] = true
		}
	}
	var visit func(any, string) error
	visit = func(value any, pointer string) error {
		if allowed[pointer] {
			return nil
		}
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				escaped := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
				if err := visit(child, pointer+"/"+escaped); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range value {
				if err := visit(child, pointer+"/"+strconv.Itoa(i)); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("argument is not governed by the operation grant")
		}
		return nil
	}
	return visit(document, "")
}

func pointerValue(document any, pointer string) (any, bool) {
	current := document
	for _, raw := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			next, exists := value[token]
			if !exists {
				return nil, false
			}
			current = next
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(value) {
				return nil, false
			}
			current = value[i]
		default:
			return nil, false
		}
	}
	return current, true
}

func validateArgumentValue(value any, rule ArgumentGrant, targets []URLTargetGrant) error {
	values := flattenScalars(value)
	if len(values) == 0 {
		return fmt.Errorf("argument has an unsupported value type")
	}
	allowed := map[string]bool{}
	for _, value := range rule.Values {
		allowed[value] = true
	}
	var pattern *regexp.Regexp
	if rule.Pattern != "" {
		pattern = regexp.MustCompile("^(?:" + rule.Pattern + ")$")
	}
	for _, value := range values {
		if rule.MaxBytes > 0 && len(value) > rule.MaxBytes {
			return fmt.Errorf("argument exceeds its byte bound")
		}
		if len(allowed) > 0 && !allowed[value] {
			return fmt.Errorf("argument value is outside its exact allowlist")
		}
		if pattern != nil && !pattern.MatchString(value) {
			return fmt.Errorf("argument value does not match its constraint")
		}
		if rule.URLTarget == "" && looksLikeURL(value) {
			return fmt.Errorf("URL-shaped argument is not granted")
		}
		if rule.URLTarget != "" {
			target, ok := findURLTarget(targets, rule.URLTarget)
			if !ok || validateGrantedURL(value, target) != nil {
				return fmt.Errorf("URL argument is outside its granted destination")
			}
		}
	}
	return nil
}

func flattenScalars(value any) []string {
	switch value := value.(type) {
	case []any:
		var out []string
		for _, item := range value {
			text, ok := scalarString(item)
			if !ok {
				return nil
			}
			out = append(out, text)
		}
		return out
	default:
		text, ok := scalarString(value)
		if !ok {
			return nil
		}
		return []string{text}
	}
}

func scalarString(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	case float64:
		return strconv.FormatFloat(value, 'g', -1, 64), true
	case bool:
		return strconv.FormatBool(value), true
	default:
		return "", false
	}
}

func findURLTarget(targets []URLTargetGrant, id string) (URLTargetGrant, bool) {
	for _, target := range targets {
		if target.ID == id {
			return target, true
		}
	}
	return URLTargetGrant{}, false
}

func validateGrantedURL(raw string, target URLTargetGrant) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("URL must be an absolute HTTPS URL without credentials or fragment")
	}
	if net.ParseIP(u.Hostname()) != nil {
		return fmt.Errorf("URL literal IPs are not granted")
	}
	escaped := strings.ToLower(u.EscapedPath())
	if u.RawPath != "" || strings.Contains(escaped, "%2e") || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || pathpkg.Clean(u.Path) != u.Path || strings.Contains(u.Path, "//") {
		return fmt.Errorf("URL path uses an alternate or non-normal form")
	}
	origin, err := parseGrantOrigin(u.Scheme + "://" + u.Host)
	if err != nil {
		return err
	}
	allowed := false
	for _, rawOrigin := range target.Origins {
		want, _ := parseGrantOrigin(rawOrigin)
		if origin == want {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("URL origin is not granted")
	}
	if len(target.Paths) > 0 {
		allowed = false
		for _, prefix := range target.Paths {
			if u.EscapedPath() == prefix || strings.HasPrefix(u.EscapedPath(), strings.TrimSuffix(prefix, "/")+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("URL path is not granted")
		}
	}
	wantQuery := url.Values(target.Query).Encode()
	// Compare the raw query with the one canonical encoding of the exact
	// operator-owned allowlist. This defaults query parameters to denied and
	// rejects aliases such as repeated/reordered keys or alternate escapes.
	if u.RawQuery != wantQuery {
		return fmt.Errorf("URL query is not exactly granted")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func decodeStrictGrantJSON(raw []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func parseGrantOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("URL origin %q must be an HTTPS origin", raw)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return "", fmt.Errorf("URL origin %q cannot be a literal IP", raw)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if err := validateGrantHostname(host); err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func validateGrantHostname(host string) error {
	if host == "" || !strings.Contains(host, ".") || len(host) > 253 {
		return fmt.Errorf("URL target host must be an explicit external DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("URL target host has an invalid DNS label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("URL target host has an invalid DNS label")
			}
		}
	}
	return nil
}

func looksLikeURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func grantDigest(grant OperationGrant) (string, error) {
	b, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func opaqueResourceID(principal, campaign, kind, namespace, value string) string {
	sum := sha256.Sum256([]byte(principal + "\x00" + campaign + "\x00" + kind + "\x00" + namespace + "\x00" + value))
	return "res_" + hex.EncodeToString(sum[:16])
}
