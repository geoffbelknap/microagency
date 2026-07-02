package mcp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Scope-at-onboarding — curated provider params.
//
// Some MCP providers grant an org-wide OAuth authorization (e.g. Supabase across
// every project) but let a client NARROW that grant at the provider itself by
// appending query params to the MCP URL — pin a single project, force read-only,
// restrict feature groups. This is distinct from microagency's read-only *gate*
// (which refuses write tools at our boundary after the fact): these params scope
// the upstream connection at the source, so the org-wide token is only ever
// exercised within the operator's chosen bounds.
//
// This file is the small, curated known-MCP catalog: it maps a provider (matched
// by MCP URL host) to its scoping knobs, and builds a scoped URL from
// operator-approved values without clobbering any existing query. It's the tested
// core; the console is just the surface that collects the values.

// ParamKind is the type of a provider scoping knob. It drives both the console
// widget (text field vs checkbox) and how a value is validated and serialized.
type ParamKind string

const (
	// ParamString is a free-text knob (e.g. Supabase project_ref).
	ParamString ParamKind = "string"
	// ParamBool is an on/off knob (e.g. Supabase read_only).
	ParamBool ParamKind = "bool"
)

// ProviderParam is one scoping knob a provider exposes. Name is the literal query
// key appended to the MCP URL; Description is operator-facing help text.
type ProviderParam struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Kind        ParamKind `json:"kind"`
}

// Provider is a known MCP server and the scoping knobs it accepts at connect time.
type Provider struct {
	// Name is operator-facing (shown in the console).
	Name string `json:"name"`
	// Host is the MCP URL host this provider is matched by (case-insensitive,
	// port ignored). Exact match — a provider on a different host is not matched.
	Host string `json:"host"`
	// Params are the scoping knobs, in the order the console should render them.
	Params []ProviderParam `json:"params"`
}

// providerCatalog is the curated known-MCP catalog. It is deliberately small and
// trivially extensible — add a Provider entry as we meet each new known MCP.
var providerCatalog = []Provider{
	{
		Name: "Supabase",
		Host: "mcp.supabase.com",
		Params: []ProviderParam{
			{
				Name:        "project_ref",
				Description: "Pin this connection to a single Supabase project (its project ref). Narrows an org-wide grant to one project.",
				Kind:        ParamString,
			},
			{
				Name:        "read_only",
				Description: "Ask Supabase to serve this connection read-only — enforced at the provider, in addition to any gateway read-only gate.",
				Kind:        ParamBool,
			},
			{
				Name:        "features",
				Description: "Restrict to a comma-separated set of Supabase feature groups (e.g. database,docs). Blank = provider default.",
				Kind:        ParamString,
			},
		},
	},
}

// providerForURL returns the catalog entry whose host matches rawURL, if any.
// Matching is by host only (case-insensitive, port stripped); scheme, path, and
// query are ignored. Returns ok=false for an unparseable or unknown URL.
func providerForURL(rawURL string) (Provider, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return Provider{}, false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return Provider{}, false
	}
	for _, p := range providerCatalog {
		if strings.EqualFold(p.Host, host) {
			return p, true
		}
	}
	return Provider{}, false
}

// ScopedURL appends operator-approved scoping params to rawURL for the provider
// that matches its host, returning the scoped URL. It is the tested core of
// scope-at-onboarding.
//
// Rules (all defensive):
//   - No values, or a URL that matches no known provider: rawURL is returned
//     untouched.
//   - Only params the matched provider DECLARES are applied; any unrecognized key
//     in values is ignored (the operator can't smuggle arbitrary query params in).
//   - Existing query params are preserved. An approved value for a key that
//     already exists in the URL replaces it (no duplicate keys).
//   - String params: the value is trimmed; a blank value is skipped (operator
//     left the field empty).
//   - Bool params: the value is parsed leniently (strconv.ParseBool) and
//     serialized as "true"/"false". An unparseable bool is an error.
func ScopedURL(rawURL string, values map[string]string) (string, error) {
	if len(values) == 0 {
		return rawURL, nil
	}
	prov, ok := providerForURL(rawURL)
	if !ok {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for _, p := range prov.Params {
		raw, present := values[p.Name]
		if !present {
			continue
		}
		val, keep, err := normalizeParam(p, raw)
		if err != nil {
			return "", err
		}
		if !keep {
			continue
		}
		q.Set(p.Name, val)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// normalizeParam validates and serializes one param value. keep=false means the
// operator left it blank and it should be omitted rather than appended.
func normalizeParam(p ProviderParam, raw string) (val string, keep bool, err error) {
	switch p.Kind {
	case ParamBool:
		s := strings.TrimSpace(raw)
		if s == "" {
			return "", false, nil
		}
		b, perr := strconv.ParseBool(s)
		if perr != nil {
			return "", false, fmt.Errorf("param %q: %q is not a boolean", p.Name, raw)
		}
		return strconv.FormatBool(b), true, nil
	case ParamString:
		s := strings.TrimSpace(raw)
		if s == "" {
			return "", false, nil
		}
		return s, true, nil
	default:
		// Unknown kind: treat as opaque string, skip when blank.
		s := strings.TrimSpace(raw)
		if s == "" {
			return "", false, nil
		}
		return s, true, nil
	}
}
