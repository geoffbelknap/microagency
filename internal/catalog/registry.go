package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DefaultRegistryURL is the official Model Context Protocol registry.
const DefaultRegistryURL = "https://registry.modelcontextprotocol.io"

// registryPageSize is how many servers to request per page; registryMaxPages bounds
// the total work of one LoadRegistry call so an operator query can't walk the entire
// registry unboundedly (ASK tenet 8 — operations are bounded).
const (
	registryPageSize = 100
	registryMaxPages  = 20
)

// registryResponse is the official MCP registry's GET /v0/servers shape:
// each entry wraps the server descriptor plus registry _meta (status, isLatest).
type registryResponse struct {
	Servers  []registryEntry `json:"servers"`
	Metadata struct {
		NextCursor string `json:"nextCursor"`
	} `json:"metadata"`
}

type registryEntry struct {
	Server struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Title       string `json:"title"`
		Remotes     []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"remotes"`
	} `json:"server"`
	Meta struct {
		// The official registry stamps status/isLatest under this key. Other
		// registries may omit it; we then fall back to including the entry.
		Official struct {
			Status   string `json:"status"`
			IsLatest bool   `json:"isLatest"`
		} `json:"io.modelcontextprotocol.registry/official"`
	} `json:"_meta"`
}

// LoadRegistry queries an MCP registry that speaks the official registry API
// (GET /v0/servers) and maps its servers into catalog entries. Only servers that
// expose an http(s) REMOTE are included — a remote URL is what microagency can
// govern as an upstream; package-only (stdio) servers are skipped. For the official
// registry, only the latest, active version of each server is kept (its _meta
// dedupes the version history). Tools are left empty: the registry does not publish
// them, so a discovered server's real tools are fetched when the operator enables
// it. query, when non-empty, filters case-insensitively over name/title/description.
// Results are bounded by limit and by registryMaxPages.
func LoadRegistry(ctx context.Context, hc *http.Client, baseURL, query string, limit int) ([]Server, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = DefaultRegistryURL
	}
	if limit <= 0 {
		limit = 50
	}
	q := strings.ToLower(strings.TrimSpace(query))

	var out []Server
	seen := map[string]bool{} // dedupe by sanitized upstream name
	cursor := ""
	for page := 0; page < registryMaxPages && len(out) < limit; page++ {
		resp, err := fetchRegistryPage(ctx, hc, base, cursor)
		if err != nil {
			return nil, err
		}
		for _, e := range resp.Servers {
			sv, ok := mapRegistryEntry(e)
			if !ok {
				continue
			}
			if q != "" && !matchesQuery(e, q) {
				continue
			}
			if seen[sv.Name] {
				continue
			}
			seen[sv.Name] = true
			out = append(out, sv)
			if len(out) >= limit {
				break
			}
		}
		if resp.Metadata.NextCursor == "" {
			break
		}
		cursor = resp.Metadata.NextCursor
	}
	return out, nil
}

func fetchRegistryPage(ctx context.Context, hc *http.Client, base, cursor string) (*registryResponse, error) {
	u := fmt.Sprintf("%s/v0/servers?limit=%d", base, registryPageSize)
	if cursor != "" {
		u += "&cursor=" + url.QueryEscape(cursor)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes))
	if err != nil {
		return nil, err
	}
	var rr registryResponse
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("registry: parse: %w", err)
	}
	return &rr, nil
}

// mapRegistryEntry converts a registry entry to a catalog Server, or ok=false to
// skip it (no usable remote, or a superseded/inactive official entry).
func mapRegistryEntry(e registryEntry) (Server, bool) {
	// For the official registry, keep only the latest active version. When the
	// official _meta is absent (a different registry), Status is "" — include it.
	if e.Meta.Official.Status != "" && (e.Meta.Official.Status != "active" || !e.Meta.Official.IsLatest) {
		return Server{}, false
	}
	remote := firstRemoteURL(e)
	name := sanitizeName(e.Server.Name)
	if remote == "" || name == "" {
		return Server{}, false
	}
	desc := strings.TrimSpace(e.Server.Description)
	if desc == "" {
		desc = strings.TrimSpace(e.Server.Title)
	}
	return Server{Name: name, URL: remote, Description: desc}, true
}

// firstRemoteURL returns the first http(s) remote URL of a registry server,
// preferring a streamable-http transport. Package-only servers yield "".
func firstRemoteURL(e registryEntry) string {
	var fallback string
	for _, r := range e.Server.Remotes {
		u := strings.TrimSpace(r.URL)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		if r.Type == "streamable-http" {
			return u
		}
		if fallback == "" {
			fallback = u
		}
	}
	return fallback
}

func matchesQuery(e registryEntry, q string) bool {
	return strings.Contains(strings.ToLower(e.Server.Name), q) ||
		strings.Contains(strings.ToLower(e.Server.Title), q) ||
		strings.Contains(strings.ToLower(e.Server.Description), q)
}

// unsafeNameChars matches anything not allowed in a clean upstream name.
var unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeName turns a registry name (e.g. "io.github.owner/server") into a valid
// upstream name: the gateway forbids the "__" namespace separator and uses the name
// as a tool prefix, so reduce it to [A-Za-z0-9._-] and collapse any "__".
func sanitizeName(raw string) string {
	n := unsafeNameChars.ReplaceAllString(strings.TrimSpace(raw), "-")
	for strings.Contains(n, "__") {
		n = strings.ReplaceAll(n, "__", "-")
	}
	return strings.Trim(n, "-._")
}
