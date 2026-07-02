package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"microagency/internal/mcp"
)

// The bypass check is enforcement hygiene, not enforcement. microagency governs
// every request that flows THROUGH it, but it cannot stop a client that also holds a
// direct connection to the same upstream MCP server — a parallel connection with its
// own token is a back door around the governed well. All microagency can do from its
// own side is INSPECT the local client's config files and warn when an upstream it
// proxies is ALSO wired up as a direct MCP server there. It raises hygiene; it does
// not enforce.
//
// LIMIT (be honest): this only sees LOCAL client config on this machine
// (~/.claude.json and a project-level .mcp.json). A genuinely separate or remote
// client holding its own token to the same upstream is invisible here — there is no
// microagency-side signal for that. So a clean bypass check means "no back door in
// the local config we can read", never "no back door exists".

// clientMCPServer is a directly-configured MCP server found in a local client config
// file — a network path the client can reach WITHOUT going through microagency.
type clientMCPServer struct {
	Name       string // the client's own name for the server
	URL        string
	ConfigPath string // which config file declared it
}

// bypassWarning is one detected back door: an upstream microagency proxies that the
// local client can ALSO reach directly, bypassing governance.
type bypassWarning struct {
	UpstreamName string // microagency's name for the upstream
	URL          string // the upstream URL (as microagency registered it)
	ClientName   string // the client's name for the same direct server
	ConfigPath   string // the client config file that declares the direct entry
}

// clientConfigPaths returns the local Claude Code config files to inspect for direct
// MCP servers: the user-level ~/.claude.json (per-project mcpServers live under
// projects.<dir>) and a project-level .mcp.json in the current directory. Missing
// files are fine — gatherClientServers skips whatever isn't there.
func clientConfigPaths() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".claude.json"))
	}
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, ".mcp.json"))
	}
	return paths
}

// gatherClientServers reads each config path and returns every directly-configured
// MCP server (with a URL) it can find. Unreadable or malformed files are skipped —
// doctor is advisory and must never fail because a client config is absent or odd.
func gatherClientServers(paths []string) []clientMCPServer {
	var out []clientMCPServer
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out = append(out, parseClientMCPServers(b, p)...)
	}
	return out
}

// parseClientMCPServers extracts every directly-configured MCP server that has a URL
// from one Claude Code config file's bytes. It handles both shapes defensively:
//
//   - a top-level "mcpServers" map (a project-level .mcp.json, or a global block), and
//   - the per-project "projects.<dir>.mcpServers" maps inside ~/.claude.json.
//
// Only entries with a "url" are back doors we care about; stdio servers (command/args,
// no url) aren't a network path around microagency, so they're ignored. Any shape it
// doesn't recognize is skipped, never fatal.
func parseClientMCPServers(data []byte, configPath string) []clientMCPServer {
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		return nil
	}
	var out []clientMCPServer
	out = append(out, extractURLServers(root["mcpServers"], configPath)...)
	if projects, ok := root["projects"].(map[string]any); ok {
		for _, p := range projects {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, extractURLServers(pm["mcpServers"], configPath)...)
		}
	}
	return out
}

// extractURLServers pulls the {name -> entry} MCP-server map out of a JSON value and
// returns the entries that carry a non-empty "url". Anything that isn't a map of
// objects, or an entry without a url, is skipped.
func extractURLServers(v any, configPath string) []clientMCPServer {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []clientMCPServer
	for name, entry := range m {
		em, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		u, ok := em["url"].(string)
		if !ok || strings.TrimSpace(u) == "" {
			continue
		}
		out = append(out, clientMCPServer{Name: name, URL: u, ConfigPath: configPath})
	}
	return out
}

// normalizeMCPURL canonicalizes an MCP server URL for comparison: lower-cased scheme
// and host, and a trailing slash trimmed from the path. This makes "https://Host/mcp"
// and "https://host/mcp/" compare equal without over-normalizing (query strings are
// preserved — some MCP endpoints key on them). On a parse failure it falls back to a
// trimmed, slash-stripped string so unusual values still compare consistently.
func normalizeMCPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Fragment = ""
	return u.String()
}

// detectBypasses returns a warning for every upstream microagency proxies whose URL
// also appears as a direct client MCP server — the back-door overlap. Matching is on
// the normalized URL, so trivial formatting differences don't hide (or fabricate) an
// overlap. microagency's own /mcp entry never matches, since it isn't one of the
// proxied upstream URLs.
func detectBypasses(upstreams []mcp.UpstreamRegistration, clientServers []clientMCPServer) []bypassWarning {
	byURL := map[string][]clientMCPServer{}
	for _, c := range clientServers {
		key := normalizeMCPURL(c.URL)
		byURL[key] = append(byURL[key], c)
	}
	var out []bypassWarning
	for _, u := range upstreams {
		for _, c := range byURL[normalizeMCPURL(u.URL)] {
			out = append(out, bypassWarning{
				UpstreamName: u.Name,
				URL:          u.URL,
				ClientName:   c.Name,
				ConfigPath:   c.ConfigPath,
			})
		}
	}
	return out
}
