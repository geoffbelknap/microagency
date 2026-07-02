// Package catalog loads a catalog of MCP servers — borrowed metadata from a
// registry (Smithery / mcp.so / the official MCP registry) or a curated file —
// into microagency's tool index as DISCOVERED entries. The agent can find these
// tools via find_tools, but they are not invocable until the operator enables the
// server: the catalog feeds discovery, never invocation (the gate stays on
// EnableUpstream). This is what lets the index be a gravity well — broader than
// what's been manually wired — without loosening trust.
package catalog

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"microagency/internal/gateway"
)

// Server is one MCP server in a catalog: its connection info and the tool
// metadata to index. Token is optional (a public catalog usually omits it; the
// operator supplies one when enabling if needed).
type Server struct {
	Name        string         `json:"name"`
	URL         string         `json:"url"`
	Token       string         `json:"token,omitempty"`
	Description string         `json:"description,omitempty"`
	Tools       []gateway.Tool `json:"tools"`
}

type doc struct {
	Servers []Server `json:"servers"`
}

const maxCatalogBytes = 16 << 20 // 16 MiB

// Load reads a catalog from a local path or an http(s) URL.
func Load(src string) ([]Server, error) {
	var data []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		data, err = fetch(src)
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", src, err)
	}
	var d doc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("catalog: parse %s: %w", src, err)
	}
	for i, sv := range d.Servers {
		if sv.Name == "" || sv.URL == "" {
			return nil, fmt.Errorf("catalog: server %d needs a name and url", i)
		}
	}
	return d.Servers, nil
}

func fetch(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes))
}
