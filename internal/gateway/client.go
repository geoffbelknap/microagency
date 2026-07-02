// Package gateway makes microagency a governing MCP aggregator: it connects to
// upstream MCP servers as a client so their tools can be re-exposed through
// microagency's own surface — curated and governed — instead of loaded directly
// into the agent. Users point their MCPs at microagency, not at their LLM.
//
// This file is the upstream client (the MCP client side, over the Streamable-
// HTTP subset: POST one JSON-RPC message, read the response). Aggregation of
// upstream tools into microagency's own server is layered on top of it.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// maxUpstreamBytes caps an upstream tool result we buffer before parsing. Generous
// (the feature parks multi-MB results off-context), but bounded against a runaway
// body. A response over the cap fails with a clear error, never a silent truncation.
const maxUpstreamBytes = 64 << 20 // 64 MiB

// Tool is one tool advertised by an upstream MCP server.
type Tool struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema json.RawMessage  `json:"inputSchema,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ToolAnnotations carries the optional MCP tool hints. Only the fields microagency
// acts on are captured; ReadOnlyHint is the authoritative read/write signal for the
// pre-egress write guard (a name heuristic is the fallback when it's absent). Pointer
// fields distinguish "hint absent" from "hint present and false".
type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
}

// Upstream is a client handle to one upstream MCP server over HTTP.
type Upstream struct {
	Name  string // local name for this upstream (used to namespace its tools)
	URL   string // the upstream's MCP endpoint
	Token string // optional static bearer token (fallback for non-OAuth upstreams)
	// Bearer, if set, supplies a fresh bearer per call — an OAuth access token that
	// refreshes itself. It takes precedence over Token. The agent never sees it.
	Bearer func(context.Context) (string, error)
	Client *http.Client // optional; defaults to http.DefaultClient

	mu        sync.Mutex
	sessionID string // Mcp-Session-Id from initialize; echoed on later requests
}

func (u *Upstream) session() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sessionID
}

func (u *Upstream) setSession(id string) {
	if id == "" {
		return
	}
	u.mu.Lock()
	u.sessionID = id
	u.mu.Unlock()
}

func (u *Upstream) bearer(ctx context.Context) (string, error) {
	if u.Bearer != nil {
		return u.Bearer(ctx)
	}
	return u.Token, nil
}

func (u *Upstream) httpClient() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return http.DefaultClient
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcReply struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data,omitempty"` // servers put diagnostics here (e.g. the missing permission)
	} `json:"error"`
}

// call sends one JSON-RPC request and returns the result, surfacing transport,
// HTTP, and JSON-RPC errors. External servers are data sources, not trusted
// callers, so every failure mode is explicit (fail-closed for the caller).
func (u *Upstream) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Streamable-HTTP servers (e.g. Supabase) require the client to accept BOTH —
	// and may answer with an SSE stream, which we parse below.
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid := u.session(); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid) // MCP Streamable-HTTP session (set by initialize)
	}
	if tok, err := u.bearer(ctx); err != nil {
		return nil, fmt.Errorf("gateway %q: %s: auth: %w", u.Name, method, err)
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway %q: %s: %w", u.Name, method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	u.setSession(resp.Header.Get("Mcp-Session-Id")) // capture/refresh the session id
	// Buffer the WHOLE body before decoding. Large upstream results (the ones most
	// likely to need off-context parking) must reassemble on byte boundaries — a
	// streaming line reader truncates at its buffer limit or cuts mid-escape at a
	// chunk boundary (\ + next chunk → invalid JSON escape). SSE is parsed from the
	// complete buffer below, after the body is whole.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gateway %q: %s: read: %w", u.Name, method, err)
	}
	if int64(len(data)) > maxUpstreamBytes {
		return nil, fmt.Errorf("gateway %q: %s: upstream response exceeds the %dMB cap", u.Name, method, maxUpstreamBytes>>20)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway %q: %s: http %d: %s", u.Name, method, resp.StatusCode, bytes.TrimSpace(data))
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		data = sseData(data)
	}
	var reply rpcReply
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, fmt.Errorf("gateway %q: %s: decode: %w", u.Name, method, err)
	}
	if reply.Error != nil {
		msg := reply.Error.Message
		if d := bytes.TrimSpace(reply.Error.Data); len(d) > 0 {
			msg += ": " + string(bytes.Trim(d, `"`)) // include the server's diagnostic (e.g. which permission is missing)
		}
		return nil, fmt.Errorf("gateway %q: %s: rpc error %d: %s", u.Name, method, reply.Error.Code, msg)
	}
	return reply.Result, nil
}

// sseData extracts the first SSE "message" event's data payload from a fully
// buffered text/event-stream body. Operating on the complete buffer (vs streaming
// line-by-line) avoids chunk-boundary corruption and any per-line size limit on
// multi-MB events. Multiple data: lines join with \n per the SSE spec.
func sseData(buf []byte) []byte {
	var data [][]byte
	for _, raw := range bytes.Split(buf, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		if len(line) == 0 { // event boundary
			if len(data) > 0 {
				return bytes.Join(data, []byte("\n"))
			}
			continue
		}
		if v, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(v, []byte(" ")))
		}
	}
	if len(data) > 0 {
		return bytes.Join(data, []byte("\n"))
	}
	return buf // not SSE-framed; use as-is
}

// Initialize performs the MCP initialize handshake, captures the session id, and
// sends the initialized notification to complete it.
func (u *Upstream) Initialize(ctx context.Context) error {
	if _, err := u.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "microagency-gateway", "version": "0.1.0"},
	}); err != nil {
		return err
	}
	u.notify(ctx, "notifications/initialized") // best-effort; some servers require it
	return nil
}

// notify posts a JSON-RPC notification (no id; no result expected).
func (u *Upstream) notify(ctx context.Context, method string) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid := u.session(); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if tok, _ := u.bearer(ctx); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if resp, err := u.httpClient().Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// ListTools returns the upstream's advertised tools.
func (u *Upstream) ListTools(ctx context.Context) ([]Tool, error) {
	res, err := u.call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return nil, fmt.Errorf("gateway %q: tools/list decode: %w", u.Name, err)
	}
	return out.Tools, nil
}

// CallTool invokes an upstream tool by its (un-namespaced) name and returns the
// raw tools/call result.
func (u *Upstream) CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	return u.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

// Probe sends an unauthenticated initialize to detect whether the upstream
// supports OAuth. It returns the resource-metadata URL (from a 401's
// WWW-Authenticate, resolved to absolute, or the RFC 9728 default) when OAuth is
// available, or "" when the upstream is usable without it.
//
// Two discovery paths: a 401 challenge names the metadata directly, but some
// servers never challenge on initialize/tools/list — they serve those publicly
// and gate auth per tool call (e.g. LimaCharlie) — yet still advertise OAuth via
// RFC 9728 protected-resource metadata. So when there's no 401, we fall back to
// fetching that metadata directly; if it declares an authorization server, OAuth
// is available.
func (u *Upstream) Probe(ctx context.Context) (string, error) {
	body, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "microagency-gateway", "version": "0.1.0"},
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return resolveResourceMetadata(u.URL, resp.Header.Get("WWW-Authenticate")), nil
	}
	// No 401 challenge — check whether the resource advertises OAuth anyway.
	rm := resolveResourceMetadata(u.URL, "") // <origin>/.well-known/oauth-protected-resource
	if u.advertisesOAuth(ctx, rm) {
		return rm, nil
	}
	return "", nil
}

// advertisesOAuth reports whether metadataURL serves RFC 9728 protected-resource
// metadata that names at least one authorization server — i.e. the resource
// declares itself OAuth-protected even without issuing a 401 challenge.
func (u *Upstream) advertisesOAuth(ctx context.Context, metadataURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var pr struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return false
	}
	return len(pr.AuthorizationServers) > 0
}

// resolveResourceMetadata extracts resource_metadata="…" from a WWW-Authenticate
// header (resolving a relative value against the upstream's origin), or derives the
// RFC 9728 default <origin>/.well-known/oauth-protected-resource.
func resolveResourceMetadata(upstreamURL, wwwAuth string) string {
	rm := ""
	if i := strings.Index(wwwAuth, "resource_metadata="); i >= 0 {
		v := strings.TrimSpace(wwwAuth[i+len("resource_metadata="):])
		v = strings.TrimPrefix(v, `"`)
		if j := strings.IndexAny(v, `",`); j >= 0 {
			v = v[:j]
		}
		rm = strings.TrimSpace(v)
	}
	base, err := url.Parse(upstreamURL)
	if err != nil {
		return rm
	}
	if rm == "" {
		return base.Scheme + "://" + base.Host + "/.well-known/oauth-protected-resource"
	}
	if ref, err := url.Parse(rm); err == nil {
		return base.ResolveReference(ref).String()
	}
	return rm
}
