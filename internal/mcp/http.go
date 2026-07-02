package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"microagency/internal/auth"
)

// maxHTTPBody caps a single request body. The tool surface takes small JSON-RPC
// messages; anything larger is rejected rather than buffered.
const maxHTTPBody = 1 << 20 // 1 MiB

// Authenticator authenticates a request to the MCP surface, returning the caller
// principal or an error (→ 401). Two implementations: a static bearer for
// loopback/dev, and an OAuth resource server for public deployments. They're
// distinct from the operator (admin) credential — the agent and operator
// surfaces never share an audience.
type Authenticator interface {
	Authenticate(r *http.Request) (*auth.Principal, error)
}

// staticAuth accepts a single shared bearer token (loopback / dev). An empty
// token means no check — safe only on loopback.
type staticAuth struct{ token string }

func (s staticAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	if s.token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			return nil, auth.ErrUnauthenticated
		}
	}
	return &auth.Principal{Subject: "local"}, nil
}

// oauthAuth validates an OAuth/OIDC access token via the resource server and,
// when a scope is required, refuses tokens that weren't granted it.
type oauthAuth struct {
	rs    *auth.ResourceServer
	scope string // "" = no scope requirement
}

func (o oauthAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	p, err := o.rs.Validate(r.Context(), tok)
	if err != nil {
		return nil, err
	}
	if o.scope != "" && !p.HasScope(o.scope) {
		// Same collapsed error as any other auth failure — no oracle for probing
		// which scopes exist. A narrower token is simply not authenticated here.
		return nil, auth.ErrUnauthenticated
	}
	return p, nil
}

// OAuthAuthenticator validates OAuth/OIDC access tokens via the resource server.
// A non-empty requiredScope must be present in the token's granted scopes;
// pass "" to accept any valid token (e.g. an external issuer that doesn't model
// scopes).
func OAuthAuthenticator(rs *auth.ResourceServer, requiredScope string) Authenticator {
	return oauthAuth{rs: rs, scope: requiredScope}
}

type ctxKey int

const principalKey ctxKey = 0

// PrincipalFrom returns the authenticated caller from the request context.
func PrincipalFrom(ctx context.Context) (*auth.Principal, bool) {
	p, ok := ctx.Value(principalKey).(*auth.Principal)
	return p, ok
}

// httpHandler serves the MCP tool surface over HTTP (the Streamable-HTTP subset:
// POST one JSON-RPC message, get the JSON-RPC response). It authenticates via the
// configured Authenticator; we push no server-initiated messages, so there is no
// GET/SSE stream.
type httpHandler struct {
	srv  *Server
	auth Authenticator
}

// HTTPHandler serves the MCP tool surface behind a static bearer token (loopback
// / dev). An empty token means no auth — safe only on loopback.
func (s *Server) HTTPHandler(token string) http.Handler {
	return &httpHandler{srv: s, auth: staticAuth{token: token}}
}

// HTTPHandlerAuth serves the MCP tool surface behind the given authenticator
// (e.g. OAuthAuthenticator for public deployments).
func (s *Server) HTTPHandlerAuth(a Authenticator) http.Handler {
	return &httpHandler{srv: s, auth: a}
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	princ, err := h.auth.Authenticate(r)
	if err != nil {
		// Point unauthenticated clients at the protected-resource metadata
		// (RFC 9728) so they can discover the authorization server.
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="/.well-known/oauth-protected-resource"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	ctx := context.WithValue(r.Context(), principalKey, princ)
	resp, write := h.srv.Handle(ctx, body)
	if !write { // a notification — accepted, no response body
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
