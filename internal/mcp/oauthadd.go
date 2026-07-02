package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"microagency/internal/auth"
	"microagency/internal/authui"
	"microagency/internal/gateway"
)

// This is the CONSOLE side of OAuth-to-upstream: adding an OAuth-capable MCP from
// the admin console as a web flow. POST /admin/upstreams with a url and no token
// starts it (DCR + a pending flow keyed by state, returning an authorize URL the
// operator's browser visits); GET /admin/oauth/callback completes the exchange and
// registers the upstream with a cred-blind, auto-refreshing token. The interactive
// CLI variant (auth.AcquireInteractive) is not used here — a non-interactive admin
// handler can't open a browser; the operator's browser drives the redirect instead.

type oauthFlow struct {
	name, url string
	discover  bool
	reauth    bool // re-authorizing an already-registered upstream (rebind, don't re-add)
	readOnly  bool // apply the read-only restriction once the upstream is registered
	// owner scopes the connection to one principal's subject at registration
	// ("" = shared). Reauth flows leave it empty — rebind preserves the record.
	owner        string
	meta         *auth.ASMetadata
	clientID     string
	clientSecret string
	pkce         auth.PKCE
	redirectURI  string
	expiry       time.Time
}

func (s *Server) httpClient() *http.Client {
	if s.upstreamClient != nil {
		return s.upstreamClient
	}
	return http.DefaultClient
}

// tokenKey is the secret-store key for an upstream's OAuth token record.
func tokenKey(name string) string { return "upstreams/" + name }

// storedClient is a persisted Dynamic Client Registration, keyed by provider so we
// REUSE it instead of registering a new OAuth app on every add attempt.
type storedClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func clientKey(issuer string) string {
	host := issuer
	if u, err := url.Parse(issuer); err == nil && u.Host != "" {
		host = u.Host
	}
	return "oauth-clients/" + host
}

// loadOrRegisterClient returns a previously-registered client for this AS (so
// retries don't spawn duplicate OAuth apps at the provider), or registers one and
// persists it.
func (s *Server) loadOrRegisterClient(ctx context.Context, meta *auth.ASMetadata, callbackURL string) (string, string, error) {
	key := clientKey(meta.Issuer)
	if s.secrets != nil {
		if raw, err := s.secrets.Load(ctx, key); err == nil {
			var c storedClient
			if json.Unmarshal(raw, &c) == nil && c.ClientID != "" {
				return c.ClientID, c.ClientSecret, nil
			}
		}
	}
	id, secret, err := auth.RegisterClient(ctx, s.httpClient(), meta.RegistrationEndpoint, callbackURL, "microagency")
	if err != nil {
		return "", "", err
	}
	if s.secrets != nil {
		b, _ := json.Marshal(storedClient{ClientID: id, ClientSecret: secret})
		_ = s.secrets.Save(ctx, key, b)
	}
	return id, secret, nil
}

// saveUpstreamToken persists an upstream's refresh-token record (best-effort —
// if the store is down, the token stays in memory and a restart re-prompts).
func (s *Server) saveUpstreamToken(name string, tok *auth.UpstreamToken) {
	if s.secrets == nil {
		return
	}
	rec, _ := json.Marshal(tok.Record())
	if err := s.secrets.Save(context.Background(), tokenKey(name), rec); err != nil {
		log.Printf("microagency: persist upstream %q token: %v", name, err)
	}
}

// refreshingBearer builds the upstream's bearer, re-persisting the rotated token.
func (s *Server) refreshingBearer(name string, tok *auth.UpstreamToken) func(context.Context) (string, error) {
	return auth.RefreshingBearer(tok, s.httpClient(), func(t *auth.UpstreamToken) {
		s.saveUpstreamToken(name, t)
	})
}

func (s *Server) putOAuthFlow(state string, f *oauthFlow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthFlows[state] = f
}

// takeOAuthFlow removes and returns the flow for state, or nil if absent/expired.
func (s *Server) takeOAuthFlow(state string) *oauthFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.oauthFlows[state]
	delete(s.oauthFlows, state)
	if f == nil || time.Now().After(f.expiry) {
		return nil
	}
	return f
}

// startUpstreamOAuth registers microagency with the upstream's AS (DCR, redirect_uri
// = the admin callback) and stashes a pending flow. Returns the authorize URL.
func (s *Server) startUpstreamOAuth(ctx context.Context, name, url string, discover, reauth, readOnly bool, owner, scope, resourceMetadataURL, callbackURL string) (string, error) {
	meta, err := auth.DiscoverAS(ctx, s.httpClient(), resourceMetadataURL)
	if err != nil {
		return "", err
	}
	clientID, clientSecret, err := s.loadOrRegisterClient(ctx, meta, callbackURL)
	if err != nil {
		return "", err
	}
	pkce := auth.NewPKCE()
	state := randState()
	s.putOAuthFlow(state, &oauthFlow{
		name: name, url: url, discover: discover, reauth: reauth, readOnly: readOnly, owner: owner, meta: meta, clientID: clientID, clientSecret: clientSecret,
		pkce: pkce, redirectURI: callbackURL, expiry: time.Now().Add(10 * time.Minute),
	})
	return auth.AuthorizeURL(meta, clientID, callbackURL, pkce, scope, state), nil
}

// adminOAuthCallback is the upstream's redirect target (a browser GET, NOT behind
// the operator token — it's protected by the unguessable state + PKCE). It
// exchanges the code and registers the upstream cred-blind.
func (s *Server) adminOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	flow := s.takeOAuthFlow(q.Get("state"))
	if flow == nil {
		authui.WriteMessage(w, "This authorization request is unknown or expired. Start again from the console.")
		return
	}
	if e := q.Get("error"); e != "" {
		authui.WriteMessage(w, "Authorization was denied ("+e+"). You can close this tab.")
		return
	}
	tok, err := auth.ExchangeCode(r.Context(), s.httpClient(), flow.meta, flow.clientID, flow.clientSecret, flow.redirectURI, q.Get("code"), flow.pkce)
	if err != nil {
		authui.WriteMessage(w, "Token exchange failed: "+err.Error())
		return
	}
	s.saveUpstreamToken(flow.name, tok) // persist the refresh token (Bao/file)
	u := &gateway.Upstream{
		Name: flow.name, URL: flow.url,
		Bearer: s.refreshingBearer(flow.name, tok), Client: s.upstreamClient,
	}
	var opts []UpstreamOption
	if flow.owner != "" {
		opts = append(opts, WithOwner(flow.owner))
	}
	switch {
	case flow.reauth:
		err = s.RebindUpstream(r.Context(), flow.name, u) // new token/scope onto the existing upstream
	case flow.discover:
		err = s.DiscoverUpstream(r.Context(), u, opts...)
	default:
		err = s.AddUpstream(r.Context(), u, opts...)
	}
	if err != nil {
		authui.WriteMessage(w, "Authorized, but registering the upstream failed: "+err.Error())
		return
	}
	s.persistRegistration(flow.name, flow.url, flow.discover, authOAuth, flow.owner) // reload across restarts
	// Apply the operator's read-only choice from onboarding (reauth preserves the
	// existing setting, so it's only applied on a fresh add/discover).
	if !flow.reauth && flow.readOnly {
		_ = s.SetUpstreamReadOnly(flow.name, true)
		s.persistReadOnly(flow.name, true)
	}
	authui.WriteConnected(w, flow.name)
}

// callbackURL is microagency's stable OAuth callback, derived from the request the
// operator's browser/console reached us on (so it matches the admin bind).
func callbackURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/admin/oauth/callback"
}

func randState() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
