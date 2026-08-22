package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
	// owner scopes the connection to one principal's canonical identity key
	// (issuer#subject) at registration ("" = shared). Reauth flows leave it
	// empty — rebind preserves the record.
	owner        string
	meta         *auth.ASMetadata
	clientID     string
	clientSecret string
	pkce         auth.PKCE
	redirectURI  string
	expiry       time.Time
	// Self-service flows bind every durable artifact to the initiating principal.
	// The callback needs no user bearer because the unguessable, single-use state
	// selects this record; ownership is applied before the connection is registered.
	selfService     bool
	template        string
	templateVersion uint64
	credentialKey   string
	clientStoreKey  string
	reservation     string
	authGeneration  uint64
}

type oauthFlowOption func(*oauthFlow)

func withSelfServiceOAuth(template string, templateVersion uint64, credentialKey, clientStoreKey string, authGeneration uint64) oauthFlowOption {
	return func(f *oauthFlow) {
		f.selfService = true
		f.template = template
		f.templateVersion = templateVersion
		f.credentialKey = credentialKey
		f.clientStoreKey = clientStoreKey
		f.authGeneration = authGeneration
	}
}

func withConnectionReservation(id string) oauthFlowOption {
	return func(f *oauthFlow) { f.reservation = id }
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

// resourceAllowedForUpstream reports whether an RFC 8707 resource indicator is safe
// to send when authorizing this upstream. An empty indicator is filled in by the
// caller; any non-empty indicator must be an absolute URL on the upstream's origin.
// A host-less or opaque audience identifier is attacker-controlled metadata too, and
// could ask the AS for a token scoped to some resource unrelated to this MCP server.
func resourceAllowedForUpstream(resource, upstreamURL string) bool {
	if resource == "" {
		return true
	}
	ru, err := url.Parse(resource)
	if err != nil || ru.Scheme == "" || ru.Host == "" {
		return false
	}
	return sameOrigin(resource, upstreamURL)
}

// sameOrigin reports whether two URLs share a scheme and host. A parse failure or a
// missing host is a fail-closed no-match.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// loadOrRegisterClient returns the OAuth client to use for this AS. Precedence:
// (1) a client already stored for this AS (so retries don't spawn duplicate apps);
// (2) operator-supplied client_id/secret — the path for an AS WITHOUT dynamic client
// registration (Google, most enterprise IdPs), persisted so it's reused; (3) dynamic
// client registration (RFC 7591). An AS with no registration endpoint and no supplied
// client fails with an actionable error telling the operator to supply credentials.
func (s *Server) loadOrRegisterClient(ctx context.Context, meta *auth.ASMetadata, callbackURL, suppliedID, suppliedSecret string) (string, string, error) {
	return s.loadOrRegisterClientAtKey(ctx, meta, callbackURL, clientKey(meta.Issuer), suppliedID, suppliedSecret)
}

func (s *Server) loadOrRegisterClientAtKey(ctx context.Context, meta *auth.ASMetadata, callbackURL, key, suppliedID, suppliedSecret string) (string, string, error) {
	if key == "" {
		key = clientKey(meta.Issuer)
	}
	// Operator-supplied client wins — including OVER a previously stored one. An
	// explicit client_id/secret means "use these", so it must be able to REPLACE the
	// stored client (e.g. switching a Google app from a personal-account client to an
	// Internal one). Persist and use it, skipping registration entirely.
	if suppliedID != "" {
		if s.secrets != nil {
			b, _ := json.Marshal(storedClient{ClientID: suppliedID, ClientSecret: suppliedSecret})
			if err := s.secrets.Save(ctx, key, b); err != nil {
				// Not fatal — the supplied client is used this session — but a failed
				// persist means it won't survive a restart, so surface it.
				slog.Warn("persist OAuth client failed", "issuer", meta.Issuer, "err", err)
			}
		}
		return suppliedID, suppliedSecret, nil
	}
	// No supplied creds: reuse a stored client so retries/reauth don't re-register.
	if s.secrets != nil {
		if raw, err := s.secrets.Load(ctx, key); err == nil {
			var c storedClient
			if json.Unmarshal(raw, &c) == nil && c.ClientID != "" {
				return c.ClientID, c.ClientSecret, nil
			}
		}
	}
	if meta.RegistrationEndpoint == "" {
		return "", "", fmt.Errorf("this authorization server does not support dynamic client registration; supply an OAuth client_id/client_secret when adding the connection")
	}
	id, secret, err := auth.RegisterClient(ctx, s.httpClient(), meta.RegistrationEndpoint, callbackURL, "microagency")
	if err != nil {
		return "", "", err
	}
	if s.secrets != nil {
		b, _ := json.Marshal(storedClient{ClientID: id, ClientSecret: secret})
		if err := s.secrets.Save(ctx, key, b); err != nil {
			// A dynamically-registered client that fails to persist re-registers a fresh
			// app on the next add/reauth (a duplicate on the AS side), so surface it.
			slog.Warn("persist registered OAuth client failed", "issuer", meta.Issuer, "err", err)
		}
	}
	return id, secret, nil
}

// saveUpstreamTokenAtKey persists an upstream's refresh-token record (best-effort
// — if the store is down, the token stays in memory and a restart re-prompts).
func (s *Server) saveUpstreamTokenAtKey(name, key string, tok *auth.UpstreamToken, authGeneration uint64, principalScoped bool) {
	if s.secrets == nil {
		return
	}
	if principalScoped {
		s.reg.mu.Lock()
		record, ok := s.reg.conns[name]
		if ok {
			if record.revoked || record.authGeneration != authGeneration {
				s.reg.mu.Unlock()
				return
			}
			// Keep the registry lock through Save. Revoke takes this same lock before
			// deleting the credential, so either this write happens first and revoke
			// deletes it, or revoke changes the generation and this write is refused.
			defer s.reg.mu.Unlock()
		} else {
			s.reg.mu.Unlock()
			// Reload may refresh while it is listing tools, before the persisted
			// connection has entered the in-memory registry. Permit that one startup
			// case only when the durable record is still live and names this exact key.
			persisted := false
			for _, registration := range s.loadRegistrations() {
				if registration.Name == name && registration.SelfService && !registration.Revoked && credentialKeyForRegistration(registration) == key {
					persisted = true
					break
				}
			}
			if !persisted {
				return
			}
		}
	}
	rec, _ := json.Marshal(tok.Record())
	if err := s.secrets.Save(context.Background(), key, rec); err != nil {
		slog.Error("persist upstream token failed", "upstream", name, "err", err)
	}
}

// refreshingBearerAtKey builds the upstream's bearer, re-persisting a rotated
// token at the connection's operator- or principal-scoped secret key.
func (s *Server) refreshingBearerAtKey(name, key string, tok *auth.UpstreamToken, authGeneration uint64, principalScoped bool) func(context.Context) (string, error) {
	return auth.RefreshingBearer(tok, s.httpClient(), func(t *auth.UpstreamToken) {
		s.saveUpstreamTokenAtKey(name, key, t, authGeneration, principalScoped)
	})
}

func (s *Server) putOAuthFlow(state string, f *oauthFlow) {
	s.flows.mu.Lock()
	defer s.flows.mu.Unlock()
	// Sweep abandoned flows on the way in — takeOAuthFlow only drops the state it
	// redeems, so a flow the operator starts and never completes would otherwise
	// linger forever. Cheap: the map only holds pending console OAuth adds.
	now := time.Now()
	for st, of := range s.flows.byState {
		if now.After(of.expiry) {
			delete(s.flows.byState, st)
		}
	}
	s.flows.byState[state] = f
}

// takeOAuthFlowFor removes and returns the flow for state and callback plane, or
// nil if absent, expired, or addressed through the wrong callback route.
func (s *Server) takeOAuthFlowFor(state string, selfService bool) *oauthFlow {
	s.flows.mu.Lock()
	defer s.flows.mu.Unlock()
	f := s.flows.byState[state]
	if f == nil || f.selfService != selfService || time.Now().After(f.expiry) {
		if f != nil && time.Now().After(f.expiry) {
			delete(s.flows.byState, state)
		}
		return nil
	}
	delete(s.flows.byState, state)
	return f
}

func (s *Server) cancelOAuthFlows(match func(*oauthFlow) bool) {
	s.flows.mu.Lock()
	reservations := make([]string, 0)
	for state, flow := range s.flows.byState {
		if match(flow) {
			delete(s.flows.byState, state)
			reservations = append(reservations, flow.reservation)
		}
	}
	s.flows.mu.Unlock()
	for _, reservation := range reservations {
		s.releaseConnectionStart(reservation)
	}
}

// startUpstreamOAuth registers microagency with the upstream's AS (DCR, redirect_uri
// = the admin callback) and stashes a pending flow. Returns the authorize URL.
func (s *Server) startUpstreamOAuth(ctx context.Context, name, url string, discover, reauth, readOnly bool, owner, scope, resourceMetadataURL, callbackURL, suppliedClientID, suppliedClientSecret string, options ...oauthFlowOption) (string, error) {
	meta, err := auth.DiscoverAS(ctx, s.httpClient(), resourceMetadataURL)
	if err != nil {
		return "", err
	}
	// RFC 8707 resource indicator. Default to the upstream's canonical URL when the
	// (attacker-controllable) protected-resource metadata names none. When it DOES name
	// one, constrain it to the upstream's origin: an unconstrained resource lets a
	// malicious upstream point the token's audience at an unrelated victim resource, so
	// the access token microagency then sends to that upstream is valid elsewhere.
	if meta.Resource == "" {
		meta.Resource = url
	} else if !resourceAllowedForUpstream(meta.Resource, url) {
		return "", fmt.Errorf("authorization server advertised resource indicator %q that is not an absolute URL on the upstream origin %q; refusing to bind a token to an unrelated resource", meta.Resource, url)
	}
	flow := &oauthFlow{name: name, url: url, discover: discover, reauth: reauth, readOnly: readOnly, owner: owner, meta: meta, redirectURI: callbackURL, expiry: time.Now().Add(10 * time.Minute)}
	for _, option := range options {
		option(flow)
	}
	clientID, clientSecret, err := s.loadOrRegisterClientAtKey(ctx, meta, callbackURL, flow.clientStoreKey, suppliedClientID, suppliedClientSecret)
	if err != nil {
		return "", err
	}
	pkce := auth.NewPKCE()
	state := randState()
	flow.clientID, flow.clientSecret, flow.pkce = clientID, clientSecret, pkce
	s.putOAuthFlow(state, flow)
	return auth.AuthorizeURL(meta, clientID, callbackURL, pkce, scope, state), nil
}

// adminOAuthCallback is the upstream's redirect target (a browser GET, NOT behind
// the operator token — it's protected by the unguessable state + PKCE). It
// exchanges the code and registers the upstream cred-blind.
func (s *Server) adminOAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.completeUpstreamOAuth(w, r, false)
}

func (s *Server) completeUpstreamOAuth(w http.ResponseWriter, r *http.Request, selfService bool) {
	writeMessage := authui.WriteMessage
	if selfService {
		writeMessage = authui.WriteUserMessage
	}
	q := r.URL.Query()
	flow := s.takeOAuthFlowFor(q.Get("state"), selfService)
	if flow == nil {
		if selfService {
			writeMessage(w, "This authorization request is unknown or expired.")
		} else {
			writeMessage(w, "This authorization request is unknown or expired. Start again from the console.")
		}
		return
	}
	defer s.releaseConnectionStart(flow.reservation)
	if flow.selfService {
		_, version, ok := s.connectionTemplateWithVersion(flow.template, false)
		if !ok || version != flow.templateVersion {
			writeMessage(w, "This connection template changed before authorization completed. Start again with the current policy.")
			return
		}
	}
	if e := q.Get("error"); e != "" {
		writeMessage(w, "Authorization was denied ("+e+"). You can close this tab.")
		return
	}
	tok, err := auth.ExchangeCode(r.Context(), s.httpClient(), flow.meta, flow.clientID, flow.clientSecret, flow.redirectURI, q.Get("code"), flow.pkce)
	if err != nil {
		if selfService {
			writeMessage(w, "Token exchange failed. Return to your account and try again.")
		} else {
			writeMessage(w, "Token exchange failed: "+err.Error())
		}
		return
	}
	key := flow.credentialKey
	if key == "" {
		key = tokenKey(flow.name)
	}
	u := &gateway.Upstream{
		Name: flow.name, URL: flow.url,
		Bearer: s.refreshingBearerAtKey(flow.name, key, tok, flow.authGeneration, flow.selfService), Client: s.upstreamClient,
	}
	var opts []UpstreamOption
	if flow.owner != "" {
		opts = append(opts, WithOwner(flow.owner))
	}
	if flow.selfService {
		opts = append(opts, WithSelfService(flow.template))
	}
	switch {
	case flow.selfService:
		err = s.commitSelfServiceOAuth(r.Context(), flow, u)
	case flow.reauth:
		err = s.RebindUpstream(r.Context(), flow.name, u) // new token/scope onto the existing upstream
	case flow.discover:
		err = s.DiscoverUpstream(r.Context(), flow.name, u, opts...)
	default:
		err = s.AddUpstream(r.Context(), flow.name, u, opts...)
	}
	if err != nil {
		if selfService {
			writeMessage(w, "Authorization succeeded, but the connection could not be registered. Return to your account and try again.")
		} else {
			writeMessage(w, "Authorized, but registering the upstream failed: "+err.Error())
		}
		return
	}
	s.saveUpstreamTokenAtKey(flow.name, key, tok, flow.authGeneration, flow.selfService) // persist only after the generation-bound registration commits
	reg := upstreamReg{Name: flow.name, URL: flow.url, Discover: flow.discover, Auth: authOAuth, ReadOnly: flow.readOnly, Owner: flow.owner, SelfService: flow.selfService, Template: flow.template}
	if flow.selfService {
		reg.Strategy = StrategyPerUserOAuth // the user's own grant IS the credential
	}
	s.persistRegistrationRecord(reg) // reload across restarts
	// Apply the operator's read-only choice from onboarding (reauth preserves the
	// existing setting, so it's only applied on a fresh add/discover).
	if !flow.selfService && !flow.reauth && flow.readOnly {
		_ = s.SetUpstreamReadOnly(flow.name, true)
		s.persistReadOnly(flow.name, true)
	}
	if flow.selfService {
		s.recordConnectionEvent(flow.owner, flow.name, "authorized")
		authui.WriteUserConnected(w, flow.name)
		return
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
