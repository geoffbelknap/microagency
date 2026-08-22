package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"microagency/internal/auth"
	"microagency/internal/gateway"
	"microagency/internal/safedial"
	"microagency/internal/secretstore"
)

// Credential strategies: how a calling principal maps to authority at the
// upstream. Declared per connection, persisted in the non-secret registry.
//
//   - static: the connection's one shared credential (or none) acts for every
//     caller — the default, and the only behavior that existed before
//     strategies were named.
//   - per-user-oauth: the connection belongs to the principal who authorized
//     it through a self-service template; the credential is that user's own
//     OAuth grant.
//   - google-dwd: one shared connection, a distinct upstream identity per
//     caller — the gateway holds a service-account key and derives a
//     short-lived token acting as each caller's provider-verified email.
const (
	StrategyStatic       = "static"
	StrategyPerUserOAuth = "per-user-oauth"
	StrategyGoogleDWD    = "google-dwd"
)

// delegationHTTPClient performs assertion exchanges at the provider token
// endpoint. That endpoint is operator-configured infrastructure (like the SSO
// issuer), not an untrusted upstream URL, so it uses a plain bounded client
// rather than the SSRF-guarded upstream client.
var delegationHTTPClient = &http.Client{Timeout: 30 * time.Second}

// DelegationSummary is the persisted NON-secret configuration of a google-dwd
// connection: the acting service account, where assertions are exchanged, and
// the scopes every derived token carries. The service-account key itself
// lives only in the secret store, under DelegationKeyKey. Exported so doctor
// can report delegated connections from the registry alone.
type DelegationSummary struct {
	ClientEmail   string   `json:"client_email"`
	TokenEndpoint string   `json:"token_endpoint"`
	Scopes        []string `json:"scopes"`
}

// DelegationKeyKey is the secret-store key holding a delegated connection's
// service-account key document.
func DelegationKeyKey(name string) string { return "delegation/upstreams/" + name + "/key" }

// strategyKind returns the registration's credential strategy: the explicit
// field when set, otherwise derived — self-service connections are
// per-user-oauth, everything else is static.
func (r upstreamReg) strategyKind() string {
	if r.Strategy != "" {
		return r.Strategy
	}
	if r.SelfService {
		return StrategyPerUserOAuth
	}
	return StrategyStatic
}

// validateStrategy refuses a registration whose declared strategy contradicts
// its other fields, so a hand-edited or torn record fails closed instead of
// reloading under the wrong caller-to-credential mapping.
func validateStrategy(r upstreamReg) error {
	switch r.strategyKind() {
	case StrategyStatic:
		if r.Delegation != nil {
			return fmt.Errorf("connection %q: a static-strategy record must not carry delegation config", r.Name)
		}
	case StrategyPerUserOAuth:
		if !r.SelfService {
			return fmt.Errorf("connection %q: per-user-oauth is the self-service strategy; this record is not self-service", r.Name)
		}
		if r.Delegation != nil {
			return fmt.Errorf("connection %q: a per-user-oauth record must not carry delegation config", r.Name)
		}
	case StrategyGoogleDWD:
		if r.Delegation == nil || len(r.Delegation.Scopes) == 0 {
			return fmt.Errorf("connection %q: a google-dwd record requires delegation config with at least one scope", r.Name)
		}
	default:
		return fmt.Errorf("connection %q: unknown credential strategy %q", r.Name, r.Strategy)
	}
	return nil
}

// delegatedCallContextKey carries the (caller identity key, delegation
// subject) pair for one delegated upstream call. Attached at the invocation
// gate after the caller's verified identity is resolved — and re-attached
// inside the in-flight runner's detached context — so the per-connection
// bearer can derive the right token on every call path.
type delegatedCallContextKey struct{}

type delegatedCall struct{ caller, subject string }

func withDelegatedCall(ctx context.Context, caller, subject string) context.Context {
	return context.WithValue(ctx, delegatedCallContextKey{}, delegatedCall{caller: caller, subject: subject})
}

func delegatedCallFrom(ctx context.Context) (caller, subject string) {
	dc, _ := ctx.Value(delegatedCallContextKey{}).(delegatedCall)
	return dc.caller, dc.subject
}

// delegatedBearer builds a gateway bearer that derives a per-caller token
// acting as the context's delegation subject. The gateway acts upstream as
// the mapped per-user identity, so the provider's own ACLs trim results — it
// never queries broadly under the service account and filters afterwards.
// Wiring-time calls (initialize and tools/list at registration) carry no
// caller and go unauthenticated rather than acting as anyone.
func delegatedBearer(src *auth.DelegatedTokenSource) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		caller, subject := delegatedCallFrom(ctx)
		if subject == "" {
			return "", nil
		}
		return src.Token(ctx, caller, subject)
	}
}

// WithDelegation marks a connection google-dwd and installs its per-caller
// token source.
func WithDelegation(src *auth.DelegatedTokenSource) UpstreamOption {
	return func(u *upstream) { u.delegation = src }
}

// SetDelegatedEmailLookup installs the subject→provider-verified-email
// mapping delegated connections act on. Wiring sets it from the federated
// sign-in identity table, before the server serves. Without it (any
// non-federated auth mode), no caller has a delegation subject, so every
// google-dwd connection is hidden from find_tools and fails closed per call.
func (s *Server) SetDelegatedEmailLookup(fn func(subject string) string) { s.delegatedEmail = fn }

// delegationSubject resolves the caller's provider-verified email, or ""
// when the caller has none. Only the verified identity recorded at sign-in
// is ever used; no fallback identity is substituted.
func (s *Server) delegationSubject(ctx context.Context) string {
	return s.delegationSubjectForSubject(principalOf(ctx).Subject)
}

func (s *Server) delegationSubjectForSubject(subject string) string {
	if s.delegatedEmail == nil {
		return ""
	}
	return s.delegatedEmail(subject)
}

// delegationSubjectForKey resolves the verified email for a canonical caller
// identity key — the find_tools path, which works from the key.
func (s *Server) delegationSubjectForKey(callerKey string) string {
	_, subject, err := auth.SplitPrincipalKey(callerKey)
	if err != nil {
		return ""
	}
	return s.delegationSubjectForSubject(subject)
}

// DelegationInfo is the operator-facing view of a delegated connection's
// non-secret configuration. KeyConfigured reports that a usable
// service-account key is installed; the key itself is never exposed.
type DelegationInfo struct {
	ClientEmail   string   `json:"client_email"`
	TokenEndpoint string   `json:"token_endpoint"`
	Scopes        []string `json:"scopes"`
	KeyConfigured bool     `json:"key_configured"`
}

// buildDelegatedSource parses a service-account key document and builds the
// per-caller token source for cfg, filling config defaults from the key.
func buildDelegatedSource(cfg DelegationSummary, rawKey []byte) (*auth.DelegatedTokenSource, error) {
	sa, err := auth.ParseServiceAccountKey(rawKey)
	if err != nil {
		return nil, err
	}
	return auth.NewDelegatedTokenSource(auth.DelegationConfig{
		ClientEmail:   cfg.ClientEmail,
		TokenEndpoint: cfg.TokenEndpoint,
		Scopes:        cfg.Scopes,
		HTTPClient:    delegationHTTPClient,
	}, sa)
}

// resolvedDelegationSummary is the non-secret config actually in force after
// key defaults are applied — what gets persisted and reported.
func resolvedDelegationSummary(src *auth.DelegatedTokenSource) *DelegationSummary {
	return &DelegationSummary{
		ClientEmail:   src.ClientEmail(),
		TokenEndpoint: src.TokenEndpoint(),
		Scopes:        src.Scopes(),
	}
}

// setUpstreamDelegation swaps the live record's token source (key rotation or
// config change), dropping the outgoing source's derived-token cache.
func (s *Server) setUpstreamDelegation(name string, src *auth.DelegatedTokenSource) error {
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	rec, ok := s.reg.conns[name]
	if !ok {
		return fmt.Errorf("gateway: unknown upstream %q", name)
	}
	if rec.delegation == nil {
		return fmt.Errorf("gateway: upstream %q is not a delegated connection", name)
	}
	rec.delegation.DropCache()
	rec.delegation = src
	return nil
}

// persistDelegation updates just the delegation config of a persisted
// google-dwd registration.
func (s *Server) persistDelegation(name string, cfg *DelegationSummary) {
	s.updateRegistrations(func(regs []upstreamReg) ([]upstreamReg, bool) {
		for i := range regs {
			if regs[i].Name == name {
				regs[i].Delegation = cfg
				return regs, true
			}
		}
		return regs, false
	})
}

// adminUpdateDelegation rotates a delegated connection's service-account key
// and/or updates its non-secret config, then rebinds the connection so the
// new source serves every subsequent call. Key material arrives only in the
// request body and lands only in the secret store; the response reports
// `key_configured`, never the key.
func (s *Server) adminUpdateDelegation(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Delegation        *DelegationSummary `json:"delegation"`
		ServiceAccountKey string             `json:"service_account_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	rec, ok := s.snapshotUpstream(name)
	if !ok {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	if rec.delegation == nil {
		http.Error(w, "upstream "+name+" is not a delegated (google-dwd) connection", http.StatusConflict)
		return
	}
	if in.Delegation == nil && in.ServiceAccountKey == "" {
		http.Error(w, "nothing to update: supply delegation config, a service_account_key, or both", http.StatusBadRequest)
		return
	}
	if s.secrets == nil {
		http.Error(w, "a secret store is required for delegated connections", http.StatusServiceUnavailable)
		return
	}
	cfg := DelegationSummary{
		ClientEmail:   rec.delegation.ClientEmail(),
		TokenEndpoint: rec.delegation.TokenEndpoint(),
		Scopes:        rec.delegation.Scopes(),
	}
	if in.Delegation != nil {
		cfg = *in.Delegation
	}
	rawKey := []byte(in.ServiceAccountKey)
	if in.ServiceAccountKey == "" {
		stored, err := s.secrets.Load(r.Context(), DelegationKeyKey(name))
		if err != nil {
			http.Error(w, "load stored service-account key: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		rawKey = stored
	}
	src, err := buildDelegatedSource(cfg, rawKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if in.ServiceAccountKey != "" {
		if err := s.secrets.Save(r.Context(), DelegationKeyKey(name), rawKey); err != nil {
			http.Error(w, "store service-account key: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	u := &gateway.Upstream{Name: name, URL: rec.conn.Endpoint(), Client: s.upstreamClient, Bearer: delegatedBearer(src)}
	if err := s.RebindUpstream(r.Context(), name, u); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.setUpstreamDelegation(name, src); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	resolved := resolvedDelegationSummary(src)
	s.persistDelegation(name, resolved)
	writeJSON(w, http.StatusOK, map[string]any{
		"name":     name,
		"strategy": StrategyGoogleDWD,
		"delegation": DelegationInfo{
			ClientEmail: resolved.ClientEmail, TokenEndpoint: resolved.TokenEndpoint,
			Scopes: resolved.Scopes, KeyConfigured: true,
		},
	})
}

// addDelegatedUpstream is the admin add path for strategy google-dwd: parse
// and store the service-account key, build the per-caller source, register
// the connection, and persist the non-secret record.
func (s *Server) addDelegatedUpstream(ctx context.Context, name, rawURL string, discover, readOnly, privateDestination bool, owner string, cfg *DelegationSummary, saKey string) (string, int, error) {
	if s.secrets == nil {
		return "", http.StatusServiceUnavailable, errors.New("a secret store is required for delegated connections")
	}
	if saKey == "" {
		return "", http.StatusBadRequest, errors.New("strategy google-dwd requires service_account_key (the provider's JSON key document)")
	}
	if cfg == nil {
		cfg = &DelegationSummary{}
	}
	src, err := buildDelegatedSource(*cfg, []byte(saKey))
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	// The key is durable before the connection is callable: if the process dies
	// between these steps, restart sees a registered connection whose key is
	// present, never a callable connection whose key is gone.
	if err := s.secrets.Save(ctx, DelegationKeyKey(name), []byte(saKey)); err != nil {
		return "", http.StatusServiceUnavailable, fmt.Errorf("store service-account key: %w", err)
	}
	client := s.upstreamClient
	opts := []UpstreamOption{WithDelegation(src)}
	if privateDestination {
		dest, derr := safedial.ParseDestination(rawURL)
		if derr != nil {
			if delErr := s.secrets.Delete(ctx, DelegationKeyKey(name)); delErr != nil && delErr != secretstore.ErrNotFound {
				derr = errors.Join(derr, delErr)
			}
			return "", http.StatusBadRequest, derr
		}
		client = safedial.GuardedClientForDestination(0, 0, dest)
		opts = append(opts, WithPrivateDestination())
	}
	u := &gateway.Upstream{Name: name, URL: rawURL, Client: client, Bearer: delegatedBearer(src)}
	if owner != "" {
		opts = append(opts, WithOwner(owner))
	}
	state := "enabled"
	if discover {
		err, state = s.DiscoverUpstream(ctx, name, u, opts...), "discovered"
	} else {
		err = s.AddUpstream(ctx, name, u, opts...)
	}
	if err != nil {
		if derr := s.secrets.Delete(ctx, DelegationKeyKey(name)); derr != nil && derr != secretstore.ErrNotFound {
			err = errors.Join(err, derr)
		}
		return "", http.StatusBadGateway, err
	}
	resolved := resolvedDelegationSummary(src)
	s.persistRegistrationRecord(upstreamReg{
		Name: name, URL: rawURL, Discover: discover, Auth: authNone,
		ReadOnly: readOnly, PrivateDestination: privateDestination, Owner: owner,
		Strategy: StrategyGoogleDWD, Delegation: resolved,
	})
	if readOnly {
		_ = s.SetUpstreamReadOnly(name, true)
		s.persistReadOnly(name, true)
	}
	return state, 0, nil
}
