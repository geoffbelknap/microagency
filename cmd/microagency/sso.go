package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"microagency/internal/auth"
	"microagency/internal/mcp"
	"microagency/internal/secretstore"
)

// SSO federation wiring: `up --sso-issuer` keeps the built-in server as the
// authorization server toward MCP clients (registration, PKCE, token minting
// unchanged) and delegates only the human sign-in to an upstream OIDC identity
// provider. Each person authenticates at the provider, so a shared gateway
// gets distinct real principals without deploying an external authorization
// server.

// ssoClientSecretEnv supplies the provider client secret on first start. It is
// read once and stored in the secret store; the flagless restart path reads it
// back from there. Never accepted on argv.
const ssoClientSecretEnv = "MICROAGENCY_SSO_CLIENT_SECRET"

// ssoClientSecretKey is the secret-store key holding the provider client
// credential, alongside the upstream credentials the gateway already guards.
const ssoClientSecretKey = "sso/client"

// ssoClientRecord binds the stored secret to the issuer and client it belongs
// to, so a changed --sso-issuer or --sso-client-id can never silently reuse the
// old client's secret.
type ssoClientRecord struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// resolveSSOClientSecret produces the provider client secret for this run: a
// freshly supplied one (env var or file) is stored and used; otherwise the
// stored one is used, provided it belongs to the configured issuer and client.
func resolveSSOClientSecret(ctx context.Context, store secretstore.Store, cfg httpConfig) (string, error) {
	envSecret := strings.TrimSpace(os.Getenv(ssoClientSecretEnv))
	var fileSecret string
	if cfg.ssoClientSecretFile != "" {
		b, err := os.ReadFile(cfg.ssoClientSecretFile)
		if err != nil {
			return "", fmt.Errorf("read --sso-client-secret-file: %w", err)
		}
		fileSecret = strings.TrimSpace(string(b))
		if fileSecret == "" {
			return "", fmt.Errorf("--sso-client-secret-file %s is empty", cfg.ssoClientSecretFile)
		}
	}
	if envSecret != "" && fileSecret != "" {
		return "", fmt.Errorf("the SSO client secret was supplied twice — both %s and --sso-client-secret-file are set; keep one", ssoClientSecretEnv)
	}
	if store == nil {
		return "", fmt.Errorf("no secret store is available to hold the SSO client secret")
	}
	if secret := firstNonEmpty(envSecret, fileSecret); secret != "" {
		rec, err := json.Marshal(ssoClientRecord{Issuer: cfg.ssoIssuer, ClientID: cfg.ssoClientID, ClientSecret: secret})
		if err != nil {
			return "", err
		}
		if err := store.Save(ctx, ssoClientSecretKey, rec); err != nil {
			return "", fmt.Errorf("store the SSO client secret: %w", err)
		}
		return secret, nil
	}
	b, err := store.Load(ctx, ssoClientSecretKey)
	if errors.Is(err, secretstore.ErrNotFound) {
		return "", fmt.Errorf("no SSO client secret is stored for issuer %s: supply it once via %s or --sso-client-secret-file; it is kept in the secret store from then on", cfg.ssoIssuer, ssoClientSecretEnv)
	}
	if err != nil {
		return "", fmt.Errorf("load the SSO client secret: %w", err)
	}
	var rec ssoClientRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", fmt.Errorf("stored SSO client secret is unreadable: %w", err)
	}
	if rec.Issuer != cfg.ssoIssuer || rec.ClientID != cfg.ssoClientID {
		return "", fmt.Errorf("the stored SSO client secret belongs to issuer %s, client %s; supply the secret for this client via %s or --sso-client-secret-file", rec.Issuer, rec.ClientID, ssoClientSecretEnv)
	}
	return rec.ClientSecret, nil
}

// configureBuiltInFederation delegates the built-in server's sign-in step to
// the configured OIDC provider. It reports whether federation is active, which
// makes the auth surface multi-principal.
func configureBuiltInFederation(builtInAS *auth.AuthServer, srv *mcp.Server, cfg httpConfig) (bool, error) {
	if cfg.ssoIssuer == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secret, err := resolveSSOClientSecret(ctx, srv.SecretStore(), cfg)
	if err != nil {
		return false, err
	}
	fed, err := auth.DiscoverFederation(ctx, auth.FederationConfig{
		Issuer: cfg.ssoIssuer, ClientID: cfg.ssoClientID, ClientSecret: secret,
		HostedDomain: cfg.ssoHD,
		HTTPClient:   &http.Client{Timeout: 15 * time.Second},
	})
	if err != nil {
		return false, fmt.Errorf("discover SSO issuer %q: %w", cfg.ssoIssuer, err)
	}
	builtInAS.ConfigureFederation(fed)
	builtInAS.LoadFederatedIdentities(ssoIdentitiesPathFor(cfg.authDir))
	// Delegated (google-dwd) connections act as the caller's provider-verified
	// email, which federation records at sign-in. This lookup is the only
	// source of that mapping; without federation it stays unset and delegated
	// connections fail closed for every caller.
	srv.SetDelegatedEmailLookup(builtInAS.FederatedEmail)
	return true, nil
}

// ssoIdentitiesPath persists the provider subjects seen and their verified
// emails (non-secret), so display names survive restarts.
func ssoIdentitiesPath() string {
	return filepath.Join(microagencyDir(), "sso-identities.json")
}

func ssoIdentitiesPathFor(dir string) string {
	if dir != "" {
		return filepath.Join(dir, "sso-identities.json")
	}
	return ssoIdentitiesPath()
}
