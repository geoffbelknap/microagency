package mcp

import (
	"context"

	"microagency/internal/auth"
)

// principalOf returns the authenticated caller from the context, or the local
// operator when there is none — the stdio / loopback path, where there is a
// single trusted user. The synthetic principal carries the fixed local issuer
// so its identity key is stable and can never collide with a token-issued one.
func principalOf(ctx context.Context) *auth.Principal {
	if p, ok := PrincipalFrom(ctx); ok && p != nil && p.Subject != "" {
		return p
	}
	return &auth.Principal{Subject: "local", Issuer: auth.LocalIssuer, Campaign: "local"}
}

// callerKey returns the caller's canonical (issuer, subject) identity key —
// the ONLY form identity is compared or persisted in. Two issuers asserting
// the same subject yield different keys, so ownership, refs, secrets, quotas,
// and grants never merge across issuers.
func callerKey(ctx context.Context) string { return principalOf(ctx).Key() }

func campaignOf(ctx context.Context) string { return principalOf(ctx).Campaign }
