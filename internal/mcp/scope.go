package mcp

import (
	"context"

	"microagency/internal/auth"
)

// principalOf returns the authenticated caller from the context, or the local
// operator when there is none — the stdio / loopback path, where there is a
// single trusted user. Per-user scoping is enforced relative to this subject.
func principalOf(ctx context.Context) *auth.Principal {
	if p, ok := PrincipalFrom(ctx); ok && p != nil && p.Subject != "" {
		return p
	}
	return &auth.Principal{Subject: "local"}
}
