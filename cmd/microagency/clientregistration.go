package main

import (
	"microagency/internal/auth"
	"microagency/internal/mcp"
)

// configureClientRegistration declares the built-in authorization server's
// dynamic-client-registration posture and points its audit sink at the gateway's
// log. Call before LoadClients, so registrations that expired while the gateway
// was down are pruned against the limits actually in effect.
func configureClientRegistration(builtInAS *auth.AuthServer, srv *mcp.Server, cfg httpConfig) {
	mode := cfg.clientRegistration
	if mode == "" {
		mode = auth.RegistrationBounded
	}
	builtInAS.SetClientRegistration(mode, auth.RegistrationLimits{})
	builtInAS.SetRegistrationRecorder(srv.RecordClientRegistration)
}
