package mcp

import (
	"microagency/internal/auth"
)

// RecordClientRegistration writes one dynamic client registration decision to
// the audit log.
//
// Registration is the one write to persistent state a public gateway accepts
// from nobody in particular, which makes it the one write an operator cannot
// otherwise account for: without a record, `oauth-clients.json` quietly gaining
// entries is the only evidence anything happened, and a refused attempt leaves
// no evidence at all.
//
// The record carries no caller identity, because there is none — that is the
// point of the event. It carries the outcome, the client_id when one was
// created, and a digest of the source, which is what distinguishes one client
// connecting from something enumerating the endpoint. The self-declared client
// name is deliberately not recorded: it is untrusted text an anonymous caller
// chose, and the registration it belongs to is already stored with it.
func (s *Server) RecordClientRegistration(event auth.RegistrationEvent) {
	s.putRun(s.nextRunID(), runRecord{
		Kind:         "client",
		Tool:         event.Outcome,
		ClientID:     event.ClientID,
		SourceDigest: event.SourceDigest,
	})
}
