package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"microagency/internal/auth"
)

// The audience rule set is operator policy, so it is managed on the operator
// surface and nowhere else: no agent tool touches it, and the principal-facing
// account API cannot see it. It is read through to its file on every access, so
// a rule added here takes effect on the next sign-in with no restart, and an
// edit made while the gateway was down is picked up without one either.

// AudienceRules exposes the operator-managed federated sign-in audience. It is
// nil-safe: a server with no state directory reports an empty rule set.
func (s *Server) AudienceRules() *auth.AudienceRules {
	return auth.NewAudienceRules(auth.AudienceRulesPath(s.stateDir))
}

func (s *Server) adminListAudienceRules(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.AudienceRules().List()
	if err != nil {
		http.Error(w, "read audience rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []auth.AudienceRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) adminAddAudienceRule(w http.ResponseWriter, r *http.Request) {
	var in auth.AudienceRule
	if err := json.NewDecoder(io.LimitReader(r.Body, maxHTTPBody)).Decode(&in); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	in.Added = time.Time{} // the gateway stamps admission time, never the caller
	rule, err := s.AudienceRules().Add(in)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) adminDeleteAudienceRule(w http.ResponseWriter, r *http.Request) {
	removed, err := s.AudienceRules().Remove(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !removed {
		http.Error(w, "unknown audience rule", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
