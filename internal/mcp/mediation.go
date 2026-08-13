package mcp

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"microagency/internal/mediation"
)

// MediationReport combines the independently inspected enforcement boundary
// with the live set of gateway-governed upstream destinations.
type MediationReport struct {
	mediation.Status
	Protected EgressPolicy `json:"protected"`
}

func (s *Server) validateMediationEndpoint(endpoint string) error {
	binding, err := mediation.Load(s.stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Once an enforced binding exists, an unreadable/corrupt replacement must
		// not silently turn upstream changes into advisory mode.
		return fmt.Errorf("configuration unavailable (fail closed): %w", err)
	}
	return mediation.ValidateUpstream(binding, endpoint)
}

func (s *Server) MediationStatus() MediationReport {
	return MediationReport{Status: mediation.Inspect(s.stateDir), Protected: s.EgressPolicy()}
}

func (s *Server) MediationDenials() ([]mediation.Denial, error) {
	binding, err := mediation.Load(s.stateDir)
	if err != nil {
		return nil, err
	}
	policy := s.EgressPolicy()
	contributors := make(map[string][]string, len(policy.Contributors))
	for host, entries := range policy.Contributors {
		for _, entry := range entries {
			if entry.Kind == "upstream" && strings.TrimSpace(entry.Name) != "" {
				contributors[host] = append(contributors[host], entry.Name)
			}
		}
	}
	return mediation.Denials(binding, contributors)
}
