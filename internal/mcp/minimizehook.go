package mcp

import (
	"context"
	"encoding/json"

	"microagency/internal/minimize"
	"microagency/internal/sandbox"
)

// This is the mediation-side wiring of the field-level minimization substrate into
// the proxy path: resolve tokenized placeholders on the way OUT to an upstream, and
// scrub sensitive field values on the way BACK to the model. It runs outside the
// agent (ASK tenet 1) and fails closed (tenet 4) — a minimizer error withholds the
// result rather than emit it un-minimized.

// SetMinimizePolicy sets (or, with nil, clears) the field-minimization policy for
// one upstream — opaque, module-defined config (e.g. a type→action map). An
// upstream with no policy is passed through untouched.
func (s *Server) SetMinimizePolicy(upstream string, policy []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy == nil {
		delete(s.minimizePolicies, upstream)
		return
	}
	s.minimizePolicies[upstream] = policy
}

// minimizePolicyFor returns the policy for an upstream, or nil if none.
func (s *Server) minimizePolicyFor(upstream string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.minimizePolicies[upstream]
}

// minimizeActive reports whether a minimizer is installed AND this upstream has a
// policy — the cheap guard the hot path checks before doing any work.
func (s *Server) minimizeActive(upstream string) bool {
	if s.minimizer == nil {
		return false
	}
	return s.minimizePolicyFor(upstream) != nil
}

// resolveOutbound restores tokenized placeholders in model-authored arguments to
// their real values before the call is dialed — the return path for tokenized
// fields. The audit records the resolved args (audit means audit); the model only
// ever authored the placeholder.
func (s *Server) resolveOutbound(args json.RawMessage) json.RawMessage {
	if s.tokens == nil || len(args) == 0 {
		return args
	}
	return minimize.ResolvePlaceholders(args, s.tokens.Snapshot())
}

// scrubInbound runs the minimizer over an inline, model-bound proxy result. It
// returns the transformed result map and any alerts, having already persisted the
// placeholder→value bindings for tokenized fields. A minimizer error is returned so
// the caller fails closed. When minimization is inactive for this upstream it
// returns the result unchanged.
//
// The whole result envelope is scrubbed as serialized JSON, so a sensitive value
// is caught wherever it sits — a top-level field, structuredContent, or nested
// inside a content[].text string — and the transformed bytes re-parse as JSON.
func (s *Server) scrubInbound(ctx context.Context, upstream, tool string, result map[string]any) (map[string]any, []minimize.Alert, error) {
	if !s.minimizeActive(upstream) {
		return result, nil, nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}
	out, err := s.minimizer.Scan(ctx, minimize.ScanInput{
		Payload:   raw,
		Upstream:  upstream,
		Tool:      tool,
		Direction: minimize.ToModel,
		Policy:    s.minimizePolicyFor(upstream),
	})
	if err != nil {
		return nil, nil, err
	}
	if s.tokens != nil && len(out.Tokens) > 0 {
		_ = s.tokens.Put(out.Tokens)
	}
	var scrubbed map[string]any
	if err := json.Unmarshal(out.Transformed, &scrubbed); err != nil {
		// The transform broke the JSON envelope — fail closed rather than return a
		// malformed (or the raw un-scrubbed) result.
		return nil, nil, err
	}
	return scrubbed, out.Alerts, nil
}

// minimizeAlertEvents turns minimizer alerts into audit events, so a detection
// shows up in /admin/runs and the console run detail alongside egress events.
func minimizeAlertEvents(alerts []minimize.Alert) []sandbox.AuditEvent {
	if len(alerts) == 0 {
		return nil
	}
	out := make([]sandbox.AuditEvent, 0, len(alerts))
	for _, a := range alerts {
		reason := a.Type
		if a.Note != "" {
			reason += ": " + a.Note
		}
		out = append(out, sandbox.AuditEvent{Event: "minimize_alert", Reason: reason})
	}
	return out
}
