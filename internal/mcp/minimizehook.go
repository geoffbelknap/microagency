package mcp

import (
	"context"
	"encoding/json"
	"log"

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

// defaultMinimizePolicy is the secure-by-default effective policy for an upstream
// with no explicit one: every high-confidence type is protected, at the safe action
// that preserves the most utility. tokenize keeps a resolvable placeholder for
// identifiers the model may pass back (account/card); redact masks the rest, keeping
// a last-4 hint where the redactor can (ssn/phone). Direct identifiers — including
// SSN and DOB — redact rather than merely alert: a secure default must not leave a
// raw identifier in front of the model, so "alert" (visible-but-flagged) is an
// opt-IN the operator sets explicitly, not the default. The operator opts DOWN by
// setting an explicit policy. Detectors only fire on what they're confident about,
// so an upstream with no sensitive fields is untouched.
var defaultMinimizePolicy = map[string]string{
	"secret": "redact", "health": "redact",
	"ssn": "redact", "dob": "redact",
	"account": "tokenize", "card": "tokenize",
	"email": "redact", "phone": "redact", "address": "redact", "name": "redact",
}

var defaultMinimizePolicyJSON, _ = json.Marshal(defaultMinimizePolicy)

// minimizePolicyFor returns the policy applied to an upstream: the operator's
// explicit one if set (an explicit empty "{}" means opted out), else the secure
// default when enabled, else none.
func (s *Server) minimizePolicyFor(upstream string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw, ok := s.minimizePolicies[upstream]; ok {
		return raw // explicit (possibly "{}" = opted out)
	}
	if s.secureDefault {
		return defaultMinimizePolicyJSON
	}
	return nil
}

// minimizeActive reports whether a minimizer is installed AND the effective policy
// has at least one type (an opted-out "{}" or an absent policy without secure-
// default is inactive) — the cheap guard the hot path checks before doing any work.
func (s *Server) minimizeActive(upstream string) bool {
	if s.minimizer == nil {
		return false
	}
	return len(s.minimizePolicyFor(upstream)) > len("{}")
}

// resolveOutbound restores tokenized placeholders in model-authored arguments to
// their real values before the call is dialed — the return path for tokenized
// fields. It resolves ONLY bindings scoped to this caller (principal) AND this
// destination upstream: a placeholder minted from upstream X for principal P is
// inert on a call to any other upstream or by any other principal, so a model can't
// replay a secret it saw from X by handing the placeholder to upstream Y. The audit
// records the resolved args (audit means audit); the model only authored the
// placeholder.
func (s *Server) resolveOutbound(ctx context.Context, upstream string, args json.RawMessage) json.RawMessage {
	if s.tokens == nil || len(args) == 0 {
		return args
	}
	scope := minimize.TokenScope{Owner: principalOf(ctx).Subject, Upstream: upstream}
	return minimize.ResolvePlaceholders(args, s.tokens.Snapshot(scope))
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
func (s *Server) scrubInbound(ctx context.Context, upstream, tool string, result map[string]any) (map[string]any, []minimize.Alert, int, error) {
	if !s.minimizeActive(upstream) {
		return result, nil, 0, nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, nil, 0, err
	}
	out, err := s.minimizer.Scan(ctx, minimize.ScanInput{
		Payload:   raw,
		Upstream:  upstream,
		Tool:      tool,
		Direction: minimize.ToModel,
		Policy:    s.minimizePolicyFor(upstream),
		Salt:      s.tokenSalt,
	})
	if err != nil {
		return nil, nil, 0, err
	}
	if s.tokens != nil && len(out.Tokens) > 0 {
		// Scope the bindings to the principal this result is surfaced to and the
		// upstream that produced them — so they resolve only on that principal's calls
		// back to this same upstream.
		scope := minimize.TokenScope{Owner: principalOf(ctx).Subject, Upstream: upstream}
		if err := s.tokens.Put(scope, out.Tokens); err != nil {
			// A dropped binding means a placeholder the model later echoes back won't
			// resolve to its real value on the outbound call — surface it rather than
			// fail silently at a distance.
			log.Printf("microagency: persist minimizer token bindings for %s: %v", upstream, err)
		}
	}
	var scrubbed map[string]any
	if err := json.Unmarshal(out.Transformed, &scrubbed); err != nil {
		// The transform broke the JSON envelope — fail closed rather than return a
		// malformed (or the raw un-scrubbed) result.
		return nil, nil, 0, err
	}
	return scrubbed, out.Alerts, out.Protected, nil
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
