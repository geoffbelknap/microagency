// Package minimize is the field-level minimization substrate: a boundary where
// pluggable modules scrutinize, redact, tokenize, or alert on sensitive field
// values before a payload crosses into (or back out of) the model's context.
//
// It is the fine-grained complement to reference-by-default. Reference-by-default
// is coarse and size-triggered — park the whole payload when it's large. A
// minimizer is content-triggered and field-level: a small, useful result can pass
// through with just its sensitive values transformed, so the model keeps the
// structure it needs without ever seeing the raw value.
//
// A Module is the pluggable unit. The intended implementation is a wasm module
// (see WasmModule): sandboxed with no network and no host state, so an operator
// can run an UNTRUSTED third-party detector over their most sensitive data and it
// is provably unable to leak what it inspects. Enforcement runs in mediation, not
// the agent (ASK tenet 1): the model can neither invoke nor perceive the pass.
package minimize

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Action is what a policy decides to do with a detected field value. It is
// advisory to the substrate — a Module encodes its own policy — but these are the
// vocabulary the four capabilities share.
type Action string

const (
	ActionPass     Action = "pass"     // leave the value untouched
	ActionRedact   Action = "redact"   // mask the value (lossy; model can't correlate)
	ActionTokenize Action = "tokenize" // swap for a stable placeholder resolvable operator-side
	ActionAlert    Action = "alert"    // leave the value, flag it to the operator
)

// Direction is which way a payload is crossing the boundary.
type Direction string

const (
	// ToModel: an upstream tool result heading into model context — the scrub point.
	ToModel Direction = "egress"
	// ToUpstream: model-authored arguments heading to an upstream — where tokenized
	// placeholders are resolved back to real values before the call is dialed.
	ToUpstream Direction = "ingress"
)

// ScanInput is one payload handed to a minimizer, with the context a module needs
// to apply per-upstream, per-tool, per-direction policy.
type ScanInput struct {
	Payload   []byte
	Upstream  string
	Tool      string
	Direction Direction
	// Policy is opaque, module-defined configuration (e.g. a type→action map). The
	// substrate passes it through verbatim.
	Policy []byte
	// Salt is a per-session secret the substrate supplies so a tokenizing module can
	// derive placeholders as a KEYED hash of the value — unguessable to an agent that
	// sees only the placeholder. It is never returned to the model. Stable within a
	// session so the same value yields the same placeholder (the model can correlate);
	// unknown to the model, so low-entropy values can't be brute-forced.
	Salt string
}

// Token is a placeholder a module substituted for a raw value. Mediation persists
// placeholder→value (owner-scoped, see refstore) so the return path can restore
// it; the model only ever sees the placeholder.
type Token struct {
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
	Type        string `json:"type,omitempty"`
	Path        string `json:"path,omitempty"`
}

// Alert is a detection a module flagged without transforming — the "scrutinize /
// alert on" capability. Mediation routes these to the audit chain and console.
type Alert struct {
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Path     string `json:"path,omitempty"`
	Note     string `json:"note,omitempty"`
}

// ScanResult is a module's output: the payload to forward, the placeholder
// bindings to persist, and the detections to surface.
type ScanResult struct {
	Transformed []byte
	Tokens      []Token
	Alerts      []Alert
	// Protected is the number of field values this scan hid (redacted or tokenized).
	// It's the minimization impact the gateway records so the work is visible in the
	// metrics, not just felt in the (scrubbed) output.
	Protected int
}

// Module is one pluggable minimizer. Implementations MUST be pure functions of the
// input with no external effects; WasmModule gets that guarantee from the sandbox
// by construction.
type Module interface {
	Name() string
	Scan(ctx context.Context, in ScanInput) (ScanResult, error)
}

// Func adapts a plain function to Module (for Go-native modules and tests).
type Func struct {
	N string
	F func(ctx context.Context, in ScanInput) (ScanResult, error)
}

func (f Func) Name() string { return f.N }

func (f Func) Scan(ctx context.Context, in ScanInput) (ScanResult, error) { return f.F(ctx, in) }

// Pipeline runs an ordered chain of modules over one payload: each module sees the
// previous module's transformed output, and tokens and alerts accumulate. It is
// FAIL-CLOSED (ASK tenet 4): if any module errors, Scan returns the error and no
// payload, so mediation must withhold the data rather than emit it un-minimized.
type Pipeline struct {
	Modules []Module
}

// Name identifies the pipeline as a composite module (it satisfies Module, so a
// pipeline can be installed anywhere a single module is expected).
func (p Pipeline) Name() string { return "pipeline" }

// Scan runs the chain. A module that only detects returns the payload unchanged;
// the substrate never invents a transform.
func (p Pipeline) Scan(ctx context.Context, in ScanInput) (ScanResult, error) {
	cur := in.Payload
	var tokens []Token
	var alerts []Alert
	protected := 0
	for _, m := range p.Modules {
		r, err := m.Scan(ctx, ScanInput{
			Payload: cur, Upstream: in.Upstream, Tool: in.Tool,
			Direction: in.Direction, Policy: in.Policy, Salt: in.Salt,
		})
		if err != nil {
			return ScanResult{}, fmt.Errorf("minimize: module %q: %w", m.Name(), err)
		}
		cur = r.Transformed
		tokens = append(tokens, r.Tokens...)
		alerts = append(alerts, r.Alerts...)
		protected += r.Protected
	}
	return ScanResult{Transformed: cur, Tokens: tokens, Alerts: alerts, Protected: protected}, nil
}

// TokenScope binds a placeholder to the context it is valid in: the principal the
// tokenized value was surfaced to, and the upstream that produced it. Resolution is
// allowed ONLY on a call by the same principal back to the same upstream. This is
// what stops a replay: a placeholder a model received from a protected upstream X is
// inert in any other principal's context AND on a call to any other upstream, so the
// model cannot hand it to an attacker-controlled upstream Y and have mediation
// substitute the raw secret before egress.
type TokenScope struct {
	Owner    string // principal subject the value was surfaced to ("" = shared/local)
	Upstream string // upstream that produced the value
}

// TokenStore persists placeholder→value bindings, scoped, so the return path
// (model-authored args → real values) can resolve them only within the scope that
// minted them. Implementations are operator-side and owner-scoped — the same custody
// model as the refstore (see #21). A binding is idempotent within a scope.
type TokenStore interface {
	Put(scope TokenScope, tokens []Token) error
	Resolve(scope TokenScope, placeholder string) (value string, ok bool)
	// Snapshot returns a copy of the bindings VISIBLE TO scope, for bulk resolution.
	Snapshot(scope TokenScope) map[string]string
}

// MemTokenStore is an in-memory TokenStore for the MVP; a persisted, encrypted,
// owner-scoped store replaces it behind this interface without touching callers.
// Bindings are keyed by (scope, placeholder) so the same value tokenized under two
// scopes stays two independent bindings — resolving in one never reaches the other.
type MemTokenStore struct {
	mu sync.Mutex
	m  map[string]map[string]string // scopeKey → placeholder → value
}

// NewMemTokenStore returns an empty store.
func NewMemTokenStore() *MemTokenStore { return &MemTokenStore{m: map[string]map[string]string{}} }

// scopeKey is the map key for a scope. The NUL separator can't appear in a principal
// subject or upstream name, so distinct scopes never collide.
func scopeKey(sc TokenScope) string { return sc.Owner + "\x00" + sc.Upstream }

func (s *MemTokenStore) Put(scope TokenScope, tokens []Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := scopeKey(scope)
	bucket := s.m[k]
	if bucket == nil {
		bucket = map[string]string{}
		s.m[k] = bucket
	}
	for _, t := range tokens {
		if t.Placeholder != "" {
			bucket[t.Placeholder] = t.Value
		}
	}
	return nil
}

func (s *MemTokenStore) Resolve(scope TokenScope, placeholder string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[scopeKey(scope)][placeholder]
	return v, ok
}

func (s *MemTokenStore) Snapshot(scope TokenScope) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.m[scopeKey(scope)]
	out := make(map[string]string, len(bucket))
	for k, v := range bucket {
		out[k] = v
	}
	return out
}

// ResolvePlaceholders substitutes every binding found in payload back to its raw
// value — the return path for tokenized fields, applied to model-authored args
// before an upstream call. Longest placeholders are replaced first so one
// placeholder can never be a prefix-clobbered fragment of another.
func ResolvePlaceholders(payload []byte, bindings map[string]string) []byte {
	if len(bindings) == 0 {
		return payload
	}
	keys := make([]string, 0, len(bindings))
	for k := range bindings {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	s := string(payload)
	for _, k := range keys {
		if k != "" && strings.Contains(s, k) {
			s = strings.ReplaceAll(s, k, bindings[k])
		}
	}
	return []byte(s)
}
