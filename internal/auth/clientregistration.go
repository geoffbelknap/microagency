package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Dynamic client registration (RFC 7591) is how a remote MCP client obtains a
// client_id without an operator provisioning one by hand, and it is the reason
// pasting a gateway URL into a client is the whole setup story. It is also an
// unauthenticated write to state that persists across restarts, which is a thing
// a public gateway should be able to bound and to switch off.
//
// The posture is declared, never inferred. A deployment that pre-provisions its
// clients says so, and both the startup banner and doctor state which mode is in
// effect beside who may sign in — the two halves of "who can get in here" read
// together or not at all.

// RegistrationMode declares who may obtain an OAuth client from the built-in
// authorization server.
type RegistrationMode string

const (
	// RegistrationBounded accepts anonymous registrations within
	// RegistrationLimits. It is the default: a client that cannot register
	// cannot connect without an operator provisioning it first, and that is a
	// worse default for the common case than a bounded open endpoint.
	RegistrationBounded RegistrationMode = "bounded"
	// RegistrationOff refuses every registration. Clients are provisioned by
	// the operator, the authorization server stops advertising a registration
	// endpoint, and the account portal is not served: it obtains its own client
	// by registering, so it has no way in on a gateway that refuses to register
	// anyone.
	RegistrationOff RegistrationMode = "off"
)

// ParseRegistrationMode resolves an operator-supplied mode name. An empty value
// is the default rather than an error, so the flag can be omitted.
func ParseRegistrationMode(raw string) (RegistrationMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return RegistrationBounded, nil
	case string(RegistrationBounded):
		return RegistrationBounded, nil
	case string(RegistrationOff):
		return RegistrationOff, nil
	default:
		return "", fmt.Errorf("client registration mode %q is not one of: bounded, off", raw)
	}
}

// RegistrationLimits bounds what RegistrationBounded accepts.
//
// Two rate windows rather than one. PerSourcePerHour is the meaningful bound on
// a directly-reachable bind, where sources are distinct. Behind a tunnel every
// request arrives from the tunnel process, so every caller looks like one
// source and that bound stops separating anyone — PerHour is what still holds
// there. Neither is derived from a forwarded-for header: that header is supplied
// by the caller, and a limiter keyed on a value the caller chooses is not a
// limiter.
type RegistrationLimits struct {
	// PerSourcePerHour caps registrations from one network source per hour.
	PerSourcePerHour int
	// PerHour caps registrations from all sources per hour.
	PerHour int
	// MaxClients caps how many registrations may exist at once.
	MaxClients int
	// UnusedTTL is how long a registration that never completed a flow is kept.
	// A client that has exchanged a code is a real client and is kept for as
	// long as the deployment does; one that registered and never came back is
	// the growth this bounds.
	UnusedTTL time.Duration
	// MaxTrackedSources caps the rate table itself, so the limiter cannot be
	// turned into unbounded memory by rotating source addresses. Once full, a
	// source with no existing window is refused rather than admitted untracked.
	MaxTrackedSources int
}

// DefaultRegistrationLimits are the bounds a gateway runs with unless an
// operator narrows them. They are generous for real clients — a person
// connecting a handful of MCP clients never approaches them — and small enough
// that an unattended endpoint cannot grow without bound.
func DefaultRegistrationLimits() RegistrationLimits {
	return RegistrationLimits{
		PerSourcePerHour:  10,
		PerHour:           60,
		MaxClients:        4096,
		UnusedTTL:         24 * time.Hour,
		MaxTrackedSources: 4096,
	}
}

// Describe renders the posture as one line for the startup banner and doctor.
// It states the limits rather than only the mode name, because "bounded" on its
// own tells an operator nothing about what the bound is.
func (m RegistrationMode) Describe(limits RegistrationLimits) string {
	if m == RegistrationOff {
		return "off — clients must be provisioned by the operator; /oauth/register refuses, and the account portal is not served"
	}
	return fmt.Sprintf("bounded — any client may register: %d/hour per source, %d/hour total, %d at once, unused expire after %s",
		limits.PerSourcePerHour, limits.PerHour, limits.MaxClients, shortDuration(limits.UnusedTTL))
}

func shortDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 && d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}

// Registration outcomes. A closed set, so an operator reading the audit log or a
// tool filtering it branches on the event name instead of parsing a sentence.
const (
	RegistrationAccepted         = "registered"
	RegistrationRefusedDisabled  = "registration_refused_disabled"
	RegistrationRefusedRate      = "registration_refused_rate"
	RegistrationRefusedCapacity  = "registration_refused_capacity"
	RegistrationRefusedMalformed = "registration_refused_malformed"
)

// RegistrationEvent is one registration decision, for the audit log.
//
// It carries no network address. SourceDigest distinguishes one source from
// another — which is what an operator looking at growth needs — without the log
// accumulating the addresses of everyone who ever probed the endpoint.
type RegistrationEvent struct {
	// Outcome is one of the Registration* constants above.
	Outcome string
	// ClientID is the client that was created, empty on a refusal.
	ClientID string
	// SourceDigest is a short one-way digest of the requesting address.
	SourceDigest string
	// ClientName is the self-declared name from the request, bounded and
	// untrusted — it is whatever the caller sent.
	ClientName string
}

// SetClientRegistration declares the registration posture. Call before Register.
// Zero-valued limit fields fall back to the defaults, so an operator can narrow
// one bound without restating the rest.
func (s *AuthServer) SetClientRegistration(mode RegistrationMode, limits RegistrationLimits) {
	defaults := DefaultRegistrationLimits()
	if limits.PerSourcePerHour <= 0 {
		limits.PerSourcePerHour = defaults.PerSourcePerHour
	}
	if limits.PerHour <= 0 {
		limits.PerHour = defaults.PerHour
	}
	if limits.MaxClients <= 0 {
		limits.MaxClients = defaults.MaxClients
	}
	if limits.UnusedTTL <= 0 {
		limits.UnusedTTL = defaults.UnusedTTL
	}
	if limits.MaxTrackedSources <= 0 {
		limits.MaxTrackedSources = defaults.MaxTrackedSources
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrationMode = mode
	s.registrationLimits = limits
}

// RegistrationPosture reports the declared mode and the limits in effect, for
// the surfaces that state it.
func (s *AuthServer) RegistrationPosture() (RegistrationMode, RegistrationLimits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effectiveRegistrationModeLocked(), s.effectiveRegistrationLimitsLocked()
}

// SetRegistrationRecorder installs the audit sink for registration decisions.
// The authorization server does not own the audit log, so it hands each decision
// to whoever does rather than growing a second one. Call before Register.
func (s *AuthServer) SetRegistrationRecorder(record func(RegistrationEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordRegistration = record
}

func (s *AuthServer) effectiveRegistrationModeLocked() RegistrationMode {
	if s.registrationMode == "" {
		return RegistrationBounded
	}
	return s.registrationMode
}

func (s *AuthServer) effectiveRegistrationLimitsLocked() RegistrationLimits {
	if s.registrationLimits.MaxClients == 0 {
		return DefaultRegistrationLimits()
	}
	return s.registrationLimits
}

// registrationSource is the network address a registration arrived from. It is
// deliberately r.RemoteAddr and never a forwarded-for header: the header is
// caller-supplied, so keying a limit on it lets one caller present as unlimited
// sources. Behind a proxy every caller collapses to one source, which makes the
// per-source bound strict rather than absent, and the global bound still holds.
func registrationSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// sourceDigest is a short one-way digest of a source address, for the audit log.
func sourceDigest(source string) string {
	if source == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("microagency/registration-source\x00" + source))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

// registrationWindow tracks one source's registrations in the current hour, and
// whether a refusal has already been recorded for it.
//
// refused exists because recording every refusal would hand an attacker an
// unbounded append to the audit log: hammering a refusing endpoint would grow
// the file as effectively as registering would have. One refusal per source per
// window is enough for an operator to see that something is trying.
type registrationWindow struct {
	since   time.Time
	count   int
	refused bool
}

// admitRegistrationLocked decides whether one registration may proceed and
// reports the outcome to record when it may not. The caller holds s.mu.
//
// Sweeping expired windows and unused registrations happens here rather than on
// a timer: the endpoint is the only thing that grows this state, so the endpoint
// is where it is bounded, and a gateway nobody registers against does no work.
func (s *AuthServer) admitRegistrationLocked(source string, now time.Time) (outcome string, record bool) {
	limits := s.effectiveRegistrationLimitsLocked()
	if s.registrationRates == nil {
		s.registrationRates = map[string]registrationWindow{}
	}
	for key, window := range s.registrationRates {
		if now.Sub(window.since) >= time.Hour {
			delete(s.registrationRates, key)
		}
	}
	s.expireUnusedClientsLocked(now, limits.UnusedTTL)

	total := 0
	for _, window := range s.registrationRates {
		total += window.count
	}
	window, tracked := s.registrationRates[source]
	if !tracked && len(s.registrationRates) >= limits.MaxTrackedSources {
		// The rate table is full. Admitting an untracked source would make the
		// limit unenforceable for exactly the caller that filled it.
		return RegistrationRefusedRate, true
	}
	if !tracked || now.Sub(window.since) >= time.Hour {
		window = registrationWindow{since: now}
	}
	if window.count >= limits.PerSourcePerHour || total >= limits.PerHour {
		first := !window.refused
		window.refused = true
		s.registrationRates[source] = window
		return RegistrationRefusedRate, first
	}
	if len(s.clients) >= limits.MaxClients {
		first := !window.refused
		window.refused = true
		s.registrationRates[source] = window
		return RegistrationRefusedCapacity, first
	}
	window.count++
	s.registrationRates[source] = window
	return RegistrationAccepted, true
}

// expireUnusedClientsLocked drops registrations that never completed a flow and
// have outlived ttl. A registration that has been used is kept: it belongs to a
// client someone actually connected, and expiring it would break that client's
// cached client_id for no gain. The caller holds s.mu.
func (s *AuthServer) expireUnusedClientsLocked(now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	removed := 0
	for id, client := range s.clients {
		if !client.usedAt.IsZero() || client.createdAt.IsZero() {
			continue // used, or a record from before registrations carried a time
		}
		if now.Sub(client.createdAt) >= ttl {
			delete(s.clients, id)
			removed++
		}
	}
	if removed > 0 {
		s.persistClientsLocked()
	}
}

// markClientUsedLocked records that a client completed a flow, which is what
// takes it out of the unused-expiry population. The caller holds s.mu.
func (s *AuthServer) markClientUsedLocked(clientID string) {
	client, known := s.clients[clientID]
	if !known || !client.usedAt.IsZero() {
		return
	}
	client.usedAt = time.Now()
	s.clients[clientID] = client
	s.persistClientsLocked()
}
