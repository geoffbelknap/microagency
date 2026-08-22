package safedial

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// alwaysRefused reports whether ip may never be dialed, even for an
// operator-declared destination. Cloud metadata services live on link-local
// addresses (169.254.169.254, and fd00:ec2::254 on IPv6), and reaching one
// hands out the host's cloud credentials. No MCP server legitimately listens
// there, so no operator declaration can unlock it. Unspecified and multicast
// addresses are refused for the same reason: they are never a real upstream.
// A nil (unparseable) IP is refused — fail closed.
func alwaysRefused(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// AWS IPv6 instance metadata.
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}

// Destination is one operator-declared upstream address that may be private.
// It is derived from the connection's own URL, so there is no second field to
// drift out of sync with the endpoint actually being dialed.
type Destination struct {
	host string // declared hostname, or the literal IP as written
	ip   net.IP // non-nil when host is a literal IP
	port string
}

// ParseDestination derives the destination from an upstream URL. It refuses a
// URL whose address may never be dialed, so an operator cannot declare the
// metadata service as a connection endpoint.
func ParseDestination(raw string) (Destination, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return Destination{}, fmt.Errorf("safedial: bad destination URL %q: %w", raw, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return Destination{}, fmt.Errorf("safedial: destination must be an http(s) URL")
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return Destination{}, fmt.Errorf("safedial: destination URL has no host")
	}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	d := Destination{host: host, ip: net.ParseIP(host), port: port}
	if d.ip != nil && alwaysRefused(d.ip) {
		return Destination{}, fmt.Errorf("safedial: address %s may never be an upstream destination", host)
	}
	return d, nil
}

// permits reports whether a concrete connect-time address is the declared
// destination. The port must match exactly. A destination written as a literal
// IP permits only that IP; a destination written as a hostname permits only the
// addresses that name currently resolves to, so a name that starts resolving
// elsewhere fails closed rather than widening the permission.
func (d Destination) permits(ip net.IP, port string) bool {
	if ip == nil || port != d.port {
		return false
	}
	if d.ip != nil {
		if d.ip.Equal(ip) {
			return true
		}
		// Loopback is one host. A destination declared as 127.0.0.1 and reached
		// as ::1 — because the connector advertises itself as "localhost" — is
		// the same machine, and refusing it is confusing without being safer.
		return d.ip.IsLoopback() && ip.IsLoopback()
	}
	resolved, err := net.LookupIP(d.host)
	if err != nil {
		return false
	}
	for _, candidate := range resolved {
		if candidate.Equal(ip) {
			return true
		}
	}
	return false
}

// matchesURL reports whether target names this same destination, so a redirect
// to a different private address is refused even within the permitted origin.
func (d Destination) matchesURL(target *url.URL) bool {
	if target == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host == d.host && port == d.port
}

// permitsLoopbackURL extends matchesURL with the same one-host rule: a declared
// loopback destination covers any loopback literal on the same port.
func (d Destination) permitsLoopbackURL(ip net.IP, target *url.URL) bool {
	if d.ip == nil || !d.ip.IsLoopback() || !ip.IsLoopback() {
		return false
	}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return port == d.port
}

// GuardedClientForDestination returns a client with GuardedClient's SSRF posture,
// except that connections to one operator-declared destination are permitted even
// when it is loopback or otherwise private. Everything else stays refused, and the
// addresses in alwaysRefused stay refused for this client too.
//
// This exists because an operator-registered connection is not the untrusted input
// the guard defends against: a gateway deployed next to the systems it serves must
// be able to reach a sidecar connector or an internal MCP server, while a URL
// supplied by a principal must not.
func GuardedClientForDestination(dialTimeout, requestTimeout time.Duration, dest Destination) *http.Client {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	if requestTimeout <= 0 {
		requestTimeout = 5 * time.Minute
	}
	dialer := &net.Dialer{Timeout: dialTimeout, Control: destinationGuard(dest)}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: requestTimeout,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: destinationTransport{base: transport, dest: dest},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("safedial: stopped after 10 redirects")
			}
			if len(via) > 0 && canonicalOrigin(req.URL) != canonicalOrigin(via[0].URL) {
				return fmt.Errorf("safedial: redirect target origin %q is not the original origin", canonicalOrigin(req.URL))
			}
			return validateDestinationTarget(req.URL, dest)
		},
	}
}

func destinationGuard(dest Destination) func(string, string, syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("safedial: bad address %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if alwaysRefused(ip) {
			return fmt.Errorf("safedial: refusing connection to %s — never a permitted destination", host)
		}
		if !isInternal(ip) {
			return nil
		}
		if dest.permits(ip, port) {
			return nil
		}
		return fmt.Errorf("safedial: refusing connection to internal address %s (SSRF guard)", host)
	}
}

type destinationTransport struct {
	base http.RoundTripper
	dest Destination
}

func (t destinationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validateDestinationTarget(req.URL, t.dest); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func validateDestinationTarget(target *url.URL, dest Destination) error {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil {
		return fmt.Errorf("safedial: target must be an http(s) URL without embedded credentials")
	}
	if ip := net.ParseIP(target.Hostname()); ip != nil && isInternal(ip) {
		if alwaysRefused(ip) || !(dest.matchesURL(target) || dest.permitsLoopbackURL(ip, target)) {
			return fmt.Errorf("safedial: refusing URL with internal address %s (SSRF guard)", target.Hostname())
		}
	}
	return nil
}
