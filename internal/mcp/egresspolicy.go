package mcp

import (
	"net/url"
	"sort"
)

// EgressPolicy is the computed set of governed data hosts: the single source of
// truth for what the gateway is permitted to reach — the host of every ENABLED
// upstream's URL.
//
// This is the READ-ONLY foundation of the dynamic runtime egress allowlist —
// the "computed policy" half. It deliberately builds no proxy, hook, or
// enforcement path; host-side enforcement is a separate slice that CONSUMES this
// policy as its source of truth (so the agent's parallel-egress path is closed
// against exactly the hosts the gateway itself governs, and nothing wider).
type EgressPolicy struct {
	// Hosts is the deduped, sorted union of every governed host.
	Hosts []string `json:"hosts"`
	// Contributors maps each host to the sources/upstreams that put it in the
	// policy — the provenance an operator needs to reason about the allowlist.
	Contributors map[string][]EgressContributor `json:"contributors"`
}

// EgressContributor records one reason a host is in the policy: an enabled
// upstream (via its URL host).
type EgressContributor struct {
	Kind string `json:"kind"` // "upstream"
	Name string `json:"name"` // upstream name
}

// EgressPolicy computes the deduped, sorted set of governed data hosts: the host
// of every ENABLED upstream's URL. Discovered-but-not-enabled upstreams are
// excluded (they are findable, not invocable, so they govern no egress yet).
// Upstream URLs that fail to parse — or parse to an empty host — are skipped
// rather than emitting a bogus allowlist entry.
func (s *Server) EgressPolicy() EgressPolicy {
	contrib := make(map[string][]EgressContributor)
	add := func(host, kind, name string) {
		if host == "" {
			return
		}
		contrib[host] = append(contrib[host], EgressContributor{Kind: kind, Name: name})
	}

	// The host of every ENABLED upstream's URL. Discovered upstreams are findable
	// but not invocable, so they contribute no governed egress.
	for _, up := range s.UpstreamList() {
		if up.State != "enabled" {
			continue
		}
		add(upstreamHost(up.URL), "upstream", up.Name)
	}

	hosts := make([]string, 0, len(contrib))
	for host := range contrib {
		hosts = append(hosts, host)
		// Stable, deterministic contributor ordering for a given host.
		sort.Slice(contrib[host], func(i, j int) bool {
			if contrib[host][i].Kind != contrib[host][j].Kind {
				return contrib[host][i].Kind < contrib[host][j].Kind
			}
			return contrib[host][i].Name < contrib[host][j].Name
		})
	}
	sort.Strings(hosts)
	return EgressPolicy{Hosts: hosts, Contributors: contrib}
}

// upstreamHost extracts the bare host (no port) from an upstream URL, returning
// "" if the URL cannot be parsed or carries no host — the caller skips empties
// so a malformed registration never widens the allowlist.
func upstreamHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
