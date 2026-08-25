package mcp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"microagency/internal/gateway"
)

// Two connections instantiated from ONE template are, by construction, identical
// to an agent. Their tools carry the same descriptions and the same input
// schemas, because they are the same upstream software; their qualified names
// differ only by the random suffix the gateway generated when each was created
// (supabase-e7592ae6a9544beb2f__execute_sql against
// supabase-3f81a0c7bb2419de84__execute_sql). A template with max_per_user above
// one invites exactly this — one project for production, one for staging — and
// find_tools cannot rank them apart, because there is no respect in which either
// is the better match. The agent picks one, and which database the statement
// runs against is decided by a coin flip nobody observed.
//
// So the gateway refuses the call. A tool name that resolves to more than one
// connection the caller cannot tell apart is not an instruction the gateway can
// carry out; it is a guess, and executing a guess against a credentialed upstream
// is the failure mode. The remedy ships with the refusal: a connection may carry
// a human-meaningful label, the label is surfaced in the agent's view of the
// tool, and a labelled connection is one the agent can choose ON PURPOSE.
//
// The gate is narrow on purpose. It fires only when two calls would BOTH have
// really worked and landed on different upstreams, which is the only case where
// picking wrong is silent. Everything else is left alone:
//
//   - one candidate — the ordinary case, and the overwhelming majority of calls;
//   - candidates from DIFFERENT templates, which differ in description and schema
//     and are therefore rankable and distinguishable;
//   - a candidate a label already picks out of its group;
//   - a call authorized by a matching operation grant, where the operator named
//     the connection exactly and no guess was made;
//   - candidates the caller cannot invoke anyway — revoked, disabled, not
//     visible, or blocked by the read-only gate — which are not real alternatives.

// ambiguousPeer is one connection a caller cannot tell apart from another.
type ambiguousPeer struct {
	name  string
	label string
}

// maxNamedPeers bounds how many sibling connections a refusal enumerates. A
// template may admit up to maxConnectionsPerUser connections, and a refusal is
// model context like any other payload.
const maxNamedPeers = 4

// connectionVisibleTo reports whether callerKey may see this connection at all.
// It is the connection-level half of the index filter, shared with the
// invocation gate so discovery and invocation cannot disagree about what a
// caller can reach.
func connectionVisibleTo(rec *upstream, callerKey, delegationSubject string) bool {
	if rec.revoked {
		return false
	}
	// A connection scoped to one principal is absent for every other.
	if rec.owner != "" && rec.owner != callerKey {
		return false
	}
	// A delegated connection is usable only by a caller with a verified email
	// to act as; for anyone else it is absent.
	if rec.delegation != nil && delegationSubject == "" {
		return false
	}
	return true
}

// toolIndexable reports whether one tool of a visible connection belongs in this
// caller's index. On an ungoverned connection every tool does; on a governed one
// only the exact operations a live matching grant covers do.
func (s *Server) toolIndexable(rec *upstream, t gateway.Tool, callerKey, campaign string) bool {
	if !s.highAssurance && len(rec.grants) == 0 {
		return true
	}
	grant, ok := matchingGrant(*rec, callerKey, campaign, t.Name)
	if !ok || (s.highAssurance && !grant.HighAssurance) || (rec.owner == "" && !grant.AllowShared) {
		return false
	}
	expires, _ := time.Parse(time.RFC3339, grant.ExpiresAt)
	grantWrites := grant.Effect == effectWrite
	if !time.Now().Before(expires) || grantWrites != isHighAssuranceWriteTool(t) || (rec.readOnly && grantWrites) {
		return false
	}
	if rec.owner == "" && grantWrites {
		if len(grant.Resources) == 0 {
			return false
		}
		for _, resource := range grant.Resources {
			if !resource.SharedWritable {
				return false
			}
		}
	}
	return true
}

// labelDistinguishes reports whether a connection's own label picks it out of
// its tie group. It must HAVE a label, and no peer may carry the same one.
//
// The comparison is case-insensitive: "Prod" and "prod" are two spellings of one
// word, and admitting them as distinct labels would let a second connection
// shadow the first with something a reader cannot tell apart at a glance — the
// same confusability the charset refuses non-ASCII letters to prevent.
func labelDistinguishes(label string, peers []ambiguousPeer) bool {
	if label == "" {
		return false
	}
	for _, peer := range peers {
		if strings.EqualFold(peer.label, label) {
			return false
		}
	}
	return true
}

// callerToolIsInvocable reports whether this caller could actually run tool on
// this connection right now. A candidate that would be refused anyway is not an
// alternative the caller might have meant, so it must not widen a tie group.
func (s *Server) callerToolIsInvocable(rec *upstream, t gateway.Tool, callerKey, campaign string) bool {
	if !rec.enabled {
		return false
	}
	if rec.readOnly && isWriteTool(t) {
		return false
	}
	return s.toolIndexable(rec, t, callerKey, campaign)
}

// indistinguishablePeers returns the OTHER connections this caller cannot tell
// apart from name for tool: same template, same upstream tool, and invocable for
// this caller. The result is sorted by connection name so a refusal reads the
// same way twice.
//
// It takes s.reg.mu, so callers must not already hold it.
func (s *Server) indistinguishablePeers(callerKey, campaign, name string, rec upstream, tool string) []ambiguousPeer {
	// Only template-instantiated connections can be siblings. Two connections an
	// operator registered by hand have distinct operator-chosen names and
	// generally distinct upstreams; they are not the accidental twins this gate
	// exists for.
	if rec.template == "" || !rec.enabled || rec.revoked {
		return nil
	}
	delegationSubject := s.delegationSubjectForKey(callerKey)
	s.reg.mu.Lock()
	defer s.reg.mu.Unlock()
	// The named connection must itself be invocable for this caller, or the more
	// specific gate that will refuse it (read-only, ungranted) owns the message.
	self, ok := s.reg.conns[name]
	if !ok {
		return nil
	}
	selfTool, ok := toolNamed(self.tools, tool)
	if !ok || !s.callerToolIsInvocable(self, selfTool, callerKey, campaign) {
		return nil
	}
	var peers []ambiguousPeer
	for peerName, peer := range s.reg.conns {
		if peerName == name || peer.template != self.template {
			continue
		}
		if !connectionVisibleTo(peer, callerKey, delegationSubject) {
			continue
		}
		peerTool, ok := toolNamed(peer.tools, tool)
		if !ok || !s.callerToolIsInvocable(peer, peerTool, callerKey, campaign) {
			continue
		}
		peers = append(peers, ambiguousPeer{name: peerName, label: peer.label})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].name < peers[j].name })
	return peers
}

// toolNamed finds an advertised tool by its un-namespaced name.
func toolNamed(tools []gateway.Tool, name string) (gateway.Tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return gateway.Tool{}, false
}

// ambiguousCallRefusal writes the refusal an agent receives when it named a tool
// that resolves to a connection it could not have chosen deliberately.
//
// It names the sibling connections. That is safe here and nowhere else: every
// connection listed passed the same visibility test the caller's own index uses,
// so the refusal discloses only what find_tools already showed this caller. The
// cross-principal case is the opposite — there the refusal must stay
// indistinguishable from an unknown tool, and it does.
func ambiguousCallRefusal(qualified, connection, template, tool, label string, owned bool, peers []ambiguousPeer) map[string]any {
	var b strings.Builder
	fmt.Fprintf(&b, "tool %q is ambiguous and was not run. ", qualified)
	named := peers
	extra := 0
	if len(named) > maxNamedPeers {
		extra = len(named) - maxNamedPeers
		named = named[:maxNamedPeers]
	}
	names := make([]string, 0, len(named)+1)
	names = append(names, fmt.Sprintf("%q", connection))
	for _, peer := range named {
		names = append(names, fmt.Sprintf("%q", peer.name))
	}
	fmt.Fprintf(&b, "Connections %s", joinWords(names))
	if extra > 0 {
		fmt.Fprintf(&b, " (and %d more)", extra)
	}
	fmt.Fprintf(&b, " all come from template %q and expose an identical %q, so this call could have meant any of them.", template, tool)
	// Say why the labels present did not settle it, rather than implying none exist.
	if label == "" {
		b.WriteString(" This connection carries no label, so there is nothing to choose it by.")
	} else {
		fmt.Fprintf(&b, " More than one is labelled %q, which does not tell them apart.", label)
	}
	if owned {
		b.WriteString(" Give each connection a distinct label — PATCH /connections/{name} with {\"label\":\"...\"} — then call the one you mean.")
	} else {
		b.WriteString(" These connections are operator-managed: ask the operator to give each a distinct label, then call the one you mean.")
	}
	b.WriteString(" A call authorized by an operation grant naming the connection is not ambiguous and is not refused.")
	return toolError("%s", b.String())
}

// joinWords renders a list as "a", "a and b", or "a, b and c".
func joinWords(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// indexCandidate is one indexed tool entry considered for a tie group: the entry
// the caller will see, plus the label that could pick it out of the group.
type indexCandidate struct {
	entry map[string]any
	label string
}

// markAmbiguousCandidates flags every indexed entry a caller could not choose
// deliberately — one of several same-template, same-tool candidates whose own
// label does not pick it out of the group. The flag is a typed field the agent
// can branch on, so the tie is learnable at discovery time rather than only from
// the refusal that follows a guess.
func markAmbiguousCandidates(groups map[string][]*indexCandidate) {
	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		for i, candidate := range group {
			peers := make([]ambiguousPeer, 0, len(group)-1)
			for j, other := range group {
				if i != j {
					peers = append(peers, ambiguousPeer{label: other.label})
				}
			}
			if !labelDistinguishes(candidate.label, peers) {
				candidate.entry["ambiguous"] = true
			}
		}
	}
}
