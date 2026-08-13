---
title: Operation and resource grants
description: Exact caller, operation, argument, resource, destination, and budget authority for shared gateways.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-13_

Operation grants are an opt-in invocation boundary for shared gateways. A
grant belongs to one signed token subject and campaign, names one connection
and one exact upstream tool, and carries finite time, request, byte, and rate
limits. The MCP request can exercise a grant but cannot select or widen it.

Start a gateway-wide deny-by-default deployment with an external issuer:

```sh
microagency up --issuer https://issuer.example \
  --audience microagency --high-assurance-multi-user
```

The issuer's access token must contain `sub` and a signed `campaign` or
`campaign_id` claim. Built-in OAuth is single-user and does not issue campaign
authority, so this mode requires `--issuer`.

Set grants through the loopback operator API. This example permits one read of
one repository until the stated expiry:

```sh
IFS= read -r MICROAGENCY_OPERATOR_TOKEN < ~/.microagency/token
curl -fsS http://127.0.0.1:8766/admin/upstreams/github/grants \
  -H "Authorization: Bearer $MICROAGENCY_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "grants": [{
      "version": "microagency.grant/v1",
      "id": "read-one-repository",
      "connection": "github",
      "tool": "get-repository",
      "effect": "read",
      "principal": "user-123",
      "campaign": "review-2026-08",
      "expires_at": "2026-08-14T00:00:00Z",
      "arguments": [{
        "pointer": "/repository",
        "required": true,
        "values": ["example/project"]
      }],
      "resources": [{
        "kind": "repository",
        "namespace": "github",
        "argument": "/repository"
      }],
      "max_requests": 1,
      "max_bytes": 4096,
      "max_response_bytes": 2048,
      "rate": {"requests": 1, "window_seconds": 60},
      "high_assurance": true
    }]
  }'
unset MICROAGENCY_OPERATOR_TOKEN
```

Grant JSON is strict. Unknown or duplicate fields are rejected. Arguments are
default-deny: every scalar leaf must be covered by an exact JSON pointer and an
exact value, a bounded regular expression, or a URL target. Extra fields,
duplicate JSON keys, missing required values, expired grants, and effect
mismatches are refused before upstream egress.

## URL targets

A URL argument needs a named target:

```json
{
  "arguments": [{
    "pointer": "/url",
    "required": true,
    "url_target": "report"
  }],
  "url_targets": [{
    "id": "report",
    "origins": ["https://reports.example"],
    "paths": ["/exports/approved"],
    "query": {"version": ["1"]}
  }]
}
```

Origins are HTTPS DNS names; literal IPs are refused. Paths must use one
normalized encoding. Query parameters default to none and, when present, must
match the exact canonical key/value set in the grant. microagency disables
environment proxies for untrusted outbound requests, checks the initial URL
and every redirect, and checks the resolved address again at connect time to
stop internal-address and DNS-rebinding escapes.

An upstream response that contains an off-platform download URL is withheld in
governed mode unless the grant includes a URL target with the reserved ID
`offload`. Set that target's `redirect` field to `true` only when redirects to
every listed destination are intended.

For a URL-fetching MCP tool, the grant constrains the exact argument sent to
the upstream. Egress performed inside a remote MCP server is outside the
gateway process; apply an egress policy at that server too when its internal
redirect behavior must be constrained.

## Shared credentials and writable resources

An unowned connection uses one credential across callers. A grant can use it
only with `allow_shared_credential: true`. A write grant also needs at least one
resource namespace. Writes through a shared connection require
`shared_writable: true` on every resource; this is never inferred.

Resource values are not copied into the decision ledger. microagency derives
an opaque identifier from the principal, campaign, resource kind, namespace,
and value. Only an explicit `shared_writable` resource omits the principal from
that privacy scope. Private resources therefore do not become a cross-principal
object channel through audit state.

## Decision ledger and budgets

Before any governed upstream call, microagency reserves the request and
declared response bytes, checks the request and rate limits, and fsyncs a signed
authorization decision. It then updates a signed head anchor in the secret
store. If the ledger, signer, anchor, or existing chain is unavailable, the
call does not cross the gateway.

Refusals record the principal, campaign, grant ID and digest when present,
connection, operation, and reason. Authorized records add the effect, reserved
bytes, and opaque resource IDs. Raw arguments and upstream results stay out of
this ledger. Verify it with:

```text
GET /admin/decisions/verify
```

The ledger is `~/.microagency/decision-ledger.jsonl`. Its budget counters and
anchor survive restart, so restarting the gateway does not replenish a grant.

Adding any grants to one connection governs that connection. The
`--high-assurance-multi-user` flag makes the rule gateway-wide: connections
without a matching high-assurance grant are deny-all. In either posture, the
agent still sees exactly `find_tools`, `call_tool`, and `reduce`.
