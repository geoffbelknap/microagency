---
title: The security model
description: Each guarantee microagency makes, and where it is enforced.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-13_

The guarantees, and where each one is enforced:

- **Credential custody.** Upstream tokens and OAuth refresh tokens live in
  the gateway's secret store — OpenBao/Vault when available, else an
  operator-key encrypted file or an explicitly degraded mode-0600 plaintext
  fallback (see
  [where credentials live](connect-clients.md#where-credentials-live)).
  Managed OpenBao can keep its unseal and AppRole bootstrap in macOS Keychain,
  Linux Secret Service, or an operator KMS helper. The initial root token is
  revoked after narrow AppRole provisioning; protected-provider failure stops
  startup instead of selecting another credential store.
  Nothing in the agent's config, context, or tool results can reveal them.
- **Least privilege.** A connection can be read-only, narrowed to specific
  OAuth scopes, restricted to one user (`owner`), or held in the index as
  discovered — findable but not invocable until an operator enables it.
  Self-service users can instantiate only operator-approved templates; the
  provider URL, scopes, curated provider parameters, and per-user quota are
  bounded before an OAuth flow starts. Their token, client registration,
  connection, and callback state are principal-bound, and self-service
  ownership cannot be transferred.
  Reffed data is likewise bound to the principal that created it: another
  user holding the `<ref_>` handle can't reduce over it.
  High-assurance shared deployments can additionally require an exact,
  expiring [operation and resource grant](operation-grants.md) for the signed
  principal and campaign. Arguments, URL targets, writable namespaces, request
  count, bytes, and rate are bounded outside the agent request.
- **Field minimization.** Sensitive field values in inline results are
  redacted or tokenized before they reach the model, on by default; a
  tokenized value is resolved back only on the principal's outbound call to
  the same upstream (see [field minimization](field-minimization.md)).
- **Mediation.** [Enforced workspace mode](mediation.md) gives one governed
  microagent workspace a host-owned locked allowlist: the gateway host is its
  only direct network destination, so upstream calls must cross `call_tool`.
  The default local-host posture is explicitly advisory. The
  [egress-guard hook](#the-egress-guard) warns, and `microagency doctor` finds
  duplicate local MCP wiring, but neither is described as packet enforcement.
- **Isolation.** Query engines run in WebAssembly modules with no network or
  credential access; Python runs in an isolated microVM that sees only its
  input data. An experimental governed program may also receive a narrow,
  run-scoped broker capability. It still receives no credential and has no
  ambient network access; every brokered read crosses the normal gateway
  invocation path.
- **Auditability.** Every proxied call and every reduce run is written to an
  append-only, hash-chained log whose lines are ES256-signed, so an edited,
  inserted, or reordered line is detectable by anyone with the public key —
  not just the operator who holds the private one. Wholesale tail truncation
  is caught by a signed, out-of-band head anchor in the secret store (real
  protection under OpenBao/Vault); see [the audit chain](audit.md). A
  declarative transform fused into `call_tool` records its engine, query
  digest, byte counts, latency, and outcome under that same run without
  retaining the query or raw result.
  Governed invocations also use a separate signed decision ledger that is
  fsynced and anchored before upstream egress. A ledger or anchor failure
  refuses the call.
- **Plane separation.** The operator surface (admin API and console) uses
  its own token. The public `/mcp` surface accepts audience-bound OAuth
  access tokens, or a separate user-supplied bearer in compatibility mode.
  Public consent and all operator routes stay on a loopback listener that
  the tunnel never exposes. An MCP token cannot authenticate the operator
  API, and the operator token cannot authenticate `/mcp`.
  The public `/connections` account API accepts the MCP principal token but
  cannot route to `/admin`; its unauthenticated provider callback is protected
  by expiring, single-use OAuth state and PKCE.

## Governed-program threat model

File-only `reduce(code)` gives guest code input files and compute, with no
route back to the gateway. A governed program adds one authority: it may ask
the host to invoke a fixed set of read-only tools. Treat the supplied Python
and every upstream response as untrusted.

The added risks are confused-deputy calls, authority widening after a schema
refresh, cross-user reference access, duplicate calls, resource exhaustion,
credential disclosure, and using the broker as ambient network access. The
controls are enforced outside the guest:

- the outer caller supplies exact names, and the gateway validates ownership,
  enabled state, and read classification before VM boot;
- the ordinary proxy gate repeats the allowlist and read classification checks
  immediately before every upstream call;
- the gateway retains the caller principal and supplies credentials only in
  its existing upstream transport;
- references are materialized only after an owner match, and every delivered
  schema or result counts against the run byte budget;
- serialized request IDs make exact retries idempotent within the run and
  reject mismatched replay;
- call, operation, request-size, byte, and wall-time bounds limit consumption;
- the broker binds host loopback, is reachable from the guest only through one
  vsock mapping, uses a random path, and disappears when the run ends; and
- normal guest egress remains deny-all and is audited by the sandbox.

The residual authority is intentional: granted read tools can expose all data
their caller and OAuth scopes permit, and program stdout can deliberately
return selected values to the model. Use the narrowest tool grant and budgets.
Client cancellation stops the VM and new broker requests, but a read already
detached into the gateway's ordinary in-flight cache may finish. Disabling or
revoking a connection quarantines future calls through the normal gate; this
experimental mode does not yet provide a separate operator control to kill an
individual in-flight read. That control, explicit approval, cost accounting,
and retry semantics are prerequisites for any future write-capable mode.

## The egress guard

`microagency hook install` prints a Claude Code PreToolUse hook that warns
when a Bash or WebFetch call would go straight to a host that's behind the
gateway, steering the agent back through `call_tool`. It warns rather than
blocks, and it fails open: if the gateway isn't running or has no token, the
guard stays silent.

This is the advisory local-host layer. It does not cover shell forms it cannot
parse, direct IPs, remote clients, or alternate processes. Use
[`microagency mediation enforce`](mediation.md) for a governed workspace whose
network boundary denies direct upstream access.
