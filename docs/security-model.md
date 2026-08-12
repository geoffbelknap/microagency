---
title: The security model
description: Each guarantee microagency makes, and where it is enforced.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

The guarantees, and where each one is enforced:

- **Credential custody.** Upstream tokens and OAuth refresh tokens live in
  the gateway's secret store — OpenBao/Vault when available, else an
  operator-key encrypted file or an explicitly degraded mode-0600 plaintext
  fallback (see
  [where credentials live](connect-clients.md#where-credentials-live)).
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
- **Field minimization.** Sensitive field values in inline results are
  redacted or tokenized before they reach the model, on by default; a
  tokenized value is resolved back only on the principal's outbound call to
  the same upstream (see [field minimization](field-minimization.md)).
- **Mediation.** The [egress-guard hook](#the-egress-guard) warns when an
  agent tries to reach a connected host directly instead of through the
  gateway; `microagency doctor` additionally flags any upstream the
  gateway proxies that a client is ALSO wired to directly — a back door
  around the gateway.
- **Isolation.** Query engines run in WebAssembly modules with no network or
  credential access; Python runs in an isolated microVM that sees only its
  input data.
- **Auditability.** Every proxied call and every reduce run is written to an
  append-only, hash-chained log whose lines are ES256-signed, so an edited,
  inserted, or reordered line is detectable by anyone with the public key —
  not just the operator who holds the private one. Wholesale tail truncation
  is caught by a signed, out-of-band head anchor in the secret store (real
  protection under OpenBao/Vault); see [the audit chain](audit.md). A
  declarative transform fused into `call_tool` records its engine, query
  digest, byte counts, latency, and outcome under that same run without
  retaining the query or raw result.
- **Plane separation.** The operator surface (admin API and console) uses
  its own token. The public `/mcp` surface accepts audience-bound OAuth
  access tokens, or a separate user-supplied bearer in compatibility mode.
  Public consent and all operator routes stay on a loopback listener that
  the tunnel never exposes. An MCP token cannot authenticate the operator
  API, and the operator token cannot authenticate `/mcp`.
  The public `/connections` account API accepts the MCP principal token but
  cannot route to `/admin`; its unauthenticated provider callback is protected
  by expiring, single-use OAuth state and PKCE.

## The egress guard

`microagency hook install` prints a Claude Code PreToolUse hook that warns
when a Bash or WebFetch call would go straight to a host that's behind the
gateway, steering the agent back through `call_tool`. It warns rather than
blocks, and it fails open: if the gateway isn't running or has no token, the
guard stays silent.
