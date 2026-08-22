---
title: Delegated per-user access
description: One shared connection, a distinct upstream identity per caller — the provider's own ACLs decide what each user sees.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

Every connection declares a credential strategy: how a calling principal
maps to authority at the upstream.

- `static` — the connection holds one shared credential (or none). Every
  caller who may invoke the connection acts as that one identity. This is
  the default, and it is how every connection worked before strategies
  were named.
- `per-user-oauth` — the connection belongs to the one user who authorized
  it through a
  [self-service template](public-mode.md#allow-self-service-connections).
  The credential is that user's own OAuth grant; no other caller can find
  or invoke the connection.
- `google-dwd` — one shared connection, a distinct upstream identity per
  caller. The gateway holds a Google service-account key with domain-wide
  delegation and derives a short-lived access token acting as each caller.

`GET /admin/upstreams` reports each connection's strategy. The rest of this
page covers `google-dwd`.

## How a delegated call runs

The secret store holds the service-account key. Per call, the gateway signs
a JWT assertion and exchanges it for an access token that acts as the
caller. The assertion's issuer is the service account, its subject the
caller's provider-verified email, its scope the connection's configured
scopes, and its audience the provider token endpoint. The derived token is
attached to that caller's upstream request and cached per caller until
shortly before expiry.

The invariant: the gateway reaches the provider as the mapped per-user
identity, so the provider's own ACLs trim what comes back. It never queries
broadly under a powerful credential and filters afterwards. A caller can
receive only what the provider would show that user directly.

Upstream MCP sessions are per caller on every connection, so a delegated
connection shares neither credentials nor server-side session state between
users.

## Prerequisites

- [Federated sign-in](public-mode.md#federated-sign-in-sso) supplies the
  delegation subject: the provider-verified email recorded when each person
  signs in. A caller with no verified email — for example, on a deployment
  without federation — cannot use a delegated connection: `find_tools`
  hides it, and a direct call fails closed with a structured error. No
  fallback identity is ever substituted.
- A Google Cloud service account with a key, and domain-wide delegation
  granted to its client ID in the Workspace Admin console, limited to the
  exact scopes the connection will carry.

## Adding a delegated connection

```sh
IFS= read -r MICROAGENCY_OPERATOR_TOKEN < ~/.microagency/token
curl -fsS http://127.0.0.1:8766/admin/upstreams \
  -H "Authorization: Bearer $MICROAGENCY_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --rawfile key sa-key.json '{
    name: "drive",
    url: "https://mcp.example.com/mcp",
    strategy: "google-dwd",
    delegation: {scopes: ["https://www.googleapis.com/auth/drive.readonly"]},
    service_account_key: $key
  }')"
```

The service-account key goes only to the secret store. The client email and
token endpoint default from the key file; responses and listings report
`"key_configured": true`, never the key. The non-secret configuration —
strategy, client email, token endpoint, scopes — lives in the connection
record.

To rotate the key or change the configuration:

```sh
curl -fsS http://127.0.0.1:8766/admin/upstreams/drive/delegation \
  -H "Authorization: Bearer $MICROAGENCY_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --rawfile key new-key.json '{service_account_key: $key}')"
```

Disabling or revoking the connection stops delegated calls at the normal
invocation gate and drops the derived-token cache. Revoking also deletes the
stored key. Tokens the provider already issued expire on their own short
lifetime; the provider owns their revocation.

## Audit

Every delegated call's proxy record carries both identities: the caller
(`user`) and the delegated identity the upstream saw (`delegated_identity`).
A refused delegated call — no verified email, or a failed derivation — is
audited like any other refusal. See [the audit chain](audit.md).

## Doctor

`microagency doctor` lists each delegated connection and verifies its
prerequisites: whether the service-account key is present in the secret
store, and whether federated sign-in is configured to supply verified
emails. A store it cannot open is reported as unverified, not as healthy.

## Scope discipline

A delegated connection's scopes are fixed operator configuration, applied to
every derived token. Grant the service account only the scopes the
connection needs — for Drive reads, `drive.readonly` — and keep the
domain-wide delegation grant in the Admin console equally narrow. See the
[security model](security-model.md) for where each guarantee is enforced.
