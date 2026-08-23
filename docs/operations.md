---
title: Operating the gateway
description: The CLI surface, state files, doctor, and what purge deletes.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

## The CLI

```sh
microagency up [flags]     # start the MCP server (runs in the background)
microagency down           # stop the background server
microagency restart        # restart with new flags; keeps OpenBao up
microagency purge [--full] # delete your data (both tiers confirm first)
microagency doctor         # check runtime + engine health
microagency openbao        # inspect or migrate managed OpenBao custody
microagency hook install   # print the Claude Code egress-guard hook setup
microagency mediation      # configure or inspect enforced workspace mediation
microagency token          # manage named operator tokens for /admin + console
```

Every command answers `--help` with its own usage; `microagency help`
shows the whole surface including `up`'s flags. `up` runs the server in
the background and returns your terminal; `--foreground` keeps it attached
for debugging, and `--stdio` serves a spawning client over stdin/stdout
instead of HTTP.

## Operator tokens

Everything under `/admin`, and the console's data API, requires an operator
token. Two credential kinds exist:

- **Named tokens**, managed with `microagency token`. Each has a name, a
  role, and an optional expiry. Only a SHA-256 hash is stored; the value is
  printed once at creation.
- **The legacy token** at `~/.microagency/token`: the original single
  credential. It keeps working as a full-admin break-glass bearer and is what
  the loopback console self-authenticates with. Its admin actions audit under
  the fixed name `legacy-operator-token`.

```sh
microagency token create ops-alice --role admin          # full operator surface
microagency token create ci-check --role auditor --expires 30d
microagency token list                                   # names/roles/expiry, never values
microagency token rotate ops-alice                       # re-mint; old value dies
microagency token revoke ci-check                        # remove immediately
```

The `admin` role covers the whole operator surface. The `auditor` role is
read-only observability: run listing, metrics, and audit/decision-ledger
verification. Auditor tokens cannot mutate anything and cannot materialize
parked data.

The running gateway re-reads the token store on every request, so create,
rotate, revoke, and expiry all take effect immediately — no restart. A
request with no valid token is always refused; there is no unauthenticated
operator mode.

Admin-plane actions are audited under the acting token's name. Materializing
a parked reference (`GET /admin/refs/{ref}`) additionally requires an
explicit `?reason=` parameter, and both the actor and the reason land in the
audit record.

## State files

Everything lives under `~/.microagency`:

| path | what it is |
|---|---|
| `token` | the legacy full-admin operator token; break-glass + console self-auth (0600) |
| `operator-tokens.json` | named operator tokens: name, role, expiry, and value hash — never the value (0600) |
| `oauth-key` | the built-in OAuth server's signing key |
| `oauth-clients.json` | dynamic client registrations, bound to their issuer |
| `oauth-revocations.json` | revoked token IDs and consumed refresh token IDs |
| `auth-posture.json` | the active public auth mode, issuer, resource, and tunnel URL stability |
| `tunnel-state.json` | the tunnel subprocess: provider, quick or named mode, URL, pid, and any recorded exit |
| `upstreams.json` | non-secret connection registrations, ownership, operation grants, template identity, and revoked state |
| `connection-templates.json` | operator-approved self-service provider, scope, parameter, and quota bounds; never OAuth client secrets |
| `mediation.json` | non-secret enforced workspace, gateway URL/host, and policy digest |
| `audit-key` | the per-gateway ES256 audit signing key |
| `audit.jsonl` | the append-only, signed audit log |
| `decision-ledger.jsonl` | fail-closed signed authorization and refusal decisions for governed calls |
| `upstream-tokens.json` | fallback credential store: encrypted with a separately supplied key, otherwise the mode-0600 unencrypted store that `--allow-plaintext-credentials` gates |
| `refs/` | parked reference payloads (encrypted; 24h TTL with `--persist-refs`) |
| `refs.key` | the refs encryption key |
| `openbao/data/` | encrypted storage for the managed OpenBao |
| `openbao/bootstrap.json` | same-disk degraded bootstrap only; absent with protected custody |
| `openbao/custody.json` | non-secret protected-provider kind, record ID, and helper path |
| `microagency.log` | the backgrounded server's log, including the secret-store posture line |
| `credential-store.json` | non-secret record of the store `up` actually opened: kind, the store in effect, and the configured store when it differs |
| `microagency.pid` | the running server's pid file |

An encrypted fallback key configured through
`MICROAGENCY_SECRET_KEY_FILE` must live outside this directory. It is not
deleted by `purge --full`.

## What purge deletes

`purge` has two tiers, and both confirm before acting:

- **Default**: deletes parked data (refs) and run/audit history. Connections,
  connection templates, credentials, and the operator tokens (legacy and
  named) are kept — no re-auth.
- **`--full`**: deletes everything under `~/.microagency` — parked data,
  history, stored upstream credentials (you will re-authenticate every
  connection), the operator tokens (legacy and named), and the local OAuth
  keys (Claude Code will re-consent). With protected OpenBao custody, it deletes the external
  bootstrap record first and keeps the state directory if that deletion fails.

`--yes`/`-y` skips the confirmation for scripted use.

See [protecting managed OpenBao](openbao-custody.md) for protector setup,
copy-then-switch migration, restart requirements, backup, and recovery.

## Doctor

`microagency doctor` reports what it can verify:

- Whether the server is running.
- The secret-store posture, meaning where your credentials are.
- The active OAuth mode, issuer, resource, and public consent location.
- Whether the operator surface (`/admin` + console) is reachable beyond
  loopback, warned on every run while that posture holds.
- The tunnel posture: quick or named, whether the URL survives restarts, and
  whether the tunnel process is still serving the public URL.
- The loaded query engines.
- Whether the microVM runtime can boot a real workload.
- Enforcement hygiene: any upstream the gateway proxies that a client is
  also wired to directly, bypassing the gateway.
- Direct-mediation posture: advisory local checks or configured/enforced
  workspace policy, plus every client class outside that boundary.

See [direct-upstream mediation](mediation.md) for the gateway-only workspace
contract, fail-closed mutation behavior, and structured denial evidence.

## Metrics

The console's impact view separates tool-schema context from invocation and
reduction responses. Read the same aggregate data from `GET /admin/metrics`,
or scrape `GET /admin/metrics/prometheus`; both endpoints accept any operator
token, including read-only auditor tokens. See [Measuring context cost](context-metrics.md) for exact byte
semantics, task correlation, privacy boundaries, and the offline baseline.
