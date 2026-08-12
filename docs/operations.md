---
title: Operating the gateway
description: The CLI surface, state files, doctor, and what purge deletes.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

## The CLI

```sh
microagency up [flags]     # start the MCP server (runs in the background)
microagency down           # stop the background server
microagency restart        # restart with new flags; keeps OpenBao up
microagency purge [--full] # delete your data (both tiers confirm first)
microagency doctor         # check runtime + engine health
microagency hook install   # print the Claude Code egress-guard hook setup
```

Every command answers `--help` with its own usage; `microagency help`
shows the whole surface including `up`'s flags. `up` runs the server in
the background and returns your terminal; `--foreground` keeps it attached
for debugging, and `--stdio` serves a spawning client over stdin/stdout
instead of HTTP.

## State files

Everything lives under `~/.microagency`:

| path | what it is |
|---|---|
| `token` | the operator token gating `/admin` and the console (0600) |
| `oauth-key` | the built-in OAuth server's signing key |
| `mcp-bearer` | the distinct MCP bearer a tunnel mints (never the operator token) |
| `audit-key` | the per-gateway ES256 audit signing key |
| `audit.jsonl` | the append-only, signed audit log |
| `upstream-tokens.json` | fallback credential store: encrypted with a separately supplied key, otherwise degraded mode-0600 plaintext |
| `refs/` | parked reference payloads (encrypted; 24h TTL with `--persist-refs`) |
| `refs.key` | the refs encryption key |
| `openbao/` | the managed OpenBao's unseal key and root token, when managed |
| `microagency.log` | the backgrounded server's log, including the secret-store posture line |
| `microagency.pid` | the running server's pid file |

An encrypted fallback key configured through
`MICROAGENCY_SECRET_KEY_FILE` must live outside this directory. It is not
deleted by `purge --full`.

## What purge deletes

`purge` has two tiers, and both confirm before acting:

- **Default**: deletes parked data (refs) and run/audit history. Connections,
  credentials, and the operator token are kept — no re-auth.
- **`--full`**: deletes everything under `~/.microagency` — parked data,
  history, stored upstream credentials (you will re-authenticate every
  connection), the operator token, and the local OAuth keys (Claude Code
  will re-consent).

`--yes`/`-y` skips the confirmation for scripted use.

## Doctor

`microagency doctor` reports what it can verify:

- Whether the server is running.
- The secret-store posture, meaning where your credentials are.
- The loaded query engines.
- Whether the microVM runtime can boot a real workload.
- Enforcement hygiene: any upstream the gateway proxies that a client is
  also wired to directly, bypassing the gateway.

## Metrics

The console's impact view separates tool-schema context from invocation and
reduction responses. Read the same aggregate data from `GET /admin/metrics`,
or scrape `GET /admin/metrics/prometheus`; both endpoints require the operator
token. See [Measuring context cost](context-metrics.md) for exact byte
semantics, task correlation, privacy boundaries, and the offline baseline.
