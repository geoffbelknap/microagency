---
title: Connecting clients and credentials
description: The four auth modes, and where every secret actually lives.
---

<!-- docs-last-updated -->
_Last updated: 2026-07-28_

## Built-in OAuth (the default)

`up` starts the MCP server on `http://127.0.0.1:8765/mcp` with a built-in
single-user OAuth 2.1 authorization server. If the `claude` CLI is on your
PATH, the URL is registered with Claude Code automatically; approve the
prompt when it opens and you're connected. Any other client works the same
way: paste the URL and approve once. You never copy, type, or store a token
yourself.

To disconnect, run `claude mcp remove microagency`. To skip
auto-registration, pass `--no-register`.

The OAuth signing key lives at `~/.microagency/oauth-key` (mode 0600), so
issued tokens survive restarts. The admin API and the console use a separate
operator token: `cat ~/.microagency/token`.

## Where credentials live

The upstream secrets microagency holds — OAuth refresh tokens, static
bearers, stored client registrations — go in a secret store, not the
plaintext registration index. On startup `up` picks one:

- If `VAULT_ADDR` (and `VAULT_TOKEN`) are set, it uses that Vault/OpenBao.
- Otherwise, if an `openbao`/`bao` binary is on your PATH, `up` starts a
  dedicated OpenBao on `127.0.0.1:8200`, stores its unseal key and root
  token under `~/.microagency/openbao/` (0600), and uses its KV-v2 engine.
  `restart` keeps this OpenBao up; `down` stops it.
- If neither is available, it falls back to an encrypted-at-rest **file
  store** under `~/.microagency`. The startup log records which posture you
  got (watch for it in `~/.microagency/microagency.log` when running
  backgrounded), so you can tell where your secrets actually are.

The managed OpenBao runs with `tls_disable` on the loopback bind (it never
leaves localhost). Auto-unseal via a system keychain/KMS is a hardening
follow-up.

## Static bearer / external OAuth

For a client that can't do OAuth, `up --token <tok>` serves a static bearer
token instead. It auto-registers with Claude Code, passing the token through
the subprocess rather than your shell. If auto-registration isn't available,
it prints a connect line that reads the token from its 0600 file so the token
stays out of your history:

```sh
claude mcp add --transport http microagency http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer \$(cat ~/.microagency/token)"
```

For a shared or hosted deployment, `up --issuer <url>` validates tokens
from an external authorization server; clients log in there — and this works
over a tunnel too (`up --tunnel … --issuer …`, see
[public mode](public-mode.md)), so external OAuth over the tunnel is
available today. What's still planned is serving the **built-in**
authorization server over the tunnel; until then, a tunnel without
`--issuer` uses a static bearer (a distinct MCP bearer, minted at
`~/.microagency/mcp-bearer`, never the operator token).

## Client-spawned (stdio)

A client or test harness can spawn the binary and talk over stdin/stdout. No
port, no token:

```sh
claude mcp add microagency -- /abs/path/to/microagency up --stdio
```

`--stdio` is meant for `reduce` and for testing the tool surface: it
doesn't run OpenBao or aggregate upstreams, so there's no console to add
servers from and the index starts empty. For the gateway story — connecting
MCP servers and proxying them — use the HTTP server (`up`).
