---
title: Connecting clients and credentials
description: The four auth modes, and where every secret actually lives.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

## Built-in OAuth (the default)

`up` starts the MCP server on `http://127.0.0.1:8765/mcp` with a built-in
single-user OAuth 2.1 authorization server. If the `claude` CLI is on your
PATH, the URL is registered with Claude Code automatically; approve the
prompt when it opens and you're connected. Any other client works the same
way: paste the URL and approve once. You never copy, type, or store a token
yourself.

To disconnect, run `claude mcp remove microagency`. To skip
auto-registration, pass `--no-register`.

On a shared gateway, the built-in server can federate its sign-in to an OIDC
identity provider (`--sso-issuer`), so each person authenticates with their
own account and becomes a distinct principal. See
[federated sign-in](public-mode.md#federated-sign-in-sso).

The OAuth signing key lives at `~/.microagency/oauth-key` (mode 0600), so
issued tokens survive restarts. Revoking a token at `/oauth/revoke` cuts off
`/mcp` access immediately, and a used refresh token stays refused after a
restart: both are recorded in `~/.microagency/oauth-revocations.json`.

The admin API and the console use separate operator tokens, never MCP
tokens. Create named ones with
`microagency token create <name> --role admin|auditor`; the original
`~/.microagency/token` keeps working as a full-admin break-glass credential.
See [operating the gateway](operations.md) for roles, expiry, rotation, and
revocation. The operator surface refuses to bind beyond loopback unless `up`
gets `--allow-remote-admin`; see
[public mode](public-mode.md#non-loopback-binds).

## Where credentials live

The upstream secrets microagency holds — OAuth refresh tokens, static
bearers, stored client registrations — go in a secret store, not the
plaintext registration index. On startup `up` picks one:

- If `VAULT_ADDR` and `VAULT_TOKEN` are set, it uses that Vault/OpenBao. Both
  are required; a partial configuration fails startup.
- Otherwise, if an `openbao`/`bao` binary is on your PATH, `up` starts a
  dedicated OpenBao on `127.0.0.1:8200` and uses its KV-v2 engine. Protected
  custody can keep its bootstrap in macOS Keychain, Linux Secret Service, or
  an operator KMS helper. Without one, the bootstrap stays beside the data
  under `~/.microagency/openbao/` and is reported as same-disk degraded.
  `restart` keeps this OpenBao up; `down` stops it.
- If neither is available and you have supplied a key file (below), it uses the
  **encrypted file store**. This needs no opt-in: it is a supported posture,
  not a downgrade.
- If neither is available and there is no key file, the only store left is a
  mode-0600 **unencrypted file** at `~/.microagency/upstream-tokens.json` —
  permission isolation, not encryption at rest. `up` **refuses to start**
  rather than put credentials there. To accept it anyway, pass
  `up --allow-plaintext-credentials` (or set
  `MICROAGENCY_ALLOW_PLAINTEXT_CREDENTIALS=1` for a unit file). The startup
  banner, the log, and `doctor` all report it as degraded.

`up` records the store it actually opened in
`~/.microagency/credential-store.json` and prints it on startup, so the store
in effect is never inferred from configuration. When the two differ — a
configured OpenBao that could not be reached, say — `doctor` names both, and
which one holds your credentials:

```
  secret store      ✗ the configured store is NOT the one holding credentials
                    configured: managed OpenBao
                    in effect:  unencrypted mode-0600 file in the state directory (running gateway, pid 4711)
                    why:        another process holds http://127.0.0.1:8200, so microagency's own instance was never reached
                    fix:        restore the configured store, then `microagency restart`
                    until then credentials are NOT encrypted at rest
```

A common cause of that "another process holds" line is an OpenBao left over
from an earlier run: it answers on `127.0.0.1:8200`, but it is not the instance
microagency recorded, so adopting it is refused. Stop whatever holds the port
and start again.

To encrypt the fallback, supply a separate 32-byte key file outside
`~/.microagency`:

```sh
install -d -m 700 ~/.config/microagency
openssl rand 32 > ~/.config/microagency/secret-store.key
chmod 600 ~/.config/microagency/secret-store.key
export MICROAGENCY_SECRET_KEY_FILE=~/.config/microagency/secret-store.key
microagency up
```

The encrypted file uses AES-256-GCM. On first startup with the key, microagency
migrates an existing plaintext `upstream-tokens.json` through a mode-0600
temporary ciphertext file and an atomic rename. It refuses a key inside
`~/.microagency`, a key accessible to group or other users, a wrong key, or a
restart without the configured key. Back up the key separately: losing it makes
the encrypted credentials unrecoverable.

The managed OpenBao runs with `tls_disable` on the loopback bind; it never
leaves localhost. On its first protected start, microagency uses the initial
root token only to configure KV v2 and a narrow AppRole, then revokes it. See
[protecting managed OpenBao](openbao-custody.md) for setup, migration,
fail-closed recovery, rotation, and backup procedures.

In a multi-user self-service deployment, each upstream token and dynamic
client record uses a principal-specific secret-store path. The path contains a
one-way digest of the caller's principal key — the token issuer and subject
together — not the raw identity. The non-secret
connection index records ownership so the gateway can rebuild the same boundary
after a restart. See [public mode](public-mode.md#allow-self-service-connections)
for the operator template and user authorization flow.

## Static bearer / external OAuth

For a client that can't do OAuth, `up --token <tok>` serves a static bearer
token instead. It auto-registers with Claude Code, passing the token through
the subprocess rather than your shell. You can read a token without storing it
in shell history:

```sh
read -rsp "MCP bearer: " MICROAGENCY_TOKEN
export MICROAGENCY_TOKEN
microagency up
```

For a shared deployment, `up --issuer <url>` validates tokens from an
external authorization server. Clients log in through that issuer. The
audience the gateway validates is always the resource identifier it
advertises in discovery metadata; see
[public mode](public-mode.md#external-authorization-server) for the defaults.

Built-in OAuth also works over Cloudflare and ngrok tunnels. There it stays
single-user unless sign-in is federated. Pass `--single-user` to acknowledge
that every remote client authenticates as you, or `--sso-issuer` to let each
person sign in with their own account; without either, `up` refuses to
start. Without federation, consent stays on the loopback operator
listener. See [public mode](public-mode.md) for the endpoints, restart
behavior, and the federated and external-issuer options.

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
