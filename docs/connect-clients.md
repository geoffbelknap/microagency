---
title: Connecting clients and credentials
description: The four auth modes, and where every secret actually lives.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-24_

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
plaintext registration index. On startup `up` picks one, highest precedence
first:

1. **An external Vault or OpenBao**, when `VAULT_ADDR` and `VAULT_TOKEN` are
   both set. Both are required; a partial configuration fails startup.
2. **The AES-256-GCM file store**, under a data key the protector named by
   `MICROAGENCY_SECRET_PROTECTOR` holds.
3. **The AES-256-GCM file store**, under a key file you place yourself and
   name with `MICROAGENCY_SECRET_KEY_FILE`.
4. **The AES-256-GCM file store**, under a data key microagency generates on
   first start and keeps in this host's own keychain — the macOS login
   Keychain, or the Linux Secret Service. This is what an install that
   configures none of the above gets. It needs no opt-in.
5. **An unencrypted mode-0600 file** at `~/.microagency/upstream-tokens.json` —
   permission isolation, not encryption at rest. `up` **refuses to start**
   rather than put credentials there. To accept it anyway, pass
   `up --allow-plaintext-credentials` (or set
   `MICROAGENCY_ALLOW_PLAINTEXT_CREDENTIALS=1` for a unit file). The startup
   banner, the log, and `doctor` all report it as degraded.

Once a start has put the data key somewhere,
`~/.microagency/credential-key-custody.json` records which protector holds it,
and later starts follow that record rather than deciding again. The host
keychain in (4) is chosen only when the operator has configured nothing:
every setting above it wins, and so does the explicit
`--allow-plaintext-credentials`. It is also never chosen over a store that is
already encrypted, because minting a second key there would make the existing
credentials unreadable.

### A fresh machine

`brew install …` then `microagency up` is the whole setup. The first start
generates the data key, stores it, reads it back to prove the store will open
again, and says where it went:

```
    Credentials    AES-256-GCM file store (data key: Linux Secret Service)
                   data key generated in your Linux Secret Service — back it up; nothing in
                   ~/.microagency can open this store without it
```

Later starts retrieve the same key and name the protector without repeating
that line. `microagency secret-store status` reports it at any time.

### A headless host

A server, a container, or a locked session has no keychain to put a key in.
`up` refuses rather than choose a lesser store for you, and it will not write a
key beside the ciphertext it opens:

```
microagency: refusing to start — upstream credentials would be stored UNENCRYPTED.
  No data key can be held outside the state directory: linux Secret Service protector
  requires secret-tool (libsecret-tools/libsecret)
  ...
  Choose one:
    - hold the key in a KMS or secret manager: set MICROAGENCY_SECRET_PROTECTOR=command and
      MICROAGENCY_SECRET_PROTECTOR_COMMAND to your helper, then start again
    - hold the key yourself: point MICROAGENCY_SECRET_KEY_FILE at a separately held
      32-byte key outside ~/.microagency, then start again
    - make this host's Linux Secret Service reachable, then start again
    - accept unencrypted credentials, knowing what that means:
      `microagency up --allow-plaintext-credentials` (or MICROAGENCY_ALLOW_PLAINTEXT_CREDENTIALS=1)
```

For a hosted deployment the first option is the one you want: a `command`
protector wraps the data key with a KMS you control. See
[protecting the credential store key](secret-store-custody.md#kms-or-secret-manager-helper).

### When the store is not the one you configured

`up` records the store it actually opened in
`~/.microagency/credential-store.json` and prints it on startup, so the store
in effect is never inferred from configuration. `doctor` reports the same
record while the gateway runs, and probes what a start would use when it is
not. A configured external store is reported only after it answers:

```
  secret store      ✗ external Vault/OpenBao (VAULT_ADDR=http://127.0.0.1:8200) did not answer
                    why:        dial tcp 127.0.0.1:8200: connect: connection refused
                    fix:        start it, or correct VAULT_ADDR/VAULT_TOKEN, then `microagency restart`
                    (a start still uses it; every credential read would fail until it answers)
```

### Encrypting the file store

The encrypted file store uses AES-256-GCM under a 32-byte data key that a
**protector** supplies. Your own host keychain is the default; name a different
one when it does not match where the gateway runs:

```sh
export MICROAGENCY_SECRET_PROTECTOR=keychain        # macOS login Keychain
export MICROAGENCY_SECRET_PROTECTOR=secret-service  # Linux Secret Service
export MICROAGENCY_SECRET_PROTECTOR=command         # your KMS or secret manager
microagency up
```

On the first start with a protector configured, microagency generates the data
key, stores it through the protector, and verifies it reads back before using
it. Later starts retrieve it. Nothing under `~/.microagency` can decrypt the
store on its own, so a copy of that directory is not a copy of your
credentials. `microagency secret-store status` reports which protector holds
the key.

You can also hold the key yourself in a file outside `~/.microagency`:

```sh
install -d -m 700 ~/.config/microagency
openssl rand 32 > ~/.config/microagency/secret-store.key
chmod 600 ~/.config/microagency/secret-store.key
export MICROAGENCY_SECRET_KEY_FILE=~/.config/microagency/secret-store.key
microagency up
```

On first startup with a key, microagency migrates an existing plaintext
`upstream-tokens.json` through a mode-0600 temporary ciphertext file and an
atomic rename. It refuses a key inside `~/.microagency`, a key accessible to
group or other users, a wrong key, or a restart without the configured key.
Back up the key separately: losing it makes the encrypted credentials
unrecoverable.

A configured protector that cannot be reached stops startup. It never falls
back to another store, because a second store beside the one you believe holds
your credentials is the failure nobody notices. See
[protecting the credential store key](secret-store-custody.md) for the helper
protocol, moving the key between protectors, and recovery.

### Upgrading from a managed OpenBao

Earlier versions could start and supervise an OpenBao of their own. This
version does not, and it cannot start one to read what is in it. If your
credentials live in a managed instance, choose a path **before** you upgrade.
See [upgrading from a managed OpenBao](secret-store-custody.md#upgrading-from-a-managed-openbao)
for both, and for removing what the managed instance left behind.

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
doesn't open a credential store or aggregate upstreams, so there's no console to add
servers from and the index starts empty. For the gateway story — connecting
MCP servers and proxying them — use the HTTP server (`up`).
