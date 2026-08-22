---
title: Public mode and multi-user gateways
description: Remote MCP for the Claude and ChatGPT web apps, and sharing one gateway safely.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

## Public mode (remote MCP in the Claude/ChatGPT web apps)

To use microagency from a web app, start its built-in tunnel mode:

```sh
microagency up --public --single-user
```

`--public` uses your installed `cloudflared` command. Use
`--tunnel ngrok` to select ngrok instead. microagency runs the command and
uses its assigned HTTPS URL as the OAuth issuer.

The built-in OAuth server identifies exactly one person: you. Every token it
issues authenticates as your local user, so several people connecting through
the tunnel would be indistinguishable and would share connections, credentials,
and parked data. `--single-user` is the required acknowledgment of that
posture. Without it — and without `--sso-issuer`, `--issuer`, or `--token`
selecting another auth mode — `up` refuses to start. Startup output and
`microagency doctor` both report the single-user posture while it is active.
To serve several people, [federate sign-in](#federated-sign-in-sso) to an
identity provider, or use an
[external authorization server](#external-authorization-server).

Paste the printed `/mcp` URL into the remote MCP client. The client discovers
the authorization server, registers, and opens a consent request. The consent
page is served from `127.0.0.1:8766`, not from the public tunnel.

Access tokens last two hours. Refresh tokens rotate and expire after 30 days.
You can revoke either token through `/oauth/revoke`. A consumed refresh token
cannot be replayed.

Cloudflare quick-tunnel URLs can change after a restart. When the URL changes,
old tokens and client registrations stop working. Reconnect the client at the
new URL, or use a named tunnel for a stable one. Startup output and
`microagency doctor` show the active issuer and resource.

## Named tunnels (stable URL)

A named Cloudflare tunnel serves a hostname you own, so the issuer survives
restarts and issued tokens stay valid. Create the tunnel and its DNS route
once with your Cloudflare account:

```sh
cloudflared tunnel login
cloudflared tunnel create microagency
cloudflared tunnel route dns microagency mcp.example.com
```

Then start microagency with the tunnel's name and its public URL:

```sh
microagency up --tunnel-name microagency --tunnel-url https://mcp.example.com \
  --single-user
```

A named tunnel changes URL stability, not the auth posture: built-in OAuth
still serves one person, so `--single-user` (or `--sso-issuer`, `--issuer`,
or `--token`) is still required.

microagency runs `cloudflared tunnel run` pointed at the local MCP listener,
overriding any ingress rules in your cloudflared config. The URL you supply
becomes the OAuth issuer and resource. It must be a plain `https://` origin
with no path, query, or credentials.

`--tunnel-name` and `--tunnel-url` are required together and imply
`--tunnel cloudflare`. Because the URL is stable, restarts keep issued tokens
and client registrations working. Changing `--tunnel-url` between runs
invalidates them, and startup says so.

microagency watches the tunnel process instead of assuming it stays up. If
`cloudflared` exits, the server log records the exit and its last output, and
`microagency doctor` reports the dead tunnel with a restart remediation.

## Federated sign-in (SSO)

To serve several people from one gateway without deploying an authorization
server, federate the built-in server's sign-in to an OIDC identity provider:

```sh
export MICROAGENCY_SSO_CLIENT_SECRET=<client-secret>   # first start only
microagency up --tunnel-name microagency --tunnel-url https://mcp.example.com \
  --sso-issuer https://accounts.google.com \
  --sso-client-id <client-id>.apps.googleusercontent.com \
  --sso-hd example.com
```

The gateway stays the authorization server toward MCP clients: dynamic client
registration, PKCE, and token minting are unchanged, and issued tokens still
carry the gateway as their issuer. Only the human sign-in step is delegated.
Pointing `--issuer` directly at a provider like Google does not work for MCP
clients. Its access tokens are opaque to a third-party resource server, its ID
tokens are audience-bound to one client, and it offers no open dynamic client
registration.

Create the OAuth client at the provider once, with the redirect URI
`<public-url>/oauth/sso/callback`. A quick tunnel changes its URL on restart,
which breaks that registration — use a named tunnel or your own stable URL.

When an MCP client starts authorization, the gateway parks the request under
single-use state and sends the person's browser to the provider with PKCE and
a nonce. On return it exchanges the code, validates the ID token — issuer,
audience, expiry, nonce, and signature against the provider's published keys —
and completes the client's authorization. Each token's subject is the
provider's stable `sub` claim, so every account is a distinct principal:
connections, parked references, and grants are scoped per person exactly as
under an external issuer. The provider-verified email is recorded alongside
for display; identity comparisons use only the subject.

With `--sso-hd`, the ID token must carry that exact `hd` (hosted domain)
claim. An account outside the domain is refused during sign-in, before any
gateway token exists.

The provider client secret is supplied once — via `MICROAGENCY_SSO_CLIENT_SECRET`
or `--sso-client-secret-file` — and is kept only in the secret store, never on
the command line. Later starts read it back from the store.

Federated mode is multi-user, so it starts without `--single-user`. A refresh
continues under the token's own subject without re-contacting the provider.
Disabling an account at the provider therefore takes effect when the gateway
refresh token expires (30 days at most), or immediately on revocation at
`/oauth/revoke`. Startup output and `microagency doctor` report the federated
posture, the provider issuer, and the hosted-domain requirement.

## External authorization server

Use an external issuer for a shared deployment or an existing identity system:

```sh
microagency up --tunnel cloudflare --issuer https://your-as.example.com
```

Without `--audience`, accepted tokens must carry the public `/mcp` URL as
their audience. The discovery metadata advertises that same value as the
resource, so a client following discovery requests exactly the token the
gateway accepts. Quick-tunnel URLs change on restart; if your authorization
server pins audiences, set `--audience` to a stable identifier. The gateway
then validates and advertises that value instead.

Add `--require-scope <scope>` to require a scope from that issuer. External
issuer mode does not mount the built-in authorization endpoints.

For a deny-by-default shared gateway, add
`--high-assurance-multi-user`. Tokens must carry a signed `campaign` or
`campaign_id` claim in addition to `sub`, and every invocation needs an exact
operator-owned operation grant. See
[operation and resource grants](operation-grants.md).

Use `--token <token>` only for a client that cannot complete OAuth. This flag
selects static bearer mode instead of built-in OAuth.

## Public endpoints

Built-in public OAuth serves these routes on the tunneled listener:

- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/revoke`
- `/oauth/jwks`
- `/oauth/sso/callback` (federated sign-in only)
- `/connections` and `/connections/*`
- `/mcp`

The tunnel exposes `/mcp`, the OAuth endpoints, and the principal-authenticated
self-service connection API. The operator
surface (`/admin` and the console) moves to its own loopback listener,
`127.0.0.1:8766` by default or wherever `--admin-addr` points, so it
isn't network-reachable from the public bind. The operator token gates that
listener and is never part of public consent.

Tunnel mode requires loopback addresses and separate agent and operator ports.
It rejects a public or shared `--admin-addr`. OAuth metadata uses the URL from
the tunnel process and ignores `Forwarded` and `X-Forwarded-*` request headers.

If you use your own reverse proxy, set `--admin-addr` to a separate loopback
port. Configure `--issuer` with the external authorization server in that mode.

## Non-loopback binds

Without a tunnel, `--http` and `--admin-addr` accept any bind address, but the
operator surface never leaves loopback silently. A bind that would serve
`/admin` and the console beyond loopback — a shared `--http 0.0.0.0:8765`, or
a non-loopback `--admin-addr` — refuses to start unless you add
`--allow-remote-admin`. The refusal names the flag that caused the exposure.

The acknowledgment covers the operator surface only. Binding just `/mcp`
beyond loopback, with `--admin-addr` on a loopback port, needs no flag: the
agent plane is authenticated and carries no operator routes.

With `--allow-remote-admin`, startup output and `microagency doctor` warn on
every run: the operator surface is cleartext HTTP gated by operator tokens
alone. Put TLS in front of it, or prefer the default — a loopback bind reached
over SSH port forwarding. A non-loopback operator surface with no usable
credential — an empty legacy token and no named operator tokens — is refused
outright, since every `/admin` request would be a 401.

## Multi-user gateways

On a multi-user gateway the audit log also minimizes what it keeps of each
caller's tool arguments. Records carry argument structure and a SHA-256
digest instead of the values, unless the operator opts a connection up to
full capture. See [argument capture](audit.md#argument-capture). The opt-up
is disclosed by `microagency doctor` and on the upstream list.

Connections are operator-curated and shared by default: every authenticated
user of the gateway can find and invoke them, against the one set of
credentials the gateway holds. To restrict a connection to a single user,
set its `owner` to that user's principal key, at add time or from the
console. A principal key is `issuer#subject` — for example
`https://issuer.example#user-123` — with any literal `#` or `%` inside either
half written as `%23` or `%25`. Identity is the issuer and subject together,
so tokens from two issuers that assert the same `sub` are two different
users. Other users can't see or call an owned connection or the credential
it holds; the index and the invocation gate both enforce it. Off-context
results are scoped the same way: each `<ref_>` is bound to the principal
that created it, so one user can't reduce over another's parked data even
with the handle.

Result caching and upstream session state follow the same boundary. The
short-lived read cache is keyed per caller, so a result produced for one
user is never replayed to another — identical reads by different users each
reach the upstream, even on a shared connection. Upstream MCP sessions are
per caller too: each user's calls run their own session handshake and present
only their own session id, so server-side session state never spans users.

### Allow self-service connections

An operator can permit a provider without permitting arbitrary upstream URLs.
Create a connection template through the loopback admin API:

```sh
IFS= read -r MICROAGENCY_OPERATOR_TOKEN < ~/.microagency/token
curl -fsS http://127.0.0.1:8766/admin/connection-templates \
  -H "Authorization: Bearer $MICROAGENCY_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "id": "supabase",
    "display_name": "Supabase",
    "url": "https://mcp.supabase.com/mcp",
    "allowed_scopes": ["mcp"],
    "default_scopes": ["mcp"],
    "allowed_params": ["project_ref", "read_only"],
    "read_only": true,
    "max_per_user": 2
  }'
unset MICROAGENCY_OPERATOR_TOKEN
```

The template fixes the upstream URL and caps each principal's connection
count. A user may request only the listed OAuth scopes and curated provider
parameters. Unknown parameters are rejected instead of being appended to the
URL. Set `disabled: true` on the template to stop new and pending
authorizations; existing connections stay in their current posture until the
operator disables, revokes, or deletes them.

Providers without dynamic client registration need an operator-configured
`client_id` and optional `client_secret` on the template. microagency writes
those values only to the secret store. The template file and every API response
contain only `client_configured: true`.

The authenticated account portal or integration uses the same principal token
as `/mcp`:

```sh
curl -fsS https://gateway.example/connections/templates \
  -H "Authorization: Bearer $MCP_ACCESS_TOKEN"

curl -fsS https://gateway.example/connections \
  -H "Authorization: Bearer $MCP_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{
    "template": "supabase",
    "params": {"project_ref": "my-project", "read_only": "true"}
  }'
```

Open the returned `authorize_url` in that user's browser. The provider returns
to `/connections/oauth/callback`; the callback state is random, single-use,
expires after ten minutes, and is bound to the initiating principal and
template. The resulting connection name is server-generated.

Use these principal-authenticated routes to manage only the caller's own
connections:

- `GET /connections`
- `POST /connections/{name}/refresh` to reload its tool index
- `POST /connections/{name}/reauthorize` to replace a revoked or changed grant
- `DELETE /connections/{name}` to remove the connection and credential

The operator retains gateway-wide controls at
`POST /admin/upstreams/{name}/disable`,
`POST /admin/upstreams/{name}/revoke`, and
`DELETE /admin/upstreams/{name}`. Disable keeps the credential but makes calls
non-invocable. Revoke deletes the credential, hides the tools, and leaves an
operator-visible tombstone that cannot be enabled without the owner completing
a new OAuth flow. Delete removes the registration; deleting the last connection
for a principal and template also removes that principal's stored client
registration.

Each self-service token, dynamic client registration, pending OAuth request,
connection record, tool view, and reference is keyed or checked against the
caller's principal key — the token issuer and subject together. Secret-store
paths use a one-way digest of that key rather than the raw identity. A
connection name or `<ref_>` handle is not authority. If an
identity changes or disappears, its old resources remain inaccessible; ownership
cannot be transferred because the OAuth grant belongs to the original identity.
The operator must revoke or delete those resources, and the new identity creates
new connections.

Per-template, per-principal, pending-flow, global-catalog, and hourly start
limits bound self-service growth. The agent-facing `tools/list` response remains
exactly `find_tools`, `call_tool`, and `reduce`; connection management is an HTTP
account surface, not another agent tool.
