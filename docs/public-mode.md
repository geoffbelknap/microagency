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
posture. Without it — and without `--issuer` or `--token` selecting another
auth mode — `up` refuses to start. Startup output and `microagency doctor`
both report the single-user posture while it is active. To serve several
people, use an [external authorization server](#external-authorization-server)
instead.

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
still serves one person, so `--single-user` (or `--issuer`/`--token`) is
still required.

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

## External authorization server

Use an external issuer for a shared deployment or an existing identity system:

```sh
microagency up --tunnel cloudflare \
  --issuer https://your-as.example.com --audience microagency
```

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

## Multi-user gateways

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
