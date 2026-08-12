---
title: Public mode and multi-user gateways
description: Remote MCP for the Claude and ChatGPT web apps, and sharing one gateway safely.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

## Public mode (remote MCP in the Claude/ChatGPT web apps)

To use microagency from a web app, start its built-in tunnel mode:

```sh
microagency up --public
```

`--public` uses your installed `cloudflared` command. Use
`--tunnel ngrok` to select ngrok instead. microagency runs the command and
uses its assigned HTTPS URL as the OAuth issuer.

Paste the printed `/mcp` URL into the remote MCP client. The client discovers
the authorization server, registers, and opens a consent request. The consent
page is served from `127.0.0.1:8766`, not from the public tunnel.

Access tokens last two hours. Refresh tokens rotate and expire after 30 days.
You can revoke either token through `/oauth/revoke`. A consumed refresh token
cannot be replayed.

Cloudflare quick-tunnel URLs can change after a restart. When the URL changes,
old tokens and client registrations stop working. Reconnect the client at the
new URL. Startup output and `microagency doctor` show the active issuer and
resource.

## External authorization server

Use an external issuer for a shared deployment or an existing identity system:

```sh
microagency up --tunnel cloudflare \
  --issuer https://your-as.example.com --audience microagency
```

Add `--require-scope <scope>` to require a scope from that issuer. External
issuer mode does not mount the built-in authorization endpoints.

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
- `/mcp`

The tunnel exposes only `/mcp` and the OAuth endpoints. The operator
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
set its `owner` to that user's token subject, at add time or from the
console. Other users can't see or call an owned connection or the credential
it holds; the index and the invocation gate both enforce it. Off-context
results are scoped the same way: each `<ref_>` is bound to the subject
that created it, so one user can't reduce over another's parked data even
with the handle. Self-service connections, where each user runs their own
OAuth flow, aren't implemented yet.
