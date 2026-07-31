---
title: Public mode and multi-user gateways
description: Remote MCP for the Claude and ChatGPT web apps, and sharing one gateway safely.
---

<!-- docs-last-updated -->
_Last updated: 2026-07-31_

## Public mode (remote MCP in the Claude/ChatGPT web apps)

To use microagency from the web apps, the endpoint must be public and
OAuth-protected. microagency validates tokens but never issues them; login
happens at an external authorization server, your IdP or a hosted AS.

```sh
microagency up --http 127.0.0.1:8765 --tunnel cloudflare \
  --issuer https://your-as.example.com --audience microagency
```

`--tunnel cloudflare` (or `ngrok`) runs your installed tunnel CLI against
the loopback bind and prints a public URL to paste into the connector;
microagency operates no tunnel itself. Add `--require-scope <scope>` to
reject tokens your issuer didn't grant that OAuth scope, or leave it off for
an IdP that doesn't model scopes.

The tunnel exposes only `/mcp` and the OAuth endpoints. The operator
surface (`/admin` and the console) moves to its own loopback listener,
`127.0.0.1:8766` by default or wherever `--admin-addr` points, so it
isn't network-reachable from the public bind at all. It is also gated by the
operator token, which is a **different secret** from the `/mcp` bearer. A
tunnel with no `--token` mints a distinct MCP bearer at
`~/.microagency/mcp-bearer` for the connector. The token you paste into
a public web app is not the one that gates `/admin`. Both the network
split and the credential split hold, so an agent's bearer can never reach
admin. If you front `--issuer` with your own reverse proxy instead of a
tunnel, set `--admin-addr` yourself to keep the operator surface off the
proxied listener.

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
