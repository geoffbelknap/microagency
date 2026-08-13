---
title: Getting started
description: Install microagency, connect a client, and add your first servers.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

## Install and start

```sh
brew install geoffbelknap/tap/microagency
microagency up
```

That's the whole setup. `up` starts the server on
`http://127.0.0.1:8765/mcp` and registers it with Claude Code if the
`claude` CLI is on your PATH; approve the prompt and you're connected. Any
other client works the same way: paste the URL and approve once. You never
copy, type, or store a token.

To stop, `microagency down`. To disconnect a client,
`claude mcp remove microagency`. `microagency restart` bounces the server
(keeping its secret store up), and `microagency purge` deletes your local
state (add `--full` to wipe everything; both confirm first).
[Operating the gateway](operations.md) covers the full CLI surface.

Your upstream credentials stay in the gateway's secret store and never enter
the agent's configuration or context. OpenBao/Vault is preferred, and managed
OpenBao can keep its own bootstrap in an OS keychain or KMS helper. If OpenBao
is unavailable, the local fallback is encrypted only when you supply a separate
key; otherwise `doctor` reports the mode-0600 plaintext fallback as degraded.
See [where credentials live](connect-clients.md#where-credentials-live).

## Add your servers

Open the console at `http://127.0.0.1:8765/console` and add a server by
URL, with a token or over OAuth. In the OAuth case the gateway runs the flow
and keeps the refresh token. You can also search the official MCP registry
from the Registry panel and import servers from there.

At add time you can narrow a connection: read-only, specific OAuth scopes,
provider parameters, or a single owner. A server can also be held as
*discovered* — findable in the index but not invocable until you enable it;
see [the tool index](tool-index.md).

## What the agent sees

Three tools, and everything you add is reached through them:

- `find_tools` — search everything you've connected
- `call_tool` — invoke what it found
- `reduce` — compute over a large result without loading it into context

Ten servers or a thousand: same three tools, same small context.

## Build from source

Clone the repo, `make build`, `./microagency up`. Go is the only build
dependency for the gateway itself (the wasm query engines are bundled by
`make build`; the `reduce` sandbox pulls its workload image on demand).

Separately, `make image` builds `ghcr.io/geoffbelknap/microagency` — the
OCI image for running **microagency itself as a microplane workload**, state
riding the guest filesystem into hibernation snapshots. Most people never
need it; it additionally requires `microagent` on PATH and a readable CA
bundle, so "Go only" does not apply to that target.

## Check the install

`microagency doctor` checks runtime and engine health:

- Whether the server is running.
- Where your credentials live.
- Which query engines are loaded.
- Whether the microVM runtime can boot.
- Whether any client is wired around the gateway.

Run it first when something misbehaves.
