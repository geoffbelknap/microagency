# microagency

Give your agent every MCP server it needs, and keep the credentials, the
datasets, and the tool clutter out of it.

A language model is the wrong tool for work that has a right answer. So
microagency helps the agent decide what to ask, sandboxed microagents do the
work on the live data outside the model's context, and the model sees
answers instead of datasets. No context bloat, no credential leaks, and far
less of your private data reaching the model at all.

The fears that keep organizations from letting AI near real data, one by
one:

- It can be wrong. Work with a right answer runs as code, not as inference,
  and code gives the same answer every time.
- It can expose private data. Large results are processed outside the
  context window and only the answer comes back. That's not zero exposure —
  small results still return inline, at a threshold you choose — but what
  the model and the inference provider see drops from whole datasets to
  answers.
- It can leak credentials. The gateway holds the keys and runs the OAuth
  flows; the agent never sees a secret.
- It can get expensive. You stop paying a model to do a script's job, and
  tool catalogs stop riding along in every request.

And because everything crosses one gateway, every call lands in a
tamper-evident audit log. When someone asks what the agent did, you show
them.

microagency is an MCP gateway. Point Claude Code, Claude Desktop, Cursor, or
any MCP client at it and put your servers behind it; one connection replaces
all of them.

## Quickstart

```sh
brew install geoffbelknap/tap/microagency
microagency up
```

That's the whole setup. `up` starts the server and registers it with Claude
Code if the `claude` CLI is on your PATH; approve the prompt and you're
connected. Any other client works the same way: paste
`http://127.0.0.1:8765/mcp` and approve once. You never copy, type, or store
a token.

To stop, `microagency down`. To disconnect a client,
`claude mcp remove microagency`. `microagency restart` bounces the server
(keeping its secret store up), and `microagency purge` deletes your local state
(add `--full` to wipe everything; both confirm first).

Your upstream credentials stay in the gateway's secret store and never enter
the agent's configuration or context. OpenBao/Vault is preferred, and managed
OpenBao can keep its own bootstrap in an OS keychain or KMS helper. If OpenBao
is unavailable, the local fallback is encrypted when you supply a separate key.
Without one, `up` refuses to start rather than keep credentials in an
unencrypted file; `--allow-plaintext-credentials` accepts that posture
explicitly, and `doctor` reports it as degraded.
See [where credentials live](docs/connect-clients.md#where-credentials-live).

Building from source instead: clone the repo, `make build`, `./microagency
up`. Go is the only build dependency for the gateway itself (the wasm query
engines are bundled by `make build`; the `reduce` sandbox pulls its workload
image on demand).

Separately, `make image` builds `ghcr.io/geoffbelknap/microagency` — the OCI
image for running **microagency itself as a microplane workload**, state
riding the guest filesystem into hibernation snapshots. Most people never
need it; it additionally requires `microagent` on PATH and a readable CA
bundle, so "Go only" does not apply to that target.

## Add your servers

Open the console at `http://127.0.0.1:8765/console` and add a server by URL,
with a token or over OAuth. In the OAuth case the gateway runs the flow and
keeps the refresh token. You can also search the official MCP registry from
the Registry panel and import servers from there.

At add time you can narrow a connection: read-only, specific OAuth scopes,
provider parameters, or a single owner.

Shared deployments can opt into exact, expiring
[operation and resource grants](docs/operation-grants.md) bound to the signed
principal and campaign, with argument, destination, resource, request, byte,
and rate limits enforced before upstream egress.

## How the agent uses it

The agent sees three tools, and everything you add is reached through them:

- `find_tools` — search everything you've connected
- `call_tool` — invoke what it found
- `reduce` — compute over a large result without loading it into context

Ten servers or a thousand: same three tools, same small context.

`reduce` runs the work two ways. Query engines handle the everyday work —
filter, count, extract — fast, without spinning up a VM. The microVM is
there for when you need to run real code. Either way the raw data stays on
the gateway; only the answer comes back.

## Going deeper

[ARCHITECTURE.md](ARCHITECTURE.md) is the conceptual overview: why
microagency exists and the shape of the system. The [docs](docs/index.md)
cover each mechanism:

- The auth modes: built-in OAuth, static bearer, external issuer, stdio.
- Where credentials live.
- The tool index, and how invocation is gated.
- Off-context data handling, the query engines, and the microVM, including
  how to write your own engine.
- Field minimization and the audit chain.
- Public mode for the Claude and ChatGPT web apps.
- Multi-user gateways, and the security model.

`microagency --help` shows the CLI surface, and `microagency doctor` checks
runtime and engine health.

Local clients get advisory bypass warnings by default. For a governed
microagent workspace, [enforced direct-upstream mediation](docs/mediation.md)
locks workspace egress to the gateway host so upstream network paths must go
through `call_tool`.
