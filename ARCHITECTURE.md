# How microagency works

This is the deep dive. If you just want to run it, the [README](README.md)
covers that in two commands.

## Why

microagency starts from a hypothesis: using a non-deterministic system to
process deterministic data is a bad trade. When an agent pulls ten thousand
rows into its context to answer "how many failed logins yesterday," you pay
three times. Tokens, because the data rides through the model on every turn.
Accuracy, because a model counting rows is sometimes wrong and a script never
is. Exposure, because your raw data, and the customer records and PII in it,
is now part of a prompt, visible to the model and to whoever runs the
inference.

The fix is a division of labor: the model decides what to ask, deterministic
code computes the answer, and only the answer enters the context. It's least
privilege applied to the model itself. The model gets the answer, not the
data.

That's a default, not an absolute. Results under the inline threshold
(`--max-inline-bytes`, default 8192) still return directly, and an answer
can itself be sensitive. The honest claim is a much smaller aperture, not
zero: what reaches the model drops from whole datasets to the answers pulled
out of them.

MCP is where agents meet data today, so microagency is an MCP gateway. The
mechanisms below — the tool index, reference handles, the query engines and
microVM, brokered credentials — are that one hypothesis applied to each part
of the agent's data path.

## The shape of it

microagency sits between one or more MCP clients and any number of MCP
servers:

```
  agent (Claude Code, Cursor, any MCP client)
        │
        │  one MCP connection (OAuth)
        ▼
  ┌────────────────────────────────────┐
  │ microagency gateway                │
  │                                    │
  │   find_tools · call_tool · reduce  │
  │                                    │
  │   tool index      secret store     │
  │   ref store       audit log        │
  └───────┬───────────────────┬────────┘
          │                   │
          ▼                   ▼
    MCP servers         operator console + admin API
    (creds held here,   (separate token, separate
     never sent to       listener in public mode)
     the agent)
```

The agent holds exactly one connection and sees exactly three tools.
Everything else lives on the gateway side of the line: credentials, tool
schemas, large results, and the audit trail.

## Connecting a client

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

### Static bearer / external OAuth

For a client that can't do OAuth, `up --token <tok>` serves a static bearer
token instead. It auto-registers with Claude Code, passing the token through
the subprocess rather than your shell. If auto-registration isn't available,
it prints a connect line that reads the token from its 0600 file so the token
stays out of your history:

```sh
claude mcp add --transport http microagency http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $(cat ~/.microagency/token)"
```

For a shared or hosted deployment, `up --issuer <url>` validates tokens from
an external authorization server; clients log in there. For the public web
apps, `up --public` wraps a tunnel. The tunnel path is static-bearer for now;
OAuth over the tunnel is planned.

### Client-spawned (stdio)

A client or test harness can spawn the binary and talk over stdin/stdout. No
port, no token:

```sh
claude mcp add microagency -- /abs/path/to/microagency up --stdio
```

## The tool index

Upstream tools are not added to `tools/list`, because hundreds of tool
schemas would swamp the model's context. They live in an index instead. The
agent searches the index with `find_tools` (returns names, descriptions, and
schemas) and invokes matches with `call_tool`, so you can aggregate as many
servers as you like and the context stays small. Ranking is keyword-based,
with past usage as a tiebreaker; an embedding ranker can replace the scorer
later without changing the tool surface.

An upstream is either enabled or discovered. Discovered means its tools are
findable in the index but `call_tool` refuses to run them; enabling is an
explicit operator action in the console. This keeps the index broad (you can
import the whole registry) while invocation stays operator-granted. Discovery
never auto-enables anything.

## Large results and reduce

A result too large to return inline is stored server-side, and the agent gets
a `<ref_N>` handle with a structural preview: field names, row counts, kind,
and no values. The inline threshold is `--max-inline-bytes` (default 8192),
and `--persist-refs` keeps reffed data across restarts (encrypted at rest,
24h TTL).

To work with the data, the agent calls `reduce`. Most of the time, working
with a big result means filtering it, counting it, or pulling out one field —
a query engine does that in milliseconds, no VM needed. When you need to run
real code for something the queries can't express, that's the microVM. Which
one runs is decided by the request:

- a declarative `query` runs in a query engine — a WebAssembly module, in
  milliseconds, with no VM. The query language picks the engine (table below).
- `code` (Python) runs in an isolated microVM that reads the data from
  `/app/input` and prints the result. This handles any size or shape.

A query engine is a WebAssembly (wasip1) module with no ambient authority: no
network, no filesystem, no credentials — only the bytes it's handed. That
isolation isn't a policy the engine has to honor; it's a property of the
runtime. So a query can run over sensitive, PII-heavy data without any way to
leak it. The same query also returns the same answer every time, which is the
point — this is work with a right answer, so it runs as code, not inference.

Only the computed answer returns to the agent, and a large answer becomes a
new reference. If you need the raw data yourself, download it from the
console; that path never touches the model.

The built-in query engines:

| engine | query | over |
|---|---|---|
| `jq` | a jq program | JSON |
| `text` | a regular expression | text / logs (matching lines) |
| `html` | a CSS selector (`sel` or `sel@attr`) | HTML |
| `sql` | `SELECT … FROM data WHERE … GROUP BY … ORDER BY … LIMIT …` | a JSON array of objects |

`make build` bundles them into the binary. Point `--engine name=path.wasm` at
any wasip1 module you trust to add or override one.

### Writing your own query engine

A query engine is just a wasip1 command with a small contract, so you can add
a query language by writing one module — in any language that compiles to
`wasm32-wasip1` (Go, Rust, Zig, C, …). The contract:

- the **query** arrives as `argv[1]`
- the **data** arrives on **stdin** (the bytes the gateway fetched, cred-blind)
- the **result** goes to **stdout**
- **errors** go to **stderr** with a non-zero exit: `2` for a bad query or
  usage, `1` for a runtime failure
- it does **pure compute** — no network, no filesystem, no credentials. The
  runtime enforces this; your module couldn't reach them if it tried.

The `engines/` directory holds the built-ins as standalone modules, one per
directory. `engines/text` is the smallest — copy it as a template. Build with
`GOOS=wasip1 GOARCH=wasm go build` (or your language's equivalent), then load
it at runtime with `--engine name=path.wasm`, or drop it in `engines/` and
`make engines` to bundle it into the binary.

One caution worth stating plainly: a query engine runs over your data, so only
load a `.wasm` you trust. The sandbox stops an engine from reaching the network
or your credentials; it does not vet what the engine does with the bytes it's
given.

## The audit chain

Every run and proxied call is written to an append-only audit log with a hash
chain, so an edited, deleted, or reordered line is detectable. Verify it from
the console (Activity → verify audit chain) or with `GET /admin/audit/verify`.

## Public mode (remote MCP in the Claude/ChatGPT web apps)

To use microagency from the web apps, the endpoint must be public and
OAuth-protected. microagency validates tokens but never issues them; login
happens at an external authorization server, your IdP or a hosted AS.

```sh
microagency up --http 127.0.0.1:8765 --tunnel cloudflare \
  --issuer https://your-as.example.com --audience microagency
```

`--tunnel cloudflare` (or `ngrok`) runs your installed tunnel CLI against the
loopback bind and prints a public URL to paste into the connector;
microagency operates no tunnel itself. Add `--require-scope <scope>` to
reject tokens your issuer didn't grant that OAuth scope, or leave it off for
an IdP that doesn't model scopes.

The tunnel exposes only `/mcp` and the OAuth endpoints. The operator surface
(`/admin` and the console) moves to its own loopback listener,
`127.0.0.1:8766` by default or wherever `--admin-addr` points, so it isn't
network-reachable from the public bind at all. It's also gated by the
operator token — which is a **different secret** from the `/mcp` bearer: a
tunnel with no `--token` mints a distinct MCP bearer at
`~/.microagency/mcp-bearer` for the connector, so the token you paste into a
public web app is not the one that gates `/admin`. Both the network split and
the credential split hold, so an agent's bearer can never reach admin. If you
front `--issuer` with your own reverse proxy instead of a tunnel, set
`--admin-addr` yourself to keep the operator surface off the proxied
listener.

## Multi-user gateways

Connections are operator-curated and shared by default: every authenticated
user of the gateway can find and invoke them, against the one set of
credentials the gateway holds. To restrict a connection to a single user, set its `owner` to
that user's token subject, at add time or from the console. Other users can't
see or call an owned connection or the credential it holds; the index and the
invocation gate both enforce it. Self-service connections, where each user
runs their own OAuth flow, aren't implemented yet.

## The egress guard

`microagency hook install` prints a Claude Code PreToolUse hook that warns
when a Bash or WebFetch call would go straight to a host that's behind the
gateway, steering the agent back through `call_tool`. It warns rather than
blocks, and it fails open: if the gateway isn't running or has no token, the
guard stays silent.

## The security model

The guarantees, and where each one is enforced:

- Credential custody. Upstream tokens and OAuth refresh tokens live in the
  gateway's secret store. Nothing in the agent's config, context, or tool
  results can reveal them.
- Least privilege. A connection can be read-only, narrowed to specific OAuth
  scopes, restricted to one user (`owner`), or held in the index as
  discovered — findable but not invocable until an operator enables it.
- Mediation. The egress-guard hook warns when an agent tries to reach a
  connected host directly instead of through the gateway.
- Isolation. Query engines run in WebAssembly modules with no network or
  credential access; Python runs in an isolated microVM that sees only its
  input data.
- Auditability. Every proxied call and every reduce run is written to an
  append-only, hash-chained log. An edited, deleted, or reordered line is
  detectable.
- Plane separation. The operator surface (admin API and console) uses its own
  token — distinct from the agent's `/mcp` bearer, including the tunnel path,
  which mints a dedicated MCP bearer rather than reusing the operator token —
  and in public mode it moves to a loopback listener the tunnel never exposes.
  Neither the credential split nor the network split alone is load-bearing: an
  agent's bearer can never reach admin.
