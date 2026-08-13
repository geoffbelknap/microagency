---
title: Large results and reduce
description: Reference handles, query engines, the microVM path, and writing your own engine.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

A result too large to return inline is stored server-side, and the agent
gets a `<ref_N>` handle with a structural preview: field names, row counts,
kind, and no values. The inline threshold is `--max-inline-bytes` (default
8192), and `--persist-refs` keeps reffed data across restarts (encrypted at
rest, 24h TTL).

To work with the data, the agent calls `reduce`. Most of the time, working
with a big result means filtering it, counting it, or pulling out one field —
a query engine does that in milliseconds, no VM needed. When you need to run
real code for something the queries can't express, that's the microVM. Which
one runs is decided by the request:

- a declarative `query` runs in a query engine — a WebAssembly module, in
  milliseconds, with no VM. The query language picks the engine (table
  below).
- `code` (Python) runs in an isolated microVM that reads the data from
  `/app/input` and prints the result. This handles any size or shape.

A query engine is a WebAssembly (wasip1) module with no ambient authority:
no network, no filesystem, no credentials — only the bytes it's handed. That
isolation isn't a policy the engine has to honor; it's a property of the
runtime. So a query can run over sensitive, PII-heavy data without any way
to leak it. The same query also returns the same answer every time — this is
work with a right answer, so it runs as code, not inference.

Only the computed answer returns to the agent, and a large answer becomes a
new reference. If you need the raw data yourself, download it from the
console; that path never touches the model.

## Read-only programs (experimental)

For pagination and joins whose next request depends on the previous result,
`reduce(code)` can opt into a bounded, read-only program. The outer request
grants exact tool names; the gateway validates that each tool is enabled,
visible to the caller, and classified as read-only before it starts the VM.

```json
{
  "data": "{}",
  "code": "from microagency import call_tool\nrows = []\npage = 1\nwhile page:\n    result = call_tool('crm__list-contacts', {'page': page})\n    rows.extend(result['items'])\n    page = result.get('next')\nprint(sum(1 for row in rows if row['active']))",
  "program": {
    "allowed_tools": ["crm__list-contacts"],
    "max_calls": 16,
    "max_bytes": 16777216,
    "max_seconds": 300
  }
}
```

The generated `microagency` Python module exposes two functions:

- `find_tools(query, limit=10)` returns typed schemas only for tools in the
  run's grant.
- `call_tool(name, arguments=None)` invokes one granted tool through the
  gateway's ordinary invocation path.

The module contains no upstream token. Its endpoint is an unguessable,
run-scoped capability carried over a guest-loopback-to-vsock bridge. Normal
guest networking remains deny-all. The host gateway supplies OAuth or static
credentials at its existing transport boundary and applies the current owner,
enabled-state, read/write, schema, minimization, result-parking, and audit
rules on every call. A schema refresh that reclassifies a granted tool as a
write stops the call before upstream egress.

Large subcall results follow the normal reference path, but the gateway may
materialize an owner-matched reference directly into the same sandbox. The
raw intermediate does not enter model context; it still counts against
`max_bytes`. Only the program's stdout returns, subject to the usual reduce
output limit.

The broker serializes requests and assigns request IDs. Repeating the exact
same request ID returns the cached response without another upstream call;
reusing it with different content fails. It caps upstream calls, discovery
operations, delivered bytes, request size, and wall time. Client cancellation
and the wall-time deadline stop the VM and refuse new broker calls. A read
already detached into the gateway's normal in-flight cache may finish and be
available to a retry, but it cannot start another program step.

Writes are deliberately unsupported. There is no approval protocol or safe
automatic retry rule for mutations yet, so write, destructive, and
unclassifiable tools fail closed. Programs also cannot invoke `reduce` or
recursively create another broker: grants name indexed upstream tools only.

## Transform during call_tool

When you already know the projection, filter, or aggregate, include one
declarative `transform` in `call_tool` instead of waiting for a reference and
making a second `reduce` call:

```json
{
  "name": "reports__search",
  "arguments": {"status": "open"},
  "transform": {"engine": "jq", "query": "length"},
  "task_id": "run-123"
}
```

The gateway validates the engine and query before contacting the upstream.
It invokes the upstream once, gives only the result bytes to the configured
WebAssembly engine, applies field minimization to the answer, and enforces the
normal inline threshold. The raw upstream result never enters model context
or the code microVM. A large transformed answer becomes a reference owned by
the caller.

The response carries the source tool, engine, run ID, and a SHA-256 digest of
the query. The audit record adds input/output byte counts, latency, and status
under that same run. It does not retain the query or raw result.

This path accepts only `query` and optional `engine`; it does not accept
arbitrary code. Use a separate `reduce` for an existing reference, several
inputs, or Python. If a transformation fails after a mutating call, the raw
result is withheld and the upstream call is never repeated. Reconcile the
upstream state from the run record before deciding whether to retry.

## The built-in query engines

| engine | query | over |
|---|---|---|
| `jq` | a jq program | JSON |
| `text` | a regular expression | text / logs (matching lines) |
| `html` | a CSS selector (`sel` or `sel@attr`) | HTML |
| `sql` | `SELECT [DISTINCT] … FROM data WHERE … GROUP BY … HAVING … ORDER BY … LIMIT … OFFSET …` | a JSON array of objects |

`make build` bundles them into the binary. Point `--engine name=path.wasm`
at any wasip1 module you trust to add or override one.

## Writing your own query engine

A query engine is just a wasip1 command with a small contract, so you can
add a query language by writing one module — in any language that compiles
to `wasm32-wasip1` (Go, Rust, Zig, C, …). The contract:

- the **query** arrives as `argv[1]`
- the **data** arrives on **stdin** (the bytes the gateway fetched,
  cred-blind)
- the **result** goes to **stdout**
- **errors** go to **stderr** with a non-zero exit: `2` for a bad query or
  usage, `1` for a runtime failure. **Exit 2 must happen before the first
  stdin read** — the gateway returns exit-2 stderr to the caller as their own
  query diagnostic, so it must be provably built from the query text alone;
  runtime (exit 1) stderr can quote the data and stays operator-only
- it does **pure compute** — no network, no filesystem, no credentials. The
  runtime enforces this; your module couldn't reach them if it tried.

The `engines/` directory holds the built-ins as standalone modules, one per
directory. `engines/text` is the smallest — copy it as a template. Build
with `GOOS=wasip1 GOARCH=wasm go build` (or your language's equivalent),
then load it at runtime with `--engine name=path.wasm`, or drop it in
`engines/` and `make engines` to bundle it into the binary.

One caution worth stating plainly: a query engine runs over your data, so
only load a `.wasm` you trust. The sandbox stops an engine from reaching
the network or your credentials; it does not vet what the engine does with
the bytes it's given.
