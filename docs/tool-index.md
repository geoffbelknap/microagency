---
title: The tool index
description: How find_tools and call_tool keep a thousand tools out of the context, and how invocation is gated.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-25_

Upstream tools are not added to `tools/list`, because hundreds of tool
schemas would swamp the model's context. They live in an index instead. The
agent searches the index with `find_tools` (returns names, descriptions,
and schemas) and invokes matches with `call_tool`, so you can aggregate as
many servers as you like and the context stays small.

## Local ranking

An exact namespaced tool name always ranks first. Other queries use a local
BM25 lexical rank over tool names, descriptions, and schema property names.
The tokenizer handles separators, camel case, conservative word stems, and a
small set of generic aliases such as `remove`/`delete` and
`meeting`/`event`. Past usage breaks equal-score ties.

Ranking runs over the caller's scoped index. Catalog text and schemas stay in
the gateway; the ranker makes no model or embedding request. Owner-scoped
tools are removed before scoring, not filtered from a shared result afterward.

The operator can inspect one scoped rank without receiving descriptions,
schemas, arguments, or example values:

```sh
curl -H "Authorization: Bearer $OPERATOR_TOKEN" \
  "http://127.0.0.1:8765/admin/tools/rank?q=reschedule+meeting"
```

`subject` selects whose scoped index to rank, as a principal key
(`issuer#subject`, URL-encoded); it defaults to the local caller.

The response reports names, scores, matched query terms, exact-name status,
and usage. The query is not stored as ranking telemetry.

## Reproduce the ranking baseline

The checked-in fixture covers exact names, synonyms, similar tool families,
ambiguous providers, schema-property lookup, a 145-tool catalog, ownership
isolation, and malformed input:

```sh
go test ./internal/mcp -run TestToolRankingEval -v
```

It compares the previous substring scorer with the selected ranker and prints
Recall@5, MRR, serialized result bytes, latency, follow-up discovery calls,
and argument-schema validity. It also evaluates bounded fixture-owned usage
examples. Those examples do not improve MRR or argument validity in the
current corpus, so production ranking does not load or return example text.

## Naming and disambiguation

A tool is indexed under `<connection>__<tool>`, so the connection a call lands
on is part of the name the agent uses. Connection names are unique, and a
self-service connection's name is generated, which makes it unambiguous but not
meaningful: `supabase-e7592ae6a9544beb2f` says nothing about which project it
reaches.

That is a problem when one template admits more than one connection. A template
with `max_per_user` above one exists so a user can connect the same provider
twice — production and staging, two workspaces, two accounts. Both connections
run the same upstream software, so their tools carry identical names, identical
descriptions, and identical input schemas. Ranking cannot separate them, because
neither is a better match for any query. The names differ only in a random
suffix, which tells the agent nothing about which one it wants.

So the gateway does not let the agent guess. `call_tool` refuses a tool name
that resolves to a connection the caller cannot tell apart from another one:
same template, same upstream tool, both visible and invocable for this caller,
and nothing distinguishing them. The refusal names the connections involved —
they are all in this caller's own index, so it discloses nothing the caller
could not already see — and states the remedy. `find_tools` marks the same
candidates with `"ambiguous": true` at discovery time, so the tie is visible
before a call is spent on it.

Connections from *different* templates are not affected. Their descriptions and
schemas differ, the ranker separates them, and a tool that reads on a Postgres
connection and a tool that reads on a GitHub connection were never the same
choice.

### Labels

A label is the remedy. It is a short human-meaningful name for one connection,
returned as its own field beside that connection's tools:

```json
{
  "name": "supabase-e7592ae6a9544beb2f__execute_sql",
  "label": "production",
  "description": "Run a SQL statement against the project database",
  "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
}
```

Two connections carrying distinct labels are distinguishable, and calls to
either run normally. A connection with no label, or one whose label another
sibling also carries, is still a guess and is still refused. Labels are compared
without regard to case, so `prod` and `PROD` do not tell two connections apart.

Set one on your own connection with the self-service API or the account portal,
and on a shared connection with the operator API or the console:

```sh
curl -fsS -X PATCH https://gateway.example/connections/supabase-e7592ae6a9544beb2f \
  -H "Authorization: Bearer $MCP_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"label": "production"}'
```

A label is text a model reads, so it is held to an identifier's rules rather
than a string's. It may be up to 32 characters of ASCII letters, digits, single
interior spaces, and `-`, `_`, `.`, and it must contain at least one letter or
digit. Line breaks, tabs, other control characters, zero-width and
bidirectional formatting characters, non-ASCII characters, leading and trailing
spaces, and `__` are refused. A label that breaks any of these rules is rejected
when it is set, with the reason — never trimmed or rewritten into something
acceptable, so the label you set is the label you read back. Sending an empty
label removes it.

The label is always its own field. It is never concatenated into a description,
so it cannot end or extend the prose around it.

An [operation grant](operation-grants.md) names one connection exactly, so a
call authorized by a matching grant was not a guess and is never refused as
ambiguous.

## Enabled and discovered

An upstream is either enabled or discovered. Discovered means its tools are
findable in the index but `call_tool` refuses to run them; enabling is an
explicit operator action in the console. This keeps the index broad (you can
import the whole registry) while invocation stays operator-granted.
Discovery never auto-enables anything.

## Keeping the index current

The tool set is captured when an upstream is added, enabled, or rebound.
Ranking rebuilds its lexical view from the current caller-scoped snapshot for
each request, so there is no separate cached search index to invalidate. An
upstream's tools can still change afterward, so
`POST /admin/upstreams/{name}/refresh` re-lists them on demand. This keeps
`find_tools` and the pre-egress write guard working against current schemas.
