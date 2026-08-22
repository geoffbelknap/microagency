---
title: The tool index
description: How find_tools and call_tool keep a thousand tools out of the context, and how invocation is gated.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

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
