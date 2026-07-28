---
title: The tool index
description: How find_tools and call_tool keep a thousand tools out of the context, and how invocation is gated.
---

<!-- docs-last-updated -->
_Last updated: 2026-07-28_

Upstream tools are not added to `tools/list`, because hundreds of tool
schemas would swamp the model's context. They live in an index instead. The
agent searches the index with `find_tools` (returns names, descriptions,
and schemas) and invokes matches with `call_tool`, so you can aggregate as
many servers as you like and the context stays small. Ranking is
keyword-based, with past usage as a tiebreaker; an embedding ranker can
replace the scorer later without changing the tool surface.

## Enabled and discovered

An upstream is either enabled or discovered. Discovered means its tools are
findable in the index but `call_tool` refuses to run them; enabling is an
explicit operator action in the console. This keeps the index broad (you can
import the whole registry) while invocation stays operator-granted.
Discovery never auto-enables anything.

## Keeping the index current

The index is captured when an upstream is added, enabled, or rebound. An
upstream's tool set can change afterward — tools added or removed, schemas
revised — so `POST /admin/upstreams/{name}/refresh` re-lists it on demand,
keeping `find_tools` and the pre-egress write guard working against current
schemas rather than a stale snapshot.
