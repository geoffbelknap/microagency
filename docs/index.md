---
title: microagency docs
description: One MCP connection for every server, with credentials, datasets, and tool clutter kept out of the model.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-13_

microagency is an MCP gateway. Point Claude Code, Claude Desktop, Cursor, or
any MCP client at it and put your servers behind it; one connection replaces
all of them. The agent sees three tools — `find_tools`, `call_tool`,
`reduce` — however many servers you connect. Credentials stay in the
gateway, large results are processed off-context, and every call lands in a
tamper-evident audit log.

[Why microagency exists and the shape of the system](../ARCHITECTURE.md) is
the conceptual overview. These pages cover each mechanism:

- [Getting started](getting-started.md) — install, connect a client, add
  servers, build from source.
- [Connecting clients and credentials](connect-clients.md) — the four auth
  modes and where every secret lives.
- [The tool index](tool-index.md) — how `find_tools` and `call_tool` keep a
  thousand tools out of the context, and how invocation is gated.
- [Operation and resource grants](operation-grants.md) — exact caller,
  operation, argument, resource, destination, and budget authority for shared
  gateways.
- [Large results and reduce](reduce.md) — reference handles, query engines,
  the microVM path, and writing your own engine.
- [Field minimization](field-minimization.md) — redaction and tokenization of
  sensitive fields in inline results.
- [The audit chain](audit.md) — the signed, hash-chained log and how to
  verify it.
- [Measuring context cost](context-metrics.md) — exact schema and response
  byte accounting, task correlation, and the offline baseline.
- [Public mode and multi-user gateways](public-mode.md) — remote MCP for the
  Claude/ChatGPT web apps, and sharing one gateway safely.
- [Direct-upstream mediation](mediation.md) — advisory local checks and a
  gateway-only locked egress policy for governed workspaces.
- [The security model](security-model.md) — each guarantee and where it is
  enforced.
- [Operating the gateway](operations.md) — the CLI surface, state files,
  doctor, and purge.
