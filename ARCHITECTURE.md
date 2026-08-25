# How microagency works

This is the conceptual overview: why microagency exists and the shape of the
system. If you just want to run it, the [README](README.md) covers that in
two commands; each mechanism has its own page under [docs/](docs/index.md).

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
can itself be sensitive. The accurate claim is a much smaller aperture, not
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

## The mechanisms

Each part of the system has its own page:

- [Connecting clients and credentials](docs/connect-clients.md) — the built-in
  OAuth server, static bearer, external issuer, stdio mode, and where every
  secret lives (an external Vault/OpenBao, an AES-256-GCM file under a data
  key a protector holds — this host's own keychain by default — or, only on an
  explicit opt-in, the unencrypted mode-0600 file).
- [The tool index](docs/tool-index.md) — why upstream tools live in an index
  instead of `tools/list`, the enabled/discovered split that gates
  invocation, index refresh, and the connection labels that keep two
  connections from one template from becoming a coin flip.
- [Large results and reduce](docs/reduce.md) — reference handles and their
  structural previews, the query engines, the microVM path for real code,
  the experimental read-only program broker, and the contract for writing
  your own engine.
- [Field minimization](docs/field-minimization.md) — redaction and
  tokenization of sensitive fields in the small results that return inline.
- [The audit chain](docs/audit.md) — the signed, hash-chained log, the head
  anchor that catches tail truncation, and how to verify.
- [Measuring context cost](docs/context-metrics.md) — exact schema and response
  byte accounting, task correlation, and the offline baseline.
- [Public mode and multi-user gateways](docs/public-mode.md) — remote MCP
  for web apps, built-in or external OAuth, federated sign-in and the declared
  audience that bounds who may sign in, the admin/tunnel split, and
  operator-approved self-service connections with principal-bound credentials.
- [Operation and resource grants](docs/operation-grants.md) — exact
  principal/campaign operation authority, argument and destination bounds,
  finite budgets, and the fail-closed decision ledger.
- [Direct-upstream mediation](docs/mediation.md) — the explicit advisory
  local-host posture and the enforced gateway-only workspace contract.
- [The security model](docs/security-model.md) — each guarantee and where it
  is enforced.
- [Operating the gateway](docs/operations.md) — the CLI, state files,
  doctor, and purge.
