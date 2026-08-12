---
title: Measuring context cost
description: Exact schema and response byte accounting, task correlation, and the reproducible offline baseline.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

microagency measures the serialized MCP tool-result bytes it returns to the
model. The operator console shows the schema and response costs separately;
the same data is available as JSON at `GET /admin/metrics` and in Prometheus
format at `GET /admin/metrics/prometheus`.

The byte counts are exact. The token count is an estimate, reported as
`bytes / 4`, because the gateway does not observe the downstream model or its
tokenizer.

## What is measured

The `context` section separates three stages:

- `discovery` counts `find_tools` calls, query bytes, result bytes, full
  schemas, schema digests, summarized entries, omitted entries, and latency.
- `invocation` counts `call_tool` calls, raw upstream bytes, parked bytes,
  bytes removed by field minimization, result bytes, and latency.
- `reduction` counts `reduce` calls, bytes processed off-context, raw reducer
  output, parked output, result bytes, and latency.

Counters are cumulative and rebuild from the tamper-evident audit log after a
restart. Stage p50 latency and task aggregates cover the bounded recent-run
window shown by the console.

`output_bytes` on a newly measured run is the exact serialized tool result,
including its content wrapper. `raw_bytes` is the result before parking or
minimization. `parked_bytes` is the payload retained behind a reference.
Historical audit entries keep their original meaning and are not relabeled as
exact context measurements after an upgrade.

## Correlating a task

All three tools accept the same optional `task_id`. Use a short opaque run ID
on each `find_tools`, `call_tool`, and `reduce` call that belongs to one task:

```json
{
  "query": "search reports",
  "task_id": "run-123:attempt-2"
}
```

The gateway reports discovery calls and exact-schema escalations per task. It
also distinguishes a separate `call_tool` then `reduce` trip from an integrated
invoke-and-reduce trip.

Do not put prompts, names, email addresses, or other user data in `task_id`.
microagency accepts only a 64-byte opaque identifier, stores a one-way digest
for correlation, and never exports task IDs as Prometheus labels. Metric
records contain byte counts, stage outcomes, and bounded counters—not queries,
schemas, results, prompts, credentials, or raw payloads. The normal audit
contract still records upstream tool arguments.

## Reproduce the baseline

The offline fixture covers a 64-tool catalog, relevant-tool selection, schema
availability for valid arguments, a large parked response, a separate
reduction, and task completion:

```sh
go test ./internal/mcp -run TestContextCostBaseline -v
```

It uses an in-memory upstream, reference store, and query engine. It does not
start a microVM or make a network request. The test prints a JSON report and
fails if tool selection, exact accounting, privacy properties, context budgets,
or the correlated task path regress.
