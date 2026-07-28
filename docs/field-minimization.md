---
title: Field minimization
description: Redaction and tokenization of sensitive fields in the small results that return inline.
---

<!-- docs-last-updated -->
_Last updated: 2026-07-28_

Reference-by-default keeps *bulk* data out of context; field minimization is
the fine-grained complement, for the small results that do return inline. As
an upstream result passes back toward the model, a pipeline of bundled
wasip1 minimizers scans its field values and can redact or **tokenize** the
sensitive ones — replacing a value with a stable placeholder (`<mtok_…>`)
instead of the real bytes. When the model later passes a placeholder back on
an outbound call, the gateway resolves it to the real value before the
request leaves — so the model can *reference* a secret it never saw.
Placeholders are keyed by a per-session secret and scoped to the principal
and upstream they came from.

This is **on by default**: an upstream with no explicit policy gets a
conservative default that protects detected sensitive fields, and the
operator opts *down* by setting a policy from the console (microagency also
auto-suggests one from each upstream's tool schemas). The count of fields
protected per call shows up in the run record and the impact metrics. If you
see tokenized values in a result, that's this pipeline — the real data is on
the gateway, resolved only on the outbound call.
