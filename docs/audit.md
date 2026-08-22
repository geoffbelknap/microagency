---
title: The audit chain
description: The signed, hash-chained log every call lands in, and how to verify it.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-22_

Every discovery, proxied call, and reduction is written to an append-only
audit log. Each line is hash-chained to its predecessor and **signed** (ES256)
over that hash with a per-gateway key at `~/.microagency/audit-key`.

The signature is what makes the log tamper-evident against someone who can
write the file. The chain hash is public and recomputable, so a hash chain
alone lets an attacker rewrite a record and recompute every hash after it.
The signature cannot be recomputed without the private key, so an edited,
inserted, or reordered line is caught.

The log is also verifiable offline by anyone holding only the public key.
Verify from the console, under Activity → verify audit chain, or with
`GET /admin/audit/verify`. It reports lines checked, how many were chained
and signed, and the first break.

## Argument capture

Every proxied call records the upstream, tool, caller, byte counts, latency,
and outcome. What the record keeps of the tool **arguments** depends on how
the gateway authenticates its callers.

A single-user gateway — the default local OAuth, stdio, or static bearer —
records the full arguments. The operator reading the log is the same person
whose calls produced it.

A multi-user gateway (an external `--issuer`) serves many authenticated
users, so full capture would concentrate every caller's raw arguments in one
operator-readable file. There, each record instead carries the argument
**structure** — keys, value types, string byte counts — and a SHA-256 digest
of the canonicalized arguments, never the values. Such records are marked
`"args_capture": "structure"`.

The digest keeps records provable without retaining values. To verify a
claimed argument set, canonicalize it — object keys sorted, no insignificant
whitespace, number literals preserved as sent, no HTML escaping — then
compare its SHA-256 against the record's `args_sha256` in the signed chain.

An operator can opt one connection back up to full capture:

```sh
curl -fsS http://127.0.0.1:8766/admin/upstreams/github/audit-capture \
  -H "Authorization: Bearer $MICROAGENCY_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' --data '{"full_args": true}'
```

Records from an opted-up connection carry `"args_capture": "full"`. The
opt-up is visible in the upstream list (`audit_full_args`) and disclosed by
`microagency doctor` as part of the auth posture. Calls authorized by an
operation grant keep their existing record shape regardless: no raw
arguments, opaque resource IDs (see the decision ledger below).

## Governed decision ledger

Operation grants use a separate `decision-ledger.jsonl`. Before a governed
call leaves the gateway, microagency reserves its finite grant budget, fsyncs
a signed authorization record, and updates the out-of-band anchor in the
secret store. Any failure refuses the call. Unlike the general activity log,
this anchor is updated for every decision because it is part of the
authorization path.

Refusals record the principal, campaign, grant, operation, and reason.
Authorized records add the effect, byte reservation, and opaque resource IDs.
Neither record contains raw arguments or results. Verify the chain and its
anchor through `GET /admin/decisions/verify`. See
[operation and resource grants](operation-grants.md) for the grant and budget
contract.

Governed programs keep the same per-call records. Each brokered discovery and
proxy call has `delivery: "program"`, the outer reduce's `parent_run_id`, and
its run-scoped `program_request_id`. Because those results went to the
sandbox rather than the model, their `output_bytes` contribution to context
is zero; raw, parked, and minimized byte accounting remains on the proxy
record. The outer reduce record summarizes `program_tools`, `program_calls`,
`program_bytes`, and `program_status`. Replay decisions and pre-egress policy
denials are separate child records under the same parent. The broker
capability path, credentials, and intermediate result bodies are not logged.

## Tail truncation and the head anchor

Deleting the last N lines leaves a validly signed prefix, which the in-file
chain cannot see. Wholesale **tail truncation** is caught instead by an
**out-of-band head anchor**.

Every 64 appends or so, microagency records the log's height and head hash,
signed, in the **secret store**. Height is the chained line count.
Verification then flags a log shorter than its anchor as truncated.

This is strongest when the secret store is OpenBao or Vault, where a log-file
attacker cannot reach the anchor. The encrypted file fallback prevents an
attacker who has only `~/.microagency` from reading or forging the anchor, because
its key is held separately. It cannot prevent replay of a previously copied,
valid ciphertext. The degraded plaintext fallback keeps the anchor readable on
the same disk. The signature detects edits, but not replay of an older valid
anchor. The residual window under the normal posture is the 64 most-recent lines
since the last anchor.

When the log and the key would otherwise share one disk, the remaining
hardening path is to keep the signing key in a KMS or the secret store.

Without a signer configured, the log falls back to an integrity-only chain.
It still catches accidental corruption and naive edits. It does not catch a
key-less attacker who recomputes the hashes.
