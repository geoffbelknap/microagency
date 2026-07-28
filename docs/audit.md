---
title: The audit chain
description: The signed, hash-chained log every call lands in, and how to verify it.
---

<!-- docs-last-updated -->
_Last updated: 2026-07-28_

Every run and proxied call is written to an append-only audit log. Each line
is hash-chained to its predecessor and **signed** (ES256) over that hash
with a per-gateway key at `~/.microagency/audit-key`. The signature is what
makes the log tamper-evident against someone who can write the file: the
chain hash is public and recomputable, so a hash chain alone lets an
attacker rewrite a record and recompute every hash after it — the signature
can't be recomputed without the private key, so an edited, inserted, or
reordered line is caught. The log is also verifiable offline by anyone
holding only the public key. Verify from the console (Activity → verify
audit chain) or with `GET /admin/audit/verify`, which reports lines
checked, how many were chained and signed, and the first break.

## Tail truncation and the head anchor

Wholesale **tail truncation** — deleting the last N lines leaves a validly
signed prefix, which the in-file chain can't see — is caught by an
**out-of-band head anchor**: every ~64 appends microagency records the log's
height (chained line count) and head hash, signed, in the **secret store**,
and verification flags a log shorter than its anchor as truncated. This is
real protection when the secret store is OpenBao/Vault, where a log-file
attacker can't reach the anchor; with the file-fallback store the anchor
sits on the same disk (weaker — but it's signed, so it can't be *lowered* to
hide a truncation without the audit key). The residual window is the
up-to-64 most-recent lines since the last anchor.

Keeping the signing key in a KMS or the secret store rather than a local
file is the remaining hardening path when the log and the key would
otherwise share one disk. Without a signer configured the log falls back to
an integrity-only chain: it still catches accidental corruption and naive
edits, but not a key-less attacker who recomputes the hashes.
