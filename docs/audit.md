---
title: The audit chain
description: The signed, hash-chained log every call lands in, and how to verify it.
---

<!-- docs-last-updated -->
_Last updated: 2026-08-12_

Every run and proxied call is written to an append-only audit log. Each line
is hash-chained to its predecessor and **signed** (ES256) over that hash
with a per-gateway key at `~/.microagency/audit-key`.

The signature is what makes the log tamper-evident against someone who can
write the file. The chain hash is public and recomputable, so a hash chain
alone lets an attacker rewrite a record and recompute every hash after it.
The signature cannot be recomputed without the private key, so an edited,
inserted, or reordered line is caught.

The log is also verifiable offline by anyone holding only the public key.
Verify from the console, under Activity → verify audit chain, or with
`GET /admin/audit/verify`. It reports lines checked, how many were chained
and signed, and the first break.

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
