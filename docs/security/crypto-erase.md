<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# Crypto-erase, mandatory tombstones, and erasure attestation (#1956 / R56)

This document is the **honest boundary** for what ai-memory's erasure
primitives do and do not guarantee. It covers the v1.0.0 R56 work
(issue #1956): per-record envelope-key destruction, mandatory tombstones
on every delete path, and the signed erasure attestation.

## What "erasure" means per record class

Deleting a memory does three things, gated on the record's at-rest class:

| Record class | On delete | Guarantee |
|---|---|---|
| **Encrypted, per-record envelope (`0x03`)** | The per-record Data Encryption Key (DEK) is **destroyed** (the `encrypted_envelope` BLOB is overwritten with the `0x04` erased marker), then the row is deleted + tombstoned | **Crypto-erased** — the ciphertext is cryptographically unrecoverable, even by a holder of the master key |
| **Plaintext at rest** (encryption disabled) | Row-deleted + tombstoned | **Deleted** — NOT crypto-erased; a plaintext row can only be removed, not cryptographically shredded |
| **Legacy per-agent envelope (`0x02`)** | Row-deleted + tombstoned | **Deleted, NOT crypto-erased** — the `0x02` scheme sealed content directly to a *shared* per-agent key, so there is no per-record key to destroy (see below) |

The erasure attestation records which of these happened in its
`erasure-kind` field: `key-destroyed` or `row-deleted-tombstoned`.

## The per-record key model (what makes crypto-erase real)

At-rest encryption (#228) originally used **one X25519 keypair per
`agent_id`** and sealed each memory's content directly to it. Under that
scheme there is nothing per-record to destroy — the only secret needed to
decrypt any row is the long-lived per-agent key, shared by every row that
agent wrote. Destroying it would brick the whole agent, not one record.

R56 introduces the standard **envelope-encryption** model on top of that
scheme, encoded as envelope version `0x03`:

1. Each record gets a fresh **random 32-byte DEK**.
2. The content is encrypted under the DEK.
3. The DEK is **wrapped** (encrypted) under the per-agent X25519 key —
   which now serves as the master **Key-Encryption-Key (KEK)** — and the
   wrapped DEK is embedded in the same `encrypted_envelope` BLOB.

Because the DEK is random and only ever persisted in wrapped form,
**destroying the wrapped DEK makes the DEK — and therefore the
ciphertext — unrecoverable, even to a holder of the master KEK.** That is
the cryptographic erasure primitive.

New encrypted writes use `0x03` automatically. Rows written before this
change carry the legacy `0x02` envelope and are, honestly, NOT
crypto-erasable — they fall back to row-delete + tombstone.

## Mandatory tombstones on every delete path

A delete that leaves no tombstone lets a federated peer resurrect the row
via last-writer-wins. R56 closes that on every path that removes a row
from `memories` without a recoverable copy:

- `forget` / `forget_for_caller` — already tombstoned (v71 / G30);
  now also crypto-erase + attest.
- `gc` (TTL expiry, **hard-delete** path) — now tombstones + crypto-erases
  + attests.
- `size_gc` (byte-cap eviction, **hard-delete** path) — same.

**`archive` is a move, not an erasure.** `gc`/`size_gc` with `archive=true`
and `archive_memory_no_tx` copy the row to `archived_memories` (restorable),
so they do **not** tombstone — a tombstone there would wrongly block a
legitimate restore. The erasure point for archived rows is the archive
reaper; tombstoning that path is tracked as a follow-up.

## Erasure attestation

Every delete/erase path emits a signed `substrate.crypto_erase` event on
the append-only `signed_events` chain, committing
`{record id, erasure-kind, actor, timestamp}`. It is chained and verified
by `verify-audit-trail` like every other signed event. The event carries
**no content** (a content fingerprint would re-leak the erased row).

## ATTESTABLE vs ESTIMABLE — the honest limits

- **ATTESTABLE** (cryptographically enforced): for a `0x03` row, key
  destruction + the signed erasure event are real, verifiable facts. After
  erasure the ciphertext cannot be decrypted from the live store by anyone,
  KEK-holder included.
- **ESTIMABLE** (operationally conditional): the *operational* guarantee
  that "this memory is gone" depends on two things outside the primitive's
  control:
  1. **Encryption must have been enabled** when the row was written
     (`AI_MEMORY_ENCRYPT_AT_REST=1` / `[encryption].at_rest`). A plaintext
     row can only be deleted, never crypto-erased.
  2. **Master-key custody is the trust root.** Crypto-erase destroys the
     per-record wrapped DEK; the master KEK's confidentiality is assumed.
     A leaked master KEK does not help recover an *erased* record (the
     wrapped DEK is gone), but the whole scheme rests on the KEK not being
     exfiltrated for records that are *not* yet erased.
- **Out of scope:** pre-erasure backups, snapshots, and WAL segments taken
  *before* the erase captured whatever the DB held at that instant — as is
  true of any in-database erasure scheme. Crypto-erase makes the plaintext
  unrecoverable from the **live store and all forward reads / exports /
  replication**; it cannot reach into a copy that was taken earlier.
