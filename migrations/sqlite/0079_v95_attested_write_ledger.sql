-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3419 — schema v95: the ATTESTED-WRITE REPLAY LEDGER.
--
-- The defect
-- ----------
-- `identity::attest::prepare_signed_store` validated a caller-presented
-- Ed25519 write signature by shape and by the ±`ATTEST_CREATED_AT_SKEW_SECS`
-- (300 s) freshness window and nothing else. Ed25519 signatures are
-- re-verifiable in perpetuity by construction, so within that window the SAME
-- captured `POST /api/v1/memories` body verified an UNBOUNDED number of times:
-- a network observer (or anything that logged a request body) could re-submit
-- it to mint duplicate rows, or to RESURRECT a memory the owner had deleted,
-- each landing `attest_level="agent_attested"` with a genuine signature. The
-- federated `/sync/push` surface has carried an `X-Memory-Nonce` guard since
-- v0.7.0 (#922 `federation_nonce_cache`); the direct write surfaces had none.
--
-- The ledger
-- ----------
-- One row per attested write ENVELOPE that this node has already accepted:
--
--   * `fingerprint` — SHA-256 over the length-prefixed
--     `(agent_id, created_at, signature)` triple
--     (`identity::attest::attested_write_fingerprint`). It is the PRIMARY KEY,
--     so "have we accepted this envelope before?" is answered by the storage
--     engine's own uniqueness constraint rather than by a check-then-act
--     read: two concurrent submissions of the same body cannot BOTH be
--     admitted, on either backend. Fail-closed by construction.
--   * `agent_id` / `created_at` — forensics: which signer, and which signed
--     instant, the refused envelope belonged to. Never load-bearing for the
--     decision (the fingerprint already commits to both).
--   * `seen_at` — unix epoch SECONDS at admission, stamped by the server
--     clock. An INTEGER (not a rendered timestamp) so the retention predicate
--     is a numeric comparison that cannot be confused by an RFC3339 offset
--     rendering, and so the sqlite and postgres twins compare identically.
--
-- Bounded by construction
-- -----------------------
-- Retention is exactly the replay window the freshness gate already enforces:
-- an envelope admitted at T can only ever be re-presented while its
-- `created_at` is still within ±300 s of the wall clock, i.e. at worst until
-- T + 2×300 s. Rows older than that are refused by the freshness gate before
-- the ledger is ever consulted, so they carry no information. Every admission
-- therefore prunes `seen_at < now - 600` first: at steady state each INSERT
-- retires roughly one expired row, so the table is amortised O(1) per write
-- and its size is bounded by the attested-write RATE, never by history. The
-- supporting index keeps that prune a range scan rather than a table scan.
--
-- PURE ADDITIVE `CREATE TABLE IF NOT EXISTS` — no full-table rebuild (so the
-- v63/v65 "a rebuild silently drops every trigger" hazard does not arise), no
-- backfill, and no existing row is read or rewritten. Reversible (revert is
-- DROP TABLE + lowering the stamp); NoLoss. Also mirrored inline in the
-- bootstrap `SCHEMA` const so a fresh install carries it without replaying the
-- ladder. Postgres twin: `PostgresStore::migrate_v95` /
-- migrations/postgres/0052_v95_attested_write_ledger.sql.

CREATE TABLE IF NOT EXISTS attested_write_ledger (
    fingerprint BLOB    NOT NULL PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    seen_at     INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_attested_write_ledger_seen_at
    ON attested_write_ledger(seen_at);
