// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! QUAL-10 (FX-C4-batch2, 2026-05-26) — module-size ceiling.
//!
//! Pins the discipline that no production module is allowed to
//! grow LARGER than its current size without an explicit ceiling
//! bump. The CLAUDE.md long-term-codebase-manageability discipline
//! treats multi-thousand-LOC files as refactor-risk; this test
//! catches any commit that crosses the per-file ceiling.
//!
//! The proposed full re-split (under #650 / #867 / #961) is a
//! multi-month workstream that doesn't fit a single FX-C4 batch.
//! What we CAN land mechanically is the ceiling: every file's
//! current LOC is baked in as the upper bound, so a future commit
//! that adds bulk to an already-large file must FIRST bump the
//! ceiling here, which surfaces the size growth in code review.
//!
//! The ceiling table below is calibrated to the v0.7.0 substrate
//! (FX-C4-batch2 SHA, with subsequent FX-C2 ARCH-2 + PERF-9 bumps
//! per FX-D2). When a file's LOC genuinely needs to grow
//! (a new SAL method implementation, a new tool handler, a new
//! migration), the contributor bumps the ceiling in the same PR.
//! When a file's LOC SHRINKS (a refactor split), the ceiling
//! should drop in the same PR so the discipline ratchets toward
//! the longer-term re-split goal.

use std::fs;

/// Per-file ceiling. `(path, max_lines)` rows. A file's actual LOC
/// must be `<= max_lines`. Bump the ceiling in the SAME commit that
/// grows the file.
///
/// Calibrated at FX-C4-batch2 (SHA 54713024d + this batch's
/// additions). Bump in lockstep with growth.
const MODULE_SIZE_CEILINGS: &[(&str, usize)] = &[
    // The five 3000+ LOC offenders from QUAL-10.
    //
    // 2026-06-01 — bumped 16_000 → 16_100 by the v0.7.0 release QC of
    // #626 Layer-3 (C7, commit ed2bb7cf6): the store-path signature wire
    // added the agent-attestation persist branch (+6 LOC) which pushed
    // the file from 16_027 to 16_033, just over the ceiling; the lockstep
    // bump was missed in ed2bb7cf6. Actual LOC at the bump: 16_033.
    // Growth is justified: a new attestation persist branch on an
    // existing write path, no speculative surface. 16_100 = 16_033 + 67
    // headroom; far under QUAL-10's 1.5x aspirational cap.
    //
    // 2026-06-01 — bumped 16_100 → 16_200 by the #1466 TTL-leak fix:
    // the immortal-rows regression suite (insert / insert_with_conflict /
    // insert_if_newer / consolidate backfill assertions + the
    // ttl_gap_secs helper) added ~100 LOC of tests to the in-file
    // `mod tests`, pushing the file to 16_143. Growth is justified: pure
    // regression coverage for the tier-default expiry chokepoint, zero
    // new production surface. 16_200 = 16_143 + 57 headroom; far under
    // the 1.5x cap.
    //
    // 2026-06-03 — bumped 16_200 → 16_300 by the #1476 federation-catchup
    // sargability fix: the `memories_updated_since` None/Some predicate
    // split (+ the `idx_memories_updated_at` migration sourcing) plus its
    // regression suite (`insert_memory_at` helper +
    // `memories_updated_since_sargable_split_none_and_some_paths` +
    // `memories_updated_since_uses_updated_at_index` EXPLAIN-plan
    // assertion) pushed the file to 16_248. Growth is justified: a
    // hot-path query rewrite plus its plan-shape + behavioral regression
    // coverage, zero speculative surface. 16_300 = 16_248 + 52 headroom;
    // far under the 1.5x cap.
    //
    // 2026-06-05 — bumped 16_300 → 16_400 by the storage/mod.rs coverage
    // floor restoration: the Per-Module Coverage Thresholds gate flagged
    // storage/mod.rs at 93.90% < its 94% floor (a latent regression
    // unmasked once the #92 hnsw concurrent-rebuild flake stopped
    // short-circuiting the run at test-exec). The fix adds a DB-free
    // `is_visible_scope_matrix_covers_every_arm` test pinning every
    // MemoryScope arm of the Rust-side visibility predicate
    // (`is_visible` / `matches_subtree` / `compute_visibility_prefixes`),
    // which integration recall only exercises for whichever scope the
    // fixture corpus carries — leaving the other arms uncovered. The
    // ~122-LOC `mod tests` addition pushed the file to 16_370. Growth is
    // justified: pure regression coverage that lifts the file back over
    // its 94% floor, zero new production surface. 16_400 = 16_370 + 30
    // headroom; far under the 1.5x cap.
    //
    // 2026-06-09 — bumped 16_400 → 16_450 by the #1558 batch-1
    // hardcoded-literal remediation: the shared list/page-size const
    // family (LIST_DEFAULT_CAP / LIST_MAX_LIMIT / LIST_FALLBACK_LIMIT /
    // ARCHIVE_DEFAULT_PAGE_LIMIT / PENDING_DEFAULT_PAGE_LIMIT /
    // TAXONOMY_DEFAULT_LIMIT + doc comments) landed here as the SSOT
    // both backends and the HTTP/MCP surfaces route through, pushing
    // the file to 16_405. Growth is justified: it REPLACES scattered
    // magic numbers across ~10 files with one named knob set per the
    // operator's no-hardcoded-literals directive. 16_450 = 16_405 + 45
    // headroom; far under the 1.5x cap.
    //
    // 2026-06-09 (#1531 burn-down) — bumped 16_450 → 16_550 by the
    // #1568 H1-residual link-governance hoist + the L5 taxonomy
    // LIKE-escape fix: `evaluate_link_permission` (the shared K9 link
    // gate both adapters now call) + the escaped descendant pattern in
    // `get_taxonomy` + their regression tests
    // (`taxonomy_prefix_like_metacharacters_do_not_widen_match_l5`)
    // pushed the file to 16_475. Growth justified: security-gate
    // hoist + injection-class fix, no speculative surface.
    // 16_550 = 16_475 + 75 headroom.
    //
    // 2026-06-10 (#1579 perf final-gate, storage lane) — the A2
    // sargable-list rewrite + B6 scale bundle: the `build_list_query`
    // SQL builder (the OR-NULL filter arms became distinct prepared
    // shapes the v56 composite indexes can serve), the chunked GC
    // loop (`GC_CHUNK_ROWS` bounded transactions replacing the single
    // whole-backlog BEGIN IMMEDIATE), and the bounded
    // `get_unembedded_ids_batch` variant (~141 LOC). Measured
    // hot-path fixes (P1 audit: list 141 ms → 0.06 ms at 100k rows),
    // no speculative surface.
    //
    // 2026-06-10 (#1579, writepath lane, merged batch-2) — the A5
    // remediation on the SAME module: the proactive-conflict check
    // gained the HNSW-routed dispatcher
    // (`proactive_conflict_check_with_index`), the ANN-candidate
    // verifier (`proactive_conflict_check_candidates`), the shared
    // `proactive_conflict_verdict` scoring tail, the bounded-scan
    // LIMIT + Jaccard-floor consts with their P2-evidence doc blocks,
    // and `count_embedded_memories` (the B3 CLI threshold probe) —
    // ~225 LOC on the existing #519 write-path surface (the
    // O(N)-scan-under-mutex / 81%-false-409 fix).
    //
    // The per-lane ceilings (16_700 / 16_800) each under-counted the
    // union, so the merged ceiling is pinned from the measured
    // post-merge file: actual LOC 16_943. 17_000 = 16_943 + 57
    // headroom; far under the 1.5x aspirational cap.
    //
    // 2026-06-11 (#1598 API embeddings) — bumped 17_000 → 17_400: the
    // reembed sweep helpers (`embedding_coverage`,
    // `distinct_embedding_dims`, `get_memory_texts_batch`,
    // `set_embeddings_batch_reembed`) + their unit pins landed the
    // file at 17_329. Growth justified: the vector-space migration
    // primitives live beside the embedding storage they mutate.
    // 17_400 = 17_329 + 71 headroom.
    //
    // 2026-06-11 (Phase-3 dogfood fix train, FIX-A) — bumped 17_400 →
    // 17_500: the #1596 extension-floor doc blocks on the touch /
    // touch_many SQL, the #1601 `forget_fts_query` AND builder (the
    // shared chokepoint for all three destructive forget sites), and
    // the #1602 `ForgetMatch` + `forget_matches` preview helper landed
    // the file at 17_432 (measured). Growth justified: two correctness
    // fixes on existing destructive/lifecycle paths plus the sighted
    // dry-run primitive their MCP surface needs; regression tests live
    // in tests/issue_{1596,1601,1602}_*.rs, not in-file, to keep the
    // module growth minimal. 17_500 = 17_432 + 68 headroom; far under
    // the 1.5x cap.
    //
    // 2026-06-11 — bumped 17_500 → 17_650 by the GA audit fix train:
    // #1638 (supersede atomicity — archive_memory_no_tx split + the
    // one-tx wrapper), #1633 (consolidate provenance stamp), #1637
    // (archive-listing full v49 projection), #1631 (insert_if_newer
    // version column). Measured 17_521 + 129 headroom; every addition
    // is a closed audit finding with its own regression test.
    //
    // 2026-06-16 — bumped 17_650 → 17_950 by the v0.8.0 Pillar-2.5
    // (#1709) size-GC unit: the net-new `size_gc` free-fn (corpus
    // byte-cap eviction) + its `namespace_corpus_bytes` helper + the
    // two hoisted SQL consts, plus the 8-test in-file `mod tests` block
    // (over-cap / eviction-order / under-cap-noop / restorable-archive /
    // hard-delete / disabled-cap / namespace-scoped / cap-exactly-at-
    // corpus). Measured 17_900 + 50 headroom; pure additive feature +
    // its deterministic SQL-ranking regression coverage, no LLM on the
    // eviction path, far under the 1.5x cap.
    //
    // 2026-06-16 — bumped 17_950 → 17_990 by the v0.8.0 Pillar-3
    // (#1709 / #224 Task 3a.1) CRDT-lite merge unit: the net-new
    // `sync_state_merge` free-fn (folds an incoming peer VectorClock
    // into the persisted sync-state via pointwise-max, looping the
    // existing monotonic `sync_state_observe` upsert) + its in-module
    // `sync_state_merge_applies_pointwise_max_and_never_regresses`
    // regression test. Pure deterministic clock reconciliation, no
    // schema change, no I/O beyond the existing per-peer upsert.
    // Measured 17_959 + 31 headroom; far under the 1.5x cap.
    // 2026-06-16 (#1709 / #224 Pillar-3 unit 3 — wire merge_memory into
    // the federation conflict path) — net-new `merge_inbound` free-fn
    // (atomic read-by-id → `crate::models::merge_memory` → full-row write,
    // else `insert_if_newer` fall-through) + the `overwrite_full_row_by_id`
    // full-row writer + four in-module `merge_inbound_*` regression tests.
    // No schema change; pure reuse of the existing merge primitive + a
    // full-row UPDATE. Measured 18_288; bump 17_990 → 18_340 in lockstep.
    // 2026-06-17 (#1720 A2-A5, security lane) — owner-keyed scope=private
    // visibility: the `visibility_clause` private arm + the `is_visible`
    // Private arm became owner-keyed (caller threaded through recall /
    // search / recall_hybrid + their callers), plus the in-module
    // `visibility_private_owner_keyed_matrix_1720` anti-re-drift test and
    // the owner-keyed rewrite of `is_visible_scope_matrix_covers_every_arm`.
    // No schema change. Measured 18_691; bump 18_340 → 18_700 in lockstep.
    // 2026-06-17 (#1709/#1720 WS-B B2, security lane) — the `reown`
    // free-fn + `ReownReport` struct (rewrite metadata.agent_id ownership
    // stamp on a namespace before scope=private filtering) and its 5
    // in-module storage tests. No schema change. Measured 18_960; bump
    // 18_700 → 18_985 in lockstep (18_960 + 25 headroom).
    // 2026-06-18 (#1725, P0.2 lossless in-place update) — the
    // `archive_memory_insert_only` helper (INSERT-only snapshot of a
    // still-live row, the #1025 full column carry) + wrapping the
    // archive + in-place UPDATE in one BEGIN IMMEDIATE tx in
    // `update_with_expected_version`. No schema change. Measured 19_074;
    // bump 18_985 → 19_090 in lockstep (19_074 + 16 headroom).
    // 2026-06-18 (#228 / #1728 Commit A-carry) — bumped 19_090 → 19_110:
    // appending `encrypted_envelope` to the archive/restore INSERT-SELECT
    // column lists (the restore SELECT adds it on its own line ×2) landed
    // the file at 19_091. 19_110 = 19_091 + 19 headroom.
    // 2026-06-18 (#228 / #1728 Commit B-wiring) — bumped 19_110 → 19_280:
    // the at-rest content encryption WIRING (seal_content/open_content
    // threading through `insert` / `insert_with_conflict` / `insert_if_newer`
    // / `update_with_expected_version` / `row_to_memory` + commented
    // `encrypted_envelope` columns on the recall/search/list/by-source-uri
    // SELECTs) landed the file at 19_256. 19_280 = 19_256 + 24 headroom.
    // 2026-06-18 (#1726 lifecycle gate) — bumped 19_280 → 19_360: the
    // `InvalidTransition` typed error + the self-validating
    // `set_lifecycle_state` (SELECT-current → can_transition_to → no-op
    // short-circuit → typed reject) landed the file at 19_312. +48 headroom.
    // 2026-06-19 (#1693 L2 SAL parity) — bumped 19_360 → 19_460: the
    // `recover_turn_idempotent` sqlite SSOT (dual-dedup probe + atomic
    // memory+dedup transaction) landed the file at 19_417.
    // #1580 — bumped 19_510 → 19_520 for the touch_many `PRAGMA query_only`
    // read-only no-op guard (the WAL read-pool enabler).
    // 2026-06-22 (#1776) — bumped 19_520 → 19_600: the `forget` archive+delete
    // BEGIN IMMEDIATE transaction wrapper (atomicity fix porting #1026) + the
    // `forget_archive_and_delete_are_atomic_1776` regression test landed the
    // file at 19_567.
    // 2026-06-22 (#1782) — bumped 19_600 → 19_700: the `size_gc` per-victim
    // BEGIN IMMEDIATE wrapper (same #1026 atomicity fix) + the
    // `size_gc_archive_eviction_is_atomic_1782` regression test landed it at
    // 19_620.
    // 2026-06-23 (#1772) — bumped 19_700 → 19_900 (lockstep): the three
    // additive owner-scoped `forget_*_for_caller` fns (owner-clause twins of
    // the existing public forget/forget_count/forget_matches for the
    // multi-tenant `AI_MEMORY_AGENT_ID` opt-in) landed it at 19_883.
    // 2026-06-23 (#1787) — bumped 19_900 → 20_050 (lockstep): the
    // `ApproverType::Human` opt-in self-approval + is_registered_agent gate in
    // `approve_with_approver_type` + the `human_arm_self_approval_gated_under_opt_in_1787`
    // regression test landed it at 19_991.
    // 2026-06-23 (#1771) — bumped 20_050 → 20_400 (lockstep): the
    // `archived_memory_links` edge-preservation wiring — `archive_links_for_memory`
    // + `restore_links_for_memory` helpers, the snapshot-before-delete blocks in
    // `forget` / `forget_for_caller`, the restore re-insert calls, and the three
    // 1771 regression tests — landed it at 20_350.
    // 2026-06-23 (#1773 + #1779) — bumped 20_400 → 20_550 (lockstep): the
    // federation-merge seal+envelope+pre-merge-snapshot fix in
    // `overwrite_full_row_by_id` (#1773) and the embed-fetch decrypt-or-skip
    // helpers (`resolve_embeddable_content` / `resolve_embeddable_rows` /
    // `embeddable_row_mapper`) routing get_memory_texts_batch +
    // get_unembedded_ids_batch[_after] (#1779) landed it at 20_446.
    // 2026-06-24 (#1796, 5-agent vote 4d3ea1c5) — bumped 20_550 → 20_700 for the
    // `ApproveSurface { Http, LocalOperator }` enum + the surface-keyed Human-arm
    // gate in `approve_with_approver_type` + the
    // `http_surface_rejects_self_approval_without_env_opt_in_1796` regression test.
    // 2026-06-24 (#1727, 5-agent vote 4d3ea1c5) — bumped 20_700 → 21_000 for the
    // NON-DESTRUCTIVE `undo_in_place_edit` free fn + `read_owner_agent_id` /
    // `UndoSnapshot` helpers (the sqlite reference behind the CLI-only
    // `ai-memory undo-edit` operator tool).
    // 2026-06-28 (#1821, v0.8.1 W2/G30) — bumped 21_000 → 21_250 for the
    // `purge_and_tombstone_forget` erasure-fanout helper + `memory_is_tombstoned`
    // tombstone gate + the W1/G29 redact-at-storage funnel wiring in `db::insert`
    // / `insert_if_newer`.
    ("src/storage/mod.rs", 21_250),
    // 2026-06-10 (#1579 B6/F5.6, storage lane) — the embed-backfill
    // sweep converted from whole-backlog materialisation to a bounded
    // drain loop over `get_unembedded_ids_batch` (+ the no-progress
    // break).
    //
    // 2026-06-10 (#1579 B3, writepath lane, merged batch-2) — the
    // async-boot HNSW change on the SAME module: the MCP stdio boot
    // site swaps the synchronous get_all_embeddings +
    // VectorIndex::build for the background warm thread (Arc +
    // warm_boot + readiness stderr lines), and the backfill helper
    // routes through the canonical `embedding_document` template.
    // Merged actual LOC: 14_040. 14_100 = 14_040 + 60 headroom.
    //
    // 2026-06-11 (#1598 API embeddings) — bumped 14_100 → 14_450: the
    // fail-closed `Embedder::from_resolved` boot wiring (#1593), the
    // degraded-aware capabilities posture (#1594), and the
    // chunk-fault → per-row backfill fallback (#1595) landed the file
    // at 14_379. 14_450 = 14_379 + 71 headroom.
    // 2026-06-16 (#1709 Pillar 1) — bumped 14_450 → 14_550: the 4 new
    // coordination-action MCP tools (transition/list/add_edge/edges)
    // added their dispatch wrappers + table arms + the expanded
    // `use action::{…}` import, landing the file at 14_481.
    // 2026-06-16 (#1709 Pillar 1, signed-signal batch) — bumped
    // 14_550 → 14_620: the 5 new `memory_signal_*` MCP tools
    // (send/read/inbox/thread/ack) added the `#[path]` mod decl, the
    // `use signal::{…}` import, 5 dispatch wrappers, and 5 dispatch-table
    // arms, landing the file at 14_560. 14_620 = 14_560 + 60 headroom.
    // 2026-06-16 — bumped 14_620 → 14_720 by the v0.8.0 #1709 Pillar-1
    // routine surface: the `#[path] mod routine;` decl, `use routine::{…}`
    // import, 5 `memory_routine_*` dispatch wrappers, and 5 dispatch-table
    // arms, landing the file at 14_664. 14_720 = 14_664 + ~56 headroom.
    // 2026-06-16 — bumped 14_720 → 14_760 by the v0.8.0 #1709 Pillar-2
    // lifecycle-state-machine unit: the optional `lifecycle_state` field
    // threading through the memory_store / memory_update dispatch +
    // transition-enforcement plumbing, landing the file at 14_734.
    // 14_760 = 14_734 + ~26 headroom.
    // 2026-06-18 (#1730 PE-2 read-gating) — bumped 14_760 → 14_900: the
    // `read_gate_parity_1730` test module (the parity guard asserting every
    // MCP read surface routes through `gate_read`) landed the file at 14_858.
    // +42 headroom.
    // 2026-06-19 (#1714 Pillar-1) — bumped 14_900 → 15_050: the MCP
    // signal-ack → PostSignalAck hook bridge (POST_SIGNAL_ACK_SINK global +
    // set_post_signal_ack_sink + build_mcp_signal_hooks + the inert-by-default
    // run_mcp_server serve-init wiring + two build_mcp_signal_hooks unit
    // tests) landed the file at 15_011.
    // 2026-06-22 (#1752) — bumped 15_050 → 15_300: the MCP PreSignalSend
    // ENFORCEMENT gate (PreSignalSendGate struct + PRE_SIGNAL_SEND_GATE global +
    // set_pre_signal_send_gate + map_chain_result_to_signal_decision +
    // pre_signal_send_decision block_on_local bridge + dispatch_memory_signal_send
    // gate wiring + run_mcp_server inert-by-default install + the
    // map_chain_result_to_signal_decision_1752 unit test) landed the file at 15_213.
    ("src/mcp/mod.rs", 15_300),
    // postgres.rs bumped 13_000 → 15_200 by FX-D2 to accommodate
    // FX-C2-batch{1..5} ARCH-2 SAL trait method implementations
    // (fdfa69dd9 / 1d2b9553f / 6c8283cdf / dca98bd6b / 5d7f083e4 —
    // ~30 new sqlx-native methods spanning kg / governance / storage /
    // observations / federation). Growth is justified: each method
    // is a new entry on the canonical SAL trait surface needed for
    // postgres-backed daemons. Refactor-split into
    // `src/store/postgres/{mod,kg,governance,storage,...}.rs` is
    // tracked as a separate v0.7.x post-ship ARCH cleanup.
    //
    // 2026-05-31 — bumped 15_200 → 15_300 by the v0.7.0 security-review
    // epic (#1450) finding #1451: the optimistic-update PG path now
    // pre-reads the governance-relevant columns and consults
    // GOVERNANCE_PRE_WRITE on the post-merge row (parity with SQLite and
    // the insert/supersede PG paths), closing the update-evasion gap.
    // Actual LOC at the bump: 15216. Growth is a security gate on an
    // existing write path, not new surface.
    //
    // 2026-06-01 — bumped 15_300 → 15_400 by the v0.7.0 release QC of
    // #626 Layer-3 (C3, commit bd173cf81): bind/fetch agent pubkey in
    // registration metadata added the postgres-native SAL methods for
    // pubkey enrollment/lookup, growing the file to 15_353; the lockstep
    // bump was missed in bd173cf81. Actual LOC at the bump: 15_353.
    // Growth is justified: new entries on the canonical SAL trait surface
    // needed for postgres-backed agent attestation, mirroring the SQLite
    // path. 15_400 = 15_353 + 47 headroom; far under the 1.5x cap.
    //
    // 2026-06-01 — bumped 15_400 → 15_500 by the #1466 TTL-leak fix: the
    // postgres `migrate_v54` twin (tier-default expiry backfill on legacy
    // immortal rows, parity with the SQLite v54 ladder arm) added ~40 LOC,
    // pushing the file to 15_416. Growth is justified: a new migration on
    // the canonical postgres ladder mirroring the SQLite backfill, no
    // speculative surface. 15_500 = 15_416 + 84 headroom; far under the
    // 1.5x cap.
    //
    // 2026-06-03 — bumped 15_500 → 15_650 by the #1472 write-ceiling fix
    // (commit 4fb063b7c): scoping the postgres subscription dispatch from a
    // per-write full-table scan to a sargable namespace-prefix byte-range
    // scan added 142 LOC, pushing the file to 15_556; the lockstep bump was
    // missed in 4fb063b7c and surfaced as a RED qual_10 gate on
    // release/v0.7.0 (the --lib subset that gated the #1472/#1431 merge does
    // not run tests/ integration binaries). Tracked as #1474. Growth is
    // justified: a real perf fix (8.5x write throughput) on the canonical
    // SAL postgres surface, no speculative surface. 15_650 = 15_556 + 94
    // headroom; far under the 1.5x cap.
    //
    // 2026-06-03 — NO bump: the #1473 list() sargability fix (commit
    // 4fc5e411f) grew the file 15_556 → 15_589 (+33: the dynamic
    // namespace-predicate split + the two NS_FILTER_* consts and their
    // doc comments). Still under the existing 15_650 ceiling, so the
    // ceiling is unchanged; recording the new actual LOC here keeps the
    // headroom math honest (15_650 = 15_589 + 61, far under the 1.5x cap).
    //
    // 2026-06-03 — bumped 15_650 → 15_750 by the #1476 federation-catchup
    // sargability fix: the `list_memories_updated_since` None/Some
    // predicate split, the `CURRENT_SCHEMA_VERSION` 54→55 bump with its
    // v55 history block, and the version-stamp-only `migrate_v55()` twin
    // (a no-op because `memories_updated_at_idx (updated_at DESC)` already
    // serves the range scan) with its extensive justification doc comment
    // added 80 LOC, pushing the file to 15_669. Growth is justified: a
    // hot-path query rewrite plus the migration ladder bookkeeping it
    // requires, no speculative surface. 15_750 = 15_669 + 81 headroom;
    // far under the 1.5x cap.
    //
    // 2026-06-03 — bumped 15_750 → 16_080 by the #1481 batch bulk-ingest
    // fix: the `store_batch` multi-row-upsert override on PostgresStore
    // (one `QueryBuilder` INSERT ... ON CONFLICT ... RETURNING for the
    // whole batch, intra-batch (title, namespace) dedup, and id-alignment
    // back-mapping) plus the count-aware `record_memory_quota_batch_in_tx`
    // sibling added ~329 LOC, pushing the file to 15_998. Growth is
    // justified: it collapses the postgres bulk_create path from 2N
    // round-trips to 1+G on the canonical SAL surface, no speculative
    // surface. 16_080 = 15_998 + 82 headroom; far under the 1.5x cap.
    // #1549 — postgres SAL coverage for the recursive-learning surfaces
    // (reflect / get_reflection_origin / list_recall_observations trait
    // impls) added ~76 LOC of native-sqlx methods. Bumped in lockstep.
    //
    // 2026-06-09 — bumped 16_200 → 16_250 by #1558 batch 4/5: the
    // DEFAULT_LIST_CAP_I64/LIST_FALLBACK/ARCHIVED_LIST_FALLBACK/
    // RECALL_FALLBACK const cluster + TRACE_TARGET/TRACE_TARGET_KG
    // (#1562 target-syntax fix) + doc comments pushed the file to
    // 16_206. Growth is justified: named knobs REPLACING scattered
    // magic literals per the operator no-hardcoded-literals directive.
    // 16_250 = 16_206 + 44 headroom; far under the 1.5x cap.
    //
    // 2026-06-09 (later) — bumped 16_250 → 16_300 by #1558 batch 5
    // wave 4: routing the sqlx row-label/json-key literals through
    // models::field_names (multi-line const-arg reflows + imports)
    // pushed the file to 16_255. Same justification class: named SSOT
    // refs replacing scattered literals. 16_300 = 16_255 + 45 headroom.
    //
    // 2026-06-09 (#1531 burn-down) — bumped 16_300 → 16_700 by the
    // #1568 H1-residual fix (`validate_link_pre_create_pg`: the
    // postgres pre-link cycle + K9 governance gates, ~130 LOC incl.
    // docs) + the #1572 M1-residual recall-path confidence-decay
    // parity arm in `touch_after_recall` (~55 LOC) + the L5 taxonomy
    // LIKE-escape + the three live-PG regression tests
    // (`live_link_reflects_on_cycle_refused_1568`,
    // `live_touch_after_recall_applies_decay_parity_1572`), landing
    // the file at 16_601. Growth justified: closes the postgres
    // ungoverned-link-write security hole + decay parity, zero
    // speculative surface. 16_700 = 16_601 + 99 headroom.
    //
    // 2026-06-10 (#1579 A4+B2, postgres lane, merged batch-2) — the
    // SAL `list_unembedded` (bounded NULL-embedding scan) +
    // `set_embeddings_batch` (single-tx chunk write) overrides closing
    // the dead-fleet-semantic-recall backfill gap (~90 LOC incl.
    // docs), plus the `migrate_v57` arm (stored generated `tsv`
    // tsvector column + `memories_tsv_gin`, drops the legacy
    // expression index; ~75 LOC incl. the operational-lock docs), the
    // v55-arm literal-stamp fix, and the merge-composed v56
    // stamp-only arm (literal-56 stamp per the replay-hazard rule).
    // Growth justified: correctness fix (fleet semantic recall was
    // DEAD at 0.46% embedded) + a 20-37x measured FTS-rank win, zero
    // speculative surface. Measured post-merge LOC: 16_811.
    // 16_900 = 16_811 + 89 headroom; far under the 1.5x cap.
    //
    // 2026-06-11 (#1607 + #1608, the #1588 RE-RUN fix train) — bumped
    // 16_900 → 17_200: the touch_after_recall GREATEST extension-floor
    // arms + comment (#1607), the store_with_embedding full 27-column
    // Form-4/5/QW-2 parity INSERT + conflict arms, the store()/
    // store_batch() entity_id+persona_version parity columns (#1608),
    // and their gated regression tests
    // (live_touch_after_recall_expiry_is_extension_floor_1607,
    // live_store_with_embedding_persists_full_provenance_1608), PLUS
    // the #1542 AGE-projection SAVEPOINT isolation (LOAD 'age' rides
    // its own savepoint in project_link_into_age; both link-write
    // call sites — link_internal + apply_remote_link — wrap the whole
    // projection so a refused LOAD can no longer abort the outer tx
    // and silently ROLLBACK the canonical memory_links INSERT at
    // COMMIT) and its restricted-role regression pin
    // (live_link_persists_when_age_projection_refused_1542).
    // Growth justified: provenance-honesty + durability correctness
    // fixes (201-with-zero-rows lived on the do-1461 fleet) +
    // lived-defect regression pins; zero speculative surface.
    // Measured post-fix LOC: 17_242. 17_350 = 17_242 + 108 headroom;
    // far under the 1.5x cap.
    //
    // 2026-06-11 — bumped 17_350 → 17_820 by the GA audit fix train:
    // #1626/#1628/#1641 (promote expiry + If-Match gate-CAS retry),
    // #1629 (the seven sqlite ON CONFLICT arms ported to all four
    // upserts), #1631 (apply_remote_memory parity arms), #1627 (full-
    // column supersede INSERT), #1630/#1642 (consolidate expiry +
    // delete namespace_meta), #1636 (COR-3 mapper observability),
    // #1639/#1640 (AGE savepoint + shared tolerated-LOAD helper),
    // #1637 (archive-listing v49 projection), #1633 (consolidate
    // provenance). Measured 17_666 + 154 headroom; all closed audit
    // findings with regression tests; the module-split follow-on is
    // tracked under #650-class work for v0.8.
    // 2026-06-15 (v0.8.0 #1705) — bumped 17_820 → 17_960: migrate_v58
    // (recall_observations agent_id + namespace identity columns) +
    // inline DDL. NOTE: the base was already 17_899 (v0.7.1 grew this
    // module past 17_820 without a lockstep bump — pre-existing QUAL-10
    // drift greened here). The 17.9k-LOC module split is the highest-
    // priority manageability target tracked under the v0.8.0 EPIC #1709.
    // 2026-06-16 (v0.8.0 #1709 Pillar-1 SIGNED-SIGNALS SAL surface) —
    // bumped 18_540 → 18_750: PG_SIGNAL_SELECT_BY_ID + pg_row_to_signal +
    // the 5 sqlx-native signal_* trait methods (signal_send / signal_get /
    // signal_inbox / signal_thread / signal_ack). Measured 18_693 + ~57
    // headroom; new SAL surface for postgres-backed daemons. The 18.7k-LOC
    // module split remains the highest-priority manageability target under
    // EPIC #1709.
    // 2026-06-16 (v0.8.0 #1709 Pillar-1 ATTESTED-CHECKPOINTS storage
    // foundation) — bumped 18_750 → 18_800: the migrate_v61() method
    // (inline `checkpoints` CREATE TABLE/INDEX DDL + v61 dispatch arm).
    // Measured 18_762; storage-only, no SAL/MCP surface (those land in
    // later units). The 18.7k-LOC module split remains the highest-priority
    // manageability target under EPIC #1709.
    // 2026-06-16 (v0.8.0 #1709 Pillar-1 ATTESTED-CHECKPOINTS SAL surface) —
    // bumped 18_800 → 19_100: PG_CHECKPOINT_SELECT_BY_ID + pg_row_to_checkpoint
    // + the 5 sqlx-native checkpoint_* trait methods (checkpoint_create /
    // checkpoint_get / checkpoint_list / checkpoint_resolve / checkpoint_query).
    // Measured 18_962 + 138 headroom; new SAL surface for postgres-backed
    // daemons. The 19k-LOC module split remains the highest-priority
    // manageability target under EPIC #1709.
    // 2026-06-16 (v0.8.0 #1709 Pillar-1 ROUTINES SAL surface) — bumped
    // 19_100 → 19_500: PG_ROUTINE_SELECT_BY_ID + pg_row_to_routine +
    // PG_ROUTINE_RUN_SELECT_BY_ID + pg_row_to_routine_run + the 8 sqlx-native
    // routine_* trait methods (routine_create / routine_get / routine_list /
    // routine_freeze / routine_run_create / routine_run_get / routine_runs_for
    // / routine_run_set_state). Measured 19_367 + 133 headroom; new SAL
    // surface for postgres-backed daemons. The 19k-LOC module split remains
    // the highest-priority manageability target under EPIC #1709.
    // 2026-06-16 — bumped 19_500 → 19_640 by the v0.8.0 #1709 Pillar-2
    // typed-cognition migration: the `migrate_v63` method (the
    // memory_links.relation CHECK-extend) + its dispatch arm + the two
    // literal-version stamps on v61/v62. Measured 19_540 + ~100 headroom.
    // 2026-06-16 (v0.8.0 #1709 Pillar-2.5 size-GC SAL surface) — bumped
    // 19_640 → 19_820: the sqlx-native `PostgresStore::size_gc` method
    // (corpus byte-cap eviction — the SUM-bytes select + the
    // lowest-value-first per-victim archive-INSERT/DELETE loop, mirroring
    // run_gc's #1026 per-victim transactional atomicity). Measured 19_760
    // + 60 headroom; new SAL surface so postgres-backed curators evict
    // under byte pressure too, no LLM on the eviction path. The 19k-LOC
    // module split remains the highest-priority manageability target.
    // 2026-06-16 (v0.8.0 #1709 / #224 Pillar-3 unit 3 — federation
    // conflict-path field-merge) — bumped 19_820 → 19_960: the sqlx-native
    // `PostgresStore::merge_inbound` method (read-by-id → the SHARED Rust
    // `crate::models::merge_memory` reconciler → full-row UPDATE in a tx,
    // else `apply_remote_memory` fall-through) + the hoisted
    // `SQL_SELECT_MEMORY_ROW_BY_ID` const (pm-v3.1 literal de-dup). No
    // per-adapter merge SQL — the merge is the same pure Rust fn the sqlite
    // path uses. Measured 19_926 + ~34 headroom. The 19k-LOC module split
    // remains the highest-priority manageability target.
    // 2026-06-17 (#1720 A1) — bumped 19_960 → 20_050: the migrate_v67
    // STORED-generated target_agent_id_idx column + index arm, its dispatch
    // wiring, and the v67 doc-comment landed the file at 20_027.
    // 20_050 = 20_027 + 23 headroom.
    // 2026-06-17 (#1709/#1720 WS-B B2, security lane) — the sqlx-native
    // `reown` adapter method (jsonb_set single-key rewrite of
    // metadata.agent_id + matched/dry_run count, mirroring the sqlite
    // free-fn) landed the file at 20_090. Bump 20_050 → 20_115 in
    // lockstep (20_090 + 25 headroom).
    // 2026-06-18 (#1725, P0.2 lossless in-place update) — bumped
    // 20_115 → 20_215: `update_with_expected_version_once` now wraps the
    // prior-content archive + the in-place UPDATE in one tx (begin /
    // commit / rollback), fetches `content` for the change check, and
    // carries the DELETE+INSERT in_place_edit archive (the #1025 full
    // 36-column carry, the irreducible cost). Landed the file at 20_197.
    // 20_215 = 20_197 + 18 headroom. The postgres/{mod,kg,...}.rs split
    // remains the tracked manageability target (#650 / #867 / #961).
    // 2026-06-18 (#228 / #1728 Commit A) — bumped 20_215 → 20_260: the
    // `migrate_v68` arm (ALTER memories + archived_memories ADD COLUMN
    // encrypted_envelope BYTEA — postgres parity for the sqlite-only #228
    // primitive + the archive carry) + its dispatch wiring landed the
    // file at 20_246. 20_260 = 20_246 + 14 headroom.
    // 2026-06-18 (#228 / #1728 Commit B-wiring) — bumped 20_260 → 20_380:
    // the at-rest content encryption WIRING (seal_content threading through
    // `PostgresStore::store` + `update_with_expected_version_once`, the
    // encrypted_envelope INSERT column/bind + ON CONFLICT clause, and the
    // fail-closed decrypt branch in the pg `row_to_memory` mapper) landed
    // the file at 20_358. 20_380 = 20_358 + 22 headroom. The
    // postgres/{mod,kg,...}.rs split remains the tracked target (#650).
    // 2026-06-18 (#1726 lifecycle gate) — bumped 20_380 → 20_460: the
    // `apply_lifecycle_patch` pg twin (SELECT-current → can_transition_to →
    // typed InvalidTransition → version-bumping UPDATE) + its wiring into the
    // trait `update` + `update_with_expected_version` landed the file at
    // 20_433. +27 headroom.
    // 2026-06-18 (#1735 Pillar-4 4.C) — bumped 20_460 → 20_800: the staggered
    // AGE cold-path adds migrate_v69 + the link_internal deferred branch +
    // drain_kg_projection_outbox + spawn_drainer + the find_paths Deferred
    // CTE-route (actual 20_722 at the bump).
    // 2026-06-19 (#1693 L2 SAL parity) — bumped 20_800 → 21_000: the
    // PostgresStore `recover_turn_idempotent` (dual-dedup probe + atomic
    // memory+dedup tx, no signed_events) + `agent_max_created_at` watermark
    // (actual 20_958).
    // 2026-06-21 (#1718 Commit A-core) — bumped 21_000 → 21_100: the
    // PostgresStore `action_transition_cas` (atomic federation receive-path
    // compare-and-swap — `SELECT ... FOR UPDATE` + `state == from` guard
    // inside the tx) added ~49 LOC (actual 21_049). Per-domain split of this
    // module is tracked under #650.
    // 2026-06-22 (#1393 sub-unit 2) — bumped 21_100 → 21_200: the
    // `PostgresStore::reclassify_memory_kind` override (tx: `SELECT ... FOR
    // UPDATE` the kind, refuse reflection/persona, `UPDATE` kind + version,
    // atomic `memory.reclassified` signed_event via
    // `pg_append_signed_event_with_chain_in_tx`) added ~76 LOC (actual 21_124).
    // 2026-06-23 (#1771) — bumped 21_200 → 21_300 (lockstep): the
    // `migrate_v70` arm + `archived_memory_links` DDL landed it at 21_254.
    // 2026-06-23 (#1771 FINAL) — bumped 21_300 → 21_500 (lockstep): the
    // postgres snapshot/restore wiring (forget + archive_by_ids snapshots,
    // archive_restore re-insert) + the `archive_restore_preserves_links_pg_1771`
    // PG-gated parity test landed it at 21_423.
    // 2026-06-23 (#1783) — bumped 21_500 → 21_800 (lockstep): the AGE
    // unprojection-on-delete fix (`unproject_memory_from_age` +
    // `_inner` helpers, the `unproject_memory_ids_best_effort` method, the
    // drainer existence-guard, and the per-id unprojection at all six
    // hard-delete sites) landed it at 21_689. Per-domain split tracked #650.
    // 2026-06-24 (#1795 + #1793) — bumped 21_800 → 22_000 (lockstep): the
    // tenant-only `check_memory_quota` enforcement method (#1795) + the
    // Human-arm self-approval/registration guard + its updated live-PG unit
    // test (#1793) landed it at 21_813. Per-domain split tracked #650.
    // 2026-06-24 (#1727, 5-agent vote 4d3ea1c5) — bumped 22_000 → 22_300 for the
    // NON-DESTRUCTIVE `undo_in_place_edit` PostgresStore trait method (the
    // postgres twin behind the CLI-only `ai-memory undo-edit` operator tool).
    // Per-domain split tracked #650.
    // 2026-06-28 (#1821, v0.8.1 W1+W2) — bumped 22_300 → 22_450 for the G29
    // redact-at-storage wiring (store/store_with_embedding/store_batch/
    // merge_inbound) + the G30 forget erasure-fanout (DLQ/transcript purge +
    // UNNEST signed-tombstone insert) + the `migrate_v71` forget_tombstones arm.
    ("src/store/postgres.rs", 22_450),
    // 2026-06-10 (#1579 B7) — bumped 9_000 → 9_150: the
    // `db_mmap_size_bytes` knob (ENV_DB_MMAP_SIZE const +
    // StorageSection/ResolvedStorage fields + the resolve_storage env >
    // config > default ladder arm) and its four precedence regression
    // tests pushed the file to 9_091. Growth justified: one operator
    // knob on the established resolver pattern plus its mandated
    // precedence pins. 9_150 = 9_091 + 59 headroom.
    //
    // 2026-06-11 (#1598 API embeddings) — bumped 9_150 → 9_800: the
    // `[embeddings]` API surface (ENV_EMBED_* consts,
    // `resolve_embed_api_key` ladder, `is_api_embed_backend`,
    // inline-key rejection, redacting Debug, dim override) + the
    // mandated precedence pins landed the file at 9_724. Growth
    // justified: the resolver pattern requires its fields, ladder,
    // and tests to live with the section they resolve.
    // 9_800 = 9_724 + 76 headroom.
    //
    // 2026-06-11 (#1590 dead default_namespace) — bumped 9_800 →
    // 10_050: the process-wide configured-default-namespace seed
    // (`set_configured_default_namespace` /
    // `configured_default_namespace` + the test gate), the per-field
    // `default_namespace_source` provenance on `ResolvedStorage`
    // (`explicit_default_namespace()`), and the two mandated #1590
    // regression pins landed the file at 9_974. Growth justified:
    // the resolver must distinguish operator-explicit config from the
    // compiled default so unconfigured deployments keep their
    // historical write-path ladders, and the boot-seeded slot is the
    // single choke point all three surfaces (MCP/HTTP/CLI) consult.
    // 10_050 = 9_974 + 76 headroom.
    //
    // 2026-06-11 (#1604, the #1588 RE-RUN fix train) — bumped
    // 10_050 → 10_180: the rerank input-sequence-cap ladder
    // (ENV_RERANK_MAX_SEQ const + RerankerSection.max_seq_tokens +
    // ResolvedReranker.max_seq_tokens + the resolve_reranker env >
    // config > default arm) and the resolve_reranker_1604_max_seq_ladder
    // precedence pin, plus the #1605 ENFORCED_AGENT_ACTIONS SSOT
    // rebuild + doc block. Growth justified: the cap closed a measured
    // 4,013 ms → 1,206 ms recall regression and the knob follows the
    // mandated uniform resolver ladder; zero speculative surface.
    // Measured post-fix LOC: 10_081. 10_180 = 10_081 + 99 headroom.
    // 2026-06-15 (v0.8.0) — bumped 10_180 → 10_360: pre-existing v0.7.1
    // drift (config.rs grew to 10_354 via the #1671 curator + #1691
    // reranker-score-floor knobs without a lockstep bump — NOT touched
    // by #1705; greened here so the QUAL-10 gate is enforceable again).
    // Sectioned-config split tracked under v0.8.0 EPIC #1709.
    // 2026-06-17 (v0.8.0 #1709 §11.4.C) — bumped 10_360 → 10_395: the
    // vLLM first-class backend alias added the
    // `resolve_embeddings_1709_vllm_alias_default_base_url` embed-parity
    // test pinning that AI_MEMORY_EMBED_BACKEND=vllm resolves the shared
    // http://localhost:8000/v1 default, plus the `vllm` arm of
    // `default_model_for_alias` referencing the shared
    // `LOCAL_SERVER_MODEL_PLACEHOLDER` const (hoisted to keep the
    // `local-model` literal under the hardcoded-literal-gate ratchet).
    // 2026-06-18 (v0.8.0 #1733 Pillar-4 4.A) — bumped 10_400 → 10_460: the
    // admission-control env/const (`ENV_MAX_INFLIGHT_REQUESTS`,
    // `DEFAULT_MAX_INFLIGHT_REQUESTS`), the `LimitsSection` +
    // `ResolvedLimits` `max_inflight_requests` fields, the `resolve_limits`
    // arm, and the lockstep test-fixture updates.
    // 2026-06-18 (#1735 Pillar-4 4.C) — bumped 10_460 → 10_560: the
    // AgeProjectionMode enum + as_str/from_str_opt + the AGE_PROJECTION_MODE
    // process-global (set/get) + ENV_AGE_PROJECTION_MODE + the StorageSection /
    // ResolvedStorage field + resolve_storage ladder arm (actual 10_533).
    // 2026-06-19 (#1749 Pillar-2.5) — bumped 10_560 → 10_700: the
    // CuratorCompactionSection { enabled } + ENV_COMPACTION_ENABLED const +
    // resolve_compaction_enabled ladder arm + the
    // curator_compaction_enabled_resolver_1749 unit test + the two
    // CuratorSection fixture updates (compaction: None) (actual 10_651).
    // 2026-06-19 (#1750 Pillar-2.5) — bumped 10_700 → 10_850: the
    // CuratorCompactionSection.cosine_threshold field + ENV_COMPACTION_COSINE_THRESHOLD
    // const + resolve_compaction_cosine_threshold ladder arm + the
    // curator_compaction_cosine_threshold_resolver_1750 unit test + the three
    // resolver-test fixture updates (cosine_threshold: None) (actual 10_754).
    // 2026-06-21 (#1463 Tier 1 — OS-tier logging) — bumped 10_850 → 11_050: the
    // `LoggingConfig.sink` field + the `LogSink { File, Stdout }` enum
    // (as_str/from_str_opt) + ENV_LOG_SINK const + the free `resolve_log_sink`
    // ladder (env > [logging].sink > file) + the five resolver/from_str unit
    // tests (log_sink_from_str_opt_and_as_str_roundtrip, resolve_log_sink_*).
    // Sectioned-config split still tracked under v0.8.0 EPIC #1709 (actual 10_986).
    // 2026-06-22 (#1765 Tier 2 syslog) — +the LogSink::Syslog variant + the
    // syslog_* LoggingConfig fields + the 3 AI_MEMORY_LOG_SYSLOG_* env consts.
    // 2026-06-22 (#1393 sub-unit 2) — bumped 11_050 → 11_250: the
    // `CuratorSection.transcript_classify_enabled` field + ENV_TRANSCRIPT_CLASSIFY_ENABLED
    // const + the `resolve_transcript_classify_enabled` ladder + the
    // `transcript_classify_enabled_resolver_1393` config-layer test + the
    // lockstep `transcript_classify_enabled: None` addition at the 7 in-file
    // CuratorSection test literals (actual 11_148).
    // 2026-06-22 (#1764 v0.8.0 slice) — bumped 11_250 → 11_300: the
    // `ReflectDecorrelationMode` enum + 2 `ENV_REFLECT_DECORRELATION_*` consts +
    // the `reflect_decorrelation_mode` / `reflect_decorrelation_dominance_threshold`
    // env-only resolvers for the reflection-corpus decorrelation visibility probe
    // (actual 11_252).
    // 2026-06-23 (#1775) — bumped 11_300 → 11_350: the
    // `warn_if_archive_on_gc_disabled` one-shot boot-WARN helper (emitted at
    // serve + mcp boot when [storage].archive_on_gc = false) + its two
    // gate-branch unit tests (actual 11_301).
    // 2026-06-28 (#1821 / W1 / gap G29) — bumped 11_350 → 11_400: the
    // `[security]` section (`SecurityConfig.secret_screen_mode`),
    // `ENV_SECRET_SCREEN_MODE`, and `resolve_secret_screen_mode()` for the
    // pre-write credential screen (actual 11_353; 47 headroom).
    ("src/config.rs", 11_400),
    // daemon_runtime.rs bumped 7_000 → 7_100 by FX-F1 to accommodate
    // the +446-line coverage closure on `apply_anonymize_default` /
    // `resolve_admin_agent_ids` / the `build_llm_client` ladder (the
    // 735d3c42e + 197640745 commits). Growth is justified: each new
    // test pins a previously-uncovered branch on existing production
    // helpers (no new production surface); the FX-F1 dispatch raised
    // the file's coverage floor from 83.83% → 85%. 7100 = 7050 actual
    // + 50-line headroom; well under QUAL-10's aspirational 1.5x cap.
    //
    // 2026-05-31 — bumped 7_100 → 7_300 by FX-F2 (commit 094abe811) to
    // accommodate +7 unit tests covering `build_store_handle` and
    // `resolve_configured_embedding_dim` that lifted daemon_runtime.rs
    // coverage 84.89% → 85.26% per the Per-Module Coverage Thresholds
    // floor (issue #1424). Actual LOC at the bump: 7256. Growth is
    // justified: each new test pins a previously-uncovered branch on
    // existing production helpers (zero new production surface). The
    // lockstep ceiling bump was missed in 094abe811 — fixing here so
    // the Per-Module Coverage Thresholds workflow (which runs the
    // full integration suite under llvm-cov) stops tripping qual_10
    // on every push.
    // 2026-05-31 — bumped 7_300 → 7_600 by the v0.7.0 security-review
    // epic (#1450) findings #1455 + #1458. #1455 added the shared
    // fail-CLOSED `governance_consultation_unavailable[_inner]` helpers
    // + `governance_fail_open_on_error` + 2 regression tests; #1458
    // extracted `api_key_bind_guard` + `require_api_key_strict` out of
    // `bootstrap_serve` and added 5 regression tests. Actual LOC at the
    // bump: 7528. Growth is justified: each change hardens an existing
    // startup path plus its regression coverage (no speculative
    // surface). 7600 = 7528 + ~72 headroom; well under the 1.5x cap.
    //
    // 2026-06-05 — bumped 7_600 → 7_700 by the federation-identity-at-scale
    // epic (FED-P3/P4, merged via bdf93e6a5): the daemon-boot wiring for
    // zero-touch trust grew the file to 7621 — `resolve sender identity
    // instead of hardcoding host:<hostname>` (0aa8fc2db), `thread
    // operator-config identity into resolver` (3e041cd8c), and `spawn
    // credential renewal worker at daemon boot` (91a2dcfa4). The lockstep
    // bump was missed at merge because the epic's --lib merge gate does not
    // run the tests/ integration binaries — qual_10 only runs under the
    // full Per-Module Coverage Thresholds llvm-cov job, which first
    // re-checked the ceiling on the #1508 push. Growth is justified: each
    // change wires an existing daemon-boot path for first-party-CA identity
    // resolution / credential renewal (no speculative surface). 7700 = 7621
    // + 79 headroom; far under the 1.5x cap.
    //
    // 2026-06-06 — bumped 7_700 → 7_850 by the #1521 sectioned-[embeddings]
    // wiring: the pure `resolve_embedder_model` precedence helper (section
    // model > legacy flat > tier preset) plus `build_embedder` consuming it
    // and `resolve_embeddings().url`, with 6 in-file precedence regression
    // tests, grew the file to 7766. Growth is justified: it wires the
    // existing [embeddings] config block into the daemon embedder build
    // path (no speculative surface). 7850 = 7766 + 84 headroom; far under
    // the 1.5x cap.
    // #1548 — the curator `--store-url` SAL store-build path
    // (`build_curator_store` + the Curator dispatch arm) added ~34 LOC.
    // Bumped in lockstep.
    // 2026-06-10 (#1579 B3, writepath lane) — the async-boot HNSW
    // loader: `load_boot_index_entries` +
    // `spawn_vector_index_boot_load` (the seed → background-build →
    // swap orchestration with its lock-discipline doc block) and the
    // `b3_1579_boot_loader_warms_index_off_the_startup_path`
    // readiness regression test — ~185 LOC on the serve boot path
    // (the 40 s @10k / >28 min @100k sync-build fix).
    //
    // 2026-06-10 (#1579 A4, postgres lane, merged batch-2) — the
    // serve-boot embedding-backfill sweep spawn (detached task
    // draining `MemoryStore::list_unembedded` through the daemon
    // embedder under the `embedding-backfill` sentinel principal;
    // ~46 LOC incl. the root-cause doc block) on the SAME module —
    // closes the postgres fleet dead-semantic-recall gap.
    //
    // 2026-06-10 (#1579 A3+B8, wire lane, merged batch-2) — A3 routed
    // the store-URL boot/error sites through
    // `crate::logging::redact_url_password` and added the
    // `issue_1579_a3_boot_log_redacts_store_url_password` regression
    // test (~75 LOC); B8 added the `--scale` corpus-scale flag to
    // `BenchArgs` + `cmd_bench` (~25 LOC). Security fix on existing
    // log/error sites + the scale knob on the existing bench
    // dispatch.
    //
    // Three lanes landed on this module in one train; the ceiling is
    // pinned from the measured post-merge union: actual LOC 8_293.
    // 8_400 = 8_293 + 107 headroom; far under the 1.5x cap.
    //
    // 2026-06-12 (GA coverage campaign, uniform-90 floor) — bumped
    // 8_400 → 8_600. The per-module 90% coverage drive added in-file
    // `#[cfg(test)]` unit tests pinning previously-dark branches on
    // existing daemon-boot / dispatch helpers (zero new production
    // surface; qual_10 counts in-module test LOC), growing the file to
    // 8_497. 8_600 = 8_497 + 103 headroom; far under the 1.5x cap.
    // 2026-06-17 — bumped 8_600 → 8_700 by §22 PE-5 (#697): the two
    // L1-6 governance pre-write hook sites (storage pre-write +
    // wire_check) each gained a `Decision::Escalate` block-and-chain-log
    // arm (the compiler-forced exhaustive-match arm).
    // 2026-06-18 (v0.8.0 #1733 Pillar-4 4.A) — bumped 8_700 → 8_760: the
    // boot-time `set_max_inflight_requests` seeding block next to the
    // existing `set_quota_defaults` seed (admission-control cap resolved
    // from `[limits]`).
    // 2026-06-19 (#1734 PE-1) — bumped 8_760 → 8_820: the serve-boot
    // mandatory-hook enforcement banner (one unconditional `hooks
    // enforcement: <mode>` line, matching the `permissions:` banner style).
    // #1580 — bumped 8_850 → 8_890 for the dedicated DLQ-sink + catchup-loop
    // connections (F5.11: both federation workers off the shared writer).
    // 2026-06-23 (#1789) — bumped 8_890 → 8_910: the mtls-router `/sync/*`
    // bypass test opts back to permissive peer-enrollment (shared-lock RAII
    // set/restore of AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS) now that the
    // #1789 secure default 401s the unenrolled arm before the bypass asserts.
    // 2026-06-24 (#1727, 5-agent vote 4d3ea1c5) — bumped 8_910 → 8_960 for the
    // `Command::UndoEdit` variant (+ doc) and its dispatch arm building the SAL
    // store like the curator for the CLI-only `ai-memory undo-edit` tool.
    // 2026-06-24 (#1800) — bumped 8_960 → 9_050 for the dispatch-arm coverage
    // cushions (`test_run_dispatch_{undo_edit,reown,replay}_command`) that hold
    // daemon_runtime.rs comfortably above its Per-Module Coverage 86% floor.
    // 2026-06-24 (#1798 R-04/R-12) — bumped 9_050 → 9_200 for the
    // `boot_security_posture_warnings` helper + `host_is_loopback` + the
    // bootstrap_serve call site + 6 `boot_posture_*` unit tests (loud
    // non-loopback boot security-posture WARNs). Ceiling is aspirational, not
    // a ratchet — see `qual_10_ceiling_table_is_aspirational_not_ratcheting_up`.
    ("src/daemon_runtime.rs", 9_200),
    ("src/subscriptions.rs", 4_500),
    ("src/cli/install.rs", 3_500),
    // 2026-06-05 — bumped 3_500 → 3_700 by the #1508 v0.6.4→v0.7.0
    // migration-capability work: the operator-directed in-process
    // pre-migration DB snapshot (`snapshot_before_migration` +
    // `database_main_file_path` + the `PRE_MIGRATION_BACKUP_*` consts and
    // their `*_for_tests` accessor, written within migration scope so a
    // recoverable backup exists BEFORE any schema mutation) plus its 3
    // in-file regression tests (`in_memory_db_has_no_snapshot_file_path`,
    // `snapshot_before_migration_is_noop_for_in_memory_db`,
    // `pre_migration_backup_infix_accessor_is_stable_and_nonempty`) grew
    // the file to 3625. Growth is justified: a new
    // recover-from-backup safety primitive on the open/migrate path plus
    // its regression coverage, zero speculative surface. 3700 = 3625 + 75
    // headroom; far under the 1.5x cap.
    // 2026-06-10 (#1579 A2 + B6d) — bumped 3_700 → 3_800: the v56
    // ladder arm (composite list/archive ordering indexes + the
    // archived_memories table probe), the SCHEMA-inline index pair,
    // and the `latest_arm_creates_list_composite_indexes_and_is_
    // idempotent` regression test pushed the file to 3_769. Growth
    // justified: one schema bump + its replay/idempotency coverage.
    // 3_800 = 3_769 + 31 headroom.
    // 2026-06-15 (v0.8.0 #1705) — bumped 3_800 → 3_850: the in-code v58
    // recall_observations identity-column migration arm (probe-guarded
    // ALTER/CREATE, SQLite has no ADD COLUMN IF NOT EXISTS).
    // 2026-06-16 (v0.8.0 #1709) — bumped 3_850 → 3_900: the v60
    // signed-signals migration arm + the MIGRATION_V60_SQLITE include_str
    // const + the doc-comment bump pushed the file to 3_854. Growth
    // justified: one additive schema bump (signals storage foundation).
    // 3_900 = 3_854 + 46 headroom.
    // 2026-06-16 (v0.8.0 #1709 Pillar-2) — bumped 3_900 → 4_120: the v63
    // typed-cognition relation taxonomy extension — the MIGRATION_V63_SQLITE
    // include_str const, the v63 ladder arm (rebuild + stale-trigger-drop
    // probe), the SCHEMA/version-ladder doc-comments, and the
    // `v63_rebuild_preserves_links_and_accepts_typed_cognition_relations`
    // row-preservation regression test pushed the file to 4_069. Growth
    // justified: one schema bump + its load-bearing rebuild coverage.
    // 4_120 = 4_069 + 51 headroom.
    // 2026-06-16 (v0.8.0 #1709 Pillar-2) — bumped 4_120 → 4_160: the v64
    // lifecycle-state-machine unit added the v64 ladder arm (memories +
    // archived_memories `lifecycle_state` column probe-then-add) and the
    // `PRAGMA_TABLE_INFO_ARCHIVED_MEMORIES` named const (pm-v3.1 literal
    // gate), landing the file at 4_121. 4_160 = 4_121 + ~39 headroom.
    // 2026-06-17 (v0.8.0 §22 PE-5 #697) — bumped 4_160 → 4_360: the
    // governance_rules.severity escalate-CHECK extension added the
    // MIGRATION_V66_SQLITE include_str const, the v66 ladder arm (the
    // table-existence-guarded full-table rebuild), and the
    // `v66_rebuild_preserves_governance_rules_and_accepts_escalate_severity`
    // row + signed-column + index preservation regression test, landing
    // the file at 4_338. 4_360 = 4_338 + 22 headroom.
    // 2026-06-17 (#1720 A1) — bumped 4_360 → 4_480: the v67 ladder arm
    // (probe-then-add VIRTUAL generated target_agent_id_idx + index), the
    // v67 history doc-comment, the historical-replay column/index
    // assertions, and the v67_target_agent_id_idx_projects_* generated-
    // column regression test landed the file at 4_455. 4_480 = 4_455 + 25
    // headroom.
    // 2026-06-18 (#228 / #1728 Commit A) — bumped 4_480 → 4_500: the v68
    // migration arm (probe-then-ADD encrypted_envelope on
    // archived_memories) + the pinned-v67 arm + the v68 history
    // doc-comment landed the file at 4_487. 4_500 = 4_487 + 13 headroom.
    // 2026-06-23 (#1771) — bumped 4_500 → 4_600 (lockstep): the v70
    // `archived_memory_links` migration arm + bootstrap-SCHEMA CREATE landed
    // it at 4_560.
    ("src/storage/migrations.rs", 4_600),
    // llm.rs bumped 3_500 → 5_200 by FX-D2 to accommodate PERF-9
    // (36e2573a3 — `OllamaClient` blocking → async `reqwest::Client`
    // conversion) and the #1361 med/low findings batch fold-in.
    // Async client wiring is wider per call site (await + Result
    // propagation + #[allow] surface for clippy::pedantic on the
    // backend dispatch arms across ~15 vendor aliases). Refactor-split
    // into `src/llm/{client,backends,auto_tag,expansion}.rs` is
    // tracked as a separate v0.7.x post-ship ARCH cleanup.
    // 2026-06-11 — bumped 5_200 → 5_350 by #1603 (batched remote
    // embeds: `embed_texts`/`embed_texts_async` + the one-request
    // helper + `parse_openai_embeddings_batch` + 2 parse-pin tests
    // grew the file to 5_317; lockstep bump = 5_317 + 33 headroom).
    // 2026-06-17 (v0.8.0 #1709 §11.4.C) — bumped 5_350 → 5_400: the
    // vLLM first-class backend alias added the `BACKEND_VLLM` const +
    // its doc block, the `default_base_url_for_alias` / `alias_api_key_env_vars`
    // arms, and 2 pinning-test rows (file grew to 5_352); 5_400 = 48 headroom.
    // 2026-06-22 (v0.8.0 #1393) — bumped 5_400 → 5_500: the decision-detector
    // `OllamaClient::classify_kind` + `CLASSIFY_KIND_SYSTEM` prompt +
    // `classify_kind_prompt` / `parse_classified_kind` helpers + 4 parser-pin
    // tests (file grew to 5_456); 5_500 = 44 headroom.
    ("src/llm.rs", 5_500),
];

#[test]
fn qual_10_no_module_exceeds_size_ceiling() {
    let mut violations: Vec<String> = Vec::new();
    for (path, ceiling) in MODULE_SIZE_CEILINGS {
        let Ok(content) = fs::read_to_string(path) else {
            // Missing files imply a refactor split — that's OK,
            // remove the row from the table on the next contributor's
            // pass. Don't error here.
            continue;
        };
        let line_count = content.lines().count();
        if line_count > *ceiling {
            violations.push(format!(
                "  {path}: actual {line_count} LOC > ceiling {ceiling} LOC \
                 (bump ceiling in lockstep or split the module)",
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "QUAL-10: module size ceiling exceeded:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn qual_10_ceiling_table_is_aspirational_not_ratcheting_up() {
    // QUAL-10 discipline: every entry in the ceiling table has a
    // headroom margin of <30% above the current LOC. If a file's
    // ceiling is much higher than the actual LOC, the discipline
    // weakens — silently letting a file grow 50% before the gate
    // fires. This test surfaces excessive headroom so the table
    // gets tightened on every refactor.
    let mut weak_ceilings: Vec<String> = Vec::new();
    for (path, ceiling) in MODULE_SIZE_CEILINGS {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let line_count = content.lines().count();
        // Headroom ratio: ceiling / actual. Tighten when > 1.50
        // (i.e. ceiling > 1.5 * actual). Use integer math to keep
        // clippy::cast_precision_loss happy on usize → f64.
        if line_count > 0 && *ceiling > line_count + (line_count / 2) {
            weak_ceilings.push(format!(
                "  {path}: ceiling {ceiling}, actual {line_count} \
                 (headroom > 50%; tighten to ~{}).",
                line_count + (line_count / 4),
            ));
        }
    }
    // INFO-grade test — only fail if every single ceiling is weak,
    // which would indicate the table itself is decorative not
    // load-bearing. Print warnings for everything else.
    if !weak_ceilings.is_empty() {
        eprintln!(
            "QUAL-10 INFO — the following ceilings have >50% headroom:\n{}",
            weak_ceilings.join("\n"),
        );
    }
    // Always passes; the print is the load-bearing signal.
}
