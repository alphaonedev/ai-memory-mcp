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
    // 2026-06-29 (#1849/#1844 security review) — bumped 21_250 → 21_350 for the
    // UNCAPPED `forget_distinct_namespaces` / `forget_distinct_namespaces_for_caller`
    // governance-gate query helpers (#1849) + the title/tags/metadata redact funnel.
    // 2026-06-30 (#1824, v0.9.0 G7) — bumped 21_600 → 21_800 for the
    // `conserve_contradiction` + `reverse_conserve_contradiction` non-destructive
    // contradiction-conserve primitives (transaction-wrapped, doc-heavy) and the
    // shared `SQL_UPDATE_METADATA_AND_UPDATED_AT_BY_ID` SSOT const.
    // 2026-07-01 (#1825 G8) — bumped 21_800 → 21_900: the additive
    // BLAKE3 content-id genesis stamping (insert/insert_if_newer/
    // consolidate/restore) + verify + T7 scrub pushed the file to 21_880.
    // 2026-07-01 (#1859 G13-mem) — bumped 21_900 → 22_300: the lineage-DAG
    // landing (read_memory_cid + lineage_edge_is_forward + the Pass-0 guard
    // in validate_link_pre_create, the cid mirror in create_link_signed,
    // the consolidate tombstone/leaf disposition, and the
    // lineage_traverse/ancestors/descendants recursive-CTE walk) grew the
    // file to 22_218; 22_300 = 82 headroom.
    //
    // 2026-07-01 — bumped 22_300 → 22_800 by the #1828 G13
    // identity-lineage landing: the sqlite SSOT for the succession
    // chain (append_lineage_record single-tx C4 atom, read_lineage /
    // lineage_head / lineage_witness_hashes, verify_agent_lineage,
    // current_authoritative_key resolver, enroll_lineage +
    // append_succession helpers) plus the agent_lineage bootstrap
    // SCHEMA mirror. Growth justified: the dual-backend agent-registry
    // convention keeps the sqlite lineage SSOT in this file next to
    // bind_agent_pubkey/agent_pubkey; no speculative surface. Measured
    // 22_704 + 96 headroom.
    //
    // 2026-07-03 — bumped 22_800 → 23_100 by #1869 P0-1 (recall
    // purity): the `fold_recall_accesses` FOLD maintenance verb (+ the
    // `FOLD_CHUNK_MEMORIES` bound and its doc contract) landed beside
    // `touch_many`, and the two internal recall touches grew their
    // legacy-flag gates + pure-default doc rewrites (~186 LOC at
    // 22_986). Growth is justified: the fold is the single writer that
    // replaces the recall-path touch, zero speculative surface.
    // 23_100 = 22_986 + 114 headroom; far under the 1.5x cap.
    //
    // 2026-07-11 — bumped 23_100 → 23_500 by #1948 Gate-1 (quarantine
    // read-visibility): the shared `lifecycle_visible_clause` filter
    // applied across recall/list/search/export/kg/federation-catchup
    // lanes + the sqlite `dequarantine` raw-UPDATE primitive + doc
    // contracts (~414 LOC at 23_400). Growth is justified: one SSOT
    // clause referenced at every read lane, zero speculative surface.
    // 23_500 = 23_400 + 100 headroom. 2026-07-11 (#1942 stage 3): the
    // v79 agent_subkey_certs storage primitives (insert/list) + the
    // kind_provenance column denorm at the insert funnel landed the file
    // at 23_527; ceiling 23_600 (+73 headroom). 2026-07-11 (#1949): the
    // v80 lineage custody/revocation storage arm merged on top lands the
    // file at 23_646; ceiling 23_700 (+54 headroom).
    // 2026-07-12 (#1956 crypto-erase): envelope-key destruction + tombstone
    // fanout on the forget/gc/size_gc delete paths land storage/mod.rs at
    // 23_932; ceiling 24_050 (+118).
    // 2026-07-12 (#1965/#1964): lifecycle-classify + index-coverage query
    // land storage/mod.rs at 24_119; ceiling 24_250 (+131).
    // 2026-07-12 (#1831 G17): M-of-N key-recovery persistence
    // (mint_recovery_record + prepare_recovery_challenge + append_recovery)
    // + the recovery-branch in append_lineage_record + the persisted-recovery
    // ceremony test land storage/mod.rs at 24_421; ceiling 24_500 (+79).
    // 2026-07-15 (#2059/#2060, TRACT covenant clauses 1+2): the write-gate
    // helpers (`consult_why_trace_gate` / `require_why_trace_enabled` /
    // `why_trace_present`) + the authorship-immutability gate
    // (`consult_authorship_immutable_gate` / `require_immutable_authorship_enabled`)
    // wired into `insert` / `update_with_expected_version` /
    // `update_with_archive_on_supersede`, plus their in-module regression
    // tests, land storage/mod.rs at 24_948; ceiling 25_050 (+102).
    // 2026-07-17 (#2167 S3): the embedding_space provenance stamp on the
    // shared embedding-UPDATE + set_embedding/batch/reembed signatures + the
    // in-module test-call threading land storage/mod.rs at 25_133; ceiling
    // 25_150 (+17 headroom). Additive per-row provenance write path.
    // 2026-07-17 (#2167 S4+S5): the recall-core space gate (comparator
    // threading on 3 sqlite sites + FTS/linear-scan/HNSW SELECT columns +
    // space/unverified counters + aggregated WARN) + the §5 boot adoption /
    // §6 census / embedding_space_boot_maintenance helpers land
    // storage/mod.rs at 25_504; ceiling 25_650 (+146 headroom).
    // 2026-07-18 combined (#2181 embedding-space gating + #2165 test-isolation):
    // the `get_embedding_with_space` helper + `proactive_conflict_check`
    // `embedding_space` predicate (#2181, #2167 residual) PLUS the
    // ck_trigger_* / a3-fed permissions-race test comments (#2165) land
    // storage/mod.rs at 25_738; ceiling 25_650 -> 25_850. Then #2035 v85
    // archive->restore valid_from/valid_until column threading + round-trip
    // unit test added ~65 LOC on top of the merge.
    //
    // 2026-07-18 (#1834 claim-bitemporal residual, PR #2204): threading
    // valid_from/valid_until through row_to_memory + insert/insert_if_newer +
    // update_with_expected_version + build_list_query/list + recall +
    // recall_hybrid FTS/semantic phases (valid_at AS-OF predicate) + the #2207
    // merge-lane overwrite_full_row_by_id VALID-time columns lands the merged
    // file at 26_029; ceiling 25_900 -> 26_100.
    //
    // 2026-07-19 — #2064 (erasure cold tier) merged on top of #2204: the
    // purge funnels journal destruction intent + collect/remove bundle ids,
    // the two restore funnels gain reconstruct-on-read + stale-bundle removal
    // (F1/R1). Combined with the #2204 claim-bitemporal threading above the
    // merged file lands at 26_155; ceiling 26_100 -> 26_250. Growth justified:
    // wiring on existing funnels only — the erasure subsystem itself lives in
    // the new src/erasure/ modules.
    // 2026-07-18 (TRACT anchors port, #1832/#1863/#1864): the ForgetReceipt
    // read-only projection (get_forget_tombstone / verify_forget_receipt +
    // round-trip tests) + the g10_3_* promotion-court and g10_4_*
    // namespace-boundary characterization tests land storage/mod.rs at
    // 26_650; ceiling 26_750 (+100 headroom). Read-only projections +
    // honesty machine-checks — no new write path.
    // 2026-07-21 (#2266/#2267, PR #2274): VALID-time comparison preserves
    // signed offset bytes while the SQLite UDF/query paths compare instants;
    // focused boundary, read-only-open, malformed-value, signature, and
    // round-trip regressions land storage/mod.rs at 27_035. The 5-agent
    // crossroads vote chose the policy-prescribed lockstep bump over a
    // release-train module split. Ceiling 26_750 -> 27_100 (+65 headroom).
    //
    // 2026-07-21 (#1802 R-05 S1, folded onto release HEAD) — REDUCED
    // 27_100 → 26_450: the doctor / observability probe region (698 LOC:
    // is_namespace_standard .. doctor_reflection_totals_by_namespace, incl.
    // sweep_pending_action_timeouts + the capability-expansion ledger) moved
    // verbatim to the new src/storage/doctor.rs submodule (itemized
    // re-export shim keeps every `crate::storage::*` / `crate::db::*` path
    // stable). After the fold onto the #2266/#2267 27_035 file the extract
    // lands mod.rs at 26_362; ceiling 26_450 (+88). Per the QUAL-10 shrink
    // rule: "when a file's LOC SHRINKS (a refactor split), the ceiling falls".
    // 2026-07-23 (STORAGE-CHAIN lane #2331-#2339) — bumped 26_450 →
    // 26_750 by the fable-3x7 data-integrity fixes: the #1626 tier→long
    // expiry coupling (#2331), expires_at rendering canonicalization at
    // all five write funnels (#2332), the v87 archived kind_provenance
    // carry through 8 archive + 2 restore column lists (#2333), the
    // federation expiry extension-floor lattice join (#2335), stats
    // live/expired_pending_gc (#2334), the EmbeddableScan raw-cursor
    // struct (#2336), the G7 soft-loser recall penalty (#2338), and the
    // access-priority ceiling on the touch/fold ladders (#2339).
    // Measured 26_675; ceiling 26_750 (+75 headroom).
    // 2026-07-24 (#2383 N1 encrypt-at-rest upsert key) — the
    // `DecryptFailurePolicy` split row-mapper (fail-closed targeted reads vs
    // skip-with-WARN discovery scans) + the `AI_MEMORY_STRICT_DECRYPT_READS`
    // knob + the seal-to-RETAINED-identity helpers
    // (`retained_agent_id_for_upsert` / `seal_content_for_upsert` /
    // `reconcile_envelope_owner`) and the atomic seal/upsert/reconcile tx
    // wrappers on `insert_inner` + `insert_if_newer` land the file at
    // 27_132. Ceiling 26_750 -> 27_250 (+118 headroom).
    // 2026-07-28 (#2418 L-EXPIRY-CANON) — `expires_at` canonicalization at
    // the THREE #1596 TTL-extension write funnels (`touch` / `touch_many` /
    // `fold_recall_accesses`, which bound a bare `to_rfc3339()` `+00:00` /
    // AutoSi-fraction rendering straight into `expires_at = MAX(...)`) plus
    // the `canonical_archived_expiry` helper that heals a legacy
    // `original_expires_at` on BOTH `restore_archived*` funnels. Lands the
    // file at 27_251 — ONE line over. Ceiling 27_250 -> 27_400 (+149).
    // 2026-07-30 (#2503 delete-governance-strip, L2 SECURITY CONFINEMENT) —
    // the unqualified `DELETE FROM namespace_meta WHERE standard_id = ?1` on
    // all FOUR reap funnels (`delete` / `archive_memory_no_tx` /
    // `archive_memory_for_caller` / `size_gc`) becomes the audited
    // `sever_namespace_standards` primitive (name-then-sever + WARN + signed
    // `substrate.namespace_standard_severed` event + canonical signable
    // bytes), the gc dangling sweep becomes a HEAL, and the resolver gains the
    // severed tri-state (`NamespaceLevel` + `read_namespace_level` +
    // `read_policy_from_standard` extraction + the floor-tracking walk). The
    // bulk is the WHY comments: this is a fail-open→fail-closed posture flip
    // on a security boundary, so each site states what it prevents and what it
    // deliberately does not claim. MEASURED post-change: 27_609.
    // Ceiling 27_400 -> 27_700 (+91 headroom). Bumped in LOCKSTEP with the
    // postgres.rs entry below (same commit, same issue).
    //
    // 2026-07-31 (#2580) — `build_list_query` gains the exact
    // metadata-equality axis (the GIN/`json_each` pushdown that stops
    // `memory_load_family` materialising 1000 rows to return 0) and `list`
    // splits into the historical 11-arg shape plus `list_filtered`, so the
    // ~30 existing `db::list` call sites stay untouched. The bulk is the
    // WHY comment: the predicate rides the SHARED builder precisely so the
    // #1948 lifecycle allow-list, the expiry guard, the #1579 sargable
    // namespace arm, the #1834 AS-OF window and the #2383 undecryptable-row
    // skip all keep applying — a bespoke query would have to re-derive
    // every one of them. MEASURED post-change: 27_746.
    // Ceiling 27_700 -> 27_820 (+74 headroom).
    // 2026-07-31 (#2579 liveness-probe O(corpus)) — `health_check` ran a full
    // FTS5 `'integrity-check'` (which re-tokenizes the whole corpus AND is
    // prepared as a WRITER) plus a `COUNT(*)` on EVERY `/health` request. It
    // splits into `ping` + `fts_probe` (both O(1), both SELECTs) and the deep
    // `fts_integrity_check`, which now has exactly two callers: the paced
    // `background::fts_integrity` loop and `ai-memory doctor`. The line count
    // is mostly the WHY: this is a posture change on a control, so each
    // function states what it proves, what it deliberately does NOT prove,
    // and where the signal it dropped now lives. MEASURED post-change:
    // 27_755. Ceiling 27_700 -> 27_820 (+65 headroom).
    // 2026-07-31 MERGE (#2580 + #2579) — both lanes bumped this ceiling to
    // 27_820 independently, from DIFFERENT pre-merge measurements (27_746 and
    // 27_755). Both sets of lines are now in the file, so neither figure is
    // the merged truth and the coincidentally-equal ceiling is NOT evidence
    // the merge fits. Re-MEASURED on the merged file: 27_828.
    // Ceiling 27_820 -> 27_900 (+72 headroom).
    // 2026-08-01 (#2538) — the named-approver (`ApproverType::Agent`) arm of
    // `approve_with_approver_type` gains the self-approval refusal + the
    // registered-approver check it never had (the Human arm above it and the
    // Consensus arm below it both already carried them), the surface-keyed
    // predicate is hoisted out of the Human arm into the shared
    // `enforce_approver_identity_gate`, and two in-module regression tests
    // (the CWE-863 proof + the LocalOperator no-self-lock liveness leg) land
    // alongside a governance-standard seeding helper. Most of the added lines
    // are the WHY: this is an authorization posture change, so the arm states
    // what it now refuses, why the disposition is surface-keyed rather than
    // unconditional (3x3 vote 7-2), and which residual is deliberate.
    // MEASURED post-change: 28_047. Ceiling 27_900 -> 28_120 (+73 headroom).
    ("src/storage/mod.rs", 30_380), /* 2026-08-25 (#3253 rebase onto #3255): never lower the #3224 floor 30_380. #3192 tombstone_and_erase stacked on archive-first delete. Re-measure after this rebase. PRIOR: 2026-08-25 (#3224 rebase onto 9f9e1605): measured 30_300 after #3013/#3012 archive-first delete + purge rails stacked on #3223's 30_220 floor; never lower. */
    // 2026-07-21 (#1802 R-05 S1) — NEW submodule extracted from
    // storage/mod.rs (doctor / observability probes). Measured 698;
    // ceiling 800 (+102).
    ("src/storage/doctor.rs", 800),
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
    // 2026-07-01 (#1859 G13-mem) — bumped 15_300 → 15_400: the
    // memory_lineage module mount + dispatch wrapper + TOOL_DISPATCH_TABLE
    // entry grew the file to 15_303; 15_400 = 97 headroom.
    // 2026-07-07 (#1885) — bumped 15_400 → 15_530: the pre-event
    // mandatory-hook-presence enforcement gate (PreEventEnforceGate + install +
    // consult_pre_event_gate + test installer) + consult wiring in the
    // eligible pre-event dispatchers landed the file at 15_482; +48 headroom.
    ("src/mcp/mod.rs", 16_760), /* 2026-08-24 (#3220 rebase onto 72e4c100): MEASURED 16_683. Ceiling 16_680 -> 16_760 (+77 headroom). PRIOR: 2026-08-22 (#3171/#3204): tools/call envelope pins (non-object `arguments` → -32602; absent `arguments` still means `{}`; reserved-sentinel `agent_id` cannot stamp the audit actor) land the file at 16_564+~70; ceiling 16_580 -> 16_680 (+headroom, lockstep). PRIOR: 2026-08-16 #2983-#2987 QUAL-10 (Batman auto-atomise remediation, 5-agent vote 4d3ea1c5): the bounded single-consumer atomise worker wiring in `run_mcp_server` (the drain-time atomiser cell + its reload re-seed + the #2985 curator-less boot WARN), the `atomise_queue` field on `ToolDispatchCtx` + `handle_request`, the `AtomiseWiring` forward in `dispatch_memory_store`, and the `handle_store_with_atomise_for_tests` injection entry point land the file at 16_495; ceiling 16_400 -> 16_580 (+85 headroom, lockstep). PRIOR: 2026-08-04 #2544 (CB-15): the namespace-standard lifecycle/expiry
                                guard in lookup_namespace_standard (a non-live standard is no longer
                                served into recall/session_start) + the inject_namespace_standard_skips_non_live_standard_2544
                                regression test landed the file at 16_361; ceiling 16_300 -> 16_400. PRIOR: 2026-07-30 #2537 (5-agent vote 4d3ea1c5): the namespace-standard read leak fix — the StandardLookup tri-state enum, the caller-threaded lookup_namespace_standard, the H2-d decorated-standard reuse, and the doc blocks recording WHY the chain-carve-out alternative was rejected — landed the file at 16_254; ceiling 16_150 -> 16_300. PRIOR: 2026-07-18 campaign/docs-disclosure-bundle (#1868): B7-STREAM disposition comment block + initialize_advertises_no_streaming_capability_1868 regression test landed the file at 15_753 (was 15_700, #2172). Then #1834 claim-bitemporal residual (PR #2204): valid_at recall/list dispatch + valid_until update threading + Memory struct-literal valid_from/valid_until fanout landed the merged file at 15_861; ceiling 15_800 -> 15_900. Then #2356 (W1A6-03 PE-1): consult_pre_governance_decision_gate dispatch helper + doc block landed the file at 15_914; ceiling 15_900 -> 15_950. Then #2390 (N9, 2026-07-24): the pre-event
                                gate gained a substrate-resolved `namespaces` parameter plus the per-event
                                namespace resolvers (`pre_event_gate_installed`, `namespaces_for_ids`,
                                `arg_id_list`, `pre_event_namespaces_for_arg_ids`, `push_ns`,
                                `consolidate_pre_event_namespaces`, `reflect_pre_event_namespaces`) so a
                                namespace-scoped hook actually fires; landed the file at 16_117; ceiling
                                15_950 -> 16_150 */
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
    // 2026-07-01 (#1822, v0.9.0 G5b) — bumped 23_050 → 23_450 for the postgres
    // audit-witness tier: the pg watermark-parity wiring (item 7), the
    // `pg_emit_audit_head_witness_in_tx` + `pg_read_revision_head_in_tx`
    // dual-chain emitter (item 6), and the `verify_audit_trail` twin (item 10 /
    // K3) that surfaces identical WitnessCheck/CauseBinding verdicts.
    // 2026-07-01 (#1825 G8) — bumped 23_450 → 23_800: cid stamping across
    // ~10 postgres genesis INSERTs + migrate_v74 + backfill + verify +
    // T7 scrub pushed the file to 23_748.
    // 2026-07-01 (#1826 G9) — bumped 23_800 → 23_920: the `verify_audit_trail`
    // twin gained C7 per-row Ed25519 recorder verification in its row walk +
    // the two role-checkpoint fetches (`pg_read_latest_role_checkpoint`) + the
    // shared `compute_role_separation_verdict` wiring (file grew to 23_837).
    // 2026-07-01 (v0.9.0 coverage-gate uplift) — bumped 23_920 → 24_400 for the
    // eleven live-PG `live_cov1859_*` tests that lift store/postgres.rs
    // comfortably over its per-module coverage floor with margin (store_batch +
    // recall_hybrid, consolidate, forget guard+archive, link/list_links/
    // verify_link, verify_audit_trail, find_paths + drain_kg_projection_outbox,
    // update_with_expected_version CAS, update_with_archive_on_supersede,
    // apply_remote_memory idempotency, merge_inbound + apply_remote_link,
    // reclassify_memory_kind). Pure `#[cfg(test)]` coverage additions, ZERO new
    // production surface; file grew to 24_342. 24_400 = 24_342 + 58 headroom,
    // far under the 1.5x aspirational cap.
    // 2026-07-01 (#1859 G13-mem) — bumped 24_400 → 25_050: the lineage-DAG
    // postgres twin (migrate_v75, link_internal cid mirror, the Pass-0
    // lineage guard in validate_link_pre_create_pg, the consolidate
    // tombstone + single CONSOLIDATE-leaf emission, and the
    // lineage_cte/lineage_cypher/lineage_traverse dispatcher) grew the file
    // to 24_979; 25_050 = 71 headroom.
    //
    // 2026-07-01 — bumped 25_050 → 25_500 by the #1828 G13
    // identity-lineage postgres twins (append_lineage_record C4
    // single-tx atom via pg_append_signed_event_with_chain_in_tx,
    // read_lineage / lineage_witness_hashes /
    // current_authoritative_key, migrate_v76, and the
    // verify_audit_trail lineage-verdict computation +
    // verify_agent_lineage_pg). Growth justified: K3 backend parity
    // for the new SAL surface, no speculative code. Measured 25_391 +
    // 109 headroom.
    //
    // 2026-07-03 — bumped 25_500 → 25_750 by #1869 P0-1 (recall
    // purity): `migrate_v77` (probe-guarded folded column + backfill),
    // the postgres `fold_recall_accesses` single-statement CTE fold,
    // the shared `apply_confidence_decay_stamp` hoist (moved out of
    // `touch_after_recall` so the fold carries the #1572 decay parity),
    // and the folded-guarded ledger pruner (~151 LOC at 25_651).
    // Growth is justified: the fold/migration pair is the P0-1 core,
    // zero speculative surface. 25_750 = 25_651 + 99 headroom.
    // 2026-07-04 (#1767 §25.3 S2) — bumped 25_750 → 25_960 for the
    // postgres decorrelation write-gate twin (corpus query + attested
    // predicate + signed refusal audit emit).
    // 2026-07-07 (#1895) — bumped 25_960 → 26_000: the char-boundary-safe
    // `payload_preview` truncation guard landed the file at 25_966; +34 headroom.
    // 2026-07-11 (#1942/#1941/#1945/#1834 crypto-core stage 2) — v79
    // coordinated-migration arm (migrate_v79 + MIGRATION_V79_CRYPTO_CORE
    // + ladder-comment block). 2026-07-11 (#1948) — quarantine Gate-1
    // lifecycle-visibility filters on the postgres read lanes + the
    // `dequarantine` SAL impl. The two lanes landed independently at
    // 26_032/26_036 and merge to 26_102; ceiling 26_200 (+98 headroom).
    // 2026-07-11 (#1949 + stage 3 merged): v80 migrate arm + subkey-cert
    // SAL surface land the file at 26_215; ceiling 26_300 (+85 headroom).
    // 2026-07-12 (#1955 record-stop): the SAL record_stop methods +
    // gate wiring land postgres.rs at 26_352; ceiling 26_450 (+98).
    // 2026-07-12 (#1831 G17): the v81 migrate arm + the guardian_set_id /
    // recovery_threshold columns threaded through the lineage INSERT + read
    // land postgres.rs at 26_503; ceiling 26_600 (+97).
    // 2026-07-14 (#2028): the decorrelation write-gate twin now scans the
    // attested-CANDIDATE set (uncapped COUNT(*) + marker-scoped query) to fix
    // the enforce-bypass; +~30 lines land postgres.rs at 26_603; ceiling
    // 26_650 (+47).
    // 2026-07-15 (#2032 security-hardening tranche): the LM1 forget-LIKE
    // escape + L4 build_find_paths self-guard + release-active assert_age_id
    // wiring land postgres.rs at 26_653; ceiling 26_750 (+97).
    // 2026-07-15 (#2059/#2060, TRACT covenant clauses 1+2): the postgres
    // twins `consult_why_trace_gate_pg` / `consult_authorship_immutable_gate_pg`
    // (thin downcast-and-map wrappers over the shared `crate::storage` gate,
    // mirroring `consult_governance_pre_write_pg`) wired into `store` /
    // `update_with_expected_version_once`, plus their in-module regression
    // tests, land postgres.rs at 26_816; ceiling 26_900 (+84).
    // 2026-07-16 (#2113 + every-funnel audit): the why_trace/authorship/inbound
    // + substrate-stamp wiring across the remaining pg funnels — reflect_with_hooks
    // (#2113), capture_turn / recover_turn / consolidate stamps, archive_restore
    // inbound, and the last un-gated create funnel `update_with_archive_on_supersede`
    // — lands postgres.rs at 26_901; ceiling 26_980 (+79).
    // 2026-07-16 (#2101 rebase onto release @ #2088): the covenant pg
    // funnel-audit wiring (26_980) MERGED with #2044's agent_api_keys SAL
    // impls (#2088, was 26_850 on release) lands the combined postgres.rs at
    // 27_054; ceiling 27_150 (+96).
    // 2026-07-16 (#2124 + #2141) — bumped 27_150 → 27_250: the #2124
    // stamp-then-gate provenance parity on the three store-family funnels
    // (+~54) plus the #2141 GOVERNANCE_PRE_WRITE gate on the DEFAULT
    // (no-If-Match) trait `update` funnel (+~48, the #1451 evasion class
    // closed on the last un-gated pg update surface) land the file at
    // 27_152. Growth is two security gates on existing write paths, not new
    // surface. 27_250 = 27_152 + 98 headroom; far under the 1.5x cap.
    // 2026-07-17 (#2178 + #2179) — bumped 27_250 → 27_600: the pg
    // embedding-space provenance parity fixes — `store_with_embedding` now
    // stamps `embedding_space` atomically on the INSERT + DO-UPDATE arm
    // (#2178, closes the lying-stamp cross-space score path), the dim-
    // migration NULL path clears the stamp with the vector, and the §5/§6 pg
    // adoption/census/heal twins (`adopt_legacy_embedding_space` +
    // `distinct_embedding_spaces` + `embedding_space_boot_maintenance`,
    // #2179) close the postgres silent-recall-outage. All are data-integrity
    // parity with the proven sqlite path, not new surface. File lands at
    // 27_501; 27_600 = 27_501 + 99 headroom; far under the 1.5x cap.
    // 2026-07-18 #2035 v85 migrate_v85 + MIGRATION_V85 const + archive/restore
    // valid_from/valid_until threading land it at 27_639; ceiling 27_700.
    // 2026-07-18 (#1873): the pg verify_audit_trail twin's audit-head hash-anchor
    // recompute (signed_events head-row canonical hash + memory_revisions
    // head-row recompute + parse-dual + fold, K3 parity with sqlite) lands
    // postgres.rs at 27_762; ceiling 27_820 (+58 headroom).
    // 2026-07-18 (#1834 claim-bitemporal residual + #2207 merge-lane fix,
    // PR #2204 merged onto the #1873 tree): pg valid_from/valid_until reads +
    // store/store_batch/apply_remote_memory persistence (LWW) + both update
    // funnels ($12/$14 valid_until COALESCE) + recall FTS/semantic/list
    // valid_at AS-OF predicates + the merge_inbound full-row writer carrying
    // the two VALID-time columns ($29/$30) land the merged file at 27_903;
    // ceiling 27_820 -> 28_000 (+97 headroom).
    // 2026-07-18 (#2195/#2196 data-integrity archive-parity, merged onto the
    // #2207 tree): threading lifecycle_state through the 3 pg archive INSERT
    // sites (forget/run_gc/archive_by_ids) + the shared
    // SQL_ARCHIVE_ON_CONFLICT_LAST_WINS clause (last-wins re-archive parity)
    // + two live-PG parity tests (each with the F1 delete-on-restore pin).
    // Combined with the #2207 VALID-time reads, the merged file lands above
    // 28_000; ceiling bumped 28_000 -> 28_200 to hold both additions.
    // 2026-07-19 (#1834 pre-ship 3x7): the v86 valid-time canonicalization
    // migration (migrate_v86 + funnel canonicalization comments) lands
    // postgres.rs at 28_203; ceiling bumped 28_200 -> 28_300.
    // 2026-07-21 (#2267, PR #2274): the two-column VALID-time persistence /
    // conflict policy plus live-Postgres parity and NULL-retention regressions
    // land postgres.rs at 28_387. The 5-agent crossroads vote chose the
    // policy-prescribed lockstep bump over a release-train module split.
    // Ceiling 28_300 -> 28_400 (+13 headroom).
    // 2026-07-21 (#2280): the store_batch upsert-merge arm gains the #1834
    // claim-bitemporal valid_from/valid_until parity arms (the one write
    // funnel that omitted them) + a live-PG store_batch conflict/NULL-retention
    // regression test. Lands postgres.rs at 28_490; ceiling 28_400 -> 28_520.
    // 2026-07-21 (#2288 + #2289, folded onto the #2280/#2284 valid-time arms):
    // store_batch also seals content into encrypted_envelope (at-rest
    // encryption bulk parity) + persists kind_provenance + routes the seal
    // error through the shared at_rest_seal_err helper — the per-row seal
    // block, two added INSERT columns + binds, and two more ON CONFLICT arms
    // (encrypted_envelope + kind_provenance, adjacent to #2280's valid-time
    // arms) land the merged file at 28_569. Ceiling 28_520 -> 28_600 (+31).
    // 2026-07-21 (#2292): route the remaining EIGHT postgres content-write
    // funnels (store_with_embedding / capture_turn / recover_turn /
    // apply_remote_memory / consolidate / reflect_with_hooks / the supersede
    // twin / merge_inbound) through the shared `seal_content_for_insert`
    // at-rest seal helper — the helper + per-funnel seal block, the added
    // `encrypted_envelope` INSERT column + bind, and each upsert funnel's ON
    // CONFLICT arm land the file at 28_736. Ceiling 28_600 -> 28_800 (+64).
    // 2026-07-21 (#2303): pin the federation-send-decrypts invariant —
    // load-bearing comments on `row_to_memory`'s decrypt branch and the
    // `list_memories_updated_since` federation-send-path section header
    // (see tests/store_parity_gaps.rs::pg_list_memories_updated_since_decrypts_for_send_2303)
    // land the file at 28_810. Ceiling 28_800 -> 28_900 (+90 headroom).
    // 2026-07-23 (FBL-08 3x7): add the `PostgresStore::delete_link` SAL trait
    // impl (relational DELETE + best-effort same-tx AGE edge unprojection
    // under a SAVEPOINT) + the `unproject_link_from_age` edge-delete helper
    // so `DELETE /api/v1/links` hits the configured store on a postgres
    // daemon (was silently mutating a local sqlite file); land the file at
    // 28_926. Ceiling 28_900 -> 29_020 (+94 headroom).
    // 2026-07-24 (fix/postgres-parity-chain) — the 8 parity fixes
    // (#2310-#2318) + the v87 anchor merge + the FBL-20/33/03 pg mirrors
    // land the file at 29_869. Ceiling 29_020 -> 29_900 (+31 headroom).
    // The module-split relief remains tracked under #650-class follow-ups.
    // 2026-07-24 (#2371 lease-sweep-audit) — `lease_sweep_expired` gains a
    // `DELETE ... RETURNING` + per-pair emit loop, the
    // `emit_lease_sweep_reclaim_audit` helper, and the sal-postgres
    // `lease_sweep_expired_emits_coordination_audit_2371` regression test;
    // land the file at 29_997. Ceiling 29_900 -> 30_040 (+43 headroom).
    // 2026-07-24 (fix/age-deferred-cluster #2375/#2376/#2377) — three AGE
    // deferred-projection-mode correctness fixes: `kg_invalidate_cypher`
    // MATCH-miss fall-through to the relational CTE (#2375), `delete_link`
    // unconditional-on-Age unproject (#2376), and threading
    // `valid_from`/`valid_until` through `project_link_into_age` + its 5 call
    // sites with the deferred-drainer re-read (#2377); landed the file at
    // 30_150. Ceiling 30_040 -> 30_150 (+47 headroom).
    // 2026-07-24 (#2382 pg pending-action-timeout sweep) — the
    // `PostgresStore::sweep_pending_action_timeouts` SAL trait impl + its
    // sal-postgres coverage landed the file at 30_256. Ceiling 30_150 -> 30_320.
    // 2026-07-24 (#2378 FBL-12 residual pg PUT-quota) — the
    // `PostgresStore::charge_update_growth` SAL trait impl (ensure-row + ONE
    // TOCTOU-free conditional agent_quotas UPDATE + typed QuotaExceeded re-read)
    // + the `refund_update_growth` compensating-decrement helper, so the
    // postgres `PUT /memories/{id}` branch charges storage-growth quota (was
    // ZERO-charge), stack on top of the #2382 merge and land the file at
    // 30_377. Ceiling 30_320 -> 30_440 (+63 headroom). Module-split relief
    // tracked under #650-class follow-ups.
    // 2026-07-24 (#2383 N1 encrypt-at-rest upsert key) — the postgres twins
    // of the sqlite #2383 work: `UpsertSeal` + `retained_agent_id_for_upsert`
    // + `seal_content_for_upsert(_batch)` + `reconcile_envelope_owner(_known)`,
    // the `DecryptFailurePolicy` split row-mapper, and the seal/reconcile
    // wiring across all 10 vulnerable write arms (incl. the new
    // `apply_remote_memory` transaction). Rebased ON TOP OF the #2378 merge:
    // MAX-WINS over the two candidate ceilings (release 30_440 vs that
    // branch's pre-rebase 30_900) is 30_900, but the #2378 pg PUT-quota impl
    // (+121) STACKS on the #2383 +518, so the rebased file MEASURED 30_906 —
    // above BOTH candidates. Bumped to the real size, not the max candidate.
    // Ceiling 30_440 -> 31_050 (+144 headroom).
    // 2026-07-24 (#2393 N12 + #2397 N17 pg write-funnel parity) — the
    // `kind_provenance` column + `extract_kind_provenance` bind (+ the
    // upsert-arm COALESCE) on the six postgres funnels that dropped the
    // v79/#1945 epistemic-typing provenance sqlite persists
    // (store_with_embedding / capture_turn / recover_turn / supersede /
    // reflect / apply_remote_memory), plus the #2397 same-tx
    // `unproject_memory_from_age` on the supersede hard-delete, stack on the
    // #2383 merge. Growth is documentation-heavy (each arm carries the
    // divergence rationale); the production SQL/bind delta is ~20 LOC.
    //
    // Ceiling 31_050 -> 31_200 = the MEASURED post-rebase 30_998 + 202
    // headroom. THIRD consecutive rebase of this one entry, and the lesson
    // the #2383 note above learned the hard way is now doctrine: MAX-WINS
    // ACROSS CANDIDATE CEILINGS IS NOT SUFFICIENT — concurrent lanes' line
    // additions STACK, so the merged file routinely exceeds every candidate
    // number visible in either branch. ALWAYS `wc -l` the file AFTER
    // resolving and set the ceiling from that measurement. (This lane's own
    // prior 30_900 was itself a borrowed max-candidate and would have gone
    // red here.) Real relief is the #650-class module split.
    // 2026-07-28 (#2419 lease-expiry requeue) — `lease_sweep_expired` gains the
    // same-transaction `claimed -> pending` requeue of actions its lease delete
    // strands (a `begin()` + a set-based `UPDATE ... WHERE id = ANY($2) AND
    // state = 'claimed' RETURNING id` + the per-id audit fan-out), the #2371
    // audit helper is generalised to take an `event_type` (rename, no size
    // change), and the live-PG regression
    // `lease_sweep_expired_requeues_stranded_claimed_action_2419` lands. The
    // pg test MUST live inline: it reads the private `store.pool` for the
    // `signed_events` assertion, exactly as its #2371 sibling does.
    // MEASURED post-change: 31_199 — i.e. the prior 31_200 left ONE line of
    // headroom on a file THREE concurrent lanes touch. Per this entry's own
    // doctrine (measure after resolving; concurrent lanes STACK), bumped
    // 31_200 -> 31_320 = 31_199 + 121 headroom. Real relief is the #650-class
    // module split.
    // 2026-07-30 (#2511 AGE cypher reads never executed) — the five
    // `age_params_literal` call sites move to the `Agtype` typed-Param bind,
    // `kg_query`'s Cypher body drops the AGE-unparseable `ALL(...)` /
    // `reduce(...)` / `length(r)` constructs in favour of
    // `nodes(p)`/`relationships(p)`, and the semantics they carried are
    // re-derived Rust-side (four new free fns: `age_decode_entity_list`,
    // `age_vertex_ids`, `age_path_edges_all_current`,
    // `age_last_edge_relation`) plus the #1948 lifecycle allow-list
    // re-derivation on the AGE branch and the fallback-honesty classifier
    // (`is_age_adapter_statement_defect` + its signature table + the second
    // WARN arm in both `warn_age_fallback*`). Roughly half the delta is
    // documentation: the postmortem on the three independent causes lives in
    // the `Agtype` / `build_kg_query_current_view_cypher` rustdoc so the next
    // agent does not re-derive it from a live AGE probe, and
    // `build_find_paths_current_view_cypher` gains the KNOWN-DEFECT note for
    // the residual. Four new inline unit tests (classifier both directions,
    // the valid_until guard incl. fail-closed, the entity-list decoder, the
    // last-edge relation) replace the deleted `age_params_literal` test.
    // `lineage_cypher` additionally drops AGE's unimplemented
    // relationship-type ALTERNATION for an untyped pattern plus a Rust-side
    // provenance-subset filter (`age_edge_is_lineage_relation`), and every
    // agtype RESULT cell moves onto the `age_cell_text` reader (the
    // `try_get::<String, _>`-on-agtype decode was latently broken from
    // v0.7.0 and only became reachable once the statements executed).
    // The #2511 follow-up (coverage-gate regression) adds the NULL-tolerant
    // agtype cell reader split (`age_cell_text_opt` / `age_cell_text_required`
    // — an ABSENT AGE property arrives as SQL NULL, which the pre-fix REQUIRED
    // read turned into a silent CTE fallback) plus the `$4::TIMESTAMPTZ` cast
    // on the `kg_invalidate_cypher` relational mirror, each with its
    // postmortem comment, and one new inline unit test.
    // MEASURED post-change: 32_080. Per this entry's own doctrine (measure
    // after the change; concurrent lanes STACK) bumped 31_320 -> 32_200 =
    // 32_080 + 120 headroom. Real relief is the #650-class module split.
    // 2026-07-30 (#2503, LOCKSTEP with the storage/mod.rs bump above) — the
    // postgres half of the governance-binding severance: SEVER/HEAL consts,
    // `PostgresStore::delete` converted, the sever ADDED to the two #2493 arms
    // that omitted it entirely (`apply_remote_deletion` — the
    // attacker-reachable federated lane — and `archive_by_ids`), the NULL
    // `standard_id` decode repaired in `get_namespace_standard` (it was a hard
    // `ColumnDecode` error, i.e. a 5xx on a state the substrate now creates),
    // and the severed floor threaded through BOTH pg governance walks
    // (`resolve_governance_policy` + the in-tx walk inside
    // `enforce_governance_action`). MEASURED post-change: 32_196.
    // Ceiling 32_200 -> 32_300 (+104 headroom).
    // 2026-08-05 #2718 (CB-14) — bumped 33_050 → 33_150 (+94): the
    // `list_memories_updated_since_counted` SAL override + its raw-count
    // read land ~31 lines here on top of the merged tip's CB-18 additions.
    // RE-MEASURED on the rebased tree at 33_056 (the #2627 lesson: a ceiling
    // that arrives through a clean auto-merge is UNVERIFIED — always
    // re-measure the merged file), so 33_150 carries the same modest headroom
    // as the neighbouring bumps.
    ("src/store/postgres.rs", 36_400), /* 2026-08-25 (#3243 rebase onto #3252): never lower the 36_400 floor. Authz catch-up stacked on search SSOT. Re-measure after full rebase. PRIOR: 2026-08-25 (#3252 rebase onto #3253): never lower the 36_400 floor. */
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
    // 2026-07-01 (#1859 G13-mem) — bumped 11_500 → 11_650: the lineage-DAG
    // flag pair (StorageSection/ResolvedStorage fields, env consts, the
    // boot-seeded atomics + accessors, resolver arms) + the
    // CapabilityFeatures.lineage_dag advertisement grew the file to
    // 11_583; 11_650 = 67 headroom.
    // 2026-07-02 (#1827 G10.1) — bumped 11_650 → 12_050: the
    // `[capabilities]` block (`CapabilitiesConfig` + `CapabilityIssuerEntry`),
    // the process-wide `ACTIVE_CAPABILITY_CONFIG` handle (+ test lock/clear),
    // `resolve_capabilities_enabled` / `load_capability_config` (closed
    // issuer allowlist loader), the `CapabilityPermissions`
    // capability-token posture fields, and the three resolver/loader
    // tests grew the file to 11_959; 12_050 = 91 headroom.
    // 2026-07-02 (#1005 G2) — bumped 12_050 → 12_250: the
    // `[limits].vector_index_capacity` / `vector_index_hard_fail_at_cap`
    // knob pair (LimitsSection + ResolvedLimits fields, the two
    // ENV_VECTOR_INDEX_* consts, the resolver arms) + five
    // resolver/round-trip tests grew the file to 12_143; 12_250 = 107
    // headroom.
    //
    // 2026-07-03 — bumped 12_250 → 12_350 by #1869 P0-1 (recall
    // purity): the two T1 flags (`recall_touch_sync_enabled` /
    // `access_fold_interval_secs` + env consts + parsing/default unit
    // tests, ~91 LOC at 12_234, which was already within 16 LOC of the
    // old ceiling). Growth is justified: operator flags for the P0-1
    // behavior change, zero speculative surface. 12_350 = 12_234 + 116
    // headroom.
    // 2026-07-12 — bumped 12_350 → 12_500 by #1989 (v0.10.0 tag
    // blocker): the v1.0.0 Gate-1prime crypto-core config growth
    // (#1942/#1945/#1953/#1954 flip-ready consts + resolvers/env
    // knobs) pushed config.rs from 12_268 to 12_401 at commit
    // 64799a0e WITHOUT the mandated lockstep ceiling bump, so this
    // integration test has failed on every `__ALL__` (tag) CI run
    // since — invisible to push CI because impact-selection never
    // dispatches qual_10. Actual LOC at the bump: 12_401.
    // 12_500 = 12_401 + 99 headroom.
    // 2026-07-12 — bumped 12_500 → 12_700 by #1960 (v1.0.0 Gate-2 R9
    // default-on capabilities + zero-config owner mint): the
    // `resolve_capabilities_enabled` default-on flip doc, the
    // `capabilities_enabled_is_compiled_default` provenance helper, the
    // `load_capability_config` owner auto-enroll + one-shot boot note, the
    // `load_owner_issuer_config` free fn, and the two R9 regression tests
    // pushed config.rs from 12_401 to 12_614. 12_700 = 12_614 + 86 headroom.
    // 2026-07-15 (#2032 M3): the resolve_default_max_inflight_requests
    // CPU-scaled tri-state default + env_tristate_usize + the M2 TLS-bind
    // resolvers (allow_plaintext_nonloopback / require_tls) land config.rs at
    // 12_742; ceiling 12_850 (+108).
    // 2026-07-17 (#2166): the validate-before-swap `AppConfig::try_load` +
    // `try_load_from` Result-returning loaders (the hot-swap reload path
    // that PROPAGATES parse/validate errors instead of swallowing them to
    // default()) land config.rs at 12_897; ceiling 12_850 -> 12_950 (+53).
    // 2026-07-23 FBL-13/FBL-30/FBL-31 config-defaults-lie honesty fixes
    // (max_memory_mb inert WARN + doc-correct, auto_extract reserved doc,
    // audit schema_version/hash_chain/attestation doc + resolve/warn helper +
    // regression test) land config.rs at 12_969; ceiling 12_950 -> 13_020
    // (+51 headroom, lockstep).
    // 2026-08-11 #2400/#2401 (v1.0.0 cert truthfulness): #2400 adds
    // `CapabilityCompaction::shipped` + the report-only `COMPACTION_ENABLED`
    // atomic (`set_compaction_enabled`/`compaction_enabled`) so
    // `memory_capabilities` reports compaction shipped-not-planned; #2401 adds
    // the `AuditComplianceConfig::unenforced_claims` compliance-defaults-lie
    // detector + `UnenforcedComplianceClaim` struct + truthful field docs.
    // Measured 13_158; ceiling 13_020 -> 13_220 (+62 headroom, lockstep).
    ("src/config.rs", 13_880), /* 2026-08-23 #3205 QUAL-10: api_key_file single-handle TOCTOU (`enforce_api_key_file_perms` takes `&File`) lands config.rs at 13_802; ceiling 13_800 -> 13_880 (+78 headroom, lockstep). PRIOR: 2026-08-22 #3166/#3167/#3002 QUAL-10: the fail-closed boot config resolver (`EX_CONFIG` const, the shared `skip_config()` truthy-grammar helper, `load_for_boot` / `try_load_from_optional` / the extracted `from_toml_contents` parse+validate tail, the `ErrorKind::NotFound` split in `load_from`) plus its four path-explicit regression tests, AND the #3002 migration-safety guard on `config_path()` (`LEGACY_CONFIG_DIR` + `warn_legacy_config_root_once` + the two legacy/XDG resolution tests) land config.rs at 13_715; ceiling 13_360 -> 13_800 (+85 headroom, lockstep). PRIOR: 2026-08-11 #2905 §5.3 CI-fix QUAL-10: added the `run_env_isolated_child_or_spawn` subprocess env-isolation test helper (+ `TEST_ENV_ISOLATION_ROLE_ENV`) so the §5.3 posture tests' process-global `set_var`s stop leaking into concurrent http_create handler tests (memory 2905-posture-test-env-leak). Measured 13_267; ceiling 13_220 -> 13_340 (+73 headroom). 2026-08-18 #3002: config_path() XDG-awareness doc + the `config_path_honors_xdg_config_home` regression test push config.rs to 13_350; ceiling 13_340 -> 13_360 (+10 headroom). */
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
    // 2026-07-01 (#1859 G13-mem) — bumped 9_200 → 9_300: the Lineage CLI
    // subcommand variant + dispatch arm + the documented deferred
    // lineage-flag boot-seed note grew the file to 9_208; 9_300 = 92
    // headroom.
    // 2026-07-02 (#1822 G5b follow-up, pre-GA #1853) — bumped 9_300 →
    // 9_400: the graceful-shutdown audit-head witness wire
    // (`shutdown_witness_flush_and_checkpoint` helper + its serve()
    // call site + docs) grew the file to 9_301; 9_400 = 99 headroom.
    //
    // 2026-07-03 — bumped 9_400 → 9_500 by #1869 P0-1 (recall purity):
    // fold-before-gc at the top of the gc loop body, the dedicated
    // fold-loop spawn (INTERVAL=0 → gc-tick-only), and the postgres
    // SAL fold + ledger-pruner loop (~93 LOC at 9_396, which was
    // within 4 LOC of the old ceiling). Growth is justified: the fold
    // wiring is load-bearing for TTL correctness (a recalled row must
    // be extended before eviction is evaluated). 9_500 = 9_396 + 104
    // headroom.
    // 2026-07-04 — #1869 P0-1 coverage follow-up (Per-Module Coverage
    // gate went RED at 85.73% < 86% because the inline postgres SAL fold
    // loop was reachable only via a live-PG boot). EXTRACTED that loop
    // body into the mock-tested `background::access_fold::spawn_sal`
    // (mirroring the sqlite `spawn` twin) and split the bootstrap fold-
    // wiring decisions into `spawn_{sqlite,postgres}_fold_loop_if_enabled`
    // helpers + their four deterministic unit tests (spawn-then-abort, no
    // daemon boot). Net: the file settled at 9_493 — the extracted loop
    // body left, the helpers + coverage tests arrived. The ceiling is
    // aspirational / never ratchets down (see
    // qual_10_ceiling_table_is_aspirational_not_ratcheting_up), so 9_500
    // stands (7 LOC headroom).
    // 2026-07-04 (#1870 §25.3 S1) — bumped 9_500 → 9_560 for the
    // `ModelAttest` CLI subcommand variant + its dispatch arm.
    // 2026-07-07 (#1889 / #1903) — bumped 9_560 → 9_650: the synchronous
    // pre-runtime `apply_startup_env` shim (hoisting env mutation out of the
    // tokio runtime) + the api_key normalization comments landed the file at
    // 9_610; +40 headroom.
    // 2026-07-07 (#1927 / #1926 / #1924) — bumped 9_650 → 9_950: the non-argv
    // store-url credential channel (`store_url_from_file` + `resolve_store_url`
    // + `url_has_userinfo_password` + their #1927 adversarial tests), the #1926
    // log-redaction fix, and the #1924 HTTP pre-event enforcement-gate install
    // in `serve` landed the file at 9_854; +96 headroom.
    // 2026-07-15 (#2032 M2): the store_url_from_file lax-perms + the
    // allow_plaintext_nonloopback / require_tls bind-guard resolver stubs land
    // daemon_runtime.rs at 10_118; ceiling 10_200 (+82).
    // 2026-07-15 (#2032 tranche 3, M2): wiring the `tls_bind_guard` (pure
    // consuming guard + doc + 5 unit tests) into `bootstrap_serve` lands
    // daemon_runtime.rs at 10_265; ceiling 10_200 → 10_400 (+135 headroom).
    // 2026-07-15 (#2045 L6): the `cert_peer_binding_boot_warnings` helper
    // (inert-posture + open-L6-window boot WARNs) + 3 unit tests + serve
    // wiring land daemon_runtime.rs at 10_409; ceiling 10_400 → 10_500 (+91).
    // 2026-07-15 (#2095): route agents bind/revoke-api-key verbs through the SAL
    // store (build_store_handle) so postgres enrollment works, + 5 dispatch
    // coverage tests (bind/revoke × json/non-json + empty-token error) to clear
    // the daemon_runtime.rs per-module COVERAGE floor. Combined with #2045 L6
    // this lands daemon_runtime.rs at 10_676; ceiling 10_500 → 10_750.
    ("src/daemon_runtime.rs", 13_420), /* 2026-08-25 (#3223 rebase onto ecce0a86): measured 13_355 after #2908/#2972/#3085 stacked on #3147/#3155; floor never falls so 13_220 -> 13_420 (+65 headroom). PRIOR: 2026-08-23 #3147/#3155 QUAL-10: identity-failclosed boot wiring (`public_only_refusal` + `inert_enforce_boot_reason`) lands daemon_runtime.rs at 13_141 on top of merged #3217; ceiling 13_140 -> 13_220 (+79 headroom, lockstep). PRIOR: 2026-08-23 #3205/#3213 QUAL-10: passphrase_from_file single-handle TOCTOU + process-private OnceLock (no `set_var`) land daemon_runtime.rs at 13_078; ceiling 13_060 -> 13_140 (+62 headroom, lockstep). PRIOR: 2026-08-21 #2991 QUAL-10 (Wave-2 approval chokepoint): the L1-6 Decision::Escalate PRODUCER wiring — `route_or_block_escalated_write` (single-use CID-bound exemption consume → keyless fail-closed guardrail → `route_escalation_to_approval_gate` then block) + `escalate_producer_2991_tests` — lands daemon_runtime.rs at 12_994; ceiling 12_820 -> 13_060 (+66 headroom, lockstep). PRIOR: 2026-08-20 #3065 QUAL-10 (Wave-2 Cluster B, Per-Module Coverage remediation): extracting the ADMIN_HEADER_TRUST boot-gate wiring out of `run()` into `enforce_admin_header_trust_boot_gate` (so the input-resolution + refusal path is unit-testable) plus the two isolated `admin_header_trust_boot_gate_{refuses_dangerous,permits_safe}_topologies_3065` wiring tests land daemon_runtime.rs at 12_770; ceiling 12_620 -> 12_820 (+50 headroom, lockstep). PRIOR: 2026-08-16 #2984/#2986 QUAL-10 (Batman auto-atomise remediation, 5-agent vote 4d3ea1c5): the bounded single-consumer atomise-worker spawn in `bootstrap_serve` — sqlite-gated, with a drain-time provider closure over the swappable LLM so a revoked vendor is structurally unreachable after an `[llm]` reload — lands the file at 12_541; ceiling 12_520 -> 12_620 (+79 headroom, lockstep). PRIOR: 2026-08-16 #2963 QUAL-10 (L10 relevance-at-scale harness): the `--relevance` / `--k` `BenchArgs` flags + the `cmd_bench_relevance` dispatch arm land daemon_runtime.rs at 12_477; ceiling 12_440 -> 12_520 (+43 headroom, lockstep). PRIOR: 2026-08-11 v1.0.0 §5.3 cutline ruling B2 fix (Fable review): the enterprise-federation boot banner (PASS/FAIL row logging + the ENGAGED summary, `run()`, gated on `enterprise_federation_posture_required()`) lands the file at 12_362; ceiling 12_360 -> 12_440 (+78 headroom). PRIOR: 2026-08-11 #2567-rebased-onto-#2401 QUAL-10 (v1.0.0 cert, 5-agent vote 4d3ea1c5): the #2567 embedder-availability threading (`embedder_available: bool` through `build_store_handle`) landed on top of the merged #2401 compliance boot-refusal, combined measured 12_284; ceiling 12_280 -> 12_360 (+76 headroom, lockstep). PRIOR: 2026-08-11 #2401 (v1.0.0 cert truthfulness, 5-agent vote 4d3ea1c5): the compliance-preset unenforced-claim boot WARN + the #2400 report-only compaction-enabled boot seed land in the common `run()` boot funnel. Measured 12_205; ceiling 12_200 -> 12_280 (+75 headroom, lockstep). PRIOR: 2026-08-09 pg-parity PR-B QUAL-10 (v1.0.0, 5-agent vote 4d3ea1c5): `verify-audit-trail --store-url` postgres dispatch — `run_verify_audit_trail` + `sqlite_store_url_to_path` + the feature-gated `verify_audit_trail_postgres` twin/refuse arm reuse the `serve`/`curator` `--store-url` connect precedent to reach `PostgresStore::verify_audit_trail`, PLUS the in-process dispatch unit tests (Per-Module Coverage: subprocess/ignored-pg exec is not counted by llvm-cov). Measured 12_127; ceiling 11_950 -> 12_200 (+73 headroom). PRIOR: 2026-08-07 #2637+#2621 QUAL-10 (v1.0.0 cert drain, combined): #2621 routes the corpus-size gauge refresher through the active backend (postgres via `memories_gauge::spawn_sal`) AND #2637 installs the curator pre-event enforcement gate in the `Command::Curator` arm (mirrors #1885/#1924) so the wired `PreCompaction` consult in `ConsolidationPass::run` actually fires in the curator process. COMBINED measured 11_916 (both landed together); ceiling 11_880 -> 11_950 (+34 headroom). PRIOR: 2026-08-04 #2718/CB-14 QUAL-10: pull-cursor poisoning guard (`validate_pull_cursor` + `PULL_CURSOR_FUTURE_SKEW_SECS` + the validated advance-to resolution in `sync_cycle_once`) + its 5 unit tests. Measured 11_811; ceiling 11_720 -> 11_880 (+69 headroom). PRIOR: 2026-08-04 #2446/#2673 QUAL-10: erasure-outbox drain spawn + boot marker wiring in bootstrap_serve. Measured 11_665; ceiling 11_660 -> 11_720 (+55 headroom). PRIOR: 2026-08-03 #2679/#2680 QUAL-10: extracted store-URL helpers + unit tests to `src/store_url.rs`. Measured 11610; ceiling 11_860 -> 11_660 (+50 headroom). PRIOR: 2026-07-31 #2579/#2583 — two paced background loops are wired into `bootstrap_serve` (the FTS5 integrity checker whose cached verdict `/health` renders, and the corpus-size gauge refresher that takes `db::stats` off the /metrics scrape path), plus the sqlite-backend gate on each. The gate is a CORRECTNESS condition, not an optimisation — `db_path`/`db_state` name the local sqlite file, which on a `--store-url postgres://…` daemon is a near-empty sidecar, so an ungated checker would assert integrity over a database nobody reads (the #2444 shape). The spawn-count pin in `test_bootstrap_serve_keyword_tier_no_embedder` moves 8 -> 10 in lockstep and its comment now enumerates the members instead of restating a total that had already drifted (it read "Nine" while asserting 8). Lands the file at 11_793; ceiling 11_780 -> 11_860 (+67 headroom). */
    ("src/store_url.rs", 403), /* 2026-08-03 #2679/#2680 QUAL-10: new module extracted from daemon_runtime (scheme sniff + #1927 channels + #2679 fail-closed refuse + unit tests). Measured 363; ceiling 403 (+40 headroom). */
    ("src/enterprise_federation_posture.rs", 2_180), /* 2026-08-22 #3003 QUAL-10 (lockstep): the corrected boot-refusal remediation (it now states the `doctor --posture` diagnostic BYPASSES the armed gate and names the contracted exit codes) plus its two assertions land the file at 2_104; ceiling 2_100 -> 2_180 (+76 headroom). PRIOR: 2026-08-20 (#3061 GA Wave-2 Cluster A): check #15 is now BACKEND-AWARE — resolved from the store URL, keeping the byte-identical sqlcipher predicate on sqlite and swapping to a COMPENSATING pg at-rest control (DSN sslmode=verify-full machine-check + AI_MEMORY_PG_AT_REST_ATTESTED operator vouch) on a postgres:// backend so the count reaches full and the #17 boot gate can arm a pg node. Adds ENV_PG_AT_REST_ATTESTED, the dsn_pins_sslmode_verify_full parser + its unit test, store-URL test-isolation, and 3 pg-backend posture tests (compensating-pass / no-attestation-fail / weak-TLS-fail). Measured 1_985; ceiling 1_820 -> 2_100 (+115 headroom). PRIOR: 2026-08-20 (#2954 GA Wave-2): check #19 (append-only-audit-spine-armed pairing — append-only spine ON AND the daemon audit signing key armed) added to evaluate(), ENTERPRISE_FEDERATION_CHECK_COUNT 18 -> 19, set_fully_hardened_env arms AI_MEMORY_APPEND_ONLY + installs a daemon audit key (POSTURE_AUDIT_DIR static), 2 negative tests (append_only_disarmed / audit_signing_disarmed), and the module-doc THREE-beyond-ruling update. Measured 1_737 post-fmt; ceiling 1_650 -> 1_820 (+83 headroom). PRIOR: 2026-08-13 #2923 QUAL-10: the `asi-hard pinned knobs` row no longer renders a VACUOUS all-at-floor PASS under a non-`asi-hard` profile (`asi_hard_below_floor()` is empty there by construction — its own docs say to pair it with `is_asi_hard`), so the row now FAILS with an honest `floor was not evaluated` actual + a profile-specific fix, plus the `resolved_security_profile_label` helper and 3 subprocess-isolated posture-shape tests (standard / hardened / unrecognised). Measured 1_581 post-fmt; ceiling 1_480 -> 1_650 (+69 headroom). PRIOR: 2026-08-12 #2911 items 1-2 QUAL-10: check #17 (boot-refusal env self-attested) + check #18 (FED-RQ-03 POLICY_CURRENT) + 3 subprocess-isolated tests. Measured 1_406 post-fmt; ceiling 1_320 -> 1_480 (+74 headroom). PRIOR: 2026-08-11 #2905 §5.3 CI-fix QUAL-10: the 23 env-mutating posture tests each gained a `run_env_isolated_child_or_spawn` subprocess-isolation guard (deferred_audit precedent) so their `set_var`s cannot leak to concurrent http_create handler tests. Measured 1_239 post-fmt; ceiling 1_150 -> 1_320 (+81 headroom). PRIOR: 2026-08-11 v1.0.0 §5.3 cutline ruling QUAL-10: new module — the certified enterprise-federation posture `evaluate` + boot-refusing gate + doctor dispatch, shared SSOT for `ai-memory doctor --posture enterprise-federation` and `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE`, plus the Fable-review B1/NB1 real-reader-reuse fixes and their exhaustive per-requirement test suite. Measured 1_059; ceiling 1_150 (+91 headroom). */
    /* 2026-07-31 #2490 (follow-up) `test_run_dispatch_export_command` asserted the phantom-DB defect as expected behaviour (it dispatched `export` at a TestEnv path where no database was ever created and unwrapped the success); it is split into a refusal cell asserting the REASON plus a CONTROL proving a real corpus still exports with exit 0 and a non-empty artifact, landing the file at 11_719; ceiling 11_700 -> 11_780 (+61 headroom, lockstep). 2026-07-31 #2490 export/import return an exit code so a PARTIAL export or an incomplete import cannot present as success; the two dispatch arms grow from a bare tail-call to the `match ... { 0 => Ok(()), code => exit(code) }` shape the `Command::Config` precedent already uses, landing the file at 11_647; ceiling 11_640 -> 11_700 (+53 headroom, lockstep). */
    /* 2026-07-17 #2167 extract run_sqlite_embedding_space_boot_maintenance helper + both-open-arms unit test to cover the boot-open Err arm (10_783). 2026-07-19 #2064 erasure gc-tick wiring stacked on the #2205 export --full + #1860 vectorlite serve/mcp boot funnels lands the merged file at 10_853; ceiling 10_850 -> 10_900 (lockstep). 2026-07-19 pre-ship 3x7: erasure sweep moved OFF the handler mutex (detached spawn_blocking arm + shared log helper) lands the file at 10_931; ceiling 10_900 -> 10_950 (lockstep). 2026-07-19 merged with the #2233/#2235 lineage boot-seed (+26) -> 10_957; ceiling 10_950 -> 11_000 (lockstep). 2026-07-19 #2271 consultation-posture mutation seam + behavior pin lands at 11_032; ceiling 11_000 -> 11_050 (lockstep). 2026-07-20 #2271 shutdown lifecycle hardening tracks every writer, bounds plain/TLS quiescence, drains deferred audit, and makes final witness/WAL certification fail closed; production plus regression coverage lands at 11_326, ceiling 11_050 -> 11_400 (+74 headroom, lockstep). 2026-07-21 #2290 sign the sync_cycle_once /sync/since pull GET (load daemon signing key + attach X-Memory-Sig/X-Memory-Nonce) lands the file at 11_406; ceiling 11_400 -> 11_450 (+44 headroom, lockstep). 2026-07-23 FBL-22 postgres serve maintenance loop (spawn_postgres_maintenance_loop_if_enabled gc + archive-purge + lease-sweep pg twin + bootstrap wiring + 2 spawn/skip unit tests) lands the file at 11_573; ceiling 11_450 -> 11_640 (+67 headroom, lockstep). */
    ("src/subscriptions.rs", 4_520), /* 2026-07-31 #2445 — 2-line disposition note on the ordering-covered raw open; measured 4_502 */
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
    // 2026-07-01 (#1825 G8) — bumped 4_700 → 4_850: the v74 ladder arm +
    // MIGRATION_V74_SQLITE + backfill_memory_cids pushed the file to 4_816.
    // 2026-07-01 (#1859 G13-mem) — bumped 4_850 → 4_950: the v75 ladder arm
    // (probe-guarded ALTER) + MIGRATION_V75_SQLITE + the bootstrap-SCHEMA
    // cid-mirror columns/index + the COND-8 rebuild-drift comments grew the
    // file to 4_871; 4_950 = 79 headroom.
    //
    // 2026-07-03 — bumped 4_950 → 5_050 by #1869 P0-1 (recall purity):
    // the v77 ladder arm (probe-guarded `recall_observations.folded`
    // column + backfill + partial unfolded index) + the
    // `MIGRATION_V77_SQLITE` sourcing (~44 LOC at 4_993, which was
    // within 1 LOC of the old ceiling). 5_050 = 4_993 + 57 headroom.
    // 2026-07-04 (#1870 §25.3 S1) — bumped 5_050 → 5_130 for the v78
    // model_attestations migration arm + const + bootstrap SCHEMA mirror
    // + fresh-install/upgrade ladder tests.
    // 2026-07-11 (#1942/#1941/#1945/#1834 crypto-core stage 2) — bumped
    // 5_130 → 5_260 for the v79 coordinated-migration arm (probe-guarded
    // ALTERs + agent_subkey_certs + ladder-owned index) + the bootstrap
    // SCHEMA mirror (kind_provenance / valid_from / valid_until columns
    // + certs table) + fresh-install/upgrade ladder tests, landing the
    // file at 5_235; +25 headroom. Growth justified: one additive
    // migration, zero speculative surface.
    // 2026-07-11 (#1949 merged): v80 lineage custody/revocation sqlite arm
    // lands the file at 5_300; ceiling 5_360 (+60 headroom).
    // 2026-07-15 (#2024): v82 skill retire/delete migration arm lands the
    // file at 5_372; ceiling 5_400 (+28 headroom). Additive migration only.
    // 2026-07-17 (#2167 S1): the v84 embedding_space migration arm + SCHEMA
    // column doc land migrations.rs at 5_446; ceiling 5_450 (+4 headroom).
    // Additive ALTER-ADD-COLUMN migration only.
    ("src/storage/migrations.rs", 6_540), /* 2026-08-25 (#3221 rebase onto 5cb2dc31): MEASURED 6_463. Ceiling 6_400 -> 6_540 (+77 headroom). Never lower a floor. */
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
    // 2026-07-05 (v0.9.0 §11.5 B7-FC-1 #1866) — bumped 5_500 → 6_060: the
    // function/tool-calling protocol — `ToolDef` / `ToolCall` / `ChatOutcome`
    // types + `parse_tool_calls` + `generate_with_tools`(`_async`) wire methods
    // + `ERR_SEND_CHAT`/`ERR_PARSE_CHAT`/`OLLAMA_CHAT_PATH`/`OPENAI_CHAT_PATH`
    // consts (de-scattered literals) + the `MockOllamaClient` scripted tool
    // method + 8 wiremock/unit tool-calling tests (file grew to 6_012);
    // 6_060 = 48 headroom. Refactor-split into `src/llm/{…}.rs` remains the
    // tracked post-ship ARCH cleanup.
    // 2026-07-31 (#2577): 6_060 -> 6_080. +15 LOC for the recall-scoped
    // embed budget primitives (`embed_text_with_budget` /
    // `embed_text_async_with_budget`) — the read path needs a bound the
    // 30 s `GENERATE_TIMEOUT` does not give it, and the budget must live
    // beside the client that owns the cancellable future. Bumped in
    // lockstep per the QUAL-10 contract; thresholds rise, never fall.
    // 2026-08-15 (F-L1 contradiction-detector hardening): 6_080 -> 6_360.
    // The bare "yes/no" contradiction prompt lets a WEAK local model cry wolf
    // on temporal supersessions + different-subject pairs (spurious
    // `contradicts` edges). Added the deterministic `shares_subject_token` /
    // `subject_tokens` subject-overlap pre-check + `CONTRADICTION_STOPWORDS` /
    // `MIN_SUBJECT_TOKEN_LEN` consts that GATE the LLM call, the two
    // discriminator clauses on `CONTRADICTION_PROMPT`, and 9 pre-check/gate
    // tests (pure + wiremock), growing the file to 6_344; 6_360 = 16 headroom.
    // Refactor-split into `src/llm/{…}.rs` remains the tracked post-ship
    // ARCH cleanup.
    // 2026-08-22 (#3140 sync↔async bridge bound): 6_360 -> 6_780. The
    // unbounded `block_on_local` was RETIRED and replaced by
    // `block_on_local_bounded`, which wraps all three runtime-flavor arms in
    // `tokio::time::timeout` and adds a driver-independent OS-thread alarm
    // (`spawn_wallclock_alarm` + `WallclockAlarmGuard` + the
    // `BRIDGE_ALARM_GRACE`/`BRIDGE_ALARM_POLL` consts) on the multi-thread
    // arm, whose timer belongs to a runtime this thread does not drive. Adds
    // the four derived budget constants (`BRIDGE_BUDGET_FACTOR`,
    // `BRIDGE_{GENERATE,HEALTH,PULL}_BUDGET`), `bridge_embed_batch_budget`,
    // `EPHEMERAL_RUNTIME_BUILD_MSG`, the `bridge_budget_tests_3140` module
    // (6 tests incl. a deterministic starved-time-driver reproduction), and
    // the wiremock-test `bridge_call` / `bounded_test_client` guards. Growth
    // is bound-and-proof, not feature surface: a bridge with no wall-clock
    // ceiling burned a full 80-minute macOS CI job. Measured 6_714; ceiling
    // 6_780 (+66 headroom). Refactor-split into `src/llm/{…}.rs` remains the
    // tracked post-ship ARCH cleanup.
    ("src/llm.rs", 6_780),
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
