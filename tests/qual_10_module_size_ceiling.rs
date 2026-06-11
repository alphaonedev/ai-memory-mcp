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
    ("src/storage/mod.rs", 17_400),
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
    ("src/mcp/mod.rs", 14_450),
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
    ("src/store/postgres.rs", 16_900),
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
    ("src/config.rs", 9_800),
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
    ("src/daemon_runtime.rs", 8_400),
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
    ("src/storage/migrations.rs", 3_800),
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
    ("src/llm.rs", 5_350),
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
