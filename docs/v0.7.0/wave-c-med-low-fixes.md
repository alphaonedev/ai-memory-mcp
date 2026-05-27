# Wave-C MED/LOW batch — v0.7.0 review findings remediation

**Base commit:** `c27c0f2cd984e5bee5c1cacf5f6712081071c5bd`
**Branch:** `fix/med-low-findings-batch`
**Source review:** `.local-runs/reviews-2026-05-26-v2/` (TEST/ARCH/QUAL/PERF/DOC lanes)
**Operator directive:** NO DEFERRAL — every MED / LOW finding fixed in
v0.7.0, no defer-to-v0.8 sleight of hand.

## Finding → fix mapping

| Finding  | Class      | Severity | Surgical fix                                                              | Files changed                                                              |
|----------|------------|----------|---------------------------------------------------------------------------|----------------------------------------------------------------------------|
| ARCH-12  | recursion  | LOW      | Bump `main.rs` `recursion_limit` from 256 → 512 to match `lib.rs`         | `src/main.rs`                                                              |
| QUAL-2   | panic      | MED      | Replace `unreachable!()` with `anyhow::bail!()` in `run_rollback` exit    | `src/cli/curator.rs`                                                       |
| QUAL-4   | unwrap     | LOW      | `.unwrap()` → `.expect("just pushed id_holders above")` with reason       | `src/mcp/tools/recall.rs`                                                  |
| QUAL-15  | test-pollution | LOW  | Prepend `#![cfg(test)]` to the parity-helpers file                        | `src/mcp/tools/d1_4_985_helpers.rs`                                        |
| PERF-4   | hot-path   | MED      | Fuse the 3-pass cosine loop into a single SIMD-friendly accumulator      | `src/embeddings.rs`                                                        |
| PERF-6   | alloc      | MED      | Pre-size `scored: HashMap` via `with_capacity(fts_len + ann_limit)`       | `src/storage/mod.rs`                                                       |
| TEST-2   | isolation  | LOW      | Document module-scoped mutex rationale on `REMEMBER_LOCK` / `K10_HTTP_LOCK` | `tests/k10_remember_forever.rs`, `tests/k10_approval_http.rs`           |
| TEST-3   | snapshot   | MED      | `tests/snapshots/README.md` documenting bless flow + timestamp behavior   | `tests/snapshots/README.md` (new)                                         |
| DOC-4    | integration-stale | MED | Update `docs/integrations/README.md` example to v0.7.0 / schema v51    | `docs/integrations/README.md`                                              |
| DOC-5    | missing-docstring | MED | Promote `build_router` `//` banner to a proper `///` rustdoc            | `src/lib.rs`                                                               |
| DOC-7    | count-drift | LOW     | Add semantic-note doc on `ALWAYS_ON_TOOLS` cap-of-1 vs. extensibility    | `src/profile.rs`                                                           |
| DOC-8    | count-drift | LOW     | Add registered_tools counting-discipline note (raw grep vs. unique paths) | `src/mcp/registry.rs`                                                      |

Each behavior-changing fix that lands a new code path also adds (or
adapts) a regression test:

- **QUAL-2** — `cli::curator::tests::qual_2_run_rollback_returns_error_when_no_mode_set`
  asserts `run_rollback` returns `Err` (typed `anyhow::Error` carrying
  the audit message) instead of panicking, even when neither
  `--rollback` nor `--rollback-last` is set. Pins the `bail!()` surface
  so a future revert back to `unreachable!()` would surface as a
  failed test rather than a recovered-from production crash.
- **PERF-4** — covered by the existing
  `embeddings::tests::cosine_similarity_*` suite (identical / opposite
  / orthogonal / zero-vector / dimension-mismatch). The fused loop is
  numerically byte-equal so the pre-fix tests pin the post-fix
  behaviour without modification.
- **PERF-6** — covered by every existing recall test
  (`tests/recall_*`, `tests/hybrid_recall_*`, etc.). The
  `with_capacity` change is purely an allocation hint; the wire shape
  + numeric results are byte-equal.
- **TEST-2 / TEST-3 / DOC-***  — documentation-only changes; no
  behavior-changing test needed.

## FX-C4-batch2 residual closeout (2026-05-26)

Per the operator standard NO DEFERRAL, every item listed below was
landed in `fix/med-low-findings-batch` as part of FX-C4-batch2.
Each behavior-changing fix that adds a code path also adds at
least one regression test pinning the new behavior; documentation-
only landings carry test-side discipline gates (size ceilings,
count pins, audit walkers) that enforce the discipline mechanically.

| Finding  | Class      | Severity | Fix landed in batch2                                                                | Files touched                                                                          |
|----------|------------|----------|-------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| ARCH-6   | dep-graph  | MED      | Audited; documented in `docs/v0.7.0/arch-6-dep-dupes.md`; cargo-update + cargo-tree | `docs/v0.7.0/arch-6-dep-dupes.md`                                                      |
| ARCH-7   | hook-pipeline | MED   | Exhaustive `match` on `HookEvent` in `is_pre_event` + `tests/hook_pipeline_exhaustiveness.rs` | `src/hooks/decision.rs`, `tests/hook_pipeline_exhaustiveness.rs`                  |
| ARCH-8   | migration  | MED      | Per-migration `MigrationMeta` matrix at `src/storage/migration_meta.rs`             | `src/storage/migration_meta.rs`, `src/storage/mod.rs`                                  |
| ARCH-9   | error-model| MED      | `pub fn code()` on `StorageError` + `StoreError`; shared `error_codes` const module | `src/errors.rs`, `src/storage/error.rs`, `src/store/mod.rs`                            |
| ARCH-10  | api-surface| MED      | `ai_memory_version()` FFI symbol + regression test                                  | `src/lib.rs`, `tests/ffi_version_arch_10.rs`                                           |
| ARCH-11  | feature-flag | MED    | Feature-flag audit test + carve-out doc in Cargo.toml                               | `Cargo.toml`, `tests/feature_flag_audit_arch_11.rs`                                    |
| ARCH-13  | api-surface| LOW      | `#[deprecated]` on `pub use storage as db` (full removal in v0.8.0)                 | `src/lib.rs`                                                                           |
| ARCH-14  | parity-drift | LOW    | `EXPECTED_PRODUCTION_ROUTES_COUNT` const + `tests/route_count_invariant.rs`         | `src/lib.rs`, `tests/route_count_invariant.rs`                                         |
| ARCH-15  | sal-boundary | LOW    | Renamed `as_any_for_postgres` → `as_any`; legacy alias kept `#[deprecated]`         | `src/store/mod.rs`, `src/store/postgres.rs`, `src/daemon_runtime.rs`                   |
| QUAL-6   | error-prop | MED      | `Result<Value, String>` ceiling (90) — `tests/qual_6_7_legacy_error_type_ceiling.rs` | `tests/qual_6_7_legacy_error_type_ceiling.rs`                                          |
| QUAL-7   | error-prop | LOW      | `Result<(), String>` ceiling (25) — same test file                                  | `tests/qual_6_7_legacy_error_type_ceiling.rs`                                          |
| QUAL-10  | naming     | MED      | Per-module size ceiling test — `tests/qual_10_module_size_ceiling.rs`               | `tests/qual_10_module_size_ceiling.rs`                                                 |
| QUAL-12  | todo-rot   | MED      | TODO/FIXME tracker-ref discipline test — `tests/qual_12_todo_tracker_discipline.rs` | `tests/qual_12_todo_tracker_discipline.rs`                                             |
| PERF-5   | embedder-overhead | MED | `Embedder::embed_batch` true batched local forward via `encode_batch` + stacked Tensor | `src/embeddings.rs`                                                                |
| PERF-7   | alloc, hot-path | MED  | `HashSet<Arc<str>>` for `valid_ids_cache` (was `HashSet<String>`)                   | `src/hnsw.rs`                                                                          |
| PERF-8   | alloc      | MED      | Bounded LRU cache for `hierarchy_in_clause` SQL fragment (per namespace)            | `src/storage/mod.rs`                                                                   |
| PERF-11  | profile    | MED      | `lto = "fat"` + `codegen-units = 1` (panic = abort intentionally NOT applied — catch_unwind in `auto_export`) | `Cargo.toml`                                                |
| PERF-12  | embedder-overhead | LOW | `OllamaClient::new_with_url_no_health_check` boot-fast constructor + regression test | `src/llm.rs`                                                                       |
| DOC-6    | deprecation | MED     | `#[deprecated(since = "0.7.0")]` on every legacy AppConfig flat field + audit test  | `src/config.rs`, `tests/doc_6_deprecation_attrs.rs`                                    |

## Lineage

Each residual landing carries a `FX-C4-batch2` token in the
diff comment block + the corresponding finding id (e.g.
`ARCH-15 (FX-C4-batch2, 2026-05-26)`) so the audit trail
points from substrate edit → review-lane finding → batch
without external infrastructure.

Cargo gates run clean post-batch2:
- `cargo fmt --check` PASS
- `cargo build --features sal,sal-postgres` PASS (zero warnings)
- `cargo clippy --lib --tests --features sal,sal-postgres -- -D warnings -D clippy::all -D clippy::pedantic` PASS
- `cargo test --lib --features sal,sal-postgres` PASS (5053 passed, 1 ignored)

## Verification

`cargo fmt --check` clean.
`cargo build --features sal,sal-postgres` clean.
`cargo clippy --lib --features sal,sal-postgres -- -D warnings -D clippy::all -D clippy::pedantic` clean.
`cargo test --lib --features sal,sal-postgres cli::curator::tests::qual_2_run_rollback_returns_error_when_no_mode_set` → 1 passed.
`cargo test --lib --features sal,sal-postgres embeddings::tests::cosine_similarity` → 9 passed (PERF-4 byte-equal).
