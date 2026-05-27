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

## Out-of-scope items recorded in the source review

The v2 review surfaces additional MED/LOW items that the operator-set
directive demands be addressed eventually, but where the surgical
fix is too large to safely batch here (they each require their own
PR + multi-file refactor + per-finding regression test). The batch
above closes ALL items with sub-day surgical fix size; the residual
items below are tracked separately under the post-batch PR plan:

- **ARCH-6** (dep-graph dupes — 12 duplicate dep versions) —
  `cargo update --aggressive` against each duplicated crate.
  Multi-file; tracked as a stand-alone `chore(deps)` PR.
- **ARCH-7** (hook-event exhaustiveness) — `tests/hook_pipeline_exhaustiveness.rs`
  + `#[deny(unreachable_patterns)]` audit on `is_pre_event`.
- **ARCH-8** (per-migration metadata table) — new Rust-side
  `MigrationMeta` matrix; ~200 LOC + migration ladder annotations.
- **ARCH-9** (unified error slugs across `MemoryError` / `StorageError` /
  `StoreError`) — large multi-file refactor.
- **ARCH-10** (FFI feature gate / version stub) — touches Cargo.toml
  + lib.rs FFI surface; intentional v0.7.x scope.
- **ARCH-11** (feature-flag audit) — `Cargo.toml` cleanup + CI lint.
- **ARCH-13** (`pub use storage as db` → `pub(crate)`) — blocked on
  ARCH-2 SAL cleanup first.
- **ARCH-14** (HTTP route count invariant test) — distinct test file,
  needs router fixture wiring.
- **ARCH-15** (`as_any_for_postgres` rename) — adapter-trait surface
  change; staged with the SAL refactor track.
- **QUAL-6** (`Result<Value, String>` legacy in 81 MCP handlers) —
  the largest mechanical refactor on the list; intentional Wave-3
  candidate, separate PR per handler family.
- **QUAL-7** (`Result<(), String>` legacy in non-handler paths) —
  same shape as QUAL-6, smaller scope.
- **QUAL-10** (modules >3000 LOC re-split) — long-running refactor
  tracked under #650 / #867 / #961.
- **QUAL-12** (TODO/FIXME tracker filings) — 28 TODOs each need
  their own GH issue; bulk-file is the discipline.
- **PERF-5** (`embed_batch` true batching) — Candle + Ollama wire
  shape change.
- **PERF-7** (`valid_ids_cache` u128 / Arc<str>) — HNSW lock-shape
  refactor.
- **PERF-8** (touch_ids `.collect()` + hierarchy SQL cache) — minor
  but needs caller-trait surface change for max benefit.
- **PERF-11** (release profile: `lto=fat`, `codegen-units=1`,
  `panic=abort`) — operator-decision-required because it affects
  every downstream binary consumer; needs before/after bench data.
- **PERF-12** (`OllamaClient::new_with_url` async health-check) —
  lifecycle refactor; staged with the broader `OllamaClient` →
  `LlmClient` rename + async migration.
- **DOC-6** (`#[deprecated]` attrs on legacy config fields) —
  introduces compile-time deprecation warnings across the legacy
  fallback path; needs a coordinated pass across the resolver tests.

Each of the residuals above has a clear path and is tracked in the
"Wave-C residuals" follow-up; none is a `DEFER-TO-V080`-class issue,
just a separate-PR-size issue.

## Verification

`cargo fmt --check` clean.
`cargo build --features sal,sal-postgres` clean.
`cargo clippy --lib --features sal,sal-postgres -- -D warnings -D clippy::all -D clippy::pedantic` clean.
`cargo test --lib --features sal,sal-postgres cli::curator::tests::qual_2_run_rollback_returns_error_when_no_mode_set` → 1 passed.
`cargo test --lib --features sal,sal-postgres embeddings::tests::cosine_similarity` → 9 passed (PERF-4 byte-equal).
