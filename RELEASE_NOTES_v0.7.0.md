# ai-memory v0.7.0 — `attested-cortex`

**Tagged:** pending operator gate (post-merge of PR #820 ship-hardening bundle, 2026-05-20).
**Theme:** attested cortex + Batman 7-form closeout + postgres+AGE first-class + 7-level provenance framework + visibility-gate cluster + typed refusal envelopes.
**One-line summary:** v0.7.0 ships **73 MCP tools at `--profile full`** (was 43 at v0.6.3, 60 at the original `attested-cortex` cut, 71 at the post-grand-slam wave, 73 after the Provenance Gap 3 + Gap 4 surfaces landed), **7 always-on tools** at `--profile core` (the original 5 + `memory_load_family` + `memory_smart_load`), **72 HTTP routes** on `127.0.0.1:9077` (canonical via [`src/lib.rs::build_router`](src/lib.rs)), all 7 Batman write-time-investment forms IMPLEMENTED, postgres + Apache AGE as a first-class storage backend, schema **v48** sqlite + v48 postgres in lockstep (canonical anchors: `CURRENT_SCHEMA_VERSION = 48` in [`src/storage/migrations.rs`](src/storage/migrations.rs) + [`src/store/postgres.rs`](src/store/postgres.rs)), per-agent Ed25519 attestation with a V-4 cross-row signed-events hash chain, the 7-level provenance framework (#884-#890), and a v0.7.0-wide visibility-gate cluster + typed refusal envelopes (#962/#963).

---

This file is the top-level entrypoint by convention (matches
[`RELEASE_NOTES_v0.6.4.md`](RELEASE_NOTES_v0.6.4.md)). The **full
release notes** — including the post-grand-slam ship-readiness wave,
the schema and tool-surface deltas, the upgrade path from v0.6.4 and
v0.7-alpha, breaking changes, and the operator-references index —
live at:

  → [`docs/v0.7.0/release-notes.md`](docs/v0.7.0/release-notes.md)

The **canonical feature inventory** (every net-new feature relative
to v0.6.4, with code-path evidence) lives at:

  → [`docs/internal/v070-feature-inventory.md`](docs/internal/v070-feature-inventory.md)

The **v0.6.4 → v0.7.0 migration guide** lives at:

  → [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md)

---

## Headline highlights

- **73 MCP tools at `--profile full`** (verified against
  `Profile::full().expected_tool_count()` in [`src/profile.rs`](src/profile.rs);
  rose from 71 at the post-grand-slam wave to 73 after the Provenance
  Gap 3 `memory_recall_observations` (#886) + Gap 4 `confidence_tier`
  surfacing (#887) landed). **7 always-on at `--profile core`** (the
  original 5 + the v0.7 B1/B2 loader pair). Default tool surface is
  unchanged in spirit for v0.6.4 callers — the two new loaders are
  additive.
- **72 HTTP routes** on `127.0.0.1:9077` (canonical via
  [`src/lib.rs::build_router`](src/lib.rs); includes the
  `/api/v1/find_paths` route alias added under #934 + the visibility
  cluster's new admin / federation paths).
- **Schema v48 sqlite + v48 postgres in lockstep**
  (`CURRENT_SCHEMA_VERSION = 48`; canonical anchors:
  [`src/storage/migrations.rs`](src/storage/migrations.rs) for sqlite,
  [`src/store/postgres.rs`](src/store/postgres.rs) for postgres; latest
  on-disk migrations `migrations/sqlite/0041_v07_federation_push_dlq.sql`
  and `migrations/postgres/0030_v07_federation_push_dlq.sql` from #933).
- **Batman 6-form audit + Forms 1-6 + 7th-form (Option-B foundation)
  closeout.** All 7 forms IMPLEMENTED at HEAD `c9472c1`. See
  [`docs/internal/batman-framework-audit.md`](docs/internal/batman-framework-audit.md)
  (prologue covers the post-audit Forms wave).
- **QW-1/2/3 (Tencent quick-wins).** File-backed reflection export,
  persona-as-artifact, context-offload primitive.
- **Substrate trust.** Per-agent Ed25519 attestation, append-only
  `signed_events` audit table, V-4 cross-row hash chain (`prev_hash`
  + `sequence`) verified by `ai-memory verify-signed-events-chain`.
- **Postgres + Apache AGE first-class backend.**
  `ai-memory serve --store-url postgres://…`, schema parity, 6-factor
  recall scoring parity, KG features on AGE Cypher with recursive-CTE
  fallback. `ai-memory schema-init` CLI verb.
- **25-event programmable hook pipeline** (`~/.config/ai-memory/hooks.toml`).
- **K8 quota tool** (`memory_quota_status` + `/api/v1/quota/status`)
  and **K10 SSE approvals** (`/api/v1/approvals/stream` with mandatory
  HMAC signing).
- **Reconciliation security sweep** (11 late-cycle commits, merged
  into trunk at `64528b1`).

## Upgrade path

For most v0.6.4 callers, **no behavior change**. Run the schema
migration once (auto on first start of a sqlite-backed daemon),
optionally generate an Ed25519 keypair (`ai-memory identity generate`),
optionally migrate the governance policy store to the new permissions
shape (`ai-memory governance migrate-to-permissions --apply`).

Full procedure: [`docs/MIGRATION_v0.7.md`](docs/MIGRATION_v0.7.md).

— AlphaOne LLC, 2026-05-15
