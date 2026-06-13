# 04 — Storage + SAL Backend (v0.7.0)

Audit of the storage substrate + Storage Abstraction Layer (SAL) of
ai-memory v0.7.0 (`release/v0.7.0`). Domains: `src/storage/` (sqlite +
migrations), `src/store/` (SAL trait + sqlite/postgres adapters),
`src/models/` (Memory / MemoryLink / enums), `src/migrate.rs`. Every
claim carries `file:line` provenance against the on-disk source.

---

## 1. Schema version (CURRENT_SCHEMA_VERSION) — must be lockstep

| Backend | Constant | Type | Value | Provenance |
|---|---|---|---|---|
| SQLite | `CURRENT_SCHEMA_VERSION` | `i64` | **53** | `src/storage/migrations.rs:554` |
| Postgres | `CURRENT_SCHEMA_VERSION` | `i32` | **53** | `src/store/postgres.rs:433` |

**Lockstep is verified, not assumed.** The two adapters share a single
logical schema number even though their on-disk migration counters
diverge (sqlite splits one file per bump; postgres has postgres-only
ladder steps such as v29 `vector(N)` conversion + v30
`memories_metadata_is_object` CHECK that have no sqlite analogue). The
parity invariant is pinned by two tests:

- `current_schema_version_matches_sqlite_ladder` — `src/store/postgres.rs:13619`
  (documents the per-step mapping; v42–v53 enumerated at lines 13633–13648).
- `live_migration_reaches_current_schema_version` — `src/store/postgres.rs:13670`.

Test-facing SSOT accessors (so test fixtures never embed the literal):
`current_schema_version_for_tests()` `src/storage/migrations.rs:566`,
`current_schema_version()` `src/storage/migrations.rs:576`.

**Type drift note:** sqlite constant is `i64`, postgres constant is
`i32`. Same numeric value; different width. Tracked in DRIFT below.

### Migration ladder — recent arms (v48–v53)

| v | Name / table delta | Issue | SQLite arm | SQLite file | Postgres arm |
|---|---|---|---|---|---|
| v48 | `federation_push_dlq` table (quorum-broadcast fanout DLQ) | #933 (Track D) | `if version < 48` `src/storage/migrations.rs:2062` | `migrations/sqlite/0041_v07_federation_push_dlq.sql` (table @ `:33`) | `migrate_v48` `src/store/postgres.rs:1904` |
| v49 | `archived_memories` + **14 nullable columns** (lossless archive→restore for full v0.7.0 Memory shape) | #1025 | `if version < 49` `:2069` | (in-ladder ALTERs) | `migrate_v49` `src/store/postgres.rs:1934` |
| v50 | `agent_quotas` PK `(agent_id)` → `(agent_id, namespace)` (per-namespace K8 quota); pre-existing rows backfill to `_global` sentinel | #1156 | `if version < 50` `:2125` | `migrations/sqlite/0042_v50_per_namespace_quota.sql` | `migrate_v50` `src/store/postgres.rs:1995` |
| v51 | `federation_nonce_cache` table (peer-replay-prevention nonce persistence across restarts) | #1255 / PR #1296 | `if version < 51` `:2164` | `migrations/sqlite/0043_v51_federation_nonce_cache.sql` (table @ `:36`) | `migrate_v51` `src/store/postgres.rs:2076` (no-op DDL stub — nonce cache lives in sqlite; postgres bumps to keep lockstep) |
| v52 | `transcript_line_dedup` table — L4 `memory_capture_turn` idempotency; `(host_pubkey_b64, line_sha256)` composite key + `memory_id` FK | #1389 (L4) | `if version < 52` `:2172` | `migrations/sqlite/0044_v52_transcript_line_dedup.sql` (table @ `:48`) | `migrate_v52` `src/store/postgres.rs:2121` |
| v53 | Scope `memories_au` FTS5 sync trigger to `(title, content, tags)` — DROP + recreate `AFTER UPDATE OF`; perf-only, byte-equal wire | #1418 (R5.F5.2) | `if version < 53` `:2182` | `migrations/sqlite/0045_v53_memories_au_trigger_columns.sql` | `migrate_v53` `src/store/postgres.rs:2200` (no-op DDL stub — postgres has no FTS5 trigger; uses pgvector+tsvector directly) |

The 14 v49 columns (`src/store/postgres.rs:13641`): `reflection_depth`,
`atomised_into`, `atom_of`, `memory_kind`, `entity_id`,
`persona_version`, `citations`, `source_uri`, `source_span`,
`confidence_source`, `confidence_signals`, `confidence_decayed_at`,
`mentioned_entity_id`, `version`.

Migration-arm metadata (version / name / idempotent / reversible /
data-loss-risk) is catalogued in the `MIGRATION_LADDER` table —
`MigrationMeta` struct `src/storage/migration_meta.rs:41`, lookup
`meta_for` `:433`, ladder-terminates-at-current invariant test
`arch_8_ladder_terminates_at_current_schema_version` `:455`.

---

## 2. The SAL trait (`MemoryStore`)

Defined `src/store/mod.rs` (`trait MemoryStore: Sync`). **~70 method
signatures** (one `capabilities()` sync getter + the rest `async`).
Returns the uniform `StoreResult<T> = Result<T, StoreError>`
(`src/store/mod.rs:272`). Every mutating method threads a
`CallerContext` (`src/store/mod.rs:278`: `agent_id`, `as_agent`,
`request_id`, `bypass_visibility`) for NHI identity + scope=private
visibility gating.

Representative surface (provenance `src/store/mod.rs`):

| Group | Methods (line) |
|---|---|
| Schema/caps | `capabilities`:`mod.rs` getter, `schema_version`:`:21`, `health_check`:`:1051`, `stats`:`:1070` |
| CRUD | `store`:`:28`, `store_with_embedding`:`:39`, `update_embedding`:`:54`, `get`:`:111`, `update`:`:116`, `delete`:`:119`, `list`:`:123`, `search`:`:128` |
| L4 capture | `capture_turn_idempotent`:`:97` |
| Links/KG | `link`:`:153`, `link_signed`:`:175`, `list_links`:`:200`, `get_links_for_anchor`:`:231`, `verify_link`:`:880`, `invalidate_link`:`:1161`, `find_paths`:`:900`, `kg_query`:`:1278`, `kg_timeline`:`:1304` |
| Recall | `recall_hybrid`:`:423`, `touch_after_recall`:`:453`, `check_duplicate_with_text`:`:1190`, `find_contradictions`:`:1133` |
| Federation | `list_memories_updated_since`:`:313`, `apply_remote_memory`:`:345`, `apply_remote_link`:`:368`, `apply_remote_deletion`:`:383` |
| Archive/GC | `run_gc`:`:608`, `archive_restore`:`:622`, `archive_purge`:`:652`, `archive_by_ids`:`:667`, `list_archived`:`:1369`, `forget`:`:563`, `consolidate`:`:588` |
| Quotas | `quota_status`:`:831`, `quota_status_ns`:`:843`, `quota_status_list`:`:854`, `quota_status_list_ns`:`:866` |
| Namespace | `set/clear/get_namespace_standard`:`:509`/`:524`/`:536`, `build_namespace_chain`:`:737`, `list_namespaces`:`:934`, `get_taxonomy`:`:956` |
| Governance | `resolve_governance_policy`:`:747`, `governance_approve_with_consensus`:`:768`, `enforce_governance_action`:`:801` |
| Agents/entities | `register_agent`:`:239`, `is_registered_agent`:`:786`, `list_agents`:`:981`, `entity_register`:`:1335`, `entity_get_by_alias`:`:1029` |
| Pending actions | `pending_decide`:`:480`, `get_pending`:`:494`, `list_pending_actions`:`:1004`, `decide_pending_action`:`:1251`, `approve_with_approver_type`:`:1228`, `execute_pending_action`:`:70` |
| Verify/export | `verify`:`:138`, `export_memories`:`:683`, `export_links`:`:693`, `notify`:`:704` |
| Tx + downcast | `begin_transaction`:`:143`, `as_any`:`:265`, `as_any_for_postgres`:`:278` |

### sqlite vs postgres dispatch

- **`SqliteStore`** `src/store/sqlite.rs:30` — holds
  `Arc<Mutex<rusqlite::Connection>>` + `PathBuf`. Implements
  `MemoryStore` `:60`. Methods are thin delegates to `crate::storage::*`
  (`db` alias) free-functions (e.g. `link` → `db::create_link`
  `sqlite.rs:261`; `find_paths` → `db::find_paths` `:1006`).
- **`PostgresStore`** `src/store/postgres.rs:502` — holds `PgPool` +
  resolved `kg_backend: KgBackend`. sqlx-native + pgvector. Implements
  `MemoryStore` (`PostgresStore → MemoryStore`).
- Both advertise `capabilities()`; `SqliteStore` deliberately does NOT
  advertise `TRANSACTIONS`/`ATOMIC_MULTI_WRITE` (`sqlite.rs:61`) and its
  `Transaction` impl is a no-op (`SqliteTransaction` `commit`/`rollback`
  return `Ok(())` `:1377`/`:1381`).

**"SAL-parity" guarantee:** any new public DB operation lands on the
trait first, then on BOTH adapters; the caller-observable wire shape is
byte-identical across backends (e.g. `link_signed` resolves the same
`attest_level` literal on sqlite `sqlite.rs:272` as postgres). Parity is
enforced by `tests/store_parity_gaps.rs` (e.g.
`sqlite_trait_update_bumps_version_1024` `:494` pins the optimistic
`version` 1→2→3 bump; Gap 1–7 postgres twins gated on
`AI_MEMORY_TEST_POSTGRES_URL`).

### Apache AGE Cypher path + pgvector

- `KgBackend` enum `src/store/mod.rs:77` — `Cte` (recursive-CTE over
  `memory_links`, default for sqlite + AGE-less postgres) | `Age`
  (Cypher over the `memory_graph` projection). `as_str` → `"cte"`/`"age"`
  `:92`.
- AGE is **probed at connect time** (`detect_kg_backend`); the
  `memory_graph` projection is bootstrapped via idempotent
  `create_graph('memory_graph')` (`ensure_memory_graph`,
  `src/store/postgres.rs:815-835`).
- **Runtime AGE→CTE graceful fallback:** `find_paths`
  `src/store/postgres.rs:4984` dispatches on `self.kg_backend`; AGE path
  is `find_paths_cypher` `:5172`, CTE fallback `find_paths_cte`; an
  AGE-runtime failure (`is_age_runtime_failure`) falls back transparently
  (`:5003`). Same pattern for `kg_query` (trait `:11179` → inherent
  `kg_query_with_history` `:4072` → `kg_query_cypher` `:4145`). Cypher
  executes via `SELECT * FROM cypher('memory_graph', $$ ... $$, ...)`
  (`:2857`).
- **pgvector:** module-level doc `src/store/postgres.rs:4`; embedding
  columns are `vector({EMBEDDING_DIM})` (`render_schema_sql` `:480`,
  placeholder `:473`). `DEFAULT_EMBEDDING_DIM = 384` (`:458`),
  `SUPPORTED_EMBEDDING_DIMS = [384, 768]` (`:465`). pgvector version is
  sanity-checked to 0.7.x–0.8.x at connect (`:745`). Full-text on
  postgres uses native `to_tsvector`/`ts_rank` (`:2644`), NOT an FTS5
  trigger.
- SAL-level visibility filter is applied AFTER traversal on both
  backends: `find_paths` drops any path touching a scope=private memory
  the caller doesn't own, fail-closed (postgres `:10413`, sqlite `:1008`).

---

## 3. Memory struct — 26 fields

Canonical: `src/models/memory.rs:430` (`pub struct Memory`). 26 fields
(confirmed by field enumeration of the struct body):

| # | Field | Type | Origin |
|---|---|---|---|
| 1 | `id` | `String` | v0.6.x |
| 2 | `tier` | `Tier` | v0.6.x (short/mid/long) |
| 3 | `namespace` | `String` | v0.6.x |
| 4 | `title` | `String` | v0.6.x |
| 5 | `content` | `String` | v0.6.x |
| 6 | `tags` | `Vec<String>` | v0.6.x |
| 7 | `priority` | `i32` (1–10) | v0.6.x |
| 8 | `confidence` | `f64` (0.0–1.0) | v0.6.x |
| 9 | `source` | `String` | v0.6.x |
| 10 | `access_count` | `i64` | v0.6.x |
| 11 | `created_at` | `String` | v0.6.x |
| 12 | `updated_at` | `String` | v0.6.x |
| 13 | `last_accessed_at` | `Option<String>` | v0.6.x |
| 14 | `expires_at` | `Option<String>` | v0.6.x |
| 15 | `metadata` | `Value` (JSON) | v0.6.x |
| 16 | `reflection_depth` | `i32` | v0.7.0 recursive-learning (schema v29 sqlite/v31 pg) |
| 17 | `memory_kind` | `MemoryKind` | Form-6 Batman vocab (schema v30) |
| 18 | `entity_id` | `Option<String>` | QW-2 persona |
| 19 | `persona_version` | `Option<i32>` | QW-2 persona (schema v36) |
| 20 | `citations` | `Vec<Citation>` | Form-4 provenance |
| 21 | `source_uri` | `Option<String>` | Form-4 provenance |
| 22 | `source_span` | `Option<SourceSpan>` | Form-4 provenance |
| 23 | `confidence_source` | `ConfidenceSource` | Form-5 calibration (schema v39 sqlite/v38 pg) |
| 24 | `confidence_signals` | `Option<ConfidenceSignals>` | Form-5 calibration |
| 25 | `confidence_decayed_at` | `Option<String>` | Form-5 calibration |
| 26 | `version` | `i64` | **schema v45 — Gap-1 optimistic concurrency** |

`version` defaults to 1 on legacy rows (SQL `DEFAULT` +
`#[serde(default = "default_memory_version")]`).

### Related enums (`src/models/memory.rs`)

- `MemoryKind` `:38` — **10 variants**: `Observation` (default),
  `Reflection`, `Persona`, `Concept`, `Entity`, `Claim`, `Relation`,
  `Event`, `Conversation`, `Decision` (`as_str` `:90`, `all()` `:129`).
- `ConfidenceSource` `:222` — **5 variants**: `CallerProvided` (default),
  `AutoDerived`, `Calibrated`, `Decayed`, `CuratorDerived` (#1242).

---

## 4. MemoryLink — 9 fields, relation enum 6 variants

`pub struct MemoryLink` `src/models/link.rs:237`. **9 fields:**
`source_id`, `target_id`, `relation` (`MemoryLinkRelation`),
`created_at`, `signature` (`Option<Vec<u8>>`), `observed_by`
(`Option<String>`), `valid_from`, `valid_until`, `attest_level`
(`Option<String>`). The temporal-validity columns (`valid_from`,
`valid_until`, `observed_by`) + attestation columns (`signature`,
`attest_level`) are the v0.7 additions.

`MemoryLinkRelation` enum `src/models/link.rs:114` — **6 variants**
(serde snake_case; paired with SQL CHECK constraint from R1-M4):

| Variant | Wire string | Meaning |
|---|---|---|
| `RelatedTo` | `related_to` | generic association (default) |
| `Supersedes` | `supersedes` | newer/authoritative version |
| `Contradicts` | `contradicts` | incompatible claims |
| `DerivedFrom` | `derived_from` | consolidation provenance |
| `ReflectsOn` | `reflects_on` | recursive-learning (Task 1/8) |
| `DerivesFrom` | `derives_from` | WT-1-A atomisation: atom row → parent memory (schema v36 sqlite/v35 pg) |

`from_str` `:148` / `as_str` `:164`. Note the deliberate
`derived_from` vs `derives_from` distinction (consolidation vs
atomisation provenance).

`AttestLevel` enum `src/models/link.rs` (`as_str` @ `:80`) — 5 variants:
`Unsigned`, `SelfSigned`, `PeerAttested`, `SignedByPeer`, `DaemonSigned`.

---

## 5. FTS5 sync triggers (sqlite)

Defined in the bundled `SCHEMA` string + the v53 migration file.
Virtual table `memories_fts` (`content='memories'`,
`content_rowid=rowid`). Three triggers (`src/storage/migrations.rs`):

| Trigger | Event | Line | Note |
|---|---|---|---|
| `memories_ai` | `AFTER INSERT` | `:221` | insert FTS row |
| `memories_ad` | `AFTER DELETE` | `:226` | FTS `'delete'` op |
| `memories_au` | **`AFTER UPDATE OF title, content, tags`** | `:237` | v53 column-scoped (was un-scoped `AFTER UPDATE`) |

The v53 scope-narrowing means UPDATEs touching only `embedding` /
`access_count` / `last_accessed_at` / `confidence_decayed_at` /
`version` no longer fire 2 spurious FTS5 row ops. Swap performed by the
`if version < 53` arm via DROP+recreate
(`migrations/sqlite/0045_v53_memories_au_trigger_columns.sql:29-32`),
gated on `memories_fts` actually existing. **Postgres has no FTS5
trigger** — uses pgvector + `to_tsvector` directly.

Also present: CHECK-enforcement triggers (tier/priority/confidence/
relation/attest_level) via `RAISE(ABORT,...)`
(`migrations/sqlite/0023_v07_check_constraints.sql`).

---

## 6. Archive / restore, GC, quotas, federation, namespace tables

| Concern | Table(s) | Provenance |
|---|---|---|
| Archive/restore | `archived_memories` (+14 v49 cols for lossless full-shape carry) | `migrate_v49` `src/store/postgres.rs:1934`; SAL `archive_restore`/`archive_purge`/`archive_by_ids`/`list_archived` |
| GC | runs every 30 min; `archive_on_gc=true` default archives before delete | SAL `run_gc` `src/store/mod.rs:608` |
| Quotas | `agent_quotas`, PK `(agent_id, namespace)` post-v50 (`_global` sentinel backfill) | v50 `migrations/sqlite/0042_v50_per_namespace_quota.sql`; SAL `quota_status*` `mod.rs:831-866` |
| Federation DLQ | `federation_push_dlq` (v48) | `0041_v07_federation_push_dlq.sql:33`; `migrate_v48` `:1904` |
| Federation nonce | `federation_nonce_cache` (v51) — persists peer-replay-prevention nonces across restarts | `0043_v51_federation_nonce_cache.sql:36`; `migrate_v51` `:2076` |
| L4 turn dedup | `transcript_line_dedup` (v52) — `(host_pubkey_b64, line_sha256)` + `memory_id` FK | `0044_v52_transcript_line_dedup.sql:48`; `migrate_v52` `:2121` |
| Optimistic concurrency | `memories.version` BIGINT (v45, Gap-1) | `Memory.version` field 26; parity test `tests/store_parity_gaps.rs:494` |

### Namespace model

- Hierarchical namespaces resolved via `build_namespace_chain`
  (`src/store/mod.rs:737`), enumerated by `list_namespaces` (`:934`),
  with per-namespace standards `set/clear/get_namespace_standard`
  (`:509`/`:524`/`:536`) and `get_taxonomy` (`:956`). Default repo
  namespace `ai-memory-mcp`.

### Backups

`SqliteStore::path()` (`src/store/sqlite.rs:50`) exposes the open DB
path for callers that spawn subprocesses (backup, rekey). The
`dogfood-rebuild.sh` flow backs up the live DB + dry-runs migrations
against the backup (per CLAUDE.md). sqlcipher (`--features sqlcipher` +
`AI_MEMORY_ENCRYPT_AT_REST`) gates encryption-at-rest.

---

## DRIFT / DEFECTS SPOTTED

1. **`CURRENT_SCHEMA_VERSION` type mismatch (cosmetic).** sqlite is
   `i64` (`src/storage/migrations.rs:554`), postgres is `i32`
   (`src/store/postgres.rs:433`). Same value (53), different width. Not
   a correctness bug (the lockstep test asserts numeric equality) but a
   constant-type drift across the two SSOTs; a single shared `i64`
   constant would remove the mismatch.

2. **CLAUDE.md "Database" section names the v51 table
   `federation_nonces`** ("v51 added the `federation_nonces` table");
   the actual table + migration file are `federation_nonce_cache`
   (`migrations/sqlite/0043_v51_federation_nonce_cache.sql:36`, code
   refs at `src/storage/migrations.rs:902`, `src/store/postgres.rs:417`).
   Doc-string vs code drift in the operator-facing prose. (Per the prime
   directive this is a real defect — file + fix the doc.)

3. **Postgres ladder v51 + v53 are no-op DDL stubs** that only record
   the schema-version reach (`migrate_v51` `:2076` comment "no-op
   postgres DDL"; `migrate_v53` `:2200`). This is intentional lockstep
   bookkeeping (the nonce cache + FTS5 trigger are sqlite-only
   primitives), NOT unused-table drift — but worth flagging as "table
   created in sqlite, version-bump-only on postgres" so an auditor isn't
   surprised by the empty postgres arms.

4. **`SqliteStore` Transaction is a no-op** (`commit`/`rollback` return
   `Ok(())`, `src/store/sqlite.rs:1377`/`:1381`) and the adapter does
   not advertise `TRANSACTIONS`/`ATOMIC_MULTI_WRITE` in `capabilities()`
   (`:61`). Honest capability reporting, but a parity asymmetry vs
   postgres worth noting for any caller relying on multi-write atomicity.
