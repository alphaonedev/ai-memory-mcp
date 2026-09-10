# AUDIT C — #3587 swarm anti-drift — CONTRACTS / TESTS / OPERABILITY lens

Read-only. codegraph 1.6.0 for every structural question (commands cited inline); grep only for literal test names / messages. Rule IDs from the project rust-1.98 skill.

## 1. VERDICT

| Unit | Verdict | Reason |
|---|---|---|
| U1 store supersession | **SHIP-WITH-CHANGES** | Mechanism right and largely already present, but the issue's premise ("existing `resolve` semantics") is factually wrong, and there are FOUR store funnels plus a title/namespace upsert collision to close first. |
| U2 `watch --host file:` | **DO-NOT-SHIP-IN-v1.0.0** | "Byte cursor persisted in the DB" is an undeclared schema v99 migration on BOTH ladders plus a `HostKind` type change with 41-symbol blast radius; the cursor is also unsafe under rotate/truncate. Ship the non-persistent `--once` subset or defer. |
| U3 curator stale-rulings | **SHIP-WITH-CHANGES** | Read-only sweep is safe and additive, but must notify through the typed explicit-sender funnel and must not inline an unbounded ruling list into the durable `_curator/reports` row (#3345 bloat class). |
| U4 `capture-turn` + install hook | **SHIP-WITH-CHANGES** | Flag shape is wrong (`--hook capture`, not `--capture-hook`), two CLI-count SSOTs move, `install codex --capture-hook` collides with a pinned refusal. Drop the Codex leg. |
| U5 docs + SSOT | **SHIP-WITH-CHANGES** | "QUAL ceilings unchanged" is FALSE: three QUAL-10 ceilings bind with 42–152 lines of headroom. The unit must own lockstep bumps, not assert none are needed. |
| U6 operator wiring | **SHIP-WITH-CHANGES** | Two unsupervised daemons, no unit file, no log destination, no restart policy, writing concurrently into DBs an MCP server already holds — not yet "manageable at scale". |

**Does it close "an agent stops writing; old facts left standing" end to end? NO — three gaps.**
(a) It closes only the *recall* half, and only for memories carrying `ruling_key`; nothing makes a stopped agent resume writing — U4's Stop hook is the sole lever and it is Claude-Code-only.
(b) U6 puts deputy memories in the f1 hive and Conductor rulings in the f2 DB. `ruling_key` supersession is scoped `(namespace, key)` **inside one store**, so a deputy ruling can never supersede a Conductor ruling. U6 leaves two disjoint truth sets and does not say so.
(c) Ranking: archiving genuinely removes a row from recall — `memories` and `archived_memories` are separate tables (`SQL_MEMORY_EXISTS_COUNT` vs src/storage/mod.rs:5319) — so U1 does fix superseded-vs-new ranking. But `resolve`, the verb the issue names as precedent, does **not** archive (F1), so every manually-resolved ruling is still ranked and returned today.

## 2. FINDINGS

**F1 — blocker — `src/cli/link.rs:152 cmd_resolve` (`codegraph impact cmd_resolve`).** COMMON.md and U1 both claim `resolve` archives the old row with `archive_reason='superseded'`. It does not: it writes a `supersedes` link, `db::update(.., Some(1), Some(0.1), ..)` demotes the loser to priority 1 / confidence 0.1, and `db::touch` extends the winner's TTL. The loser stays in `memories` and stays recallable. It is also `refuse_pg_store(db_path, "resolve", out)` — sqlite-ONLY (#2572), absent on Postgres.
*Amendment:* stop describing U1 as "existing `resolve` semantics". The real precedent is append-and-archive in `src/mcp/tools/update.rs` / `src/storage/mod.rs:4325+` (`EditSource::Llm|Hook`, `field_names::SUPERSEDED_ID`, `emit_upsert_supersede_leaf_if_enabled:1724`). Add a sub-task: either make `resolve` archive, or state in CLI_REFERENCE that it is a demote-not-archive verb. Two verbs named "supersede" with different durability IS the drift this issue exists to stop.

**F2 — blocker — four write funnels, not "the store path"** (`codegraph explore "handle_store create_memory cli store insert"`). `src/mcp/tools/store/mod.rs` (MCP); `src/handlers/create.rs` (HTTP — its own comments say it *mirrors* `handle_store`, it does not call it); `src/cli/store.rs` + `src/cli/post_store.rs` (CLI — #3402 exists precisely because the CLI called `db::insert` and stopped); SAL `MemoryStore::store` (src/store/mod.rs:1276) for Postgres. U1 phrases this as one edit; it is four, and #3402 is the proof that a mirrored funnel drifts.
*Amendment:* land ONE funnel beneath all four (`storage::supersede_by_ruling_key`, inside the same `BEGIN IMMEDIATE` as the insert, plus a `PostgresStore` twin), and add a `parity_write_funnels.rs`-style test asserting all four surfaces emit a byte-identical `superseded` field. Never per-surface.

**F3 — blocker — `db::insert` ON CONFLICT(title, namespace) collides with `ruling_key`** (src/storage/mod.rs:2087, `DO UPDATE` arm). A Conductor re-stating a ruling under the same title in the same namespace UPSERTS the existing row: `actual_id == old id`, so U1's `superseded: <old id>` names the row just overwritten, with no archived pre-state. An in-place mutation reported as a supersession — a data-integrity inversion.
*Amendment:* the ruling_key path must resolve the conflict arm FIRST — a live `(namespace, ruling_key)` match forces the mint-new-id path (`insert_no_overwrite` / `ConflictMode`) so the old row can be archived intact.

**F4 — major — `ruling_key` is erasable by a routine metadata patch** (`src/identity/mod.rs:1036 preserve_update_provenance_keys`). `memory_update --metadata` / `PUT /memories/{id}` is a whole-blob REPLACE; only `UPDATE_PRESERVED_ATTESTATION_KEYS` + `preserve_provenance_keys` survive. One ordinary patch silently un-rulings a ruling and the next store stops superseding — "old facts left standing", reintroduced through the back door.
*Amendment:* add `field_names::RULING_KEY` to the preserved set and define it as a const in `src/models/field_names.rs` (`check-hardcoded-literals.sh` / `check-const-name-literals.sh` will hard-block a bare `"ruling_key"` once it appears on enough production sites).

**F5 — blocker — U2's DB-persisted cursor is an undeclared schema migration.** `src/recover/watcher.rs:413 poll_once_with_resolver` keeps state in an in-memory `HashMap<HostKind, HostPollState>`; no cursor table exists. `CURRENT_SCHEMA_VERSION = 98` in TWO places (`src/storage/migrations.rs:995`, `src/store/postgres.rs:2013`); ladders end at `0082_v98_*.sql` / `0055_v98_*.sql`. U2 mentions no migration, no version bump, no `MIGRATION_LADDER` tail (ARCH-8, `src/storage/migration_meta.rs:609`), no downgrade/poison guards, no `check-docs-vs-ssot.sh` "schema v98" doc sweep.
*Amendment:* either declare v99 + both ladder files + both const bumps + doc sweep as explicit U2 scope (roughly doubles it), or drop persistence and ship `--host file:` `--once`-only with an in-memory cursor. In GA week: the second.

**F6 — blocker — `HostKind` cannot carry a path** (`codegraph impact HostKind` — 41 affected symbols across 6 files). `HostKind` (src/recover/transcript_paths.rs:18) is a fieldless `Copy` enum: `poll_once_with_resolver` does `for &host in &cfg.hosts`, `states: HashMap<HostKind, HostPollState>` needs `Hash + Eq`, and `HostTickOutcome { host: HostKind }` derives `Serialize/Deserialize/Default` — so it is part of the `watch --json` WIRE SHAPE. A `File(PathBuf)` variant drops `Copy` (rust-1.98 API-06 / OWN-03: never silently remove a `Copy` bound from a published type), forces `as_str() -> &'static str` to allocate, and changes the JSON payload for every existing host.
*Amendment:* do NOT extend `HostKind`. Add `WatchConfig.files: Vec<PathBuf>` and a `WatchSource { Host(HostKind), File(PathBuf) }` at the outcome layer only, keeping `HostKind` byte-identical.

**F7 — major — the byte cursor is unsafe on rotate/truncate (fail-closed violation).** A bare offset re-read after rotation (new file, same path, offset < len) yields a MID-LINE read → a corrupt memory; after truncation (offset > len) it skips or errors. The proposal mentions only "partial-line safety".
*Amendment:* cursor = `(dev, ino, len, mtime, offset)`, reset to 0 when ino changes or `len < offset`; a partial trailing line is never consumed until newline-terminated.

**F8 — major — U3 must not use `handle_notify`** (`codegraph callers handle_notify_as_sender`). `src/mcp/tools/notify.rs:handle_notify` returns `Result<Value, String>` — a QUAL-6 legacy row, ceiling 132, no bumps — and resolves the sender from `mcp_client` / ambient identity. The curator is not an MCP client. `handle_notify_as_sender(..., sender: &str) -> Result<Value, MemoryError>` is the #3579 explicit-principal funnel.
*Amendment:* call `handle_notify_as_sender` with the curator's resolved agent id. Add a DENIED test that `notify_agent_id` is a RECIPIENT only and can never be adopted as the sender (self-asserted-principal class, #3578/#3581 lineage).

**F9 — major — U3 re-opens the #3345 curator-report bloat regression.** `CuratorReport` (src/curator/mod.rs:207) is serialised into a durable `_curator/reports` memory; `tests/curator_report_bloat_3345.rs` + `_pg.rs` exist because that row grew without bound. "every memory tagged `ruling` … is reported (JSON)" inlines an unbounded list.
*Amendment:* the persisted report carries counts + a capped top-N id list (named const, M-DOCUMENTED-MAGIC); the full list goes to stdout under `--json` only. New fields `#[serde(default)]`, matching the struct's existing convention, so old reports still deserialise.

**F10 — major — U4's flag shape contradicts the existing extension point** (`src/cli/install.rs:186-215`). `TargetArgs` already has `--hook <KIND>` with `enum HookKind { Pretool }`, whose doc says verbatim "future variants (e.g. `PostToolUse`, `Stop`) plug into the same dispatch shape". A new `--capture-hook` bool is a second parallel mechanism — and because `TargetArgs` is SHARED by all ten `TargetCmd` variants it would silently appear on `install cursor`, `install cline`, etc.
*Amendment:* `--hook capture` (add `HookKind::Capture`), reusing the existing `if t_args.hook.is_some() && target != Target::ClaudeCode { bail!(…) }` guard.

**F11 — major — `install codex --capture-hook` collides with a pinned refusal.** `tests/cli_install_pretool_hook.rs:305` asserts the literal `"only supported for \`claude-code\`"`, and `TargetCmd::Codex` already exists as an *MCP-server* install target — so the same flag would mean two different things.
*Amendment:* drop the Codex leg from v1.0.0 (U4 already hedges it). Document the Codex `notify` equivalent in prose. Re-pin the refusal test unchanged.

**F12 — blocker for U5's own claim — three QUAL-10 ceilings bind. Measured on this tree:** `src/storage/mod.rs` 33,848 / **34,000** (152 headroom) — U1's funnel + U2's cursor land here; `src/config.rs` 15,028 / **15,120** (92 headroom) — `[autonomy]` is a NEW section (today `autonomous_hooks` is a flat top-level `AppConfig` field at src/config.rs:3219; there is no `[autonomy]` table) plus two `[curator]` fields, and this repo writes 20–40-line doc comments per config field; `src/cli/install.rs` 3,558 / **3,600** (42 headroom) — U4 cannot fit.
*Amendment:* U5 must read "QUAL-6 stays 132 (no new `Result<Value,String>`); QUAL-10 ceilings bumped in lockstep with a dated rationale comment in the same PR" — the documented convention. As written ("QUAL ceilings unchanged … no bumps") the first unit to land reds CI.

**F13 — major — the new config keys: section, defaults, env policy.** No `[autonomy]` table exists; adding one touches `AppConfig`, `docs/CONFIG_SCHEMA.md`, `docs/CONFIGURATION.md`, `deploy/reference-configs/*` (pinned by `tests/ec1_reference_configs_resolve.rs`) and `src/config_redact.rs`. Per the GA rule "no new env knobs without a ruling", all three keys ship **config-file-only** — no `AI_MEMORY_SUPERSEDE_ON_CONTRADICTION`, `AI_MEMORY_CURATOR_STALE_RULING_DAYS`, `AI_MEMORY_CURATOR_NOTIFY_AGENT_ID`. Note this makes them the FIRST curator knobs without env overrides (`AI_MEMORY_CURATOR_INTERVAL_SECS`/`_MAX_OPS`/`_DRY_RUN` are documented in `packaging/systemd/ai-memory-curator.service`); tell the operator explicitly rather than letting them find out in production.
*Amendment:* defaults `supersede_on_contradiction = false`, `stale_ruling_days = 14` (named const, not a literal), `notify_agent_id = None`.

**F14 — major — U6 adds a second writer to DBs that already have one.** `watch --daemon` opens its own `rusqlite::Connection`; every capture takes `BEGIN IMMEDIATE` (src/storage/mod.rs:1982, 2013). On f2 the Conductor DB is already held by a live MCP stdio server. The watcher already carries the #2134/#2150 bounded-retry machinery for exactly this — `WATCH_RECOVERY_MAX_RETRIES = 3`, whose doc names `SQLITE_BUSY` on the per-turn `BEGIN IMMEDIATE` — so the worst case is a dropped capture after 3 retries, not corruption: degrade-not-corrupt holds. But U6 never says so, and an operator watching `errors_total` climb has no documented remedy.
*Amendment:* U6 states the posture (WAL + bounded retry; capture may defer a tick under contention) and the runbook names `errors_total` / `changes_detected` as the two gauges.

**F15 — major — U6 has no daemon lifecycle.** `packaging/systemd/` ships `ai-memory{,-curator,-sync,-backup,-wake-hub{,-refresh}}.service` — there is NO watch unit. "under the Conductor's own pid" means no `Restart=on-failure`, no `RestartSec`, no `KillSignal=SIGINT` (the watcher's documented clean-shutdown signal), stdout wherever the parent's went, and death with the Conductor session; f1 adds a second unsupervised process.
*Amendment:* add `packaging/systemd/ai-memory-watch.service` modelled on `ai-memory-curator.service` (`Type=simple`, `After/Wants=ai-memory.service`, `Restart=on-failure`, `RestartSec=5s`, `KillSignal=SIGINT`, `TimeoutStopSec=90`) plus a launchd plist for the f2 macOS host matching `ops/com.alphaone.claude-campaign.plist`. Logs resolve via `AI_MEMORY_LOG_DIR` / `${XDG_STATE_HOME}/ai-memory/logs/` (src/log_paths.rs) — name that path in the runbook. **What the operator sees on failure:** a locked DB → `errors_total` rises, `memories_captured` flat; a rotated/truncated file → today, silence (F7 fixes that into a cursor reset + a counted event).

**F16 — minor — `src/cli/json_contract.rs::json_support` is an exhaustive `match` over `daemon_runtime::Command` with NO `_` arm** ("a new subcommand does not compile until somebody decides what `--json` means for it"). U4's `CaptureTurn` must be classified `JsonSupport::Global`.

**F17 — minor — U2's tag vocabulary (`READY|STATUS|BLOCKER|ACK|NOTE|MASTER→…`) is six hardcoded literals** across parse + tag + test sites; `check-hardcoded-literals.sh` is a ratchet whose baseline can only shrink, so it hard-blocks. One `const SWARM_LINE_TAGS: &[&str]`, the way `HostKind::as_str` is already the SSOT `parse_host` reads (src/cli/watch.rs:71) rather than a second literal copy.

## 2b. MCP / HTTP / CLI PARITY CONTRACT — required twin per new surface

| New surface | Required twin | Parity artefacts that change |
|---|---|---|
| `metadata.ruling_key` + `superseded` response field (U1) | none new — rides `memory_store` / `POST /api/v1/memories` / `ai-memory store` | `tests/mcp_schema_handler_parity.rs`, `mcp_handler_params_subset_of_schema.rs`, `mcp_schema_drift_912.rs`. `tools_list` snapshots (`tests/snapshots/tools_list_{core,full,power,graph,admin}.json`) ONLY if `memory_store`'s description/schema moves. `ruling_key` lives INSIDE `metadata`, so **no** `ALL_PARAM_NAMES` entry and **no** `tests/mcp_param_names_invariant.rs` change — keep it that way, it is the cheap path. |
| `[autonomy] supersede_on_contradiction` (U1) | config only | `docs/CONFIG_SCHEMA.md`, `docs/CONFIGURATION.md`, `deploy/reference-configs/*` + `tests/ec1_reference_configs_resolve.rs`, `src/config_redact.rs`. |
| `watch --host file:` (U2) | CLI-only (precedent: `recover-previous-session`, which CLI_REFERENCE explicitly documents as having no MCP counterpart) | `docs/CLI_REFERENCE.md` §`watch` flag table; `WatchReport`/`HostTickOutcome` `--json` shape; `tests/watch_notify_1978.rs`. |
| `curator --stale-rulings` (U3) | CLI-only, consistent with the rest of `curator` | `docs/CLI_REFERENCE.md`; `CuratorReport` JSON; `tests/curator_report_bloat_3345{,_pg}.rs`. |
| `ai-memory capture-turn` (U4) | MCP `memory_capture_turn` + HTTP `POST /api/v1/capture_turn` (both exist) — closes the last leg of an existing 2-of-3 | `docs/CLI_REFERENCE.md` §"FX-12 / FX-C3 MCP↔CLI parity subcommands" — add a `capture-turn` \| `memory_capture_turn` row; `EXPECTED_CLI_SUBCOMMANDS_DEFAULT` 95→96 and `_SAL` 97→98 (`src/lib.rs:536,563`) + `tests/cli_subcommand_count_invariant.rs`; `check-docs-vs-ssot.sh` "<N> CLI subcommands" doc claims; `check-doc-surface-completeness.sh` CLI rule (every non-hidden `Command` variant must appear in CLI_REFERENCE); `src/cli/json_contract.rs`. |
| `install claude-code --hook capture` (U4) | none (installer) | `tests/cli_install_pretool_hook.rs` — add a `capture` sibling; re-pin the `--help` assertion at :465 and the non-claude-code refusal at :305. |

**Do tools/list descriptions change? NO for U1–U6 as scoped** — no new MCP tool, no new advertised param. So `FULL_PROFILE_TOKEN_CEILING = 8_110` (tests/budget_tokens.rs:133) and `EXPECTED_PRODUCTION_ROUTES_COUNT` both stay put. **Treat that as a constraint, not an observation:** if any unit adds an advertised param or edits a tool description, it must run `cargo test --test budget_tokens -- --ignored` (the ceiling comment records that CI runs the `#[ignore]`d test explicitly, and that a lane missed it once) and re-bless all five profile snapshots.

## 3. BLAST RADIUS (rule (e) — old-contract pins across src/ AND tests/)

- **U1** — `src/storage/mod.rs::{insert, insert_with_conflict, ON CONFLICT arm :2087, emit_upsert_supersede_leaf_if_enabled:1724}`; `src/mcp/tools/store/mod.rs`; `src/handlers/create.rs`; `src/cli/{store,post_store}.rs`; `src/store/postgres.rs::store`; `src/identity/mod.rs::preserve_update_provenance_keys`; `src/models/field_names.rs`. Pins: `tests/append_only_upsert_supersede_2948.rs`, `append_only_spine_flagon_g6.rs`, `store_parity_gaps.rs`, `parity_write_funnels.rs`, `detect_contradiction_3387.rs`, `archive_on_gc_config_3385.rs`, `qual_pg_write_funnel_parity_2393_2397.rs`, `postgres_schema_parity.rs`; `src/autonomy.rs::forget_if_superseded` + its 6 in-file tests.
- **U2** — `codegraph impact HostKind` → 41 symbols / 6 files: `src/recover/{transcript_paths,mod,watcher}.rs`, `src/cli/watch.rs::{parse_host,build_config}`, `src/cli/commands/recover_previous_session.rs::parse_host_kind`, `src/logging.rs`, `src/subscriptions.rs`. Pins: `tests/watch_notify_1978.rs`; `watcher.rs::{default_watch_hosts_excludes_auto, watch_report_absorb_tick_accumulates_counters, absorb_tick_surfaces_embedded_recover_errors_2136, exhaustion_warning_names_stranded_count_and_remediation_2150}`. If persistence lands, add `src/storage/migrations.rs:995`, `src/store/postgres.rs:2013`, `src/storage/migration_meta.rs:609`, `tests/{postgres_schema_parity, schema_downgrade_guard_2445, postgres_schema_downgrade_guard_2445, schema_version_poison_guard_2555, postgres_schema_version_poison_guard_2555, s75_capabilities_db_schema_version, wt_1_a_schema_migration, migration_ladder_integrity}.rs`.
- **U3** — `src/curator/mod.rs::{CuratorReport, run_cycle}`, `src/cli/curator.rs::CuratorArgs` (its `conflicts_with_all` sets must gain `stale_rulings`), `src/mcp/tools/notify.rs`. Pins: `tests/curator_report_bloat_3345{,_pg}.rs`, `cov_curator_store_backed_3521.rs`, `curator_conserves_contradiction_g7.rs`, `curator.rs`, `tests/curator/`.
- **U4** — `src/daemon_runtime.rs::{Command, run}`, `src/cli/json_contract.rs`, `src/cli/install.rs::{TargetArgs, HookKind, run}`, `src/lib.rs:536,563`. Pins: `tests/cli_subcommand_count_invariant.rs`, `cli_install_pretool_hook.rs`, `http_capture_turn_k9_3225.rs`, `capture_turn_security_integrity.rs`, `http_capture_attestation_3406.rs`, `capture_layers_perf_budget.rs::l4_capture_turn_p95_under_budget`, `qual_pg_write_funnel_parity_2393_2397.rs:81`.
- **U5** — `tests/qual_10_module_size_ceiling.rs` (3 rows), `tests/doc_claims_integrity.rs`, `scripts/check-{docs-vs-ssot,doc-surface-completeness,doc-symbol-anchors,hardcoded-literals,const-name-literals}.sh`, `changelog.d/`.

**Suites pinning the CURRENT contract of the named surfaces (rule (e) census):** `resolve` → `src/cli/link.rs` `test_resolve_*` (9 in-file tests) + `daemon_runtime.rs:10018,11987` dispatch pins. `autonomous_hooks` → `src/config.rs:9145-9151` precedence + `:11509,11519` env cleanup, `src/mcp/tools/store/legacy_classifier.rs`, `tests/detect_contradiction_3387.rs`, `tests/auto_tag_envelope_3381.rs`, `src/background/auto_tag_worker.rs:81`. `watch` → `tests/watch_notify_1978.rs` + the watcher in-file tests above. `curator` → `tests/curator.rs`, `tests/curator/`, `curator_report_bloat_3345{,_pg}.rs`, `cov_curator_store_backed_3521.rs`, `confidence_source_curator_derived_1242.rs`. `install` → `tests/cli_install_pretool_hook.rs` (sole file).

## 4. TEST PLAN GAPS — DENIED/ALLOWED pairs the proposal is missing
Convention `<behaviour>_<issue>`; every store-path pair needs a `_pg` twin (`#[ignore]`d live-pg leg).

**U1** (has cross-agent / cross-namespace / higher-priority / admin; missing:)
- DENIED `same_title_ruling_key_does_not_inplace_upsert_3587` (+`_pg`) — F3.
- DENIED `metadata_patch_cannot_erase_ruling_key_3587` (+`_pg`) — F4.
- DENIED `ruling_key_supersede_refuses_when_old_row_already_archived_3587` — a second identical store must be a no-op, never a double-archive.
- DENIED `ruling_key_supersede_refuses_across_agents_under_admin_header_untrusted_3587` — the admin carve-out keys off the authenticated principal, never a request-body `agent_id`.
- DENIED `equal_priority_is_not_higher_priority_3587` — pin `>` vs `>=`; an off-by-one here silently drops rulings.
- DENIED `ruling_key_empty_or_oversized_refused_3587` — validation before any write.
- ALLOWED `ruling_key_supersede_archives_old_and_links_new_3587` (+`_pg`) — old row ABSENT from `memories`, PRESENT in `archived_memories` with `archive_reason='superseded'`, `supersedes` link new→old.
- ALLOWED `ruling_key_supersede_identical_on_mcp_http_cli_3587` — F2, one assertion over three envelopes.
- ALLOWED `superseded_row_is_not_returned_by_recall_3587` (+`_pg`) — the actual drift property.
- ALLOWED `supersede_on_contradiction_false_links_only_3587` / DENIED `supersede_on_contradiction_true_archives_only_same_author_3587` — the knob's two arms.
- ALLOWED `ruling_key_supersede_emits_audit_event_3587` — the issue asks for it with no shape; pin the event name and that it lands on the append-only spine.

**U2**
- DENIED `watch_file_cursor_resets_on_inode_change_3587`, `watch_file_cursor_refuses_shrunk_file_3587`, `watch_file_holds_partial_trailing_line_3587` — F7.
- DENIED `watch_file_host_refuses_path_outside_allowed_roots_3587` — the proposal has NO path containment; `--host file:/etc/shadow` must refuse (compare the `skill export` jail, #3357).
- DENIED `watch_file_host_refuses_symlink_escape_3587`; DENIED `watch_file_host_refuses_binary_or_oversized_line_3587`.
- ALLOWED `watch_file_dry_run_writes_nothing_3587`, `watch_file_limit_bounds_lines_per_tick_3587`, `watch_file_tag_extraction_is_ssot_driven_3587` (F17).

**U3**
- DENIED `stale_ruling_sweep_writes_nothing_to_the_rulings_3587` (+`_pg`) — the unit's core claim, asserted by row-hash before/after, not by absence of an error.
- DENIED `stale_ruling_digest_not_sent_when_notify_agent_id_unset_3587`.
- DENIED `stale_ruling_notify_sender_is_the_curator_not_the_config_value_3587` — F8.
- DENIED `stale_ruling_report_list_is_capped_3587` — F9.
- ALLOWED `stale_ruling_digest_sent_once_per_sweep_3587` — exactly ONE inbox row for N stale rulings, and none on a second sweep inside the window.
- ALLOWED `ruling_with_verified_link_is_not_stale_3587` / `ruling_with_superseded_by_link_is_not_stale_3587`.

**U4**
- DENIED `capture_turn_cli_refuses_empty_stdin_3587`; DENIED `install_capture_hook_rejected_on_non_claude_code_3587` (F11).
- ALLOWED `capture_turn_cli_envelope_matches_mcp_tool_3587` — byte-equal, the acceptance criterion.
- ALLOWED `install_capture_hook_is_idempotent_3587` — apply twice, one managed block, byte-identical file.
- ALLOWED `install_capture_hook_uninstall_leaves_operator_hooks_3587` — the installer deliberately APPENDS to a pre-existing array; uninstall must not eat operator entries.

## 5. EFFORT + ORDERING (deputy-days)

| Unit | My estimate | vs issue's implied scope |
|---|---|---|
| U1 | **4.0** | reads as ~2; F2 (four funnels + pg twin) and F3 (upsert collision) are the cost |
| U2 | **1.0** as `--once`/in-memory/jailed — **4.5** as specified with v99 persistence | reads as ~1.5 |
| U3 | **1.5** | matches |
| U4 | **2.0** Claude-Code-only (3.5 with the Codex leg, which I would cut) | reads as ~1.5 |
| U5 | **1.0** | reads as ~0.5; three ceiling bumps + two subcommand-count SSOTs are real work |
| U6 | **1.0** | reads as ~0.25; unit file + runbook + two-DB reconciliation are unbudgeted |

**Ordering — each unit independently shippable and green alone:**
1. **U5a first, not last.** Split U5: land the CHANGELOG/doc scaffolding plus the three QUAL-10 ceiling bumps and the `field_names::RULING_KEY` const as a standalone no-behaviour PR. Every later unit then lands without a ceiling fight, and the bumps get reviewed on their own merits.
2. **U4** — purely additive parity, no store semantics, closes an existing 2-of-3 gap; gives U6 its Stop hook early (the only lever that makes a stopped agent write again).
3. **U1** — the load-bearing unit. Do not start before U5a.
4. **U2** in its reduced `--once` form — independent of everything above.
5. **U3** — needs U1's `ruling_key` for its second predicate; wire it to ship on the `ruling` TAG alone so a U1 slip does not block it.
6. **U5b** (CLI_REFERENCE / CONFIG_SCHEMA / doc-claims reconciliation) and **U6** together, last. U6 must not merge without F15's systemd/launchd unit and a runbook paragraph naming the f1/f2 two-database boundary from gap (b).

AUDIT C DONE
