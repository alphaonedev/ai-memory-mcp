# Audit B — ARCHITECTURE & BLAST-RADIUS lens on #3587 (codegraph-driven)

Repo: <tree> @ 6082af8a9 (release/v1.0.0). Read-only; no cargo run.
Tooling: `codegraph explore` / `codegraph impact` 1.6.0 first, grep only for literals.

## 1. VERDICT per unit

| Unit | Verdict | One-line reason |
|---|---|---|
| U1 store supersession | **SHIP-WITH-CHANGES** | The spec is self-contradictory: you cannot archive the old row *and* write a `supersedes` link to it — the `memory_links.target_id` FK references `memories(id)` and the archived row has left that table (documented at `src/storage/mod.rs:4243`, blocked on #895). Must use the existing `metadata.superseded_id` forward pointer. |
| U2 watch line-file host | **SHIP-WITH-CHANGES** | Sound idea, wrong seams: it must NOT extend `HostKind`, must NOT add a byte-cursor table, and must NOT take `agent_id` from the file's own bytes. |
| U3 curator stale-ruling sweep | **SHIP-WITH-CHANGES** | The "no `supersedes`/`superseded_by` link" staleness criterion cannot ever be satisfied (see U1) ⇒ every ruling reports stale forever, i.e. a daily digest storm at `ai:fable`. Also must be placed before the no-LLM early return. |
| U4 capture-turn CLI + install hook | **SHIP-WITH-CHANGES** | `--capture-hook` should be `--hook stop` on the already-built extension point; the Stop payload carries no `host_turn_index`, so the L4 idempotency key cannot be populated as specified; install.rs has 42 LOC of QUAL-10 headroom. |
| U5 docs + SSOT | **SHIP-WITH-CHANGES** | "QUAL ceilings unchanged" is false: `EXPECTED_CLI_SUBCOMMANDS_DEFAULT/_SAL` (95/97) and the `src/cli/install.rs` QUAL-10 ceiling (3_600 vs actual 3_558) both move. |
| U6 operator wiring | **DO-NOT-SHIP-IN-v1.0.0 as written** | `ai-memory watch` has NO Postgres path and does NOT call `refuse_pg_store`; pointing it at a Postgres-backed hive silently writes deputy outbox lines into a conjured local sqlite file — unintentional data loss, the exact class #2572 exists to prevent. |

## 2. FINDINGS

### F1 (blocker) — U1: "archive the old row + write a `supersedes` link" is structurally impossible
`src/storage/mod.rs:4203-4270 update_with_archive_on_supersede` / `SupersedeResult`. Verbatim:
> "A `memory_links` `supersedes` edge is **NOT** written because the FK `target_id REFERENCES memories(id)` would reject it (the archived row no longer lives in the live `memories` table). See #895…"

The proposal asks for both. Worse, COMMON.md's "product fact" that `ai-memory resolve` archives with `archive_reason='superseded'` is **wrong**: `src/cli/link.rs:152 cmd_resolve` creates a `Supersedes` link, then **demotes** the loser (`priority=1, confidence=0.1`) and touches the winner's TTL — the loser stays **live**. Two incompatible supersession semantics exist; U1 conflates them.
**Amendment:** pick ONE. Recommended: reuse `update_with_archive_on_supersede`'s contract — archive old + `metadata.superseded_id` on the new row + `archive_reason='superseded'`; drop the link requirement and say so in the issue. Then U3's staleness predicate keys off `metadata.superseded_id` / archive state, not links.
`codegraph`: `codegraph impact handle_store` (73 symbols); grep for `archive_reason='superseded'`.

### F2 (blocker) — U1: `resolve` refuses on Postgres, so "existing resolve semantics" cannot be twin-tested
`src/cli/link.rs:159` → `crate::cli::backup::refuse_pg_store(db_path, "resolve", out)` (#2572). Every local CLI write verb (`store/update/delete/link/resolve/forget/archive/consolidate`) refuses a Postgres store. If U1 lands in the shared store funnel (`storage::insert` + `PostgresStore` twin) it is fine; if it is built on the `resolve` helper it is sqlite-only and the "SQLite + Postgres twin tests" line is unachievable.
**Amendment:** state explicitly that supersession lands in the **store funnel** (`src/storage/mod.rs` + `src/store/postgres.rs` twin), not on the `resolve` verb.

### F3 (blocker) — U2: `agent_id` from "the line's actor prefix" is a self-asserted-authorship hole
Proposal: "`agent_id` from the line's actor prefix when present". The L2/L3 recovery write path runs under `CallerContext::for_admin(&opts.agent_id)` (`src/recover/mod.rs:511`, C8-allowlisted in `scripts/qc-codegraph-allowlists/for-admin-bypass.txt`). A transcript is the operator's own local agent output; a **deputy outbox/inbox** is written by *other* processes, possibly over a shared mount. Letting file bytes choose `agent_id` under an admin-bypass context means anything that can append one line mints memories attributed to any agent — the GA authority boundary (#3578/#3581) forbids exactly this (key off the authenticated principal, never a self-asserted field).
**Amendment:** the memory's `agent_id` is ALWAYS the resolved `--agent-id` of the watch process. The parsed actor prefix goes in `metadata.observed_actor` (untrusted, clearly labelled) and/or a tag. Add the new write path to the C8 allowlist with a reviewed rationale, or (better) run it under the watcher's own principal without `bypass_visibility`.

### F4 (blocker) — U2: do NOT add a `File(PathBuf)` variant to `HostKind`
`src/recover/transcript_paths.rs:16-48`: `#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)] #[serde(rename_all="kebab-case")] enum HostKind`, with `as_str(self) -> &'static str`. A payload-carrying variant:
- kills `Copy` → breaks `for &host in &cfg.hosts`, `states.entry(host)`, `HostTickOutcome{host}` (`src/recover/watcher.rs:394-628`);
- kills `as_str() -> &'static str` — the documented SSOT for the host-tag vocabulary that `src/cli/watch.rs:71 parse_host` and the vendor-literal carve-out depend on;
- changes the **JSON wire shape** of `WatchReport`/`HostTickOutcome`/`RecoverReport` (`"claude-code"` → `{"file":"…"}`), an `--json` contract break;
- forces new arms in `resolve_transcript`, `watch_dirs` (`transcript_paths.rs:174`), `recover_previous_session.rs:238 parse_host_kind`.
`codegraph impact HostKind` → **41 symbols across 6 files + `tests/watch_notify_1978.rs`**.
**Amendment:** introduce a watcher-layer `enum WatchTarget { Transcript(HostKind), LineFile(PathBuf) }` (or a `trait WatchSource`) in `src/recover/watcher.rs`. `HostKind` stays byte-identical. `WatchConfig.hosts: Vec<HostKind>` becomes `targets: Vec<WatchTarget>` — that is a 27-symbol blast radius (below), all local.

### F5 (major) — U2: "per-file byte cursor persisted in the DB" is the wrong idempotency primitive and costs a schema bump
The watcher has **no persisted cursor today**. `HostPollState` (`watcher.rs:152-180`) is an in-memory `(path, mtime, len)` watermark rebuilt each start; restart-safety comes from the **content-hash** table `transcript_line_dedup` (`migrations/sqlite/0044_v52…`, PK `sha256`, `host_kind TEXT NOT NULL` free-form, no CHECK). A byte cursor is actively dangerous for deputy outboxes: on truncation/rotation (logrotate on an outbox is normal) a stale cursor silently skips every line before it — unintentional data loss, North-Star violation. It also forces `CURRENT_SCHEMA_VERSION` 98 → 99 on **both** backends (`src/storage/migrations.rs:995`, `src/store/postgres.rs:2013`), a new `migrations/sqlite/0083_*`, `tests/postgres_schema_parity.rs`, `tests/store_parity_gaps.rs`, and every "schema v98" doc claim via `scripts/check-docs-vs-ssot.sh`.
**Amendment:** reuse `transcript_line_dedup` with `host_kind = "file"` and `transcript_path = <abs path>`; sha256 over the verbatim line bytes. Zero schema change, restart-safe, rotation-safe, truncation-safe, and byte-identical idempotency to the transcript hosts. Keep `(mtime, len)` in memory purely as the cheap change detector. Update the 0044 migration's doc comment (it enumerates the host_kind vocabulary as claude-code/codex/gemini/auto) — that is a doc-claim.

### F6 (major) — U2: the line-file host must not reuse the transcript pipeline, and must not inherit its retry state machine
`poll_once_with_resolver` funnels everything into `recover_from_transcript` with `bypass_fast_path: true` (`watcher.rs:485-500`), which runs the **host JSONL parser table** (`recover/parsers`). A plain line file has no `ParsedTurn`, no `host_session_id`, no `host_turn_index`. What MUST be shared: `transcript_line_dedup`, the per-tick `--limit`, `--dry-run` (never arm `pending_drain`/retry in dry-run — `watcher.rs:596` and `#2126` case (b)), the per-target error isolation, `absorb_tick` counters. What MUST NOT be shared: the parser table, `RecoverOpts.transcript_override`/watermark fast-path, `HostPollState.retry_attempts` semantics (a line file that fails a write is retried by re-hashing the same line, which dedup already makes idempotent — do not re-implement `WATCH_RECOVERY_MAX_RETRIES`), and `watch_dirs` (fs-notify): if `--host file:` is to work under `--features fs-notify`, `run_watch_daemon_notify` must watch the file's **parent dir**, or the feature leg must explicitly fall back to polling for line-file targets. The proposal is silent on fs-notify.

### F7 (blocker) — U6/U2: `watch` has no Postgres path and no `refuse_pg_store` guard
`src/cli/watch.rs:158 run` → `watcher::poll_once(db_path, …)` → `recover_from_transcript(db_path, &opts)` — **sqlite only**. A SAL twin exists (`src/recover/mod.rs:493 recover_from_transcript_store`, `#[cfg(feature="sal")]`, #1693) but the watcher never calls it, and unlike every other local write verb `watch` never calls `refuse_pg_store`. U6 wires `watch --daemon --host file:` "into the f1 hive"; if that hive is Postgres-backed, every deputy line lands in a phantom local sqlite and is silently lost.
**Amendment (pick one, in the same PR as U2):** (a) add `refuse_pg_store(db_path, "watch", out)` so it fails closed and loudly, or (b) route the watcher through `recover_from_transcript_store` under `--features sal`. (a) is the v1.0.0-sized fix; (b) is the correct one. Either way U6 is blocked until this lands.

### F8 (blocker) — U4: the Stop payload has no `host_turn_index`, so the L4 dedup key cannot be filled
Authoritative Claude Code Stop-hook stdin (docs `hooks.md`, v2.1.196+): `session_id`, `prompt_id`, `transcript_path`, `cwd`, `scratchpad_dir`, `permission_mode`, `hook_event_name:"Stop"`, `effort`, plus Stop-specific **`last_assistant_message`** (the full assistant text) and `stop_hook_active`. Good news: the text IS on stdin — the hook must NOT parse `transcript_path` (Claude Code documents that JSONL entry format as internal and version-unstable). Bad news: `MemoryCaptureTurnRequest` requires `host_session_id: String` **and** `host_turn_index: i64` (`src/mcp/tools/capture_turn.rs:108-120`), and the payload provides no index — only an opaque `prompt_id` UUID.
**Amendment:** add an explicit derivation inside the existing `BEGIN IMMEDIATE` transaction (`storage::capture_turn_idempotent`): when the CLI passes `--host-turn-index auto`, resolve `COALESCE(MAX(host_turn_index),-1)+1 FOR host_session_id` *inside* the transaction so it is race-free, and dedup on the sha256 content hash as the second guard. Do not let the CLI compute it out of band (two Stop hooks in two panes on the same session id would collide and one turn would be swallowed as a dedup hit).

### F9 (major) — U4: `--capture-hook` should be `--hook stop`; the extension point already exists
`src/cli/install.rs:1234-1237` verbatim: *"Apply the requested hook variant. Today only `--hook pretool` for claude-code is wired; the dispatch is split out so future hook kinds (PostToolUse, **Stop**) plug in without touching `run`."* `TargetArgs.hook: Option<HookKind>` (install.rs:184-192) and `enum HookKind { Pretool }` (install.rs:208) are the designed seam, and `run` (install.rs:322-338) already routes `apply_hook_block` / `remove_hook_block`. A new boolean `--capture-hook` would be a second, parallel flag vocabulary on a shared `TargetArgs` visible on every target.
**Amendment:** `HookKind::Stop` + `(Target::ClaudeCode, HookKind::Stop)` arms in `apply_hook_block`/`remove_hook_block`, mirroring `apply_claude_code_pretool`/`remove_claude_code_pretool`. Note the flag is **exclusive** with the default managed block (`if let Some(hook_kind) … else { apply_managed_block }`), so `install claude-code` and `install claude-code --hook stop` are two invocations — document that; it is the same as `--hook pretool` today.

### F10 (major) — U4: how settings.json is actually written (merge/idempotency/clobber answer)
`install::run` (install.rs:292-420): reads the whole file (`read_config_or_empty`, **errors** on malformed JSON rather than overwriting — good), computes an after-value from the parsed `before_value`, re-serialises with `serde_json::to_string_pretty`, **re-parses the output as a round-trip check**, no-ops if `before_text.trim()==after_text.trim()`, dry-run by default, and on `--apply` writes a timestamped `<config>.bak.<ts>` first. Per-array mutation is `arr.retain(|v| !is_managed_value(v))` then prepend (SessionStart) / append (PreToolUse) — **operator-authored hooks are preserved**, and each remover only touches its own event key. So: **yes, a Stop hook can be added without clobbering operator hooks**, provided the new remover follows the same `is_managed_value` retain shape.
Two caveats to write into the unit: (i) `serde_json` is declared without the `preserve_order` feature (`Cargo.toml:42`), so `Map` is a `BTreeMap` — **every `--apply` alphabetically reorders the operator's whole settings.json**. Existing behaviour, reversible via the `.bak`, but U6 runs it on the live Conductor box; call it out. (ii) The Stop event **does not support `matcher`**; the managed-entry builder always emits `"matcher"` + `MANAGED_KEYS_PROPERTY: ["matcher","hooks"]`. Emit `MANAGED_KEYS_PROPERTY: ["hooks"]` (and either omit `matcher` or write `""`) so uninstall removes exactly what was written.

### F11 (major) — U4: the Stop hook must be non-blocking and must never exit 2
Stop-hook exit semantics: `0` = proceed, **`2` = blocks the stop and forces Claude to continue**, other = non-blocking error; hook `timeout` defaults to 600 s; an `"async": true` field exists. A capture hook that shells out to `ai-memory capture-turn` and hits `SQLITE_BUSY` (very likely — U6 also runs `watch --daemon` holding the write lock on the same DB) would stall the operator's every turn for up to 600 s.
**Amendment:** write the entry with `"async": true`, give `capture-turn` a `--quiet` never-fail contract (always exit 0, like `boot --quiet`), and have the hook wrapper read `last_assistant_message` and no-op cleanly when the field is absent (Claude Code < 2.1.196) rather than storing an empty memory. Never emit a `decision` field.

### F12 (major) — U4: `capture-turn` must call `refuse_pg_store`
Every local CLI write verb does (`src/cli/{store,update,crud,link,forget,archive,consolidate}.rs`, #2572). `handle_capture_turn` takes a `&rusqlite::Connection` (capture_turn.rs:309) — the CLI twin is sqlite-only by construction, while the Postgres L4 path is `src/handlers/capture_turn.rs:75` (async, SAL). Without the guard, a Stop hook on a Postgres deployment silently captures into a conjured sqlite file.

### F13 (major) — U3: the sweep must sit before the no-LLM early return, and it inherits a sqlite-only curator
`src/curator/mod.rs:314 run_once(&Connection, Option<&OllamaClient>, &CuratorConfig, …)`. `run_size_gc_pass` (mod.rs:344) is the precedent: *"Pure SQL, LLM-free … Placed before the no-LLM early-return below precisely so byte-pressure eviction is NOT silently skipped on LLM-less deployments."* At mod.rs:346 an LLM-less run returns immediately. The f1/f2 hives are plausibly LLM-less ⇒ a stale-ruling sweep placed after that line never runs. Also `CuratorConfig` (mod.rs:172-201) has no `stale_ruling_days`/`notify_agent_id`; add them `#[serde(default)]` so existing config.toml files keep parsing (fail-open on config is correct here — the sweep is read-only).
**Amendment:** `run_stale_ruling_pass(conn, cfg, &mut report)` immediately after `run_size_gc_pass`; new `CuratorReport` fields must be `#[serde(default)]` (the report is a serialised wire shape consumed by `tests/curator_report_bloat_3345{,_pg}.rs`). `--stale-rulings` needs `conflicts_with_all` wiring alongside `--reflect`/`--rollback` in `CuratorArgs` (`src/cli/curator.rs:26-97`).

### F14 (minor) — U2/U4: literal-gate constraints
`scripts/check-vendor-literals.sh` allowlists 10 files + 2; **`src/cli/install.rs` and `src/cli/watch.rs` are NOT on it** — new `"claude-code"`/`"codex"` occurrences must be `const`s (const-definition lines are exempt), as `AGENT_TARGET_CLAUDE_CODE` already is. `scripts/check-hardcoded-literals.sh` is a ratchet: any string ≥ MIN_LEN appearing on ≥ threshold production sites over baseline hard-blocks — so the `"file:"` prefix, `"READY"/"BLOCKER"/"STATUS"/"ACK"/"NOTE"` tag vocabulary, and the `"capture-turn"` verb label must each be a single named const with one definition site. `scripts/check-l3-boundary.sh` bans `rqgm|epoch_manifest|red.?queen` anywhere in `src/` — no interaction expected, but do not name anything "red-queen".

## 3. BLAST RADIUS (callers + old-contract pins, src/ AND tests/)

**U2 — `codegraph impact WatchConfig` (27 symbols):**
- src/recover/watcher.rs: `WatchConfig::new:277`, `base_config:949`, `poll_once:394`, `poll_once_with_resolver:413`, `run_watch_daemon:674`, `run_watch_daemon_with_resolver:688`, `run_watch_daemon_notify:736`, `notify_backed_watch:785`, and the 9 in-file unit tests `no_transcript_is_unchanged_and_benign:983`, `poll_once_detects_new_transcript_then_skips_unchanged:1012`, `run_watch_daemon_stops_promptly_on_shutdown_signal:1199`, `pending_drain_tail_drains_even_after_watermark_advances_2126:1240`, `dry_run_oversized_transcript_does_not_busy_loop_2126:1307`, `..._2134:1349`, `..._2150:1434`, `..._2150_2126:1510`, `..._resets_on_fresh_delta_2150:1562`.
- src/cli/watch.rs: `build_config:90`, `run:158`, `run_watch_daemon_with_primitives:266`, test `daemon_primitives_bridge_returns_on_shutdown:451`.
- tests/watch_notify_1978.rs: `base_cfg:47`, `fs_event_triggers_recovery_tick:63`, `no_watchable_dir_reports_fallback:123`, `run_watch_daemon_falls_back_and_honors_preset_shutdown:153`.
- `codegraph impact HostKind` (41 symbols) is the radius you AVOID by not touching the enum — plus `src/recover/mod.rs` (`RecoverReport::new:115`, `recover_from_transcript:298`, `recover_from_transcript_store:493`, `RecoverOpts::for_session_start_hook:254`), `src/cli/commands/recover_previous_session.rs` (`parse_host_kind:238`, `build_opts:183`), `tests/{capture_layers_perf_budget,postgres_l2_rehydration_1693,recover_previous_session_after_sigkill}.rs`.
- Docs pin: `docs/CLI_REFERENCE.md:1381-1397` (the `watch` section, `--host` vocabulary).

**U4 — `codegraph impact handle_capture_turn` (27 symbols):** src/mcp/tools/capture_turn.rs (9 in-file tests incl. `handler_idempotent_on_same_session_turn:830`), `src/mcp/mod.rs:2813 dispatch_memory_capture_turn`, `tests/capture_turn_security_integrity.rs` (10 tests — the agent-id-agreement / signature / signed_events pins a CLI twin must not weaken), `tests/capture_layers_perf_budget.rs:493,592` (p95 budget), `tests/http_capture_turn_k9_3225.rs`, `tests/http_capture_attestation_3406.rs`.
**U4 — `codegraph impact is_managed_value` (15 symbols) / `apply_claude_code` (3):** `apply_hook_block:1240`, `remove_hook_block:1267`, `run:292`, plus every per-target remover. Test pins: `tests/cli_install_pretool_hook.rs` (14 fns — the black-box shape a Stop-hook suite must mirror), and the in-file `src/cli/install.rs` tests at :1629, :1677, :3135, :3297, :3347.
**SSOT pins that MUST move for U4/U5:** `src/lib.rs:536 EXPECTED_CLI_SUBCOMMANDS_DEFAULT = 95` and `:563 _SAL = 97` (+1 each for `capture-turn`), enforced by `tests/cli_subcommand_count_invariant.rs:126,141` and narrated in docs via `scripts/check-docs-vs-ssot.sh`; `tests/qual_10_module_size_ceiling.rs:1454 ("src/cli/install.rs", 3_600)` vs actual **3_558 → 42 LOC headroom** (a Stop entry builder + command fn + apply/remove pair + doc comments ≈ 90-140 LOC ⇒ **bump required, with a dated lockstep comment**); `docs/CLI_REFERENCE.md`, `docs/integrations/claude-code.md`, `tests/doc_claims_integrity.rs`, CHANGELOG [Unreleased].
**U1 pins:** `src/storage/mod.rs` QUAL-10 ceiling 34_000 vs actual **33_848 (152 headroom)**; `src/store/postgres.rs` 42_500 vs 42_344-ish — both tight. `tests/qual_6_7_legacy_error_type_ceiling.rs:216 QUAL_6_CEILING = 132` stays only if the new refusal is a typed error, not a new `Result<Value,String>`. C5 `tests/budget_tokens.rs:122` (8110) is untouched unless a tool description changes.
**Unchanged:** `tests/mcp_param_names_invariant.rs` (`ruling_key` is a metadata key, not an MCP param), `EXPECTED_PRODUCTION_ROUTES_COUNT` (no new routes), `CURRENT_SCHEMA_VERSION` (**only if** F5's amendment is taken).

## 4. TEST PLAN GAPS (DENIED/ALLOWED pairs the proposal is missing)

1. **U2 authorship:** line `MASTER→f1: READY` from a file whose actor prefix names `ai:fable` → memory `agent_id` is the **watch process's** resolved id (ALLOWED), `metadata.observed_actor="ai:fable"`; a test asserting the memory is NOT authored as `ai:fable` (DENIED).
2. **U2 rotation/truncation:** file truncated to 0 then re-grown with *different* content → every new line captured. Same file re-grown with the *same* first N bytes → dedup, no duplicate memory. (A byte cursor fails the first; content-hash passes both.)
3. **U2 partial line:** a trailing line with no `\n` is NOT captured this tick and IS captured, exactly once, after the newline arrives.
4. **U2 backend:** `watch --host file:` against a Postgres-configured store → typed refusal (DENIED), not a silent sqlite write. Plus the sqlite ALLOWED twin.
5. **U2 path safety:** `--host file:` pointing at a symlink, a FIFO, a directory, a >1 GiB file, and a path outside the operator's uid → refuse or bound; `--limit` honoured per target per tick.
6. **U1:** same `(N,K)` different `agent_id` → DENIED (typed error, **no write at all**, old row untouched); admin caller → ALLOWED; old row `priority > new` → DENIED; cross-namespace same K → two independent live rows (ALLOWED, no supersession); `ruling_key` present + governance Deny → DENIED with the old row still live; concurrent double-store of the same `(N,K)` → exactly one supersession (BEGIN IMMEDIATE), never two archives of the same row.
7. **U3:** a ruling that HAS been superseded → absent from the report (this is the test F1/F13 make possible); `notify_agent_id` unset → report only, zero writes; two sweeps in one `--once` → exactly one digest; the sweep runs with **no LLM configured**.
8. **U4:** install `--hook stop` on a settings.json that already has an operator `Stop` entry → operator entry survives, ours appended; re-run → byte-identical no-op; `--uninstall --hook stop` leaves the SessionStart and PreToolUse managed blocks intact; malformed settings.json → refuse, file unmodified.
9. **U4 parity:** `ai-memory capture-turn --json < payload` and `memory_capture_turn` over MCP with the same body produce byte-equal envelopes (the `notify`/`inbox`/`subscribe` #3433 twin contract: build a `params: Value`, call the **same** `crate::mcp::handle_*`, print the envelope verbatim — see `src/cli/commands/notify.rs:74-97`).
10. **U4 idempotency:** two Stop hooks firing for the same `session_id` concurrently → exactly one memory per turn, no index collision.

## 5. EFFORT (deputy-days) and ordering

| Unit | Est. | Note |
|---|---|---|
| U1 | 4.0 | Store-funnel change on both backends + authority gate + audit event; the F1/F2 rework is most of the cost. |
| U2 | 3.5 | New `WatchTarget` seam + line-source + dedup reuse + the pg refusal (F7); 1.0 of that is F7 alone. |
| U3 | 1.5 | Pure-SQL read-only pass; cheap once U1 fixes the predicate. |
| U4 | 3.0 | CLI twin (0.75) + `HookKind::Stop` (0.75) + turn-index derivation (1.0) + install test suite (0.5). |
| U5 | 1.0 | Docs + the two SSOT bumps + CHANGELOG. |
| U6 | 0.5 | Config only — but **gated on F7**. |

**Ordering:** F7 (watch pg refusal, standalone hotfix) → U1 (amended per F1/F2) → U2 → U3 → U4 → U5 → U6. U2 and U4 are the two Grok lanes and both touch `src/cli/`, but they touch disjoint files (`cli/watch.rs`+`recover/watcher.rs` vs `cli/install.rs`+`cli/commands/capture_turn.rs`), so they can run in parallel provided the `EXPECTED_CLI_SUBCOMMANDS_*` bump lands only in U4's lane.

## Codegraph commands run
`codegraph explore "watch host abstraction: WatchHost enum, transcript host trait, cursor persistence, atomise path in src/watcher"`; `codegraph explore "transcript_line_dedup table: dedup key, insertion, schema migration"`; `codegraph impact HostKind`; `codegraph impact WatchConfig`; `codegraph impact poll_once`; `codegraph impact run_watch_daemon`; `codegraph impact parse_host`; `codegraph impact handle_capture_turn`; `codegraph impact apply_claude_code`; `codegraph impact is_managed_value`; `codegraph impact handle_store`.

## Rust-standard rule IDs cited
ERRORS-08/ERRORS-19 (never fold a DB `Err` into "no result" — the U3 sweep's link/metadata probe), CONCURRENCY-22 (blocking curator/watch bodies on `spawn_blocking`), M-MOCKABLE-SYSCALLS (the line-file source needs an injectable reader, as `poll_once_with_resolver` has), M-DOCUMENTED-MAGIC (any new limit/tag const carries its rationale), M-REGULAR-FN (keep the tag-extraction and index-derivation as pure, unit-testable functions).

AUDIT B DONE
