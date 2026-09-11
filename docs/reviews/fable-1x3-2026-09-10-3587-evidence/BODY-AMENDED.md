## Why (operator directive 2026-09-10, AI NHI autonomous)
The multi-model swarm (Fable Conductor, Codex, Grok, Opus subagents) stays coherent only while every ruling is written to ai-memory with a priority and old facts are superseded. Today that is a manual habit. The operator ruled: **fix 100% of it in the product and ship it in v1.0.0 GA.** Tracking issue; one deputy lane per unit, exact-head on chain/next, Conductor review + merge-result gate per unit.

✎ **Amended 2026-09-10 after the 1x3 audit + codegraph audit** (findings comment below). Every ✎ line replaces the original wording; the original premise that `resolve` archives with `archive_reason='superseded'` was wrong (`resolve` demotes and links, SQLite-only, no authority check). The real precedent is the append-and-archive arm of `memory_update` (`EditSource::{Llm,Hook}`, `metadata.superseded_id`).

## Units (amended)

### U5a — Ceiling and SSOT scaffolding (Grok, FIRST, no behaviour change)
- ✎ Lockstep QUAL-10 bumps with dated rationale comments: `src/storage/mod.rs` (34_000 → room for U1/U2), `src/config.rs` (15_120 → room for the two `[curator]` keys), `src/cli/install.rs` (3_600 → room for U4). QUAL-6 stays 132.
- ✎ `field_names::RULING_KEY` const; `changelog.d/` fragments scaffolded per unit.

### U1 — Deterministic supersession on store (Codex, hard; after #3582 and U3; own review gate as a GA-boundary change)
- ✎ New optional memory metadata key `ruling_key`. A store carrying `metadata.ruling_key = K` in namespace N **archives** the previous live memory with the same `(N, K)` via a NEW two-backend primitive `archive_as_superseded(old_id, new_id)` in ONE write transaction: `archive_memory(old, reason='superseded')` + `metadata.superseded_id = old` on the new row (+ `superseded_by` on the archived snapshot). **No `supersedes` link** (a link to an archived row violates the `memory_links` FK; #895). Response carries `superseded: <old id>`.
- ✎ Lands in ONE funnel beneath all four write arms (MCP `handle_store`, HTTP sqlite `create.rs`, HTTP postgres `create_memory_postgres`, CLI `store`) with a `PostgresStore` twin and a parity test asserting a byte-identical `superseded` field on every surface; bulk rows carrying `ruling_key` are refused (typed), never silently dropped; federation-forward decides once on the HTTP side.
- ✎ Conflict arm: any store carrying `ruling_key` forces `OnConflict::Error` / mint-new-id regardless of client default, and asserts `actual_id != old_id` before archiving (the default `merge` upsert on `(title, namespace)` would otherwise overwrite the old ruling in place).
- ✎ Authority, fail-closed, keyed on a HARDENED principal only: (1) `AI_MEMORY_AGENT_ID` set and == old owner; or (2) agent-attested store whose verified signer == old owner; or (3) HTTP `X-Agent-Id` == old owner; or (4) `as_admin` + `identity::is_admin_agent` (the #3383 gate, `record_decision` on refuse). Otherwise the new row is stored and NOT superseded, echoing `supersede_skipped: "unauthenticated_principal"`. Legacy rows with empty owner are refused. Never cross-namespace; a namespace prefix is not a match. Priority is NOT part of the authority set (it is caller-controlled).
- ✎ Replay/oscillation: refuse unless the new row's `created_at` is strictly newer; an old row already carrying `superseded_by` is an idempotent no-op. `ruling_key` is write-once: `memory_update` refuses to introduce or change it; it joins the preserved-keys set.
- ✎ Audit: `AuditAction::Update` + `governance::audit::record_decision`; a Deny row on every refused supersession.
- ✎ **CUT from v1.0.0:** `[autonomy] supersede_on_contradiction`. It would archive on an LLM boolean and reverses the v0.9.0 G7 (#1824) "neither memory is deleted" ruling. The contradiction path keeps today's link + soft down-weight. No `[autonomy]` section is added.
- Tests (both backends, MCP/HTTP/CLI): the 15 DENIED/ALLOWED pairs in the audit comment (unauthenticated principal, forged clientInfo, unowned legacy row, title/namespace collision under merge, replay, cross-namespace, admin allowed/denied, env-only admin on CLI, metadata patch cannot erase key, same-title no in-place upsert, already-archived no double-archive, recall excludes the superseded row, audit Deny rows, federation once, backend parity).

### U2 — `watch` line-file source (Grok, after U5a)
- ✎ `ai-memory watch --host file:<path>` (repeatable) modelled as a watcher-layer `WatchSource { Transcript(HostKind), LineFile(PathBuf) }`. `HostKind` stays byte-identical (41-symbol blast radius, `Copy`, `--json` wire shape).
- ✎ Idempotency reuses `transcript_line_dedup` (`host_kind="file"`, `transcript_path=<abs path>`, sha256 of the verbatim line bytes): zero schema change, restart-, rotation- and truncation-safe. In-memory `(dev, ino, len, offset)` is only the change detector, reset on inode change or shrink; a trailing line without newline is never consumed.
- ✎ `agent_id` is ALWAYS the watch process's resolved `--agent-id`; the parsed actor prefix goes to `metadata.observed_actor` (untrusted). Tags from a single `const SWARM_LINE_TAGS` (READY/STATUS/BLOCKER/ACK/NOTE/MASTER). Title = `<basename>:<line sha8>` so two identical lines from two files never collide on `(title, namespace)`.
- ✎ Path safety: regular file only, no symlink components, same uid, bounded line size and `--limit` per source per tick; `--dry-run` writes nothing and never arms retry state. Under `--features fs-notify` line-file sources fall back to polling.
- ✎ Postgres: `watch` gains `refuse_pg_store` (fail closed, loud) AND the SAL path through `recover_from_transcript_store` for line-file sources under `--features sal`, so U6 can write the f1 Postgres hive.
- Tests: rotation, truncation, partial line, dedup on regrow, authorship DENIED/ALLOWED, pg refusal + sal ALLOWED twin, symlink/FIFO/dir/oversized refusals, limit, tag SSOT.

### U3 — Curator stale-ruling sweep (Codex, after #3582, BEFORE U1)
- ✎ `run_stale_ruling_pass` placed right after `run_size_gc_pass`, before the no-LLM early return. Predicate: tag `ruling` OR `metadata.ruling_key`, live (not archived), older than `[curator] stale_ruling_days` (default 14, named const), no `superseded_id`/`superseded_by`/`verified_at` marker, and for keyed rows the latest for its key. Links are not consulted.
- ✎ Digest: `handle_notify_as_sender` with the curator's own resolved id (`notify_agent_id` is a RECIPIENT only, validated at curator boot against reserved ids); de-duplicated on the stale-id-set hash and a hard floor `stale_ruling_notify_min_interval_secs` (default 86400) independent of the sweep interval; `Tier::Short`; suppressed under `--dry-run`.
- ✎ Report: counts + capped top-N ids in the persisted `CuratorReport` (`#[serde(default)]`), full list on stdout under `--json` only (#3345 bloat class). `--stale-rulings` joins the `conflicts_with_all` sets.
- ✎ Guarantee pinned: no writes to the ruling rows (unchanged `version`/`updated_at`, zero `archived_memories` delta), both backends. Config-file-only keys, no env knobs.

### U4 — `capture-turn` CLI twin + `install claude-code --hook capture` (Grok, after U2)
- ✎ `HookKind::Capture` on the existing `--hook` extension point (Stop event); no `--capture-hook` bool; non-claude-code targets keep the pinned refusal. **Codex leg dropped** (documented in prose).
- ✎ The Stop payload provides `last_assistant_message` on stdin (no transcript parsing) and no turn index: `capture-turn --host-turn-index auto` derives `MAX+1` inside the existing `BEGIN IMMEDIATE` transaction; content-hash dedup as the second guard. Hook entry written with `"async": true`, managed keys `["hooks"]`, no `matcher`, explicit `--agent-id <resolved>` in the command; `capture-turn --quiet` never fails (exit 0), no-op when the field is absent; keeps the agent-id agreement check (#1413); `refuse_pg_store`.
- ✎ SSOT: `EXPECTED_CLI_SUBCOMMANDS_DEFAULT` 95→96 and `_SAL` 97→98, `json_contract` classification `Global`, CLI_REFERENCE twin-table row. Byte-equal envelope parity test vs `memory_capture_turn`; install idempotency and operator-hook preservation tests.

### U5b — Docs + SSOT reconciliation (Grok, last)
CLI_REFERENCE (watch, capture-turn, install, curator, `resolve` documented as demote-not-archive), CONFIG_SCHEMA/CONFIGURATION (`ruling_key`, `[curator]` keys, config-file-only), reference configs, doc-claims, docs-vs-ssot, CHANGELOG.

### U6 — Operator wiring (Conductor, after U2 and U4 merge)
- ✎ `packaging/systemd/ai-memory-watch.service` (modelled on the curator unit) + launchd plist; runbook naming `errors_total` / `changes_detected` and the log dir; WAL + bounded retry posture stated.
- ✎ f2: `watch --daemon --host claude-code` and `install claude-code --hook capture` for the Conductor; the Conductor's MCP memory server gets `AI_MEMORY_AGENT_ID` so its stores carry a hardened principal (recorded operator-config change). Every Conductor ruling stores with `ruling_key`.
- ✎ f1: `watch --daemon --host file:` on both outboxes and inboxes into the f1 hive under `--features sal`. Documented boundary: Conductor rulings live in the f2 DB, deputy lines in the f1 hive; supersession is per store.
- Curator `--stale-rulings` daily via the existing routine, digest to `ai:fable`.

## Gate rules for this issue
Exact-head lanes on chain/next; rule (e) pin census across src/ + tests/; codegraph 1.6.0 + rust-1.98 rule IDs in READY; both backends; QUAL-6 stays 132; U1 reviewed as a GA-boundary change (#3578 / #3581 lineage) in its own gate; no new env knobs.

## Effort (adjudicated from the three audits, deputy-days)
U5a 0.5 · U3 2.5 · U1 7 · U2 4.5 · U4 3 · U5b 1 · U6 1 → about 19.5 deputy-days across two lanes.

## Progress
- [ ] U5a ceilings + RULING_KEY const (Grok)
- [ ] U3 curator stale-rulings (Codex)
- [ ] U2 watch line-file source (Grok)
- [ ] U1 store supersession (Codex)
- [ ] U4 capture-turn + install --hook capture (Grok)
- [ ] U5b docs/SSOT (Grok)
- [ ] U6 operator wiring (Conductor)
