---
layout: doc
---
# AI NHI Execution Prompt — v0.8.0 Remaining-Work Closeout (gauntlet-verified)
### Feed verbatim to the Claude Code CLI `/goal` loop driving EPIC #1709

> **What this is.** The single load-bearing brief for the **remaining** v0.8.0 work — the genuinely-undone set, deconflicted against everything already shipped at `release/v0.8.0` HEAD by an 8-agent codegraph verification gauntlet (2026-06-17). Its first job is to **stop the loop redoing shipped work** (§2), its second is to close the verified residual in priority order (§5–§6). Source of truth: this doc + the #1709 body + `ROADMAP.md`. Companion kickoff: [`docs/v0.8.0/GOAL-EPIC-KICKOFF.md`](GOAL-EPIC-KICKOFF.html).
>
> **Authority.** AI NHI is 100% autonomous on execution EXCEPT the release tag-cut + 5-channel publish (operator-gated). Only `alphaonedev`. No external code injection, ever. (CLAUDE.md sole-authority + commit/push policy govern.)

---

## 0. How to use

Paste into Claude Code as the `/goal`:

> **`/goal`** Close out the remaining v0.8.0 work per `docs/v0.8.0/REMAINING-WORK-EXECUTION-PROMPT.md` exactly. FIRST read §2 (already-done — do NOT redo) and internalize it. THEN work §6's ordered list top-to-bottom. For every item: codegraph-verify the anchors at HEAD FIRST (line numbers drift), SAL-trait-FIRST, both sqlite + postgres adapters, three-surface parity, tests, the four cargo gates + three script lint-gates, then commit. Each item is its own sub-issue under #1709 — fix → test → re-check → close with evidence. Respect §7 tracker hygiene (do NOT reopen closed work; do NOT close #1693). Stop at the §8 honesty gate before any tag-cut signal; tag-cut is operator-gated.

Then let it run. It self-sequences from §6.

---

## 1. Mission

The v0.8.0 substrate is far more complete than older planning docs imply. A codegraph gauntlet verified, lane by lane, what is DONE vs OPEN at HEAD. The mission now is narrow and surgical: **close the verified-open residual without re-touching the verified-shipped surface.** Every change still passes the §3 scope test (strengthens ≥1 of the seven §2 properties) and the full gate battery (§9).

---

## 2. ✅ ALREADY DONE — do NOT redo (deconfliction payload)

These were codegraph-verified shipped at HEAD. **Do not re-implement, re-file, or re-open them.** If a stale planning line says otherwise, the planning line is wrong.

- **#1720 — ENTIRE issue shipped + CLOSED.** Owner-keyed `visibility_clause` (`src/storage/mod.rs:383` — `scope_idx='private' AND ?caller IS NOT NULL AND (agent_id_idx=? OR target_agent_id_idx=?)`); `caller: Option<&str>` threaded through `recall`/`search`/`recall_hybrid`; Rust HNSW `is_visible` delegates to `visibility::is_visible_to_caller`; `agent_id_idx` + `target_agent_id_idx` generated columns (v67); B1 durable pid-free owner stamps (`src/identity/mod.rs`); B2 `reown` CLI + SAL `reown`/`claim_unowned` both backends; B3 `AI_MEMORY_REQUIRE_OWNED_ROWS` lockout guard; **C `CorePolicy.required_scope` refuse-only** (`src/models/namespace.rs:550`, wired into both `enforce_governance` gates); `tests/visibility_private_leak_1720.rs` + `tests/sqlite_admin_bypass_visibility_a7_1720.rs`. The cross-tenant private-memory leak is **fixed**. Only optional non-blocking follow-on: D2 curator output-stamp.
- **#1715 — §2.5 read-time attested-provenance shipped + CLOSED.** `decorate_memory_many` (batched, `src/mcp/tools/recall.rs`), `provenance_tier`, `insert_confidence_filter_meta`, `scheduled_validity`, session_start routed through the decorator. Zero residual.
- **Pillar-1 coordination — shipped both backends.** actions (8 MCP tools + state machine + DAG edges + leases + heartbeat sweeper), signals (5 tools + Ed25519), checkpoints (4 tools + attested resolution), routines (5 tools + freeze attestation), `memory_action_frontier`/`memory_action_next`. **Routines are NOT defer-v0.8.1 — they shipped.** (The ONE Pillar-1 residual is the signal hooks — see §5.7.)
- **#888** `update_with_archive_on_supersede` now HAS a production caller (`src/mcp/tools/update.rs:336`, `edit_source=llm|hook`). The "zero-callers / unwired" note is stale.
- **#1670 CLOSED** — `SqliteStore::capabilities()` (`src/store/sqlite.rs:73`) honestly advertises `ATOMIC_MULTI_WRITE`, withholds `TRANSACTIONS` with rationale. Do not "fix" it.
- **#1680 CLOSED** — single hoisted `DEFAULT_REFLECTION_MAX_DEPTH_CAP` const (`src/lib.rs:52`); no two-literal drift.
- **PE-5** `Decision::Escalate` (v66) + blocking-audit gating; **PE-8** `ai-memory verify-audit-trail` CLI — both shipped.
- **Pillar-2.5 size-GC** (`storage::size_gc` + SAL both adapters), **vLLM alias** (`BACKEND_VLLM`, `src/llm.rs`), **Goal/Plan/Step `MemoryKind`s** (`src/models/memory.rs`) — shipped. (Note: lifecycle *enforcement* is NOT done — see §5.4.)

---

## 3. Codegraph-first mandate (standing operator directive)

- Keep the index current and lean on it: `codegraph sync .` after each unit's edits; `codegraph status` to verify. A cold session syncs first (pass `projectPath` to the MCP tools — the server may launch outside the workspace).
- **Re-verify every anchor in this doc via `codegraph_explore` / `codegraph_search` BEFORE editing** — line numbers drift, and the loop is live. Do NOT re-verify codegraph hits with grep.
- Use `codegraph_callers` / `codegraph_impact` for blast-radius before touching handler/SAL/trait surface; run `scripts/qc-codegraph-precheck.sh` (C8) after.

---

## 4. Non-negotiable disciplines (every item, every PR)

1. **`memory_store` FIRST** on any operator multi-step directive (kind=`decision`).
2. **SAL-trait-FIRST** for every new DB op: land on `MemoryStore` + implement on BOTH `SqliteStore` and `PostgresStore` BEFORE handler wiring. A free-fn-only op → postgres 501 (the #1693/#1694 class). Gate it.
3. **Three-surface parity** (MCP + HTTP + CLI) for new surfaces; update the SSOT counts + drift tests (`Profile::full().expected_tool_count()`, `EXPECTED_PRODUCTION_ROUTES_COUNT`, `EXPECTED_CLI_SUBCOMMANDS_*`).
4. **Schema lockstep** — additive `CREATE TABLE`/`ADD COLUMN` only; sqlite migration + postgres `migrate_vN` in lockstep; bump `CURRENT_SCHEMA_VERSION` in both; extend `tests/postgres_schema_parity.rs` for every new table. Idempotent + reversible. A full-table-rebuild migration MUST recreate every trigger + run the trigger suite (the migration-rebuild-drops-all-triggers lesson).
5. **Four cargo gates** green before commit: `cargo fmt --check`; `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic`; `AI_MEMORY_NO_CONFIG=1 cargo test` (FULL, not `--lib`); `cargo audit`.
6. **Three script lint-gates** (HARD-BLOCK): `scripts/check-hardcoded-literals.sh` (no ≥10-char literal on ≥3 sites — name a const), `scripts/check-vendor-literals.sh`, `scripts/qc-codegraph-precheck.sh`. **No hardcoded literals — ENFORCED.**
7. **Verify-before-claiming (pm-v3.3)** — no incapacity/behavioral claim without 2 attempts + logged errors + recompile-retest against a freshly-spawned subprocess. Banned phrases ("non-blocking", "out of scope", "DEFER", "operator should…") prohibited in reports.
8. **Prime directive** — find an issue → file it → fix it → close it (fix + regression test + gates + commit + `gh issue close` with the close-comment URL).
9. **No agent files under `/tmp`** — scratch in `.local-runs/` only.
10. **Commit/push** — commit at logical checkpoints (explicit paths, `Co-Authored-By: Claude Opus 4.8 (1M context)` trailer); push to `release/v0.8.0` pre-approved; never `main`/`develop`; never force-push; tag-cut operator-gated.

---

## 5. The verified-open work items (anchors to re-confirm at HEAD)

> Each item: the residual, the fix, acceptance, phase. Re-verify anchors via codegraph first.

### 5.1 — #1464 per-write cryptographic agent_id attestation (P0, Phase 7) — `security-high`
**Residual:** `attest_write` / `verify_write` (`src/identity/verify.rs:275 / :236`) have **zero callers**; `attribute_agent_for_quota` (`src/handlers/federation_receive.rs:171`) trusts `mem.metadata['agent_id']` verbatim. The header-vs-body refusal half IS shipped (`src/federation/identity/peer_attestation.rs:257`, gating `sync_push` at `federation_receive.rs:386`) — **do not redo that half.**
**Fix:** wire `verify_write`/`attest_write` into the `sync_push` receive loop so each synced memory's `agent_id` is cryptographically verified against the sender's bound key before it is trusted for quota/ownership; reject/quarantine on failure (mirror the existing refusal envelope). Both backends.
**Acceptance:** a synced row whose `metadata.agent_id` is not signed by the enrolled sender key is rejected (or lands `attest_level` reflecting unverified, not trusted-for-quota); regression test on the receive path; SAL parity.

### 5.2 — #1725 / #884 default update path is content-lossy (P0, Phase 2/4) — `correctness`
**Residual:** `update_with_expected_version` (`src/storage/mod.rs:1468`+`:1581` sqlite, `src/store/postgres.rs:3244` pg) overwrites `content` in place with **no archive**; it is the DEFAULT path (`SqliteStore::update` → `sqlite.rs:162`; HTTP `PUT /memories/{id}`; plain `memory_update`). The lossless `update_with_archive_on_supersede` (#888) only fires for `edit_source=llm|hook` (`update.rs:336`).
**Fix (A — unify):** when `content_changed` (already computed at `storage/mod.rs:1508`), call `archive_memory_no_tx` to persist the **prior content body** (e.g. `archive_reason='in_place_edit'`) BEFORE the in-place `UPDATE`, in the same transaction, keeping the stable `memory_id` (no fork → no orphaned `reflects_on`/`atom_of`/`memory_link` edges). Non-content fields (priority/confidence/tags/tier/expires_at/metadata) stay in-place/non-archiving. Postgres twin identical. Do NOT route content edits to #888 (it forks a new id → orphans edges; `#895` edge-rewrite doesn't exist).
**Acceptance:** edit content via `memory_update` → prior body present in `archived_memories` with `archive_reason='in_place_edit'`, `memory_id` unchanged; non-content edit → no archive row; both backends; `tests/store_parity_gaps.rs`. See issue **#1725** for the full spec.

### 5.3 — #228 E2E content encryption is unwired (P0, carried-hardening) — `security-high`
**Residual:** `src/encryption/mod.rs` is an MVP with **zero production callers** (all encrypt/decrypt callers are in-file tests); the `should_encrypt_at_rest` gate (`encryption/mod.rs:346`) exists but `storage::insert` (`:681`) / `get` / `list` / `search` never route through it. At-rest confidentiality is currently **claimed but absent**.
**Fix:** wire encrypt-on-insert + decrypt-on-read gated by `should_encrypt_at_rest`, keyed by operator-supplied key material (compose with the existing sqlcipher posture; decide the boundary — this is column-level content encryption distinct from sqlcipher whole-DB). Fail-closed when encryption is configured but key material is missing.
**Acceptance:** with encryption enabled, on-disk `content` is ciphertext, recall returns plaintext, a missing key fails closed; regression test; do not regress the no-encryption default path.

### 5.4 — #1726 lifecycle_state transition gate is INERT (P1, Phase 4) — `correctness` + §17 drift
**Residual:** the v64 `lifecycle_state` column ships but the gate is never invoked: `LifecycleState::can_transition_to` (`src/models/memory.rs:331`) and `storage::set_lifecycle_state` (`src/storage/mod.rs:1419`) have **zero callers**; `SqliteStore::update` (`sqlite.rs:162`) / `PostgresStore::update` (`postgres.rs:10353`) carry no `lifecycle_state` arg or gate; `UpdatePatch` doesn't carry it. **The CHANGELOG `[Unreleased]` v64 entry falsely claims `memory_update` enforces `can_transition_to`** — §17 honesty drift.
**Fix:** make `set_lifecycle_state` SELECT-current + validate `current.can_transition_to(target)` (typed `InvalidTransition` on failure), both backends; thread a transition target through `memory_update` (and/or a `memory_promote` lifecycle step) so the gate has a real caller; **correct the CHANGELOG v64 entry** to match shipped reality.
**Acceptance:** legal `open→active` succeeds; illegal `open→done` and any move out of a terminal state rejected; both backends; CHANGELOG accurate. See issue **#1726**.

### 5.5 — PE-2 read-action gating (P1, #697 / Phase 6) — `enhancement`
**Residual:** `AgentAction` enum (`src/governance/agent_action.rs:124-170`) has **no `Read` variant**; engine-level read gating absent.
**Fix:** add `AgentAction::Read` + `read_action` wire kind + check-path gating across recall/search/list/get/session_boot so reads land in `signed_events` alongside writes.
**Acceptance:** a governed `read` action is evaluated + audited; rule can deny a read; both backends.

### 5.6 — PE-4 crash-durable audit queue (P1, #697 / Phase 6) — `correctness`
**Residual:** the deferred-audit queue (`src/governance/deferred_audit.rs:51`) is an in-memory unbounded mpsc; a SIGKILL before drain loses pending refusal rows (`signed_events_dlq:582` does NOT cover the pre-drain window).
**Fix:** add a persistent on-disk submit queue durable across restart with drain-on-recovery at boot.
**Acceptance:** refusal enqueued → SIGKILL before drain → row recovered + chained on next boot; test.

### 5.7 — Pillar-1 signal coordination hooks (P1, Phase 1) — the ONLY Pillar-1 gap
**Residual:** `HookEvent::PreSignalSend` (`src/hooks/events.rs:243`) / `PostSignalAck` (`:255`) are declared + classified but have **zero fire sites**; `handle_signal_send` (`src/mcp/tools/signal.rs:24`) / `handle_signal_ack` (`:208`) never invoke the chain; the `SignalDelta`/`SignalAck` payload structs are undefined.
**Fix:** define the `SignalDelta`/`SignalAck` payload structs; plumb `HookChain` + `ExecutorRegistry` into the signal handlers (currently `(conn, params[, keypair])`); fire `PreSignalSend` before the insert (`signal.rs:99`) honoring Allow/Modify/Deny/AskUser; fire `PostSignalAck` after the ack stamp. Non-trivial (signature plumbing + missing payload types).
**Acceptance:** a `pre_signal_send` hook can Deny/Modify a signal; `post_signal_ack` fires post-commit; tests pin both decision paths.

---

## 6. Ordered attack sequence

Work top-to-bottom. P0 first (security/data-integrity), then P1 (correctness), then P2 build-out only if substrate ships clean.

1. **#1464** wire `attest_write` into `sync_push` — claimed-not-attested per-write `agent_id` undermines the ownership/quota trust the shipped #1720 visibility work rests on.
2. **#1725** make the default update path lossless — the most-used write path silently destroys prior content.
3. **#228** wire encryption into `storage::insert/get` — the at-rest claim is currently false.
4. **#1726** enforce `can_transition_to` in `set_lifecycle_state` + fix the CHANGELOG — small, high-correctness; illegal transitions pass silently today.
5. **Pillar-1 signal hooks** (§5.7) — last gap in an otherwise-complete coordination surface.
6. **PE-2** (§5.5) then **PE-4** (§5.6).
7. **P2 build-out** (§6.1) — large net-new; only after 1–6 land clean, and respect the live cutline.

### 6.1 P2 build-out backlog (large; each its own sub-issue; codegraph-confirm absence first)
- **Pillar-2.5** wire the dead-code 6-stage `ConsolidationPass` (`src/curator/compaction.rs:80`, zero callers) into the curator daemon tick + **Stage-6 rollback (#664)** (`compaction.rs:261/237`) + Stage-1 dedupe. (size-GC already shipped.)
- **Pillar-4** 4.A admission control (`AI_MEMORY_MAX_INFLIGHT_REQUESTS` + inflight layer on `build_router` `src/lib.rs:712` → typed 503); 4.C Hot/Cold contract + **staggered AGE cold-path** (the synchronous per-link `project_link_into_age` MERGE at `src/store/postgres.rs:6884` in `link_internal` `:6694`); 4.B PgBouncer per-module pooler (deploy templates + infra test); 4.D empirical module-envelope X measurement.
- **Pillar-3** full CRDT (PN-Counter/OR-Set/per-memory vector clock/attested-LWW) + R6 consensus — only field-wise LWW "CRDT-lite" exists today (`src/storage/crdt_merge.rs:292`).
- **§5 decorrelation** N≥3 multi-reflector quorum at consolidation-time — `consolidate` (`storage/mod.rs:4240`) / `reflect` (`src/storage/reflect.rs:265`) are single-reflector. *(unsized — carry a sizing placeholder; #1171 panel adjudicates the mechanism.)*
- **#654** model-signature chain — no `model_attestations` table, no `model_digest` in `signed_events`.
- **Phase-5 capture** — #1390 SDK client-library shims (`clients/` holds only the L4 capture-turn host-adapter shims, not an SDK package); #1391 IDE transcript paths (`src/recover/transcript_paths.rs` `HostKind` has only Auto/ClaudeCode/Codex/Gemini — add IDE variants); #1393 decision-detector (blocked on vLLM #1677).
- **PE-1** mandatory-hook `--enforce` profile; **PE-3** eBPF subprocess-chain visibility (platform-specific; or formally scope out).
- **Cleanups** — `memory_get_taxonomy` → `memory_namespace_taxonomy` rename; `crate::db` alias removal (`src/lib.rs:530`, deprecated, ~40 sites); legacy v0.6.x flat-config-field removal.

### Unverified (NOT codegraph-checkable — confirm by reading docs/benchmarks, not codegraph)
- LongMemEval Gemma-4 refresh (§11.4.A) — re-run + re-publish R@5/R@10/R@20.

---

## 7. Tracker hygiene — do NOT re-churn

- **#1720 / #1715 / #1670 / #1680 are CLOSED + shipped.** Do not reopen, re-file, or re-implement (§2).
- **#1693 stays OPEN.** A prior gauntlet lane recommended closing it on a "no SAL 501" reading — that answered the wrong question. The issue is the real limitation *"postgres daemons never rehydrate from host transcripts"* (`recover_from_transcript` is a sqlite CLI/hook path), which still holds. Leave open; if you address it, build the postgres rehydration path.
- **#1464 is PARTIAL** — header-refusal shipped; the per-write crypto half (§5.1) is the residual.
- New items get their own sub-issue under #1709 with a "Proposed fix" (file:line + LOC) per the prime directive.

---

## 8. §17 honesty gate (before any tag-cut signal)

- Every PR's CHANGELOG entry names the §2 property it strengthens, with code anchors. A release strengthening none → re-evaluate against §3.
- **#1726 carries a doc-fix:** the CHANGELOG v64 lifecycle-enforcement claim must be corrected to match shipped reality (or the gate wired) before tag-cut.
- Do not tag with any property claim that codegraph cannot substantiate at HEAD.

---

## 9. Quality gates (per item, before close)

```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo test --test postgres_schema_parity        # if schema touched
cargo test --test store_parity_gaps             # SAL both-backend parity
cargo llvm-cov --fail-under-lines 92
ai-memory bench --baseline performance/baseline.json   # recall p95 within 10%
cargo audit
./scripts/check-hardcoded-literals.sh
./scripts/check-vendor-literals.sh
./scripts/qc-codegraph-precheck.sh
```
Plus: CHANGELOG §2-property declaration with anchors; sub-issue closed with fix-SHA + test-name + retest evidence.

---

## 10. Definition of done for this closeout

P0 (§5.1–5.3) + P1 (§5.4–5.7) all closed (fix → test → re-check → close) OR explicitly cutlined with operator approval; both-backend tests green; CHANGELOG honest (§8); the #1709 body checklist reflects each closure. P2 (§6.1) proceeds only after, against the live cutline. Stop and post SHIP-RECOMMENDED on #1709 when the gate battery is green; tag-cut is operator-gated.

*Provenance: 8-agent codegraph verification gauntlet at release/v0.8.0 HEAD e85f9a15, 2026-06-17; load-bearing anchors hand-reconfirmed. Companion: GOAL-EPIC-KICKOFF.md. Build the OSS. Forever.*
