# 06 — Hooks / Curator / Autonomy / Subscriptions / Notification (v0.7.0)

Audit scope: the automation / reactive subsystem of ai-memory v0.7.0 —
`src/hooks/` (lifecycle hook pipeline), `src/curator/` (curator daemon +
compaction passes), `src/autonomy.rs` (full-autonomy loop), `src/subscriptions.rs`
(webhook fan-out), `src/notification/` (invalidation propagation),
`src/background/` (offload TTL sweep), `src/recover/nag.rs` (capture-lag watcher).
Every count and claim below carries a `file:line` provenance and is
verifiable against the `release/v0.7.0` tree. Drift / defects are collected in
the final section.

---

## 1. Hook lifecycle events — `HookEvent` enum

**Canonical count: 25 variants.** Defined at `src/hooks/events.rs` (enum
`HookEvent`). The count is test-pinned twice:

- `src/hooks/events.rs` — `hook_event_all_variants_round_trip` asserts
  `table.len() == 25`.
- `src/hooks/timeouts.rs:339` — `event_class_table_covers_all_25_variants`
  asserts `table.len() == 25` ("v0.7.0 L1-7 mapping must cover exactly the 25
  HookEvent variants").

The §24 prior claim of "25 events" is **correct in count**. (See DRIFT D1 for
the events.rs module-doc lines that stale-claim "21".)

### 1.1 Full variant list (25), with class + decision class

`EventClass` (write budget bucket) is from `src/hooks/timeouts.rs:137`
(`event_class`). "Pre/Post/On" decision-relevance is from
`src/hooks/decision.rs` `is_pre_event()`.

| # | Variant | EventClass | Pre? (can Deny/Modify mutate the op) | Notes / provenance |
|---|---------|-----------|--------------------------------------|--------------------|
| 1 | PreStore | Write | yes (pre) | baseline; `src/hooks/events.rs` |
| 2 | PostStore | Write | no (post) | baseline |
| 3 | PreRecall | Read | yes | baseline |
| 4 | PostRecall | Read | no | baseline; hot-path, daemon-mode default |
| 5 | PreSearch | Read | yes | baseline |
| 6 | PostSearch | Read | no | baseline; hot-path, daemon-mode default |
| 7 | PreDelete | Write | yes | baseline |
| 8 | PostDelete | Write | no | baseline |
| 9 | PrePromote | Write | yes | baseline |
| 10 | PostPromote | Write | no | baseline |
| 11 | PreLink | Write | yes | baseline |
| 12 | PostLink | Write | no | baseline |
| 13 | PreConsolidate | Write | yes | baseline |
| 14 | PostConsolidate | Write | no | baseline |
| 15 | PreGovernanceDecision | Write | yes | baseline |
| 16 | PostGovernanceDecision | Write | no | baseline |
| 17 | OnIndexEviction | Index | no (on) | baseline; fired off hot path via eviction observer (R3-S1) |
| 18 | PreArchive | Write | yes | baseline |
| 19 | PreTranscriptStore | Transcript | yes | baseline (I-track) |
| 20 | PostTranscriptStore | Transcript | no | baseline (I-track) |
| 21 | PreRecallExpand | **HotPath** | yes | G10; 50ms whole-chain budget; payload `RecallExpandQuery{query,namespace,k}` |
| 22 | PreReflect | Write | yes | v0.7.0 Task 6/8; fires BEFORE the reflect depth-cap |
| 23 | PostReflect | Write | no | v0.7.0 Task 6/8; notify-class |
| 24 | PreCompaction | Write | yes | v0.7.0 L1-7; fires before `ConsolidationPass` summarise; payload `CompactionDelta{pass_name,candidate_ids,namespace}` |
| 25 | OnCompactionRollback | Write | no | v0.7.0 L1-7; notify-only; payload `CompactionRollbackEvent` |

**EventClass tallies** (`src/hooks/timeouts.rs:341-372`, test-pinned):
Write 17, Read 4, Index 1, Transcript 2, HotPath 1 — sum 25.

**Pre-event tally** (`src/hooks/decision.rs` `is_pre_event`, exhaustive
`#[deny(unreachable_patterns)]` match): **13 pre-events true** (PreStore,
PreRecall, PreSearch, PreDelete, PrePromote, PreLink, PreConsolidate,
PreGovernanceDecision, PreArchive, PreTranscriptStore, PreRecallExpand,
PreReflect, PreCompaction); **12 post/on false**.

### 1.2 Wiring status of each variant (DEFECT class — see D2)

Most **baseline** variants (1-20) carry `TODO(G3-G11): wire here at <symbol>`
comments in `src/hooks/events.rs`, indicating the lifecycle tag exists and is
config/dispatch-addressable but the **real call site does not yet fire it**. The
variants with demonstrated real call-site firing in this tree:

- `PreRecallExpand` (G10 hot path), `OnIndexEviction` (eviction observer,
  `fire_on_index_eviction` + `spawn_eviction_observer` in `src/hooks/chain.rs`).
- `PreCompaction` / `OnCompactionRollback` fire inside
  `ConsolidationPass::run` (`src/curator/compaction.rs:22-30`), but
  `compaction.rs:60-62` marks the call-site wiring `#[allow(dead_code)]`
  ("call-site wiring (autonomy loop integration) ships in L2-1") — i.e. the
  pass struct is defined but **not yet wired into the autonomy loop** in this
  tree.
- The in-substrate `pre_store` / `post_reflect` automations (§5) are wired and
  run in-process; they are DISTINCT from the cross-process `HookEvent::PreStore`/
  `PostReflect` (`src/hooks/mod.rs`).

This is the single largest honest-disclosure item: the 25-event surface is
**fully built (schema, executor, chain, class deadlines, decision contract)**
but only a minority of events are fired at real memory-operation call sites in
v0.7.0.

---

## 2. Hook decision contract — `HookDecision`

`src/hooks/decision.rs` — `HookDecision` has **4 variants**:

| Variant | Wire shape | Semantics |
|---------|-----------|-----------|
| `Allow` | `{"action":"allow"}`, `{}`, empty body, empty stdout | proceed unchanged. Empty/blank → Allow ("fail open, log loudly") |
| `Modify(ModifyPayload{delta: MemoryDelta})` | `{"action":"modify","delta":{...}}` | mutate the pending op via `MemoryDelta` |
| `Deny{reason, code}` | `{"action":"deny","reason":...}` (code default **403**) | refuse the op; first-deny-wins in chain |
| `AskUser{prompt, options, default}` | `{"action":"ask_user",...}` | defer to operator; `default` "names the option the runner falls back to on operator timeout" |

- `is_pre_event()` (`src/hooks/decision.rs:344`) — exhaustive classifier (13
  true, 12 false).
- `degrade_modify_for_post_event` (`src/hooks/decision.rs:312`) — logs `warn`
  and **degrades Modify→Allow** when a post-event hook returns Modify (a
  post-event cannot mutate an already-committed op).
- Unknown action → `DecisionParseError` → wrapped to `ExecutorError::Decode`
  (`src/hooks/executor.rs:391`).

### 2.1 Reflect-path decision divergence (HookVeto vs DepthExceeded)

`src/storage/reflect.rs:54` — the reflect path uses a **2-variant**
`ReflectHookDecision` (Allow, Deny{reason,code}) — **no Modify/AskUser**. Two
distinct refusal outcomes:

| Error | Source | Audited? | When |
|-------|--------|----------|------|
| `ReflectError::HookVeto{reason,code}` | caller-policy refusal (hook said Deny) | **no** depth-cap audit row | fires earlier, at step 4 |
| `ReflectError::DepthExceeded{attempted,cap,namespace}` | substrate self-cap | **yes** (Task 5 audited) | when reflect recursion exceeds cap |

This is a deliberate, correct distinction: a policy veto is not the same as the
substrate's own depth guard, and only the latter writes an audit row.

---

## 3. Hook chain — ordering, fail-mode, AskUser, dispatch

`src/hooks/chain.rs` (`HookChain`, `ChainResult`).

- **Ordering**: priority-descending **stable** sort; ties preserve `hooks.toml`
  insertion order.
- **ChainResult variants**: `Allow`, `ModifiedAllow(MemoryDelta)`,
  `Deny{reason,code}`, `AskUser{queued: Vec<AskUserPrompt>}`.
- **First-deny-wins** short-circuit on pre-events.
- **FailMode** (`src/hooks/config.rs:111`):
  - `Open` (default) — executor `Err` (spawn/decode/timeout/daemon-unavailable)
    → log warn + treat as `Allow` ("a buggy hook must not brick recall").
  - `Closed` — executor error → `ChainResult::Deny` **503**; chain-deadline
    exhaustion → **504**. Reserved for compliance-critical gates (PII redaction,
    regulated-tenant access).
- **AskUser queueing**: "first non-AskUser decision wins"; the AskUser queue is
  cleared on any later Allow/Modify.
- **Dispatch ordering** (`dispatch_event_with_hooks`):
  - pre-events fire **hooks first** (a Deny skips subscription dispatch);
  - post-events fire **subscriptions first, then hooks**.
- **Index-eviction bridge**: `fire_on_index_eviction` + `spawn_eviction_observer`
  bridge the `VectorIndex` eviction channel (R3-S1) onto the
  `on_index_eviction` chain **off the hot path**.

### 3.1 Per-event-class deadlines — `src/hooks/timeouts.rs`

| EventClass | Constant | Deadline | Members |
|-----------|----------|----------|---------|
| Write | `WRITE_CLASS_DEADLINE_MS` (`:115`) | 5000ms | 17 store/delete/promote/link/consolidate/governance/archive/reflect/compaction events |
| Read | `READ_CLASS_DEADLINE_MS` (`:117`) | 2000ms | pre/post recall + search |
| Index | `INDEX_CLASS_DEADLINE_MS` (`:119`) | 1000ms | on_index_eviction |
| Transcript | `TRANSCRIPT_CLASS_DEADLINE_MS` (`:121`) | 5000ms | pre/post transcript store |
| HotPath | `HOT_PATH_CLASS_DEADLINE_MS` (`:127`) | **50ms** | pre_recall_expand (G10; = v0.6.3 recall p95 budget) |

- Per-hook budget = `min(chain_remaining, hook.timeout_ms)`
  (`per_hook_budget_ms`, `:264`). Returns `None` once chain deadline passes →
  caller records a violation + fail-open Allow.
- Process-wide `TIMEOUT_VIOLATIONS` atomic counter (`:302`), surfaced by
  `ai-memory doctor --hooks` via `timeout_violations_total()` (`:313`).
- Test-only `AI_MEMORY_TEST_TIMING_BUDGET_MULT` multiplier (`:216`,
  compiled out of release) scales deadlines 1..=100× for macOS fork-pressure
  flake mitigation (#1207). Production = constant-folded `1`.

---

## 4. Hook executor — `src/hooks/executor.rs`

Two `HookExecutor` impls registered per `[[hook]]` block via `ExecutorRegistry`
(`:1152`; `Vec<(HookConfig, Arc<dyn HookExecutor>)>`, full-struct-equality
keyed — one daemon child per block, never shared):

| Mode | Type | Model | Default for |
|------|------|-------|-------------|
| Exec | `ExecExecutor` (`:595`) | subprocess per fire; payload to stdin, decision = last non-empty stdout line | cold-path events (default) |
| Daemon | `DaemonExecutor` (`:821`) | one long-lived child; **NDJSON** framing; single-flight connection mutex; reconnect backoff 100ms→5s, max 5 attempts | hot-path events: post_recall, post_search, pre_recall_expand (`src/hooks/config.rs:157` `default_mode_for_event`) |

- **Spawn retry** (`spawn_with_transient_retry`, `:204`): retries transient
  fork errnos EAGAIN/ENOMEM/EMFILE/ETXTBSY on a `[10,50,200,1000]`ms ladder
  (#1207). Closes the G8 flake where EAGAIN under FailMode::Open silently
  masqueraded as a passing Allow with a never-run child.
- **ProcessSpawn governance gate** (`:671`, `:1041`): every spawn (exec per
  fire; daemon at connect) is checked through
  `governance::wire_check::check(AgentAction::ProcessSpawn)`; a refusal returns
  `ExecutorError::GovernanceRefused` (distinct from a Spawn IO error). Binary
  identifier built from raw `OsStr` (SEC-13/SEC-17 #767) so non-UTF-8 path
  injection can't bypass a substring rule.
- **stderr redaction** (`redact_stderr_tail`, `:303`): env-var-shaped
  `VAR=value` lines → `VAR=<redacted>`; secret-keyword lines dropped. Raw stderr
  is **never** put into `ExecutorError::ChildExit` `Display` (which flows into
  `ChainResult::Deny.reason` → JSON-RPC caller) — exfil guard for a hostile
  `printenv >&2; exit 1` hook.
- `ExecutorError` variants: Spawn, Io, ChildExit, Decode, Timeout,
  DaemonUnavailable, GovernanceRefused (`:405`).

### 4.1 Config + hot-reload — `src/hooks/config.rs`

- `hooks.toml` schema: `[[hook]]` blocks with `event, command, priority,
  timeout_ms, mode?, enabled, namespace, fail_mode?`.
- `mode` optional (R3-S3) → resolved by `default_mode_for_event`.
- `fail_mode` optional → defaults `Open` (`:118`).
- `timeout_ms` capped at `MAX_TIMEOUT_MS = 30_000` (`:138`); over-cap rejected.
- **SIGHUP hot-reload**: `spawn_reload_task` (`:424`, unix-only) atomically
  swaps the `Arc<RwLock<Vec<HookConfig>>>` snapshot; reload failure keeps
  last-known-good config. Default path
  `dirs::config_dir()/ai-memory/hooks.toml`.
- **Default posture**: hooks are **off** unless a `hooks.toml` exists and lists
  enabled blocks (empty file → zero hooks, `empty_file_yields_zero_hooks`).
- **Namespace matching is NOT a glob yet** — `validate_hook`
  (`src/hooks/config.rs:310`) only checks non-empty; comment: "no glob matcher
  exists in src/ … For now we accept any non-empty string." (DRIFT D3.)

---

## 5. In-substrate automations (NOT cross-process hooks)

`src/hooks/mod.rs` — sub-modules `post_reflect` and `pre_store` are
**in-process** automations that run synchronously inside the substrate, distinct
from the cross-process `HookEvent` subprocess pipeline:

- `pre_store`: `auto_atomise`, `auto_classify_kind`.
- `post_reflect`: `auto_export`, `auto_persona`.

These always run in-process (no subprocess, no hooks.toml gating); they are the
"hooks" actually exercised on the default request path in v0.7.0.

---

## 6. Curator — daemon + compaction

`src/curator/mod.rs` (curator daemon, v0.6.1+).

- **Both standalone and in-daemon**: CLI `ai-memory curator` (`src/cli/curator.rs`)
  AND in-daemon via `run_curator_daemon_with_shutdown`
  (`src/daemon_runtime.rs:4321`) / `run_curator_daemon_with_primitives`
  (`:4356`).
- **Periodic sweep** (`run_once`, `src/curator/mod.rs:210`):
  `(conn, llm: Option<&OllamaClient>, cfg, active_keypair) -> CuratorReport`.
  Sweep work = curator-LLM `auto_tag` + `detect_contradiction` over candidates.
- **Constants**: `DEFAULT_INTERVAL_SECS = 3600`, `DEFAULT_MAX_OPS_PER_CYCLE =
  100`, `MIN_CONTENT_LEN = 50`. `CuratorConfig.interval_secs` clamped
  `[60, 86400]`.
- **CompactionConfig**: `enabled = false` by default (opt-in), `cosine_threshold`
  default 0.75, optional reflection pass.

### 6.1 What the curator LLM does

The curator/autonomy LLM trait `AutonomyLlm` (`src/autonomy.rs`) exposes
`auto_tag`, `detect_contradiction`, `summarize_memories`, impl'd for
`OllamaClient`. Additional curator-class LLM verbs (`expand_query`, summarise)
are reachable through the same provider-agnostic client. The **backend is NOT
hardcoded** (see §9).

### 6.2 Compaction passes — `src/curator/compaction.rs`

`ConsolidationPass` (`:63`) implements `CompactionPass`:

- **Clustering**: primary `CosineClustering` on embeddings; **fallback**
  `JaccardClustering` when no embedder or cosine yields zero clusters
  (`cluster()`, `:102`).
- **Eligibility** (`eligible`, `:117`): ≥2 members, same namespace, no reserved
  (`_`-prefixed) namespace.
- **Fires `PreCompaction`** (Allow/Modify/Deny/AskUser — Deny aborts the cluster,
  no summary/persist/verify) and **`OnCompactionRollback`** (notify-only, fired
  on verify failure). `compaction.rs:29` — **"Rollback itself is not implemented
  yet" (deferred to v0.8.0 Pillar 2.5, issue #664)**. (DRIFT D4.)
- Pass struct is `#[allow(dead_code)]` pending autonomy-loop wiring (L2-1,
  `:60-62`). (DRIFT D2.)

Sibling curator modules: `cluster.rs`, `pipeline.rs` (`CompactionPass` trait),
`persist.rs`, `candidates.rs`, `reflection_pass.rs`.

---

## 7. Autonomy — `src/autonomy.rs` (full-autonomy loop)

`run_autonomy_passes(conn, llm: &dyn AutonomyLlm, candidates, dry_run)` runs
**4 passes**:

1. **Consolidation** — cluster + LLM-summarise near-duplicates.
2. **Forget-superseded** — drop rows whose `confirmed_contradictions` metadata
   names a live superseder.
3. **Priority feedback** — bump hot+recent, decrement cold+old (±1).
4. **Rollback-log + self-report** — write reversibility log + report.

- **Clustering constants**: `CONSOLIDATE_JACCARD_THRESHOLD = 0.55` (pre-filter),
  `CONSOLIDATE_COSINE_THRESHOLD = 0.75` (primary),
  `CONSOLIDATE_MAX_CLUSTER_SIZE = 8` (cap; test-enforced
  `consolidation_cluster_respects_max_size_cap`, `:1780`).
- **Reversibility**: `RollbackEntry` enum (Consolidate / Forget / PriorityAdjust);
  `reverse_rollback_entry` aborts on a (title, namespace) collision
  ("rollback aborted", test `:1556`).
- **Reserved namespace**: `CURATOR_NAMESPACE = "_curator"`; self-reports to
  `_curator/reports/<ts>`, rollback log to `_curator/rollback/<ts>`.
- **dry_run** fully threaded: every pass has a dry-run branch that produces a
  report but writes nothing (test `run_autonomy_passes_dry_run_writes_no_changes`,
  `:1681`).

### 7.1 "Autonomy tiers (basic/smart/autonomous)" — terminology drift (D5)

There is **no enum named `AutonomyTier`** and **no `TierLocked` refusal in the
autonomy/hook layer**. The closest real constructs:

- `FeatureTier` (`src/config.rs:115`): Keyword / Semantic / Smart / Autonomous —
  a **capability/memory-budget** tier (FTS5 → MiniLM+HNSW → nomic+LLM →
  nomic+LLM+cross-encoder), NOT an autonomy-gating refusal.
- `atomisation::TierLocked` (`src/atomisation/mod.rs:150`) — an atomisation-state
  enum member, unrelated to autonomy gating.

So "tier gating / TierLocked refusal" as an autonomy concept **does not exist by
that name** in v0.7.0; the prompt terminology maps onto `FeatureTier` (gates
which LLM/embedder is available, not whether an autonomous action is permitted).

---

## 8. Subscriptions — `src/subscriptions.rs` (webhook fan-out)

- **HMAC-SHA256 mandatory** (R3-S1.HMAC, 2026-05-13): dispatch **refuses to send
  an unsigned payload**. Signature = `HMAC-SHA256(SHA256(secret), "<ts>.<body>")`,
  header `X-Ai-Memory-Signature: sha256=<hex>` (`:936-943`, `:1376`). If neither
  a per-sub secret nor the server-wide `[hooks.subscription] hmac_secret` is
  present, the dispatcher logs `error`, synthesises
  `DeliveryOutcome::unsigned_refused()` (`:960`, `:1187`), and routes the event
  to the **DLQ** instead of sending in clear (`:944-996`). New subscriptions
  cannot register without a secret source.
- **SSRF hardening** (module doc `:11`): `http://` only to `127.0.0.0/8` /
  `localhost`; everywhere else requires `https://`. RFC1918/RFC4193/link-local
  rejected unless `allow_private_networks = true`. `validate_url` (`:1686`),
  `validate_url_dns` (`:1528`).
- **DLQ**: `subscription_dlq` table; `record_dlq` (`:1917`) /
  `record_dlq_with_conn` (`:1961`). Per-subscription cap
  `MAX_SUBSCRIPTION_DLQ_ROWS = 10_000` (#1253, `:1957`); overflow → typed
  `dlq_overflow` error + `ai_memory_subscription_dlq_overflow_total` counter.
  `list_dlq` (`:2020`).
- **Replay**: `replay_subscription_events` (`:2071`); MCP
  `memory_subscription_replay` handler `:2100`. Cross-tenant authz: `get_owner`
  (`:273`, #1115/#1118) gates `memory_subscription_replay` +
  `memory_subscription_dlq_list` so a tenant cannot read another's
  subscriptions; not-found and cross-tenant collapse to the same envelope (no
  id-existence leak).
- **Dispatch concurrency**: bounded by a process `Semaphore`
  (`dispatch_semaphore`, `:485`; `dispatch_concurrency_bound`, `:464`).
- **Event-type filter** (P5/G9): structured `event_types` opt-in column
  overrides the legacy comma-separated `events` whitelist; `list_by_event`
  (`:293`) coarse-prefilters in SQL, `matches_filters` is the authoritative
  in-memory gate.
- **Canonical webhook event types** (`WEBHOOK_EVENT_TYPES`, `:97`): memory_store,
  memory_promote, memory_delete, memory_link_created, memory_link_invalidated,
  memory_consolidated, approval_requested (K4 added approval_requested; J4/G14
  added memory_link_invalidated).
- **Cross-tenant authz** on delete/list (#870/#872): owner-scoped when a
  `caller_agent_id` is supplied; dispatch fan-out intentionally uses `None`
  (global view) since scoping there would drop other tenants' valid subscribers.

---

## 9. LLM backend wiring (provider-agnostic; verifies the "OpenRouter Gemma" claim)

`src/llm.rs` — `OllamaClient` is a **provider-agnostic** chat+embedding client
(post-#1066/#1067). `OllamaClient::from_env` (`:483`) resolves
`AI_MEMORY_LLM_BACKEND` (default `ollama`) against **15+ vendor aliases**
including `openrouter` (`default_base_url_for_alias` → `https://openrouter.ai/api/v1`,
`:208`; api-key env `OPENROUTER_API_KEY`, `:232`). `openrouter` default model is
`openai/gpt-5` (`:504`) absent an override.

Curator/daemon LLM is built by `build_llm_client(feature_tier, app_config)`
(`src/daemon_runtime.rs:2110`) via `OllamaClient::build_from_resolved_async`
(`:2157`), which folds CLI/env/`[llm]`/legacy/compiled config.

**Adjudication**: "OpenRouter Gemma 4 26B per current config" is a **runtime
operator choice** (env/`[llm]` selecting `openrouter` + a Gemma model), **NOT a
hardcoded substrate fact**. The tier system (`FeatureTier`, `src/config.rs:115`)
still names "Gemma 4 E2B/E4B via Ollama" as the *built-in preset* for
Smart/Autonomous, but per CLAUDE.md/#1067 the tier no longer dictates the
vendor — the operator's `AI_MEMORY_LLM_BACKEND` wins. (DRIFT D6: the
`FeatureTier` doc strings still hard-name Ollama/Gemma presets that the
resolver overrides.)

---

## 10. Notification — `src/notification/invalidation.rs`

v0.7.0 L2-3 (#668) — **reflection invalidation = notification, NOT cascade**.

- When a `supersedes` edge lands with both endpoints `memory_kind =
  'reflection'`, the walker finds every dependent `Mi` with a `reflects_on` link
  to the invalidated reflection and writes one **notification memory** into
  `<Mi.namespace>/_invalidations` carrying `dependent_id`, `invalidated_id`,
  `invalidating_id`, `timestamp`; and appends one
  `reflection.invalidation_notified` `signed_events` row per notification.
- **Dependents are NOT auto-superseded** — deliberate: auto-cascade would
  destroy curator judgment and risk nuking an arbitrary reflection sub-graph.
- **Not internally idempotent** in v0.7.0 (`:46`): a second call re-attempts the
  insert per dependent; the single MCP call site (`handle_link`) fires the
  walker once per supersede, so duplicates require deliberate re-invocation.
  v0.8.0 backlog tracks moving idempotency into the walker. (DRIFT D7.)
- Surfaced to operators via the `memory_dependents_of_invalidated` MCP tool.

---

## 11. Background workers

| Worker | Spawn site | Cadence / notes |
|--------|-----------|-----------------|
| Offload TTL sweep (`offloaded_blobs`) | `src/background/offload_ttl_sweep.rs:54` (`spawn`) | daily; QW-3; per-row sleep under lock |
| Pending-actions timeout sweeper (K2) | `src/daemon_runtime.rs:2381` | periodic; expired ids dispatched to approval path; non-positive cadence disables |
| Transcript archive→prune sweeper (I3) | `src/daemon_runtime.rs:2444` | ~10min lifecycle sweep |
| Lease/decay sweeper | `src/daemon_runtime.rs:2490`, `:2516` | periodic (same model as K2) |
| Federation push DLQ replay worker | `src/daemon_runtime.rs:3541` (`federation::spawn_replay_federation_push_dlq`) | polls every N s; replays failed federation pushes |
| Eviction observer → on_index_eviction chain | `src/hooks/chain.rs` (`spawn_eviction_observer`) | bridges VectorIndex eviction channel off hot path |
| hooks.toml SIGHUP reload | `src/hooks/config.rs:424` | signal-driven |

Note: `src/background/` itself contains **only** the offload TTL sweep
(`background/mod.rs:7`: "Today this carries just the daily TTL sweep"); the other
workers are spawned inline from `daemon_runtime.rs`.

---

## 12. Capture-lag watcher — `src/recover/nag.rs`

`CaptureNagWatcher` (L1 `memory_capture_nag`, #1388/#1389 layered-capture):

- Env: `AI_MEMORY_CAPTURE_NAG_THRESHOLD` (default 5),
  `AI_MEMORY_CAPTURE_NAG_ESCALATE_THRESHOLD` (default 20).
- `NagAction`: None / Warn / WarnAndEscalate.
- `classify_tool()` — allowlist of MemoryWrite tools (memory_store,
  memory_update, memory_link, memory_atomise, memory_capture_turn, …).
- On threshold breach emits a stderr `WARN` + a signed `capture_lag` event;
  per-`(agent_id, session_id)` counter. Integrated in
  `src/mcp/mod.rs::handle_request`.
- **Observation-only — does NOT block** the request. Correct posture for a nag.

---

## 13. PreToolUse Claude Code hook integration

`src/cli/install.rs` — `claude_code_pretool_entry()` (`:922`),
`apply_claude_code_pretool()` (`:958`), `remove_claude_code_pretool()` (`:1021`);
exercised by `tests/cli_install_pretool_hook.rs`. `ai-memory install` writes a
Claude Code PreToolUse hook so capture/nag fires on tool use from the editor
side. This is a **Claude-Code-side** integration, separate from the substrate
`HookEvent` pipeline.

---

## DRIFT / DEFECTS SPOTTED

| ID | Severity | Defect | Provenance |
|----|----------|--------|------------|
| D1 | doc | `src/hooks/events.rs` module doc (lines ~56, ~59) stale-claims "the 21 lifecycle event tags" / "The 21 lifecycle events", contradicting the actual **25** variants and its own corrected doc (lines ~78-88, "25 lifecycle events (20 baseline + 5 v0.7.0 additions)"). Internal documentation drift. | `src/hooks/events.rs` |
| D2 | **functional** | The 25-event surface is fully built (schema/executor/chain/deadlines/decision) but **most baseline variants (1-20) carry `TODO(G3-G11): wire here` and are NOT fired at real memory-op call sites**; `ConsolidationPass` (which fires PreCompaction/OnCompactionRollback) is `#[allow(dead_code)]` pending autonomy-loop wiring (L2-1). The advertised event surface materially over-states what actually fires in v0.7.0. | `src/hooks/events.rs`; `src/curator/compaction.rs:60-62` |
| D3 | functional | Hook `namespace` filtering is **not a glob/subtree matcher** — `validate_hook` only enforces non-empty; no pattern matcher exists in `src/` for this layer ("For now we accept any non-empty string"). A `namespace = "team/*"` entry is accepted but the pattern is not actually matched at dispatch. | `src/hooks/config.rs:310-320` |
| D4 | functional | `OnCompactionRollback` fires but **actual rollback is not implemented** — deferred to v0.8.0 Pillar 2.5 (issue #664). The event is notify-only; a verify failure does not undo the compaction. | `src/curator/compaction.rs:28-30` |
| D5 | terminology | No `AutonomyTier` enum and no autonomy-layer `TierLocked` refusal exist. The prompt's "basic/smart/autonomous autonomy tiers + TierLocked refusal" map to `FeatureTier` (a capability/budget tier, `src/config.rs:115`) and `atomisation::TierLocked` (unrelated atomisation state, `src/atomisation/mod.rs:150`). | `src/config.rs:115`; `src/atomisation/mod.rs:150` |
| D6 | doc | `FeatureTier` doc strings still hard-name "Gemma 4 E2B/E4B via Ollama" presets for Smart/Autonomous, but the resolver (`OllamaClient::from_env` / `build_from_resolved`) lets `AI_MEMORY_LLM_BACKEND` (e.g. `openrouter`) override the vendor — tier no longer dictates LLM vendor (#1067). Doc/behaviour drift. | `src/config.rs:115`; `src/llm.rs:483` |
| D7 | functional | Reflection-invalidation walker is **not internally idempotent** in v0.7.0; a deliberate re-invocation writes duplicate notification memories per dependent. Mitigated only by the single MCP call site firing once per supersede; flagged for v0.8.0. | `src/notification/invalidation.rs:44-55` |

No fabricated counts: every event tally (25 variants; 13 pre / 12 post; Write 17
/ Read 4 / Index 1 / Transcript 2 / HotPath 1) is test-pinned in
`src/hooks/events.rs` and `src/hooks/timeouts.rs:339-378`.
