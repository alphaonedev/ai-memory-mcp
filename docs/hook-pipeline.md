---
layout: doc
---
# Hook pipeline (Track G — 22 lifecycle events)

v0.7.0 ships a programmable extension surface that fires on every
substrate lifecycle point. Hooks return one of `Allow`,
`Modify(delta)`, `Deny{reason, code}`, or `AskUser{prompt, options, default}`.
Default off — a v0.7.0 install with no `hooks.toml` behaves
identically to v0.6.4 at the lifecycle layer.

- **Code paths:** [`src/hooks/mod.rs`](../src/hooks/mod.rs),
  [`src/hooks/chain.rs`](../src/hooks/chain.rs),
  [`src/hooks/config.rs`](../src/hooks/config.rs),
  [`src/hooks/decision.rs`](../src/hooks/decision.rs),
  [`src/hooks/events.rs`](../src/hooks/events.rs),
  [`src/hooks/executor.rs`](../src/hooks/executor.rs),
  [`src/hooks/recall.rs`](../src/hooks/recall.rs),
  [`src/hooks/timeouts.rs`](../src/hooks/timeouts.rs),
  pre-store hook subtree under [`src/hooks/pre_store/`](../src/hooks/pre_store/),
  post-reflect hook subtree under [`src/hooks/post_reflect/`](../src/hooks/post_reflect/).
- **Helper binary:** [`tools/auto-link-detector/`](../tools/auto-link-detector/)
  is the R3 reference `pre_link` hook (~775 LoC).
- **Capability registry entry:** `CapabilityHooks` in
  [`src/config.rs:944`](../src/config.rs).
- **Config file:** `~/.config/ai-memory/hooks.toml` — hot-reloadable
  via `SIGHUP` ([`src/hooks/config.rs:424`](../src/hooks/config.rs)).

## Configuration

```toml
[[hook]]
event = "post_store"
command = "/usr/local/bin/auto-link-detector"
priority = 100
timeout_ms = 5000
mode = "daemon"          # daemon | exec (optional; default per event class)
enabled = true
namespace = "team/*"     # glob match (today: non-empty string accepted)
fail_mode = "open"       # open (default) | closed
```

Fields ([`src/hooks/config.rs:174-190`](../src/hooks/config.rs)):

- **`event`** — one of the 22 events below.
- **`command`** — absolute path to the helper binary.
- **`priority`** — higher fires first; first `Deny` short-circuits the chain.
- **`timeout_ms`** — wall-clock budget per call; capped at
  `MAX_TIMEOUT_MS = 30_000` ([`src/hooks/config.rs:138`](../src/hooks/config.rs)).
  Exceeded → executor returns `Timeout`; chain converts per `fail_mode`.
- **`mode`** — `daemon` (long-lived subprocess, stdin JSON-RPC) or
  `exec` (one-shot fork+exec). Optional in TOML; missing values resolve
  via `default_mode_for_event` ([`src/hooks/config.rs:157`](../src/hooks/config.rs))
  — daemon for hot-path events (`post_recall`, `post_search`,
  `pre_recall_expand`), exec otherwise.
- **`enabled`** — soft-disable without removing the row.
- **`namespace`** — glob pattern; chain is filtered before invocation.
  `*` or empty (the schema default) matches every namespace; otherwise the
  pattern matches EXACTLY, or as a `prefix/*` glob covering the prefix itself
  and any child under it. Validation is shape-only (`validate_hook` at
  [`src/hooks/config.rs:297`](../src/hooks/config.rs)); the runtime matcher is
  [`HookConfig::matches_namespace`](../src/hooks/config.rs). See
  §"Namespace scoping on pre-* events" below for how the in-flight namespace is
  resolved.
- **`fail_mode`** — `open` (default; executor errors → chain logs
  warning, treats hook as `Allow`) or `closed` (executor errors →
  chain `Deny` and short-circuit). Use `closed` only for
  compliance-critical hooks (PII redaction, regulated-tenant access
  control) where silent fail-open is worse than a hard refusal.
  Defined at [`src/hooks/config.rs:111-122`](../src/hooks/config.rs).

## Namespace scoping on pre-\* events (#2390)

A `namespace`-scoped hook only fires when the substrate can say which namespace
the in-flight operation touches. For every pre-\* event that runs through the
enforcement gate, that namespace is resolved by the SUBSTRATE — never read from
the request body — using the same rule the operation's own handler uses:

| Event | In-flight namespace |
|---|---|
| `pre_store` | the resolved target namespace: caller `namespace` > `[storage].default_namespace` > compiled default. Omitting `namespace` scopes on the DEFAULT namespace, not on "no namespace". Bulk stores contribute every distinct namespace in the batch. |
| `pre_delete` / `pre_promote` | the TARGET ROW's namespace |
| `pre_link` | BOTH endpoints' namespaces |
| `pre_consolidate` | the resolved target namespace + every source row's namespace |
| `pre_reflect` | the caller `namespace`, else the FIRST source memory's namespace, + every source row's namespace |
| `pre_governance_decision` | the namespace the decision is being made in |

Two consequences worth knowing before you scope a hook:

- **Fire-if-ANY.** An operation that spans several namespaces (a link's two
  endpoints, a consolidation's sources, a bulk store) fires every hook covering
  ANY of them. A `prod`-scoped hook therefore fires on a link between a
  `scratch` source and a `prod` target — otherwise swapping `source_id` and
  `target_id` would choose which guard hook runs.
- **A caller cannot pick its own scope.** A `namespace` field in the request
  body is NOT what the hook is scoped against; the substrate-resolved value
  overwrites it in the payload the hook receives.

**Unresolvable namespace.** If the namespace cannot be resolved (a memory id
that does not exist, a concurrent delete) AND at least one namespace-scoped hook
is configured for that event, the operation is refused with `503` under
`enforce_mode = "enforce"` (WARN + allow under `advisory`, no-op under `off`)
rather than silently skipping the hook. When every configured hook for the event
is wildcard-scoped, the namespace is irrelevant to the firing decision and the
chain runs normally — so unscoped deployments never see this.

**Presence is namespace-blind.** `[hooks].required_events` asks "does an enabled
hook exist for this event?", not "does one cover this namespace". If every
enabled hook for a required event is namespace-scoped, writes OUTSIDE that scope
run UNGOVERNED while the presence gate reads as satisfied. `ai-memory doctor
--hooks` flags exactly this config; add a `namespace = "*"` hook to cover the
rest. Namespace-qualified `required_events` is tracked as a follow-up.

## 22-event matrix

The 15 baseline events (#2758 removed `pre_recall` / `pre_search` and the
whole transcript hook family `pre_transcript_store` / `post_transcript_store`;
the `post_recall` / `post_search` notify events are retained):

| Event | Phase | Class | Fires on | Wired at v1.0.0? |
|---|---|---|---|---|
| `pre_store` | write | Write | `memory_store`, `memory_update` (when content changes) | **yes** |
| `post_store` | write | Write | intended: post-INSERT | **no — never fires** |
| `post_recall` | read | Read | intended: `memory_recall`, family-loader recall | **no — never fires** |
| `post_search` | read | Read | intended: `memory_search` | **no — never fires** |
| `pre_delete` | write | Write | `memory_delete` | **yes** |
| `post_delete` | write | Write | intended: post-DELETE | **no — never fires** |
| `pre_promote` | write | Write | tier promotion (manual + auto) | **yes** |
| `post_promote` | write | Write | intended: post-UPDATE | **no — never fires** |
| `pre_link` | write | Write | `memory_link` | **yes** |
| `post_link` | write | Write | intended: post-INSERT | **no — never fires** |
| `pre_consolidate` | write | Write | `memory_consolidate` | **yes** |
| `post_consolidate` | write | Write | intended: post-return | **no — never fires** |
| `pre_governance_decision` | gate | Write | governance pipeline | **yes** |
| `post_governance_decision` | gate | Write | intended: post-return | **no — never fires** |
| `on_index_eviction` | maintenance | Index | intended: HNSW eviction | **no — sink never installed** |

> ### ⚠️ Firing status at v1.0.0 — read this before configuring a `post_*` hook
>
> **The decision-class `pre_*` events all fire. Most notify-class events do
> not.** Verified against `release/v1.0.0`:
>
> - **Wired (11 of 22)** — every one of the 10 decision-class `pre_*` events
>   (`pre_store`, `pre_delete`, `pre_promote`, `pre_link`, `pre_consolidate`,
>   `pre_governance_decision`, `pre_reflect`, `pre_compaction`,
>   `pre_recall_expand`, `pre_signal_send`) plus the one notify event
>   `post_signal_ack` (installed only when an operator has configured a
>   `post_signal_ack` hook). **Hook-based ENFORCEMENT is fully wired** — a
>   `Deny` from any `pre_*` hook really refuses the operation.
> - **Advertised but NOT wired (11 of 22)** — `post_store`, `post_recall`,
>   `post_search`, `post_delete`, `post_promote`, `post_link`,
>   `post_consolidate`, `post_governance_decision`, `post_reflect`,
>   `on_index_eviction`, `on_compaction_rollback`. These variants parse from
>   `hooks.toml`, classify, and appear in `ai-memory doctor --hooks`, but no
>   production code path fires them, so a hook configured on one of them will
>   **never execute**. (`on_index_eviction` has a complete producer/observer
>   bridge in `src/hnsw.rs` + `src/hooks/chain.rs`, but nothing calls
>   `set_eviction_sink` outside tests, so the channel is never connected.)
>
> This contradicts the standard this project states for itself under #2637 /
> #2758 — "a hook the substrate advertises must actually fire, or it must not
> be advertised". The disposition for these 11 (wire them, or remove them as
> `pre_archive` / `pre_recall` / `pre_search` were removed) is **open**, and
> is a code change, not a docs change. This table records the measured
> behaviour in the meantime. Do not build observability or audit pipelines on
> an unwired event.

> **#2758 (v1.0.0):** `pre_recall`, `pre_search`, and the whole transcript
> hook family (`pre_transcript_store` + `post_transcript_store`) were REMOVED.
> Recall and search are pure read paths (recall mutates zero rows since
> #1869/#1953), so a pre-READ governance gate has no destructive op to gate —
> the `post_recall` / `post_search` notify events were retained. **Correction
> (claims audit, 2026-08-22):** the #2758 rationale asserted that the retained
> `post_recall` / `post_search` siblings "fire on real production read paths".
> They do not — neither has a production fire site at v1.0.0 (see the firing-status
> note above). The removal decision for `pre_recall` / `pre_search` stands on
> its own reasoning (a pure read path has no destructive op to gate); only the
> stated justification for RETAINING the `post_*` pair was wrong.
> `crate::transcripts::store` has NO
> production caller (every caller is test-only), so NEITHER transcript event
> ever fired — the `post_transcript_store` notify was inert for the same
> reason as its `pre_*` sibling, so the whole family (both events + the
> now-uninhabited `Transcript` `EventClass`) was removed. Advertising an
> enforcement/notify point that never fires is a false claim (the #2637
> `pre_archive` disposition).

The 5 grand-slam additions:

| Event | Track | Class | Fires on |
|---|---|---|---|
| `pre_recall_expand` | G10 | **HotPath** | query-expansion synthesise step |
| `pre_reflect` / `post_reflect` | Recursive-learning Task 6/8 | Write | `memory_reflect` |
| `pre_compaction` / `on_compaction_rollback` | L1-7 | Write | curator compaction pipeline |

The 2 v0.8.0 Pillar-1 additions:

| Event | Track | Class | Fires on |
|---|---|---|---|
| `pre_signal_send` | v0.8.0 #1709 | Write | before a signed coordination signal (`memory_signal_send`) is persisted |
| `post_signal_ack` | v0.8.0 #1709 | Write (notify-only) | after a coordination signal is acknowledged (`memory_signal_ack`) |

The discriminator strings (snake_case of the variant names via
`#[serde(rename_all = "snake_case")]`) and the `HookEvent` enum live at
[`src/hooks/events.rs:91`](../src/hooks/events.rs); the canonical wire
shapes for every event's payload (`MemoryDelta`, `RecallQuery`,
`SearchResult`, `ReflectDelta`, `CompactionDelta`, …) start right
after the enum (≈[`src/hooks/events.rs:235`](../src/hooks/events.rs))
and span the rest of the module.

## Decision-class semantics

Every hook returns a `HookDecision`
([`src/hooks/decision.rs:87`](../src/hooks/decision.rs)):

- **`Allow`** — chain proceeds to the next hook (or to the substrate
  if this was the last one).
- **`Modify(delta)`** — chain proceeds, but the in-flight payload is
  rewritten using the hook's delta. Only legal on `pre_*` events
  whose payload type implements the modify protocol (e.g.
  `pre_store` carries `MemoryDelta`, `pre_link` carries `LinkDelta`).
- **`Deny{reason, code}`** — chain short-circuits; the substrate
  refuses the operation and surfaces `code` (an `i32` status-style
  code, serde-defaulted when the hook omits it) to the caller along
  with the `reason` string.
- **`AskUser{prompt, options, default}`** — chain pauses pending an
  operator decision. Today the only consumer is the K10 SSE approval
  loop ([`docs/k10-sse-approvals.md`](k10-sse-approvals.html)). The
  default is applied if the K10 sweeper expires the row before an
  operator answers.

`is_pre_event` ([`src/hooks/decision.rs:344`](../src/hooks/decision.rs))
is the canonical predicate for "may this event return `Modify`" — the
chain runner rejects `Modify` decisions on `post_*` events.

## Per-class deadline budgets

The chain runner reads `event_class(event)`
([`src/hooks/timeouts.rs:137`](../src/hooks/timeouts.rs)) at fire
entry and computes a wall-clock ceiling on the *entire* chain. Per-hook
budgets are derived by `per_hook_budget_ms`
([`src/hooks/timeouts.rs:264`](../src/hooks/timeouts.rs)) and shrink
monotonically as earlier hooks consume time:

| Class | Deadline | Events |
|---|---|---|
| `Write` | **5,000 ms** | store/delete/promote/link/consolidate/governance/archive/reflect/compaction |
| `Read` | **2,000 ms** | recall/search |
| `Index` | **1,000 ms** | `on_index_eviction` |
| `HotPath` | **50 ms** | `pre_recall_expand` (only inhabitant today) |

The HotPath ceiling is the v0.6.3 recall p95 budget — a hook that
can't return a decision in 50ms cannot be wired on the read path
without blowing SLO. The class deadline is the **whole-chain**
ceiling; individual hook `timeout_ms` values may be smaller. A hook's
effective per-call budget is `min(timeout_ms, remaining_chain_ms)`.

When `per_hook_budget_ms` returns `None`, the chain has already
exhausted its class deadline before this hook even fired. The runner
increments the process-wide
`timeout_violations_total` counter
([`src/hooks/timeouts.rs:306-313`](../src/hooks/timeouts.rs)) and
handles the missed hook per its `fail_mode` (`open` → treated as
`Allow`; `closed` → chain `Deny`). The doctor surface reads this
counter for the "did we trip a budget since boot" panel.

## Hot-path constraint

`post_recall` and `post_search` default to `mode = "daemon"`
([`src/hooks/config.rs:157`](../src/hooks/config.rs)). The v0.6.3
recall p95 budget is 50 ms; the daemon subprocess keeps the hook
chain off the synchronous fork/exec path. `mode = "exec"` is
permitted for these events but requires the explicit setting — the
default is intentionally biased toward latency-preserving behavior.
(At v1.0.0 this is a *latent* contract: neither event has a production
fire site, so neither mode costs anything on the live recall path today
— see the firing-status note above.)

`pre_recall_expand` defaults to `daemon` for the same reason but is
classed as `HotPath` rather than `Read` (50 ms whole-chain ceiling vs
2 s), so a misconfigured exec-mode expansion hook still cannot park
the recall path for a full second.

## Hot-reload (SIGHUP)

`spawn_reload_task` ([`src/hooks/config.rs:424`](../src/hooks/config.rs))
listens for `SIGHUP` on Linux/macOS and atomically swaps the chain's
config snapshot (a shared `Arc<HookConfigSnapshot>`, i.e.
`RwLock<Vec<HookConfig>>`). Read-side dispatch resolves the
snapshot once per fire, so a reload mid-fire never tears: any
in-flight chain finishes against the old config; new chains see the
new config. On non-Unix targets the function is a no-op
([`src/hooks/config.rs:473`](../src/hooks/config.rs)).

**Race window discussion.** Between the operator's `kill -HUP <pid>`
and the chain snapshot swap there is a sub-millisecond window where a
new chain fire may have already loaded the pre-swap snapshot. This is
intentional — the alternative (locking writers out of the chain
during reload) would convert hot-reload into a brief outage on a
busy daemon. The operator-visible consequence: a single in-flight
chain may run against the pre-reload config even after `SIGHUP` is
delivered. Verification of the swap is via the `tracing::info!`
emitted by the reload task ("hooks: reloaded config on SIGHUP") — if
the operator wants strict observability they grep for the line
before treating the reload as effective.

On parse failure (TOML error, validation error, missing file) the
reload task logs an error and **keeps the previous config**
([`src/hooks/config.rs:456`](../src/hooks/config.rs)). The daemon
never reloads to an empty config because of operator typo — silent
hook removal would be a security regression.

## Security hardening

- **Stderr redaction** — the executor unconditionally scrubs the
  captured stderr tail through a keyword/shape-based pass
  (`redact_stderr_tail`,
  [`src/hooks/executor.rs:303`](../src/hooks/executor.rs)) before
  forwarding to the daemon log — conservative, favouring
  over-redaction over leaking. Pinned by
  [`tests/g3_hooks_stderr_drain.rs`](../tests/g3_hooks_stderr_drain.rs).
- **Timeout enforcement** — hooks past their `timeout_ms` surface
  `ExecutorError::Timeout`; the child process is reaped via tokio's
  `kill_on_drop(true)` (hard kill — no graceful-shutdown window).
  Pinned by
  [`tests/hooks_timeout_budget.rs`](../tests/hooks_timeout_budget.rs).
- **Substrate authority** — hook decisions are advisory unless the
  substrate explicitly elevates them (e.g., the 7th-form
  `storage::insert` pre-write hook gates on the rule corpus, not on
  arbitrary user hooks). User-supplied hooks cannot bypass governance.

## Tests

Pinned by [`tests/hooks_executor_test.rs`](../tests/hooks_executor_test.rs),
[`tests/hooks_hot_reload.rs`](../tests/hooks_hot_reload.rs),
[`tests/hooks_pre_recall.rs`](../tests/hooks_pre_recall.rs),
[`tests/hooks_timeout_budget.rs`](../tests/hooks_timeout_budget.rs),
[`tests/g3_hooks_stderr_drain.rs`](../tests/g3_hooks_stderr_drain.rs),
[`tests/g11_auto_link_detector.rs`](../tests/g11_auto_link_detector.rs).

## Operator workflow

1. **Author the helper binary.** Use the auto-link-detector as the
   reference (`tools/auto-link-detector/src/main.rs`). Speak JSON-RPC
   over stdin/stdout for `mode = "daemon"`; one-shot exec for
   `mode = "exec"`.
2. **Drop the binary on `PATH`** and `chmod +x`.
3. **Edit `~/.config/ai-memory/hooks.toml`** with the row schema above.
4. **Reload** with `kill -HUP $(pgrep -f 'ai-memory mcp')` or restart
   the daemon. The reload task logs `hooks: reloaded config on SIGHUP`
   on success.
5. **Verify** the reload landed via the
   `hooks: reloaded config on SIGHUP` log line (it carries the loaded
   hook count). The capabilities `hooks` block
   (`memory_capabilities` over MCP, e.g.
   `printf '<JSON-RPC tools/call>' | ai-memory mcp --profile full`)
   reports `hook_events_count` (26) and `registered_count` — it does
   not enumerate per-event hook rows.

## Tuning guidance

Recommended `priority` bands:

- **`priority = 1000+`** — security / compliance hooks. Run first so
  they can `Deny` before a Modify hook rewrites the payload past
  their checks.
- **`priority = 100-999`** — semantic-extraction hooks
  (auto-tagging, auto-link, embeddings). Run after compliance, before
  observability.
- **`priority = 1-99`** — observability / metrics hooks. Run last;
  they see the final payload that the substrate is about to commit.

Recommended `timeout_ms` per event class:

| Class | Recommended `timeout_ms` | Rationale |
|---|---|---|
| Write | 500-2000 | Most hooks finish in <100ms; budget gives headroom for an Ollama call or a network lookup. |
| Read | 200-1000 | Read path is hot; keep budgets tight. |
| HotPath (`pre_recall_expand`) | 30-45 | Class ceiling is 50ms; leave 5-20ms headroom for chain overhead. |
| Index | 100-500 | Background loop; small payloads. |
| Transcript | 500-2000 | Same as Write; transcript payloads can be larger. |

For deployment sizes:

- **Small (1-5 agents)** — single `daemon`-mode auto-link-detector
  hook is plenty. Default `fail_mode = "open"` keeps the substrate
  resilient to hook bugs.
- **Medium (10-50 agents)** — multiple hooks per event acceptable;
  watch `timeout_violations_total` weekly. If non-zero, either tighten
  individual `timeout_ms` or move long-running work to a post-write
  queue.
- **Large (100+ agents, regulated tenant)** — compliance hooks at
  `fail_mode = "closed"` so a buggy hook produces a hard refusal
  rather than silent fail-open. Pair with an on-call alert on
  `timeout_violations_total` delta > 0.

## Troubleshooting

| Symptom | Likely cause | Diagnostic recipe |
|---|---|---|
| Hook not firing | Namespace mismatch, `enabled = false`, or config not loaded | Confirm the `hooks: reloaded config on SIGHUP` line reported a non-zero hook count (or restart and watch boot logs). Then `RUST_LOG=ai_memory::hooks=debug` and watch the chain's per-hook warn/debug lines. |
| Hook fires but result ignored | Returned `Modify` on a `post_*` event | Check `decision.rs:344` `is_pre_event` — `Modify` is only valid on pre-events. Daemon log carries the rejection reason. |
| No hook log lines on any write | No `hooks.toml`, or zero matching rows (an empty chain is a silent no-op returning `Allow`) | This is the **expected v0.6.4-equivalent behavior**. Confirms hooks aren't quietly firing. |
| Recall p95 regressed after enabling hook | Hook is `mode = "exec"` on a hot-path event | Switch to `mode = "daemon"`. If already daemon, reduce `timeout_ms` and inspect helper-binary tracing for the slow path. |
| `timeout_violations_total` growing | A hook's class deadline tripping | Compare to per-hook `ExecutorMetrics` ([`src/hooks/executor.rs:530`](../src/hooks/executor.rs)) to identify the slow hook; widen its `timeout_ms` (cap is 30s) or migrate work off the synchronous path. |
| Daemon-mode hook respawn loop | Helper binary panics on framed stdin | Inspect daemon log for the `hook spawn failed for <command>` error. Fix the helper, redeploy, `SIGHUP`. The chain fails open in the meantime (per `fail_mode = "open"` default). |
| Reload didn't pick up new hook | TOML parse error | Look for `hooks: SIGHUP reload failed; keeping previous config` in the log. Validate the file with `cat ~/.config/ai-memory/hooks.toml | toml --check` (or `taplo lint`). |

## Operator runbook (3am procedures)

**A hook is denying every write — substrate appears stuck.**

1. Set `RUST_LOG=ai_memory::hooks=debug` (`pkill -USR2 ai-memory` if
   you have the dynamic-log signal wired; otherwise restart).
2. Inspect the refused callers' error responses — a hook `Deny`
   short-circuits the chain and surfaces `{reason, code}` directly to
   the caller (`ChainResult::Deny`); fail-mode conversions
   additionally log `hooks: chain hook errored; fail_mode=closed,
   denying` lines naming the hook command and event.
3. To unblock: edit `~/.config/ai-memory/hooks.toml`, set
   `enabled = false` on the offending row, `kill -HUP`. Confirm via
   the `hooks: reloaded config on SIGHUP` log line.
4. RCA after the bleeding stops — replay the captured payload against
   the helper binary on the command line (daemon-mode helpers speak
   framed JSON-RPC on stdin/stdout, so a single-request replay is a
   `printf | helper` one-liner).

**Reload appears to have hung.**

`SIGHUP` reload is async and idempotent. If you don't see the
`hooks: reloaded config on SIGHUP` log line within ~1s, the most
likely cause is a TOML parse error — look for the warning line.
Re-issue `kill -HUP` after fixing the file. If the daemon process
itself is unresponsive, fall through to standard restart procedure
(`scripts/dogfood-rebuild.sh` documents the live-binary swap dance).

**Hot-path latency regressed; suspect a hook.**

1. Review `~/.config/ai-memory/hooks.toml` (and the loaded-count on
   the last `hooks: reloaded config on SIGHUP` line) — confirm which
   events have hooks attached.
2. Temporarily disable hot-path hooks (`enabled = false` on
   `post_recall` / `post_search` / `pre_recall_expand` rows), `SIGHUP`.
3. Re-measure recall p95. If recovered, the hook was the cause.
4. Look at per-hook `ExecutorMetrics` for the trip — usually the
   helper binary blocked on an upstream (Ollama, network). Move the
   work async or relax the SLO.

## Migration

A v0.6.4 → v0.7.0 install with no `hooks.toml` is a no-op at the
lifecycle layer (an empty chain returns `Allow` without spawning
anything). To opt in, follow the operator workflow above. To verify
hooks are NOT firing on a write path, set
`RUST_LOG=ai_memory::hooks=debug` and confirm the absence of per-hook
chain log lines on writes.

See also: [`docs/MIGRATION_v0.7.md` §"Hook pipeline (opt-in)"](MIGRATION_v0.7.html#hook-pipeline-opt-in),
the canonical inventory in
[`docs/internal/v070-feature-inventory.md` §"Feature: Hook pipeline (Track G, 25 events)"](internal/v070-feature-inventory.html),
the SSE approval pipeline that consumes `AskUser` decisions at
[`docs/k10-sse-approvals.md`](k10-sse-approvals.html), the
transcript-store hook reference at
[`docs/sidechain-transcripts.md`](sidechain-transcripts.html), the K8
quotas substrate that gates write events after hook decisions at
[`docs/k8-quotas.md`](k8-quotas.html), the federation hardening that
applies the same hook chain to inbound peer writes at
[`docs/federation.md`](federation.html), and the signed-events chain
that records every governance-gated write at
[`docs/signed-events-v4.md`](signed-events-v4.html).
