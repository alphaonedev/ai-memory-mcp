# Wave 1 — juror D: agent-host continuity

GPT 6 Astra. Independent first-wave lens, source `87f86a0a1399d8282a60690ce463cba2ba688ebe`. No other juror ballot or root final draft read. CodeGraph CLI explore used first; explicit production-function/full-file direct read coverage is in `source-coverage-continuity.json`. This is not an every-line repository review. No daemon, agent host or database was restarted by this juror.

## Ballot

- Operational value to AI agents: **YES, conditional on host capture and read integration**.
- Grand slam: **NO**.
- Broad Fortune 500/government mission-critical bet-the-farm readiness: **NOT PROVEN**.

Persistent mission records and discoverable resumption context are useful external state. They do not preserve model execution, guarantee context injection, or guarantee that a reconstructed agent chooses the correct next action. Those are host+substrate end-to-end contracts.

## Positive evidence: the three restart numbers are traceable

The downloaded f2 artifact `continuity-a56d9a.json` dated 2026-09-01T20:30:27Z contains the displayed 1089.0, 1014.4 and 996.7 ms, respectively. It records 91/91, 112/112 and 130/130 acknowledged writes present after restart: **333/333 across those three cycles**. Mission memory, inbox row, recall, and a signed post-restart write all pass. Three further one-cycle artifacts (`13cd0d`, `ae919f`, `815e36`) record the same check family passing, at 1059.0, 1051.7 and 1191.8 ms. This is concrete process-restart durability evidence, stronger than an unsupported dashboard assertion. The harness is downloaded evidence, not freshly executed by this review, and its run records do not bind an exact binary hash or source SHA.

`continuity-cycle.py` itself computes `resume_ms` and writes per-run JSON. Manual copying into the published dashboard key is a separate pipeline problem; do not state that no producer computes the value. The script creates signed load-generation identities, writes a synthetic mission string, starts 16 loader tasks, waits four seconds, SIGKILLs the memory daemon, waits 0.5 seconds, stops and drains loaders, starts the daemon, then waits for health/embedder readiness. `resume_ms` ends **before** verification. It includes deliberate wait/drain/restart time; it is not a model-resumption or first-correct-action latency. Python clients remain alive, and no model generation occurs in this script.

Important test limitations: the mission check verifies ID retrieval rather than exact full checkpoint bytes; acknowledged rows are verified by successful GET, not content hashes; in-flight writes with lost responses are not reconciled; no external side-effect ledger is examined; no PostgreSQL process, power, machine or storage failure is injected. `wait_ready` can return finite times when the outer timeout expires while `embedder_ready` is still false, and the aggregate `retained` predicate does not gate on readiness/timing at all. Fix that latent false-green path even though the supplied runs show matching health/embedding times. The earlier `a23546` artifact reports 0/N acknowledged rows visible while totals rise. The current harness comments document owner-scoped GET as a correction. This supports a verifier-identity explanation but does not by itself prove what older code ran; do not count these as demonstrated physical data loss or silently erase them.

## D-01: Python adapters can falsely acknowledge unpersisted capture

**Confirmed source behavior with a local isolated experiment.** `src/mcp/tools/capture_turn.rs:369-375` returns `status:ask`, and `:417-424` returns `status:pending`, before reaching persistence at `:434`. These are legitimate governance outcomes, not transport errors. Both Python transports (`clients/openai-shim-py/ai_memory_openai_shim/_capture.py:143-153`, `clients/anthropic-shim-py/ai_memory_anthropic_shim/_capture.py:155-165`) inspect JSON-RPC error and MCP `isError`, then return `True` without requiring a persisted `memory_id` or checking pending/ask status.

An isolated subprocess-response seam supplied three envelopes to each real transport function: pending, ask and persisted-memory. All six returned `True`; the four unpersisted cases emitted no warning. Output is `capture-pending-probe.json`. This did not change production policy or establish a governance bypass: policy still prevents the write. It establishes a **false capture receipt**, which lets callers or telemetry overstate continuity.

Required correction: parse the tool payload, accept a validated persisted/dedup receipt only, report pending/ask distinctly, and expose failed/unconfirmed capture counts. Preserve best-effort operation where selected, but make a mission-critical host able to require checkpoint acknowledgment before proceeding past its commit boundary. Test actual governed transports, not just this isolated envelope seam.

## D-02: host ABI and completeness remain part of the guarantee

`src/llm_cli_wrap.rs:86-96` maps Codex to `--system`; its test at `:172-180` pins the same assumption. This proves consistency with itself, not compatibility with an installed vendor CLI. Versioned real-host smoke tests must launch each supported host and prove context was received. The wrapper core (`src/cli/wrap.rs:194-244`, `:384-408`) deliberately allows boot failure and still launches; `--no-boot` still emits the generic memory-access preamble. This is a reasonable interactive availability default, insufficient as an application checkpoint guarantee.

The OpenAI Python shim fully delegates ordinary calls, moves capture work off the async event loop (`shim.py:98-105`), and intentionally records request only for streaming (`:94-95`, `:103-105`). It captures Chat Completions, not every host API. The recorder ignores the capture boolean (`:50-58`), and its generated default session ID and counter are process-local (`:40-44`). Durable host session/turn identity, streaming completion/tool-call capture, loss accounting, and a replayable journal must be specified per supported host before claiming automatic universal continuity. No claim is made here that every integration shares these limits.

`memory_session_start` core (`src/mcp/tools/session_start.rs:40-172`) validates namespace, gates reads, filters visibility before clustering, decorates rows, and optionally summarizes. Useful, concrete behavior. It lists recent rows; it is not a transactional mission/goal/next-step checkpoint selector. Summary generation success is not a proof that the consumer received, understood or used the current mission state.

## D-03: wake hints are correctly separated from durable truth

The fully read wake core/pending modules make wake a bounded content-free hint, while inbox rows remain the durable record. Pending IDs coalesce, overflow sets `lagged`, and unknown-recipient wakes cannot grow the table. These are defensible design choices: loss of a hint must trigger catch-up rather than loss of a business message. Poll-backstop execution must be tested in the actual consumer; the module comment cannot guarantee an external client implements it.

Do not describe the current tree as having only a deny-all hub: `delegation_verifier` is present, even though some module comments retain the earlier staging description. Issue #3473 is open and calls for hub-vs-stream p50/p99 at 128/256 agents, A-B-A-B load tests, and hub kill without inbox loss. That wake-hub acceptance is distinct from the downloaded September 1 memory-daemon restart harness. Issue-title screening also surfaced #2430 (task-blind partial read delivery), #3393 (capture identity ladder), #3504 (allowlist refresh), and #3511 (timestamp handshake race). Those are investigation pointers, not newly proven findings in this ballot.

## Strongest counterargument and response

The system already preserves signed rows, mission retrieval and durable inbox state across destructive daemon kills under concurrent writes; requiring it to resurrect a model's hidden state would be unfair. Agreed. The negative vote is **not** a demand for hidden-state preservation. It asks that published claims stop at the measured boundary and that real agents demonstrate safe checkpoint reconstruction and the next correct action with duplicate-effect suppression. D-01 is independently actionable even under that narrower substrate boundary.

## Acceptance additions for the second document

1. Instrument separate clocks for daemon health, dependencies ready, inbox available, checkpoint fetched+verified, first model action, and first correct committed business effect.
2. Kill separately: model host before/after capture acknowledgment, adapter, memory daemon, wake hub, PostgreSQL, network link, and entire host. Use isolated infrastructure and an explicit fault window.
3. For every killed run reconcile acknowledged, unacknowledged-but-committed, failed, duplicate and missing operations against content hashes and an external effect ledger.
4. Resume a fresh agent process with only authorized durable state, inject a superseding instruction and stale checkpoint, and require correct continuation, scoped authority and no duplicated external effect.
5. Test streaming, tool calls/results, session identity reuse, compaction, adapter receipt pending/ask/denied, provider outage and backlog recovery on real supported host versions.
6. Publish immutable raw events plus producer/source/binary/config hashes. Generate dashboard state from those results. A manual row cannot satisfy the automated release gate.
