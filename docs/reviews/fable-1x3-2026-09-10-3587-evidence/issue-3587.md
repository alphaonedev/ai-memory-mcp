## Why (operator directive 2026-09-10, AI NHI autonomous)
The multi-model swarm (Fable Conductor, Codex, Grok, Opus subagents) stays coherent only while every ruling is written to ai-memory with a priority and old facts are superseded. Today that is a manual habit. The operator ruled: **fix 100% of it in the product and ship it in v1.0.0 GA.** Tracking issue; one deputy lane per unit, exact-head on chain/next, Conductor review + merge-result gate per unit.

## Units

### U1 — Deterministic supersession on store (Codex, hard)
- New optional memory metadata key `ruling_key` (string). A successful store carrying `metadata.ruling_key = K` in namespace N by author A **automatically supersedes** the previous non-archived memory with the same `(N, K)`: old row archived with `archive_reason='superseded'` (existing `resolve` semantics), `supersedes` link new→old, response carries `superseded: <old id>`.
- Authority, fail-closed: only when the old memory's `agent_id` == caller (or caller is admin under the existing admin gate); never across namespaces; never a memory with higher priority than the new one (refuse with a typed error, no write).
- No LLM, no config knob required; works on MCP, HTTP and CLI store paths and both backends (SQLite + Postgres twin tests).
- `[autonomy] supersede_on_contradiction = true` (default false): when `autonomous_hooks` detect_contradiction reports a contradiction with an older same-author memory, apply the same supersession; otherwise link `contradicts` only (today's behaviour).
- Tests: DENIED/ALLOWED pairs per rule (cross-agent, cross-namespace, higher-priority, admin), sqlite + pg, HTTP/MCP/CLI parity, audit-trail event.

### U2 — `watch` line-file host (Grok)
- `ai-memory watch --host file:<path>` (repeatable): generic append-only line protocol files (deputy outboxes/inboxes, Grok pass logs). Per-file byte cursor persisted in the DB (survives restarts), each new line atomised into a memory in `--namespace` (default `swarm`), tags from the leading token (`READY|STATUS|BLOCKER|ACK|NOTE|MASTER→…`), `agent_id` from the line's actor prefix when present, `source_uri = file path`, mid tier, priority 6 (READY/BLOCKER = 8).
- Existing hosts untouched; `--dry-run` and `--once` honoured; bounded by `--limit`.
- Tests: cursor persistence, partial-line safety, tag extraction, sqlite + pg.

### U3 — Curator stale-ruling sweep (Codex, after U1)
- `[curator] stale_ruling_days = N` (default 14) and `curator --stale-rulings` (also part of `--once`): every memory tagged `ruling` (or carrying `ruling_key`) older than N days with no `supersedes`/`superseded_by`/`verified` link is reported (JSON) and, when `[curator] notify_agent_id` is set, sent as one `memory_notify` digest to that agent (rate-limited: one digest per sweep).
- Tests: report shape, notify once, no writes to the rulings themselves.

### U4 — `capture-turn` CLI + install hook (Grok, after U2)
- CLI twin `ai-memory capture-turn` of `memory_capture_turn` (byte-equal envelope; stdin body; `--agent-id` honoured per #3433).
- `ai-memory install claude-code --capture-hook`: writes a Claude Code `Stop` hook that pipes the last assistant turn to `capture-turn` (idempotent, `--json`). Codex: document the `notify` hook equivalent; add `install codex --capture-hook` if the Codex hook contract allows a stdin payload.
- Tests: install idempotency, hook JSON shape, capture-turn parity with the MCP tool.

### U5 — Docs + SSOT (Grok, with U4)
CLI_REFERENCE (watch, capture-turn, install, curator), config reference (`ruling_key`, `[autonomy].supersede_on_contradiction`, `[curator].stale_ruling_days/notify_agent_id`), CHANGELOG fragments per unit, doc-claims integrity, QUAL ceilings unchanged (typed errors, no bumps), C5 only if a tool description changes.

### U6 — Operator wiring (Conductor, after merges)
- f2: `ai-memory watch --daemon --host claude-code` under the Conductor's own pid against the Conductor memory DB; Conductor stores every ruling with `ruling_key`.
- f1: `watch --daemon --host file:` on both deputy outboxes and inboxes into the f1 hive, namespace `swarm`.
- Curator `--stale-rulings` daily via the existing routine; digest to `ai:fable`.

## Gate rules for this issue
Exact-head lanes on chain/next; rule (e) pin census across src/ + tests/; codegraph 1.6.0 + rust-1.98 rule IDs in READY; both backends; QUAL-6 stays 132; write-authority pins reviewed by the Conductor as part of the GA boundary (#3578 / #3581 lineage).

## Progress
- [ ] U1 store supersession (Codex)
- [ ] U2 watch file host (Grok)
- [ ] U3 curator stale-rulings (Codex)
- [ ] U4 capture-turn + install hook (Grok)
- [ ] U5 docs/SSOT (Grok)
- [ ] U6 operator wiring (Conductor)
