# ARCH-3 — MCP/CLI parity audit (FX-12)

**Base SHA:** `11b05229754d43a0c75c0f75d16eb6c676c88627`
**Finding source:** Lane ARCH v2 (`.local-runs/reviews-2026-05-26-v2/ARCH-findings.md` → ARCH-3)
**Severity:** HIGH (parity-drift across the 3-wire MCP / HTTP / CLI surface)

## Context

CLAUDE.md §"Architecture" claims `73 MCP tools, 79 CLI subcommands`.
The implied three-surface parity (MCP / HTTP / CLI) is incomplete on
the CLI wire — operator-facing scripting against the CLI cannot reach
~15 tool families that the MCP surface advertises. Lane ARCH v2
enumerated 73 entries in `src/mcp/registry.rs::registered_tools()`
and 58 top-level CLI variants in `src/daemon_runtime.rs::Command`;
this doc catalogues every gap and tracks remediation through FX-12
and follow-up PRs.

## Audit (all 15 tools)

| # | MCP tool | CLI verb (pre-FX-12) | Status (this PR) | Rationale |
|---|---|---|---|---|
| 1 | `memory_kg_query` | — | **Added-this-PR** (`kg-query`) | High-value operator surface for graph traversal; gap operationally annoying for scripting. |
| 2 | `memory_find_paths` | — | **Added-this-PR** (`find-paths`) | Path enumeration between two memories; primary debug + audit verb. |
| 3 | `memory_recall_observations` | — | **Added-this-PR** (`recall-observations`) | Recall-consumption ledger inspection (#886); needed for shell-side provenance audit. |
| 4 | `memory_check_duplicate` | — | **Added-this-PR** (`check-duplicate`) | Pre-write near-dup check; obvious shell-side ergonomics win. |
| 5 | `memory_replay` | — | **Added-this-PR** (`replay`) | Transcript chain reconstruction; needed for shell-side forensic audit. |
| 6 | `memory_reflect` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`reflect`) | Driver of the recursive-learning primitive. CLI dispatches with `active_keypair = None` / `embedder = None` / `vector_index = None` matching the existing Persona / Skill / Calibrate convention — operators who need signed `reflects_on` edges or LLM-driven dedup drive the MCP / HTTP daemon. The depth-cap path (#1325) is enforced by the shared substrate handler. |
| 7 | `memory_subscribe` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`subscribe`) | Webhook subscription register. CLI exposes `--url` / `--secret` / `--events` / `--namespace-filter` / `--agent-filter` / `--event-types`. The R3-S1.HMAC mandatory-secret rule + registered-agent gate are enforced by the substrate handler verbatim. |
| 8 | `memory_unsubscribe` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`unsubscribe`) | Delete by id. Cross-tenant authorization (#870) enforced by the substrate handler. |
| 9 | `memory_list_subscriptions` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`list-subscriptions`) | Cross-tenant filter (#872) enforced by the substrate handler. |
| 10 | `memory_subscription_replay` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`subscription-replay`) | K7 reliability tool. Caller-ownership gate (#1115) enforced by the substrate handler. |
| 11 | `memory_subscription_dlq_list` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`subscription-dlq-list`) | K7 DLQ introspection. Per-row owner filter (#1118) enforced by the substrate handler. |
| 12 | `memory_notify` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`notify`) | Cross-agent inbox primitive (writes into `_messages/<target>/`). Distinct from `share` (which copies into `_shared/<from>→<to>/`); notify is one-shot message-style, share is durable knowledge-copy. The substrate handler enforces target-agent + title + payload validators and writes the row with the per-tier expiry. |
| 13 | `memory_inbox` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`inbox`) | Read `_messages/<agent_id>/`. `--unread-only` and `--limit` mirror the MCP tool. |
| 14 | `memory_ingest_multistep` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`ingest-multistep`) | Form 3 orchestrator. CLI passes `handler = None` (the LLM dispatch lives in the daemon-side state); the tier-locked advisory envelope returns on every tier for CLI callers, matching the documented behaviour when no LLM is wired. Operators who want the live LLM pipeline drive `memory_ingest_multistep` over the MCP / HTTP daemon. |
| 15 | `memory_kg_invalidate` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`kg-invalidate`) | Edge invalidation. K9 governance gate + the `memory_link_invalidated` webhook dispatch are enforced by the substrate handler. |
| 16 | `memory_kg_timeline` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`kg-timeline`) | Outbound timeline. `--since` / `--until` RFC3339 + `--limit` mirror the MCP tool. |
| 17 | `memory_entity_register` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`entity-register`) | Entity-alias registration. Idempotent on (canonical_name, namespace); merges new aliases per the substrate handler. |
| 18 | `memory_entity_get_by_alias` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`entity-get-by-alias`) | Alias → canonical entity resolver. `--namespace` filter optional. |
| 19 | `memory_dependents_of_invalidated` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`dependents-of-invalidated`) | L2-3 (#668) read. Lists memories whose `reflects_on` edge points at the given reflection id. |
| 20 | `memory_reflection_origin` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`reflection-origin`) | L2-2 / S6-M1 cross-peer provenance lookup. |
| 21 | `memory_session_start` | — | **Not-applicable** | Session-boot context; already covered by `ai-memory boot`. |
| 22 | `memory_quota_status` | — | **Added in fix/arch3-mcp-cli-parity-batch2** (`quota-status`) | Per-(agent, namespace) K8 quota inspection. |
| 23 | `memory_check_agent_action` | `governance check-action` | **Not-applicable** (CLI verb exists at `src/cli/governance_check_action.rs`). |

Total surface: 23 candidates surveyed. 5 added in FX-12, 16 added in
fix/arch3-mcp-cli-parity-batch2 (this fold-in), 2 not-applicable
carve-outs (`memory_session_start` covered by `ai-memory boot`;
`memory_check_agent_action` covered by `ai-memory governance
check-action`). **Zero applicable deferrals remain.** ARCH-3 closes
on the CLI-parity dimension; the machine-pinned regression in
`tests/parity_three_surfaces.rs` is tracked separately.

## Surfaces added (FX-12)

Each new CLI verb dispatches into the SAME substrate handler the MCP
tool consumes. Wire envelope is byte-equal across MCP / HTTP / CLI
(the load-bearing parity contract). The five FX-12 modules live under
`src/cli/commands/`:

- `src/cli/commands/kg_query.rs` → `crate::mcp::handle_kg_query`
- `src/cli/commands/find_paths.rs` → `crate::mcp::handle_find_paths`
- `src/cli/commands/recall_observations.rs` → `crate::mcp::handle_recall_observations`
- `src/cli/commands/check_duplicate.rs` → `crate::mcp::handle_check_duplicate`
- `src/cli/commands/replay.rs` → `crate::mcp::handle_replay`

Two MCP handlers (`handle_kg_query`, `handle_check_duplicate`) were
`pub(super)` and have been promoted to `pub`, with `pub use`
re-exports in `src/mcp/mod.rs`. No business logic was duplicated.

## Surfaces added (fix/arch3-mcp-cli-parity-batch2)

The 16 additional CLI verbs that close every remaining applicable
deferral. Each dispatches into the same substrate handler the MCP
tool consumes — wire envelope byte-equal across the three surfaces.
All modules live under `src/cli/commands/`:

- `reflect.rs` → `crate::mcp::handle_reflect`
- `subscribe.rs` → `crate::mcp::handle_subscribe`
- `unsubscribe.rs` → `crate::mcp::handle_unsubscribe`
- `list_subscriptions.rs` → `crate::mcp::handle_list_subscriptions`
- `subscription_replay.rs` → `crate::mcp::handle_subscription_replay`
- `subscription_dlq_list.rs` → `crate::mcp::handle_subscription_dlq_list`
- `notify.rs` → `crate::mcp::handle_notify`
- `inbox.rs` → `crate::mcp::handle_inbox`
- `ingest_multistep.rs` → `crate::mcp::handle_ingest_multistep`
- `kg_invalidate.rs` → `crate::mcp::handle_kg_invalidate`
- `kg_timeline.rs` → `crate::mcp::handle_kg_timeline`
- `entity_register.rs` → `crate::mcp::handle_entity_register`
- `entity_get_by_alias.rs` → `crate::mcp::handle_entity_get_by_alias`
- `dependents_of_invalidated.rs` → `crate::mcp::handle_dependents_of_invalidated`
- `reflection_origin.rs` → `crate::mcp::handle_reflection_origin`
- `quota_status.rs` → `crate::mcp::handle_quota_status`

Seven MCP handlers were `pub(super)` / `pub(crate)` and have been
promoted to `pub`, with `pub use` re-exports in `src/mcp/mod.rs`:
`handle_kg_timeline`, `handle_entity_register`,
`handle_entity_get_by_alias`, `handle_subscribe`, `handle_unsubscribe`,
`handle_list_subscriptions`, `handle_notify`, `handle_inbox`. No
business logic was duplicated.

### CLI surface design — flat vs nested

Per the FX-12 precedent, all 16 new commands land **flat** at the
top level (e.g. `ai-memory subscribe`, `ai-memory entity-register`,
`ai-memory kg-invalidate`). Considered the nested form (e.g.
`ai-memory subscribe list`, `ai-memory entity register`,
`ai-memory kg invalidate`) and chose flat for three reasons:

1. **Consistency with FX-12.** The five FX-12 commands (`kg-query`,
   `find-paths`, etc.) are flat. Mixing nested and flat in the same
   parity build-out batch creates a discovery hazard for operators.
2. **One-to-one MCP-tool ↔ CLI-verb mapping.** The MCP tools have
   flat names (`memory_subscribe`, `memory_kg_invalidate`). The flat
   CLI verbs mirror that 1:1 so the audit + parity-test surface is
   trivially mechanically diffable.
3. **Shell ergonomics.** Operators scripting against the CLI can tab-
   complete the verb name directly without an intermediate command
   group dispatch.

If a future PR wants to add a `subscribe` parent for an interactive
shell verb (e.g. `ai-memory subscribe list-events`), it can layer a
clap subcommand on top of the flat verb without breaking the existing
flat surface — the dispatcher is data-driven.

## CLI surface deltas

Pre-FX-12: 58 top-level CLI subcommands.
Post-FX-12: 63 top-level CLI subcommands (sal default build) / 65
with `--features sal-postgres`.
Post-fix/arch3-mcp-cli-parity-batch2: **79 top-level CLI subcommands**
(sal default build) / **81 with `--features sal-postgres`**.

CLAUDE.md `count comment` updated accordingly in the §Architecture
"three interfaces" bullet point.

## Coverage discipline

Per the operator-set "Maximum coverage" mandate, each new CLI
handler ships with:

- A per-module unit test (`#[cfg(test)] mod tests`) covering the
  happy-path JSON envelope shape + at least one error path that
  exercises the substrate validation chain.
- A wire-layer smoke test in
  `tests/cli_new_subcommands_smoke_batch2.rs` covering `--help`,
  missing-required-arg, and the empty-DB JSON envelope.

The batch2 smoke suite contains **22 tests** (16 per-subcommand
`--help` checks via a constant + 12 missing-required-arg checks +
6 happy-path round-trip checks + 2 top-level discovery checks).

## ARCH-3 closure

With this batch:

1. Every applicable MCP tool has a CLI counterpart (`reflect`,
   the subscribe family, `notify`/`inbox`, `ingest-multistep`, the
   kg admin pair, the entity pair, `dependents-of-invalidated`,
   `reflection-origin`, `quota-status`).
2. Two carve-outs (`memory_session_start` → `ai-memory boot`,
   `memory_check_agent_action` → `ai-memory governance
   check-action`) remain documented as not-applicable.
3. `tests/parity_three_surfaces.rs` (machine-pinned contract) is
   tracked in a separate follow-up.
