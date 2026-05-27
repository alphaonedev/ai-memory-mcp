# ARCH-3 — MCP/CLI parity audit (FX-12)

**Base SHA:** `11b05229754d43a0c75c0f75d16eb6c676c88627`
**Finding source:** Lane ARCH v2 (`.local-runs/reviews-2026-05-26-v2/ARCH-findings.md` → ARCH-3)
**Severity:** HIGH (parity-drift across the 3-wire MCP / HTTP / CLI surface)

## Context

CLAUDE.md §"Architecture" claims `73 MCP tools, 58 CLI subcommands`.
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
| 6 | `memory_reflect` | — | **Deferred** | Driver of the recursive-learning primitive — the existing `verify-reflection-chain` is read-only; a write-side CLI would need depth-cap + signing key plumbing. Tracked under follow-up. |
| 7 | `memory_subscribe` | — | **Deferred** | Webhook subscription register; CLI shape needs careful design (URL, HMAC secret, filter). Bundle with #7-10 in subscribe family follow-up. |
| 8 | `memory_unsubscribe` | — | **Deferred** | Bundle with #7. |
| 9 | `memory_list_subscriptions` | — | **Deferred** | Bundle with #7. |
| 10 | `memory_subscription_replay` | — | **Deferred** | Bundle with #7. |
| 11 | `memory_subscription_dlq_list` | — | **Deferred** | Bundle with #7. |
| 12 | `memory_notify` | — | **Deferred** | Cross-agent inbox primitive; CLI may overlap with `share` semantically. |
| 13 | `memory_inbox` | — | **Deferred** | Bundle with #12. |
| 14 | `memory_ingest_multistep` | — | **Deferred** | Two-phase ingest orchestrator (Form 3); requires multi-step state machine. |
| 15 | `memory_kg_invalidate` | — | **Deferred** | Edge invalidation; bundle with the broader kg admin family. |
| 16 | `memory_kg_timeline` | — | **Deferred** | Historical edge timeline; bundle with #15. |
| 17 | `memory_entity_register` | — | **Deferred** | Entity-alias surface; bundle with #18. |
| 18 | `memory_entity_get_by_alias` | — | **Deferred** | Bundle with #17. |
| 19 | `memory_dependents_of_invalidated` | — | **Deferred** | Reflection invalidation propagation read; rarely shell-side use. |
| 20 | `memory_reflection_origin` | — | **Deferred** | Reflection ancestry lookup. |
| 21 | `memory_session_start` | — | **Deferred** | Session-boot context; already covered by `ai-memory boot`. **Not-applicable** (existing CLI verb covers the use case via the recommended SessionStart hook). |
| 22 | `memory_quota_status` | — | **Deferred** | Per-namespace quota inspection. |
| 23 | `memory_check_agent_action` | `governance check-action` | **Not-applicable** (CLI verb exists at `src/cli/governance_check_action.rs`). |

Total surface: 23 candidates surveyed. 5 added in this PR, 1
applicable-but-deferred subscribe family (5 tools), 7 other deferred,
2 already covered, 3 in the "applicable" deferred pile (`memory_reflect`,
`memory_ingest_multistep`, the kg admin pair). The ARCH-3 finding
mentioned `~15`; the actual full enumeration is 23 with the carve-outs
above making the "applicable gap" 13 at PR start, reduced to 8 here.

## Surfaces added (this PR)

Each new CLI verb dispatches into the SAME substrate handler the MCP
tool consumes. Wire envelope is byte-equal across MCP / HTTP / CLI
(the load-bearing parity contract). All five new modules live under
`src/cli/commands/`:

- `src/cli/commands/kg_query.rs` → `crate::mcp::handle_kg_query`
- `src/cli/commands/find_paths.rs` → `crate::mcp::handle_find_paths`
- `src/cli/commands/recall_observations.rs` → `crate::mcp::handle_recall_observations`
- `src/cli/commands/check_duplicate.rs` → `crate::mcp::handle_check_duplicate`
- `src/cli/commands/replay.rs` → `crate::mcp::handle_replay`

Two MCP handlers (`handle_kg_query`, `handle_check_duplicate`) were
`pub(super)` and have been promoted to `pub`, with `pub use`
re-exports in `src/mcp/mod.rs`. No business logic was duplicated.

## CLI surface deltas

Pre-FX-12: 58 top-level CLI subcommands.
Post-FX-12: **63 top-level CLI subcommands** (sal default build) / 65
with `--features sal-postgres`.

CLAUDE.md `count comment` updated accordingly in the §Architecture
"three interfaces" bullet point.

## Follow-up

The 8 remaining applicable deferrals (excluding the carve-outs +
session_start dup + governance check_action dup) are tracked in
follow-up issues. Per the prime directive: no findings rot — each
deferred tool gets its own tracker entry. ARCH-3 closes when:

1. The 8 remaining MCP tools (or their family bundles) have CLI
   counterparts OR an explicit "not-applicable" justification in
   this audit.
2. `tests/parity_three_surfaces.rs` machine-pins the contract
   (proposed fix in the original finding).
