# Recursive learning (v0.7.0)

> **Status (2026-05-12):** Tasks 1-4 of the v0.7.0 recursive-learning
> add-on (issue [#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655))
> have landed on `feat/v0.7.0-recursive-learning`. Tasks 5-8 (signed-events
> audit row, hook events, ship-gate test suite, docs + repro script) are
> in flight on the same branch and roll up into the v0.7.0 tag rather
> than carving a separate v0.7.1 release.

ai-memory v0.7.0 ships a **substrate-native primitive for recursive
refinement**: an agent reads one or more memories, synthesises a
higher-order reflection (a lesson, pattern, contradiction-resolution,
etc.), and persists it with cryptographic-grade provenance back to
each source it reflects on. Reflection depth is bounded by a
substrate-enforced cap. No autonomous goal modification, no model
fine-tuning loops, no unbounded recursion — the substrate refuses
runaway recursion before any write opens.

This page is the engineering-precise primer. The procurement-level
introduction lives in [`v0.7.0/release-notes.md`](v0.7.0/release-notes.md).
The CHANGELOG block sits under v0.7.0 in [`../CHANGELOG.md`](../CHANGELOG.md).

## Conceptual model

A **reflection** is a higher-order memory whose `reflection_depth` is
strictly greater than zero and whose `reflects_on` provenance links
point back to one or more lower-depth source memories. The reflection
row is just another memory — the same recall, search, governance,
federation, attestation, and audit primitives apply to it. What's new
is the recursion contract:

- Every memory carries `reflection_depth: i32` (column on
  `memories`). Caller-minted (and pre-v0.7.0) rows are `depth = 0`.
- A reflection minted by `memory_reflect` over a set of sources S
  has `depth = max(depth_of_each_source) + 1`.
- The substrate writes one `reflects_on` link per source, with the
  reflection as `source_id` and the original as `target_id`. The
  arrow points **from** the reflection **to** the original — same
  directionality contract as `derived_from`.
- A `memory_reflect` call is atomic: the reflection insert and N
  `reflects_on` link writes happen inside a single transaction. Any
  failure rolls back the whole write — the reflection row never
  survives a half-written state.
- The reflection's `metadata.reflection_metadata` block records
  `reflected_on_source_ids`, `reflection_depth`, and
  `reflection_created_at` (RFC3339). Caller-supplied metadata keys
  win on collision (documented additive contract).

A reflection is **provenance-pinned, not just provenance-claimed.**
The `reflects_on` edges are the cryptographic-grade link — when the
v0.7.0 H-track Ed25519 keypair is configured, the link is signed and
verifiable via `memory_verify`. A downstream auditor can walk the
reflection chain and re-verify every step.

## The depth cap

Reflection depth is **substrate-enforced**, not application-enforced.
`db::reflect` (and the postgres parity `PostgresStore::reflect`)
consult `GovernancePolicy.max_reflection_depth` for the resolved
namespace before opening the write transaction. If the proposed depth
exceeds the cap, the substrate refuses with a structured error —
no partial write, no autonomous escape hatch.

### Why 3?

The compiled default is **3**. It bounds reflection recursion without
strangling the legitimate reflection-on-reflection chains the v0.8.0
Pillar 2.5 curator mode is being designed against. Operators who want
a different global default change the constant at the
`effective_max_reflection_depth` accessor; per-namespace overrides
ride the same JSON governance blob `resolve_governance_policy` already
walks leaf-first.

### Per-namespace override

`GovernancePolicy.max_reflection_depth: Option<u32>` is a pure JSON
metadata field on the standard-memory governance object. No schema
bump — it rides alongside the existing `write`, `promote`, `delete`,
`approver`, and `inherit` fields. The accessor is flat:

```rust
pub fn effective_max_reflection_depth(&self) -> u32 {
    self.max_reflection_depth.unwrap_or(3)
}
```

Resolution is leaf-first via `resolve_governance_policy` (same path
the rest of the K1/G1 governance enforcement walks), so a child
namespace's `max_reflection_depth = None` falls through to the
nearest ancestor that does set it, and finally to the compiled
default `3`.

### `Some(0)` is the kill-switch

The substrate-side check is `attempted > cap`, not `attempted >= cap`.
That means `cap = 0` refuses every reflection — depth `1` already
exceeds `0`, depth `2` exceeds it, and so on. **`Some(0)` is the
documented kill-switch** for a namespace (or subtree) that should
never accept reflection writes. Set it on a namespace whose contents
must remain caller-minted and you have a per-namespace opt-out from
the entire primitive.

## API surfaces

| Surface | Where | Notes |
|---|---|---|
| `memories.reflection_depth INTEGER NOT NULL DEFAULT 0` | SQLite schema v29 (`src/db.rs`); Postgres schema v31 ([`src/store/postgres_schema.sql`](../src/store/postgres_schema.sql), [`migrations/postgres/0013_v0700_reflection_depth.sql`](../migrations/postgres/0013_v0700_reflection_depth.sql)) | Caller-minted rows are 0; reflections are `max(source_depths) + 1`. UPSERT clauses take `MAX(old, new)` so federation merges preserve the higher-depth signal. |
| `Memory::reflection_depth: i32` | [`src/models.rs`](../src/models.rs) | `#[serde(default)]` keeps wire-compat with pre-v0.7.0 federation peers. `impl Default for Memory` ships in the same commit so future struct-field adds stop fanning out to ~50 test fixtures. |
| `GovernancePolicy::max_reflection_depth: Option<u32>` | [`src/models.rs`](../src/models.rs) | Per-namespace cap. `None` → compiled default 3. `Some(0)` → kill-switch. |
| `GovernancePolicy::effective_max_reflection_depth(&self) -> u32` | [`src/models.rs`](../src/models.rs) | Flat accessor. Does NOT walk ancestors — call `resolve_governance_policy` first, then this accessor on the result. |
| `reflects_on` relation | [`src/validate.rs`](../src/validate.rs) (`VALID_RELATIONS`); MCP enums in [`src/mcp.rs`](../src/mcp.rs) for `memory_link` / `memory_unlink`; `claude_help` prompt pipe-list | No schema migration required. `memory_links.relation` has no `CHECK (relation IN ...)` clause on either adapter — adding a label is a pure validator + documentation change. |
| `memory_reflect` MCP tool | [`src/mcp.rs`](../src/mcp.rs); substrate impl `db::reflect` in [`src/db.rs`](../src/db.rs); postgres parity `PostgresStore::reflect` in [`src/store/postgres.rs`](../src/store/postgres.rs) | `Family::Power`. Tool count 51 → 52. Atomic insert + N `reflects_on` link writes inside a single `BEGIN IMMEDIATE` / `COMMIT` block (SQLite) or `sqlx::Transaction` (Postgres). |
| `MemoryError::ReflectionDepthExceeded { attempted: u32, cap: u32, namespace: String }` | [`src/errors.rs`](../src/errors.rs) | HTTP `409 CONFLICT`, code `REFLECTION_DEPTH_EXCEEDED`. The structured triple is what downstream auditors and hook emitters need without parsing error strings. |

## Directionality contract for `reflects_on`

The reflection memory is the link's `source_id`; the original being
reflected on is the link's `target_id`. This matches the existing
`derived_from` convention:

```
reflection_memory  --reflects_on-->  original_source
(reflection_depth = N)               (reflection_depth = N-1 or less)
   ^^ link.source_id                    ^^ link.target_id
```

The arrow points **from** the newer/derived row **to** the original.
A consolidated memory `derived_from` its sources is the same shape —
the derived row is on the left, the source on the right. Operators
tracing reflection provenance walk edges *outward* from the reflection
to find its sources, exactly as they walk edges *outward* from a
consolidated memory to find the inputs that produced it.

## `find_paths` chain-walk behaviour

`db::find_paths`'s recursive CTE projects every edge in `memory_links`
**without filtering by relation label**. That means `reflects_on`
edges auto-participate in chain walks alongside the other relations —
operators tracing reflection provenance see chains surface naturally
without further work. The Task 3 regression test
(`tests/recursive_learning_task3_reflects_on.rs::
sqlite_find_paths_walks_reflects_on_edges`) pins this behaviour
against a 3-hop chain.

When walking a reflection chain, expect the path to alternate
between memories that were caller-minted (`reflection_depth = 0`) and
their reflections (`reflection_depth > 0`). A reflection of a
reflection of a reflection is a 3-edge `reflects_on` chain whose
terminal nodes carry depths `0`, `1`, `2`, `3` from leaf to root.

## Reproducibility

The end-to-end demo script is
[`scripts/reproduce-recursive-learning.sh`](../scripts/reproduce-recursive-learning.sh).
It builds the release binary, creates a fresh sqlite DB under
`.local-runs/repro-recursive-learning-<timestamp>/`, inserts three
sample memories, calls `memory_reflect` to produce a reflection at
depth=1, recursively reflects up to depth=3 (the default cap), and
demonstrates the refusal at depth=4 with a clearly-formatted
`REFLECTION_DEPTH_EXCEEDED` verdict block. Idempotent on re-run (each
invocation uses a fresh timestamped subdirectory).

The script honors the project no-`/tmp` HARD RULE — all scratch lives
under `.local-runs/`, which is gitignored.

## Future work

- **Task 5/8** — `signed_events` audit row for every depth-cap
  refusal. Event type `reflection.depth_exceeded`; payload is the
  canonical-CBOR encoding of `{agent_id, attempted, cap, namespace,
  source_ids, proposed_title, created_at}`; `payload_hash` is
  SHA-256 of those bytes. Fires inside `db::reflect` before the
  refusal propagates to the caller, so every cap refusal becomes
  part of the tamper-evident audit chain. In flight on the same
  branch.
- **Task 6/8** — `pre_reflect` / `post_reflect` hook events. `Write`
  event class (same deadline budget as the other write-path hooks).
  Pre-event is veto-capable (returning `Deny` short-circuits before
  the cap check + before the transaction opens). Post-event is
  notify-only and fires after `COMMIT`. In flight on the same
  branch.
- **Task 7/8** — ship-gate test suite consolidating the Task 1-6
  regression coverage into the standard `cargo test --features
  sal-postgres` ladder. Includes the
  `recursive_learning_task{1..6}_*.rs` integration tests + the
  capabilities-honesty assertions Task 8 introduces.
- **Task 8/8** — docs + release-notes + capabilities-JSON-honesty
  pass + reproducibility script. **This page** is the docs leg of
  Task 8.
- **v0.8.0 Pillar 2.5** — reflection-pass curator mode. Builds on
  Task 1-7; introduces a curator daemon mode that periodically
  reflects across a namespace's high-confidence memories to mint
  pattern-level summaries. The substrate primitive is the
  precondition; the curator is the orchestrator.
- **v0.9.0** — skill-composition manifests. A reflection chain
  becomes a skill manifest — a composable, verifiable, depth-bounded
  primitive for codifying agent learnings into reusable assets.

## Cross-references

- CHANGELOG entry: [`../CHANGELOG.md`](../CHANGELOG.md) §v0.7.0
  ("v0.7.0 recursive-learning add-on")
- Release notes: [`v0.7.0/release-notes.md`](v0.7.0/release-notes.md)
  §"Substrate-native recursive refinement"
- Tracker issue: [#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655)
- Task 1 commit: [`f5d8a9e`](https://github.com/alphaonedev/ai-memory-mcp/commit/f5d8a9e)
- Task 2 commit: [`630a6db`](https://github.com/alphaonedev/ai-memory-mcp/commit/630a6db)
- Task 3 commit: [`b51a3f3`](https://github.com/alphaonedev/ai-memory-mcp/commit/b51a3f3)
- Task 4 commit: [`3dc76f3`](https://github.com/alphaonedev/ai-memory-mcp/commit/3dc76f3)
- v0.7.0 epic scope: [`v0.7/V0.7-EPIC.md`](v0.7/V0.7-EPIC.md)
- ROADMAP context: [`../ROADMAP2.md`](../ROADMAP2.md) §7.4 (recursive
  learning) and §Pillar 2.5 (reflection-pass curator)
