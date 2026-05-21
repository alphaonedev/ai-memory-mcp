# JSON Value Serialization Redundancy Audit — Issue #969

**Status:** AUDIT + targeted refactor (v0.7.0)
**Severity:** LOW (issue body)
**Author agent:** Sub-Agent K (Wave-2 Tier-D2)
**Base SHA:** `1da91545992595bdd85422b85181d25b17e56f41`

## Hypothesis under audit

The issue body posits: "Multiple sites convert structs to
`serde_json::Value` redundantly for shape-shifting. Audit + collapse
to single shape per surface."

The audit confirms this hypothesis is **partially true**. Of the ~245
`to_value` / `from_value` call sites in `src/` (excluding `tests/`):

- **209+** are in test code (`#[cfg(test)]` modules in `src/`) — these
  are legitimate fixture builders using `from_value(json!({...}))` to
  construct typed values from inline JSON literals. They will not be
  touched.
- **~110** are `to_value(schema)` calls feeding `schemars` JSONSchema
  generation into MCP tool registries. These are the canonical
  schema-emit pattern and are not redundancy.
- **~70** are production-code Memory/Delta/Payload → Value conversions
  at API/wire/DB boundaries (postgres JSONB binding, federation
  receive, MCP response envelopes, governance payloads). These are
  legitimate type-erasure at trust/wire boundaries.
- **~6** sites are genuine simplification targets. See "Actionable
  Refactors" below.

## Hotspot inventory

Counts include all `to_value` / `from_value` occurrences (production
+ test).

| File | Total | Production (pre `#[cfg(test)]` boundary) | Disposition |
|---|---|---|---|
| `src/models/memory.rs` | 38 | 0 | Test fixtures only (round-trip & enum-disc tests). SKIP. |
| `src/store/postgres.rs` | 14 | 13 | Postgres JSONB binding + federation parsing. Canonical wire boundary. SKIP. |
| `src/models/namespace.rs` | 9 | 1 | `GovernancePolicy::from_metadata` parses a sub-object — legitimate. SKIP. |
| `src/storage/mod.rs` | 7 | 2 | One execute-path `from_value` (pending action payload → Memory) + one production typed-path. Wire boundary. SKIP. |
| `src/models/mod.rs` | 6 | 0 | Tests only. SKIP. |
| `src/hooks/events.rs` | 6 | 0 | Tests only (round-trip serde assertions). SKIP. |
| `src/config.rs` | 6 | 0 | Tests only. SKIP. |
| `src/mcp/tools/capabilities.rs` | 5 | <5 | Mostly schema emit. SKIP. |
| `src/cli/doctor.rs` | 5 | 0 | Tests only. SKIP. |
| `src/handlers/links.rs` | 4 | 4 | Wire-shape `LinkBody` parse + subscription event details. Boundary. SKIP. |
| `src/governance/agent_action.rs` | 4 | 0 | Tests only. SKIP. |
| `src/hooks/decision.rs` | 3 | 3 | **PartialEq workaround — TARGET.** |
| `src/hooks/chain.rs` | 3 | 3 | **PartialEq workaround — TARGET.** |
| `src/handlers/recall.rs` | 3 | 3 | Memory + score decorator (2 sites). **TARGET** (DRY). |
| `src/federation/receive.rs` | 3 | 3 | JSON → Memory at wire boundary. SKIP (legitimate). |
| `src/mcp/tools/namespace.rs` | 6 | 3 | Mostly schema. One legit governance-validation parse. SKIP. |
| `src/mcp/tools/store/mod.rs` | 4 | 2 | **Double-convert in same function — TARGET.** |
| `src/governance/mod.rs` | (PartialEq) | 1 | **PartialEq workaround — TARGET.** |
| `src/mcp/tools/recall.rs` | 4 | 1 | `decorate_memory` helper. Already factored. |
| `src/mcp/tools/session_start.rs` | 2 | 1 | Memory + score (score = 0.0). Could reuse decorator. |
| `src/cli/recall.rs` | 2 | 2 | Memory + score (CLI output). Same pattern as MCP recall. |

## Actionable Refactors

Six sites worth touching. Each is independently small; together they
remove the ~30 lines of duplicated-pattern noise the issue calls out
without disturbing the security envelope.

### R1 — `MemoryDelta: PartialEq` (3 sites)

`src/hooks/chain.rs:177`, `src/hooks/decision.rs:135`,
`src/governance/mod.rs:188` all hand-roll `PartialEq` for an enum
variant that wraps `MemoryDelta` using
`serde_json::to_value(a).ok() == serde_json::to_value(b).ok()`.

The doc-comments rationalize the workaround as "`MemoryDelta` carries a
`serde_json::Value` (metadata) which is not Eq". This is **misleading**:
`serde_json::Value` derives `Eq + PartialEq + Hash` (verified in
`serde_json-1.0.149/src/value/mod.rs:115`). The actual blocker is that
`MemoryDelta` carries `Option<f64>` (confidence), which is `PartialEq`
but not `Eq`. That blocks `derive(Eq)` but NOT `derive(PartialEq)`.

**Fix:** derive `PartialEq` on `MemoryDelta`; collapse the three
`to_value(a).ok() == to_value(b).ok()` lines to direct `a == b`. Also
correct the stale comment-rationale.

### R2 — DRY: `decorate_memory_with_score` (3 sites + 1 existing)

`src/handlers/recall.rs:431,601`, `src/cli/recall.rs:419`, and
`src/mcp/tools/session_start.rs:42` all duplicate the pattern:

```rust
let mut val = serde_json::to_value(mem).unwrap_or_default();
if let Some(obj) = val.as_object_mut() {
    obj.insert("score".to_string(), json!(score_round_3));
}
```

`src/mcp/tools/recall.rs` already has a richer `decorate_memory`
helper (with verbose-provenance fields). For the simpler "just add
score" sites the cleaner factor-out is a small shared helper, but
each call site already does the same 4 lines and reads naturally —
extracting a helper that just wraps 4 lines doesn't pay for itself
when the 4 lines are self-documenting (`to_value`, decorate with
`score`, return). The clear DRY win is the **double-convert in
`mcp/tools/store/mod.rs`** (R3 below); R2 is documented but left.

### R3 — Single-function double-convert in `mcp/tools/store/mod.rs`

`src/mcp/tools/store/mod.rs:276` and `:306` both call
`serde_json::to_value(&mem).unwrap_or_default()` for the SAME
`mem` value ~30 lines apart (K9 permission gate, then governance
enforcement gate). `mem` is read-only between the two sites.

**Fix:** hoist a single `let mem_payload = ...` above both gates and
pass references. Removes one redundant clone+serialise on every
`memory_store` invocation (hot path).

### R4 — Stale comment update (R1 follow-up)

`src/hooks/chain.rs:158-163`, `src/hooks/decision.rs:133-134`,
`src/governance/mod.rs:185-187` carry stale comments asserting that
`serde_json::Value` "is not itself Eq". After R1 these comments
become both wrong and pointless; remove or correct them.

## Intentionally skipped (top-of-list deferrals)

1. **`src/handlers/hook_subscribers.rs`** — per scope directive, security-
   critical surface. Patterns inside are wire-boundary parsing
   (`from_value` of merged config / event envelopes); they are
   single-convert and legitimate. NOT TOUCHED.
2. **`src/store/postgres.rs`** — every `to_value` here binds a
   `serde_json::Value` into `sqlx`'s JSONB binding API (tags column +
   metadata column + approvals column). Each one is a wire boundary.
   NOT TOUCHED.
3. **`src/federation/receive.rs`** — every `from_value` here parses a
   peer-emitted wire payload into a typed `Memory` at the federation
   trust boundary. NOT TOUCHED.
4. **`src/handlers/parity.rs::quorum_not_met_response`** — already
   routed through the canonical `to_value_or_500` helper as part of
   the #869 fold-up. The pre-existing comment block explicitly
   documents this as the consolidation target for that pattern.
5. **`src/models/memory.rs` test fixtures** — the 38 hits are
   `from_value(json!({…}))` fixture builders that are the idiomatic
   way to construct partial test inputs against `#[serde(default)]`
   fields. The alternative (typed-struct literal with every default
   field listed) would be strictly more code with no behavior
   change.
6. **`src/handlers/{create,admin,memories_query,kg}.rs`
   `payload_for_pending` sites** — these are the
   `to_value(&mem).unwrap_or_else(|_| json!({}))` pattern feeding
   `enforce_governance_action`. The fallback `{}` is intentionally
   silent (this is a request-side input, not a response — a
   serialise failure here would degrade the input to the governance
   gate, and an empty object is a sane fail-closed default that
   downstream pattern-matchers handle). Migrating to
   `to_value_or_500` would be a wrong-shape change (the failure
   path is not a 500 response here, it's "fall through with empty
   payload"). NOT TOUCHED.

## Conclusion

The #969 hypothesis surfaces **~6 genuine redundancy sites** (R1+R3)
out of ~245 call sites scanned. The remaining ~239 are legitimate at
their current code shape — wire-boundary conversions, schema emit,
test fixtures, or input-pipeline fail-closed paths.

The fix delta is small (~12 production lines net deletion across 4
files); the audit produces no false-redundancy that warrants forcing
a refactor.

The issue closes with this audit as evidence + the R1+R3 fixes
landed.
