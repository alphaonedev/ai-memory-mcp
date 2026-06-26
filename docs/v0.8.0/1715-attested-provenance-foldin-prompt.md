# AI NHI Build Prompt — Read-time Attested-Provenance Surfacing (§2.5)
### v0.8.0 EPIC #1709 fold-in · reframed from #1715 "confidence honesty"

> **Feed this verbatim to the Claude Code CLI loop driving v0.8.0 EPIC #1709.**
> Scope: the v0.8.0 deliverable only — a small, branch-free, perf-gated §2.5 attested-provenance decoration lane. Everything else from #1715 is explicitly deferred or cut (see §7). Build the v0.8.0 lane; do not build the v0.9/cut items.

---

## 0. Role & mission

You are an autonomous AI NHI engineer working inside the `ai-memory` substrate (`/home/fate_two/v07/v07-f5`, branch `release/v0.8.0`), under the v0.8.0 Distributed Coordination Substrate EPIC (#1709). Your task is a **self-contained, ~half-day, ships-clean** increment that strengthens **§2.5 (attested)** by surfacing **attested provenance** in recall output and demoting the stored confidence scalar to an honest ranking-cache — implementing the principle *"never store confidence as truth; recompute it at read from already-merged signed evidence."*

This is incremental §2.5 polish, NOT a new subsystem. Touch the minimum surface. Every change must pass the existing CI gates (§5) with **zero recall-latency regression**.

## 1. Non-negotiable constraints (read before writing any code)

1. **Scope test (ROADMAP §3/§5).** This work is in-scope ONLY as §2.5 attested (provenance surfacing) + §2.4 improvable (the recall-feedback loop, which lives in #1706/#1707 — do NOT touch it here). Do not reintroduce the word "confidence" as a *property* claim. The CHANGELOG entry must name **§2.5** with code anchors (§17 gate) — no property claim without an anchor.
2. **No hardcoded literals** (operator HARD RULE). Any threshold/weight/bucket must be a named constant in the canonical config/const location, never an inline literal. If you introduce a tier cutoff or as-of bucket size, name it.
3. **Performance is CI-enforced (§9.6).** `memory_recall` p95: semantic ≤ 35 ms, autonomous ≤ 90 ms; `bench --baseline performance/baseline.json` fails any PR > 10 % over budget. Your recompute must be **branch-free arithmetic over the already-fetched top-K (K ≤ 50) inside `decorate_memory`**, with **zero additional DB round-trips** and **no LLM call on the read path**.
4. **Stored `m.confidence` stays a grow-only ranking-cache scalar.** It is consumed by the SQL score `ORDER BY (… + m.confidence*2.0 …)` (`src/storage/mod.rs:2952`) over the FTS-bounded candidate set. **Your recompute must never write to, or change the sort contribution of, this term.** (There is no `idx_memories_confidence`; the only confidence index is the partial `idx_memories_confidence_source`, migration `0033:102`. Describe it as "the stored scalar consumed by the FTS-bounded in-query score," not "indexed scalar.")
5. **Recall determinism invariant.** `tests/bias_displacement_invariants_2_6.rs` (Invariant 1) pins **id-ranking byte-equality** over an identical `(memory-set, query)` — it tolerates a wall-clock recency term in the *score* but the *id ordering* must be stable. Therefore: anything you recompute is **decoration only** (returned fields), never a new ranking key; and it must be a **pure function of stored fields + a quantized as-of bucket** so two reads over the same `(memory-set, query, as-of-bucket)` are identical. Run this test; it must stay green.
6. **No in-place confidence mutation, no unsigned writes of belief.** Do not add any path that decrements/derives `memories.confidence`. (B1/decay are out of scope here; note for context that `src/confidence/decay.rs:170` currently writes confidence in-place *unsigned* — do not extend that pattern.)
7. **Additive schema only, sqlite+postgres lockstep.** If any column is needed (likely none), it is additive, both adapters, `tests/postgres_schema_parity.rs` green, version bumped via the SSOT (`current_schema_version_for_tests()`). Prefer **no schema change** — this lane should be pure read-side composition.

## 2. Codegraph-anchored map (verify before editing — use codegraph, not grep)

Use the codegraph MCP (`codegraph_explore`, `projectPath="/home/fate_two/v07/v07-f5"`) to confirm each anchor at HEAD before editing; line numbers may drift.

- `src/mcp/tools/recall.rs:302` — `decorate_memory` (the read-side decorator; already emits `confidence_tier`, `freshness_state`, `latest_link_attest_level`). **Primary edit site.**
- `src/mcp/tools/recall.rs:352` — `freshness_state` (pure, "no DB queries") — the precedent pattern for label-free recompute.
- `src/mcp/tools/recall.rs:402–422` — `attest_rank` ladder (`Unsigned < SelfSigned < DaemonSigned < PeerAttested < SignedByPeer`).
- `src/mcp/tools/recall.rs:433` — `latest_link_attest_level_many` (batched `IN(...)`; currently HTTP-handler-only).
- `src/mcp/tools/recall.rs:768` — the MCP `scored_memories` closure that calls `decorate_memory` → `latest_link_attest_level` → `db::get_links` **per row** (the regression to fix in T0).
- `src/models/memory.rs:832` — `confidence_tier()` (pure mapping; the tier model). `memory.rs:620–629` — `effective_expires_at`/expiry path. `memory.rs:227` — `ConfidenceSource` enum.
- `src/storage/mod.rs:2952` — the recall score SQL (ORDER BY). `storage/mod.rs:667` — the federation same-key merge `confidence = MAX(...)` (context: grow-only; why B1 is deferred).
- `tests/bias_displacement_invariants_2_6.rs` — determinism + vendor-blindness invariants. `tests/confidence_tier.rs` — existing tier-filter tests.

## 3. Tasks (build in this order; each its own commit, each green before the next)

### T0 — Prereq: kill the per-row link round-trip on the MCP recall path
**Why first:** T1 adds provenance composition to `decorate_memory`; if the MCP closure still calls `get_links` per row (`recall.rs:768`), piling on ships a day-one N-round-trip regression that blows §9.6.
**Do:** migrate the MCP `scored_memories` path to the batched `latest_link_attest_level_many` (`recall.rs:433`) already used by the HTTP handler — one batched `IN(...)` for the top-K, then decorate from the prefetched map.
**Done when:** MCP recall makes O(1) link queries for K rows (not O(K)); `bench --baseline` shows recall p95 flat-or-better; all recall tests green.

### T1 — C1a: emit `provenance_tier` in `decorate_memory` (§2.5)
**Do:** add a `provenance_tier` field to the decorated object, composed **purely** from already-fetched data: `confidence_source` (`memory.rs:227`) + `signing_agent`/attestation + the `attest_rank` ladder (`recall.rs:402–422`). Surface a small ordered enum (e.g. `signed_peer > curator_derived > self_signed > unsigned_caller`); name the mapping as a const, no inline literals. **No new query** (uses the T0 prefetched attest map). Gate behind the existing `verbose_provenance` default (already `true`).
**Done when:** every recall row carries `provenance_tier`; value matches the attest ladder; zero added queries; unit test asserts tier for each `ConfidenceSource`/attest combination.

### T2 — A1: route `session_start` through `decorate_memory`
**Do:** make the `session_start` recall path return rows via `decorate_memory` so `provenance_tier`/`confidence_tier`/`freshness_state` are uniform across MCP / HTTP / session_start (today session_start bypasses the decorator).
**Done when:** session_start output carries the same decoration fields as MCP recall; no latency regression (session_start is a `db::list`, still O(1) decoration over top-K).

### T3 — A2: make the `confidence_tier` filter non-silent
**Do:** when the `confidence_tier` recall filter drops rows, surface `meta.confidence_filtered_out` (count) + `meta.had_filtered_candidates` (bool) so a caller asking for `confirmed` and getting `count:0` can tell "no memory" from "all below your bar." Filter + tests already exist (`tests/confidence_tier.rs`); this is a meta-field addition.
**Done when:** the meta fields are present and correct; existing tier-filter tests extended to assert them.

### T4 — D1-anchor: deterministic scheduled-fact recompute
**Do:** for claims with an anchor timestamp (scheduled facts), recompute current validity as a **pure function** in the freshness path (`recall.rs:352` / `effective_expires_at`, `memory.rs:620–629`) under `AI_MEMORY_CONFIDENCE_DECAY` — recompute from the anchor instead of exp-decaying, mirroring `freshness_state`. **No DB, branch-free, no learned model.** Quantize any "now" to a named as-of bucket so determinism (Invariant 1) holds.
**Done when:** a scheduled-fact memory reports validity recomputed from its anchor deterministically; determinism invariant green.

## 4. Explicitly OUT of scope for this lane (do NOT build)
- **B1** contradiction down-weight, **C1b** provenance-weighted contradiction → **v0.9**, gated on #1706 + §11.4.D. (Design of record: signed, append-only, model-digest-bound CvRDT contradiction-evidence + read-time recompute — never an in-place decrement of the grow-only `MAX`-merged scalar. Do not implement now.)
- **B2** `confidence_envelope`/`all_below_confirmed`, **D2** unknown-mass display, reported-vs-true tri-display → **sibling repo (§13)**.
- Any **learned calibration** (Beta/Cox/Platt/`J(Θ)`), any resurrection of `confidence::derive()` or `calibrate_from_shadow` as a producer, any consensus→confidence write. **Forbidden.**
- The **recall-feedback loop** itself (#1706/#1707/#1710) — invariants already posted there; do not touch.

## 5. Quality gates (must all pass before opening the PR)
```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo test --test bias_displacement_invariants_2_6      # determinism + vendor-blindness
cargo test --test confidence_tier                       # tier filter + new meta fields
cargo test --test postgres_schema_parity                # only if any schema touched (prefer none)
cargo llvm-cov --fail-under-lines 92
ai-memory bench --baseline performance/baseline.json    # recall p95 within 10%
```
Plus: CHANGELOG entry naming **§2.5 attested** with the `recall.rs` code anchors (§17 gate). Update `docs/` only if a public surface field changed (the new `provenance_tier`/meta fields → API_REFERENCE).

## 6. Acceptance criteria (definition of done for the v0.8.0 lane)
1. MCP recall, HTTP recall, and session_start all return `provenance_tier` (+ existing `confidence_tier`/`freshness_state`) uniformly, composed from signed/attested evidence, with **zero added per-read DB queries** and **no LLM on the read path**.
2. The `confidence_tier` filter is non-silent (`confidence_filtered_out` + `had_filtered_candidates`).
3. Scheduled-fact validity is recomputed deterministically from an anchor (D1-anchor).
4. `m.confidence` is untouched as a stored value and unchanged in its ranking contribution; recompute is decoration-only.
5. All §5 gates green, including `bias_displacement_invariants_2_6` and `bench --baseline` (no recall p95 regression).
6. CHANGELOG declares §2.5 with anchors. PR references #1709 and #1715.

## 7. Working discipline
- **Verify anchors via codegraph before editing** (line numbers drift). Answer architecture/trace questions with one `codegraph_explore` call, not grep loops.
- **One commit per task (T0→T4), each green before proceeding.** Conventional, minimal diffs that read like the surrounding code.
- **Attest your decisions:** store substrate-design decisions/gotchas to ai-memory as you go (signed), per repo discipline.
- **Branch off `release/v0.8.0`;** do not commit to a release branch directly — open a PR targeting the EPIC's integration branch per repo CODEOWNERS/AI_DEVELOPER_WORKFLOW.md. Human approves all merges.
- If any constraint in §1 cannot be satisfied (e.g. a task would require an LLM on the read path or a confidence write), **stop and surface it as structured data** (a typed blocker note on #1709) rather than working around it.

## 8. References
- EPIC: #1709. Source assessment: #1715 (verdict comment 4720476369, full per-lens findings 4720479690).
- Recall-feedback homes: #1706 (v0.9 shadow), #1707 (v0.9 conditional live), #1710 (ledger population).
- ROADMAP: §2.5 (attested), §3/§5 (scope test), §9.6 (perf budgets), §11.4.D (model-signature chain), §13 (sibling repos), §17 (per-release property-anchor gate). Moonshot §2.6.1 (bias-displacement invariants).
