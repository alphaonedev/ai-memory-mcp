---
layout: doc
---
# AI NHI Build Prompt — Unify the `private` Visibility Predicate + Durable Ownership + Namespace Required-Scope (§2.2)
### v0.8.0 EPIC #1709 fold-in · issue #1720 · `security-high` cross-tenant leak fix

> **Feed this verbatim to the Claude Code CLI loop driving v0.8.0 EPIC #1709.**
> Scope: close issue #1720 100% — collapse the three divergent `scope=private` predicates onto one owner-keyed canonical, make ownership durable, add namespace required-scope (refuse-only), and decide the curator posture. This is a **security-correctness** lane: a confirmed cross-tenant private-memory leak on the recall+search paths. Build A→B→C→D in order; do **not** build the C-alt coercion variant (deferred).

---

## 0. Role & mission

You are an autonomous AI NHI engineer inside the `ai-memory` substrate (`/home/fate_two/v07/v07-f5`, branch `release/v0.8.0`), under the v0.8.0 Distributed Coordination Substrate EPIC (#1709). Your mission is to make `scope=private` **mean one thing on every read path** — owner-keyed, matching the canonical `is_visible_to_caller` (#951) — and then make that enforcement **safe to enable** (durable ownership), **configurable per namespace** (refuse-only required-scope), and **leak-free through the curator**.

This strengthens **§2.2 (coherent)**: a `scope=private` row must resolve identically across MCP recall, HTTP recall, search, hybrid (HNSW + linear), list, get, and session_start. It is a hard prerequisite for safe multi-agent **§2.1 (endpoint-resident)** operation. It is a release-blocker independent of property mapping.

> **The confirmed defect (re-verify before trusting):** three implementations of the `private` check exist; two are namespace-keyed (leak), one is owner-keyed (canonical). A `scope=private` row in `fortitude/X` owned by alice is **returned to a different agent bob who shares namespace `fortitude/X`** via recall/search, while `list` correctly hides it.

## 1. Non-negotiable constraints (read before writing any code)

1. **Scope test (ROADMAP §3/§17).** In-scope as **§2.2 coherent** (one private predicate) + prerequisite for §2.1. The CHANGELOG entry MUST name **§2.2** with code anchors (`src/storage/mod.rs`, `src/visibility.rs`) — no property claim without an anchor.
2. **No hardcoded literals (operator HARD RULE).** Every scope/owner string routes through the `MemoryScope` / `META_KEY_SCOPE` / `META_KEY_AGENT_ID` / `META_KEY_TARGET_AGENT_ID` SSOTs (`src/lib.rs:257`, `src/models/namespace.rs`). No inline `"private"` / `"agent_id"` literals in new code; keep the literal CI gate green.
3. **SAL-trait-first + both-backend lockstep (the #1693/#1694 lesson, an EPIC Phase-0 gate).** Any predicate change lands on sqlite AND postgres with parity; `tests/postgres_schema_parity.rs` + `tests/store_parity_gaps.rs` green. No primitive may return 501 on postgres.
4. **Additive, idempotent, reversible schema only.** The new `agent_id_idx` / `target_agent_id_idx` columns are **VIRTUAL GENERATED** (mirror `scope_idx`); `ALTER TABLE ADD COLUMN <virtual generated>` must NOT rebuild the table (assert this — the migration-rebuild-drops-ALL-triggers lesson). Register the version in `src/storage/migration_meta.rs` (the `MIGRATION_LADDER` SSOT) with correct `idempotent`/`reversible`/`data_loss_risk`.
5. **Determinism + perf invariants stay green.** Threading `caller` into the SQL adds one bound parameter, not a new ranking key — id-ranking byte-equality (`tests/bias_displacement_invariants_2_6.rs` Invariant 1) must hold; `ai-memory bench --baseline performance/baseline.json` recall p95 within 10%. Generated columns are projections (no extra round-trips).
6. **Fail-closed on ambiguity.** When `caller` is `Some`, an unowned (`empty agent_id`) `scope=private` row is hidden from a named caller (preserve `empty_owner_blocks_named_caller`). When `caller` is `None`, preserve the documented single-tenant trust-all short-circuit (`?caller IS NULL` / `is_visible` `p.is_none()` / list `caller==None`) — do not silently change the trust-all posture; that flip is an operator decision (Op-0), not a code default.
7. **`target_agent_id` inbox carve-out is load-bearing.** Any owner-keyed rewrite MUST keep `target_agent_id == caller` visible (`inbox_target_can_see_private_row`). Do not regress the inbox.

## 2. Codegraph-anchored map (verify before editing — use codegraph, not grep)

Use the codegraph MCP (`codegraph_explore`, `projectPath="/home/fate_two/v07/v07-f5"`) to confirm each anchor at HEAD.

- `src/visibility.rs:46` — `is_visible_to_caller` (**canonical, owner-keyed**, #951). The target semantics every other path must match. Owner check `:69`, inbox carve-out `:72-77`, default-private `:60`.
- `src/storage/mod.rs:330` — SQL `visibility_clause`; the broken `private` arm is `:340` (`scope_idx='private' AND m.namespace = ?private`). Team/unit/org arms `:341-343` stay namespace-keyed.
- `src/storage/mod.rs:192` — Rust `is_visible` (HNSW branch); broken `Private` arm `:215` (`&mem.namespace == ns`). `matches_subtree` `:222`.
- `src/storage/mod.rs:176` — `compute_visibility_prefixes` (namespace tuple from `as_agent`). **Do not overload this with owner identity** — `caller` (agent_id) is a separate axis; thread it as a new param.
- `src/storage/mod.rs:2929` `recall`, `:2372` `search`, `:8960` hybrid linear-SQL `visibility_clause` call-sites (each ~4 callers — the blast radius). `:2952` recall score SQL (do not touch ordering).
- `src/storage/migrations.rs:1364` — `scope_idx` VIRTUAL GENERATED column (the pattern to mirror). `src/storage/migration_meta.rs` — `MIGRATION_LADDER`.
- `src/identity/mod.rs:238` — `resolve_read_visibility_caller` (env `AI_MEMORY_AGENT_ID` → caller; unset → None → trust-all). `:152-218` — `resolve_agent_id` (PID-suffixed synth at `:184`). `src/mcp/mod.rs:1239/1398/1404` — read dispatchers.
- `src/store/sqlite.rs` (`get`/`list`/`search` SAL) + `src/store/postgres.rs:10262/10450/10508` — adapter read paths; PG `list` owner clause `:10508` is the parity reference.
- `src/mcp/tools/list.rs:237` `private_mem` + tests `caller_*` (the owner-exclusion contract that exists for `list` only — mirror to recall/search).
- `src/store/mod.rs:431` — `CallerContext::for_admin` → `bypass_visibility`. `src/curator/reflection_pass.rs:109` (curator caller) + `:290` (reflection owner stamp `ai:curator`, `src/identity/sentinels.rs:79`).
- Governance (Workstream C): `src/daemon_runtime.rs:3169` pre-write payload builder + `:3229` Decision mapping; `src/store/postgres.rs:8001` PG twin; `src/models/namespace.rs:478` `CorePolicy`/`GovernancePolicy`, `:375` `GovernanceLevel`; `src/handlers/hook_subscribers.rs` `set_namespace_standard`.

## 3. Tasks (build in this order; each its own commit, each green before the next)

### A0 — Confirm the schema gap (no commit)
`codegraph_search agent_id_idx` against the sqlite schema. Expect: present on postgres, **absent on sqlite**. This decides A1.

### A1 — Migration: add owner-index generated columns (sqlite; postgres parity)
Add **VIRTUAL GENERATED** columns mirroring `scope_idx` (`migrations.rs:1364`):
- `agent_id_idx TEXT GENERATED ALWAYS AS (CASE WHEN json_valid(metadata) THEN json_extract(metadata,'$.agent_id') ELSE NULL END) VIRTUAL`
- `target_agent_id_idx` likewise from `$.target_agent_id`
+ partial indexes. Register in `migration_meta.rs`. Postgres: confirm/add the equivalent expression-index parity. **Done when:** migration applies idempotently, table is NOT rebuilt (assert), all triggers survive (trigger suite green), `postgres_schema_parity` green.

### A2 — Rewrite the SQL `private` arm to owner-keyed
At `visibility_clause` (`mod.rs:340`) replace the namespace-equality private arm with:
`scope_idx='private' AND (agent_id_idx = ?caller OR target_agent_id_idx = ?caller)`.
Keep team/unit/org/collective arms unchanged. Add a `?caller` placeholder; keep the `?caller IS NULL → all rows` trust-all short-circuit. **Done when:** clause compiles, placeholder scheme consistent across all three call-sites.

### A3 — Thread `caller` through the SQL read paths
Add `caller: Option<&str>` to `recall` (`:2929`), `search` (`:2372`), hybrid-linear (`:8960`); bind at every call-site. Source `caller` from `resolve_read_visibility_caller()` at the SAL/handler boundary (sqlite SAL + dispatchers `src/mcp/mod.rs`). Keep `as_agent` (namespace) plumbing intact — separate axis. **Done when:** caller flows end-to-end; trust-all (None) and named-caller paths both compile and pass existing tests.

### A4 — Fix the HNSW Rust branch
In `is_visible` (`mod.rs:215`) make the `Private` arm owner-keyed by delegating to canonical `is_visible_to_caller(mem, caller)`; keep team/unit/org local via `matches_subtree`. Thread `caller` into the HNSW branch of `recall_hybrid`. **Done when:** HNSW and linear branches agree for private rows.

### A5 — Anti-re-drift matrix test
One test asserting `visibility_clause` (SQL), `is_visible` (Rust HNSW), and `is_visible_to_caller` (canonical) return identical visibility across the cross-product `(scope ∈ {private,team,unit,org,collective,absent}) × (owner == / != caller) × (namespace == / != caller_ns) × (target == / != caller)`. **Done when:** all three agree on every cell.

### A6 — Cross-namespace leak regression tests
Mirror `caller_non_owner_excludes_cross_agent_private` (today `list`-only) for **recall**, **search**, **hybrid-HNSW**, **hybrid-linear**: agent bob with `as_agent="fortitude/X"` and `caller="bob"` must NOT retrieve alice's `scope=private` row in `fortitude/X`; alice must. Plus a no-scope-insert-excluded-for-non-owner test (pins `scope_idx` default-private → visibility). **Done when:** all green; each fails if A2/A4 is reverted.

### A7 — Postgres parity
Confirm PG recall/search are owner-keyed (PG `list` already is, `postgres.rs:10508`); fix if not. Add the bob/alice parity test to `tests/store_parity_gaps.rs`. **Done when:** identical leak-exclusion behavior on both backends.

### B1 — Durable owner identity
Make the operator owner stamp stable (drop the PID suffix in `resolve_agent_id` `:184` for the operator principal, or require `AI_MEMORY_AGENT_ID`). Document the stable value for `~/.claude.json` env + curator unit. **Done when:** two daemon restarts produce the same owner id for the same principal.

### B2 — `reown` tool + claim-unowned path
New CLI subcommand (e.g. `ai-memory reown --namespace <ns> --to <id> [--claim-unowned]`) that rewrites `metadata.agent_id` on existing rows via the SAL, and claims legacy empty-`agent_id` rows. **Done when:** a dry-run + apply rewrites `fortitude/*` owners; idempotent; both backends.

### B3 — Lockout guard
Startup check: if `AI_MEMORY_AGENT_ID` is set but rows exist owned by a different / pid-suffixed id, warn loudly (config-gated refuse option). **Done when:** enabling enforcement without B2 surfaces a clear pre-flight error, not a silent lockout.

### C1–C5 — Namespace required-scope (refuse-only)
- **C1** add `scope` (+`owner`) to the pre-write governance payload (`daemon_runtime.rs:3169` + PG twin `postgres.rs:8001`).
- **C2** add `required_scope: Option<MemoryScope>` to `CorePolicy` (`namespace.rs:478`) with `#[serde(default)]`; tolerant deserialize.
- **C3** evaluate: effective write scope (absent ⇒ private default) ≠ `required_scope` ⇒ `Decision::Refuse` + `GOVERNANCE_REFUSED`. Accept absent/default-private. **Refuse-only — the hook cannot mutate.**
- **C4** expose in `set_namespace_standard` handler + SDK parity (python/ts namespace-standard body).
- **C5** tests both backends: `scope:shared` into `required_scope=private` ns ⇒ refused; `scope:private`/absent ⇒ allowed.

### D1–D2 — Curator posture
- **D1** decide whether curator (`bypass_visibility=true`, `reflection_pass.rs:109`) may read private namespaces; if not, add a namespace exclusion to autonomy/consolidation passes (or run non-bypass for those).
- **D2** stamp curator-written consolidations (`reflection_pass.rs:290`) with an explicit, intended owner/scope (not accidental `ai:curator`-owned private that leaks on trust-all today and goes operator-invisible once filtering is on).

## 4. Explicitly OUT of scope for this lane (do NOT build)
- **C-alt true silent coercion** (fill absent scope from namespace policy via a new pre-validate mutation stage in `src/storage::insert` + both adapters) — large; deferred unless transparent inheritance becomes a hard requirement. The refuse-only variant (C1–C5) satisfies the security goal.
- **Flipping the trust-all read posture by default** (setting `AI_MEMORY_AGENT_ID` in shipped config) — that is the **Op-0 operator decision**, recorded in the issue, not a code default.
- Team/unit/org hierarchical semantics — they are intentionally namespace-keyed; only `private` is owner-keyed. Do not "fix" them.

## 5. Quality gates (must all pass before opening the PR)
```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo test --test bias_displacement_invariants_2_6      # determinism unchanged
cargo test --test postgres_schema_parity                # new generated columns parity
cargo test --test store_parity_gaps                     # A7 bob/alice PG parity
cargo test visibility is_visible_to_caller              # canonical + new matrix/leak tests
cargo llvm-cov --fail-under-lines 92
ai-memory bench --baseline performance/baseline.json    # recall p95 within 10%
./scripts/check-vendor-literals.sh                      # no-hardcoded-literals gate
```
Plus: CHANGELOG entry naming **§2.2 coherent** with `src/storage/mod.rs` + `src/visibility.rs` anchors (§17 gate). Update `docs/API_REFERENCE` if `reown` or `required_scope` change a public surface.

## 6. Acceptance criteria (definition of done for #1720)
1. All three predicates agree (A5 matrix green); cross-namespace leak excluded on recall/search/hybrid, **both backends** (A6/A7).
2. `target_agent_id` inbox carve-out + `empty_owner_blocks_named_caller` + trust-all-on-None all preserved.
3. Owner stamps durable (B1); `reown` ships (B2); lockout guard active (B3).
4. Namespace `required_scope` (refuse-only) ships, configurable, SDK parity (C1–C5).
5. Curator posture decided + enforced (D1/D2).
6. All §5 gates green incl. determinism + `bench --baseline`; CHANGELOG declares §2.2 with anchors. PR references #1709 and #1720.
7. **Op-0 posture decision** recorded on #1720 (single-operator trust-all vs enforced multi-agent). If enforced, A+B land before any enforcement flip.

## 7. Working discipline
- **Verify every anchor via codegraph before editing** (line numbers drift). Answer trace/architecture questions with one `codegraph_explore`, not grep loops.
- **One commit per task (A1→A7, B1→B3, C1→C5, D1→D2), each green before the next.** Minimal diffs that read like the surrounding code.
- **Order is load-bearing:** A (correctness) before any enforcement; B before flipping `AI_MEMORY_AGENT_ID`; C and D parallelizable after A. Never enable filtering on a buggy predicate or undurable owners.
- This is the canonical-predicate consolidation #951 always intended — leave exactly **one** owner-keyed private check, or a single shared spec the three sites delegate to.
