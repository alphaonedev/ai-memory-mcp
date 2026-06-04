# Work Prompt — v0.7.0 Enhancement (a): Config-Driven Postgres Pool Sizing + Doc-Drift Fix

> **Document type:** Operational AI-NHI work prompt. The operator feeds this
> document back to the agent to BEGIN the work. Each task below carries a
> self-contained starter prompt. Execute tasks in order; QC-gate every task;
> open ONE PR; merge + push to `release/v0.7.0` when the PR is complete.
>
> **Campaign:** ai-memory v0.7.0 ship-hardening. Namespace `ai-memory-mcp`.
> **Scope owner:** `alphaonedev` (sole-authority rule applies — no external code injection, ever).
> **Provenance:** operator directive 2026-06-04; design memory `1b9bdfe0`.

---

## FIRST READ — non-negotiable engineering discipline (re-read before EVERY task)

1. **USE VARIABLES AND CONSTANTS. NEVER HARDCODE LITERALS. EVER.**
   - Every numeric default lands as a named `const` (e.g. `DEFAULT_MIN_CONNECTIONS`),
     never an inline `2` / `16` / `30` at a call site.
   - Every env-var name lands as a named `const` (e.g. `ENV_PG_POOL_MAX`), never an
     inline `"AI_MEMORY_PG_POOL_MAX"` string literal at the read site — mirror the
     existing `ENV_MAX_*` constants used by `resolve_limits()` (`src/config.rs`).
   - Time values use the `SECS_PER_HOUR` / `SECS_PER_DAY` / `SECS_PER_WEEK` named
     constants from `src/lib.rs` — never `3600` / `86400` / `604800`. The
     `scripts/check-vendor-literals.sh` gate HARD-BLOCKS the raw `Duration::from_secs`
     magic numbers.
   - Vendor identifiers (`postgres`, etc.) stay in the existing `crate::llm::*` /
     `crate::config::*` carve-outs; do not scatter new literals. This is enforced by
     `scripts/check-vendor-literals.sh` (pm-v3.1, CLAUDE.md §"Lint gates").
   - **The bar:** a reviewer grepping the diff for bare numeric/string literals at
     logic sites finds NONE. Defaults and names are all `const`-declared with a
     doc-comment explaining the value.

2. **Mirror the existing precedent, do not invent a new shape.** The connection-level
   `statement_timeout` knob (`postgres_statement_timeout_secs`) is the EXACT template:
   - AppConfig flat field: `src/config.rs:2724`
   - Serialization round-trip: `src/config.rs:2911`
   - Default-fill test: `src/config.rs:7442`
   - Connect-chain threading: `src/store/postgres.rs:558` → `:582` → `:594`
     (`connect_with_dim_and_timeout`), pool built at `:626`
   - Daemon wiring: `src/daemon_runtime.rs:2670` (param) → `:2691` (resolve) → `:3617` (call)
   Follow this shape field-for-field. No new `[postgres]` config section (YAGNI) —
   the resolver + flat-field + env-var ladder already exists and is the precedent.

3. **Precedence ladder is universal:** `CLI flag > AI_MEMORY_* env > config.toml > compiled default`.
   Non-positive / unparseable values at any layer fall through to the next layer
   (copy the `env_pos_*` filter pattern from `resolve_limits()`).

4. **Every task is QC'd** (four cargo gates + two script gates) before commit.
   **Maximum code line coverage** — every new branch gets a test. **One PR**, merged
   and pushed to `release/v0.7.0` when complete.

5. **Banned phrases** (CLAUDE.md prime directive): "non-blocking", "out of scope",
   "DEFER-TO-V080", "operator should…", "I lack…". Discovery → fix → close is one
   workflow.

---

## Background — what (a) is and why

`docs/enterprise-deployment.md §5.6` documents two operator knobs —
`AI_MEMORY_PG_POOL_MIN` / `AI_MEMORY_PG_POOL_MAX` (claimed `min=2 max=16`) — and
points at `src/store/postgres.rs:468`. **Neither env var is implemented.**
`grep -rn AI_MEMORY_PG_POOL src/` returns ZERO hits. The pool is hardcoded:

```rust
// src/store/postgres.rs:497-498
const DEFAULT_MAX_CONNECTIONS: u32 = 16;
const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
// pool built at :626-628 — max_connections(DEFAULT_MAX_CONNECTIONS),
// acquire_timeout(DEFAULT_ACQUIRE_TIMEOUT), NO min_connections set (sqlx default 0).
```

So (a) is BOTH a feature (make the pool size config-driven so a module/daemon can be
tuned without a recompile) AND a doc/code-drift fix (the docs promise a knob the
binary does not read). It is cheap, low-risk v0.7.0 ship-hardening: it mirrors an
existing precedent exactly and touches the postgres adapter + config resolver only.

**Out of THIS prompt's scope (these are v0.8.0, tracked separately):** the
load-shed/admission-control layer on `build_router` (enhancement b), PgBouncer
deployment, and the module-model consolidation contract.

---

## Task graph

| Task | Title | Files | Est. |
|---|---|---|---|
| T1 | Named pool-default constants + `PoolConfig` carrier | `src/store/postgres.rs` | S |
| T2 | Thread `PoolConfig` through the connect chain | `src/store/postgres.rs` | M |
| T3 | AppConfig fields + `resolve_pg_pool()` resolver + env consts | `src/config.rs` | M |
| T4 | Wire resolved pool config into daemon `build_store_handle` | `src/daemon_runtime.rs` | S |
| T5 | Fix doc-drift (postgres.rs docstring + enterprise-deployment.md + config example + CLAUDE.md env table) | docs + `src/config.rs` table | S |
| T6 | Tests: precedence + resolver + pool-build + doc-name-match | `tests/config_precedence.rs`, unit mods | M |
| T7 | QC gates + coverage + commit + PR + merge + push to release/v0.7.0 | — | S |

---

### T1 — Named pool-default constants + `PoolConfig` carrier

**Starter prompt:**
> RE-READ the FIRST READ block. In `src/store/postgres.rs`, near the existing
> `DEFAULT_MAX_CONNECTIONS` / `DEFAULT_ACQUIRE_TIMEOUT` constants (`:497-498`), add a
> named `const DEFAULT_MIN_CONNECTIONS: u32 = 2;` with a doc-comment matching the
> `min=2` value the enterprise deployment guide documents. Define a small
> `#[derive(Clone, Copy, Debug)] pub struct PoolConfig { pub max_connections: u32,
> pub min_connections: u32, pub acquire_timeout_secs: u64 }` with a `Default` impl
> that reads from the three named constants (acquire-timeout default derived from
> `DEFAULT_ACQUIRE_TIMEOUT.as_secs()` — do NOT re-type `30`). Add a `#[must_use] pub
> const fn` or `Default`-based constructor. NO inline literals: every field default
> traces to a named `const`. Delete the stale `PostgresStore::with_pool_options`
> doc-reference at `:494-496` (that method does not exist) and replace it with a
> reference to the real `PoolConfig` carrier. Run `cargo fmt` + `cargo clippy
> -- -D warnings -D clippy::pedantic` and confirm clean before reporting.

**Done when:** `PoolConfig` exists, all defaults are `const`-sourced, the stale
docstring is gone, clippy-pedantic clean.

---

### T2 — Thread `PoolConfig` through the connect chain

**Starter prompt:**
> RE-READ the FIRST READ block. The connect chain is
> `connect` → `connect_with_timeout` → `connect_with_dim` →
> `connect_with_dim_and_timeout` (the fully-parameterised entry, `:594`), plus the
> `_auto_migrate` sibling (`:905`). Extend the fully-parameterised entry to accept a
> `PoolConfig` (add it as the trailing parameter, exactly as `statement_timeout_secs`
> was threaded through as a trailing parameter in the M4 change). At the pool-build
> site (`:626`), replace `.max_connections(DEFAULT_MAX_CONNECTIONS)` /
> `.acquire_timeout(DEFAULT_ACQUIRE_TIMEOUT)` with values read from the passed
> `PoolConfig`, and ADD `.min_connections(pool.min_connections)` (currently absent —
> this is the documented `min=2` that never shipped). Convert
> `acquire_timeout_secs` → `Duration` via `Duration::from_secs(...)` on the config
> value (the value is a named field, not a literal). Preserve the existing
> shorter-arity entry points by having them pass `PoolConfig::default()`. Keep the
> `after_connect` statement_timeout/lock_timeout hook exactly as-is. fmt + clippy
> pedantic clean.

**Done when:** the pool honors `PoolConfig`; `min_connections` is now set; all
existing call sites compile via `PoolConfig::default()`; gates clean.

---

### T3 — AppConfig fields + `resolve_pg_pool()` resolver + env consts

**Starter prompt:**
> RE-READ the FIRST READ block. In `src/config.rs`, add three flat AppConfig
> `Option` fields mirroring `postgres_statement_timeout_secs` (`:2724`) field-for-field
> (declaration + serialization round-trip near `:2911` + default-fill test near
> `:7442`): `postgres_pool_max_connections: Option<u32>`,
> `postgres_pool_min_connections: Option<u32>`, `postgres_acquire_timeout_secs:
> Option<u64>`, each with a doc-comment. Add named env-name constants alongside the
> existing `ENV_MAX_*` consts: `ENV_PG_POOL_MAX = "AI_MEMORY_PG_POOL_MAX"`,
> `ENV_PG_POOL_MIN = "AI_MEMORY_PG_POOL_MIN"`, `ENV_PG_ACQUIRE_TIMEOUT_SECS =
> "AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS"` — the first two names MUST byte-match the
> names already documented in `enterprise-deployment.md §5.6`. Write
> `pub fn resolve_pg_pool(&self) -> crate::store::postgres::PoolConfig` modeled on
> `resolve_limits()` (`:6089`): reuse the `env_pos_*` positive-filter helpers, apply
> the `env > config > compiled-default` ladder per field, and source every default
> from the `PoolConfig::default()` named constants — NO numeric literals in the
> resolver body (copy the "no numeric literals live in this resolver" discipline from
> the `resolve_limits` doc-comment). fmt + clippy pedantic clean.

**Done when:** three fields + three env consts + `resolve_pg_pool()` exist; env names
match the docs; resolver has zero numeric literals; gates clean.

---

### T4 — Wire resolved pool config into daemon `build_store_handle`

**Starter prompt:**
> RE-READ the FIRST READ block. In `src/daemon_runtime.rs`, `build_store_handle`
> (`:2667`) currently receives `postgres_statement_timeout_secs` and resolves it at
> `:2691`. Add a `pool: PoolConfig` parameter (resolved by the caller via
> `app_config.resolve_pg_pool()` — see the `:3617` call site that already passes
> `app_config.postgres_statement_timeout_secs`). Pass `pool` into the
> fully-parameterised `connect_*` entry points for BOTH the auto-migrate branch
> (`:2704`) and the plain branch (`:2714`). Update the `tracing::info!` lines to log
> the resolved `max`/`min`/`acquire_timeout` alongside the existing
> `statement_timeout` so operators see which pool sizing won. Keep the
> `#[cfg(not(feature = "sal-postgres"))]` and `None` arms compiling (add `let _ =
> pool;` where the timeout already has one). fmt + clippy pedantic clean.

**Done when:** the daemon resolves + threads `PoolConfig` end-to-end; the boot log
shows resolved pool sizing; all cfg arms compile; gates clean.

---

### T5 — Fix doc-drift (the second half of (a))

**Starter prompt:**
> RE-READ the FIRST READ block. Reconcile every doc surface to the now-real knobs:
> (1) `docs/enterprise-deployment.md §5.6` — correct the stale
> `src/store/postgres.rs:468` line reference to the real `PoolConfig` / resolver
> location, and confirm the `min=2 max=16` + env-var-name prose matches the shipped
> defaults and `ENV_PG_POOL_*` names. (2) Add `AI_MEMORY_PG_POOL_MAX`,
> `AI_MEMORY_PG_POOL_MIN`, `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` rows to the
> Environment Variables table in `CLAUDE.md` (and the in-code env table if one
> mirrors it) with type/default/surface/class columns matching the existing rows —
> defaults stated as the named constants, class `config`. (3) Add a commented
> `# postgres_pool_max_connections = 16` / `min` / `acquire_timeout_secs` example to
> the default config template (`write_default_if_missing`, `src/config.rs:6165`).
> (4) Confirm NO remaining reference to the nonexistent `with_pool_options` anywhere
> (`grep -rn with_pool_options`). Per the prime directive, doc drift is a real
> defect — this task closes it.

**Done when:** `grep -rn with_pool_options` is empty; the env table + deployment
guide + config template all describe the real, shipped knobs; env-var names byte-match.

---

### T6 — Tests: precedence + resolver + pool-build + doc-name-match

**Starter prompt:**
> RE-READ the FIRST READ block. Maximize coverage on every new branch:
> (1) In `tests/config_precedence.rs`, add `test_pg_pool_env_overrides_config` and
> `test_pg_pool_config_overrides_default` and `test_pg_pool_zero_falls_through`
> (a `0`/negative env or config value must fall through to the next layer, never
> clamp the pool to 0) — mirror the existing `[limits]` precedence tests.
> (2) Unit-test `resolve_pg_pool()` directly for all three fields across the full
> ladder (env > config > default), asserting the resolved `PoolConfig` values.
> (3) Add a `PoolConfig::default()` test asserting it equals the named constants
> (`DEFAULT_MAX_CONNECTIONS` / `DEFAULT_MIN_CONNECTIONS` / `DEFAULT_ACQUIRE_TIMEOUT`).
> (4) Add a doc-name-match guard test asserting `ENV_PG_POOL_MAX` /
> `ENV_PG_POOL_MIN` string values equal the names the deployment guide documents
> (pin the drift so it can never recur). If a live `AI_MEMORY_TEST_POSTGRES_URL` is
> available, add a gated integration test asserting the pool actually opens with the
> resolved `max_connections`. Run `AI_MEMORY_NO_CONFIG=1 cargo test` green.

**Done when:** every new branch is covered; precedence + zero-fallthrough +
default-equality + doc-name-match tests pass; full suite green.

---

### T7 — QC gates + coverage + commit + PR + merge + push

**Starter prompt:**
> RE-READ the FIRST READ block. Run the full gate set on a fresh build:
> `cargo fmt --check`; `cargo clippy --all-targets --features sal,sal-postgres --
> -D warnings -D clippy::all -D clippy::pedantic`; `AI_MEMORY_NO_CONFIG=1 cargo test
> --features sal,sal-postgres`; `cargo audit`; `bash scripts/check-vendor-literals.sh`
> (+ `--self-test`); `bash scripts/qc-codegraph-precheck.sh`. Then run the
> per-module coverage check (`bash coverage/check-thresholds.sh
> coverage/thresholds.toml <current.json>`) and confirm `store/postgres.rs` +
> `config.rs` coverage did not regress — RAISE the floor if the new tests lifted it
> (Lane 2 discipline: floors rise, never fall). Stage EXPLICIT paths only (no
> `git add -A`). Commit grouped by intent:
> `feat(config): config-driven postgres pool sizing (AI_MEMORY_PG_POOL_*)` and
> `docs: reconcile pool-sizing drift in enterprise-deployment + env table`. Every
> commit ends with `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.
> Open ONE PR targeting `release/v0.7.0` with the AI-involvement section, a Summary
> citing the doc-drift defect closed, and a Test plan checklist. When the PR is
> complete and gates are green, merge and push to `release/v0.7.0` (pre-approved per
> the commit/push policy). Report the PR URL + merge SHA.

**Done when:** all six gates green, coverage non-regressed (raised where lifted),
PR opened + merged + pushed to `release/v0.7.0`, PR URL + SHA reported.

---

## Definition of done (whole prompt)

- [ ] Pool size is config-driven via `AI_MEMORY_PG_POOL_MAX` / `_MIN` /
      `_ACQUIRE_TIMEOUT_SECS` + `config.toml` + compiled defaults, full precedence ladder.
- [ ] `min_connections` is now actually set (was silently 0).
- [ ] Zero new hardcoded literals at logic sites — all defaults + env names are `const`.
- [ ] Doc-drift closed: no `with_pool_options` refs; env table + deployment guide +
      config template describe the real knobs; env-var names byte-match a guard test.
- [ ] Every new branch covered; coverage floors raised where lifted.
- [ ] Six QC gates green; one PR merged + pushed to `release/v0.7.0`; URL + SHA reported.
