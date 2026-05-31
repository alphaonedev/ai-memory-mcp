# v0.7.0 #1182 — Final Testing off Pristine Clean Baseline (2026-05-31)

NO FAIL MISSION final regression run. Operator-approved AI-NHI autonomous
campaign: pristine rig restart → run all testing off the clean baseline →
file/fix/PR/merge/retest 100% of issues 1:1 → document all results →
publish to Evidence Hub.

Branch: `release/v0.7.0`. Base at campaign start: `f869eae8c`.

## 1. Pristine baseline (verified)

The `infra/lan-parity-test` rig was fully recreated (`docker compose down -v`
+ `up -d`) — all volumes wiped (pg-age data, alice/bob keys + audit) so no
prior-run state leaks into final tests. All three containers reached
`healthy` in 33s.

### LLM / model wiring — all ai-memory surfaces → OpenRouter Gemma 4 26B

| Surface | Backend | Model | Base URL | Reachability |
|---|---|---|---|---|
| Host ai-memory (`doctor`) | `openrouter` | `google/gemma-4-26b-a4b-it` | `https://openrouter.ai/api/v1` | 200 / 71ms |
| Direct API probe | `openrouter` | `google/gemma-4-26b-a4b-it` → `-20260403` (DekaLLM) | same | 200 / 0.88s, returned `OPENROUTER_OK` |
| Container `alice` (in-container) | `openrouter` | `google/gemma-4-26b-a4b-it` | alias default | 200 / 0.11s |
| Container `bob` (in-container) | `openrouter` | `google/gemma-4-26b-a4b-it` | alias default | 200 / 0.10s |

`OPENROUTER_API_KEY` is present inside each docker instance (sourced from
this node's `~/.env` at compose up). `IronClaw` product (separate) = xAI
Grok 4.3; the lan-parity rig runs the `ai-memory` binary → OpenRouter.

### Substrate tier / federation / storage

| Item | alice | bob | pg-age |
|---|---|---|---|
| Feature tier | autonomous | autonomous | — |
| Embedder | nomic-embed-text | nomic-embed-text | — |
| A2A peer reach | alice→bob 200 | bob→alice 200 | — |
| Status | Up, healthy | Up, healthy | Up, healthy |
| PG extensions | — | — | `age`, `vector` present |

### Rig topology

| Container | Role | Port (host→ctr) | Store schema |
|---|---|---|---|
| `ai-memory-lan-parity-alice` | A2A peer A | `127.0.0.1:19180→19077` | pg-age `ic_alice` |
| `ai-memory-lan-parity-bob` | A2A peer B | `127.0.0.1:19181→19077` | pg-age `ic_bob` |
| `ai-memory-lan-parity-pg-age` | Postgres 16 + AGE 1.6 + pgvector | `127.0.0.1:15432→5432` | — |

## 2. Findings (filed → fixed → closed 1:1)

| # | Severity | Finding | Fix | Status |
|---|---|---|---|---|
| [#1444](https://github.com/alphaonedev/ai-memory-mcp/issues/1444) | hygiene (C8) | Stale `for_admin` allowlist entry `src/handlers/power.rs:ai:http-internal` (bypass removed by #945 admin-gate hardening) | Pruned stale line; C8 precheck clean | CLOSED — commit `4aaa2d1b4` |
| [#1445](https://github.com/alphaonedev/ai-memory-mcp/issues/1445) | low (3-surface parity) | HTTP `POST /api/v1/expand_query` emitted `{expansions, original}` while MCP/CLI emit `{original, expanded_terms}` — envelope-key divergence across surfaces | Renamed HTTP handler key to `expanded_terms`; added regression test asserting both directions; corrected `expand.rs` DRY-contract docstring | CLOSED — commit `a37cdea24` |
| [#1446](https://github.com/alphaonedev/ai-memory-mcp/issues/1446) | low (doc drift) | `CLAUDE.md` CLI subcommand counts stale (78/80) after #1443 `Expand` landed (SSOT = 79/81) | Updated both CLI-interface + Key-Modules rows to 79/81; appended `Expand` (#1443) to subcommand-growth history | CLOSED — commit `3c68d174a` |

### 2.1 QC audit cycle (pm-v3.2 NO-FAIL-MISSION closure)

Closure requires THREE independent codegraph-driven QC audits all reporting
`ZERO-DEFECTS-CONFIRMED` (asymmetric — a single `REMAINING-VIOLATIONS-FOUND`
reopens the gate).

| Audit | First pass | Action | Re-audit |
|---|---|---|---|
| A | ZERO-DEFECTS-CONFIRMED | — | — |
| B | REMAINING-VIOLATIONS-FOUND (#1445 envelope-key, #1446 doc drift) | filed → fixed → gated → closed 1:1 | ZERO-DEFECTS-CONFIRMED |
| C | ZERO-DEFECTS-CONFIRMED | — | — |

All three audits clean after the B remediation → asymmetric closure condition
satisfied.

## 3. Regression results

### Domain 2 — Postgres + Apache AGE SAL-parity (`--features sal,sal-postgres`)

**GREEN.** `cargo exit code: 0`. **8493 passed, 0 failed, 37 ignored**
across 331 test binaries, against the pristine pg-age container
(`AI_MEMORY_TEST_POSTGRES_URL=postgres://…@127.0.0.1:15432/ai_memory_test`).
Covers the postgres-gated A2A / federation / governance / store-parity
suites (`federation_postgres_fanout`, `governance_postgres_inheritance`,
`postgres_schema_parity`, `serve_postgres_handler_parity`,
`governance_pre_write_postgres_parity`, `a2a_campaign_round1::A2A-7`, …).

Note: one `ERROR` line in the log is a deliberate fault-injection test
(`governance::deferred_audit` mock-sink configured panic exercising the
supervisor-restart path) — the test passed (failed=0).

Log: `.local-runs/lan-parity-2026-05-31T22-17-47Z.log`.

### Domain 1 — A2A + default-feature (sqlite) shipping-build suite

**GREEN.** `AI_MEMORY_NO_CONFIG=1 cargo test` (default features), exit 0.
**7457 passed, 0 failed, 16 ignored** across 331 test binaries. No compile
errors/warnings. Covers the in-process A2A campaign
(`a2a_campaign_round1` A2A-1…A2A-8), `fold_a2a1_6_remaining_substrate`,
`governance_a2a_rules`, the `federation_*` suite, and
`mcp_schema_handler_parity`.

Log: `.local-runs/domain1-default-<ts>.log`.

### Post-fix retest (after #1445 / #1446)

**GREEN.** Default-feature `cargo test` re-run after the #1445 envelope-key
fix (which added the `http_expand_query_success_envelope_uses_expanded_terms_key`
regression test) and the #1446 doc-only change. `cargo exit code: 0`.
**7458 passed, 0 failed, 16 ignored** (+1 = the new regression test). One
`ERROR` line in the log is the same deliberate `governance::deferred_audit`
mock-sink fault-injection test (configured panic exercising the
supervisor-restart path) — the test passed (failed=0).

Log: `.local-runs/retest-1445-1446-2026-05-31T23-31-29Z.log`.

## 4. Ship gates (non-cargo)

| Gate | Result |
|---|---|
| `scripts/check-vendor-literals.sh` | PASS |
| `scripts/qc-codegraph-precheck.sh` (C8) | OK (for_agent 0, for_admin 8), no WARN after #1444 |
