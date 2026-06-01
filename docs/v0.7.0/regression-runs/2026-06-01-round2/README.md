# v0.7.0 #1182 — Round 2 A2A Regression (reproducibility confirmation, 2026-06-01)

Operator directive (2026-05-31): *"Do a 2nd round of A2A testing once the
1st round goes 100% Green."* Round 1 (#1182) closed 100% GREEN; this is the
independent re-run off a second pristine rig restart to confirm the result
is reproducible and stable — not a one-shot.

Branch: `release/v0.7.0`. Same pm-v3.2 NO-FAIL discipline as #1182.

## 1. Pristine baseline (verified — second wipe)

The `infra/lan-parity-test` rig was fully recreated again
(`docker compose down -v` + `up -d`) — all five volumes wiped
(`pg-age-data`, `ic-parity-alice-keys`, `ic-parity-alice-audit`,
`ic-parity-bob-keys`, `ic-parity-bob-audit`) so zero round-1 state leaks
into round 2. All three containers reached `healthy`.

| Check | Result |
|---|---|
| Containers healthy (alice / bob / pg-age) | 3 / 3 |
| PG extensions | `age`, `vector` present |
| LLM backend (alice `doctor`) | `openrouter` · `google/gemma-4-26b-a4b-it` · `https://openrouter.ai/api/v1` |
| A2A mesh reach `alice → ic-parity-bob:19077` | 401 (TCP-reachable + HMAC-secured — unauthenticated GET rejected by design) |
| A2A mesh reach `bob → ic-parity-alice:19077` | 401 (same) |
| Postgres reach `127.0.0.1:15432` | OK |

## 2. Regression results

### Domain 1 — default-feature (sqlite) shipping build

**GREEN.** `AI_MEMORY_NO_CONFIG=1 cargo test` (default features), exit 0.
**7,458 passed / 0 failed / 16 ignored.** Identical to the round-1 post-fix
retest — bit-for-bit reproducible.

Log: `.local-runs/round2-domain1-sqlite-2026-06-01T00-26-51Z.log`.

### Domain 2 — Postgres + Apache AGE SAL-parity (`--features sal,sal-postgres`)

**GREEN.** `cargo test --features sal,sal-postgres --release`, exit 0.
**8,494 passed / 0 failed / 37 ignored** against the freshly-wiped pg-age
container. This is **+1** vs round-1's 8,493 — the extra test is the #1445
regression test (`http_expand_query_success_envelope_uses_expanded_terms_key`),
which landed *after* round-1's Domain 2 run, so round 2 is the first
postgres-feature build to compile it.

Log: `.local-runs/round2-domain2-pgage-2026-05-31T23-50-37Z.log`.

### Combined: **15,952 passed / 0 failed**

In both domains the lone `ERROR` log line is the same deliberate
`governance::deferred_audit` mock-sink fault-injection test (configured
panic exercising the supervisor-restart path) — the test passed (failed=0).

## 3. Findings

**None.** Round 2 surfaced zero new defects. No GH issues filed; the
pm-v3 file→fix→retest loop was a no-op this round. The four round-1 defects
(#1444 / #1445 / #1446 / #1447) remain closed.

## 4. Verdict

Round 2 confirms the #1182 result is **reproducible and stable** across an
independent pristine rig. Combined 15,952 passed / 0 failed; all green; no
new defects. v0.7.0 regression posture holds.

| Run | Domain 1 (sqlite) | Domain 2 (pg+AGE) | Combined | New defects |
|---|---|---|---|---|
| Round 1 (#1182) | 7,458 / 0 / 16 | 8,493 / 0 / 37 | 15,951 / 0 | 4 (all fixed 1:1) |
| Round 2 | 7,458 / 0 / 16 | 8,494 / 0 / 37 | 15,952 / 0 | 0 |
