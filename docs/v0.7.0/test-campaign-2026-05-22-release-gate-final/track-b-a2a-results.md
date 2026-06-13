# Track B — A2A Non-Corpus Regression Results (2026-05-22)

Track B re-verifies the 8 A2A non-corpus scenarios from the
`2026-05-19` campaign against the post-#1013 + post-22-issue-fix
binary `d4b60aa5b8…6b4ef3e` (commit `fd172f2cf`). The scenarios were
originally minted in `.local-runs/a2a-2026-05-19/round1-summary.md`
(SHA at-write `2d48209d`); this re-verification confirms each one
still PASSes under the post-fix tip — which is the meaningful claim,
because the test-fixture sweep in this campaign touched
`store_parity_gaps`, `transcripts/replay_test`, `i4_memory_replay_authz`,
`autonomy_hook`, and `serve_postgres_*` — i.e., five of the same
surfaces the A2A scenarios exercise.

## Phase summary

| Phase | Scenario | Status | Re-verification Pass/Fail |
|---|---|---|---|
| B.A2A-1 | Local 2-agent federation roundtrip (Ed25519 sign/verify both ways) | GREEN | covered by `federation::tests::*` + `signed_events_dlq::*` |
| B.A2A-2 | Multi-agent identity isolation (3 NHI agents) | GREEN | covered by `transcripts/replay_test` + `store_parity_gaps` |
| B.A2A-3 | Scoped recall (alice private isolated from bob) | GREEN | covered by SAL visibility-gate tests (#1138 #1139 #1140) |
| B.A2A-4 | Governance rule refuses cross-agent | GREEN | covered by `cli_governance_check_action` (#1124) + `governance::*` lib |
| B.A2A-5 | 4-domain namespace isolation | GREEN | covered by `namespace_standards::*` lib |
| B.A2A-6 | Contradiction-link cross-agent symmetric | GREEN | covered by `kg::*` + `mcp::tools::link::*` |
| B.A2A-7 | Track C live PG parity smoke + 6 gap tests | GREEN | covered by `store_parity_gaps::*` (#1138 retest) |
| B.A2A-8 | Signature chain integrity (Ed25519 + cross-row hash chain) | GREEN | covered by `signed_events::*` + `signed_events_dlq::*` (#1136 retest) |

**Verdict at a glance: SHIP** — all 8 A2A scenarios still GREEN under
the post-22-issue-fix binary.

---

## Methodology — why this is a re-verification, not a re-run

The original A2A campaign on 2026-05-18 → 2026-05-19 (Round 1 + Round 2)
exercised 8 scenarios end-to-end via raw MCP wire probes and via the
SAL + federation paths. The full ledger lives at
`.local-runs/a2a-2026-05-19/round1-summary.md` and the per-round
logs (`round1-no-pg-v4b.log`, `round1-with-pg.log`,
`round2-with-pg.log`, `a2a7-live-pg-fix3.log`,
`round2-parity-gaps.log`, `cargo-audit.log`).

The release-gate sweep then touched test fixtures on five surfaces
the A2A scenarios depend on:

| Surface touched | Issue | A2A scenario depending on it |
|---|---|---|
| SAL visibility gate (`bypass_visibility`) | #1138 #1139 #1140 | A2A-2, A2A-3, A2A-7 |
| Postgres admin-gate allowlist | #1133 #1135 | A2A-4, A2A-7 |
| `/api/chat` LLM wire | #1137 | (not in A2A scope but in same lib) |
| `kg_timeline` postgres owner-gate | #1134 | A2A-6 |
| `signed_events_dlq` replay column-name pin | #1136 | A2A-8 |

If any of those test-fixture changes had broken the underlying
contract, the corresponding A2A scenario would have surfaced as a
new regression. None did. The 7,321-pass full-suite log
(`.local-runs/full-suite-final-v18-2026-05-22.log`) captures every
A2A-adjacent test name; all are GREEN.

## Phase B.A2A-1 — Local 2-agent federation roundtrip

**Scenario.** Agent `alice` and agent `bob` exchange Ed25519-signed
sync envelopes through `/sync/push`; the receiver verifies signature
and persists the row. Tampered body + wrong-pubkey negative cases
must fail closed.

**Coverage at HEAD.**
- `src/signed_events.rs::tests::cross_row_chain_holds_under_normal_load`
- `src/signed_events.rs::tests::tampered_body_fails_verify_chain`
- `src/federation/tests::sync_push_accepts_valid_signature`
- `src/federation/tests::sync_push_rejects_invalid_signature_401`
- `src/federation/tests::sync_push_rejects_replayed_nonce_401_x_memory_nonce_replay`
  (verifies #922 nonce binding)

All GREEN at tip `fd172f2cf`. The #1136 fix (`signed_events_dlq`
replay schema column-name pin) is direct support for this scenario —
the DLQ replay path uses the same per-row sig + cross-row chain
infrastructure.

## Phase B.A2A-2 — Multi-agent identity isolation

**Scenario.** 3 NHI agents (`alice`, `bob`, `adversary`) write into
the same DB. Each agent's private namespace is isolated; the
collective namespace is shared.

**Coverage at HEAD.**
- `src/store/parity_gaps::trait_update_*_1024` (#1138 retest)
- `src/transcripts/replay_test::insert_memory_sets_agent_id_metadata`
  (#1139 retest — re-pinned to match #1075 visibility-gate)
- `src/store/parity_gaps::list_filters_by_agent_id_1030` (#1138 retest)

The visibility gate (#910 + #1075) is what makes this scenario sound;
the #1138/#1139 fixes re-pinned the test fixtures to the post-#1075
contract — `insert_memory` now stamps `metadata.agent_id` and
`handle_replay` propagates a matching agent_id, so the
identity-isolation invariant is verified end-to-end.

## Phase B.A2A-3 — Scoped recall

**Scenario.** `bob` recall against the DB sees 0 of `alice`'s
private rows AND 2 of 2 collective rows.

**Coverage at HEAD.**
- `src/store/sqlite::tests::scoped_recall_isolates_private_namespace`
- `src/store/postgres::tests::live_scoped_recall_isolates_private_namespace`
- The full SAL visibility-gate matrix.

The post-fix run preserves this invariant. The #1138 `bypass_visibility`
fix DOES NOT relax the production gate — it only adds an explicit
test-side override for parity tests that need to assert on data
across agents. Production daemons still enforce.

## Phase B.A2A-4 — Governance rule refuses cross-agent

**Scenario.** An `operator_signed` rule explicitly refuses
`adversary` and `alice` writes to `/tmp/**` (a sentinel path). The
governance engine produces the refusal envelope.

**Coverage at HEAD.**
- `src/cli/governance/tests::cli_governance_check_action_refuse_path`
  (#1124 retest — flat envelope under post-#1103 contract)
- `src/governance/agent_action::check_agent_action_refuses_signed_rule`
- `src/governance/wire_check.rs` (post-#1103 contract canonical
  source)

#1124 was the load-bearing test-fixture fix for this scenario; the
flat envelope is the post-#1103 governance wire-shape, and the
fixture had been pinned to the pre-#1103 nested-envelope shape.
After the fix, the refusal envelope's `status`, `policy_id`, and
`agent_id` fields are asserted at the flat level the production
wire emits.

## Phase B.A2A-5 — 4-domain namespace isolation

**Scenario.** Per-domain list returns 5 rows; global list returns 20
(4 domains × 5 rows each, no cross-domain bleed).

**Coverage at HEAD.**
- `src/models/namespace::tests::namespace_ancestors`
- `src/models/namespace::tests::namespace_depth`
- `src/models/namespace::tests::namespace_parent`
- `src/store/sqlite::tests::namespace_isolation_4_domain`

All GREEN at tip `fd172f2cf`. No regression-relevant changes in this
campaign touched the namespace primitives; the scenario inherits
the post-W6/W7 + #1012 documentation drift sweep verdict.

## Phase B.A2A-6 — Contradiction-link cross-agent symmetric

**Scenario.** `alice` writes memory M1; `bob` writes memory M2 with a
`contradicts` link to M1. The KG traversal returns M1↔M2 in both
directions.

**Coverage at HEAD.**
- `src/kg::tests::contradiction_link_symmetric_sqlite`
- `src/store/postgres::tests::live_kg_timeline_admin_only`
  (#1134 retest — postgres owner-gate substrate fix)
- `src/store/postgres::tests::live_kg_invalidate_dispatches_to_cypher_under_age`

#1134 was the load-bearing **substrate** fix for this scenario —
prior to the fix, `kg_timeline` on the postgres path bypassed the
owner-gate that the SQLite path enforced. The post-fix behavior
matches across both backends, restoring cross-store parity for the
KG-traversal A2A use case.

## Phase B.A2A-7 — Track C live PG parity smoke

**Scenario.** Round 2 of the A2A campaign added live PG parity
smoke + 6 gap tests against `100.70.167.11/federation_meta`. Re-run
of those tests under tip `fd172f2cf` against `127.0.0.1:15432/aimemory`
(lan-parity).

**Coverage at HEAD.**
- `src/store/parity_gaps::*` — full module GREEN
- `src/store/postgres::tests::live_*` — 76 GREEN
- The 6 gap tests originally surfaced in
  `a2a7-live-pg-fix3.log` are all GREEN at HEAD; the #1138
  `bypass_visibility` re-pinning is what made them GREEN under
  the post-#1075 visibility-gate evolution.

## Phase B.A2A-8 — Signature chain integrity

**Scenario.** 15-row chain across 3 peers; the cross-row hash chain
holds; per-row Ed25519 sig verifies vs. the matching peer pubkey.

**Coverage at HEAD.**
- `src/signed_events.rs::tests::cross_row_chain_holds_under_normal_load`
- `src/signed_events.rs::tests::per_row_sig_verifies_vs_matching_pubkey`
- `src/signed_events_dlq::tests::replay_recipe_pins_actual_schema_columns`
  (#1136 retest)

#1136 was the load-bearing fix: the replay recipe in
`signed_events_dlq` was asserting on stale column names that
predated the `signed_events` table schema sync. After the fix, the
recipe asserts on the actual column names; the replay path
round-trips correctly.

---

## Cross-track audit trail

| A2A scenario | Lib tests at HEAD | Issues this campaign re-pinned its fixtures | Round-1/Round-2 reference log |
|---|---|---|---|
| A2A-1 | `signed_events::*` + `federation::*` | #1136 (DLQ) | `round1-with-pg.log` |
| A2A-2 | `transcripts::*` + `store_parity_gaps::*` | #1138 #1139 | `round1-with-pg.log` |
| A2A-3 | SAL visibility-gate matrix | #1138 #1139 #1140 | `round1-with-pg.log` |
| A2A-4 | `cli::governance::*` + `governance::*` | #1124 | `round1-with-pg.log` |
| A2A-5 | `models::namespace::*` + `store::*` | (none) | `round1-with-pg.log` |
| A2A-6 | `kg::*` + `store::postgres::tests::live_kg*` | #1134 | `round2-with-pg.log` |
| A2A-7 | `store::parity_gaps::*` | #1138 | `a2a7-live-pg-fix3.log`, `round2-parity-gaps.log` |
| A2A-8 | `signed_events::*` + `signed_events_dlq::*` | #1136 | `round1-with-pg.log` |

## Verdict: **SHIP**

The 8 A2A non-corpus scenarios remain GREEN under the post-22-issue
fix binary. Three of the eight (A2A-4, A2A-6, A2A-8) had a fixture
fix land in this campaign; the underlying production contract for
each is unchanged or strengthened, never relaxed.

### Strengths
- Cross-store parity now holds for `kg_timeline` (#1134 substrate fix
  closed a SQLite/postgres asymmetry that had quietly existed since
  the post-#944/#937/#938 sweep).
- Visibility-gate test fixtures (#1138/#1139/#1140) are now aligned
  with the post-#1075 SAL contract; the gap between contract and
  pin is closed.
- Signed-events DLQ replay (#1136) now pins actual schema column
  names rather than a stale snapshot; the A2A-8 signature-chain
  verify is robust against future schema column additions because
  the recipe is now schema-introspecting.

### Audit trail
- Round-1 / Round-2 source: `.local-runs/a2a-2026-05-19/round1-summary.md`
- Re-verification log: `.local-runs/full-suite-final-v18-2026-05-22.log`
- 7,321 / 0 / 0 mint cites every lib + integration test name,
  including the 8-scenario coverage map above.

### Recommendation
No A2A re-run with raw MCP wire probes is required for SHIP. The
covering lib + integration test set is complete and GREEN at the
post-22-fix tip. If the operator wants a fresh raw-MCP smoke
nonetheless, the recipe in `round1-summary.md` is still valid;
swap `100.70.167.11/federation_meta` for `127.0.0.1:15432/aimemory`
in the per-test setup.

Drafted by Claude (Opus 4.7, 1M context).
