# ai-memory v0.7.0 — Release-Gate Final Testing Dossier (2026-05-22)

## What this is

The release-gate final testing campaign for ai-memory v0.7.0. The branch
`release/v0.7.0-mobile-ci-1068` (tracks `origin/release/v0.7.0`) was put
through the full Tier-1 + Tier-6 binary-validation sweep against the
post-#1013 ship-hardening tip, with the lan-parity Postgres + Apache AGE
container topology bound for the postgres half. Three test surfaces were
exercised under one matrix:

- **Track A — sqlite path** (default features + sqlite-bundled). The
  NHI playbook regression suite + 4,800-plus lib unit tests + integration
  + governance + MCP wire + HTTP handler suites.
- **Track B — A2A non-corpus scenarios** (Round 1 + Round 2 from
  `2026-05-19/round1-summary.md`). All 8 cross-agent scenarios still
  green under the post-#1013 binary; federation Ed25519 sign/verify,
  multi-agent identity isolation, scoped recall, governance refusal,
  contradiction-link symmetry, and the 15-row signature-chain verify.
- **Track C — Postgres + Apache AGE** lan-parity container. 76
  `store::postgres::tests::live_*` rows + 36 postgres-gated integration
  tests against the live PG16 + AGE 1.6.0 + pgvector 0.8.2 instance
  bound to `127.0.0.1:15432`.

Aggregate: **7,321 passed; 0 failed; 0 ignored** across 269 test
binaries (full log at
`.local-runs/full-suite-final-v18-2026-05-22.log`).

22 release-gate defects (issue numbers #1120 through #1141, plus the
fd172f2cf cargo-fmt + clippy-allow follow-up) were filed, fixed,
retested + re-checked, and CLOSED in-campaign. **No deferrals to
v0.8.0.** Per the prime directive (memory
`cd8ede94-3376-4837-b570-9d975290ae08`, namespace `global/policies`),
every test-surface defect — even those that the test framework would
call "test-fixture drift" rather than "production defect" — was treated
as a real defect and fixed in v0.7.0.

The campaign authored 22 commits on `release/v0.7.0`; the post-fix tip
is `fd172f2cf`. Two QC passes (`a92308816df776eb7` covering #1120–#1129;
`a561ae68f0605cb1e` covering #1130–#1141) verified the batch against
the C1–C8 orchestrator-safeguard set.

## Verdict at a glance

**SHIP-RECOMMENDED.** The release-gate Tier-1 (CI green), Tier-2 (Lane
3 full-spectrum testing), Tier-3 (refactor green at HEAD), Tier-6
(`cargo audit` + four-gates + release-notes) checkboxes for #836 are
agent-completable and now GREEN against tip `fd172f2cf`. The remaining
Tier-2 Track C subnet-routing block and the Tier-6 24h dogfood-rebuild
loop are explicitly operator-gated by #836's own checklist (cannot be
agent-completed).

## How this directory is organised

| File | Audience | Purpose |
|------|----------|---------|
| `README.md` | All readers | Campaign index — this file |
| `track-a-build-install-results.md` | Engineering | Phase-1 build + install verification (binary SHA, symlink topology, container topology) |
| `track-b-a2a-results.md` | Engineering | A2A scenarios re-verified post-#1013 + post-22-issue fix batch |
| `track-c-postgres-age-results.md` | Engineering | Postgres + Apache AGE full regression (v15→v49 migration ladder, AGE dispatch, pgvector pin) |
| `audience-non-technical.md` | End users / curious observers | 600–800 words, plain English |
| `audience-c-level.md` | Executive / PM / decision-maker | 800–1,000 words, verdict + risk + cost + roadmap |
| `audience-sme-engineer.md` | SME engineers + architects | 1,500–2,000 words, reproducibility + methodology + per-issue root-cause table + future-bug prevention |
| `index.html` | GitHub Pages | Dark-theme landing card-grid |

## Issues closed in this campaign

| # | Title | Commit | Category |
|---|---|---|---|
| [#1120](https://github.com/alphaonedev/ai-memory-mcp/issues/1120) | pgvector lands in `ag_catalog` not `public` — breaks 30 `live_*` tests | `1cdc67da6` | substrate bug |
| [#1121](https://github.com/alphaonedev/ai-memory-mcp/issues/1121) | `live_gemma_e2b_smoke` — model typo + insufficient skip robustness | `6653e81df` | environment isolation |
| [#1122](https://github.com/alphaonedev/ai-memory-mcp/issues/1122) | `docs/index.html` 56 CLI subcommand drift | `f1a7f31dc` | docs drift |
| [#1123](https://github.com/alphaonedev/ai-memory-mcp/issues/1123) | `CLAUDE.md` 56 CLI subcommand drift | `f1a7f31dc` | docs drift |
| [#1124](https://github.com/alphaonedev/ai-memory-mcp/issues/1124) | `cli_governance_check_action` — pre-#1103 nested envelope assertion | `55f4c1998` | wire-shape drift |
| [#1125](https://github.com/alphaonedev/ai-memory-mcp/issues/1125) | `discovery_gate_t1_t3` — 4 stale gate-pin panics (B1/B2 shipped) | `fc1ccc2b0` | stale gate-pin |
| [#1126](https://github.com/alphaonedev/ai-memory-mcp/issues/1126) | `governance_install_defaults` — host `operator.key.pub` leakage | `8d995dc45` | environment isolation |
| [#1127](https://github.com/alphaonedev/ai-memory-mcp/issues/1127) | `pg_run_gc_happy` — post-#1027 admin-gate drift | `683261fa2` | admin-gate drift |
| [#1128](https://github.com/alphaonedev/ai-memory-mcp/issues/1128) | `i4_memory_replay_authz` — pre-#1075 K9 deny shape | `070e78219` | wire-shape drift |
| [#1129](https://github.com/alphaonedev/ai-memory-mcp/issues/1129) | `http_run_gc_happy` — same #1027 admin-gate drift | `2c48b3a8d` | admin-gate drift |
| [#1130](https://github.com/alphaonedev/ai-memory-mcp/issues/1130) | `tools/list` snapshots — post-#1057/#1058/#1059 wire-trim re-bless | `0b104b3c9` | wire-shape drift |
| [#1131](https://github.com/alphaonedev/ai-memory-mcp/issues/1131) | `column_exists` schema-qualify to `public` (ag_catalog interference) | `202d09cf1` | schema-qualify |
| [#1132](https://github.com/alphaonedev/ai-memory-mcp/issues/1132) | `POSTGRES_CURRENT_VERSION` 48 → 49 | `2b8e704b3` | schema-pin |
| [#1133](https://github.com/alphaonedev/ai-memory-mcp/issues/1133) | `serve_postgres_extended` — empty admin allowlist | `ba776f00d` | admin-gate drift |
| [#1134](https://github.com/alphaonedev/ai-memory-mcp/issues/1134) | `kg_timeline` postgres owner-gate (substrate fix) | `3f911f630` | substrate bug |
| [#1135](https://github.com/alphaonedev/ai-memory-mcp/issues/1135) | `serve_postgres_handler_parity` — empty admin allowlist | `3f911f630` | admin-gate drift |
| [#1136](https://github.com/alphaonedev/ai-memory-mcp/issues/1136) | `signed_events_dlq` replay recipe schema sync | `4f29eb007` | schema-pin |
| [#1137](https://github.com/alphaonedev/ai-memory-mcp/issues/1137) | `autonomy_hook` tests — post-#1067 `/api/chat` unification | `557659a40` | wire-shape drift |
| [#1138](https://github.com/alphaonedev/ai-memory-mcp/issues/1138) | `store_parity_gaps` `bypass_visibility` | `1620aaa45` | visibility-gate |
| [#1139](https://github.com/alphaonedev/ai-memory-mcp/issues/1139) | `transcripts/replay_test` agent_id propagation | `5f747512e` | visibility-gate |
| [#1140](https://github.com/alphaonedev/ai-memory-mcp/issues/1140) | `v49_archive_roundtrip` postgres `bypass_visibility` | `07f22e6d3` | visibility-gate |
| [#1141](https://github.com/alphaonedev/ai-memory-mcp/issues/1141) | `register_mcp_tool` doctest text annotation | `bc6402dbf` | doctest annotation |
| (style) | `cargo fmt` + #1125 `clippy::needless_update` allow | `fd172f2cf` | style cleanup |

### Categorical breakdown

| Category | Count | Issues |
|---|---|---|
| Substrate code fixes | 2 | #1120 #1134 |
| Admin-gate test drift (post-#946/#957/#1027) | 4 | #1127 #1129 #1133 #1135 |
| Wire-shape test drift (post-#1057/#1067/#1075/#1103) | 5 | #1124 #1128 #1130 #1136 #1137 |
| Visibility-gate (post-#910/#1075 SAL visibility) | 3 | #1138 #1139 #1140 |
| Stale gate-pin | 1 | #1125 |
| Schema-qualify | 1 | #1131 |
| Schema-version track | 1 | #1132 |
| Doctest annotation | 1 | #1141 |
| Environment isolation | 2 | #1121 #1126 |
| Docs CLI-count drift | 2 | #1122 #1123 |
| Style cleanup | 1 | (cargo fmt) |

Only **2 of 22** were genuine substrate code defects (#1120 pgvector
schema-pin oversight in `init-age.sql`; #1134 `kg_timeline` SQLite-only
owner-gate that the #944/#937/#938 sweep missed). The remaining 20 are
the gap between substrate-contract evolution and pin-update discipline.
See the SME-engineer file for the full meta-pattern analysis.

## Code commits this campaign

| SHA | Type | Scope |
|-----|------|-------|
| `1cdc67da6` | fix(#1120) | pgvector schema-pin in `init-age.sql` (substrate) |
| `93080712b` | fix(#1121) | `live_gemma_e2b_smoke` model name + 404 skip |
| `6653e81df` | fix(#1121 follow-up) | widen smoke skip to timeout + transport errors |
| `f1a7f31dc` | docs(#1122,#1123) | CLI subcommand count 56 → 57 |
| `55f4c1998` | fix(#1124) | `cli_governance_check_action` flat envelope |
| `fc1ccc2b0` | fix(#1125) | `discovery_gate_t1_t3` replace stale panics |
| `8d995dc45` | fix(#1126) | `governance_install_defaults` HomeGuard isolation |
| `683261fa2` | fix(#1127) | `pg_run_gc_happy` → `_rejects_empty_allowlist_403` |
| `070e78219` | fix(#1128) | `i4_memory_replay_authz` post-#1075 |
| `2c48b3a8d` | fix(#1129) | `http_run_gc_happy` → `_rejects_empty_allowlist_403` |
| `0b104b3c9` | test(#1130) | `tools/list` snapshot re-bless |
| `202d09cf1` | fix(#1131) | `column_exists`/`index_exists` schema-qualify |
| `2b8e704b3` | fix(#1132) | `POSTGRES_CURRENT_VERSION` 48 → 49 |
| `ba776f00d` | fix(#1133) | `serve_postgres_extended` admin allowlist |
| `3f911f630` | fix(#1134,#1135) | `kg_timeline` postgres owner-gate (substrate) + parity-test admin allowlist |
| `4f29eb007` | fix(#1136) | `signed_events_dlq` replay schema column-name pin |
| `557659a40` | fix(#1137) | `autonomy_hook` `/api/chat` content routing |
| `1620aaa45` | fix(#1138) | `store_parity_gaps` `bypass_visibility` |
| `5f747512e` | fix(#1139) | `transcripts/replay_test` agent_id propagation |
| `07f22e6d3` | fix(#1140) | `v49_archive_roundtrip_1025` postgres `bypass_visibility` |
| `bc6402dbf` | fix(#1141) | `register_mcp_tool` doctest `text` annotation |
| `fd172f2cf` | style | `cargo fmt` sweep + #1125 `clippy::needless_update` allow |

## Reproducibility contract

1. **Branch + tip.** `release/v0.7.0-mobile-ci-1068` (tracks
   `origin/release/v0.7.0`); HEAD `fd172f2cf629309514cd5dad486c2e59ac4eed39`.
2. **Binary.** Single release SHA
   `d4b60aa5b8f97470d95007f30bddb15e7e35c3855f0085c6b4f43d57f6b4ef3e`
   at `/Users/fate/v07/v07-fixes/.cargo-shared-target/release/ai-memory`
   (symlinked to `/opt/homebrew/bin/ai-memory`).
3. **Test invocation.**
   `cargo test --release --no-default-features --features sal,sal-postgres,sqlite-bundled -- --include-ignored --test-threads=1`.
4. **Test environment.** macOS Sequoia / Darwin 25.4.0; lan-parity PG +
   AGE container `ai-memory-lan-parity-pg-age` on `127.0.0.1:15432`
   (PG16 + AGE 1.6.0 + pgvector 0.8.2); `AI_MEMORY_TEST_POSTGRES_URL`
   and `AI_MEMORY_TEST_AGE_URL` both bound to that DB.
5. **Schema version.** v49 (current at v0.7.0 release; postgres ladder
   ends at `migrate_v49()`, sqlite at the `if version < 49` arm).
6. **Authoring agent.** Claude (Opus 4.7, 1M context). QC pass 1:
   agent `a92308816df776eb7`. QC pass 2: agent
   `a561ae68f0605cb1e`.

## Hard rules during the campaign

Per the prime directive pm-v3 (memory
`cd8ede94-3376-4837-b570-9d975290ae08`, namespace `global/policies`)
and the testing-loop addendum:

- **Testing-loop discipline.** Every failure surfaced during the
  release-gate sweep was filed as a GH issue at the moment of
  discovery, not after the campaign closed. 22 issues filed; 22 fixed;
  22 closed with retest + re-check evidence.
- **Verify-before-claiming.** Every "tests pass" claim cites the
  exact `cargo test` invocation + result line. Every "I committed X"
  cites a SHA verifiable via `git show <SHA>`. No banned phrases
  ("non-blocking", "P2/P3 follow-up", "DEFER-TO-V080", "operator
  should…") were used.
- **No deferral to v0.8.** Even test-fixture drift (20 of 22 issues
  by category) was fixed in v0.7.0. Test-fixture drift IS a real
  defect — the test surface is part of the release contract.
- **Recompile + batch retest.** Each commit landed against a freshly
  recompiled binary; the final full-suite run (v18) ran against the
  composite tip `fd172f2cf` to mint the 7,321 / 0 / 0 verdict.
- **Audit trail mandatory.** Every GH issue body links to the
  commit; every commit references the issue; this dossier links
  both.

## Memory namespace convention

| Item | Namespace | Title pattern |
|------|-----------|---------------|
| Release-gate phase results | `ai-memory/v0.7.0-release-gate-2026-05-22` | `RG-{phase}-{result}` |
| Verdict | `ai-memory/v0.7.0-release-gate-2026-05-22` | `Release-gate verdict 2026-05-22` |
| Prime directive pm-v3 | `global/policies` | memory `cd8ede94-3376-4837-b570-9d975290ae08` |
| Orchestrator safeguards | `_v070_orchestrator_safeguards` | memory `a1cc142d-053a-49ab-83bd-1a99992fa93e` |
| Strategic tracking | `_v070_strategic_tracking` | lane index `f970d6f6-7bde-4d6b-9a53-500734961e04` |
| Release-gate checklist | `_v070_release_gate` | issue #836 mirror |

## Provenance

| Item | Value |
|------|-------|
| Campaign date | 2026-05-22 |
| Operator | justin@alpha-one.mobi |
| Authoring agent | Claude (Opus 4.7, 1M context) |
| Authority | Autonomous execution under pm-v3 (verify-before-claiming + no-operator-handoffs + fix-all-in-current-release) |
| QC pass 1 | agent `a92308816df776eb7` (C1–C8 verified #1120–#1129) |
| QC pass 2 | agent `a561ae68f0605cb1e` (C1–C8 verified #1130–#1141) |
| Prior campaign | `docs/v0.7.0/test-campaign-2026-05-18-dogfood/` |
| Binary at write time | SHA `d4b60aa5b8f97470d95007f30bddb15e7e35c3855f0085c6b4f43d57f6b4ef3e` (commit `fd172f2cf`) |
| Full-suite log | `.local-runs/full-suite-final-v18-2026-05-22.log` |

Apache-2.0, © 2026 AlphaOne LLC.
Drafted by Claude (Opus 4.7, 1M context).
