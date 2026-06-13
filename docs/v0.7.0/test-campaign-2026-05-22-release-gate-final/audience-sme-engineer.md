# v0.7.0 Release-Gate Final Testing — SME / Engineer / Architect Briefing

## Verdict

**SHIP-RECOMMENDED.** 7,321 passed / 0 failed / 0 ignored across 269
test binaries on `cargo test --release --no-default-features
--features sal,sal-postgres,sqlite-bundled -- --include-ignored
--test-threads=1` at HEAD `fd172f2cf` against the lan-parity PG +
AGE container. 22 in-campaign issue closures (#1120–#1141 plus the
`fd172f2cf` cargo-fmt + clippy-allow follow-up). Two QC passes
(`a92308816df776eb7`, `a561ae68f0605cb1e`) verified the batch
against the C1–C8 orchestrator-safeguard set.

## Reproducibility contract

```
Branch:    release/v0.7.0-mobile-ci-1068  (tracks origin/release/v0.7.0)
HEAD:      fd172f2cf629309514cd5dad486c2e59ac4eed39
Binary:    /Users/fate/v07/v07-fixes/.cargo-shared-target/release/ai-memory
Binary SHA256:
           d4b60aa5b8f97470d95007f30bddb15e7e35c3855f0085c6b4f43d57f6b4ef3e
Symlink:   /opt/homebrew/bin/ai-memory -> (above)
Container: ai-memory-lan-parity-pg-age (UP 23h, healthy)
           127.0.0.1:15432 -> 5432/tcp
           PG16 + AGE 1.6.0 + pgvector 0.8.2
Env vars:  AI_MEMORY_TEST_POSTGRES_URL=postgresql://aimemory:****@127.0.0.1:15432/aimemory
           AI_MEMORY_TEST_AGE_URL=postgresql://aimemory:****@127.0.0.1:15432/aimemory
Schema:    v49 (sqlite ladder + postgres ladder both at migrate_v49())
Models:    embedder nomic-ai/nomic-embed-text-v1.5 (768-dim),
           reranker cross-encoder/ms-marco-MiniLM-L-6-v2,
           LLM tier-independent (#1067 selector)
Test invocation:
  cargo test --release --no-default-features \
    --features sal,sal-postgres,sqlite-bundled \
    -- --include-ignored --test-threads=1
Full log:  .local-runs/full-suite-final-v18-2026-05-22.log
Authoring agent: Claude (Opus 4.7, 1M context)
```

## Methodology

The release-gate sweep ran four gates in sequence:

1. `cargo fmt --check` — formatting invariant, GREEN at tip.
2. `cargo clippy --lib --bins --release -- -D warnings -D clippy::all
   -D clippy::pedantic` — production-code pedantic gate, GREEN.
3. `cargo clippy --tests --features sal,sal-postgres,sqlite-bundled
   --release -- -D warnings -D clippy::all -D clippy::pedantic` —
   test-surface pedantic gate, GREEN. This is the more demanding
   gate; the `fd172f2cf` follow-up added one
   `#[allow(clippy::needless_update)]` to the #1125 test fixture to
   keep it green.
4. `cargo audit` — RustSec advisory scan, GREEN across 529 deps.

Then the full suite under the canonical release-gate invocation
(above). The `--include-ignored` flag is load-bearing — without it,
the 30 `live_*` rows behind the previous `#[ignore]` gate would not
have run, and #1120 (pgvector schema-pin) would not have surfaced.

### Why `--test-threads=1`

The lan-parity container is a single shared DB. Cross-test
interference (one test's INSERT colliding with another test's
expected count) is eliminated by serial execution. Total wall-clock
cost: ~7 min for the postgres half; the sqlite half is
embarrassingly parallel and would not benefit from the
serialization, but the harness applies it uniformly. v0.7.x
follow-up: split the matrix into a parallel sqlite-only run plus a
serial postgres-only run; not a release-gate blocker.

### Cargo-feature matrix

| Feature flag | Purpose |
|---|---|
| `sal` | enable the storage-abstraction layer (always on at v0.7.0) |
| `sal-postgres` | compile the Postgres + AGE backend |
| `sqlite-bundled` | use the bundled rusqlite library (deterministic, no host-sqlite version drift) |
| `--no-default-features` | drop the default `sqlite` feature so the bundled variant takes over |

This matrix is the one #836 Tier-6 mandates. It is the cross-product
that an operator running a v0.7.0 release binary will exercise (the
released binary is built with these features; the
`--no-default-features` flag here is for test isolation, not for
release-build configuration).

## Per-issue root-cause table

| # | Title | Substrate evolution it lagged | Fix shape | Commit |
|---|---|---|---|---|
| 1120 | pgvector lands in `ag_catalog` not `public` | AGE init pushes `ag_catalog` to head of `search_path` | `CREATE EXTENSION ... SCHEMA public` in `init-age.sql` | `1cdc67da6` |
| 1121 | `live_gemma_e2b_smoke` model typo + skip robustness | external LLM smoke flaky on 404 + transport errors | corrected model name + widened skip predicate | `93080712b`, `6653e81df` |
| 1122 | `docs/index.html` 56 CLI subcommand drift | CLI 56→57 (sal-postgres build adds `schema-init`) | s/56/57/ in nav block | `f1a7f31dc` |
| 1123 | `CLAUDE.md` 56 CLI subcommand drift | same | s/56/57/ in architecture section | `f1a7f31dc` |
| 1124 | `cli_governance_check_action` pre-#1103 envelope | #1103 flat-envelope conversion | re-pinned assertions to flat shape | `55f4c1998` |
| 1125 | `discovery_gate_t1_t3` stale gate-pin panics | B1/B2 shipped earlier; test still asserted pre-ship | replaced 4 stale panics with live assertions | `fc1ccc2b0` |
| 1126 | `governance_install_defaults` host key leakage | `init-defaults` reads host `operator.key.pub` | HomeGuard isolation around test | `8d995dc45` |
| 1127 | `pg_run_gc_happy` post-#1027 admin-gate drift | #1027 tightened admin-gate (empty allowlist → 403) | renamed test to `_rejects_empty_allowlist_403` and re-pinned | `683261fa2` |
| 1128 | `i4_memory_replay_authz` pre-#1075 K9 deny shape | #1075 SAL visibility-gate silent-empty | re-pinned to silent-empty contract | `070e78219` |
| 1129 | `http_run_gc_happy` same #1027 admin-gate drift | same as #1127, http surface | rename + re-pin | `2c48b3a8d` |
| 1130 | `tools/list` snapshots post-#1057/#1058/#1059 trim | wire-trim added (`strip_docs_from_tools`) | re-blessed snapshots | `0b104b3c9` |
| 1131 | `column_exists` schema-qualify | ag_catalog interference with `information_schema` | added `table_schema='public'` filter | `202d09cf1` |
| 1132 | `POSTGRES_CURRENT_VERSION` 48 → 49 | #1025 added v49 | bumped constant | `2b8e704b3` |
| 1133 | `serve_postgres_extended` empty admin allowlist | #1027 tightened admin-gate | added `ai:ext-test` to fixture allowlist | `ba776f00d` |
| 1134 | `kg_timeline` postgres owner-gate (substrate) | #944/#937/#938 sqlite-side owner-gate not mirrored on PG | added 3-line `WHERE` to postgres path | `3f911f630` |
| 1135 | `serve_postgres_handler_parity` empty admin allowlist | same as #1133 | same fix shape | `3f911f630` |
| 1136 | `signed_events_dlq` replay recipe schema sync | replay recipe pinned to stale column names | re-pinned to actual schema columns | `4f29eb007` |
| 1137 | `autonomy_hook` tests post-#1067 `/api/chat` | #1067 unified LLM client to `/api/chat` | route by prompt content under unified wire | `557659a40` |
| 1138 | `store_parity_gaps` `bypass_visibility` | #1075 SAL visibility-gate | added `bypass_visibility=true` to parity tests | `1620aaa45` |
| 1139 | `transcripts/replay_test` agent_id propagation | #1075 visibility-gate filters on `metadata.agent_id` | stamped agent_id in `insert_memory` + propagated through `handle_replay` | `5f747512e` |
| 1140 | `v49_archive_roundtrip` postgres `bypass_visibility` | #1075 + #1025 | added bypass to postgres half | `07f22e6d3` |
| 1141 | `register_mcp_tool` doctest text annotation | rust toolchain `ignore`-vs-`text` UX | switched annotation + dropped trailing comma | `bc6402dbf` |
| — | cargo fmt + #1125 clippy allow | post-batch formatting + needless_update | `cargo fmt` + 1 `#[allow]` | `fd172f2cf` |

## The meta-pattern: substrate evolution outruns test-fixture pin discipline

20 of 22 issues were not production defects — they were test
fixtures that pinned a contract older than the one production now
exhibits. The campaign surfaced the gap; the fixes closed it; the
meta-pattern is worth documenting because it is the actual
SHIP-significant signal in the campaign.

### Categorical decomposition

| Substrate sweep | Date band | Affected test fixtures |
|---|---|---|
| Admin-gate `for_admin_checked` tightening | March–April 2026 (#946 → #957 → #1027) | #1127 #1129 #1133 #1135 |
| MCP wire-trim + flat-envelope evolution | April–May 2026 (#1057 → #1058 → #1059 → #1067 → #1075 → #1103) | #1124 #1128 #1130 #1136 #1137 |
| SAL visibility-gate enforcement | February–May 2026 (#910 → #1075) | #1138 #1139 #1140 |
| Schema v48 → v49 bump | May 2026 (#1025) | #1132 #1140 |
| AGE/pgvector init-script ordering | (long-standing, surfaced by container rebuild) | #1120 substrate + #1131 hygiene |
| `init-defaults` host-env isolation | (long-standing) | #1126 |
| Stale gate-pins after B1/B2 ship | (pre-campaign) | #1125 |
| External-LLM smoke resilience | (network-dependent) | #1121 |
| Doc-count drift | (CLI expansion) | #1122 #1123 |
| Doctest annotation cleanup | (toolchain UX) | #1141 |

### Why the drift accumulated

Three mechanical reasons, in order of impact:

1. **`#[ignore]`'d tests don't run on PR CI.** The 30 `live_*`
   embedding tests behind the previously-`#[ignore]`'d gate were
   not exercised on PRs that touched the postgres backend; the
   #1120 substrate defect therefore landed without surfacing until
   the lan-parity container was re-initialized from scratch and
   the `--include-ignored` flag was added to the release-gate
   sweep.
2. **Test fixtures live in different files than the substrate they
   pin.** A PR that tightens `for_admin_checked` in
   `src/governance/*` does not necessarily change
   `tests/serve_postgres_extended.rs`; the test imports the
   tightened API but the fixture's setup data (the admin allowlist
   in env) is silently the old shape. CI runs all tests, but if
   the originally-passing fixture didn't exercise the new branch,
   it passes anyway. The gap surfaces only when the test runs
   against a configuration that exercises the new branch — e.g.,
   `--include-ignored` plus the lan-parity container.
3. **Snapshot tests bypass the "would this fixture catch the
   change?" question.** The MCP `tools/list` snapshot at
   `tests/__snapshots__/*` was last re-blessed pre-#1057. Three
   substrate evolutions (#1057, #1058, #1059) added new
   wire-trim behavior; the snapshot needed a re-bless under each.
   Snapshot tests fail loudly when the wire shape changes, but
   they don't fail loudly when the human re-blesses with a
   one-liner — the re-bless makes the test pass without any
   substantive review, so the fixture's contract drifts silently
   relative to the snapshot's prose-form documentation.

### Future-bug prevention — proposed gates

Three CI gates would close the recurrence vector:

1. **`--include-ignored` on the same matrix as the default suite,
   at least for the `release/v0.7.0` branch.** Today, ignored
   tests run only on local pre-PR sweeps; promoting them into the
   PR matrix would have caught the 20 fixture-drift items as
   they landed, not at release-gate. Cost: ~7 min CI wall-clock,
   gated by feature flags so non-postgres PRs don't pay.

2. **Schema-pin enforcement via clippy lint.** Every `#[ignore]`
   annotation must cite a tracking issue with a date threshold
   (e.g., `#[ignore = "tracking #1120; revisit by 2026-06-01"]`).
   A clippy-driven lint rejects bare `#[ignore]` annotations and
   any annotation whose date threshold is in the past. This
   converts "we'll get to it" into a mechanical gate that
   surfaces in CI.

3. **Snapshot re-bless audit-log.** When a snapshot test is
   re-blessed (via `cargo insta accept` or `INSTA_UPDATE=always`),
   the re-bless commit must include the issue number that
   motivated the substrate change in the commit message. CI can
   parse the snapshot diff and refuse to merge if the diff
   exceeds N% without a referenced issue. v0.7.x
   follow-up tracking item.

## Substrate-fix-vs-test-fixture decomposition

| Category | Count | Issues | What it tells us |
|---|---|---|---|
| Genuine substrate defects | 2 | #1120, #1134 | Cross-store parity gaps in init-script ordering + SAL trait coverage. Both fixed in the campaign. |
| Test-fixture drift (admin-gate) | 4 | #1127, #1129, #1133, #1135 | Admin-gate tightening sweep missed 4 fixtures. #1027 was the latest; the older #946/#957 sweep also contributed. |
| Test-fixture drift (wire-shape) | 5 | #1124, #1128, #1130, #1136, #1137 | The MCP wire-shape evolution since #1057 has high churn; the test fixtures lag. |
| Test-fixture drift (visibility-gate) | 3 | #1138, #1139, #1140 | The #1075 SAL visibility-gate is the most recent substrate sweep; parity tests need `bypass_visibility=true`. |
| Schema-pin / annotation | 3 | #1132, #1141, (and #1140 partial) | Mechanical pin bumps; the v50+ ceiling will need the same discipline. |
| Schema-qualify | 1 | #1131 | Test-instrumentation hardening; not a production change. |
| Environment isolation | 2 | #1121, #1126 | External-LLM smoke + host-config leak; hardened test isolation. |
| Stale gate-pin | 1 | #1125 | B1/B2 shipped; 4 panics in the gate-pin test were unreachable; replaced with live assertions. |
| Docs CLI-count | 2 | #1122, #1123 | Hand-counted Markdown documentation drift; the CLI subcommand inventory drifted 56→57. |
| Style cleanup | 1 | (fd172f2cf) | Post-batch `cargo fmt` + one `#[allow]`. |

## Gate-matrix evidence

The Tier-1 + Tier-6 gates from #836 are all GREEN at agent scope at
tip `fd172f2cf`:

| Tier | Gate | Result |
|---|---|---|
| Tier-1 | CI tool-count-drift | ✓ (54→57 subcommand expansion blessed by #1122/#1123) |
| Tier-1 | CI c8-precheck | ✓ (no new `CallerContext::for_agent("<literal>")` outside allowlist) |
| Tier-1 | CI fmt+clippy+test+audit | ✓ (this campaign at `fd172f2cf`) |
| Tier-2 | Track A NHI | ✓ (carried forward from 2026-05-18 + verified post-fix) |
| Tier-2 | Track B A2A | ✓ (this dossier `track-b-a2a-results.md`) |
| Tier-2 | Track C postgres+AGE | ✓ (this dossier `track-c-postgres-age-results.md`) |
| Tier-2 | Track D cross-node | n/a — operator-gated |
| Tier-2 | Tracks E1/E2 | WITHDRAWN per `338278f5` |
| Tier-3 | Wave 1/2/3 refactor green | ✓ (256 → 269 test binaries at HEAD; all green) |
| Tier-4 | Coverage floors enforced | ✓ (workflow `Per-Module Coverage Thresholds` armed) |
| Tier-5 | Docs drift 100% | ✓ (#1122/#1123 closed; #1012 22-file sweep prior) |
| Tier-5 | GitHub Pages | ✓ (this dossier's `index.html` adds a new card) |
| Tier-6 | `cargo audit` clean | ✓ (529 deps scanned) |
| Tier-6 | Four gates GREEN on fresh checkout | ✓ (this campaign) |
| Tier-6 | Release notes complete | ✓ (`docs/v0.7.0/release-notes.md`, 1135 LOC unchanged) |
| Tier-6 | 24h dogfood loop | operator-gated |
| Tier-6 | Install E2E on fresh hosts | operator-gated |

## QC trail

The 22-issue batch was QC'd in two passes per orchestrator
discipline:

- **Pass 1** (`a92308816df776eb7`) verified #1120 through #1129
  against the C1–C8 set: banned-phrase scan, close-comment URL
  presence, commit SHA verifiability, test-evidence
  verifiability, six-step incapacity-claim discipline,
  per-issue end-to-end protocol, discrepancy detection, and the
  C8 CodeGraph structural-drift check.

- **Pass 2** (`a561ae68f0605cb1e`) verified #1130 through #1141
  against the same C1–C8 set.

Both passes APPROVED. No HARD-BLOCK fails; no banned phrases
detected; every commit SHA resolves via `git show`; every "tests
pass" claim cites the exact `cargo test` invocation and result
line.

## Postgres + AGE cross-store parity at HEAD

| SAL trait method | SQLite (`SqliteStore`) | Postgres (`PostgresStore`) | Cypher (`AGE`) | Parity |
|---|---|---|---|---|
| `store` | GREEN | GREEN | n/a | OK |
| `insert_if_newer` | GREEN | GREEN | n/a | OK |
| `update` | GREEN | GREEN | n/a | OK |
| `delete` | GREEN | GREEN | n/a | OK |
| `list` (`bypass_visibility=true`) | GREEN | GREEN | n/a | OK (post-#1138) |
| `archive` / `restore` (v49 round-trip) | GREEN | GREEN | n/a | OK (post-#1140) |
| `kg_traverse` | GREEN (CTE) | GREEN (CTE / Cypher) | GREEN (Cypher) | OK |
| `kg_timeline` | GREEN | GREEN (post-#1134) | GREEN | OK (substrate parity restored by #1134) |
| `kg_invalidate` | GREEN | GREEN | GREEN | OK |
| `recall_observations` | GREEN | GREEN | n/a | OK |
| `governance_check` | GREEN | GREEN | n/a | OK |
| `signed_events_chain_verify` | GREEN | GREEN | n/a | OK |

## Lessons learned, in priority order

1. **`--include-ignored` is load-bearing for substrate parity.** The
   30 `live_*` rows behind the previous gate were the only test
   surface that would have caught #1120 + #1134 before
   release-gate. Promote `--include-ignored` to the PR CI matrix on
   the `release/**` branch family.

2. **Test fixtures lag substrate by 1–3 months at this churn rate.**
   #910 (visibility-gate) and #946 (admin-gate) were both pre-March
   2026; their test-fixture drift surfaced in May 2026. The lag is
   small enough that quarterly fixture-audit sweeps could catch it,
   but mechanical (clippy-lint-driven) gates are stronger.

3. **Snapshot re-bless without referenced issue is silent-drift.**
   #1130 fixed three snapshots that had been silently outdated
   since #1057/#1058/#1059. Add the audit-log gate proposed above.

4. **External-LLM smoke tests need skip-robust predicates.** #1121
   surfaced under a flaky external endpoint; the fix widened the
   skip predicate to cover timeout + transport errors, not just
   404. v0.7.x: split external-LLM tests into a separate matrix
   with explicit `network-dependent` markers.

5. **`init-defaults` and similar one-shot setup tests should
   isolate from host config by default.** #1126 leaked the host's
   `operator.key.pub` into the test; HomeGuard isolation prevents
   that. v0.7.x: lint for any test that reads `$HOME` without
   HomeGuard.

6. **Cross-store parity is the most fragile invariant.** #1134 was
   a 3-line `WHERE` clause omission on one of two backends. The
   parity test set catches these once they exist; the gap is
   whether the parity-test surface keeps pace with every SAL trait
   method addition. v0.7.x: enforce "every SAL trait method must
   have both a SQLite and a Postgres `live_*` test" as a CI gate.

## Recommendation

SHIP. The release-gate Tier-1, Tier-2 (sqlite + A2A + postgres),
Tier-3, Tier-5, and Tier-6 (`cargo audit` + four gates +
release-notes) are all GREEN at HEAD `fd172f2cf`. The Tier-2
Track D + Tier-6 dogfood loop remain operator-gated per #836; they
are not engineering-completable.

The 22-issue closure batch validates the testing-loop discipline
operator directive (pm-v3) — every defect surfaced was filed, fixed,
retested + re-checked, and closed in-campaign with audit trail. The
gap analysis surfaced three v0.7.x follow-up CI gates that would
close the recurrence vector for the 20 fixture-drift items; those
are documented above and not blockers for v0.7.0 cut.

The two genuine substrate defects (#1120, #1134) are exactly the
class of pre-release-gate findings the gate exists for. Both are
fixed in the v0.7.0 binary; neither ships as a known issue.

## Audit trail

| Artifact | Path |
|---|---|
| Full-suite log | `.local-runs/full-suite-final-v18-2026-05-22.log` |
| Postgres + AGE retest log | `.local-runs/postgres-lib-retest-with-age-2026-05-22.log` |
| Release-gate issue | [#836](https://github.com/alphaonedev/ai-memory-mcp/issues/836) |
| Reference campaign (2026-05-18 dogfood) | `docs/v0.7.0/test-campaign-2026-05-18-dogfood/` |
| Reference campaign (2026-05-18 Track A re-run) | `docs/v0.7.0/test-campaign-2026-05-18/` |
| Prior A2A campaign | `.local-runs/a2a-2026-05-19/round1-summary.md` |
| Lan-parity container spec | `infra/lan-parity-test/docker-compose.yml` |
| Schema migration source | `src/storage/migrations.rs` + `src/store/postgres.rs:391` |
| `init-age.sql` (post-#1120 fix) | `infra/lan-parity-test/init-age.sql` |
| `kg_timeline` postgres (post-#1134 fix) | `src/store/postgres.rs` |
| Authoring agent | Claude (Opus 4.7, 1M context) |
| QC pass 1 | agent `a92308816df776eb7` (C1–C8 verified #1120–#1129) |
| QC pass 2 | agent `a561ae68f0605cb1e` (C1–C8 verified #1130–#1141) |
| Prime directive pm-v3 | memory `cd8ede94-3376-4837-b570-9d975290ae08` |
| Orchestrator safeguards | memory `a1cc142d-053a-49ab-83bd-1a99992fa93e` |

---

*Apache-2.0, © 2026 AlphaOne LLC. Authored autonomously by Claude
(Opus 4.7, 1M context).*
