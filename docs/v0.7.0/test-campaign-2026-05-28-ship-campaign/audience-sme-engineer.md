# v0.7.0 Ship Campaign 2026-05-28 — SME / Engineer / Architect Briefing

## Verdict

**SHIP-CLEARED.** Six tracks exercised against integrated tip
`be3347d704dad03bcc210c9eb0a517946dbe555f` on `release/v0.7.0`:
build + 1hr dogfood loop, A2A in-host via lan-parity Docker stack,
postgres + Apache AGE full regression (`cargo test --features
sal,sal-postgres --release --no-fail-fast` → 8,028 / 9 / 27 / 312),
docs + GitHub Pages drift remediation closing #1197 + #1198,
scope-disciplined CoALA prior-art citation (PR #1380), and a
parallel-dispatched heterogeneous AI-NHI assessment v3 (in-flight at
write time). Three codegraph-driven QC audits on the Track-D fix
batch (A literal / B structural / C fault-injection) returned
ZERO-DEFECTS-CONFIRMED. Substrate untouched by all campaign
findings; the one substrate-adjacent fix (PR #1382) lives entirely
in `tests/**`.

## Reproducibility contract

```
Branch:           release/v0.7.0
HEAD:             be3347d704dad03bcc210c9eb0a517946dbe555f
Binary:           target/release/ai-memory  (thin LTO + stripped)
Install symlink:  /opt/homebrew/bin/ai-memory -> (above)
Dogfood daemon:   PID 10338, started 2026-05-27 16:55:25Z,
                  RSS ~18 MB sustained over 16h+
Lan-parity stack: infra/lan-parity-test/docker-compose.yml
                  - ai-memory-lan-parity-alice  (127.0.0.1:19180->19077)
                  - ai-memory-lan-parity-bob    (127.0.0.1:19181->19077)
                  - ai-memory-lan-parity-pg-age (127.0.0.1:15432->5432)
                  PG16 + AGE 1.6.0 + pgvector 0.8.2, schema v51
Env vars:         AI_MEMORY_TEST_POSTGRES_URL=postgresql://aimemory:****@127.0.0.1:15432/aimemory
                  AI_MEMORY_TEST_AGE_URL=postgresql://aimemory:****@127.0.0.1:15432/aimemory
Schema:           v51 (sqlite ladder + postgres ladder both at migrate_v51();
                  v50 #1156 K8 quota PK extension; v51 #1255 / PR #1296
                  federation_nonces durable peer-replay nonces)
Test invocation (Track C):
  cargo test --features sal,sal-postgres --release --no-fail-fast
Authoring agent:  Claude (Opus 4.7, 1M context)
```

## Methodology

The campaign exercised six tracks under one matrix:

1. **Track A — Build + 1hr dogfood loop.** Binary built from
   `release/v0.7.0` HEAD; install symlink updated; live MCP daemon
   PID 10338 observed across a 1h00m window (2026-05-28T11:44:53Z →
   12:44:53Z) and extended to 16h+ sustained. RSS profile flat at
   ~18 MB at every probe — no leak.
2. **Track B — A2A in-host via lan-parity Docker.** Rebuilt 3-
   container stack against integrated HEAD; alice + bob + pg-age
   all UP healthy on loopback; federation paths exercised via
   `cargo test --features sal,sal-postgres` against the shared
   pg-age URL.
3. **Track C — Postgres + AGE full regression.** Full sweep at
   `--no-fail-fast` against the lan-parity pg-age; 8,028 / 9 / 27 /
   312. Triage: 5 of 9 = cargo-target races (environmental); 4 of
   9 = real test-isolation defects → #1381 → fixed in PR #1382 via
   new `tests/common/postgres_env.rs` per-test schema isolation
   helper.
4. **Track D — Docs + Pages drift remediation.** Codegraph-driven
   detection (41 sites / 23 files initial) → 3 commits on PR #1379
   (cumulative ~54 sites / ~24–27 files) → 3 codegraph-driven QC
   audits (Audit A literal, Audit B structural, Audit C fault-
   injection). Closes #1197 + #1198.
5. **Track E — CoALA prior-art citation.** PR #1380 scope-
   disciplined: 3 deliverables (ROADMAP citation, positioning
   section, new `docs/strategy/coala-mapping.md`), 3 rejected
   proposals (§2.8 subsection, §11.4.D/§22 reframing, capabilities-v3
   `coala` block). Substrate untouched.
6. **Track F — AI-NHI assessment v3.** Parallel-dispatched fresh
   Opus 4.7 agent against post-fix HEAD. Report expected at
   `docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v3.md`.

### Why three QC audits on Track D

The Track-D drift remediation is the highest-volume mechanical
correction the campaign did (~54 sites across ~24–27 files). One
detection pass is insufficient because:

- **Literal enumeration (Audit A)** catches stale numeric literals
  at scale but misses sites where the number appears as part of a
  larger expression or in a less-obvious context (e.g., the
  `feature-matrix.html:249-250` pill row that contradicted the
  banner 4 lines above — a literal `grep` finds both occurrences,
  but the consistency check requires structural awareness).
- **Structural call-graph (Audit B)** traverses from each
  canonical-source symbol to every doc location that should
  reference it; catches the cases where a doc page should mention
  a canonical count but doesn't (or mentions it in a non-
  literally-greppable form).
- **Fault-injection (Audit C)** verifies the *enforcing* contracts:
  inject a deliberate drift into the source-side pin tests, confirm
  each one fails loudly. This is the load-bearing-vs-decorative
  test: a pin test that doesn't fail under deliberate drift is
  worse than no pin test, because it gives false confidence.

The 3-audit discipline surfaced 13 sites that the initial pass
missed (Audit A: 6; Audit B: 7) — that's a 32% miss rate on the
single-pass detection. The 3-audit closure is what enables the
ZERO-DEFECTS-CONFIRMED verdict.

## Per-issue root-cause table

| # | Title | Substrate evolution it lagged | Fix shape | PR / Commit |
|---|---|---|---|---|
| 1197 | Docs drift NO FAIL MISSION (post-#1174 follow-up) | CLI 57→79 (FX-12/ARCH-3 + FX-C3 batch2); schema v49→v50→v51; HTTP-route framing 73→87/73 unique | 3-commit drift sweep across ~24–27 distinct files | PR #1379 (`e6ac824bb` + `3001ffd47` + `73f3c7af5`) |
| 1198 | GitHub Pages drift NO FAIL MISSION (post-#1174 follow-up) | same as #1197 | same 3 commits cover both issues | PR #1379 (same) |
| 1378 | `ai-memory install codex` rejects TOML config | Codex CLI uses `~/.codex/config.toml` (TOML), but installer assumes JSON | (v0.7.x follow-up: detect file ext; route TOML through `toml::from_str`) | not yet fixed; open + non-blocking |
| 1381 | 4 postgres tests assume empty shared schema (lan-parity) | Lan-parity stack's always-on `ic_alice` / `ic_bob` daemon schemas + cross-test state accumulation under `--no-fail-fast` | New `tests/common/postgres_env.rs` per-test schema isolation helper (421 LOC) | PR #1382 (`d1d5b33de`) |
| (PR #1382) | per-test PostgresTestEnv schema isolation | (the fix PR for #1381) | 4 file edits + 1 new file; substrate untouched | PR #1382 (`d1d5b33de`) |

### The 4 #1381 sub-defects

```
1. embedding_dim_migration::auto_migrate_converts_384_schema_to_768_on_daemon_bootstrap
2. issue_1213_atttypmod_age_schema_scope::issue_1213_unscoped_probe_demonstrates_root_cause
3. issue_1213_atttypmod_age_schema_scope::issue_1213_atttypmod_probe_scopes_to_public_schema
4. migrate_links_roundtrip::migrate_links_sqlite_to_postgres_to_sqlite_roundtrip
```

All four share one root cause: tests assume an empty / known schema
state on the postgres container but other tests in the same `cargo
test --no-fail-fast` invocation, AND the long-lived `ic_alice` /
`ic_bob` daemon schemas from the lan-parity stack, accumulate
state. CI's Postgres-feature gate runs `--test-threads=1` against a
**one-shot container per job** so the issue doesn't manifest there;
only the **LAN-parity shared-container path** surfaces it.

### Why no substrate code touched

The PR #1382 fix is **entirely on the test side**: a new
`tests/common/postgres_env.rs` (421 LOC) ships a `PostgresTestEnv`
helper that, per test invocation, runs `CREATE SCHEMA test_<name>_<uuid8>`
against the base postgres URL and returns a per-test connection
URL with `?options=-c%20search_path=<schema>,public` set. Drop impl
cleans up. Three substrate sites where `n.nspname = 'public'` is
hardcoded (`src/store/postgres.rs:770`, `:2788`, `:3217`) are
documented in the helper's module doc but NOT modified — the
hardcoded scope is intentional for the substrate's own dim probe;
the test-side fix mirrors it where needed.

This is the right shape: the **bug is at the test-discipline layer**
(tests not isolating their own state), not at the production-code
layer. Production daemons running against a real customer postgres
do not accumulate test state because they are not run alongside
other tests; the failure mode is specific to the test-runner
+ shared-container combination.

## The meta-pattern: test-isolation discipline at the realistic-deployment substrate

The 2026-05-22 campaign's meta-pattern was "substrate evolution
outruns test-fixture pin discipline" (20 of 22 issues were
fixture-drift, fixed by re-pinning). The 2026-05-28 campaign's
meta-pattern is the next layer in: **test-isolation discipline at
the realistic-deployment substrate**.

The 4 #1381 sub-defects are not pin-drift — the pins are correct.
They are tests that work fine in CI (one-shot container per job)
but fail under the realistic-deployment substrate (a long-lived
shared container with multiple daemons connected). The fix is not
a pin update — it is a new helper that ensures each test gets its
own schema namespace.

This is meaningful because the lan-parity stack IS the realistic
deployment substrate: a single managed-postgres instance backing
multiple agents is the v0.7.0 "managed-postgres" story. Test
fixtures that only work against CI's isolated single-binary
container would have shipped a v0.7.0 with a known test-discipline
debt; the campaign caught it and closed it.

### Future-bug prevention — proposed gates

Two CI gates would close the recurrence vector for the 2026-05-28
defect class:

1. **Add the lan-parity stack to the CI test matrix.** Today, CI
   runs one-shot containers; promote a "lan-parity-shared-container"
   job to the matrix that runs the full test sweep against a
   long-lived dual-daemon backend. Cost: ~10 min CI wall-clock per
   job; gated by feature flags. This would have caught the 4 #1381
   sub-defects at PR time, not at ship time.

2. **`doc-drift-detection` workflow (v0.8).** Per the Track-D
   Audit C latent-drift-risk finding: the doc sites themselves
   have no enforcing CI pin test. A v0.8 workflow scopes a CI step
   that greps `docs/**.md` + `docs/**.html` for canonical-count
   literals and validates against `codegraph_search` of the
   canonical-source symbols. Adds a consistency check across pages
   (so the `73 routes` vs. `87 registrations` framing across two
   pages cannot drift relative to each other).

Both gates are v0.7.x / v0.8 follow-ups, not v0.7.0 SHIP blockers.

## Gate-matrix evidence at HEAD `be3347d70`

| Tier | Gate | Result |
|---|---|---|
| Tier-1 | CI workflow on `release/v0.7.0` HEAD | GREEN (per `be3347d70` chore(release-prep) re-validation push) |
| Tier-1 | `cargo fmt --check` | GREEN at HEAD + PR #1382 |
| Tier-1 | `cargo clippy --tests --features sal,sal-postgres --release -- -D warnings -D clippy::all -D clippy::pedantic` | GREEN at HEAD + PR #1382 |
| Tier-1 | `cargo audit` | GREEN across 529 deps |
| Tier-2 | Track A NHI (carried fwd from 2026-05-22 + 1hr dogfood) | GREEN |
| Tier-2 | Track B A2A via lan-parity stack | GREEN (this dossier `track-b-a2a-docker-results.md`) |
| Tier-2 | Track C postgres+AGE regression | GREEN post-PR #1382 (this dossier `track-c-postgres-age-results.md`) |
| Tier-2 | Track D cross-node | n/a — operator-gated |
| Tier-2 | Tracks E1/E2 | WITHDRAWN per `338278f5` (operator memory) |
| Tier-3 | Wave 1/2/3 refactor green | GREEN (2026-05-25/26 Wave-A audit-merge campaign + integrated HEAD validation) |
| Tier-5 | Docs drift 100% | GREEN — ZERO-DEFECTS-CONFIRMED across 3 audits (closes #1197 + #1198) |
| Tier-5 | GitHub Pages drift 100% | GREEN — same (closes #1198) |
| Tier-6 | `cargo audit` clean | GREEN (529 deps) |
| Tier-6 | Four gates GREEN on fresh checkout | GREEN at HEAD + PR #1382 |
| Tier-6 | Release notes complete | GREEN (`docs/v0.7.0/release-notes.md` + CHANGELOG `[Unreleased]` block) |
| Tier-6 | 24h dogfood loop | operator-gated (1h portion GREEN; extended 16h+ portion observed) |

## QC trail

The 2026-05-28 campaign's QC discipline shifted from
orchestrator-safeguard C1–C8 enumeration (2026-05-22 style — apt
for the 22-issue-batch shape) to **3 codegraph-driven audits** (apt
for the Track-D drift-sweep shape):

- **QC Audit A (literal enumeration).** Independent codegraph-
  driven literal enumeration of every drift-vulnerable surface.
  Found 6 sites missed in the initial pass; verdict was
  REMAINING-VIOLATIONS-FOUND on round 1. Cleared on round 2.
- **QC Audit B (structural call-graph).** Codegraph traversal from
  each canonical-source symbol to every doc location. Found 7
  additional sites concentrated in the compliance/inventory bundle.
- **QC Audit C (regression-invariance fault-injection).**
  Deliberate-drift injection into the source-side pin tests;
  confirmed each fails loudly. **ZERO-DEFECTS-CONFIRMED on
  load-bearing pin tests.** Flagged latent-drift-risk for v0.8
  doc-drift-detection workflow.

All three audits APPROVED at final state. No HARD-BLOCK fails on
the docs+Pages remediation. The Track E (CoALA citation) audit
returned ZERO-DEFECTS-CONFIRMED on the first pass (the scope
discipline made multi-pass auditing unnecessary).

## Postgres + AGE cross-store parity at HEAD `be3347d70`

| SAL trait method | SQLite | Postgres | Cypher (AGE) | Parity |
|---|---|---|---|---|
| `store` | GREEN | GREEN | n/a | OK |
| `insert_if_newer` | GREEN | GREEN | n/a | OK |
| `update` | GREEN | GREEN | n/a | OK |
| `delete` | GREEN | GREEN | n/a | OK |
| `list` (`bypass_visibility=true`) | GREEN | GREEN | n/a | OK (post-#1138) |
| `archive` / `restore` (v51 round-trip) | GREEN | GREEN | n/a | OK (post-#1140 + v51) |
| `kg_traverse` | GREEN (CTE) | GREEN (CTE / Cypher) | GREEN (Cypher) | OK |
| `kg_timeline` | GREEN | GREEN | GREEN | OK |
| `kg_invalidate` | GREEN | GREEN | GREEN | OK |
| `recall_observations` | GREEN | GREEN | n/a | OK |
| `governance_check` | GREEN | GREEN | n/a | OK |
| `signed_events_chain_verify` | GREEN | GREEN | n/a | OK |
| `federation_nonces` (v51) | GREEN | GREEN | n/a | OK (new at v51 #1255) |
| `agent_quotas` per-namespace (v50) | GREEN | GREEN | n/a | OK (new at v50 #1156) |

## Lessons learned, in priority order

1. **Test isolation at realistic-deployment substrates is a
   distinct discipline from test-fixture pin maintenance.** The
   2026-05-22 campaign closed pin-drift; the 2026-05-28 campaign
   closed isolation-discipline at the lan-parity shared-container
   substrate. v0.7.x / v0.8 follow-up: promote the lan-parity
   stack to the CI matrix so this discipline is mechanically
   enforced.

2. **Doc pins need their own enforcing CI gate.** The 3-audit
   ZERO-DEFECTS-CONFIRMED on Track D is fragile against the next
   substrate count bump — a future PR that bumps the source count
   + updates the source pin test + forgets the docs would slip.
   v0.8 `doc-drift-detection` workflow scoped.

3. **Three codegraph-driven audits with different lenses are
   meaningfully better than one.** The 32% miss rate on the
   initial Track-D detection pass would have been customer-visible
   docs drift had the campaign closed after one pass. The
   structural lens (Audit B) caught a class of defects that the
   literal lens (Audit A) cannot see; the fault-injection lens
   (Audit C) catches enforcement gaps that no detection pass can.

4. **Scope discipline on adjacent-temptation PRs is a CI-saving
   discipline.** The Track-E (CoALA citation) PR rejected 3
   plausible-sounding adjacent enhancements (§2.8 subsection,
   §11.4.D/§22 reframing, capabilities-v3 block). Each rejected
   enhancement was a substantive design change that should travel
   under its own work order. The 3-deliverable / 3-rejection
   contract is the right shape for citation-discipline PRs.

5. **16h+ sustained dogfood with flat RSS is a load-bearing signal
   for substrate stability.** The 1hr window was the operator-set
   minimum; the extended 16h+ sample is the meaningful one. The
   PRAGMA-tuned SQLite footprint + HNSW async-rebuild double-buffer
   + Once-gated config-load WARN combine to give a flat memory
   curve under live load. Any future regression in those three
   subsystems would show as RSS growth in this window.

6. **Substrate-untouched fix PRs are the right shape when the bug
   is test-discipline.** PR #1382 closes 4 deterministic test
   failures via a new helper module; zero `src/**` change. The
   discipline: when a defect manifests at the test substrate,
   first ask "is this a test-isolation defect or a substrate
   defect?" The 4 #1381 sub-defects were test-isolation; the fix
   correctly lived at the test layer.

## Recommendation

SHIP. The release-gate Tier-1, Tier-2 (sqlite + A2A in-host via
lan-parity + postgres+AGE post-#1382), Tier-3, Tier-5, and Tier-6
(`cargo audit` + four gates + release-notes) are all GREEN at HEAD
`be3347d70` (with PR #1379 + PR #1380 + PR #1382 pending operator
merge). The Tier-2 Track D cross-node + Tier-6 24h dogfood loop
remain operator-gated per #836; they are not engineering-
completable.

The 5-issue campaign closure (#1197 + #1198 closed via PR #1379; 4
#1381 sub-defects closed via PR #1382; #1378 open + non-blocking)
validates the testing-loop discipline (pm-v3.3) — every defect
surfaced was filed at discovery, traced through fix → audit →
re-fix → audit → close, with substrate kept untouched where the
defect was test-side.

The Track-F (AI-NHI assessment v3) report, when it lands, will
provide an independent fresh-eyes structural review of the
post-fix HEAD as an additional confidence-building data point;
the SHIP-CLEARED verdict on the 5 in-host tracks does not depend
on it.

## Audit trail

| Artifact | Path / Reference |
|---|---|
| HEAD SHA | `be3347d704dad03bcc210c9eb0a517946dbe555f` |
| Lan-parity stack source | `infra/lan-parity-test/docker-compose.yml` |
| Live dogfood daemon | PID 10338, lstart 2026-05-27 16:55:25Z |
| Track-C test invocation | `cargo test --features sal,sal-postgres --release --no-fail-fast` |
| `PostgresTestEnv` helper | `tests/common/postgres_env.rs` (PR #1382 `d1d5b33de`) |
| Track-D drift fix PR | [#1379](https://github.com/alphaonedev/ai-memory-mcp/pull/1379) (3 commits) |
| Track-E CoALA citation PR | [#1380](https://github.com/alphaonedev/ai-memory-mcp/pull/1380) |
| Track-F AI-NHI assessment v3 | `docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v3.md` (in-flight) |
| Release-gate issue | [#836](https://github.com/alphaonedev/ai-memory-mcp/issues/836) |
| Prior campaign | `docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/` |
| Schema migration source | `src/storage/migrations.rs` (sqlite, v51) + `src/store/postgres.rs` (postgres, v51) |
| Federation nonces table | v51 #1255 / PR #1296 (`federation_nonces`) |
| Per-namespace quota PK | v50 #1156 (`agent_quotas` PK `(agent_id, namespace)`) |
| Prime directive pm-v3.3 | ai-memory `global/policies` memory (supersedes `cd8ede94-3376-4837-b570-9d975290ae08`) |
| Authoring agent | Claude (Opus 4.7, 1M context) |
| QC pass A (literal) | codegraph-driven enumeration |
| QC pass B (structural) | codegraph call-graph traversal |
| QC pass C (fault-injection) | regression-invariance on pinning tests |

---

*Apache-2.0, © 2026 AlphaOne LLC. Authored autonomously by Claude
(Opus 4.7, 1M context).*
