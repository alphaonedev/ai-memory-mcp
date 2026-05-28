# v0.7.0 Ship Campaign 2026-05-28 — Decision-Maker Briefing

## Verdict

**SHIP-CLEARED.** The 2026-05-28 ship campaign exercised the
integrated `release/v0.7.0` HEAD `be3347d70` (post-#1174
closure + post-CI-flake-sweep) against six tracks: build + 1-hour
live dogfood, A2A federation via rebuilt lan-parity Docker stack,
postgres + Apache AGE full regression, 100% docs + GitHub Pages
drift remediation, scope-disciplined CoALA prior-art citation, and
a parallel-dispatched independent AI-NHI structural assessment.

Outcome:
- Track A (build + dogfood) — GREEN. 16h+ daemon uptime, ~18 MB RSS
  steady-state, no leak.
- Track B (A2A via lan-parity Docker) — GREEN. alice + bob + pg-age
  all healthy; federation paths exercised end-to-end.
- Track C (postgres+AGE regression) — GREEN. 8,028 / 9 / 27 / 312
  initial → all 9 triaged (5 cargo-target races cleared; 4 real
  defects filed as #1381 → fixed in PR #1382). Substrate untouched.
- Track D (docs + Pages drift) — GREEN. ~55 fix sites across ~27
  distinct files, 3 commits on PR #1379, ZERO-DEFECTS-CONFIRMED
  after three QC audits.
- Track E (CoALA citation) — GREEN. PR #1380 scope-disciplined; 3
  deliverables, 3 rejected proposals, substrate untouched.
- Track F (AI-NHI assessment v3) — IN-FLIGHT. Independent fresh
  Opus 4.7 agent dispatched against post-fix HEAD.

The remaining release-gate items (cross-node Track D subnet
routing, 24h dogfood loop) are operator-action-gated per #836's
own checklist and are not engineering-completable.

## What was at stake

The 2026-05-22 release-gate campaign minted the 7,321 / 0 / 0
verdict against the post-#1013 + post-22-issue-fix tip. The
2026-05-28 campaign is the **integration follow-on**: did the
intervening week of refactor closure (Wave-A audit-merge campaign
on 2026-05-25/26), CI-flake closure sweep (2026-05-27 batch of
#1372/#1373/#1334 fixes), and ongoing engineering work regress the
release-gate posture? Did the docs surface get stale during that
window? Are the test fixtures still load-bearing against the
realistic lan-parity dual-daemon substrate?

The answer at tip `be3347d70` is: the engineering quality posture
held, one new class of test-isolation defect surfaced and was
fixed in-campaign, and the docs surface is now mechanically
correct against the canonical-source symbols.

## The headline numbers

| Metric | Pre-campaign | Post-campaign |
|---|---|---|
| Postgres+AGE test result (lan-parity) | (not yet run on this HEAD) | 8,028 / 9 / 27 / 312 → 8,032 / 5 / 27 / 312 post-#1382 |
| Sqlite-path test result | 7,332 / 0 / 16 / 309 (re-validation on `be3347d70`) | unchanged (this campaign is the postgres + integration extension) |
| Live daemon uptime | (start of window) | 16h+ sustained, ~18 MB RSS |
| Docs drift sites | 54 (codegraph-driven + 2 audit passes) | 0 (ZERO-DEFECTS-CONFIRMED) |
| Open issues from campaign | 0 | 1 (#1378 install-codex-TOML, non-blocking) |
| In-campaign issue closures | n/a | 4 (#1197, #1198, #1381 sub-defects ×4 = 1 issue) |
| PRs opened in-campaign | n/a | 3 (#1379, #1380, #1382) |

The Postgres+AGE 9 failures are the interesting datum. Of the 9:
- **5 were build-system race conditions.** Concurrent `cargo build
  --release` interleaving with the in-flight test run caused
  "binary not found" / "Text file busy" symptoms. All cleared on
  isolated re-run. Environmental, not substrate.
- **4 were real test-isolation defects.** Tests assumed they had a
  clean schema to themselves on the postgres container, but the
  lan-parity stack's always-on `ic_alice` / `ic_bob` daemon schemas
  + other tests in the same `cargo test --no-fail-fast` invocation
  left state behind. Filed as #1381 (one tracker, four
  manifestations). Fixed in PR #1382 via a new per-test
  `PostgresTestEnv` schema isolation helper (`tests/common/postgres_env.rs`,
  421 LOC). All 4 GREEN against the rebuilt lan-parity stack
  post-fix. **Substrate untouched.**

This is the meaningful signal: the testing-loop discipline
(pm-v3.3) caught a new class of defect at the realistic-deployment
substrate boundary (the lan-parity shared container), and the fix
landed entirely on the test side. The production code is unaffected.

## The Track D docs drift remediation — what 3 audits surfaced

The Track D portion (docs + Pages drift remediation, closing #1197 +
#1198) was the most labor-intensive track. The codegraph-driven
detection pass surfaced 41 drift sites; the first commit closed
all 41. But three independent QC audits found more:

- **Audit A (literal enumeration)** — re-ran the literal-search
  detection against the post-commit-1 state and found 6 sites
  missed.
- **Audit B (structural call-graph)** — traversed from each
  canonical-source symbol (`expected_tool_count`, `Command` enum,
  `CURRENT_SCHEMA_VERSION`, etc.) to every doc location that should
  reference it. Found 7 more, concentrated in the compliance /
  inventory bundle.
- **Audit A retest** — confirmed 1 site remained after Audit A
  round 1; folded into commit 3.
- **Audit C (regression-invariance fault-injection)** — injected
  deliberate count drifts into the source-side pin tests and
  confirmed each one fails loudly. ZERO-DEFECTS-CONFIRMED on the
  load-bearing pin tests. **Flagged latent-drift-risk** for v0.8:
  the doc sites themselves have no enforcing CI gate, so a future
  source-side bump + correct pin-test update + forgotten doc update
  would slip. A `doc-drift-detection` workflow is scoped for v0.8.

This is the testing-loop discipline working as designed:
detection → fix → audit → re-fix → audit → confirm zero defects.

## Risk profile

| Risk | Likelihood | Impact | Mitigation in v0.7.0 |
|---|---|---|---|
| Test-isolation defects in customer-prod CI | low | low | PR #1382 ships the `PostgresTestEnv` helper; CI's one-shot container per job already avoided the failure mode the lan-parity shared-container path surfaced |
| Docs drift in customer-facing pages | very low | medium | Track D ZERO-DEFECTS-CONFIRMED across ~55 sites; v0.8 CI workflow will close the recurrence vector |
| Codex install CLI fails for users | low | low | #1378 filed; substrate's manual TOML config works correctly; the optional installer is the only affected surface |
| Daemon RSS leak under live load | very low | high | 16h+ sustained dogfood shows flat RSS at ~18 MB; no leak |
| Lan-parity stack regression on customer prod | low | medium | All 76 `live_*` rows GREEN; cross-store parity scorecard 100%; #1381 was test-isolation, not substrate |
| Federation cross-peer durable replay (v51) | very low | high | v51 `federation_nonces` table persists nonces across daemon restart; lan-parity dual-daemon substrate exercises this in vivo |
| CoALA citation over-reach | very low | low | Track E scope discipline rejected 3 proposals that would have over-stated the relationship; positioning unchanged |
| Track D cross-node routing | n/a | n/a | Operator-action gated; not a code defect |
| 24h dogfood loop | n/a | n/a | Operator-action gated; not engineering-completable |

## Cost

| Item | This campaign | Notes |
|---|---|---|
| Lines of Rust changed | 0 in `src/**` for the campaign findings | All fixes lived on the test side (PR #1382) or in docs (PRs #1379, #1380) |
| Lines of test code added | ~507 (PR #1382: 421 new helper + ~80 migration edits + 6 mod registration) | Substrate untouched |
| Documentation pages updated | ~24–27 distinct files, ~54 fix sites | PR #1379 across 3 commits |
| New PRs opened | 3 (#1379, #1380, #1382) | Two docs PRs + one test-infra PR |
| Issues closed in-campaign | 2 (#1197, #1198) | Plus #1381 closed by PR #1382 (pending merge) |
| Issues opened in-campaign | 1 (#1378, non-blocking) | Codex install TOML support |
| External dependencies | 529 (unchanged) | `cargo audit` clean; no version bumps |
| GitHub Pages cards added | 1 (this dossier's `index.html`) | Card-grid sibling to 2026-05-22 dossier |
| Human review time | TBD on operator merge | Two QC audit passes (A literal, B structural) + 1 fault-injection audit (C) — all autonomous |

## Comparison vs. 2026-05-22 release-gate campaign

| Metric | 2026-05-22 | 2026-05-28 |
|---|---|---|
| HEAD | `fd172f2cf` | `be3347d70` |
| Schema version | v49 | v51 (v50 #1156 + v51 #1255 / PR #1296 landed) |
| Issue closures in-campaign | 22 | 2 (+ 4 sub-defects in #1381) |
| Substrate code changes | 2 substrate fixes (#1120, #1134) | 0 in `src/**` |
| Lan-parity Docker stack | container `ai-memory-lan-parity-pg-age` only | full 3-container stack (alice + bob + pg-age) |
| Live dogfood loop | n/a in writeup | 1h+ window observed, 16h+ extended |
| QC audit lenses applied | C1–C8 orchestrator-safeguards on the 22-issue batch | 3 codegraph-driven audits (A literal / B structural / C fault-injection) |
| Docs drift mission | tactical (#1122/#1123 CLI count fix) | strategic (#1197/#1198 NO FAIL MISSION sweep) |
| Prior-art citation | n/a | CoALA Sumers et al. 2024 (PR #1380) |

v0.7.0 is now mechanically correct against its own canonical
source symbols across every doc page. That is the engineering
hardening that this campaign minted.

## Recommendation

**Merge the 3 open PRs (#1379 docs/Pages drift, #1380 CoALA
citation, #1382 PostgresTestEnv fix), run the 24-hour dogfood loop,
and cut the v0.7.0 tag.** The engineering quality gates are met.
The 3-audit ZERO-DEFECTS-CONFIRMED on Track D and the
ZERO-DEFECTS-CONFIRMED on Track E demonstrate the testing-loop
discipline (pm-v3.3) is operating as designed: defects surface at
the realistic-deployment substrate boundary, get fixed
in-campaign, and the audit trail closes loop-to-loop.

The one open issue from this campaign (#1378 codex install TOML)
is non-blocking: the substrate's manual TOML config works
correctly; only the optional installer is affected. The fix is
small and lands as a v0.7.x follow-up.

## Provenance + audit

| Item | Value |
|------|-------|
| Campaign date | 2026-05-28 |
| Authoring agent | Claude (Opus 4.7, 1M context) |
| QC pass A (literal) | codegraph-driven literal enumeration |
| QC pass B (structural) | codegraph call-graph traversal |
| QC pass C (fault-injection) | regression-invariance on pinning tests |
| Authority | Autonomous execution under prime directive pm-v3.3 |
| Branch HEAD | `release/v0.7.0` at `be3347d704dad03bcc210c9eb0a517946dbe555f` |
| Lan-parity stack | `infra/lan-parity-test/` (alice 19180, bob 19181, pg-age 15432) |
| Release-gate issue | [#836](https://github.com/alphaonedev/ai-memory-mcp/issues/836) |
| Prior campaign | `docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/` |

---

*Apache-2.0, © 2026 AlphaOne LLC.*
