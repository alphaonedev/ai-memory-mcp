# Track F — Heterogeneous AI-NHI Assessment v3 Pointer (2026-05-28)

Track F is the parallel-dispatched heterogeneous AI-NHI assessment
v3, dispatched to a fresh Opus 4.7 (1M context) agent against the
post-drift-fix `release/v0.7.0` HEAD `be3347d70` (with PR #1379
docs+Pages remediation, PR #1380 CoALA citation, and PR #1382
PostgresTestEnv fix pending operator merge).

## Status

**IN-FLIGHT** at dossier write time. The agent was dispatched in
parallel with this dossier-build task; the report lands when the
agent returns.

## Expected report path

```
/Users/fate/v07/v07-f5/docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v3.md
```

If the report is not yet present at the time you are reading this
dossier, expect it to land at the path above. The directory
`docs/v0.7.0/heterogeneous-ai-nhi-assessment/` already exists and
hosts the prior-version reports + the assessment-framework
documentation.

## Assessment scope

The v3 assessment dispatches a fresh Opus 4.7 agent to evaluate
ai-memory v0.7.0 as a substrate for heterogeneous AI-NHI (Non-Human
Identity) operations. The dispatch frame includes:

1. **The post-drift-fix HEAD.** `release/v0.7.0` at `be3347d70` with
   PR #1379 + PR #1380 + PR #1382 effects assumed merged.
2. **The 73 MCP tools at `--profile full` surface.** Including the
   v0.7.0-net-new tools (`memory_reflect`, `memory_atomise`,
   `memory_skill_*`, `memory_persona_*`, `memory_check_agent_action`,
   `memory_rule_list`, etc.).
3. **The 26-field Memory shape + 6 MemoryLink variants** for full
   provenance + confidence-calibration + recursive-learning
   coverage.
4. **The lan-parity dual-agent topology** as the realistic
   heterogeneous-NHI substrate (alice + bob at separate HTTP ports
   against a shared pg-age postgres).
5. **The CoALA prior-art citation context** (Track E / PR #1380)
   so the agent can position the substrate against the published
   cognitive-architecture literature without conflating the
   citation with a design constraint.

## Scope discipline

Per pm-v3.3, the v3 agent operates under:

- **Recompile-retest discipline (C5 step 7).** Any load-bearing
  behavioral finding about a running MCP/HTTP/CLI daemon must
  reproduce against a freshly-spawned subprocess against the
  rebuilt binary, NOT the long-running PID 10338 (which may carry
  a binary snapshot that pre-dates code changes on disk).
- **No banned phrases.** "Non-blocking", "DEFER-TO-V080",
  "operator should…", etc. are HARD-BLOCKed by the orchestrator
  safeguards.
- **Issue-filed-at-discovery contract.** Any defect surfaced is
  filed as a GH issue at the moment of discovery, not bundled at
  the end of the assessment.

## Lineage

The v3 assessment is the third in a series:

| Version | Date | Agent | HEAD |
|---|---|---|---|
| v1 | 2026-05-24 | Claude Opus 4.7 | (pre-#1174 closure tip) |
| v2 | 2026-05-25 | Claude Opus 4.7 (independent re-dispatch) | (post-Wave-A audit-merge campaign) |
| v3 | 2026-05-28 (IN-FLIGHT) | Claude Opus 4.7 (post-drift-fix dispatch) | `be3347d70` |

The v1 + v2 reports live under
`docs/v0.7.0/heterogeneous-ai-nhi-assessment/`. The v3 report (this
campaign's instance) will land at the path noted above.

The lineage matters because the **#1315 stale-binary lesson** (from
v1 Phase-1) is the canonical example of pm-v3.3 step-7's necessity:
the v1 agent filed #1315 as a wire-layer regression that the QC
subagent's fresh-subprocess re-probe later proved was a stale-binary
diagnosis (not a substrate defect). The v3 dispatch frame
explicitly cites this lesson so the v3 agent applies step 7
mechanically from the start.

## Cross-track relationship

- Track A's 1hr dogfood + extended uptime evidence (16h+ on PID
  10338) gives the v3 agent the load-bearing daemon-stability data
  point.
- Track B's lan-parity A2A evidence gives the v3 agent the
  heterogeneous-NHI federation data point (alice + bob across
  shared pg-age substrate).
- Track C's PR #1382 fix (test-isolation discipline for the
  lan-parity shared-container path) is one of the substrates the
  v3 agent will probe — the agent should NOT re-discover #1381 as
  a new defect.
- Track D's docs+Pages remediation gives the v3 agent the
  canonical-count surface to reference (so the agent does not
  mis-cite v50 / 57 / 73-routes-instead-of-87, etc.).
- Track E's CoALA citation gives the v3 agent the prior-art
  citation discipline to mirror in its own positioning sections.

## Expected report shape

When the v3 report lands at the expected path, expect it to follow
the v1 + v2 conventions:

1. **Verdict at a glance.** SHIP-recommended / SHIP-with-caveats /
   NEEDS-REWORK.
2. **Phase-by-phase methodology.** Bootstrap, capability discovery,
   write+recall roundtrip, federation roundtrip, governance
   refusal, KG traversal, signed-events chain, etc.
3. **Per-phase findings.** Each phase ends with PASS / FAIL /
   PARTIAL plus the per-finding GH issue numbers (filed at
   discovery per pm-v3.3).
4. **Cross-cutting observations.** Wire-shape consistency,
   error-envelope discipline, capability-overlay correctness,
   heterogeneous-NHI identity-attribution behavior.
5. **Recommendations.** v0.7.x follow-up items, v0.8 design
   considerations, NO banned phrases.

## Audit trail (placeholder; will be populated when the report lands)

- Report path:
  `docs/v0.7.0/heterogeneous-ai-nhi-assessment/report-claude-opus-4-7-v3.md`
  (expected; may be IN-FLIGHT at dossier read time)
- Dispatch evidence:
  `.local-runs/2026-05-28-ship-campaign/nhi-assessment-opus-4-7-v3/`
  (dispatch artifacts)
- Prior reports:
  `docs/v0.7.0/heterogeneous-ai-nhi-assessment/` (v1, v2)
- Dispatch HEAD: `be3347d70`
- Dispatch frame: post-drift-fix (#1379 + #1380 + #1382 applied)

## Cross-reference

For the full assessment-framework documentation, see
`docs/v0.7.0/heterogeneous-ai-nhi-assessment/` index. For the
methodology that pm-v3.3 step 7 codified, see CLAUDE.md
"Verify-before-claiming + no-operator-handoffs" §"Lineage of this
step" (which cites #1315 as the canonical stale-binary example).

## Verdict: **POINTER (IN-FLIGHT)**

This track-F document is a pointer to the parallel-dispatched v3
report. The final ship-campaign verdict (in README.md) does NOT
depend on the v3 report's verdict for SHIP-CLEARED on the 5 in-host
tracks (A–E); the v3 report is an additional independent assessment
that complements the in-host evidence with a fresh-eyes structural
review.

Drafted by Claude (Opus 4.7, 1M context).
