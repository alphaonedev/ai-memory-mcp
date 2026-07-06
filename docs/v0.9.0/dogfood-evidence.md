# v0.9.0 — AI-NHI dogfood evidence (GA Step 3)

> **Status: 3 CONSECUTIVE ROUNDS GREEN + real-data migration lossless.** The
> `release/v0.9.0` binary (tip `728db5b2`, built `--release --features
> sal-postgres`) was run against a **copy of the operator's live production
> memory database** (1667 real memories, schema v71) — never the original —
> to exercise the real upgrade path and the full NHI operation surface under
> real use. Decided by AI-NHI (operator delegated all decisions 2026-07-06).

## Real-data migration — v71 -> v78, zero loss

| | schema_version | memories |
|--|--|--|
| Before (operator DB copy) | 71 | 1667 |
| After v0.9.0 opened it | **78** | **1667** |

The v0.9.0 binary migrated a real 77 MB / 1667-memory database from schema v71
to v78 in-place on open, with **zero memory loss** and a clean `doctor`
health report. This is the exact migration existing users will run on upgrade —
exercised here on real data, which CI's fresh-DB tests cannot cover.

## The rounds (3 consecutive, all GREEN)

Each round, via the CLI against the migrated sqlite substrate (real NHI use;
`AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` for the behavioral flow — see the
attestation note below):

| Step | Result |
|------|--------|
| 1. store x3 | OK — memories persisted, ids returned |
| 2. recall | OK — >=1 relevant hit per query |
| 3. graph link | OK — `link <a> <b> --relation depends_on` created the edge |
| 4. secret-screen | OK — a store containing an AWS key + password was REJECTED |
| 5. forget | OK — pattern-forget removed matched memories |

**Rounds: 3/3 GREEN, 0 RED.**

## Notable dogfood findings

1. **Agent attestation is REQUIRED on writes by default (v0.9, #1751).** An
   unsigned CLI store is rejected out-of-box: `agent attestation failed:
   agent attestation is required but this write is unsigned or the agent has
   no bound public key`. This is the intended secure-default flip documented
   in CHANGELOG.md under "Breaking / secure-default changes ... (#1751)". The
   dogfood confirms the breaking change behaves exactly as documented; the
   behavioral flow above sets `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` to
   exercise the operations (the standard local-dev opt-out). Existing MCP
   users upgrading from v0.8.x must either configure a bound agent key or set
   the opt-out — as the CHANGELOG breaking-change section states.
2. **Relation validation is enforced.** `link --relation supports` is
   rejected with the valid-relation list (`related_to, supersedes,
   contradicts, derived_from, reflects_on, derives_from, decomposes_into,
   depends_on, advances`) — input validation working as intended.

## Complementarity with Step 2

Step 2 (DigitalOcean) proved the **postgres + AGE + pgvector** backend on real
cloud infra; this Step 3 dogfood proves the **default sqlite** backend, the
**real v71->v78 migration on real data**, and the write-path **attestation
secure-default** — together covering both shipped backends end-to-end.
