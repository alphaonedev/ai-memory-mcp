# Perfect Endpoint AI Memory Assessment (Grok 4.5)

> ## ⚠️ FROZEN ARTEFACT — assessed against v0.9.0. Do NOT read the default-state tables as current.
>
> Every ballot under `waves/` (and the two `w7-*` syntheses) is a **dated snapshot of the
> pre-v1.0.0 substrate**. Several of the defaults these documents assert as fact were
> deliberately FLIPPED by the v1.0.0 work these very ballots recommended, so the tables now
> understate the shipped posture. Known reversals, verified at the v1.0.0 release base:
>
> | Knob | This tree asserts | v1.0.0 reality | Flipped by |
> |---|---|---|---|
> | `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | OFF / permissive / opt-in | **ON** (`FED_REQUIRE_WRITE_SIG_DEFAULT = true`) | #1801→#1954 |
> | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | OFF / permissive | **ON** | #1801→#1954 |
> | `AI_MEMORY_CAPABILITIES` | OFF (inert GA) | **ON** (grant-only; adds no denials) | #1960 |
> | `AI_MEMORY_REFLECT_DECORRELATION_MODE` | `off` | **`advisory`** | #1952 |
> | `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` | required on ALL surfaces (v0.9 #1751) | **surface-scoped** — HTTP direct-write required, MCP/CLI permissive | #1985 |
>
> This includes `w7-a3-claims-discipline.md`: the replacement wordings that register
> *prescribes* are themselves now stale in both directions. For the current defaults use
> CLAUDE.md §"Environment Variables", `docs/federation.md`, and
> `docs/compliance/nsa-csi-mcp-security-mapping.md` — never this tree.
>
> Preserved unedited: these are the ballots that drove the v1.0.0 decisions, and re-pointing
> their numbers at today's code would falsify the record.

**Canonical product document:**
[`../UPDATED-ROADMAP-GROK-4-5-ASSESSMENT-PERFECT-ENDPOINT-AI-MEMORY.md`](../UPDATED-ROADMAP-GROK-4-5-ASSESSMENT-PERFECT-ENDPOINT-AI-MEMORY.md)

**Method:** 7 waves × 7 adversarial agents (49) against ai-memory v0.9.0 + ROADMAP.

| Artifact | Role |
|----------|------|
| `w7-a7-grand-synthesis.md` | Grand synthesis CORE draft |
| `w7-a2-v1-epic-dag.md` | v1.0.0 executable epic DAG |
| `waves/` | Per-agent ballots (W1–W7) |

Date: 2026-07-08 · Does **not** cut a release tag.
