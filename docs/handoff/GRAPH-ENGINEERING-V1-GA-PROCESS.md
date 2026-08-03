# Graph Engineering × Grok Build — v1.0.0 GA Process Charter

**Epic issue:** https://github.com/alphaonedev/ai-memory-mcp/issues/2682  
**Kicked off:** 2026-08-03  
**Orchestrator:** AI NHI (Grok 4.5) — 100% engineering decision authority  
**North Star:** Enterprise-certify ai-memory v1.0.0 GA **ready-to-tag** as quickly as possible  

Operator-gated only: tag cut + publish. Never tags. Never `workflow_dispatch` release.yml.

---

## Why this exists

Chat turns stop. Status questions stop. A production autonomous campaign needs:

1. **Outer cycle** with falsifiable DONE (`/goal`)  
2. **Stateful graph** of gates and edges (not a prompt blob)  
3. **Beat subgraphs** for multi-agent work (workflows)  
4. **Dogfood state** (ai-memory dual checkpoint + git)  

This document + #2682 are the process SSOT. Handoff docs remain binding for environment rules.

---

## Three layers

### Layer A — `/goal` (outer cycle)

Objective ends only when independent evidence review confirms **ready-to-tag** (Gate 4 + evidence pack). Not when a PR merges. Not when the tag is cut.

### Layer B — Campaign graph

```
SessionStart
  → Gate1 structural confinement (/sync/push choke + exhaustiveness; + pull)
  → Gate2 claims (#2655 → #2656 → #2668 → #2659 LAST)
  → Capacity (#2643 authz, #2644 bulk, #2662/#2663/#2673 fed)
  → #2676 packaging Tier0 remainder
  → Gate3 measured evidence (asserted features + PG+AGE+pgvector + hostssl)
  → Gate4 agreement vote
  → Ready-to-tag tip SHA + certification note
  ✕ operator tag + publish
```

**Edges:** `strict:true` one merge at a time; one CHANGELOG writer; cutline forbids hand-enumerated confinement patches; T1–T6 → 3×3 vote; `Closes #N` inert on non-default — close manually.

### Layer C — Beat subgraph

Load SSOT → codegraph → [3×3?] → implement → rust-skills → tests → review+security → CI → merge → dual checkpoint → reclaim disk.

Workflows: `.grok/workflows/v1-ga-*.rhai`.

---

## Binding paths

| Kind | Path |
|------|------|
| Resume | `docs/handoff/GROK-4.5-RESUME-CHECKPOINT-2026-08-03.md` |
| Full handoff | `docs/handoff/GROK-4.5-HANDOFF-v1.0.0-GA.md` |
| Cutline | `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md` |
| Issues | `docs/audit/3x7-issue-register-2026-08-01.md` |
| Claims | `docs/audit/3x7-claims-register-2026-08-01.md` |
| Codegraph | `projectPath=/home/fate_two/v07/v09-dev` only |
| Rust skills | `~/.claude/skills/rust-skills`, `~/.claude/skills/rust-microsoft` |
| Memory ns | `ai-memory` — dual protocol every epic beat |

---

## Dual checkpoint (dogfood)

Every epic beat:

1. `memory_store` (namespace `ai-memory`, tags `checkpoint,epic-pointer,rolling`)  
2. `git commit` if code/docs (SSH-signed, Co-Authored-By)  
3. Refresh rolling epic-pointer content  

Standing protocol memory: `2668b316`.

---

## PR merge bar (release/v1.0.0)

1. Green required checks (check-runs API authoritative)  
2. **Code review** of the control (not the diff summary)  
3. **Security audit** of the control  
4. Merge commit only  
5. Manual issue close with evidence  

---

## Kickoff tip

`release/v1.0.0` @ `b766713b` when this process launched (#2680+#2681 Tier-0 GA blockers closed).
