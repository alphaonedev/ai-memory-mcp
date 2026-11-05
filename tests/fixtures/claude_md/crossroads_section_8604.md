## Crossroads decision protocol — 1x3 adversarial vote with a threshold (operator-set 2026-06-18, slimmed 2026-10-10)

> Canonical memories: ai-memory `4d3ea1c5-9017-4f97-b966-e0d41e83a801`
> (`global`, long tier, priority 10; the T1-T6 conditions, original) and
> `6def5ab6-2b47-4600-8608-b850717413d2` (the 1x3 shape + usage threshold;
> supersedes the 5-agent shape). This section is the repo-enforced mirror so
> EVERY agent — not just one with those memories recalled — applies the same
> rule. Operator directive, 2026-10-10, verbatim: "set a threshold do a 1x3
> voting scheme slim it down - set a threshold for when it should be used -
> otherwise do not use it for trivial things".

**The standard.** At a genuine, costly crossroads do NOT idle-wait and do NOT
unilaterally guess: run a **1x3 adversarial vote** (one round, three agents),
synthesize the verdict, and execute it. Forward motion AND a verified
decision, at a fraction of the former 5-agent cost. The vote is for
hard-to-reverse choices only; it is never run for trivial ones.

**Condition (T1-T6).** A vote is a candidate whenever **ANY** condition `Tn`
holds:

- **T1 — public-contract shape change** with ≥2 viable forms: a SAL
  `MemoryStore` trait method signature add/change; a new/renamed public
  struct/enum field crossing a module boundary; a new MCP tool / HTTP
  route / CLI subcommand; a wire-JSON or DB-schema (migration) shape.
- **T2 — a sync↔async boundary decision** (wiring async into a sync path
  or vice-versa; `block_on` vs callback-bundle vs channel). *(This is the
  condition that fired for #1729 signal hooks.)*
- **T3 — a security/governance posture choice**: fail-open vs
  fail-closed, a new gate / auth / visibility / encryption boundary, or
  relaxing an existing gate.
- **T4 — a hard-to-reverse representation**: on-disk format, persisted /
  attested / signed-bytes layout, or anything that becomes a back-compat
  obligation once shipped.
- **T5 — deviation from a written spec / acceptance criterion** (doing
  other than what the issue or `§`-spec literally prescribes).
- **T6 — ≥2 mutually-exclusive implementation paths** where the codebase
  has **no single clear precedent** to copy.

**Threshold (BOTH must hold, otherwise do not vote).** Vote ONLY when
(1) a `T1`-`T6` condition matches, AND (2) the choice is hard to reverse or
safety-bearing, meaning one of: a public contract or wire / on-disk format
(`T1` / `T4`); a fail-open vs fail-closed or gate-relaxation posture (`T3`);
the same work has failed review twice on the same defect class; or reversing
the choice would cost a full lane round (~2 h) or touch 3+ files across
module boundaries.

**No vote (decide and build; write one line `decision: X over Y because Z`
in the commit body or issue comment):** naming, wording, docs, test
structure, numeric ceilings / timeouts / budgets, which branch to cut or how
to sequence landings, LOW / MEDIUM review findings, choosing between
mechanically equivalent implementations when a precedent exists, and anything
reversible inside one commit.

**Exempt (decide & build, NO vote — record the decision inline in the
commit / issue comment instead):** internal-only refactors with no
public-surface change; naming / comments / error-message wording / test
structure; mechanical edits dictated by an existing precedent (e.g. add a
field to all N construction sites); single-correct-answer bug fixes;
error-code / HTTP-status mapping that mirrors an existing pattern; no-op /
idempotent semantics. When a precedent exists and is being copied, **T6
does not fire** — copying the precedent IS the decision.

**Vote shape (fixed).** One round, exactly **3 concurrent read-only
scout-tier `Agent` calls**, each a **distinct adversarial lens** (diversity is
mandatory so they do not converge by groupthink, e.g. precedent /
correctness-and-safety / blast-radius). The prompt carries the measured facts.
Each returns `VERDICT / CONFIDENCE / RATIONALE (<=120 words) / TOP_RISK /
KILLER_OBJECTION`. The majority decides; a 1-1-1 split means the conductor
decides and records why. `memory_store` the decision (options, tally, chosen
pathway, why) BEFORE implementing. Budget cap ~25k tokens per voter (~75k total). Voters do NOT re-derive the measured facts the prompt carries (6def5ab6).

**Audit.** If the threshold was met, the commit / issue note MUST cite
`3-agent vote (6def5ab6)`. Shipping a change that clears the threshold
WITHOUT a vote is a self-flagged process violation the agent must surface to
the operator (and the orchestrator treats it the same as a C1–C8 hard-block
on agent return). Prior 5-agent votes (`4d3ea1c5`) stand.
