# Track E — CoALA Prior-Art Citation Results (2026-05-28)

Track E is the scope-disciplined CoALA prior-art citation PR
**#1380** (`27828b8858967ac51745ecd2c42b5ba29052c597`). Authored as
a separate PR from Track D (docs/Pages drift) and from Track C
(test-isolation fix) per operator work order: small, focused,
scope-test-disciplined, and explicitly NOT a substrate reframing.

The work-order acceptance criteria were specific. Three deliverables
land, three plausible-sounding adjacent proposals are rejected by
scope, and no substrate code touches the wire.

## Phase summary

| Phase | Status | Detail |
|---|---|---|
| E.1 ROADMAP §2 citation | GREEN | One paragraph in ROADMAP §2 intro citing Sumers et al. as `[^2]`, plus footnote, plus revision-history entry |
| E.2 positioning.md "Relationship to CoALA" section | GREEN | Additive section appended to docs/positioning.md; no existing content modified |
| E.3 docs/strategy/coala-mapping.md (NEW) | GREEN | New reference document mapping ai-memory primitives to the CoALA framework |
| E.4 §2.8 subsection rejected | REJECTED (per scope) | "Adding a §2.8 'Relationship to Prior Art (CoALA)' subsection to ROADMAP" — declined; would reframe roadmap structure |
| E.5 §11.4.D / §22 reframing rejected | REJECTED (per scope) | "Restructuring §11.4.D + §22 to claim CoALA-mapping-as-design-principle" — declined; would change positioning |
| E.6 `coala` capabilities-v3 block rejected | REJECTED (per scope) | "Adding a `coala_mapping` block to the v3 capabilities envelope" — declined; would change wire shape |
| E.7 No substrate code touched | GREEN | Zero `src/**` change; zero schema change; zero capability-block change |
| E.8 Audit verdict | GREEN | ZERO-DEFECTS-CONFIRMED |

**Verdict at a glance: SHIP-CLEARED (ZERO-DEFECTS-CONFIRMED).** The
3 deliverables land; the 3 rejected proposals are documented as
out-of-scope; substrate is untouched.

---

## What is CoALA, and why this citation?

CoALA — **Co**gnitive **A**rchitectures for **L**anguage **A**gents —
is the framework introduced by Sumers, Yao, Narasimhan & Griffiths
in "Cognitive Architectures for Language Agents," TMLR 02/2024
(arXiv:2309.02427). The framework partitions language-agent
architectures into memory modules (working / long-term: episodic /
semantic / procedural), action space (internal vs. external), and a
decision procedure that loops over the action space against
working+long-term memory.

ai-memory is, mechanically, a long-term memory substrate for
language agents. It implements primitives (episodic recall,
semantic embedding-based retrieval, procedural skill registry,
namespaced isolation, governance gates) that map cleanly onto the
CoALA module taxonomy. The operator decision is: **cite the
prior art, acknowledge the conceptual lineage, but do NOT reframe
ai-memory's design as "CoALA-implementing."** The design history is
independent; the mapping is post-hoc; the substrate has its own
seven §2 properties that remain authoritative.

PR #1380 makes the citation discipline explicit and adds the
post-hoc mapping as reference material (not constraint).

## Phase E.1 — ROADMAP §2 citation

The commit adds one paragraph in ROADMAP.md §2 introduction citing
Sumers et al. as `[^2]`, plus the `[^2]` footnote definition, plus
a revision-history entry.

The paragraph is additive — no existing §2 content modified. The
footnote points readers to the arXiv URL + the TMLR DOI. The
revision-history entry is dated 2026-05-28 and pairs the addition
with PR #1380.

## Phase E.2 — positioning.md "Relationship to CoALA" section

A new "Relationship to CoALA" section is appended to
`docs/positioning.md`. The section:

1. Names CoALA + the Sumers et al. 2024 reference.
2. Acknowledges the conceptual lineage (long-term memory for
   language agents).
3. States that ai-memory's design is independent and that the
   mapping is post-hoc reference material.
4. Points readers to `docs/strategy/coala-mapping.md` for the full
   mapping table.

The section is **additive** — no existing content of
`docs/positioning.md` is modified. The "Moonshot synthesis" and
"seven §2 properties" framings remain authoritative; CoALA is
reference, not constraint.

## Phase E.3 — docs/strategy/coala-mapping.md (NEW)

The new reference document `docs/strategy/coala-mapping.md` maps
ai-memory primitives to the CoALA framework:

| CoALA module | ai-memory primitive | Source path |
|---|---|---|
| Working memory | (out of scope; ai-memory is long-term substrate) | n/a |
| Long-term: episodic | `Memory { memory_kind: Observation \| Event \| Conversation }` + `recall_observations` ledger | `src/models/memory.rs` + `src/observations/` |
| Long-term: semantic | `Memory { memory_kind: Concept \| Claim \| Entity }` + embedding-based recall | `src/models/memory.rs` + `src/reranker.rs` + `src/hnsw.rs` |
| Long-term: procedural | `memory_skill_register` + `memory_skill_get` + `memory_skill_resource` + `memory_skill_compositional_context` | `src/skills/` + `src/mcp/tools/skill_*.rs` |
| Action space: internal | `memory_reflect` (recursive learning) + `memory_atomise` + `memory_consolidate` | `src/atomisation/` + `src/synthesis/` + `src/mcp/tools/reflect.rs` |
| Action space: external | (out of scope; ai-memory is substrate, not agent loop) | n/a |
| Decision procedure | (out of scope; ai-memory is substrate, not agent loop) | n/a |
| Governance / rules | `memory_check_agent_action` + `memory_rule_list` (signed L1-6 substrate rules) | `src/governance/` |

The document is **reference material** — the operator-set
positioning is unchanged. The mapping is post-hoc; ai-memory's
design history pre-dates CoALA's 2024 publication.

## Phase E.4 — §2.8 subsection rejected (per scope)

**Proposal:** Add a §2.8 subsection to ROADMAP.md titled
"Relationship to Prior Art (CoALA)."

**Disposition:** REJECTED.

**Reasoning:** A §2.8 subsection would reframe the roadmap as
hierarchically including CoALA as one of its design considerations
— elevating the post-hoc mapping to first-order roadmap status. The
operator decision is the opposite: cite as prior art at the §2
introduction level, not subsection. The citation belongs at the
introduction, not in a sibling-of-§2.1-through-§2.7 slot.

## Phase E.5 — §11.4.D / §22 reframing rejected (per scope)

**Proposal:** Restructure §11.4.D and §22 of the ROADMAP to claim
CoALA-mapping-as-design-principle.

**Disposition:** REJECTED.

**Reasoning:** §11.4.D + §22 contain the operator-set positioning
(seven §2 properties, moonshot synthesis). Reframing them to claim
CoALA as a design principle would re-positions the entire roadmap
around the post-hoc citation. The operator decision is the
opposite: positioning is unchanged; CoALA citation is additive.

## Phase E.6 — `coala` capabilities-v3 block rejected (per scope)

**Proposal:** Add a `coala_mapping` block to the v3 capabilities
envelope so MCP/HTTP clients can discover the CoALA-module-to-tool
mapping at runtime.

**Disposition:** REJECTED.

**Reasoning:** This would (a) change the wire shape (v3 capabilities
schema is operator-frozen for v0.7.0), (b) require code changes in
`src/mcp/tools/capabilities.rs` (substrate change for a citation
PR — out of scope), (c) couple the substrate's wire contract to a
post-hoc mapping that is intentionally reference-only, not
constraint. The mapping lives in markdown reference material; if
runtime discovery becomes useful later, it can be added as a
separate scope-disciplined PR with its own work order.

## Phase E.7 — No substrate code touched

**Files touched by PR #1380** (`27828b885 --stat`):

```
ROADMAP.md                       | <small diff>
docs/positioning.md              | <appended section>
docs/strategy/coala-mapping.md   | NEW
```

- Zero `src/**` change.
- Zero schema change.
- Zero capability-block change.
- Zero wire-shape change.
- Zero test addition (reference docs do not require regression
  tests).

This is the scope-discipline contract: the PR is exactly what the
work order described, no scope creep, no plausible-sounding
adjacent enhancements absorbed mid-PR.

## Phase E.8 — Audit verdict: ZERO-DEFECTS-CONFIRMED

The audit pass against PR #1380 verified:

1. The 3 deliverables (ROADMAP citation, positioning section, new
   reference doc) all land as described.
2. The 3 rejected proposals are documented as out-of-scope (not
   silently absorbed, not silently skipped without explanation).
3. No substrate code is touched.
4. No wire shape is changed.
5. The new reference doc explicitly states it is reference-only,
   not constraint.
6. The positioning's "Moonshot synthesis" and "seven §2 properties"
   remain authoritative.

**Verdict: ZERO-DEFECTS-CONFIRMED.**

## Cross-track relationship

- PR #1380 is **separate from** PR #1379 (Track D docs+Pages drift
  remediation). The two were intentionally not combined because
  the work orders are different: Track D is mechanical correction
  of stale numbers, Track E is a citation discipline decision
  with explicit scope rejections.
- PR #1380 is **separate from** PR #1382 (Track C test-isolation
  fix). The two are different categories of change.
- The combined effect of Tracks D + E is: by the time both PRs
  merge, every doc surface that should cite the canonical counts
  cites them correctly, AND the CoALA prior-art citation is in
  place at the right scope (§2 introduction, positioning section,
  reference doc).

## Verdict: **SHIP-CLEARED (ZERO-DEFECTS-CONFIRMED)**

The CoALA prior-art citation lands as the 3 deliverables exactly as
described in the work order. The 3 rejected proposals are
documented. Substrate is untouched. The mapping is reference, not
constraint.

### Strengths
- Scope discipline is mechanically enforceable: the diff is so
  small + so contained that any future PR that tries to absorb
  "while we're here, add CoALA to capabilities" would be a visibly
  separate change.
- The reference doc gives readers the full post-hoc mapping
  without requiring the substrate to declare CoALA-compliance.
- Operator's positioning (seven §2 properties + moonshot synthesis)
  is preserved verbatim; CoALA is cited at the §2 introduction
  level only.

### Audit trail
- PR [#1380](https://github.com/alphaonedev/ai-memory-mcp/pull/1380)
- Commit `27828b8858967ac51745ecd2c42b5ba29052c597`
- Files touched: ROADMAP.md, docs/positioning.md,
  docs/strategy/coala-mapping.md (NEW)
- Substrate: untouched
- Reference: Sumers, Yao, Narasimhan & Griffiths, "Cognitive
  Architectures for Language Agents," TMLR 02/2024
  (arXiv:2309.02427)

### Recommendation
SHIP. The CoALA citation is scope-disciplined, reference-only, and
preserves operator positioning verbatim. ZERO-DEFECTS-CONFIRMED.

Drafted by Claude (Opus 4.7, 1M context).
