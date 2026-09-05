# Wave 2 — full seven-juror cross-examination: architecture juror G

Assessor: GPT 6 Astra. Reviewed source baseline: `87f86a0a1399d8282a60690ce463cba2ba688ebe`. This wave read all seven `w1-{retrieval,security,enterprise,continuity,cognition,operations,architecture}.md` ballots and both complete current GPT-6-ASTRA assessment/test-plan drafts. Wave 1 evidence was challenged against the existing directly read source, not promoted into independent reproduction.

## Ballot

| Proposition | Vote | Confidence |
|---|---|---|
| Operational value for AI agents | YES, within a tested contract | High |
| Universal grand slam / absolute first choice established | NOT PROVEN | High |
| Broad mission-critical bet-the-farm qualification established | NO | High |

No vote changed. The enlarged panel materially strengthens the case through distinct failure mechanisms; agreement does not produce a quantified safety probability.

## Accepted and rejected challenges

| Challenge from the full panel | Disposition |
|---|---|
| A: A memory service can be useful despite the retrieval-version defect because guarded updates refuse stale CAS. | Accept. Refusal mitigates lost updates, but fresh content combined with a fabricated version remains an avoidable contract failure and extra round trip. Do not call this observed durable corruption. |
| A/B: Confidence and signed-edge decoration can mislead a model. | Accept the interpretation risk. Reject “signed false content,” crypto bypass or ranking manipulation as claims proved by these probes. The assessment now separates these axes and preserves genesis CID semantics. |
| B: Alternate entry points can miss source-read or administrator checks. | Accept as high-priority, source-confirmed findings with the stated posture qualifications. Reject extrapolation from local shared MCP to demonstrated PostgreSQL/HTTP exploitation. The proposed common authority boundary and allowed/denied pairs address the architectural cause. |
| C: Native PostgreSQL, transactional replay and AGE recovery are already real. | Accept. My export finding cannot support “PostgreSQL is not durable,” “AGE is fake,” or “nothing beyond local CRUD works.” Extension checks, application tests, historical certificates and future fault qualification are distinct evidence classes. |
| D: Daemon survival and automatic model continuation are different contracts; Python capture may report True for pending/ask. | Accept. The isolated adapter seam is concrete evidence of false persistence acknowledgment, not proof of a policy bypass. It strengthens the need for typed receipts and host checkpoint barriers. The report fairly credits 333/333 historical acknowledged rows. |
| E: No controlled outcome uplift means no benefit at all is too strong; true memory can be inapplicable. | Accept both corrections. Retention and correct retrieval are operational benefits. A matched-information reasoning comparison asks a different question. The plan now includes separate cohorts, whole-swarm randomization and per-mechanism ablations. |
| F: Authenticated backup selection and qualified builds cannot be inferred from hashes and attestations alone. | Accept. A co-located hash is not independent origin authentication, and a build attestation does not attest unrun tests. Reject extending SQLite restore weaknesses to native PostgreSQL tooling or ignoring the repository's real branch protection. |
| G: Large modules or an incomplete convenience export alone justify rejecting any production use. | Reject. The current export explicitly labels portability incomplete, and an operator may use a separately certified native recovery contract. Module decomposition should follow shared invariant coverage, not become a destabilizing release prerequisite. |

## Adjudication of G1/G2

The current assessment's wording is faithful to the actual scope. It says PostgreSQL convenience-export pages/links lack a shared snapshot, notes discarded per-run withholding/redaction accounting, credits `portability_complete:false`, and explicitly excludes PostgreSQL-native backup from the finding.

The important issue is agent-observable semantics: the agent should be able to distinguish a point-in-time export from a live scan, and a naturally small corpus from a filtered artifact. This does not require disclosing withheld IDs or source secrets. The plan correctly requires non-sensitive counts and separate native recovery tests.

No juror identified an enclosing snapshot across the concrete calls, or a current HTTP response carrying the discarded per-run ledger. G1/G2 therefore stand as source-derived limits. No new runtime concurrent-export test was performed in this wave.

## Test-plan assessment

The plan covers the failure classes identified by the panel: canonical record fidelity, authority on indirect writers, capture receipt semantics, agent-to-business-effect continuation, projection recovery, stale/poisoned memory, backup/key/policy coordination, release provenance and matched-budget agent outcomes. Its sequence makes the investigation actionable rather than demanding every possible state before any adoption.

One precision improvement is advisable: explicitly state that CAS counters are local revision identities where the product defines them that way. Tests should require fidelity between retrieval lanes at the same endpoint and correct per-operation import/federation semantics, rather than blindly asserting that imported or independently updated replica records have equal numeric versions. Likewise, genesis CID assertions must reflect intentional identity restamping. The existing “preserve intentional representation differences” language partly covers this, but an explicit sentence would prevent an incorrect conformance oracle.

No further substantive blocker to the two drafts from this lens. Final approval still requires completed Wave 3 bookkeeping, the actual evidence files linked by the report, and accurate source coverage boundaries. A promise that 21 ballots will exist is not a completed voting scheme.

## Dissent, confidence and falsifiers

My universal vote remains NOT PROVEN rather than an absolute claim that ai-memory can never be best for a task. My readiness NO is a present decision on the broad proposed reliance; other jurors use NOT PROVEN for the same evidence boundary. This is terminological dissent, not evidence that a specific bounded deployment is necessarily unfit.

The strongest positive counterexample would be a mission-specific hardened deployment with verified identity, correct memory receipts, controlled recovery, independently checked business effects and reproducible superior task outcomes. It could justify selection without winning every benchmark or solving model truth.

Source-specific falsifiers remain concrete: show a shared export snapshot across pages and links to withdraw G1; show serialized non-sensitive per-run accounting on the inspected HTTP path to withdraw G2. An issue closure, source comment or favorable vote does not satisfy either.

## Coverage delta

No additional production source ranges were read in Wave 2; `source-coverage-architecture.json` remains the exact conservative source ledger. Full new reading was the seven first-wave ballots and both drafts. I did not repeat tests or claim other jurors' executions as my own.
