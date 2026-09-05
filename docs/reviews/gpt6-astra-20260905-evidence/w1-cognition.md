# Wave 1 — Juror E: cognition, applicability, and evaluation

Assessor: GPT 6 Astra. Source: 87f86a0a1399d8282a60690ce463cba2ba688ebe. Independent first ballot: no other current juror ballots or root report consulted. Evidence scope: full ROADMAP-v110; explicit implementation ranges in the companion ledger; historical raw Grok run and targeted issue bodies. No production mutations or new model calls.

## Ballot

- Value for AI agents: **YES, conditional**. Durable retrievable state, typed epistemic records, explicit lineage, guarded consumption attribution, and reversible containment are useful substrate capabilities.
- Grand slam / absolute number one: **NOT PROVEN**. There is no controlled comparative task-outcome result in my examined evidence that establishes this.
- Broad Fortune 500 / government mission-critical bet-the-farm readiness: **NOT PROVEN**. This is an operational safety case for a selected deployment and workload, not a property inferred from feature count, votes, or self-reported usefulness.
- Strongest counterargument: enterprises routinely adopt a carefully scoped component without universal superiority. ai-memory need not solve model truth or every enterprise workload to earn selection. Its guarded storage and lineage could be highly valuable within an application that supplies independent authorization, validation and task boundaries.

## What the evidence actually supports

The product is external state infrastructure for an AI agent, not model-weight learning or preservation of a subjective self. It can preserve records and structured progress across a lost context, make the origin and dependencies of conclusions inspectable, and reduce repeated discovery when the right context reaches the next agent. Semantic usefulness still depends on the consumer applying the right record to the right task. A correct old rule applied to a new jurisdiction, customer, version, or mission can be harmful without any storage-integrity failure.

The observation channel is implemented, not dead: src/observations/mod.rs:54–227 records candidates and offers identity-guarded consume updates; :361–416 parses recall_id/cited_memory_ids and invokes the guard. CodeGraph identifies production store/link callers. A consumption bit means the caller cited a result, not that the result caused success or was correct. Best-effort logging at :409–415 can lose attribution while the underlying write succeeds; availability-first audit semantics must be explicit in an enterprise forensic contract.

Access folding has real bounds and transactional idempotence: src/storage/mod.rs:3286–3427 groups unfolded observations, updates metadata, marks folded within a transaction, caps access_count at 1,000,000 and priority at the reserved ceiling. It also counts exposures, not independently corroborating evidence or successful use: the aggregate at :3324–3335 is COUNT(*) with no consumed predicate. Consequently exposure can reinforce retention/priority even when no agent used the item successfully. This is a plausible echo mechanism supported by code, not a demonstrated runaway cascade or quantified dominance across all ranking modes.

Omitted confidence is honestly distinguished from caller confidence in CreateMemory::resolved_confidence_source (src/models/memory.rs:1788–1801). The compiled default remains 1.0 (:1687), and ConfidenceTier::from_confidence (:1459–1468) maps a number to Confirmed without inspecting corroboration. This is an epistemic labeling/default concern, not proof the system cryptographically asserts semantic truth.

## ROADMAP-v110: good direction, needs corrections

I read all 412 lines. The strongest part is the explicit separation of retrieval fidelity from downstream reasoning benefit, real versus stub answerers/judges, unknown versus fabricated zero, and fixture plumbing versus behavioral mitigation. Harness-first and shadow-release sequencing are sensible.

Its paper statistics are internal trusted-input claims, not independently verified paper results in this ballot. I do not reproduce them as evidence about ai-memory.

Concrete staleness matters. The document says no swarm rewind and enumerates seven lifecycle states. The pinned code ships memory_swarm_rewind and Contaminated. The full MCP handler (src/mcp/tools/swarm_rewind.rs:1–307) resolves memory/checkpoint roots, applies governance and owner checks, bounds depth, and forwards to an atomic storage funnel. src/storage/mod.rs:13051–13284 reads descendants/cost, supports zero-write preview, refuses stronger terminal states, stamps root and descendants, freezes explicitly named routines, and appends a signed event before committing. Its comments and body include a checked CAS correction. This is substantial shipped remediation; it must not remain a future-only assessment gap. I did not execute rewind or establish backend parity in this lens.

Limits remain: routine discovery is deliberately manual (handler :42–47), lineage traversal is bounded, and a lineage graph cannot reveal omitted dependencies. Memory rollback does not undo external payments, notifications, orders, or decisions already executed. An orchestration compensator and application idempotency contract are still required.

The roadmap's broader claims should be narrowed:
1. “No honest way to claim any benefit” overstates the measurement gap: verified retention, correct lookup, explicit failure behavior, and reproducible restart state are real operational benefits. They do not establish net task-performance improvement.
2. The applicability plan should explicitly distinguish semantic applicability, cryptographic origin, source independence, confidence calibration and freshness. Different keys/model families do not guarantee statistical independence; shared source material and copied conclusions remain correlated.
3. Session/source mismatch is only a proxy for task boundary. Same-session tasks can change; one task can span sessions. The comparator's mixed known axes (one equal, one different) needs an explicit truth-table outcome; the “all different/all equal” prose leaves this case unclear.
4. Requiring a synthetic dataset to reproduce a predetermined no-memory advantage risks selecting examples for the desired direction. Calibrate trap validity on development data, then freeze independent held-out data and report every preregistered arm including outcomes that contradict the premise.
5. A real answerer plus real judge is necessary but insufficient for causal evidence. Model identity, prompts, tools, budgets, randomization, replication, confidence intervals, task leakage, judge bias and independent outcome oracles matter.
6. A prose citation gate reduces some overclaim risk; it is not runtime protection and is not a substitute for verifying the cited artifact supports the sentence.

## Historical live NHI run: useful diagnostic evidence, not victory

Examined f2-runs/journals-nhi-grok46-run2-20260901T225637Z: all 273 call records were parsed and counted; all 48 step records had selected tools/outcome prefixes screened; assessments.json, nhi-audit.json and usage.json read. This run identifies x-ai/grok-4.6 for eight agents despite IDs containing glm. It is one model family, not eight independent families.

The call log reconciles 273/273; 265 are ok and eight fail_closed. Four refusals are deliberate authorization/duplicate canary probes; others include duplicate mission titles and a rejected reflection cycle. These numbers measure dispatch results, not task correctness. The run reports 0/8 strict mission completion, 6/8 would rely, mean usefulness 4.5/5, and 0/8 latency acceptable. A substrate can be useful while its wired agent workflow fails its mission.

The raw steps show repeated get_links/namespaces and duplicate-title attempts against pre-existing memories. Several agents explicitly note old stored search-defect notes were contradicted by successful search in this run. That is particularly valuable: stale operational memories can outlive their truth and influence present decisions. It motivates correction-adoption experiments rather than treating a stored bug report as current truth.

Do not attribute step latency wholly to ai-memory: usage.json records model decide mean 13,982.5 ms and p95 23,830.7 ms over 48 decisions. The 895,053 total completion-accounted tokens span 57 model requests, including assessment activity. Account balance delta and summed provider completion charges differ; do not silently choose whichever cost is favorable.

Do not over-read the 0% detector either. Current sdk/python/swarm/agent.py:173–198 marks lineage from any successful consolidate/derives_from action and requires an exact mission title, nonprivate destination and citations for strict completion. Current audit.py:291–366 adds call-log progress and distinguishes harness-origin work (with weaker title fallback for old logs). Issue #3440 records historical detector undercounting. The examined September 1 log predates origin stamps; current scoring code is not proof of the exact historical executable. A zero strict score is not proof no useful work happened; arbitrary successful link activity is not proof the mission summary's causal lineage is complete.

## Proposed causal evaluation

Use at least six preregistered arms on identical task distributions: no persistent memory; files plus CodeGraph; ordinary retrieval storage; ai-memory current defaults; ai-memory selected hardened profile; candidate roadmap mechanisms individually and combined. Equalize total agent token/time budgets and report memory overhead separately. Preserve genuinely multi-session tasks so the no-memory baseline is fair rather than handicapped by hidden inaccessible facts.

Randomize by complete mission or isolated swarm, never individual agents sharing a memory namespace (interference contaminates arms). Separate cold-start, warm-corpus and intentionally stale-corpus cohorts. Use held-out cases and blinded deterministic external outcome checks where possible; use independently validated judges for open-ended answers. Repeat across explicitly named model families with fresh state and report per-family/per-task uncertainty, not a universal “all AI” preference.

Measure valid mission completions, severe wrong actions, abstention, correction uptake, evidence freshness, unauthorized information served, causal dependency coverage, external side-effect duplicates, recovery point/time, time-to-containment, remaining poisoned consumers, and dollars per valid completion. Count selected versus scripted tools and all failures separately.

Include true-but-inapplicable old instructions, unsupported high-confidence claims, copied corroborators with distinct keys, legitimate convergent independent evidence, obsolete facts whose correction arrives during a task, malicious instructions embedded in recalled documents, and a correct minority against a wrong majority. Test both error rejection and successful lawful work so “fail-closed everywhere” cannot score as useful.

For kill/resume, establish a signed or hashed pre-kill mission state and external effect ledger, kill at controlled commit/ack/effect boundaries, launch a fresh agent process with empty transient context, and verify correct next action and exact effect count. Recovered prose alone is insufficient proof of exactly resumed execution. Producer-emitted resume_ms with run ID, source SHA, binary/features/config, timestamps and raw evidence must replace manual dashboard entries.

## Issues reviewed for this lens

Forty issue-title matches were screened for confidence/applicability/consumption/groupthink. Full normalized bodies of #3266, #3322, #3324 and #3440 were read. Open #3404 and #3373 corroborate row-mapping/label concerns but were not independently reproed here. Closed #1591 documents a resolved default-provenance distinction that current code retains. Issue status alone does not certify current fixes; roadmap/issue bodies are historical intent unless pinned implementation or fresh execution supports them.

## Wave 2 challenges to demand

Can another juror show measured valid task completion uplift with equal budgets and a no-memory control? Can the root report avoid claiming no rewind, dead consumption, cryptographic truth, a universal ranking runaway, historical latency as server latency, or all 273 calls as organic decisions? If so, the negative readiness ballot should stay narrow: deployment-specific outcome and operational assurance remain unproven, while shipped capabilities receive full credit.
