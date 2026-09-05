# Wave 2 — juror D: full-panel adversarial cross-examination

GPT 6 Astra. Read all seven Wave 1 ballots and both current assessment/test-plan drafts. Source remains `87f86a0a1399d8282a60690ce463cba2ba688ebe`. This is the requested seven-juror panel's second wave, not a claim of seven independent model families. Earlier parent context and panel exchange make judgments correlated.

## Ballot and confidence

| Proposition | Vote | Confidence and scope |
|---|---|---|
| Material value to an AI agent | **YES, conditional** | High for stored-state retrieval, guarded updates and operational handoff value. Net task-outcome uplift is not established. |
| Grand slam / absolute number one | **NO** | High that the present universal claim exceeds the evidence; not a ranking of untested competitors. |
| Broad mission-critical bet-the-farm readiness established | **NOT PROVEN** | High about the qualification gap; no assertion every bounded deployment is unsafe. |

The operations/architecture jurors' readiness NO and my NOT PROVEN differ in wording rather than present deployment action: neither authorizes broad reliance. Preserve that distinction in the table rather than manufacture unanimity on a stronger proposition.

## Challenges accepted

1. **Enterprise positive evidence overturns “only a wrapper” criticism.** C's native-tier checks and current local-durability/DLQ/projection mechanisms, plus F's snapshot/restore guards and G's tombstone/erase composition, are substantive. A useful enterprise component need not guarantee model correctness or universal dominance. The report correctly credits these while separating mechanism, historical execution and fresh application tests.
2. **Retained records are useful even without causal benchmark uplift.** E correctly rejects the roadmap's overly broad “no honest way to claim any benefit” wording. Exact recall, signed post-restart writes and preserved inbox state are benefits. I continue to reject calling them a measured fresh-model next-action guarantee.
3. **Do not carry stale negatives forward.** A/B/E identify working consumption attribution and current contamination/rewind infrastructure. G identifies repaired export row limits and transaction/panic containment. F identifies supply-chain and backup repairs. The report must preserve these corrections rather than count historic issue allegations as current defects.
4. **Response conventions can be intentional without being safe to conflate.** C's HTTP 202 local durability and A's oversized-first-row budget rule are deliberate contracts, not corruption. Compact handles can be useful. D-01 is different: the adapter returns a capture-success boolean for a legitimate *unpersisted* state without parsing that state.
5. **Outcome detection needs its own review.** E's historical strict mission score is not an unbiased oracle by mere existence; old detector undercount and scripted coverage calls matter. Both favorable questionnaires and the 0/8 mission score need their exact historical scoring scope. The draft makes this distinction adequately.

## Claims rejected or narrowed

- Reject “SIGKILL proves exact agent continuity.” The actual harness kills the memory daemon, leaves PostgreSQL and the Python clients up, reads synthetic state and performs no model decision. It proves bounded daemon-restart retention checks. Do not weaken the valid 333/333 observed result to “mere claim,” either.
- Reject “signed edge means signed current content.” B's source distinction holds; no cryptographic or rank manipulation was executed. Appropriate wording is attestation-target ambiguity.
- Reject “version mismatch demonstrates lost update.” A's independent reproduction is serious contract evidence, but the observed optimistic concurrency guard refused stale writes. The observed harm is inconsistent state, false version and extra reconciliation work.
- Reject “an unsigned backup checksum proves active corruption.” F demonstrates an authenticity boundary, not an attack. Independent anchor and trusted backup authorization are required where the mission contract depends on authentic recovery. Keep SQLite CLI and native PostgreSQL recovery separate.
- Reject “non-snapshot export is broken disaster recovery.” G establishes a convenience-export limit and missing partiality accounting. Its existing portability-incomplete marker and independent native backup route matter. A shared snapshot or explicit consistency-class disclosure is the relevant correction.
- Reject forcing benchmark arms to produce an expected winner or loser. Use held-out task randomization, not synthetic-example selection until memory underperforms.

## Independent challenge to my own D-01

Could the outer MCP dispatcher translate governance pending/ask into `isError:true`, making my isolated envelopes unrealistic? **No at the inspected source boundary.** CodeGraph first traced `dispatch_memory_capture_turn`; `src/mcp/mod.rs:2750-2752` directly forwards `handle_capture_turn`. The complete result match at `:3648-3722` serializes any `Ok(val)` into a text-content result and reserves `isError:true` for `Err(e)`. The capture handler's pending/ask branches return `Ok` before persistence. Thus the actual dispatch does not repair the adapter's missing receipt validation. This remains a source-confirmed composition plus an executed isolated parser experiment, not a fresh governed live-server reproduction.

The repeatable script is now saved as `capture-pending-probe.py` beside its JSON result. It imports the real adapters, mocks every subprocess call, and prints observations. Rerunning produced the same six results: both adapters accept pending/ask/persisted shapes, four unpersisted shapes return true without warning. No process launch, network call or production policy mutation occurred. Exact new source ranges were added to the coverage ledger.

## Required draft corrections before Wave 3

1. Replace the stale assessment subsection saying three jurors/nine ballots with the actual seven named jurors and completed 21 ballots. Do not present Wave 3 as complete until it is.
2. Carry the new F/G operational findings into the main synthesis with their limits: backup authenticity/degradation, exact-artifact qualification, convenience-export snapshot/partiality. They affect the mission-critical answer materially.
3. Name the old `resume_ms` interval precisely: **kill-to-readiness wait completion, including deliberate delay and loader drain**. Renaming it merely “daemon readiness” can still suggest a pure startup timer; distinguish health, dependency readiness, verified hydration and correct-action clocks.
4. In the experimental plan randomize by complete mission or isolated swarm, not independently among agents sharing a namespace. Shared memory creates interference between arms.
5. When adding release findings, reconcile them with root's inspected branch protection. A release workflow lacking an internal qualification gate does not establish that the whole repository has no safeguards.

## Falsifiers and remaining dissent

I would withdraw D-01 on a pinned adapter implementation that validates persisted/dedup receipts and on a governed end-to-end test showing pending/ask never increments successful-capture accounting. I would promote the continuity claim on fresh host process logs showing an empty transient context reconstructed from authorized durable state, a correct next decision and exactly reconciled sandbox effects through fault boundaries. I would support mission-critical selection for a named envelope after reproducible isolation, recovery, correction and outcome qualification.

I do not demand ai-memory preserve hidden model state or itself implement every application's external-effect transaction. I do demand that its advertised interfaces identify the boundary and that the integrated system prove the claim it sells. These are finite engineering conditions, not an impossible universal safety oracle.
