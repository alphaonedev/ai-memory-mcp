# Current Objective — ai-memory v1.0.0 GA

**Status as of:** 2026-08-01
**Release branch:** `release/v1.0.0` @ `03bbd556` · **main** @ `260c3d3b`
**Owner:** the AI NHI development loop. Fable 5 orchestrates, reviews, audits, and is sole merge approver.

---

## The objective, in one sentence

**The AI NHI certifies ai-memory v1.0.0 GA as enterprise ready** — and that certification is a consensus verdict reached by adversarial vote, not an assertion.

---

## What "enterprise ready" means here

Operator definition, verbatim:

> a Fortune 500 company would bet their entire business integrating all their AI agents with ai-memory v1.0.0 GA — they would bet the entire farm on ai-memory doing **everything it claims** it can, reliably, consistently, without error.

Four consequences follow, and the first is the one most easily missed:

1. **The binding surface is the published claims, not the code.** A correct system that overclaims fails this bar. Closing every open issue would not by itself satisfy it.
2. **Reliably** — no silent data loss. A control that reports success while doing nothing is a direct hit.
3. **Consistently** — identical behaviour across backends and across runs. An enterprise runs PostgreSQL, so SQLite-only correctness is not consistency.
4. **Without error** — correctness of results, not merely the absence of crashes.

The certification must also be **falsifiable**. It names the trust boundary it certifies, rests on executed evidence against the real PostgreSQL + AGE + pgvector tier rather than on assertions, and states plainly what it does **not** cover. A certification that cannot be falsified is a rubber stamp.

---

## Certified scale claim

**500–1000 agents per cluster, composed in 500-agent modules.**

This is grounded in what the documents already support — `docs/enterprise-deployment.md` puts tier T6 at 1000+ agents per regional cluster — and it replaces the published 1M+ figure, which sits about three orders of magnitude beyond the same documents' own topology envelope.

Two axes must not be conflated, because they have different limits:

| Axis | Limit |
|---|---|
| **Agents → one cluster** | bounded by connections, pooling and contention. This is the 500–1000 number. |
| **Daemons → daemons (federation peer mesh)** | `docs/federation.md` states that beyond ~50 peers "the peer-to-peer mesh model is the wrong shape". |

So modules scale by **composition**, not by widening the mesh. Independent modules compose without limit; a *single shared memory fabric* does not, and no coordinator or gossip layer exists in the code today. That distinction is load-bearing for anyone building on the claim.

**The number is not yet earned.** The capacity table is labelled PROVISIONAL in the docs, 11 of its 14 throughput cells have no producer in `benches/` at all, and the envelope measurement script has never been run. Until measured, PROVISIONAL stays.

---

## The four gates

Certification is reached by closing these in order. Nothing is signed until all four are green.

### Gate 1 — the 25 must-close issues

The binding cut-line ruling (13 adversarial lenses, unanimous on both questions) identified 25 issues that must close before an enterprise-federation certification can honestly be signed.

**The crux is not bug count.** `README.md:60` names the adversary in the product's own words — *"an enrolled-but-untrusted peer"* — and #2489, #2480, #2504, #2529, #2532, #2536 are each that exact control failing open against that exact adversary. `docs/federation.md` states namespace scoping is applied on "every lane that can reach a write". It is not. That is not stale documentation; it is wrong about the security model.

The ruling also forbids the obvious fix. Confinement was retrofitted lane-by-lane across #1934 → #2447 → #2478 → #2479, and each wave believed it had closed the last hole. **A further hand-enumerated patch is not acceptable.** The requirement is one structural choke point on the `/sync/push` apply path, a reflection-based exhaustiveness test that fails when any new subcollection lands unconfined, and the same on the pull path.

That census has already justified itself: it found two further unconfined lanes nobody had catalogued — `action_transitions` (#2649) and `checkpoints` (#2650).

### Gate 2 — the 71 false or overclaimed published claims

265 falsifiable claims were harvested across seven published surfaces and adjudicated against the code. **71 came back FALSE or OVERCLAIMED**, nine at bet-the-farm blast radius. README and the federation docs graded DISQUALIFYING.

The finding is not that the code is bad. It is the opposite: **the engineering is repeatedly more conservative than the prose describing it**, and the code often states its own limits accurately while a document asserts otherwise.

- `src/audit.rs:913` says an anti-truncation marker *"is NOT yet implemented"*; `docs/security/audit-trail.md` publishes it as the mitigation for exactly that attack.
- `src/governance/rules_store.rs:203` warns *"Substrate is in FAIL-OPEN posture"*; `src/config.rs:1527` reports `rules_engine: "operator_signed"` on that daemon.
- `benchmarks/longmemeval/results.md` says conflating the Python shadow harness with the shipped binary *"would be dishonest"* and publishes **96.4%**; `README.md:770` publishes **97.0%** from that harness, undisclosed.

Corrections split three ways: fix the code where the claim is right, **retire the claim** where it was never going to be true, and close the recurrence gap so corrections do not drift back.

### Gate 3 — measured evidence

A dedicated, uncontended environment, because several findings were closed as unsupported for being measured on a box at load 12–45 with six concurrent lanes and a shared database mutated mid-run.

Requirements: the binary built from the release SHA with the version asserted; the certified stack SHA-pinned (PostgreSQL 18.4, Apache AGE 1.7.0, pgvector 0.8.6 — all verified current stable); and **PostgreSQL communications encrypted**, with `hostssl`-only enforcement proven by demonstrating that a cleartext connection is *refused*, not merely that TLS is configured.

The measurement harness itself must be rewritten first: the shipped one forks `curl` and three `python3` invocations per operation with interpreter startup inside the timed window, at up to 1024 workers on one box. It measures the load generator.

### Gate 4 — the agreement vote

A fresh adversarial vote against the **shipped artifact**, executed against the real data tier. Any dissent carrying an unanswered killer objection blocks. Cutting the tag remains the single operator-reserved action.

---

## Current state

| | |
|---|---|
| Open issues | 175 |
| Closed during this campaign, with evidence | 37 |
| Opened during this campaign | 99 |
| Merged to `release/v1.0.0` | 9 |
| Open PRs, all green, zero failures | 3 |

**Merged:** four performance fixes — a self-amplifying forensic-log re-read at every process start, a family query returning incomplete results above 1,000 memories, an O(corpus) integrity check on the liveness probe, a metric reporting zero on a populated corpus, an unbounded query-embedding call on the read path.

**In flight:** three PRs closing nine must-close issues; the structural choke point; the claims corrections; the measurement environment.

---

## How decisions are made

The AI NHI decides everything inside the operator's direction and constraints. Crossroads are settled by **3×3 adversarial vote** — nine independent lenses returning verdict, confidence, rationale, top risk and killer objection, tallied and recorded before implementation. Decisions are not escalated.

**Every PR is code-reviewed and security-audited before merge. Green CI is necessary and not sufficient.** Coders test their own work and report what they ran and observed, including R-203 evidence: the regression test must fail at the parent commit and pass after.

That gate is not ceremony. Three defects were found in PRs that had already merged with green CI, including one where a failing health verdict is cleared by restart — and a failing health verdict is what causes an orchestrator to restart.

---

## Schedule, and why it changed

**2–3 weeks.** The earlier 3–4 day estimate was wrong.

It was wrong because the confinement work is structural rather than six patches, and the ruling that says so had been committed to `main` but not to the release branch — so the lane briefed to do it inherited none of it. It checked the citation instead of trusting it, found the ruling absent, and stopped before writing a line of the forbidden shape. Had it complied, #1968 would have become GA-blocking and the schedule would have moved further.

All four audit documents now live on the release branch. **A binding ruling that lives only on the branch nobody develops against is not binding.**

---

## What is working

Every lane in this campaign has caught something the orchestrator got wrong: a scope-token decision that would have shipped a write/read incoherence; a premise that the write path was already gated, which was false on three caller-facing surfaces; the entire shape of a lane brief; four infrastructure errors that prior code in this repository had already solved; and an issue-filing claim that was never actually made.

Findings have been retracted when the evidence did not support them — five closed as unsupported, including one whose premise turned out to be measuring a sibling process's scratch state rather than production.

**That property is the point.** The certification is worth something only because the process keeps catching its own author.

---

*Every claim in this document is verifiable against the repository at the commits named. Where a number is provisional, it says so.*
