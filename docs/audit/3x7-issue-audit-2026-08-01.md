# ai-memory v1.0.0 — 3×7 Issue Audit

**Date:** 2026-08-01
**Scope:** All 180 open issues, audited against the live `release/v1.0.0` codebase
**Method:** Seven independent adversarial review lenses, plus two challenge lenses aimed at the audit's own output
**Codebase state:** HEAD `5449b6da`, verified identical to `origin/release/v1.0.0`
**Status:** Round 1 complete

---

## Executive Summary

We audited every open issue against the actual code, rather than against what the issues claim. Three things came out of it.

**First, the issue backlog was materially wrong in both directions.** Nine issues were already fixed and still sitting open, because GitHub's `Closes #N` automation does not fire on a non-default branch — so completed work never closed itself. In the other direction, several headline findings did not survive contact with their own evidence: one measured a sibling process's scratch state and reported it as production, another rested on a graph 64× too small to be representative, a third had three of its four load-bearing claims refuted by the engineer who fixed it.

**Second, we found defects in work merged the same day.** Two of the three performance fixes that landed during this audit introduced new problems — one of which converts an orchestrator's own remediation into a mechanism for serving corrupt data. Both were caught by pointing the audit at ourselves, not by CI.

**Third, and most significant: several of the controls that certify this system's safety do not work.** The supply-chain gate that enforces the project's strictest rule verifies two packages out of 558. The gate proving that all other CI gates function is not itself required. A destructive-operation hook that operators can configure has no implementation outside test builds.

None of these produced a visible failure. Every one of them reports success.

### By the numbers

| | |
|---|---|
| Open issues at audit start | 180 |
| Verified already fixed, closed with evidence | 9 |
| New defects filed during this audit | 10 |
| Findings refuted or materially corrected | 6 |
| Duplicate clusters identified for merge | 4 |
| Crossroads decisions, adjudicated by 3×3 vote | 12 |
| SSOT constants checked — all correct | 8 of 8 |

### The five findings that matter most

| # | Finding | Why it matters |
|---|---|---|
| **#2635** | The supply-chain build-script gate iterates a 2-entry ledger while the dependency tree has 558 packages. It never checks the reverse direction. | This is the mechanical enforcement of "no external code injection, ever." A new dependency with hostile compile-time code passes with a green `PASS`. |
| **#2630** | A failing health check is cleared by restarting the process — and a failing health check is what causes orchestrators to restart processes. | The system serves traffic over a corrupt search index for up to five minutes on every restart, in a loop the orchestrator itself drives. Introduced by a fix that landed today. |
| **#2567** | Boot-time migration erases stored embeddings using a `force` flag, on daemons that may have no ability to regenerate them. | Destroys derived data that cannot be rebuilt, unattended, before any user request is served. PostgreSQL deployments have no repair path. |
| **#2538** | The named-approver authorization check is a bare string comparison — no self-approval check, no registration check, on both storage backends. | Whoever the request claims to be, is. This converts every other authorization gap into a full execution path. |
| **#2636** | The gate that proves the other 24 CI gates actually function is not itself a required check. | A change that breaks it merges. This is the same defect the project fixed one level down two weeks ago, recurring one level up. |

---

## 1. What Was Audited, and How

### The structure

Seven lenses examined all 180 open issues simultaneously, each from a different angle, each verifying claims against the real code rather than against issue text:

| Lens | Question it asked |
|---|---|
| **Stale / already-fixed** | Does the code this issue describes still exist in the form the issue assumes? |
| **Data integrity** | What is silently lost or wrongly reported, and can the operator tell? |
| **Security & confinement** | What is the trust boundary, who is on each side, and does it fail open? |
| **Backend parity** | Do the SQLite and PostgreSQL adapters mean the same thing? |
| **Contract & documentation drift** | Does what we say match what the code does? |
| **Dependencies & sequencing** | Which issues are duplicates, which block which, and in what order should they be fixed? |
| **Gate & test soundness** | Would this control actually fail if the defect it targets came back? |

Two further lenses were pointed at the audit itself: one challenging the evidence behind our own findings, one challenging the fixes we had already merged.

### What makes these results trustworthy

Every claim in this document was verified by reading the code at a known commit. Where a lens could not settle a question without running something, it said so and stopped rather than guessing — those items are marked as needing execution and are not presented as findings.

The lenses were deliberately told that the audit had already produced confident-but-wrong claims, and were given those instances as worked examples. Finding that our own work was weak was treated as a more valuable result than confirming it.

### What this audit does not cover

- **Runtime behaviour under load.** The lenses ran read-only while a performance measurement occupied the machine. Claims requiring execution are flagged, not asserted.
- **Completeness of the issue corpus.** We audited what is filed. Defects nobody has noticed are, by definition, out of scope.
- **The live PostgreSQL tier.** Deliberately untouched, to avoid disturbing a shared certified environment.

---

## 2. Findings by Severity

### 2.1 Controls that report success while doing nothing

This is the most consequential category, because each item actively creates false confidence. A missing control is a known gap; a control that reports success is a gap nobody is looking for.

**#2635 — The supply-chain gate verifies 2 of 558 packages.**

The script is presented in CI as *"Verify reviewed build-script pins and closure"*. It loops over the entries in a ledger file. That ledger contains two packages. The dependency tree contains 558, dozens of which run code at compile time.

There is no reverse check — nothing looks for a package that runs compile-time code and is *absent* from the ledger. A new dependency with a hostile build script is never examined, and the gate prints `PASS (2 records verified)`.

Three factors compound it: the gate has no self-test (the only one in the project without one, so there has never been evidence it works); it runs inside a job that reports "skipped" for documentation-only changes, which branch protection counts as satisfied; and it is the one supply-chain check written outside the main test suite.

This is the mechanical enforcement of the project's firmest standing rule, adopted after an external party attempted precisely this vector — including recommending a package that did not yet exist, so that they could publish it later.

**#2636 — The gate that proves the gates work is not required.**

Four integrity gates run on every pull request and are required by nothing. One of them is the check that proves the other 24 required gates are creatable, reachable, non-skipping and correctly named. A change that breaks it merges without comment.

This is structurally identical to a defect the project fixed two weeks ago, where the job classifying changes governed eleven required checks while being required by nothing. The same shape has reappeared one level up. The document that records this gap lists two of the four instances and misses the two most important — including the one protecting the document.

**#2637 — A destructive-operation hook with no implementation.**

Operators can configure a hook to interpose on memory compaction, which permanently deletes near-duplicate records. The function that fires that hook exists only in test builds, returns a hardcoded `true`, and carries a comment noting that the tests assert the constant is referenced.

So the tests verify that a test-only stub mentions a name. In production the hook does not exist. An operator who configures it — with failure-closed semantics, believing they have interposed on a destructive path — has interposed on nothing. The configuration is accepted and the deletion proceeds.

**#2486 — Commit signing that cannot reject anything.** Signature enforcement on release branches is self-satisfying: the platform creates *and signs* merge commits with its own key, so the rule signs whatever it merges. It should be struck from the control inventory rather than counted.

**#2548 — Tests that never run.** Every PostgreSQL and graph-database test cell is gated behind an opt-in flag whose only runner is a nightly job that executes from the default branch — where these tests do not exist — and which is currently failing. Several merged security fixes rest entirely on one engineer's local machine.

### 2.2 Data integrity — silent loss and wrong results

The project's stated priority order is: never corrupt, never lose data unintentionally, degrade rather than return wrong results. These findings are ordered against that standard.

**#2567 — Boot migration erases embeddings it cannot rebuild.** On startup, a PostgreSQL daemon runs a dimension migration with a `force` flag that deliberately bypasses the safety check protecting stored vectors. Nothing verifies that this process can actually regenerate them. A daemon started with inference disabled will erase every stored vector and have no means of refilling them — and the repair tool does not support PostgreSQL. Unattended, irreversible in practice, before any request is served.

**#2588 / #2551 / #2550 / #2552 — Bulk writes report rows they did not write.** A single funnel produces four distinct failures: a quota rejection rolls back the entire batch but returns HTTP 200 with one opaque word (31,000 rows dropped, no log); the success count reports rows *sent* rather than rows *persisted*; caller-specified sharing scope is silently downgraded to private; and every row error collapses to the same message. Root cause is common — the bulk path re-implements the single-write path instead of calling it — so one correction closes the cluster.

**#2569 / #2570 / #2571 — The system cannot re-import its own backup.** The default import mode cannot restore onto an existing corpus at all. Any record that was ever edited makes its own backup un-importable. And the export omits archived records and governance bindings entirely. Disaster recovery does not round-trip. This is at least loud rather than silent — but a backup that cannot be restored is the worst possible place for a latent failure.

**#2564 — Zeroing a version number replays every migration with the safety snapshot suppressed.** The upgrade guard protects against a database *newer* than the binary. It does not protect against one reporting version zero, which reads as "fresh" — so the full migration ladder replays over a populated database, and because the pre-migration backup is conditional on a non-zero version, that backup is skipped.

**#2600 — Quarantined records are served as truth.** Records held back for lacking provenance are structurally hidden from every read path except one — an always-available tool that hands them to agents as substrate truth. A failure-closed control with a hole in it is worse than no control, because it is trusted.

**#2385 — Restoring an archived record changes its permanent identity.** The archive table does not carry the content-address columns, so restoration mints a new one while existing references still point at the original. Provenance links dangle silently, with no write intent and no signal.

**#2436 — A safety mechanism that can never fire.** The contradiction-penalty check compares a JSON boolean against the string `'1'` on PostgreSQL. It matches nothing. A record the system has already determined to be contradicted is served at full rank on the backend every multi-tenant deployment must use. SQLite applies the penalty correctly — the two backends rank the same query differently.

**#2621 — A metric that certifies its own wrong answer.** On PostgreSQL deployments the record-count gauge reads from the local SQLite file, reporting zero for a populated corpus. A companion freshness timestamp — added specifically so a stale gauge would be detectable — is updated correctly. The detector actively certifies the wrong number.

### 2.3 Security — authorization boundaries

**#2538 — Named-approver authorization is a string comparison.** The approval path supports three approver types. Two of them check for self-approval and verify the approver is registered. The third — the one selected specifically to name a single approver — does neither. The requester approving their own request satisfies it. Identical on both backends.

There is a trap in fixing this: the relevant method is overridden on SQLite only, and PostgreSQL falls through to a shared default. A correction applied to the obvious place would not reach PostgreSQL.

**#2633 — A typo makes a private record public.** An unrecognised sharing-scope value resolves to *broadly visible*. A record with no scope set defaults to private; a record with a misspelled scope is world-readable. These two behaviours are one character apart. This violates the project's own established rule that an unrecognised value must never widen a posture.

**#2504 — One malformed character disables every federation boundary.** A parse failure in the peer configuration falls back to an empty allowlist, and that emptiness is the master switch for the namespace confinement gates *and* the unenrolled-peer rejection. Two controls designed to be independent share a single failure point. The warning message issued in that state describes the read path as denying by default and says nothing about the delete path, which becomes permissive.

**#2541 — A gate that only fires if the attacker opts in.** The ownership check on namespace governance runs only when the caller volunteers an identity field. Omitting the field skips the check entirely. The exemption is keyed on a self-asserted request field rather than on the authenticated principal.

**#2489 — Two federation lanes remain unconfined.** Namespace scoping was added to the write and delete paths. Signals and links were not covered. A peer restricted to one namespace can still deliver signals into another, and can plant relationship edges — including the "contradicts" and "supersedes" types that influence ranking — against a namespace it cannot read.

**#2529 — A decided governance action can be rolled back over the network.** The federated upsert overwrites all columns including status and decision fields. A rejected action can be flipped back to pending, re-armed with attacker-chosen content, and its approval list overwritten.

### 2.4 Documentation and contract accuracy

All eight mechanically-pinned constants are correct. Every file-and-symbol citation in the 151-row environment variable table resolves. The drift is concentrated where no gate looks.

**Eleven locations still state the HTTP route count as 92 or 93; the actual figure is 94.** Only the five phrasings matching the gate's exact pattern were updated. Six documentation files carrying the same claim are not in the gate's scan list at all — including one that states it in the gate's *exact* matching syntax and is missed purely because the file was never added.

**#2629-class — the gate checks values but not symbols.** Prose naming a function or a file is entirely unguarded. A reader searching for the referenced function finds it, and concludes the documentation is current.

**A published specification understates a closed vocabulary.** The normative specification, served at the project's canonical URL, states that relationship types are "a closed set — six variants". There are nine. An importer written against that table drops three types. This is the precise failure mode the project's own gate comments cite as the reason the gate exists.

**One gate rule is dead.** The relationship-count rule's pattern matches zero lines anywhere in the corpus, and the only string it could ever accept is historically false. That constant has no documentation-side enforcement at all, while a docstring in the code asserts it is the single source of truth for exactly that narrative.

---

## 3. Work Completed During This Audit

Three fixes were merged to `release/v1.0.0`, each with proven semantics rather than assumed ones.

| Merged | What it corrected | Evidence of correctness |
|---|---|---|
| `30c25974` | Every command re-read the entire day's audit log at startup — self-amplifying, since each run appends to the file it will re-read. Also: a family query applied its row limit *before* filtering, returning incomplete results above 1,000 records. | Both binaries, given identical copies of the real 39,660-line log, produced identical cryptographic chain hashes. A 74-shape comparison returned 72 byte-identical. |
| `b820a313` | The health endpoint ran a full search-index integrity check on every probe. The record-count metric ran full table scans per scrape. | Backend gating verified on both adapters; the corrupt-versus-unavailable distinction preserved end to end. |
| `5449b6da` | Composite ordering indexes had never been created on PostgreSQL. The recall ledger wrote one row per round trip. A query fetched every column including embedding vectors. | Every column read by the mapper enumerated against the shipped schema; query plans measured identical with and without the new index. |

Nine further issues were verified as already fixed and closed with evidence, several with an explicit correction of the record where the fix was right but the original diagnosis was wrong.

---

## 4. What the Audit Found in Its Own Work

This section exists because the audit's credibility depends on it. Every item below was self-reported.

**Measurements taken on a contaminated machine.** Several latency figures were captured while the machine was heavily loaded, with concurrent builds and a process sweep running. One finding's central premise — that a database index existed — was true only because a sibling process had created it minutes earlier on a shared instance. It measured its neighbour's scratch state and reported it as production.

**Statistics computed from too few samples.** A reported *+184% regression* became a *−32.1% improvement* once the sample count rose from 100 to 300. At 100 samples the 99th percentile is simply the maximum. Had it shipped, we would have filed a phantom regression against our own correction.

**Premises asserted rather than verified.** The orchestrator introduced three false premises into lens briefings: a claimed field mapping that was wrong three ways; cold-start latency presented as steady-state; and an embedding dimension taken from a configuration *example* rather than the live schema. Each was caught by a lens refusing to accept it.

**A performance win correctly refused.** One engineer was handed a change that would improve the headline metric and declined it, because the speedup came from truncating documents — buying latency by discarding content. At the proposed setting, 91.8% of test pairs would have been truncated. A relevance regression priced as a performance win.

**Three benchmark harness defects caught before publication.** A parent binary built with different features than the one under test (the tell: the *patched* binary was smaller, which is impossible when a change only adds code). A comparison baseline pinned to a moving branch tip, which would have folded another engineer's work into our own measured improvement. And a broken model path that silently downgraded *both* sides to a fallback scorer — while the response field still reported the full pipeline.

That last one produced the audit's most reusable rule: **a downstream field agreeing with you is not proof the upstream component ran.** The tell was an implausibly fast result. A number that is too good is a defect report, not a result.

---

## 5. Crossroads Decisions

**These are decided by the AI NHI development loop, not escalated.** Each item below is a genuine crossroads — it changes what is worth building rather than how to build it — and each is adjudicated by a **3×3 adversarial vote**: nine independent lenses returning a verdict, confidence, rationale, top risk and killer objection, tallied and synthesized into one decision that is recorded before implementation and cited in the resulting change.

The standing governance is: the operator sets direction and constraints; the development loop decides everything inside them and keeps building. The single reserved action is cutting a release tag, which is a release action rather than a decision.

What follows is therefore the *docket* — the twelve crossroads identified by this audit, with the evidence each vote must weigh. Outcomes are recorded against each issue as the votes conclude.

### 5.1 The reranking question — governs roughly eight issues

The neural reranking stage runs *after* results are truncated to the requested page size. It therefore cannot change **which** records are returned — only their order within an already-fixed set. Across twenty test queries it never changed the top result.

It costs approximately 1.1 seconds per query and caps throughput at roughly 2 queries per second per node.

An accidental measurement during this audit gave the comparison: the lightweight scorer returns in 173 milliseconds against the neural path's ~1,290 milliseconds. That figure came from an invalidated run and is a pointer, not proof — nobody has yet checked whether the lightweight ordering is *worse*, only that it is far cheaper.

**The candidate positions the vote must weigh:** default it off for the release and keep it opt-in; widen the candidate pool so it can genuinely affect results, accepting slower queries in exchange for better ones; ship as-is with the limitation documented; or run the measurement first — set overlap, top-result agreement, ordering divergence — which existing tooling can do.

Paying the cost without knowing which of these is right is the one position the vote should rule out.

### 5.2 Release scope — four programmes labelled for this release

Each is a multi-week programme rather than a defect, and each is currently marked as blocking. The vote decides, per item, whether it holds the release or moves to the next one:

- **Federation encryption.** Content replicated between nodes is currently plaintext.
- **Fleet-wide un-forget.** Deletion is node-local today; a fleet-level retraction protocol does not exist.
- **The "100% Rust" claim.** The published 97.0% recall headline was produced by a 353-line Python reimplementation of the ranker, and one supply-chain gate is Python. If the claim must hold, both must be ported before release.
- **The published scale target.** Materials claim a million-plus agent target; the documented topology envelope is a thousand-plus per mesh. Both are public, and they differ by three orders of magnitude.

### 5.3 Three changes already built and waiting on a flag

- **Graph projection mode.** A deferred projection mode is implemented, shipped, drained and documented. Making it the default buys a 2.3× improvement in relationship-write throughput with reads remaining correct.
- **Admission control threshold.** The current default never engages — measured zero rejections through a 73× latency collapse, which makes it indistinguishable from disabled. Lowering it to the measured saturation point makes the control actually work.
- **The graph traversal claim.** The graph engine implements none of the required predicates, so that code path is unreachable. Deleting it and withdrawing the capability claim is cheaper than porting it.

### 5.4 Merge governance

The release branch requires **zero reviews**. Both release-blocking fixes merged with no second approver, and the audit's own merges were made under the same conditions. Full evidence was published for each, but nothing mechanically required a second look.

The positions: continue and correct after release; or require an adversarial review lens to challenge every change before it merges. The evidence favours the second — pointing a review lens at code already merged during this audit found three real defects, including one that converts an orchestrator's own remediation into a mechanism for serving corrupt data. Escalating individual merges to a human is not among the options; the loop is autonomous by design, so the control must be a machine one that scales with it.

---

## 6. Release Blockers and Deferrals

**Release-blocking — data integrity (approximately 25 issues).**
Boot-time embedding erasure; the four bulk-write reporting defects; backup that cannot be restored; the migration replay hazard; quarantined records served as truth; identity drift on restore; expiry silently shortened by re-writes; dangling governance bindings across seven of eight PostgreSQL paths; graph nodes orphaned by archival; deletion that does not replicate while writes do.

**Release-blocking — security (approximately 16 issues).**
The approver string comparison; the visibility fail-open; the federation configuration single point of failure; the opt-in ownership gate; unconfined signal and link lanes; governance state rollback; ancestor-governs-descendant policy resolution.

**Release-blocking — control integrity (approximately 10 issues).**
The supply-chain gate; the unrequired meta-gate; zero required reviews; self-satisfying signature enforcement; tests that never run; required checks that narrow their own scope; documentation gates with unscanned files.

**Deferred to a later release (24 issues), correctly.** Each carries a recorded decision. One deserves re-reading, however: the module-split deferral is no longer a deferral — two files now hold 35 of the open issues between them, and that concentration is the direct constraint on how much work can proceed in parallel. The deferral is now the bottleneck.

---

## 7. Recommended Sequence

**Wave 0 — unblock the campaign.** Close the nine verified-fixed issues. Resolve the shared-file contention that makes every parallel change conflict. Fix the test fixtures that fail for reasons unrelated to the change under review. Repair branch protection. Land the pending performance fix, which gates ten further issues. Take the twelve decisions above.

**Wave 1 — data integrity.** Six parallel workstreams on non-overlapping files, plus one serialised stream for the two high-contention files.

**Wave 2 — security and federation.** Runs alongside Wave 1 except where it touches the contended files.

**Wave 3 — performance.** Begins only after one specific fix lands: background maintenance loops currently hold the write lock across unbounded work, which means **every SQLite tail-latency number in this corpus is contaminated until that is corrected.** Measuring before then produces numbers that describe the harness rather than the system.

**Two standing rules for whoever dispatches this work:** the two high-contention files get exactly one workstream at a time; and no performance change merges before the data-integrity wave completes, per the stated priority ordering.

---

## 8. What Keeps Recurring

Three patterns account for most of what this audit found. They are worth naming because they will produce the next set of defects too.

**Controls that report success without acting.** The supply-chain gate, the compaction hook, the signature rule, the metric certifying its own wrong value, the bulk write reporting rows it did not write, the migration test passing because of the invoking shell's file permissions. In every case the code runs, the tests pass, and the thing being checked is not the thing that matters. Green checks imply a rigour that is not present — which is worse than a visibly missing control, because nobody investigates a passing check.

**Relocation changes a control's subject, not just its timing.** Every performance fix that moves work off a hot path — caching it, backgrounding it, filtering it earlier — silently changes *what* the control examines. A health check moved to a background loop began pointing at an empty database on one backend. A cache keyed on a shared default value served one component's results to another. A benchmark reported a full pipeline while running a fallback. The question to ask at every relocated call site is not "is this faster?" but **"is this still measuring the thing it claims to measure?"**

**Evidence degrades quietly.** A number is uninterpretable without the state that produced it. Two identical measurements were not agreement — they came from different trees. Two different measurements were not disagreement — same reason. A shared test database mutated by concurrent work invalidated an entire class of measurements. Four different corpus states were cited interchangeably as "the corpus". None of this is visible in the number itself, which is why measurements must carry their provenance.

---

## Appendix A — Issues Closed

| Issue | Resolved by | Note |
|---|---|---|
| #2580, #2584 | `30c25974` | #2584's original diagnosis was refuted on all three counts; the symptom and fix were real |
| #2579, #2583 | `b820a313` | #2579's first draft would have manufactured the defect it removed; caught pre-merge |
| #2586 | `b820a313` | Duplicate of #2579 — same file, same line, filed independently by two lenses |
| #2578, #2581, #2582, #2585 | `5449b6da` | #2582's "60×" figure and #2585's headline numbers were both refuted; code shapes were real |

## Appendix B — Issues Opened

| Issue | Category |
|---|---|
| #2627 | Two changes bumping a limit to the same value from different measurements merge silently |
| #2628 | 34 tests whose result depends on the invoking shell's file-permission mask |
| #2629 | Documentation gate checks values but not symbol names |
| #2630 | Health verdict cleared by restart, restoring traffic over a corrupt index |
| #2631 | Index build on the boot path under a cluster-wide lock, with a bound 10× its own stated deadline |
| #2632 | Two merged changes each measured against a baseline the other invalidates |
| #2633 | An unrecognised visibility value widens a record to world-readable |
| #2634 | Audit log records an authorization verdict before the check that can refuse it |
| #2635 | Supply-chain gate verifies 2 of 558 packages |
| #2636 | The gate proving the other gates work is not itself required |
| #2637 | Destructive-operation hook has no implementation outside test builds |
| #2638 | Storage trait defaults silently discard data and drop atomicity guarantees |
| #2639 | One deployment shape has no embedding backfill at all; affected records are permanently unsearchable by meaning |

---

*Prepared by the AI NHI development loop under the v1.0.0 release campaign. Every finding was verified against `release/v1.0.0` at commit `5449b6da`. Claims that could not be settled without execution are marked as such in the underlying issues and are not presented as findings here.*
