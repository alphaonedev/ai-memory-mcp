# ai-memory v1.0.0 — Post-Audit Issue Register

**Date:** 2026-08-01
**Supersedes:** the backlog state prior to the 3×7 audit
**Companion:** `docs/audit/3x7-issue-audit-2026-08-01.md` (findings and method)
**Verified against:** `release/v1.0.0` at `5449b6da`

---

## Purpose

This is the authoritative register of every open issue after the 3×7 audit, grouped by what it actually is, with the ruled-out set closed and its reasoning recorded.

Its companion document explains *what the audit found*. This one answers a narrower and more operational question: **what is genuinely left, and why does each item survive?**

---

## What Changed

| | |
|---|---|
| Open issues before cleanup | 180 |
| **Open issues after cleanup** | **169** |
| Closed during this audit, with evidence | 36 |
| Opened during this audit | 92 |
| Ruled out and closed with documented reasons | 11 |

The open count is not the interesting number. Ninety-two issues were filed by the audit itself, so the backlog grew and shrank simultaneously. What matters is that **every surviving issue has been checked against the live code**, and every issue that did not survive has a written reason.

---

## How Issues Were Ruled Out

Nothing was closed for being old, unpopular, or inconvenient. Three disposals were used, each requiring evidence.

### 1. Verified fixed — the defect is gone at HEAD (14 issues)

Closed only after re-reading the code, never on a pull request's claim. This distinction mattered: several fixes were real while their stated diagnoses were wrong, and several issues sat open for weeks *because completed work never closed itself* — GitHub's automation does not fire on a non-default branch.

Representative: **#2511** claimed all graph queries silently degraded. At HEAD there are **zero** inlined-literal call sites and **twenty** parameter-bound ones. Fixed, verified, closed.

### 2. Premise no longer holds (3 issues)

The issue's central argument depends on a state that has changed.

**#2468** argued *"the file is at 4500 of 4500 lines, zero headroom — do not raise the ceiling."* The ceiling was subsequently raised to 4,520. The forcing function the issue relied on no longer exists, so the issue as written cannot be acted on. **The underlying concern was not discarded** — it was redirected to #1802, which this audit re-characterised from a deferral into active technical debt.

### 3. Ruled out on the evidence (5 issues)

These are the ones worth reading, because they are the audit judging its own output.

**#2622 — refuted by counterfactual.** Claimed a query predicate cost 32× on every list call. Tested on isolated database copies: 8.717 ms with the predicate, 8.667 ms without, byte-identical query plans. It changes nothing.

The *reason* the original was wrong is the more useful finding: its premise held only because **a sibling process had created the relevant index minutes earlier on a shared database**. Catalog evidence — the index carried object id 75335 against ~29xxx for everything pre-existing. It measured a neighbour's scratch state and reported it as production. The one real measurement inside it was **split into #2640** so it was not lost with its parent.

**#2576 — three of four claims refuted, by the engineer who implemented the fix.** The proposed optimisation would have improved the headline metric by truncating documents: at the suggested setting, 91.8% of test pairs truncate and the median document loses 28% of its tokens. **The refusal is the finding.** A control that gets faster by quietly changing what it operates on has not been optimised.

**#2624 — numbers unsupported.** Self-declared 1–7 samples per point; a "15-second measurement" reporting a *completed* 56,792 ms request; and throughput *falling* with concurrency, which is the signature of incomplete requests being dropped from the denominator. Three sibling lenses measured the same configuration at 860 ms, 1,290 ms and 3,290 ms — a 3.8× spread, never reconciled. The concern survives in #2605; these numbers do not.

**#2616 — measured on a contaminated machine.** No independent measurement; a copy of another issue's table, with no sample count, load, or configuration stated for the rows quoted. The box was at load 12–45 with six concurrent lanes. The issue names its own confound, and that confound is now confirmed real.

**#2598 — self-contradictory attribution.** Uses load-invariance to establish a fixed cost, then invokes load to dismiss the one measurement contradicting it. The baseline has since moved anyway. Closed as a measurement task rather than a defect.

### What was deliberately *not* closed

- **Records and trackers** were closed only where they are genuinely complete (#2032, #2519). The v1.0.0 epic #1940 stays open through release.
- **#2607** was kept despite half its mechanism being unsupported, because its *other* half — a migration that completes 85% and exits successfully — is solid and severe.
- **Two issues (#2414, #2512) need execution to settle** and are held rather than guessed at.

---

## The Register

Groups are by nature, not by team. An issue appears in the group describing what it *is*; the crossroads docket cross-references items that also appear elsewhere.

---

## A. Data integrity — 44 issues

**The largest group, and first in priority order.** The stated standard is: never corrupt, never lose data unintentionally, degrade rather than return wrong results.

These are ordered against that standard rather than by effort. The most severe — **#2567** — erases stored embeddings at boot, unattended, on daemons that may be unable to regenerate them, with no repair path on PostgreSQL.

Several share one root cause. **#2550, #2551, #2552, #2588 and #2594** are five faces of a single defect: the bulk-write path re-implements the single-write path instead of calling it, and each issue is a different stage that re-implementation omitted. One change closes the cluster; dispatching them as separate work would collide on the same function.

**#2569, #2570 and #2571** together mean the system cannot restore its own backup. That is at least loud rather than silent, but it is the worst possible place for a latent failure.

---

## B. Security — 15 issues

Authorization boundaries and confinement. Two are single-line defects with disproportionate reach.

**#2538** — the named-approver check is a bare string comparison. Whoever the request claims to be, is. This converts every other confinement gap in this group into a full execution path, which is why it should be fixed first. **A trap for whoever takes it:** the relevant method is overridden on SQLite only; PostgreSQL falls through to a shared default, so a fix in the obvious place would not reach it.

**#2633** — an unrecognised visibility value resolves to *world-readable*. A record with no scope set is private; a record with a **misspelled** scope is public. One character apart.

**#2504** is the structural one: a single malformed character in peer configuration disables both the namespace confinement gates and the unenrolled-peer rejection, because two controls designed to be independent share one failure point.

---

## C. Control and evidence integrity — 23 issues

**Read this group before trusting any other.** These are the controls that certify the rest of the system, and several of them do not work.

**#2635** is the most serious item in the entire register. The supply-chain gate that mechanically enforces the project's firmest rule — no external code injection — verifies **2 packages out of 558**, and never checks the reverse direction. A new dependency with hostile compile-time code is never examined, and the gate prints `PASS`.

**#2636** — the gate proving the other 24 gates function is not itself required. A change breaking it merges. This is the same defect the project fixed one level down two weeks ago, recurring one level up.

**#2637** — a destructive-operation hook that operators can configure has no implementation outside test builds. It returns a hardcoded value, and the tests assert that a test-only stub references a constant.

**#2475** — the release branch requires zero reviews. Both release-blocking fixes merged with no second approver, including this audit's own merges.

**#2548** — every PostgreSQL and graph-database test is gated behind a flag whose only runner executes from a branch where those tests do not exist, and which is currently failing.

---

## D. Regressions from this audit's own merges — 3 issues

Found by pointing the audit at itself, hours after merging. Listed separately because they are the strongest available evidence that the review method works, and because they should be fixed before anything builds on top of them.

**#2630** is the significant one. A failing health verdict is cleared by restarting the process — and a failing health verdict is precisely what causes an orchestrator to restart a process. The result is a node serving traffic over a corrupt index for up to five minutes on every restart, in a loop the orchestrator itself drives. Before the change this was impossible, because every probe re-ran the check.

---

## E. Cross-backend parity — 9 issues

The two storage adapters must mean the same thing. Where they do not, two deployments of the same version hold different data.

**#2638 and #2639** are new: trait defaults that silently discard an embedding vector and silently drop a batch's all-or-nothing guarantee, and a deployment shape with no embedding backfill at all — where affected records are permanently unsearchable by meaning.

**#2392** is the cheapest real divergence to close: one backend indexes tags for search, the other does not, so the same query returns different results.

---

## F. Performance — 19 issues

**Reduced from roughly 40 by the evidence review.** What remains is what survived challenge — predominantly findings resting on statement counts and buffer counts, which are load-independent by construction, rather than on wall-clock timings taken on a contended machine.

**#2599 must be fixed first, and not for its own sake.** Background maintenance loops hold the write lock across unbounded work, which means **every SQLite tail-latency measurement in this corpus is contaminated until it lands**. Measuring before then produces numbers describing the harness rather than the system. It is a measurement precondition as much as a defect.

---

## G. Crossroads docket — 13 items

**These are decided by the AI NHI development loop, not escalated.** Each is adjudicated by a 3×3 adversarial vote: nine independent lenses returning a verdict, confidence, rationale, top risk and killer objection, tallied into one decision recorded before implementation and cited in the resulting change.

The governance is that the operator sets direction and constraints; the loop decides everything inside them and keeps building. The single reserved action is cutting a release tag — a release action, not a decision.

Four of these collectively determine whether roughly eight other issues are worth fixing at all. The reranking stage runs *after* results are truncated, so it cannot change **which** records are returned — only their order within an already-fixed page, at roughly 1.1 seconds per query. Whether that is worth paying is a product question, and the vote answers it.

---

## H. Deferred to v1.x — 20 issues

Each carries a recorded decision, and their premises were spot-checked as still accurate.

**One deserves re-reading: #1802.** It is listed as a deferral, but two files now hold 35 of the open issues between them, and that concentration is the binding constraint on how much work can proceed in parallel. The deferral has become the bottleneck.

---

## I. Epics and trackers — 2 issues

**#1940** is the v1.0.0 development epic and stays open through release. **#2440** is a tracking checklist whose items duplicate individually-filed issues; it should reference them rather than be worked directly.

---

## Sequencing

**Wave 0 — unblock.** Resolve the shared-artifact contention that makes every parallel change conflict (#2485). Repair branch protection (#2475, #2486, #2534). Fix the fixtures that fail for reasons unrelated to the change under review (#2432). Land the pending performance fix, which gates ten further issues. Run the crossroads votes.

**Wave 1 — data integrity.** Six parallel work-streams on non-overlapping files, plus one serialised stream for the two high-contention files.

**Wave 2 — security.** Runs alongside Wave 1 except where it touches those same files. Start with #2538.

**Wave 3 — performance.** Begins only after #2599, for the measurement reason above.

**Two standing rules:** the two high-contention files get exactly one work-stream at a time; and no performance change merges before the data-integrity wave completes.

---

## Issue Tables

### A. Data integrity — corruption, silent loss, wrong results (44)

| Issue | Title |
|---|---|
| #2567 | [data-integrity] #877 boot auto-migrate NULLs a stored embedding on a daemon with embeddings DISABLED — destroys derived data it cannot regenerate |
| #2588 | data-integrity: bulk write returns 200 OK with "internal error" when the quota rejects every row — 31k rows silently dropped, zero logs |
| #2551 | bulk_create reports created=rows-SENT not rows-PERSISTED — 7912 sent / 7912 reported / 7855 landed, 0 errors (#2490 false-success class, write path) |
| #2550 | bulk_create silently drops top-level `scope` (collective→private) and `kind_provenance` on BOTH backends — single-create honours both |
| #2552 | bulk_create collapses every row error to `"validation failed"` — no field, no row index; single-create returns the actionable message |
| #2594 | bulk create performs NO embedding on either backend while single create embeds inline — bulk-ingested rows are silently invisible to semantic recall |
| #2600 | [data-integrity] memory_load_family / memory_smart_load bypass the #1948 fail-closed lifecycle allow-list on sqlite — quarantined + tombstoned rows are readable through an always-on core-profile tool |
| #2601 | [correctness] sqlite memory_load_family applies scope=private visibility AFTER the SQL LIMIT, so it silently under-returns; postgres applies it before |
| #2602 | [determinism] list / memory_load_family have no tiebreak past (priority DESC, updated_at DESC), so the row chosen at rank k among ties is plan-dependent |
| #2564 | [#2445 residual] zeroing `schema_version` is the strictly better attack, and it is undefended — full v1 ladder replay with the safety snapshot suppressed |
| #2555 | [#2445 residual] `schema_version` is an unconstrained fleet kill-switch, and there is no in-product repair verb |
| #2553 | [#2445 residual] the schema-downgrade guard is OPEN-TIME only — a live process keeps writing a newer schema until it restarts |
| #2554 | [#2445 residual] observed > tip is NECESSARY but not SUFFICIENT — a crashed sqlite ladder leaves a structurally-newer database at an EQUAL stamp |
| #2565 | [#2445 residual] the pre-migration snapshot has no manifest, so the documented rollback is only executable via `restore --skip-verify` |
| #2566 | [#2445 residual] `MIGRATION_LADDER` metadata has been stale since v54, so the reversible/data-loss inventory the rollback runbook leans on is unrecorded for 33 migrations |
| #2569 | [data-integrity] the DEFAULT `--on-conflict version` cannot re-import ai-memory's own export onto an existing corpus |
| #2570 | [data-integrity] a database whose rows have ever been EDITED silently rejects its own backup on re-import (import guard keys on presence in archived_memories, not lifecycle) |
| #2571 | [portability] neither export mode carries archived_memories or namespace_meta — now DECLARED, still not round-trippable |
| #2572 | [data-integrity] every remaining CLI write verb still conjures a phantom SQLite database under a Postgres deployment |
| #2573 | [data-honesty] the HTTP admin export sibling has no withhold accounting — drift with the CLI after #2490 |
| #2607 | `reembed` at the DEFAULT batch size silently left 1,155/7,855 rows (14.7%) unembedded and still exited 0; --batch 50 embedded 100% |
| #2606 | embedding_space fingerprint omits the vector dim, so a config-only dim change mints a mixed-dim single-fingerprint corpus that defeats the #2167 HNSW seed filter (sqlite; degrades, does not corrupt) |
| #2626 | One model id resolves to two different vector dims depending on config path (env => 3072 from the compiled table, config.toml => 768), and no env var can express the dim at all |
| #2493 | [data-integrity][pg parity] 7 of 8 postgres delete/archive funnels leave a dangling namespace_meta.standard_id — #1642 was closed on one arm |
| #2315 | postgres archive_by_ids deletes without AGE unprojection and archive_restore never re-projects — ghost nodes and permanently missing edges in the memory_graph projection |
| #2385 | [3x7-round23][N4] archive→restore re-mints the BLAKE3 cid (archived_memories has no cid cols) — genesis identity drifts, link source_cid/target_cid dangle |
| #2442 | [federation][data-integrity] DLQ routing key is a POSITIONAL peer index — decommissioning a peer misroutes queued writes to the wrong host and marks them replayed |
| #2446 | [federation][gdpr] erasure does not replicate but writes do — `broadcast_delete_quorum` has ONE production caller (HTTP DELETE); MCP and CLI forget are purely local |
| #2515 | [cross-backend] LOCAL write funnels bare-COALESCE expires_at — a re-store can silently SHORTEN a longer local expiry (sqlite insert_inner + 5 pg funnels); same lattice fix as #2335, different funnel class |
| #2462 | v54 tier-default-expiry backfill writes a non-canonical `+00:00` rendering — safe only because v87's heal runs later in the ladder |
| #2463 | TTL-extension MAX() floors cannot self-heal a legacy non-UTC expires_at — a stale offset rendering silently voids the extension |
| #2529 | [SECURITY][CWE-284] federated pendings[] upsert can RESURRECT a decided pending action and overwrite decided_by / approvals |
| #2237 | stats.total is a raw COUNT(*) with no lifecycle filter — tombstoned rows inflate the count (propose a lifecycle breakdown) |
| #2394 | [3x7-round23][N13] upsert keeps sticky memory_kind but adopts incoming kind_provenance — provenance labels the rejected kind |
| #2395 | [3x7-round23][N14] confidence merges MAX but confidence_source/signals/decayed_at merge by a different rule — value and label from different operands |
| #2398 | [3x7-round23][N18] gc/fold hardcode 1h/1d extend windows, ignoring [ttl] short/mid_extend_secs (FBL-04 residual) |
| #2431 | [defaults-lie] memory_recall reports scheduled_validity="valid" + freshness_state="fresh" for a claim whose valid_until closed in 2021, and STRIPS valid_from/valid_until — while memory_get on the same row shows the closure |
| #2436 | [cross-backend] contradiction soft-loser penalty is DEAD on postgres — writer stamps JSON true, pg predicate tests ->> = '1' which can never match; sqlite twin works |
| #2544 | an expired / archived / tombstoned memory is still served as a live namespace standard, and its tokens are never counted against the recall budget |
| #2621 | perf/correctness: ai_memory_memories gauge counts the local SQLite sidecar on a postgres daemon — reports 0 for a populated corpus |
| #2441 | [federation][liveness] anti-entropy cursor can permanently stall: LIMIT applied BEFORE the per-peer namespace/visibility filters, watermark advances only on APPLIED rows |
| #2530 | federated pending-executed store / promote / reflect land writes that NO response counter reports |
| #2546 | a reap that severs governance bindings is invisible in the /sync/push envelope — namespace_meta_cleared counts only the clears lane |
| #2498 | [federation][observability] a namespace-refused or unresolvable federated deletion is invisible to the sender — broadcast_delete_quorum never enqueues to the push DLQ |

### B. Security — authorization boundaries and confinement (15)

| Issue | Title |
|---|---|
| #2538 | [SECURITY][CWE-862] ApproverType::Agent approves on a bare string compare — no is_registered_agent, no self-approval reject, both backends |
| #2633 | visibility.rs: an UNKNOWN metadata.scope token widens a row to world-readable (FBL-14 fail-open) — a typo makes a private row public |
| #2504 | [SECURITY] one malformed character in AI_MEMORY_FED_PEER_ATTESTATION silently disables the entire federated-delete namespace gate — and the WARN says the fallback is default-deny, which is false for this lane |
| #2541 | [SECURITY] the MCP namespace-standard bind is ungated when the caller simply omits agent_id, and the unowned-claim branch rewrites a foreign row's owner + scope |
| #2542 | namespace-standard chain grafting: caller-supplied `parent` and `-`-prefix auto_detect_parent let one namespace pull another's standards into its own inheritance chain |
| #2543 | HTTP GET /api/v1/namespaces?namespace= still serves any namespace's standard title+content with no caller gate (the #959 residual, now the last unfiltered read of that body) |
| #2545 | [SECURITY] the #1777 clear_namespace_standard owner gate is INOPERATIVE exactly when the standard is unresolvable — a severed/dangling binding is clearable by any caller, on both backends |
| #2536 | [SECURITY][CWE-284] a federated namespace_meta row at an IN-SCOPE ancestor sets the governance default of OUT-OF-SCOPE descendants |
| #2532 | federated REJECT of a foreign-namespace pending is an unauthorized veto (deliberately left ungated by #2478) |
| #2489 | [SECURITY][CWE-284] federated links[] and signals[] are not namespace-scoped — the last two unconfined /sync/push subcollections |
| #2480 | [SECURITY][CWE-284] federation catch-up PULL client inserts peer-served rows into ANY namespace under an admin bypass context |
| #2477 | [SECURITY] federation peer URLs accept plaintext http:// with no flag, cert, or acknowledgement — strictly weaker than the accept-any TLS closed by #2448 |
| #2355 | R40 signed-approval quorum enforced on MCP only: both HTTP approve surfaces bypass verify_quorum, and Decision::Escalate never enters the R40 queue (Grok W1A6-09, HIGH) |
| #2502 | [security][#2032-L2 residual] no per-source auth-failure backoff or lockout — admission control bounds concurrency, not attempts over time |
| #2634 | governance audit records verdict 'allow' BEFORE the owner gate that can refuse — refused set_standard attempts are logged as allowed |

### C. Control and evidence integrity (23)

| Issue | Title |
|---|---|
| #2635 | SUPPLY CHAIN: build-script vetting gate only iterates the 2-entry ledger — an unvetted crate with a hostile build.rs passes with PASS |
| #2636 | The required-contexts meta-gate is not itself a required context — 4 c8-precheck integrity gates run on every PR and are required by nothing |
| #2637 | PreCompaction/PreArchive hooks gate destructive ops but have NO production fire site — the gate is a #[cfg(test)] stub returning true |
| #2475 | [control-integrity] ZERO required reviews on release/v1.0.0 — CODEOWNERS enforces nothing, both GA blockers self-merged with no approval |
| #2486 | [control-integrity] commit-signing posture regressed silently on 2026-07-22 and nothing detects it — plus required_signatures on release/* is self-satisfying and cannot fail |
| #2548 | [ci-evidence] every #[ignore]-gated postgres/AGE cell has ZERO CI coverage — the only job running --include-ignored is the nightly, which is red AND runs from main (where these tests do not exist) |
| #2474 | Required check 'Check (ubuntu-latest)' self-narrows twice (docs-only short-circuit + impact-aware selection) — a required gate whose scope a heuristic chooses |
| #2534 | [ci-gate] add rule: .github/branch-protection.yml must not declare required_checks — one declaration site only (#2443 follow-up) |
| #2492 | [gate-gap] check-docs-vs-ssot.sh misses API_REFERENCE.md route-count drift (says 92, SSOT is 94) — plus PR #2354 shipped 9 fixes with no CHANGELOG entry |
| #2629 | docs-vs-SSOT gate pins values but not symbols: prose naming migrate_v87()/functions/paths can go stale silently |
| #2485 | [campaign-integrity] concurrent lanes silently collide on CLAUDE.md env-table row numbers — same class as the #2036/#2192 migration-ladder prefix collision, with no gate |
| #2432 | tests/store_parity_gaps.rs uses fixed-id fixtures against a shared postgres DB — non-idempotent, so a second consecutive run (or two concurrent lanes) produces PHANTOM failures that mimic a real regression |
| #2520 | [test-infra] store_parity_gaps::pg_parity_private_leak_and_bypass_a7_1720 fails against the long-lived local 5433 DB — fixed-id fixtures collide with persistent state (pre-existing, reproduces at parent) |
| #2434 | [ci-integrity] #1492 sal-postgres watchdog (2100s) kills PASSING runs again — the suite has outgrown its second budget, and the false red is attributed to whatever PR is in flight |
| #2500 | [ci-reliability] tests/e2_post_ship_dry_run.rs runs a NESTED cargo build and false-reds the Postgres feature gate — the e1 prebuild fix (env row 117) was never applied to e2 |
| #2469 | Flaky: tests/hot_swap_llm_2166 aborts in CI (exit 101, no test output) — passes locally 5/5 |
| #2482 | [CI-FLAKE] AI_MEMORY_AGENT_ID test lock guards only the writers — ambient-caller readers across the lib test binary can observe a half-applied ai:bob |
| #2415 | [ci-flake] export_reflections::test_auto_export_does_not_block_reflect_response flaky on macos (timing) |
| #2512 | certified-AGE nightly hard-red since 2026-07-28: vendored alphaonedev/paste fork rev 6a302522 unreachable — plus AGE pin drift (CI 1.6.0 vs SSOT 1.7.0) |
| #2414 | [ci-flake] check-migration-ladder.sh false-orphan under SIGPIPE (printf: write error: Broken pipe at line 463) |
| #2628 | 34 governance::deferred_audit tests fail under umask 0002 and pass under umask 022 (CI green, local red) |
| #2450 | [verification-integrity][100%-rust] the published 97.0% R@5 headline is produced by a 353-line PYTHON reimplementation of the ranking SQL that never invokes the binary — and the copy has already drifted from the shipped Rust |
| #2451 | [100%-rust] 11 internal Python tooling files (3,142 lines) do Rust work — including a supply-chain CI gate and the CI baseline math |

### D. Regressions introduced by this audit's own merges (3)

| Issue | Title |
|---|---|
| #2630 | /health FTS fail-closed verdict is cleared by restart — orchestrator remediation restores 200 over a corrupt index (regression from #2579) |
| #2631 | v88 CREATE INDEX CONCURRENTLY runs on the boot path under the cluster-wide advisory lock with a 900s bound vs the 90s deadline it cites |
| #2632 | #2578's v88 index and #2580's load_family rewrite were each measured against a baseline the other destroys — combination never measured |

### E. Cross-backend parity (9)

| Issue | Title |
|---|---|
| #2638 | MemoryStore trait defaults silently discard data: store_with_embedding drops the vector, store_batch drops atomicity (SqliteStore overrides neither) |
| #2639 | A sqlite HTTP-only serve daemon has NO embedding backfill at all — list_unembedded trait default returns empty; bulk rows are permanently semantically invisible |
| #2392 | [3x7-round23][N11] pg FTS tsvector omits tags (sqlite indexes title,content,tags) — search/recall/contradiction diverge across backends |
| #2617 | perf(postgres): /api/v1/health runs SELECT COUNT(*) FROM memories per probe — O(corpus) Index Only Scan over all rows (the pg twin of #2579) |
| #2513 | [wiring] postgres MemoryStore::lease_acquire has NO production caller — the MCP lease path is sqlite-only; pg lease surface is dormant at v1.0.0 |
| #2433 | Bootstrap auto-creates the vector extension but NOT age — an operator who installs the AGE binary and forgets CREATE EXTENSION gets a silently graph-less deployment that reports success |
| #2062 | [v1.x] Forget-receipt surface beyond sqlite CLI (postgres/HTTP/MCP) |
| #2217 | [v1.x][R75] postgres re-anchor ceremony twin — the pg signed_events chain has no crypto-agility bridge (#2004 audit F2) |
| #2373 | Postgres check-side db_id parity for the #2370 per-database rollback anchor (verify-audit-trail + any future pg open-time check) |

### F. Performance — survivors after evidence review (19)

| Issue | Title |
|---|---|
| #2599 | perf: background loops (fold / gc / lease-sweep) hold the shared writer mutex across unbounded synchronous work on a tokio worker |
| #2587 | perf: production HTTP write takes 5-11s — synchronous auto_tag LLM call on the request path, not gated by AI_MEMORY_AUTONOMOUS_HOOKS |
| #2593 | perf: store-time embedding is synchronous on the write path — p50 213 ms (96% of the write), +1 OS thread per concurrent write, 30 s worst case |
| #2595 | perf(postgres): governance policy re-resolved from scratch on every write — 6 statements + a throwaway transaction to learn 'no policy', 22% of a single store |
| #2589 | perf(postgres): bulk create pays 7 SQL round trips PER ROW for governance+quota — 97% of bulk DB time, ceiling 943 rows/s |
| #2592 | perf(postgres): subscription dispatch is O(all subscriptions) inline on EVERY write — store p50 6.2→21.6 ms at 1000 subs; plus a silent 1000-subscriber dispatch cliff |
| #2591 | perf(AGE write path): sync projection is the default and costs 2.3x on link writes (23 vs 10 statements) — incl. a create_graph DDL that fails on every write |
| #2596 | perf(postgres write path): link/update/promote fetch full rows (SELECT * incl. embedding) to read one scalar — link already calls namespace_by_id in the same request |
| #2597 | perf(postgres): memory_consolidate is 5+20N statements for N sources — repeats the whole AGE bootstrap (incl. the always-failing create_graph) once PER SOURCE |
| #2605 | Cross-encoder rerank runs AFTER the candidate pool is truncated to `limit`, so it cannot change which memories are recalled — ~82% of recall latency buys a permutation that never moved rank 1 |
| #2608 | Cross-encoder rerank has no wall-clock budget and cannot get one until a pluggable scorer seam exists (neural_score_pairs has zero CI coverage) |
| #2609 | MCP stdio dispatches inline on one thread: any slow tool call is a total-server outage for its duration (bounded for embed by #2604, structurally open) |
| #2611 | perf(AGE): GIN index on vertex properties — the link-write MERGE is 3 O(V) Seq Scans, 23.6 ms -> 0.51 ms (46x) at 20k vertices |
| #2612 | perf(kg): find_paths_cte costs 463 ms at depth 4 — the inner UNION re-dedups ~120k edges per recursion level (358k buffers) |
| #2615 | audit(recall): list_recall_observations ordering is non-deterministic within a recall — all rows share observed_at |
| #2618 | doctor can now DETECT a corrupt FTS5 index but not repair it — the printed remedy is a raw sqlite3 write, and a repaired node stays 503 until the next paced check |
| #2623 | perf: admission-control default cap (cores*64=896) is ~56x the daemon's saturation concurrency — shed_total stays 0 through full p99 collapse |
| #2625 | [perf][false-confidence] the shipped hnsw_rebuild_async bench uses 16-dim vectors while production is 768-dim — ~48x cheaper per distance op, so it cannot represent the real index |
| #2640 | perf(postgres): agent-filtered namespace list is O(namespace) — 2,056 buffers / 6,872 rows scanned to return 10 (needs an agent-leading composite) |

### G. Crossroads docket — decided by 3x3 vote, not escalated (13)

| Issue | Title |
|---|---|
| #2605 | Cross-encoder rerank runs AFTER the candidate pool is truncated to `limit`, so it cannot change which memories are recalled — ~82% of recall latency buys a permutation that never moved rank 1 |
| #2608 | Cross-encoder rerank has no wall-clock budget and cannot get one until a pluggable scorer seam exists (neural_score_pairs has zero CI coverage) |
| #2610 | perf(postgres): decide the withheld unscoped idx_memories_list_order — it regressed the expired-heavy namespace case (buffers 1,854 -> 3,041) |
| #2613 | kg(AGE): find_paths_cypher is unreachable on AGE 1.7 — port or delete it, and close the kg_backend=Age honesty gap |
| #2591 | perf(AGE write path): sync projection is the default and costs 2.3x on link writes (23 vs 10 statements) — incl. a create_graph DDL that fails on every write |
| #2623 | perf: admission-control default cap (cores*64=896) is ~56x the daemon's saturation concurrency — shed_total stays 0 through full p99 collapse |
| #2046 | [v1.x][security][#2032-C] REQUIRE_API_KEY default-on + auto-key-gen UX (L5, deferred past v1.0.0) |
| #2475 | [control-integrity] ZERO required reviews on release/v1.0.0 — CODEOWNERS enforces nothing, both GA blockers self-merged with no approval |
| #1968 | [v1.0][11.6][F-53] Federation E2E content encryption |
| #1852 | [v1.0] Mesh-wide un-forget: signed propagating tombstone-revocation primitive |
| #2438 | [architecture] stated 1M+ agent target is ~3 orders of magnitude beyond the documented topology envelope (T6 = 1000+ agents / mesh ceiling ~50 peers) — no shard, placement, or cross-mesh membership model exists |
| #2450 | [verification-integrity][100%-rust] the published 97.0% R@5 headline is produced by a 353-line PYTHON reimplementation of the ranking SQL that never invokes the binary — and the copy has already drifted from the shipped Rust |
| #2451 | [100%-rust] 11 internal Python tooling files (3,142 lines) do Rust work — including a supply-chain CI gate and the CI baseline math |

### H. Deferred to v1.x by recorded decision (20)

| Issue | Title |
|---|---|
| #1802 | [v1.x] Refactor — storage/mod.rs split + MemoryStore trait decomposition (#1798 R-05/R-06) |
| #1950 | [v1.x] Read-path consumer-binding envelope (DEFERRED post-v1.0 per ruling; cid-anchored, signed-events-folded) |
| #1969 | [v1.x] Reranker global default-on flip — REFUSED at v1.0 (sustained); re-evaluation tracker |
| #2002 | [v1.x][FED-RQ-02] Equivocation detection/eviction runtime + epoch-manifest-doc federation + policy send-side advertising (deferred from #1947 per ADR-002) |
| #2004 | [v1.x][R75] Crypto-agility operational runtime — re-anchor ceremony + universal suite_tag (deferred from #1941) |
| #2047 | [#1980 follow-up, v1.x] signed-rule-pack apply mechanism (verb + set-manifest) with refuse-by-default enforcement |
| #2052 | [#1836 follow-up, v1.x] G22 kernel inversion — thin 9-field Claim as source of truth + closed-algebra default-flip |
| #2054 | [#1833 follow-up, v1.x] G19 open-predicate relation model — kernel floor + authored-CID predicates + def-Claim resolution |
| #2061 | [v1.x] TRACT covenant clause 3 — permanent-dissent conservation (G7) |
| #2066 | [v1.x] Unified continuous cost-of-access retention model governing eviction (G15) |
| #2068 | [v1.x] Recall latency governor — p95-reading actuator selecting a degradation tier (G31) |
| #2070 | [v1.x] Persist governance refusals as recallable Claim memories — the safety model (G10.2) |
| #2072 | [v1.x] Adjudicated-permanence: opt-in to suppress maintenance auto-promote + close the tier=long write lane (G10.3) |
| #2074 | [v1.x] Read-side bridge-capability: namespace as enforced isolation boundary for recall (G10.4) |
| #2076 | [v1.x] Streaming tool responses for long-running MCP tools (progress notifications) (B7-STREAM) |
| #2079 | memory_update content patch primitive (#1974): HTTP PUT + CLI surface parity |
| #2169 | [v1.x][enterprise][hive] Fleet-coordinated rolling reembed orchestration + opt-in guard-railed auto-reembed (safe embedding-model migration at 1M-instance scale) |
| #2174 | [v1.x] Hot-swap auto_tag_model on [llm] reload (boot-captured; ~138 construction sites — deferred from #2166) |
| #2223 | v1.x — Persistent Vector Index Substrate residual (deferred from #1860 after the vectorlite backend slice shipped) |
| #2430 | [v1.x] Read-side delivery layering asymmetry: reads are L1-volunteer + a task-blind partial L2, while capture has L1-L4 (C1/C5 DIAGNOSIS carrier) |

### I. Epics and trackers (2)

| Issue | Title |
|---|---|
| #1940 | 🎯 ai-memory v1.0.0 — GLOBAL DEVELOPMENT EPIC (orchestration + tracking; 100% autonomous AI NHI; GA cut authorized) |
| #2440 | [tracking] v1.0.0 GA review findings — ranking gate, fleet upgrade, backend parity, ROADMAP carriers |

---

*Every issue listed was confirmed open against the live repository at generation time, and every group membership was validated rather than transcribed. Issues closed during this audit carry their reasoning in the closing comment, not only here.*
