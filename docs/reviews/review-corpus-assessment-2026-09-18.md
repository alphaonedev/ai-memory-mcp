# Review-corpus assessment — v1.0.0 GA status, v1.1.0 roadmap gap, enterprise-class delta

**Date:** 2026-09-18 · **Measured on:** rehearsal/audit-wip `0fcd36f82` (chain 9d tip; chain 9e measuring on `36ab35b7a`) · **Release tip:** `abd8d259d` · **Author:** Conductor (Claude Fable 5.1), from three read-only scout measurements (Opus 5) on the same tree.

## 0. What was assessed and how

Five review documents on `release/v1.0.0`:

| Doc | Date | Lines | What it is |
|---|---|---|---|
| `GPT-6-ASTRA-FULL-SPECTRUM-ASSESSMENT-2026-09-05.md` | 09-05 | prose | Astra's findings (unnumbered) |
| `GPT-6-ASTRA-AI-NHI-TEST-PLAN-2026-09-05.md` | 09-05 | prose | Astra's acceptance requirements (unnumbered) |
| `FABLE-5.1-FULL-SPECTRUM-AUDIT-OF-GPT-6-ASTRA-2026-09-09.md` | 09-09 | 400+ | Fable's audit of both; assigns A1–A42, T1–T41, F1–F15, N1–N31, V1–V10 |
| `AI-MEMORY-V1.0.0-MISSION-CRITICAL-CERTIFICATION-STANDARD-2026-09-09.md` | 09-09 | 372 | The certification standard (adopted verbatim by #3557 as `docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md`) |
| `FINITE-CONTEXT-AND-AI-MEMORY-2026-09-11.md` | 09-11 | 85 | The product thesis (non-normative) |

**Method.** Every claim was measured against `0fcd36f82` by `git log`/`git grep`/`git ls-tree`, the live issue tracker (`gh`), `approved-queue.txt` (the Conductor's single source of truth for approvals and landings) and `ROADMAP.md` + `docs/ROADMAP-v110.md` on `origin/release/v1.0.0`.

**Caveats that bound every statement below.**
1. The codegraph MCP server failed to connect for this session, so "no test / no code" means *no file or symbol names it*, not a call-graph proof. Two findings (#3032 "rules engine inert", #3126 "11 of 22 hook events never fire") are exactly the exists-but-unreachable hazard this method cannot see.
2. **LANDED means a commit whose subject cites the issue is an ancestor of `0fcd36f82`** — not that the fix is correct, complete or green. Several are self-labelled WIP in their subjects.
3. Nothing was executed (`cargo`, gate scripts). The chain measurements (`gates-for-diff.sh` on every landing) are the only run evidence and they are cited by chain, not re-run here.
4. `origin/release/v1.0.0` (`abd8d259d`) is not an ancestor of `0fcd36f82`: three docs-only commits exist only on release. Every fix commit counted is on both.

## 1. Headline findings

1. **Fable refuted zero Astra findings.** Every source-level claim held; two were narrowed in consequence (A18 `pending`, A23). The only struck claims were three scout/wave-2 claims and one of Fable's own drafts (F7, rewritten narrower and then fixed). There are **no refuted findings with open issues** — nothing to close on that ground.
2. **Of the 39 audit-owned carriers (#3543–#3574 plus 7 amendments): 12 fixed and closed, 5 fixed-on-rehearsal and queued (open until promotion), 1 fixed-on-rehearsal and unowned (#3288), 21 open-unowned.** Of the 21, 20 are labelled `v1.1.0` / `cert-blocker` / `deferred-v1.x` by the operator's 2026-09-09 freeze ruling; one (#3556, the certificate watch-set widening) is a `ga-blocker` with 0 commits.
3. **The test plan's 41 T-ids: 15 have substrate on the tree, 26 have none.** Of the 26, 22 have an open v1.1.0/cert issue. **Four have nothing at all: T13, T15, T16 (partial-staging leg), T18** — all integrity/mixed-state classes (§4).
4. **The certification standard's 17 measurable clauses: 1 implemented and measured (clock 1, 329–382 ms), 8 implemented and declared unmeasured, 4 implemented with a defect in enforcement, 6 open, 1 missing.** Two enforcement defects are cheap and should land before promotion (§5).
5. **`ROADMAP.md` on the release branch contains zero occurrences of `v1.1`.** It is dated 2026-05-25, says schema v91 while the tree is at v100, never references `docs/ROADMAP-v110.md` (412 lines on the same branch), and does not record the 2026-09-09 freeze ruling that made v1.1.0 the certification release. Roadmap coverage of the five documents is **0 of ~140 rows** (Astra/Fable), **0 of 17** (standard), **1 of 10** (finite-context, and that one is a v0.8.0 pillar).
6. **Workstream B of the f1 3x7 program (the v1.1.1 roadmap ballot) never ran** — zero ballots, zero ledger lines. The `v1.1.0` label (64 open) is doing that job unranked.
7. **The finite-context document's central claim — a replacement agent boots from the store — is clock 3 of the standard and is `NOT_MEASURED`** (`v1.0.0-DECLARATION.md:75`). The product thesis has no number at GA; #3559 (v1.1.0) is the only producer.
8. **The enterprise-federation certificate says "STATUS — LIVE as of 2026-09-12" on a binding (`ab6f2175`) whose watched surface has since changed by +2498 lines under the old rule and +5381 under the adopted §5 rule.** The expiry gate stays green because it accepts "cert doc touched in the same change" (`scripts/check-cert-expiry.sh:270`). Owner #3556 (pending review of `37cacaaa5`) + #3501.
9. **Seven `ga-blocker`s were landed on rehearsal with no row in the Conductor's queue**, so the dashboard counted them as not started: #3743, #3752, #3393, #3646, #3124 rebound today as landed; #3730 and #3638 rebound as owned. Dashboard moved 55→60 landed, 10→3 not started, arithmetic predicted before each republish and matched.
10. **The one unaddressed data-integrity finding in the corpus is #3152** (F15/N28: one logical update persisted across two commits on both backends). The audit pulled it into GA; the Conductor deferred it on 09-18 07:05Z under the freeze rule. Both scouts flag that reversal as the ruling most worth revisiting. Ruling below (§8).

## 2. Astra assessment + test plan + Fable audit — status on `0fcd36f82`

### 2.1 Fixed and closed (12 audit carriers)
#3543 (N1 continuity readiness oracle), #3546 (N6 release qualification + tag verify), #3547 (N7 evidence harness relocation to `scripts/evidence/` + the missing `mcp-tools-state.py` producer), #3549 (N11 shared authority boundary ruling), #3550 (N12 restore ordering), #3551 (N23 `export_reflection` disclosure incl. the pg `for_admin` bypass), #3552 (N24 certified-pin evidence merge-blocking), #3553 (N26 SQLite `synchronous` default), #3554 (N27 38-vs-35 required contexts), #3297 (N15 AGE rationale drift), #3363, #3383 / #3379 (share/purge authority).

### 2.2 Fixed on rehearsal, issue open until promotion
#3404 (N2, A1/A1b/A2/A3 projection fidelity — `75e60de95`, `436459898`), #3544 (N3 shim `pending`/`ask` — landed chain 9d `e4fdac8e6`), #3548 (N8 `provenance_tier`/`confidence_tier` honesty), #3555 (N29 write receipts — `7a6561cd4`, `f5dc91e76`), #3557 (N22 standard adoption + declaration hash gate — `3d6c00c86`), #3288 (N13 pg export snapshot — 5 commits, **no queue row; add**), #3124 (A15 carrier — merged chain 12 `5aa53cd57`, rebound today), #3393 (F13 residue — `c65f34460`, rebound today).

### 2.3 Open, unowned, ruled v1.1.0 / deferred (20)
Cert track: #3558 (N14 §2 inventory), #3559 (N16 five clocks / RTO), #3560 (N17), #3561 (N20 soak + growth ledger + power-loss VM), #3562 (N21 on-call rehearsal), #3563 (N25 CONFIG-2 harness), #3564 (N31 mission suite). V-series: #3567 (abstention signal), #3568 (equal-budget baselines), #3569 (obsolete-advice hazard), #3570 (trap benchmark), #3571 (TOON handles), #3572, #3573 (AGE `find_paths`), #3574. Recall: #3565 (N9 `budget_tokens` not a ceiling), #3566 (N10 reads mutate). Other: #3545 (N4 `wrap codex --system`, now `deferred-v1.x`), #2440 (V7 stale ROADMAP-v110 statements), #2623, #2169.

### 2.4 Open, `ga-blocker`, zero commits
**#3556** (N30 — widen `check-cert-expiry.sh` watch set and re-bind the certificate). Queue row `# PENDING 00:10Z 3556 37cacaaa5` — a cherry-pick awaiting review. This is the §1.8 stale-LIVE certificate. **Priority raised: review next.**

### 2.5 Test-plan T-ids with no substrate and no issue
| T | Requirement | Why it matters | Disposition |
|---|---|---|---|
| T13 | Source-edge integrity across delete / invalidate / restore / export | Restore or export resurrecting an invalidated edge is the "deleted source silently reappears" class | **File v1.1.0** |
| T15 | Governance rule-set atomicity (malformed hot reload, partial application, replay of an older set, enforced policy version recorded) | The governance analogue of #3152 mixed state; #2047 covers the verb, not the contract | **File v1.1.0** |
| T18 | Cryptographic-erasure boundary declared (live / archived / derived indexes / queues / keys / backups) | §0.4's own logic ("do not assert erasure from offline backups") is unfiled; #2224 is adjacent | **File v1.1.0** |
| T16 | Consolidation under partial staging / repeated runs | #2893/#2894 landed but the partial-staging leg is not pinned | **Note on #2894** |
| A31 | Semantic recall p99 951 ms@16 → 4,018 ms@64 | Parked as `bug,low,v1.1.0` (#3335) with 0 commits; Fable said "label understates" | **Relabel high, keep v1.1.0** |

## 3. Mission-Critical Certification Standard — clause status

| Clause | Status on `0fcd36f82` | Owner |
|---|---|---|
| §0 artifact binding (`binary_sha256` + `source_commit` on `/capabilities`) | **Code absent** (0 hits in `src/`) — no published number is recomputable from a bound artifact; the premise of the standard | item 3b, **unfiled** → file v1.1.0 |
| §0.2 pre-registered declaration + hash gate | **Landed** (`v1.0.0-DECLARATION.md` rev 1, pin verified equal, gate `check-declaration-hash.sh` D1–D4, job in `c8-precheck.yml`) | #3557 landed |
| §0.2 gate is a merge gate | **No** — deliberately in `required-contexts-not-required.txt:64` until #3769 promotes | Conductor lockstep after promotion (with #3200, #3782) |
| §0.2 latency cells, pooled samples | Targets, not samples; 5 postgres rows are "2× the SQLite row (no pooled postgres sample)" | #3561 |
| §0.2 RPO per durability class | Type landed (`write_receipt.rs`); **no receipt from every write funnel**; power-cut fsync unevidenced | #3555 landed (partial), funnel coverage item 1c |
| §0.2 RTO (clock 3) | **`NOT_MEASURED`**; only clock 1 measured (329–382 ms) | #3559 |
| §0.2 unauthorized effects = 0 | Declared 0; no generated inventory to diff against | #3558 |
| §0.2 correction reachability ≥90 %, n≥30 | No baseline on the branch | #3564 |
| §0.2 growth budget | Unmeasured; `signals/actions/checkpoints/routine_runs` **excluded** and never pruned | #3561, #3011 |
| §1 evidence schema, `envelope_ref` enforcement | Bundle validator exists with 9 negative fixtures; **`envelope_ref` never read** → the declaration's core FAIL sentence has no enforcer | **defect, cheap** → #3557 follow-up |
| §2 surface inventory | Nothing | #3558 |
| §3 G1–G8 | G7 only; G6 partial; G8 red (below) | #3558–#3564 |
| §4 VENDOR SELF-CERTIFIED banner | In 2 of 4 compliance docs; absent from README, `/capabilities`, release notes | #3557 follow-up |
| §5 expiry watch set widened | **Not implemented**; certificate stale-but-green | **#3556, #3501** |
| §6 item 18 procurement appendix + ballot | Landed; every row says not certified; appendix↔standard regeneration **ungated** | #3557 landed |
| §7 GA statement in release note / README / `/capabilities` | **Nothing, no issue** | #3557 follow-up |
| §7.4 N-id → issue index, D4-enforced | **Mis-mapped 19 of 31 rows** (points at tracker #3308 / #3199 where #3543–#3566 exist); D4 cannot catch it; fix is `revision: 2` + re-pin, pre-authorised as "index only" | #3557 follow-up, **before #3769 promotes** |

**What a buyer reading `PROCUREMENT-APPENDIX-v1.0.0.md` finds unmeasured at GA:** every §8 row; no G1–G8 bundle for any artifact; latency as targets; RTO unmeasured; RPO uncomputable without receipts on every funnel; growth unbounded on the coordination plane; correction reachability without baseline; the 0-unauthorized-effects claim undemonstrated; the binary binding absent; `envelope_ref` unenforced; the declaration gate not required; and the "NOT CERTIFIED for mission-critical use" sentence said nowhere a buyer looks.

## 4. Finite-context document — claim → surface

| Claim | Status |
|---|---|
| Durable namespaced memory, verbatim recall | Surface exists; no "verbatim, not summary" pin; #3404 landed, open |
| Agent turnover without oral history | **= clock 3, `NOT_MEASURED`** (#3559) |
| Multi-agent shared state (inbox/signals/leases/lineage) | Exists; **no retention** (#3011), excluded from the growth budget |
| Provenance the agent cannot fake | Spine solid; derived tiers fixed on rehearsal (#3548, open) |
| Wake plane (≤256-byte hints, ≤60 s backstop, peer-cred UDS, isolation) | **Fully pinned** — six named tests |
| Latency a design target until #3473 | Discipline holds; #3473 open, no harness in tree |
| Cross-host wakes (#3631) | Landed (`applied_wake.rs`, `federation_inbox_wake_3631.rs`); issue open; dogfood #3630 open |
| "What is NOT the product's job" | **Nothing** in README / `honest-limitations.md` / `/capabilities`; the document is referenced by no other doc |
| Context budgeting | `budget_tokens` exists, not a ceiling (#3565); `limit` silently clamped at 50; ROADMAP records it as shipped |
| Compaction pipeline | Exists with a live `PreCompaction` site; the only ROADMAP-covered claim (v0.8.0 pillar) |

## 5. Two cheap defects to land before #3769 promotes (Conductor ruling)

Both are defects in the landed #3557 artifact, so they enter under the freeze rule. Cost to a paying customer if not fixed: a procurement reader following the declaration's traceability spine lands on a 300-comment tracker instead of the filed issue, and the README/release note give no envelope statement at all — a claims-truth gap in the two documents a buyer opens first.

1. **Declaration revision 2**: correct the 19 §6 rows to #3543–#3566; re-pin `declaration.sha256`; no miss line owed (`:157-159`). Re-pinning after the gate becomes required costs a lockstep ceremony, so do it first.
2. **§7 GA statement** in README, the v1.0.0 release note fragment and `/api/v1/capabilities` (a `certification: "not-certified-mission-critical"` field plus the envelope pointer); add the 3×3 VENDOR SELF-CERTIFIED banner to `v1.0.0-DECLARATION.md` and `BALLOT-PROCEDURE.md`; add the finite-context "what this does not fix" paragraph to `honest-limitations.md`. Docs + one small handler change. Also make `check-evidence-bundle.sh` refuse a run record whose `envelope_ref` ≠ the pinned hash (with a negative fixture, rule (m)).

## 6. v1.1.0 roadmap — the delta

`ROADMAP.md` needs one docs PR (owner: easy-coder lane, spawned today) adding:

- **§11.8 v1.0.x** — branch hygiene parts 2–4 (#3786), the 234-file pg lane-guard sweep (#3777 ruling), #3717 S2–S4 key rotation, coverage-job step timeout (no issue existed; filed today), #3702 schema-version double-claim gate, #3725, **#3152 at the top**.
- **§11.9 v1.1.0 — the certification release** (record the 2026-09-09 freeze ruling; refresh §9.8): G1 inventory #3558; G2/G3 continuity + mission suite, five clocks, RTO #3559/#3564; G4 CONFIG-2 + E3 #3563/#3560; G5 soak, power-loss VM, growth ledger #3561 with #3011 retention as prerequisite; G6 reproducible build + negative release fixtures; G8 widened expiry + re-issue #3556/#3501; item 3b binary/commit binding + `envelope_ref` enforcement; #3473 wake-plane acceptance; #3565 budget ceiling; #2671/#2631 fleet catch-up jitter and boot-path index build; #3567–#3574; assessor independence to drop VENDOR SELF-CERTIFIED; T13/T15/T18 (filed today).
- **Cross-references**: `docs/ROADMAP-v110.md` ↔ `ROADMAP.md`, `docs/compliance/` ↔ `ROADMAP.md`; header refresh (schema v100, tool count).
- **Commercial line** (v1.1.0): #3701 entitlement/licensing, #3716 settings plan/apply/rollback, #2647 PostgreSQL row-level security, #2407 OpenTelemetry, and the private AgenticMem health-monitoring framework consuming #3646's surface (§7).

## 7. Enterprise-class gap ranking (customer impact, with the cost stated)

Exists and is better than the reviews imply: `ai-memory keys` init/status/recover/prune with escrow; `doctor --posture` reading live `PRAGMA synchronous`; `/api/v1/monitoring/{status,metrics}` (#3646 landed chain 12); CycloneDX SBOM with its own Sigstore attestation; SSH-signed tag verification against an allowlist; SHA-pinned `attest-build-provenance`; `WriteDurability` type; four compliance documents; five runbooks.

Confirmed absent (0 grep hits): `binary_sha256`/`source_commit`; PostgreSQL row-level security; OTLP; `keys rotate` for 11 of 12 key roles; `doctor --host`; `SUPPORT.md` / SLA / DR / upgrade-rollback docs; any licensing or entitlement surface.

| Rank | Item | Cost to a paying customer | Where |
|---|---|---|---|
| 1 | #3404 read-surface fidelity | An agent acts on a stale revision and the audit cannot adjudicate which row it saw (§0.4 CERT-VOID) | landed, open |
| 2 | #3152 two-commit update on both backends | A crash between the content patch and the lifecycle transition leaves a row the caller was told failed but that half-persisted | **deferred v1.0.x — top of list** |
| 3 | #3717 S2–S4 | No rotation path for 11 of 12 key roles; a botched manual rotation loses the at-rest key and the text with it | v1.0.x |
| 4 | #3555 `durability_class` on every funnel | A `local-only` ack is indistinguishable from `replicated+backup`; RPO uncomputable | partial, item 1c |
| 5 | #3011 coordination-plane retention | Unbounded growth of signals/actions/checkpoints; blocks G5 outright | v1.1.0 |
| 6 | #3556 / #3501 stale-but-green certificate | The one certificate in the tree claims LIVE on a surface that has moved by thousands of lines | **ga-blocker, review next** |
| 7 | Item 3b binary binding + `envelope_ref` | No published number can be tied to the binary that produced it | v1.1.0 (+ cheap half in §5) |
| 8 | #3559 clock 3 | The product thesis (replacement agent hydrates from the store) has no number | v1.1.0 |
| 9 | #2647 RLS, #3701 entitlement, #3716 settings plan/apply | Single-plane tenant isolation; nothing to sell or meter; 178 settings with no rollback | v1.1.0 commercial |
| 10 | #2671 / #2631 fleet catch-up jitter, boot-path index build | Fleet-synchronised pulls and a 900 s cluster-wide lock at boot | v1.1.0 |
| 11 | #3473 wake-plane acceptance | Every wake latency sentence stays a design target | v1.1.0 |
| 12 | Observability residue #3656, #3657, #3673, #3686 | Remote doctor omits the probe; wake counters not emitted; status hardcoded degraded | open, unowned; #3673 is a defect in the landed #3646 surface |
| 13 | OTLP (#2407), `SUPPORT.md`/SLA/DR docs | No standard telemetry export; no support contract a buyer can read | v1.1.0 |

## 8. Rulings recorded today

- **#3152 deferral stands for v1.0.0** (the fix restructures the update transaction on both backends at the freeze line; the failure needs a crash between two commits and returns `Err` to the caller, so the caller does not believe the write succeeded). It is the first item of v1.0.x and the roadmap says so. Cost stated above (rank 2).
- **#3556 review moves to the front of the owned queue** (ga-blocker, 0 commits, the stale-LIVE certificate).
- **#3557 follow-up (§5 items 1–2) admitted** as defects in a landed artifact; owner assigned by the Conductor to an easy-coder lane after the ROADMAP PR.
- **T13, T15, T18 filed as v1.1.0 issues**; the coverage-job headroom filed as v1.0.x CI hygiene; #3335 relabelled high.
- **#3288 row added** (fixed on rehearsal, was invisible); #3743/#3752/#3393/#3646/#3124 rebound landed; #3730/#3638 rebound owned.
- **Commercial health monitoring** lives in the private `alphaonedev/ai-memory-health-mon` repo (P0–P3 merged 2026-08-31, P3.5–P7 open, dormant since); its public-side dependency #3646 is landed and #3673/#3686 are the residue. Nothing from it enters the public roadmap beyond the API surface.

## 9. What this assessment could not verify
Live branch-protection contexts (not queried); `check-declaration-hash.sh --self-test` at `0fcd36f82` (not run); whether `37cacaaa5` actually widens the watch set (queue note only); reachability of #3032/#3126 (codegraph down); whether `memory_session_start` returns rules + decisions + open items + role inbox in one call (handler body not read); which wake tests run in a required CI context.
