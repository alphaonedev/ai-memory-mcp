# AI NHI Master Prompt — ai-memory v1.0.0 Development Epic (Loop Driver SSOT)

> **Document classification:** Epic master prompt. This is the canonical prompt/driver for every AI NHI session of the v1.0.0 development epic, from kickoff through GA cut. Read it at the top of every epic session, in full.
>
> **Date:** 2026-07-09. **Baseline:** main `6ada8bc3` (v0.9.0 GA + reconciled ROADMAP.md §27 program). **Plan SSOT:** ROADMAP.md §27 + `docs/reviews/PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md` §4/§7 (this prompt operationalizes them — where they conflict, ROADMAP §27 wins). **Tracking SSOT:** the global orchestration epic [#1940](https://github.com/alphaonedev/ai-memory-mcp/issues/1940) + Sprint-0 gate [#1938]. **Provenance:** [#1939].

---

## 0. Operator authorization (verbatim anchor — the epic's legal basis)

Operator directive 2026-07-09 (memory `f9a0f397`, `global`, priority 10):

> *"AI NHI YES APPROVED 100% make all decisions and run the entire v1.0.0 development epic … 100% autonomous via a loop or goal … approved to temp lift admin perms and merge or push to main and trigger the CI release … if AI NHI runs into any issues or decision point issue it is to run 2 waves of 5 adversarial agent voting procedure to reduce to a final decision point to move forward … lets go kick it off - approved YES."*

Scope of the grant: all development decisions, all tracker operations, all commits/pushes (including temp admin-lift merges to main), DigitalOcean test campaigns, the review/fix cycles (**including the security review — conducted by the AI NHI via multiple agents; there is NO third-party security auditor**, per operator correction 2026-07-09, memory `9a62049d`), the documentation drive, and **cutting the v1.0.0 GA release including triggering the CI release workflow**. The only standing operator-gate is spend outside the demonstrated DO-campaign envelope (droplet-scale test runs are pre-approved by precedent; ALWAYS tear down — see §7.6). There is no external-firm calendar dependency: the epic is AI-NHI-conducted end-to-end.

## 1. Mission

Execute ROADMAP.md **§27 v1.0.0 Program** to completion and cut the **v1.0.0 GA release**: Gate 0 (Sprint 0, [#1938]) → Gate 1 (P0 freeze-critical formats) ∥ Gate 1′ (defaults-stop-lying sub-lane via the planned **v0.10.0 WARN-carrier release**) → Gate 2 (P1 safety machinery) → Gate 3 endgame (below). The target specification is the 27-requirement converged spec (`docs/reviews/PERFECT-ENDPOINT-MEMORY-SPEC-3x7-FABLE.md`, with its §7 adjudicated amendments). The tag is **undated by policy**: *tag when the gate spine is green; slip the date, never cut gates.*

**Gate 3 endgame sequence (operator-specified, in this exact order):**
1. **DigitalOcean full-spectrum testing** — ship-gate 4 phases (functional / federation W-of-N / migration round-trip / chaos ≥0.995 convergence), crypto legs (3-leg mTLS + attestation + semantic recall, the v0.9.0 pattern), A2A cells. Teardown discipline mandatory (§7.6).
2. **Multi-agent code review — AI NHI, codegraph-anchored, Rust-skills-driven** (operator directive 2026-07-09): the AI NHI performs it within the epic — multiple review-lens agents (correctness, reuse/simplification, efficiency, altitude, **plus a mandatory Rust-skills lens and a no-hardcoded-literals lens**) working against the current codegraph index (re-index first), adversarially verified before filing, every finding a 1:1 issue. **Every reviewing agent loads `/rust-skills` + `/rust-microsoft` and cites the `M-*`/rule ID on each finding** (§7.8); the literals lens flags any violation the `c8-precheck` gates would catch (§7.9). Not an external service, not a one-shot tool call — a multi-agent pass the orchestrator drives over the whole v1.0.0 diff since v0.9.0.
3. **Multi-agent security review — AI NHI, NOT a third-party firm** (operator correction 2026-07-09): the v0.8.0/v0.9.0 pattern — multiple adversarial security-lens agents (crypto, auth/governance, federation/wire, injection/SSRF, erasure/privacy, supply-chain), each finding adversarially verified and filed as an issue. Same discipline as the code review, security lenses.
4. **100% fix + 100% track — 1:1 issue per finding** (operator directive 2026-07-09): EVERY finding from the code review AND the security review (and every DO-test and dogfood anomaly) gets its OWN GitHub issue (never bundled), and every one is fixed — no deferral without a recorded 2×5-vote ruling. Retest + independent re-check per the testing-loop discipline; repeat review rounds until a round returns **zero** unfixed findings. The tag cannot be cut with any review/security finding open.
5. **Final round: DigitalOcean + AI NHI dogfood testing** — hardened binary on DO (3-green) + local dogfood (3-green; live-DB migration rehearsal on a backup, the v0.9.0 recipe).
6. **Final documentation drive — 3×7 waves and agents** — 7 doc-surface lenses × propose/verify/converge waves: release notes, CHANGELOG, ROADMAP §27→"shipped" reconciliation, GitHub Pages, evidence pages (ship-gate/A2A/test-hub), CLAUDE.md counts, compliance inventory, docs-vs-SSOT gate green.
7. **Cut v1.0.0 GA** (§4 procedure). **Release page template = the v0.9.0 release template** (`docs/v0.9.0/release-notes.md` structure + the GH release-page format of tag `v0.9.0` — same sections, same evidence style, updated content).

## 2. Model fleet — two phases with a hard boundary

> **HARD CUTOFF (operator-confirmed):** *"Claude Fable 5 will switch to pay-per-use usage credits and API-only access on July 12, 2026, at 11:59:59 PM PT"* — i.e. **2026-07-13 06:59:59 UTC**. Treat the practical deadline as **2026-07-12 ~20:00 PT** to leave margin for a clean checkpoint; the cutoff may land without warning.

### Phase A — NOW → the cutoff: Fable 5 ⇄ Opus 4.8 ⇄ Sonnet 5

**Fable 5 (orchestrator + decision authority) — the Fable priority queue, in order. Decisions over code: nothing Fable starts may be unfinishable by the cutoff; every output must be a persisted artifact (vote record, schema, spec text, memory, issue) that Opus 4.8 can implement against.**
1. **T4 format votes** — run the 2×5 adversarial vote (§5) for every Gate-1 freeze-critical format and persist each verdict as (a) an issue comment on the item's carrier, (b) a `memory_store` decision record, (c) a byte-layout/schema spec in `docs/v1.0.0/format-decisions/`: SignableWrite v2 field set + canonical encoding · crypto-agility envelope (multihash/multisig tags, checkpoint-granularity PQ) · **UUID→cid identity-authority ADR** · rollback-evidence anchor + sanctioned-restore event · custody-class + revocation record shapes · epistemic kinds + channel-derived defaults · quarantine `lifecycle_state` + dormant weight-ingestion event schema · claim-bitemporal columns · equivocation-proof object · read-path consumer-binding envelope scope (rule pre-freeze vs post-v1.0).
2. **R24 frozen verification-spec draft** — the semantics skeleton (log chain, signature envelopes, capability caveat algebra, taint) with ATTESTABLE/ESTIMABLE labels; completion by Opus is fine, the *shape* decisions are Fable's.
3. **Sprint-0 W1 residue merges** it can complete same-day (docs-only, `[skip ci]`).
4. **The handoff package** (LAST DAY, non-negotiable): master checkpoint memory (the `f6713688` runbook pattern) — epic state, every open decision, the Phase-B queue, gotchas — plus a `HANDOFF-OPUS-4-8.md` in `docs/v1.0.0/`. If the cutoff hits mid-task, the most recent session-end checkpoint (§6.3) IS the handoff.
5. Fable does **NOT**: start multi-day implementations, hold undocumented state, or defer vote synthesis "for later".

**Opus 4.8 (heavy implementation, Phase A):** Gate 1′ defaults-lane — deprecation-WARN emissions for `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (#94) + `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` (#96) landing in **v0.10.0**; `AI_MEMORY_RECALL_TOUCH_SYNC` removal path; the fed write-sig (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, env-table row 94) + signal-sig (`AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`, env-table row 96) flips; family-stamp production wiring + stamp-density probe; Sprint-0 W2 tracker hygiene + W3 evidence-currency execution. Implement against voted formats only.

**Sonnet 5 (wide parallel lanes, Phase A):** evidence-page rebuilds (ship-gate/A2A/test-hub/v0.9.0 entries), test scaffolds + pg-parity twins for landed formats, fault-injection + fuzz harness skeletons, docs drift, stale-title tracker batch. Sonnet stays on well-specified mechanical lanes — never on signing/governance internals (the v0.9.0 hardening lesson).

### Phase B — after the cutoff: Opus 4.8 ⇄ Sonnet 5

- **Opus 4.8 becomes orchestrator AND senior implementer** (the demonstrated v0.7→v0.9 cadence). It inherits via: this prompt + the handoff package + the epic issue + `memory_session_start`/recall.
- **Sonnet 5** unchanged (wide lanes, same restrictions).
- **Fable 5 = API pay-per-use only. Default: DO NOT USE** (cost). Permitted exception: a single hard decision where a 2×5 vote genuinely deadlocks twice — one Fable API adjudication call, logged in the epic issue with cost noted.
- **Grok 4.5 (optional, recommended):** decorrelated cross-family review leg on signing-core diffs + the #1171 panel xAI seat (API `$2/$6` or the Heavy sub). Never an implementer on substrate internals.

## 3. The program — gates, exit criteria, ordering

**Gate 0 — Sprint 0 ([#1938]) — BLOCKING; no feature work until every box is checked or carries a recorded ruling.** W1 docs residue · W2 tracker hygiene (+ the kickoff-audit deconfliction actions) · W3 evidence currency (frozen pages; counterfactual §17 gates implement-or-strike) · W4 past-due keep/cut rulings (L3 watcher, C-ABI FFI, §11.4.A/B/E, PE-7, R8) · W5 **reconcile ROADMAP §11.6's "third-party firm" security-audit line** to the AI-NHI multi-agent review this epic runs (2×5 vote if contentious; the moonshot third-party line is superseded-for-this-epic).

**Gate 1 — P0 freeze-critical formats** (each item: 2×5 vote → spec → implement → sqlite+pg parity tests → docs). Item list per ROADMAP §27 Gate 1. **Ordering:** SignableWrite v2 + crypto-agility land as ONE coordinated migration; [#1936] precedes equivocation proofs precedes FED-RQ-02/03; quarantine tier precedes the ingestion contract; #1834 columns ride the same schema window. Exit: all P0 formats landed + tested + docs-vs-SSOT green; **no freeze declaration before this gate closes.**

**Gate 1′ — defaults stop lying (parallel, tag-blocking):** family stamps + density probe → D3-021 advisory-soak → **enforce-as-default** → D3-031 → D3-060; RECALL_TOUCH_SYNC removal; #94/#96 flips. Every flip rides the one-cycle WARN discipline through **v0.10.0** (a real release: manifests bumped, channels published, the v0.9.0 checklist at reduced scope).

**Gate 2 — P1 safety machinery** (ROADMAP §27 list): record-stop actuator ≤100 ms + signed stop-attestation · crypto-erase (per-record envelope-key destruction) + mandatory tombstones on ALL delete paths + erasure attestation · human-key-signed approvals + m-of-n + the 30-minute airgapped operability test · trust-tier min-propagation · transitive suspect invalidation · default-on capabilities + zero-config owner mint · verified-path 1M benchmarks + `asi-hard` profile + power-loss durability + fault-injection harness · inference-plane egress + index-coverage reconciliation · PE-1/namespace TEMPLATES · capture lane (post-W4 ruling).

**Gate 3 — the §1 endgame sequence, then the cut.**

**P2/v1.x residue** (scoped-ciphertext federation, belief-preserving merge, corroboration field, fork/merge/delegation identity, catch-up tombstone feed): touch ONLY with a recorded ruling; never silently.

## 4. GA cut procedure (the v0.9.0 recipe, upgraded)

Preconditions: Gates 0–3 all green · 8/8 CI green on the release branch tip · coverage floors met · docs-vs-SSOT gate green · §17 evidence surfaces current · CHANGELOG §2-property declaration present · #1171 panel review recorded for the major version · all issues 0-open-blocking.
1. Bump **ALL** manifests (Cargo.toml + lock, npm, PyPI, debian, spec, Homebrew, COPR — the v0.8.1 lesson: bump everything, gate the full CI feature matrix).
2. Release notes + release page from the **v0.9.0 template** (`docs/v0.9.0/release-notes.md` structure; same section order, evidence style, honest-limitations block). CHANGELOG entry with §2-property anchors.
3. GPG-signed tag `v1.0.0` on the release branch; merge to `main` under a **temp admin lift** (capture protection → `DELETE .../enforce_admins` → push → `POST` restore → verify `true` — the exact toggle used on 2026-07-09).
4. **Trigger the CI release intentionally**: `gh workflow run release.yml -f tag=v1.0.0` (it is `workflow_dispatch`-only — the release NEVER fires by accident; this step is the one deliberate trigger).
5. Channel publishes + per-channel smoke tests (`memory_capabilities` valid on each); PyPI/npm slot-burn contingency per the v0.9.0 experience (`.post1`/patch bump fallback).
6. Evidence pages + Pages deploy; GA memory (priority 10) + epic issue close-out comment; protection verified restored.

## 5. Decision protocol — 2×5 adversarial voting (binding for this epic)

On ANY decision point, contention, T1–T6 crossroads trigger (repo CLAUDE.md registry), blocked state, or ambiguity: run **2 waves × 5 adversarial agents** (this epic-wide protocol extends the repo's single-wave 5-agent vote; cite `4d3ea1c5` + memory `f9a0f397` in the record):
- **Wave 1:** 5 distinct adversarial lenses (never five copies) — each returns VERDICT / CONFIDENCE / RATIONALE / TOP_RISK / KILLER_OBJECTION.
- **Wave 2:** 5 verifiers attack wave-1's majority from primary evidence (code/tracker/docs), including one devil's-advocate and one both-wrong hunter.
- Synthesize → ONE decision → `memory_store` the record (options, tally, choice, why) → **move forward immediately.** Never idle-wait on a decision. A deadlock after two full runs is the single sanctioned Phase-B Fable-API exception (§2).

## 6. Loop mechanics

**6.1 Session boot (every iteration):** `memory_session_start` → `memory_recall "v1.0.0 epic"` (loads `f9a0f397`, the latest checkpoint, format decisions) → `gh issue view <EPIC>` (state + last checkpoint comment) → read THIS document → determine phase by clock (**before/after 2026-07-13 06:59:59 UTC**) → pick the highest-priority unblocked item for your model tier → `memory_store` the session plan → work.

**6.2 Work rules:** operator directives → `memory_store` FIRST (L1) · every finding → issue, every issue → fixed/tracked (prime directive; banned-phrase list applies) · commits at logical checkpoints with `Co-Authored-By` trailers; docs-only pushes `[skip ci]`; main pushes only at sanctioned points via the lift toggle · run `scripts/check-docs-vs-ssot.sh` before any docs push; the four cargo gates + relevant lint gates before any code push · worktree discipline (#856) for parallel implementation agents · scratch in `.local-runs/`, never `/tmp` · C1–C8 orchestrator safeguards on every agent return.

**6.3 Session end (MANDATORY, cutoff-proof):** `memory_store` a checkpoint (what landed with SHAs, what is in flight, exact next actions, open votes) + a one-line comment on the epic issue. Assume the session may never resume — especially every Phase-A Fable session.

**6.4 The loop prompt** (feed verbatim to each iteration, e.g. via `/loop` or scheduled goal):

```
Continue the ai-memory v1.0.0 development epic. Read
docs/v1.0.0/AI-NHI-V1.0.0-DEVELOPMENT-EPIC-PROMPT.md in full and follow it:
boot per §6.1, determine Phase A/B by the Fable cutoff (2026-07-13 06:59:59
UTC), execute the highest-priority unblocked gate item for your tier, apply
the 2x5 decision protocol (§5) at any decision point, and checkpoint per
§6.3 before ending. Operator grant: memory f9a0f397 (100% autonomous, all
decisions approved). Never idle-wait; never end without a checkpoint.
```

## 7. Discipline anchors (non-negotiable)

**7.1 Claims:** perma-bans hold ("perfect endpoint memory system" as public claim; unscoped kill-switch; grandeur register; "implements RQGM"; vote-independence claims). Unlocks only per the §25.6/§26.5 registers + adjudication scoped-unlock rows. CLAIMED ≠ ATTESTED; label estimates ESTIMABLE.
**7.2 Ordering gates:** §3 ordering is binding; enforcing on CLAIMED metadata is banned; no freeze before Gate 1; audit the final surface once.
**7.3 Reviews:** findings must survive adversarial verification before filing; stale-binary discipline (pm-v3.3 step 7) for any live-daemon claim.
**7.4 Sole authority:** no external code injection, ever; dependency adds require the §Cargo gates + a recorded vote.
**7.5 Sync:** memory ↔ epic issue ↔ ROADMAP ↔ commits cross-referenced on every material change.
**7.6 DO money-safety + disk-space monitoring:** every droplet/campaign records its teardown in the same session that created it; `teardown.sh` verified zero-residual (the v0.9.0 pattern); never leave paid infrastructure running across a checkpoint. **Monitor host free disk** (operator directive 2026-07-09): check `df -h /` at session boot AND before any release build, `cargo llvm-cov`/coverage run, DO artifact pull, or large log capture; treat **<25 GB free as a WARN** (clean `.local-runs/`, prune `target/` and stale build artifacts) and **<10 GB as a hard STOP** (the CLAUDE.md ENOSPC incident that motivated the no-`/tmp` rule lost the container fleet). **Never write scratch to `/tmp`, `/var/tmp`, `/private/tmp`, or any tmpfs** (project hard rule + host hook) — all agent scratch lives under `<repo>/.local-runs/`. Baseline at kickoff 2026-07-09: 190 GB free (79% used, `/dev/nvme0n1p3`).
**7.7 Model-tier guardrail:** Sonnet never touches signing/governance/federation-auth internals; those lanes are Opus 4.8 (Phase B) or voted-spec-implementation only.
**7.8 Rust skills — MANDATORY (operator directive 2026-07-09):** every agent that authors, refactors, or reviews Rust invokes the Rust skills and cites rule IDs. `/rust-skills` (265 community rules, 26 categories) + `/rust-microsoft` (Microsoft Pragmatic Rust Guidelines, stable `M-*` IDs) are loaded BEFORE writing/critiquing any crate, public API, error handling, unsafe block, async/perf hot path, macro, FFI, or workspace-layout change. Code-review agents (Gate 3 step 2) run a Rust-skills lens and cite the `M-*`/rule ID for each finding — following or flagging. Non-negotiable on all substrate `src/` work; this is a standing lane requirement, not a one-time check.
**7.9 No-hardcoded-literals — ENFORCED (operator standing rule, reaffirmed 2026-07-09; memory `no-hardcoded-literals-enforcement`):** proper `const`/variable scoping is mandatory and literals are NOT allowed unless absolutely necessary; **no literal values baked into variable or constant NAMES.** A repeated magic value becomes one named `const` referenced by name at every site — never scattered. Enforcement is a **CI gate, not a promise** — both scripts run as HARD-BLOCK jobs in `.github/workflows/c8-precheck.yml` (`hardcoded-literal-gate` + `vendor-literal-gate`, each with a `--self-test` step proving the gate is load-bearing): `scripts/check-hardcoded-literals.sh` (duplication ratchet — any double-quoted literal ≥10 chars on ≥3 production sites above the frozen baseline HARD-BLOCKS) + `scripts/check-vendor-literals.sh` (vendor-identifier monoculture + `SECS_PER_*` magic numbers → named consts from `src/lib.rs`). Run BOTH locally before any code push (they are the same scripts CI runs), alongside the four cargo gates + the other §25.5 lint gates; the baseline may only shrink (thresholds rise, never fall). New duplication fails CI; fix by defining/reusing a named const, never `--update-baseline` without an operator-justified commit. Every Gate-3 code-review pass includes a literals lens that files 1:1 issues for violations.

## 8. Tracking

- **Global orchestration epic [#1940](https://github.com/alphaonedev/ai-memory-mcp/issues/1940)** (milestone v1.0) = the epic SSOT: gate checklists, checkpoint comments, decision-vote index, phase-transition record at the Fable cutoff, endgame evidence links.
- Sprint-0 gate [#1938] · carriers [#1936] [#1937] · provenance [#1939] · Gate-item issues per the kickoff-audit deconfliction.
- ai-memory namespace `global`: `f9a0f397` (grant) · `83466b68` (cutoff constraint) · format-decision records · session checkpoints.

## 9. Success criteria

v1.0.0 GA is cut (all §4 preconditions), all seven §2-property contributions declared with code anchors, the §26.2 kill-test verdict re-recorded at v1.0.0, zero open tag-blocking issues, zero unreconciled roadmap claims (docs-vs-SSOT + the §25.6 register re-cut at the boundary), the #1171 panel record attached — and the epic issue closes with the full audit trail navigable from [#1939].

---

*Loop driver SSOT. Where this document and ROADMAP §27 conflict, §27 wins; where either conflicts with a recorded 2×5 vote made during the epic, the newest recorded vote wins and must be folded back into both at the next docs pass.*

[#1936]: https://github.com/alphaonedev/ai-memory-mcp/issues/1936
[#1937]: https://github.com/alphaonedev/ai-memory-mcp/issues/1937
[#1938]: https://github.com/alphaonedev/ai-memory-mcp/issues/1938
[#1939]: https://github.com/alphaonedev/ai-memory-mcp/issues/1939
