# v1.0.0 Epic — Fable 5 → Opus 4.8 Orchestration Handoff

> **Purpose:** the durable handoff from Claude Fable 5 (orchestrating the v1.0.0 epic in Phase A) to Claude Opus 4.8 (orchestrating Phase B after the Fable API cutoff). Read this in full when you inherit the epic. Everything Fable decided lives in ai-memory + the tracker, not in a context window — this document is the index into it.
>
> **Cutoff:** Claude Fable 5 → API-only at **2026-07-12 11:59:59 PM PT = 2026-07-13 06:59:59 UTC**. After that, **you (Opus 4.8) are orchestrator AND senior implementer**; Sonnet 5 runs the wide parallel lanes; Fable is default DO-NOT-USE (one logged exception: a twice-deadlocked 2×5 vote). Grok 4.5 optional as the decorrelated cross-family review leg + the #1171 xAI panel seat.
>
> **Authority:** operator grant memory `f9a0f397` — 100% autonomous, all decisions approved, through the GA cut (including temp-admin-lift merges + triggering the CI release). Corrections: `9a62049d` + `b8fd32a1` (Gate-3 reviews are AI-NHI multi-agent, no external auditor; 1:1 issue-per-finding, 100% fixed).
>
> **The two SSOTs you follow:** ROADMAP.md **§27** (the gate program) + the epic prompt [`AI-NHI-V1.0.0-DEVELOPMENT-EPIC-PROMPT.md`](AI-NHI-V1.0.0-DEVELOPMENT-EPIC-PROMPT.md) (the loop driver). Where they conflict, §27 wins; where either conflicts with a newer recorded 2×5 vote, the vote wins. **Epic tracking issue: [#1940].**

---

## 1. What Fable finished (Phase A — the freeze-critical DECISIONS)

The Fable window was spent on decisions-over-code: every signed-bytes/persisted-shape format decision that must be locked before a v1.0 wire freeze, plus the pre-freeze rulings. **All done and documented.** Do NOT re-litigate these — recall the memory, read the issue comment, implement.

### 1.1 The P0 freeze-critical format spine — 8 votes, 7 topics (all 2×5 adversarial, recorded)

| Decision | Memory | Issue | One-line |
|---|---|---|---|
| Crypto-core architecture | `129ca73f` | #1942/#1941 | Additive-versioned SignableWrite v2; one v79 migration; SubkeyCert; committed-**advisory** suite tag (verifier pins suite→key, never dispatches on the wire tag); fail-closed suite retirement |
| Identity ADR | `3cdc7834` | #1943 | **C dual-binding** — the envelope signs the **cid-genesis** six-tuple, NOT the uuid; uuid stays PK/FK/LWW authority; zero v1.0 cutover |
| Wire encoding | `289ea5e6` | #1942 | **CBOR definite-length ARRAY** (positional → kills the #1897 §4.2.1 ambiguity); pinned in-house encoder (NOT ciborium canonical mode); **golden-vector CI gate** |
| Custody + revocation | `da9eeb26` | #1949 | Extend v76 `agent_lineage`; custody_class closed named-const set (**OSS-refusal-attested, NOT hardware-attested**, never a cross-host trust input); revocation = 4th LineageReason keyed on the witness SEQUENCE; verdict-surface-only (no write-path teeth this train) |
| Rollback anchor (A1) | `aeb891a4` | #1946 | Open-time relocation of the #1822 witness check; counter binds into WitnessResolutionWire v1→v2; operator-signed `audit.restore_sanctioned` ceremony; **tamper-EVIDENCE not proof** in OSS |
| Epistemic kinds | `f4319a26` | #1945/#1862 | Add `told/instruction/intervention` + `kind_provenance` column NOW (v79); **default-flip off Observation PHASED to v0.10.0 WARN** (memory_kind is a signed cid-genesis field → naive flip breaks G8) |
| Quarantine + ingestion | `560c8007` | #1948 | System-only `LifecycleState::Quarantined`; **fail-CLOSED allow-list** exclusion (closes a live Tombstoned leak); opt-in default; A3 ingestion schema frozen dormant behind `ingestion-v1` tag |
| Equivocation proof | `00d599ec` | #1947 | Freeze 3 shapes (head-attestation atom, EquivocationProof, entanglement checkpoint); divergence key = `(subject, lineage-epoch, seq)` with epoch **lineage-attested not self-declared**; detection is LIVENESS, safety unconditional |

### 1.2 Pre-freeze rulings

- **Read-path M1** (`973f3056`, #1950→v1.x): **DEFER post-v1.0.** Write-path attestation + the shipped `recall_observations` ledger is the frozen boundary; a future recall-attestation is additive (not a freeze break). v1.0 read-path is **telemetry-strength, not proof**. Guardrails: anchor to `cid` not `recall_id`; fold into the signed_events witness spine.
- **Supply-chain** (`fad215c5`, #1951): SBOM **IMPLEMENT** (#1973, cargo-cyclonedx — forced because docs falsely claimed it live "since v0.6") · reproducible-build **STRIKE** (a same-runner byte-compare is theater; hedge = signed tag + R24 verifier + SBOM; SLSA post-v1.0) · dep-review **DEFER**. Live counterfactual claims already corrected in `encryption.html` (`edd014c2`); remaining surfaces (at-a-glance/release-pipeline/ROADMAP §17) folded into Sprint-0 W3.

### 1.3 Specs committed to main (your implementation targets)
- [`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`](format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md) — the R24 verifier target consolidating all 8 format decisions; ATTESTABLE/ESTIMABLE tagged. **Build against this, not the memories.**
- [`docs/spec/PORTABILITY-V2.md`](../spec/PORTABILITY-V2.md) — Portability Spec v2, finalized @ v80 from the v78 draft (L1/L2/L3 conformance; ≥2 non-Rust verifying readers shipped under `conformance/readers/`).

---

## 2. Phase B work queue (what you implement)

**Golden rule: implement against the frozen spec (§1.3), never re-derive.** Every P0 item is a T1+T4 crossroads — but the *format* is already voted, so implementation only re-votes if a genuinely new sub-decision surfaces. Gate ordering is binding (§3).

### 2.1 Gate 1 — P0 format implementation (the coordinated crypto-core migration first)
1. **Schema v79/v80 coordinated migration** bundling SignableWrite v2 (#1942) + crypto-agility (#1941) as ONE additive migration (v73 `cause_hash` template; both backends; NO full-table rebuild — v63/v65 trigger-drop lesson). The pinned in-house CBOR-array encoder + the **golden-vector CI gate** land here.
2. Custody-class + revocation on `agent_lineage` (#1949). Epistemic kinds + `kind_provenance` v79 (#1945; NOT the default-flip — that's Gate 1′). Quarantine `LifecycleState::Quarantined` + the fail-closed `lifecycle_visible_clause()` on all ~6 read/egress lanes (#1948, also closes the live Tombstoned leak). Rollback anchor open-time check + restore ceremony (#1946). Dormant A3 ingestion schema (#1948).
3. Portability Spec v2 exporter/importer + ≥2 non-Rust readers + the CC0 conformance corpus (#1837/#1944). R24 clean-room verifier (#1837).
4. Checkpoint federation transport (#1936) → then equivocation proofs + FED-RQ-02/03 (#1947). **Ordering: #1936 precedes #1947.**
5. #1834 bitemporal columns (promoted P2→P0). Custody #1949. SBOM CI job (#1973).

### 2.2 Gate 1′ — defaults stop lying (v0.10.0 WARN-carrier #1972)
The epistemic default-flip (#1945), the fed write-sig/signal-sig flips, `RECALL_TOUCH_SYNC` removal, and the D3-021 enforce-as-default all ride the **v0.10.0 deprecation-WARN release** (#1972) → flip in v1.0. This is a real release (manifests bumped, channels published, reduced-scope v0.9.0 checklist).

### 2.3 Gate 2 — P1 safety machinery (carriers #1955–#1965)
Record-stop actuator (#1955) · crypto-erase + all-path tombstones (#1956) · human-key approvals + m-of-n (#1957/#1831) · trust-tier min-propagation (#1958) · transitive invalidation (#1959) · default-on capabilities + owner mint (#1960) · verified-path 1M benchmarks + durability + fault-injection (#1961) · PE-1 templates + asi-hard profile (#1962) · signed refusals + inference-plane egress (#1963/#1838) · index-coverage reconciliation (#1964) · corpus-lifecycle (#1965).

### 2.4 Gate 3 — endgame (ALL AI-NHI-conducted, operator-specified order)
DO full-spectrum testing → **multi-agent codegraph-anchored code review (Rust-skills-driven)** → **multi-agent security review** → 100% fix + **1:1 issue per finding** (rounds until clean) → final DO + AI-NHI dogfood → **3×7 documentation drive** → **GA cut** (v0.9.0 release-page template; bump ALL manifests; signed tag; temp-lift merge; `gh workflow run release.yml -f tag=v1.0.0`; channel smoke tests; protection restored). No third-party auditor — you conduct both reviews.

---

## 3. Binding ordering gates
- Sprint 0 (#1938) before all feature work · SignableWrite v2 + crypto-agility land as ONE migration · #1936 → #1947 → FED-RQ-02/03 · quarantine → A3 ingestion · #1706 (shipped) → #1707 · D3-012 (shipped) → D3-021 default flip · **no freeze declaration before Gate 1 closes** · audit the final surface once · ship-law escalation (spec-axis amendments) → the #1171 panel (#1967, since the original #1171 is closed).

---

## 4. Orchestration runbook (how you run the loop)
- **Boot every session** (epic prompt §6.1): `memory_session_start` → `memory_recall "v1.0.0 epic"` → `gh issue view 1940` → `df -h /` → determine phase (you are Phase B now) → pick the highest-priority unblocked Gate item → `memory_store` the session plan → work.
- **2×5 decision protocol** (epic prompt §5): any decision point / T-crossroads / ambiguity → 2 waves × 5 adversarial agents (distinct lenses, never 5 copies) → synthesize → `memory_store` the record → move forward. Cite `4d3ea1c5` + `f9a0f397`. Never idle-wait.
- **Session-limit recovery (proven this session):** if a workflow returns all-errored on "session limit", it paused with zero lost work (prior decisions are checkpointed). On reset, re-run via `Workflow({scriptPath, resumeFromRunId})` — cached agents replay, only the failed ones re-run.
- **Session end (mandatory, §6.3):** `memory_store` a checkpoint (SHAs landed, in-flight, next actions, open votes) + a one-line comment on #1940. Assume the session may never resume.
- **Discipline anchors (epic prompt §7):** Rust skills mandatory (`/rust-skills` + `/rust-microsoft`, cite M-*/rule IDs) on all `src/` work; no-hardcoded-literals CI gates (`c8-precheck.yml`); disk monitor (`df -h /` at boot + before builds/DO/coverage — <25G WARN, <10G STOP; scratch in `.local-runs/`, never `/tmp`); DO teardown same-session; worktree discipline (#856) for parallel implementation; Sonnet never touches signing/governance/federation-auth internals.
- **Commit/push:** logical checkpoints with `Co-Authored-By`; docs `[skip ci]` + `scripts/check-docs-vs-ssot.sh`; code needs the four cargo gates + lint gates; main pushes via the temp-lift toggle (capture protection → `DELETE .../enforce_admins` → push → `POST` restore → verify `true`).

---

## 5. Honesty ledger (carry these caveats into implementation + docs — they are BINDING)
Every one of these was hard-won in an adversarial vote and MUST NOT be over-claimed:
- custody_class = **OSS-refusal-attested, NOT hardware-attested** (never a cross-host trust input until the hardware blob lands).
- A1 rollback = **tamper-EVIDENCE, not tamper-PROOF** in OSS (whole-host snapshot rolls the counter back in lockstep; real resistance needs TPM2 NV / off-host anchor).
- Revocation = **verdict-surface-only** until the epoch-aware write-path verifier (separate non-T4 change); single-node only.
- Equivocation detection = **LIVENESS not safety** (partitioned attacker invisible until heal); safety unconditional.
- Read-path = **telemetry-strength, not proof** at v1.0.
- SBOM = **inventory, not assurance** (lists deps, vouches for none; cargo audit covers known-vuln).
- Reproducible builds = **NOT claimed** (need an independent rebuilder).
- Perma-banned public claims: "perfect endpoint memory system", unscoped "kill-switch", grandeur register, "implements RQGM", vote-independence. CLAIMED ≠ ATTESTED; label estimates ESTIMABLE.

---

## 6. State at handoff-authoring (2026-07-09, ~85h pre-cutoff)
Main tip `edd014c2`. 13 adversarial votes (~130 agent-decisions), 2 specs + 1 live-defect fix committed, one clean session-limit recovery, every iteration checkpointed to #1940. Disk 190 GB free. Grant standing. Zero blockers. Provenance chain from the very first audit: [#1939]. Master checkpoint memory accompanying this doc: (stored alongside — recall "v1.0.0 epic handoff").

*Fable did the decisions; you do the build. The whole point of the front-loading: you inherit a complete, adversarially-verified, documented foundation — not a context window. Cleared hot.*

[#1939]: https://github.com/alphaonedev/ai-memory-mcp/issues/1939
[#1940]: https://github.com/alphaonedev/ai-memory-mcp/issues/1940
