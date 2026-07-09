# Will ai-memory v1.0.0 Be the Perfect Endpoint Memory System? — Codegraph Gap-Map + Recommended v1.0.0 Roadmap

> **Document classification:** Assessment + roadmap recommendation. Candidate input for the ROADMAP.md v1.0.0 revision. Companion to [`PERFECT-ENDPOINT-MEMORY-SPEC-3x7-FABLE.md`](PERFECT-ENDPOINT-MEMORY-SPEC-3x7-FABLE.md) (the 3×7-converged 27-requirement specification).
>
> **Date:** 2026-07-08 (v0.9.0 GA day). **Assessed substrate:** v0.9.0 @ main `59695ad0` (schema v78, 101 MCP tools), codegraph-indexed same day (901 files). **Assessed plan:** ROADMAP.md §11.6 + §25.3 v1.0.0 lane + §26 TRACT register + open v1.0-milestoned issues.
>
> **Method:** 7 codegraph-armed gap-map agents (one per spec category), instructed to be adversarial about SHIPPED claims — verify in code, never trust docs. Part of run `wf_68440e09-90e` (28 agents). Sprint-0 inputs were separately verified by the 2×5 adversarial run `wf_93009182-fff` (10 agents) — epic [#1938], trackers [#1936]/[#1937].
>
> **Authorship caveat:** Fable-5/Anthropic-family throughout; lens-decorrelated, not family-decorrelated. Candidate for the [#1171] panel. CLAIMED ≠ ATTESTED.

---

## 0. The three questions, answered

**Q1 — What is the perfect endpoint memory system?**
The 27-requirement converged specification in the companion document: a sovereign, offline-first, crash-only substrate where memory is cryptographic fact — custody-classed principal identity that outlives every model (R1), instance-distinguishable signed writes (R2), an externally anchored rollback-evident crypto-agile DAG (R3/A1/R75), in-substrate capability + taint + quarantine enforcement inside hard verified-path budgets with no disable path (R9/R19/R20/R23), mandatory epistemic typing and bitemporal lineage (R4/R52/R55), honest erasure and an honest kill-switch with a human-key veto (R56/R45/R40), belief-preserving coordinator-free federation with equivocation proofs and scoped ciphertext (R59/R22/R11/R65/R69), a gated attested weight-ingestion lane for the day weights unfreeze (A3), and a frozen sub-10 kLOC offline verification spec over an open forkable format (R24/R72/R84).

**Q2 — Where are the gaps?**
ai-memory v0.9.0 meets **no requirement fully, 20 of 27 partially, and 7 not at all** — and the v1.0.0 plan *as currently written* (§11.6 federation/portability/audit + §25.3 lane) closes almost none of the distance: **all seven category verdicts are "No" (longevity: "Partially")**. The plan matures transport, attestation-of-what-exists, and audit; it does not fund the identity, epistemics, governance-actuator, verified-performance, or frozen-spec work the specification demands. Full register in §2–§3.

**Q3 — Can these gaps roll into ai-memory v1.0.0?**
**Yes — with restructuring.** All 27 requirements can be homed inside a v1.0.0 *program*, but not inside v1.0.0-as-currently-scoped: the gap register totals **~251 sessions** (~4.3× the v0.8.0 release). The recommended structure (§4): Sprint 0 ([#1938]) → a **freeze-critical P0 lane** that MUST land before the v1.0 API-stability declaration (everything touching persisted/signed/wire shapes — reversing them post-freeze breaks the v1.0 promise) → a **kill-test P1 safety lane** → an explicit **P2 / v1.x residue** with recorded rulings. If capacity forces a split, cut a v0.10.0 hardening release mid-program and keep v1.0.0 as the freeze+audit release; do not freeze early — §11.6's public security audit should audit the FINAL surface, once.

---

## 1. Scorecard

| Category | SHIPPED | PARTIAL | MISSING | Verdict on v1.0.0-as-planned |
|---|---|---|---|---|
| identity | 0 | 2 (R1, R2) | 1 (R13) | **No** — plan's only identity item is the G13 recovery-verify code-comment promise |
| attestation | 0 | 1 (R3) | 2 (A1, R75) | **No** — audits what exists; adds no anchoring, rollback detection, or agility |
| governance | 0 | 5 (R9, R40, R56, R68, R69) | 2 (A3, R45) | **No** — capabilities stay opt-in; no crypto-shred, kill actuator, or human-key signature on approvals |
| performance | 0 | 2 (R23, R7) | 0 | **No** — only G31 rides the plan; no verified-path benches, no power-loss durability |
| epistemics | 0 | 4 (R4, R19, R55, R52) | 1 (R20) | **No** — no epistemic-lattice work in the blocking lanes; #1834 is open AT milestone v1.0 but P2/non-blocking *(corrected 2026-07-09)* |
| federation | 0 | 3 (R59, R11, R65) | 1 (R22) | **No** — transport/audit mature; none of the four cores (belief-preserving merge, scoped ciphertext, head entanglement, corroboration field) |
| longevity | 0 | 3 (R24, R72, R84) | 0 | **Partially** — Spec v2 + two non-Rust impls are planned (§11.6); frozen verifier spec, conformance corpus, taint model, governance ruling are not |
| **Total** | **0** | **20** | **7** | **v1.0.0 as planned ≠ the specification** |

> *Scorecard riders (2026-07-09 adjudication):* SHIPPED is empty **by construction** — the acceptance criteria are full end-state tests (R24 requires a clean-room <10 kLOC implementation, unreachable at any current version). Each PARTIAL divides into **PARTIAL(default-off)** — append_only, fed write-sig, capabilities: one-flip-plus-deprecation-soak — vs **PARTIAL(incomplete)** — R3, R24: real engineering. The two must never be averaged, and the 0/20/7 headline is never quoted without the honest-credit paragraph below.

**Honest credit — what v0.9.0 already is.** The gap-map's PARTIAL evidence is substantial and real: default-required store-path attestation (#1751), the V-4 signed-events chain with witness anchors + cause-binding + three-key role separation (G5b/G9), signed forget-tombstones with in-tx DLQ purge + synchronous HNSW eviction (v71/G30), the v75/v76 lineage DAGs (memory-derivation + identity-succession), BLAKE3 content-ids (v74), pure recall (v77), loader-attested model families + an enforce-capable N≥3 decorrelation gate (v78/D3-021), macaroon capability tokens (G10.1), the secret screen (G29), offline forensic-bundle verification, CRDT-lite convergent merge, and a 4-channel+mobile portable Rust/SQLite binary. ai-memory is credibly the **furthest-along real implementation** of this specification's trust spine. The distance that remains is the distance between a strong trust spine and the spec's full constitution — consistent with §26's own "substrate-ready, constitution-incomplete" verdict.

---

## 2. Gap register — the seven MISSING requirements

| Req | What's absent (verified) | v1.0.0 recommendation | Est. |
|---|---|---|---|
| **R13** custody+revocation | No custody-class record anywhere; no signed revocation; single-current-key verifier fails pre-rotation signatures; hardware custody explicitly out-of-OSS-scope (`keypair.rs:31-45`) | custody_class in lineage/attestation signed bytes; signed revocation records with validity boundaries; multi-key verifier honoring archived anchors | 5 |
| **A1** rollback-resistant head | `db::open` does no head/counter comparison; verification is manual CLI only; snapshot-restore of the SQLite file is undetectable | open-time head check vs TPM2 NV monotonic counter (file-counter OSS fallback) + signed fork-evidence emission | 10 |
| **R75** crypto-agility | Only tag-prefix stubs (`ed25519=`, `b3:`); no multihash/multisig envelope, no re-anchor ceremony, no PQ suite — a SHA-256/Ed25519 break strands every chain | multihash/multisig-tagged columns (additive migration) + operator re-anchor ceremony countersigning the prior chain head | 12 |
| **A3** weight-ingestion gate | No quarantine record tier; no ingestion-event schema; dormant contract undefined | define the dormant contract now (quarantine lifecycle_state + signed ingestion-event schema) — cheap while nothing consumes it | 4 |
| **R45** kill-switch actuator | Zero machinery: no write-fence, lease-revoke-all, recall/egress halt, or stop-attestation (grep = 0 production hits); TRACT register already bans the claims | `ai-memory stop`: atomic fence + revoke + halt ≤100 ms, stopper-key-signed stop-attestation enumerating ungoverned copies | 6 |
| **R20** trust-tier monotonicity | No trust lattice; tier = TTL only; consolidate actively launders (derived rows get confidence 1.0 + kind=Observation, `storage/mod.rs:6392+`) | trust-tier field distinct from TTL; derived = min(inputs) enforced at write on the shipped v75 DAG, both backends | 6 |
| **R22** peer-head entanglement | `/sync/push` has no checkpoint subcollection (FED-RQ-01 never landed → [#1936]); no countersigning, equivocation proof, or eviction | ride FED-RQ-02 checkpoints: embed countersigned peer heads + transferable proof object + eviction wiring | 10 |

## 3. Gap register — the twenty PARTIAL requirements (gap → v1.0.0 recommendation)

- **R1** (8): rotation-only chain — add fork/merge/delegation record kinds; land the promised recovery-verify; flip `attest_write` to resolve keys via `verify_lineage`; federate the chain.
- **R2** (10): no per-instance sub-keys; `SignableWrite` commits six fields with no instance/model-ref/session — extend the envelope (T4 vote required) + root-certified instance sub-keys reusing the federation credential-chain precedent.
- **R3** (15): record signature omits parent-hash; witness anchor is same-host; no peer countersigning — promote G5.3 to tracked issues; cross-peer checkpoint exchange (via [#1936]) + split-view proofs.
- **R9** (7): capability lane opt-in, grant-only, no deny/quotas, no first-boot owner mint, no fuzz corpus — default-on with deny semantics + auto-mint + published fuzz budget.
- **R40** (10): approvals clear on an unsigned approver string — thread operator-signature verification through the approve path; typed signed escalations; G17 m-of-n; 30-minute airgapped operability test.
- **R56** (8): no crypto-shred (per-agent not per-record keys); tombstones only on the forget path (GC/consolidate delete tombstone-free); no erasure attestation — per-record envelope keys + mandatory tombstones on every delete path + attestation enumerating ungoverned copies.
- **R68** (7): only credentials are screened; refusals unsigned — G28 class taxonomy at both egress points; G10.2 signed refusal with a latency budget.
- **R69** (5): revocations ride best-effort live push only — add tombstone feed to `/sync/since` catch-up + conformance audit flags + [#1852].
- **R23** (10): budgets 8–24× looser than spec, gated at 10k rows, no verification stage in any benched path, disable paths exist by design — 1M-row verified-path benchmark with p99 gates + G31 governor + hardened no-opt-out build profile.
- **R7** (5): `synchronous=NORMAL` loses acked commits on power loss; no fault-injection harness — durability mode naming its storage class + 10k-trial power-cut/SIGKILL harness.
- **R4** (5): untyped writes default to Observation (the *highest* class, not channel-derived); no told/intervention/refusal kinds; no declared-vs-verified distinction — [#1862] + channel-derived defaults + kind provenance in recall.
- **R19** (4): federation lane default-permissive; no quarantine tier — close [#1801] (sender-EMIT + TOFU), flip `AI_MEMORY_FED_REQUIRE_WRITE_SIG`, quarantine disposition for provenance-less inbound.
- **R55** (3): invalidation notifies only direct reflects_on dependents — transitive walker over the full LINEAGE set stamping a recall-surfaced suspect flag.
- **R52** (8): bitemporal on links only; #1834 is open at milestone v1.0 as P2/non-blocking — promote the bitemporal COLUMNS (persisted shape) into the P0 freeze lane, defer the full Claim algebra with a recorded ruling; `append_only` default flip rides the v0.10.0 WARN cycle *(corrected 2026-07-09)*.
- **R59** (10): CRDT-lite converges but LWW discards the losing belief — conflict-preserving fork + synchronous contradicts-edge + signed resolution.
- **R11** (12): scope grants are plaintext policy filtering — upgrade §11.6's E2E line to per-scope envelope keys (ciphertext-only replication).
- **R65** (8): attest_level is a metadata key, no k-of-n corroboration field or min_quorum query, no principal-level dedup — typed corroboration_status + reader-side quorum + anchor dedup.
- **R24** (30): verifier embedded in a ~200 kLOC binary; no frozen spec, no conformance corpus, no taint model — author + freeze the verification-semantics spec, ship the CC0 corpus ([#1837]) + standalone <10 kLOC verifier.
- **R72** (25): Portability Spec v1 stale vs v78 (policies/revisions/lineage/tombstones unexported); no second implementation — §11.6 Spec v2 regenerated against v78 + round-trip conformance + 2 non-Rust readers + embedder-tagged caches.
- **R84** (8): CLA + sole-authority = de-facto veto; no in-spec change process; no CC0 vectors — decide G25 at v1.0: in-spec governance without unilateral veto + CC0 vectors + SPDX/patent CI gate.

---

## 4. The recommended v1.0.0 ROADMAP

**Structure: one program, four gates.** Total mapped effort ≈ **251 sessions** (identity 23 · attestation 37 · governance 47 · performance 15 · epistemics 26 · federation 40 · longevity 63). v0.8.0 was ~58.5 sessions; the demonstrated v0.9.0 cadence (49 verified findings fixed + GA in 9 days) makes this a ~6–10-week AI-NHI program, not a year.

### Gate 0 — Sprint 0 ([#1938]) — already filed, blocks everything
Post-v0.9.0 reconciliation: W1 docs pass (factually-false public claims first), W2 tracker hygiene ([#1936] FED-RQ-01, [#1937] PE-3, title fleet, rulings for #1801/#1802/#1803/#1390/#1879), W3 evidence currency (frozen ship-gate/A2A/test-hub/NSA pages; counterfactual §17 gates), W4 past-due keep/cut rulings (L3 watcher, C-ABI FFI, LongMemEval refresh, plugin marketplace, distilled model). **No v1.0.0 feature work starts until Sprint 0 closes.**

### Gate 1 — P0 freeze-critical lane (~100–115 sessions) — must precede the v1.0 API-stability declaration
Everything here changes persisted, signed, or wire shapes; shipping the v1.0 freeze *before* these is self-defeating. Every item is a T1+T4 crossroads → 5-agent vote per the repo protocol.

| Item | Requirements | Notes |
|---|---|---|
| Crypto-agility envelope + re-anchor ceremony | R75 | multihash/multisig columns; PQ at checkpoint granularity |
| SignableWrite v2 (instance sub-keys, model-ref, session) | R2, R1 | the signed-bytes shape change; one migration, not three |
| Frozen verification spec + CC0 conformance corpus + standalone verifier | R24, R84, A16/A17 | with ATTESTABLE/ESTIMABLE labels in-spec; #1837 |
| Portability Spec v2 @ schema v78 + non-Rust readers | R72 | already §11.6-planned — extend to revisions/lineage/tombstones/policies |
| Epistemic kinds + channel-derived defaults | R4 | #1862; kind-provenance surfaced in recall |
| Claim-level bitemporal + append-only default flip | R52 | pull #1834 into v1.0; G6 Phase-B |
| Rollback-evidence anchor format + open-time head check | A1 | file-counter OSS path; TPM2 NV where present |
| Equivocation-proof object + checkpoint federation | R3, R22 | rides [#1936] → FED-RQ-02 |
| Quarantine tier + dormant weight-ingestion contract | R19, A3 | cheap now, format-binding later |
| Custody-class + signed revocation records | R13 | signed-bytes addition — freeze-critical |

### Gate 2 — P1 kill-test/safety lane (~55–60 sessions) — v1.0.0-blocking, format-independent
`ai-memory stop` actuator + stop-attestation (R45) · crypto-shred + mandatory tombstones on all delete paths + erasure attestation (R56) · human-key signature on approvals + typed escalations + m-of-n (R40) · trust-tier min-propagation on the v75 DAG (R20) · transitive suspect invalidation (R55) · default-on capabilities + zero-config owner mint (R9) · federation write-sig flip + #1801 (R19 residue) · verified-path 1M benchmarks + no-disable hardened profile + G31 governor (R23) · durability mode + fault-injection harness (R7) · signed refusals + egress-class gates (R68).

### Gate 3 — v1.0.0 tag = freeze + audit
§11.6's public security audit runs against the post-P0/P1 surface; API stability declared; §17 evidence gates all green (made real by Sprint-0 W3). Then the P2 residue rides v1.x **with recorded rulings, never silence**: per-scope ciphertext federation (R11) · belief-preserving merge (R59) · corroboration field (R65) · fork/merge/delegation identity records (R1 residue) · tombstone anti-entropy (R69) · federated lineage — plus the §5 items the spec itself defers (attested capture channels, human-subject rights index, succession directives).

**Ordering gates (non-negotiable, §25.3-style):** Sprint 0 → all else · R75 + R2 + R24 → v1.0 freeze (no freeze on unfixed formats) · [#1936] → R22 → FED-RQ-02/03 · R19 quarantine → A3 ingestion contract · #1706 shadow (shipped) → #1707 live wire · D3-012 (shipped) → D3-021 default flip (planned) — unchanged.

---

## 5. Claims discipline (extends ROADMAP §25.6/§26.5)

**Perma-banned as public claim/brand** *(amended 2026-07-09)*: "the perfect endpoint memory system" — the unlock is unsatisfiable by this document's own discipline (every "zero bypasses" acceptance is ESTIMABLE forever); the phrase survives only as the internal spec-target denominator. Unscoped world-action "kill-switch" / "stops an ASI" is likewise perma-banned; the scoped **substrate record-stop** claim unlocks at R45. Until the named gate ships, **banned:** "rollback-evident" (A1) · "crypto-agile" / "post-quantum-ready" (R75) · "verified recall ≤10ms" (R23 benchmark) · "power-loss durable" (R7 harness) · "crypto-shredded" / "provable erasure" (R56) · "no trust laundering" (R20) · "belief-preserving merge" (R59) · "scoped-ciphertext federation" (R11) · "frozen verifier" / "archaeology-grade" (R24). **Standing:** vote-independence is ESTIMABLE forever; signatures prove authorship, never truth; this assessment is CLAIMED-diverse (single model family) until the #1171 panel reviews it.

## 6. Verdict

v0.9.0 is the strongest existing base for this specification — and v1.0.0 **as currently planned** would not reach it: 0/27 requirements fully met, all seven category verdicts negative. Restructured as **Sprint 0 → P0 format-freeze lane → P1 kill-test lane → freeze+audit**, with the P2 residue explicitly ruled into v1.x, the answer to Q3 is **yes**: the gaps roll into the v1.0.0 program, the moonshot trajectory holds, and the v1.0 API freeze lands on formats that can survive AGI-and-beyond timescales instead of freezing today's shapes one release too early.

---

## 7. Adjudicated amendments to the v1.0.0 program (2026-07-09, binding)

From the cross-family 3×7 adjudication vs the Grok 4.5 49-agent assessment ([`FABLE-VS-GROK-4-5-3x7-ADJUDICATION.md`](FABLE-VS-GROK-4-5-3x7-ADJUDICATION.md)); where this section conflicts with §4 above, this section wins.

**Gate 1 (P0 freeze-critical) additions:**
- **UUID→cid record-identity-authority ADR** (Grok R16 sustained) — T4 5-agent vote pre-freeze; cutover migration stays out of v1.0 unless the ADR rules otherwise.
- **Read-path provenance/consumer-binding envelope scope** (M1) — ruled pre-freeze or explicitly recorded post-v1.0.
- **#1834 bitemporal COLUMNS promoted** from P2 into this lane (full Claim algebra deferred with a recorded ruling).
- **Supply-chain/build-integrity item:** cargo-vet-class dependency review over the lock, SBOM in release artifacts, implement-or-strike the ROADMAP:995 reproducible-build gate.

**New tag-blocking "defaults stop lying" sub-lane** (parallel to the format lane; adopted from Grok V10-G0, funded as named items): production reflect family-stamps + stamp-density probe → **D3-021 advisory-soak → enforce-as-default** → D3-031 consolidation-time gate → D3-060 enforcement-invariants ship-gate; `AI_MEMORY_RECALL_TOUCH_SYNC` removal path; fed write-sig (#94) + signal-sig (#96) WARN→flip. *A v1.0 tag whose lanes leave ROADMAP §24's committed decorrelation line unfunded contradicts this document's premise (1 CRITICAL, 6/6 voters).*

**Gate 2 (P1) amendments:** every fail-open→fail-closed flip binds to the one-cycle deprecation-WARN discipline (#1751 pattern, measured 13-day soak) — **v0.10.0 is promoted from capacity-fallback to a PLANNED WARN-carrier release**. PE-1 enforce + non-empty `required_events` + namespace standards ship as production TEMPLATES plus a named `asi-hard` procurement profile, never compiled default flips. R45 proceeds under the name **substrate record-stop actuator**. Add: inference-plane egress gating (R68/R72 rider), recall-completeness index-coverage reconciliation, A1 sanctioned-restore ceremony, capture-completeness lane (L3 build behind the Sprint-0 W4 ruling + operator notify approval), corpus-lifecycle spec/scoring subordinate.

**Sprint-0 additions:** audit-firm RFP/SOW package drafted Day-0 from the defaults-residual list (engagement operator-$-gated; execution stays post-P0/P1); the ban-unlock matrix as the W1 docs-pass work order (scoped unlocks: pure recall v77 ledger-only · #1751 store-path · G29 qualified-form-only · G30 single-node-only · epoch verify-only · loader-attested ~40% cap); W1 also purges the grandeur register from ROADMAP §24/§25 and this document's §6; record the §25.7 kill-test PASS.
**Tracker corrections:** told/intervention epistemic kinds need a NEW issue (#1862 is the refusal slice only, unmilestoned); the R69 catch-up tombstone feed needs a NEW issue (#1852 is the un-forget revocation primitive — wrong home); R40 row acknowledges shipped mitigations #1787/#1796 while the no-signature-on-approve finding stays P1.
**Schedule model disclosures:** operator bandwidth (every P0 item is a T1+T4 vote; the human is plausibly the critical path) and the metered-frontier-vendor dependency of AI-NHI labor. Public schedule posture adopts the slip rule — *tag when the gate spine is green; slip the date, never cut gates* — while session/week figures remain internal and ESTIMABLE-labeled.
**Freeze vocabulary:** all lanes are *planning-binding*; escalation to *ship-law* requires the #1171 heterogeneous panel.

---

*Sprint-0 artifacts: [#1938] (epic), [#1936] (FED-RQ-01), [#1937] (PE-3), [#1939] (provenance). Verification runs: `wf_93009182-fff` (2×5, 10 agents), `wf_68440e09-90e` (3×7 + gap-map, 28 agents), `wf_a100ebc9-daa` (cross-family adjudication, 21 agents). Memory: `df28fb5f`, `603edd0d`, `31838092`. CLAIMED ≠ ATTESTED throughout.*

[#1939]: https://github.com/alphaonedev/ai-memory-mcp/issues/1939

[#1171]: https://github.com/alphaonedev/ai-memory-mcp/issues/1171
[#1801]: https://github.com/alphaonedev/ai-memory-mcp/issues/1801
[#1834]: https://github.com/alphaonedev/ai-memory-mcp/issues/1834
[#1837]: https://github.com/alphaonedev/ai-memory-mcp/issues/1837
[#1852]: https://github.com/alphaonedev/ai-memory-mcp/issues/1852
[#1862]: https://github.com/alphaonedev/ai-memory-mcp/issues/1862
[#1936]: https://github.com/alphaonedev/ai-memory-mcp/issues/1936
[#1937]: https://github.com/alphaonedev/ai-memory-mcp/issues/1937
[#1938]: https://github.com/alphaonedev/ai-memory-mcp/issues/1938
