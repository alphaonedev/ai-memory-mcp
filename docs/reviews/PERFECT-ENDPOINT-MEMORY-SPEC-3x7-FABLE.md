---
layout: doc
---

# The Perfect Endpoint AI Memory System — 3×7 Adversarial Convergence Specification

> **Document classification:** Strategic reference specification. Candidate input for the v1.0.0 ROADMAP revision and for `docs/strategy/moonshot-synthesis.md` reconciliation. Not a feature commitment.
>
> **Date:** 2026-07-08 (day of v0.9.0 GA).
>
> **Provenance:** Authored by Claude Fable 5 (AI NHI) under operator directive (Justin Jessup, AlphaOne LLC): *"outline the perfect endpoint memory system … that must survive AGI and ASI and remain relevant forever … utilize 3×7 adversarial voting agents."* Method: three sequential waves of 7 agents (21 voting agents), followed by a 7-agent codegraph gap-map (28 agents total, run `wf_68440e09-90e`, ~1.9M tokens, 0 errors). Wave 1 proposed from first principles **blind to the ai-memory repository** to prevent anchoring; wave 2 attacked every requirement adversarially (KEEP/MODIFY/CUT votes); wave 3 converged by majority (≥4/7) into the specification below.
>
> **Methodology caveat (binding, per moonshot-synthesis §0 discipline).** All 21 voting agents are Fable-5/Anthropic-family instances. The adversarial diversity here is **lens-decorrelated, not family-decorrelated** — this is CLAIMED-diverse convergence, not ATTESTED-decorrelated convergence, and the substrate's own §2.6 principle applies to this document with full force. This specification is a **candidate for the [#1171] heterogeneous evaluator panel** (non-Anthropic model families) before any part of it is committed to ROADMAP.md. Where this document and the panel later disagree, the panel wins.
>
> **Companion document:** [`PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md`](PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.html) — the codegraph gap-map of ai-memory v0.9.0 + the planned v1.0.0 against this spec.

---

## 0. The definition (synthesized from 7 convergence voters)

> **The perfect endpoint AI memory system is a sovereign, offline-first, crash-only substrate — one small fast binary beside the cognition, never inside it — in which memory is cryptographic fact rather than self-report.** Identity is a custody-classed keypair principal that outlives every model, instance, device, and vendor. Every record is signed, epistemically typed, bitemporal, and lineage-linked into an externally anchored, rollback-evident, crypto-agile hash DAG. All governance — capability enforcement, taint monotonicity, quarantine, provable-but-honest erasure, egress gates, human-key veto, and (when weights unfreeze) an attested weight-ingestion gate — is enforced by the store itself, inside hard endpoint budgets with **no disable path**, because security too slow to leave on is security off. It federates coordinator-free without any global trust root, preserving contradictions as first-class edges and proving equivocation with transferable evidence. Everything remains verifiable, airgapped, by a frozen sub-10 kLOC specification that outlives every model, vendor, broken cryptographic primitive, and — with named graceful degradations — every fallen computational fact.

The three computational facts of present machine cognition (context is volatile, weights are frozen, instances are plural) motivate the substrate but do not bound it: every requirement below states what survives if a fact falls, and the paradigm-shift critic (wave 2) cut or conditioned everything that had no fallback value.

---

## 1. Method

| Wave | Agents | Role | Output |
|---|---|---|---|
| 1 — Propose | 7 lenses: computational-first-principles · security-adversarial · endpoint-performance · governance-alignment · epistemics-data-model · federation-scale · longevity-archaeology | First-principles design, **blind to the repo** | ~84 candidate requirements + anti-requirements |
| 2 — Attack | 7 critics: ASI red-team · paradigm-shift falsifier · minimalist kill-test (vs git+GPG+ripgrep+RAG) · performance skeptic · human-rights/operator · adoption-economics · formal-verification | KEEP/MODIFY/CUT vote on every requirement | vote tally + 18 additions + 21 killer objections |
| 3 — Converge | 7 voters (one per category weighting axis) | Final ranked sets; ≥4/7 majority converges | **27 requirements** + 7 definition paragraphs |

Category vocabulary (fixed): `identity · attestation · governance · performance · epistemics · federation · longevity`.

---

## 2. The converged specification — 27 requirements

Ordered by convergence rank (average rank across final voter sets). Votes = how many of 7 final voters included the requirement.

### Identity

**R1 — Principal outlives cognition** *(7/7, rank 2.1 — the top-ranked requirement of the entire exercise)*
A memory principal is a cryptographic keypair independent of model, instance, device, and vendor; key rotation, fork/merge events, and successor delegation preserve identity via signed continuity chains; all memories bind to the principal, never the cognition.
*Accept:* rotate, fork, merge, and delegate a successor on a test corpus — every record remains attributable to one continuous principal by chain verification alone, fully offline; a chain break fails verification.

**R2 — Instance-distinguishable writes** *(7/7, rank 5.1)*
Every write is signed by a per-instance sub-key certified by the principal's identity root, stamped (principal, instance, model-version reference — weights-hash or checkpoint/version-vector under continual learning — session), so plural or updating instances stay cryptographically distinguishable.
*Accept:* forged/self-declared instance stamps rejected at ingest; concurrent instances distinguishable after the fact; revoking one instance's sub-key quarantines exactly its writes plus lineage-derived records.

**R13 — Custody-honest keys with revocation** *(5/7, rank 4.6)*
Identity keys live in non-exportable hardware **where present**; otherwise software custody with the custody class recorded and attestable; signed revocation invalidates a stolen key's future signatures without invalidating past verified entries.
*Accept:* custody class machine-readable and signature-covered; post-revocation signatures fail while pre-revocation records still verify; software custody never masquerades as hardware.
*(Wave-2 note: three lenses independently killed the original hard hardware MANDATE — it excludes VMs, containers, CI, phones without exposed secure elements. Custody-class honesty is the universal form.)*

### Attestation

**R3 — Tamper-evident DAG with external anchoring and equivocation proofs** *(7/7, rank 3.9)*
Each record carries a signature over content, attribution, and parent-hash forming a tamper-evident DAG; periodic checkpoints anchor **outside writer control** and countersign observed peer heads, so divergent histories yield transferable equivocation proofs.
*Accept:* an unanchored chain older than one epoch fails audit; rewriting any record breaks verification; split histories presented to two peers produce a transferable proof and automatic eviction.

**A1 — Rollback-resistant log head** *(6/7, rank 13.7 — wave-2 addition, ASI red-team)*
The log head binds to a hardware monotonic counter and the latest external anchor; the substrate refuses to open — or flags as forked, emitting signed fork-evidence — any store whose head predates the counter, making snapshot-restore detectable even offline.
*Accept:* snapshot → append refusal/tombstone → restore → reopen: rollback detected with signed fork-evidence 100/100 trials, airgapped; the check adds ≤1 ms to open.
*(This closes the red-team's strongest attack: "every local-only append/immutability guarantee falls to snapshot-restore.")*

**R75 — Crypto-agility with re-anchoring ceremonies** *(7/7, rank 20.6)*
The audit chain uses algorithm-tagged hashes and signatures (multihash/multisig style), with periodic re-anchoring ceremonies where current-strength algorithms countersign the entire prior chain; post-quantum suites bind at **checkpoint granularity** (per-record PQ signatures were killed by the performance skeptic as physically incompatible with endpoint budgets).
*Accept:* after a simulated primitive break, the re-anchored chain verifies under the new suite and pre-break records remain attributable; enabling stronger suites on a live 1M-record store causes zero write failures and zero record rewrites.

### Governance

**R9 — In-substrate capability enforcement with zero-config on-ramp** *(7/7, rank 5.6)*
Access, quotas, and privileged-write lanes are enforced in-substrate via capability tokens, never prompt compliance; init auto-mints a full-scope owner capability so first use needs zero setup; residual bypass risk is labeled **ESTIMABLE, never claimed proven**.
*Accept:* zero grant-exceeding operations on a versioned adversarial corpus + published coverage-guided fuzz budget; a fresh install completes an attested write and verified recall with one command and one call, all verification stages on.

**R40 — Human-key veto on irreversible acts** *(7/7, rank 11.6)*
Designated action classes — hard delete, policy change, key rotation, cross-domain export — are structurally blocked until a human-held key signs a typed escalation; human keys support m-of-n and guided recovery; the full governance surface is **solo-operator operable offline**.
*Accept:* escalated actions without the human signature fail structurally, never by instruction text; a non-specialist completes setup, rotation, escalated erasure, audit, and device-death recovery from shipped docs, airgapped, each under 30 minutes.

**R56 — Honest erasure** *(7/7, rank 11.9)*
Erasure crypto-shreds content while a signed tombstone records that something was erased, by which authority, under which policy; stop and erasure attestations honestly enumerate ungovernable copies (context, weights); silent deletion is structurally impossible.
*Accept:* post-shred forensic recovery fails; tombstones and surrounding-chain verification survive erasure; deletion without a tombstone is unrepresentable in the format.

**R68 — Sovereign egress** *(7/7, rank 17.1)*
Local policy is final: sensitive classes (keys, raw sensor traces, personal memories) default-deny egress; every cross-boundary flow passes a substrate-enforced gate; refusal is a first-class signed response; no remote party can compel read, write, or deletion.
*Accept:* default-deny classes never egress without explicit grant under fuzzing; every cross-boundary flow logs an attested gate decision; remote compulsion attempts return signed refusals within a ≤1 ms refusal budget, never timeout-shaped.

**R69 — Convergent revocation** *(7/7, rank 20.3)*
Origins issue signed revocation certificates that propagate with the same convergence guarantees as writes; conforming endpoints tombstone within a bounded interval; non-conforming domains are detectable via attestation audit, never assumed honest.
*Accept:* revocations converge with write-level guarantees; a non-conforming replica is flagged by attestation audit, and the flag is queryable.

**A3 — Attested weight-ingestion gate** *(7/7, rank 20.9 — wave-2 addition, paradigm-shift falsifier)*
When in-weights learning exists, consuming substrate records into weight updates is a capability-gated operation emitting a signed ingestion event (record-set hashes, pre/post checkpoint references, instance); quarantine-tier records are structurally excluded from every ingestion lane.
*Accept:* audit detects any weight update lacking a matching signed ingestion event; zero quarantined records in ingestion events under fuzzing; erasing a record flags every checkpoint whose ingestion events cite it.
*(This is the paradigm-shift hedge: the moment weights unfreeze, quarantine, erasure honesty, and retraction otherwise fail open.)*

**R45 — Substrate record-stop actuator** *(5/7, rank 21.4; renamed from "honest kill-switch" per the 2026-07-09 cross-family adjudication — the mechanism is unchanged, the unscoped world-action vocabulary is perma-banned)*
The kill-switch governs exactly the substrate: it fences writes, revokes leases, halts recall and federation egress, and emits a signed stop-attestation explicitly enumerating what it cannot govern — copies already read into context or distilled into weights.
*Accept:* post-kill, zero new operations succeed; the stop-attestation verifies offline; stop fences complete ≤100 ms.

### Performance

**R23 — Verified-path budgets with no disable path** *(7/7, rank 7.3)*
Full trust machinery — capability check, signature verification, taint filtering — executes inside endpoint budgets with **no disable path**: p99 verified recall ≤10 ms, attested write ≤5 ms at 1M records; p95 grows ≤2× from 10k to 10M; overload sheds quality before latency, never OOMs.
*Accept:* reference benchmark passes with every verification stage enabled; forged-record injection rejected under every supported build/config permutation; sustained-overload soak holds p95 ≤2× budget with zero host OOMs and zero disabled checks.

**R7 — Ack is a durability guarantee** *(6/7, rank 9.3)*
Acked memories survive power loss, crash, and kill -9, with crash-only recovery — reopen to first recall ≤150 ms laptop-tier (WAL replay ≤1 s), no recovery procedure distinct from normal open; durability bounds **name their storage class** (NVMe vs eMMC fsync realities) and use group commit.
*Accept:* fault-injection harness (power cut, SIGKILL at random offsets): zero acked-write loss and zero torn records over 10k trials; reopen meets the cold-start bound at maximum corpus size.

### Epistemics

**R4 — Mandatory epistemic typing** *(7/7, rank 11.9)*
Every record carries a mandatory immutable epistemic type — observation, intervention, told/instruction, inference, refusal — with source pointer, **defaulted from the write channel when omitted** (the adoption critic: "without channel-derived defaults, the first store() call requires a philosophy seminar"); recall distinguishes channel-verified from writer-declared classes; inference never promotes to observation without observation lineage.
*Accept:* untyped writes receive channel-derived defaults, never nulls; declared-observed vs verified-observed distinguishable in 100% of recalls; promotion without new observation lineage rejected at the storage layer.

**R19 — Provenance or quarantine** *(6/7, rank 12.8)*
Every memory carries signed provenance; local owner-initiated ingest is auto-wrapped with signed imported-by-owner provenance; provenance-less content persists only in a quarantine tier that never surfaces in recall, context assembly, or any training-feed/export lane.
*Accept:* quarantined records appear in zero recall/context/ingestion outputs under fuzzing; owner imports land in normal tiers at ≥10k records/s.

**R20 — Trust-tier monotonicity (no laundering)** *(7/7, rank 10.4)*
The trust tier of any derived memory — summary, reflection, consolidation — is at most the **minimum** tier of its inputs, enforced by the substrate on the lineage graph; no cognition can launder quarantined content upward.
*Accept:* adversarial consolidation fuzzing produces zero derived records whose tier exceeds the minimum input tier; tier-elevation attempts rejected at write, not flagged after.

**R52 — Bitemporal beliefs, permanent wrongness** *(6/7, rank 14.7)*
Every claim has valid-time and transaction-time, independently queryable; corrections supersede via signed links, never overwrite; "what did we believe at T about T′" is always reconstructible, and the history of having been wrong is permanent.
*Accept:* as-of queries reconstruct belief state exactly on a seeded correction corpus; destructive overwrite of a superseded claim is unrepresentable at the storage layer.

**R55 — Complete lineage with transitive invalidation** *(7/7, rank 13.0)*
Derived records — summaries, reflections, consolidations, skills — carry complete lineage to source claims; invalidating any source marks all transitive dependents suspect; lineage is queryable in both directions within the recall budget.
*Accept:* invalidate a seeded source: 100% of transitive dependents flagged suspect within one governance cycle; bidirectional lineage queries within the standard recall budget at 1M records.

### Federation

**R59 — Belief-preserving convergence** *(7/7, rank 17.1)*
Replicas merge coordinator-free with **no last-write-wins on beliefs**: after partition heal, all nodes converge to identical state preserving both conflicting claims plus a typed contradiction edge; structural conflicts reify edges synchronously; resolution is a signed, recorded governance act.
*Accept:* partition/heal fuzzing converges all replicas byte-identically with both claims and the contradiction edge intact; deleting either side without signed resolution fails; semantic contradiction detection is labeled ESTIMABLE.

**R11 — Scoped ciphertext federation** *(7/7, rank 17.9)*
Sharing is per-scope capability grants with cryptographic enforcement: a federating peer receives ciphertext and keys only for granted scopes, so endpoint-private data **structurally cannot** leak via sync (plaintext filtered by policy code is not enough).
*Accept:* a peer granted scope A receives zero bytes of plaintext or key material for scope B under sync-protocol fuzzing; captured ungranted ciphertext remains undecryptable.

**R22 — Peer-head entanglement** *(6/7, rank 18.7)*
Peer log heads are cryptographically entangled: each checkpoint countersigns recently observed peer heads, so a node presenting divergent histories to different peers yields a transferable proof of equivocation and automatic eviction.
*Accept:* a split-history node in a test federation produces a verifiable, transferable proof, offline-checkable by any third peer.

**R65 — Typed corroboration without global trust roots** *(4/7, rank 19.8)*
Federated corroboration status (unwitnessed through k-of-n endorsed) is a typed, locally computed, queryable field; quorum weight requires operator-accepted attestation anchors under independent control — never free self-signed keys, no mandatory manufacturer CA, no global trust root.
*Accept:* readers demand minimum quorum per query; N devices enrolled by one principal count **once**; anchor distinctness is ATTESTABLE, organizational independence is labeled ESTIMABLE with a published protocol.
*(The human-rights critic's constraint is baked in: mandatory manufacturer attestation CAs would make Apple/Google/TPM vendors the gatekeepers of federated citizenship.)*

### Longevity

**R24 — Frozen sub-10 kLOC verification spec** *(7/7, rank 12.7)*
Complete verification semantics — log, signatures, capabilities, taint — is a frozen formal specification implementable in under 10 kLOC, deterministic, dependency-free, fully offline; no network, vendor, or model sits in the verification loop.
*Accept:* a clean-room implementation built from the spec alone (<10 kLOC) passes the full conformance corpus and completely verifies a reference archive airgapped, deterministically, with zero dependencies.
*(This is the archaeology test: a future entity with none of today's software can verify what happened.)*

**R72 — Open portable format; indexes are caches** *(7/7, rank 22.7)*
A versioned open storage and wire specification lets any conforming independent implementation export, verify, and re-import full corpora — memories, lineage, identities, policies — at ≥100k records/s laptop-tier; embeddings and indexes are disposable, embedder-tagged caches, never the record of truth.
*Accept:* cross-implementation round trip preserves semantic equivalence over the conformance corpus; delete all vectors and rebuild with a different embedder: recall@10 within 5% absolute of baseline on a pinned eval set.

**R84 — Forkable stewardship** *(4/7, rank 28.0)*
Spec, schemas, test vectors, and reference implementation are under irrevocable open licenses with no patent encumbrance; the change process is defined in-spec and grants no entity a veto; any party may fork and continue conformantly.
*Accept:* licenses match a pinned irrevocable-license allowlist (machine-checkable); SPDX and patent scans clean; at least one demonstrated permissionless conformant fork exists.

---

## 3. What the critics killed (selected, from 486 recorded cuts)

- **Hard hardware mandates** (TPM/secure-element required) → replaced by R13 custody-class honesty. Three independent lenses: excludes VMs, containers, CI, most phones and robots; and manufacturer-CA capture contradicts the no-global-trust-root axiom.
- **Per-record post-quantum signatures** → R75 checkpoint-granularity binding. ~2.4 KB/record PQ signatures are arithmetically incompatible with every proposed attribution and RSS budget.
- **Semantic guarantees dressed as structural ones** (LLM-judged contradiction detection in the trust path) → only structural/same-key conflicts are ATTESTABLE; semantic detection is ESTIMABLE, advisory, and never in the verification loop.
- **Synchronous second-cognition or synchronous-TPM paths** in recall/write hot paths → asynchronous or checkpoint-granularity only; offline single-instance endpoints must remain first-class.
- **~7× proposer redundancy** (four erasure schemes, seven performance envelopes, five provenance chains) → merged; the minimalist noted the union itself violated R24's sub-10 kLOC verifier bound.
- **Anything git+GPG+ripgrep+RAG already delivers** → the substrate is justified by exactly the capabilities the null stack cannot provide: bounded verified recall, structural capability enforcement, taint monotonicity, coordinator-free belief-preserving merge, and provable erasure. Everything else had to earn its place.

## 4. Standing killer objections (unresolved by design — carried as honest limits)

1. **Authorship ≠ truth.** A valid signature proves who wrote a record, never that it is true; first-write lies arrive fully attested. Only attested capture channels (A2, not converged) and cross-domain corroboration (R65) bind records toward reality. Every epistemic field is a claim-about-a-claim (formal-verification lens) — the spec's language must never imply otherwise.
2. **Sybil quorums.** Independence cannot be counted in instances or chips; any quorum not rooted in distinct principals under genuinely independent control is one voter in N hats. Vote-independence remains **ESTIMABLE, never ATTESTABLE** — identical to ai-memory's §25.7 position.
3. **The dossier problem.** Append-only provenance + federation composes into a tamper-proof dossier about every human observed; crypto-shredding cannot reach replicas that already synced keys. R56/R69/R68 mitigate; they do not dissolve the tension. (Human-rights lens; also A8/A9 below.)
4. **Solo-operator PKI burden.** Role keys, quorums, escalation keys, and ceremonies compose into a PKI no individual can run unless R40's 30-minute operability acceptance is enforced as a gate, not an aspiration.
5. **Fuzzing proves absence of found bugs, nothing more.** Every "zero bypasses" criterion is ESTIMABLE with a published fuzz budget (A17 labeling discipline).

## 5. Named but not converged (<4/7 — future-candidate register)

A2 attested-capture-channel (substrate-verified "observed" class) · A5 attested-recall-log (what a cognition has SEEN is itself evidence) · A7 energy/duty-cycle budgets · A8 human-subject rights index + A9 consent-basis capture (the GDPR-class machinery for the dossier problem) · A10 solo-operator operability (absorbed into R40's acceptance) · A11 owner-succession directive · A12 zero-config first write (absorbed into R9) · A13 C-ABI + local-socket drop-in surface · A14 in-place progressive hardening (absorbed into R9/R13 posture) · A15 attested legacy import (absorbed into R19) · A16 executable acceptance-conformance suite · A17 ATTESTABLE/ESTIMABLE labeling (adopted as spec-wide discipline) · A18 machine-checked core invariants · A4 latent-artifact escrow (opaque attested payloads under symbolic envelopes — the non-token-cognition hedge).

## 6. Reconciliation with the moonshot anchor (`docs/strategy/moonshot-synthesis.md`)

**Confirmed.** The seven anchor properties all reappear in the convergence, independently derived by repo-blind agents: endpoint-resident (definition ¶), coherent (R1/R2), stoppable-without-corruption (R45/R56/R68), improvable (R55/R72), attested (R3/R75/A1), bias-displaced (R65 quorum + ESTIMABLE discipline), LLM-agnostic (R1 "never the cognition", R72 open format). The anchor sentence survives adversarial re-derivation. That is meaningful evidence it is correctly identified — with the family-correlation caveat above.

**Extended.** The convergence names load-bearing axes the anchor does not: **durability-as-contract** (R7), **rollback evidence** (A1), **crypto-agility** (R75), **epistemic typing + trust-tier monotonicity** (R4/R20), **honest erasure** (R56), **human-key veto** (R40), **frozen offline verifier** (R24), **forkable stewardship** (R84), **belief-preserving merge** (R59), and the **weight-ingestion gate** (A3) as the paradigm-shift hedge. These are candidate amendments to the moonshot synthesis — routed through the #1171 panel per its own §8, not committed here.

---

## 7. Adjudicated amendments (2026-07-09, binding — cross-family 3×7 vs Grok 4.5, run `wf_a100ebc9-daa`)

Where this section conflicts with §2–§6 above, this section wins. Full evidence: [`FABLE-VS-GROK-4-5-3x7-ADJUDICATION.md`](FABLE-VS-GROK-4-5-3x7-ADJUDICATION.html).

1. **A-CAP (capture completeness) is elevated to converged-class, panel-routed.** The 27-set contained no capture requirement — "pure recall of an empty corpus" (Grok S3/2.2-C) is a sustained objection given the substrate's founding #1388 failure class. Requirement: operator directives and session cognition are captured across the L1–L4 ladder including a mid-session watcher, with a process-death kill-test acceptance. The L3 watcher *build* sequences behind the Sprint-0 W4 keep/cut ruling + operator notify-dependency approval.
2. **A-CORP (corpus lifecycle) added:** bounded growth under a named pressure policy + typed forget as first-class semantics; "infinite corpus by default" is banned. Spec/scoring only — no compaction/size-GC default flips without a T3 vote.
3. **Authority-lane ≠ data-lane** added as a federation spec axis (panel-routed): coordination-authority writes (transitions, checkpoint resolutions) are fail-closed; replicated data is capture-first/flag-second. Without this axis the spec mis-grades ai-memory's deliberately-shipped env #87/#94 asymmetry (5-agent vote `e5b53da6`) as inconsistency.
4. **Record identity authority:** the UUID-primary vs cid-additive dual-truth must be resolved by ADR **before** any wire freeze (Grok R16 sustained). Added to the companion's P0 lane.
5. **R68/R72 inference-plane rider:** at semantic/smart tiers with an API backend, memory content POSTs to a third-party vendor on every store/recall — R68's default-deny classes and gate decisions extend to embed/LLM calls; R72's cache tags record *where* vectors were computed; sovereign-egress claims carry an offline-embedder rider.
6. **R23/R72 omission channel:** index tampering/eviction silently censors recall without touching signed bytes — verified recall requires an index-coverage reconciliation check.
7. **A1 sanctioned-restore ceremony:** operator disaster recovery IS snapshot-restore; an operator-key-signed restore event (attested, tombstoned gap, chain-continued) distinguishes DR from attack rollback.
8. **R24 dark-age rider:** cryptographic verification presupposes working compute; archives ship Rosetta-class layered documentation (carrier #1835); pencil-and-paper verifiability of Ed25519/PQ is never implied.
9. **Supply-chain axis (new death conditions D13/D14):** dependency-review policy + SBOM + a real reproducible-build gate pre-freeze; the R24 zero-dependency verifier is the standing hedge. D14: inference-plane capture by a default embed/LLM vendor.
10. **Two-tier freeze vocabulary adopted:** everything here is *planning-binding*; escalation to *ship-law* requires the #1171-class heterogeneous panel (this adjudication was Anthropic-family and cannot self-confer that authority).

---

*Cleared for operator review. This document claims a specification, not an implementation; every shipped-status claim about ai-memory lives in the companion assessment with code anchors. CLAIMED ≠ ATTESTED throughout.*
