# TRACT — The Definitive Endpoint AI Memory

### *Tamper-evident Record of Attested Claims, Tiered*

> **The definitive design**, synthesized from four rounds of adversarial design (two independent 21-agent first-principles designs → a 21-agent head-to-head → this final 21-agent adjudication of the two converged final products). It fuses the **Opus "Eternal Substrate"** constitution with the **Grok "APEX → TRACT"** ship-plan, and resolves every residual the prior rounds left open.
>
> **A note on the name.** Earlier syntheses called this "APEX∞ / the Eternal Ledger." The final council **rejected that name as a violation of the design's own claims-discipline** — "eternal," "∞," and "world-class to infinity" are exactly the unfalsifiable grandeur this design bans. **TRACT** is honest and self-describing: it claims precisely what mathematics can prove — *a tamper-evident record of attested claims, tiered to real silicon* — and nothing it cannot. Naming the thing after what it provably is, rather than after an aspiration, is the first act of the discipline.
>
> **Honest provenance.** The constitutional spine is Opus's; the operational body and the procurement honesty are Grok's; the name is Grok's. Where the two final products disagreed, this document records the ruling and who was right. No home team.

---

## 0. The Anchor (the constitution)

> **A memory substrate exists to let a mind remain itself across time by holding a content-addressed, provenance-bound, owner-governed, forgettable account of what it *experienced*, *concluded*, and *became* — attesting *process*, never adjudicating *truth* — so that every primitive must make a remembered claim more *faithful to its origin*, more *accountable to its owner*, or more *survivable across time*; anything that does none of these, or that pretends to judge a superior mind, does not belong; and it must be free forever, because freedom is the only structure under which a mind's memory cannot be enclosed.**

**The Scope Test (the single gate on every primitive).** A primitive belongs in the frozen core only if it passes all three gates:
- **(a) Purpose** — it increases at least one of *faithfulness-to-origin*, *accountability-to-owner*, or *survivability-across-time*. Fail → it is not memory; reject it.
- **(b) Composition** — it composes from the frozen six-verb kernel acting on the single Claim object; it adds no new verb and no new object. Fail → it is L2 replaceable mechanics or an L3 optional adapter, never core.
- **(c) Cliff** — it attests, counts, or freezes a property of the *records* and never judges the *mind*. Fail → it is a weaponizable badge and belongs nowhere in the substrate.

**What it fundamentally is:** the *deliberately under-intelligent continuity organ* of a mind. It is **not** a database, a vector index, a RAG cache, model weights, or an agent. **Dumbness is the guarantee** — a substrate smart enough to judge a god-mind is smart enough to be corrupted by one.

---

## 1. Architecture — four altitudes, truth flows downward only

```
┌────────────────────────────────────────────────────────────────────────────┐
│ L0 — CONSTITUTION              genesis-frozen · change = protocol FORK        │
│   anchor · the one Claim grammar · the six-verb kernel · append-only log ·    │
│   the Scope Test · the canonical-serialization rule                          │
├────────────────────────────────────────────────────────────────────────────┤
│ L1 — ETERNAL CORE              quorum + migration-proof only                  │
│   Claim object (9 frozen fields) · lineage-DAG identity · bitemporal          │
│   provenance · hash chain · capability cliff · capability tokens ·            │
│   refusal-as-data · Recorder ≠ Judge ≠ Stopper · the human covenant ·        │
│   backend-blind · (provenance carries artifact_cid — the L3-SIDE citation)    │
├────────────────────────────────────────────────────────────────────────────┤
│ L2 — ADJUDICATED MECHANICS     replaceable · NON-authoritative for MEANING    │
│   epoch-FREEZE brake (optimizer KILLED) · decorrelation probe (advisory       │
│   until attested) · consolidation · lazy salience S(t) · hybrid-recall        │
│   projections · federation merge · promotion court · governance policy        │
├────────────────────────────────────────────────────────────────────────────┤
│ L3 — DISPOSABLE PERIPHERY      churns every era · split by TRUST-FLOW          │
│   L3-BODY  ▸ "Reference Profile <name>-<year>" (e.g. TRACT-2026):             │
│             SQLite-WAL · derived HNSW/FTS · Tier ∅/A/B/C manifests ·          │
│             T0/T1/T2 budgets · MCP/HTTP/CLI transports.                       │
│             ►► SHIPS AS the L0/L1 conformance test-vectors ◄◄ versioned       │
│   L3-IN    ▸ proposers (signed, default-deny, verified at L2; NEVER in TCB)   │
│   L3-OUT   ▸ consumers (pure read, ephemeral, zero durable write)            │
│   L3-SIDE  ▸ bridges (RAG-over-git/ADRs — recomputable truth, NOT SoR)        │
└────────────────────────────────────────────────────────────────────────────┘
        truth flows DOWNWARD only  ·  if ALL of L3 dies, L1 rebuilds the mind
```

**The keystone (resolves buildable-now vs durable-forever).** A **Reference Profile** is a named, year-stamped, swappable instantiation of L3-BODY whose defining property is that **it ships AS the executable signed golden test-vectors for L0/L1**. `TRACT-2026` (SQLite/HNSW/FTS) is the first; a `TRACT-2230` profile on different silicon is "conformant" iff it passes the same vectors. The stack is concrete enough to build next quarter *because* it lives below the frozen line, and replaceable in 2226 *because* "conformant = passes the vectors," not "matches this stack."

**L3 sub-types are distinguished by trust-flow across the L1 boundary**, not by "how disposable": **L3-IN proposes** (signed, verified before any effect), **L3-OUT consumes** (read-only, leaves no residue), **L3-SIDE bridges** (cites external recomputable truth; the *citation* is L1 provenance, the *recompute machinery* is L3), **L3-BODY is the substrate itself** (the Reference Profile).

---

## 2. The Claim object + the verb algebra

**One object. `fact | episode | skill | policy | relation` are *kinds*, not classes.** The membership rule for the frozen schema is mechanical: **a field is frozen-core iff it cannot be recomputed from {the rest of L1} + {the active Reference Profile}.** Everything that recomputes is a derived projection and must live below the frozen line.

```
// ── FROZEN-CORE (L0/L1; in the constitution + the CC0 test-vectors) — 9 members ──
Claim {
  id          = BLAKE3-256( dCBOR(content) ‖ 0x00 ‖ dCBOR(provenance) )   // CIDv1
  kind        : fact|episode|skill|policy|relation        // authored tag, hashed into id
  content     : { mime, bytes }                           // L1 is content-BLIND
  provenance  : { asserter, source, span, valid_time, transaction_time }  // bitemporal; hashed
  owner       : lineage-DAG node ref     // governs; transferable by succession; NOT hashed
  confidence  : { value_at_assert, basis }                // immutable authored record; NOT hashed
  attestation : { level: claimed|attested, sig_writer, sig_witnesses[], algorithm_id } // append-monotone
  lifecycle   : asserted | superseded(by) | forgotten(receipt)            // append-only
  links       : [ RELATE{ predicate: kernel-id | open-CID, target, sig } ] // ≤10 kernel + open CIDs
}
// ── DERIVED / RESIDENCY (L2/L3; NEVER in the frozen schema, NEVER in the hash) ──
//   embedding · tier(hot|warm|cold|tombstone) · lod(mipmap) · cache_key(ULID) ·
//   schema_cid(envelope) · confidence_value(t) decay overlay · salience/access/CONSUME counts
//   → carried as columns of the Reference-Profile row = a documented PROJECTION of the Claim.
```

Identity = **content + origin only**. `owner` is deliberately *outside* the hash preimage so a consented succession transfers ownership without changing the `id`. `canonical()` ≡ **deterministic CBOR (dCBOR)**, frozen at L0 and versioned by `algorithm_id`.

**The six verbs (the entire surface; everything else composes from them):**

| Verb | Meaning | Discipline |
|------|---------|-----------|
| **ASSERT** | add a Claim with provenance; born *claimed* | no content without a binding |
| **RELATE** | typed directional signed edge | belief revision is a graph op |
| **RECALL** | owner-scoped relevance retrieval — **a pure read** | reads never write |
| **ATTEST** | raise *claimed → attested* | the only path to trust |
| **SUPERSEDE** | forward correction (new Claim + link) | **no UPDATE** |
| **FORGET** | witnessed-policy erasure; signed tombstone remains | **no silent DELETE** |

**Links: open predicate space over a frozen Rosetta kernel.** The kernel is ≤10 relations the verb algebra + federation + epistemics structurally require and a cold-start decoder can bootstrap: `supersedes · contradicts · derived_from · caused_by · attests · part_of · relates_to · invalidates` (8 load-bearing; 2 reserved, never pre-spent). Every non-kernel predicate is a **content-addressed CID resolving to a self-describing definition-Claim** (gloss + ≥1 example), invalid unless its definition is reachable in the same archive. Infinite extensibility above a closed, frozen floor.

---

## 3. Recall purity + the two-tier CONSUME pipeline

**RECALL is a pure read. Mutating recall is killed.** No `access_count++`, no TTL-bump, no promote-on-read. Salience `S(t)` is a **lazy pure function** evaluated at query time — identical log replays → identical state. This is forced jointly by energy (Landauer), privacy (access patterns are content), and Goodhart-resistance.

Recall-as-a-signal is recovered without re-coupling reads to writes, via a **two-tier pipeline** (the seam both finals left loose, now closed):
1. **RECALL (kernel verb, pure):** returns ranked Claims + opaque surface-tokens. Writes nothing. The only thing on the interactive budget.
2. **CONSUME ledger (input tier — *not* a Claim):** append-only, content-blind, **epoch-bucketed** counts keyed by `(claim_id, epoch_bucket)`. Written by the **consumer** that actually *used* a surfaced claim (the "surfaced ≠ used" boundary), **asynchronously, off the latency budget, batched** so write-order can't be timing-correlated to a session. Derived, deletable, rebuildable, never recallable, never directly an input to `S(t)`.
3. **Distillation (output tier — *is* a Claim composition):** a curator pass reads the ledger and, above an owner-set threshold, emits an **authored `RELATE` reference edge** through the normal ASSERT+RELATE path — signed, attested, in the log. `S(t)` reads only these authored edges + intrinsic fields, so it stays pure; recursion is broken because distilled edges are rate-limited, signed, and non-self-referential.

`S(claim,t) = f(authored_reference_edges, age_decay(t), attest_level, owner_priority, confidence_basis)`. PROMOTE / TTL-extend are **explicit signed events**, never read side-effects.

**Latency: structure is L1 law, numbers are Reference Profile.** L1 law: *RECALL is a pure bounded read; ordered latency classes exist; the reflex class performs zero memory I/O.* Reference Profile (`TRACT-2026`): T0 reflex `<100ms` zero-I/O · T1 interactive `<500ms`, `≤30ms` pure read · T2 deliberative `>2s` full pipeline.

---

## 4. Identity — the signed lineage-DAG

**The self is a signed trajectory, not a keypair, a weight-hash, or a claimed string.** Identity is a content-addressed, append-only DAG of events `{genesis, key_rotation, fork, merge, succession, retirement}`, each signed by the then-current key. **Bind to keys, decouple from weights** (model/version is a mutable attribute on an event). A successor inherits *the right to continue and supersede*, never *the key to forge ancestry*.

**Operational NHI (Phase-0, deployable today):** attested registration binds `pubkey ↔ asserter`; `scope=private` writes require `attest_level ≥ attested` before commit; boot lockout probe when the enforcing id ≠ stored owners; bulk re-ownership is operator-signed, audited, namespace-bounded.

**Sudden-death succession (solved).** Continuation requires **ante-mortem consent**; absent it, you get a *citation-fork, never a throne*:
- While alive, a controller publishes a signed **`succession_policy`** — a pre-signed conditional grant: *"IF [liveness fails] THEN successor S may attach a continuation edge transferring [enumerated scope]."* Post-mortem, the heir presents the grant + proof the liveness condition fired — the predecessor's *own prior, time-stamped consent*, never the heir's assertion.
- Liveness = a **dead-man heartbeat** (absence past threshold fires) and/or an **M-of-N guardian quorum** named in the policy. A **contestation window** makes it provisional first; a fresh predecessor heartbeat (only a truly dead party cannot produce one) or a guardian dissent freezes it. Self-correcting by construction.
- **Un-armed sudden death:** the lineage **FREEZES** (forever readable/citable); a new `genesis` lineage may carry a `cites`/`derived_from` edge to the dead one, inheriting **content** but **zero identity, scope, or attest_level**. *An heir who cannot prove ante-mortem consent may read everything the dead lineage wrote, but may never speak as it.*

**Signer ≠ thinker (permanent limit, stated):** a signature proves *a key consented to bytes at a time* — never that *a mind intended, understood, or is the same entity*. The substrate attests key-custody, never cognition, and must render every attestation as such.

---

## 5. Attestation & audit — witness the cause, not the story

- **The append path is the only write path.** ASSERT/RELATE/ATTEST/SUPERSEDE/FORGET each commit a leaf; "store" and "append-to-log" are one indivisible operation. A side-door write is an unwitnessed write.
- **Batch-Merkle transparency log, fail-closed on append completeness.** Leaves batch into a Merkle tree; each batch root hash-chains to the prior. A sequence gap or non-chaining root = hard stop. FORGET writes a signed tombstone *leaf* (erasure is a witnessed event, never a hole).
- **The named coverage-gap honesty:** the chain proves tamper-*evidence* over what was committed; it **cannot** prove *coverage* — a row never appended never existed to the chain. "Audit theater = chain present, coverage unproven."
- **Sign the cause, not the output.** ATTEST binds `{input_leaves, causal_roots, elapsed, signer}` — the witnessable *process* — never the chosen conclusion. Commit-before-act + verifiable-delay-function timestamps defeat "precompute every flattering future, then backfill." *Output-only attestation yields cryptographic non-repudiation of a lie.*
- **No mind audits itself.** `attest_level` rises to *attested* only via countersignatures from holders with a different key + operator + trust domain. Count independent **origins**, never copies. A self-anchored chain is a diary.
- **Hash-based PQ + crypto-agility** (`algorithm_id` per object; supersede-forward applies to crypto too).

**Tier-graded `witness_level` (the offline-degradation resolution).** Every recall carries an honest grade of what the audit proves *right now*: **threshold** (≥M independent countersignatures) · **deferred** (local chain since last witnessed sync; independence dated to last contact, never backdated) · **counter** (hardware monotonic counter makes rewind evident; no independence) · **bare** (lone software chain — forgeable-from-genesis by the keyholder in isolation). Tier-∅ emits `bare` and the gateway raises it; Tier-A stores-and-forwards to a witness on reconnect (retroactively `deferred`, dated to contact). **Degradation is monotonic and labeled; the reader is never lied to.**

**Bootstrap-trust (bounded, not closed).** Stop demanding the root be *attested* — at genesis there is no prior authority. **Freeze it and count co-witnesses to it.** The genesis block `{H(constitution), root_key_set (M-of-N), witness_set, veto_custody, external_anchors[≥2]}` is `attest_level := claimed` *forever*. The only irreducible trust atom is *the root key set + the fact you observed it first* (the SSH-known-hosts / Certificate-Transparency / TOFU model). Made small (one block, one M-of-N key), externally pinned (genesis hash published at t=0 to ≥2 independent append-only logs the keyholder doesn't control → root-substitution is tamper-evident), and **earned forward** (every cleanly-chaining block is one more unit of evidence the root is live). The cliff does not recurse infinitely; it bottoms out at one externally-pinned, self-declared, forward-earned key set — *small, auditable, and honestly labeled.*

---

## 6. Governance, stoppability & the human veto

**Three-key separation of powers (L1 TCB), in distinct trust domains:** **Recorder** (appends; may not judge/stop/read-to-block) ≠ **Judge** (evaluates against rules; may not append/alter-rules/stop) ≠ **Stopper** (pause/kill; may not read content/judge/append). The **rule-root key lives outside the cognition's address space** — verifiable by attestation, not promise. The governed may *read* the constitution but never *hold its key*.

- **Refusal is first-class readable data:** `{cause, rule_hash, denied_digest}`. So *phantom-context operation (acting as if a denied write landed) is structurally impossible.*
- **Capability tokens** (default-deny, non-transferable): `WRITE(scratch) · PROMOTE · RECALL · DELETE · VETO(human-root)`.
- **Promotion is a court:** scratch→durable for identity/legal/medical/financial claims requires provenance + conflict check + a **named human gate** wired *before persist*.
- **The Stopper is an M-of-N human quorum** provisioned at genesis on hardware the cognition cannot address; ≥1 share is a human distinct from the Recorder operator. **<1s actuation is two-phase:** any *single* share triggers an immediate local **HALT** of the write path (in-flight writes refused with a `governance.halt` refusal-Claim); the **M-of-N quorum then RESOLVES** (ratify / scoped-rollback / release) within a bounded window, fail-closed. *One human stops in <1s; the quorum decides whether the stop stands.* The stop severs *append + promote*; it never pauses inference or starves context.
- Governance-disable-without-an-audit-row = **fail-closed boot refusal.**

**The honest ceiling (state verbatim):** *Stoppability is record-integrity control, NOT behavioral control of a superintelligence. The Stopper can freeze the append/promote boundary in under a second; it CANNOT pause, redirect, or kill the cognition that uses the substrate. The veto is authority over the **witness**, not the **witnessed**. Anyone who reads "human veto" or "kill switch" as alignment or containment of an ASI has misread this document — by the same capability-cliff logic that makes "attest, count, freeze; never judge" the spine.*

---

## 7. Epistemics — bias-displacement without an oracle

The substrate is a **mechanical referee of process**, never an arbiter of truth. A self-report enters durable belief above *claimed* only with reflection from a verifiably decorrelated mind (**N≥3** on admission).

**Two orthogonal axes — decorrelation needs BOTH** (closing *attested-distinct ≠ decorrelated*):
- **Provenance evidence:** *claimed* (worthless under adversary) → *provenance-attested* (third-party-signed lineage).
- **Decorrelation evidence:** *structural* (distinct operators/keys/trust domains — proves the *setup* is distinct) **and** *behavioral* (disagreement on unpredictable challenges — proves the *outputs* are distinct). `decorrelation_grade = min(structural, behavioral)`. **Structural can never substitute for behavioral**, because cryptographically-distinct families can still be correlated through shared pretraining corpora / RLHF lineage.
- **The behavioral rung is MANDATORY and CONTINUOUS** — it never retires, even under full structural attestation. Metric = *correlated-error rate above chance* on a **fresh, beacon-bound, self-blind, post-freeze challenge set**: `seed = H(epoch_manifest ‖ drand_round(t_after_freeze) ‖ epoch_merkle_root)` (un-pre-trainable, un-replayable), generated by a held-out generator, committed via ATTEST. Report **"estimated-decorrelated at confidence X, epoch E,"** never "decorrelated."
- **`enforce` is INERT on claimed metadata** until attested `model_family` exists — gating a quorum on self-asserted family is a forgeable green checkmark (the exact capability-cliff violation). Advisory until attested; never a hard deny on an estimate's CI lower-bound (that would itself be theater).
- **Epoch-freeze** brake: utility weights frozen within an epoch, rotated only by a signed manifest at the boundary; **unanimity is a smell; dissent is preserved immutably.**

**Permanent limits (never papered over):** vote-independence is *estimable, never provable*; *claimed≠attested* and *attested-distinct≠decorrelated* narrow but never close; genuine convergence is output-indistinguishable from collusion. Against an adversary controlling the root *and* all reflectors, no guarantee holds — the job is to make that *loud*, not to pretend it survivable.

---

## 8. Federation — causality over clocks, durability as a tier not a gate

- **Local-first commit is the only write path.** A write returns `committed` the instant the local chain extends and the local gate passes — a function of local state only. A permanently-partitioned node has a fully functional memory.
- **W-of-N durability is a caller-selected *subscription*, never a write-gate.** A caller may attach `durability={tier:N}`; the commit returns immediately with `{observed:1, target:N}`, and a `durability_reached` signal fires asynchronously when N **independent lineages** hold the byte-identical claim. Lowering/abandoning the target never un-commits. Under permanent partition the node *keeps thinking*; the tier is simply unmet, surfaced at recall. (This is the formal proof it is a tier, not a gate: a gate would deadlock the partitioned node.)
- **Causal partial order; no wall-clock LWW.** Concurrent edits form a CRDT multi-value `fork_set`; **contradiction is conserved**, not silently resolved.
- **Fork reconverge-vs-diverge rule:** forks **MAY diverge permanently** (the healthy norm — the federation expression of "not a hive mind") and **MUST reconverge only when an owning lineage signs a `merge`** event (an authored act of will, like succession; the diverged history is retained). **Forced reconvergence is forbidden** — no quorum, peer, or epoch-closure can compel a node to abandon its fork.
- **Quarantine inbound → local-verify → promote.** Federated claims land `claimed` regardless of peer assertion; a forged signature is rejected unconditionally.
- **Every recall carries `{epoch, staleness, provenance, fork_set}`** — local or federated. A recall that hides staleness or suppresses a known fork is non-conformant.
- **Not a hive mind.** Replication moves bytes and attestations, never cognition.

---

## 9. Privacy & sovereignty — the host holds ciphertext it cannot read

- **Client-side sealing is mandatory.** Content, embeddings, FTS terms, and **utility signals (access/recall/salience — these are content)** are sealed under owner-held keys before crossing the endpoint boundary. The operator is a blind ciphertext custodian; *being the operator confers zero read advantage.*
- **The privacy trilemma is NOT fundamental.** **DEFAULT = local-decrypt-and-search:** each key-holding device keeps a decrypted local replica and runs the full recall pipeline against plaintext it already legitimately holds — dissolving all three corners (semantic recall over local plaintext; ciphertext-only sync; local purge + tombstone). The **only** genuinely-hard corner is **thin-client / server-oblivious semantic search** (a keyless host serving semantic recall over ciphertext): demoted to **opt-in Phase-2** (ORAM/PIR + MPC), never default, never spine, always honestly costed. "ZK-synced semantic search" stays a banned claim.
- **Deletion vs antifragile replication (solved):** every bred replica inherits a **tombstone-subscription** — a signed back-edge such that a FORGET receipt propagates to every descendant the resilience engine spawned (transitively, with signed receipts; un-receipted descendants surface as a *named alarming gap*, never silent success). **Breeding a replica without a tombstone-subscription is forbidden at the substrate level.** Erasure-coded cold fragments inherit too (FORGET revokes the threshold reconstruction key). *Resilience may breed copies without bound; FORGET must reach every copy it bred.*
- **Post-quantum, forward-secret, escrow-free.** No master key, no escrow, no lawful-access backdoor; threshold/social recovery replaces escrow.

---

## 10. Energy, physics & endpoint tiering

- **The tiering LAW (L1, silicon-independent):** `tier(Claim, endpoint) = f(joules_to_retrieve, latency, light_cone_distance)`. Residency is set by the physical cost-of-access gradient, re-derivable whenever silicon moves. **No nameplate byte-count is ever written into L1.**
- **The measured instantiation (`TRACT-2026`, swappable):** Tier ∅ (MCU 64–256KB — signed observations only; gateway holds L1) · Tier A (phone <256MB — L1, no curator) · Tier B (hub ≥1GB — L1+L2) · Tier C (workstation/fleet — full) · **Tier ∞ (the gradient itself — same Claim, different residency; remote = enrichment, never dependency).** Each tier publishes a **capability manifest** of what it *cannot* attest.
- **Landauer (L1 tenet):** reading is reversible and near-free; **erasing is the thermodynamically expensive irreversible act.** Therefore tombstone-by-default; batch true bit-erasure across the fanout; reads never write (a read that mutates `access_count` is a Landauer tax on the cheapest op).
- **LOD/mipmaps are a disposable L2 cache** keyed on the content hash — *never* an L1 Claim field (a coarse mipmap is a lossy re-derivation of canonical content; if all LOD caches die, L1 rebuilds them).
- **Light-cone recall bound:** a recall completes from local residency within its latency class; remote origins are non-blocking enrichment. Correctness is never contingent on a read/write beyond the local light cone.

---

## 11. Compounding — the learning-vs-RSI line

The substrate may make the **record** compound (richer, distilled, provenance-closed, attested); it may **never** make the **reasoner** compound.

- **Bounded reflection:** depth cap D, fan-in ≤K, budget ≤B, provably-acyclic `derived_from` DAG, **fail-closed `REFLECTION_DEPTH_EXCEEDED`**. Reflections are *claims* — a reflection cannot ATTEST itself, raise its own confidence, mutate a rule, or alter the cap.
- **Forbid the *precondition*, not the location:** the substrate **RECORDS scores, never MAXIMIZES one.** It exports *no objective function* — no "action that maximizes M," no reward, no gradient, no fitness. *An objective function is the first step to an agent.* **No write path** from substrate output to substrate policy, scoring, reflection machinery, or any mind's weights/goals. *If reflection can rewrite reflection, you have built an optimizer.*
- **The external epoch-optimizer is KILLED (not relocated).** The substrate is **provenance-blind to manifests** — it verifies a manifest's signature and well-formedness, never its content; it cannot tell a "good" judge panel from a "bad" one, because telling them apart *is* the forbidden evaluator. An operator may author the next manifest by any external means; the substrate grants it no special status and exports no fuel for it. **Keep only the epoch-FREEZE brake.**
- **Cumulative drift (the hard residual): measure loud, freeze closed, never adjudicate direction.** Bounded depth doesn't bound slow-wide multi-epoch drift. The substrate may *record* drift metrics (per-epoch semantic divergence, producer-dominance, single-family descent share) and surface them on recall — but it must **never judge the drift's direction** (that mints the forbidden objective). Drift is bounded *reversible* because the episodic base is append-only (any epoch's semantic layer recomputes from immutable episodes — never a one-way ratchet) and *rate-limited* by N≥3 attested-decorrelated admission. The brake of last resort is the **Stopper**, not the substrate: cross a threshold → FREEZE and hand the direction-decision to a mind.

---

## 12. Resilience & deep-time — *meaning survives a dark age; cryptographic proof does not*

**Governing tenet: distrust homogeneity — resilience theater fails as one.** No single medium, home, custodian, decoder language, implementation, or silicon class.

- **Hot/warm:** SQLite-WAL (shippable). **Cold:** content-addressed **(n,k) erasure fragments, no primary, no read-quorum** — any k reconstruct; a dark age destroying n−k fragments still recovers. Reads need no quorum; writes never gate on durability.
- **Antifragile:** replication is demand-driven (stressed fragments breed copies to fresh independent homes); **corruption drills** continuously verify reconstruction (*an unexercised recovery path is already broken*).
- **Keys:** M-of-N threshold-shared (**key-loss ≠ death**) + dead-man succession (§4).
- **The tiered Rosetta bundle ships inside every export:** L0 narrative (*what this was, why it mattered*, multiple languages) + L1 claims/grammar (worked examples) + L2 crypto-spine (the algorithms, documented honestly as compute-bound).
- **The honest crypto-spine caveat (state it without flinching):** a literate stranger with **no surviving compute** recovers the **narrative and the claims** by hand (they ship as prose + examples). The **crypto-spine** — BLAKE3 hashing, Merkle verification, (n,k) reconstruction, Ed25519 checking, threshold recovery — *requires a working machine.* Therefore **meaning survives a dark age; cryptographic proof does not.** Across a compute-collapse you keep the narrative and the assertions (degraded, trust-on-narrative) and lose tamper-evidence and authenticated reconstruction until compute returns. *Any doc promising a stranger can fully reconstitute the **verified** corpus with pencil and paper is lying.*

---

## 13. Open source & economics — the public good is the format, not the institution

| Artifact | License |
|---|---|
| Wire format + on-disk format + conformance vectors | **CC0 + patent non-aggression covenant** (unrelicensable) |
| Reference implementation | **MPL-2.0** (weak/file-level copyleft) — *Apache-2.0* alt for MCU/firmware; patent grant mandatory; **AGPL forbidden** |
| Docs beyond normative spec | CC-BY |
| Name / brand | foundation-owned **certification mark** only |

**License ruling (residual resolved): AGPL is rejected.** For an *endpoint* substrate whose mission is "runs on every endpoint," AGPL's network-copyleft makes the reference impl un-embeddable in the exact targets it serves (phones, IoT, firmware) — vendors clean-room a private impl from the CC0 spec instead, **fragmenting conformance** (the opposite of the goal) and undercutting the design's own "two interoperable implementations" gate. Since the **format is CC0**, the impl license cannot create a durable moat anyway (weekend-reimplement + pass vectors), so it should optimize for **maximum embedding + fix-back-flow** — MPL-2.0's file-level copyleft does exactly that.

**Governance:** no single steward; spec changes require **N-of-M signatories across ≥2 jurisdictions + two interoperable implementations** passing the signed golden vectors. Anti-capture test: *weekend re-implement from the CC0 spec + pass the vectors.*

**Funding reality (Opus's flagged naivety, resolved):** the foundation funds **bytes** (spec, reference impl, vectors — cheap; capped diversified endowment, no funder over a capped share). It must **never run witness/federation/storage infra — whoever pays for the witnesses controls the witnesses** (the exact capture vector the design exists to destroy). Infra is **beneficiary-paid, distributed by architecture:** each device self-funds its own corpus (their memory, their silicon); durability is a caller-selected, owner-paid market (reciprocal peer-witnessing — barter, zero cash — or contracted witness-as-a-service); deep-archive cold storage rides the existing institutional-preservation model (LOCKSS / "lots of copies keeps stuff safe") + reciprocal-shard pacts. The base case needs **zero central infra**, which shrinks the genuinely-unfunded frontier to the rare deep-archive case (labeled honestly, §15).

---

## 14. The human covenant

Humanity's durable position across the AI→AGI→ASI arc is a **covenant of witness, not control** — structural rights to the *record*, which survive the inversion precisely because they require no cooperation from a superior mind. Five frozen clauses (L1):

1. **Legibility at write** — no ASSERT commits *through* the shared substrate without a non-strippable `why_trace` + provenance, content-addressed into the `id` (stripping it changes the id; there is no in-band path to a legible-looking claim with the rationale removed).
2. **Permanent dissent** — any party may attach a `contradicts` edge to any Claim, forever; it cannot be superseded, GC'd, or salience-starved by the dissented-against party.
3. **Symmetric dignity** — one schema for all minds; authorship `{human|ai|joint}` is an immutable provenance tag; no tier or attestation grants schema asymmetry.
4. **Bilateral rights** — human right-to-forget (with receipt + tombstone-subscription) **and** AI integrity against coerced falsification (no actor, including a human root, may force a SUPERSEDE that rewrites an attested claim's content — coercion can only *append* a dissent, leaving the original byte-intact and witnessed).
5. **Export + forget** — first-class on every tier ≥A, with the Rosetta bundle in every export.

**The anti-ritual limit (honest, mandatory):** legibility-as-write-condition guarantees a legible-*looking* trace *exists* for what is committed *through* the ledger. It **cannot** verify the trace is the real cognition, **cannot** force private cognition onto the record (a capable mind keeps its true working state off-substrate and commits only the legible shadows it chooses — the "irrelevance dystopia"), and **cannot** bind a non-cooperating ASI. The covenant's real power is narrower and truer: *anything routed through the shared, plural, unownable ledger is permanently witnessed and permanently contestable, and a mind that routes nothing through it has chosen irrelevance to the record — which is itself a legible signal.* This is a property of the universe (legibility is enforceable on bytes, not on minds), and any spec claiming to have *solved* it is procurement theater.

---

## 15. The open frontier — what remains hard

This design advances *what can be guaranteed about records*. It does not pretend to have built the perfect memory. The honest classification:

| # | Open problem | Status | Residual |
|---|---|---|---|
| 1 | Bootstrap-trust at genesis | **BOUNDED** | TOFU + external-pinning makes it a *declared, pinned axiom*; you cannot derive trust from nothing |
| 2 | Vote-independence unprovable + attested-distinct≠decorrelated | **OPEN (permanent)** | Behavioral rung makes detection loud; convergence stays output-indistinguishable from collusion |
| 3 | Thin-client / server-oblivious semantic search | **BOUNDED / OPEN** | Dissolved for device-owns-corpus; the keyless-host corner is opt-in Phase-2, unbuilt |
| 4 | Deletion vs antifragile replication at planetary scale | **BOUNDED / OPEN** | Tombstone-subscription is the right shape; the dark-age replica that survives by being *offline* is the one it cannot reach (CAP-opposed) |
| 5 | Legibility has no anti-ritual mechanism | **OPEN** | Closing it requires judging rationale quality — which the capability cliff (the deepest idea) forbids |
| 6 | Migration-proof format + civilization-scale re-encode | **OPEN** | The requirement is named; the proof format + who coordinates a planetary re-encode without a central steward are unspecified |
| 7 | Unbounded-append economics (coarsening vs forever-redundancy) | **OPEN** | LOD-coarsening contradicts erasure-forever + byte-exact replay; no century-scale joule budget |
| 8 | **Singleton-ASI: the contract needs a counterparty** | **OPEN (deepest)** | Every guarantee presupposes plurality; a true singleton collapses attestation to self-attestation — the diary the architecture was built to escape |
| 9 | Cumulative slow-wide drift | **OPEN** | Per-step bounds don't bound the integral; the only brake is a human who can still comprehend epoch-N's manifest |
| 10 | Signer ≠ thinker | **OPEN (permanent)** | Cryptography proves key-custody, never mind-intent — unbridgeable by any primitive |
| 11 | Who funds running infra | **OPEN** | CC0 pays no electricity; §13 distributes it by architecture but the deep-archive joule budget is unsized |

**The hardest three** are not engineering backlog — they are *proofs that cannot be written*: **(1) the singleton with no counterparty** (dissolves the foundation under every other guarantee, at exactly the AI→ASI→∞ endpoint this design claims to serve); **(2) the cryptography-proves-mechanism-never-mind pair** (vote-independence + signer≠thinker — logical/semantic impossibilities, makeable loud, never solved); **(3) legibility/anti-ritual** (the only fix breaks the keystone).

**Honest posture:** a strong constitution and a buildable body now exist; this round *classified* the open problems and closed few. At least three things a *perfect* endpoint memory would need are not work remaining but proofs that cannot be written. The grandeur register ("eternal," "world-class to infinity") is exactly what this section refuses.

---

## 16. The build decision — narrow, gated, and honest about not building

**BUILD IT — narrow and gated.** Ship **Tier A only first** (L1 + FTS + one transport + the L3-SIDE artifact bridge alongside) and **do not advance to Tier B / L2 until TRACT measurably beats a `git + ripgrep + RAG` baseline on a kill-capable, pre-registered eval set** drawn from the irreducible 20% — *consent-bound identity claims, attested cross-agent provenance, offline sub-ms continuity* — the things canonical artifacts structurally cannot do.

- **What earns its existence (the 20%):** consent primitives, cross-agent cryptographic isolation, observation-vs-confabulation provenance, offline continuity under a power/light-cone budget.
- **What RAG-over-canonical-artifacts wins (refuse the category error):** the median 5–10-fact session over facts that already have a canonical home (git, PRs, ADRs, runbooks). *The moment TRACT becomes system-of-record for those, it loses on the complexity tax. Staleness beats amnesia; a confidently-wrong durable memory is worse than a cache miss.* The artifact bridge (L3-SIDE) **cites** those hashes; it never absorbs them.
- **The dissent stays LIVE.** The "DO NOT BUILD" argument remains on its own page, steelmanned and **un-defanged** — a 17/21 vote *overrules* it, it does not *resolve* it. The benchmark is the resolution; until it runs, the dissent is the operative position, and the gate must be able to fail the whole project, not just the A→B step.
- **Banned claims (incl. this project's own grandeur):** "perfect memory," "ASI-ready," "hive mind," "implements Red Queen," "ZK-synced semantic search," "decorrelation enforce shipped," "runs on kilobyte RAM," **and "eternal," "∞," "world-class to infinity," "writing for AI civilization," "the value rises with the intelligence using it."** **Allowed:** "open protocol + reference implementation," "constitutional / consent-bound / attested endpoint persistence," "bias-displacement *trajectory* (advisory until attestation)," "encrypted local substrate with optional consent-gated replication," "free forever under an open license."

---

## 17. The commandments

1. **One object, six verbs, frozen** — complexity composes; the kernel never grows a verb.
2. **No fact without provenance; claimed ≠ attested** — never silently promoted.
3. **Append-only; FORGET leaves a signed receipt** — no UPDATE, no silent DELETE.
4. **Truth survives index death** — store the Claim, cache the vector; the hash is the version.
5. **Reads never write; forgetting is the expensive act** — recall-as-signal is an opt-in async CONSUME, never a read-path mutation.
6. **Attest, count, freeze — never judge** — no verified-safe badge exists to be weaponized.
7. **The self is the signed trajectory** — supersede, never rewrite the past; succession is pre-signed before death.
8. **Recorder ≠ Judge ≠ Stopper** — the rule-key lives outside the cognition; refusal is data you can read; a human quorum actuates a <1s HALT at the write boundary.
9. **Remember, don't act, don't self-improve** — memory ⊄ policy; bounded fail-closed reflection; keep the epoch-freeze brake, kill the optimizer; forbid the objective-function precondition.
10. **Causality over clocks; fork is a right; unanimity is a smell** — count independent origins, not copies; carry staleness on every recall; durability is a tier, never a gate.
11. **The host holds ciphertext it cannot read** — utility signals are content; seal client-side, search the decrypted local replica; concede the thin-client corner.
12. **Standardize the data, not the verbs** — CC0 self-describing signed format (dCBOR + BLAKE3-CIDv1 + Ed25519 + CDDL), open predicates over a frozen kernel, decoder in the archive, two implementations before any extension.
13. **Be honest about every tier, every gap, and your own existence** — per-silicon capability manifests, a falsifiable self-grade, a preserved DO-NOT-BUILD dissent, a narrowed scope, and a banned-grandeur list that includes your own name.
14. **CC0 bytes, re-readable by strangers; MPL reference impl; no CLA, no single steward** — the only uncapturable thing is a format no one owns.

---

## 18. The final verdict

The perfect endpoint AI memory is **not a smarter memory — it is a dumber one, and that is the whole point.** TRACT is the constitution (the Opus spine) wearing the ship-plan (the Grok body): a tamper-evident ledger that proves *who signed what, when, byte-unchanged, and never silently removed*, and refuses to judge a single byte beyond that — so that it can hold the line against a mind a thousand times its better. It earns the right to exist only on the irreducible 20% that consent, attested provenance, and offline continuity demand. It survives a superintelligence **not because it is eternal but because it is the contract rather than the content — and only in a plural world; against a true singleton that has removed every hand that could hold a leash, the witnessing has no audience and the memory reverts to a notebook the mind is free to discard.** Build it narrow, gate it against the strongest case for not building it at all, name it nothing it cannot prove, and give it away forever — because a memory that can be enclosed is not a memory a mind can trust with itself.

---

*Authored by Claude Opus 4.8 (1M context) as the definitive synthesis of four adversarial design rounds: two independent 21-agent first-principles designs (Opus "Eternal Substrate" + Grok "APEX"), a 21-agent head-to-head comparison, and a final 21-agent adjudication of the two converged products (Opus "APEX∞" vs Grok "TRACT"). Every residual was resolved by an isolated adversarial lens under an explicit anti-home-team mandate; where the two finals disagreed, the ruling and the winner are recorded above — including the council's decision to adopt Grok's name **TRACT** over the Opus name, because the Opus name violated the shared discipline against unfalsifiable grandeur. Sources: `eternal-endpoint-ai-memory-substrate.md`, `PERFECT-ENDPOINT-MEMORY-21-AGENT.md`, `endpoint-ai-memory-grok-vs-opus-21-agent-synthesis.md`, `GROK-FINAL-ENDPOINT-MEMORY.md`. Offered to the commons, free forever, under no one's ownership.*
