# W4-A1 — Cryptographic succession & crypto-agility for ASI

**Lens:** What must perfect endpoint memory do about Ed25519 forever?
**Surfaces:** quantum threat, key rotation (`agent_lineage` schema v76 / #1828 G13), witness / role keys, hash spine.
**Code anchors:** `src/identity/lineage.rs`, `src/identity/sign.rs` (`LINEAGE_DOMAIN`, `SignableSuccession`), `src/identity/keypair.rs` (`rotate_with_succession`), `src/governance/audit.rs` (witness K1/K2), `src/federation/signing.rs` (`ed25519=` prefix), TRACT §4–5 / §12.

---

## VERDICT

**Ed25519 is a shippable *present* algorithm, never a permanent identity substrate.** Perfect endpoint memory treats every signature algorithm as **rotatable evidence about keys**, not as the self. The self is a **signed succession trajectory** (genesis → rotation → recovery → retirement) with **crypto-agility first-class**: each signed object carries an `algorithm_id`; supersede-forward applies to crypto the same way it applies to claims. Classical-only Ed25519 is acceptable for v0.9 operational NHI; locking the long-horizon archive, audit spine, or identity continuity to “Ed25519 forever” is a **deep-time failure**.

---

## CONFIDENCE

**0.86** on the architectural claim (agility + succession + PQ hybrid path).  
**0.92** on the v0.9 gap inventory (schema + verify paths are load-bearing and readable).  
**0.70** on *which* PQ suite wins (NIST ML-DSA vs SLH-DSA vs hybrid profiles still move; the requirement is agility, not premature lock-in).

---

## REQUIREMENTS

Perfect endpoint memory must:

### R1 — Identity ≠ algorithm ≠ one keypair
- Identity is content-addressed succession of **events**, each signed by the *then-current* key under an explicit domain (`LINEAGE_DOMAIN`-style, versioned).
- A successor inherits the **right to continue and supersede**, never the ability to forge ancestry (TRACT §4).
- `algorithm_id` is a first-class field on every signable preimage (write / link / succession / audit-witness / role verdict / federation envelope), not an implied constant.

### R2 — Crypto-agility (supersede-forward for crypto)
- Verifiers MUST tolerate multi-algorithm chains: `ed25519` today, hybrid and/or PQ tomorrow, without rewriting history.
- Wire already sketches this for federation (`X-Memory-Sig: ed25519=<b64>` + trailing `;k=v` tolerance in `federation/signing.rs`); that pattern must become **substrate-wide**, not header-only.
- Algorithm retirement is a **signed policy event**, not a binary recompile that orphans the corpus.

### R3 — Quantum honesty (CRQC)
- **Ed25519 (and all ECDLP/discrete-log signatures) fail under a cryptographically relevant quantum computer.** Assume multi-decade memory archives outlive classical-only trust.
- **Hash spines** (SHA-256 audit chain, BLAKE3 `cid` outer address) degrade under Grover (~halved bits) but 256-bit digests remain operationally viable if algorithms stay hash-based and re-bindable.
- Transition plan: **hybrid signatures** (classical || PQ) during the window; pure PQ only after verifier ubiquity; **never** a hard cut that invalidates historical leaves.

### R4 — Key rotation (what v76 already points at)
- Live path: predecessor signs handoff → successor becomes head → flat `metadata.agent_pubkey` stays in sync in the **same transaction** as an append-only `signed_events` witness (C1/C4).
- Composite PK `(agent_id, epoch)` is the anti-equivocation primitive (C5).
- Rotation MUST also be able to carry **algorithm upgrade** (K_ed25519 → K_hybrid → K_pq) inside the same succession record shape — not a parallel ad-hoc table.

### R5 — Key-loss ≠ identity death
- Rotation survival ≠ loss resilience. Without ante-mortem consent / pre-enrolled recovery / M-of-N threshold, key loss freezes the lineage (readable/citable) and forces a **citation-fork**, not a throne (TRACT sudden-death).
- Recovery VERIFY + same-epoch fork tie-break are load-bearing; stubs that fail-closed without a path are honest only if operators can enroll recovery *before* loss.

### R6 — Witness & role keys are independent successions
- Audit-witness (`AI_MEMORY_WITNESS_KEY_DIR` / `AI_MEMORY_WITNESS_PUBKEY` K1 pin), Recorder / Judge / Stopper, operator rule keys, and agent author keys are **distinct custody domains**.
- Each needs: rotation, pin-update procedure, algorithm agility, and physical separation (already sketched for witness vs daemon).
- K1 pins must support **multi-key / multi-alg pin sets** during rollover (single pinned 32-byte Ed25519 pubkey is a single-alg cliff).

### R7 — Federation visibility
- Local succession that peers never re-enroll is invisible continuity. Perfect memory either (a) federates lineage records with the same witness discipline, or (b) labels peer trust as **TOFU re-enrollment**, never silent “same agent_id = same self.”

### R8 — Dark-age & compute-collapse honesty
- Meaning (narrative + claims) may survive without machines; **cryptographic proof does not** (TRACT §12). Exports must ship Rosetta L0/L1/L2 and never claim pencil-and-paper verification of Ed25519/PQ.

### R9 — Signer ≠ thinker (permanent limit)
- A signature proves *key custody over bytes at a time*, never cognitive continuity. Algorithm upgrade does not upgrade that epistemic ceiling.

---

## GAPS in v0.9

| # | Gap | Evidence |
|---|-----|----------|
| G1 | **Ed25519 monoculture** | `ed25519_dalek` hardwired in identity, federation, signals, checkpoints, audit roles; no `algorithm_id` on `SignableSuccession` / most preimages |
| G2 | **Lineage = rotation-only** | `lineage.rs` C7: not key-loss; `reason=recovery` wire exists, VERIFY fail-closes; G13 stays OPEN until v1.0 recovery |
| G3 | **Advisory only** | `attest_write` still reads flat `metadata.agent_pubkey`; lineage feeds `verify_audit_trail` / CLI, not the hot path (C6) |
| G4 | **No cross-host lineage** | Peers use on-disk `lookup_peer_public_key`; rotation is local-only |
| G5 | **Witness pin is single-key Ed25519** | `AI_MEMORY_WITNESS_PUBKEY` = one 32-byte key; no multi-alg pin set / dual-sign window |
| G6 | **Thin agility hook only on federation header** | `ed25519=` prefix + suffix tolerance; body/succession/audit formats lack parallel tags |
| G7 | **No hybrid / PQ suite** | No ML-DSA / SLH-DSA / hybrid encode-verify; no algorithm-retirement event type |
| G8 | **Role keys (G9) not succession-chained** | Recorder/Judge/Stopper are custody dirs + env pins; no `agent_lineage`-class chain for role keys |
| G9 | **Hash re-bind policy missing** | If SHA-256/BLAKE3 ever need domain/version bump, no supersede-forward recipe for cid + chain leaves |
| G10 | **Unsigned / missing-key daemons** | Audit chain without enrolled keys loses forgery detection on whole-suffix rewrite (documented #1850 posture) |

v0.9 **does ship** load-bearing pieces to build on: v76 `agent_lineage`, domain-tagged `LINEAGE_DOMAIN` (`…-v1\0`), `rotate_with_succession` (sign-before-destroy), co-tx `signed_events` witnesses, role separation + witness K1/K2, BLAKE3 additive `cid` (partial corruption + genesis bind, not PQ signatures).

---

## VOTE (single-lens synthetic; 5-axis internal)

| Lens | Stance |
|------|--------|
| Precedent | Follow v76 succession + versioned domains; extend, don’t replace |
| Spec / TRACT | Align with §4 self-as-trajectory + §5 `algorithm_id` + §12 dark-age honesty |
| Security posture | Fail-closed on unknown alg at **enforce**; multi-alg verify during hybrid window |
| Testability | Golden vectors per `algorithm_id`; multi-epoch multi-alg chain fixtures |
| Blast radius | Additive columns + dual-sign window; never hard-cut Ed25519 verification of historical leaves |

**Tally:** 5/5 — **do not freeze Ed25519 forever; make succession + algorithm agility L1.**

**Chosen pathway:** Keep Ed25519 as default operational suite; schedule (1) `algorithm_id` on all signables, (2) recovery VERIFY + threshold/social recovery, (3) hybrid PQ profiles, (4) federated lineage, (5) multi-key witness/role pin sets — in that dependency order.

---

## KILLER_OBJECTION

**“We already have key rotation (v76), so quantum is someone else’s problem.”**  
Rotation under a **single breakable algorithm** only lengthens the forgery window after a CRQC: every historical leaf still verifies under broken math if the adversary can forge past keys, and a rotation chain of broken signatures is theater. Without **algorithm succession + hybrid re-binding of long-lived roots (witness, operator, genesis pins)**, succession is classical hygiene, not ASI-horizon continuity.

---

## TOP_RISK

**Silent monoculture ossification:** shipping more Ed25519 surfaces (capabilities, lineage federation, role chains) without `algorithm_id` and dual-verify windows will make a future PQ migration a **full corpus re-sign or trust reset** — the worst outcome for an append-only endpoint memory that promises multi-decade attestation. Secondary: key-loss with no armed recovery freezes operator identity while the cognition process keeps running — continuity of *compute* without continuity of *attested self*.

---

## One-line north star

> **Ed25519 is today’s ink; succession + crypto-agility are the pen. Perfect endpoint memory never mistakes the ink for the author.**
