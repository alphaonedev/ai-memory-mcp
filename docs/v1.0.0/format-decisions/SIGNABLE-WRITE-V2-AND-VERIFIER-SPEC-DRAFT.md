# ai-memory v1.0.0 — Frozen Format Spec + R24 Verifier Semantics (DRAFT SKELETON)

> **Classification:** Draft format specification + the R24 frozen-verifier target. This is the SSOT consolidating the 8 adversarially-voted P0 freeze-critical format decisions of the v1.0.0 development epic (#1940) into one coherent wire/signed-bytes contract, so the clean-room conformance corpus (R24 acceptance, #1837) and every implementer build against ONE document.
>
> **Status:** DRAFT — authored in the Fable window (2026-07-09) from the recorded 2×5 vote decisions. Each section cites its decision memory; where a byte-exact field list is still `TBD` it is a documented implementation-phase detail, not an unresolved freeze decision. The freeze decisions themselves are DONE.
>
> **R24 target:** the verification semantics below (log chain, signature envelopes, capability caveat algebra [deferred], taint/exclusion) must be implementable in a clean-room, **dependency-free, offline, deterministic, sub-10 kLOC** verifier that passes the CC0 conformance corpus (#1837). No network, vendor, or model in the verification loop.
>
> **Labeling discipline (binding, per ROADMAP §25.6/§26.5):** every property below is tagged **ATTESTABLE** (machine-verifiable from the artifacts alone) or **ESTIMABLE** (statistical/operational assurance, never cryptographic proof). CLAIMED ≠ ATTESTED throughout.

---

## 0. Scope and provenance

Consolidates 8 decisions across 7 topics (epic #1940, grant memory `f9a0f397`, decision protocol `4d3ea1c5`):

| # | Topic | Decision memory | Carrier |
|---|---|---|---|
| 1 | Crypto-core architecture | `129ca73f` | #1942/#1941 |
| 2 | Identity ADR (dual-binding) | `3cdc7834` | #1943 |
| 3 | Wire encoding | `289ea5e6` | #1942 |
| 4 | Custody-class + revocation | `da9eeb26` | #1949 |
| 5 | Rollback-evidence anchor | `aeb891a4` | #1946 |
| 6 | Epistemic kinds + provenance | `f4319a26` | #1945/#1862 |
| 7 | Quarantine + dormant ingestion | `560c8007` | #1948 |
| 8 | Equivocation proof + head-entanglement | `00d599ec` | #1947 |

**What is frozen here:** the signed-byte layouts and wire grammars that become permanent back-compat + forensic obligations at the v1.0 tag. **What is NOT frozen here:** runtime behavior, enforcement verifiers, migration timing, and default-value flips — those are additive-later and phased per each decision.

---

## 1. Canonical encoding (decision 3 · `289ea5e6`)

**Every v2 signed record is a CBOR *definite-length array* (major type 4), positional, profile-restricted.** ATTESTABLE.

- **Why array not map:** a positional array has no keys, so the RFC 8949 §4.2.1-vs-§4.2.3 canonical key-ordering ambiguity (live in this repo as #1897) **cannot fire by construction**. This keeps CBOR precedent (v1 + 9 sibling `Signable*` types) while gaining fixed-TLV determinism.
- **Frozen value profile:** definite-length only; values ∈ `{ text (mt3) | uint (mt0) / nint (mt1), shortest-form | byte-string (mt2) }`. **Forbidden:** floats/simple (mt7), tags (mt6), indefinite-length, `null`, duplicate/ambiguous encodings.
- **Element 0 of every array is a domain/version tag** (`_dst`-style string prefix, e.g. `"ai-memory/write/v2"`), following the `SignableSuccession`/`LINEAGE_DOMAIN` precedent — the newest identity-critical surface already abandoned the in-map `_dst` key for an explicit leading domain prefix "because cross-protocol reinterpretation would be catastrophic."
- **Encoder obligation (from the refute lens):** the v2 encoder MUST be a **pinned, in-house, profile-enforcing** serializer — it MUST NOT delegate canonicalization to `ciborium`'s canonical mode (which `canonical_cbor_map` does today at HEAD, runtime-sorting keys). Frozen by a **golden input→hex test-vector corpus as a hard CI gate**. This is the R24 verifier's re-encode path.
- **v1 records** stay CBOR-map, retained verbatim; v1↔v2 never cross-verify (distinct domain tag).

---

## 2. SignableWrite v2 envelope (decisions 1, 2, 3 · `129ca73f` / `3cdc7834` / `289ea5e6`)

**Additive-versioned.** ATTESTABLE. The v1 six-field envelope is retained verbatim (zero legacy rewrite); v2 is a new domain-tagged array.

### 2.1 Record identity (decision 2, ADR #1943 — C dual-binding)
- **Signed identity = the cid-genesis content-identity.** The v2 array commits the `canonical_cid_preimage` six-tuple that v1 already signs: `agent_id, namespace, screen(title), memory_kind, created_at, SHA256(screen(content))`. `cid = b3(genesis)` is therefore the tamper-evident, receiver-recomputable, screen-mode-independent signed content-address. ATTESTABLE.
- **The envelope does NOT sign the `uuid`** (server-assigned, not signer-predictable in the #626 detached-signing flow). `uuid` remains the storage/FK/LWW-tiebreak authority (`crdt_merge.rs remote_wins_lww` on `(updated_at, attest_rank, id=uuid)`).
- **Disjoint frozen roles:** storage/convergence = `uuid` alone; signed content-identity = `cid` alone. Resolves the dual-truth hazard (each question has exactly one authority). **Deferred:** pure content-addressing (IPFS/Merkle) is a future breaking migration this envelope does not pre-buy.

### 2.2 v2 array element order (frozen positions)
```
[0]  _dst = "ai-memory/write/v2"          (domain+version discriminator, committed)
[1]  agent_id            (text)
[2]  namespace           (text)
[3]  screen(title)       (text; secret-screened per AI_MEMORY_SECRET_SCREEN_MODE, mode-independent)
[4]  memory_kind         (text; closed vocab — §6)
[5]  created_at          (text, RFC3339)
[6]  content_digest      (byte-string; self-describing MULTIHASH: <codec-varint><len-varint><digest>)
[7]  instance_key_id     (byte-string; root-certified per-instance sub-key id — §2.3)
[8]  model_version_ref   (byte-string; a b3: cid of the v78 model_attestation, or weights-hash/version-vector under continual learning)
[9]  session_id          (text; present-encoded, None≠empty)
[10] suite_tag           (int/text; committed-ADVISORY algorithm suite — §2.4)
```
*(Exact codec ints, varint widths, and the presence-encoding for optional elements are implementation-phase detail (`TBD-impl`); the FIELD SET, ORDER, and domain tag are frozen.)*

### 2.3 Instance sub-key certification (decision 1 · R2)
- Every write is signed by a **per-instance sub-key**, itself certified by the principal identity root via a **`SubkeyCert`** (own domain `"ai-memory/subkey-cert/v1"`, principal-root-signed, binding `principal + instance_key_id + model_version_ref + not_before/not_after`). ATTESTABLE.
- **Ingest order (mandatory):** verify `SubkeyCert` under the principal root → THEN verify the write under the sub-key. A self-declared instance stamp with no valid cert is **rejected at ingest** (satisfies R2 "certified, not self-declared"). Evaluate reuse of the federation credential-chain machinery.

### 2.4 Algorithm agility (decision 1 · R75)
- The `suite_tag` is committed **inside** the signed bytes (binds the suite; kills `alg:none`/downgrade at the encoding layer). **ATTESTABLE.**
- **Security invariant (binding):** the tag is **verification-ADVISORY, never a selector.** The enrolled key/epoch is the **sole authority** on the acceptable suite; the verifier pins suite→key and only cross-checks the wire tag. Dispatching the verification suite off the wire tag is the JWS `alg`-confusion forgery class — **banned.**
- Content digest is a self-describing multihash (§2.2 [6]) so a PQ/new hash binds by swapping the codec byte. **Per-record PQ signatures are forbidden** (arithmetically incompatible with endpoint budgets); PQ binds at **checkpoint granularity** via a re-anchor ceremony (§5.3).
- **Suite retirement, not just addition:** the epoch-manifest accepted-suite allowlist (RQ-10) MUST be enforced **fail-closed**, else a compromised legacy Ed25519 key is a forever-valid write path.

---

## 3. Identity lineage: custody + revocation (decision 4 · `da9eeb26` · R13)

Both ride the v76 `agent_lineage` chain (predecessor-signed, epoch-monotone, `signed_events`-witnessed) — **not** a new table/domain. ATTESTABLE (chain integrity) / ESTIMABLE (custody-class trust — see caveat).

- **`custody_class`** — a CLOSED named-const value set committed **inside** the predecessor-signed `SignableSuccession` bytes (never a bare crypto-unauthenticated column): `software-file` + RESERVED `{tpm2, pkcs11-hsm, secure-enclave, kms}`; `from_str` fail-closes on unknown.
  - ⚠️ **ESTIMABLE, not ATTESTABLE:** custody_class is **attested-by-OSS-refusal-and-custody-separation, NOT attested-by-hardware.** The OSS build structurally refuses to mint any non-`software-file` slug. It **MUST NOT be a cross-host trust input** — a peer never grants a `tpm2`-claiming key more authority than `software-file` — until a reserved inner hardware-attestation blob (TPM quote / PKCS#11 cert chain) lands (v1.0+/commercial). Local provenance marker + refuse-guard only.
- **Revocation** — a 4th `LineageReason::Revocation` on the same chain at epoch N+1; reuses `LINEAGE_DOMAIN`, the C1 witness anchor, C3 truncation-detection, the `(agent_id,epoch)` composite-PK anti-equivocation (C5), and the single `verify_lineage` walk.
  - **Ordering authority = the append-only `signed_events` witness high-water-mark SEQUENCE**, never attacker-suppliable wall-clock/`not_before` (the timestamp-horizon design was refuted as forgeable). ATTESTABLE.
  - `recovery_pubkey` flips Option→REQUIRED at genesis so the stolen-AND-lost-key case is coverable (recovery signs both fresh head + revocation); the full recovery VERIFY path stays v1.0-deferred, but the FORMAT ships now so v1.0 only adds a signer.
  - ⚠️ **Honest scope (ESTIMABLE / deferred enforcement):** revocation is **verdict-surface-only** (surfaced by `verify-audit-trail` like `LineageCheck`) until the epoch-aware multi-key **write-path** verifier lands as a separate non-T4 change — **no write-path teeth claimed this train.** Single-node only (cross-host propagation deferred). Past forgeries in `[suspected_compromise_from_seq, S_rev)` stay past-valid by construction (CRL/OCSP/SSH parity) — downgraded to a Suspect verdict, never cryptographically un-verified (R13 "past verified entries still verify").

---

## 4. Epistemic typing (decision 6 · `f4319a26` · R4)

Decoupled into three ship-speeds:

- **Vocab (ship now, additive):** add named consts `told` (received/hearsay, below Observation), `instruction` (received imperative — fixes the L1 operator-directive mis-stamp), `intervention` (enacted `do(X)` ground-truth, do-calculus complement of Observation). `memory_kind` has no CHECK on either backend → code-only vocab widen. These slugs are **signed genesis bytes** (§2.2 [4]) → **T4-frozen now.** ATTESTABLE (the value is in the signed bytes).
- **`kind_provenance` column (ship now, additive, v79):** `{declared, channel_derived, regex, llm}`, a clone of the `ConfidenceSource` precedent, **unsigned metadata** (not part of the envelope). Surfaced in recall so a consumer distinguishes caller-DECLARED from channel-DERIVED. ESTIMABLE (it records *how* the kind was assigned, not that the kind is true).
- **Default-flip (PHASED to v0.10.0 WARN → v0.11.0, #1972):** no channel manufactures `Observation` from caller silence; the silence sink becomes `Claim`. **Why phased:** `memory_kind` is folded into `cid_genesis` — flipping the untyped default silently changes the content-address and **breaks G8 cross-node cid-equivalence**, so it must ride the coordinated fleet-upgrade WARN cycle.
- **No-promote-without-lineage (R4d):** the silent write-time untyped→Observation IS the violation, fixed by the default-flip; also enforced at reflect/consolidate over the v75 lineage DAG.

---

## 5. Audit spine, rollback, and epoch anchoring (decisions 5, 8 · `aeb891a4` / `00d599ec`)

### 5.1 Rollback-evidence anchor (decision 5 · A1)
- **Net-new = an OPEN-TIME head check** (`db::open`) reusing the #1822 witness + off-table watermark comparison verbatim (nothing checks rollback at open today). ATTESTABLE (detects db-FILE-only rollback).
- Counter binds additively into `WitnessResolutionWire` v:1→v:2 as a present-only `rollback{value,source}` sub-object, witness-key-signed. Source-agnostic; OSS default = a witness-signed `head-anchor.log` on the `AI_MEMORY_WITNESS_KEY_DIR` mount; TPM2 NV reserved-when-present.
- **Disposition: configurable-both** — default flag-fork-emit-evidence (no self-DOS on legit DR); refuse-open in require-mode.
- ⚠️ **ESTIMABLE, honest limit:** in the OSS build A1 is **tamper-EVIDENCE, not tamper-PROOF.** An on-host file-counter rolls back in lockstep with a whole-host snapshot — zero resistance vs the imaged-disk attacker; genuine whole-host resistance needs TPM2 NV or an off-host anchor. Degrade to WITHHOLD/Unknown, never a false all-clear.
- **Sanctioned-restore ceremony:** `ai-memory audit restore-attest --sign` emits one append-only operator-signed event (`audit.restore_sanctioned`), signed with `AI_MEMORY_OPERATOR_PUBKEY` (custody-separate from daemon AND witness keys, never on DB-writable disk), committing `{old_head, new_head, gap, timestamp}`. The operator signature is the ONLY discriminator between sanctioned DR and attack rollback (at the byte level DR *is* a rollback). ATTESTABLE.

### 5.2 Equivocation proof + peer-head entanglement (decision 8 · R3/R22)
Three frozen byte shapes (format only; transport = #1936, runtime = FED-RQ-02/03):
- **`SignableHeadAttestation`** (`"ai-memory/peer-head-attestation-v1"`) — every proof is a *pair*; commits `{subject_agent_id, epoch, head_sequence, head_hash, signed_at, sig}`; domain tag inside the signed pre-image (mandatory — `SignableCheckpointResolution` excludes `condition_type`/`metadata`). ATTESTABLE.
- **`EquivocationProof`** (`"ai-memory/equivocation-proof/v1"`) — self-contained CBOR carrying both subject-signed head-attestations + the subject's 32-byte pubkey; **offline-verifiable by any third peer with zero shared state.** ATTESTABLE.
- **Entanglement record** — a free-text `ConditionType::PeerHeadEntanglement` resolved-checkpoint (no CHECK → zero migration); reserved namespace `_peer_head_entanglement` write-reserved (CI-pinned).
- **Divergence key = `(subject_id, epoch, head_sequence) → head_hash`, epoch drawn from the SIGNED v76 lineage succession (not self-declared)** — threads between the epoch-lie escape hatch (self-declared epoch voids the proof) and losing rotation-straddle detection. Ordering authority = the subject's own `signed_events` V-4 `prev_hash` chain.
- ⚠️ **Honest scope:** detection is a **LIVENESS** property (a permanently-partitioned Byzantine node is invisible until heal — the inherent equivocation lower bound); **SAFETY holds unconditionally** (no false eviction, no fork accepted-as-linear once observed). Eviction consults the v76 lineage chain (not the raw pubkey) so a stale proof after a legit genesis re-key can't self-evict; a stale epoch-key view returns INDETERMINATE (correct-failing).

### 5.3 PQ re-anchor ceremony (decision 1 · R75)
Current-strength algorithms countersign the entire prior chain head under a new suite at **checkpoint granularity**; pre-break records remain attributable; enabling stronger suites on a live corpus causes zero write failures and zero record rewrites. *(Ceremony record shape: `TBD-impl`; the checkpoint-granularity binding is frozen.)*

---

## 6. Read-path exclusion / quarantine (decision 7 · `560c8007` · R19/A3)

- **Quarantine = a system-only `LifecycleState::Quarantined`** on the v64 `lifecycle_state` column (raw-UPDATE only, absent from `can_transition_to`, `validate_lifecycle_state` rejects it as caller input → no self-exfiltration).
- **The exclusion is a fail-CLOSED ALLOW-LIST** — `lifecycle_state IN {open,active,blocked,done,abandoned}` / `is_recall_visible()` — NOT a deny-list, so unknown/future values fail closed. The storage funnel authors the exclusion; the reader is never trusted. ATTESTABLE. **This also closes a live bug** (Tombstoned is excluded by no SQL predicate today) via one shared `lifecycle_visible_clause()` on all ~6 read/egress lanes + a regression test per site.
- **Route in** (write-boundary only): provenance-less inbound federation-receive writes; opt-in/permissive by default (mirrors #94). Quarantine STORES the row (bytes converge); only the node-local view differs. **Route out:** dequarantine-on-attest + operator dequarantine. Honest caveat: a quarantined row doesn't relay onward (black-hole until dequarantine).
- **A3 dormant ingestion-event schema (frozen, no runtime):** a domain-separated (`"ingestion-v1"`) canonical-CBOR Ed25519 record — `{record-set Merkle-root, pre-checkpoint ref, post-checkpoint ref, instance_id, timestamp}` — reusing the §2 array grammar; quarantine structurally excluded from the record-set. Frozen because the first real event's bytes are a permanent obligation.

---

## 7. R24 verifier — what a clean-room reader must do (ATTESTABLE core)

A conforming sub-10kLOC dependency-free offline verifier, given only the artifacts + enrolled pubkeys, must:
1. **Re-encode** any v2 record via the pinned §1 array profile and check the Ed25519 signature (never decode-and-trust; re-encode-and-compare). Golden vectors (#1837) pin the bytes.
2. **Walk the V-4 chain** (`prev_hash + sequence`) and confirm tamper-evidence; detect middle-deletion (hash break) and, with the witness/watermark, tail-truncation.
3. **Verify the SubkeyCert→write chain** (§2.3): cert-under-root then write-under-subkey; reject self-declared instances.
4. **Pin suite→key** (§2.4): cross-check the advisory tag; never dispatch on it.
5. **Resolve lineage epoch** (§3, §5.2) from the signed succession for revocation windows and equivocation keys; return INDETERMINATE on a stale view (never a false accusation).
6. **Apply the fail-closed visibility allow-list** (§6) to any surfaced set.
7. **Verify an `EquivocationProof`** (§5.2) self-contained, offline, from the subject pubkey alone.

**Out of the frozen-verifier scope (deferred / ESTIMABLE):** capability caveat algebra (the capability layer stays additive), the epoch-aware write-path revocation enforcement, hardware custody attestation, whole-host rollback resistance, and vote-independence (permanently ESTIMABLE — the verifier sees signed bytes, never the generating process).

### 7.1 Read-path consumer-binding — DEFERRED post-v1.0 (ruling #1950 · `973f3056` · unanimous)

Write-path attestation (§2) + the shipped `recall_observations` ledger is the **frozen read-path boundary** for v1.0; **zero read-path bytes freeze now.** A future recall-attestation is a clean additive artifact (its own `"ai-memory/recall-attestation/v1"` domain tag; ephemeral/derived; consumes the already-frozen `cid` + SubkeyCert + content_digest), so retrofit is provably not a freeze break.
- ⚠️ **v1.0 read-path assurance is TELEMETRY strength, not proof.** `recall_observations` is unsigned, local-only, best-effort (7d TTL) — a compromised node can forge/omit its own rows. **Never claim consumer-binding/proof at v1.0.** ESTIMABLE.
- **Frozen design guardrails for the future envelope** (recorded now, no bytes): it SHALL anchor to `cid` (per-record, tamper-evident), never `recall_id` (per-event, stays unsigned telemetry); it SHOULD fold into the `signed_events` witness spine (present-only, v73 `cause_hash` precedent) to be drop-evident.
- **Honest ceiling:** the substrate can attest *what it returned*, never *what the caller did with it* (outside the substrate — same boundary as the record-stop actuator and vote-independence).

---

## 8. Migration summary

All decisions are **additive, both backends, no full-table rebuild** (heeding the v63/v65 lesson — a sqlite rebuild silently drops all triggers; recreate + test each). Two-speed where noted: vocab/format additions land at the target schema (≈v79/v80) as the coordinated crypto-core migration; default-VALUE flips (epistemic default, secure-default fed flips) ride the v0.10.0 WARN-carrier (#1972). The v1.0 wire freeze is declared only after every §1–§6 shape is landed + golden-vector-gated.

---

*Draft skeleton — authored 2026-07-09 in the Fable window. Freeze decisions are final (memories cited); byte-exact `TBD-impl` details resolve during implementation against these frozen shapes. This document + the golden-vector corpus (#1837) are the R24 conformance target. Ship-law escalation of any spec-axis amendment routes through the #1171 heterogeneous panel (#1967).*
