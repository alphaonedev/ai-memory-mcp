---
layout: doc
---
# ADR-002 — FED-RQ-02 equivocation runtime + epoch-manifest-doc federation deferred to v1.x

Status: **ACCEPTED**

Date: 2026-07-13
Author: Claude Opus 4.8 on behalf of @alphaonedev
Decision record: ai-memory memory `5a999226-6b5f-439e-ba64-6365908b6256`
(#1947 RATIFIED MINIMAL scope, 5-agent adversarial vote `wd8wtmg0n` —
`A_MINIMAL` 9/10; crossroads policy `4d3ea1c5`).
Related: #1947 (this ADR + FED-RQ-03), #1936 (FED-RQ-01 checkpoint
federation transport), #1878 (`epoch-apply` verify-only consumer),
#1990 (postgres verbatim checkpoint-apply parity), #1828 (v76 identity
lineage), crossroads-vote policy `4d3ea1c5`.
Spec SSOT: `docs/attestation.md` §"Equivocation proofs + peer-head
entanglement"; C8 floor `docs/v1.0.0/perfect-endpoint-assessment/waves/w7-a2-v1-epic-dag.md:383`.

---

## Context

The v1.0.0 federation-floor gate is **C8**
(`docs/v1.0.0/perfect-endpoint-assessment/waves/w7-a2-v1-epic-dag.md:383`):

> **C8** — Federation floor: FED-RQ-02/03 green **or** ADR-deferred with no
> "federation mature" claim.

Three federation requirements bound the floor:

- **FED-RQ-01 (#1936)** — resolved commit-checkpoint federation over
  `/sync/push`, fail-closed per-resolution attestation. **Shipped.**
- **FED-RQ-03 (#1947)** — cross-node governance `policy_version`
  REFUSE-STALE gate. **Shipped in this same PR** (receive-path refusal of a
  push governed by a policy strictly behind the receiver's committed
  governance policy; typed `409 stale_policy_version`; fail-open on absent /
  undeterminable; env opt-out `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`).
- **FED-RQ-02** — the equivocation-detection **runtime**: peer-head
  recording, cross-view detection, proof assembly, `PeerHeadEntanglement`
  checkpoint bookkeeping, and auto-eviction of a detected equivocator.

What already exists for FED-RQ-02 is the **wire FORMAT + the offline
verifier ONLY** — `SignableHeadAttestation`, `EquivocationProof`, and the
clean-room `verify` (`src/identity/equivocation.rs`, frozen golden
byte-vectors). The RUNTIME that would *produce, transport, detect, and act
on* those proofs is not built. Also unbuilt is **epoch-manifest-DOC
federation** — the signed `SignableEpochManifest` (which carries the
authoritative attested `(policy_seq, policy_digest_hex)`) does not ride the
wire; only the `EpochAdvance` checkpoint's `content_hash` federates today.

C8 permits either "FED-RQ-02/03 green" **or** "ADR-deferred with no
'federation mature' claim". FED-RQ-03 is green; FED-RQ-02 is deferred here.

## Decision

**Defer the entire FED-RQ-02 equivocation RUNTIME and epoch-manifest-DOC
federation to v1.x.** Ship only the already-frozen FORMAT + offline verifier
(unchanged) plus the FED-RQ-03 policy-refuse-stale gate.

Deferred, explicitly NOT built at v1.0.0:

- peer-head recording + cross-view equivocation **detection**;
- `EquivocationProof` **assembly** on a live substrate + its **transport**
  between peers;
- `PeerHeadEntanglement` checkpoint bookkeeping;
- **auto-eviction** of a detected equivocator;
- **epoch-manifest-DOC federation** (putting the signed
  `SignableEpochManifest` `(policy_seq, policy_digest_hex)` on the wire so a
  receiver learns a peer's **attested** governance epoch). FED-RQ-03 today
  gates on a minimal ADDITIVE **unsigned** `sender_policy_seq` wire field —
  enough to refuse an HONEST stale peer that advertises; the **attested**
  advertising (and full send-side emission) rides this deferred manifest
  federation.

### The permitted claims (and the banned ones)

**BANNED** in release notes, CHANGELOG, docs, marketing, and agent reports
until FED-RQ-02 **and** FED-RQ-03 are both green with the runtime landed:

- "federation mature" / "federation is mature";
- "equivocation shipped" / "equivocation enforced" / "equivocation
  detection live";
- "eviction shipped" / "auto-eviction live" / "Byzantine node eviction".

**PERMITTED** (the narrow, truthful claims only):

- the equivocation wire **FORMAT** (`SignableHeadAttestation`,
  `EquivocationProof`) + the **offline verifier** are **frozen with a
  permanent back-compat guarantee** (golden byte-vectors in
  `src/identity/equivocation.rs`);
- runtime **detection / eviction is DEFERRED** to v1.x;
- operators can detect equivocation **OUT-OF-BAND** today using the shipped
  offline verifier (feed it two conflicting signed head attestations
  gathered manually);
- FED-RQ-01 checkpoint federation is **live**; FED-RQ-03 policy
  **REFUSE-STALE** is **live**.

## Consequences

- **SAFETY holds UNCONDITIONALLY; only LIVENESS-detection defers.** Per
  `docs/attestation.md:584-591`: detection is a **LIVENESS** property — a
  permanently-partitioned Byzantine node that never lets one verifier see
  both of its stories stays invisible until the views heal (the inherent
  equivocation lower bound). What holds unconditionally is **SAFETY**: a
  well-formed `EquivocationProof` is a genuine two-signature contradiction,
  so the offline verifier **never falsely accuses** and **never accepts a
  fork as linear** once it has observed one. Deferring the runtime removes
  no safety property that the shipped format+verifier provide; it only
  postpones the *automatic liveness* of catching an equivocator on-line.
- **C8 is satisfied by the OR-branch:** FED-RQ-03 green **and** FED-RQ-02
  ADR-deferred, with the "federation mature" / "equivocation shipped" claims
  banned above.
- **#1990 is a HARD pg-parity PREREQUISITE** for whichever v1.x issue picks
  up the deferred checkpoint-federating work. FED-RQ-02's proof transport
  (and any epoch-manifest-doc federation that lands a resolved checkpoint on
  a postgres receiver) needs `apply_remote_checkpoint_resolution` /
  postgres **verbatim checkpoint-apply** to exist on the `MemoryStore`
  trait; today the postgres funnel reports inbound checkpoints as
  `unsupported_on_postgres` (honest count, never a silent drop). FED-RQ-03,
  by deliberate design, is a **receive-path refusal that touches NO
  checkpoint-apply path**, so it is postgres-clean and independent of #1990
  — the deferred work is not.
- **Zero cutover.** The frozen format + offline verifier are untouched
  (golden vectors unchanged); FED-RQ-03 adds one additive, backward-
  compatible wire field (`sender_policy_seq`, `#[serde(default)]`) and a
  receive-path gate that is fail-open on absence, so pre-#1947 peers are
  byte-identical.
- **The receive gate ships ACTIVE-but-INERT between stock daemons (honest
  status).** The gate is wired, typed, tested, and backend-identical, but
  **no stock daemon yet advertises `sender_policy_seq`**, so between two
  unmodified nodes the fail-open-on-absence rule means the live T3 refusal
  ("silent authority-under-old-rules") is **not exercised** until send-side
  advertising lands. Send-side emission is deferred WITH the attested-manifest
  work (not merely for convenience) because **no clean ≤3-site outbound
  chokepoint exists**: there are **13 distinct `SyncPushBody` builders**
  across the `broadcast_*_quorum` family + the catch-up push
  (`src/federation/sync.rs`), `FederationConfig` carries **no db/governance
  handle** (and `FederationConfig::build` is a boot-time constructor with no
  governance connection in scope), and the async broadcasters hold no lock —
  so a *live* (footgun-free) `current_policy_version()` read would require
  either an `app.db` async lock on the **hot replication fanout** at all 13
  sites, or a process-global seq counter bumped after every
  `append_policy_advance` **commit** (which is `no_tx`, so the commit — and
  thus a correct post-commit bump — lives in each *caller*: `remove_signed`,
  `set_enabled_signed`, CLI `rules add --sign`, re-scattering the change).
  Both exceed the A_MINIMAL blast radius and belong with the attested
  advertising below. A boot **snapshot** was rejected outright: it goes stale
  on a post-boot policy advance and would make a node **self-refuse** at
  peers once it advances its own policy.
- **The unsigned field is peer-spoofable — by design, and only in the
  permissive direction.** `sender_policy_seq` is not signed, so a malicious
  peer can forge a **higher** seq to EVADE the gate (claim currency it does
  not hold). It has no incentive to forge a **lower** seq (self-refusal), so
  the gate reliably catches an **HONEST** stale peer today. The
  attack-resistant form is the **signed `SignableEpochManifest`**
  `(policy_seq, policy_digest_hex)` binding (the epoch-manifest-doc
  federation deferred above): that is the only version that resists a peer
  lying about its governance epoch, and it is the correct home for the
  send-side advertising.

## Alternatives rejected

- **A — build the FED-RQ-02 runtime for v1.0.0.** Rejected by the
  `wd8wtmg0n` vote (`A_MINIMAL` 9/10): the detection + proof-transport +
  eviction runtime is a large, hard-to-reverse on-wire + on-disk surface
  (peer-head bookkeeping, `PeerHeadEntanglement` checkpoints, eviction
  policy) whose safety benefit over the shipped SAFETY guarantee is only
  *automatic liveness*, and whose correct postgres parity is blocked on
  #1990. Shipping it under GA time pressure risks freezing a wire/format
  obligation before it is proven — exactly what the ADR/format-freeze
  discipline exists to prevent.
- **B — federate the signed epoch-manifest doc now (attested
  `policy_seq`).** Rejected as out-of-minimal-scope: it re-opens the
  manifest wire shape (T4 hard-to-reverse representation) and couples the
  FED-RQ-03 gate to the deferred checkpoint-federation + #1990 pg parity.
  The minimal unsigned `sender_policy_seq` field refuses an HONEST stale
  peer today; the attested path is the natural home for this manifest
  federation when the runtime lands.

---

*C8 is met via the OR-branch: FED-RQ-03 (policy refuse-stale) is green and
the FED-RQ-02 equivocation RUNTIME + epoch-manifest-doc federation are
ADR-deferred to v1.x. The equivocation FORMAT + offline verifier stay frozen
(permanent back-compat); SAFETY holds unconditionally and only
liveness-detection defers. No "federation mature" / "equivocation shipped"
claim is permitted until both requirements are green with the runtime
landed.*
