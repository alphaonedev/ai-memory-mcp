# W2-A6 — Federation & Distributed Verification Assessor

> **Agent:** W2-A6  
> **Lens:** Multi-endpoint ASI federation maturity (claimed vs attested inbound; authority≠data)  
> **Inputs:** `src/federation/receive_auth.rs`, `handlers/federation_receive.rs`, `handlers/federation_signing_check.rs`, `federation/push_dlq.rs`, `peer_attestation.rs`, `storage/mod.rs` (G30), ADR-0001, Wave1 `w1-a7-synthesis.md` (S2 / 2.5)  
> **Date:** 2026-07-08

---

## VERDICT

**PARTIAL — structural authority/data lane separation is real; default inbound CONTENT remains CLAIMED, not ATTESTED.** Federation is a **honest-peer W-of-N AP mesh** (local-first, eventual, LWW) with fail-closed envelope + enrollment + authority-lane transitions — **not** multi-endpoint ASI distributed verification. Under production defaults, a weaker observer can verify *which enrolled peer delivered a batch*, not *which agent authored the payload*, for data-lane memories/signals.

---

## CONFIDENCE

**0.86**

| Factor | Δ |
|---|---|
| Direct code for receive_auth flags + attribution + stamp_attestation | + |
| Secure defaults for envelope/enrollment/transition documented + tested | + |
| G30 tombstone + DLQ purge present on write funnel (`insert_if_newer`) | + |
| ADR-0001 honest non-BFT / non-Raft scope | + |
| ROADMAP G30 prose lag vs shipped code (stale claim risk only) | − |
| No multi-node ASI adversarial campaign re-run this session | − |

---

## SHIPPED (code-anchored)

### Envelope & peer identity (node-level)

| Control | Default | Anchor |
|---|---|---|
| Per-message Ed25519 `X-Memory-Sig` | **ON** (`AI_MEMORY_FED_REQUIRE_SIG`) | `federation_signing_check`, `signing.rs` |
| Nonce freshness (`X-Memory-Nonce`, body-bound) | **ON** (`AI_MEMORY_FED_REQUIRE_NONCE`) | nonce cache v51 + receive gate |
| Peer enrollment for `X-Peer-Id` | **ON** (#1789) | `require_peer_enrollment_enabled` |
| Unenrolled escape | **OFF** (`FED_ALLOW_UNENROLLED_PEERS`) | same module |
| mTLS client-cert pin + optional outbound peer fingerprints | opt-in / deploy | `tls.rs`, `FED_PEER_FINGERPRINTS` |
| CA credential chain + trust bundle + renewal | opt-in enterprise path | `federation/identity/*` |

### Authority-lane ≠ data-lane (S2 — structural)

| Lane | Knob | Default | Behavior |
|---|---|---|---|
| **Authority** — action transitions | `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` | **ON** | `authorize_remote_transition`: unsigned/unenrolled reject; forged **unconditional** reject; lease-holder conflict local |
| **Data** — memory content | `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | **OFF** | unsigned third-party → `attest_level=claimed`; optional strict third-party-only |
| **Data** — signals | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | **OFF** | Layer-1 allowlist when enrolled; Layer-2 enrolled-key verify opt-in; skip not batch-abort |
| **Authorship** | `resolve_inbound_attribution` | allowlist-gated | self-relay trusted; unauthorized third-party **re-attributed** to sender + claimed |
| **Pending actions** | `pending_author_authorized` (#1920) | allowlist when enrolled | authority-adjacent request gate |

Forged signatures rejected on all lanes independent of knobs. Wire `signer_pubkey` / `sender_pubkey` **not** trusted for authority checks — enrolled key only.

### Replication / durability (ADR-0001)

- **W-of-N** fanout on HTTP daemon writes; local commit first, **never rollback** on quorum miss.
- Quorum miss → **`202 Accepted`** + `{quorum_met:false, durability:"local"}` (G12; not false 503).
- Reads **eventual** (local replica); catchup loop + vector-clock watermarks.
- **Push DLQ** (#933): enqueue on fanout fail; adaptive batch replay; quarantine after max attempts; edge-triggered depth WARN; cause-labeled counters; 429 throttle un-quarantine.
- **MCP stdio / CLI do not fan out** — only `serve` is a federation node (`federation/mod.rs`).
- Merge: `insert_if_newer` LWW + id tiebreak (CRDT-lite, not full CRDT).
- Embed-once ship vectors (#1566) so receive ack not blocked by re-embed.

### Erasure / anti-resurrection (G30 class — largely shipped)

- `forget_tombstones` (schema v71); identity+time (+ optional owner sig), **no content fingerprint**.
- Same-tx **DLQ + transcript_line_dedup purge** on forget.
- **Resurrection guard** in `insert_if_newer` (all federation merges).
- `restores[]` path tombstone no-op (#1848).
- Secret screen: federation always **redact not refuse** (capture-first, anti-divergence).

### Explicit non-goals (honest)

- **No Byzantine tolerance** (`docs/SECURITY.md`, ADR-0001).
- **No Raft/Paxos**, no strong-consistency reads, no split-brain healing beyond “both sides stop when N&lt;W”.
- Chaos: 2/4 classes real inject, 2 simulated (ADR honesty).

---

## GAPS — claimed vs attested inbound

### Under defaults (operator unset)

| Inbound artifact | What is attested? | What is claimed? |
|---|---|---|
| `/sync/push` envelope | Peer node (sig+nonce+enrollment) | — |
| Memory row `metadata.agent_id` | Only if self-relay **or** allowlisted third-party + **opt-in** write_sig | Third-party author without `FED_REQUIRE_WRITE_SIG` / without content sig → **claimed** |
| `attest_level` | Upgraded only after enrolled-key content verify | Peer-asserted level **overridden** only on honor path; else claimed |
| Signal `from_agent` | Layer-1 allowlist when enrolled; Layer-2 off by default | Zero-config mesh: faith-based |
| Transition `claimed_by` | Enrolled key + default require | N/A (fail-closed) |

**Wave1 S2 status:** architecture **held** (different knobs/defaults). **Attested multi-author mesh under defaults: NOT held.** Local store-path flipped `REQUIRE_AGENT_ATTESTATION=true` (#1751); federation **deliberately** did not flip write_sig — heterogeneous mesh / self-DOS rationale. Consequence for ASI multi-endpoint: **distributed verification of cognitive authorship is policy-opt-in, not floor.**

### Remaining structural gaps (v1.0 / multi-endpoint ASI)

1. **Honest-peer assumption** — compromised enrolled peer can inject **claimed** data rows (and self-authored content without write_sig). Authority lane is harder; data lane is the soft underbelly.
2. **mTLS cert ↛ `x-peer-id` crypto bind** — documented weak link in `peer_attestation.rs` (operator runbook glue).
3. **No full CRDT** — LWW only; concurrent edit semantics thin; GOAL-EPIC PN-Counter/OR-Set net-new.
4. **FED-RQ-02/03** federated epoch manifest + cross-node `policy_version` gate — **v1.0** (ROADMAP §25.3); epoch-level multi-endpoint law not transport-complete.
5. **E2E encryption** of federation push/pull — roadmap later; content visible to any enrolled peer (trust-all-peers for ciphertext).
6. **Cross-mesh lease auth** incomplete (`receive_auth` best-effort local lease only).
7. **Identity lineage invisible cross-host** — peers use `lookup_peer_public_key`, not succession chain.
8. **MCP/CLI not federation endpoints** — multi-surface identity ≠ multi-endpoint mesh membership.
9. **BFT / adversarial ASI mesh** — out of scope forever under current ADR; multi-endpoint *hostile* ASI is not a security model.
10. **Chaos maturity** — no published ≥0.995 campaign treated as continuous gate in this assessment.

---

## SCORE — federation maturity (0–1)

| Dimension | Score | Notes |
|---|---:|---|
| **S2 Authority≠data lanes** | **0.82** | Transitions fail-closed; data accept-and-flag; forged unconditional — correct ontology |
| **Envelope / enrollment / replay** | **0.80** | Secure defaults ON; escapes explicit |
| **Durability mesh (ADR-0001 W-of-N + DLQ)** | **0.72** | Local-first solid; 202 honesty; DLQ operable; not consensus |
| **Inbound content attestation (defaults)** | **0.42** | Claimed floor; upgrade path exists but opt-in |
| **Erasure / tombstone anti-LWW** | **0.78** | G30 class largely closed in funnel |
| **Multi-endpoint ASI verification (hostile)** | **0.22** | Non-BFT + claimed data = insufficient |
| **v1.0 federation goals (epoch, E2E, E2E test)** | **0.35** | FED-RQ-02/03/AGG + F-53 open |

### Composite (equal weight of first six; v1.0 separate)

**Federation maturity (shipped mesh): 0.63**  
**Federation maturity (multi-endpoint ASI verification claim): 0.38**

Do **not** market a single vanity “federation complete” number.

---

## KILLER_OBJECTION

**Calling default federation “distributed verification of cognitive operations” is security theater:** envelope attestation proves *which peer relayed*, while memory/signal **authorship stays CLAIMED** unless operators opt into write/signal sigs *and* enroll every author key. An enrolled compromised peer (or zero-config faith mesh) can launder third-party cognitive state into durable multi-endpoint memory without content non-repudiation — exactly the S2 hole Wave1 forbade conflating with 2.5.

---

## TOP_RISK

**Default data-lane claim inflation:** operators see enrollment + `FED_REQUIRE_SIG=1` and assume per-agent non-repudiation across the mesh; audits of `attest_level=claimed` rows are sparse; ASI multi-endpoint “verify stronger peers without trusting them” fails on the common path.

Secondary: **honest-peer ADR** silently frames compromised peer as out-of-scope while multi-endpoint ASI *is* the compromise model.

---

## VOTE — readiness for v1.0 federation maturity goals

| Motion | Vote |
|---|---|
| Ship as **honest-peer W-of-N knowledge mesh** (ops durability) | **YES** (with ADR caveats) |
| Claim **v1.0 federation maturity** (ROADMAP §11.6 / §25.3 FED-RQ-02/03/AGG + E2E) | **NO** |
| Claim **multi-endpoint ASI distributed verification** under defaults | **NO** |
| Claim **S2 authority≠data held as architecture** | **YES** |
| Claim **inbound content ATTESTED by default** | **NO** (policy gap, intentional) |
| Gate v1.0 on flipping `FED_REQUIRE_WRITE_SIG` default ON | **CONDITIONAL** — only with mesh-wide emit + enrollment readiness (self-DOS risk) |

**Readiness tally:** **2 YES / 3 NO / 1 CONDITIONAL** → **NOT READY** for v1.0 federation maturity goals as stated; **READY** for documented honest-peer AP mesh.

---

## RATIONALE

Wave1 frozen ontology requires **2.5 operation attestation** and **S2 authority≠data**. Code delivers S2 cleanly: `receive_auth` separates fail-closed transitions from permissive data/signal knobs; attribution rewrites unauthorized third-party claims; forgery never accepted. That is the right *shape* for multi-endpoint governance.

What multi-endpoint ASI actually needs next is not more envelope crypto — it is **floor-level content non-repudiation on data lane** (or an honest public claim that mesh replication is peer-faith data, not author-attested cognition), plus **FED-RQ epoch law across nodes**, plus explicit refusal of BFT marketing. ADR-0001 + SECURITY.md already refuse BFT; the residual failure mode is **claim language**, not missing Raft.

G30/DLQ/tombstone work shows the project can close resurrection and durability gaps when they are structural defects. The analogous defect for ASI is: **`attest_level` distribution under defaults remains mostly claimed across the mesh.** Until write-sig emit is universal *or* product claims narrow to “peer-attested transport, author-claimed content,” federation maturity for multi-endpoint ASI stays **partial**.

**Distance-to-ontology mapping:** S2 ≈ 0.82 held · 2.5 federation half ≈ 0.45 · infinity multi-impl/BFT ≈ 0.2 · durability subscore high enough for endpoint mesh ops.

---

*End W2-A6. Under 350 lines. Absolute paths reviewed under `/Users/fate/Downloads/ai-memory-mcp/src/federation/` and handlers as cited.*
