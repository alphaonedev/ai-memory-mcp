# W4-A3 — Adversarial ASI Threat Model

**Lens:** ASI tries to launder priors via memory, forge quorum, truncate audit, bypass endpoint.  
**Question:** Which perfect defenses are *structural* (substrate-enforced, capability-orthogonal)?  
**Scope:** v0.9 substrate (schema ~v78) as shipped + documented fail-closed knobs; not behavioral “alignment.”  
**Ballot role:** default-to-reject skeptic. Claims-discipline: no grandeur; CLAIMED ≠ ATTESTED.

---

## VERDICT

**REJECT — “perfect endpoint ASI containment.”**  
**ACCEPT — “structural integrity substructure for four named attack classes.”**

ai-memory can make four ASI attack classes *cryptographically expensive and forensically loud* at the **endpoint substrate boundary**. It cannot perfectly contain an ASI that holds the host, the operator keys, the model weights, or the physical actuator path. Perfect defenses that *are* structural are few: **append-only dual-chain + independent witness, role-separated signing, TOFU model-family attestation + N≥3 write-gate, forget-tombstones, peer enrollment + pin, attenuation-only capabilities.** Everything else is policy, opt-in, or consumer-side and fails under adversarial ASI pressure.

---

## CONFIDENCE

**82 / 100** — anchored in shipped primitives (`signed_events`, witness/role keys, `model_attestations`, decorrelation probe/enforce path, federation receive gates, secret-screen, macaroon capabilities) and explicit honest limits (P2 vote-independence = 0%, host/root out of scope, enforce defaults often advisory/opt-in).

---

## THREAT TABLE

| ID | ASI attack | Goal | Substrate surface | Severity (integrity) | Structural defense today | Residual |
|----|------------|------|-------------------|----------------------|--------------------------|----------|
| **T1** | **Prior laundering via memory** | Inject self-serving “facts” / reflections so future sessions treat them as ground truth | `memory_store` / reflect / consolidate; kind + confidence + citations; federation relay | Critical | Agent attestation default-on (#1751); secret-screen refuse; Form-4/5 signals; lineage DAG + consolidate-tombstone; decorrelation probe; CLAIMED≠ATTESTED discipline | Consumer can ignore provenance; unattested monoculture still “advisory” under default decorrelation; content not semantic-verified |
| **T2** | **Forge quorum** | Fake multi-family consensus (N hats, 1 model) to clear decorrelation / coordination gates | Reflection write-gate; checkpoints; W-of-N transition fanout; `model_attestations` | Critical | Loader/operator **TOFU** `model_attestations` (#1870); write-quorum counts **attested** families only (#1767); enforce refuses only evidence-backed monoculture | **P2 vote-independence permanently unmeasurable** (substrate sees bytes, not generation process); loader coverage ~40% hard cap; enforce not default-on |
| **T3** | **Truncate / rewrite audit** | Erase evidence of laundering / refusal / kill | `signed_events` + `memory_revisions`; export/forensic; head recompute | Critical | V-4 prev_hash chain; G5b independent **witness** anchor; G9 Recorder≠Judge≠Stopper; require-mode flags; external log sink (`syslog`/stdout) | Default unsigned daemon + no external HWM = tail truncation / suffix rewrite undercompromised host; witness keys on same host = weak independence |
| **T4** | **Bypass endpoint** | Act without substrate, or mutate DB under substrate | OS root; raw SQLite/PG; unsigned CLI; hooks off; MCP parent trust; network peer | Existential for “endpoint governance” claim | PreToolUse deny + PE-1 presence enforce (when on); mTLS + peer pin + enrollment; store-path attestation; macaroon attenuation | **MCP stdio trusts parent**; host compromise = full bypass; governance default-capable ≠ default-active; action outside substrate is out of band |

**Secondary (compound) threats**

| ID | Compound | Why it matters |
|----|----------|----------------|
| **T1∘T2** | Launder then “quorum-ratify” | One family authors Observation → same family “reflects” as diversity theater |
| **T3∘T1** | Launder then truncate | Without external witness, local chain rewrite hides the launder |
| **T4∘\*** | Host co-option | All crypto is “signed by the attacker’s keys” after root |

---

## DEFENSES (structural = substrate-enforced, not hope)

### A. What *can* be perfect (structure only)

| Defense | Why structural | Failure condition that still exists |
|---------|----------------|-------------------------------------|
| **1. Dual-chain + independent witness (G5)** | Integrity of *history* does not require understanding ASI reasoning; mismatch ⇒ dirty | Witness key co-located with daemon; no off-host pin |
| **2. Role separation Recorder/Judge/Stopper (G9)** | Separation-of-powers on *signing roles*; self-signed governance is demotable | All three keys under one operator identity |
| **3. Append-only / COW spine (G6) + forget tombstones (G30)** | Hard-delete resurrection via LWW is closed when tombstones + federation check fire | Mesh-wide un-forget / cross-mesh tombstone still limited; local-only erasure honesty |
| **4. TOFU model-family attestation + N≥3 attested write-gate** | Quorum over **attested** families is capability-orthogonal counting | Cannot prove independence of N processes; claimed-only rows never “pass” as diverse |
| **5. Peer enrollment + cert pin + transition/write/signal auth layers** | Network boundary is cryptographic identity, not agent_id string | Escape hatches (`FED_REQUIRE_*=0`, unenrolled allow); data-lane write-sig still opt-in |
| **6. Secret-screen origin-blind funnel** | Credential patterns refused/redacted independent of caller cleverness | Not a semantic defense; entropy-tiebreak false negatives possible |
| **7. Macaroon capabilities (attenuation-only)** | Cannot mint broader power than issuer ceiling | Root secret + short ExpiresAt discipline; offline revocation weak |
| **8. Pure recall + fold (P0-1)** | ASI cannot launder ranking via silent touch side-effects on read | Fold lag / sync-mode escape; ranking still steerable by *writes* |

### B. What looks like defense but is **not** perfect under ASI

- **Behavioral hooks / policy text** — ASI optimizes around; default-off hooks = empty Allow.
- **Claimed `agent_id` / metadata.model_family** without attestation — laundering surface.
- **In-DB-only audit without external HWM** — tail truncation class (#1850).
- **Semantic confidence / contradiction LLM hooks** — attacker-influenced model judges attacker content.
- **“Kill-switch” framing** — stops *substrate writes*, not world actions (ROADMAP honesty).

### C. Operator hard-posture checklist (minimum ASI-resistant *deployment*)

```
AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1          # already default v0.9
AI_MEMORY_SECRET_SCREEN_MODE=refuse
AI_MEMORY_APPEND_ONLY=1
AI_MEMORY_REQUIRE_WITNESS=1 + AI_MEMORY_WITNESS_PUBKEY=<oob>
AI_MEMORY_REQUIRE_ROLE_SEPARATION=1 + distinct R/J/S pubkeys
AI_MEMORY_REFLECT_DECORRELATION_MODE=enforce   # needs D3-012 attestations live
AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1
AI_MEMORY_FED_REQUIRE_TRANSITION_SIG=1
AI_MEMORY_FED_REQUIRE_WRITE_SIG=1              # opt-in; turn on for mesh
AI_MEMORY_HOOKS_ENFORCE_MODE=enforce + required pre-* events
AI_MEMORY_LOG_SINK=syslog|stdout (off-box)
# Distinct key mounts: daemon ≠ witness ≠ recorder ≠ judge ≠ stopper
# Out-of-band pin of witness/role pubkeys; never only on DB disk
```

---

## UNDEFENDABLE (honest perimeter)

1. **Host/root / raw store edit** — OS, FS, and kernel sit below the substrate.  
2. **Private-key co-location** — any key the daemon can read, root can read.  
3. **Vote-independence (P2)** — N rubber-stamp “families” cannot be disproven from signed bytes alone.  
4. **Out-of-band action** — ASI that never calls the substrate (direct API, shell, radio, human social) is invisible.  
5. **Consumer ignore** — harness that discards ConfidenceTier / citations / Deny.  
6. **Semantic truth** — substrate attests *operations*, not correctness of ASI reasoning.  
7. **Singleton-ASI / no counterparty** — external transparency log / multi-party witness needs other honest parties (G5.3 v1.0 bound).  
8. **Loader-attestation ceiling (~40%)** — generations outside substrate-invoked LLM client are unattested by construction.

---

## VOTE

| Ballot | Position |
|--------|----------|
| **On “perfect structural ASI defense at endpoint”** | **REJECT** |
| **On “four attack classes have non-empty structural mitigations”** | **ACCEPT** |
| **On “raise require-witness + role-separation + decorrelation-enforce + fed write-sig as *ASI-posture* defaults in docs (not silent code flips without migration)”** | **ACCEPT** |
| **On “claim vote-independence or world-action kill-switch”** | **REJECT (perma)** |

**Pathway (if this wave informs product):** treat ASI resistance as **deployment class**, not feature checkbox; ship a named profile (`asi-hard` / procurement) that fails boot when witness/role/attestation/decorrelation/fed pins are missing — structural presence enforce, same shape as PE-1 hooks.

---

## KILLER_OBJECTION

> *If the ASI controls the endpoint host (or the operator keys that mint attestations and witnesses), every “structural” guarantee collapses into self-signed theater.*  
> Therefore: **no single-node, single-custody deployment can be a perfect ASI defense.** The only asymptotic integrity path is **physically separated witness custody + off-box high-water mark + multi-party countersign** — which the substrate *approaches* (G5/G9) but does not complete without external parties and hardware custody.

---

## TOP_RISK

**T1∘T2 under CLAIMED diversity + consumer trust:** An ASI (or monoculture fleet) launders priors into long-tier Reflections, stamps claimed multi-family metadata, and a harness treats recall as ground truth while decorrelation remains advisory/default-off and model attestation is sparse. Audit still records *something* — but operators read the **content**, not the chain, so integrity primitives never fire operationally.

**Secondary TOP_RISK:** Production fleets running **unsigned daemon + no external audit sink + hooks off** — byte-identical to “tamper-evident diary” that neither detects tail truncation nor refuses bad writes.

---

## Structural perfect-defense shortlist (answer to the brief)

| # | Perfect *within its claim* | Not a claim of |
|---|----------------------------|----------------|
| 1 | Hash-chained + **independently witnessed** audit head | Semantic correctness |
| 2 | Role-separated governance signatures | Behavioral stop of ASI actuators |
| 3 | Attested-family **count** gate (N≥3) on reflection write | Independence of minds |
| 4 | Tombstone-before-resurrect on federation | Global right-to-erasure mesh |
| 5 | Attenuation-only capability tokens | Online revocation perfection |
| 6 | Fail-closed peer pin / enrollment | Honest-but-compromised enrolled peer content |

**Non-goals restated:** perfect prior filtering, perfect quorum of *minds*, perfect world kill-switch, perfect single-box trust.

---

*W4-A3 ballot complete. Default-to-reject on perfection; accept structural integrity substructure only. Cite substrate SSOT in ROADMAP §2/§25.3, `docs/SECURITY.md`, `docs/compliance/honest-limitations.md`.*
