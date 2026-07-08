# W7-A4 — Perfect-System Target Architecture (Final Design)

> **Agent:** W7-A4 (Perfect-system architecture)  
> **Date:** 2026-07-08  
> **Lens:** End-state architecture — what the *perfect* endpoint cognitive-governance substrate **is**, as a design target  
> **Binds (do not re-argue):**  
> - W1 ontology (seven properties + S1–S5)  
> - W2 distance radar (held-fraction under defaults)  
> - W3 category ban on “perfect memory” · v1.0 ≠ perfect-system · L1/L2 contracts IN · RQGM OUT  
> - W4 security scorecard · fail-closed ladder · dual-plane erasure  
> **Canonical sources:** `ROADMAP.md` §0–§6 · §13 · §25 · §26 · `docs/design/TRACT-the-definitive-endpoint-ai-memory.md` · `docs/strategy/moonshot-synthesis.md` · waves `w3-a4` / `w3-a7` / `w4-a7`

---

## 0. Naming discipline (read first)

| Phrase | Meaning in this document |
|---|---|
| **Perfect system** | The **design target** — full TRACT constitution + moonshot seven properties held *by architecture*, under defaults, with L1/L2/L3 separation-of-powers. **Not** a product brand. **Not** v1.0. |
| **v1.0 contract freeze** | Audited governance-substrate floor (W3-A5/A7). Necessary rung; **incomplete** perfect system. |
| **TRACT-2026** | Named L3-BODY **Reference Profile** (SQLite/HNSW/FTS + current surfaces) that *ships as* L0/L1 conformance vectors — swappable later without forking meaning. |
| **Category** | **Endpoint-resident cognitive governance substrate** (attested, stoppable, federated, bias-displaced under attested N≥3). **Banned brand:** “perfect endpoint AI memory” (W3-A6). |

**One-line target:**

> A deliberately under-intelligent continuity organ that lets any mind remain itself across time by holding a content-addressed, provenance-bound, owner-governed, forgettable, tiered record of attested claims — attesting *process*, never adjudicating *truth* — with separation-of-powers so the verifier is never the player.

---

## 1. Two L-stacks (do not collapse)

The perfect system uses **two orthogonal L-axes**. Conflating them is the #1 design failure mode.

| Axis | Levels | Question answered |
|---|---|---|
| **A · Separation-of-powers (RQ / moonshot)** | L1 substrate · L2 curator · L3 RQGM sibling | Who may *persist*, *freeze*, *optimize*? |
| **B · Altitude / durability (TRACT)** | L0 constitution · L1 eternal core · L2 mechanics · L3 periphery | What is *frozen forever* vs *replaceable silicon*? |

```mermaid
flowchart TB
  subgraph POW["Axis A — Separation of powers (grep-provable one-way)"]
    L3A["L3 EXTERNAL<br/>ai-memory-rqgm sibling<br/>search · panel breeding · adversarial objectives"]
    L2A["L2 IN-REPO<br/>curator · verify-only epoch consumer<br/>decorrelation every cycle"]
    L1A["L1 IN-REPO<br/>persist · attest · refuse · pure recall<br/>RuleEngine · V-4 · federation"]
    L3A -->|"UNSIGNED draft manifest"| OP["Operator Ed25519"]
    OP -->|"signed epoch artifact"| L2A
    L2A -->|"SAL / hooks · EpochAdvance · V-4 bind"| L1A
    L3A -.->|"READ-ONLY aggregate export"| L1A
  end

  subgraph ALT["Axis B — TRACT altitudes (truth flows downward only)"]
    L0B["L0 CONSTITUTION<br/>anchor · Claim grammar · six verbs · Scope Test"]
    L1B["L1 ETERNAL CORE<br/>Claim · lineage-DAG · hash chain · 3-key · cliff"]
    L2B["L2 ADJUDICATED MECHANICS<br/>epoch-FREEZE · consolidate · hybrid recall · merge"]
    L3B["L3 DISPOSABLE PERIPHERY<br/>BODY profile · IN proposers · OUT consumers · SIDE bridges"]
    L0B --> L1B --> L2B --> L3B
  end

  POW -.->|"L1A implements TRACT L1B+L2B under profile L3B"| ALT
```

**Hard rules (eternity):**

1. `rg -i 'rqgm|epoch_manifest|red.?queen' src/` = **0** forever (`check-l3-boundary.sh`).  
2. No flag merges L2+L3 into one process.  
3. L3 may **never** compile-depend on substrate internals; substrate may **never** import L3.  
4. If **all** of Axis-B L3 dies, Axis-B L1 still rebuilds the mind.  
5. L2 is **verify-only** for epoch law — optimizer is external and **killed as in-process player**.

---

## 2. System context (perfect deployment topology)

```mermaid
flowchart LR
  subgraph ENDPOINTS["Physical endpoints"]
    T0["Tier ∅ MCU<br/>signed obs only"]
    TA["Tier A phone/edge<br/>L1 only"]
    TB["Tier B hub ≥1GB<br/>L1+L2"]
    TC["Tier C workstation/fleet<br/>full"]
  end

  GW["Gateway / hub<br/>holds L1 for Tier ∅"]
  T0 --> GW
  GW --> TB

  subgraph COG["Cognition plane — NOT substrate TCB"]
    P["Producer model family F₁"]
    R1["Reflector F₂"]
    R2["Reflector F₃"]
    R3["Reflector Fₙ≥3"]
  end

  subgraph SUB["Substrate plane — TCB"]
    L1S["L1 law + store"]
    L2C["L2 curator"]
  end

  subgraph SIBLING["Sibling plane"]
    RQ["L3 RQGM"]
    VIEW["viewer"]
    EVAL["eval-panel"]
  end

  P & R1 & R2 & R3 -->|"MCP / HTTP / CLI / C-ABI"| L1S
  L2C --> L1S
  RQ -->|"aggregate read + draft"| L2C
  VIEW & EVAL -->|"read APIs only"| L1S

  TB <-->|"mTLS + W-of-N durability tier"| TC
  TA <-->|"store-and-forward witness"| TB
```

**Capability cliff (TRACT):** the substrate **attests, counts, freezes**. It never judges whether a superior mind’s content is *true*, *safe*, or *aligned*. Oversight of ASI is **integrity UX over the record**, not semantic grading of the mind (W4-A4).

---

## 3. Axis A — L1 / L2 / L3 in depth

### 3.1 L1 — Substrate (law + persistence)

**Home:** `ai-memory` monorepo (`src/`).  
**Role:** The only place durable cognitive artifacts land.

| Domain | Perfect-system obligation |
|---|---|
| **Persist** | ASSERT / RELATE / SUPERSEDE / FORGET as **append-first** paths; UUID operational PK may coexist, but **cid / content-address** is authoritative identity for meaning |
| **Recall** | **Pure read** — zero mutation of `memories` on recall path; access signal is ledgered then **folded** off-path (P0-1 permanence; no `RECALL_TOUCH_SYNC` escape) |
| **Attest** | Store + federation DATA + authority lanes require attestation by default; claimed is a **labeled degradation**, never silent majority |
| **Refuse** | Typed refusal-as-data (hooks, depth, tier-lock, secret-screen, decorrelation, governance); record-stop ≠ world kill-switch |
| **RuleEngine** | Operator-signed only; **read-only** to agents; three-key Recorder ≠ Judge ≠ Stopper when enrolled |
| **Audit** | V-4 chain + cause-binding + independent witness + role separation **require-modes ON** after key enroll |
| **Decorrelate** | Write-time **and** consolidate-time N≥3 on **attested** families only; enforce inert on CLAIMED (theater ban) |
| **Identity** | Self = signed lineage-DAG; rotation + ante-mortem succession; M-of-N recovery; crypto-agility (`algorithm_id`) |
| **Federation** | Local-first commit; W-of-N = durability **tier** not write gate; causal `fork_set`; quarantine inbound |
| **Erasure** | Dual-plane: forget is witnessed tombstone + purge (DLQ, HNSW, replicas via tombstone-subscription); forensics retain **identity-only** where law demands |
| **Portability** | C-ABI / staticlib+cdylib + cross-compile; Portability Spec + ≥2 interoperable impls (CC0 vectors) |
| **Surfaces** | MCP + HTTP + CLI as three equal APIs over one SAL; no viewer/UI in-daemon |

### 3.2 L2 — Curator (verify-only freeze + maintenance)

**Home:** same binary / `ai-memory curator`, still monorepo.  
**Role:** Bounded maintenance **inside** the law; **never** invents epoch law.

| Duty | Perfect posture |
|---|---|
| Epoch consumer | Verify `SignableEpochManifest` → bind `EpochAdvance` checkpoint → V-4 `epoch.manifest_applied` |
| Decorrelation | Run every cycle; advisory→enforce only on attested families; dominance + quorum N |
| Compaction | Consolidation with D3-031 re-correlation gate; tombstone sources when lineage DAG ON |
| Capture | L1 agent discipline + L2 recover-on-boot + **L3 substrate watcher** (filesystem notify) + L4 turn capture — layered, not single-point |
| Reflect | Bounded depth; stamps `model_family` + `loader_observed`; refuses self-attestation of reflections |
| Export for L3 | Privacy-preserving **aggregate** utility / dominance only — never raw rates or public leaderboards |

### 3.3 L3 — RQGM sibling (external optimizer)

**Home:** `ai-memory-rqgm` (sibling, never `src/`).  
**Role:** Search, panel breeding, adversarial objectives — **player**, not referee.

```
L3 READS  → aggregate telemetry exports (read-only)
L3 WRITES → one UNSIGNED epoch_manifest draft
Operator  → Ed25519 signs draft (out of band)
L2        → verifies signature + schema + binds to chain
L1        → holds frozen-within-epoch law as data, not as L3 code
```

**Why external forever:** welding the optimizer into the verifier falsifies §2.6 (separation-of-powers) and the TRACT cliff. Perfect systems are **federations of roles**, not monorepos of features (W3-A4).

### 3.4 Other siblings (perfect consumption graph)

| Sibling | Consumes | Must never |
|---|---|---|
| `ai-memory-viewer` | read APIs, metrics, signed_events | embed in daemon / write law |
| `ai-memory-schema-tools` | schema SSOT / migrations **definitions** | become second substrate |
| `ai-memory-eval-panel` | read APIs + #1171 methodology | rewrite epoch slots via MCP |
| `alphaone-dev-skills` | source-URI knowledge | store bare wiki propositions as L1 truth |

---

## 4. Axis B — TRACT altitudes (perfect data/trust stack)

```mermaid
flowchart TB
  L0["L0 — Constitution<br/>• Anchor sentence + Scope Test<br/>• One Claim grammar<br/>• Six-verb kernel<br/>• Append-only log law<br/>• Canonical serialization"]
  L1["L1 — Eternal core<br/>• Claim object (content-addressed)<br/>• Lineage-DAG identity<br/>• Bitemporal provenance<br/>• Hash / Merkle chain<br/>• Capability cliff<br/>• Refusal-as-data<br/>• Recorder ≠ Judge ≠ Stopper<br/>• Human covenant"]
  L2["L2 — Adjudicated mechanics<br/>• Epoch-FREEZE brake<br/>• Decorrelation probe / enforce path<br/>• Consolidation court<br/>• Lazy salience S(t)<br/>• Hybrid recall projections<br/>• Federation merge / fork_set<br/>• Governance policy apply"]
  L3["L3 — Disposable periphery<br/>BODY: Reference Profile year-stamped<br/>IN: signed proposers never TCB<br/>OUT: pure consumers<br/>SIDE: RAG/git bridges via citation only"]

  L0 --> L1 --> L2 --> L3

  note1["If L3 dies → L1 rebuilds mind"]
  L3 -.-> note1
  L1 -.-> note1
```

### 4.1 Six-verb kernel (perfect surface)

| Verb | Law |
|---|---|
| **ASSERT** | Add Claim with provenance; born *claimed* |
| **RELATE** | Typed directional signed edge |
| **RECALL** | Owner-scoped relevance — **pure read** |
| **ATTEST** | Raise claimed → attested (only trust upgrade path) |
| **SUPERSEDE** | Forward correction; **no silent UPDATE** |
| **FORGET** | Witnessed erasure + tombstone; **no silent DELETE** |

Everything else (MCP tools, HTTP routes, CLI verbs, skills, actions, signals, checkpoints) **composes** from these — or lives at L2/L3 as non-authoritative mechanics.

### 4.2 Recall purity + CONSUME (perfect read path)

```mermaid
sequenceDiagram
  participant C as Caller
  participant R as RECALL pure
  participant L as CONSUME ledger
  participant K as Curator distill
  participant S as Claim store

  C->>R: query
  R->>S: read-only rank
  S-->>R: claims + surface tokens
  R-->>C: results (zero memory row writes)
  Note over C,L: async, off interactive budget
  C->>L: CONSUME batch (content-blind counts)
  K->>L: read ledger
  K->>S: ASSERT RELATE reference edges (signed)
```

**Landauer discipline:** reading is cheap/reversible; erasure is the expensive irreversible act. Reads never tax the store.

---

## 5. Endpoint tiers (silicon map, not nameplate L1 fields)

**L1 law (silicon-independent):**  
`tier(Claim, endpoint) = f(joules_to_retrieve, latency, light_cone_distance)`.  
No fixed byte-count is constitutional.

**TRACT-2026 measured instantiation (swappable):**

| Tier | Hardware sketch | Hosts | Cannot claim |
|---|---|---|---|
| **∅** | MCU 64–256 KB | Signed observations only; **gateway holds L1** | Local pure semantic recall, curator, full audit independence |
| **A** | Phone / edge &lt;256 MB RSS class | L1 store + pure recall; no full curator | Epoch breeding, heavy reflect, full 3-key hub |
| **B** | Hub ≥1 GB | L1 + L2 curator + local witness raise | Multi-org BFT; hive-of-millions alone |
| **C** | Workstation / fleet node | Full profile: federation, AGE option, 3-key, RQGM export | ASI behavioral containment |
| **∞** | Gradient itself | Same Claim, different residency; remote = **enrichment never dependency** | — |

```mermaid
flowchart LR
  subgraph TIER["Residency gradient"]
    Z["∅ MCU<br/>obs → gateway"]
    A["A Edge<br/>L1"]
    B["B Hub<br/>L1+L2"]
    C["C Fleet<br/>full"]
  end
  Z --> A --> B --> C
  C -->|"enrichment only"| B
  B -->|"enrichment only"| A

  subgraph LAT["Latency classes — profile numbers, L1 structure"]
    T0L["T0 reflex &lt;100ms · zero memory I/O"]
    T1L["T1 interactive · pure RECALL"]
    T2L["T2 deliberative · full pipeline"]
  end
```

**Witness_level degrades honestly (never backdates independence):**  
`threshold` → `deferred` → `counter` → `bare`. Tier ∅ emits `bare`; gateway raises on contact.

**Floor honesty (moonshot correction D-OPUS-5):** real binary floor ~31 MB / ~18–25 MB idle RSS — tens-of-MB endpoints, not kilobyte MCUs for self-host L1.

---

## 6. Properties — perfect held-state

### 6.1 Moonshot seven (§2) — what “held” means at perfect

```mermaid
mindmap
  root((Perfect substrate))
    2.1 Endpoint-resident
      local-first commit
      C-ABI + cross-compile
      no SaaS SoR
    2.2 Coherent
      persona + lineage-DAG
      capture L1–L4 complete
      model-generation handoff
    2.3 Stoppable record
      refusal-as-data
      PE-1 presence enforce
      3-key Stopper M-of-N
    2.4 Improvable
      atomise→reflect→skill
      bounded depth
      no objective-function export
    2.5 Attested ops
      append-only spine default
      witness + cause + roles
      cid + revision leaves
    2.6 Bias-displaced
      N≥3 ATTESTED families
      write + consolidate gates
      L3 optimizer external
    2.7 LLM-agnostic
      vendor-neutral every role
      no lab-capture default path
```

| Prop | Perfect held criterion (falsifiable) |
|---|---|
| **2.1** | Any Tier ≥A node commits locally without cloud; Tier ∅ via gateway; light-cone recall correct offline |
| **2.2** | Agent identity + corpus survive process death, model swap, and SIGKILL mid-dialog (capture L1–L4) |
| **2.3** | Every deny is a typed, auditable row; phantom-context “as if write landed” impossible; **record-stop only** (no world kill-switch claim) |
| **2.4** | Skills/reflections compound across model gens; reflection cannot rewrite reflection machinery |
| **2.5** | Under enrolled defaults, every state-changing op is non-repudiable; green `verify-audit-trail` implies require-modes satisfied |
| **2.6** | Reflection admission / consolidate refuse monoculture on **attested** families; CLAIMED never green-checks enforce |
| **2.7** | Producer/reflector/curator roles swappable without code fork; no single-vendor required for core path |

### 6.2 Structural S-properties (W1 bind — perfect targets)

| ID | Name | Perfect posture |
|---|---|---|
| **S1** | Hold / refuse classes | Secrets refuse; namespace write not Any-by-silence; governance fail-closed |
| **S2** | Authority ≠ data | Action transitions + signals author-bound; memory lane attested on mesh |
| **S3** | Capture under death | L3 watcher + L4 idempotent turn capture complete the #1389 stack |
| **S4** | Anti-launder envelope | Pure recall permanent; dual identity resolved (cid authority / UUID operational or migration ADR closed) |
| **S5** | Capability cliff | No semantic ASI judge in TCB; attest-only oversight |

### 6.3 Explicit non-properties (perfect system still refuses these claims)

- World-action kill-switch / behavioral ASI containment  
- Vote-independence **proof** (estimable only)  
- Signer = thinker  
- “Implements RQGM” inside `src/`  
- BLAKE3-primary without dual-truth ADR if UUID still LWW  
- Capability/model-state attestation as full DeepMind capability standard  
- Hive-of-millions BFT under hostile peers  

These are **honesty features** of the perfect design, not backlog bugs.

---

## 7. Trust, identity, federation (perfect spine)

```mermaid
flowchart TB
  subgraph ID["Identity"]
    G["genesis claimed forever<br/>externally pinned"]
    L["lineage-DAG events<br/>rotate · fork · merge · succession · retire"]
    G --> L
    SP["succession_policy<br/>ante-mortem + dead-man / M-of-N"]
    L --> SP
  end

  subgraph KEYS["Three-key TCB"]
    REC["Recorder"]
    JUD["Judge"]
    STP["Stopper"]
    REC -.->|"distinct custody"| JUD
    JUD -.-> STP
  end

  subgraph FED["Federation"]
    LOC["local commit first"]
    DUR["W-of-N durability tier async"]
    FORK["fork_set conserved"]
    Q["quarantine inbound → local verify"]
    LOC --> DUR
    LOC --> FORK
    Q --> LOC
  end

  L --> REC
  REC --> LOC
```

**Secure-default matrix (perfect ops, not cold-flip theater):**

| Domain | Perfect default |
|---|---|
| Store attestation | ON (v0.9 #1751 already) |
| Fed envelope / nonce / peer enrollment / transition sig | ON |
| Fed write-sig + signal-sig | ON after one-cycle WARN (W4-A5 ladder) |
| Secret screen | refuse (caller); redact degrade on receive |
| Append-only spine | ON |
| Decorrelation | enforce on attested N≥3 after soak + D3-060 |
| Witness / role / identity lineage require | ON **after** key enroll (never greenwash empty install) |
| PE-1 hooks | enforce + non-empty Pre\* required_events in procurement profile |
| Escape hatches | exist, logged, doctor-flagged if permanent |

---

## 8. Data model (perfect Claim vs shipped Memory)

Perfect system end-state is **one Claim object** (TRACT §2) with kinds-as-tags, not parallel class hierarchies.

| Perfect Claim field | Role |
|---|---|
| `id` | Content-address (BLAKE3/dCBOR of content‖provenance) |
| `kind` | fact \| episode \| skill \| policy \| relation (authored, hashed) |
| `content` | mime+bytes; L1 content-blind for sealing |
| `provenance` | asserter, source, span, valid_time, transaction_time |
| `owner` | lineage-DAG ref (outside hash for succession) |
| `confidence` | value_at_assert + basis (immutable authored) |
| `attestation` | claimed \| attested + sigs + algorithm_id |
| `lifecycle` | asserted \| superseded \| forgotten(receipt) |
| `links` | kernel relations + open CID predicates |

**Shipped Memory (v0.9)** is a TRACT-2026 **projection**: UUID PK, additive `cid`, `memory_kind` (13 variants), tiers short/mid/long, FTS/HNSW derived columns. Perfect system either:

1. Completes **Claim algebra migration** (TRACT G22) with dual-write → cutover, **or**  
2. Freezes an explicit dual-model ADR where Memory remains profile projection of Claim with proven round-trip vectors.

Either path is allowed; **silent dual-truth without ADR is not**.

---

## 9. Cognitive pipeline (perfect compound record)

```mermaid
flowchart LR
  OBS["Observation / Event"] --> ATOM["Atomise"]
  ATOM --> REFL["Reflect<br/>N≥3 attested"]
  REFL --> SKILL["Skill promote"]
  REFL --> CONS["Consolidate<br/>D3-031 gate"]
  CONS --> LINE["Lineage DAG P<br/>derived_from · reflects_on · derives_from"]
  SKILL --> LINE

  CAP["Capture L1–L4"] --> OBS
  FORB["Forbidden"]
  REFL -.->|"no self-ATTEST<br/>no rule rewrite<br/>no objective MAX"| FORB
```

**Learning-vs-RSI line:** the substrate may compound the **record**; it may never compound the **reasoner**. No write path from substrate scores into substrate policy, reflection caps, or model weights.

---

## 10. Deployment architectures (perfect consumption patterns)

| Pattern | Maps to tiers | Properties stressed |
|---|---|---|
| Personal SQLite MCP | A/B | 2.1, 2.2, 2.7 |
| Team hub + Postgres+AGE | B/C | 2.5, 2.6, S2 |
| Multi-org federation | C mesh | 2.5, S2, FED honest-peer |
| Edge gateway + MCU | ∅+B | 2.1, witness degrade honesty |
| Air-gapped clinical / defense | B/C offline | 2.3, 2.5, secret refuse, export/forget |

**Never the perfect core:** multi-tenant SaaS as System of Record; general orchestration product; emotion-internals product; third DB backend gravity well.

---

## 11. Conformance & moat (perfect openness)

```mermaid
flowchart TB
  SPEC["CC0 wire + on-disk format<br/>+ golden vectors"]
  IMPL1["Reference impl<br/>ai-memory TRACT-2026"]
  IMPL2["Second impl<br/>weekend reimplement gate"]
  CERT["Certification mark only<br/>pass vectors = conformant"]

  SPEC --> IMPL1
  SPEC --> IMPL2
  IMPL1 --> CERT
  IMPL2 --> CERT
```

**Durable moat (W3-A6):** composition of attest-never-judge + record-stop + multi-org federation + **enforced** multi-family bias-displacement + portable multi-impl protocol — **not** R@k race vs Mem0/Zep/Letta.

---

## 12. Perfect vs v1.0 vs v0.9 (distance honesty)

```mermaid
gantt
  title Rungs toward perfect system (conceptual — not calendar commits)
  dateFormat  YYYY
  axisFormat  %Y

  section Shipped
  v0.9 spine P0 partial           :done, 2026, 2026

  section Contract
  v1.0 freeze + audit + FED floor :active, 2027, 2027

  section Perfect residual
  Claim algebra + cid authority   :2027, 2029
  Enforce-default 2.6 + D3-060    :2027, 2028
  3-key hub physics default TCB   :2028, 2029
  M-of-N recovery + PQ agility    :2028, 2030
  Multi-impl CC0 program mature   :2027, 2030
  Privacy-preserving cross-mind   :2029, 2032
```

| Rung | Is perfect system? | What it is |
|---|---|---|
| **v0.9.0** | **No** | Machinery-rich Reference Profile; soft defaults residual (W2/W4) |
| **v1.0.0** | **No** | Stable contract + default integrity + audited federation floor (W3) |
| **Perfect system** | **Target** | Properties held under defaults; TRACT L1 data-model complete; L1/L2/L3 powers separated; multi-impl gravity real |

---

## 13. Acceptance tests for “architecture is perfect” (design gates)

A future release may claim **perfect-system architecture closed** only when **all** hold:

1. **Axis A:** L3 sibling ships; L2 verify-only epoch path live; `src/` RQGM boundary CI green.  
2. **Axis B:** L0/L1 frozen; Reference Profile year-stamped; golden vectors pass on ≥2 impls.  
3. **Seven properties** held under **compiled defaults** (not only max-enrolled posture).  
4. **2.6** enforce path field-fireable on attested families + consolidate gate; ban unlock only after D3-060.  
5. **S1–S5** non-theater (PE-1 non-empty; pure recall permanent; dual-identity ADR closed).  
6. **Capture** L1–L4 complete including L3 watcher.  
7. **Federation** data-lane attestation default ON; durability tier language honest.  
8. **Erasure dual-plane** fleet-aware (tombstone-subscription).  
9. **Crypto** succession + recovery + algorithm_id agility beyond Ed25519 monoculture.  
10. **Claims pack** still bans grandeur, RQGM-in-tree, vote-independence proof, world kill-switch, TRACT-L1-complete-as-marketing-lie.

Until then: ship **rungs**, never brand perfection.

---

## 14. Synthesis diagrams — single-page target

```mermaid
flowchart TB
  subgraph PERFECT["Perfect endpoint cognitive governance substrate"]
    direction TB
    subgraph POW2["Powers"]
      L3x["L3 RQGM external"]
      L2x["L2 curator verify"]
      L1x["L1 law + store"]
      L3x --> L2x --> L1x
    end
    subgraph PROPS["Properties 2.1–2.7 + S1–S5"]
      P["endpoint · coherent · stoppable · improvable · attested · bias-displaced · LLM-agnostic"]
    end
    subgraph TIERS2["Tiers ∅→∞"]
      T["MCU gateway · edge · hub · fleet · gradient"]
    end
    subgraph VERBS["Six verbs"]
      V["ASSERT RELATE RECALL ATTEST SUPERSEDE FORGET"]
    end
    POW2 --- PROPS
    PROPS --- TIERS2
    TIERS2 --- VERBS
  end

  OUT["OUT forever: RQGM-in-src · viewer-in-daemon · SaaS SoR · CLAIMED-enforce · world kill-switch · grandeur brand"]
  PERFECT -.->|"scope test §3"| OUT
```

---

## 15. Verdict

| Question | Answer |
|---|---|
| What is the perfect architecture? | **Two-axis L-stack** (powers + altitudes) + **tiered residency** + **seven+S properties** held under defaults + **six-verb Claim core** + **external optimizer** + **multi-impl CC0 gravity** |
| Is v0.9 / v1.0 that architecture? | **No** — necessary rungs (W3/W4) |
| May we brand “perfect memory”? | **No** (W3-A6) — brand governance substrate |
| May RQGM enter `src/` for cohesion? | **Eternity NO** |
| What is IN that looks cut-adjacent? | Epoch verify, attested N≥3, pure recall, aggregate L3 export, C-ABI (W3-A4) |

**One-line close:**

> *Perfect system = TRACT-complete continuity organ under moonshot powers — L1 persists/attests/refuses, L2 freezes/verifies, L3 optimizes outside the TCB — tiered to real silicon, pure on recall, hard on attestation, soft never on CLAIMED enforce, honest about every proof it cannot make.*

---

## Handoff

| Next | Use this doc for |
|---|---|
| W7 synthesis / ROADMAP § rewrite | Canonical **target** picture vs v1.0 epic cutline |
| Implementation epics | Map each V10-G* / TRACT G* to a box above; refuse scope that fails §3 |
| Positioning / site | Category language + mermaid-exportable architecture only |
| Never | Treat this as a claim that HEAD is perfect |

---

*W7-A4 · Perfect-system target architecture · final design · mermaid + narrative · under 550 lines*  
*Absolute path: `/Users/fate/Downloads/ai-memory-mcp/waves/w7-a4-perfect-architecture.md`*
