# W7-A3 — Claims Discipline & Banned Language (FINAL)

> **Agent:** W7-A3 (Claims / marketing / ROADMAP language finalizer)  
> **Date:** 2026-07-08  
> **Scope:** Master **allowed / banned / perma-banned** claim table for **public ROADMAP**, release notes, landing pages, positioning, capabilities prose, and procurement marketing — **at v0.9.0** and **after v1.0.0**.  
> **Does not:** re-score Wave-2 distance, re-open Wave-1 ontology, or change product scope.  
> **Anchors (SSOT stack, in force order):**  
> 1. This file — **public-surface claims master** for v0.9 / post-v1.0 wording  
> 2. `ROADMAP.md` §25.6 · §26.5 · §26.6 (binding constitutional bans)  
> 3. `waves/w3-a3-p0-ordering.md` · `waves/w3-a7-synthesis.md` R5 (ban unlocks)  
> 4. `waves/w4-a6-erasure-forensics.md` · `waves/w4-a7-synthesis.md` (security / erase / honest non-claim)  
> 5. `docs/reviews/RED-QUEEN-FINAL-DECISION-AND-ROADMAP-OPUS.md` §9  
> 6. Code truth at schema **v78** (P0-1 pure recall, P0-2a model_attestations, P0-3 store-path, P0-4 epoch consumer, G29/G30 single-node, G6/G8 additive)

**Prime rule:** Un-ban a claim **only** when its gate ships **and** is test-pinned. Premature flip is itself a DoD / claims-discipline violation. **CLAIMED ≠ ATTESTED** throughout.

---

## VERDICT

| Surface | Rule |
|---|---|
| **v0.9 public prose** | Claim only what defaults + tests hold **under stock install**, or prefix every stronger claim with **opt-in / enrolled / single-node / loader-attested / verify-only**. |
| **v1.0 public prose** | Unlock rows below **only** after the listed AND-gates; never OR-gates. Slip **date**, not honesty. |
| **Forever** | Perma-ban grandeur + RQGM-in-src + vote-independence-as-attested + ASI containment / world kill-switch. |
| **Category** | Public category = **endpoint-resident cognitive governance substrate** — not “perfect agent memory,” not Mem0-class RAG race. |

**Kill-test for any public sentence:** maps to (a) a row in the master table below, (b) a codegraph-reachable surface + regression test name, and (c) either **default score ≥ 0.80** on the relevant W2/W4 axis **or** an explicit scope qualifier (*opt-in / enrolled / single-node / caveated*).

---

## CONFIDENCE

**0.90** on the ban/unlock matrix (code-anchored P0 + G29/G30 + ROADMAP §26.5).  
**0.85** on post-v1.0 unlock wording (depends on V10-G* epic execution; table states gates, not calendar certainty).

---

## 1. How to read the master table

| Column | Meaning |
|---|---|
| **Claim phrase** | Exact or near-exact public wording (ROADMAP, README, landing, release notes, `memory_capabilities` prose, marketing). |
| **Class** | `ALLOWED` · `SCOPED-ALLOWED` · `BANNED→UNLOCK` · `PERMA-BAN` |
| **v0.9** | Status **now** against shipped code (schema 78 era). |
| **v1.0+ unlock** | Minimum AND-gate set. Empty for perma-ban. |
| **Honest substitute** | What public copy **may** say instead (when banned) or **must** say (when scoped). |

**Legend — v0.9 cells**

| Tag | Meaning |
|---|---|
| ✅ **claimable** | Allowed under stock wording (still prefer the “Honest substitute” precision). |
| ⚠️ **scoped** | Allowed **only** with the listed qualifier; unscoped form remains banned. |
| 🚫 **banned** | Do not use on any public surface. |
| ☠️ **perma** | Never unlocks; category error or architectural limit. |

---

## 2. MASTER TABLE — P0 spine & Red Queen / §2.6

| # | Claim phrase | Class | v0.9 | v1.0+ unlock (AND) | Honest substitute (public) |
|---|---|---|---|---|---|
| **C01** | “pure recall” / “recall does not mutate memory state” | SCOPED-ALLOWED | ⚠️ **scoped** — pure default shipped (#1869 / v77); ledger write + eventual FOLD remain | **V10-G0:** remove/hard-refuse `AI_MEMORY_RECALL_TOUCH_SYNC` (escape hatch gone) | “**Pure-by-default recall** (kill-tested): no silent mutation of `memories` on read; append-only `recall_observations` ledger + periodic fold. Sync-touch opt-in is **deprecated**.” |
| **C02** | “attests model family” (unqualified) | BANNED→UNLOCK | 🚫 unqualified banned | True training/RLHF family distance needs industry standard (post-v1.0 horizon) | **Never** unqualified. Use C03 only. |
| **C03** | “loader-attested model family (~40% hard cap)” | SCOPED-ALLOWED | ⚠️ **claimable scoped** — D3-012 / #1870 / v78 TOFU | Raise coverage only with measured telemetry; **hard cap ~40%** remains structural (substrate-invoked generation only) | “**Loader-observed / operator-signed** `model_family` attestation (TOFU). Coverage hard-caps ~**40%**; caller-CLAIMED family is **not** attestation.” |
| **C04** | “decorrelation enforced” / “N independent producers” / “bias-displaced by architecture” | BANNED→UNLOCK | 🚫 **banned** — enforce-capable, default `off` | **V10-G1** compiled default `enforce` (or advisory soak → enforce) **+ V10-G2** D3-060 invariants **+** field stamps live on attested path | “**Opt-in** write-time refuse of **attested** monoculture (`AI_MEMORY_REFLECT_DECORRELATION_MODE`); stock default is **off**. Advisory probe is CLAIMED-visible, not architecture.” |
| **C05** | “secure-by-default attestation” (blanket / network) | BANNED→UNLOCK | 🚫 blanket banned | Store path already default-true (#1751) **+ V10-G3** `AI_MEMORY_FED_REQUIRE_WRITE_SIG` secure default + escape documented | Split claims — see C06 / C07. |
| **C06** | “store-path agent attestation required by default” | SCOPED-ALLOWED | ⚠️ **claimable scoped** (#1751) | Keep escape hatch documented if retained | “**Direct store path** (MCP/HTTP/CLI) requires agent signature by default (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`); unsigned → 403. Federation data-lane is separate.” |
| **C07** | “federation / mesh authorship attested by default” | BANNED→UNLOCK | 🚫 banned — write-sig permissive default | **V10-G3** + soak + migration WARN | “Relay memory content attestation is **opt-in** (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`); accept-and-flag is the stock data-lane posture.” |
| **C08** | “epoch closure shipped” / “RQ-01 shipped” | SCOPED-ALLOWED | ⚠️ **verify-only claimable** (RQ-10 consumer + git-tracked schema) | Cluster-wide: FED-RQ-02..05 + policy_version cross-node | “**Verify-only epoch-manifest consumer** shipped (`ai-memory epoch-apply`, V-4 `epoch.manifest_applied`). Not a live optimizer; not cluster epoch closure.” |
| **C09** | “cluster-wide epoch closure” / “federated epoch manifest shipped” | BANNED→UNLOCK | 🚫 banned | FED-RQ-02..05 green + E2E | “FED-RQ-01 checkpoint federation only where shipped and cited; no cluster epoch claim.” |
| **C10** | “closed recursive self-improvement loop” | BANNED→UNLOCK | 🚫 for **live** loop | Shadow only: #1706 proves signal; live #1707 never marketed as RSI | “**Shadow** recall-utility observations only; live ranking wire is conditional and not an RSI engine.” |
| **C11** | “implements RQGM” / “co-evolving evaluators shipped” / “self-improving agent framework” | PERMA-BAN | ☠️ | **Never in-repo** (category error; L3 sibling only) | “Red-Queen-**principles**-aligned substrate; optimizer stays **outside** `src/`.” |
| **C12** | “vote-independent” / “votes are independent minds” (as fact) | PERMA-BAN | ☠️ | Estimator may ship as **advisory**; independence remains un-attestable | “Vote-independence is an **architectural limit** (0% attestable); substrate counts signatures, not generating processes.” |

---

## 3. MASTER TABLE — TRACT data-model / G-series

| # | Claim phrase | Class | v0.9 | v1.0+ unlock (AND) | Honest substitute (public) |
|---|---|---|---|---|---|
| **C20** | “append-only” / “no silent delete” (as present default) | BANNED→UNLOCK | 🚫 as **default fact** — flag opt-in (`AI_MEMORY_APPEND_ONLY`) | Default-on **or** capabilities refuse the claim when off + dual-backend parity tests | “**Optional** append-only spine (`AI_MEMORY_APPEND_ONLY`): signed identity-only `memory_revisions` leaves. Stock install remains in-place/hard-delete unless enabled.” |
| **C21** | “content-addressed” / “BLAKE3 identity” (primary) | BANNED→UNLOCK | 🚫 as **primary identity** | BLAKE3-primary migration / constitutional cid path (G24-class + ops) if ever chosen | “**Additive** BLAKE3 `cid` beside UUID PK — partial-corruption detection + genesis bind; **not** primary PK; detect-and-log enforce only.” |
| **C22** | “TRACT-conformant” / “L1-conformant” / “TRACT L1 complete” | BANNED→UNLOCK | 🚫 banned | G24 CC0 vectors + multi-impl harness + frozen L1 Claim algebra (honest residual list published) | “**TRACT-2026 L3-BODY *reference profile*** of endpoint governance (trust spine strong; data-model partial). Two-axis grades only — never one composite.” |
| **C23** | “three-key / Recorder-Judge-Stopper cryptographic split held by default” | BANNED→UNLOCK | 🚫 as default TCB fact | Enrolled distinct custody + `REQUIRE_ROLE_SEPARATION` production posture + runbooks; still single-host unless multi-party | “**Enrollable** logical role keys (opt-in custody dirs); stock daemon may still be single-TCB. Capabilities must declare non-conformance when unenrolled.” |
| **C24** | “witnessed / dual-chain non-repudiation by default” | BANNED→UNLOCK | 🚫 default | Enrolled witness key + `AI_MEMORY_REQUIRE_WITNESS` + external HWM story | “V-4 mid-chain tamper-evidence under **enrolled** daemon/witness keys; missing witness → withhold unless require-mode.” |
| **C25** | “verify-audit-trail green = tamper-proof / safe” | PERMA-BAN | ☠️ as safety claim | Integrity ≠ capability (W4-A4) | “Green trail = **chain integrity under enrolled keys**, not mind safety or ASI containment.” |
| **C26** | “causal-CRDT / fork_set complete” | BANNED→UNLOCK | 🚫 | Full fork algebra ship-gate | Do not claim; list as TRACT residual. |
| **C27** | “identity lineage = key-loss resilience / recovery” | BANNED→UNLOCK | 🚫 — rotation-only (G13 open) | G17 recovery VERIFY + ante-mortem / threshold path | “Signed **key-rotation** succession (v76); **not** key-loss recovery.” |

---

## 4. MASTER TABLE — Secrets, erasure, forensics (G29 / G30 / dual-plane)

| # | Claim phrase | Class | v0.9 | v1.0+ unlock (AND) | Honest substitute (public) |
|---|---|---|---|---|---|
| **C30** | “secrets are screened” / “credential-safe storage” (unqualified) | SCOPED-ALLOWED | ⚠️ **scoped** — G29 refuse default on **caller** writes | Broader detector corpus + export-class G28 completeness as needed | “**Caller-origin** writes refuse credential-shaped content by default (`AI_MEMORY_SECRET_SCREEN_MODE=refuse`). Federation/L2 degrade refuse→redact. Detectors are best-effort patterns, not formal secret DLP.” |
| **C31** | “forget erases” / “complete erasure” / “right-to-erasure” / “GDPR complete” (unqualified or fleet) | BANNED→UNLOCK | 🚫 unqualified / fleet | Fleet: #1852 mesh tombstone prop + ship-gate + no-resurrect E2E | **Never** unqualified. Use C32. |
| **C32** | “single-node forget purges content + vectors + DLQ + content-free tombstone” | SCOPED-ALLOWED | ⚠️ **claimable scoped** (G30 on-node) | Mesh remains separate | “**Single-node** dual-plane forget: content destroyed (row/FTS/DLQ/HNSW); identity tombstone + audit leaf retained (content-free). Host transcripts / OS backups / WAL outside substrate.” |
| **C33** | “tombstoned delete” as full soft-row default everywhere | BANNED→UNLOCK | 🚫 as default | Soft-tombstone default policy if product chooses | “v71 `forget_tombstones` anti-resurrection; consolidate-tombstone sources optional when lineage DAG on.” |
| **C34** | “forensic bundle is secret-safe” | SCOPED-ALLOWED | ⚠️ with G29 egress mask | G28 forbidden-export-class complete | “Forensic egress runs secret-screen redaction; pre-screen residuals and embeddings export class still operator-scoped.” |
| **C35** | “archive = forgotten” | PERMA-BAN | ☠️ | — | “**Archive ≠ erase.** Archive preserves recoverable content; forget destroys content plane.” |

---

## 5. MASTER TABLE — Security / federation / multi-tenant / crypto

| # | Claim phrase | Class | v0.9 | v1.0+ unlock (AND) | Honest substitute (public) |
|---|---|---|---|---|---|
| **C40** | “ASI containment” / “perfect endpoint ASI survival” / “stops ASI” | PERMA-BAN | ☠️ | Out of TCB (W1/W4) | “**Necessary-but-not-sufficient** integrity frictions for ASI-era *operations history*; does not contain, evaluate, or stop minds.” |
| **C41** | “world kill-switch” / unscoped “kill-switch” | PERMA-BAN | ☠️ | World-actions out of scope | “**Record-stop** / typed refuse on **daemon memory writes** when hooks/governance configured — not a world actuator.” |
| **C42** | “BFT / Byzantine-safe federation” / “ASI-hostile mesh security” | PERMA-BAN | ☠️ as product claim | Horizon research only | “Honest-peer AP federation with enrollment, signatures, nonces; **not** BFT.” |
| **C43** | “multi-tenant NHI isolation under shared API key” | BANNED→UNLOCK | 🚫 full isolation | Principal-bound authn beyond shared key + visibility enforcement E2E | “Privacy is **conditional**: store attest + visibility filters; shared API key is not full tenant isolation.” |
| **C44** | “cryptographic non-repudiation by default” | BANNED→UNLOCK | 🚫 | Enrolled keys + witness/HWM + unsigned residual closed | “Non-repudiation of **operations** under enrolled keys and optional external watermark; unsigned daemons are weaker.” |
| **C45** | “Ed25519 forever” / “quantum-ready signatures” | PERMA-BAN / BANNED | ☠️ forever claim; 🚫 quantum-ready | PQ hybrid + `algorithm_id` succession | “Ed25519 is the **present** operational suite; succession / crypto-agility is roadmap, not shipped PQ.” |
| **C46** | “capability attestation / knows what an ASI can do” | PERMA-BAN | ☠️ | External L3 only | “Oversight UX = **operation history**, never power or capability certificates.” |
| **C47** | “capture under process death guaranteed” / “never loses context” | BANNED→UNLOCK | 🚫 L3 watcher missing | L3 substrate watcher + dogfood proof | “Layered capture L1+L2+L4 shipped; L3 watcher deferred — not total death-capture.” |
| **C48** | “session-coherent from pure recall alone” | PERMA-BAN | ☠️ category error | — | Pure recall ≠ capture (S3) ≠ session continuity product. |
| **C49** | “federation mature for multi-org trust” (unqualified) | BANNED→UNLOCK | 🚫 | V10 federation floor + public audit + author attest defaults | “Federation primitives shipped; maturity claims need E2E + secure defaults + published residual list.” |

---

## 6. MASTER TABLE — Category, marketing, grandeur, competitive

| # | Claim phrase | Class | v0.9 | v1.0+ unlock | Honest substitute (public) |
|---|---|---|---|---|---|
| **C60** | “perfect memory” / “perfect endpoint memory” as product category | PERMA-BAN | ☠️ | — | “**Endpoint-resident cognitive governance substrate** (attested, stoppable, federatable, bias-displacement *path*).” |
| **C61** | Grandeur register: “eternity-grade”, “civilization-scale”, “world-class”, “for eternity”, “∞”, “driving toward perfection”, “hive of millions” | PERMA-BAN | ☠️ | — | Falsifiable engineering claims only. Mechanisms may aim long-horizon; **words** stay modest. |
| **C62** | “best agent memory” / “beats Mem0/Zep/Letta on recall” without published harness | BANNED→UNLOCK | 🚫 without evidence | Published head-to-head under shared harness + dated artifact | “Governance / attestation differentiators; recall numbers only with linked benchmark artifact.” |
| **C63** | “101 tools / 92 routes means complete” | PERMA-BAN | ☠️ as quality claim | — | Surface counts are inventory SSOT, **not** product quality or moat. |
| **C64** | “Apache 2.0 + Rust + MCP is the differentiator” | PERMA-BAN as sole claim | ☠️ as differentiation | — | Commodity floor; differentiation is attestation + federation + stoppability composition. |
| **C65** | “bias-displaced by architecture” (ROADMAP lead language) | BANNED→UNLOCK | 🚫 until C04 unlocks | Same as C04 | Align §24 / §0 prose to “**path** / **machinery shipped** / **default off**.” |
| **C66** | “enforces every contact” (unscoped) | BANNED→UNLOCK | 🚫 | PE-1 procurement profile with non-empty required_events under enforce | “Hooks/governance enforce when configured; PE-1 presence gate is mode-dependent.” |
| **C67** | Optimization-readiness “~100%” / “RQGM-ready” | BANNED→UNLOCK | 🚫 | Never 100% without external L3; ceiling ~70–80% at v1.0 per §25.6 | Publish trajectory: **~50–60% (v0.9)** → **~70–80% (v1.0)** optimization-readiness; principles-aligned only. |
| **C68** | Family-verify “>40%” without new attestation class | BANNED→UNLOCK | 🚫 | New attestation class beyond loader-observed | Cap remains **~40% loader-attested** unless architecture expands. |

---

## 7. PERMA-BAN register (quick scan)

Copy-paste block for release-note / PR checklists:

```
PERMA-BANNED (never unlock):
- implements RQGM / co-evolving evaluators shipped / self-improving agent framework (in-repo)
- vote-independence as attested fact
- grandeur: eternity-grade | civilization-scale | world-class | for eternity | ∞ | perfect memory
- ASI containment / perfect ASI survival / world kill-switch
- BFT / Byzantine ASI mesh / capability certificates for minds
- verify-audit-trail green = safe mind
- archive = forgotten
- pure recall alone = session continuity / capture guarantee
- surface-count supremacy as quality
```

---

## 8. ALLOWED v0.9 boilerplate (marketing / ROADMAP public)

Use **only** variants of the following. Prefer linking tests / schema version.

### 8.1 One-paragraph honest non-claim (binding — W4-A7)

> ai-memory **v0.9.0** is an **endpoint-resident integrity substrate**: multi-layer audit machinery, typed **record-stop** when configured, **pure-by-default recall**, dual-plane **single-node** erasure, multi-vendor cognitive boundaries, and **opt-in** decorrelation / multi-key / lineage scaffolds. It enables less-capable observers to verify **history of operations**, not **power or truth of minds**. It does **not** perfectly contain ASI, enforce bias-displaced self by default, non-repudiate without enrolled keys and external watermarks, stop world-actions, guarantee capture under process death, attest mesh authorship under defaults, erase content fleet-wide, or provide cryptographic succession beyond classical Ed25519 monoculture. It is **not** a BFT ASI control plane or capability certificate.

### 8.2 Short elevator (allowed)

> Local-first **governance substrate** for agent memory: Ed25519-attested writes (store path default), V-4 audit chain, federation with fail-closed enrollment options, pure-by-default recall, and honest CLAIMED≠ATTESTED limits.

### 8.3 Allowed bullet pack (v0.9)

| May claim | Must not imply |
|---|---|
| Pure-by-default recall (ledger + fold) | No writes ever; no `RECALL_TOUCH_SYNC` residual |
| Store-path attestation default-on (#1751) | Mesh authorship default-on |
| Loader-attested model_family (~40% cap) | Training-family distance / full coverage |
| Verify-only epoch-manifest consumer | Live RQGM / cluster epoch |
| Single-node dual-plane forget (G30) | Fleet GDPR / complete erasure |
| G29 caller refuse-default secret screen | Perfect DLP / all secret classes |
| TRACT L3-BODY reference profile | TRACT L1 complete |
| Red-Queen-**principles**-aligned (~50–60% opt-readiness) | Implements RQGM |
| Authority≠data federation **shape** | Content authorship attested by default |
| Opt-in attested monoculture refuse | Decorrelation enforced under stock config |

### 8.4 Readiness percentages (must publish with claims)

| Metric | v0.8 | v0.9 | v1.0 target | Cap / note |
|---|---:|---:|---:|---|
| Optimization-readiness (RQ principles) | ~15% | ~50–60% | ~70–80% | Never “implements RQGM” |
| Family-verify (loader-attested) | ~5% | ~40% | ~40% | **Hard cap** until new attestation class |
| Vote-independence | 0% | 0% | 0% attestable | Estimator advisory only |

---

## 9. Post-v1.0 unlock checklist (public flip protocol)

Before any ban-row flips on ROADMAP / release notes / site:

1. **Code green:** feature default or named procurement profile holds the claim.  
2. **Test pin:** named regression (sqlite + postgres where dual-backend).  
3. **Codegraph / SSOT:** schema version + env default documented in CLAUDE.md env table if operator-visible.  
4. **5-agent vote cite** when T1–T6 (public contract / security posture).  
5. **Edit this table** + ROADMAP §26.5 in the **same** change set (no doc lag).  
6. **Capabilities honesty:** `memory_capabilities` / TRACT manifest declares residual non-conformance.  
7. **Kill-test sentence:** public sentence maps to default ≥0.80 **or** retains explicit qualifier.

| Unlock ID | Unlocks claim(s) | Minimum gates |
|---|---|---|
| **U-P0-1** | C01 full (no sync escape) | V10-G0 |
| **U-P0-2b** | C04 | V10-G1 + V10-G2 + live stamps |
| **U-P0-3f** | C05 / C07 | V10-G3 + docs |
| **U-APPEND** | C20 as default | append_only default-on **or** capabilities refuse |
| **U-BLAKE3** | C21 primary | constitutional migration + tests |
| **U-TRACT-L1** | C22 | G24 + multi-impl + residual list |
| **U-MESH-ERASE** | C31 fleet | #1852 + no-resurrect E2E |
| **U-WITNESS** | C24 default non-repudiation path | enroll + require-mode + HWM story |
| **U-FED-MATURE** | C49 | federation floor + audit + author defaults |

---

## 10. Surfaces that must obey this table

| Surface | Enforcement |
|---|---|
| `ROADMAP.md` §0–§2 lead, §24–§26 | Rewrite any unscoped C04/C05/C31/C61 before public cut |
| `README.md` / `docs/positioning.md` / audience HTML | Category = governance substrate; no grandeur |
| Release notes / CHANGELOG | Ban unlocks only with gate + test name |
| `docs/compliance/honest-limitations.md` | Carry CLAIMED≠ATTESTED + readiness caps |
| GitHub Pages / `docs/whats-new-v09.html` | Same as README |
| `memory_capabilities` prose / TRACT manifest | Declare non-conformance (three-key, Stopper, L1) |
| Competitive benchmark claims | Artifact link or silence |
| Agent-authored marketing / PR blurbs | C1 scan for perma-ban strings |

**Suggested mechanical tripwire (v1.0 CI, not blocking this doc):** extend vendor/literal-style gate for a **small** perma-ban string set on `docs/**/*.md` + root marketing files (`implements RQGM`, `eternity-grade`, `civilization-scale`, `world-class only`, `perfect ASI`, `vote-independent`). Grandeur in *internal* design drafts may remain for archaeology; **public** paths hard-block.

---

## 11. Theater vs strength (claims lens)

| Sounds strong | Theater unless… | Real strength wording |
|---|---|---|
| Bias-displaced by architecture | Default enforce + attested stamps | Opt-in attested monoculture refuse |
| Secure-by-default attestation | Store **and** mesh | Store-path default-on; mesh opt-in |
| GDPR / right-to-erasure | Fleet prop + no archive confusion | Single-node dual-plane forget |
| Tamper-proof audit | Enrolled keys + external HWM | V-4 mid-chain under enrolled keys |
| Kill-switch | World actuators | Configured record-stop on writes |
| Content-addressed identity | BLAKE3-primary | Additive cid + UUID PK |
| Three-key governance | Multi-custody enrolled | Opt-in role keys; single TCB residual |

**Not theater (claim freely with scope):** pure-by-default recall kill-tests; #1751 store attest; G29 refuse; G30 single-node purge+tombstone; S2 authority≠data shape; forged-sig unconditional refuse; RQGM-external cut; verify-only epoch consumer.

---

## 12. ROADMAP rewrite instructions (for docs agents)

When rebasing public ROADMAP (W3-A7 R5):

| Action | Detail |
|---|---|
| **Unlock now (scoped)** | pure recall · store-path secure attest · epoch closure (verify-only) · loader-attested family (~40%) · single-node forget (dual-plane) · G29 caller screen |
| **Keep banned** | decorrelation enforced · blanket network attest · BLAKE3-primary · append_only as present · TRACT-L1-conformant · RQGM · grandeur · fleet erase · vote-independence |
| **Fix lead language** | Replace unscoped “enforces every contact” / “Bias-displaced by architecture” with machinery + default-off honesty |
| **§26.5 paragraph** | Replace stale “banned until ships” list that still bans pure recall after ship — point here as master |

Stale §26.5 line that still bans pure recall / epoch / store attest **after v0.9 ship** is **docs lag**, not code truth. This file is the corrective SSOT for public wording until ROADMAP is rewritten.

---

## 13. VOTE (self-discipline freeze)

| Motion | Ballot |
|---|---|
| Freeze this table as public claims master for v0.9 / post-v1.0 | **AYE** |
| Unscoped “decorrelation enforced” remains banned at v0.9 | **AYE** |
| Pure recall / store attest / epoch verify-only / loader-attested / single-node forget may appear with scope | **AYE** |
| Grandeur + RQGM-in-src + ASI containment perma-ban | **AYE** |
| Allow “TRACT L1 complete” at v1.0 without G24 multi-impl | **NAY** |
| Allow fleet “forget erases” without #1852 | **NAY** |

**Synthesis:** **ACCEPT-AND-FREEZE** — narrower honest claims beat perfect vocabulary. Marketing sells **verifiable integrity under named posture**, not moonshot adjectives.

---

## 14. Handoff

| Consumer | Use |
|---|---|
| ROADMAP editors | §25.6 / §26.5 rewrite from §2 + §9–§12 |
| Release / GA checklist | §7 perma-ban + §9 unlock protocol |
| Positioning / Pages | §6 category + §8 boilerplate |
| Security audit kit | §5 + §11 theater table + honest non-claim |
| CI tripwire owner | §10 string gate proposal |
| W7 peers (procurement / UX) | Do not invent claims outside this matrix |

---

## Related

- [`ROADMAP.md`](../ROADMAP.md) §25.6, §26.5, §26.6  
- [`waves/w3-a3-p0-ordering.md`](w3-a3-p0-ordering.md) · [`waves/w3-a7-synthesis.md`](w3-a7-synthesis.md)  
- [`waves/w4-a6-erasure-forensics.md`](w4-a6-erasure-forensics.md) · [`waves/w4-a7-synthesis.md`](w4-a7-synthesis.md)  
- [`docs/reviews/RED-QUEEN-FINAL-DECISION-AND-ROADMAP-OPUS.md`](../docs/reviews/RED-QUEEN-FINAL-DECISION-AND-ROADMAP-OPUS.md)  
- [`docs/compliance/honest-limitations.md`](../docs/compliance/honest-limitations.md) (when present)  
- Epic: [`docs/v0.9.0/V0.9.0-AI-NHI-AUTONOMOUS-DEVELOPMENT-EPIC.md`](../docs/v0.9.0/V0.9.0-AI-NHI-AUTONOMOUS-DEVELOPMENT-EPIC.md) claims-discipline DoD

---

*W7-A3 · Claims discipline FINAL · master allowed/banned table for public ROADMAP + marketing · v0.9 scoped unlocks · v1.0 AND-gates · perma-ban freeze · no code changes*
