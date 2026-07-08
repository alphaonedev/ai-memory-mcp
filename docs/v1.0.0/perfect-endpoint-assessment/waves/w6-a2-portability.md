# W6-A2 — Memory Portability Spec + multi-impl gravity (infinity)

**Lens:** What must perfect endpoint memory do so the *format* outlives any one binary, steward, language, or model generation?
**Surfaces:** Memory Portability Spec v1 → v2, CC0 golden vectors (TRACT G24 / P2-G26), second-impl gravity, export/import, `cid` / lineage / audit envelope portability, infinity-horizon lock-in.
**Code / doc anchors:** `docs/spec/v1.md`, `docs/spec/v1.html`, export/import paths, `src/identity/cid.rs` (v74), lineage DAG (#1859), `signed_events` / revisions spine, ROADMAP §11.6, waves W3-A5/A6/A7, W4-A1/A7, TRACT design gaps G24/G26/G27.

---

## VERDICT

**Portability is not a deployment brochure; it is the infinity-horizon moat.**  
A single Rust binary with a rich MCP/HTTP/CLI surface is *product gravity*. Perfect endpoint memory needs **protocol gravity**: a frozen, falsifiable export + attestation envelope that any implementation can produce/consume, gated by **CC0 golden vectors** and a **two-implementation rule**. Without that, every cryptographic and governance primitive in the repo remains a proprietary feature set a well-funded peer can reimplement — or the steward can relicense — and “endpoint-resident forever” collapses to “this binary until it doesn’t.”

**Multi-impl for infinity does *not* mean N full substrates by Q2 2027.** It means: (1) Spec v2 as a **conformance target**, (2) **≥1 non-Rust reference consumer** (SDK/spec client, not a second daemon), (3) **G24 skeleton** that fails CI when vectors and the reference impl diverge. Full second substrate + TRACT L1 Claim algebra + foundation anti-capture are **v1.x+ / operator-governance**, not the v1.0 tag spine.

---

## CONFIDENCE

| Claim | Score |
|---|---|
| Spec v1 is real but single-impl / code-wins / no CC0 gate | **0.93** |
| Multi-impl *gravity starts* = vectors + one foreign consumer + runner | **0.90** |
| Full second substrate + two-impl *gate on every format change* by v1.0 | **0.35** (over-claim; slip risk) |
| Portability+conformance is category-defining vs Mem0-class products | **0.88** (aligned W3-A6 moat #5) |

---

## REQUIREMENTS

Perfect endpoint memory must:

### R1 — Spec is the product of record for bytes
- The **wire/disk/export envelope** is the durable public good; the reference daemon is replaceable.
- Spec versions are **semver-stable**: unknown fields preserved (v1 forward-compat rule); breaking envelope changes require major bump.
- When code and spec disagree, that is a **defect** — “code wins” is an interim honesty for Draft v1, not an infinity posture.

### R2 — Conformance levels that scale
| Level | Obligation |
|---|---|
| **Producer** | Emit envelope + required tables; stamp `schema_version`; encode embeddings with magic family |
| **Consumer** | Accept any conformant envelope of supported majors; preserve unknowns; reject unknown majors |
| **Round-trip** | Produce→consume→produce byte-stable under `--preserve-timestamps` |
| **Attested-export** (v2) | Optional: signatures, `cid`/`cid_genesis`, tombstones, revisions leaves, lineage edges, witness anchors verifiable *without* the original DB |
| **Interop** (v2+) | Second implementation passes the same golden suite |

### R3 — CC0 golden-vector harness (TRACT G24 keystone)
- **Conformant = passes the signed golden vectors**, not “our tests on our binary.”
- Vectors + envelope grammar licensed **CC0** (or equivalent unrelicensable public-domain dedication), separate from Apache-2.0 application code.
- Runner is language-agnostic at the I/O boundary (JSON normative; TOON secondary as today).
- Spec changes that break vectors **HARD-BLOCK** — the harness is the kill-test for format fashion.

### R4 — Multi-impl gravity (not theater)
- **Minimum gravity (v1.0 / C6):** Portability Spec v2 + golden suite + **≥1 non-Rust consumer** (TS and/or Python SDK as *spec client*: import/verify/export subset).
- **Strong gravity (v1.x):** two interoperable *producers* (Rust reference + one other) gate envelope changes.
- **Anti-pattern:** claiming “multi-implementation interop” while only the monorepo rounds-trips against itself.

### R5 — Infinity surfaces in the envelope
v2 MUST carry (at least as optional attested sections) what makes history navigable across stewards:
- Memory rows + links + archive (v1 baseline)
- **Content-id** (`cid` / `cid_genesis` posture) and lineage-relevant edges
- Forget tombstones / revision leaves (identity-only where designed)
- Audit chain export or external-watermark pointers (honest about what verifies offline)
- Algorithm tags where signatures appear (binds W4-A1 crypto-agility)
- Secret-screen disposition honesty (redacted content stays redacted; refuse→redact on federation path documented)

### R6 — Backend ≠ format
- SQLite and Postgres+AGE are **adapters** under one logical envelope; export MUST NOT require the consumer to speak sqlx/AGE.
- Graph projection (AGE) is a **derived view**; relational + envelope are source of truth for portability.

### R7 — Honest non-claims
- Portability does **not** equal live federation convergence, BFT mesh agreement, or capability attestation of minds.
- A golden-vector pass proves **byte and crypto envelope fidelity**, not that two ASIs share a self.

### R8 — Governance path (operator, not engineering fake)
- Long-horizon anti-capture (CC0 format carve-out, two-impl rule, CLA/DCO, foundation) is **TRACT G25/G27** — flag, do not simulate with marketing alone.

---

## GAPS in v0.9 / today

| # | Gap | Evidence |
|---|-----|----------|
| G1 | **Spec v1 is Draft + single-impl** | `docs/spec/v1.md`: “single-implementation reference”; multi-impl deferred to v2 |
| G2 | **Code wins over spec** | Explicit in v1 §0 — breaks infinity “format is SSOT” |
| G3 | **No CC0 golden-vector suite** | TRACT P2-G26 / G24 UNTRACKED keystone; no signed vectors gating format |
| G4 | **No two-implementation rule** | ROADMAP §11.6 promises v2 interop; not started as CI gate |
| G5 | **Schema drift vs envelope** | Live `CURRENT_SCHEMA_VERSION` = 78; v1 doc still frames early db_schema_version examples — envelope field set lags Memory 28-field + v74–v78 tables |
| G6 | **SDKs are API clients, not envelope consumers** | `sdk/python`, `sdk/typescript` talk live surfaces; not golden-vector importers |
| G7 | **Attested history not first-class in export story** | cid, lineage, tombstones, revisions, model_attestations, witness checkpoints lack a frozen export section + vectors |
| G8 | **TOON / JSON dual path un-gated externally** | Internal round-trip discipline ≠ public interop suite |
| G9 | **License structure is monorepo Apache + CLA** | TRACT G27: no CC0 format carve-out; single steward — operator decision |
| G10 | **“Portable” often means LLVM/mobile** | ROADMAP §2.1 portability matrix is **host binary** portability — necessary but **orthogonal** to multi-impl *protocol* gravity |

**Already load-bearing (build on, don’t reinvent):** export/import surfaces; forward-compat unknown-field rule; embedding magic-byte family; dual backend adapters; additive `cid`; archive losslessness work; SDKs as seeds for foreign consumers.

---

## VOTE (5-axis internal)

| Lens | Stance |
|---|---|
| Precedent | Extend Spec v1 envelope; do not replace with greenfield L1 Claim-only format mid-flight |
| Spec / TRACT | G24 keystone first; two-impl is gravity, not day-one N substrates |
| Security | Attested-export sections verify offline; never claim mesh non-repudiation from envelope alone |
| Testability | Golden vectors + foreign consumer CI; kill-test on format change |
| Blast radius | Additive v2 sections + major-version bump; preserve v1 consumers via unknown-field rule |

**Tally:** 5/5 — **ship protocol gravity: Spec v2 + CC0 vectors + ≥1 non-Rust consumer; refuse “multi-impl” marketing without the harness.**

**Chosen pathway (dependency order):**
1. Inventory envelope vs schema v78 (close G5) — additive fields only.
2. Freeze **JSON golden corpus** (memories/links/archive + minimal attested fixtures) under CC0 path.
3. Conformance runner (Rust first) + CI HARD-BLOCK on vector break.
4. Spec v2 doc: levels R2 + attested-export sections + algorithm_id hooks.
5. **Non-Rust consumer** (prefer existing TS or Python SDK): import + verify + re-export subset.
6. Second *producer* and full two-impl gate → v1.x; foundation/CLA/CC0 carve-out → operator track (G27).

**Not on the critical path for gravity start:** second full daemon, mDNS, MVCC, OTel, Claim algebra migration.

---

## KILLER_OBJECTION

**“We already ship Memory Portability Spec v1 and five install channels — we’re portable.”**  
Host portability (Rust → iOS/Android/Linux) keeps *one* implementation alive on many devices. It does **nothing** if that implementation dies, forks hostile, relicenses, or silently drifts the envelope. Without **CC0 vectors + a second consumer that can fail the first**, “portability” is a distribution story — the exact failure mode W3-A6 named: *one binary ≈ forkable feature set*, category dies as overbuilt RAG with no protocol network effects.

---

## TOP_RISK

**Spec theater at freeze time:** shipping “Portability Spec v2” as narrative in ROADMAP/release notes while golden vectors remain monorepo-only self-tests — procurement and infinity both false-green. Secondary risks: (a) freezing the wrong L1 Claim shape too early under API stability pressure; (b) envelope bloat that no foreign consumer will implement; (c) conflating LLVM mobile portability with multi-impl gravity in public claims.

**Mitigants:** V10-G9 / C6 exit criteria = vectors + ≥1 reference consumer, not word count; ban “multi-implementation interop” until G3+G4 close; keep v2 sections optional/profiled so a minimal consumer stays weekend-reachable.

---

## Binding to other waves

| Wave | Bind |
|---|---|
| W3-A5 | Portability multi-impl *if* = one client + vectors, not N full substrates by Q2 2027 |
| W3-A6 | Moat #5 / R4 — conformance + invite second impl |
| W3-A7 | R13, C6, V10-G9 — gravity *starts* at v1.0 |
| W4-A1 | Envelope must carry `algorithm_id` on signed objects (crypto succession) |
| W4-A7 | Infinity line item 9; honest non-claim binds W5/W6 public text |

---

## One-line north star

> **The binary is temporary; the envelope + golden vectors are the civilization-scale API. Multi-impl gravity is how endpoint memory survives its authors.**

---

*W6-A2 Portability / multi-impl · ≤250 lines · adversarial · evidence-weighted against Spec v1 + TRACT G24 + W3/W4 synthesis.*
