# W3-A1 — ROADMAP Completeness vs Perfect System (v0.9.0 code)

> **Agent:** W3-A1 · **Date:** 2026-07-08  
> **Scope:** ROADMAP.md §11.4–11.7, §23–26 · Wave-2 SSOT `w2-a7-synthesis.md` · code SSOT CLAUDE.md / schema **v78**  
> **Not reopened:** Wave-1 seven axes · Wave-2 held-fractions (cited, not re-scored)

---

## VERDICT

**ROADMAP is a partially honest trajectory document frozen across three release eras — not a v0.9.0 truth surface.**

Relative to **code reality at schema 78 / 101 MCP / 92 HTTP / 87·89 CLI**:

| Bucket | Headline |
|---|---|
| **SHIPPED** (ahead of or matching calendar prose) | Most of §11.4 Pillar 1–4 machinery; pure recall (P0-1); store-path agent-attest default ON (P0-3/#1751); `model_attestations` v78 (D3-012 substrate); secret screen G29; forget tombstones G30 (core); skills `parameters_schema` + version; LLM tool-calls (#1866); #1706 shadow backfill; G7-step2 rerank pool; #1005 G2/G4 knobs; vLLM **alias**; CRDT-lite merge primitives; PE-1 wired when configured |
| **STALE** (prose lagging code) | §11.5/§23 calendars (Q1 2027 “v0.9”); §24 ship-state frozen at v0.7.1; §26.5 bans on “pure recall” + “secure-by-default attestation”; §26.6 “G29/G30 until ship”; §26.4 “no crypto family attestation yet”; §11.4 “retire `db` alias at v0.8”; cutline “defer signals/model-attest to v0.9” while both landed earlier |
| **MISSING** (committed, not in code) | §23 persistent 3-backend index (sqlite-vec / vectorlite / hnsw_rs); G3 disk persistence; `IndexInserted|Rebuilt` audit events; `memory_reindex` / `migrate-index`; default-on fail-loud reranker (still lexical fallback); MCP streaming tools; L3 capture watcher; 8/10 Pillar-1 hook events; full §11.4.D release-key model digest chain; RQ-10 git-tracked epoch consumer; D3-031 consolidate gate; live #1707 utility term; production reflect `model_family` stamp (W2-A2) |
| **OVERPROMISED** (language > held property) | “Cryptographic non-repudiation” of signals without enrolled defaults; vLLM as §2.6 load-bearing at federation scale (alias ≠ decorrelated reflector); §23 as the v0.9 identity of the release; §24 trailing “Bias-displaced by architecture”; kill-test P0-2 “minimum bar at v0.9.0” while enforce remains opt-in/off |

**Ship posture for Wave 3:** ROADMAP needs a **v0.9.0 rebase** (shipped / partial / open matrix) before it can adjudicate perfect-endpoint distance. Do not treat §11.5 “Q1 2027” or §26.5 ban list as live gates without code re-probe.

---

## CONFIDENCE

**0.87**

| + | − |
|---|---|
| Code anchors on env flags, schema ladder, tool names, W2 scores | Did not re-run full test suite / multi-node federation |
| ROADMAP self-admits some gaps (hooks 2/10, L3 deferred, claims discipline) | Issue tracker close-state not fully re-audited |
| W2 theater list aligns with §25.6/§26.5 spirit | Calendar fiction may hide further mid-v0.9 commits |

---

## SCORE — roadmap-truth **52 / 100**

| Band | Meaning |
|---|---|
| 80–100 | Calendar + ban lists + DoD match code under defaults |
| 60–79 | Minor lag; major shipped/open correctly labeled |
| **40–59** | **This band — directionally right pillars; frozen adjudication + §23 DoD + stale bans** |
| 0–39 | Marketing fiction |

**Why 52, not lower:** Pillar 4 shipped-state block, hook honesty line, L3 deferral, §25.6 anti-theater rules, and G-cut language remain load-bearing and mostly correct.  
**Why 52, not higher:** §23 full DoD still unread as future while half of §11.5 already partial-shipped; §26.5/§26.6 actively **mis-ban shipped properties**; dates imply v0.9 is next year.

---

## STALE CLAIMS (prose ≠ code)

1. **§11.5 header “Q1 2027” / §24 cadence “v0.9 (Q1 2027)”** — codebase is already **v0.9.0-class** (schema 78, #1751/#1869/#1870, CLAUDE surface counts). Calendar is fiction.
2. **§26.5 ban: “pure recall” until P0-1** — **SHIPPED** (#1869 pure-by-default; W2-A3 **0.93**). Ban must unlock or rephrase to “legacy sync opt-in only.”
3. **§26.5 ban: “secure-by-default attestation” until P0-3** — **SHIPPED** store-path (`require_agent_attestation_enabled` default true, #1751). Federation data-lane still claimed — ban should **narrow**, not remain absolute.
4. **§26.6 G29 “no write-path screening”** — **SHIPPED** (`secret_screen`, default `refuse`, #1821). Ban “secrets screened” is **stale**.
5. **§26.6 G30 “no tombstone / incomplete forget”** — **core SHIPPED** (`forget_tombstones` v71). Residual risks (HNSW/DLQ edge cases) may remain; absolute “no tombstone” is **stale**.
6. **§26.4 “no cryptographic model-family attestation exists yet (#1719)”** — **partially false**: v78 `model_attestations` + `model_family` normalizer exist; **field stamp + enforce** still open (W2 **0.34**).
7. **§24 ship-state** still narrates **v0.7.1** (74 tools, schema 57, 25 hooks) with a parenthetical “advanced to 78/101/27” — readers who stop at the freeze miss v0.8–v0.9 spine.
8. **§11.4 “`crate::db` alias retires at v0.8.0”** — `pub use storage as db` **still in** `src/lib.rs`.
9. **§11.4 cutline “defer signed signals / model signature chain to v0.9”** — signals MCP + tables are in tree; model path is **TOFU substrate**, not the full AlphaOne release-key evidence packet.
10. **§23 as “the” v0.9 plan** — G2 capacity/hard-fail + G4 dim-match + ns allowlist landed **without** sqlite-vec/vectorlite swap; §23 DoD language overstates current index identity.

---

## MISSING COMMITS (still open vs ROADMAP commitments)

### A. §23 Vector index substrate (largest structural miss vs §11.5/§23)

| Commitment | Code reality |
|---|---|
| sqlite-vec primary + vectorlite + builtin `hnsw_rs` | Still **in-memory `instant-distance`** behind `VectorSearchIndex` |
| `--index=auto|sqlite-vec|vectorlite|builtin` | **Absent** |
| `IndexInserted|Deleted|Rebuilt|MigrationCompleted` signed events | **Absent** |
| `embedder_registry` / `migration_state` / `migrate-index` / `memory_reindex` | **Absent** |
| G3 cold-start disk persistence | **Open** (rebuild-from-DB still) |
| Five-channel release bundling extension libs | **N/A until backends exist** |

**Partial credit (not §23 DoD):** `AI_MEMORY_VECTOR_INDEX_CAPACITY` / `HARD_FAIL` (G2), `REQUIRE_DIM_MATCH` (G4), `VECTOR_NAMESPACE_ALLOWLIST`, async double-buffer rebuild, `Box<dyn VectorSearchIndex>` seam only.

### B. §11.5 product items

| Item | Status |
|---|---|
| Skill memories first-class (`parameters_schema`, version, …) | **Partial** — #1865 validation + version chain; not full `tier=long,namespace=_skills/<id>` formal type story |
| Function calling in `llm.rs` | **Partial SHIP** — #1866 `generate_with_tools` / `ToolCalls` |
| Cross-encoder default-on, fail-loud `mode:"degraded"`, no silent lexical fallback | **MISSING** — still logs + **lexical fallback** |
| #1706 shadow recall-utility | **SHIP** (`backfill_recall_outcomes`) |
| #1707 live utility term | **MISSING** (conditional, correctly gated) |
| Streaming MCP tool responses | **MISSING** |
| G7-step2 Bert pool ~CPU count | **SHIP** (`resolve_reranker_pool_size`, #1867) |

### C. §11.4 residual / deferred

| Item | Status |
|---|---|
| Pillar 1 actions/leases/DAG/signals/checkpoints/routines/frontier | **SHIPPED** MCP surface |
| Pillar 2 typed cognition (Goal/Plan/Step + kinds) | **Mostly SHIP** (13 kinds) |
| Pillar 2.5 compaction + curator | **SHIP** (opt-in flags) |
| Pillar 3 full CRDT four-primitive + R6 consensus 4-of-5 | **Partial** — `PnCounter`/`OrSet`/merge + version_vector; not full G-Counter/LWW product + consensus truth |
| Pillar 4.A–C code | **SHIP**; 4.D envelope **harness only** (operator measure) |
| Hooks: 10 coordination events | **2/10** (`PreSignalSend`/`PostSignalAck`) — ROADMAP admits; rest **MISSING** |
| §11.4.C vLLM “first-class load-bearing §2.6” | **Alias SHIP** (`BACKEND_VLLM`); **not** structural bias-displacement |
| §11.4.D model signature verification chain (release-key, reject digest, evidence packet) | **OVERPROMISED vs TOFU table** — v78 is loader/operator TOFU, ~40% cap (W2) |
| §11.4.H L3 watcher / SDK shims / IDE paths | L3 **MISSING**; H.4 transcript-classify **opt-in ship** |
| LongMemEval Gemma 4 refresh / plugin marketplace | **Not verified in-tree** (docs/marketplace absent) |

### D. §25–26 P0 / TRACT

| Gate | Code |
|---|---|
| P0-1 recall purity | **SHIP** under defaults |
| P0-2 D3-012 substrate | **SHIP** v78 |
| P0-2 D3-021 enforce | **Partial** — pure core + dual-backend; mode default **off**; production stamp hole (W2) |
| P0-2 D3-031 / D3-060 | **MISSING** |
| P0-3 agent attest flip | **SHIP** store-path |
| P0-4 RQ-10 epoch consumer | **Partial** — `SignableEpochManifest` / EpochAdvance types; schema git-untracked / no full wired consumer; “RQ-01 shipped” still **correctly banned** |
| §26.3 durability-503 | **OPEN** — `create.rs` still “quorum gates 201 vs 503” after local durability |
| L3 RQGM external | **HELD** (grep ban) |

### E. Perfect-system gaps ROADMAP under-commits (vs W2 top-10)

Capture L3, witness/cause/role **require** defaults, UUID‖cid dual-truth / `append_only` OFF, PE-1 default Off, federation content-sig opt-in, physics floor preset, refusal-as-content — **called in W2 handoff**, only partly named in §11.4.H / §25. These are **missing toward perfect**, not always missing *as dated ROADMAP line items*.

---

## SHIPPED (credit — do not re-litigate)

- Coordination substrate tools + tables (actions, signals, checkpoints, routines).
- Admission control, AGE deferred projection, PgBouncer templates.
- Pure recall + fold job; agent-attest default ON; secret refuse; forget tombstones.
- Additive cid + lineage DAG machinery; revisions under `append_only` flag.
- Multi-vendor LLM/embed; vLLM alias; vendor-literal gate.
- Model attestation **table** + write-quorum pure functions.
- Claims discipline **spirit** (§25.6 / §26.5 theater bans) still correct for **2.6 enforce / epoch closure / RQGM / BLAKE3-primary**.

---

## OVERPROMISED (claim shape → code)

| Claim shape | Reality |
|---|---|
| Signals: “Sender cannot repudiate… procurement-defensible” | Requires enrolled keys + ops; not default non-repudiation (W2 2.5 **0.63**) |
| vLLM closes §2.6 at federation scale | Backend alias; decorrelation mode **off**; no family stamp on reflect |
| §23 = v0.9 vector story complete | In-memory HNSW + knobs ≠ three backends |
| “Bias-displaced by architecture” (§24 close) | W2 **0.34**; architecture **target**, not hold |
| Kill-test: pure recall + decorrelation at v0.9.0 | Pure recall **yes**; decorrelation enforce **no** |
| Model attestation “every signed_events row carries model_digest” (§11.4.D table) | Not the v78 TOFU design |

---

## Crosswalk — ROADMAP eras vs code

```
§11.4 v0.8 plan  ──► mostly IN TREE early (schema 59–78 continues past “vN”)
§11.5 v0.9 plan  ──► partial early ship + §23 still OPEN
§11.6 v1.0       ──► correctly FUTURE (mdns, E2E enc, OTel, portability, audit firm)
§11.7 horizon    ──► OK as forever backlog; embedders partially done (#1598)
§23 DoD          ──► NOT met → cannot mint “§23 SHIPPED”
§24 net          ──► strategic anchor OK; ship-state STALE
§25 RQ pathway   ──► mechanism selection OK; P0 spine half-green
§26 TRACT grade  ──► A−/C+ era grade; W2 lifts pure-recall/cid → data-model C+/B−
                     but ROADMAP text not updated to W2
```

---

## KILLER_OBJECTION

**A roadmap that freezes TRACT bans and v0.7 ship counts while the binary has already flipped P0-1/P0-3 and added v78 attestation trains two failure modes at once:** (1) engineers re-implement shipped work or keep “banned” language on true properties; (2) planners treat §23’s full three-backend DoD as the definition of “v0.9 done” while marketing may already say v0.9 from other spine work — **version identity splits from vector-substrate identity**. Perfect-endpoint distance cannot be measured from a document whose ban list and calendar are off-by-one major spine.

---

## TOP_RISK

**Procurement / release-note drift:** mixing (a) honest anti-2.6 theater with (b) stale “pure recall banned” and (c) §23 aspirational DoD produces **either false humility (undercount) or false completeness (overcount)**. Secondary: durability-503 still open while trust-spine grades sound “A−”; operators equate green `verify_audit_trail` + model_attestations with held §2.5/§2.6 (W2 TOP_RISK compound).

---

## VOTE

| Motion | Vote |
|---|---|
| ROADMAP §11.4–11.7 + §23–26 is accurate SSOT for v0.9.0 distance | **NO** |
| Requires v0.9.0 **shipped/partial/open rebase** before W5 claims pack | **YES** |
| §23 three-backend DoD is open / blocking “vector substrate complete” | **YES** |
| Unlock §26.5 pure-recall + store-path secure-attest bans (narrow residual bans) | **YES** |
| Keep bans: decorrelation enforced · epoch closure · RQGM-in-src · BLAKE3-primary · kill-switch world | **YES** |
| Perfect endpoint attained because ROADMAP cadence reached “v0.9” | **NO** (align W2 **0/7**) |

**Chair-style one-liner:** *Rebase ROADMAP to code; keep anti-theater; finish or descope §23 honestly; do not grade perfect from frozen §26.*

---

## Recommended rebase checklist (non-binding; for W3/W5)

1. §11.4 → **SHIPPED matrix** with residual rows only.  
2. §11.5 → mark SHIP / PARTIAL / OPEN per item; drop Q1 2027 as “not started.”  
3. §23 → status **OPEN**; list G2/G4 knobs as interim, not DoD.  
4. §24 → replace v0.7.1 freeze with v0.9 surface counts + two-axis **W2** grade.  
5. §25.3 / §26.2 → tick P0-1, P0-3; P0-2 substrate vs enforce split; P0-4 partial.  
6. §26.5–26.6 → unlock pure recall, store attest, G29, G30 core; retain 2.6/epoch/RQGM/cid-primary bans.  
7. File or close durability-503 (§26.3) with current `create.rs` evidence.

---

*W3-A1 · &lt;350 lines · read-only assessment · no code changes*
