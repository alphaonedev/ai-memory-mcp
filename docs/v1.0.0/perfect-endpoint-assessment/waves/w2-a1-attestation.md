# W2-A1 — §2.5 Attested (cryptographic non-repudiation)

> **Agent:** W2-A1 (Attestation & Audit Spine Assessor)  
> **Date:** 2026-07-08  
> **Scope:** v0.9.0 shipped code vs perfect-endpoint axiom §2.5  
> **Wave-1 binding:** `w1-a7-synthesis.md` — 2.5 CONFIRM as lead ASI argument; incomplete postures (unsigned daemon, no external HWM, opt-in witness) ≠ “attested enough.”

---

## VERDICT

**STRUCTURALLY REAL, DEFAULT-POSTURE INCOMPLETE.**  
v0.9.0 ships a genuine multi-layer audit spine (V-4 hash chain, full-row daemon sigs #1925, forensic watermark, dual-chain witness, three-key role separation, cause-binding *machinery*, store-path agent attestation required-by-default, `model_attestations` TOFU). This is **not vapor**.  

It is also **not held as “attested cryptographic non-repudiation” under compiled defaults**: witness / cause-require / role-separation-require are **opt-in fail-open (withhold)**, cause_hash is written on **~1 production path** (sqlite reclassify only), daemon may boot **unsigned**, and tail-truncation resistance without enrolled keys + off-host sink is **detection theater against a co-resident DB attacker**. Weaker observers can verify *when operators enroll keys*; they cannot assume verification out of the box.

---

## CONFIDENCE

**0.86** — anchors are in-tree with line-level docs + dual sqlite/postgres verify twins; residual uncertainty is only “which call sites append `signed_events` on every write class” (not re-enumerated exhaustively).

---

## SHIPPED_PRIMITIVES (file:line)

| Primitive | Status | Anchors |
|---|---|---|
| **V-4 cross-row chain** (`prev_hash` + monotonic `sequence`) | **ON always** | `src/signed_events.rs:51–73`, `canonical_chain_bytes` / `verify_chain` / `append_signed_event` (~660–820, ~1990–2080) |
| **Full-row daemon signing** (not payload-only) | **ON when key enrolled** | `daemon_row_signing_input` `signed_events.rs:605–658` (#1925 CWE-347); head rewrite no longer silent under signed daemon |
| **Empty-sig / unsigned path** | **Explicit residual** | `with_daemon_signature` → `signature: None`, `attest_level=unsigned` `signed_events.rs:414–420`; boot `main.rs:156–159` “continuing unsigned” |
| **Tail truncation detection** | **Conditional** | `TruncationCheck` `signed_events.rs:1108–1138`; `verify_audit_trail` vs forensic watermark `1632–1667`; honesty block `1581–1625` |
| **Forensic JSONL watermark** | **ON when sink init** | `WATERMARK_INTERVAL=64` `governance/audit.rs:886`; stamp at append chokepoint `signed_events.rs:2042–2071` |
| **Independent dual-chain WITNESS** | **Opt-in keys; require OFF** | `WitnessCheck` `1141–1183`; `maybe_emit_audit_head_witness` `2073–2119`; `require_witness_enabled` default **false** `audit.rs:1120–1125` |
| **cause_hash column + present-only fold** | **Schema+verify ON; writers sparse** | v73 migration; `compute_cause_hash` `signed_events.rs:524–558`; `CauseBinding` `1185–1196`; `require_cause_binding` default **false** `audit.rs:1127–1132` |
| **Three-key role separation** (Recorder/Judge/Stopper) | **Opt-in; require OFF** | domains + loaders `audit.rs:1275–1324`; `RoleSeparationCheck` + `compute_role_separation_verdict` in `signed_events.rs`; `require_role_separation` default **false** |
| **Store-path agent attestation** | **Default REQUIRED (v0.9)** | `identity/attest.rs:20–90` `#1751`; forged always refuse; unsigned refuse unless `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` |
| **AttestLevel claimed vs agent_attested** | **Shipped** | `identity/verify.rs:153–197` |
| **`model_attestations` (v78)** | **TOFU substrate** | table bootstrap `storage/migrations.rs:391–405`; writers `storage/model_attest.rs:8–26` — `loader_observed` = process-lifetime self-report, **~40% coverage hard-cap**; `operator_signed` enroll path |
| **`verify_audit_trail` composite** | **Shipped both backends** | sqlite `signed_events.rs:1632+`; postgres twin `store/postgres.rs:9999+`; `is_clean` `1510–1548` treats **Unknown as clean** (withhold) |
| **Identity lineage (v76) + revisions spine** | **Adjacent** | witness covers `memory_revisions` head; lineage require-mode also default OFF |

**Schema ladder:** v73 cause → v74 cid → v75 lineage cid → v76 agent_lineage → v77 recall fold → v78 model_attestations (`CURRENT_SCHEMA_VERSION = 78`).

---

## GAPS

1. **Cause-binding coverage ≈ zero outside one path.** Grep shows production `compute_cause_hash(` call only at `store/sqlite.rs:1958` (reclassify). Postgres reclassify **explicitly** passes `None` (`postgres.rs:20520–20538`). Undo / federation / coordination audit paths document `None`. Require-mode must stay OFF or almost every real chain dirties — machinery ≠ load-bearing binding.
2. **High-assurance gates default withhold:** `AI_MEMORY_REQUIRE_WITNESS`, `REQUIRE_CAUSE_BINDING`, `REQUIRE_ROLE_SEPARATION` all default false (`audit.rs:1120–1324`). `is_clean` does not fail closed on missing witness/role/cause.
3. **Unsigned daemon residual** (`signed_events.rs:1603–1625`, `main.rs:156–159`): no per-row Ed25519 → whole-suffix rewrite + unsigned JSONL watermark dual-rewrite **undetectable** to co-resident attacker. Residual close = enrolled key **and** off-host `AI_MEMORY_LOG_SINK=syslog` (#86/#88–90) — policy, not default architecture.
4. **Tail truncation without external HWM:** in-table chain alone cannot see suffix DELETE; on-host forensic watermark is dual-atomic detection, not unconditional proof (`1581–1616`).
5. **`model_attestations` ≠ operation non-repudiation.** TOFU `loader_observed` is substrate self-report for §2.6 family quorum, not a per-write crypto proof of which model produced a cognition (`model_attest.rs:10–16`). Capability attestation still sibling / GA-inert (`AI_MEMORY_CAPABILITIES` off).
6. **Authority-lane vs data-lane asymmetry (S2 of 2.5):** store-path agent attestation flipped required; federation `FED_REQUIRE_WRITE_SIG` / `FED_REQUIRE_SIGNAL_SIG` remain permissive opt-in — data-lane relay can stay `claimed` under defaults (CLAUDE.md env #94/#96).
7. **Postgres parity lag on cause writers** — column round-trips; binding does not match sqlite reclassify.

---

## THEATER_RISKS

| Claim shape | Risk |
|---|---|
| “V-4 chain = full non-repudiation” | **Theater if unsigned.** Hash integrity ≠ authorship; docs already admit suffix rewrite under empty verifier. |
| “cause_hash closes causal non-repudiation” | **Near-theater.** Schema + verify exist; production binding is a single path; require OFF. Marketing “cause-bound audit” overclaims. |
| “Witness / three-key SoP shipped” | **Opt-in architecture, not default property.** Code is real; zero enrolled keys → `Unknown` → clean. |
| “model_attestations attests generations” | **Label theater if sold as crypto.** Loader TOFU + ~40% coverage; forgery of metadata alone blocked by S2 row probe, not by per-token signatures. |
| “require_agent_attestation = whole-system attested” | **Scope theater.** STORE direct path only; curator/admin + federation authorship paths use different models. |
| “verify-audit-trail green = tamper-proof” | **Withhold-as-clean.** Missing anchors do not dirty (`is_clean` Unknown paths). Green under default install is weak evidence. |

**Not theater:** V-4 middle-of-chain breaks, #1925 full-row bind under signed daemon, forged-signature always refuse, dual-backend verify twins, append-only `signed_events` writer discipline, watermark/witness emission at single append chokepoint.

---

## SCORE

### **63 / 100** for §2.5 Attested

| Band | Meaning |
|---|---|
| 0–40 | Prose / empty hooks |
| 41–60 | Partial primitives, easy default fail |
| **61–75** | **← here: real spine, defaults incomplete, sparse cause, unsigned residual** |
| 76–90 | Secure-by-default enrollment + cause-bound majority of ops + off-host HWM |
| 91–100 | Weaker observers verify without trusting host *or* operator discipline |

**Default posture contribution:** ~40 pts structural chain + agent-attest flip; high-assurance layers locked behind enrollment ≈ +23 for existence, not for held property.

---

## KILLER_OBJECTION

**An install with no witness key, no role keys, no agent-bound keys forced only by env opt-out in tests, and a missing/unseeded forensic sink can still print a “clean” audit trail while an on-host attacker rewrites an unsigned suffix — and `cause_hash` is almost never present to bind *why* a row exists.** Shipping the moonshot sentence “operations are cryptographically non-repudiable” from that posture is Federalist/attestation theater worse than a narrower honest claim: *“tamper-evident hash chain + optional multi-key anchors; non-repudiation requires enrolled keys + off-host watermark.”*

---

## TOP_RISK

**Default-clean verification under incomplete enrollment** — operators (and procurement) treat `verify_audit_trail` / exit-0 as proof of non-repudiation while `Unknown` witness/cause/role and unsigned daemon silently withhold the load-bearing checks. Secondary: sparse cause writers make `AI_MEMORY_REQUIRE_CAUSE_BINDING=1` unusable in production until binding is universalized.

---

## VOTE

**partial** — ready for a **v1.0 security audit as a concrete surface** (falsifiable primitives, dual backends, documented residuals), **not** ready to **pass** that audit as “§2.5 held under defaults.”

- **Y for audit engagement** (code is audit-grade).  
- **N for “attested enough for v1.0 property claim”** without secure-default flip on witness (or external HWM), universal cause binding on append paths, and hard refuse of unsigned daemon in production profiles.

---

## RATIONALE

Wave 1 froze §2.5 as the **lead ASI argument**: weaker observers verify stronger cognitions **without trusting them**. v0.9.0 built the right *stack* (chain → watermark → independent witness → role keys → agent attest → model family TOFU) with unusual honesty in comments (`signed_events.rs` CWE-354 / unsigned residual). Distance to the axiom is almost entirely **default posture + coverage**, not missing classes of primitive:

1. **Always-on integrity:** V-4 + sequence gaps + (when signed) per-row Ed25519 over full attribution — real.  
2. **Default authorship gate:** `#1751` store-path required attestation — real, scoped.  
3. **Independent anchors:** watermark + witness + role SoP — real engineering, **opt-in**.  
4. **Causal bind:** present-only fold is correct crypto design; **writers not generalized** → property not held.  
5. **Model attest:** supports §2.6, should not be counted as §2.5 operation non-repudiation.

**Distance (default install):** ~0.37 held / ~0.63 gap on a 0–1 Wave-2 scale (inverse of score band).  
**Distance (enrolled daemon key + witness + off-host syslog + agent keys + no unsigned opt-out):** jumps toward ~0.75–0.80 still short of perfect (cause sparse, capability sibling, federation data-lane permissive).

Honest one-liner for W5/W6:

> *ai-memory v0.9.0 provides a tamper-evident, multi-anchor audit spine for endpoint operations; cryptographic non-repudiation is operator-enrolled and incomplete by default — not a universal attestation of every cognition.*

---

*End W2-A1 · under 350 lines · no code changes.*
