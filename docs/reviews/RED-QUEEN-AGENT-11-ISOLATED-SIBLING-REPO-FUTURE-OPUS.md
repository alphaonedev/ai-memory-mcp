---
layout: doc
---

# Sibling Repo / External-L3 Future-Proofing (OPUS re-issue)

**Lens:** Sibling Repo / Future-Proofing — Opus re-verification of the Grok Agent-11 isolated run ([`RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE.md`](RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE.html), base `c85b9c56`)
**Author:** Claude Opus 4.8 (1M context)
**Re-verification date:** 2026-06-28
**Codebase:** `release/v0.8.0` @ `ead3da0c` (working tree)
**Method:** CodeGraph CLI (`/Users/fate/.grok/bin/codegraph`) + `rg`/`Read`/`git`. 7-agent adversarial red-team (Auditor 7 = sibling lens; Auditor 3 = checkpoint-vs-manifest).
**Paper:** [RQGM, arXiv:2606.26294](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al.). **Provenance:** surfaced by **Nick Jensen** ([X](https://x.com/howtoprompt__/status/2070824205663273175)).
**Crossroads cite:** `5-agent vote (4d3ea1c5)`.

---

## Structured verdict

| Field | Value |
|-------|-------|
| **VERDICT** | EXTERNAL L3 **hard line** holds; sibling scope (RQ-20..23) is right. **One correction:** RQ-01 is **drafted/untracked/no-consumer**, not "delivered/P0-done". **One open decision:** epoch boundary as net-new signed JSON **vs** bound to an attested `Checkpoint` → a genuine **T1+T4 crossroads** requiring a 5-agent vote before `git add`. |
| **CONFIDENCE** | **90%** (95% on dependency-direction cleanliness — grep-provable; 80% on the manifest-vs-checkpoint resolution) |
| **ASI_MOONSHOT_GRADE** | **B+** — pathway preserves the seven §2 properties; capped (from the prior A−) because the RQ-01 consumer is vaporware, the schema is untracked, and the decorrelation export the sibling needs does not exist |
| **TOP_RISK** | An untracked schema with no `src/` verifier drifts silently against the eventual L3 producer; "external L3" stays deployable fiction until an `EpochManifest` type + verifier land |
| **KILLER_OBJECTION** | Internal RQGM ossifies algorithm churn at the wrong layer; **all search churn must live in the sibling**, bound by a signed contract — but that contract is currently a JSON file no Rust code reads |

### Votes (re-confirmed)

| Q | Vote | Opus note |
|---|------|-----------|
| Q1 | YES principles · CUT full RQGM from `src/` | `rg -i 'rqgm\|epoch_manifest\|red.?queen' src/` = **0 hits** — clean |
| Q2 | HYBRID-as-contract; **L3 EXTERNAL hard** | dependency direction is grep-provable (below) |
| Q3 | Quorum + signed epoch artifact + shadow ledger + optional runner | artifact = manifest **bound to** an `EpochAdvance` Checkpoint (Auditor 3) |
| Q4 | v0.9 spine → curator L2 → `ai-memory-rqgm` sibling v0.9.1+ | RQ-01 = git-track **after** the checkpoint fork resolves |
| Q5 | §2.6 N≥3 quorum + epoch > internal RQGM | conditional on attested family + vote-independence (both unbuilt) |

---

## 1. Dependency-direction proof (the anchor claim — grep-provable, not asserted)

The load-bearing property of the whole proposal is that the substrate has **zero compile-time dependency on any sibling**. This is mechanically provable today:

- `rg -i 'rqgm|epoch_manifest|red.?queen' src/` → **0 hits, exit 1.** No crate, module, import, or fs-watch in `src/` references a sibling.
- `rg 'epoch_manifest|RQGM|evolutionary|genetic|fitness|co-evolv' src/` (production) → **0 hits** (corroborated in [`RQGM-…-OPUS.md`](RQGM-2606.26294-vs-v0.8.0-OPUS.html)).
- The only `epoch_manifest` artifact in the tree is `docs/contracts/epoch_manifest.schema.json` — docs-only, **untracked**.

**Conclusion:** `ai-memory → ai-memory-rqgm` has **no** compile dependency. The sibling depends on the substrate (reads exports); never the reverse. This clean one-directionality is the strongest part of the proposal and should lead any procurement framing.

---

## 2. Read surfaces the sibling consumes (verified reachable read-only)

| Surface | Reachable? | Evidence |
|---------|-----------|----------|
| `recall_observations` ledger | **✅ three-surface read parity** | CLI `ai-memory recall-observations` (`daemon_runtime.rs:459,1783`); HTTP `POST /api/v1/memory_recall_observations` (`handlers/route_1111.rs:266-305`, route const `routes.rs:57`); read fn `observations/mod.rs:239`. **Note:** the MCP *list* path uses the sqlite-only free-fn → split-brain vs the HTTP SAL path (defect **D-OPUS-7**). |
| Confidence shadow | **✅** | CLI `ai-memory calibrate confidence --from-shadow` (`cli/commands/calibrate_confidence.rs:5,63`); HTTP (`route_1111.rs:431-433`) over `confidence_shadow_observations`. |
| Decorrelation / dominance stats | **⚠ CURATOR-LOCKED (gap)** | `compute_producer_dominance`/`dominance_ratio`/`run_decorrelation_probe` (`curator/decorrelation_probe.rs:132,139,254`) run only inside the curator `--reflect` path (`cli/curator.rs:786`). **No CLI/HTTP/MCP read-only export exposes the `DominanceReport`.** |

**New deliverable (not in the prior doc) — RQ-20.1:** the sibling must either **recompute** `compute_producer_dominance` from the Reflection-kind corpus (reachable via `memory_recall`/list), **or** v0.9 must add a **read-only decorrelation export**. The prior doc glossed this — dominance verdicts are curator-internal today.

---

## 3. Write surface — signed-manifest-only (enforceable, no API leak path)

The sibling's **only** legitimate write product is an **unsigned `epoch_manifest.json` draft** that the operator signs out-of-band. This constraint is enforceable:

- Every substrate write is gated: memories/links via MCP/HTTP (quota + governance + attestation gates) or operator-run CLI; governance rules require operator Ed25519 (`ai-memory rules … --sign`, `governance/mod.rs:59`).
- There is **no fs-watcher, no untrusted-import daemon, no external IPC** that lands writes without a gated surface.
- The manifest `signature` is Ed25519 over `canonical_signed_bytes(manifest sans signature)` (`epoch_manifest.schema.json`), mirroring the forensic-bundle / governance-pack pattern — the sibling **cannot self-sign**.

**Residual caveat (OS-perm, not an API path):** the read surfaces live in a shared SQLite file; a sibling with raw filesystem access could read it (fine — one-directional) or even raw-write the DB (an OS-permission concern, not an API write path). The sibling **SHOULD** consume the read-only CLI/HTTP exports, never the raw DB.

---

## 4. Checkpoint-vs-manifest reconciliation (NEW — resolves the open fork)

The prior doc treated a net-new signed `epoch_manifest.json` as **the** contract. The 21-agent OPUS run raised a competing primitive: the attested `Checkpoint`. Auditor 3 (adversarial) resolved this as **complementary, not either/or** — correcting the OPUS-21 "duplication" framing:

- **The Checkpoint is a signed/frozen/federated/audited *decision* gate, but it attests a DECISION, not a payload.** Its resolution signature commits only to `{checkpoint_id, namespace, state, resolved_by, resolution, resolved_at}` and **deliberately excludes** `condition`/`metadata` (`identity/sign.rs:650-678`). So a Checkpoint row **physically cannot** carry a content-attested epoch payload.
- **The manifest carries — and signs — what a Checkpoint cannot:** `panel.slots[]` (N≥3 role/backend/model_family quorum), `policy_version`, `prior_epoch_id` supersession, `utility.frozen_within_epoch=true` + weights, and a `provenance.content_hash` the signature covers (`epoch_manifest.schema.json`). The manifest is genuinely **richer, not redundant**.
- **`ConditionType` is SAL-enforced, not a SQL CHECK** (`models/checkpoint.rs:13-32`), so adding `ConditionType::EpochAdvance` needs **no migration** — and `condition: serde_json::Value` (`:115`) can carry a manifest reference.

**Recommended v0.9 design (the union, cryptographically linked):**

```
  signed epoch_manifest.json  ── signs the WHAT ──►  panel · utility · policy_version · prior_epoch_id · content_hash
            │ provenance.content_hash
            ▼
  EpochAdvance Checkpoint      ── attests WHEN+WHO ──►  resolution = manifest content_hash (a SIGNED field)
            │                     reuses FED-RQ-01 transport (federated, fail-closed, CAS-applied) for free
            ▼
  V-4 epoch.manifest_applied   ── anchors the apply ──►  tamper-evident audit row (RQ-10)
```

This gets **epoch-freeze federation + audit** from the Checkpoint **and** **payload attestation** from the manifest — neither primitive alone provides both. **This is a T1+T4 crossroads** (public-contract shape + hard-to-reverse persisted layout): resolve it via a 5-agent vote **before** `git add`-ing the schema.

---

## 5. Corrected codegraph evidence (re-verified at `ead3da0c`)

| Finding | Prior cite | Re-verification |
|---------|-----------|-----------------|
| Stationary judge | `build_curator_llm @ cli/curator.rs:114` | **HOLDS ✓** (single resolver, one `OllamaClient`) |
| Decorrelation not in daemon | 0 hits in `daemon_runtime.rs` | **HOLDS ✓** (`rg -ic decorrelation src/daemon_runtime.rs` = 0; `--reflect`-only) |
| `enforce` inert | `decorrelation_probe.rs:272-280` | **HOLDS ✓** (`:272` `if mode==Enforce` → advisory degrade) |
| MCP hooks empty | `reflect_with_hooks(…, ReflectHooks::empty())` sqlite `843` / postgres `7906` | **HOLDS ✓** (both real; +a 3rd site `postgres.rs:14064`; the MCP-handler site is `mcp/tools/reflect.rs:496` — see [Auditor 1 reconciliation](RED-QUEEN-21-AGENT-VOTE-OPUS.html)) |
| Forensic `Manifest` ≠ epoch | `forensic/bundle.rs:151` | **HOLDS ✓** (tar-bundle index, not an epoch manifest) |
| **RQ-01 status** | "✅ delivered this run" | **CORRECTED → drafted, git-untracked, zero `src/` consumer** (`git status` `?? docs/contracts/`) |
| **Checkpoint primitive (new)** | — | `models/checkpoint.rs:109` (struct); `checkpoints/mod.rs:47-72` (`resolution_signable`/`verify_checkpoint_resolution`); MCP `mcp/tools/checkpoint.rs` |

---

## 6. `ai-memory-rqgm` sibling — minimum viable scope (RQ-20..23, preserved + extended)

**Repo:** `alphaonedev/ai-memory-rqgm` (SHOULD, v0.9.1+, not blocking v0.9.0 tag). Dependency: sibling → reads L1 exports; **no** `ai-memory → ai-memory-rqgm` compile dep (§1).

| Component | Responsibility | Must NOT |
|-----------|----------------|----------|
| Ledger reader | Pull `recall_observations` + confidence-shadow exports | Write memories without L1 MCP/HTTP |
| **Decorrelation recompute (RQ-20.1, NEW)** | Recompute `compute_producer_dominance` from the Reflection corpus (or consume a v0.9 read-only export) | Reach into curator internals |
| Panel breeder | Propose `panel.slots[]` for epoch N+1 | Mutate `RuleEngine` / governance DB |
| Manifest writer | Emit **unsigned** `epoch_manifest.json` draft | Self-sign (operator signs) |
| RQGM reference harness | Reproduce the paper loop against a fixture corpus | Ship inside `ai-memory` `src/curator/` |

---

## 7. Q4 pathway (Agent 11 lens, corrected)

**Phase 0 — Contract (Week 1):** RQ-02 (`RECURSIVE_LEARNING.md` L1/L2/L3 boundary), RQ-03 (`honest-limitations.md` addendum). **RQ-01 = git-track the schema *after* the checkpoint-vs-manifest fork resolves (§4)** — do NOT commit a schema the design may supersede.
**Phase 1 — v0.9 P0 (substrate + curator L2):** RQ-10 (`SignableEpochManifest` + V-4 `epoch.manifest_applied`), RQ-11 (decorrelation every cycle), RQ-12 (manifest panel), RQ-13 (epoch stamps); + the cross-cutting P0s (D3-012 family attestation, D1-001 MCP PreReflect, RQ-PARITY-01 curator unification, F-40 governance silent-disable, F-41 policy_version).
**Phase 2 — v0.9.1+ sibling:** RQ-20..23 reference harness (after the RQ-10..13 consumer exists); FED-RQ-02..05 federated manifest.

**CUT (reinforced):** RQGM population genetics in `src/`; `--rqgm` flag merging L2+L3; MCP tools for evolutionary search; marketing "implements Red Queen" / "co-evolving evaluators shipped".

---

## 8. Claims discipline

**Allowed:** "epoch-gated bias-displacement trajectory" · "optional exterior runner contract **spec** (drafted, untracked)" · "Red Queen-principles-aligned (~15% optimization-readiness)".
**Banned:** "implements RQGM" · "co-evolving evaluators shipped" · "decorrelation enforce" (v0.8.0) · "self-improving agent framework" · **"RQ-01 shipped" / "epoch manifest contract committed"** (it is untracked).

---

## One-sentence outcome (Opus re-issue)

> Adopt Red Queen **principles** in L1+L2; keep **all algorithm churn** in **`ai-memory-rqgm`** (dependency direction grep-provably clean); bind layers with a **content-signed epoch manifest pinned to an `EpochAdvance` Checkpoint and anchored to the V-4 chain** — and correct the record: **RQ-01 is drafted-untracked-no-consumer, the decorrelation export the sibling needs does not yet exist, and the manifest-vs-Checkpoint shape is an open T1+T4 vote**, not a settled contract.

---

**AI involvement:** Opus 4.8 re-verification of the Grok Agent-11 isolated run; 7-agent adversarial red-team (Auditors 3 + 7 lenses). Operator directive 2026-06-28 (provenance: Nick Jensen). Crossroads cite: `5-agent vote (4d3ea1c5)`.
