---
layout: doc
---
# Memory Portability Spec v2 — DRAFT (schema v78)

> **Status:** DRAFT, authored 2026-07-09 in the v1.0.0 development epic (#1940, #1944). Extends [Memory Portability Spec v1](v1.md) from its frozen v0.6.3.1 baseline to the **v0.9.0 GA substrate (schema v78)**. v1 defined a lossless *data* envelope for 7 record classes; the substrate has since added **signed / governance / lineage record classes** that v1 never mentions, so a v1 round-trip silently drops them. v2 closes that gap and adds the multi-implementation conformance requirements ROADMAP §11.6 commits for v1.0.
>
> **Relationship to the format freeze:** the signed record classes below (§V2-2) carry the byte layouts frozen in [`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`](../v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md). This portability spec defines how they cross the *export envelope*; that spec defines their *signed bytes*. Where they overlap, the format spec is authoritative for bytes and this spec is authoritative for envelope placement.
>
> **Source of truth for the schema:** the code (`src/storage/`, `src/store/postgres.rs`, `migrations/`). When this document and the code disagree, the code wins.

---

## V2-0. What changed since v1 (v0.6.3.1 → v78)

v1 exports: `namespaces, memories, links, archived, agents, entities, subscriptions`. Since then the substrate added record classes that are **not** in the v1 envelope and are therefore **dropped on a v1 round-trip** — several of them are the substrate's tamper-evidence and governance spine, so their loss is a silent integrity regression, not a cosmetic gap:

| Record class | Schema | Table | Why it must round-trip |
|---|---|---|---|
| Governance policies | — | `governance_rules` | Operator-signed L1-6 rules; a restore without them silently drops enforcement posture |
| Append-only revisions | v72 | `memory_revisions` | The G6 identity-only revision spine; losing it breaks supersession history |
| Forget tombstones | v71 | `forget_tombstones` | Signed erasure receipts; losing them lets forgotten rows resurrect via LWW re-push |
| Agent lineage | v76 | `agent_lineage` | Signed key-succession + (per #1949) custody-class + revocation; identity continuity |
| Model attestations | v78 | `model_attestations` | Loader/operator model-family provenance (D3-012); decorrelation evidence |
| Audit chain | — | `signed_events` | The V-4 cross-row hash chain; the whole attestation story |
| Content-id + lineage-cid | v74/v75 | `memories.cid`, `memory_links.{source,target}_cid` | Content-address identity + derivation lineage edges |

Plus per-row additions to already-exported classes: `memories` gains `cid`, `cid_genesis`, `lifecycle_state` (v64, incl. the v1.0 `quarantined`/`tombstoned` system values), and the epistemic-kind additions (`told`/`instruction`/`intervention`) + `kind_provenance` (v79, per #1945).

---

## V2-1. Conformance levels (extends v1 §1)

- **L1 — Data portable** (v1 baseline): the 7 v1 classes round-trip losslessly. Unchanged.
- **L2 — Integrity portable** (NEW, v2): additionally, all signed classes in §V2-2 round-trip **with signatures byte-preserved and re-verifiable at the destination** — a conforming importer MUST NOT re-sign; it preserves the original signed bytes so the V-4 chain and every per-row signature still verify. An L2 export whose signed bytes fail re-verification at import is non-conformant.
- **L3 — Governance portable** (NEW, v2): additionally, `governance_rules` + the operator-key trust anchors round-trip so the destination reconstructs the same enforcement posture.

**Multi-implementation requirement (ROADMAP §11.6, NOT relaxed):** v2 conformance requires **≥2 independent non-Rust reference reader implementations** that verify (not merely parse) an L2 export against the CC0 conformance corpus (#1837). "Parse" is insufficient — a conforming reader must re-derive the signed bytes and check the signatures with no ai-memory dependency. (The cross-family adjudication explicitly refused C6's relaxation to ≥1.)

---

## V2-2. New signed record classes (envelope placement)

Each rides the frozen format-spec byte layout; this section defines only its envelope array + the preservation rule. All are **optional envelope arrays** (omit if the table is empty) but **required at L2 if present in the source**.

### V2-2.1 `signed_events[]` — the audit chain
- Columns: `sequence` (int, the global-monotonic rank), `prev_hash`, `payload_hash`, `cause_hash` (v73, nullable — present-only), `sig` (nullable on the unsigned daemon), `signed_by`, `event_type`, `created_at`, and the record body.
- **Preservation rule (L2):** `sequence`, `prev_hash`, `cause_hash`, and `sig` are byte-preserved; the importer re-runs `verify_audit_trail` and the export is conformant only if the chain verifies end-to-end (monotonic sequence, hash-linked, signatures valid where present). Tail-truncation detection requires the off-table witness (§V2-2.6).

### V2-2.2 `memory_revisions[]` — append-only spine (v72)
Identity-only revision leaves (supersede/erase/consolidate). Signed; byte-preserved; the `revision_leaf_signable_bytes` must re-verify at import.

### V2-2.3 `forget_tombstones[]` — signed erasure receipts (v71)
Identity + time + signature (no content fingerprint). **Load-bearing for erasure correctness:** the destination's federation receive path checks these before accepting an inbound write, so dropping them on restore re-opens the resurrection hole. Byte-preserved.

### V2-2.4 `agent_lineage[]` — key succession + custody + revocation (v76, extended by #1949)
One signed record per `(agent_id, epoch)`: predecessor-signed succession, plus (per the #1949 decision) the `custody_class` value and `LineageReason::Revocation` records. Byte-preserved; `verify_lineage` must reconcile against the witness set at import. ⚠️ Carries the honest caveat: `custody_class` is OSS-refusal-attested, not hardware-attested, and MUST NOT become a cross-host trust input on import.

### V2-2.5 `model_attestations[]` — model-family provenance (v78)
Write-once TOFU records `(provider, model_ref, model_family, agent_id)`. `agent_id` is `NOT NULL DEFAULT ''` (keeps the UNIQUE-TOFU constraint backend-identical). Preserve verbatim; do not re-attest on import.

### V2-2.6 `governance_rules[]` + trust anchors (L3)
Operator-signed rule rows + the enrolled operator/witness/recorder/judge/stopper **public** keys (never private). The importer verifies each rule's operator signature; an unverifiable rule is dropped with a loud WARN, never silently imported. Private keys NEVER cross the envelope (mirrors the v1 §6.7 secret-stripping rule for subscriptions).

---

## V2-3. Per-row additions to v1 classes

- **`memories[]`** gains: `cid` (TEXT `b3:…`), `cid_genesis` (BYTEA, NULLed on erasure), `lifecycle_state` (v64; the v1.0 system values `quarantined`/`tombstoned` are export-visible but a conforming importer applies the §6-fail-closed visibility allow-list so a quarantined row is not surfaced post-import), `kind_provenance` (v79). The `memory_kind` vocab may include `told`/`instruction`/`intervention` (v1.0). **cid preservation:** `cid` is preserved verbatim (it is content-derived and receiver-recomputable — an importer MAY recompute and MUST match, or WARN under `AI_MEMORY_CID_ENFORCE`).
- **`links[]`** gains: `source_cid`, `target_cid` (v75 lineage-cid mirror) — preserved so a lineage traversal resolves stable node identity even after an endpoint is tombstoned.

---

## V2-4. Embeddings + indexes are disposable, embedder-tagged caches (R72)

Extends v1 §4. **Embeddings and any ANN/vector index are NEVER the record of truth** — they are disposable caches rebuildable from `memories.content` under a named embedder. v2 requires:
- Every exported embedding carries an **`embedder_tag`** = `{model, dim, backend}` (e.g. `google/gemini-embedding-2 / 768 / openrouter`) so an importer knows whether to reuse or re-embed.
- A conforming importer MAY drop all embeddings and rebuild; the acceptance bar (R72) is **recall@10 within 5% absolute of baseline** on a pinned eval set after a different-embedder rebuild.
- The index itself is never exported as authoritative; only the embedder tag + the source content are.

---

## V2-5. Round-trip conformance test (NEW)

The v1 spec promised but never shipped a round-trip test. v2 requires a CC0 conformance corpus (#1837) exercising: L1 data round-trip; L2 signed-class byte-preservation + re-verification; L3 governance round-trip; the embedder-swap recall bar; and the fail-closed visibility of imported `quarantined`/`tombstoned` rows. Each of the ≥2 non-Rust readers runs the corpus airgapped.

---

## V2-6. Migration + versioning

The envelope carries a `spec_version: "2"` field. A v2 importer reading a v1 envelope treats the missing signed arrays as "source predates integrity export" (L1-only, WARN). A v1 importer reading a v2 envelope ignores unknown arrays (v1 §3.3 forward-compat rule) — so a v2 export degrades to L1 on a v1 reader without error, but loses integrity classes (documented, expected).

---

*Draft — authored 2026-07-09 (Fable window) for #1944. Completes the §11.6 v1.0 commitment: Spec v2 @ v78 + ≥2 non-Rust readers + round-trip conformance. Byte layouts for the signed classes are authoritative in the format-decisions spec; this document is authoritative for envelope placement + conformance levels. Ship-law escalation routes through the #1171 panel (#1967).*
