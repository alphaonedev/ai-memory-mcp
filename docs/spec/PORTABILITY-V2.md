---
layout: doc
---
# Memory Portability Spec v2 (schema v80)

> **Status:** FINAL for the v1.0.0 development epic (#1940, #1944) — finalized 2026-07-12 from the 2026-07-09 draft (`v2-draft.md`, retired). Extends [Memory Portability Spec v1](v1.md) from its frozen v0.6.3.1 baseline to the **v1.0.0-dev substrate (schema v80)**. v1 defined a lossless *data* envelope for 7 record classes; the substrate has since added **signed / governance / lineage record classes** that v1 never mentions, so a v1 round-trip silently drops them. v2 closes that gap and adds the multi-implementation conformance requirements ROADMAP §11.6 commits for v1.0.
>
> **Relationship to the format freeze:** the signed record classes below (§V2-2) carry the byte layouts frozen in [`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`](../v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md). This portability spec defines how they cross the *export envelope*; that spec defines their *signed bytes*. Where they overlap, the format spec is authoritative for bytes and this spec is authoritative for envelope placement.
>
> **Conformance corpus:** the CC0 corpus + reference readers live at [`conformance/`](../../conformance/README.md) (#1837); the plain-English decoder-in-archive is [`conformance/ROSETTA.md`](../../conformance/ROSETTA.md) (#1835).
>
> **Source of truth for the schema:** the code (`src/models/`, `src/storage/`, `src/store/postgres.rs`, `migrations/`). When this document and the code disagree, the code wins. Counts cited below are pinned to named consts (`Memory::FIELD_COUNT`, `MemoryLinkRelation::COUNT`, `CURRENT_SCHEMA_VERSION`) so the docs-vs-SSOT gate can police drift.

---

## V2-0. What changed since v1 (v0.6.3.1 / schema 17 → schema 80)

v1 exports: `namespaces, memories, links, archived, agents, entities, subscriptions`. Since then the substrate added record classes that are **not** in the v1 envelope and are therefore **dropped on a v1 round-trip** — several of them are the substrate's tamper-evidence and governance spine, so their loss is a silent integrity regression, not a cosmetic gap:

| Record class | Schema | Table | Why it must round-trip |
|---|---|---|---|
| Governance policies | — | `governance_rules` | Operator-signed L1-6 rules; a restore without them silently drops enforcement posture |
| Append-only revisions | v72 | `memory_revisions` | The G6 identity-only revision spine; losing it breaks supersession history |
| Forget tombstones | v71 | `forget_tombstones` | Signed erasure receipts; losing them lets forgotten rows resurrect via LWW re-push |
| Agent lineage | v76+v80 | `agent_lineage` | Signed key-succession + (per #1949, v80) custody-class + revocation; identity continuity |
| Model attestations | v78 | `model_attestations` | Loader/operator model-family provenance (D3-012); decorrelation evidence |
| Audit chain | — | `signed_events` | The V-4 cross-row hash chain; the whole attestation story |
| Content-id + lineage-cid | v74/v75 | `memories.cid`, `memory_links.{source,target}_cid` | Content-address identity + derivation lineage edges |

Plus per-row additions to already-exported classes (§V2-3), including the v79 `kind_provenance` column and the v1.0 epistemic-kind vocabulary additions (`told` / `instruction` / `intervention`, #1945).

---

## V2-1. Conformance levels (extends v1 §1)

- **L1 — Data portable** (v1 baseline): the 7 v1 classes round-trip losslessly. Unchanged.
- **L2 — Integrity portable** (NEW, v2): additionally, all signed classes in §V2-2 round-trip **with signatures byte-preserved and re-verifiable at the destination** — a conforming importer MUST NOT re-sign; it preserves the original signed bytes so the V-4 chain and every per-row signature still verify. An L2 export whose signed bytes fail re-verification at import is non-conformant.
- **L3 — Governance portable** (NEW, v2): additionally, `governance_rules` + the operator-key trust anchors round-trip so the destination reconstructs the same enforcement posture.

**Multi-implementation requirement (ROADMAP §11.6, NOT relaxed):** v2 conformance requires **≥2 independent non-Rust reference reader implementations** that verify (not merely parse) the signed-record family against the CC0 conformance corpus (#1837). "Parse" is insufficient — a conforming reader must re-derive the signed bytes (re-encode-and-compare) and check the signatures with no ai-memory dependency. (The cross-family adjudication explicitly refused C6's relaxation to ≥1.) **Discharged at v80** by [`conformance/readers/reader.py`](../../conformance/readers/reader.py) (Python 3, stdlib-only) and [`conformance/readers/reader.mjs`](../../conformance/readers/reader.mjs) (Node ≥ 19, stdlib-only, WebCrypto Ed25519); their capability matrix — including the honest Python-stdlib signature-check limitation — is in [`conformance/README.md`](../../conformance/README.md).

---

## V2-2. Signed record classes (envelope placement)

Each rides the frozen format-spec byte layout; this section defines only its envelope array + the preservation rule. All are **optional envelope arrays** (omit if the table is empty) but **required at L2 if present in the source**. The frozen v2 signed-byte family itself (the CBOR-array records — `ai-memory/write/v2`, `ai-memory/subkey-cert/v1`, `ai-memory/peer-head-attestation-v1`, `ai-memory/equivocation-proof/v1`, `ingestion-v1` — and the reserved `ai-memory/recall-attestation/v1` tag) is specified in the format spec §1–§6 + Appendix A; its domain-tag registry is mirrored in `conformance/manifest.json` and human-decoded in `ROSETTA.md`. Signed bytes cross the envelope **hex- or base64-encoded verbatim**; an importer never re-canonicalizes them.

### V2-2.1 `signed_events[]` — the audit chain
- Columns: `sequence` (int, the global-monotonic rank), `prev_hash`, `payload_hash`, `cause_hash` (v73, nullable — present-only), `sig` (nullable on the unsigned daemon), `signed_by`, `event_type`, `created_at`, and the record body.
- **Preservation rule (L2):** `sequence`, `prev_hash`, `cause_hash`, and `sig` are byte-preserved; the importer re-runs `verify_audit_trail` and the export is conformant only if the chain verifies end-to-end (monotonic sequence, hash-linked, signatures valid where present). Tail-truncation detection requires the off-table witness (§V2-2.6).

### V2-2.2 `memory_revisions[]` — append-only spine (v72)
Identity-only revision leaves (supersede/erase/consolidate). Signed; byte-preserved; the `revision_leaf_signable_bytes` must re-verify at import.

### V2-2.3 `forget_tombstones[]` — signed erasure receipts (v71)
Identity + time + signature (no content fingerprint). **Load-bearing for erasure correctness:** the destination's federation receive path checks these before accepting an inbound write, so dropping them on restore re-opens the resurrection hole. Byte-preserved.

### V2-2.4 `agent_lineage[]` — key succession + custody + revocation (v76, extended by #1949 at v80)
One signed record per `(agent_id, epoch)`: predecessor-signed succession, plus (per the #1949 decision, schema v80) the `custody_class` value and `LineageReason::Revocation` records. Byte-preserved; `verify_lineage` must reconcile against the witness set at import. ⚠️ Carries the honest caveat: `custody_class` is OSS-refusal-attested, not hardware-attested, and MUST NOT become a cross-host trust input on import.

### V2-2.5 `model_attestations[]` — model-family provenance (v78)
Write-once TOFU records `(provider, model_ref, model_family, agent_id)`. `agent_id` is `NOT NULL DEFAULT ''` (keeps the UNIQUE-TOFU constraint backend-identical). Preserve verbatim; do not re-attest on import.

### V2-2.6 `governance_rules[]` + trust anchors (L3)
Operator-signed rule rows + the enrolled operator/witness/recorder/judge/stopper **public** keys (never private). The importer verifies each rule's operator signature; an unverifiable rule is dropped with a loud WARN, never silently imported. Private keys NEVER cross the envelope (mirrors the v1 §6.7 secret-stripping rule for subscriptions; see also §V2-5a).

---

## V2-3. The v2 `memories[]` / `links[]` shapes

### V2-3.1 `memories[]` — the 30-field Memory record

The v2 memory row is the serialized `Memory` struct (`src/models/memory.rs`; `Memory::FIELD_COUNT = 30` is the canonical count the mechanical field-count test pins). The 30 fields, in struct order:

`id`, `tier`, `namespace`, `title`, `content`, `tags[]`, `priority`, `confidence`, `source`, `access_count`, `created_at`, `updated_at`, `last_accessed_at?`, `expires_at?`, `metadata{}`, `reflection_depth`, `memory_kind`, `entity_id?`, `persona_version?`, `citations[]`, `source_uri?`, `source_span?`, `confidence_source`, `confidence_signals?`, `confidence_decayed_at?`, `version`, `lifecycle_state`, `cid?`, `valid_from?`, `valid_until?`

(`?` = optional/nullable, omitted from JSON when absent per the struct's `skip_serializing_if` attributes; `[]`/`{}` = array/object.) v1 §6.2 semantics carry over for the fields v1 already defined; the additions since v1:

- **`cid`** (TEXT, `b3:…`) — the BLAKE3 content-address over the cid-genesis six-tuple (v74). Preserved verbatim; it is content-derived and receiver-recomputable — an importer MAY recompute and MUST match, or WARN under `AI_MEMORY_CID_ENFORCE`.
- **`lifecycle_state`** (v64) — including the v1.0 system values `quarantined`/`tombstoned`, which are export-visible but a conforming importer applies the fail-closed visibility allow-list (format spec §6) so such a row is not surfaced post-import.
- **`memory_kind`** — the closed vocabulary now includes the v1.0 epistemic kinds `told` / `instruction` / `intervention` (#1945).
- **`version`** (v45) — the optimistic-concurrency counter; preserved so re-import doesn't reset conflict lineage.
- **`valid_from?` / `valid_until?`** (v79, #1834) — the claim-bitemporal VALID-time interval (RFC3339): the half-open `[valid_from, valid_until)` window over which a claim is asserted to hold, distinct from `created_at` transaction-time. Both nullable/unbounded; `valid_from` is IMMUTABLE after store while `valid_until` is updatable via `memory_update`. UNSIGNED, non-attested metadata — NOT part of the `SignableWrite` v2 envelope. **A conforming importer MUST preserve both as instants**: an importer coded to the pre-#1834 28-field shape silently DROPS the claim-validity interval, a data-loss defect — the interval is the only record of WHEN a backfilled or time-bounded claim is true. Since schema v86 (PR #2265) the substrate canonicalizes both values at every write boundary to the ONE fixed UTC rendering `YYYY-MM-DDTHH:MM:SS.ffffffZ` (microsecond precision, `Z` suffix), so a round-trip preserves the INSTANT exactly while the stored/re-exported rendering is the canonical form (a `+05:00`- or `Z`-rendered input re-emerges as canonical micros+`Z`).
- The Form-4/Form-5 provenance block (`citations`, `source_uri`, `source_span`, `confidence_source`, `confidence_signals`, `confidence_decayed_at`) and the v0.7 typed-cognition fields (`reflection_depth`, `entity_id`, `persona_version`).

Two **storage-internal companion columns** do not ride the struct but MUST cross an L2 envelope as sidecar fields on the memory record: **`cid_genesis`** (BYTEA; the signed genesis preimage snapshot — NULLed on erasure and NULL stays NULL) and **`kind_provenance`** (v79; `{declared, channel_derived, regex, llm}` — unsigned metadata recording *how* `memory_kind` was assigned). An L1-only exporter MAY omit them; an L2 exporter MUST NOT, because `cid_genesis` is what makes the cid receiver-verifiable without recomputation ambiguity.

### V2-3.2 `links[]`

The serialized `MemoryLink` struct: `source_id`, `target_id`, `relation` (closed vocabulary, `MemoryLinkRelation::COUNT = 9` variants at v80), `created_at`, plus the signed-link block `signature?`, `observed_by?`, `valid_from?`, `valid_until?`, `attest_level?`. Link signatures are byte-preserved at L2 like every signed class. The storage-internal **`source_cid` / `target_cid`** mirror columns (v75) MUST cross an L2 envelope as sidecar fields — they are what lets a lineage traversal resolve stable node identity after an endpoint is tombstoned.

### V2-3.3 cid/uuid dual identity (normative, from the #1943 ADR)

- **`id` (uuid) is the sole storage / FK / LWW-tiebreak authority.** Importers preserve it verbatim (v1 §5.1 unchanged) and resolve conflicts on `(updated_at, attest_rank, id)`.
- **`cid` is the sole signed content-identity authority.** It is never a storage key, never an FK, and never re-minted on import.
- Each identity question has exactly one authority; an implementation that keys storage on `cid` or signs `id` is non-conformant.

---

## V2-4. Export grammar (JSON + NDJSON)

The v2 envelope keeps v1 §3's JSON object shape with these changes:

- `spec_version: "2"` **replaces** v1's `schema_version: "v1"` stamp (the field `db_schema_version` still carries the integer storage schema, `80` at this spec's anchor — producers stamp whatever `CURRENT_SCHEMA_VERSION` they build against).
- The §V2-2 arrays are legal top-level members: `signed_events`, `memory_revisions`, `forget_tombstones`, `agent_lineage`, `model_attestations`, `governance_rules`, `trust_anchors`.
- All v1 required/optional members and their §6 semantics are retained.

**Single-document JSON** (v1-compatible framing): one UTF-8 JSON object, member order not significant, suitable for small/medium corpora.

**NDJSON streaming form** (NEW; for corpora too large to hold in memory): line 1 is a **header record** `{"record":"header", "spec_version":"2", "source":…, "exported_at":…, "db_schema_version":…}`; every subsequent line is one record `{"record":"<class>", …row fields…}` where `<class>` is a singular member name (`memory`, `link`, `namespace`, `archived`, `agent`, `entity`, `subscription`, `signed_event`, `memory_revision`, `forget_tombstone`, `agent_lineage`, `model_attestation`, `governance_rule`, `trust_anchor`). Records of one class need not be contiguous, but `signed_event` records MUST appear in ascending `sequence` order so a streaming importer can chain-verify without buffering. A file is either single-document JSON (first non-whitespace byte `{` and the object has `spec_version`) or NDJSON (first line parses as the header record); producers MUST NOT mix framings.

**Forward-compat (v1 §3.3 retained):** importers MUST preserve unknown members/fields and MUST reject an unknown `spec_version`. A v2 importer reading a v1 envelope treats the missing signed arrays as "source predates integrity export" (L1-only, WARN). A v1 importer reading a v2 single-document envelope ignores unknown arrays — a v2 export degrades to L1 on a v1 reader without error, but loses integrity classes (documented, expected).

---

## V2-5. Embeddings + indexes are disposable, embedder-tagged caches (R72)

Extends v1 §4. **Embeddings and any ANN/vector index are NEVER the record of truth** — they are disposable caches rebuildable from `memories.content` under a named embedder. v2 requires:
- Every exported embedding carries an **`embedder_tag`** = `{model, dim, backend}` (e.g. `google/gemini-embedding-2 / 768 / openrouter`) so an importer knows whether to reuse or re-embed.
- A conforming importer MAY drop all embeddings and rebuild; the acceptance bar (R72) is **recall@10 within 5% absolute of baseline** on a pinned eval set after a different-embedder rebuild.
- The index itself is never exported as authoritative; only the embedder tag + the source content are.

## V2-5a. Secret-screening + erasure obligations on export (normative)

- **Secrets never cross.** Stored `title`/`content` are already secret-screened at write time (`src/secret_screen`, mode-independent for the signed identity per `canonical_cid_preimage`); an exporter MUST NOT reverse or bypass screening, MUST strip subscription secrets (v1 §6.7), and MUST NOT export any private key material — daemon, witness, operator, or instance sub-keys. Only **public** keys ride the §V2-2.6 trust-anchor array.
- **Erasure survives export.** A row erased via the forget path has its `cid_genesis` NULLed and a signed tombstone minted; the exporter MUST carry the tombstone (§V2-2.3) and MUST NOT resurrect erased content from archives or snapshots into the envelope. An importer MUST apply tombstones before admitting rows (the same check its federation receive path runs).
- **Quarantine is not laundered.** `quarantined` rows export with their state intact; an exporter MUST NOT rewrite `lifecycle_state` to a visible value.

---

## V2-6. Round-trip conformance test

The v1 spec promised but never shipped a round-trip test. v2 requires a CC0 conformance corpus (#1837) exercising: L1 data round-trip; L2 signed-class byte-preservation + re-verification; L3 governance round-trip; the embedder-swap recall bar; and the fail-closed visibility of imported `quarantined`/`tombstoned` rows. Each of the ≥2 non-Rust readers runs the corpus airgapped.

**Shipped at v80:** the corpus (`conformance/`, generated + drift-gated by `tests/conformance_corpus.rs`) covers the signed-record byte family — profile decode, re-encode-and-compare, Ed25519 verify + mandatory-reject, and the self-contained equivocation proof — plus both non-Rust readers and the Rust integration test that drives them (`tests/conformance_readers.rs`). The V-4 chain fixture, the SubkeyCert→write two-link chain, and the lineage/revocation vectors ship as the `chain/`, `subkey_chain/`, and `lineage/` manifest groups. The **envelope-level L1/L2/L3 round-trip fixture** now ships too (#2030, `conformance/vectors/export/round_trip_l3.json`): an encoder-generated, deterministic single-document v2 envelope produced by `ai-memory export --full` (the #2006 exporter — the former "#1944 v1.x producer" blocker is discharged), round-tripped through the production importer with per-class byte-exact + re-verify assertions in `tests/conformance_export_roundtrip_2030.rs`.

---

## V2-7. Implementation status @ schema v85 (honest ledger)

This spec is normative for v1.0; the integrity-complete exporter/importer SHIPPED at v1.0.0 (#2006, vote `34bbf781`):

| Surface | Status |
|---|---|
| `ai-memory export` (default) | Emits `{memories, links, count, exported_at}` pretty JSON (`src/cli/io.rs::export`) — the memories carry all 30 struct fields, but the envelope lacks `spec_version`, the v1 metadata members, and every §V2-2 signed array. **The default `export` is NOT the portability path** — it is a memories + links CONVENIENCE view. As of #1944 (B_WARN de-silencing) it emits a stderr WARN plus additive in-payload markers (`export_scope="memories+links"`, `portability_complete=false`, `excludes=[governance, revisions, tombstones, lineage, attestations, signed_events, archived_memories, namespace_meta]`) so a pipe-to-file consumer learns the scope. **[#2490, v1.0.0]** `archived_memories` + `namespace_meta` joined that list (both were ALWAYS omitted — the marker simply did not say so), an additive `withheld` marker now carries the counts + class histogram of rows the confidentiality boundary dropped and rows whose bytes it altered, and the verb refuses a Postgres store / a non-existent database instead of conjuring one. The `{memories, links, count, exported_at}` shape itself is unchanged. |
| `ai-memory export --full` | **[#2006, v1.0.0]** Emits the full v2 envelope (`src/portability/emit.rs`): `spec_version="2"`, `db_schema_version`, and every §V2-2 signed array (`signed_events`, `memory_revisions`, `forget_tombstones`, `agent_lineage`, `model_attestations`, `governance_rules`, `trust_anchors`) byte-preserved (hex-encoded signature bytes). The `conformance_level` (L1/L2/L3) marker is COMPUTED from an in-export re-verify pass — a source whose audit chain is broken honestly downgrades to L1 — alongside a per-class `conformance_by_class`; `portability_complete` stays a bool, true iff L3 **AND nothing was withheld** (#2490 — it was computed from the chain re-verify alone, so an envelope could assert completeness over a corpus whose forbidden-class or quarantined rows the export boundary had dropped; it is now an AND). **SQLite deployments only** — like `backup` (#2444), `export --full` REFUSES when the resolved store is Postgres rather than conjuring an empty SQLite database and emitting a `count: 0` envelope wrapped around real bootstrapped `governance_rules` (#2490). A PARTIAL export exits `3` (distinct from a crash) after writing the artifact; `--expect-withheld <N>` is the ratchet for an acknowledged steady-state withholding. Trust anchors carry the enrolled role PUBLIC keys only. **[#2571, v1.0.0]** The envelope now ALSO carries the v1 §6.1/§6.4 classes v2 had never implemented despite §V2-4 claiming "all v1 members are retained": `archived_memories[]` (archived rows, the v1 §6.4 shape extended with the v49/#1025 atomisation/entity columns + v84/v87 `embedding_space`/`kind_provenance`; content crosses decrypted exactly like `memories[]`), `namespace_meta[]` (v1 §6.1 governance bindings — `standard_id`/`parent_namespace`), and `archived_memory_links[]` (the v70/#1771 archive-link snapshot). Archived rows cross the SAME confidentiality screen (`classify_memory` + `secret_screen::redact_memory_for_storage`) `memories[]` gets — a NEW closure, since `list_archive`/`restore_archived` are admin-authorization-gated only with zero content screening (#943) and `export --full` carries no such gate; withheld/redacted archived rows fold into the SAME `ExportWithholdLedger` the memories screen populates, so `portability_complete` honestly reflects an archived-row drop too. All three arrays are `#[serde(default, skip_serializing_if = "Vec::is_empty")]` and additive to the existing `spec_version="2"` shape (no version bump) — an OLD pre-#2571 export still imports on the fixed binary via serde defaults; a NEW export's unknown fields make a pre-#2571 binary's importer REFUSE via `deny_unknown_fields` (the same fail-closed posture every prior #2006 signed-array addition already has). The DEFAULT (non-`--full`) `export`'s `excludes` marker is UNCHANGED — it still lists `archived_memories`/`namespace_meta` as excluded, honestly, since #2571 scoped the fix to the documented "portability path" only. |
| `ai-memory import` | Default L1-grade (memories + links, validation, conflict disposition, agent-id restamping). **[#2006]** A v2 envelope (detected by `spec_version`) imports at L2/L3 via `src/portability/import.rs::import_full_envelope`, which is **FAIL-CLOSED + ALL-OR-NOTHING**: every class is staged inside ONE transaction, the imported audit spine is re-verified with `verify_audit_trail` BEFORE commit, and a malformed / tampered / truncated bundle (a broken hash link, a sequence gap, or detected tail-truncation) is REJECTED with the transaction rolled back — a rejected bundle applies **ZERO rows** (no partial apply). The signed classes are re-inserted byte-preserved (RAW inserts — the importer NEVER re-signs; `agent_lineage` `record_bytes` is recomputed byte-identically via the record's own canonical-CBOR encoder and its witnesses ride the `signed_events` array, so lineage is never re-witnessed), tombstones-before-admit, memories id-keyed idempotent, governance rules verify-or-drop, trust anchors advisory-only. **[#2571, v1.0.0]** `archived_memories[]` import REFUSES a row that would create illegal dual residency — the id LIVE at the destination under a GENUINE archive reason (the #2570 `in_place_edit` live-snapshot exception is always admitted) — counted `archived_memories_skipped_dual_residency`, never silently clobbering the destination's live row. **[#3150, v1.0.0]** The archived lane is NO LONGER a raw byte-preserved insert: a bundle is UNAUTHENTICATED input on EVERY lane, so `archived_memories[]` now runs the SAME three admission gates the live `memories[]` lane runs, in the same order — identity restamp (#2211; `metadata.agent_id` on an archived row is the ownership predicate `restore_archived_for_caller` gates on, so a bundle-chosen author decided who could promote the row back to LIVE), redact-before-attestation (#2353) plus destination-side attestation re-derivation (a wire `attest_level` is NEVER trusted; a presented-but-FORGED `write_signature` SKIPS the row, counted `forged_signature_skipped`), and the L1-parity `validate::validate_memory` (per-row skip + WARN, counted `invalid_skipped`). Archived authors are resolved in the SAME pre-transaction enrolled-key snapshot as live authors, so the in-bundle self-enrollment hole stays closed. `namespace_meta[]` import NEVER clobbers an existing destination binding (`ON CONFLICT DO NOTHING`) — an import must not silently override governance policy the destination operator already established — and **[#3151, v1.0.0]** a binding that was NOT applied because the destination's differs is no longer a silent drop: it is counted `namespace_meta_skipped_divergent` and carries a WARN. `archived_memory_links[]` import is an `INSERT OR IGNORE` with no endpoint-presence gate (the table carries no FK by design, unlike live `memory_links`). **[#3151, v1.0.0]** On ALL THREE #2571 lanes a suppressed insert is now PROBED rather than assumed: a BYTE-IDENTICAL survivor is an honest idempotent re-import (counted `idempotent_rows_already_present`, NOT reported as staged), and a DIVERGENT survivor leaves the destination's row in place, is NOT counted as staged, and is reported — `archived_memories_skipped_divergent` / `archived_memory_links_skipped_divergent` / `namespace_meta_skipped_divergent` plus a per-row WARN. Archived content is compared DECRYPTED, because the insert re-seals against the destination's at-rest policy with a fresh per-record DEK. This is the LIVE `memories[]` lane's divergence disposition and deliberately NOT a bundle refusal: two independently-running nodes hold different `in_place_edit` snapshots (#1725) under the same id as a matter of course, so a refusal would pin a repeat restore permanently red on a steady-state merge condition — the same objection-O9 reasoning that governs the import exit code. The write-once SIGNED lanes keep the #2209/#3149 refusal, because a conflicting erasure receipt or TOFU pin IS an integrity signal. |
| Forensic bundle (`export-forensic-bundle`) | Carries the crypto spine (signed events et al.) as a separate signed tar — an orthogonal signed-egress path. |
| Signed-record byte family | FROZEN + corpus-gated (this spec §V2-2, format spec, `conformance/`) |
| Non-Rust readers | SHIPPED (2: python3 + node, `conformance/readers/`) |

The full v2 envelope emit+import is shipped at v1.0.0 via `export --full` + the v2 importer (#2006), with an end-to-end byte-exact round-trip test (`tests/portability_roundtrip_2006.rs`). **Deferred to v1.x follow-ups** (tracked as their own issues): the NDJSON streaming framing (§V2-4) and the embedder-tag round-trip (§V2-5). The GA portability claim rests on Portability Spec v2 + the CC0 conformance corpus (#1837) + the two non-Rust readers + `ai-memory backup` (lossless SQLite `VACUUM INTO` — SQLite deployments only; it refuses a non-SQLite store rather than emitting an empty artifact, #2444) + now `ai-memory export --full` (**also SQLite deployments only**, and likewise refusing rather than emitting an empty artifact since #2490 — the qualifier belongs on BOTH verbs, and its absence here is what #2490 named); the default `ai-memory export` remains the scope-limited convenience view — do not claim the DEFAULT export round-trips the integrity spine.

---

*Finalized 2026-07-12 for #1944 at schema v80. Completes the §11.6 v1.0 commitment: Spec v2 + ≥2 non-Rust readers + conformance corpus (#1837) + decoder-in-archive (#1835). Byte layouts for the signed classes are authoritative in the format-decisions spec; this document is authoritative for envelope placement + conformance levels. Ship-law escalation routes through the #1171 panel (#1967).*
