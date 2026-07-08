# W2-A5 — Data Model / CID / Lineage / Append-only

**Agent:** W2-A5 (Data Model / CID / Lineage / Append-only Assessor)  
**Axis:** TRACT data-model (G6, G8, G13-mem)  
**Peers:** W1-A6 epistemics · W1-A7 synthesis (S4)  
**Date:** 2026-07-08  
**Anchors:** `src/identity/cid.rs`, `src/identity/lineage.rs`, `src/revisions.rs`, `src/models/memory.rs`, `src/models/link.rs`, schema v74–v76, `src/config.rs` flags  

---

## VERDICT

**Spine machinery shipped; constitution still dual-truth and default-mutable.**

v0.9.0 landed the three TRACT data-model scaffolds:

| Gap | Shipped surface | Production posture |
|---|---|---|
| **G8** | Additive BLAKE3 `cid` + `cid_genesis` (schema v74); mint on insert both backends; secret-screen mode-independent preimage; `verify_cid` partial-corruption check | **UUID remains sole PK/FK/LWW identity.** CID is a second name, not authority. `AI_MEMORY_CID_ENFORCE` default OFF = detect-and-log only; never refuses write/receive. |
| **G6** | `memory_revisions` identity-only leaves (`RecordKind` ×7); gated by `AI_MEMORY_APPEND_ONLY` | **Default OFF.** Flag-ON is capture-then-compact on the *same UUID* (in-place UPDATE + `in_place_edit` archive + SUPERSEDE leaf) — not new-id SUPERSEDE. Hard `DELETE` still exists when OFF. |
| **G13-mem** | `memory_links.source_cid`/`target_cid` (v75); P={`derived_from`,`reflects_on`,`derives_from`}; three-surface walk (MCP/HTTP/CLI); consolidate-tombstone path; P-wide chrono acyclicity | **Resolved default ON** (`lineage_dag=true` → tombstone-sources tracks ON). Unseeded process atomic stays OFF (test isolation). |
| **G13 identity** | `agent_lineage` table (v76); signed succession + `signed_events` witness | **Rotation-only; recovery VERIFY deferred; cross-host invisible; verdict-only** (`attest_write` still flat `agent_pubkey`). |

**Memory shape:** 28-field `Memory` (`FIELD_COUNT=28`) + 13 `MemoryKind` tags + `LifecycleState` incl. `Tombstoned` + Form-4/5 columns. Pure recall default (#1869) is the one fully flipped epistemic verb. Kind still **defaults Observation**; Form-4 provenance is **optional**, not a write-gate.

**Relative to W1-A6 “epistemically perfect enough” bar:** content-address *exists* (additive); SUPERSEDE-not-UPDATE *exists as opt-in COW*; pure RECALL *held*; confidence.basis *column exists, not mandatory truth*; lineage-on-consolidate *held when daemon seeds config*. That is **L3-BODY with a migration ladder**, not L1 Claim constitution. ROADMAP §26.5 ban on advertising “append-only” / “BLAKE3 identity” remains correct.

---

## CONFIDENCE

**0.84**

| Factor | Δ |
|---|---|
| Schema + mint + consolidate-tombstone + pure-recall code paths read | + |
| Defaults ladder (`append_only` false / `lineage_dag` true / unseeded atomics false) verified | + |
| W1-A6 / A7 S4 criteria explicit | + |
| Full mutation-site inventory under `append_only` not exhaustively re-enumerated this wave | − |
| Whether every production boot path seeds `set_lineage_dag` (daemon_runtime docs say yes; MCP-only edge cases) | − |

---

## SHIPPED

### G8 — content-id (schema v74, #1825)

- Preimage: `memory-cid-v1\0` ‖ `agent_id` ‖ `namespace` ‖ `screen(title)` ‖ `kind` ‖ `created_at` ‖ `SHA256(screen(content))` → outer `b3:<hex>` (`src/identity/cid.rs`).
- `cid_genesis` stored for re-verify; **NULLed on Forget** (anti confirmation-oracle); `cid` retained.
- Genesis mint at store/reflect/consolidate/capture paths (sqlite + postgres).
- Honest claim-scope in module docs: **partial corruption only**, not at-rest forgery-evidence (consistent dual-column rewrite verifies clean). Unforgeable path deferred to keyed/`SignableWrite` binding.
- Owner/`confidence`/embeddings **not** in preimage (correct TRACT split); kind+content+agent+ns+time **are**.

### G6 — append-only spine (#1823)

- `memory_revisions` signed identity-only leaves: SUPERSEDE / TOMBSTONE / FORGET / ARCHIVE / EXPIRE / EVICT / CONSOLIDATE.
- `emit_revision_leaf_if_enabled` hard-gates on `append_only_enabled()`; consolidate uses dual predicate `append_only || consolidate_tombstone_sources` (exactly-one leaf invariant).
- Flag-ON update path: archive prior under `in_place_edit` + same-id UPDATE + SUPERSEDE leaf (documented “path-a COW”).

### G13-mem — derivation lineage (#1859, schema v75)

- Edge cid mirrors at link-create time; walk returns `{id,cid,relation,depth}`; tombstoned ancestors included.
- Consolidate under tombstone flag: retain sources, `lifecycle_state=tombstoned`, navigable `derived_from` C→source, CONSOLIDATE leaf; OFF → hard-DELETE + non-navigable metadata only.
- Three-surface parity: `memory_lineage` / `GET …/lineage` / `ai-memory lineage`.

### G13 identity (#1828, schema v76)

- `agent_lineage` PK `(agent_id, epoch)` anti-equivocation; genesis/rotation/recovery reasons; recovery mint refused until v1.0.
- `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` default OFF (withhold).

### Envelope (supporting S4, not identity)

- 13 kinds (Observation…Step); 9 link relations; Form-4 citations/source_uri/source_span; Form-5 confidence_source/signals/decay; `version` optimistic concurrency; pure recall default.

---

## GAPS

1. **UUID authority** — FKs, federation LWW, every link endpoint keyed by UUID. CID equality is not the merge/continuity oracle (W1 T6 open).
2. **`append_only` default OFF** — production still silent in-place mutators + hard delete without revision leaves. Cannot claim G6 held.
3. **SUPERSEDE ≠ new Claim id** — COW keeps UUID; TRACT wants prior id immutable + new content-addressed unit + link. Archive snapshot is recovery aid, not public belief graph.
4. **CID not write-authority / not SignableWrite** — enforce is log-only; dual-column reforge passes; no keyed outer seal.
5. **Kind default Observation** — soft epistemics; unknown kinds dropped on parse (forward-compat) rather than refuse-on-write for perfect posture.
6. **Provenance optional** — Form-4 never required on ASSERT; confidence defaults `caller_provided`.
7. **agent_lineage incomplete** — no key-loss recovery; federation peers ignore chain; attest path flat.
8. **Contradiction conservation** (TRACT G7 sibling) — still outside this axis’s green; consolidate/autonomy can erase losers when tombstone path OFF.
9. **Doc drift** — `config.rs` still has stale “STEP 1 not wired” comments while storage consults the flag (honesty debt, not functional gap).
10. **TRACT 5-kind kernel mapping** — 13 tags exist; no mechanical projection to L1 Rosetta five (W1 T5).

---

## SCORE

### **data-model: 61 / 100**

| Component | Weight | Subscore | Note |
|---|---|---|---|
| G8 additive CID mint+verify+fed screen | 0.25 | 72 | Real preimage discipline; authority still UUID |
| G6 revision spine + default posture | 0.25 | 42 | Machinery high; default OFF + same-id COW caps score |
| G13-mem edge mirror + walk + tombstone consolidate | 0.25 | 78 | Best-held sub-axis under resolved boot defaults |
| G13 agent succession | 0.10 | 48 | Rotation-only advisory |
| Epistemic envelope (kind/Form4/5/pure-recall) | 0.15 | 58 | Vocabulary strong; gates soft; pure-recall helps |

**Band:** upper **C+ / low B−** on a 0–100 scale — consistent with ROADMAP §26.0 data-model **C+**, with measurable lift from v0.9 G6/G8/G13-mem *scaffolding* but not yet a re-grade to B. Do **not** average with trust-spine A−.

**Distance-to-perfect (W1-A6 ship bar):** ~0.55 remaining — flip append_only secure-default *or* make SUPERSEDE-new-id the only content mutator; promote cid (or cid‖sig) to continuity authority; write-gate kind+provenance; finish agent recovery + fed lineage.

---

## KILLER_OBJECTION

**Having `cid`, `memory_revisions`, and `lineage` columns is not holding content-addressed, append-only memory.**

If UUID stays LWW/FK truth, `append_only` stays OFF, and updates overwrite the live row, a successor model rehydrates a **mutable diary with optional digests**, not a reconstructible Claim trajectory. That is false continuity: the substrate *looks* content-addressed in capabilities banners while federation and operators still treat random UUIDs as “the same belief.” Advertising “BLAKE3 identity” or “append-only spine” under current defaults is CLAIMED ≠ ATTESTED — banned by §26.5.

---

## TOP_RISK

**Dual-identity freeze + default-mutable ops → epistemic laundering under consolidate/reflect.**

Operators see `lineage_dag` default ON and assume derivation is immortal; a process that never seeds config atomics, or turns tombstone OFF, hard-deletes sources; append_only OFF leaves no SUPERSEDE leaf; reflections mint prose without enforceable kind/provenance. Successor minds inherit smoothed UUID blobs. **Mitigation:** secure-default append_only (or refuse content UPDATE), cid-prefer merge/export, mandatory kind+basis on ASSERT, keep consolidate-tombstone non-optional when lineage is on, finish SignableWrite-bound cid.

---

## VOTE — UUID-primary vs BLAKE3-primary

| Option | Vote |
|---|---|
| Freeze UUID-primary forever; cid cosmetic | **REJECT** |
| UUID-primary + additive cid **as permanent dual-truth** | **REJECT as end-state** |
| UUID-primary + additive cid **as migration ladder only** | **ACCEPT current ship** |
| **BLAKE3-primary (content‖provenance) as constitutional identity; UUID as local cache/FK convenience** | **ADOPT target** |
| Content-hash without provenance in preimage | **REJECT** (origin-blind) |

**Binding conditions for target:** preimage keeps kind+screened content digest+origin fields; owner outside hash; lifecycle transitions never rewrite prior unit’s content-address; federation equivalence prefers cid; optional Ed25519/keyed seal for forgery-evidence (CID alone remains partial).

---

## RATIONALE

W1-A6: perfect endpoint = one content-addressed Claim with kind tags, SUPERSEDE-not-UPDATE, pure RECALL, provenance+confidence.basis mandatory. W1-A7 folded that as **S4**. Code evidence shows v0.9 executed the **honest migration half** of G8/G6/G13-mem (parallel write path, revision table, lineage walk, pure recall) without claiming the constitutional flip.

Scoring 61 rather than mid-70s because **defaults define held properties** (A7 axiom 10: policy ≠ architecture). Lineage default ON is real progress; append_only OFF + UUID authority are load-bearing deficits. Scoring not lower than mid-50s because mint discipline, mode-independent screening, consolidate-tombstone path, and pure-recall default are structural, not prose.

**Honest marketing sentence for this axis:**  
*“L3-BODY memory store with additive genesis CIDs, opt-in revision leaves, and navigable derivation lineage when the daemon seeds config — not yet a content-addressed append-only Claim ledger.”*

---

*End W2-A5. Under 350 lines. Code-anchored. No grandeur register.*
