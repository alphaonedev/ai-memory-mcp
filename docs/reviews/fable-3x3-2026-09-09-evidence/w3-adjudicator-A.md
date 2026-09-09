# Ballot — Adjudicator A, wave 3 (audit emphasis)

Tree: `<release-checkout>` at `495404d79`. Every line below was read directly with `sed`/`grep`; issue labels pulled live with `gh`. Read-only; nothing edited, filed, or run beyond reads.

## 1. Accepted corrections — applied faithfully?

| §9 accepted item | Revised text (quoted) | On tree | Ruling |
|---|---|---|---|
| W1-A `caller_provided` not `default` | A1b: "reports `confidence_source: caller_provided` regardless of its stored value (`ConfidenceSource` `#[default] CallerProvided`, `src/models/memory.rs:610-611`; mapper `.unwrap_or_default()` `:1195-1199`)" | `memory.rs:610-611` `#[default] CallerProvided`; `mod.rs:1195-1199` `.unwrap_or_default()` | APPLIED |
| W1-A A24 body range | "response bodies `:1090-1099` and `:1128-1136` omit it" | `admin.rs:1128-1136` is the JSON body, no `withheld` key | APPLIED |
| W1-A eight tag checkouts | A25: "all **eight** later checkouts … (`:103`, `:176`, `:417`, `:515`, `:655`, `:795`, `:987`, `:1042`)" | grep → exactly those 8; `needs.preflight.outputs.sha` referenced 0 times | APPLIED |
| W1-A fifteen call sites | §4: "appears at fifteen sites in fourteen files" | grep → 15 hits / 14 files | APPLIED |
| W1-A F1 → HTTP + pg `for_admin` | F1: "HTTP: `POST /api/v1/memory_export_reflection` (`src/handlers/route_1111.rs:699-716`), doc-comment 'Read-only; no caller-ownership gate' … pg arm constructs `CallerContext::for_admin("http:export-reflection")` (`:761-764`)" | `route_1111.rs:701-702` doc-comment verbatim; sqlite arm `:716` calls `handle_export_reflection` with no caller; `:763` `for_admin` | APPLIED |
| W1-A F2 MCP-only | F2: "(MCP-only; the HTTP twin `src/handlers/skills.rs:361` is `require_admin`-gated)" | `skills.rs:361` `skill_promote_route`, `:378` `require_admin(&app, &headers, "skill_promote")` | APPLIED |
| W1-A F11 `NORMAL` default | F11: "`DEFAULT_DB_SYNCHRONOUS = "NORMAL"` … `src/storage/connection.rs:550-558`" | `connection.rs:558` verbatim | APPLIED |
| W1-A/C `enterprise-fed` is a CI lane; 38/35 contexts | Standard §0.1 "The CI lane named `enterprise-fed` is `sal-postgres` … not a Cargo feature"; item 12 "38 declared … 35 live" | `required-contexts-release.txt` 38 non-comment lines | APPLIED |
| W1-B authority undercount | A15 lists #3364 #3386 #3506 #3419 #3406 #3124 #3200 #3204 #2502 | all OPEN, labels as stated | APPLIED |
| W1-B #2437 second cert-blocker | §0 reason 5; §6.1 row | live `cert-blocker, ga-blocker` | APPLIED |
| W1-B `recall_observations` write | A11: "`record_recall_observations` `:773`, called `:1365`, `:1402`, `:1484`… pinned by `tests/recall_purity_p01.rs:9` and `:397-399`" | all five lines verbatim | APPLIED |
| W1-B AGE 1.8.0 vs 1.7.0 | A20: "certified pin is now AGE **1.8.0** (`deploy/docker-1461/provision/lib.sh:113`, apt `1.8.0~rc0`)" | `lib.sh:113` `1.8.0~rc0-2.pgdg13+1` | APPLIED |
| W1-B #2431 regressed | A1: "#2431's validity filter reads `valid_from`/`valid_until` off the mapped row (`recall.rs:756-757`), which the recall SELECT omits" | `recall.rs:756-757` `mem.valid_from/valid_until`; SELECT `:8220-8226` has no `valid_*`, `version`, `cid`, `lifecycle_state` | APPLIED, and this is the load-bearing fact behind reason 1 |
| W1-B hard-coded path; Appendix A key; N16/N17/N20 alignment | F6 `REPO = "<operator-path>"`; Appendix A present; N16 "five remaining", N17 E3-only, N20 soak-only | — | APPLIED |
| W1-C `postgres.rs:648`; A27b `:107-111` | A3 and A27b as stated | `postgres.rs:648` `MEMORY_READ_COLUMNS`; `postgres_parity.rs:130` uses it | APPLIED |
| W2-A A1b reachability | "the HNSW branch returns at `:20063` whenever a vector index or precomputed hits exist (`:19876`); the linear scan runs only when no index was built" | `mod.rs:19876` `if precomputed_hnsw_hits.is_some() \|\| vector_index.is_some()`, `:20063` `return Ok(…)`, `:20066` "Fallback: linear scan" | APPLIED (nit: `src/cli/recall.rs:414` is the build site; the exact threshold gate is `:281`) |
| W2-A A13 #936 pin | "`tests/mcp_archive_purge_owner_gate_936.rs:142-161` (`mcp_as_admin_true_purges_cross_tenant_936`) pins that an unenrolled `as_admin:true` caller MUST purge cross-tenant" | fn at `:142`, `agent_id: "ops:admin", as_admin: true`, "MUST purge cross-tenant" | APPLIED |
| W2-A A23 unlink-after-rename, #3131 pin | "sidecars are unlinked **after** the rename (`:1121` → `:1135`)"; pin `:2209` | rename `:1121`; `remove_stale_sidecars` `:1134` (off by 1); test fn `:2209` | APPLIED |
| W2-A A18 split; A16 severity; A24 admin-gated; A25 no ruleset; F7 rewritten; F11 no flip; F13 new; reason 2 rewritten | all present as described in §2/§5/§0 | F13: `identity/mod.rs:487` `resolve_read_visibility_caller`, `:483-485` "preserves the single-tenant 'trust the local caller' read posture: the handler skips the ownership post-filter entirely" | APPLIED |
| W2-B program dispositions (N2→#3404 amendment, N11 resolver, N12 native-pg→v1.1, N14 ceiling, N15→#3297, N17/N20/N25→#3308 children, N18→V10, N21 cert, N22 first, N23 in lane step, N26 S, N27 admin-lift, N3/N4/N7 split, V6/V7/V9, path re-order, two tracks, V-series ruling) | §7.1–7.3 and §8 carry each; standard 0a/0b/1a/22h/25b match | — | APPLIED |
| W2-C evidence items (A27 constant `embedder_ready`, A27b, A34, A28 no producer, A30 loadgen, F5, F7, F8, F9, F12, #3152→N28) | §3/§5 carry each | `transport.rs:1267` `"embedder_ready": app.embedder.as_ref().is_some()`; `mcp-tools-state` grep → only `index.html`, `mcp-tools.html` (consumers) and `remote-capture-manifest.json:30` (a captured copy) — no producer | APPLIED |
| W2-C standard clauses (binding via `/proc/<pid>/exe`, `durability_class`, NOT-YET-EVIDENCED, `artifact_kind`, independent definition, `attempts`/`PASS_ON_RETRY`, ratchet, `model_case`, §0.5 with #2671/#2631, n ≥ 30, `SOURCE_DATE_EPOCH`, region definition, §4 distinct principals, FIPS/800-53 appendix) | all grep-present; independent defined at standard `:145-147` | — | APPLIED |

**Applied wrongly or with stale evidence (must fix before merge):**

1. **F15 line citations are stale.** `storage/mod.rs:3560→3669`, `:3239`, `postgres.rs:18646`, `:18654` are copied from #3152's body (scout-verified at `cda57210`). On `495404d7`, `mod.rs:3560` is inside a lifecycle-transition guard and `postgres.rs:18646` is `kg_query_row_cap`. The defect **does** hold: `src/store/sqlite.rs:718` `db::update_with_expected_version(…)` then `:750` `db::set_lifecycle_state(&conn, id, target)` outside that transaction; `src/store/postgres.rs:8085-8090` `update_with_expected_version_once(…).await?` then `self.apply_lifecycle_patch(id, lifecycle_target).await?` (def `:8141`). Replace the four citations.
2. **F7 `coverage.yml:440`** is `echo "pg container: …"`; the `apache/age:release_PG16_1.6.0` image is at **`:183`**. `:472-477` is correct.
3. **§6.1 #3455 "OPEN, security"** — live labels are `v1.0, fable-qc` only. Either the row or the label is wrong; §0 reason 2 counts it among "ten open MCP-handler gaps" so the label should be added, not the row softened.
4. **§8 "25 open `ga-blocker`"** — 24 live now; no `ga-blocker` has closed since 2026-09-06, so 25 was a miscount when written. Say 24.

## 2. Rejected items

| Rejection | Ruling | Evidence |
|---|---|---|
| W2-C "`doctor --posture` does not exist" | **REJECTION-UPHELD** | `src/cli/doctor.rs:735` doc-comment "`ai-memory doctor --posture <NAME>`", grep shows the flag wired (`:241`, `:271`, `:704`). N26 correctly extends it rather than creating it. |
| W2-B "N21 post-tag only" → accepted as cert track, not dropped | **REJECTION-UPHELD** (in substance an acceptance) | W2-B asked for post-tag/pre-customer; §7.2 N21 and standard 22b place it exactly there. Nothing to overturn; the "rejected" framing is cosmetic. |
| W2-B "N9 needs a standard item" — "it has one (22g)" | **REJECTION-UPHELD on state, MISATTRIBUTED on record** | W2-B did not raise this; W2-B wrote "N9 STANDS (v1.0, non-blocking) Consistent between documents (22g)". The claim came from W1-A and W1-C, was correct at the time, and was **accepted** (22g exists; N9 dropped `ga-blocker` to `bug, medium, v1.0`). Move it to the wave-1 "accepted" cells and delete it from W2-B's rejected column. |

## 3. §0 as a procurement reviewer

| Reason | Ruling | Fix if needed |
|---|---|---|
| Preamble "Every source-level claim it makes holds" | **OVERSTATED (slightly)** | The audit itself narrowed A18's `pending` half (durable `pending_id`, `capture_turn.rs:417-425`) and A23's consequence. Say: "Every source-level claim holds, two narrowed in consequence (A18 `pending`, A23)." |
| 1. Read-surface fidelity | **SUSTAINED** | `recall.rs:756-757` reads `valid_from/valid_until`; SELECT `:8220-8226` omits them: a selection defect, cert-void class. "Provenance" differs only on the scan path (A1b), which the row already scopes. |
| 2. Authority boundary = HTTP; stdio single trust domain | **SUSTAINED**, one arithmetic wobble | "ten … Four have reviewed fixes, one is in progress, two are net-new (§5)" reads as 4+1+2 of ten. The ten are #3379 #3380 #3381 #3382 (queued) #3383 (in progress) #3455 #3499 #3364 #3386 #3506 (unassigned); F1/F2 are beyond the ten. Say "four queued, one in progress, five unassigned; F1/F2 are net-new beyond them." |
| 3. Evidence not recomputable | **SUSTAINED** | No producer for `mcp-tools-state.json`; harnesses untracked (`.gitignore:53`); `state.json` unbound. |
| 4. Release workflow | **OVERSTATED by tense** | "a tag name … that moved between jobs" asserts an event; the evidence (no tag ruleset, eight by-name checkouts, `outputs.sha` unused) supports "that can move between jobs". Change "moved" → "can move". |
| 5. Two cert-blockers | **SUSTAINED** | #3501 `cert-blocker, ga-blocker`; #2437 `cert-blocker, ga-blocker`, qualifier already present. |

## 4. Audit §7 vs standard §6 consistency

Consistent (id, track): N1 N2 N3 N6 N7 N8 N10 N12 N13 N14 N15 N16 N17 N20 N21 N23 N24 N25 N26 N27 N28 N29 N30 V2 V3 V8 V9 V10. Mismatches:

- **N11** (audit §7.1, tag, `security, high, ga-blocker`) has **no Work row** in standard §6; it is referenced only inside 0b ("inside N11") and item 4 ("N11's matrix"). Add a row or state that 0b carries it.
- **V1, V4, V5** (audit §7.3, `deferred-v1.x`) are absent from standard §6.
- **N22** is tag-only in the audit; the standard splits it into 0a (tag) and 18 (cert, procurement appendix). Audit §8's cert path says "procurement appendix" with no id.
- **V6, V7** carry track "—" in audit §7.3 but `v1.1` in standard 25/26.
- Standard item **14 "P"** still has no N-id (W2-B flagged it as unfilable; unaddressed).

## 5. Spot-checks not already made by waves 1–2

1. F13 `identity/mod.rs:470-497` — fn at `:487`, "trust the local caller … skips the ownership post-filter" `:483-485`. HOLDS.
2. A1b reachability `mod.rs:19876` / `:20063` / `:20066`. HOLDS.
3. A28 "no producer anywhere in the tree" — grep across tracked and untracked (excl. `.git`, `target`): consumers only. HOLDS.
4. A13 `mcp_archive_purge_owner_gate_936.rs:142` fn name and assertion text. HOLDS.
5. A23 `backup.rs:1121` rename / `:1134` sidecar unlink / `:2209` #3131 pin. HOLDS (one line off).
6. F1 `route_1111.rs:701-702, :716, :763`; F2 `skills.rs:361, :378`. HOLDS.
7. F11 `connection.rs:558`; §4 `doctor.rs:735`. HOLDS.
8. A1 `recall.rs:756-757` + SELECT `:8220-8226`. HOLDS.
9. F15 lines — **STALE** (see §1.1); defect present at `sqlite.rs:718→750`, `postgres.rs:8085-8090`.
10. F7 `coverage.yml:440` — **WRONG** (`:183`); `:472-477`, `ci.yml:1184`, `:1333-1340` HOLD.
11. A20 `lib.sh:113`; A3 `postgres.rs:648` / `postgres_parity.rs:130`; F12 = 38 declared. HOLD.
12. §6.1 labels for 41 issues — all match except **#3455** (no `security`).
13. Appendix A rows A16 (0.153.4, Astra `:153`), A28 (manual transfer `:194`), A31 (`:208`), A32/A33 (`:225`), A38 (`:249` "8 successful and 3 failed out of 11"), A39 (`:251`), A40 (`:257`), T26 (12 table rows at test plan `:258+`), T40 (`:343`). All trace.

## 6. Final ballot: **MERGE-AFTER-FIXES**

All fixes are text-level; none touches a verdict:
(a) replace the four F15 citations; (b) `coverage.yml:440` → `:183`; (c) reconcile #3455's `security` label with the §6.1 row; (d) §8 24 not 25 `ga-blocker`; (e) reason 4 "moved" → "can move"; (f) reason 2 arithmetic sentence; (g) preamble "every claim holds" → "two narrowed"; (h) §9 move "N9 needs a standard item" to wave-1 accepted and drop it from W2-B rejected; (i) add an N11 row to standard §6 (or name 0b as its carrier), add V1/V4/V5, give item 14 an id, and align N22/V6/V7 tracks between the documents.

**What a Fortune 500 or federal reader must not misread.** "All five are closable … three weeks" applies to the *tag* track only; the *certificate* is an October artifact at the earliest, depends on two operator-provisioned hosts with no date, and — because all nine ballots and this one come from one model family in one organisation — will carry the label VENDOR SELF-CERTIFIED under the standard's own §4 until an assessor independent of the vendor signs a wave-3 ballot. A v1.0.0 tag, if the operator chooses to tag before certifying, is therefore not a certificate, and the stdio disposition in §0.1 means that every "caller-owns" gate on MCP over stdio is defence in depth inside one trust domain, not tenant isolation: multi-principal claims are certifiable only over HTTP with per-agent enrolled keys.

— Adjudicator A, wave 3