---
layout: doc
---
# Track A — NHI Playbook Results (P0–P11), v1.0.0 Enterprise Certification

Per the committed NHI dogfood playbook
[`docs/v1.0.0/nhi-playbook-P0-P11.md`](../nhi-playbook-P0-P11.md) and the
campaign [`PLAN.md`](./PLAN.md). All twelve phases driven **locally ($0)**
against the **certified enterprise config** — encryption + attestation ON,
PostgreSQL 16 + Apache AGE 1.6.0 + pgvector, over the HTTPS + mTLS REST surface
and the CLI/MCP surfaces. Run date **2026-08-09**.

> **Stack-evidence note ([#2913](https://github.com/alphaonedev/ai-memory-mcp/issues/2913)).**
> The backend banner below is the **as-run record**: PostgreSQL 16.10 +
> Apache AGE 1.6.0 + **pgvector 0.8.6** (local single-node). It is not a
> PG18 run. The later enterprise-federation certification pins the
> disjoint **PG18.4 + AGE 1.7.0 + pgvector 0.8.5** single-node CI stack
> (run [`31601974424`](https://github.com/alphaonedev/ai-memory-mcp/actions/runs/31601974424)
> at `b80e7fff`). Track A/B recorded pgvector **0.8.6**; the DO 2-node
> mesh recorded **0.8.4** — both kept as written. See
> [`PLAN.md`](./PLAN.md) §"Stack-evidence reconciliation".

> **⚠️ The FIX-FIRST verdict below is the FIRST-PASS record (2026-08-09 @
> `25329b2b`) and has been SUPERSEDED.** The fixes landed and the affected
> phases were re-run against the fixed tip. The current Track A verdict is
> **SHIP (Track A local scope)** — see
> [Re-mint 2026-08-09 @ `5ceab18b`](#re-mint-2026-08-09--5ceab18b) at the end
> of this document. The first-pass sections are preserved verbatim rather
> than rewritten: they describe the substrate **as it was**, and re-pointing
> them at the fixed tip would falsify the record.

## Config banner (certified)

| Fact | Value |
|------|-------|
| Binary | `ai-memory 1.0.0`, `target/release/ai-memory` |
| Binary sha256 | `e6c28d0112a9f62fc2e12760538fffe1b25842f4d248cb865fe581437b9e7d09` |
| Git commit | `25329b2b1aca33d6406ad88b1a626aeb76bd5c74` (release/v1.0.0 merged tip; incl. #2789 recall_hybrid fix) |
| Build features | `sal, sal-postgres` (+ `attest_sign` example) |
| Backend | **PostgreSQL 16.10 + Apache AGE 1.6.0 + pgvector 0.8.6**, dedicated DB `nhi_p0p11`, schema **v88**, 37 tables, AGE `memory_graph` projection created |
| Encryption / transport | **TLS ON** (rustls, server cert) + **mTLS ON** (client-cert allowlist) |
| Attestation | **ON** — `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`; agent `ai:alice` Ed25519 key registered + bound over the admin HTTP route |
| Auth | top-level `api_key` (admin gate), `AI_MEMORY_ADMIN_AGENT_IDS=ai:admin`, tier=semantic (MiniLM 384-dim embedder loaded) |
| Drive surfaces | pg substrate via HTTPS REST (signed writes via `attest_sign`) + CLI; MCP-stdio (sqlite) for wire-schema + parity per playbook §"How to run" |

## Phase summary (FIRST PASS, 2026-08-09 @ `25329b2b`)

| Phase | Status | Verdict | Notes |
|-------|--------|---------|-------|
| P0  Environment & version handshake | ✅ | **PASS** | version/handshake/tool-counts/caps all SSOT-correct |
| P1  Core CRUD + DF-1..DF-4 | ✅ | **PASS** | full CRUD + all four provenance-wire assertions |
| P2  Lifecycle | ✅ | **PASS** | pure recall, fold auto-promote, forget archive+scoping (delete-verb caveat) |
| P3  Knowledge graph | ❌ | **FAIL** | 2 postgres defects: #2792 (kg_query), #2793 (kg_invalidate) |
| P4  Governance & security | ⚠️ | **PASS (security core); pg gap** | SSRF HMAC gate + attestation PASS; rule_list/check_agent_action 501 on pg (#2794) |
| P5  Power tools (LLM) | ⏸️ | **PARTIAL / BLOCKED-BY-NO-LLM** | check_duplicate (embeddings) PASS; expand/auto_tag/contradiction need an LLM backend (none in $0 env) |
| P6  Capabilities v3 | ✅ | **PASS** | schema_version 3, 8 families loaded, always_on bootstrap |
| P7  Token budget | ✅ | **PASS** | `token_budget_guard` 3/3, trimmed < 11000 cl100k |
| P8  Hooks & subscriptions | ✅ | **PASS** | hook_events=22, registered=0, HMAC-required dispatch |
| P9  MCP/HTTP/CLI parity | ✅ | **PASS** | per-interface source stamp; identical validation refusals |
| P10 Performance & scale | ✅ | **PASS** | stats/health/metrics shapes; doctor pg-direct gap (#2795) |
| P11 Failure & chaos (fail-closed) | ✅ | **PASS** | sanitized errors, adversarial refusals, sustained recalls; audit-tool pg gap (#2795) |
| **Overall** | — | **FIX-FIRST** (first pass — SUPERSEDED, see the re-mint) | 2 fixable pg defects (P3) block a campaign SHIP; no data-integrity / fail-closed VIOLATION observed |

Issues filed: **#2792, #2793, #2794, #2795, #2796**.

---

## P0 — Environment & version handshake — PASS

| Test | Expected | Actual | Verdict |
|------|----------|--------|---------|
| `ai-memory --version` + realpath | `1.0.0`, campaign build | `ai-memory 1.0.0`, `target/release/ai-memory` | PASS |
| MCP `initialize` serverInfo.version | `1.0.0` | `1.0.0` (identity schema `v88`) | PASS |
| `tools/list` `--profile full` | 103 (SSOT `Profile::full().expected_tool_count()`) | **103** | PASS |
| `tools/list` `--profile core` | 7 (playbook) | **8** = 7 callable core + always-on `memory_capabilities` — SSOT-consistent with the full "102 callable + bootstrap = 103" framing | PASS (playbook wording drift → #2796) |
| `memory_capabilities.schema_version` / `.version` | `"3"` / `1.0.0` | `"3"` / `1.0.0` | PASS |
| All families loaded | true | 8 families all `loaded:true`; `always_on:["memory_capabilities"]` | PASS |
| HTTP `/health` version | `1.0.0` | `1.0.0`, status ok | PASS |

## P1 — Core CRUD + DF-1..DF-4 — PASS

CRUD driven over HTTPS (signed) on pg; DF-1/DF-2/DF-4 on MCP (sqlite) per playbook.

| Test | Result | Evidence |
|------|--------|----------|
| store → recall → search → list → delete | PASS | signed store 201, `attest_level=agent_attested`; recall `mode:hybrid` top score **0.792** (semantic); FTS `search?q=duck` count 1; ns-scoped list=3 |
| agent_id auto-stamp + immutable across update | PASS | stamped `ai:alice`; PUT with spoofed `agent_id:ai:attacker` → stored stays `ai:alice` (pg confirmed) |
| DF-1 `memory_store.inputSchema.source_uri` | PASS | MCP `tools/list` → `properties.source_uri` present |
| DF-2 `memory_update` `expected_version`+`edit_source`+`source_uri` | PASS | all three present in `memory_update.inputSchema.properties` |
| DF-3 `source_uri` persists end-to-end | PASS | store `{source_uri:"doc:DF3"}` → `SELECT source_uri FROM memories` = `doc:DF3` (pg) |
| DF-4 `edit_source:"llm"` archive-and-supersede | PASS | MCP `memory_update{edit_source:llm}` → `archived_memories.archive_reason='superseded'` + new current row with `metadata.superseded_id=<old id>` |

## P2 — Lifecycle — PASS

| Test | Result | Evidence |
|------|--------|----------|
| default tier = mid | PASS | new rows land `tier=mid` |
| recall is PURE (#1869/#1953) | PASS | after 5 recalls, `access_count=0`, `tier=mid` **pre-fold** |
| auto-promote mid→long at PROMOTION_THRESHOLD=5 (via FOLD) | PASS | after fold: `access_count=5`, `tier=long`, `expires_at` cleared (fold wired on pg) |
| explicit `memory_promote` mid→long | PASS | `POST /memories/{id}/promote` → `tier=long`, expiry cleared |
| `forget` by namespace EXACT-scoped | PASS | `forget ns=p2team` → parent gone, child `p2team/sub` survives |
| archive-before-delete (forget) | PASS | `archived_memories.archive_reason='forget'` for the forgotten row |

**Caveat (→ #2796):** `DELETE /memories/{id}` (`db::delete`, **both** backends) is a **hard delete with no archive** — only `forget` (and GC eviction) archive. The playbook's "every explicit delete/forget archives" conflates the two verbs; under default `append_only=off`, `DELETE`-by-id destroys durable text irreversibly. This is the explicit destructive verb (forget is the reversible path), so not a data-loss defect — but the playbook text and an operator caveat need correcting.

## P3 — Knowledge graph — **FAIL (2 postgres defects)**

Driven over the AGE Cypher path on pg (`links`, `kg/query`, `kg/timeline`, `kg/invalidate`, `kg/find_paths`, `taxonomy`).

| Test | Result | Evidence |
|------|--------|----------|
| `memory_link` (9-relation taxonomy) carries `valid_from` + `attest_level` | PASS | edge `attest_level=self_signed`, `valid_from` set (get_links temporal cols present) |
| `kg_query` traversal (related_to chain) | PASS | X→Y→Z: `count:2` |
| `kg_query` traversal (non-`related_to` edge) | **FAIL** | identical `supersedes` edge: **pg count:0**, sqlite count:1 → **#2792** (pg AGE Cypher hard-codes `[r:related_to*1..N]`; silently drops the other 8 relations; AGE graph itself is complete) |
| `kg_timeline` returns events with `valid_from` | PASS | 1 event, `valid_from` set |
| `kg_invalidate` sets `valid_until`; re-query drops edge | **FAIL** | `POST /kg/invalidate` on an existing pg source → **404 "source memory not found"** → **#2793** (ownership pre-check reads empty sqlite scratch via `db::get(&lock.0)`, never reaches the pg `invalidate_link` branch); `valid_until` never set |
| `find_paths` / `kg/find_paths` | MIXED | `POST /find_paths` → 501 not-implemented-on-pg; `POST /kg/find_paths` **works** (path `[X,Y,Z]`) |
| `taxonomy` / `get_links` (temporal cols) | PASS | taxonomy 200 (admin-gated); get_links exposes `valid_from`, `attest_level`, `observed_by` |
| entity_register / entity_get_by_alias | N/A on pg | no HTTP route (MCP-sqlite only); out of scope for the pg HTTP surface |

## P4 — Governance & security — PASS (security core); postgres inspection gap

| Test | Result | Evidence |
|------|--------|----------|
| `pending` clean state | PASS | `{count:0, pending:[]}` |
| `quota/status` | PASS | returns per-agent quota (current/max memories, links, storage bytes) |
| **Attestation ON** — signed lands `agent_attested`, unsigned `403` | PASS | signed 201 `attest_level=agent_attested` (`write_signature` persisted); unsigned → **403 `ATTESTATION_FAILED`** |
| **SSRF probes refused at HMAC gate BEFORE URL validation** | PASS | AWS-metadata `169.254.169.254`, loopback `127.0.0.1`, `file://` — **all 3** → `HMAC secret required`; **zero** orphan subscription rows |
| `notify` → `inbox` round-trip | PASS | notify 201 → inbox `unread:1` |
| `memory_rule_list` / `memory_check_agent_action` | **GAP** | **501 not-implemented-on-postgres** → **#2794** (governance engine enforces on pg, but its inspection surfaces are unimplemented) |

## P5 — Power tools (LLM) — PARTIAL / BLOCKED-BY-NO-LLM

| Test | Result | Evidence |
|------|--------|----------|
| `check_duplicate` (embedding similarity) | PASS | `is_duplicate:true`, nearest score **0.949** vs threshold 0.85 (no LLM needed) |
| `expand_query` / `auto_tag` / `detect_contradiction` | **BLOCKED** | `expand_query` → **503 "LLM not configured"**. No LLM backend reachable in the $0 local env (no Ollama, no API key). Playbook §P5 explicitly requires a real LLM; these are **not certifiable locally** — must be re-run on the DO round with Grok 4.5. **Not a substrate defect** (fail-closed 503, no wrong result). |

## P6 — Capabilities v3 — PASS

`schema_version="3"`, `version="1.0.0"`, `summary`+`to_describe_to_user`+`tools`+`hooks` present, 8 families `loaded:true`, `always_on:["memory_capabilities"]`, `memory_smart_load`+`memory_load_family` exposed. Tool-count reconciles to SSOT (103 full).

## P7 — Token budget — PASS

`cargo test --test token_budget_guard --features sal,sal-postgres`: **3 passed / 0 failed** — trimmed full-profile `tools/list` under `TRIMMED_FULL_PROFILE_CEILING_TOKENS` (11000 cl100k), verbose under its ceiling, trimmed strictly smaller than verbose.

## P8 — Hooks & subscriptions — PASS

`capabilities.hooks.hook_events_count = 22` (matches the compiled `HookEvent` SSOT), `registered_count = 0` (clean), `webhook_events` enumerated (7). Subscription dispatch is HMAC-required — the three dangerous-URL probes (P4) are refused at the HMAC gate **before** URL validation.

## P9 — MCP / HTTP / CLI parity — PASS

| Test | Result | Evidence |
|------|--------|----------|
| per-interface source stamping | PASS | CLI store → `source=cli` (agent `ai:cli`); MCP store → `source=nhi` (agent `ai:claude@<host>`); HTTP → `source=api`. Distinguishable per-interface. (Playbook says MCP source `claude`; now `nhi` → #2796.) |
| validation parity — `agent_id` metachar `$` | PASS | CLI + MCP both refuse: "invalid character '$'" (identical) |
| validation parity — >128-byte `agent_id` | PASS | CLI + MCP both refuse: "exceeds max length of 128 bytes" (identical) |
| cross-interface contradiction | PARTIAL | proactive-conflict fires only under an embedding tier; the isolated MCP/CLI sqlite instances used for parity run keyword-tier (no embedder), so this specific cross-store flag is a harness limitation, not a defect. Embedding-based dup detection is proven on the pg HTTP surface (P5 check_duplicate). |

## P10 — Performance & scale — PASS

| Test | Result | Evidence |
|------|--------|----------|
| `memory_stats` shape | PASS | `by_namespace`, `by_tier` (long:3/mid:12/short:1), `db_size_bytes`, `links_count`, `total_memories` present (playbook says `total`; field is `total_memories` → #2796) |
| `/health` FTS verdict (#2579) | PASS (pg-adapted) | `fts_index:not_applicable`, `fts_integrity:disabled` — expected on postgres (tsvector, not FTS5); no per-request scan cost |
| `/metrics` corpus gauge (#2583) | PASS | `ai_memory_memories 16` + companion `ai_memory_memories_refreshed_at_seconds` published |
| `ai-memory doctor` overall INFO / no corruption | PASS (sqlite) / GAP (pg) | doctor on sqlite → overall **INFO**, `fts_index_integrity verified`. `doctor` has **no `--store-url`** (only `--db`/`--remote`) → cannot open the pg store directly → **#2795** |
| sustained sequential recalls | PASS | 10/10 → 200, consistent shape, no lock starvation |

## P11 — Failure & chaos (fail-closed) — PASS

| Test | Result | Evidence |
|------|--------|----------|
| `memory_get` bogus UUID → sanitized not-found | PASS | `{"error":"not found"}` 404, no leak |
| adversarial `agent_id` `$` | PASS | 400 `VALIDATION_FAILED` "invalid character '$'" |
| adversarial `agent_id` 200-char overflow | PASS | 400 `VALIDATION_FAILED` "exceeds max length of 128 bytes" |
| adversarial `agent_id` null byte | PASS (indirect) | validator regex rejects control chars (metachar+overflow proven); a raw null in a curl header is stripped by the shell before transit |
| sequential recalls across distinct contexts | PASS | 10/10 clean, no DB-lock errors |
| fail-closed integrity: `doctor` clean / `verify-audit-trail` clean | PASS (sqlite) / GAP (pg) | pg `signed_events` chain intact (verified by direct SQL — `prev_hash` linked). **`verify-audit-trail` has no `--store-url` / remote path** → a pg deployment cannot verify its audit chain via the shipped CLI → **#2795** |
| power-loss durability | PASS (pinned) | `tests/power_loss_durability.rs` is the CI-pinned proof (`AI_MEMORY_DB_SYNCHRONOUS`, abort-after-commit injection); sqlite-scoped |

---

## Findings (all filed; prime-directive discovery→file→fix)

| # | Phase | Severity | Issue | One-line |
|---|-------|----------|-------|----------|
| 1 | P3 | **fix-first** | [#2792](https://github.com/alphaonedev/ai-memory-mcp/issues/2792) | `kg_query` on pg/AGE traverses only `related_to`; sqlite traverses all 9 → silent parity break |
| 2 | P3 | **fix-first** | [#2793](https://github.com/alphaonedev/ai-memory-mcp/issues/2793) | `kg_invalidate` always 404s on pg — ownership pre-check reads empty sqlite scratch |
| 3 | P4 | fix-first | [#2794](https://github.com/alphaonedev/ai-memory-mcp/issues/2794) | `memory_rule_list` + `memory_check_agent_action` 501 on pg (inspection surface unimplemented) |
| 4 | P10/P11 | fix-first | [#2795](https://github.com/alphaonedev/ai-memory-mcp/issues/2795) | `doctor` + `verify-audit-trail` have no `--store-url` → pg deployments can't run first-party health/audit verification |
| 5 | P0/P2/P9/P10 | docs | [#2796](https://github.com/alphaonedev/ai-memory-mcp/issues/2796) | playbook doc drift: core count (8), delete-vs-forget, MCP source `nhi`, stats `total_memories` |

## Verdict — **FIX-FIRST**

The substrate held every **security-critical and data-integrity** assertion on the
certified config: attestation fails **closed** (unsigned HTTP write → 403), the
subscription SSRF probes are refused at the **HMAC gate before URL validation**
with zero orphan rows, adversarial identities are rejected at the validation
layer, errors are sanitized, `agent_id` is immutable across update, `forget`
archives before delete, recall is pure, and the pg `signed_events` chain is
intact. **No fail-closed bypass and no unintentional data loss / corruption was
observed** — so this is **not a HOLD**.

Two **fixable** postgres defects surfaced in P3 (#2792 silent `kg_query`
under-report, #2793 non-functional `kg_invalidate`), plus a postgres governance-
inspection gap (#2794) and a postgres integrity-tooling gap (#2795). Per the
playbook rubric, "the verdict cannot be SHIP while any surfaced finding is open,"
and these are FIXABLE — so the Track A verdict is **FIX-FIRST**: file → fix →
retest → re-run P3/P4/P10/P11 on postgres, then re-mint. P5 (LLM power tools)
is **blocked-by-no-LLM** locally and must be certified on the DO round with a
real Grok 4.5 backend; it is not counted as a substrate failure.

**PROVEN vs blocked (honesty ledger):** P0/P1/P2/P6/P7/P8/P9 and the P4 security
core and P10/P11 fail-closed behaviors are **PROVEN** on the certified pg stack.
P3 kg_query/kg_invalidate are **PROVEN-BROKEN on pg**. P5 LLM tools are
**BLOCKED-BY-NO-LLM** (not tested). `doctor`/`verify-audit-trail` pg paths are
**BLOCKED-BY-TOOLING** (sqlite-only), with the pg audit chain verified out-of-band
by direct SQL.

---

# Re-mint 2026-08-09 @ `5ceab18b`

The first-pass verdict was **FIX-FIRST**. The fixes landed
([PR #2798](https://github.com/alphaonedev/ai-memory-mcp/pull/2798) for
#2792/#2793 + the coupled #2800,
[PR #2802](https://github.com/alphaonedev/ai-memory-mcp/pull/2802) for #2795's
`verify-audit-trail --store-url`, and
[PR #2811](https://github.com/alphaonedev/ai-memory-mcp/pull/2811) for the
Phase-2 truthfulness floor that re-scoped #2794 to v1.x
[#2807](https://github.com/alphaonedev/ai-memory-mcp/issues/2807)). Per the
playbook rubric ("file → fix → retest → re-check, then re-run the affected
phase") the RED / BLOCKED assertions were re-run against the fixed tip on a
**fresh database**.

**Scope of this re-mint.** ONLY the assertions that were RED or BLOCKED in the
first pass: **P3** (all), the **P4** governance-inspection gap plus an
enforcement control, and the **P10/P11** integrity-tooling gap. P0/P1/P2/P6/P7/
P8/P9 and the P4 security core are NOT re-run — they were green on the first
pass and none of the three merged PRs touches them. P5 remains
BLOCKED-BY-NO-LLM.

## Config banner (re-mint)

| Fact | Value |
|------|-------|
| Binary | `ai-memory 1.0.0` (frozen copy of the tip `target/release/ai-memory` — a concurrent agent shares `target/`, so the SUT was copied aside before the run) |
| Binary sha256 | `38b2d944ce5449ddeda710e969db3afaa61615f7667757f9df5c4fa970accf2a` |
| Git commit | `5ceab18bf37ecc1fd00a3576b10fbb4d6c99fde7` (release/v1.0.0; incl. #2798, #2802, #2811) |
| Build features | `sal, sal-postgres` |
| Tip-binary proof | `ai-memory verify-audit-trail --help` advertises `--store-url` (the #2802 flag) — a direct behavioural check, not an mtime |
| Backend | **PostgreSQL 16 + Apache AGE 1.6.0 + pgvector**, **FRESH** DB `tracka_remint`, schema **v88**, 37 tables, AGE `memory_graph` projection created, `embedding_dim=384` |
| Encryption / transport | **TLS ON** (rustls) + **mTLS ON** (client-cert allowlist), port **19666** |
| Attestation | **ON** — `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`; `ai:alice` Ed25519 key registered + bound over the admin HTTP route |
| Auth | top-level `api_key`, `AI_MEMORY_ADMIN_AGENT_IDS=ai:admin`, tier=semantic (MiniLM 384-dim) |
| Evidence log | `.local-runs/cert-campaign/tracka/remint-2026-08-09/evidence.log` (raw, unedited command output) |

## P3 — Knowledge graph — **PASS** (was FAIL)

Driven over the AGE Cypher path on pg. All nine `MemoryLinkRelation` variants
are exercised with a real edge each.

| # | Assertion | Result | Evidence |
|---|-----------|--------|----------|
| P3-0 | one edge per relation created (9/9) | **PASS** | all nine `POST /links` return `linked:true`, `attest_level=self_signed` |
| P3-A | `kg_query(max_depth=3)` traverses **ALL 9** relations (#2792) | **PASS** | `count:9`; `relations_returned=advances,contradicts,decomposes_into,depends_on,derived_from,derives_from,reflects_on,related_to,supersedes` |
| P3-A2 | the AGE projection itself carries all 9 | **PASS** | untyped Cypher `MATCH (a)-[r]->(b) WHERE a.id=<hub>` → 9 rows, one per relation |
| P3-A3 | fail-closed control: the #1859 lineage guard still refuses a BACKWARDS provenance edge | **PASS** | `derived_from` older→newer → **409** `link refused: reflection cycle` |
| P3-B | `kg_timeline` carries all 9 relations (#2800 sibling) | **PASS** | `timeline_relations` = the same 9 |
| P3-C | `kg_invalidate` on an OWNED pg row is **200 found:true**, not 404 (#2793) | **PASS** | `http_code=200`, `{"found":true,"valid_until":"2026-08-09T…"}` |
| P3-C2 | invalidation visible in the relational row | **PASS** | `SELECT relation, valid_until FROM memory_links` → `supersedes` / `valid_until=2026-08-09 …` |
| P3-C3 | invalidated edge EXCLUDED from the kg_query current view | **PASS** | re-query `count:8`, `supersedes` absent |
| P3-C4 | `include_invalidated:true` returns it — history preserved, **no data loss** | **PASS** | `count:9`, `supersedes` present |
| P3-C5 | the AGE edge carries `valid_until` too (the #2793 coupled AGE-stamp fix) | **PASS** | Cypher returns `"supersedes"` with `valid_until = "2026-08-09T…"` |
| P3-D | ownership still enforced — NON-owner `kg_invalidate` refused, **no IDOR** | **PASS** | `ai:mallory` → **404** `source memory not found`; the targeted edge's `valid_until` stays **NULL** (unmodified) |
| P3-E | `kg/find_paths` + `taxonomy` + `get_links` temporal/attest columns | **PASS** | find_paths returns a path; taxonomy `200`; get_links exposes `valid_from`/`valid_until`/`attest_level` |

**Chronology note (harness, not substrate).** The provenance subset
P = {`derived_from`, `reflects_on`, `derives_from`} is governed by the #1859
lineage-DAG acyclicity guard (postgres Pass 0 of
`src/store/postgres.rs::validate_link_pre_create_pg`), which refuses a
provenance edge whose TARGET is newer than its SOURCE. A first attempt seeded
the hub BEFORE its provenance targets, so those three edges were correctly
REFUSED at creation and `kg_query` returned 6 relations — the three missing
ones had no edge to traverse. Re-seeding the three provenance ancestors before
the hub produced all nine edges and the 9/9 result above. Recorded because the
6-of-9 reading would otherwise look like a partial #2792 regression; it was a
test-ordering error, and P3-A3 pins the guard still fires.

**Observation (not a defect, not filed):** the refusal message for a
`derived_from` / `derives_from` edge reads `… --reflects_on--> … would close a
cycle`. The relation name is hard-coded in the shared
`StorageError::LinkReflectionCycle` Display, deliberately, so the wire body is
byte-identical across sqlite and postgres. It is accurate about the guard and
imprecise about which relation the caller used.

## P4 — Governance & security — **PASS**

#2794 was RESCOPED to v1.x ([#2807](https://github.com/alphaonedev/ai-memory-mcp/issues/2807))
by the frozen 59/21 pg-supported partition (PLAN.md §2.0, PR #2811). Both
routes are in the **21 fully-501** set, so the cert-scope assertion is that the
501 is HONEST and TYPED — a fail-closed refusal, never wrong data — and that
governance ENFORCEMENT still works on pg.

| # | Assertion | Result | Evidence |
|---|-----------|--------|----------|
| P4-A | `memory_rule_list` on pg is an honest, TYPED 501 | **PASS** | `501` + `{"error":"endpoint not yet implemented for postgres-backed daemon","endpoint":"/api/v1/memory_rule_list","method":"POST","storage_backend":"postgres","remediation":"…"}` |
| P4-B | `memory_check_agent_action` on pg is an honest, TYPED 501 | **PASS** | same typed envelope, `endpoint=/api/v1/memory_check_agent_action` |
| P4-B2 | the 501 is STRUCTURALLY honest — nothing to read | **PASS** | `SELECT to_regclass('public.governance_rules')` → **NULL** (no such table on pg). The 501 is a refusal, not a silent read of the empty sqlite scratch |
| P4-C | attestation ON — UNSIGNED direct HTTP store refused | **PASS** | **403** `ATTESTATION_FAILED` |
| P4-D | SIGNED write lands `agent_attested` (verified in pg, not the response echo) | **PASS** | `SELECT metadata->>'attest_level'` → `agent_attested`, `write_signature` persisted (`has_write_sig=t`) |
| P4-E | governance ENFORCEMENT on pg — a `write=approve` namespace standard is persisted | **PASS** | `metadata->'governance'` on pg = `{"write":"approve","delete":"owner","inherit":true,"promote":"owner"}`; `namespace_meta` binds it |
| P4-E2 | a signed+attested governed write is **GATED**, not accepted | **PASS** | response `{"status":"pending","pending_id":"89362545-…"}`; `SELECT count(*) … WHERE title='p4enf governed write probe'` → **0 landed**; `pending_actions` → one row: `action_type=store`, `status=pending`, `requested_by=ai:alice`, `namespace=p4enf` |
| P4-E3 | control — the same write into an UNGOVERNED namespace lands | **PASS** | `201`, `attest_level=agent_attested` |
| P4-F | SSRF probes refused at the HMAC gate BEFORE URL validation | **PASS** | AWS-metadata `169.254.169.254`, loopback `127.0.0.1:22`, `file:///etc/passwd` — all three → `HMAC secret required`; `SELECT count(*) FROM subscriptions` → **0** orphan rows |
| P4-G | pending + quota surfaces on pg | **PASS** | `/pending` `{count:…, storage_backend:"postgres"}`; `quota/status` returns per-agent/per-namespace rows |

P4-E is the load-bearing one: because the probe write is signed AND attested, it
clears the attestation gate, so the refusal can only come from governance. The
approve-gated write is routed to `pending_actions` and zero rows land — the
inspection API 501s, the ENFORCEMENT does not.

## P10 / P11 — Perf, tooling, chaos, fail-closed — **PASS**

| # | Assertion | Result | Evidence |
|---|-----------|--------|----------|
| P10/11-A0 | a REAL pg audit chain is seeded | **PASS** | `POST /capture_turn` ×5 → 5×`201`; `signed_events` sequences 1-5 with linked `prev_hash`/`this_hash` |
| P10/11-A | `verify-audit-trail --store-url postgres://…` verifies FIRST-PARTY against the pg chain (#2795 → PR #2802) | **PASS** | `exit_code=0`, `chain_intact:true`, 5 events checked |
| P10/11-A2 | human-readable render (shared verdict fns, GATE K3) | **PASS** | same verdict, exit 0 |
| P10/11-A3 | flag-absent invocation is UNCHANGED (local sqlite `--db`) | **PASS** | exit 0 on the local scratch DB |
| P10/11-A5 | **TAMPER DETECTION** — delete a true MIDDLE row (sequence-ordered offset 2 of 5) | **PASS** | `exit_code=1`, `chain_intact:false` — the break is DETECTED and the tool fails loudly |
| P10/11-A6 | **TAIL truncation** — a different detection mechanism, tested deliberately | **PASS (honest degrade)** | with no witness anchor enrolled: `truncation:{status:"unknown"}`, `witness:{status:"unknown"}`, exit 0 — the verifier WITHHOLDS judgement, it never claims the chain is verified-untruncated. With `AI_MEMORY_REQUIRE_WITNESS=1`: `witness:{status:"missing"}`, **exit 1** — fail-closed. This matches the documented `signed_events` tamper-evidence scope (tail truncation is caught by the #1850 off-table watermark, which is opt-in custody) |
| P10/11-B1 | `doctor --store-url <pg>` REFUSED at argv parse — cannot silently open the wrong store | **PASS** | `error: unexpected argument '--store-url' found`, exit 2 |
| P10/11-B2 | `doctor --help` does not advertise `--store-url` | **PASS** | `store_url_occurrences_in_doctor_help=0` |
| P10/11-B3 | `doctor --db` does NOT falsely claim pg health | **PASS** | report names its own scope: `"mode":"local"`, `"source":"<the sqlite path>"`, `total_memories 0` — while the pg corpus holds **20**. It reports on the store it opened and says which one that is |
| P10/11-B4 | `doctor --remote` against the certified daemon | **FAIL-LOUD, new finding** | `Capabilities` section `severity:"critical"`, `note:"could not reach https://127.0.0.1:19666/api/v1/capabilities"` → **[#2815](https://github.com/alphaonedev/ai-memory-mcp/issues/2815)** (below). No false health claim |
| P10 | stats / health / metrics shapes on pg | **PASS** | `stats` → `total_memories:20, links_count:9, by_tier{long:7,mid:13}`; `/api/v1/health` → `status:ok, version:1.0.0`; `/metrics` → `ai_memory_memories 20` + `ai_memory_memories_refreshed_at_seconds` |
| P11 | sanitized not-found on a bogus UUID | **PASS** | `{"error":"not found"}` `404`, no leak |
| P11 | adversarial `agent_id` (shell metachar / 200-char overflow) | **PASS** | both `400`: `invalid character '$'` / `exceeds max length of 128 bytes` |
| P11 | sustained sequential recalls on pg | **PASS** | 10/10 `200`, 19-27 ms, no lock starvation |

## New finding — [#2815](https://github.com/alphaonedev/ai-memory-mcp/issues/2815)

`doctor --remote` exposes **no** `--ca-cert` / `--client-cert` / `--api-key`
flags (`doctor --help` grep count = 0), so it cannot authenticate to a
TLS + mTLS + api-key daemon. Isolated against the **same** pg store: the same
command succeeds over plain HTTP on `:19667` (all sections `info`) and fails
against the certified daemon on `:19666`. Postgres is therefore held constant
and the transport posture is the only variable.

The consequence is that on the certified enterprise config a pg deployment has
**no working first-party `doctor` path at all**: `--store-url` does not exist
(#2810, deferred to v1.x) and `--remote` — the remediation #2810 and PR #2802's
commit message both name — cannot authenticate.

It is **not** a data-integrity defect and **not** a false-health claim: doctor
renders the section `critical` with `could not reach <url>` and names the
`source` it queried. It is a missing capability plus a claims-truthfulness gap
in #2810's stated remediation, so it does not move the verdict to HOLD.

## Claims-parity spot check

`tests/pg_supported_route_inventory_gate_2799.rs` — the Phase-1 anti-regression
gate that freezes the 59-supported / 21-fully-501 partition — run in release
against this fresh database:

```
AI_MEMORY_TEST_POSTGRES_URL=postgres://…/tracka_remint \
  cargo test --features sal,sal-postgres --release \
             --test pg_supported_route_inventory_gate_2799

test already_open_sal_route_1111_routes_stay_supported ... ok
test pg_supported_inventory_and_counts_are_pinned ... ok
test allowlist_membership_is_frozen_at_source ... ok
test result: ok. 3 passed; 0 failed; 0 ignored
```

**PASS (3/3)** — the pg-supported inventory and the source-level allow-list
membership are unchanged, so the 59/21 partition this re-mint certifies against
is the one the gate pins. Log:
`.local-runs/cert-campaign/tracka/remint-2026-08-09/gate2799.log`.

## Harness corrections made during this re-mint (disclosed)

Three errors were mine, not the substrate's. They are recorded because each one
initially LOOKED like a defect:

1. **Provenance chronology** (P3) — seeding the hub before its provenance
   ancestors made the #1859 guard refuse three edges; `kg_query` then honestly
   returned 6 of 9. Fixed by seeding ancestors first; the guard is pinned by
   P3-A3.
2. **`namespace_standard` wire shape** (P4) — the body field is `id`, not
   `memory_id`. With the invented field the handler synthesised a default
   standard carrying no `governance` blob, so the governed write was correctly
   ungated. With the real shape (`{"governance":{…}}`) enforcement fires.
3. **Evidence-log truncation** — `curl -o /dev/stdout` re-opens the
   already-redirected evidence file with `O_TRUNC` and destroys it. The whole
   sequence was re-run on a fresh database after removing that flag, so the
   committed `evidence.log` is one coherent artifact rather than a repaired one.

## Re-minted Track A verdict — **SHIP (Track A local scope)**

Per the playbook rubric:

- **Every re-run assertion is GREEN.** P3 went FAIL → PASS (all 9 relations
  traverse on pg/AGE; `kg_invalidate` works on an owned row and the
  invalidation is visible relationally, in the current view, and on the AGE
  edge). P4's 501s are honest and typed, and governance ENFORCEMENT is proven
  on pg by an approve-gated write that lands zero rows. P10/P11's
  `verify-audit-trail --store-url` verifies the pg chain first-party and
  DETECTS a middle-row tamper with exit 1.
- **Every negative / fail-closed assertion was correctly REFUSED**: unsigned
  write `403`, non-owner `kg_invalidate` refused with the edge left untouched,
  backwards provenance edge `409`, three SSRF probes stopped at the HMAC gate
  with zero orphan rows, adversarial identities `400`, `doctor --store-url`
  refused at argv parse.
- **No data-integrity or fail-closed VIOLATION was observed**, so HOLD does not
  apply. Invalidation is reversible (`include_invalidated` returns the edge);
  no durable text was destroyed by any operation in this run.
- **No in-scope finding remains open.** #2792, #2793, #2800 and #2795 are FIXED
  and re-verified here. #2794 → #2807 and the `doctor` pg-direct gap → #2810 are
  RESCOPED to v1.x by the frozen 59/21 cert boundary and are DISCLOSED, not
  hidden — both surfaces refuse honestly rather than returning wrong data.

**Honesty ledger (what this verdict does and does not cover).**

- **PROVEN on the certified pg stack, this re-mint:** P3 in full, the P4
  governance 501-honesty + ENFORCEMENT + attestation + SSRF assertions, and the
  P10/P11 audit-chain, tamper-detection, doctor-disclosure and chaos
  assertions.
- **PROVEN on the first pass and not re-run** (no merged PR touches them):
  P0/P1/P2/P6/P7/P8/P9.
- **BLOCKED-BY-NO-LLM:** P5 `expand_query` / `auto_tag` / `detect_contradiction`
  are **not certifiable in this $0 local env** and are NOT claimed. They must be
  certified on the DO round with a real Grok 4.5 backend. `check_duplicate`
  (embeddings, no LLM) passed on the first pass.
- **DISCLOSED GAPS, deliberately outside the cert boundary:** the 21 fully-501
  pg routes (#2803), `doctor` pg-direct (#2810), and `doctor --remote` on a
  hardened daemon (#2815, filed by this re-mint).
- **SCOPE:** this verdict is Track A, LOCAL. A campaign-level SHIP additionally
  requires reproduction on the DO re-host with a real LLM, per PLAN.md.
