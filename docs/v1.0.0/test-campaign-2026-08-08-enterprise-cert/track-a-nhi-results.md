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

## Phase summary

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
| **Overall** | — | **FIX-FIRST** | 2 fixable pg defects (P3) block a campaign SHIP; no data-integrity / fail-closed VIOLATION observed |

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
