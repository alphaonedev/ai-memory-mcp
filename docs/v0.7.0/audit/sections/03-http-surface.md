# 03 — HTTP Route Surface (v0.7.0)

Domain: `src/handlers/` (~35.3k LOC across 32 files) + the route-registration
table in `src/lib.rs` (`build_router_with_timeout`, lines 620-934).

All `file:line` provenance below is against branch `release/v0.7.0`. Counts are
derived mechanically; the exact commands are recorded in the
[Counts & Derivation](#counts--derivation) section.

---

## Counts & Derivation

The single source of truth for the daemon route table is
`build_router_with_timeout` in `src/lib.rs`. The `Router::new()...` chain runs
**lines 655-908** (the `#[cfg(test)] mod h7_timeout_tests` block with the extra
`/slow` route begins at line 962). `codegraph_search kind=route` is the
authoritative enumerator but caps at 100 results and intermixes the
`src/handlers/tests.rs` test-router literals, so the production counts below
are derived from the line-bounded router block directly.

| Metric | Value | Derivation |
|---|---|---|
| Production `.route(...)` registrations | **88** | `awk 'NR>=655 && NR<=908 && /\.route\(/' src/lib.rs \| wc -l` → 88 |
| Unique URL paths (multi-line-aware) | **74** | `awk 'NR>=655 && NR<=908 && /\.route\(/{f=1} f && /"\/[^"]*"/{match($0,/"\/[^"]*"/);print substr($0,RSTART,RLENGTH);f=0}' src/lib.rs \| sort -u \| wc -l` → 74 |
| Distinct `/api/v1` + `/metrics` literals | **74** | `grep -oE '"/(api/v1\|metrics)[^"]*"' src/lib.rs \| grep -v '/api/v1/\.\.\.' \| sort -u \| wc -l` → 74 (excludes the doc-comment literal `"/api/v1/..."` at `src/lib.rs:51`) |
| Total `.route(` in file (incl. `#[cfg(test)] /slow`) | **92** | `grep -c '\.route(' src/lib.rs` → 92. The 89th–92nd are inside the `h7_timeout_tests` module (`/slow` at `src/lib.rs:996` + test-router duplicates). The 89th production-counted `.route(` does NOT exist; the +4 are all test-only. |

**Verdict on the README/evidence claim (~88 registrations / ~74 unique paths /
"73 route literals"):**
- **88 registrations — CONFIRMED** exactly.
- **74 unique paths — CONFIRMED** exactly (`src/lib.rs:571-572` docstring
  asserts "88 production routes / 74 unique URL paths").
- **"73 route literals" — STALE.** That was the v0.6.4 figure (also referenced
  in `CLAUDE.md`'s "Count grew from v0.6.4's 73…" passage). At v0.7.0 the
  distinct `/api/v1` + `/metrics` literal count is **74**, not 73. See
  [DRIFT/DEFECTS SPOTTED](#driftdefects-spotted).

The 88-vs-74 delta is the set of paths that carry multiple HTTP methods
(e.g. `/api/v1/memories` GET+POST, `/api/v1/memories/{id}` GET+PUT+DELETE,
`/api/v1/archive` GET+POST+DELETE, `/api/v1/namespaces` GET+POST+DELETE,
`/api/v1/subscriptions` GET+POST+DELETE, `/api/v1/links` POST+DELETE,
`/metrics`+`/api/v1/metrics` duplicate mount, etc.).

---

## Route Catalogue (by area)

Handler `file:line` is the `pub async fn` definition site. Registration site is
in `src/lib.rs` within the `655-908` router block.

### Health & Metrics

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | `transport.rs:833` | Liveness/DB health probe; **exempt from api-key auth** (`transport.rs:753`). |
| GET | `/metrics` | `transport.rs:882` (`prometheus_metrics`) | Prometheus scrape (community convention path). |
| GET | `/api/v1/metrics` | `transport.rs:882` (`prometheus_metrics`) | Same handler, REST-consistent path. |

### Memory CRUD

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/memories` | `memories_query.rs:47` (`list_memories`) | List memories (filterable, incl. `?agent_id=`). |
| POST | `/api/v1/memories` | `create.rs:917` (`create_memory`) | Store a memory (UPSERT on `(title, namespace)`). |
| POST | `/api/v1/memories/bulk` | `memories_query.rs:500` (`bulk_create`) | Bulk store. |
| GET | `/api/v1/memories/{id}` | `memories.rs:31` (`get_memory`) | Fetch one by id. |
| PUT | `/api/v1/memories/{id}` | `memories.rs:188` (`update_memory`) | Update (Gap-1 optimistic-concurrency `version`). |
| DELETE | `/api/v1/memories/{id}` | `memories.rs:511` (`delete_memory`) | Delete by id. |
| POST | `/api/v1/memories/{id}/promote` | `memories.rs:885` (`promote_memory`) | Tier promotion (→ long by default). |

### Recall / Search

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/search` | `memories_query.rs:200` (`search_memories`) | FTS5 keyword search. |
| GET | `/api/v1/recall` | `recall.rs:85` (`recall_memories_get`) | Hybrid recall (query-string form). |
| POST | `/api/v1/recall` | `recall.rs:163` (`recall_memories_post`) | Hybrid recall (body form). |
| POST | `/api/v1/expand_query` | `power_consolidation.rs:614` (`expand_query_handler`) | LLM query expansion — see [envelope](#postapiv1expand_query-envelope-1445). |
| POST | `/api/v1/auto_tag` | `power_consolidation.rs:494` (`auto_tag_handler`) | LLM auto-tag (S51 mirror; 503 when no LLM). |

### Capture (L4 layered-capture)

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/capture_turn` | `capture_turn.rs:68` (`capture_turn`) | #1416 L4 idempotent turn-capture HTTP mirror of MCP `memory_capture_turn` (routes through SAL `capture_turn_idempotent`). |

### Links

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/links` | `links.rs:272` (`create_link`) | Create a typed directional link. |
| DELETE | `/api/v1/links` | `links.rs:651` (`delete_link`) | Delete a link. |
| GET | `/api/v1/links/{id}` | `links.rs:820` (`get_links`) | List links for a memory. |
| POST | `/api/v1/links/verify` | `links.rs:87` (`verify_link_handler`) | S52 link-signature verification. |

### Knowledge Graph (KG)

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/kg/timeline` | `kg.rs:511` (`kg_timeline`) | Temporal KG timeline (Pillar 2 / Stream C). |
| POST | `/api/v1/kg/invalidate` | `kg.rs:759` (`kg_invalidate`) | KG link supersession (admin-gated). |
| POST | `/api/v1/kg/query` | `kg.rs:1166` (`kg_query`) | Outbound KG traversal. |
| POST | `/api/v1/kg/find_paths` | `kg.rs:983` (`kg_find_paths`) | S65 path enumeration. |
| POST | `/api/v1/find_paths` | `kg.rs:983` (`kg_find_paths`) | #934 alias to the same handler (legacy callers / MCP `memory_find_paths` shape). |
| POST | `/api/v1/check_duplicate` | `power.rs:690` (`check_duplicate`) | Pre-write near-dup check (Pillar 2 / Stream D). |
| POST | `/api/v1/entities` | `kg.rs:76` (`entity_register`) | Entity registry (Pillar 2 / Stream B). |
| GET | `/api/v1/entities/by_alias` | `kg.rs:291` (`entity_get_by_alias`) | Entity lookup by alias. |
| GET | `/api/v1/contradictions` | `power.rs:68` (`detect_contradictions`) | LLM contradiction detection. |
| POST | `/api/v1/consolidate` | `power_consolidation.rs:227` (`consolidate_memories`) | LLM consolidate (H8 timeout, `power_consolidation.rs:138`). |
| POST | `/api/v1/forget` | `memories_query.rs:388` (`forget_memories`) | Bulk forget. |

### Namespace / Taxonomy / Governance

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/namespaces` | `hook_subscribers.rs:835` (`get_namespace_standard_qs`) | List namespaces / fetch standard (`?namespace=`). |
| POST | `/api/v1/namespaces` | `hook_subscribers.rs:816` (`set_namespace_standard_qs`) | Set a namespace standard (query-string form). |
| DELETE | `/api/v1/namespaces` | `hook_subscribers.rs:989` (`clear_namespace_standard_qs`) | Clear a standard (query-string form). |
| POST | `/api/v1/namespaces/{ns}/standard` | `hook_subscribers.rs:772` (`set_namespace_standard`) | Set standard (path form, MCP parity). |
| GET | `/api/v1/namespaces/{ns}/standard` | `hook_subscribers.rs:789` (`get_namespace_standard`) | Get standard (path form). |
| DELETE | `/api/v1/namespaces/{ns}/standard` | `hook_subscribers.rs:807` (`clear_namespace_standard`) | Clear standard (path form). |
| GET | `/api/v1/taxonomy` | `power.rs:449` (`get_taxonomy`) | Hierarchical namespace taxonomy (Pillar 1 / Stream A). |
| GET | `/api/v1/pending` | `governance.rs:47` (`list_pending`) | List pending governance approvals. |
| POST | `/api/v1/pending/{id}/approve` | `governance.rs:166` (`approve_pending`) | Approve a pending write (FORBIDDEN gate `governance.rs:301`). |
| POST | `/api/v1/pending/{id}/reject` | `governance.rs:398` (`reject_pending`) | Reject a pending write (FORBIDDEN gate `governance.rs:383`). |

### Approvals (K10 — HMAC-gated)

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/approvals/{pending_id}` | `approvals.rs:210` (`approval_decide`) | HMAC-signed approval decision. Verifies `X-AI-Memory-Signature` + `X-AI-Memory-Timestamp` over `{ts}.{method}.{pending_id}.{body}`; 300s replay window, single-use nonce (`approvals.rs:112-183`). |
| GET | `/api/v1/approvals/stream` | `approvals.rs:490` (`approvals_sse`) | SSE stream (rides existing api-key auth, no extra gate). |

### Federation

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/sync/push` | `federation_receive.rs:305` (`sync_push`) | Peer push receive; Ed25519 `X-Memory-Sig` + nonce (`AI_MEMORY_FED_REQUIRE_SIG=1` / `_REQUIRE_NONCE=1` defaults). |
| GET | `/api/v1/sync/since` | `federation_sync_since.rs:32` (`sync_since`) | Peer pull-since; signed-GET gate (#1031). |

> **Federation auth bypass:** when mTLS is enforced, `/api/v1/sync/*` bypasses
> the `x-api-key` middleware (`transport.rs:796`) because the request already
> cleared cert-fingerprint pinning; the downstream signed-message gate binds
> `X-Peer-Id` to an enrolled Ed25519 key.

### Identity / Agents

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/agents` | `admin.rs:221` (`list_agents`) | List registered agents. |
| POST | `/api/v1/agents` | `admin.rs:40` (`register_agent`) | Register an agent (NHI). |
| GET | `/api/v1/capabilities` | `system.rs:21` (`get_capabilities`) | Capabilities envelope (schema v3; `Accept-Capabilities` negotiable). |
| POST | `/api/v1/session/start` | `hook_subscribers.rs:1102` (`session_start`) | Session-start hook ingest. |
| POST | `/api/v1/share` | `share.rs:48` (`share_memory`) | #1095 share-to-agent (MCP `memory_share` parity). |

### Skills (Cluster E API-2, #767 — 7 routes)

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/skill/register` | `skills.rs:59` (`skill_register_route`) | Register a skill. |
| GET | `/api/v1/skill/list` | `skills.rs:88` (`skill_list_route`) | List skills. |
| GET | `/api/v1/skill/{id}` | `skills.rs:131` (`skill_get_route`) | Get a skill. |
| GET | `/api/v1/skill/{id}/resource` | `skills.rs:176` (`skill_resource_route`) | Fetch a skill resource. |
| POST | `/api/v1/skill/{id}/export` | `skills.rs:216` (`skill_export_route`) | Export a skill. |
| POST | `/api/v1/skill/{id}/promote` | `skills.rs:261` (`skill_promote_route`) | Promote skill from reflection. |
| POST | `/api/v1/skill/{id}/compose` | `skills.rs:305` (`skill_compose_route`) | Compositional-context compose. |

### Subscriptions / Notify / Inbox

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| POST | `/api/v1/subscriptions` | `subscriptions.rs:242` (`subscribe`) | Create a webhook subscription (HMAC mandatory at v0.7.0). |
| DELETE | `/api/v1/subscriptions` | `subscriptions.rs:545` (`unsubscribe`) | Delete a subscription. |
| GET | `/api/v1/subscriptions` | `subscriptions.rs:732` (`list_subscriptions`) | List subscriptions. |
| POST | `/api/v1/notify` | `subscriptions.rs:55` (`notify`) | Emit a notification (FORBIDDEN gates `subscriptions.rs:82,262,...`). |
| GET | `/api/v1/inbox` | `hook_subscribers.rs:37` (`get_inbox`) | Fetch inbox notifications. |

### Admin

| Method | Path | Handler `file:line` | Purpose |
|---|---|---|---|
| GET | `/api/v1/tools/list` | `admin.rs:888` (`tools_list`) | L9 HTTP parity for MCP `tools/list`. |
| POST | `/api/v1/memory_load_family` | `power_consolidation.rs:752` (`load_family_handler`) | L10 HTTP parity for `memory_load_family`. |
| POST | `/api/v1/quota/status` | `admin.rs:300` (`quota_status_handler`) | S61 per-agent quota status. |
| GET | `/api/v1/stats` | `admin.rs:417` (`get_stats`) | Store statistics. |
| POST | `/api/v1/gc` | `admin.rs:479` (`run_gc`) | Trigger GC (takes `HeaderMap` → admin-gated). |
| GET | `/api/v1/export` | `admin.rs:532` (`export_memories`) | Export (takes `HeaderMap` → admin-gated). |
| POST | `/api/v1/import` | `admin.rs:610` (`import_memories`) | Import. |
| GET | `/api/v1/archive` | `archive.rs:52` (`list_archive`) | List archived memories. |
| POST | `/api/v1/archive` | `archive.rs:435` (`archive_by_ids`) | Archive by ids. |
| DELETE | `/api/v1/archive` | `archive.rs:270` (`purge_archive`) | Purge archive. |
| POST | `/api/v1/archive/{id}/restore` | `archive.rs:122` (`restore_archive`) | Restore archived memory. |
| GET | `/api/v1/archive/stats` | `archive.rs:369` (`archive_stats`) | Archive statistics. |

### Parity routes (#1111 — 14 thin MCP wrappers, all in `route_1111.rs`)

All POST, all in `src/handlers/route_1111.rs`. Each wraps the existing
`crate::mcp::handle_<name>` substrate primitive; wire envelopes byte-equal to MCP.

| Method | Path | Handler `file:line` |
|---|---|---|
| POST | `/api/v1/memory_smart_load` | `route_1111.rs:67` (`handle_smart_load_http`) |
| POST | `/api/v1/memory_reflect` | `route_1111.rs:91` (`handle_reflect_http`) |
| POST | `/api/v1/memory_recall_observations` | `route_1111.rs:129` (`handle_recall_observations_http`) |
| POST | `/api/v1/memory_reflection_origin` | `route_1111.rs:146` (`handle_reflection_origin_http`) |
| POST | `/api/v1/memory_dependents_of_invalidated` | `route_1111.rs:163` (`handle_dependents_of_invalidated_http`) |
| POST | `/api/v1/memory_export_reflection` | `route_1111.rs:181` (`handle_export_reflection_http`) |
| POST | `/api/v1/memory_atomise` | `route_1111.rs:203` (`handle_atomise_http`) |
| POST | `/api/v1/memory_calibrate_confidence` | `route_1111.rs:222` (`handle_calibrate_confidence_http`) |
| POST | `/api/v1/memory_verify` | `route_1111.rs:239` (`handle_verify_http`) |
| POST | `/api/v1/memory_replay` | `route_1111.rs:256` (`handle_replay_http`) |
| POST | `/api/v1/memory_subscription_replay` | `route_1111.rs:286` (`handle_subscription_replay_http`) |
| POST | `/api/v1/memory_subscription_dlq_list` | `route_1111.rs:311` (`handle_subscription_dlq_list_http`) |
| POST | `/api/v1/memory_rule_list` | `route_1111.rs:333` (`handle_rule_list_http`) |
| POST | `/api/v1/memory_check_agent_action` | `route_1111.rs:351` (`handle_check_agent_action_http`) |

---

## Auth / Admin Gating Posture

**Middleware stack** (applied in `build_router_with_timeout`, outermost last):
1. `api_key_auth` (`transport.rs:742`, registered `src/lib.rs:909-912`)
2. `postgres_route_gate_layer` (`src/lib.rs:919-922`)
3. `TraceLayer` → `DefaultBodyLimit::max(2 MiB)` → `CorsLayer` → `timeout_layer` (H7)

### API-key auth (`transport.rs:742-831`)
- If no key configured → **allow all** (`transport.rs:747-750`).
- `/api/v1/health` is **always exempt** (`transport.rs:753`).
- `/api/v1/sync/*` is **exempt when mTLS is enforced** (`transport.rs:796`).
- Key accepted via `X-API-Key` header (constant-time compare, `transport.rs:801-806`)
  OR `?api_key=` query param (URL-decoded first, #337, `transport.rs:815-824`).
- Failure → **`401 Unauthorized`** `{"error":"missing or invalid API key"}`
  (`transport.rs:826-830`).

### HMAC gating (write-path / approval)
- **K10 approvals** (`POST /api/v1/approvals/{pending_id}`): mandatory HMAC over
  `{ts}.{method}.{pending_id}.{body}` via `X-AI-Memory-Signature` +
  `X-AI-Memory-Timestamp`; 300s replay window, single-use nonce cache. Every
  failure mode → **`401`** (`approvals.rs:112-183`). No server HMAC secret
  configured → reject-all (strict default).
- **Subscriptions / notify** HMAC-signed dispatch is mandatory at v0.7.0
  (unsigned dispatch disabled); refusals surface as **`403 Forbidden`**
  (`subscriptions.rs:82,262,576,657,752`).
- **Federation** `/sync/push` + `/sync/since`: Ed25519 `X-Memory-Sig` + nonce,
  default-secure → **`401`** on missing/invalid sig or nonce replay.

### Admin gating (privacy-bypass)
- `CallerContext::for_admin_checked(caller, is_admin)` is the typed admin gate
  (#1062). Live sites in this surface: `archive.rs:327`, `kg.rs:346`.
- Admin allowlist composed from the resolved daemon `agent_id` +
  `AI_MEMORY_ADMIN_AGENT_IDS`; admin ops are audit-logged.
- Header-resolved-caller handlers (`run_gc`, `export_memories`, `import_memories`
  take `headers: HeaderMap`) apply the admin/caller scope per the postgres-gate
  C8 invariant.
- Governance approve/reject and notify return **`403 Forbidden`** on
  authorization failure (`governance.rs:301,383`).

### H7 per-request timeout (`src/lib.rs:620-653`)
- Custom `axum::middleware::from_fn` wraps every request in
  `tokio::time::timeout`. On expiry → **`504 Gateway Timeout`**
  `{"error":"request timed out"}` (`src/lib.rs:646-648`). Default 60s
  (`AppConfig::effective_request_timeout_secs`). 504 is deliberately distinct
  from request-shape 400s.

### H8 per-LLM-call timeout
- Distinct from H7. Bounds the upstream LLM call by `app.llm_call_timeout`
  (default 30s) inside LLM handlers. On timeout the handler degrades gracefully
  (empty expansion / empty tags / summarization fallback), not 504:
  - `consolidate`: `power_consolidation.rs:138`
  - `auto_tag`: `power_consolidation.rs:578`
  - `expand_query`: `power_consolidation.rs:661`

### Status-code granularity (HTTP-layer)
- **401** — api-key failure (`transport.rs:827`), HMAC/federation sig failures.
- **403** — governance / subscription authorization refusals.
- **501** — postgres-route-gate: un-migrated endpoint on a postgres-backed
  daemon returns `{"error":"endpoint not yet implemented for postgres-backed
  daemon"}` (`postgres_gate.rs:66-69`), allow-list = `postgres_endpoint_supported`
  (`postgres_gate.rs:95`). On sqlite this layer is a pure pass-through.
- **502** — LLM upstream error in `expand_query` (`power_consolidation.rs:654`).
- **503** — LLM not configured (`expand_query` `power_consolidation.rs:620`;
  `auto_tag` likewise).
- **400** — empty/missing query (`expand_query` `power_consolidation.rs:628`).
- **504** — H7 request timeout (`src/lib.rs:646`).

---

## `POST /api/v1/expand_query` envelope (#1445)

Handler `power_consolidation.rs:614-676`. Docstring `power_consolidation.rs:603-613`.

- **Request:** `{query, namespace?}` (`ExpandQueryBody`).
- **200 OK envelope:** `{"original": <query>, "expanded_terms": [..]}`
  (`power_consolidation.rs:668-674`).
- **Three-surface envelope parity (#1445):** the `{original, expanded_terms}`
  keys are byte-identical to the MCP `memory_expand_query` tool and the
  `ai-memory expand` CLI surface. Parity is asserted in the handler docstring
  (`power_consolidation.rs:608-610`).
- **Degradation / error matrix:**
  - `503 {"error":"LLM not configured"}` when `app.llm.is_none()` (line 620).
  - `400 {"error":"query is required"}` on empty/whitespace query (line 628).
  - `502 {"error":"LLM expand_query failed: ..."}` on upstream LLM error (line 654).
  - **H8 timeout path:** on `tokio::time::timeout(llm_timeout, ...)` expiry the
    handler returns **200 with an empty `expanded_terms` list** (matches the
    LLM-absent fallback shape) rather than an error (`power_consolidation.rs:659-665`).

---

## DRIFT/DEFECTS SPOTTED

1. **"73 route literals" is stale (count drift).** The v0.7.0 surface has **74**
   distinct `/api/v1`+`/metrics` literals, not 73. 73 was the v0.6.4 figure
   (`CLAUDE.md`: "Count grew from v0.6.4's 73…"). The README/evidence's "88
   registrations / 74 unique paths" pair IS correct; only the bare "73 route
   literals" phrasing is a v0.6.4 carry-over. **Severity: docs-drift** — file
   + correct per the prime directive.

2. **`codegraph_search kind=route` undercounts/over-mixes for this file.** It
   caps at 100 and intermixes `src/handlers/tests.rs` test-router literals with
   the production `src/lib.rs` registrations (e.g. it surfaces
   `DELETE /api/v1/subscribe`, a **test-only** path at `tests.rs:12053` that has
   **no production route**). Auditors must derive production counts from the
   line-bounded `src/lib.rs:655-908` block, not from the raw route index.
   **Not a code defect** — a tooling caveat to record so the count isn't
   double-counted.

3. **Doc-comment literal `"/api/v1/..."` at `src/lib.rs:51`** is a path-pattern
   illustration, not a route; naive `grep '"/api/v1'` counting includes it and
   inflates the unique-path count by 1 (would yield 75). The `grep -v
   '/api/v1/\.\.\.'` filter is required for an accurate 74.

4. **No "registered-route-without-handler" drift found.** Every one of the 88
   `.route(...)` registrations resolves to a defined `pub async fn` handler
   (all 88 handler sites confirmed in §Route Catalogue). The `/api/v1/find_paths`
   ↔ `/api/v1/kg/find_paths` pair intentionally share one handler
   (`kg.rs:983`, #934 alias) — not a defect.
