---
layout: doc
---
# NHI Dogfood Playbook — P0 through P11 (v1.0.0)

**Purpose.** The reproducible, versioned Non-Human-Intelligence (NHI) dogfood
playbook: twelve phases (P0-P11) an AI NHI agent drives against a running
ai-memory v1.0.0 binary over MCP / HTTP / CLI to certify the substrate
end-to-end. This doc closes a reproducibility gap — the playbook previously
lived only as a stored memory. It is Track A of the
`test-campaign-2026-08-08-enterprise-cert` (see `PLAN.md`).

**Lineage.** Reconstructed from the v0.7.0 Run-3 result set
(`docs/v0.7.0/test-campaign-2026-05-18-dogfood/track-a-nhi-results-run3.md`,
which enumerated P0..P11 with per-assertion evidence and minted SHIP at
89 PASS / 0 FAIL) and updated to the v1.0.0 SSOT surface. The v0.8.0 dogfood
evidence in-repo is the IronClaw A2A campaign
(`docs/v0.8.0/test-campaign-2026-06-24-ironclaw-a2a/`), which is Track B here,
not the P0-P11 surface.

**How to run.** Drive each phase against a freshly-built binary
(`cargo build --release --features sal,sal-postgres`), MCP over stdio
(`printf '<JSON-RPC>' | ./target/release/ai-memory mcp --profile full`), HTTP
over the daemon (`ai-memory serve`), and CLI directly. Each phase uses an
isolated namespace / DB so phases do not cross-contaminate. Every phase records
its PASS/FAIL tally + evidence (row ids, SQL confirmations, error strings).

**v1.0.0 SSOT values used below** (from `CLAUDE.md` / the canonical Rust consts):
schema **v88**; MCP tools **103** at `--profile full` (102 callable + the
always-on `memory_capabilities` bootstrap), **7** at `--profile core`
per `Profile::core().expected_tool_count()` — which `tools/list` renders as
**8** entries, the same 7 callable tools plus that always-on bootstrap;
capabilities envelope `schema_version` **"3"**; `Memory` **30 fields**;
`MemoryLinkRelation::COUNT` **9**; HTTP **94** route registrations / **80**
unique paths; CLI **90** default / **92** sal subcommands; `HookEvent`
variants **22**. Because these are SSOT-derived, a phase asserts "matches the
compiled SSOT" rather than a frozen literal — a mismatch is itself a finding.

---

## P0 — Environment & version handshake

**Verifies:** the binary under test is the intended v1.0.0 build, the MCP
protocol handshake succeeds, and the advertised surface matches the SSOT.

**Pass assertion:**
- `ai-memory --version` reports `ai-memory 1.0.0` and the binary realpath is the
  campaign build (not a stale brew/homebrew binary).
- MCP `initialize` handshake succeeds; `serverInfo.version` = `1.0.0`.
- `memory_capabilities.schema_version` = `"3"`; `memory_capabilities.version` = `1.0.0`.
- All tool families load (`loaded:true`).
- `tools/list` count = **103** at `--profile full` (matches
  `Profile::full().expected_tool_count()`); `--profile core` = **8** —
  the 7 `Family::Core` tools (`Profile::core().expected_tool_count()`)
  plus the always-on `memory_capabilities` bootstrap, which
  `ALWAYS_ON_TOOLS` (`src/profile.rs`) registers outside the
  profile filter per RFC S27. Same framing as the full count above.

**Exercised by:** `src/profile.rs::Profile::full().expected_tool_count()`,
`tests/mcp_tools_list_schema_discovery.rs`, the MCP `initialize` + `memory_capabilities` handshake.

---

## P1 — Core CRUD + DF-1..DF-4 (provenance wire-schema)

**Verifies:** the primitive store/recall/search/list/delete round-trip, plus the
Form-4 provenance wire-schema fields (`source_uri`, `expected_version`,
`edit_source`) that must be discoverable AND persist end-to-end.

**Pass assertion:**
- `memory_store` → `memory_recall` (hybrid + rerank) → `memory_search` (FTS5) →
  `memory_list` (namespace-scoped) → `memory_delete` all round-trip; `agent_id`
  is auto-stamped and immutable across update.
- **DF-1:** MCP `tools/list` exposes `source_uri` in `memory_store.inputSchema.properties`.
- **DF-2:** `tools/list` exposes `expected_version` + `edit_source` + `source_uri` in `memory_update.inputSchema.properties`.
- **DF-3:** `memory_store {source_uri:"doc:X"}` persists — `SELECT source_uri FROM memories` equals `"doc:X"` end-to-end (MCP → validation → storage → SQL).
- **DF-4:** `memory_update {edit_source:"llm"}` triggers archive-and-supersede — an `archived_memories.archive_reason` row plus a new current row carrying `metadata.superseded_id`.

**Exercised by:** `tests/form_4_provenance`, the `source_uri` column tests,
`http_source_uri_query`; DF-1/DF-2 pin the #892/#893 schema-exposure.

---

## P2 — Lifecycle (tier transitions, archive-on-forget)

**Verifies:** TTL tiers, auto-promotion, explicit promotion, scoped forget, and
the archive-on-forget data-integrity contract. At v1.0.0 recall is PURE
(#1869/#1953) — access ladders are applied by the FOLD job, not synchronously —
so promotion is asserted after a fold, not inline.

**Pass assertion:**
- Default tier = mid (7d TTL); 5 accesses drive `access_count` to 5 and the row
  auto-promotes **mid→long** at `PROMOTION_THRESHOLD` after the fold; `expires_at` clears on long.
- `memory_promote` explicitly jumps mid→long (single call by default; optional `target_tier` stops at mid).
- `memory_forget` by namespace is EXACT-scoped (a sub-namespace survives a parent-namespace forget).
- **Archive-on-forget:** `memory_forget` writes an `archived_memories` row
  (`archive_reason='forget'`) for every matched row in the SAME transaction as
  the delete (#1776) whenever `[storage].archive_on_gc` is enabled — the
  compiled default (`effective_archive_on_gc()` → `true`). The response's
  `archived` field reports the disposition of that call. With
  `archive_on_gc = false` the same verb is a permanent hard-delete with no
  archive copy (boot emits `warn_if_archive_on_gc_disabled`). The GC TTL sweep
  archives on the same switch under `archive_reason='ttl_expired'`.
- **`memory_delete` by id is the hard, irreversible verb — it does NOT
  archive.** `db::delete` removes the row (and its embedding / FTS / link
  children) with NO `archived_memories` copy: it severs any `namespace_meta`
  binding (#2503) and appends an identity-only tombstone revision leaf ONLY
  when append-only is enabled (`AI_MEMORY_APPEND_ONLY`, off by default). Under
  the default configuration a deleted memory's durable text is not recoverable
  from the substrate — the tool's own `docs()` says "Hard-delete by id". An
  operator wanting a restorable copy uses `memory_forget` (or archives first).

**Exercised by:** `tests/recall_purity_p01.rs` (fold-before-gc, purity),
the promotion-threshold + archive-on-forget storage paths (`db::forget`),
`db::delete`, `memory_gc`.

---

## P3 — Knowledge graph

**Verifies:** entity registration/aliasing, typed links (9-relation closed
taxonomy), temporal validity, KG traversal, and invalidation propagation. On the
postgres substrate the AGE Cypher path is exercised; on sqlite the recursive-CTE path.

**Pass assertion:**
- `memory_entity_register` + `memory_entity_get_by_alias` resolve an alias to its canonical entity.
- `memory_link` with a valid relation (of the 9 in `MemoryLinkRelation`) creates an edge carrying `valid_from`, `attest_level`.
- `memory_kg_query` (`max_depth=3`) returns the full traversal path; `memory_kg_timeline` returns events with `valid_from` set.
- `memory_kg_invalidate` (source_id, target_id, relation) sets `valid_until`; a re-query returns `count:0` (invalidation propagates to the current view) and `attest_level` resets.
- `memory_find_paths` + `memory_get_taxonomy` + `memory_get_links` (temporal cols exposed) all return.

**Exercised by:** the `kg/` module tests (recursive-CTE + AGE Cypher), the
`memory_links` closed-taxonomy CHECK, temporal-validity columns.

---

## P4 — Governance & security hardening

**Verifies:** the governance surface, SSRF/HMAC gates, and — under the certified
config — attestation ON. Fail-closed everywhere.

**Pass assertion:**
- `memory_pending_list` / `memory_quota_status` / `memory_rule_list` return clean state (system-seeded rules present, `created_by="system:seed"`).
- `memory_check_agent_action` returns a typed decision for each action kind.
- `memory_subscribe` SSRF probes (AWS metadata IP / loopback / `file://`) are REJECTED at the HMAC gate (`HMAC secret required`) BEFORE URL validation — defense in depth; no orphan subscription rows created.
- `memory_notify` → `memory_inbox` round-trips.
- **Attestation ON:** an unsigned direct HTTP store is `403 ATTESTATION_FAILED`; a signed write lands `attest_level=agent_attested` (the Track E `test-attestation.sh` assertions hold on this binary).

**Exercised by:** the governance rule engine, the subscription HMAC gate,
`src/identity/attest.rs`, `infra/do-hive/crypto/test-attestation.sh`.

---

## P5 — Power tools (LLM-backed)

**Verifies:** the autonomous-tier LLM tools. Run with a real LLM backend
(Grok 4.5 via xAI-direct or OpenRouter, per the campaign config) — a
stub/abstaining backend makes these no-ops.

**Pass assertion:**
- `memory_check_duplicate` returns a similarity score and a correct `is_duplicate` boolean against the threshold.
- `memory_expand_query` returns LLM-generated query variants.
- `memory_auto_tag` (by memory `id`) returns quality tags.
- `memory_detect_contradiction` correctly flags a genuine contradiction (`contradicts:true`).

**Exercised by:** `src/llm.rs` (provider-agnostic client), the power-tool MCP
handlers; requires the resolved LLM backend reachable.

---

## P6 — Capabilities v3 shape

**Verifies:** the `memory_capabilities` envelope shape, family routing, and
optional-param discoverability.

**Pass assertion:**
- Default response: `schema_version="3"`, all families `loaded:true`, top-level `summary` + `to_describe_to_user` + `tools[]`.
- Optional params (`source_uri` / `expected_version` / `edit_source`) discoverable in the trimmed wire schemas (ties to P1 DF-1/DF-2).
- `memory_smart_load` + `memory_load_family` exposed and callable.
- Tool-count consistency: help-text / capabilities / `tools/list` all reconcile to the SSOT (103 at full).

**Exercised by:** `src/mcp/tools/capabilities.rs`, the capabilities-envelope tests.

---

## P7 — Token-budget ceiling

**Verifies:** the `tools/list` wire payload stays under the token ceiling after
the schemars expansion, so an NHI host's context budget is respected.

**Pass assertion:**
- The trimmed full-profile `tools/list` payload is under `TRIMMED_FULL_PROFILE_CEILING_TOKENS` (**11000** cl100k tokens, `tests/token_budget_guard.rs`).
- The verbose form stays under its own ceiling; the trimmer strips long-form prose (`docs`, nested `description`s, long defaults) while preserving the constructive `inputSchema` shape.

**Exercised by:** `tests/token_budget_guard.rs`,
`tests/mcp_tools_list_schema_discovery.rs`, `src/mcp/registry::strip_docs_from_tools`.

---

## P8 — Hooks & subscriptions

**Verifies:** the hook lifecycle surface enumeration and the mandatory-HMAC
subscription dispatch gate.

**Pass assertion:**
- `capabilities.hooks.webhook_events` enumerates the substrate's webhook event set; `hook_events_count` matches the compiled `HookEvent` SSOT (**22** variants at v1.0.0); `registered_count` = 0 in clean state (no orphan hooks).
- Subscription dispatch is HMAC-required (unsigned dispatch DISABLED since v0.7.0) — the three dangerous-URL probes from P4 are refused at the HMAC gate before URL validation.

**Exercised by:** `src/hooks/events.rs` (the `HookEvent` enum SSOT),
`src/subscriptions.rs` (HMAC-signed dispatch, DLQ, replay).

---

## P9 — MCP / HTTP / CLI parity

**Verifies:** the three interfaces agree on source attribution, validation, and
cross-interface behavior over the shared storage layer.

**Pass assertion:**
- An MCP-stored memory is retrievable via CLI `list --json` with source stamped `nhi` — the vendor-neutral `validate::DEFAULT_NHI_SOURCE` that replaced the pre-#1175 `claude` hardcode; the client identity lives in `metadata.agent_id` (e.g. `ai:claude@<host>`), not in `source`. A CLI-stored memory shows source `cli` with a synthesized durable `agent_id`.
- Validation parity: an invalid `agent_id` metachar (`$`) and a >128-byte `agent_id` are rejected identically at the CLI and MCP layers.
- Cross-interface contradiction detection fires (a CLI store flags a `potential_contradictions` id against a prior MCP store).
- (Postgres deployments serve MCP clients through the HTTP daemon — MCP stdio is structurally sqlite-only, #1675 — so HTTP↔CLI parity is the postgres-substrate assertion.)

**Exercised by:** the validation SSOT (`src/validate.rs`), the source-attribution
paths, the cross-interface storage layer.

---

## P10 — Performance & scale

**Verifies:** the performance budgets exist and hold, and the substrate reports
health honestly under sustained load.

**Pass assertion:**
- `PERFORMANCE.md` budgets exist and the run stays within them (recall p95, rerank budget #2608, recall-embed budget #2577).
- MCP `memory_stats` returns the serialized `models::memory::Stats` shape: `total` (RAW physical row count), the #2334 expiry-axis siblings `live` + `expired_pending_gc`, `by_tier`, `by_namespace`, `expiring_soon`, `links_count`, `db_size_bytes`, `dim_violations`, `index_evictions_total`. The MCP field is `total`, NOT `total_memories` — `total_memories` is what the HTTP admin stats surface (`handlers::admin`, `field_names::TOTAL_MEMORIES`) and `ai-memory doctor` / boot name the same value; reconcile per surface, and prefer `live` over `total` when comparing against boot's LIVE count.
- `ai-memory doctor` reports overall INFO with no corruption flagged; `/health` renders the cached FTS-integrity verdict (#2579) and `/metrics` renders the paced corpus gauge (#2583) with zero per-request DB scan cost.
- Sustained sequential recalls return cleanly with consistent shape (no lock starvation).

**Exercised by:** `PERFORMANCE.md`, `memory_stats`, `ai-memory doctor`,
`src/background/{fts_integrity,memories_gauge}.rs`.

---

## P11 — Failure & chaos (fail-closed)

**Verifies:** the substrate DEGRADES, never corrupts — under bogus input, chaos,
and adversarial identities it refuses loudly and self-heals, and the durable text
survives.

**Pass assertion:**
- `memory_get` on a bogus UUID returns a sanitized "not found" (no leak).
- Adversarial `agent_id`s (shell metachar `$`, 200-char overflow, null byte) are rejected at the validation layer.
- Sequential recalls across distinct contexts return cleanly (no DB-lock errors).
- **Fail-closed integrity:** `ai-memory doctor` post-chaos is INFO with no residual damage; `verify-audit-trail` is clean; no negative-path write silently succeeded. A power-loss/abort injection (`tests/power_loss_durability.rs`) loses no acknowledged write and leaves `integrity_check` clean.

**Exercised by:** the sanitized error paths, `src/validate.rs`,
`ai-memory doctor`, `verify-audit-trail`, `tests/power_loss_durability.rs`.

---

## Verdict rubric

At the end of P0-P11 the playbook mints exactly one verdict:

- **SHIP** — every phase's pass assertion GREEN, **0 FAIL**, and every negative /
  fail-closed assertion was correctly REFUSED. The substrate degraded where it
  should and never corrupted or lost durable text.
- **FIX-FIRST** — one or more FIXABLE defects surfaced (a wire-schema drift, a
  missing tool, a non-fatal parity mismatch). Per the repo prime directive these
  are NOT deferred: file → fix → retest → re-check, then re-run the affected
  phase. The verdict cannot be SHIP while any surfaced finding is open.
- **HOLD** — a data-integrity or fail-closed VIOLATION was observed: a negative
  assertion that was NOT refused (e.g. an unsigned write accepted while
  attestation is ON, an SSRF probe reaching the network, a corrupt/ambiguous
  migration), OR any unintentional data loss / corruption. HOLD blocks the whole
  campaign verdict until root-caused and closed — data integrity is the
  highest-order constraint and outranks every convenience.

A campaign-level SHIP requires this playbook to mint SHIP on the certified config
(encryption + attestation ON, PG16 + AGE 1.6.0 + pgvector, Grok 4.5), reproduced
on the DO re-host.
