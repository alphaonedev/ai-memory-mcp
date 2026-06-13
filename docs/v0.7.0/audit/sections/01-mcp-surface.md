# 01 — MCP Tool Surface (v0.7.0)

Scope: everything under `src/mcp/` (~45.8k LOC) plus `src/profile.rs` (the
tool-count SSOT). Every claim below carries a `file:line` anchor verified
against the `release/v0.7.0` checkout at `/Users/fate/v07/v07-f5`. Numbers
are derived from source, not from prose.

---

## 1. Headline counts (with SSOT anchors)

| Quantity | Value | SSOT |
|---|---|---|
| `Profile::full().expected_tool_count()` | **74** advertised entries | `src/profile.rs:630-632` (sum over `Family::all()`), derived from `Family::tool_names()` slices `src/profile.rs:352-517` |
| `Profile::core().expected_tool_count()` | **7** tools | `src/profile.rs:564-569` (Core family only); Core slice = 7 names `src/profile.rs:360-374` |
| Callable "memory tools" (full, ex-bootstrap) | **73** | `73 + 1 always-on = 74`; user-facing count computed at `src/mcp/tools/capabilities.rs:523-527` |
| Always-on bootstrap tools | **1** (`memory_capabilities`) | `src/profile.rs:130` (`ALWAYS_ON_TOOLS`, `len == 1`) |
| `tool_names::ALL` length | **74** | `src/mcp/registry.rs:127-202` (74 `MEMORY_*` consts) |
| `TOOL_DISPATCH_TABLE` entries | **74** | `src/mcp/mod.rs:1679-1872` (74 `register_mcp_tool!`) |
| `registered_tools()` rows | **74** | `src/mcp/registry.rs:572-650` (74 `RegisteredTool::of`) |

**The "74" is the single canonical number for `--profile full`.** All three
independent enumerations (the family `tool_names` slices feeding
`Profile::full().expected_tool_count()`, the `tool_names::ALL` const slice,
and the `registered_tools()` iterator) agree at 74, and the cross-module
invariant tests pin them in lockstep:

- `family_tool_names_cover_registry_all` — union of all 8 family slices ==
  `tool_names::ALL.len()` — `src/profile.rs:786-802`.
- `const_count_matches_full_profile` — `tool_names::ALL.len()` ==
  `Profile::full().expected_tool_count()` — `src/mcp/registry.rs:213-231`.
- `consts_match_registered_tools` — `tool_names::ALL` set ==
  `registered_tools()` name set — `src/mcp/registry.rs:367-389`.
- `profile_full_matches_registry_all` — `Profile::full()` count ==
  `tool_names::ALL.len()` — `src/profile.rs:888-905`.

`memory_capabilities` is counted **inside** the `Meta` family slice
(`src/profile.rs:487`) AND is the sole `ALWAYS_ON_TOOLS` entry
(`src/profile.rs:130`). It is registered like any other tool in
`registered_tools()` (`src/mcp/registry.rs:609`) and in the dispatch table
(`src/mcp/mod.rs:1745`). So the "73 callable + 1 always-on = 74" framing is
a *presentation* split (CLAUDE.md / issue #862), not two disjoint sets — all
74 are dispatchable; `memory_capabilities` just also loads under every
profile regardless of family gating.

---

## 2. The profile system

### 2.1 Families (the gating unit)

`Family` enum — 8 variants, declaration order is the load/preview order
(`src/profile.rs:73-108`, `Family::all()` at `src/profile.rs:308-319`):

| Family | Count | Members (SSOT slice) |
|---|---|---|
| `Core` | 7 | store, recall, list, get, search, load_family, smart_load — `src/profile.rs:360-374` |
| `Lifecycle` | 6 | update, delete, forget, gc, promote, **capture_turn** — `src/profile.rs:375-385` |
| `Graph` | 11 | kg_query, kg_timeline, kg_invalidate, link, get_links, entity_register, entity_get_by_alias, get_taxonomy, replay, verify, find_paths — `src/profile.rs:386-404` |
| `Governance` | 8 | pending_list/approve/reject, namespace_set/get/clear_standard, subscribe, unsubscribe — `src/profile.rs:405-414` |
| `Power` | 23 | consolidate, detect_contradiction, check_duplicate, auto_tag, expand_query, inbox, subscription_replay, subscription_dlq_list, quota_status, reflect, reflection_origin, dependents_of_invalidated, check_agent_action, rule_list, export_reflection, offload, deref, atomise, persona, persona_generate, ingest_multistep, calibrate_confidence, share — `src/profile.rs:415-485` |
| `Meta` | 6 | **capabilities**, agent_register, agent_list, session_start, stats, recall_observations — `src/profile.rs:486-495` |
| `Archive` | 4 | archive_list, archive_purge, archive_restore, archive_stats — `src/profile.rs:496-501` |
| `Other` | 9 | list_subscriptions, notify, skill_register, skill_list, skill_get, skill_resource, skill_export, skill_promote_from_reflection, skill_compositional_context — `src/profile.rs:502-515` |

Sum: 7+6+11+8+23+6+4+9 = **74**. `Family::expected_tool_count()` is
`self.tool_names().len()` — no hand-maintained magic numbers
(`src/profile.rs:333-335`). NOTE the doc comments at `src/profile.rs:182`
("power — 23") are correct; the older module-level prose (`src/profile.rs:33`,
"~15 tools", "8 LLM-augmented") is stale narrative — see DRIFT §6.

### 2.2 Named profiles

| Profile | Families | Count | Constructor |
|---|---|---|---|
| `core` (default) | Core | 7 | `src/profile.rs:564-569`; `Default` → core `src/profile.rs:722-726` |
| `graph` | Core+Graph | 18 | `src/profile.rs:575-580` |
| `admin` | Core+Lifecycle+Governance | 21 | `src/profile.rs:585-590` |
| `power` | Core+Power | 30 | `src/profile.rs:596-601` |
| `full` | all 8 | 74 | `src/profile.rs:608-613` |

`admin` is 7+6+8 = **21** (the doc comment at `src/profile.rs:582` says "20
tools" — stale, pre-`capture_turn`; see DRIFT §6). `power` is 7+23 = **30**
(the `src/profile.rs:592` comment says "15 tools" — also stale).

Resolution order: `CLI flag > AI_MEMORY_PROFILE env > [mcp].profile config >
"core"` (`src/profile.rs:15-17`). Env var documented as `AI_MEMORY_PROFILE`,
MCP-only (CLAUDE.md env table row 6).

### 2.3 Custom-profile parsing (`Profile::parse`, `src/profile.rs:657-719`)

- empty / whitespace-only → `core()` (`:659-661`)
- mixed-case (`Core`) → `ProfileParseError::CaseMismatch` (`:666-668`)
- comma list mixes profile + family names; `core` implicitly added if absent
  (`:708-710`); `core,full` → `full` (`:695`)
- unknown token → `UnknownFamily` listing every valid name (`:736-759`)
- dedupe + declaration-order sort so `graph,core` == `core,graph` (`:715-716`)

### 2.4 Profile gating predicate

`Profile::loads(name)` returns true if the name is in `ALWAYS_ON_TOOLS`
**OR** its family is in the profile (`src/profile.rs:639-644`). This is the
mechanism by which `memory_capabilities` is callable under `--profile core`
even though `Meta` is not loaded.

---

## 3. Dispatch routing & registry plumbing

- **`McpTool` trait** (`src/mcp/registry.rs:436-459`) — each tool is a
  zero-sized type exposing `name()`, `description()` (≤50 cl100k tokens, bare
  `tools/list`), `docs()` (long-form, reachable via `memory_capabilities`),
  `input_schema()` (schemars-derived from the per-tool `<Tool>Request`
  struct), `family()`.
- **`RegisteredTool` / `registered_tools()`** (`src/mcp/registry.rs:472-650`)
  — the canonical catalog iterator; one `RegisteredTool::of::<T>()` line per
  tool. `to_value()` (`:520-537`) renders the wire shape
  `{name, description, docs, inputSchema}`, back-filling `"properties": {}`
  for zero-field request structs.
- **`TOOL_DISPATCH_TABLE`** (`src/mcp/mod.rs:1679-1872`) — `&[(&str,
  DispatchFn)]`; each arm references a `tool_names::*` const so a rename is a
  one-line edit. `DispatchFn = fn(&ToolDispatchCtx) -> Result<Value, String>`
  (`src/mcp/mod.rs:1006`). Each `dispatch_memory_*` wrapper un-bundles
  `ToolDispatchCtx` (`src/mcp/mod.rs:971`) into the positional args its
  handler expects.
- **`lookup_dispatch(name)`** (`src/mcp/mod.rs:1884`) — O(1) `OnceLock`
  HashMap built from the dispatch table (#1105); `None` → JSON-RPC `-32601`
  method-not-found.
- **MCP transport** is a synchronous single-threaded stdio loop over
  `stdin.lock().lines()`; the connection is a plain `rusqlite::Connection`
  (no `Arc`/`Mutex`) — `src/mcp/mod.rs:2013` per CLAUDE.md.

### Input-schema shaping (the wire trimmers)

- `tool_definitions_for_profile(profile)` — memoized per-`Profile`
  (`src/mcp/registry.rs:970-990`); cache-miss path
  `build_tool_definitions_for_profile` (`:995-1002`).
- Default path applies `trim_optional_params` (`:728-756` — strips per-prop
  `description` prose but **preserves every property + structural metadata**
  post-#859) then `wire_compact_descriptions` (`:1021-1037`).
- `strip_docs_from_tools` drops the top-level `docs` field + schemars-only
  metadata so the bare `tools/list` holds the C5 ≤11000-token ceiling
  (CLAUDE.md; `tests/token_budget_guard.rs:75`).
- Verbose escape hatch: `tool_definitions_for_profile_verbose`
  (`:1101+`) and env `AI_MEMORY_TOOLS_VERBOSE` (`tools_verbose_env_enabled`,
  `:1079-1086`).
- `TOOLS_VERSION = "2026-05-06"` (`src/mcp/registry.rs:667`) — `tools/list`
  schema version tag.

---

## 4. The capabilities envelope (`memory_capabilities`)

- Handler: v1/v2 → `handle_capabilities_with_conn`
  (`src/mcp/tools/capabilities.rs:229`); v3 →
  `handle_capabilities_with_conn_v3` (`:269`). Dispatch wrapper
  `dispatch_memory_capabilities` (`src/mcp/mod.rs:1347`).
- **`schema_version` is `"3"` at v0.7.0** — emitted at `src/config.rs:1733`
  (`schema_version: "3".to_string()`); pinned by `assert_eq!(v["schema_version"],
  "3")` at `src/mcp/mod.rs:12806`.
- Accept negotiation: `CapabilitiesAccept { V1, V2, V3 }`
  (`src/mcp/tools/capabilities.rs:176-202`). `parse()` falls back to **V3**
  on unknown/missing; explicit `"v2"`/`"2"` and `"v1"`/`"1"` honored. HTTP
  sends `Accept-Capabilities:`; MCP passes `accept:` param.
- v3 additive fields over v2: `summary` (`build_capabilities_summary`
  `:508`), `to_describe_to_user` (`build_capabilities_describe_to_user`
  `:573`), per-tool `tools[].callable_now` (`build_capabilities_tools`
  `:658`), optional `agent_permitted_families`
  (`build_agent_permitted_families` `:847`), and `governance.agent_action_check`
  + `governance.rules_immutable_seed` (#691, `:315-329`).
- `CapabilitiesRequest` fields: `accept`, `family`, `include_schema`,
  `verbose` — all `Option`, all `#[serde(default)]`
  (`src/mcp/tools/capabilities.rs:32-55`).
- Family drilldown: `handle_capabilities_family`
  (`src/mcp/registry.rs:835-946`) — `include_schema` gated by
  `[mcp.allowlist]` (`:861-886`), grants/denies recorded via
  `record_capability_expansion`; `verbose` controls docs + optional-param
  retention.
- `families_overview` (`src/mcp/registry.rs:770-799`) emits per-family
  `{name, tool_count, loaded, tools}` plus `always_on` list; its own
  `schema_version` is the family-local tag `"v0.6.4-families-1"`.

---

## 5. Full tool catalogue by functional area

Handler symbol + `file:line` from `src/mcp/tools/*`; description = the
verbatim `McpTool::description()` (bare-wire one-liner). All 74 below.

### Core / store-recall-search (Family::Core, 7)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_store` | Store a memory; deduplicates by title+namespace. | `handle_store` `store/mod.rs:240` |
| `memory_recall` | Recall memories relevant to a context (ranked). | `handle_recall` `recall.rs:622` (DTO: `handle_recall_dto:656`) |
| `memory_search` | Search memories by exact keyword match (AND semantics). | `handle_search` `search.rs:70` |
| `memory_list` | List memories, optionally filtered by namespace or tier. | `handle_list` `list.rs:60` |
| `memory_get` | Get a specific memory by ID, including its links. | `handle_get` `get.rs:45` |
| `memory_load_family` | Load top-k recent + high-priority memories from a Family. | `handle_load_family` `load_family.rs:238` |
| `memory_smart_load` | Intent-routed loader: free-text intent picks the best Family. | `handle_smart_load` `load_family.rs:332` |

### Lifecycle (Family::Lifecycle, 6)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_update` | Update an existing memory by ID (only provided fields change). | `handle_update` `update.rs:117` |
| `memory_delete` | Delete a memory by ID. | `handle_delete` `delete.rs:69` |
| `memory_forget` | Bulk delete memories matching a pattern/namespace/tier (archives first). | `handle_forget` `forget.rs:10` |
| `memory_gc` | Trigger garbage collection on expired memories (archives first). | `handle_gc` `archive.rs:122` |
| `memory_promote` | Promote a memory to long (or chosen tier) / ancestor namespace. | `handle_promote` `promote.rs:78` |
| `memory_capture_turn` | **L4 host-volunteered idempotent turn capture (RFC-0001).** | `handle_capture_turn` `capture_turn.rs:294` |

### Knowledge graph (Family::Graph, 11)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_kg_query` | Outbound KG traversal from a source memory (<=5 hops). | `handle_kg_query` `kg_query.rs:78` |
| `memory_kg_timeline` | Ordered fact timeline for an entity (outbound KG by valid_from). | `handle_kg_timeline` `kg_timeline.rs:57` |
| `memory_kg_invalidate` | Mark a KG link superseded via its valid_until column. | `handle_kg_invalidate` `kg_invalidate.rs:60` |
| `memory_link` | Create a typed link between two memories. | `handle_link` `link.rs:93` |
| `memory_get_links` | Get all links for a memory (both directions). | `handle_get_links` `link.rs:406` |
| `memory_entity_register` | Register an entity (canonical name + aliases) under a namespace. | `handle_entity_register` `entity_register.rs:60` |
| `memory_entity_get_by_alias` | Resolve an alias to its registered entity. | `handle_entity_get_by_alias` `entity_get_by_alias.rs:49` |
| `memory_get_taxonomy` | Return a hierarchical tree of namespaces with counts. | `handle_get_taxonomy` `get_taxonomy.rs:54` |
| `memory_replay` | Reconstruct the conversation transcript chain that produced a memory. | `handle_replay` `replay.rs:126` |
| `memory_verify` | Re-verify a stored memory_links row's Ed25519 signature on demand. | `handle_verify` `verify.rs:96` |
| `memory_find_paths` | Enumerate up to N paths through the KG between two memories (BFS, max_depth<=7). | `handle_find_paths` `find_paths.rs:70` |

### Governance (Family::Governance, 8)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_pending_list` | List pending governance-queued actions. | `handle_pending_list` `pending.rs:209` |
| `memory_pending_approve` | Approve a pending action; `remember` auto-decides next time. | `handle_pending_approve` `pending.rs:294` |
| `memory_pending_reject` | Reject a pending action; `remember` auto-decides next time. | `handle_pending_reject` `pending.rs:697` |
| `memory_namespace_set_standard` | Set a memory as the standard/policy for a namespace. | `handle_namespace_set_standard` `namespace.rs:124` |
| `memory_namespace_get_standard` | Get the standard/policy memory for a namespace. | `handle_namespace_get_standard` `namespace.rs:314` |
| `memory_namespace_clear_standard` | Clear the standard/policy for a namespace. | `handle_namespace_clear_standard` `namespace.rs:479` |
| `memory_subscribe` | Register a webhook subscription for memory events. | `handle_subscribe` `subscribe.rs:95` |
| `memory_unsubscribe` | Delete a subscription by id. | `handle_unsubscribe` `subscribe.rs:182` |

### Power — LLM-augmented + operator (Family::Power, 23)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_consolidate` | Consolidate multiple memories into one long-term summary. | `handle_consolidate` `consolidate.rs:13` |
| `memory_detect_contradiction` | LLM-check whether two memories contradict (smart/autonomous). | `handle_detect_contradiction` `detect_contradiction.rs:18` |
| `memory_check_duplicate` | Pre-write near-duplicate check via cosine over embeddings. | `handle_check_duplicate` `check_duplicate.rs:14` |
| `memory_auto_tag` | LLM-generate tags for a memory (smart/autonomous). | `handle_auto_tag` `auto_tag.rs:19` |
| `memory_expand_query` | LLM-expand a search query into related terms (smart/autonomous). | `handle_expand_query` `expand_query.rs:17` |
| `memory_inbox` | List messages sent to an agent via memory_notify. | `handle_inbox` `notify.rs:89` |
| `memory_subscription_replay` | Replay subscription_events since an RFC3339 timestamp. | `handle_subscription_replay` `subscribe.rs:215` |
| `memory_subscription_dlq_list` | List subscription_dlq rows (exhausted retry ladder). | `handle_subscription_dlq_list` `pending.rs:125` |
| `memory_quota_status` | Report per-agent + per-namespace quota usage. Operator-facing. | `handle_quota_status` `quota_status.rs:32` |
| `memory_reflect` | Persist a reflection memory plus reflects_on links to each source. | `handle_reflect` `reflect.rs:85` |
| `memory_reflection_origin` | Inspect the cross-peer provenance of a reflection memory. | `handle_reflection_origin` `reflection_origin.rs:36` |
| `memory_dependents_of_invalidated` | List dependents flagged by the L2-3 invalidation walker. | `handle_dependents_of_invalidated` `dependents_of_invalidated.rs:38` |
| `memory_check_agent_action` | Check action vs governance_rules (#691); Allow/Refuse/Warn. | `handle_check_agent_action` `check_agent_action.rs:49` |
| `memory_rule_list` | List substrate-level agent-action rules. Read-only (#691). | `handle_rule_list` `rule_list.rs:39` |
| `memory_export_reflection` | Render a single reflection memory as markdown or JSON (no FS write). | `handle_export_reflection` `export_reflection.rs:47` |
| `memory_offload` | Offload verbatim content; returns ref_id. | `handle_offload` `offload.rs:44` |
| `memory_deref` | Dereference a memory_offload ref_id. | `handle_deref` `offload.rs:75` |
| `memory_atomise` | Decompose a memory into 2-10 atomic propositions; source archived. Smart+. | `handle_atomise` `atomise.rs:121` |
| `memory_persona` | Fetch the latest Persona artefact for an entity (read-only). | `handle_persona` `persona.rs:55` |
| `memory_persona_generate` | Generate/regen a Persona artefact for an entity. | `handle_persona_generate` `persona.rs:90` |
| `memory_ingest_multistep` | Form 3 multi-step ingest: deterministic helpers + LLM stages. | `handle_ingest_multistep` `ingest_multistep.rs:99` |
| `memory_calibrate_confidence` | Scan confidence_shadow_observations; emit per-source baselines (Form 5). | `handle_calibrate_confidence` `calibrate_confidence.rs:37` |
| `memory_share` | Share a memory with another agent (copy into _shared/<from>→<to>/). | `handle_share` `share.rs:56` |

### Meta (Family::Meta, 6)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_capabilities` | Discover runtime capabilities; family=<name> drills in. **(always-on bootstrap)** | `handle_capabilities_with_conn[_v3]` `capabilities.rs:229/269` |
| `memory_agent_register` | Register an agent in the reserved _agents namespace. | `handle_agent_register` `agent.rs:8` |
| `memory_agent_list` | List every registered agent. | `handle_agent_list` `agent.rs:60` |
| `memory_session_start` | Auto-recall recent memories on session start. | `handle_session_start` `session_start.rs:26` |
| `memory_stats` | Get memory store statistics (counts, tier breakdown, sizes). | `handle_stats` `forget.rs:31` |
| `memory_recall_observations` | List recall_observations (#886). | `handle_recall_observations` `recall_observations.rs:16` |

### Archive (Family::Archive, 4)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_archive_list` | List archived (expired) memories. | `handle_archive_list` `archive.rs:8` |
| `memory_archive_purge` | Permanently delete archived memories. | `handle_archive_purge` `archive.rs:33` |
| `memory_archive_restore` | Restore an archived memory back to the active store. | `handle_archive_restore` `archive.rs:20` |
| `memory_archive_stats` | Show archive statistics (total + per-namespace breakdown). | `handle_archive_stats` `archive.rs:118` |

### Other — federation/messaging + skills (Family::Other, 9)

| Tool | Purpose | Handler |
|---|---|---|
| `memory_list_subscriptions` | List active webhook subscriptions. | `handle_list_subscriptions` `subscribe.rs:199` |
| `memory_notify` | Send a message from the caller to another agent's inbox. | `handle_notify` `notify.rs:10` |
| `memory_skill_register` | Register an agentskills.io SKILL.md from a folder or inline text. | `handle_skill_register` `skill_register.rs:246` |
| `memory_skill_list` | List current (non-superseded) skills; body not returned. | `handle_skill_list` `skill_list.rs:23` |
| `memory_skill_get` | Get full skill activation payload (metadata + body). | `handle_skill_get` `skill_get.rs:23` |
| `memory_skill_resource` | Fetch + digest-verify a skill resource. | `handle_skill_resource` `skill_resource.rs:24` |
| `memory_skill_export` | Export a skill to a folder; re-register produces identical digest. | `handle_skill_export` `skill_export.rs:23` |
| `memory_skill_promote_from_reflection` | Promote a Reflection into a reusable Agent Skill. | `handle_skill_promote_from_reflection` `skill_promote.rs:101` |
| `memory_skill_compositional_context` | Skill body + composes_with_reflections (bounded by max_reflection_depth). | `handle_skill_compositional_context` `skill_compositional_context.rs:75` |

---

## 6. Special-status tools

- **Always-on bootstrap:** `memory_capabilities` — `ALWAYS_ON_TOOLS`
  `src/profile.rs:130`; loads under every profile via `Profile::loads`
  `src/profile.rs:639-644`. It is *also* a regular `Meta` family member, so
  it is not a separate registration — it is double-listed by design (the
  family count includes it; the always-on slice re-asserts it).
- **`memory_capture_turn` (#1389 L4):** `Family::Lifecycle`
  (`src/profile.rs:384`), registered `src/mcp/registry.rs:611`, dispatch
  `src/mcp/mod.rs:1817-1820` → `dispatch_memory_capture_turn`
  (`src/mcp/mod.rs:1554`) → `handle_capture_turn` (`capture_turn.rs:294`).
  Host-signature path gated by env `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST`
  (`capture_turn.rs:82`, read at `:534`); unenrolled pubkey →
  `HOST_PUBKEY_NOT_ENROLLED`; verified → `attest_level = "signed_by_peer"`.
  Always tagged `layer = L4` (`capture_turn.rs:703`).
- **Deprecated/aliased tools:** none. There is no alias map in the dispatch
  table; every dispatch arm is a distinct `tool_names::*` const, and pin
  tests forbid duplicates (`const_set_is_deduplicated`
  `src/mcp/registry.rs:233-245`). No tool name is marked deprecated in the
  registry.

---

## DRIFT / DEFECTS SPOTTED

1. **Stale per-family counts in `src/profile.rs` module-level prose
   (`:27-42`).** The module doc says `power` is "~15 tools" and "the 8
   LLM-augmented + operator tools", and that the family is "8 LLM-augmented".
   The actual `Power` slice (`src/profile.rs:415-485`) holds **23** tools and
   the inline arm comment at `:182` correctly says "power (23)". The
   module-prose numbers are pre-#1389/pre-QW/pre-WT narrative that was never
   re-synced. Cosmetic (the *code* counts derive from the slice, never these
   numbers) but doc-drift per the prime directive.

2. **Stale named-profile counts in constructor doc comments.**
   `admin()` doc says "20 tools" (`src/profile.rs:582`) but Core(7)+Lifecycle(6)+
   Governance(8) = **21** — the comment predates the `memory_capture_turn`
   addition to Lifecycle. `power()` doc says "15 tools" (`src/profile.rs:592`)
   but Core(7)+Power(23) = **30**. `graph()` doc "18 tools" (`:571`) is
   correct (7+11). These are doc-only; the runtime counts are slice-derived
   and correct.

3. **Stale "43"-era assertions in test/prose comments.** `Family::for_tool`
   doc references `tool_definitions_returns_43_tools` (`src/profile.rs:137`)
   and a baseline test hard-asserts `baseline.len() == 66`
   (`src/profile.rs:1116-1134`) — that 66-name baseline list is a
   *subset-coverage* check (it does NOT include all 74; e.g. it omits
   `memory_capture_turn`, `memory_quota_status` is present but several Other/
   Power names are partial), so it is intentionally smaller than 74 and not a
   contradiction, but the "= 66" magic number is hand-maintained and will
   drift on the next tool add. Flag for conversion to a slice-derived count.

4. **`CapabilitiesRequest` is dead-code-PoC in capabilities.rs but the live
   schema is identical.** `CapabilitiesTool` / `CapabilitiesRequest` carry
   `#[allow(dead_code)]` annotations dated to the D1.1 PoC window
   (`src/mcp/tools/capabilities.rs:31,63`) even though D1.6 (#987) wired
   `CapabilitiesTool` into `registered_tools()` (`src/mcp/registry.rs:609`).
   The `dead_code` allow is now stale — the type IS the live schema source.
   Harmless, but the comment ("handler still parses Value directly until
   D1.3", `:31`) is no longer accurate.

5. **`C4_KEEP_OPTIONAL_PARAMS` is retained-but-unconsulted** — explicitly
   dead per its own doc (`src/mcp/registry.rs:682-683`); kept as a narrative
   marker. Not a defect, noted for completeness (an advertised knob that no
   longer gates anything).

6. **No drift between advertised and wired tools.** Every name in
   `tool_names::ALL` has a dispatch arm AND a `registered_tools()` row AND a
   handler symbol — verified by the three lockstep tests in §1 plus the
   handler-symbol enumeration in §5 (74/74 resolved). No tool is advertised
   without a handler, and no handler is unreachable from the dispatch table.
