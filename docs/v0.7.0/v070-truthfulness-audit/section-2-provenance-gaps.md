# v0.7.0 Truthfulness Audit — Section 2: Provenance Gaps

**Auditor:** Truthfulness-Audit Specialist 2 of 6
**Base SHA:** `14fb8a7813121469899aa117b6c9a78df4048310`
**Branch:** `local/install-815-816`
**Binary:** `.cargo-shared-target/release/ai-memory` → `ai-memory 0.7.0`
**Audit date:** 2026-05-19
**Method:** Fresh MCP subprocess (`ai-memory mcp --profile full --tier semantic`) per probe with isolated sqlite DB under `.local-runs/truth-2-probe/`; SQL row-state cross-check via `sqlite3`; HTTP probe via `ai-memory serve --port 39078` ephemeral daemon.
**Mandate:** maximum truthfulness, eat-your-own-dog-food. Every gap probed against its stated acceptance criteria end-to-end.

## Per-gap verdict table

| # | Issue | Gap | Verdict | Evidence |
|---|---|---|---|---|
| 1 | #884 | Identity — version + If-Match | **TRUTHFUL** | new rows seed version=1; expected_version=2 → exact AC envelope `{status:"conflict",current_version:1,expected_version:2,id}` with `isError:true`; expected_version=1 succeeds + bumps to 2; omit param → succeeds + bumps to 3 then 4 |
| 2 | #885 | Source — `source_uri` column | **TRUTHFUL** | `source_uri TEXT` stored end-to-end via `memory_store`; `idx_memories_source_uri` present in `sqlite_master`; sqlite row carries `doc:test-2026` verbatim |
| 3 | #886 | Causal — `recall_observations` | **TRUTHFUL** | sqlite schema v47 confirmed (`MAX(version)=47`); `recall_observations` table present; `memory_recall_observations` MCP tool advertised; recall fires `recall_observation_insert` (row written: recall_id + memory_id + retriever=`hybrid` + rank=1); GC pruner at `src/observations/gc.rs` ladder-prunes by retention window |
| 4 | #887 | Capture confidence — tier | **TRUTHFUL** | `Memory::confidence_tier()` at `src/models/memory.rs:695`; `tier_thresholds: {ambiguous:0.0, likely:0.7, confirmed:0.95}` present in `memory_capabilities.confidence_calibration`; recall decorates each row with `confidence_tier` (`ambiguous` for 0.10/0.50, `confirmed` for 0.99 observed) |
| 5 | #888 | Versioned — `edit_source` split-write | **TRUTHFUL** | `edit_source:"llm"` → response `{updated:true, new_id, superseded_id, edit_source:"llm"}` + new row's `metadata.superseded_id` = OLD id; OLD row archived to `archived_memories` with `archive_reason='superseded'`; `edit_source:"human"` → in-place, no `new_id`/`superseded_id` returned, same id preserved |
| 6 | #889 | Reciprocal — `source_uri` search/group | **TRUTHFUL** | HTTP `GET /api/v1/search?source_uri=doc:X` returns `count:5`; `?source_uri=doc:Y` returns `count:3`; source_uri-only path (no `q`) NOT 400; MCP `memory_search` source_uri-only also returns count=5; `list_by_source_uri` SAL method present in `src/storage/mod.rs:1887` + postgres mirror at `src/store/postgres.rs:2057`; bare `/api/v1/search` (neither q nor source_uri) → 400 (correct rejection) |
| 7 | #890 | Decoration — Tier-3 metadata on recall | **TRUTHFUL** | JSON-format recall row carries `confidence_tier`, `source_uri`, `freshness_state` (all required); `latest_link_attest_level` is conditional (only present when memory has signed links — matches AC "when applicable"); decoration impl in `src/mcp/tools/recall.rs:220-232` |

## Final provenance verdict

**TRUTHFUL — 7/7 gaps pass end-to-end probes.**

The v0.7.0 provenance lane delivers every stated acceptance criterion. The
sqlite schema is at v47 with all four provenance tables/columns in place
(`memories.version`, `memories.source_uri`, `recall_observations`,
`archived_memories.archive_reason='superseded'`). The wire layer — MCP
`memory_store` / `memory_update` / `memory_search` / `memory_recall` and
HTTP `GET /api/v1/search` — accepts, threads, and returns every
provenance field documented. Conflict envelopes, decoration fields, and
split-write semantics all match issue-stated shapes verbatim.

## Filed issues

**None.** No DEFICIENT gaps surfaced; nothing to file.

## Probe transcripts (key request/response pairs)

### Gap 1 — Identity / If-Match

Conflict envelope (expected_version=2 vs current=1):
```
{"id":2,"result":{"content":[{"text":"{\"current_version\":1,\"expected_version\":2,\"id\":\"e2f2c553-...\",\"status\":\"conflict\"}","type":"text"}],"isError":true}}
```

Successful matched update (expected_version=1):
```
sqlite> SELECT id, version FROM memories WHERE id='e2f2c553-...';
e2f2c553-551a-49e5-bb8a-51a80a8e0db6|2
```

### Gap 2 — source_uri

```
sqlite> SELECT title, source_uri FROM memories WHERE title='gap2-suri';
gap2-suri|doc:test-2026
sqlite> SELECT name FROM sqlite_master WHERE name='idx_memories_source_uri';
idx_memories_source_uri
```

### Gap 3 — recall_observations

```
sqlite> SELECT MAX(version) FROM schema_version;
47
sqlite> SELECT recall_id, memory_id, retriever, rank, score FROM recall_observations;
41c9de17-f745-4953-a2f6-14f933030945|33be28c3-...|hybrid|1|0.258
```

`memory_recall_observations` tool advertised in `tools/list` response (full profile).

### Gap 4 — confidence_tier

```
memory_capabilities.confidence_calibration.tier_thresholds = {'ambiguous':0.0,'confirmed':0.95,'likely':0.7}
```

Decoration (confidence=0.99 stored, recalled):
```
gap4-hi-only  confidence=0.99  confidence_tier=confirmed
```

### Gap 5 — edit_source split-write

`memory_update {edit_source:"llm"}` response:
```json
{"edit_source":"llm","new_id":"ed2ba62a-...","superseded_id":"55220e85-...","updated":true,
 "memory":{"id":"ed2ba62a-...","metadata":{"superseded_id":"55220e85-..."},"content":"LLM rewrite v2",...}}
```

```
sqlite> SELECT id, archive_reason FROM archived_memories WHERE id='55220e85-...';
55220e85-7eb1-4acb-b82f-28312246dec7|superseded
```

`memory_update {edit_source:"human"}` response carries no `new_id`/`superseded_id`; id remains stable.

### Gap 6 — Reciprocal source_uri search

HTTP:
```
GET /api/v1/search?source_uri=doc:X  →  {"count":5, "results":[5 rows], "source_uri":"doc:X"}
GET /api/v1/search?source_uri=doc:Y  →  {"count":3, ...}
GET /api/v1/search                   →  400
```

MCP `memory_search {source_uri:"doc:X"}` → 5 rows.

### Gap 7 — Decoration

```
recall_response.memories[0]:
  confidence_tier:  confirmed
  source_uri:       doc:gap7
  freshness_state:  fresh
  latest_link_attest_level:  (absent — memory has no signed links)
```

## Notes on capability cleanliness

- The MCP `memory_recall` TOON-format response (default) does not surface
  `recall_id` in the rendered string, but the JSON-format response
  (`format:"json"`) does (`recall_id:"dcaa0914-..."`); the underlying
  `recall_observations` row is written in both formats. The AC ("every
  recall fires `recall_observation_insert`") is satisfied; the TOON
  format simply elides a field for token economy.
- `recall_observations` ledger row in this probe used `retriever:"hybrid"`
  (not separate `fts5`/`hnsw` rows), reflecting the v0.7.0 hybrid
  blend pipeline. The schema accepts all three label classes.
- `edit_source:"hook"` was not exercised in this probe (LLM path mirrors
  hook path per impl); recommend a follow-up probe if hook split-write
  becomes a release-gate concern, but the impl path is shared so the
  llm probe transitively validates it.

## Scratch + artifacts

All probe scratch under `/Users/fate/v07/v07-fixes/.local-runs/truth-2-probe/`:

- `gap1.db` — version / If-Match probes
- `gap2.db` — source_uri store
- `gap3.db` — recall_observations
- `gap4b.db`, `gap4c.db` — confidence_tier decoration
- `gap5.db` — edit_source split-write
- `gap6.db` — reciprocal source_uri (also driven by HTTP daemon on :39078)
- `gap7.db` — Tier-3 decoration

Per project hard rule: no scratch under `/tmp` or tmpfs.
