# #3623: one-time baseline coverage correction (2026-09-12)

The Conductor authorized this expansion when correcting the scanner's production/test
classification, which previously hid roughly 13.9k production lines. The decrease-only
ratchet resumes after this correction. Follow-up [#3668](https://github.com/alphaonedev/ai-memory-mcp/issues/3668)
tracks consolidation of the newly visible duplication into named constants.

## Provenance

The NEW hardcoded-literal scanner was run against `git archive` snapshots of each
UNMODIFIED base's `src/`, `tools/`, and `scripts/`. Only the scanner and its two new
production-filter helpers were overlaid; no source files were changed. All source
files were byte-compared before/after scanning. The entire regenerated count map,
not merely the additions, equals the branch baseline for the corresponding base.

- Original base `f0175b709cc304fffd8731669c67c16a5388e5fa`: 517 source files verified;
  48/48 added or changed rows match exactly; 44 new keys, 2 removed keys, 70 total.
- Rebased base `e8d8eb67a6852887bc1a951bf5384cbd1f5d014c`: 519 source files verified;
  47/47 added or changed rows match exactly; 43 new keys, 2 removed keys, 69 total.

No production Rust file is changed by #3623, and no branch-introduced duplication is
baseline material. The earlier +58/-16 textual diff includes sorting churn; it does
not represent 58 new literal keys. On the rebased sources `target_agent_id` drops
below the threshold and is no longer frozen.

Test-item occurrences are excluded rather than grandfathered. The refreshed baseline
also retires stale counts: the removed keys `AI_MEMORY_LLM_API_KEY` and `{}/api/tags`
were already below threshold with the OLD scanner on the rebased base. Therefore it
would be inaccurate to attribute every removed diff line solely to this scanner fix.

`REFLECT_TRACE_TARGET` remains the named constant for `mcp.reflect`; that literal is
absent from the regenerated baseline. No tracing literal is reintroduced.

## Rebased count comparison

Every row below differs from the old frozen baseline. Zero means absent (below the
three-site threshold). Both decreases and additions are shown, with exact matches.

| Literal | Old frozen count | Branch count | New scanner on unmodified base |
| --- | ---: | ---: | ---: |
| `<anonymous>` | 0 | 3 | 3 |
| `AI_MEMORY_EMBED_OFFLINE` | 0 | 5 | 5 |
| `ai_memory::identity::attest` | 0 | 3 | 3 |
| `ai_memory::identity::replay` | 0 | 10 | 10 |
| `attest_level` | 0 | 5 | 5 |
| `autonomous` | 0 | 3 | 3 |
| `budget_overflow` | 0 | 3 | 3 |
| `budget_tokens_remaining` | 0 | 3 | 3 |
| `budget_tokens_used` | 0 | 3 | 3 |
| `confidence` | 3 | 5 | 5 |
| `config.json` | 0 | 3 | 3 |
| `conflict: already exists` | 0 | 3 | 3 |
| `created_at` | 0 | 3 | 3 |
| `current_version` | 0 | 3 | 3 |
| `delivered_at` | 0 | 3 | 3 |
| `derives_from` | 0 | 3 | 3 |
| `description` | 0 | 7 | 7 |
| `edit_source` | 0 | 4 | 4 |
| `expected_version` | 0 | 4 | 4 |
| `expires_at` | 0 | 3 | 3 |
| `federation::peer_attestation` | 0 | 3 | 3 |
| `folder_path` | 0 | 3 | 3 |
| `governance` | 0 | 4 | 4 |
| `http://localhost:11434` | 9 | 8 | 8 |
| `inline_skill` | 0 | 3 | 3 |
| `inputSchema` | 0 | 6 | 6 |
| `iterations` | 0 | 3 | 3 |
| `loaded_under_active_profile` | 0 | 3 | 3 |
| `memory_recall (rerank stage, depth=1)` | 0 | 3 | 3 |
| `memory_search (FTS5)` | 0 | 4 | 4 |
| `memory_store` | 0 | 5 | 5 |
| `memory_store (no embedding)` | 0 | 4 | 4 |
| `model_family` | 0 | 3 | 3 |
| `nomic-embed-text-v1.5` | 4 | 3 | 3 |
| `observations` | 0 | 3 | 3 |
| `older_than_days` | 0 | 3 | 3 |
| `owner-level action has no resolvable owner` | 0 | 3 | 3 |
| `pending_id` | 0 | 7 | 7 |
| `potential_contradictions` | 0 | 3 | 3 |
| `properties` | 0 | 6 | 6 |
| `recall response is always a JSON object` | 0 | 5 | 5 |
| `schema_version` | 3 | 6 | 6 |
| `set_embeddings_batch` | 0 | 3 | 3 |
| `target_tier 'short' is not a valid promote target (would be a downgrade)` | 0 | 3 | 3 |
| `target_tier must be one of 'mid' or 'long' (got '{other}')` | 0 | 3 | 3 |
| `to_namespace` | 0 | 3 | 3 |
| `update_embedding` | 0 | 3 | 3 |
