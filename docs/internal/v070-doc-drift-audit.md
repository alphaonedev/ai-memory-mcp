# v0.7.0 Documentation Drift Audit (DOC-F)

**Audit ID:** DOC-F (100% docs + GitHub Pages drift audit + remediation)
**Branch:** `release/v0.7.0-mobile-ci-1068` (HEAD at audit start: `42401c1f2`)
**Auditor:** AI NHI agent (Claude Opus 4.7, 1M context)
**Date:** 2026-05-22
**Scope:** `docs/**`, `README.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`,
`PERFORMANCE.md`, `ROADMAP.md` — minus paths owned by DOC-A through DOC-E.

## Inventory totals

- **206** doc files (markdown + html) under `docs/`
- **68,491** total lines across `docs/`
- 5 additional doc-style root files audited: `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, `PERFORMANCE.md`, `ROADMAP.md`.

Categorisation:
- **End-user / GitHub Pages public surface:** every `docs/*.html`, `docs/audience/*.html`,
  `docs/essays/*.html`, plus `README.md`, the integration recipes under
  `docs/integrations/`, the marketing-adjacent reference pages
  (`USER_GUIDE.md`, `API_REFERENCE.md`, `CLI_REFERENCE.md`, `INSTALL.md`,
  `QUICKSTART.md`, `GLOSSARY.md`, `feature-matrix.html`, `architectures*.html`,
  `evidence.html`, `at-a-glance.html`, `integrations.html`).
- **Operator:** `ADMIN_GUIDE.md`, `RUNBOOK-*.md`, `production-deployment.md`,
  `plan-c-deployment.md`, `operations/doctor.md`, `signed-events-v4.md`,
  `governance.md`, `policy-engine.md`.
- **Internal:** `docs/internal/**`, `docs/v0.7.0/**`, `docs/v0.7/**`,
  `docs/v0.6.4/**`, `docs/v0.6.5/**`, `docs/v0.8/**`, `docs/audit/**`,
  `docs/benchmarks/**`, `docs/rationale/**`.
- **Reference:** `DEVELOPER_GUIDE.md`, `ENGINEERING_STANDARDS.md`,
  `RECURSIVE_LEARNING.md`, `confidence-calibration.md`, `atomisation.md`,
  `persona.md`, `multistep-ingest.md`, `memory-kind-vocab.md`, `recall.md`,
  `provenance.md`, `forensic-export.md`, `federation.md`, `telemetry.md`,
  `kg-backend-fallback.md`, `hook-pipeline.md`, `sidechain-transcripts.md`,
  `agent-skills.md`, `spec/v1.md`, `spec/v1.html`.

## Truth table (snapshot from code at HEAD `42401c1f2`)

| Claim | Truth | Source-of-truth citation |
|---|---|---|
| MCP tools at `--profile full` | **73** | `src/mcp/registry.rs:168-251` — `registered_tools()` returns 73 `RegisteredTool::of::<…>` entries. Sum-asserted by `Profile::full().expected_tool_count()` (7+5+6+11+8+23+4+9=73) in `src/profile.rs:290-335`. |
| Default `--profile core` advertises | **7** + the always-on `memory_capabilities` bootstrap | `src/profile.rs:294` (`Self::Core => 7`); tool names at `src/profile.rs:352-366`. |
| Callable "memory tools" at full profile | **72** | 73 − 1 (the always-on `memory_capabilities` bootstrap). |
| HTTP routes (distinct paths) | **73** | `grep -oE '"/api/v1[^"]*"\|"/metrics"' src/lib.rs \| sort -u \| wc -l` = 73 across `src/lib.rs:252-493` (production router); 14 of those land via the #1111 sweep (`route_1111::handle_*`). |
| HTTP route registrations (count of `.route(` calls, verbs combined) | **87** | `grep -c '^\s*\.route(' src/lib.rs` returns 88 (one is in the test mod under `#[cfg(test)]`). Production = 87. |
| CLI top-level subcommands (default build) | **55** | `Command` enum in `src/daemon_runtime.rs:157-416`. 57 total variants; 2 (`Migrate` + `SchemaInit`) are `#[cfg(feature = "sal")]`. Default `cargo build` (sal feature OFF) compiles 55. |
| CLI top-level subcommands (`--features sal` / `--features sal-postgres`) | **57** | Same enum + the 2 sal-gated variants. |
| Schema version | **v49** | `const CURRENT_SCHEMA_VERSION: i64 = 49` at `src/storage/migrations.rs:516`; same constant on postgres at `src/store/postgres.rs:391`. |
| Sqlite migration files | **32** (0010-0041) | `ls migrations/sqlite/ \| wc -l`. The number is not the schema version: file-name counters lag the `PRAGMA user_version` because both ladders apply post-v34 deltas via in-process arms. |
| Memory fields | **26** | `pub struct Memory { … }` at `src/models/memory.rs:401-514` (the 25 + the v45 `version: i64` for Gap-1 optimistic concurrency). |
| MemoryLink variants | **6** | `pub enum MemoryLinkRelation { … }` at `src/models/link.rs:88-112`: `RelatedTo`, `Supersedes`, `Contradicts`, `DerivedFrom`, `ReflectsOn`, `DerivesFrom`. |
| Capabilities envelope `schema_version` | **"3"** | `src/mcp/tools/capabilities.rs` (post-A5); v1/v2 still negotiable via `accept=` / `Accept-Capabilities`. |
| V-4 signed-events cross-row hash chain | **Live** at sqlite v34 (issue #698); chain holds through v49 | `src/signed_events.rs`, migration `0028_v07_signed_events_chain.sql`. |
| mTLS fingerprint allowlist | **Live** at v0.7.0 (governance + federation) | `src/federation/` peer-attestation marker `AI_MEMORY_FED_PEER_ATTESTATION`. |
| X-Memory-Sig / X-Memory-Nonce wire signing | **Required by default** (`AI_MEMORY_FED_REQUIRE_SIG=1`, `AI_MEMORY_FED_REQUIRE_NONCE=1`) | CLAUDE.md env-var table entries #29 + #30; #791 + #922. |
| Governance L1-L6 rules engine | **Live**; `memory_check_agent_action` + `memory_rule_list` MCP tools | Migration `0024_v07_governance_rules.sql`; `src/governance/`. |
| HNSW double-buffer async rebuild | **Live** at v0.7.x post-#968 | `src/hnsw.rs::VectorIndex::try_swap_warming`; CLAUDE.md "Recall Pipeline" §2. |
| Persona + atomisation + multistep ingest | **Live** at v0.7.0 | `src/persona/`, `src/atomisation/`, `src/multistep_ingest/`; MCP tools `memory_persona*` / `memory_atomise` / `memory_ingest_multistep`. |

**Tool-count nomenclature.** The codebase consistently uses two paired numbers
because the always-on bootstrap tool (`memory_capabilities`) lives in the Meta
family but is always advertised regardless of profile:

- **73** = `tools/list` length under `--profile full` (the "advertised" count).
- **72** = "callable memory tools" excluding the bootstrap, i.e. the 73 minus
  `memory_capabilities`. Used in operator-facing language to distinguish the
  per-feature tool surface from the bootstrap.

Both numbers MUST appear together when invoking the disambiguation, e.g.
"73 advertised entries — 72 callable memory tools + the always-on
`memory_capabilities` bootstrap". Pre-existing doc text uses 71/70 which is
the wrong pair (the post-#987 D1.6 split added two tools after the 71/70
framing was authored: see the CHANGELOG entry at line 1115 and #876).

## Drift findings (severity-grouped)

See § "Findings ledger" below for each file:line entry with before → after and
fix commit SHA. Fixes are applied in clusters; each cluster's commit SHA is
appended after push.

## Issues filed (with numbers + titles)

See § "Issues filed" below — populated after fixes are pushed.

## Verification re-run output

Populated after each fix cluster.

## Findings ledger

Populated by the auditor as each file is touched. Format:

```
<severity> | <file>:<line> | "<before>" → "<after>" | <fix commit SHA>
```

### Drift dimensions audited

For each of the dimensions below the auditor ran a workspace-wide grep, then
the affected files were edited in clusters. The dimensions are:

1. **MCP tool counts.** `71 tools`, `71 advertised`, `70 callable`, `71-tool surface`, `71 MCP tools/entries` → **73 / 72-callable / 73-tool surface**.
2. **HTTP route counts.** `72 HTTP routes`, `72 routes`, `72-route surface` → **73**.
3. **CLI subcommand counts.** `55 CLI subcommands`, `56 CLI subcommands`, `~50 subcommands`, `50 CLI subcommands` → **57** (with sal-postgres) / **55** (default build). Docs that don't qualify the feature build are updated to the "57 with sal" headline since v0.7.0's hero use case is the postgres+AGE backend.
4. **Memory field counts.** `25 fields`, `25-field`, `15-field` (in v0.7.0 context) → **26**.
5. **MemoryLink variant counts.** `four`, `5`, `four variants` (in v0.7.0 context) → **6**.
6. **Schema versions.** `schema v43`, `schema v47`, `sqlite v34/v41/v45/v47`, `postgres v29/v33/v40` → **schema v49** (single logical version both backends).
7. **Migration file numbers.** Where docs cite specific migration file numbers, the reference is verified against `migrations/sqlite/{0010..0041}.sql` and `migrations/postgres/`.
8. **Capabilities envelope.** Confirm `schema_version="3"` is current; v1/v2 still negotiable via `accept=`.
9. **Tool / route / CLI subcommand names.** Each named symbol is grep-checked against the source.
10. **Deprecated feature references.** Scan for any "v0.6.x advisory mode", "pre-v0.7", "smart-only LLM", etc.

