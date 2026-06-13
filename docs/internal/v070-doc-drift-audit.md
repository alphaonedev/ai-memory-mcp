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

- **[#1122](https://github.com/alphaonedev/ai-memory-mcp/issues/1122)** — `docs(drift): docs/index.html has '56 CLI subcommands' — code shows 57 (sal-postgres) / 55 (default-build)`. Filed because `docs/index.html` is owned by the DOC-A agent in this release-gate session and the DOC-F sweep can't touch it without creating a merge conflict.
- **[#1123](https://github.com/alphaonedev/ai-memory-mcp/issues/1123)** — `docs(drift): CLAUDE.md says '56 CLI subcommands' but code shows 57 (sal-postgres) / 55 (default-build)`. Filed because CLAUDE.md updates are normally operator-authored and have their own cadence; the DOC-F sweep flags but does not edit.

## Verification re-run output

After each fix-cluster push, the same grep that surfaced the drift was re-run; zero residual matches across the in-scope set. Final post-batch-5 grep:

```
grep -rn -E "\b71 (MCP|tool|tools|advertised|entries)\b|\b72 (MCP|tool|tools)\b|\b70 callable\b" \
  docs/ README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md PERFORMANCE.md ROADMAP.md \
  | grep -vE "(test-campaign|v070-truthfulness|v070-security-review|v070-feature-inventory|v070-review-synthesis|/v0.6.4/|/v0.7.1/|audit/|migration-v064-to-v070|v070-doc-drift-audit|v070-ship-readiness-adrs|initiative-9-v0.8|inference-attestation|mtp-bench|v0.7-vs-v0.8|roadmap-audit|rfc-attested-cortex|/v0.7.0/release-notes|/V0.7-EPIC|/v0.7-nhi-prompts|/CHANGELOG.md|POST-SHIP|schema-compaction|/v070-accepted-debt)"
```

Returns zero matches outside the historical RFC/audit/test-campaign corpus, where the historical numbers are preserved with a forward note in the lead paragraph (see `docs/v0.7.0/rfc-nhi-viewpoint.md` for the canonical pattern).

The CLI-subcommand count is 57 (sal-postgres) / 55 (default-build) everywhere DOC-F can edit. Two sites still read 56 — `docs/index.html` (DOC-A territory, issue #1122) and `CLAUDE.md` (operator-cadence, issue #1123). Both are tracked.

## Findings ledger

The full grep-resolved drift surface across the five fix-clusters, by severity. CRITICAL = wrong load-bearing number (badge, surface count, schema version). HIGH = wrong feature description (e.g. "four variants" when the truth is six). MEDIUM = wrong supporting reference (historical schema-bump number, file-name counter mismatch with logical schema version). LOW = cosmetic / phrasing.

### CRITICAL — wrong load-bearing numbers

| File:line | Before | After | Fix commit |
|---|---|---|---|
| `README.md:136` | "CLI (56 subcommands at v0.7.0)" | "CLI (57 subcommands at v0.7.0 with --features sal-postgres; 55 in the default build)" | `55c68ad2f` |
| `README.md:598` | "complete CLI (56 subcommands at v0.7.0)" | same shape | `55c68ad2f` |
| `README.md:630` | "56 CLI commands" | "57 CLI subcommands at v0.7.0 with --features sal-postgres (55 in the default build)" | `55c68ad2f` |
| `README.md:909` | "56 top-level subcommands at v0.7.0" | qualified 57/55 | `55c68ad2f` |
| `CHANGELOG.md:1362` | "71 MCP tools at full profile (Family::Power: 22)" | "73 MCP tools at full profile (Family::Power: 23 at v0.7.0 release HEAD)" | `55c68ad2f` |
| `CHANGELOG.md:1362` | "sqlite v39 / postgres v38" | "schema v49 single logical version both backends" | `55c68ad2f` |
| `CHANGELOG.md:1640-1641` | "sqlite … `CURRENT_SCHEMA_VERSION = 39`" + "postgres … `CURRENT_SCHEMA_VERSION = 38`" | full ladder v34 → v49 with `CURRENT_SCHEMA_VERSION = 49` on both | `7cd6b36ab` |
| `CHANGELOG.md:1645` | "Full profile: 71 tools … Family::Power: 22 tools" | "Full profile: 73 tools at release HEAD … Family::Power: 23" | `7cd6b36ab` |
| `CHANGELOG.md:422` | "duplicated across 50+ HTTP routes, 73 MCP tools, and 55 CLI subcommands" | "73 HTTP routes, 73 MCP tools, and 57 CLI subcommands (55 in the default build)" | `55c68ad2f` |
| `docs/USER_GUIDE.md:77` | "71 entries at --profile full (70 callable)" | 73 / 72 | `55c68ad2f` |
| `docs/CLI_REFERENCE.md:210` | "71 entries (70 callable memory tools + bootstrap)" | 73 / 72 | `55c68ad2f` |
| `docs/INSTALL.md:129` | "71 advertised entries — 70 callable memory tools + bootstrap" | 73 / 72 | `55c68ad2f` |
| `docs/ADMIN_GUIDE.md:456` | "71 advertised entries at v0.7.0 (70 callable)" | 73 / 72 | `55c68ad2f` |
| `docs/ADMIN_GUIDE.md:1089` | "72 routes at v0.7.0" + wrong count recipe | 73 routes + correct count recipe | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:9` | "72 routes at v0.7.0" | 73 | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:16` | "~50 subcommands" | "57 subcommands … 55 in the default build" | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:18` | "Memory (25 fields)" | "Memory (26 fields)" | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:64` | "~50 top-level subcommands" | "57 with --features sal-postgres … 55 default-build" | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:76` | "25 fields at v0.7.0" | "26 fields at v0.7.0" + version-column callout | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:86` | "71 advertised entries (70 callable)" | 73 / 72 | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:537` | "72 routes" + wrong count recipe | 73 + corrected recipe | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:808` | "72 routes" | 73 | `55c68ad2f` |
| `docs/DEVELOPER_GUIDE.md:816` | "71 entries (70 callable)" | 73 / 72 | `55c68ad2f` |
| `docs/GLOSSARY.md:138-139` | "71 advertised entries … 70 callable" | 73 / 72 | `55c68ad2f` |
| `docs/GLOSSARY.md:149` | "25-field record at v0.7.0" | "26-field record at v0.7.0" + version-column callout | `55c68ad2f` |
| `docs/evidence.html:192` | "MCP tools advertised: 71 (70 callable + bootstrap)" | 73 / 72 | `4a2d507f8` |
| `docs/evidence.html:194` | "HTTP routes: 72" | 73 + correct count recipe | `4a2d507f8` |
| `docs/evidence.html:195` | "CLI subcommands: ~50" | "57 / 55" qualified | `4a2d507f8` |
| `docs/evidence.html:196` | "Schema version (sqlite): v43" | "v49 single logical version both backends" | `4a2d507f8` |
| `docs/evidence.html:198` | "Memory struct fields: 25" | 26 | `4a2d507f8` |
| `docs/evidence.html:234` | "71 MCP tools … 72 HTTP routes … ~50 CLI subcommands" | 73 / 73 / 57 qualified | `4a2d507f8` |
| `docs/architecture.svg:94` | "JSON-RPC · 71 tools" | "JSON-RPC · 73 tools" | `4a2d507f8` |
| `docs/architecture.svg:98` | "REST · 72 routes · :9077" | "REST · 73 routes · :9077" | `4a2d507f8` |
| `docs/architecture.svg:102` | "~50 subcommands · scriptable" | "57 subcommands · scriptable" | `4a2d507f8` |
| `docs/architecture.svg:133` | "storage/ · schema v43" | "storage/ · schema v49" | `4a2d507f8` |
| `docs/architectures.html:392` | "73 advertised … 72 HTTP routes" | "73 / 73" | `4a2d507f8` |
| `docs/architectures-t1.html:411-414` | "~50 subcommands … 71 advertised entries … 72 /api/v1/* routes … schema v15" | qualified 57/55, 73/72, 73, "v49 per v0.7.0 release notes" | `4a2d507f8` |
| `docs/audience/decision-maker.html:132` | "72 HTTP routes, 55 CLI subcommands" | "73 HTTP routes, 57 CLI subcommands (with --features sal-postgres; 55 in the default build)" | `4a2d507f8` |
| `docs/audience/decision-maker.html:197` | "schema v43" | "schema v49" | `4a2d507f8` |
| `docs/audience/developer.html:112` | "72 routes at /api/v1/" | 73 | `4a2d507f8` |
| `docs/audience/developer.html:121` | "55 subcommands" | "57 subcommands at --features sal-postgres (55 default-build)" | `4a2d507f8` |
| `docs/audience/developer.html:266-267` | "72 routes / 55 subcommands" | "73 / 57" | `4a2d507f8` |
| `docs/feature-matrix.html:15` | meta description "73 MCP, 73 HTTP, 56 CLI subcommands" | "57 CLI subcommands (55 default-build)" | `4a2d507f8` |
| `docs/feature-matrix.html:248-250` | "73 / 72 / 55" pill row | "73 / 73 / 57" | `4a2d507f8` |
| `docs/feature-matrix.html:298` | "71 MCP Tools" eyebrow | 73 | `4a2d507f8` |
| `docs/feature-matrix.html:644` | "56 CLI Subcommands" eyebrow | "57 / 55 default-build" | `4a2d507f8` |
| `docs/integrations.html:159` | "all 71 tools at --profile full" | 73 | `4a2d507f8` |
| `docs/integrations.html:197` | "all 71 tools" | 73 | `4a2d507f8` |
| `docs/integrations.html:408` | "71 advertised entries" | 73 | `4a2d507f8` |
| `docs/integrations.html:445` | "all 71 tool definitions" | 73 | `4a2d507f8` |
| `docs/essays/brass-tacks-3-why.html:82` | "25-field Memory struct" | 26 | `4a2d507f8` |
| `docs/essays/brass-tacks-3-why.html:139` | "71 MCP entries, 72 HTTP routes, ~50 CLI subcommands" | "73 MCP entries, 73 HTTP routes, 57 (sal-postgres) / 55 (default-build) CLI subcommands" | `4a2d507f8` |
| `docs/essays/brass-tacks-3-why.html:140` | "Schema version v43, 25-field Memory" | "Schema version v49, 26-field Memory" | `4a2d507f8` |
| `docs/v0.7.0/release-notes.md:474` | "Schema ladder advances to sqlite v47 / postgres v29" | "schema ladder reaches v49 on both backends … #933 v48 federation_push_dlq + #1025 v49 archived_memories 14-column carry" | `7cd6b36ab` |
| `docs/v0.7.0/release-notes.md:1216` | "71 MCP tools, 28 net-new … 8 new HTTP routes, 20 sqlite + 10 postgres new migrations" | "73 MCP tools at release HEAD … 73 HTTP routes total … 32 sqlite migrations on disk + the in-process v35-v49 arms" | `7cd6b36ab` |
| `docs/internal/v070-ship-readiness-final.md:22` | "71 MCP tools, 17 net-new env vars, 8 new HTTP routes" | "73 MCP tools at release HEAD, 17 net-new env vars, 73 HTTP routes total" | `7cd6b36ab` |
| `docs/internal/v070-ship-readiness-final.md:41-47` | "MCP tool count: 71 total" + "sqlite v41, postgres v40" | "73 total" + "v49 on both backends at release HEAD" + per-family count refresh (Power 22→23, Meta 5→6) | `7cd6b36ab` |
| `docs/internal/v070-ship-readiness-final.md:131-133` | tool baseline 71, schema sqlite v41 / postgres v40 | 73, v49 single-logical | `7cd6b36ab` |
| `docs/a2a-harness-integration.md:25-31` | "71 MCP tools, 72 HTTP routes, Schema v43/v41, 25-field Memory" | "73 MCP tools, 73 HTTP routes, Schema v49, 26-field Memory" | `7cd6b36ab` |
| `docs/batman-active-mode.md:50` | "--profile full exposes all 71 tools" | 73 | `7cd6b36ab` |
| `docs/BASELINE-v0.6.3.1.md:75` | forward-note "71 entries (70 callable)" | 73 / 72 | `7cd6b36ab` |
| `docs/v0.7/v0.7-nhi-prompts.md:37-38` | template string "currently 71 at v0.7.0 — 70 callable memory tools" | 73 / 72 | `7cd6b36ab` |
| `docs/API_REFERENCE.md:763` | "71 at full, 7 at core" | "73 at full, 7 at core" | `ce1aee327` |
| `docs/API_REFERENCE.md:765-767` | "Total HTTP surface … ~42 routes" + wrong count recipe | "73 distinct route paths" + correct count recipe | `ce1aee327` |
| `docs/API_REFERENCE.md:784-785` | "canonical 71-tool full inventory" | "canonical 73-tool full inventory" + corrected count recipe | `ce1aee327` |
| `docs/knowledge-graph.html:12` | meta "v0.6.3.1 KG … memory_links with 4 relations" | "v0.7.0 KG … memory_links with 6 relations" + named list | `ce1aee327` |
| `docs/knowledge-graph.html:268-292` | "The four relations" + 4 cards | "The six relations (v0.7.0)" + 6 cards (added `reflects_on`, `derives_from`) | `ce1aee327` |
| `docs/spec/v1.md:281` | link-relation row enumerated only 4 of 6 | full 6 with v0.7.0 provenance tags | `ce1aee327` |
| `PERFORMANCE.md:44` | "The '71 tools serialize on a mutex' framing" | 73 (current substrate count for the audit refutation) | `7cd6b36ab` |

### HIGH — wrong / incomplete feature descriptions

| File:line | Before | After | Fix commit |
|---|---|---|---|
| `README.md:619` | link relations: "related_to, supersedes, contradicts, derived_from" (4) | full 6 with v0.7.0 provenance tags | `55c68ad2f` |
| `docs/v0.7.0/rfc-nhi-viewpoint.md` (5 sites) | "71 tools" historical snapshot | forward-note added at L3-L13 preserving the historical-evidence-chain integrity while flagging the live count | `ce1aee327` |

### MEDIUM — historic schema-version cross-references

These all describe the introduction schema for a feature ("schema v36 atomisation foundation", "schema v45 Gap-1 optimistic concurrency"). The references are technically accurate as introduction-anchors. The DOC-F sweep verified each anchor matches its actual SQL migration file. No edits were necessary; the references remain accurate.

| File:line | Reference | Verification |
|---|---|---|
| `docs/RECURSIVE_LEARNING.md:156` | "SQLite schema v29" | matches `0027_v07_memory_kind.sql` ancestry + `src/storage/migrations.rs` v29 arm |
| `docs/signed-events-v4.md:18` | "V-4 cross-row chain columns (schema v34)" | matches `0028_v07_signed_events_chain.sql` |
| `docs/atomisation.md:107` | "atom_of is a structural foreign key (schema v36)" | matches `0030_v07_atomisation.sql` |
| `docs/provenance.md:57-58` | "sqlite schema v38 / postgres schema v37" | matches `0032_v07_form4_provenance.sql` (sqlite) + `0019_v07_form4_provenance.sql` (postgres) |
| `docs/confidence-calibration.md:21` | "schema v39 sqlite / v38 postgres" | matches `0033_v07_form5_confidence_calibration.sql` (sqlite) + `0020_v07_form5_confidence_calibration.sql` (postgres) |
| `docs/GLOSSARY.md:154` (post-fix) | "version (schema v45 Gap-1 optimistic concurrency)" | matches the v45 in-process migration arm |
| `docs/DEVELOPER_GUIDE.md:76` (post-fix) | "version (schema v45 — Gap-1 optimistic concurrency)" | same |

### LOW — cosmetic / phrasing

No remaining cosmetic findings; the audit prioritised load-bearing facts.

## Findings ledger format (for future audits)

The format used above:

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

