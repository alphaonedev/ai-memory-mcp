# v0.7.0 Truthfulness Audit — Section 1: Numeric Architecture

**Auditor:** Truthfulness-Audit Specialist 1 of 6
**Base SHA:** `14fb8a7813121469899aa117b6c9a78df4048310` on `local/install-815-816`
**Binary:** `.cargo-shared-target/release/ai-memory` (rebuilt 2026-05-19, 27.6 MB)
**Method:** fresh JSON-RPC probes via the release binary + direct source-of-truth grep, per axis.

## Verdict table

| Axis | Claim location | Claim | Probe result | Verdict |
|------|---------------|-------|--------------|---------|
| A1.1 MCP tool count | `CLAUDE.md:155`, `README.md:18` | 73 advertised at `--profile full` (72 callable + `memory_capabilities` bootstrap); `Profile::full().expected_tool_count() == 73` (`src/profile.rs:768-771`) | Fresh stdio `tools/list` returned **73**, list includes `memory_capabilities`; runtime stderr: `expected tool count = 73` | **MATCH** |
| A1.2 CLI subcommand count | `CLAUDE.md:157`, `README.md:136,577,878` | 55 top-level subcommands at v0.7.0 | `ai-memory --help` → **55** entries (54 user-defined + builtin `help`). `Command` enum has 56 variants but `Migrate` + `SchemaInit` are gated behind `#[cfg(feature = "sal")]` and absent from the default release build | **MATCH** (default build) |
| A1.3 HTTP route count | `CLAUDE.md:156`, `README.md:136,577,843` | 72 `.route(...)` registrations in `src/lib.rs` | `grep -c '\.route(' src/lib.rs` → **72** | **MATCH** |
| A1.4 Schema version | `CLAUDE.md:217` says "Current schema = v43"; `src/storage/migrations.rs:478` defines v47 | v43 vs v47 conflict | Fresh sqlite DB from release binary → `SELECT MAX(version) FROM schema_version` → **47** | **DRIFT** (doc undercount by 4; code + DB correct) |
| A1.5 Token budget | `CLAUDE.md` cl100k ceilings: verbose ≤ 10000, trimmed ≤ 5000 | `doctor --tokens --json` measures `full_profile_total_tokens` + `trimmed_full_profile_total_tokens` | verbose = **9974** ≤ 10000 ✓; trimmed = **4796** ≤ 5000 ✓; family `tool_count` sum = 7+11+5+8+23+6+4+9 = **73** ✓ | **MATCH** |
| A1.6 Test count | No numeric claim found in `CLAUDE.md` (line 489 mentions "tests pass" as a category, not a count) | n/a | `grep -c '#\[test\]\|#\[tokio::test\]'` across `src/` + `tests/` → **6362** test fns (informational) | **N/A** (nothing to audit) |
| A1.7 Memory struct fields | `CLAUDE.md:171,197` says "25 fields"/"25-field struct at v0.7.0 (was 15 at v0.6.x)"; enumerates 15 baseline + 10 v0.7.0 additions = 25 | Manual scan of `src/models/memory.rs:382-495` lists **26 fields** | The 26th is `version: i64` (line 493, Provenance Gap 1, issue #884, schema v45 sqlite). Not enumerated in CLAUDE.md | **DRIFT** (doc undercount by 1; code is the canonical truth) |
| A1.8 MemoryLinkRelation variants | `CLAUDE.md:198` says "Six variants at v0.7.0" (`related_to`, `supersedes`, `contradicts`, `derived_from`, `reflects_on`, `derives_from`) | Enum at `src/models/link.rs:88-112` has **6** variants in the listed order; `from_str` (lines 122-132) matches all 6 wire strings | All six present, no extras | **MATCH** |

## Summary

- **MATCH: 5** (A1.1, A1.2, A1.3, A1.5, A1.8)
- **DRIFT: 2** (A1.4, A1.7)
- **N/A: 1** (A1.6 — no numeric claim to audit)

Both drifts are documentation undercounts; the **implementation is correct** in every case. The release binary advertises 73 tools, registers 72 routes, exposes 55 user-facing CLI subcommands, runs schema v47 in a fresh sqlite, fits inside both token budgets, and serialises 26 Memory fields + 6 link relations.

Additional internal drift: `src/daemon_runtime.rs:181-185` carries a doc-comment claiming "71 advertised entries / 70 callable" — stale against the actual 73/72 numbers everywhere else (README, CLAUDE.md, `expected_tool_count` test, runtime banner). This is a Rust-source doc-comment, not a user-visible claim, but filed for hygiene.

## Filed issues

- **#913** — `CLAUDE.md:217` schema = v43 → v47 (doc-fix)
- **#914** — `CLAUDE.md:171,197` Memory 25 fields → 26 (doc-fix; add `version` to enumeration)
- **#915** — `src/daemon_runtime.rs:181-185` doc-comment 71 → 73 (source-comment fix)

All issues labelled `auto-filed-by-agent` and reference base SHA `14fb8a781`.

## Final numeric-architecture verdict

**TRUTHFUL with documentation drift.** Every implementation-side numeric claim audited is honest: the binary delivers the numbers the user-facing surfaces (README, runtime banner, MCP `tools/list`, HTTP `/api/v1/*`, doctor JSON) report. The drift is one-directional (docs lag behind the impl), affects two CLAUDE.md lines and one Rust doc-comment, and is filed for doc-fix. No SEVERE truthfulness deficiency (impl never lies about what it ships).

Numeric-architecture axis status for the v0.7.0 ship gate: **PASS pending the three doc-fix PRs** (#913, #914, #915). None of the drifts represent the binary or user-facing docs claiming a capability it does not deliver.

## Probe artefacts

- `.local-runs/truth1/tools-list-full.jsonl` — raw stdio response (73 tools)
- `.local-runs/truth1/tool-names.txt` — newline-separated tool names
- `.local-runs/truth1/cli-help.txt` — `ai-memory --help` capture
- `.local-runs/truth1/cli-subs.txt` — extracted CLI subcommand list (55)
- `.local-runs/truth1/enum-variants.txt` — `Command` enum scan (56 variants; 2 cfg-gated)
- `.local-runs/truth1/doctor-tokens.json` — `doctor --tokens --json` capture
- `.local-runs/truth1/schema-test.db` — fresh sqlite DB at v47
