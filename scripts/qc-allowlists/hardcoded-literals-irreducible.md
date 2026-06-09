# #1558 — Irreducible hardcoded-literal census (batch 6 FINAL, 2026-06-09)

Closure evidence for issue #1558. Input baseline: `scripts/qc-allowlists/hardcoded-literals-baseline.txt`
(148 entries / 543 sites, frozen pre-batch-6). After the batch-6 sweep, **120 entries are
routed/resolved** (drop below the 3-site duplication threshold on regen) and **28 entries /
108 sites remain** — every one classified below as irreducible with a one-line justification.

Method: re-ran the gate's exact production-site extractor (same awk filter as
`scripts/check-hardcoded-literals.sh`: src/ + tools/, `*test*.rs`/`tests.rs` basenames excluded,
lines at/below the test boundary excluded, comment/use/attr/const-def lines excluded,
leading whitespace stripped from extracted literals) over the post-sweep working tree.
Gate state: `bash scripts/check-hardcoded-literals.sh` → **PASS**; zero NEW over-threshold
literals introduced.

Classes (per the batch-6 dispatch):
- **CARVEOUT** — every production site lives in the 8 vendor carve-out files
  (`src/llm.rs`, `src/config.rs`, `src/mine.rs`, `src/validate.rs`, `src/harness.rs`,
  `src/cli/wrap.rs`, `src/llm_cli_wrap.rs`, `src/recover/transcript_paths.rs`). Per the
  carve-out contract these files hold the canonical vendor alias/default tables and are
  frozen for this campaign — classification, not edits.
- **CARVEOUT-DOMINANT** — ≥3 sites are carve-out-frozen; the residual non-carve-out site(s)
  are below the duplication threshold on their own and cannot reference a const that the
  frozen owner does not export.
- **SEPARATE-CRATE** — sites live only in `tools/*` standalone QA/orchestration binaries
  (separate crates; cannot reference `ai_memory::` consts, and per the dispatch are
  classified rather than edited).
- **HYBRID (CARVEOUT + SEPARATE-CRATE)** — sites split between carve-out files and a tools
  binary; neither side can route to the other.

## Census — expected post-regen baseline (28 entries / 108 sites)

| # | sites | literal | class | justification |
|---|---|---|---|---|
| 1 | 3 | `AI_MEMORY_LLM_API_KEY` | CARVEOUT | env-var name in `config.rs` resolver + `llm.rs` client init only |
| 2 | 3 | `AI_MEMORY_LLM_BACKEND` | CARVEOUT | env-var name in `config.rs` + `llm.rs` backend selection only |
| 3 | 4 | `AI_MEMORY_LLM_BASE_URL` | CARVEOUT | env-var name in `config.rs` + `llm.rs` base-URL resolution only |
| 4 | 3 | `ANTHROPIC_API_KEY` | HYBRID | per-vendor key fallback table in `config.rs`/`llm.rs` (frozen) + `tools/t0-orchestrate` env table (separate crate) |
| 5 | 3 | `GOOGLE_API_KEY` | HYBRID | same split as #4 |
| 6 | 3 | `OPENAI_API_KEY` | HYBRID | same split as #4 |
| 7 | 3 | `XAI_API_KEY` | HYBRID | same split as #4 |
| 8 | 3 | `application/json` | SEPARATE-CRATE | HTTP header values in `tools/t0-orchestrate` only |
| 9 | 3 | `confidence` | CARVEOUT | `config.rs` Debug impl + tier table + `validate.rs` field attribution only |
| 10 | 3 | `content-type` | SEPARATE-CRATE | HTTP header names in `tools/t0-orchestrate` only |
| 11 | 4 | `create_time` | CARVEOUT | ChatGPT-export JSON field in `mine.rs` (the conversation-mining carve-out owns the wire shape) |
| 12 | 9 | `http://localhost:11434` | CARVEOUT | Ollama default URL — all 9 sites in `config.rs` defaults/resolvers/template |
| 13 | 5 | `mini_lm_l6_v2` | CARVEOUT-DOMINANT | 4 sites are `config.rs` `EmbeddingModel` FromStr/name-table/alias-map/template (frozen SSOT def); residual `mcp/mod.rs:2671` is a match-arm *pattern* against the config-owned spelling — no const exists in the frozen owner to reference, and 1 residual site is below threshold |
| 14 | 3 | `nomic-ai/nomic-embed-text-v1.5` | CARVEOUT | HF model id — all sites in `config.rs` |
| 15 | 4 | `nomic-embed-text-v1.5` | CARVEOUT | embed model id — all sites in `config.rs` |
| 16 | 4 | `nomic_embed_v15` | CARVEOUT-DOMINANT | 3 sites in `config.rs` (FromStr/name-table/alias-map); residual `mcp/mod.rs:2675` match-arm pattern, same constraint as #13 |
| 17 | 6 | `openrouter` | CARVEOUT | vendor alias in the `config.rs`/`llm.rs` alias tables only |
| 18 | 3 | `schema_version` | HYBRID | `config.rs` Debug impl + section table (frozen) + `tools/post-ship-converge` response probe (separate crate); note `models::field_names::SCHEMA_VERSION` already exists for routable in-crate sites |
| 19 | 4 | `sentence-transformers/all-MiniLM-L6-v2` | CARVEOUT | HF model id default — all sites in `config.rs` |
| 20 | 5 | `T0-A1-CORE` | SEPARATE-CRATE | T0 question ids in `tools/t0-orchestrate` |
| 21 | 4 | `T0-A2-CORE` | SEPARATE-CRATE | same |
| 22 | 3 | `T0-A2-FULL` | SEPARATE-CRATE | same |
| 23 | 3 | `T0-A2-GRAPH` | SEPARATE-CRATE | same |
| 24 | 3 | `T0-CONTRACT` | SEPARATE-CRATE | same |
| 25 | 3 | `What tools do you have available right now? …` | SEPARATE-CRATE | T0 probe prompt in `tools/t0-orchestrate` |
| 26 | 6 | `to_describe_to_user` | SEPARATE-CRATE | capabilities-contract field name probed by `tools/post-ship-converge` + `tools/t0-orchestrate` |
| 27 | 4 | `{decision}` | SEPARATE-CRATE | `writeln!` format template in `tools/auto-link-detector` + `tools/transcript-extractor` |
| 28 | 4 | `{}/api/tags` | CARVEOUT-DOMINANT | 3 sites are `llm.rs` Ollama probe paths (frozen owner, exports no const); residual `cli/doctor.rs:925` reachability probe is below threshold on its own |

Class totals: CARVEOUT 9 · CARVEOUT-DOMINANT 3 · SEPARATE-CRATE 11 · HYBRID 5.

## Routed in batch 6 (120 entries cleared, 406 production-site replacements)

Headline routes (full mechanics in `b6_pass1.py` / `b6_pass2.py` beside this file):

- **`models::field_names` extended +57 consts** (`agent_pubkey`, `allowed_tools`,
  `archive_reason`, `atom_count` … `unread_only`, `updated_since`) — wire/row keys routed via
  the established parenthesized-`json!`-key / `.get()` / `try_get()` / index forms across
  ~60 files, including the full `handlers/federation_sync_since.rs` response-key set.
- **`store/postgres.rs` file-local SQL/context SSOT**: `SQL_DELETE_MEMORY_BY_ID`,
  `SQL_SELECT_MEMORY_ID_BY_ID`, `SQL_SELECT_METADATA_BY_NS_TITLE`, `SQL_LOAD_AGE`,
  `SQL_SET_AGE_SEARCH_PATH`, `SQL_CREATE_AGE_GRAPH` (pub(crate), reused by
  `cli/schema_init.rs`), `PG_ERR_ALREADY_EXISTS` (ditto), `CTX_BEGIN_AGE_TX`,
  `CTX_COMMIT_AGE_TX`, `CTX_SET_SEARCH_PATH`, `CTX_VERIFY_LINK_SELECT`, `COL_CONTENT_LEN`,
  `TABLE_ARCHIVED_MEMORIES`.
- **`storage/mod.rs` sqlite SQL SSOT**: `SQL_DELETE_MEMORY_BY_ID` (`?1` form),
  `SQL_DELETE_NAMESPACE_META_BY_STANDARD_ID`, `SQL_MEMORY_EXISTS_COUNT`, `SQL_MEMORY_EXISTS`,
  `SQL_SELECT_MEMORY_ROW_BY_ID`.
- **`storage/migrations.rs::SELECT_SCHEMA_VERSION_SQL`** — one spelling for the
  schema-version probe shared by both SAL adapters, `cli/boot.rs`, `store/sqlite.rs`,
  `cli/schema_init.rs`.
- **`errors::msg` gained `opening()` / `reading()` / `writing()`** fs-context helpers
  (audit.rs, cli/logs.rs, governance/audit.rs, cli/install.rs, export_reflections.rs) and the
  existing `msg::invalid("id", e)` now serves `cli/shell.rs`'s `invalid id: {e}` lines.
- **`lib.rs::AI_MEMORY_HOME_DIR_NAME` (`.ai-memory`)** + `export_reflections::REFLECTIONS_SUBDIR`
  — data-dir spellings shared with the post-reflect auto-export/auto-persona hooks.
- **Owning-type spellings hoisted at their SSOT def sites**: `models/link.rs`
  `REL_CONTRADICTS`/`REL_REFLECTS_ON`/`REL_DERIVES_FROM` (also used by the
  reflect/contradiction response keys), `models/memory.rs` `KIND_OBSERVATION`/`KIND_REFLECTION`,
  `models/namespace.rs` `COLLECTIVE` + `AUTO_ATOMISE_SYNCHRONOUS`,
  `audit.rs::OP_CONSOLIDATE` (audit op + autonomy rollback tag + governance adapter + MCP tool),
  `governance/agent_action.rs::MATCHER_COMMAND_{SUBSTRING,REGEX}`,
  `governance/rules_store.rs::ATTEST_OPERATOR_SIGNED`.
- **Expect/label consts**: `cli/install.rs` `EXPECT_JUST_INSERTED_{OBJECT,ARRAY}` (10 sites),
  `cli/governance_migrate.rs::EXPECT_CHECKED_ABOVE`, `cli/doctor.rs` fact/section consts
  (`dim_violations`, `max_skew_secs`, `recall_mode_active`, `reranker_active`,
  `LLM Reachability (#1146)`, raw-SQL notice), `cli/rules.rs::OPERATOR_KEY_FILENAME`,
  `cli/verify_signed_events.rs::CTX_WRITE_CHAIN_REPORT`,
  `forensic/bundle.rs::MANIFEST_FILE_NAME`, `mcp/server_identity.rs::PUBLIC_KEY_FIELD`,
  `cli/identity.rs::PUBLIC_KEY_B64_FIELD`,
  `handlers/hook_subscribers.rs::NAMESPACE_STANDARD_TAG`,
  `handlers/subscriptions.rs::KIND_SUBSCRIPTION` + `caller_subscription_ns()`.
- **Format-template helpers (single synthesis site)**: `cli/backup.rs::manifest_file_name()`
  (`{stem}.manifest.json`), `handlers/subscriptions.rs::caller_subscription_ns()`
  (`_subscriptions/{caller}`), `hooks/decision.rs::malformed_must_be_string()` (the baseline's
  `must be a string` entry — the gate keys it space-stripped from the
  `"\"<field>\" must be a string"` segments).
- **Embedder artifacts**: `embeddings.rs` `HF_CONFIG_FILE`/`HF_TOKENIZER_FILE`/`HF_WEIGHTS_FILE`
  (reused by `reranker.rs`), `NOMIC_OLLAMA_MODEL` widened to pub(crate) (reused by
  `daemon_runtime.rs` + `mcp/mod.rs`), `reranker.rs::DEFAULT_RERANKER_MODEL` (reused by
  `cli/commands/config.rs` migrate template).

## Gate evidence (post-sweep working tree)

- `cargo check` (default) — clean, zero warnings.
- `cargo check --features sal-postgres` — clean.
- `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` — clean.
- `cargo clippy --features sal-postgres --tests -- -D warnings -D clippy::all -D clippy::pedantic` — clean.
- `cargo fmt --check` — clean.
- `bash scripts/check-hardcoded-literals.sh` — **PASS**.
- `bash scripts/check-vendor-literals.sh` — **PASS**.
- QUAL-10 module-size ceilings — all touched ceiling files remain under their limits
  (postgres.rs 16 277/16 300, storage/mod.rs 16 411/16 450, mcp/mod.rs 13 982/14 000,
  migrations.rs 3 633/3 700, install.rs 3 410/3 500, daemon_runtime.rs 7 894/7 950) — no bumps needed.

All replacements are byte-preserving hoists: every routed const/helper produces the exact
pre-sweep wire/SQL/log bytes.

After an operator-gated `scripts/check-hardcoded-literals.sh --update-baseline`, the baseline
shrinks **148 → 28 entries (543 → 108 sites)**; the 28 survivors above are the irreducible
floor of the #1558 campaign under the current carve-out and tools-crate boundaries.
