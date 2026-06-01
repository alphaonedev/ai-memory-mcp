# 02 — CLI Subcommand Surface (v0.7.0)

Audit of the `ai-memory` clap CLI surface: the top-level `pub enum Command`
in `src/daemon_runtime.rs`, its dispatch arms in `daemon_runtime::run`, the
per-subcommand handler modules under `src/cli/`, and the subcommand-count
SSOT constants in `src/lib.rs`. All `file:line` provenance is from the
`release/v0.7.0` checkout at `/Users/fate/v07/v07-f5`.

## 1. Counts — SSOT and feature-gating

| Build | Subcommand count | SSOT constant | file:line |
|---|---|---|---|
| **Default** (no `sal`) | **79** | `EXPECTED_CLI_SUBCOMMANDS_DEFAULT` | `src/lib.rs:257` |
| **`--features sal`** / **`sal-postgres`** | **81** | `EXPECTED_CLI_SUBCOMMANDS_SAL` | `src/lib.rs:264` |

- The source `pub enum Command` declares **81** variants (`src/daemon_runtime.rs:157-523`). Verified mechanically: `awk '/^pub enum Command/,/^}/' src/daemon_runtime.rs | grep -E '^    [A-Z]' | wc -l` = **81**.
- **2-variant gap.** Exactly two variants are `#[cfg(feature = "sal")]`-gated and excluded from the default build:
  - `Migrate(MigrateArgs)` — gate at `src/daemon_runtime.rs:315`, variant at `:316`.
  - `SchemaInit(...)` — gate at `src/daemon_runtime.rs:326`, variant at `:327`.
- `sal-postgres` implies `sal` in `Cargo.toml`, so both `sal` and `sal-postgres` unlock the same 2 variants → 81. Neither variant is postgres-only at compile time; `SchemaInit` performs an *additional* `SELECT create_graph('memory_graph')` only when the target store is Postgres + Apache AGE (`src/daemon_runtime.rs:317-325` doc).
- **Mechanical pin:** `tests/cli_subcommand_count_invariant.rs` parses the enum body and asserts both SSOT constants (`cli_subcommand_count_default_build_matches_ssot` :110, `cli_subcommand_count_sal_build_matches_ssot` :125). The counter walks backward over doc-comments to detect the `#[cfg(feature = "sal")]` attribute (`:90-95`).

### Count lineage (per `src/lib.rs:240-264` + CLAUDE.md)
`57` (dev tip) → `58` (#1146 `Config`) → `63` (#1095 `Share` + FX-12/ARCH-3 `KgQuery`/`FindPaths`/`RecallObservations`/`CheckDuplicate`/`Replay`) → `77` (FX-C3 batch2, +16 parity variants) → `78` (#1389 L2 `RecoverPreviousSession`) → **`79`** (#1443 `Expand`). The sal total tracks +2 → **`81`**.

## 2. Global args (`Cli` struct, `src/daemon_runtime.rs:125-154`)

| Flag | Type | Env | Notes | line |
|---|---|---|---|---|
| `--db` | `PathBuf` | `AI_MEMORY_DB` | global; default `DEFAULT_DB` | `:134` |
| `--json` | `bool` | — | global; machine-parseable output | `:137` |
| `--agent-id` | `Option<String>` | `AI_MEMORY_AGENT_ID` | global; NHI identity | `:142` |
| `--db-passphrase-file` | `Option<PathBuf>` | — | global; sqlcipher passphrase, mode 0400 | `:152` |

`name = "ai-memory"`, `version`, about-string at `:126-130`. Dispatch entry: `pub async fn run(cli: Cli, app_config: &AppConfig)` at `src/daemon_runtime.rs:773`. Thin `main.rs` shim (218 lines) re-exports `Cli` and delegates to `run`.

## 3. Full subcommand catalogue (by area)

Enum variant declarations are in `src/daemon_runtime.rs`; dispatch arms are
in `daemon_runtime::run` (also `src/daemon_runtime.rs`). Both `file:line`
columns reference that file.

### Daemon / serve / MCP
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Serve` | Start HTTP memory daemon (tier from config; TLS/mTLS/quorum flags) | `:170` | `:796` |
| `Mcp` | Run MCP stdio JSON-RPC tool server (`--tier`, `--profile`) | `:172` | `:825` |

### Store / recall / search / CRUD
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Store` | Store a new memory | `:195` | `:875` |
| `Update` | Update an existing memory by ID | `:197` | `:890` |
| `Recall` | Recall memories relevant to a context | `:199` | `:898` |
| `Search` | Search memories by text | `:201` | `:906` |
| `Get` | Retrieve a memory by ID | `:203` | `:914` |
| `List` | List memories | `:205` | `:922` |
| `Delete` | Delete a memory by ID | `:207` | `:930` |
| `Promote` | Promote a memory to long-term | `:209` | `:938` |
| `Forget` | Delete memories matching a pattern | `:211` | `:946` |
| `Link` | Link two memories | `:213` | `:954` |
| `Consolidate` | Consolidate multiple memories into one | `:215` | `:962` |
| `Resolve` | Resolve a contradiction (supersede) | `:244` | `:970` |
| `Gc` | Run garbage collection | `:217` | `:996` |
| `Stats` | Show statistics | `:219` | `:1004` |
| `Namespaces` | List all namespaces | `:221` | `:1012` |
| `Export` | Export all memories as JSON | `:240` | `:1047` |
| `Import` | Import memories from JSON (stdin) | `:242` | `:1055` |
| `Shell` | Interactive memory shell (REPL) | `:246` | `:978` |
| `AutoConsolidate` | Auto-consolidate short-term memories by namespace | `:255` | `:988` |

### Namespace / config / governance
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Namespace` | Per-namespace standard-policy CRUD (set/get/clear-standard + batman-policy) (#800) | `:229` | `:1020` |
| `Config` | `config migrate` — rewrite legacy v1 config to v2 sectioned shape (#1146) | `:238` | `:1033` |
| `Governance` | Migrate legacy `[governance]` → `[[permissions.rules]]`; sub-verbs below (K11) | `:372` | `:1368` |
| `Rules` | Substrate agent-action rules engine CRUD (#691); mutations require operator key | `:288` | `:1143` |
| `Pending` | List / approve / reject governance-pending actions | `:290` | `:1154` |

`Governance` sub-subcommands (`GovernanceAction`, `src/daemon_runtime.rs:538-552`): `MigrateToPermissions` (:541), `InstallDefaults` (:546, #760 — activate seed rules R001-R004), `CheckAction` (:551, #863 — dry-run Allow/Refuse/Warn verdict).

### Federation / sync
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Sync` | Sync memories between two database files | `:248` | `:979` |
| `SyncDaemon` | Run the P2P sync daemon (live HTTP peer mesh) | `:253` | `:987` |

### Identity / agents / keys
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Agents` | Register or list agents (Task 1.3) | `:265` | `:1101` |
| `Identity` | Per-agent Ed25519 keypair lifecycle (generate/import/list/export-pub) | `:271` | `:1109` |

### Offload (context substrate, QW-3)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Offload` | Persist a file/stdin into `offloaded_blobs`, print `ref_id` | `:276` | `:1120` |
| `Deref` | Dereference a previously-offloaded `ref_id` (SHA-256 verified) | `:280` | `:1133` |

### Backup / curator / bench / postgres-SAL (gated)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Backup` | Snapshot SQLite DB to timestamped backup (VACUUM INTO) | `:294` | `:1162` |
| `Restore` | Restore SQLite DB from a backup (manifest sha256 verified) | `:299` | `:1170` |
| `Curator` | Run the autonomous curator (`--once`/`--daemon`) | `:304` | `:1178` |
| `Bench` | Run canonical perf workload, p50/p95/p99 vs budgets | `:310` | `:1210` |
| `Migrate` 🔒sal | Migrate memories between SAL backends | `:316` | `:1212` |
| `SchemaInit` 🔒sal | Bootstrap a SAL backend's schema by URL | `:327` | `:1214` |

🔒 = `#[cfg(feature = "sal")]`-gated; absent in the default build.

### Health / boot / install / wrap / logs / audit
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Doctor` | Operator health dashboard; `--remote`/`--json`/`--tokens`/`--hooks`/`--fail-on-warn` | `:334` | `:1222` |
| `Boot` | Emit session-boot context (universal hook primitive, #487) | `:342` | `:1290` |
| `Install` | Wire boot + MCP into agent config files (#487 PR-2) | `:349` | `:1315` |
| `Wrap` | Rust replacement for bash/PowerShell agent wrappers (#487 PR-6) | `:357` | `:1326` |
| `Logs` | Operational-logging CLI (tail/cat/archive/purge); default-OFF | `:362` | `:1349` |
| `Audit` | Security audit-trail CLI (verify/tail/path); default-OFF | `:366` | `:1357` |

### Other utilities
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Completions` | Generate shell completions | `:257` | `:1063` |
| `Man` | Generate man page | `:259` | `:1072` |
| `Mine` | Import memories from Claude/ChatGPT/Slack exports | `:261` | `:1078` |
| `Archive` | Manage the memory archive (list/restore/purge/stats) | `:263` | `:1093` |

### Forensic / verification (procurement-grade)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `VerifyReflectionChain` | Verify reflection chain (`reflects_on` edges), Ed25519 sigs | `:378` | `:1386` |
| `VerifySignedEventsChain` | Verify SQL-side `signed_events` cross-row hash chain (v34) | `:385` | `:1397` |
| `ExportForensicBundle` | Export signed forensic evidence bundle (#670) | `:390` | `:1408` |
| `VerifyForensicBundle` | Verify a forensic evidence bundle | `:395` | `:1419` |
| `ExportReflections` | Write reflection memories to disk (`.md`/`.json`) (QW-1) | `:401` | `:1430` |

### Capture / recover / atomise / persona / calibrate (v0.7.0 substrate primitives)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `RecoverPreviousSession` | Fail-safe context recovery from host transcript (#1389 L2) | `:409` | `:1441` |
| `Atomise` | Decompose one memory into atomic propositions (WT-1-F) | `:417` | `:1456` |
| `Persona` | Fetch/regenerate Persona artefact for an entity (QW-2) | `:421` | `:1473` |
| `Calibrate` | Calibration driver (`calibrate confidence --from-shadow`) (Form 5) | `:426` | `:1490` |
| `Skill` | Agent-Skills CLI parity (register/list/get/resource/export/promote/compose) (#767) | `:432` | `:1508` |
| `Share` | Copy a memory into a recipient's `_shared/<from>→<to>/` namespace (#1095) | `:439` | `:1528` |

### Expand (#1443)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `Expand` | LLM query-expansion over free-text query; three-surface parity with `memory_expand_query` MCP + `POST /api/v1/expand_query` | `:459` | `:1577` |

### KG / parity batch (FX-12 / ARCH-3 + FX-C3 batch2)
| Subcommand | Purpose | variant | dispatch |
|---|---|---|---|
| `KgQuery` | Outbound KG traversal (≤5 hops) | `:443` | `:1544` |
| `FindPaths` | Enumerate ≤N KG paths between two memories (BFS, ≤7) | `:447` | `:1552` |
| `RecallObservations` | List recall-consumption ledger rows (#886) | `:451` | `:1560` |
| `CheckDuplicate` | Pre-write near-duplicate check via cosine | `:464` | `:1568` |
| `Replay` | Reconstruct conversation transcript chain | `:468` | `:1588` |
| `Reflect` | CLI parity for `memory_reflect` | `:473` | `:1602` |
| `Subscribe` | CLI parity for `memory_subscribe` | `:476` | `:1610` |
| `Unsubscribe` | CLI parity for `memory_unsubscribe` | `:479` | `:1618` |
| `ListSubscriptions` | CLI parity for `memory_list_subscriptions` | `:482` | `:1626` |
| `SubscriptionReplay` | CLI parity for `memory_subscription_replay` | `:485` | `:1634` |
| `SubscriptionDlqList` | CLI parity for `memory_subscription_dlq_list` | `:488` | `:1642` |
| `Notify` | CLI parity for `memory_notify` | `:491` | `:1650` |
| `Inbox` | CLI parity for `memory_inbox` | `:494` | `:1658` |
| `IngestMultistep` | CLI parity for `memory_ingest_multistep` | `:499` | `:1666` |
| `KgInvalidate` | CLI parity for `memory_kg_invalidate` | `:502` | `:1674` |
| `KgTimeline` | CLI parity for `memory_kg_timeline` | `:505` | `:1682` |
| `EntityRegister` | CLI parity for `memory_entity_register` | `:508` | `:1690` |
| `EntityGetByAlias` | CLI parity for `memory_entity_get_by_alias` | `:511` | `:1698` |
| `DependentsOfInvalidated` | CLI parity for `memory_dependents_of_invalidated` | `:514` | `:1706` |
| `ReflectionOrigin` | CLI parity for `memory_reflection_origin` | `:519` | `:1716` |
| `QuotaStatus` | CLI parity for `memory_quota_status` | `:522` | `:1724` |

**Variant total:** 79 default-build rows above + `Migrate` + `SchemaInit` = **81** declared / **79** compiled by default.

## 4. Output formatting, exit codes, write-classification

### `--json` global flag
`Cli.json` (`src/daemon_runtime.rs:137`) is a global boolean; most handlers
honor it. Output is rendered via `cli::CliOutput` (locks stdout/stderr;
constructed `CliOutput::from_std(&mut so, &mut se)`, e.g. `:1241`).

### Exit-code contracts
The CLI uses `std::process::exit(code)` for handlers with structured exit
contracts (rather than returning `Result`). Sites in `daemon_runtime::run`:

| Subcommand | Contract | line |
|---|---|---|
| `Mcp` (tier-resolution failure) | exit 2 | `:835` |
| `Config` migrate | passes through handler `code` | `:1044` |
| `SchemaInit` | exit `code` | `:1251`/`:1267` (tokens/hooks branches), `:1285` |
| `Wrap` | propagates wrapped-agent exit code | `:1346` |
| `Governance` | exit `code` | `:1365` |
| `VerifyReflectionChain` / `VerifySignedEventsChain` | 0 if verified, non-zero otherwise | `:1394` / `:1405` |
| `ExportForensicBundle` / `VerifyForensicBundle` | exit `code` | `:1416` / `:1427` |
| `ExportReflections`, `RecoverPreviousSession`, `Atomise`, `Persona`, `Calibrate`, `Skill`, `Share`, `Expand` | exit `code` | `:1438`, `:1453`, `:1470`, `:1487`, `:1503`, `:1525`, (others through `:1585`) |
| `Doctor` | **0** healthy, **1** warnings (with `--fail-on-warn`), **2** critical (`src/daemon_runtime.rs:328-333` doc; computed from severity, propagated via process-exit) | `:1222` |
| `Bench` | non-zero when any p95 exceeds budget +10% tolerance | `:310` doc |

`Atomise` exit codes are centralized in `crate::cli::commands::atomise::exit_code` (`src/cli/commands/atomise.rs`, referenced at `src/daemon_runtime.rs:416`).

### Write-classification gate (`is_write_command`, `src/daemon_runtime.rs:1752-1800`)
A `matches!` predicate flags write-class subcommands so the post-run WAL
checkpoint fires. Write-class set: `Store`, `Update`, `Delete`, `Promote`,
`Forget`, `Link`, `Consolidate`, `Resolve`, `Sync`, `SyncDaemon`, `Import`,
`AutoConsolidate`, `Gc`, `Atomise`, `Skill`, `Namespace`, `Share`, `Reflect`,
`Subscribe`, `Unsubscribe`, `Notify`, `IngestMultistep`, `KgInvalidate`,
`EntityRegister`. (Read-only verbs in the same families — e.g. `get-standard`,
`list-subscriptions`, `subscription-dlq-list`, `inbox`, `kg-timeline`,
`quota-status` — are deliberately omitted; `Skill` and `Namespace` are
classified whole-family as write-class even though some of their sub-verbs read.)

### Admin / operator-gated subcommands
- `Rules` mutation verbs (add/enable/disable/remove) require the operator's
  Ed25519 keypair at `<key-dir>/operator.priv` (mode 0600); without `--sign`
  they refuse with `governance.no_operator_key`. Read verbs (list/check) are
  unprivileged (`src/daemon_runtime.rs:281-288` doc).
- `Governance install-defaults` flips seed rules R001-R004 to enabled;
  interactive confirmation unless `--yes` (`:542-546`).
- Admin allowlist composition is via `AI_MEMORY_ADMIN_AGENT_IDS`
  (CLAUDE.md env-var table #36) — relevant to the daemon's `for_admin_checked`
  privacy-bypass gate, not a CLI-flag.

## 5. Handler module inventory (`src/cli/`, ~70 files)

Top-level handler modules (selected): `serve_banner.rs`, `store.rs`,
`recall.rs`, `search.rs`, `crud.rs`, `consolidate.rs`, `forget.rs`, `link.rs`,
`promote.rs`, `gc.rs`, `namespace.rs`, `identity.rs`, `agents.rs`, `offload.rs`,
`rules.rs`, `governance.rs`, `governance_migrate.rs`,
`governance_install_defaults.rs`, `governance_check_action.rs`, `backup.rs`,
`curator.rs`, `schema_init.rs`, `doctor.rs` (117 symbols — largest),
`install.rs` (187 symbols — largest overall), `boot.rs`, `wrap.rs`, `logs.rs`,
`audit.rs`, `verify.rs`, `verify_signed_events.rs`, `share.rs`, `sync.rs`,
`archive.rs`, `export.rs`, `update.rs`, `io.rs`/`io_writer.rs` (`CliOutput`),
`shell.rs`, `helpers.rs`.

Per-MCP-parity handlers live under `src/cli/commands/` (one file per
subcommand): `atomise.rs`, `calibrate_confidence.rs`, `check_duplicate.rs`,
`config.rs`, `dependents_of_invalidated.rs`, `entity_get_by_alias.rs`,
`entity_register.rs`, `export_reflections.rs`, `expand.rs`, `find_paths.rs`,
`inbox.rs`, `ingest_multistep.rs`, `kg_invalidate.rs`, `kg_query.rs`,
`kg_timeline.rs`, `list_subscriptions.rs`, `notify.rs`, `persona.rs`,
`quota_status.rs`, `recall_observations.rs`, `recover_previous_session.rs`,
`reflect.rs`, `reflection_origin.rs`, `replay.rs`, `skill.rs`, `subscribe.rs`,
`subscription_dlq_list.rs`, `subscription_replay.rs`, `unsubscribe.rs`.

(`src/cli/commands/mod.rs:37` declares `pub mod expand;` (#1443); confirmed
present — the `Expand` arm at `src/daemon_runtime.rs:459`/`:1577` is fully
reachable.)

## 6. DRIFT / DEFECTS SPOTTED

1. **Stale count in the count-invariant test's own docstring.**
   `tests/cli_subcommand_count_invariant.rs:40-41` states *"The recipe
   returns 80 today; ... using the same shape on the `#[cfg(feature = "sal")]`
   attribute lines."* — and the module-level `//!` header at `:6-7` says
   the pre-sweep count was cited as `80`/`82`. The actual SSOT (and the
   live `awk` count) is **79 default / 81 sal**. The docstring narrative is
   stale relative to the assertions the same file enforces (the *assertions*
   are correct against `EXPECTED_CLI_SUBCOMMANDS_DEFAULT=79` / `_SAL=81`; only
   the prose comment drifts). Low-severity doc-drift inside a test file.

2. **CLAUDE.md "Prime directive" / "Sole-authority" prose still cites `80`
   CLI subcommands.** CLAUDE.md §"Prime directive" reads *"80 CLI subcommands
   at v0.7.0 (post FX-12/ARCH-3 + FX-C3 batch2 + #1389 L2 `RecoverPreviousSession`)"*
   — i.e. it pre-dates #1443's `Expand` bump to 79. The §"Architecture" and
   §"Key Modules" sections of the SAME CLAUDE.md correctly say 79/81. Internal
   self-contradiction; the §"Prime directive" figure is stale by one (`Expand`
   not counted). Defect-class: doc-drift contradiction.

3. **(Resolved — not a defect.)** The CodeGraph file index did not surface an
   `expand` entry under `src/cli/commands/`, but a direct read confirms
   `pub mod expand;` at `src/cli/commands/mod.rs:37` (#1443). The CodeGraph
   omission was index-lag; the `Expand` arm (`src/daemon_runtime.rs:459`/`:1577`)
   is fully reachable. No action needed.

4. **No unreachable variants detected.** All 81 declared variants have a
   matching dispatch arm in `daemon_runtime::run` (`Serve`@:796 … `QuotaStatus`@:1724),
   including both sal-gated arms (`Migrate`@:1212, `SchemaInit`@:1214). No
   present-but-unreachable subcommand was found.
</content>
</invoke>
