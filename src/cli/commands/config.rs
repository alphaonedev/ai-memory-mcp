// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x (#1146) — `ai-memory config <subcommand>` CLI surface.
//!
//! Exposes `migrate` (rewrite a legacy v1 flat-field `config.toml` to
//! the canonical v2 sectioned shape) and `check` (#3197 — parse-only
//! TOML validation that never echoes the file, so a secret-bearing
//! config cannot leak into logs).
//!
//! ## Wire shape
//!
//! ```bash
//! ai-memory config migrate              # write <file>.bak.<ts> + rewrite
//! ai-memory config migrate --dry-run    # print diff, write nothing
//! ai-memory config migrate \
//!     --also-clean-claude-json          # additionally remove the
//!                                       # mcpServers.<*>.env block from
//!                                       # ~/.claude.json after verifying
//!                                       # the new config.toml works
//! ai-memory config check                # validate resolved config.toml
//! ai-memory config check --file PATH    # validate a specific file
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning                                                  |
//! |-----:|----------------------------------------------------------|
//! |   0  | success — file migrated or already v2 (no-op INFO)       |
//! |   1  | informational — dry-run mode, no writes performed        |
//! |   2  | file not found (no `~/.config/ai-memory/config.toml`)    |
//! |   3  | parse error — input is not valid TOML, OR (#3001) the     |
//! |      | migrated output does not round-trip through `AppConfig`   |
//! |      | (refused; no file written, original untouched)           |
//! |   4  | write error — could not write `.bak` or new file         |

use crate::models::field_names;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::CliOutput;
use crate::config::config_keys;

/// Args for `ai-memory config <subcommand>`.
#[derive(Args, Debug, Clone)]
pub struct ConfigCliArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Rewrite a legacy v1 (flat-field) `config.toml` to the v2
    /// sectioned shape (`[llm]`, `[embeddings]`, `[reranker]`,
    /// `[storage]`).
    ///
    /// Default behaviour: write `<config.toml>.bak.<timestamp>` then
    /// rewrite the live file. Idempotent — running against a v2 file
    /// is a no-op `INFO` log.
    Migrate {
        /// Print the diff to stderr without writing anything. Exits
        /// with code 1 (informational).
        #[arg(long)]
        dry_run: bool,

        /// Additionally remove every `mcpServers.<*>.env` block whose
        /// command resolves to `ai-memory` from `~/.claude.json`. A
        /// timestamped `.bak` is written alongside. Default OFF — the
        /// operator must opt in after verifying the new
        /// `config.toml` works.
        #[arg(long)]
        also_clean_claude_json: bool,
    },

    /// Validate that a config file is parseable TOML without printing
    /// its contents (#3197). Used by `entrypoint.plan-c.sh` after
    /// rendering so a malformed secret cannot leak into container
    /// logs via `config migrate --dry-run`'s diff, and so a parse
    /// failure refuses `exec` (EX_CONFIG) instead of
    /// `AppConfig::load_from` fail-opening to a keyless daemon.
    ///
    /// Exit 0 = valid TOML with no unknown keys; 2 = file missing; 3 =
    /// not valid TOML; 4 = unreadable; 5 = valid TOML carrying keys the
    /// daemon refuses to boot on (#3715 — run this BEFORE upgrading; it
    /// never refuses, it reports). The toml crate's `Display` is deliberately
    /// omitted from the error line — it can echo the offending
    /// source, which may carry `api_key`.
    Check {
        /// Config file to validate. Defaults to the resolved
        /// `~/.config/ai-memory/config.toml`.
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
    },

    /// #3714 — print the deployment shape and every setting it derives,
    /// each marked FLOOR (an override below it refuses boot) or default
    /// (an explicit value wins). Prints no secret and no effective
    /// value: it renders what the SHAPE says, so an operator can see
    /// which knobs they may override before they touch one.
    Show {
        /// Config file to read the `[deployment]` block from. Defaults to
        /// the resolved `~/.config/ai-memory/config.toml`; a missing file
        /// renders the `singleton` table.
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
        /// #3715 — print the configuration AS THE DAEMON RESOLVES IT (the
        /// same loader `serve` boots through: file over compiled defaults,
        /// unknown and removed keys refused), rendered as TOML with every
        /// secret-bearing value masked.
        #[arg(long)]
        effective: bool,
        /// #3715 — with --effective: one line per accepted key naming its
        /// value and origin (`file <path>` or `compiled-default`, plus the
        /// deprecation state), then the AI_MEMORY_* environment variables
        /// present in this process (names only; each is consulted by its
        /// own setting at use time).
        #[arg(long, requires = "effective")]
        provenance: bool,
    },
}

/// Entry point dispatched by `daemon_runtime::run`.
///
/// # Errors
///
/// Returns the underlying I/O / parse error if the migration fails.
pub fn run(_db: &Path, args: ConfigCliArgs, out: &mut CliOutput) -> Result<i32> {
    match args.action {
        ConfigAction::Migrate {
            dry_run,
            also_clean_claude_json,
        } => migrate(dry_run, also_clean_claude_json, out),
        ConfigAction::Check { file } => check_toml(file.as_deref(), out),
        ConfigAction::Show {
            file,
            effective: false,
            ..
        } => show_shape(file.as_deref(), out),
        ConfigAction::Show {
            file,
            effective: true,
            provenance,
        } => show_effective(file.as_deref(), provenance, out),
    }
}

/// #3715 item 4 — the provenance word for a leaf the file does not set.
const ORIGIN_COMPILED_DEFAULT: &str = "compiled-default";

/// #3715 item 4 — where the effective configuration came from.
enum EffectiveSource {
    File(PathBuf),
    NoFile(Option<PathBuf>),
    SkipConfig,
}

impl EffectiveSource {
    fn describe(&self) -> String {
        match self {
            Self::File(p) => format!("loaded from {}", p.display()),
            Self::NoFile(Some(p)) => format!("no config at {} — compiled defaults", p.display()),
            Self::NoFile(None) => "no config path ($HOME unset) — compiled defaults".to_string(),
            Self::SkipConfig => "AI_MEMORY_NO_CONFIG set — compiled defaults".to_string(),
        }
    }
}

/// #3715 item 4 — `config show --effective [--provenance]`.
///
/// ONE loader: [`AppConfig::try_load_from_optional`], the boot funnel, so an
/// unknown or removed key refuses here exactly as it refuses `serve`
/// (exit [`crate::config::EX_CONFIG`]), and what prints is what boots.
/// Rendering goes through the #3432 redaction funnel — a secret-bearing
/// value is masked, a URL keeps only its allowlisted parts.
///
/// Provenance in this cut is `file <path>` / `compiled-default` per accepted
/// leaf plus the deprecation row; environment overrides are applied by each
/// setting's own accessor at use time (not merged here), so they are listed
/// by NAME as present, never attributed to a leaf and never printed by value.
fn show_effective(file: Option<&Path>, provenance: bool, out: &mut CliOutput) -> Result<i32> {
    use crate::config::AppConfig;

    let (source, path) = match file {
        Some(p) if p.exists() => (
            EffectiveSource::File(p.to_path_buf()),
            Some(p.to_path_buf()),
        ),
        Some(p) => (EffectiveSource::NoFile(Some(p.to_path_buf())), None),
        None if crate::config::skip_config() => (EffectiveSource::SkipConfig, None),
        None => match AppConfig::config_path() {
            Some(p) if p.exists() => (EffectiveSource::File(p.clone()), Some(p)),
            other => (EffectiveSource::NoFile(other), None),
        },
    };
    let cfg = match &path {
        Some(p) => match AppConfig::try_load_from_optional(p) {
            Ok(cfg) => cfg,
            Err(e) => {
                let _ = writeln!(out.stderr, "ERROR: {e:#}");
                return Ok(crate::config::EX_CONFIG);
            }
        },
        None => AppConfig::default(),
    };
    let serialised = toml::to_string(&cfg).context("serialising the effective configuration")?;
    let effective: toml::Value =
        toml::from_str(&serialised).context("re-parsing the effective configuration")?;
    let table = effective
        .as_table()
        .cloned()
        .context("the effective configuration is not a table")?;
    let _ = writeln!(
        out.stdout,
        "# effective configuration: {} (the document the boot loader accepted, secrets \
         masked; a setting absent here takes its compiled default at use)",
        source.describe()
    );
    let _ = write!(
        out.stdout,
        "{}",
        crate::config_redact::render_redacted_toml(&table)
    );
    if !provenance {
        return Ok(0);
    }

    // The raw document decides "file" vs "compiled-default": a key the
    // operator wrote is in the raw tree; everything else is a default.
    let raw: Option<toml::Value> = path
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| toml::from_str(&c).ok());
    let mut redacted = toml::Value::Table(table);
    crate::config_redact::redact_toml_value(&mut redacted);
    let _ = writeln!(out.stdout);
    let _ = writeln!(
        out.stdout,
        "# provenance: <key> = <value>  # <origin>  (origin: file <path> | {ORIGIN_COMPILED_DEFAULT})"
    );
    for key in crate::config::unknown_keys::accepted_leaf_keys() {
        if key.contains("<key>") || key.contains("[]") {
            // Map / array-of-tables wildcards have no single leaf to name.
            continue;
        }
        // Every top-level `AppConfig` field is an `Option`: a leaf the file
        // does not set is ABSENT here and takes its compiled default inside
        // its own accessor at use time — say so, rather than print a value
        // this verb did not resolve.
        let file_origin = match (&raw, &path) {
            (Some(raw_tree), Some(p)) if lookup_path(raw_tree, key).is_some() => {
                Some(format!("file {}", p.display()))
            }
            _ => None,
        };
        let (rendered, origin) = match (lookup_path(&redacted, key), file_origin) {
            (Some(value), Some(origin)) => (render_scalar(value), origin),
            (Some(value), None) => (render_scalar(value), ORIGIN_COMPILED_DEFAULT.to_string()),
            // In the file but withheld by the serialiser: a secret-bearing
            // field (`skip_serializing`). The key is real; the bytes are not
            // this verb's to print.
            (None, Some(origin)) => (
                format!("{:?}", crate::config_redact::CONFIG_REDACTION_MASK),
                origin,
            ),
            (None, None) => (
                "(unset: the compiled default applies at use)".to_string(),
                ORIGIN_COMPILED_DEFAULT.to_string(),
            ),
        };
        let deprecation =
            crate::config::deprecated_keys::lookup(key).map_or_else(String::new, |row| {
                format!(
                    "  # DEPRECATED since {} — use {}; removal {}",
                    row.deprecated_in,
                    row.replacement,
                    row.removed_in.map_or_else(
                        || "not scheduled".to_string(),
                        |r| format!("scheduled for {r}")
                    )
                )
            });
        let _ = writeln!(out.stdout, "{key} = {rendered}  # {origin}{deprecation}");
    }
    let mut env_names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| k.starts_with("AI_MEMORY_"))
        .collect();
    env_names.sort();
    let _ = writeln!(out.stdout);
    let _ = writeln!(
        out.stdout,
        "# environment: {} AI_MEMORY_* variable{} present (names only; each is consulted by \
         its own setting at use time and is NOT merged into the table above)",
        env_names.len(),
        if env_names.len() == 1 { "" } else { "s" }
    );
    for name in env_names {
        // Escaped: a name is the operator's own process state, but control
        // characters in a NAME are pathological and this line is pasted
        // into tickets (the #3264 S1 rule for operator-facing renders).
        let _ = writeln!(out.stdout, "#   {name:?}");
    }
    Ok(0)
}

/// Walk a dotted key path through a TOML tree.
fn lookup_path<'a>(tree: &'a toml::Value, dotted: &str) -> Option<&'a toml::Value> {
    dotted
        .split('.')
        .try_fold(tree, |node, seg| node.as_table().and_then(|t| t.get(seg)))
}

/// A scalar or inline value on one line, TOML-quoted.
fn render_scalar(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

/// #3714 — render the shape-derived table for the config at `file`.
/// Parses through `toml::Value` first so an unknown key elsewhere in the
/// file cannot stop the operator from seeing what their shape derives;
/// only the `[deployment]` block is interpreted.
fn show_shape(file: Option<&Path>, out: &mut CliOutput) -> Result<i32> {
    use crate::config::{AppConfig, DeploymentShape};

    let resolved;
    let path: Option<&Path> = if let Some(p) = file {
        Some(p)
    } else {
        resolved = AppConfig::config_path();
        resolved.as_deref()
    };
    let shape = match path {
        Some(p) if p.exists() => {
            let contents = std::fs::read_to_string(p)
                .with_context(|| crate::config::reading_config_context(p))?;
            let value: toml::Value = match toml::from_str(&contents) {
                Ok(v) => v,
                Err(e) => {
                    write_not_valid_toml(out, p, &e);
                    return Ok(3);
                }
            };
            match value
                .get(field_names::DEPLOYMENT)
                .and_then(|d| d.get(field_names::SHAPE))
                .and_then(toml::Value::as_str)
            {
                Some(token) => match DeploymentShape::parse(token) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = writeln!(out.stderr, "ERROR: {}: {e}", p.display());
                        return Ok(3);
                    }
                },
                None => DeploymentShape::Singleton,
            }
        }
        _ => DeploymentShape::Singleton,
    };
    let source = match path {
        Some(p) if p.exists() => format!("from {}", p.display()),
        Some(p) => format!("no config at {} — singleton", p.display()),
        None => "no config path ($HOME unset) — singleton".to_string(),
    };
    let _ = writeln!(out.stdout, "# {source}");
    let _ = write!(out.stdout, "{}", shape.derive().render_table());
    Ok(0)
}

/// The ONE "not valid TOML" error line (three verbs; pm-v3.1
/// hardcoded-literal gate). Routes the toml error through the #3432
/// redaction funnel so the offending source line is never echoed.
fn write_not_valid_toml(out: &mut CliOutput, path: &Path, e: &toml::de::Error) {
    let _ = writeln!(
        out.stderr,
        "ERROR: {} is not valid TOML: {}",
        path.display(),
        crate::config_redact::redact_parse_error(e)
    );
}

/// #3197 — parse-only TOML check. Does not migrate, does not print the
/// file, does not run `AppConfig::load_from` (which fail-opens).
fn check_toml(file: Option<&Path>, out: &mut CliOutput) -> Result<i32> {
    use crate::config::AppConfig;

    let resolved;
    let path: &Path = if let Some(p) = file {
        p
    } else {
        let Some(p) = AppConfig::config_path() else {
            let _ = writeln!(
                out.stderr,
                "ERROR: $HOME is not set; cannot resolve config path."
            );
            return Ok(2);
        };
        resolved = p;
        &resolved
    };
    if !path.exists() {
        let _ = writeln!(
            out.stderr,
            "ERROR: no config file at {} — nothing to check.",
            path.display()
        );
        return Ok(2);
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                out.stderr,
                "ERROR: could not read {}: {}",
                path.display(),
                e
            );
            return Ok(4);
        }
    };
    match toml::from_str::<toml::Value>(&contents) {
        Ok(value) => {
            // #3715 — the DETECTOR half of fail-closed unknown keys. This
            // verb parses through `toml::Value` and never refuses; it
            // reports what the boot loader WOULD refuse so an operator
            // finds it on their schedule, before upgrading. Exit 5 =
            // valid TOML that the daemon would refuse to boot on.
            let unknown = crate::config::unknown_keys::find_unknown_keys(&value);
            if unknown.is_empty() {
                let _ = writeln!(
                    out.stderr,
                    "OK: {} is valid TOML with no unknown keys",
                    path.display()
                );
                return Ok(0);
            }
            let _ = writeln!(
                out.stderr,
                "WOULD REFUSE: {} is valid TOML but carries {} unknown key{} the daemon \
                 refuses to boot on (#3715):",
                path.display(),
                unknown.len(),
                if unknown.len() == 1 { "" } else { "s" }
            );
            for u in &unknown {
                let _ = writeln!(
                    out.stderr,
                    "  - {}",
                    crate::config::unknown_keys::describe(u)
                );
            }
            let _ = writeln!(
                out.stderr,
                "  {}",
                crate::config::unknown_keys::repair_hint(path, &unknown)
            );
            Ok(5)
        }
        Err(e) => {
            // #3197 refused to interpolate the toml error at all, because
            // its `Display` echoes the offending line (which may carry
            // `api_key`). #3432 keeps that guarantee and restores the
            // position: the shared funnel drops the echoed source block and
            // screens what is left, so the operator gets "line 3, column 11"
            // instead of an unlocatable "not valid TOML".
            write_not_valid_toml(out, path, &e);
            Ok(3)
        }
    }
}

fn migrate(dry_run: bool, also_clean_claude_json: bool, out: &mut CliOutput) -> Result<i32> {
    use crate::config::AppConfig;

    let Some(path) = AppConfig::config_path() else {
        let _ = writeln!(
            out.stderr,
            "ERROR: $HOME is not set; cannot resolve config path."
        );
        return Ok(2);
    };

    if !path.exists() {
        let _ = writeln!(
            out.stderr,
            "ERROR: no config file at {} — nothing to migrate.",
            path.display()
        );
        return Ok(2);
    }

    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                out.stderr,
                "ERROR: could not read {}: {}",
                path.display(),
                e
            );
            return Ok(4);
        }
    };

    let original_value: toml::Value = match toml::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            // #3432 — the `toml` Display renders the OFFENDING SOURCE LINE
            // under a gutter, so interpolating it raw echoes whatever the
            // operator wrote on that line (typically an `api_key`). This is
            // the same leak `config check` (#3197) declined to take; route
            // it through the shared funnel, which keeps the position and
            // drops the echoed source.
            write_not_valid_toml(out, &path, &e);
            return Ok(3);
        }
    };

    let original_table = match original_value.as_table() {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                out.stderr,
                "ERROR: {} is valid TOML but not a top-level table.",
                path.display()
            );
            return Ok(3);
        }
    };

    // Detect idempotent no-op: schema_version >= 2 AND no legacy
    // fields present.
    let v2_already = original_table
        .get(field_names::SCHEMA_VERSION)
        .and_then(toml::Value::as_integer)
        .is_some_and(|v| v >= 2);
    let has_legacy = LEGACY_FIELDS
        .iter()
        .any(|k| original_table.contains_key(*k));

    if v2_already && !has_legacy {
        let _ = writeln!(
            out.stderr,
            "INFO: {} is already schema_version >= 2 with no legacy fields; no migration needed.",
            path.display()
        );
        return Ok(0);
    }

    let migrated_table = build_migrated_table(&original_table);
    // #3432 — the display copy the redaction funnel renders. Kept separate
    // from `migrated_value`/`migrated_text` so the bytes written to disk
    // can never be the masked ones.
    let migrated_table_for_display = migrated_table.clone();
    let migrated_value = toml::Value::Table(migrated_table);
    let migrated_text = toml::to_string_pretty(&migrated_value).unwrap_or_else(|_| String::new());

    if dry_run {
        // #3432 — print the REDACTED rendering, never `migrated_text`.
        // `migrated_text` is the byte-exact thing a real `migrate` writes
        // to disk and it carries every inline credential in the source
        // config verbatim (`[reranker] api_key`, the legacy top-level
        // `api_key`, `[hooks.subscription] hmac_secret`, …). Printing it
        // was the exact leak `config check` (#3197) was added to prevent —
        // one verb hardened while its sibling echoed the same file.
        //
        // The redaction is DISPLAY-ONLY: `migrated_text` above is
        // untouched, so the write path below still persists the real
        // secrets. A masked value written back would be silent credential
        // destruction.
        let redacted_text = crate::config_redact::render_redacted_toml(&migrated_table_for_display);
        let _ = writeln!(
            out.stderr,
            "--- DRY RUN — {} would be rewritten as (secret values masked as `{}`): ---",
            path.display(),
            crate::config_redact::CONFIG_REDACTION_MASK,
        );
        let _ = writeln!(out.stderr, "{redacted_text}");
        let _ = writeln!(out.stderr, "--- end dry run ---");
        if also_clean_claude_json {
            let _ = writeln!(
                out.stderr,
                "(--also-clean-claude-json also skipped in dry-run.)"
            );
        }
        return Ok(1);
    }

    // #3001 — FAIL LOUD, never fail-open. The migrator is SUPPOSED to
    // produce a valid v2 file; a malformed legacy value (e.g. a string
    // where `[reranker].enabled` expects a bool) would otherwise be
    // laundered verbatim into the v2 output, we would print "OK: migrated"
    // and exit 0, and the NEXT process would fail to parse it and silently
    // fall back to `AppConfig::default()` — tier / db / llm / namespace all
    // discarded. Validate that the migrated text round-trips through the
    // SAME parser the daemon uses BEFORE writing anything; on failure,
    // refuse with a non-zero exit and leave the original config untouched.
    // #3001 / #3215 Fable MED — same validating tail the daemon uses
    // (`from_toml_contents` = parse + `validate_secret_handling`). A
    // migrated file that parses but carries an inline secret must not
    // print "OK: migrated" and then 78 on the next boot.
    match toml::from_str::<AppConfig>(&migrated_text) {
        Err(e) => {
            let _ = writeln!(
                out.stderr,
                "ERROR: refusing to write {} — the migrated config does not parse \
                 ({}). No file was written and your original config is untouched. \
                 This usually means a legacy field in {} holds a value of the wrong \
                 type; fix it and re-run.",
                path.display(),
                // #3432 — same source-echo hazard as the parse arm above.
                crate::config_redact::redact_parse_error(&e),
                path.display()
            );
            return Ok(3);
        }
        Ok(cfg) => {
            if let Err(reason) = cfg.validate_secret_handling() {
                let _ = writeln!(
                    out.stderr,
                    "ERROR: refusing to write {} — the migrated config is rejected \
                     by the daemon's secret-handling validator ({reason}). No file \
                     was written and your original config is untouched.",
                    path.display()
                );
                return Ok(3);
            }
        }
    }

    // Write backup.
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let backup_path = path.with_extension(format!("toml.bak.{timestamp}"));
    if let Err(e) = std::fs::write(&backup_path, &contents) {
        let _ = writeln!(
            out.stderr,
            "ERROR: could not write backup {}: {}",
            backup_path.display(),
            e
        );
        return Ok(4);
    }

    // Write migrated file.
    if let Err(e) = std::fs::write(&path, &migrated_text) {
        let _ = writeln!(
            out.stderr,
            "ERROR: could not write {}: {}",
            path.display(),
            e
        );
        return Ok(4);
    }

    let _ = writeln!(
        out.stderr,
        "OK: migrated {} (backup: {})",
        path.display(),
        backup_path.display()
    );

    if also_clean_claude_json {
        match clean_claude_json(&timestamp) {
            Ok(Some(claude_path)) => {
                let _ = writeln!(
                    out.stderr,
                    "OK: cleaned ~/.claude.json (backup: {claude_path})"
                );
            }
            Ok(None) => {
                let _ = writeln!(
                    out.stderr,
                    "INFO: ~/.claude.json had no mcpServers env block referencing ai-memory; no changes."
                );
            }
            Err(e) => {
                let _ = writeln!(out.stderr, "WARN: ~/.claude.json clean failed: {e}");
            }
        }
    } else {
        let _ = writeln!(
            out.stderr,
            "INFO: your ~/.claude.json may still carry an mcpServers env block. \
             Re-run with `--also-clean-claude-json` to remove it after verifying \
             the new config.toml works."
        );
    }

    Ok(0)
}

/// Legacy v1 flat-field names that the migrator folds into v2 sections.
const LEGACY_FIELDS: &[&str] = &[
    "llm_model",
    config_keys::OLLAMA_URL,
    "embed_url",
    config_keys::EMBEDDING_MODEL,
    config_keys::CROSS_ENCODER,
    config_keys::DEFAULT_NAMESPACE,
    config_keys::ARCHIVE_ON_GC,
    config_keys::ARCHIVE_MAX_DAYS,
    config_keys::MAX_MEMORY_MB,
    config_keys::AUTO_TAG_MODEL,
];

/// Construct the v2 migrated table from a parsed v1 table. Pure (no
/// I/O) so the dry-run path and the apply path share one implementation.
fn build_migrated_table(
    original: &toml::map::Map<String, toml::Value>,
) -> toml::map::Map<String, toml::Value> {
    let mut migrated = original.clone();

    // Remove legacy fields from the top-level.
    let mut llm_model: Option<toml::Value> = None;
    let mut ollama_url: Option<toml::Value> = None;
    let mut embed_url: Option<toml::Value> = None;
    let mut embedding_model: Option<toml::Value> = None;
    let mut cross_encoder: Option<toml::Value> = None;
    let mut default_namespace: Option<toml::Value> = None;
    let mut archive_on_gc: Option<toml::Value> = None;
    let mut archive_max_days: Option<toml::Value> = None;
    let mut max_memory_mb: Option<toml::Value> = None;
    let mut auto_tag_model: Option<toml::Value> = None;

    macro_rules! take {
        ($name:expr, $target:ident) => {
            if let Some(v) = migrated.remove($name) {
                $target = Some(v);
            }
        };
    }

    take!("llm_model", llm_model);
    take!(config_keys::OLLAMA_URL, ollama_url);
    take!("embed_url", embed_url);
    take!(config_keys::EMBEDDING_MODEL, embedding_model);
    take!(config_keys::CROSS_ENCODER, cross_encoder);
    take!(config_keys::DEFAULT_NAMESPACE, default_namespace);
    take!(config_keys::ARCHIVE_ON_GC, archive_on_gc);
    take!(config_keys::ARCHIVE_MAX_DAYS, archive_max_days);
    take!(config_keys::MAX_MEMORY_MB, max_memory_mb);
    take!(config_keys::AUTO_TAG_MODEL, auto_tag_model);

    // schema_version = 2 (highest priority on insert).
    migrated.insert(
        field_names::SCHEMA_VERSION.to_string(),
        toml::Value::Integer(2),
    );

    // [llm] section — synthesise only if a legacy LLM field was present
    // OR the existing [llm] section is missing. (When the existing
    // [llm] section is present, the v1 legacy llm_model/ollama_url
    // were either redundant or operator drift; drop them.)
    if !migrated.contains_key("llm") && llm_model.is_some() {
        let mut llm = toml::map::Map::new();
        // Legacy v1 configs implied the Ollama-native backend
        // (`llm_model` + `ollama_url` were the only LLM knobs).
        // Reference the canonical backend-name const in `llm.rs`
        // (issue #1174 PR4 — substrate-vendor cleanup) so the
        // migrator never re-names the vendor.
        llm.insert(
            "backend".to_string(),
            toml::Value::String(crate::llm::BACKEND_OLLAMA.to_string()),
        );
        if let Some(v) = llm_model {
            llm.insert("model".to_string(), v);
        }
        if let Some(v) = ollama_url {
            llm.insert("base_url".to_string(), v);
        }
        // [llm.auto_tag] if legacy `auto_tag_model` was set.
        if let Some(v) = auto_tag_model {
            let mut sub = toml::map::Map::new();
            sub.insert("model".to_string(), v);
            llm.insert("auto_tag".to_string(), toml::Value::Table(sub));
        }
        migrated.insert("llm".to_string(), toml::Value::Table(llm));
    }

    // [embeddings] section.
    if !migrated.contains_key(config_keys::SECTION_EMBEDDINGS)
        && (embed_url.is_some() || embedding_model.is_some())
    {
        let mut emb = toml::map::Map::new();
        // Same legacy implication for embeddings — pre-v0.7.x configs
        // only spoke to Ollama for embedding generation.
        emb.insert(
            "backend".to_string(),
            toml::Value::String(crate::llm::BACKEND_OLLAMA.to_string()),
        );
        if let Some(v) = embed_url {
            emb.insert("url".to_string(), v);
        }
        if let Some(v) = embedding_model {
            emb.insert("model".to_string(), v);
        }
        migrated.insert(
            config_keys::SECTION_EMBEDDINGS.to_string(),
            toml::Value::Table(emb),
        );
    }

    // [reranker] section.
    if !migrated.contains_key("reranker") && cross_encoder.is_some() {
        let mut rerank = toml::map::Map::new();
        if let Some(v) = cross_encoder.clone() {
            rerank.insert("enabled".to_string(), v);
        }
        rerank.insert(
            "model".to_string(),
            toml::Value::String(crate::reranker::DEFAULT_RERANKER_MODEL.to_string()),
        );
        migrated.insert("reranker".to_string(), toml::Value::Table(rerank));
    }

    // [storage] section.
    if !migrated.contains_key("storage")
        && (default_namespace.is_some()
            || archive_on_gc.is_some()
            || archive_max_days.is_some()
            || max_memory_mb.is_some())
    {
        let mut storage = toml::map::Map::new();
        if let Some(v) = default_namespace {
            storage.insert(config_keys::DEFAULT_NAMESPACE.to_string(), v);
        }
        if let Some(v) = archive_on_gc {
            storage.insert(config_keys::ARCHIVE_ON_GC.to_string(), v);
        }
        if let Some(v) = archive_max_days {
            storage.insert(config_keys::ARCHIVE_MAX_DAYS.to_string(), v);
        }
        if let Some(v) = max_memory_mb {
            storage.insert(config_keys::MAX_MEMORY_MB.to_string(), v);
        }
        migrated.insert("storage".to_string(), toml::Value::Table(storage));
    }

    migrated
}

/// Remove `mcpServers.<*>.env` blocks (the entire `env` key) from any
/// `mcpServers` entry whose `command` resolves to an `ai-memory`
/// binary. Returns the backup path on change; `None` when no change
/// was needed.
fn clean_claude_json(timestamp: &str) -> Result<Option<String>> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("$HOME not set"))?;
    let path = PathBuf::from(&home).join(".claude.json");
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&path)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;

    let mut changed = false;
    if let Some(servers) = value
        .get_mut(crate::cli::install::KEY_MCP_SERVERS)
        .and_then(serde_json::Value::as_object_mut)
    {
        for (_name, entry) in servers.iter_mut() {
            let is_ai_memory = entry
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(|c| c.ends_with("/ai-memory") || c == "ai-memory")
                .unwrap_or(false);
            if !is_ai_memory {
                continue;
            }
            if let Some(obj) = entry.as_object_mut() {
                if obj.remove("env").is_some() {
                    changed = true;
                }
            }
        }
    }

    if !changed {
        return Ok(None);
    }

    let backup_path = format!("{}.bak.{}", path.display(), timestamp);
    std::fs::write(&backup_path, &contents)?;
    std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;

    Ok(Some(backup_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliOutput;

    /// Serialise the `$HOME`-mutating `run`/`migrate` tests — env
    /// mutation is process-global, so two of these running concurrently
    /// would race on `AppConfig::config_path()`.
    ///
    /// #1998: delegates to the single crate-canonical
    /// [`crate::config::test_env_lock`]. These tests mutate `HOME`, and the
    /// `config::tests` filter runs this module alongside `config::tests`;
    /// a private per-module mutex here let a `HOME` restore land inside a
    /// `config::tests` critical section (which then read the real
    /// `~/.config/ai-memory/config.toml`). One shared lock closes the race.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::test_env_lock()
    }

    /// Run `migrate` against a `config.toml` materialised under a
    /// tempdir `$HOME`. Returns (exit_code, stdout_text, stderr_text,
    /// on_disk_config). Holds the env lock for the duration.
    fn run_migrate_with_home(
        config_body: Option<&str>,
        dry_run: bool,
        also_clean: bool,
    ) -> (i32, String, String, String) {
        let _g = env_lock();
        let home = tempfile::tempdir().expect("tempdir");
        let cfg_path = home.path().join(".config/ai-memory/config.toml");
        if let Some(body) = config_body {
            let dir = cfg_path.parent().expect("config parent");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&cfg_path, body).unwrap();
        }
        let prev_home = std::env::var("HOME").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        // SAFETY: serialised via `env_lock()`; restored before the lock
        // is released so no other test observes the tempdir HOME.
        //
        // #3002 — `AppConfig::config_path()` now resolves through
        // `dirs::config_dir()`, which honors `XDG_CONFIG_HOME`. Pin it to
        // the tempdir's `.config` so the migrate command resolves to the
        // same `<home>/.config/ai-memory/config.toml` this helper writes,
        // regardless of the ambient host `XDG_CONFIG_HOME`.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("XDG_CONFIG_HOME", home.path().join(".config"));
        }
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Migrate {
                    dry_run,
                    also_clean_claude_json: also_clean,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        let on_disk = std::fs::read_to_string(&cfg_path).unwrap_or_default();
        unsafe {
            match prev_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
            on_disk,
        )
    }

    // -----------------------------------------------------------------
    // #3432 — no config-printing verb may echo a secret value
    //
    // `config check` (#3197) was hardened so a secret-bearing config could
    // not reach container logs; `config migrate --dry-run` then printed the
    // whole resolved table, and both migrate parse arms interpolated the
    // `toml` Display, which renders the offending SOURCE LINE. These tests
    // pin BOTH directions: no secret VALUE on either stream, and the
    // output still useful (non-secret values, key names and the `_env` /
    // `_file` pointers survive) — plus the data-integrity half, that the
    // redaction is display-only and the durable file keeps the real secret.
    // -----------------------------------------------------------------

    const S_LEGACY_TOP: &str = "legacy-top-level-secret-must-not-leak-3432";
    const S_RERANKER: &str = "reranker-secret-must-not-leak-3432";
    const S_LLM: &str = "llm-secret-must-not-leak-3432";
    const S_EMBEDDINGS: &str = "embeddings-secret-must-not-leak-3432";
    const S_HMAC: &str = "hmac-secret-must-not-leak-3432";
    /// #3432 amendment 2 — a NUMERIC secret. Deliberately not
    /// credential-shaped, so only the message-body masking can stop it.
    const S_WRONG_TYPED: &str = "987654321321";

    /// Legacy (v1 flat-field) layout carrying every inline-secret shape,
    /// including the two (`[llm]` / `[embeddings]` `api_key`) the daemon's
    /// secret-handling validator refuses. Used for the dry-run and the
    /// REFUSED arms.
    fn legacy_body_maximal() -> String {
        format!(
            "tier = \"smart\"\n\
             llm_model = \"gemma\"\n\
             ollama_url = \"http://localhost:11434\"\n\
             api_key = \"{S_LEGACY_TOP}\"\n\
             \n[reranker]\nenabled = true\napi_key = \"{S_RERANKER}\"\n\
             \n[llm]\nbackend = \"xai\"\napi_key = \"{S_LLM}\"\n\
             \n[embeddings]\nbackend = \"xai\"\napi_key = \"{S_EMBEDDINGS}\"\n\
             \n[hooks.subscription]\nhmac_secret = \"{S_HMAC}\"\n"
        )
    }

    /// Legacy layout whose inline secrets all live in sections the
    /// validator does not refuse, so a real (non-dry-run) migrate succeeds
    /// and writes.
    fn legacy_body_migratable() -> String {
        format!(
            "tier = \"smart\"\n\
             llm_model = \"gemma\"\n\
             ollama_url = \"http://localhost:11434\"\n\
             api_key = \"{S_LEGACY_TOP}\"\n\
             \n[reranker]\nenabled = true\napi_key = \"{S_RERANKER}\"\n\
             \n[hooks.subscription]\nhmac_secret = \"{S_HMAC}\"\n"
        )
    }

    /// A numeric secret in a string-typed field. The migrated text parses as
    /// TOML but FAILS `toml::from_str::<AppConfig>`, and serde's
    /// `invalid type: integer \`…\`, expected a string` embeds the VALUE in
    /// the message BODY — outside any gutter, and not vendor-shaped, so
    /// neither the gutter filter nor the value-shape screen catches it.
    /// #3432 amendment 2.
    fn legacy_body_wrong_typed_secret() -> String {
        format!(
            "tier = \"smart\"\n\
             llm_model = \"gemma\"\n\
             \n[hooks.subscription]\nhmac_secret = {S_WRONG_TYPED}\n"
        )
    }

    /// v2 sectioned layout that still carries ONE legacy field (a partially
    /// migrated file — the realistic shape an operator runs `migrate`
    /// against). A pure v2 file is a no-op that prints nothing, so it has
    /// no print path to test.
    fn v2_body_partial() -> String {
        format!(
            "schema_version = 2\n\
             tier = \"smart\"\n\
             default_namespace = \"proj\"\n\
             api_key = \"{S_LEGACY_TOP}\"\n\
             \n[llm]\nbackend = \"xai\"\napi_key_env = \"XAI_API_KEY\"\n\
             \n[reranker]\nenabled = true\napi_key = \"{S_RERANKER}\"\n\
             \n[hooks.subscription]\nhmac_secret = \"{S_HMAC}\"\n"
        )
    }

    /// #3432 — like [`run_migrate_with_home`] but also returns stdout and
    /// the on-disk config AFTER the run, so a test can assert both that no
    /// secret reached a stream and that the durable file still holds the
    /// real secret (the redaction is display-only).
    fn run_migrate_capture(config_body: &str, dry_run: bool) -> (i32, String, String, String) {
        run_migrate_with_home(Some(config_body), dry_run, false)
    }

    /// DENIED path, table-driven: across both layouts and both modes (and
    /// the validator-refused arm), no secret VALUE may appear on stdout or
    /// stderr.
    #[test]
    fn migrate_never_prints_a_secret_value_3432() {
        let secrets = [
            S_LEGACY_TOP,
            S_RERANKER,
            S_LLM,
            S_EMBEDDINGS,
            S_HMAC,
            S_WRONG_TYPED,
        ];
        let cases: [(&str, String, bool, i32); 7] = [
            ("legacy/maximal", legacy_body_maximal(), true, 1),
            // The migrated file carries an inline `[llm].api_key`, so the
            // daemon's secret-handling validator refuses the write. The
            // refusal message must not carry the secret either.
            ("legacy/maximal", legacy_body_maximal(), false, 3),
            ("legacy/migratable", legacy_body_migratable(), true, 1),
            ("legacy/migratable", legacy_body_migratable(), false, 0),
            ("v2/partial", v2_body_partial(), true, 1),
            ("v2/partial", v2_body_partial(), false, 0),
            // #3432 amendment 2 — the round-trip arm. The migrated text is
            // valid TOML but does not deserialize into `AppConfig`, so
            // `migrate` refuses (exit 3) and reports serde's error, which
            // embeds the offending VALUE in the message BODY.
            (
                "legacy/wrong-typed-secret",
                legacy_body_wrong_typed_secret(),
                false,
                3,
            ),
        ];
        for (layout, body, dry_run, expected_code) in cases {
            let (code, stdout, stderr, on_disk) = run_migrate_capture(&body, dry_run);
            assert_eq!(
                code, expected_code,
                "{layout} dry_run={dry_run}: unexpected exit\nstderr: {stderr}"
            );
            for secret in secrets {
                if !body.contains(secret) {
                    continue;
                }
                assert!(
                    !stdout.contains(secret),
                    "{layout} dry_run={dry_run}: {secret} leaked on STDOUT:\n{stdout}"
                );
                assert!(
                    !stderr.contains(secret),
                    "{layout} dry_run={dry_run}: {secret} leaked on STDERR:\n{stderr}"
                );
            }
            // Data integrity: the redaction is DISPLAY-ONLY. Whatever ends
            // up on disk must still hold the real credentials — a masked
            // value written back would be silent credential destruction.
            if code == 0 {
                for secret in secrets {
                    if body.contains(secret) {
                        assert!(
                            on_disk.contains(secret),
                            "{layout}: migrate MASKED {secret} in the written file — \
                             redaction must never touch the durable artifact\n{on_disk}"
                        );
                    }
                }
            } else {
                assert_eq!(
                    on_disk, body,
                    "{layout} dry_run={dry_run}: a non-success run must leave the \
                     original config byte-identical"
                );
            }
        }
    }

    /// ALLOWED path: the dry-run is still worth running — the structure,
    /// the non-secret values, the secret field NAMES and the `_env`
    /// pointer all survive, with the mask standing in for the values.
    #[test]
    fn migrate_dry_run_stays_useful_after_redaction_3432() {
        let (code, _stdout, stderr, _on_disk) = run_migrate_capture(&v2_body_partial(), true);
        assert_eq!(code, 1);
        for expected in [
            "tier = \"smart\"",
            "[reranker]",
            "enabled = true",
            // The pointer an operator migrates TO must stay readable.
            "api_key_env = \"XAI_API_KEY\"",
            // The legacy flat field really did move into [storage].
            "default_namespace",
            // The masked fields are still named, so the mapping is visible.
            "api_key",
            "hmac_secret",
            crate::config_redact::CONFIG_REDACTION_MASK,
        ] {
            assert!(
                stderr.contains(expected),
                "dry-run lost {expected}; a redactor nobody can use gets bypassed:\n{stderr}"
            );
        }
    }

    /// DENIED path, parse arm: the `toml` Display renders the offending
    /// SOURCE LINE, so a malformed secret line must not be echoed back —
    /// the same guarantee `config check` (#3197) makes.
    #[test]
    fn migrate_parse_error_does_not_echo_the_offending_line_3432() {
        let body = format!("api_key = \"{S_LEGACY_TOP}\"unclosed\n");
        let (code, stdout, stderr, on_disk) = run_migrate_capture(&body, true);
        assert_eq!(code, 3, "stderr: {stderr}");
        assert!(!stdout.contains(S_LEGACY_TOP), "leaked on stdout: {stdout}");
        assert!(!stderr.contains(S_LEGACY_TOP), "leaked on stderr: {stderr}");
        assert!(stderr.contains("not valid TOML"), "{stderr}");
        assert_eq!(on_disk, body, "a parse failure must write nothing");
    }

    /// `config check`'s #3197 guarantee is preserved AND its diagnostics
    /// improved: the position survives, the value does not.
    #[test]
    fn check_reports_the_position_without_the_value_3432() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-3432.toml");
        std::fs::write(&path, format!("api_key = \"{S_LEGACY_TOP}\"unclosed\n")).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check {
                    file: Some(path.clone()),
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 3);
        let err = String::from_utf8(stderr).unwrap();
        assert!(!err.contains(S_LEGACY_TOP), "leaked: {err}");
        assert!(err.contains("not valid TOML"), "{err}");
        assert!(
            err.contains("line"),
            "the position must survive so the operator can fix it: {err}"
        );
        assert!(String::from_utf8(stdout).unwrap().is_empty());
    }

    #[test]
    fn run_migrate_missing_file_returns_two() {
        let (code, _stdout, stderr, _on_disk) = run_migrate_with_home(None, false, false);
        assert_eq!(code, 2);
        assert!(stderr.contains("no config file"), "got: {stderr}");
    }

    #[test]
    fn run_migrate_invalid_toml_returns_three() {
        let (code, _stdout, stderr, _on_disk) =
            run_migrate_with_home(Some("this is { not valid toml"), false, false);
        assert_eq!(code, 3);
        assert!(stderr.contains("not valid TOML"), "got: {stderr}");
    }

    #[test]
    fn run_migrate_already_v2_is_noop() {
        let body = "schema_version = 2\ntier = \"autonomous\"\n\n[llm]\nbackend = \"xai\"\n";
        let (code, _stdout, stderr, _on_disk) = run_migrate_with_home(Some(body), false, false);
        assert_eq!(code, 0);
        assert!(stderr.contains("no migration needed"), "got: {stderr}");
    }

    #[test]
    fn run_migrate_dry_run_returns_one() {
        let body = "llm_model = \"gemma\"\nollama_url = \"http://localhost:11434\"\n";
        let (code, _stdout, stderr, _on_disk) = run_migrate_with_home(Some(body), true, true);
        assert_eq!(code, 1);
        assert!(stderr.contains("DRY RUN"), "got: {stderr}");
        assert!(
            stderr.contains("also-clean-claude-json also skipped"),
            "got: {stderr}"
        );
    }

    #[test]
    fn run_migrate_apply_writes_backup_and_succeeds() {
        let body = "llm_model = \"gemma\"\nollama_url = \"http://localhost:11434\"\n";
        let (code, _stdout, stderr, _on_disk) = run_migrate_with_home(Some(body), false, false);
        assert_eq!(code, 0);
        assert!(stderr.contains("OK: migrated"), "got: {stderr}");
        assert!(stderr.contains("backup:"), "got: {stderr}");
        // The non-clean branch advises re-running with the clean flag.
        assert!(stderr.contains("--also-clean-claude-json"), "got: {stderr}");
    }

    #[test]
    fn run_migrate_apply_with_clean_no_claude_json() {
        let body = "embedding_model = \"nomic_embed_v15\"\n";
        let (code, _stdout, stderr, _on_disk) = run_migrate_with_home(Some(body), false, true);
        assert_eq!(code, 0);
        // No ~/.claude.json in the tempdir HOME → INFO no-change line.
        assert!(stderr.contains("no mcpServers env block"), "got: {stderr}");
    }

    /// #3001 — a malformed legacy value (here `cross_encoder` as a STRING,
    /// which the migrator folds into `[reranker].enabled` where a bool is
    /// expected) must NOT be laundered into a v2 file the daemon then fails
    /// to parse. The migrate command must FAIL LOUD (non-zero exit, no v2
    /// file written, no `.bak`), leaving the original config byte-identical.
    #[test]
    fn run_migrate_malformed_legacy_fails_closed_and_writes_nothing() {
        let _g = env_lock();
        let home = tempfile::tempdir().expect("tempdir");
        let dir = home.path().join(".config/ai-memory");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        // Valid TOML, but `cross_encoder` is a STRING (should be a bool);
        // `build_migrated_table` maps it into `[reranker].enabled`.
        let body = "tier = \"autonomous\"\ncross_encoder = \"ms-marco-MiniLM-L-6-v2\"\n";
        std::fs::write(&cfg_path, body).unwrap();

        let prev_home = std::env::var("HOME").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        // SAFETY: serialised via `env_lock()`; restored below.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("XDG_CONFIG_HOME", home.path().join(".config"));
        }
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Migrate {
                    dry_run: false,
                    also_clean_claude_json: false,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        unsafe {
            match prev_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }

        let stderr = String::from_utf8(stderr).unwrap();
        // FAIL LOUD: non-zero exit, never "OK: migrated".
        assert_ne!(
            code, 0,
            "expected non-zero refusal, got 0; stderr: {stderr}"
        );
        assert!(
            stderr.contains("does not parse") && stderr.contains("refusing to write"),
            "expected a loud parse-refusal, got: {stderr}"
        );
        assert!(
            !stderr.contains("OK: migrated"),
            "must NOT claim success, got: {stderr}"
        );
        // The original config is byte-identical (nothing was written).
        assert_eq!(
            std::fs::read_to_string(&cfg_path).unwrap(),
            body,
            "original config must be untouched"
        );
        // No `.bak` file was written alongside it.
        let bak_present = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".bak."));
        assert!(
            !bak_present,
            "no backup file must be written on a refused migrate"
        );
    }

    #[test]
    fn migrate_v1_legacy_fields_to_sections() {
        let toml_text = r#"
tier = "autonomous"
db = "/tmp/test.db"
llm_model = "gemma4:e4b"
ollama_url = "http://localhost:11434"
embed_url = "http://localhost:11434"
embedding_model = "nomic_embed_v15"
cross_encoder = true
default_namespace = "alphaone"
archive_on_gc = true
"#;
        let value: toml::Value = toml::from_str(toml_text).unwrap();
        let original = value.as_table().unwrap().clone();

        let migrated = build_migrated_table(&original);

        assert_eq!(
            migrated
                .get("schema_version")
                .and_then(toml::Value::as_integer),
            Some(2),
            "schema_version must land at 2"
        );

        // Legacy fields stripped from top-level.
        for k in LEGACY_FIELDS {
            assert!(
                !migrated.contains_key(*k),
                "legacy field {k} should have been removed"
            );
        }

        // [llm] section populated.
        let llm = migrated.get("llm").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            llm.get("backend").and_then(toml::Value::as_str),
            Some("ollama")
        );
        assert_eq!(
            llm.get("model").and_then(toml::Value::as_str),
            Some("gemma4:e4b")
        );
        assert_eq!(
            llm.get("base_url").and_then(toml::Value::as_str),
            Some("http://localhost:11434")
        );

        // [embeddings] section populated.
        let emb = migrated
            .get("embeddings")
            .and_then(toml::Value::as_table)
            .unwrap();
        assert_eq!(
            emb.get("model").and_then(toml::Value::as_str),
            Some("nomic_embed_v15")
        );

        // [reranker] section populated.
        let rerank = migrated
            .get("reranker")
            .and_then(toml::Value::as_table)
            .unwrap();
        assert_eq!(
            rerank.get("enabled").and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            rerank.get("model").and_then(toml::Value::as_str),
            Some("ms-marco-MiniLM-L-6-v2")
        );

        // [storage] section populated.
        let storage = migrated
            .get("storage")
            .and_then(toml::Value::as_table)
            .unwrap();
        assert_eq!(
            storage
                .get("default_namespace")
                .and_then(toml::Value::as_str),
            Some("alphaone")
        );
        assert_eq!(
            storage.get("archive_on_gc").and_then(toml::Value::as_bool),
            Some(true)
        );

        // Top-level non-legacy fields preserved.
        assert_eq!(
            migrated.get("tier").and_then(toml::Value::as_str),
            Some("autonomous")
        );
        assert_eq!(
            migrated.get("db").and_then(toml::Value::as_str),
            Some("/tmp/test.db")
        );
    }

    #[test]
    fn migrate_idempotent_on_already_v2() {
        let toml_text = r#"
schema_version = 2
tier = "autonomous"

[llm]
backend = "xai"
model = "grok-4.3"
api_key_env = "XAI_API_KEY"

[storage]
default_namespace = "alphaone"
"#;
        let value: toml::Value = toml::from_str(toml_text).unwrap();
        let original = value.as_table().unwrap().clone();

        let migrated = build_migrated_table(&original);

        // schema_version stays 2.
        assert_eq!(
            migrated
                .get("schema_version")
                .and_then(toml::Value::as_integer),
            Some(2)
        );

        // Existing [llm] preserved verbatim.
        let llm = migrated.get("llm").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            llm.get("backend").and_then(toml::Value::as_str),
            Some("xai")
        );
        assert_eq!(
            llm.get("model").and_then(toml::Value::as_str),
            Some("grok-4.3")
        );
    }

    #[test]
    fn migrate_does_not_overwrite_existing_sections() {
        // Pathological: operator left both legacy AND v2 fields. The
        // migrator should preserve the existing [llm] section and drop
        // the legacy field rather than clobbering.
        let toml_text = r#"
llm_model = "legacy-model"
ollama_url = "http://stale:9999"

[llm]
backend = "xai"
model = "grok-4.3"
"#;
        let value: toml::Value = toml::from_str(toml_text).unwrap();
        let original = value.as_table().unwrap().clone();

        let migrated = build_migrated_table(&original);

        // Legacy fields stripped.
        assert!(!migrated.contains_key("llm_model"));
        assert!(!migrated.contains_key("ollama_url"));

        // [llm] section preserved verbatim.
        let llm = migrated.get("llm").and_then(toml::Value::as_table).unwrap();
        assert_eq!(
            llm.get("backend").and_then(toml::Value::as_str),
            Some("xai")
        );
        assert_eq!(
            llm.get("model").and_then(toml::Value::as_str),
            Some("grok-4.3")
        );
    }

    #[test]
    fn check_valid_toml_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.toml");
        std::fs::write(&path, "tier = \"keyword\"\n").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check { file: Some(path) },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 0);
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("valid TOML"), "got: {err}");
    }

    #[test]
    fn check_invalid_toml_returns_three_without_echoing_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "api_key = \"sekrit-must-not-leak\"unclosed\n").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check { file: Some(path) },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 3);
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("not valid TOML"), "got: {err}");
        assert!(
            !err.contains("sekrit-must-not-leak"),
            "toml error Display must not leak the secret, got: {err}"
        );
    }

    #[test]
    fn check_missing_file_returns_two() {
        let path = std::path::PathBuf::from("/no/such/config-3197.toml");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check { file: Some(path) },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 2);
    }

    /// #3715 — `config check` is the DETECTOR: valid TOML carrying keys the
    /// daemon would refuse to boot on exits 5, names every key with its
    /// nearest sibling and the repair command, and never refuses (it is a
    /// report). Secrets on the same file are not echoed.
    #[test]
    fn check_reports_unknown_keys_with_exit_five_and_no_secret_echo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        std::fs::write(
            &path,
            "api_key = \"sekrit-must-not-leak\"\n\n[memory]\ntier = \"x\"\n\n[storage]\ndb_mmap_size_byte = 1\n",
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check {
                    file: Some(path.clone()),
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 5);
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("WOULD REFUSE"), "got: {err}");
        assert!(err.contains("`memory`"), "got: {err}");
        assert!(err.contains("`storage.db_mmap_size_byte`"), "got: {err}");
        assert!(err.contains("db_mmap_size_bytes"), "nearest sibling: {err}");
        assert!(err.contains("config check --file"), "repair hint: {err}");
        assert!(
            !err.contains("sekrit-must-not-leak"),
            "secret echoed: {err}"
        );
        // The file is untouched — a detector never repairs.
        assert!(std::fs::read_to_string(&path).unwrap().contains("[memory]"));
    }

    /// #3715 — a clean file still exits 0 and says so.
    #[test]
    fn check_clean_file_reports_no_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        std::fs::write(
            &path,
            "schema_version = 2\n[deployment]\nshape = \"team\"\n",
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Check { file: Some(path) },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("no unknown keys")
        );
    }

    /// #3714 — `config show` renders the shape's derivation table with a
    /// FLOOR / default marker on every row; a missing file renders
    /// `singleton`; an unknown key ELSEWHERE in the file does not stop the
    /// render (it parses through `toml::Value`).
    #[test]
    fn show_renders_the_shape_table_with_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        std::fs::write(
            &path,
            "[deployment]\nshape = \"production\"\n\n[memory]\ntier = \"x\"\n",
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Show {
                    file: Some(path),
                    effective: false,
                    provenance: false,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).unwrap();
        assert!(
            text.contains("[deployment] shape = \"production\""),
            "{text}"
        );
        assert!(
            text.contains("security_posture") && text.contains("asi-hard"),
            "{text}"
        );
        assert!(text.contains("FLOOR"), "{text}");
        assert!(
            text.contains("at_rest") && text.contains("pending recovery escrow"),
            "{text}"
        );

        let missing = dir.path().join("absent.toml");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Show {
                    file: Some(missing),
                    effective: false,
                    provenance: false,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).unwrap();
        assert!(
            text.contains("[deployment] shape = \"singleton\""),
            "{text}"
        );
        assert!(text.contains("standard"), "{text}");
    }

    /// #3714 — a typo in the primary input fails loud, never `singleton`.
    #[test]
    fn show_refuses_an_unrecognised_shape_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        std::fs::write(&path, "[deployment]\nshape = \"prod\"\n").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Show {
                    file: Some(path),
                    effective: false,
                    provenance: false,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        assert_eq!(code, 3);
        assert!(String::from_utf8(stderr).unwrap().contains("production"));
    }

    fn run_show_effective(path: &std::path::Path, provenance: bool) -> (i32, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            let args = ConfigCliArgs {
                action: ConfigAction::Show {
                    file: Some(path.to_path_buf()),
                    effective: true,
                    provenance,
                },
            };
            run(std::path::Path::new("unused.db"), args, &mut out).expect("run ok")
        };
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    /// #3715 item 4 — `--effective --provenance`: a value the file sets is
    /// printed and attributed to the file (presence); a leaf the file does
    /// not set is listed as unset / compiled-default (absence on the same
    /// manifest); a secret-bearing value is masked while its key stays
    /// (presence of the key, absence of the credential); the printed
    /// document re-loads through the boot loader to the same configuration
    /// and carries no key the schema does not know.
    #[test]
    fn issue_3715_show_effective_attributes_each_leaf_and_masks_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        // The #3432 funnel's value-shape backstop is what this cell holds
        // load-bearing: NO accepted, serialised AppConfig field carries a
        // secret-suffixed NAME (`api_key` / `hmac_secret` are skip-serialised;
        // `[llm].api_key` is refused at load), so the funnel's key heuristic
        // has nothing to mask here — but a credential parked in an INNOCENT
        // field (an AWS access-key id as `[llm].model`) is exactly what the
        // backstop exists for, and bypassing `render_redacted_toml` prints it.
        crate::secret_screen::set_screen_mode(crate::secret_screen::SecretScreenMode::Redact);
        std::fs::write(
            &path,
            "schema_version = 2\napi_key = \"sk-PLAINTEXT-CREDENTIAL-3715\"\n\
             [llm]\nmodel = \"AKIAEXAMPLE3715AAAAB\"\n\
             [storage]\ndefault_namespace = \"team-x\"\n",
        )
        .unwrap();
        let (code, text, err) = run_show_effective(&path, true);
        assert_eq!(code, 0, "{err}");
        let file_origin = format!("# file {}", path.display());
        assert!(
            !text.contains("AKIAEXAMPLE3715AAAAB"),
            "the funnel masks a credential-shaped value: {text}"
        );
        assert!(
            text.contains(&format!(
                "model = {:?}",
                crate::secret_screen::REDACTION_PLACEHOLDER
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "llm.model = {:?}  {file_origin}",
                crate::secret_screen::REDACTION_PLACEHOLDER
            )),
            "the manifest carries the masked value too: {text}"
        );
        assert!(
            text.contains("# effective configuration: loaded from"),
            "{text}"
        );
        // Presence: the file value, in the document and in the manifest.
        assert!(text.contains("default_namespace = \"team-x\""), "{text}");
        assert!(
            text.contains(&format!(
                "storage.default_namespace = \"team-x\"  {file_origin}"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("schema_version = 2  {file_origin}")),
            "{text}"
        );
        // Absence on the same manifest: an unset leaf is not attributed to
        // the file and is not given a value this verb did not resolve.
        assert!(
            text.contains(
                "storage.archive_on_gc = (unset: the compiled default applies at use)  \
                 # compiled-default"
            ),
            "{text}"
        );
        // The credential: key present, bytes absent.
        assert!(!text.contains("sk-PLAINTEXT-CREDENTIAL-3715"), "{text}");
        assert!(
            text.contains(&format!(
                "api_key = {:?}  {file_origin}",
                crate::config_redact::CONFIG_REDACTION_MASK
            )),
            "{text}"
        );
        // The environment section names variables, never values.
        assert!(text.contains("# environment: "), "{text}");
        assert!(text.contains("names only"), "{text}");
        // Round trip: the printed document (above the manifest) is a config
        // the boot loader accepts with no unknown key, and it resolves to
        // the same storage section.
        let document: String = text
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("# provenance"))
            .collect::<Vec<_>>()
            .join("\n");
        let again = dir.path().join("again.toml");
        std::fs::write(&again, &document).unwrap();
        let reloaded = crate::config::AppConfig::try_load_from_optional(&again)
            .expect("the effective document re-loads through the boot loader");
        assert_eq!(
            reloaded
                .storage
                .as_ref()
                .and_then(|s| s.default_namespace.clone())
                .as_deref(),
            Some("team-x")
        );
        assert_eq!(reloaded.schema_version, Some(2));
        let value: toml::Value = toml::from_str(&document).unwrap();
        assert!(
            crate::config::unknown_keys::find_unknown_keys(&value).is_empty(),
            "the effective document must carry no key the schema does not know"
        );
    }

    /// #3715 item 3 through item 4: a deprecated key is shown with its
    /// replacement on the manifest and its value still applies (control);
    /// the boot loader's refusals reach this verb unchanged — an unknown
    /// key exits EX_CONFIG with the unknown-key text, and the document is
    /// not printed.
    #[test]
    fn issue_3715_show_effective_names_deprecations_and_refuses_like_boot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.toml");
        std::fs::write(&path, "llm_model = \"legacy-m\"\n").unwrap();
        let (code, text, err) = run_show_effective(&path, true);
        assert_eq!(code, 0, "{err}");
        assert!(
            text.contains("llm_model = \"legacy-m\""),
            "the value still applies: {text}"
        );
        assert!(
            text.contains("# DEPRECATED since 0.7.0 — use [llm].model; removal not scheduled"),
            "{text}"
        );
        // A replacement key carries no deprecation note (absence, same manifest).
        assert!(!text.contains("llm.model = (unset: the compiled default applies at use)  # compiled-default  # DEPRECATED"), "{text}");

        let bad = dir.path().join("typo.toml");
        std::fs::write(&bad, "[storage]\ndefault_namespac = \"x\"\n").unwrap();
        let (code, text, err) = run_show_effective(&bad, false);
        assert_eq!(code, crate::config::EX_CONFIG, "{err}");
        assert!(err.contains("unknown key"), "{err}");
        assert!(err.contains("default_namespac"), "{err}");
        assert!(
            !text.contains("default_namespac"),
            "nothing printed on refusal: {text}"
        );
    }
}
