// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x (#1146) — `ai-memory config <subcommand>` CLI surface.
//!
//! Today exposes a single action: `migrate`. Rewrites a legacy v1
//! (flat-field) `config.toml` to the canonical v2 sectioned shape
//! (`[llm]`, `[embeddings]`, `[reranker]`, `[storage]`) defined in
//! issue #1146.
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
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning                                                  |
//! |-----:|----------------------------------------------------------|
//! |   0  | success — file migrated or already v2 (no-op INFO)       |
//! |   1  | informational — dry-run mode, no writes performed        |
//! |   2  | file not found (no `~/.config/ai-memory/config.toml`)    |
//! |   3  | parse error — file is not valid TOML                     |
//! |   4  | write error — could not write `.bak` or new file         |

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::CliOutput;

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
            let _ = writeln!(
                out.stderr,
                "ERROR: {} is not valid TOML: {}",
                path.display(),
                e
            );
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
        .get("schema_version")
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
    let migrated_value = toml::Value::Table(migrated_table);
    let migrated_text = toml::to_string_pretty(&migrated_value).unwrap_or_else(|_| String::new());

    if dry_run {
        let _ = writeln!(
            out.stderr,
            "--- DRY RUN — {} would be rewritten as: ---",
            path.display()
        );
        let _ = writeln!(out.stderr, "{migrated_text}");
        let _ = writeln!(out.stderr, "--- end dry run ---");
        if also_clean_claude_json {
            let _ = writeln!(
                out.stderr,
                "(--also-clean-claude-json also skipped in dry-run.)"
            );
        }
        return Ok(1);
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
    "ollama_url",
    "embed_url",
    "embedding_model",
    "cross_encoder",
    "default_namespace",
    "archive_on_gc",
    "archive_max_days",
    "max_memory_mb",
    "auto_tag_model",
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
        ($name:literal, $target:ident) => {
            if let Some(v) = migrated.remove($name) {
                $target = Some(v);
            }
        };
    }

    take!("llm_model", llm_model);
    take!("ollama_url", ollama_url);
    take!("embed_url", embed_url);
    take!("embedding_model", embedding_model);
    take!("cross_encoder", cross_encoder);
    take!("default_namespace", default_namespace);
    take!("archive_on_gc", archive_on_gc);
    take!("archive_max_days", archive_max_days);
    take!("max_memory_mb", max_memory_mb);
    take!("auto_tag_model", auto_tag_model);

    // schema_version = 2 (highest priority on insert).
    migrated.insert("schema_version".to_string(), toml::Value::Integer(2));

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
    if !migrated.contains_key("embeddings") && (embed_url.is_some() || embedding_model.is_some()) {
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
        migrated.insert("embeddings".to_string(), toml::Value::Table(emb));
    }

    // [reranker] section.
    if !migrated.contains_key("reranker") && cross_encoder.is_some() {
        let mut rerank = toml::map::Map::new();
        if let Some(v) = cross_encoder.clone() {
            rerank.insert("enabled".to_string(), v);
        }
        rerank.insert(
            "model".to_string(),
            toml::Value::String("ms-marco-MiniLM-L-6-v2".to_string()),
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
            storage.insert("default_namespace".to_string(), v);
        }
        if let Some(v) = archive_on_gc {
            storage.insert("archive_on_gc".to_string(), v);
        }
        if let Some(v) = archive_max_days {
            storage.insert("archive_max_days".to_string(), v);
        }
        if let Some(v) = max_memory_mb {
            storage.insert("max_memory_mb".to_string(), v);
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
        .get_mut("mcpServers")
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
}
