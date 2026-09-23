// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3715 item 3 — the configuration-key DEPRECATION LIFECYCLE, as
//! data.
//!
//! Before this module the lifecycle lived in prose: a `Once`-gated WARN said
//! the legacy flat keys "will be removed in v0.8.0" (they were not: v1.0.0
//! still accepts every one of them), and a key that HAD been removed was
//! indistinguishable from a typo — both fell to the #3715 unknown-key
//! refusal, which cannot name a replacement it does not know.
//!
//! [`DEPRECATED_KEYS`] is the one table: for every deprecated key the
//! replacement, the release that deprecated it, and the release that removes
//! it (or `None` while removal is unscheduled). The loader consults the table
//! in its ONE funnel ([`crate::config::AppConfig::from_toml_contents`]) before
//! the unknown-key check:
//!
//! - a key that is deprecated but still accepted produces one WARN naming the
//!   replacement and the removal release, and its value still applies (it is
//!   not inert — #3385);
//! - a key whose removal release is at or below the running version REFUSES
//!   the load with `EX_CONFIG`, naming the replacement — never the generic
//!   unknown-key text.
//!
//! The classification is a pure function of the document and a table, so the
//! removal arm is pinned with a table that carries a removed key rather than
//! with a test-only code path.

use std::fmt::Write as _;

/// One row of the lifecycle table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeprecatedKey {
    /// The dotted key path as written in `config.toml` (`llm_model`,
    /// `storage.archive_on_gc`).
    pub key: &'static str,
    /// Where the setting lives now, in operator terms (`[llm].model`).
    pub replacement: &'static str,
    /// The release that deprecated the key.
    pub deprecated_in: &'static str,
    /// The release that removes it; `None` while removal is unscheduled.
    pub removed_in: Option<&'static str>,
}

/// The release the v1 flat fields were deprecated in (#1146).
const V1_FLAT_DEPRECATED_IN: &str = "0.7.0";

/// The lifecycle table. Removal of the v1 flat fields is UNSCHEDULED: the
/// pre-#3715 WARN promised v0.8.0 and v1.0.0 still accepts them; the table
/// says what is true. Schedule a removal by filling `removed_in`; the loader
/// refuses the key from that release on, naming the replacement.
pub const DEPRECATED_KEYS: &[DeprecatedKey] = &[
    DeprecatedKey {
        key: "llm_model",
        replacement: "[llm].model",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "ollama_url",
        replacement: "[llm].base_url (and [embeddings].url)",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "embed_url",
        replacement: crate::config::config_keys::EMBEDDINGS_URL,
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "embedding_model",
        replacement: "[embeddings].model",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "cross_encoder",
        replacement: "[reranker].enabled",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "default_namespace",
        replacement: "[storage].default_namespace",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "archive_on_gc",
        replacement: "[storage].archive_on_gc",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "archive_max_days",
        replacement: "[storage].archive_max_days",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "max_memory_mb",
        replacement: "[limits].max_storage_bytes (max_memory_mb is parsed but never enforced)",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
    DeprecatedKey {
        key: "auto_tag_model",
        replacement: "[llm.auto_tag].model",
        deprecated_in: V1_FLAT_DEPRECATED_IN,
        removed_in: None,
    },
];

/// A deprecated key found in a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub row: DeprecatedKey,
}

/// What the table says about one document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Classification {
    /// Deprecated keys that still apply (WARN).
    pub deprecated: Vec<Finding>,
    /// Keys whose removal release is at or below `running` (REFUSE).
    pub removed: Vec<Finding>,
}

/// `major.minor.patch` of a release string; anything unparseable is
/// `None` and never triggers a removal (fail towards the WARN, never a
/// silent refusal from a typo in the table — the table test pins the
/// shape of every row).
fn version_triple(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next()??;
    Some((major, minor, patch))
}

/// `true` when `removed_in` is a release the `running` version has reached.
fn is_removed(removed_in: Option<&str>, running: &str) -> bool {
    match (removed_in.and_then(version_triple), version_triple(running)) {
        (Some(r), Some(now)) => now >= r,
        _ => false,
    }
}

fn collect_leaf_paths(value: &toml::Value, prefix: &mut Vec<String>, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                prefix.push(k.clone());
                collect_leaf_paths(v, prefix, out);
                prefix.pop();
            }
        }
        _ => out.push(prefix.join(".")),
    }
}

/// Classify every key of `document` against `table` for the `running`
/// release. Pure; the loader calls it with [`DEPRECATED_KEYS`] and
/// [`crate::PKG_VERSION`].
#[must_use]
pub fn classify(document: &toml::Value, table: &[DeprecatedKey], running: &str) -> Classification {
    let mut present = Vec::new();
    collect_leaf_paths(document, &mut Vec::new(), &mut present);
    let mut out = Classification::default();
    for row in table {
        if !present.iter().any(|p| p == row.key) {
            continue;
        }
        let finding = Finding { row: *row };
        if is_removed(row.removed_in, running) {
            out.removed.push(finding);
        } else {
            out.deprecated.push(finding);
        }
    }
    out
}

/// The WARN line for one deprecated-but-accepted key.
#[must_use]
pub fn warn_line(path: &std::path::Path, f: &Finding) -> String {
    format!(
        "ai-memory: WARN — config key `{}` in {} is deprecated since {} (replacement: {}; \
         removal: {}); the value still applies. Run `ai-memory config migrate`.",
        f.row.key,
        path.display(),
        f.row.deprecated_in,
        f.row.replacement,
        f.row.removed_in.map_or_else(
            || "not scheduled".to_string(),
            |r| format!("scheduled for {r}")
        ),
    )
}

/// The refusal for a document carrying removed keys. Same `config rejected`
/// shape as every other `EX_CONFIG` refusal; names each replacement.
#[must_use]
pub fn refusal_message(path: &std::path::Path, removed: &[Finding], running: &str) -> String {
    let mut msg = format!(
        "config rejected ({}): {} key{} removed in this release ({running}):",
        path.display(),
        removed.len(),
        if removed.len() == 1 { "" } else { "s" }
    );
    for f in removed {
        let _ = write!(
            msg,
            "\n  - `{}` was deprecated in {} and REMOVED in {}; use {}",
            f.row.key,
            f.row.deprecated_in,
            f.row.removed_in.unwrap_or("?"),
            f.row.replacement
        );
    }
    msg.push_str("\n  Run `ai-memory config migrate`, or edit the file; nothing was started.");
    msg
}

/// The table row for `key`, when it is deprecated.
#[must_use]
pub fn lookup(key: &str) -> Option<&'static DeprecatedKey> {
    DEPRECATED_KEYS.iter().find(|r| r.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = "1.0.0";

    fn doc(s: &str) -> toml::Value {
        toml::from_str(s).expect("fixture parses")
    }

    /// Every row of the shipped table names a schema-known key, a
    /// replacement, a parseable deprecation release, and a parseable
    /// removal release when one is scheduled.
    #[test]
    fn issue_3715_table_rows_are_well_formed_and_schema_known() {
        let accepted = crate::config::unknown_keys::accepted_leaf_keys();
        for row in DEPRECATED_KEYS {
            assert!(
                accepted.iter().any(|k| k == row.key),
                "{}: a deprecated key must still be in the accepted schema until it is \
                 removed (a removed key is refused by name, never parsed)",
                row.key
            );
            assert!(!row.replacement.is_empty(), "{}", row.key);
            assert!(version_triple(row.deprecated_in).is_some(), "{}", row.key);
            if let Some(r) = row.removed_in {
                assert!(version_triple(r).is_some(), "{}", row.key);
            }
        }
    }

    /// Deprecated-but-accepted: WARN naming replacement and removal state;
    /// the classification never refuses (control on the shipped table).
    #[test]
    fn issue_3715_shipped_table_warns_and_never_refuses_a_v1_flat_key() {
        let c = classify(
            &doc("llm_model = \"gemma3\"\n[storage]\ndefault_namespace = \"x\"\n"),
            DEPRECATED_KEYS,
            RUNNING,
        );
        assert!(c.removed.is_empty(), "{c:?}");
        assert_eq!(c.deprecated.len(), 1, "{c:?}");
        assert_eq!(c.deprecated[0].row.key, "llm_model");
        let line = warn_line(
            std::path::Path::new("/etc/ai-memory/config.toml"),
            &c.deprecated[0],
        );
        assert!(line.contains("`llm_model`"), "{line}");
        assert!(line.contains("replacement: [llm].model"), "{line}");
        assert!(line.contains("removal: not scheduled"), "{line}");
        assert!(line.contains("the value still applies"), "{line}");
        // The sectioned replacement is not deprecated (absence on the same table).
        let c = classify(
            &doc("[llm]\nmodel = \"gemma3\"\n"),
            DEPRECATED_KEYS,
            RUNNING,
        );
        assert_eq!(c, Classification::default());
    }

    /// Removed: a table whose row schedules removal at or below the running
    /// release REFUSES naming the replacement; the same row one release
    /// ahead only WARNs (the lifecycle boundary is the version compare).
    #[test]
    fn issue_3715_removed_key_refuses_naming_the_replacement_and_future_removal_warns() {
        const TABLE: &[DeprecatedKey] = &[DeprecatedKey {
            key: "governance.legacy_switch",
            replacement: "[permissions].mode",
            deprecated_in: "0.9.0",
            removed_in: Some("1.0.0"),
        }];
        let d = doc("[governance]\nlegacy_switch = true\n");
        let c = classify(&d, TABLE, "1.0.0");
        assert_eq!(c.removed.len(), 1, "{c:?}");
        assert!(c.deprecated.is_empty());
        let msg = refusal_message(std::path::Path::new("/x/config.toml"), &c.removed, "1.0.0");
        assert!(msg.starts_with("config rejected (/x/config.toml)"), "{msg}");
        assert!(msg.contains("`governance.legacy_switch`"), "{msg}");
        assert!(msg.contains("REMOVED in 1.0.0"), "{msg}");
        assert!(msg.contains("use [permissions].mode"), "{msg}");
        assert!(!msg.contains("unknown key"), "{msg}");
        // One release earlier than the scheduled removal: still accepted, WARN.
        let c = classify(&d, TABLE, "0.9.5");
        assert!(c.removed.is_empty(), "{c:?}");
        assert_eq!(c.deprecated.len(), 1);
        assert!(
            warn_line(std::path::Path::new("/x/config.toml"), &c.deprecated[0])
                .contains("removal: scheduled for 1.0.0")
        );
        // A pre-release running version compares on its core.
        assert!(is_removed(Some("1.0.0"), "1.0.0-rc.1"));
        assert!(!is_removed(Some("1.0.1"), "1.0.0"));
        assert!(!is_removed(Some("not-a-version"), "1.0.0"));
    }
}
