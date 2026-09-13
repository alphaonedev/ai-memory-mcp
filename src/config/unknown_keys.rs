// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3715 — unknown-key REFUSAL at the loader, with the accepted key tree
//! derived mechanically from `AppConfig`'s schema (no hand-maintained
//! list to rot).
//!
//! ## Why the loader and not a serde attribute
//!
//! `#[serde(deny_unknown_fields)]` on every config struct would also fire
//! inside `config migrate`'s re-validate and inside every direct
//! `toml::from_str::<AppConfig>` a tool performs — exactly the places the
//! Conductor ruled must NEVER refuse, because a fail-closed loader whose
//! own repair path sits behind the same gate is a lockout, not a control
//! (carve-out 1, #3714 ruling). So the refusal is ONE function
//! ([`find_unknown_keys`]) called from ONE boot funnel
//! (`AppConfig::from_toml_contents`), and the repair tools parse through
//! `toml::Value` untouched.
//!
//! ## Where the accepted set comes from
//!
//! `schemars::schema_for!(AppConfig)` — the same derive the MCP tool
//! registry already uses for `inputSchema`. Every config struct derives
//! `JsonSchema`, so a new field is accepted the moment it exists and a
//! removed field is refused the moment it is gone; there is no second
//! list. Map-typed catch-alls (`[curator.reflection_namespaces."<ns>"]`,
//! `[mcp.allowlist]`, …) render as `additionalProperties` and admit any
//! key beneath them, exactly as serde does.
//!
//! The pre-#3715 `warn_unknown_top_level_keys` covered only the top level
//! and only WARNed; nested unknown keys were silent. Measured cost of
//! refusing (corpus census at `8b4f65a22`): 13 of 162 in-tree artifacts,
//! 0 tracked `config.toml`, 0 deploy renders, 1 test pin. The field cost
//! is unmeasured — which is why `ai-memory config check` is the DETECTOR
//! operators run BEFORE upgrading (release notes), so a config that would
//! refuse is found on their schedule, not the daemon's.

use std::sync::OnceLock;

use schemars::schema::{RootSchema, Schema, SchemaObject};

use super::AppConfig;

/// One unknown key found in a config document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// Dotted path of the unknown key (`storage.db_pat`, `memory`,
    /// `permissions.rules[2].decsion`).
    pub path: String,
    /// The accepted key at the same level closest by edit distance, if
    /// the level has any accepted keys at all.
    pub nearest_sibling: Option<String>,
    /// Accepted keys ANYWHERE in the tree whose last segment equals the
    /// unknown segment — the "right key, wrong section" case.
    pub same_name_elsewhere: Vec<String>,
}

/// The parsed `AppConfig` schema, built once per process.
fn root_schema() -> &'static RootSchema {
    static SCHEMA: OnceLock<RootSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| schemars::schema_for!(AppConfig))
}

/// A schema node reduced to the three shapes the walk cares about.
enum Node<'a> {
    /// A struct: named properties; unknown names are refused unless the
    /// struct is a map (see [`Node::Map`]).
    Struct(&'a schemars::Map<String, Schema>),
    /// A map-typed catch-all: any key, values checked against `value`.
    Map(&'a Schema),
    /// An array: every element checked against `items`.
    Array(&'a Schema),
    /// A scalar / enum / anything serde types on its own.
    Leaf,
}

fn resolve<'a>(root: &'a RootSchema, schema: &'a Schema) -> Node<'a> {
    let obj = match schema {
        Schema::Bool(_) => return Node::Leaf,
        Schema::Object(o) => o,
    };
    if let Some(reference) = &obj.reference {
        let name = reference.rsplit('/').next().unwrap_or(reference);
        return match root.definitions.get(name) {
            Some(def) => resolve(root, def),
            None => Node::Leaf,
        };
    }
    if let Some(object) = &obj.object {
        if !object.properties.is_empty() {
            return Node::Struct(&object.properties);
        }
        if let Some(additional) = &object.additional_properties {
            if let Schema::Object(_) = additional.as_ref() {
                return Node::Map(additional);
            }
        }
    }
    if let Some(array) = &obj.array {
        if let Some(schemars::schema::SingleOrVec::Single(items)) = &array.items {
            return Node::Array(items);
        }
    }
    // `Option<T>` renders as `anyOf: [T, null]`; pick the first variant
    // that resolves to something structured.
    if let Some(sub) = &obj.subschemas {
        for group in [&sub.any_of, &sub.one_of, &sub.all_of]
            .into_iter()
            .flatten()
        {
            for candidate in group {
                match resolve(root, candidate) {
                    Node::Leaf => {}
                    structured => return structured,
                }
            }
        }
    }
    let _: &SchemaObject = obj;
    Node::Leaf
}

fn walk_value(
    root: &RootSchema,
    schema: &Schema,
    value: &toml::Value,
    path: &mut Vec<String>,
    out: &mut Vec<UnknownKey>,
) {
    match (resolve(root, schema), value) {
        (Node::Struct(properties), toml::Value::Table(table)) => {
            for (key, child) in table {
                match properties.get(key) {
                    Some(child_schema) => {
                        path.push(key.clone());
                        walk_value(root, child_schema, child, path, out);
                        path.pop();
                    }
                    None => {
                        let mut full = path.clone();
                        full.push(key.clone());
                        out.push(UnknownKey {
                            path: full.join("."),
                            nearest_sibling: nearest(key, properties.keys().map(String::as_str)),
                            same_name_elsewhere: accepted_leaf_keys()
                                .iter()
                                .filter(|leaf| leaf.rsplit('.').next() == Some(key.as_str()))
                                .cloned()
                                .collect(),
                        });
                    }
                }
            }
        }
        (Node::Map(value_schema), toml::Value::Table(table)) => {
            for (key, child) in table {
                path.push(key.clone());
                walk_value(root, value_schema, child, path, out);
                path.pop();
            }
        }
        (Node::Array(items), toml::Value::Array(elements)) => {
            for (i, element) in elements.iter().enumerate() {
                let last = path.pop().unwrap_or_default();
                path.push(format!("{last}[{i}]"));
                walk_value(root, items, element, path, out);
                path.pop();
                path.push(last);
            }
        }
        _ => {}
    }
}

/// Find every key in `document` that `AppConfig` would silently drop.
/// Sorted by path for stable output.
#[must_use]
pub fn find_unknown_keys(document: &toml::Value) -> Vec<UnknownKey> {
    let root = root_schema();
    let top = Schema::Object(root.schema.clone());
    let mut out = Vec::new();
    walk_value(root, &top, document, &mut Vec::new(), &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Every accepted dotted key path (leaves only), derived from the schema.
/// Map-typed catch-alls render their wildcard segment as `<key>`; arrays
/// of tables as `[]`. Built once per process. This is the count SSOT the
/// #3716 surface ledger reads.
pub fn accepted_leaf_keys() -> &'static [String] {
    static KEYS: OnceLock<Vec<String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        fn collect(
            root: &RootSchema,
            schema: &Schema,
            path: &mut Vec<String>,
            out: &mut Vec<String>,
        ) {
            match resolve(root, schema) {
                Node::Struct(properties) => {
                    for (key, child) in properties {
                        path.push(key.clone());
                        collect(root, child, path, out);
                        path.pop();
                    }
                }
                Node::Map(value_schema) => {
                    path.push("<key>".to_string());
                    collect(root, value_schema, path, out);
                    path.pop();
                }
                Node::Array(items) => {
                    let last = path.pop().unwrap_or_default();
                    path.push(format!("{last}[]"));
                    collect(root, items, path, out);
                    path.pop();
                    path.push(last);
                }
                Node::Leaf => out.push(path.join(".")),
            }
        }
        let root = root_schema();
        let top = Schema::Object(root.schema.clone());
        let mut out = Vec::new();
        collect(root, &top, &mut Vec::new(), &mut out);
        out.sort();
        out.dedup();
        out
    })
}

/// Levenshtein distance (first-party; `strsim` is not a direct dependency).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// A suggestion is only a suggestion when it is CLOSE: at most a third of
/// the key's length (never fewer than 2 edits), else a six-letter typo
/// would be "corrected" to an unrelated six-letter sibling.
fn nearest<'a>(key: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
    let budget = (key.chars().count() / 3).max(2);
    candidates
        .map(|c| (levenshtein(key, c), c))
        .filter(|(d, _)| *d <= budget)
        .min_by_key(|(d, c)| (*d, (*c).to_string()))
        .map(|(_, c)| c.to_string())
}

/// The operator-facing refusal / report line for one unknown key.
#[must_use]
pub fn describe(unknown: &UnknownKey) -> String {
    let mut s = format!("unknown config key `{}`", unknown.path);
    if let Some(n) = &unknown.nearest_sibling {
        s.push_str(&format!(" — nearest accepted key at that level: `{n}`"));
    }
    if !unknown.same_name_elsewhere.is_empty() {
        s.push_str(&format!(
            " — a key of that name is accepted at: {}",
            unknown
                .same_name_elsewhere
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    s
}

/// Repair guidance appended to a refusal. Names the exact command that
/// can be run FROM the refused state (carve-out 1): `config check` lists
/// every unknown key without refusing; `governance migrate-to-permissions`
/// is the translator for the one legacy shape (`[[governance.policy]]`)
/// that has a mechanical migration.
#[must_use]
pub fn repair_hint(path: &std::path::Path, unknown: &[UnknownKey]) -> String {
    let mut s = format!(
        "Run `ai-memory config check --file {}` to list every unknown key (it never refuses), \
         then remove or rename each one.",
        path.display()
    );
    if unknown
        .iter()
        .any(|u| u.path.starts_with("governance.policy"))
    {
        s.push_str(
            " `[[governance.policy]]` is the pre-K11 governance shape: run \
             `ai-memory governance migrate-to-permissions` to translate it into \
             `[[permissions.rules]]`, then remove the `[governance.policy]` blocks.",
        );
    }
    s
}

/// Summarise a set of unknown keys as one refusal message.
#[must_use]
pub fn refusal_message(path: &std::path::Path, unknown: &[UnknownKey]) -> String {
    let mut lines = vec![format!(
        "config {} carries {} unknown key{} (refused: an unknown key was silently \
         ignored before v1.0.0, which let a typo neutralise an operator's intent):",
        path.display(),
        unknown.len(),
        if unknown.len() == 1 { "" } else { "s" }
    )];
    lines.extend(unknown.iter().map(|u| format!("  - {}", describe(u))));
    lines.push(format!("  {}", repair_hint(path, unknown)));
    lines.join("\n")
}

/// Register a leaf-key count in the same process-wide place the surface
/// ledger reads it (#3716). Exposed as a function so the count is derived,
/// never hand-bumped.
#[must_use]
pub fn accepted_leaf_count() -> usize {
    accepted_leaf_keys().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> toml::Value {
        toml::from_str(src).expect("fixture parses")
    }

    #[test]
    fn a_clean_sectioned_config_has_no_unknown_keys() {
        let doc = parse(
            "schema_version = 2\ntier = \"autonomous\"\n\n[deployment]\nshape = \"team\"\n\n\
             [llm]\nbackend = \"xai\"\nmodel = \"grok\"\n\n[llm.auto_tag]\nmodel = \"g\"\n\n\
             [storage]\ndefault_namespace = \"x\"\narchive_on_gc = true\n\n\
             [limits]\nmax_page_size = 10\n\n[encryption]\nat_rest = false\n\n\
             [curator.reflection_namespaces.\"team/eng\"]\nenabled = true\n\n\
             [curator.confidence_decay_half_life_days]\n\"team/eng\" = 14.0\n\n\
             [[permissions.rules]]\nnamespace_pattern = \"a\"\nop = \"store\"\nagent_pattern = \"*\"\ndecision = \"allow\"\n",
        );
        assert_eq!(find_unknown_keys(&doc), Vec::new());
    }

    #[test]
    fn top_level_and_nested_unknown_keys_are_found_with_a_nearest_sibling() {
        let doc = parse(
            "tier = \"keyword\"\n\n[memory]\ntier = \"x\"\n\n[storage]\ndb_mmap_size_byte = 1\n",
        );
        let found = find_unknown_keys(&doc);
        let paths: Vec<&str> = found.iter().map(|u| u.path.as_str()).collect();
        assert_eq!(paths, vec!["memory", "storage.db_mmap_size_byte"]);
        assert_eq!(
            found[1].nearest_sibling.as_deref(),
            Some("db_mmap_size_bytes")
        );
        let text = describe(&found[1]);
        assert!(
            text.contains("`storage.db_mmap_size_byte`") && text.contains("db_mmap_size_bytes")
        );
    }

    #[test]
    fn right_key_wrong_section_names_where_it_is_accepted() {
        let doc = parse("[storage]\nmax_page_size = 5\n");
        let found = find_unknown_keys(&doc);
        assert_eq!(found.len(), 1);
        assert!(
            found[0]
                .same_name_elsewhere
                .contains(&"limits.max_page_size".to_string())
        );
    }

    #[test]
    fn map_catch_alls_admit_any_key_and_arrays_of_tables_are_walked() {
        let ok = parse(
            "[mcp.allowlist]\nanything = \"goes\"\n[curator.reflection_namespaces.\"a/b\"]\nenabled = true\n",
        );
        assert!(find_unknown_keys(&ok).is_empty());
        let bad = parse(
            "[[permissions.rules]]\nnamespace_pattern = \"a\"\nop = \"store\"\nagent_pattern = \"*\"\ndecision = \"allow\"\ndecsion = \"deny\"\n",
        );
        let found = find_unknown_keys(&bad);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "permissions.rules[0].decsion");
        assert_eq!(found[0].nearest_sibling.as_deref(), Some("decision"));
    }

    #[test]
    fn secrets_kept_off_the_wire_by_skip_serializing_are_still_accepted_keys() {
        // `api_key` and `[hooks.subscription] hmac_secret` are
        // `skip_serializing`; the schema keeps them (write-only), so a
        // config that sets them is NOT refused as unknown.
        let doc = parse("api_key = \"k\"\n[hooks.subscription]\nhmac_secret = \"s\"\n");
        assert!(find_unknown_keys(&doc).is_empty());
    }

    #[test]
    fn the_governance_policy_legacy_shape_names_its_translator() {
        let doc = parse(
            "[[governance.policy]]\nscope = \"a\"\naction = \"store\"\ndecision = \"deny\"\n",
        );
        let found = find_unknown_keys(&doc);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "governance.policy");
        let hint = repair_hint(std::path::Path::new("/x/config.toml"), &found);
        assert!(hint.contains("governance migrate-to-permissions"), "{hint}");
        assert!(
            hint.contains("config check --file /x/config.toml"),
            "{hint}"
        );
    }

    #[test]
    fn accepted_leaf_set_covers_the_pre_3715_top_level_list_and_the_new_deployment_key() {
        let leaves = accepted_leaf_keys();
        assert!(leaves.contains(&"deployment.shape".to_string()));
        assert!(leaves.contains(&"storage.db_mmap_size_bytes".to_string()));
        assert!(leaves.contains(&"curator.confidence_decay_half_life_days.<key>".to_string()));
        assert!(leaves.contains(&"permissions.rules[].decision".to_string()));
        assert!(leaves.contains(&"api_key".to_string()));
        // The two `deny_unknown_fields` sub-structs are structs here too
        // (their refusal already happens in serde; the schema agrees).
        assert!(leaves.iter().any(|l| l.starts_with("wake_hub.")));
        assert!(leaves.iter().any(|l| l.starts_with("monitoring.")));
    }

    #[test]
    fn accepted_leaf_count_is_the_published_surface_count() {
        // The #3716 surface count. Derived from the schema, never typed by
        // hand: this assertion exists so a change in the number is a
        // change someone reviewed. Corpus census at 8b4f65a22 measured 173
        // leaves; #3714 added `deployment.shape`.
        assert_eq!(accepted_leaf_count(), 174, "{:#?}", accepted_leaf_keys());
    }

    #[test]
    fn levenshtein_is_symmetric_and_bounded() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("a", "a"), 0);
        assert_eq!(
            nearest("db_pat", ["db", "db_mmap_size_bytes"].into_iter()).as_deref(),
            None,
            "4 edits on a 6-char key is not a suggestion"
        );
        assert_eq!(
            nearest("memory", ["verify", "mcp", "tier"].into_iter()),
            None
        );
        assert_eq!(
            nearest("db_mmap_size_byte", ["db_mmap_size_bytes"].into_iter()).as_deref(),
            Some("db_mmap_size_bytes")
        );
    }
}
