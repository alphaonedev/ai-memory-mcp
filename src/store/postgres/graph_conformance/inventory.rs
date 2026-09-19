// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Parse complete files, including appended items and recursive submodules.
//! Inventory SQL sites, not a `_cypher` naming convention. Each occurrence
//! counts, so appending SQL to an already inventoried reader also fails.
use std::{collections::BTreeMap, path::Path};
use syn::visit::{self, Visit};

#[derive(Default)]
struct Sites {
    owner: String,
    found: BTreeMap<String, usize>,
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        // Only test-only modules are excluded, never name-based paths.
        if item.attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Ident>()
                    .is_ok_and(|name| name == "test")
        }) {
            return;
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.owner = item.sig.ident.to_string();
        visit::visit_impl_item_fn(self, item);
        self.owner.clear();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.owner = item.sig.ident.to_string();
        visit::visit_item_fn(self, item);
        self.owner.clear();
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        let value: String = literal
            .value()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"')
            .collect::<String>()
            .to_ascii_lowercase();
        if value.contains("cypher(") || value.contains("memory_graph.") {
            *self.found.entry(self.owner.clone()).or_default() += 1;
        }
    }

    fn visit_attribute(&mut self, _: &'ast syn::Attribute) {}

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // syn leaves format! bodies as token streams. Inspect string tokens
        // recursively; comments and unrelated identifiers never count.
        fn strings(tokens: proc_macro2::TokenStream, sites: &mut Sites) {
            for token in tokens {
                match token {
                    proc_macro2::TokenTree::Group(group) => strings(group.stream(), sites),
                    proc_macro2::TokenTree::Literal(literal) => {
                        if let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                            sites.visit_lit_str(&value);
                        }
                    }
                    _ => {}
                }
            }
        }
        strings(mac.tokens.clone(), self);
    }
}

fn scan(path: &Path, out: &mut BTreeMap<String, usize>) {
    let source = std::fs::read_to_string(path).expect("read graph inventory source");
    let mut sites = Sites::default();
    sites.visit_file(&syn::parse_file(&source).expect("parse graph inventory source"));
    for (name, count) in sites.found {
        *out.entry(name).or_default() += count;
    }
    // Walk declared modules, not just files known at the original cut.
    fn modules(items: &[syn::Item], directory: &Path, out: &mut BTreeMap<String, usize>) {
        for item in items {
            if let syn::Item::Mod(module) = item {
                if module.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg")
                        && attr
                            .parse_args::<syn::Ident>()
                            .is_ok_and(|name| name == "test")
                }) {
                    continue;
                }
                if let Some((_, children)) = &module.content {
                    modules(children, &directory.join(module.ident.to_string()), out);
                } else {
                    let explicit = module.attrs.iter().find_map(|attr| {
                        if attr.path().is_ident("path") {
                            if let syn::Meta::NameValue(value) = &attr.meta {
                                if let syn::Expr::Lit(lit) = &value.value {
                                    if let syn::Lit::Str(path) = &lit.lit {
                                        return Some(path.value());
                                    }
                                }
                            }
                        }
                        None
                    });
                    let target = explicit.map_or_else(
                        || directory.join(format!("{}.rs", module.ident)),
                        |p| directory.parent().expect("module parent").join(p),
                    );
                    let target = if target.is_file() {
                        target
                    } else {
                        directory.join(module.ident.to_string()).join("mod.rs")
                    };
                    scan(&target, out);
                }
            }
        }
    }
    let parsed = syn::parse_file(&source).expect("parse modules");
    let directory = if path.file_name().is_some_and(|name| name == "mod.rs") {
        path.parent().expect("module parent").to_path_buf()
    } else {
        path.with_extension("")
    };
    modules(&parsed.items, &directory, out);
}

#[test]
fn every_age_sql_site_is_classified() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/postgres.rs");
    let mut actual = BTreeMap::new();
    scan(&root, &mut actual);
    let expected: BTreeMap<String, usize> = [
        // Executed by matrix.rs, with per-cell nonempty plan requirements.
        ("kg_query_cypher", 1),
        ("kg_timeline_cypher", 1),
        ("kg_invalidate_cypher", 2),
        ("lineage_cypher", 1),
        // Projection writers, exercised while seeding; not graph readers.
        ("project_link_into_age", 2),
        ("unproject_memory_from_age_inner", 1),
        ("unproject_link_from_age", 1),
    ]
    .into_iter()
    .map(|(name, count)| (name.to_owned(), count))
    .collect();
    assert_eq!(
        actual, expected,
        "unclassified AGE SQL: add an executed matrix cell or justify a writer"
    );
}

#[test]
fn inventory_sees_appended_non_cypher_names_and_macro_strings() {
    let mut sites = Sites::default();
    sites.visit_file(
        &syn::parse_file(
            r#"
        fn old_reader() { let q = "SELECT * FROM cypher('g', $$ MATCH (n) RETURN n $$)"; }
        fn newly_appended_reader() { let q = format!("SELECT * FROM ag_catalog.CYPHER ('g', $$ {body} $$)"); }
        fn direct_table_reader() { let q = "SELECT * FROM memory_graph._ag_label_edge"; }
    "#,
        )
        .expect("mutation fixture"),
    );
    assert_eq!(sites.found.len(), 3);
    assert_eq!(sites.found["newly_appended_reader"], 1);
    assert_eq!(sites.found["direct_table_reader"], 1);
}

#[test]
fn inventory_follows_submodules_and_counts_appends() {
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch directory");
    let root = tempfile::tempdir_in(scratch).expect("inventory fixture");
    let file = root.path().join("postgres.rs");
    std::fs::create_dir(root.path().join("postgres")).expect("module directory");
    std::fs::write(&file, "mod newly_added;\n").expect("root source");
    let module = root.path().join("postgres/newly_added.rs");
    let reader =
        "fn ordinary_name() { let sql = \"SELECT * FROM cypher('g', $$ MATCH (n) RETURN n $$)\"; }";
    std::fs::write(&module, reader).expect("reader source");
    let mut baseline = BTreeMap::new();
    scan(&file, &mut baseline);
    assert_eq!(
        baseline["ordinary_name"], 1,
        "new non-suffix reader in submodule"
    );
    std::fs::write(
        &module,
        format!("{reader}\n{}", reader.replace("ordinary_name", "appended")),
    )
    .expect("append reader");
    let mut appended = BTreeMap::new();
    scan(&file, &mut appended);
    assert_ne!(baseline, appended, "appending must alter the inventory");
    assert_eq!(appended["appended"], 1);
    std::fs::write(
        &module,
        reader.replace(
            "; }",
            "; let extra = \"SELECT * FROM cypher('g', $$ MATCH (n) RETURN n $$)\"; }",
        ),
    )
    .expect("append same function SQL");
    let mut repeated = BTreeMap::new();
    scan(&file, &mut repeated);
    assert_eq!(
        repeated["ordinary_name"], 2,
        "second SQL site cannot hide in a listed reader"
    );
}
