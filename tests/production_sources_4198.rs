// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4198 — cells for the ONE production view of `src/` that every
//! structural scanner shares (`tests/common/cfg_test_modules.rs`). The
//! helpers are included by `#[path]` into each scanner; their own cells live
//! here so they run once.

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

use cfg_test_modules::{cfg_requires_test, production_sources, strip_cfg_test_inline_mods};

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The real tree lexes end to end (no unclosed test module panics), a
/// parent-declared test-only file is excluded (the #4200 module), and an
/// ordinary production file is present.
#[test]
fn the_real_src_tree_has_one_production_view_4198() {
    let view = production_sources(&root());
    let has = |rel: &str| view.iter().any(|(r, _)| r == rel);
    assert!(
        !has("src/store/sqlite/owner_gate_txn_3957.rs"),
        "a module its parent declares #[cfg(test)] is not production"
    );
    assert!(has("src/store/sqlite.rs"), "its parent is production");
    assert!(has("src/lib.rs"));
    // No inline cfg(test) module header survives in the production view.
    for (rel, text) in &view {
        let lines: Vec<&str> = text.lines().collect();
        for w in lines.windows(2) {
            assert!(
                !(w[0].trim() == "#[cfg(test)]"
                    && w[1].trim_start().starts_with("mod ")
                    && w[1].trim_end().ends_with('{')),
                "{rel}: an inline cfg(test) module survived the strip"
            );
        }
    }
}

/// A test-looking NAME is never a reason to skip (#4054): a file the tree
/// declares normally stays in the view whatever it is called.
#[test]
fn a_test_looking_name_alone_is_production_4198() {
    let view = production_sources(&root());
    let test_named: Vec<&String> = view
        .iter()
        .map(|(r, _)| r)
        .filter(|r| r.rsplit('/').next().is_some_and(|f| f.contains("test")))
        .collect();
    // src/mcp/dispatch_test_hook.rs is production per #4054; if it exists it
    // must be in the view.
    if std::path::Path::new(&root().join("src/mcp/dispatch_test_hook.rs")).exists() {
        assert!(
            test_named
                .iter()
                .any(|r| r.as_str() == "src/mcp/dispatch_test_hook.rs"),
            "dispatch_test_hook.rs is production (#4054): {test_named:?}"
        );
    }
}

#[test]
fn cfg_requires_test_is_top_level_only_4198() {
    assert!(cfg_requires_test("#[cfg(test)]"));
    assert!(cfg_requires_test(r#"#[cfg(all(test, feature = "sal"))]"#));
    assert!(!cfg_requires_test(r#"#[cfg(any(test, feature = "x"))]"#));
    assert!(!cfg_requires_test("#[cfg(not(test))]"));
    assert!(!cfg_requires_test(r#"#[cfg(feature = "sal")]"#));
}

#[test]
fn strip_keeps_callers_after_test_modules_and_handles_strings_4198() {
    let src = "fn a() {}\n#[cfg(test)]\nmod tests {\n    const R: &str = r#\" \" { \"#;\n    const M: &str = \"line one\n { line two\";\n    let _c = '}';\n}\nfn late() { x.call(); }\n#[cfg(any(test, feature = \"x\"))]\nmod maybe {\n    fn m() {}\n}\n";
    let kept = strip_cfg_test_inline_mods(src);
    assert!(kept.contains("fn late() { x.call(); }"), "{kept}");
    assert!(
        kept.contains("fn m() {}"),
        "any(test, ..) is production: {kept}"
    );
    assert!(!kept.contains("const R"), "{kept}");
}

#[test]
#[should_panic(expected = "never closes")]
fn strip_fails_closed_on_an_unclosed_test_module_4198() {
    let _ = strip_cfg_test_inline_mods("#[cfg(test)]\nmod tests {\n    fn x() {}\nfn late() {}\n");
}

/// #4198 f2r review — the real tree's parent-declared test-only files are
/// test-only, including the two shapes the first resolver missed:
/// `#[cfg(test)] #[path = ".."] mod x;` and a `mod x;` declared INSIDE an
/// inline `#[cfg(test)] mod tests { .. }`. Every one of them was returned as
/// production by the 1e19ce2d0 resolver.
#[test]
fn every_parent_declared_test_module_in_src_is_test_only_4198() {
    let view = production_sources(&root());
    let prod: std::collections::HashSet<&str> = view.iter().map(|(r, _)| r.as_str()).collect();
    for rel in [
        // #[cfg(test)] + #[path]
        "src/handlers/tests.rs",
        "src/mcp/tools/store/tests.rs",
        "src/daemon_runtime_shutdown_tests.rs",
        "src/mcp/tools/d1_4_985_helpers.rs",
        "src/mcp/tools/routine/freeze_3616.rs",
        // declared inside an inline #[cfg(test)] mod tests
        "src/cli/backup/tests/publish_3550.rs",
        "src/cli/backup/tests/signed_manifest_3199.rs",
        // the #4149 / #4200 shape
        "src/store/sqlite/owner_gate_txn_3957.rs",
    ] {
        assert!(
            std::path::Path::new(&root().join(rel)).exists(),
            "fixture drift: {rel} no longer exists; update this cell"
        );
        assert!(
            !prod.contains(rel),
            "{rel} is test-only and must not be production"
        );
    }
    // A production #[path] module is still production (src/mcp/mod.rs loads
    // the tool modules through #[path]).
    assert!(prod.contains("src/mcp/tools/action.rs"));
}

/// The module graph on synthetic trees: #[path] under cfg(test), children
/// inside an inline test module, an intervening attribute, and a production
/// #[path]; strict mode reports an orphan.
#[test]
fn module_graph_follows_path_attrs_and_inline_children_4198() {
    let f = |p: &str, s: &str| (p.to_string(), s.to_string());
    let files = vec![
        f(
            "src/lib.rs",
            "mod a;\n#[cfg(test)]\n#[path = \"a_tests.rs\"]\nmod a_tests;\n#[path = \"tools/b.rs\"]\nmod b;\n",
        ),
        f(
            "src/a.rs",
            "#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n    mod child;\n}\n",
        ),
        f("src/a/tests/child.rs", "fn c() {}\n"),
        f("src/a_tests.rs", "fn t() {}\n"),
        f("src/tools/b.rs", "fn prod() {}\n"),
        f("src/orphan.rs", "fn o() {}\n"),
    ];
    let g = cfg_test_modules::module_graph(&files, true);
    assert!(g.test_only.contains("src/a_tests.rs"), "{g:?}");
    assert!(g.test_only.contains("src/a/tests/child.rs"), "{g:?}");
    assert!(g.production.contains("src/tools/b.rs"), "{g:?}");
    assert!(g.production.contains("src/a.rs"), "{g:?}");
    assert_eq!(g.orphans, vec!["src/orphan.rs".to_string()], "{g:?}");
}

#[test]
#[should_panic(expected = "which is not a src file")]
fn an_unresolved_production_declaration_panics_4198() {
    let files = vec![("src/lib.rs".to_string(), "mod missing;\n".to_string())];
    let _ = cfg_test_modules::module_graph(&files, true);
}
