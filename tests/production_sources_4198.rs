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
