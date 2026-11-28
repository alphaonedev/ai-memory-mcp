// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The red test of #10286 to #10289: the reviewer's forms of PR 10226 (N1,
//! N2b, N3, N3b, N6b, N11), each through the whole census of a one-file
//! tree, with every line the census must print for that file written out.
//! It uses only the census entry point, so it runs on the base unchanged.
//! Each site digest below is the one the independent Python scanner
//! (`scripts/ci/census_rows_10286.py`) gives the same text.

use super::{Tree, census};

fn lines_of(rel: &str, text: &str) -> Vec<String> {
    let tree = Tree {
        files: vec![(rel.to_string(), text.as_bytes().to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{rel}:");
    let mut out: Vec<String> = census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head))
        .collect();
    out.sort();
    out
}

/// `(name, file, text, the lines the census prints for that file)`.
const FORMS: &[(&str, &str, &str, &[&str])] = &[
    (
        "N1",
        "Cargo.toml",
        "[package]\nname = \"x\"\n\n[dependencies]\nlc = { package = \"libc\", version = \"0.2\" }\n",
        &[
            "Cargo.toml: dependencies.lc.package = \"libc\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
        ],
    ),
    (
        "N2b",
        "src/n2b.rs",
        "#[cfg(target_os = \"macos\")]\nmacro_rules! mk {\n    ($t:ty) => { <$t>::new(\"sh\") };\n}\n#[cfg(target_os = \"macos\")]\npub fn f() { let _ = mk!(std::process::Command); }\n",
        &[
            "src/n2b.rs: 2 watched process, libc, nix or proptest tokens, TOKEN_ROWS has 0; every reference under any cfg, in any macro or by any path needs its exact row (#10176)",
            "src/n2b.rs: 2 watched sites, SITE_ROWS has 0; a new or removed site needs its row (#10286)",
            "src/n2b.rs: site 0 (line 6, process) pins 8f057ec87e479168900f6960a54ccc5f, SITE_ROWS has nothing; an edit of a watched statement needs its row (#10286)",
            "src/n2b.rs:3: <$t: a macro metavariable in type position; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)",
            "src/n2b.rs:6: hot-arg: a macro invocation whose arguments name a watched, proptest, env or fork name; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)",
        ],
    ),
    (
        "N3",
        "src/n3.rs",
        "use std::env as e;\nfn f() {\n    e::set_var(format!(\"{}{}\", \"PROP\", \"TEST_FORK\"), \"true\");\n}\n",
        &[
            "src/n3.rs: 1 environment names that are not one string literal or one named constant, ENV_NAME_ROWS has 0; a built name can switch proptest fork on (#10176)",
            "src/n3.rs: 2 watched sites, SITE_ROWS has 0; a new or removed site needs its row (#10286)",
            "src/n3.rs: site 0 (line 1, a use of env) pins c86384c840d0b218d8d9b29085c07bf7, SITE_ROWS has nothing; an edit of a watched statement needs its row (#10286)",
        ],
    ),
    (
        "N3b",
        "src/n3b.rs",
        "use std::env::set_var;\nfn f() {\n    set_var(format!(\"{}{}\", \"PROP\", \"TEST_FORK\"), \"true\");\n}\n",
        &[
            "src/n3b.rs: 1 environment names that are not one string literal or one named constant, ENV_NAME_ROWS has 0; a built name can switch proptest fork on (#10176)",
            "src/n3b.rs: 2 watched sites, SITE_ROWS has 0; a new or removed site needs its row (#10286)",
            "src/n3b.rs: site 0 (line 1, a use of env) pins 2f6cd4457dc1befdf179e797ada2d6ef, SITE_ROWS has nothing; an edit of a watched statement needs its row (#10286)",
        ],
    ),
    (
        "N6b",
        "tests/n6b.rs",
        "macro_rules! run {\n    ($m:ident) => { $m! { #[test] fn wrapped(x in 0u8..2) { let _ = x; } } };\n}\nrun!(proptest);\n",
        &[
            "tests/n6b.rs: 1 watched process, libc, nix or proptest tokens, TOKEN_ROWS has 0; every reference under any cfg, in any macro or by any path needs its exact row (#10176)",
            "tests/n6b.rs: 1 watched sites, SITE_ROWS has 0; a new or removed site needs its row (#10286)",
            "tests/n6b.rs: site 0 (line 4, proptest) pins a8633061910b0efc6cc26e2dcadd15ff, SITE_ROWS has nothing; an edit of a watched statement needs its row (#10286)",
            "tests/n6b.rs:2: $m!: a macro metavariable in invocation position; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)",
            "tests/n6b.rs:4: hot-arg: a macro invocation whose arguments name a watched, proptest, env or fork name; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)",
        ],
    ),
    (
        "N11",
        "tests/n11.rs",
        "use proptest::test_runner::Config as ProptestConfig;\nfn cfg() -> ProptestConfig { ProptestConfig { fork: true, ..ProptestConfig::default() } }\n",
        &[
            "tests/n11.rs: 1 watched process, libc, nix or proptest tokens, TOKEN_ROWS has 0; every reference under any cfg, in any macro or by any path needs its exact row (#10176)",
            "tests/n11.rs: 1 watched sites, SITE_ROWS has 0; a new or removed site needs its row (#10286)",
            "tests/n11.rs: site 0 (line 1, proptest) pins 526dcf14d126662eaa42815082ba44ae, SITE_ROWS has nothing; an edit of a watched statement needs its row (#10286)",
            "tests/n11.rs:1: a proptest Config bound to another name (as or type), which hides its literals from this scan; a proptest config with fork or timeout on re-runs this test binary outside the sandbox (#10176)",
            "tests/n11.rs:2: a fork or timeout field in a proptest Config literal; a proptest config with fork or timeout on re-runs this test binary outside the sandbox (#10176)",
        ],
    ),
];

#[test]
fn every_reviewer_form_of_round_three_is_red_10286() {
    let mut wrong = Vec::new();
    for (name, rel, text, want) in FORMS {
        let mut want: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
        want.sort();
        let got = lines_of(rel, text);
        if got != want {
            wrong.push(format!("{name}: got {got:#?}\nwant {want:#?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
