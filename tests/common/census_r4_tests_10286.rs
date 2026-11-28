// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Round-four tests of the process-start census (#10286 to #10290). Every
//! expected line is written out here; the site digests are the values the
//! independent Python scanner (`scripts/ci/census_rows_10286.py`) gives the
//! same fixture, never values read back from the Rust census.

use super::*;
use std::fmt::Write as _;

/// The sites of one file, with the closures of that file alone.
fn sites(text: &str) -> Vec<census_pins::Site> {
    let toks = lex(text);
    let prep = Prep::new(&toks);
    let preps = std::slice::from_ref(&prep);
    let watched = census_pins::closure(preps, WATCHED);
    let env_mod = census_pins::closure(preps, census_pins::ENV_MOD_SEED);
    let env_fns = census_pins::closure(preps, census_pins::ENV_FN_SEED);
    let reach: BTreeSet<String> = env_mod.union(&env_fns).cloned().collect();
    census_pins::sites_of(&prep, &watched, &reach, &env_fns)
}

fn site_count(rel: &str, have: usize, want: usize) -> String {
    format!(
        "{rel}: {have} watched sites, SITE_ROWS has {want}; a new or removed site needs its row (#10286)"
    )
}

fn site_pin(rel: &str, i: usize, line: usize, what: &str, pin: &str, want: &str) -> String {
    format!(
        "{rel}: site {i} (line {line}, {what}) pins {pin}, SITE_ROWS has {want}; an edit at or next to a watched token needs its row (#10286)"
    )
}

fn macro_line(rel: &str, line: usize, form: &str, what: &str) -> String {
    format!(
        "{rel}:{line}: {form}: {what}; a macro form that can carry a watched name past the census needs a MACRO_ROWS row with its reason (#10287)"
    )
}

const EXIT: &str = "fn f() {\n    std::process::exit(1);\n}\n";
const ABORT: &str = "fn f() {\n    std::process::abort(1);\n}\n";
/// The scanner's digests of [`EXIT`] and [`ABORT`].
const EXIT_PIN: &str = "c7ea80509606d240";
const ABORT_PIN: &str = "3d3efeb6714e96ef";

#[test]
fn a_swap_that_keeps_the_count_is_red_by_its_site_pin_10286() {
    let rel = "src/s.rs";
    let a: Vec<String> = sites(EXIT).into_iter().map(|s| s.digest).collect();
    assert_eq!(
        a,
        vec![EXIT_PIN.to_string()],
        "the scanner and the census agree"
    );
    let b = sites(ABORT);
    assert_eq!(b.len(), a.len(), "the swap keeps the count");
    let row: Vec<&str> = a.iter().map(String::as_str).collect();
    assert_eq!(
        census_pins::site_findings(rel, &b, Some(&row)),
        vec![site_pin(rel, 0, 2, "process", ABORT_PIN, EXIT_PIN)]
    );
    let row_b = [ABORT_PIN];
    assert!(census_pins::site_findings(rel, &b, Some(&row_b)).is_empty());
    assert_eq!(
        census_pins::site_findings(rel, &b, None),
        vec![
            site_count(rel, 1, 0),
            site_pin(rel, 0, 2, "process", ABORT_PIN, "nothing"),
        ]
    );
}

#[test]
fn a_bad_stale_or_unsorted_site_row_is_red_10286() {
    let have: BTreeSet<&str> = ["a.rs", "b.rs"].into_iter().collect();
    let good: &[&str] = &[EXIT_PIN];
    let short: &[&str] = &["c7ea"];
    let upper: &[&str] = &["C7EA80509606D240"];
    let rows: &[(&str, &[&str])] = &[
        ("b.rs", good),
        ("a.rs", short),
        ("a.rs", upper),
        ("z.rs", good),
    ];
    assert_eq!(
        census_pins::site_table_findings(rows, &have),
        vec![
            "a.rs: SITE_ROWS digest \"c7ea\" is not 16 lower-case hex digits (#10286)".to_string(),
            "a.rs: SITE_ROWS digest \"C7EA80509606D240\" is not 16 lower-case hex digits (#10286)"
                .to_string(),
            "z.rs: 0 watched sites, SITE_ROWS has 1; a stale row is red (#10286)".to_string(),
            "a.rs: SITE_ROWS is not sorted or holds the file twice (#10286)".to_string(),
            "a.rs: SITE_ROWS is not sorted or holds the file twice (#10286)".to_string(),
        ]
    );
    let sorted: &[(&str, &[&str])] = &[("a.rs", good), ("b.rs", good)];
    assert!(census_pins::site_table_findings(sorted, &have).is_empty());
}

#[test]
fn every_env_reach_form_is_a_pinned_site_10286() {
    let rel = "src/e.rs";
    // N3 and N3b: the env module under another name, and an env function
    // imported by name, each with a run-time-built name.
    let n3 = "use std::env as e;\nfn f() {\n    e::set_var(format!(\"{}{}\", \"PROP\", \"TEST_FORK\"), \"true\");\n}\n";
    let n3b = "use std::env::set_var;\nfn f() {\n    set_var(format!(\"{}{}\", \"PROP\", \"TEST_FORK\"), \"true\");\n}\n";
    let rows: &[(&str, &[(&str, usize, &str)])] = &[
        (
            n3,
            &[
                ("c86384c840d0b218", 1, "a use of env"),
                ("e2d61c03c43b7aaa", 3, "env reach set_var"),
            ],
        ),
        (
            n3b,
            &[
                ("2f6cd4457dc1befd", 1, "a use of env"),
                ("6d96c2e1ffbfc428", 3, "env reach set_var"),
            ],
        ),
    ];
    for (text, want) in rows {
        let got: Vec<(String, usize, String)> = sites(text)
            .into_iter()
            .map(|s| (s.digest, s.line, s.what))
            .collect();
        let want: Vec<(String, usize, String)> = want
            .iter()
            .map(|(d, l, w)| ((*d).to_string(), *l, (*w).to_string()))
            .collect();
        assert_eq!(got, want, "fixture:\n{text}");
        let r4 = r4_fixture(rel, text);
        assert_eq!(
            r4,
            vec![
                site_count(rel, 2, 0),
                site_pin(rel, 0, 1, "a use of env", &want[0].0, "nothing"),
            ],
            "fixture:\n{text}"
        );
    }
}

#[test]
fn every_macro_form_is_red_without_its_row_10287() {
    let rel = "src/m.rs";
    let mac = "#[cfg(target_os = \"macos\")]\n";
    let n2b = format!(
        "{mac}macro_rules! mk {{\n    ($t:ty) => {{ <$t>::new(\"sh\") }};\n}}\n{mac}fn f() {{ let _ = mk!(std::process::Command); }}\n"
    );
    let n6b = "macro_rules! run {\n    ($m:ident) => { $m! { #[test] fn wrapped(x in 0u8..2) { let _ = x; } } };\n}\nrun!(proptest);\n".to_string();
    let w = |f: &str| {
        census_macros::FORMS
            .iter()
            .find(|(k, _)| *k == f)
            .map(|(_, w)| *w)
            .unwrap_or_default()
    };
    let rows: Vec<(String, Vec<(usize, &str)>)> = vec![
        (n2b, vec![(3, "<$t"), (6, "hot-arg")]),
        (n6b, vec![(2, "$m!"), (4, "hot-arg")]),
        (
            "macro_rules! m { ($t:path) => { $t::new(\"x\") }; }\n".to_string(),
            vec![(1, "$t::")],
        ),
        (
            "macro_rules! m { ($t:ident) => { $t { cases: 1 } }; }\n".to_string(),
            vec![(1, "$t{")],
        ),
        (
            "macro_rules! m { ($($p:ident)::+) => { $($p)::+::new(\"x\") }; }\n".to_string(),
            vec![(1, "$(..)::"), (1, "$(..)::")],
        ),
        ("macro mk() { 1 }\n".to_string(), vec![(1, "decl-macro")]),
        (
            "#[proc_macro]\npub fn m(i: TokenStream) -> TokenStream { i }\n".to_string(),
            vec![(1, "proc-macro")],
        ),
        (
            "macro_rules! format { () => {} }\n".to_string(),
            vec![(1, "allow-redefined")],
        ),
        (
            "macro format() { 1 }\n".to_string(),
            vec![(1, "decl-macro"), (1, "allow-redefined")],
        ),
        (
            "pub(crate) use my_spawn as vec;\n".to_string(),
            vec![(1, "allow-renamed")],
        ),
        (
            "fn f() { run_it!(Config::default().with_fork(true)); }\n".to_string(),
            vec![(1, "hot-arg")],
        ),
        (
            "fn f() { go!(std::env::set_var); }\n".to_string(),
            vec![(1, "hot-arg")],
        ),
    ];
    for (text, forms) in &rows {
        let mut want: Vec<String> = forms
            .iter()
            .map(|(line, f)| macro_line(rel, *line, f, w(f)))
            .collect();
        want.sort();
        let mut got: Vec<String> = r4_fixture(rel, text)
            .into_iter()
            .filter(|l| l.ends_with("(#10287)"))
            .collect();
        got.sort();
        assert_eq!(got, want, "fixture:\n{text}");
    }
    for text in [
        "fn f() { let v = vec![1, 2]; println!(\"{v:?}\"); }\n",
        "macro_rules! m { ($e:expr) => { $e + 1 }; }\n",
        "fn f() { assert_eq!(std::process::id(), 1); }\n",
    ] {
        let got: Vec<String> = r4_fixture(rel, text)
            .into_iter()
            .filter(|l| l.ends_with("(#10287)"))
            .collect();
        assert!(got.is_empty(), "fixture:\n{text}\n{got:?}");
    }
}

#[test]
fn a_wrong_stale_unknown_or_reasonless_macro_row_is_red_10287() {
    let mut have: BTreeMap<(String, &'static str), Vec<usize>> = BTreeMap::new();
    have.insert(("a.rs".to_string(), "$m!"), vec![1, 2]);
    have.insert(("b.rs".to_string(), "hot-arg"), vec![3]);
    let why = "a reason of at least twenty bytes";
    let rows: &[(&str, &str, usize, &str)] = &[
        ("a.rs", "$m!", 1, why),
        ("b.rs", "hot-arg", 1, "short"),
        ("c.rs", "$t::", 2, why),
        ("c.rs", "nope", 1, why),
        ("c.rs", "$t::", 2, why),
    ];
    assert_eq!(
        census_macros::macro_findings(&have, rows),
        vec![
            "a.rs: 2 $m! forms, MACRO_ROWS has 1; a new or removed macro form needs its row (#10287)"
                .to_string(),
            "b.rs: the MACRO_ROWS row for hot-arg has no reason of at least 20 bytes (#10287)"
                .to_string(),
            "c.rs: 0 $t:: forms, MACRO_ROWS has 2; a stale row is red (#10287)".to_string(),
            "c.rs: MACRO_ROWS names the unknown form \"nope\" (#10287)".to_string(),
            "c.rs: 0 $t:: forms, MACRO_ROWS has 2; a stale row is red (#10287)".to_string(),
            "c.rs: MACRO_ROWS is not sorted or holds the file and form twice (#10287)".to_string(),
        ]
    );
    let good: &[(&str, &str, usize, &str)] =
        &[("a.rs", "$m!", 2, why), ("b.rs", "hot-arg", 1, why)];
    assert!(census_macros::macro_findings(&have, good).is_empty());
}

#[test]
fn every_watched_crate_rename_and_bad_manifest_is_red_10289() {
    let rel = "Cargo.toml";
    let rows: &[(&str, &[&str])] = &[
        (
            "[dependencies]\nlc = { package = \"libc\", version = \"0.2\" }\n",
            &[
                "Cargo.toml: dependencies.lc.package = \"libc\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[dev-dependencies.pt]\npackage = \"proptest\"\nversion = \"1\"\n",
            &[
                "Cargo.toml: dev-dependencies.pt.package = \"proptest\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[target.'cfg(unix)'.dependencies]\nn = { package = \"nix\", version = \"0.29\" }\n",
            &[
                "Cargo.toml: target.cfg(unix).dependencies.n.package = \"nix\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[dependencies]\nlibc = { package = \"not-libc\", version = \"0.2\" }\n",
            &[
                "Cargo.toml: dependencies.libc.package = \"not-libc\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[workspace.dependencies]\nrf = { package = \"rusty-fork\", version = \"0.3\" }\n",
            &[
                "Cargo.toml: workspace.dependencies.rf.package = \"rusty-fork\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[patch.crates-io]\nlibc = { path = \"x\" }\n",
            &[
                "Cargo.toml: patch.crates-io.libc.path patches the watched crate libc; a patched watched crate runs code the census never reads (#10289)",
            ],
        ),
        (
            "[replace]\n\"nix:0.29.0\" = { path = \"x\" }\n",
            &[
                "Cargo.toml: replace.nix:0.29.0.path replaces the watched crate nix:0.29.0; a replaced watched crate runs code the census never reads (#10289)",
            ],
        ),
        (
            "[lib]\nname = \"libc\"\n",
            &["Cargo.toml: lib.name = \"libc\" gives a target a watched crate's name (#10289)"],
        ),
        (
            "[[bin]]\nname = \"proptest\"\n",
            &[
                "Cargo.toml: bin.#0.name = \"proptest\" gives a target a watched crate's name (#10289)",
            ],
        ),
        (
            "[dependencies]\nlc.package = \"libc\"\n",
            &[
                "Cargo.toml: dependencies.lc.package = \"libc\" renames a watched crate; the census reads a watched crate only by its own name (#10289)",
            ],
        ),
        (
            "[dependencies\nlibc = \"0.2\"\n",
            &[
                "Cargo.toml: line 1: an unclosed table header; an unparseable Cargo.toml is not clean (#10289)",
            ],
        ),
    ];
    for (text, want) in rows {
        let want: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            census_cargo::manifest_findings(rel, text.as_bytes()),
            want,
            "fixture:\n{text}"
        );
    }
    assert_eq!(
        census_cargo::manifest_findings(rel, b"[package]\nname = \"x\xff\"\n"),
        vec!["Cargo.toml: not UTF-8; an unreadable Cargo.toml is not clean (#10289)".to_string()]
    );
    for text in [
        "[package]\nname = \"ai-memory\"\n\n[dependencies]\nlibc = \"0.2\"\nserde = { version = \"1\", features = [\"derive\"] }\n",
        "[dev-dependencies]\nproptest = { version = \"1\", default-features = false }\n",
    ] {
        assert!(
            census_cargo::manifest_findings(rel, text.as_bytes()).is_empty(),
            "fixture:\n{text}"
        );
    }
}

#[test]
fn a_config_bound_to_another_name_is_red_10176() {
    let rel = "tests/p.rs";
    for text in [
        "use proptest::test_runner::Config as C;\n",
        "type C = ProptestConfig;\n",
    ] {
        let (_, forms) = pt_findings(rel, text);
        assert_eq!(
            forms,
            vec![fork_form(rel, 1, FORM_CONFIG_NAME)],
            "fixture: {text}"
        );
    }
    // N11: a fork literal outside any proptest! block, through a renamed
    // Config, is still red.
    let (_, forms) = pt_findings(
        rel,
        "type C = ProptestConfig;\nfn cfg() -> C { C { fork: true, ..C::default() } }\n",
    );
    assert_eq!(
        forms,
        vec![
            fork_form(rel, 1, FORM_CONFIG_NAME),
            fork_form(rel, 2, FORM_FIELD),
            fork_form(rel, 2, FORM_UPDATE),
        ]
    );
}

#[test]
fn the_round_four_scans_are_linear_on_large_input_10286() {
    let mut text = String::new();
    for i in 0..12_000 {
        writeln!(
            text,
            "macro_rules! m{i} {{ ($t:ty) => {{ <$t>::new() }}; }}\nfn f{i}() {{ go!(std::env::set_var(\"A\", \"1\")); std::process::exit(1); }}"
        )
        .expect("writing to a String cannot fail");
    }
    let mut toml = String::from("[dependencies]\n");
    for i in 0..30_000 {
        writeln!(
            toml,
            "d{i} = {{ version = \"1\", features = [\"a\", \"b\"] }}"
        )
        .expect("writing to a String cannot fail");
    }
    assert!(text.len() > 1_000_000 && toml.len() > 1_000_000);
    let t0 = std::time::Instant::now();
    let got = r4_fixture("src/big4.rs", &text);
    let found = census_cargo::manifest_findings("Cargo.toml", toml.as_bytes());
    let dt = t0.elapsed();
    assert!(found.is_empty());
    assert_eq!(
        got.iter().filter(|l| l.ends_with("(#10287)")).count(),
        24_000,
        "one <$t and one hot-arg per item"
    );
    assert!(
        dt < std::time::Duration::from_secs(20),
        "round-four scans took {dt:?}"
    );
}
