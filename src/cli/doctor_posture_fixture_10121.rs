// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10121 — `doctor --posture` builds its hardened environment from the ONE
//! fixture, `enterprise_federation_posture::hardened_env_fixture::PostureEnv`.
//!
//! Commit 44598c23f added posture check #23 and seeded its key in the posture
//! suite's fixture only; the hand-rolled copy in `cli::doctor::tests` drifted
//! and the doctor proof of GA standard 5 went red. The ratchet below keeps a
//! second copy out of `src/cli/doctor.rs`: it is an allowlist of the env
//! mutation sites the file may hold, so any new one fails and names the
//! fixture to use instead.

use std::collections::BTreeMap;

/// The file the ratchet guards.
const DOCTOR_SOURCE: &str = include_str!("doctor.rs");

/// The one fixture a test uses to build a posture environment.
const FIXTURE: &str = "crate::enterprise_federation_posture::hardened_env_fixture::PostureEnv";

/// Identifiers that mutate the process environment, in every call or alias
/// form (`std::env::set_var`, `env::set_var`, `use std::env::set_var as x`,
/// `libc::setenv`, ...): the token is counted wherever it appears in code.
const ENV_MUTATORS: &[&str] = &["set_var", "remove_var", "setenv", "unsetenv", "putenv"];

/// Identifiers that only a hardened-posture construction names. None may
/// appear in the file in code at all; each lives in the fixture.
const POSTURE_BUILDERS: &[&str] = &[
    "enforce_at_boot",
    "seed_anchor_key",
    "OPERATOR_PUBKEY_FILE",
    "approver_pubkey_b64",
];

/// Literal file names only a hardened-posture construction writes.
const POSTURE_FILES: &[&str] = &["operator.key.pub", "ai:posture-10086.pub"];

/// Every function of `src/cli/doctor.rs` allowed to mutate the environment,
/// with its exact count of mutation tokens. None of them builds a posture.
const ALLOWED_MUTATION_SITES: &[(&str, usize)] = &[
    // #2905 — clears the two store-URL channels under `StoreUrlEnvGuard`.
    ("run_local_collect_under", 2),
    // #3430 — save / set / restore `AI_MEMORY_OPERATOR_PUBKEY` (governance).
    ("governance_section_flags_enabled_but_inert_rules_3430", 3),
    (
        "governance_section_reports_a_correctly_signed_rule_as_enforced_3430",
        3,
    ),
    // `EnvScope` — the LLM / embed reach probe's restoring env setter.
    ("set", 2),
    ("drop", 2),
    ("clear_llm_embed_env", 1),
];

/// One violation of the ratchet, for an exact assertion.
#[derive(Debug, PartialEq, Eq)]
enum Violation {
    /// A posture-construction identifier or file name appears in code.
    PostureBuilder { line: usize, token: String },
    /// The mutation-site census differs from [`ALLOWED_MUTATION_SITES`].
    MutationSites(BTreeMap<String, usize>),
}

/// The identifiers of one line, in order.
fn identifiers(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
}

/// The function a line belongs to: the latest `fn <name>` seen so far.
fn fn_name(line: &str) -> Option<&str> {
    let mut ids = identifiers(line);
    while let Some(id) = ids.next() {
        if id == "fn" {
            return ids.next();
        }
    }
    None
}

/// Scan `source` (comment lines skipped) and return every violation.
fn scan(source: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut sites = BTreeMap::<String, usize>::new();
    let mut current_fn = String::from("<module>");
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with("//") {
            continue;
        }
        if let Some(name) = fn_name(line) {
            current_fn = name.to_owned();
        }
        for id in identifiers(line) {
            if ENV_MUTATORS.contains(&id) {
                *sites.entry(current_fn.clone()).or_default() += 1;
            }
            if POSTURE_BUILDERS.contains(&id) {
                violations.push(Violation::PostureBuilder {
                    line: index + 1,
                    token: id.to_owned(),
                });
            }
        }
        for file in POSTURE_FILES {
            if line.contains(file) {
                violations.push(Violation::PostureBuilder {
                    line: index + 1,
                    token: (*file).to_owned(),
                });
            }
        }
    }
    let allowed: BTreeMap<String, usize> = ALLOWED_MUTATION_SITES
        .iter()
        .map(|(name, count)| ((*name).to_owned(), *count))
        .collect();
    if sites != allowed {
        violations.push(Violation::MutationSites(sites));
    }
    violations
}

/// The ratchet over the real file.
#[test]
fn doctor_holds_no_hand_rolled_posture_env() {
    let violations = scan(DOCTOR_SOURCE);
    assert!(
        violations.is_empty(),
        "src/cli/doctor.rs builds a posture environment by hand; use {FIXTURE} \
         (`bare` / `fully_hardened`) instead, or allowlist a non-posture env \
         mutation in ALLOWED_MUTATION_SITES with its reason: {violations:?}"
    );
}

/// The base file, with only the allowlisted functions, scans clean; every
/// spelling of a hand-rolled posture block added to it is refused.
#[test]
fn ratchet_refuses_every_form_of_a_second_posture_block() {
    let allowed_body: String = ALLOWED_MUTATION_SITES
        .iter()
        .map(|(name, count)| {
            let calls = "unsafe { std::env::remove_var(K) };\n".repeat(*count);
            format!("fn {name}() {{\n{calls}}}\n")
        })
        .collect();
    assert_eq!(
        scan(&allowed_body),
        Vec::new(),
        "the allowlist alone is clean"
    );

    let mutants: &[(&str, &str)] = &[
        (
            "path call",
            "fn t() { unsafe { std::env::set_var(X, \"1\") }; }",
        ),
        (
            "short path",
            "fn t() { unsafe { env::set_var(X, \"1\") }; }",
        ),
        (
            "spaced call",
            "fn t() { unsafe { std::env :: set_var (X, \"1\") }; }",
        ),
        (
            "alias import",
            "use std::env::set_var as put;\nfn t() { unsafe { put(X, \"1\") }; }",
        ),
        (
            "remove form",
            "fn t() { unsafe { std::env::remove_var(X) }; }",
        ),
        (
            "libc setenv",
            "fn t() { unsafe { libc::setenv(k, v, 1) }; }",
        ),
        ("libc unsetenv", "fn t() { unsafe { libc::unsetenv(k) }; }"),
        ("putenv", "fn t() { unsafe { libc::putenv(kv) }; }"),
        (
            "extra in an allowed fn",
            "fn drop() { unsafe { std::env::set_var(X, \"1\") }; }",
        ),
        (
            "split across lines",
            "fn t() {\n    unsafe {\n        std::env::\n        set_var(\n X, \"1\") };\n}",
        ),
    ];
    for (form, mutant) in mutants {
        let source = format!("{allowed_body}{mutant}\n");
        let found = scan(&source);
        assert!(
            found
                .iter()
                .any(|v| matches!(v, Violation::MutationSites(_))),
            "{form}: a new env mutation must be refused: {found:?}"
        );
    }

    let builders: &[(&str, &str, &str)] = &[
        (
            "boot pin",
            "crate::security_profile::enforce_at_boot().unwrap();",
            "enforce_at_boot",
        ),
        (
            "boot pin alias",
            "use crate::security_profile::enforce_at_boot as pin;",
            "enforce_at_boot",
        ),
        ("anchor seed", "seed_anchor_key(&dir);", "seed_anchor_key"),
        (
            "operator key literal",
            "std::fs::write(d.join(\"operator.key.pub\"), k);",
            "operator.key.pub",
        ),
        (
            "operator key const",
            "d.join(OPERATOR_PUBKEY_FILE);",
            "OPERATOR_PUBKEY_FILE",
        ),
        (
            "anchor key literal",
            "d.join(\"ai:posture-10086.pub\");",
            "ai:posture-10086.pub",
        ),
        (
            "approver key",
            "let k = approver_pubkey_b64();",
            "approver_pubkey_b64",
        ),
    ];
    for (form, line, token) in builders {
        let source = format!("{allowed_body}fn t() {{\n{line}\n}}\n");
        let found = scan(&source);
        let line_no = allowed_body.lines().count() + 2;
        assert_eq!(
            found,
            vec![Violation::PostureBuilder {
                line: line_no,
                token: (*token).to_owned(),
            }],
            "{form}: a posture builder must be refused with its exact token"
        );
    }

    // A comment naming a token is documentation, not construction.
    let documented =
        format!("{allowed_body}/// `enforce_at_boot` pins FULL; set_var is not called here.\n");
    assert_eq!(scan(&documented), Vec::new());
}

/// #10121 negative: the certified posture with its agent keys removed has
/// exactly one failing row besides the build-dependent at-rest row — check
/// #23, `row attestation trust anchor`, naming the empty key directory — and
/// `doctor --posture` exits 2.
#[test]
fn run_posture_fails_only_the_anchor_row_without_an_agent_key_10121() {
    if crate::config::run_env_isolated_child_or_spawn(
        "cli::doctor::doctor_posture_fixture_10121::run_posture_fails_only_the_anchor_row_without_an_agent_key_10121",
    ) {
        return;
    }
    let lock = crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard::acquire();
    let env =
        crate::enterprise_federation_posture::hardened_env_fixture::PostureEnv::fully_hardened(
            &lock,
        );
    assert_eq!(
        env.remove_agent_keys(),
        1,
        "the fixture seeds exactly one agent key"
    );

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
    let exit = super::run_posture(
        crate::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION,
        true,
        None,
        &mut out,
    )
    .expect("posture report");
    assert_eq!(exit, 2, "an unanchored verifier must fail the posture");

    let v: serde_json::Value = serde_json::from_slice(&stdout).expect("posture JSON");
    assert_eq!(v["pass"], false);
    let sqlcipher_compiled = crate::build_features::has_feature("sqlcipher");
    let failing: Vec<&serde_json::Value> = v["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .filter(|c| c["pass"] == false)
        .filter(|c| sqlcipher_compiled || c["control"] != crate::encryption::ENV_ENCRYPT_AT_REST)
        .collect();
    assert_eq!(failing.len(), 1, "exactly one failing row: {failing:?}");
    let row = failing[0];
    assert_eq!(row["control"], "row attestation trust anchor", "{row}");
    let key_dir = env
        .key_dir()
        .expect("hardened key dir")
        .display()
        .to_string();
    assert_eq!(
        row["actual"],
        format!("unanchored: key directory {key_dir} holds no public key"),
        "{row}"
    );
    drop(stderr);
}
