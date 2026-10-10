// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3437 — every keypair `rules keygen --out <path>` writes must be one the
//! operator-key loaders read.
//!
//! `keygen --out <path>` wrote `<path>` (raw seed) and `<path>.pub` (base64)
//! for ANY basename, but the signer (`load_operator_signing_key_from_dir`)
//! and the verifier (`rules_store::resolve_operator_pubkey`) read only the
//! fixed names `operator.key` + `operator.key.pub` (or the legacy
//! `operator.priv` + raw `operator.pub`). So `--out <dir>/team.seed` and
//! `--out <dir>/operator.priv` (which writes `operator.priv.pub`, a name no
//! loader reads) exited 0 and produced a key `rules enable --sign` could not
//! load.
//!
//! The fix (5-agent vote 4d3ea1c5, 5/5 option C): `--out` may relocate the
//! key's DIRECTORY but not rename it. A basename other than `operator.key`
//! is refused before anything is written, and the error names the remedy.
//! The loaders are unchanged, so signer and verifier cannot diverge.

use ai_memory::cli::CliOutput;
use ai_memory::cli::rules as cli_rules;
use ai_memory::governance::rules_store::{self, Rule};
use std::path::Path;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const RULE_ID: &str = "R-KEYGEN-OUT-3437";

/// A migrated db carrying one disabled, unsigned rule to enable.
fn init_db(path: &Path) {
    let conn = ai_memory::db::open(path).expect("open db");
    rules_store::insert(
        &conn,
        &Rule {
            id: RULE_ID.into(),
            kind: "filesystem_write".into(),
            matcher: r#"{"glob":"/scratch-3437/**"}"#.into(),
            severity: "refuse".into(),
            reason: "keygen --out layout test rule".into(),
            namespace: "_global".into(),
            created_by: "system:test".into(),
            created_at: 0,
            enabled: false,
            signature: None,
            attest_level: "unsigned".into(),
        },
    )
    .expect("insert rule");
}

fn run_rules(db: &Path, key_dir: &Path, action: cli_rules::RulesAction) -> anyhow::Result<()> {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    cli_rules::run(
        db,
        cli_rules::RulesArgs {
            key_dir: Some(key_dir.to_path_buf()),
            action,
        },
        false,
        &mut out,
    )
}

fn keygen(db: &Path, key_dir: &Path, out: &Path) -> anyhow::Result<()> {
    run_rules(
        db,
        key_dir,
        cli_rules::RulesAction::Keygen {
            out: Some(out.to_path_buf()),
            force: false,
        },
    )
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read key dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Denied path: a basename no loader reads is refused, names the remedy,
/// and writes nothing.
#[test]
fn keygen_out_with_unloadable_basename_is_refused_and_writes_nothing_3437() {
    // Review F7/M11 (#6052): names that merely END in `operator.key`, differ
    // only in case, or swap the dot for an underscore are just as unloadable.
    for basename in [
        "team.seed",
        "operator.priv",
        "operator",
        "x.operator.key",
        "OPERATOR.KEY",
        "operator_key",
    ] {
        let tdir = tempfile::tempdir().expect("tempdir");
        let db = tdir.path().join("rules.db");
        init_db(&db);
        let key_dir = tdir.path().join("keys");
        key_dir_sandbox::mkdir_0700(&key_dir);

        let result = keygen(&db, &key_dir, &key_dir.join(basename));
        let err = match result {
            Ok(()) => panic!(
                "#3437: `rules keygen --out <dir>/{basename}` must be refused (no loader reads \
                 that name), but it succeeded and wrote {:?}",
                entries(&key_dir)
            ),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("operator.key"),
            "#3437: the refusal must name the loadable basename; got {err}"
        );
        assert!(
            entries(&key_dir).is_empty(),
            "#3437: a refused keygen must write nothing; found {:?}",
            entries(&key_dir)
        );
    }
}

/// Allowed path: `--out <dir>/operator.key` loads, and `rules enable --sign`
/// against that directory signs with it.
#[test]
fn keygen_out_operator_key_loads_and_signs_3437() {
    let tdir = tempfile::tempdir().expect("tempdir");
    let db = tdir.path().join("rules.db");
    init_db(&db);
    let key_dir = tdir.path().join("keys");
    key_dir_sandbox::mkdir_0700(&key_dir);

    keygen(&db, &key_dir, &key_dir.join("operator.key")).expect("keygen --out operator.key");
    assert_eq!(
        entries(&key_dir),
        vec!["operator.key".to_string(), "operator.key.pub".to_string()]
    );
    run_rules(
        &db,
        &key_dir,
        cli_rules::RulesAction::Enable {
            id: RULE_ID.into(),
            sign: true,
        },
    )
    .expect("enable --sign must load the keygen output");
    let conn = ai_memory::db::open(&db).expect("reopen db");
    let rule = rules_store::get(&conn, RULE_ID)
        .expect("get rule")
        .expect("rule exists");
    assert!(rule.enabled);
    assert_eq!(rule.attest_level, "operator_signed");
    assert!(rule.signature.is_some());
}

/// Review F8 (#6052) — with a key-dir override in force, `--out` pointing at a
/// DIFFERENT directory produced a key the follow-up `rules --key-dir <A>
/// enable --sign` could not find (keygen wrote B, the signer read A). Refused
/// before anything is written, naming both paths.
#[test]
fn keygen_out_outside_the_overridden_key_dir_is_refused_3437() {
    let tdir = tempfile::tempdir().expect("tempdir");
    let db = tdir.path().join("rules.db");
    init_db(&db);
    let key_dir = tdir.path().join("keys-a");
    let other = tdir.path().join("keys-b");
    key_dir_sandbox::mkdir_0700(&key_dir);
    key_dir_sandbox::mkdir_0700(&other);

    let out_path = other.join("operator.key");
    let err = match keygen(&db, &key_dir, &out_path) {
        Ok(()) => panic!(
            "#3437: `rules --key-dir A keygen --out B/operator.key` must be refused (the \
             signer reads A), but it wrote {:?}",
            entries(&other)
        ),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains(&key_dir.display().to_string()),
        "#3437: the refusal must name the key dir; got {err}"
    );
    assert!(
        err.contains(&out_path.display().to_string()),
        "#3437: the refusal must name the --out path; got {err}"
    );
    assert!(
        entries(&key_dir).is_empty() && entries(&other).is_empty(),
        "#3437: a refused keygen must write nothing; found {:?} / {:?}",
        entries(&key_dir),
        entries(&other)
    );
}

/// Review F4 (#6052) — the documented end-to-end operator workflow must run
/// as written: every `rules` step names the same `--key-dir`, and `enable`
/// takes the rule by `--id` (a positional `R001` is rejected by clap).
#[test]
fn claude_code_operator_workflow_uses_one_key_dir_3437() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/integrations/claude-code.md"),
    )
    .expect("read docs/integrations/claude-code.md");
    let rules_lines: Vec<&str> = doc
        .lines()
        .filter(|l| l.contains("ai-memory rules "))
        .collect();
    assert!(
        !rules_lines.is_empty(),
        "the claude-code integration doc documents `ai-memory rules` verbs"
    );
    for line in &rules_lines {
        assert!(
            !line.contains("enable R00"),
            "#3437: `rules enable` takes `--id <ID>`, not a positional id: {line}"
        );
    }
    for verb in ["keygen", "sign-seed", "enable"] {
        let step = rules_lines
            .iter()
            .find(|l| l.contains(&format!(" {verb}")) && l.contains("**"))
            .unwrap_or_else(|| panic!("workflow step for `rules {verb}` is documented"));
        assert!(
            step.contains("--key-dir <dir>"),
            "#3437: the `rules {verb}` workflow step must use the one `--key-dir <dir>` \
             the signer reads: {step}"
        );
    }
}
