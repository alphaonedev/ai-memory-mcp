// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3061 / #3106 — pin posture control #15's BACKEND-AWARE resolution and the
//! SATISFIABILITY of the certified enterprise-federation posture on postgres.
//!
//! ## What regressed (and why this file exists)
//!
//! #3061 made control #15 (at-rest encryption) backend-aware: the exact
//! pre-#3061 sqlcipher predicate on sqlite, and a COMPENSATING pg at-rest
//! control (`AI_MEMORY_PG_AT_REST_ATTESTED` + a DSN pinning
//! `sslmode=verify-full`) on a `postgres://` store — without which #15 is
//! UNSATISFIABLE on pg and the #17 boot gate can never arm a pg node.
//!
//! #3106 added posture control #20 (an enrolled R40 approver key) and updated
//! THREE of the four places that encode "the certified config" — the posture
//! module's own test helper, `doctor.rs`'s test helper, and
//! `docs/deploy/enterprise-federation.env` — but not the fourth,
//! `scripts/check-bootstrap-cert-gate.sh` LEG A. That harness ALSO exports
//! `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1`, so its now-keyless
//! node was refused by the boot gate in `fn main()` BEFORE `doctor --posture`
//! could run: exit 1 (not `run_posture`'s documented 2) with an EMPTY stdout.
//! Its second assertion — a grep over that never-written JSON — then reported
//! "control #15 did not resolve to the pg compensating control". Control #15
//! was never the defect; its row was simply never emitted.
//!
//! These tests are the in-tree guard the cert job alone did not provide (that
//! job is not a required context, so its red did not block the merge). They
//! run on EVERY CI leg and pin:
//!
//! 1. Control #15 resolves from the STORE URL — the pg compensating control
//!    on a `postgres://` DSN (PASSing on `sslmode=verify-full` + attested,
//!    FAILing below that), and the byte-identical sqlcipher predicate
//!    otherwise. Asserted INDEPENDENTLY of every other control, so a future
//!    control addition can never again masquerade as a #15 failure.
//! 2. The certified pg config is SATISFIABLE end-to-end: with the certified
//!    env complete, `doctor --posture` exits 0 with all
//!    `ENTERPRISE_FEDERATION_CHECK_COUNT` controls green. A control added
//!    without extending the certified env turns THIS red, in the adding PR.
//!
//! Driven through the real binary (`CARGO_BIN_EXE_ai-memory`) so the
//! assertions are over the same rendered `--json` payload the cert gate
//! greps. NOT feature-gated: `doctor --posture` never opens the store, so the
//! `postgres://` DSN below is parsed, never connected — the pg legs are
//! meaningful on the default sqlite-only build too.

use std::path::{Path, PathBuf};
use std::process::Output;

/// A `postgres://` DSN that is NEVER connected — `doctor --posture` is
/// env-only, and the query string is all control #15 machine-checks.
const PG_DSN_VERIFY_FULL: &str = "postgres://u@db.internal:5432/mem?sslmode=verify-full";
const PG_DSN_REQUIRE_ONLY: &str = "postgres://u@db.internal:5432/mem?sslmode=require";

// Every env name below is the ONE `pub const` that declares it (project
// no-hardcoded-literals rule) — a rename in the module that owns the knob
// breaks this file loudly instead of silently un-pinning the control.

/// The pg COMPENSATING half of control #15 (#3061). The rendered control
/// label embeds this env name, so the row is matched by prefix.
const PG_AT_REST_ENV: &str = ai_memory::enterprise_federation_posture::ENV_PG_AT_REST_ATTESTED;
/// The sqlite/sqlcipher STRUCTURAL half of control #15 (pre-#3061 verbatim).
const SQLCIPHER_ENV: &str = ai_memory::encryption::ENV_ENCRYPT_AT_REST;
/// The §5.3 boot-refusing gate; check #17 requires it armed.
const REQUIRE_POSTURE_ENV: &str =
    ai_memory::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE;
/// No `pub const` declares the agent-id env (the identity module's copy is
/// private, and clap owns the flag), so it is spelled once here.
const AGENT_ID_ENV: &str = "AI_MEMORY_AGENT_ID";
/// Agent id under which the daemon audit signing key (check #19) resolves.
const AGENT_ID: &str = "cert-node-3106";
/// Approver identity minted for the check #20 enrollment.
const APPROVER_ID: &str = "cert-approver-3106";

/// A fresh sandbox under `.local-runs/` (project no-`/tmp` HARD RULE).
fn sandbox(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3106-posture-control15");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Spawn the real binary with a HERMETIC environment: EVERY ambient
/// `AI_MEMORY_*` var is stripped, then `envs` is applied. A developer (or a
/// CI leg) with posture knobs exported must not be able to flip which branch
/// of control #15 resolves, nor pre-satisfy a control under test.
fn run_bin(key_dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.args(args);
    for (k, _) in std::env::vars() {
        if k.starts_with("AI_MEMORY_") {
            cmd.env_remove(k);
        }
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd.env(ai_memory::identity::keypair::KEY_DIR_ENV, key_dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

/// `doctor --posture enterprise-federation --json` under a hermetic env.
fn run_posture_json(key_dir: &Path, envs: &[(&str, &str)]) -> Output {
    run_bin(
        key_dir,
        &[
            "doctor",
            "--posture",
            ai_memory::enterprise_federation_posture::POSTURE_ENTERPRISE_FEDERATION,
            "--json",
        ],
        envs,
    )
}

/// The `(control, pass)` rows of a `--posture --json` payload.
fn control_rows(out: &Output) -> Vec<(String, bool)> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "`doctor --posture --json` must emit parseable JSON on stdout; parse error: {e}\
             \n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    payload["checks"]
        .as_array()
        .expect("`checks` must be an array")
        .iter()
        .map(|c| {
            (
                c["control"].as_str().unwrap_or_default().to_string(),
                c["pass"].as_bool().unwrap_or_default(),
            )
        })
        .collect()
}

/// The pass/fail of the SINGLE row whose control label starts with `prefix`,
/// or `None` when that control did not resolve at all.
fn row(rows: &[(String, bool)], prefix: &str) -> Option<bool> {
    let matched: Vec<&(String, bool)> = rows
        .iter()
        .filter(|(control, _)| control.starts_with(prefix))
        .collect();
    assert!(
        matched.len() <= 1,
        "control #15 must resolve to exactly ONE row for {prefix}, got {matched:?}"
    );
    matched.first().map(|(_, pass)| *pass)
}

/// LEG 1 — on a `postgres://` DSN, control #15 IS the pg compensating control
/// and PASSes on `sslmode=verify-full` + the operator at-rest attestation.
///
/// Asserted with the rest of the posture deliberately DEVIATING: #15's
/// resolution must be readable on its own, never inferred from the overall
/// verdict — inferring it from the verdict is exactly what made the #3106
/// regression read as a control-#15 failure.
#[test]
fn pg_dsn_resolves_control_15_to_the_compensating_control() {
    let sb = sandbox("pg-compensating");
    let out = run_posture_json(
        sb.path(),
        &[
            (ai_memory::store_url::STORE_URL_ENV, PG_DSN_VERIFY_FULL),
            (PG_AT_REST_ENV, "1"),
        ],
    );
    let rows = control_rows(&out);
    assert_eq!(
        rows.len(),
        ai_memory::enterprise_federation_posture::ENTERPRISE_FEDERATION_CHECK_COUNT,
        "the report must render EVERY control, not a truncated set"
    );
    assert_eq!(
        row(&rows, PG_AT_REST_ENV),
        Some(true),
        "#3061: on a postgres DSN pinning sslmode=verify-full WITH the operator \
         at-rest attestation, control #15 must be the pg COMPENSATING control and \
         must PASS — it is what makes the certified posture satisfiable on pg. \
         rows={rows:?}"
    );
    assert!(
        row(&rows, SQLCIPHER_ENV).is_none(),
        "#3061: the sqlcipher predicate is UNSATISFIABLE on postgres and must not \
         be the #15 row there. rows={rows:?}"
    );
}

/// LEG 2 — the pg compensating control is genuinely load-bearing: weakening
/// the DSN below `verify-full` FAILs the same row (a real check, not a
/// backend-shaped rubber stamp).
#[test]
fn pg_control_15_fails_below_verify_full() {
    let sb = sandbox("pg-weak-tls");
    let out = run_posture_json(
        sb.path(),
        &[
            (ai_memory::store_url::STORE_URL_ENV, PG_DSN_REQUIRE_ONLY),
            (PG_AT_REST_ENV, "1"),
        ],
    );
    let rows = control_rows(&out);
    assert_eq!(
        row(&rows, PG_AT_REST_ENV),
        Some(false),
        "sslmode=require is below verify-full — the pg #15 row must FAIL. rows={rows:?}"
    );
}

/// LEG 3 — the sqlite behaviour is UNCHANGED: with no store URL, control #15
/// is the byte-identical pre-#3061 sqlcipher predicate, and the pg
/// compensating control is absent even with its attestation exported.
#[test]
fn sqlite_control_15_is_still_the_sqlcipher_predicate() {
    let sb = sandbox("sqlite-default");
    let out = run_posture_json(sb.path(), &[(PG_AT_REST_ENV, "1")]);
    let rows = control_rows(&out);
    assert_eq!(
        row(&rows, SQLCIPHER_ENV),
        Some(false),
        "with no store URL, #15 must be the sqlcipher predicate — FAILing here \
         because the env is unset on a non-sqlcipher test binary. rows={rows:?}"
    );
    assert!(
        row(&rows, PG_AT_REST_ENV).is_none(),
        "the pg compensating control must NOT appear on a sqlite store, and its \
         attestation must never substitute for the structural control. rows={rows:?}"
    );
}

/// LEG 4 (the #3106 regression guard) — the certified pg config is
/// SATISFIABLE: every control green, `doctor --posture` exit 0.
///
/// The in-tree twin of `scripts/check-bootstrap-cert-gate.sh` LEG A, and the
/// assertion that actually broke. A control added to `evaluate()` without
/// extending the certified env turns this red in the ADDING PR, on every CI
/// leg — rather than a day later in a non-required cert job whose failure
/// text names an unrelated control.
#[test]
fn certified_pg_config_reaches_all_pass() {
    let sb = sandbox("certified-pg");
    let key_dir = sb.path().join("keys");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    // check #19 — the daemon audit signing key, resolved under AGENT_ID.
    let gen_node = run_bin(
        &key_dir,
        &["identity", "generate", "--agent-id", AGENT_ID],
        &[],
    );
    assert!(
        gen_node.status.success(),
        "identity generate (node key) failed: {}",
        String::from_utf8_lossy(&gen_node.stderr)
    );
    // check #20 — a REAL Ed25519 approver key minted by the same binary
    // (never a hardcoded literal), enrolled below.
    let gen_approver = run_bin(
        &key_dir,
        &["identity", "generate", "--agent-id", APPROVER_ID],
        &[],
    );
    assert!(
        gen_approver.status.success(),
        "identity generate (approver) failed: {}",
        String::from_utf8_lossy(&gen_approver.stderr)
    );
    let exported = run_bin(
        &key_dir,
        &["identity", "export-pub", "--agent-id", APPROVER_ID],
        &[],
    );
    assert!(
        exported.status.success(),
        "identity export-pub failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let approver_pubkey = String::from_utf8_lossy(&exported.stdout).trim().to_string();
    assert!(!approver_pubkey.is_empty(), "empty approver pubkey");

    // checks #9-#12 — trust domain + peer fingerprints pin file + the peer
    // attestation JSON (a prefix-CONFINED scope, never a bare `**`).
    let fingerprints = sb.path().join("peer-fingerprints.txt");
    std::fs::write(
        &fingerprints,
        "example.org 0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .expect("write fingerprints");
    let fingerprints = fingerprints.to_string_lossy().into_owned();

    let out = run_posture_json(
        &key_dir,
        &[
            (
                ai_memory::security_profile::ENV_SECURITY_PROFILE,
                ai_memory::security_profile::SecurityPosture::AsiHard.as_str(),
            ),
            (
                ai_memory::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
                "test-fleet",
            ),
            (ai_memory::tls::FED_PEER_FINGERPRINTS_ENV, &fingerprints),
            (
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                r#"{"peer-1":{"allowed_namespaces":["public/*"]}}"#,
            ),
            (ai_memory::store_url::STORE_URL_ENV, PG_DSN_VERIFY_FULL),
            (PG_AT_REST_ENV, "1"),
            (ai_memory::config::ENV_APPEND_ONLY, "1"),
            (AGENT_ID_ENV, AGENT_ID),
            (
                ai_memory::approvals::signed::APPROVER_PUBKEYS_ENV,
                &approver_pubkey,
            ),
            (REQUIRE_POSTURE_ENV, "1"),
        ],
    );

    let rows = control_rows(&out);
    let failing: Vec<&(String, bool)> = rows.iter().filter(|(_, pass)| !*pass).collect();
    assert!(
        failing.is_empty(),
        "the certified pg config must satisfy EVERY control — a control added \
         without extending the certified env shows up here. failing={failing:?}"
    );
    assert_eq!(
        rows.len(),
        ai_memory::enterprise_federation_posture::ENTERPRISE_FEDERATION_CHECK_COUNT,
        "check-count SSOT drift"
    );
    assert_eq!(
        row(&rows, PG_AT_REST_ENV),
        Some(true),
        "#15 must be the pg compensating control in the certified pg config"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the certified pg config must exit 0 (#3061 armable); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
