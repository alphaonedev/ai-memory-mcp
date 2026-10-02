// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(not(feature = "sal-postgres"))]
//! #4434 - a binary built WITHOUT `sal-postgres` (the shipped release
//! configuration, `--features sal`) has no postgres driver to parse a store
//! DSN with, so it can never PROVE `sslmode=verify-full`. Its compliance
//! reports must not say it did: the floor verdict is never `Pinned`, doctor's
//! Transit-encryption section reports REFUSES (unverifiable in this build),
//! and enterprise posture check #15 FAILS - for every #4434 bypass shape AND
//! for a plain verify-full URL. Runs on every leg that builds without
//! `sal-postgres` (the default and `--features sal` legs).

use ai_memory::transit_encryption::{
    SslmodeFloor, dsn_floor_verdict, dsn_pins_sslmode_verify_full,
};

const SECRET: &str = "S3CRET-4434-nopg";

fn shapes() -> Vec<(&'static str, String)> {
    let base = format!("postgres://u:{SECRET}@127.0.0.1:5432/db");
    vec![
        ("plain verify-full", format!("{base}?sslmode=verify-full")),
        (
            "alias key",
            format!("{base}?sslmode=verify-full&ssl-mode=disable"),
        ),
        (
            "upper-case key",
            format!("{base}?sslmode=disable&SSLMODE=verify-full"),
        ),
        (
            "percent-encoded key",
            format!("{base}?sslmode=verify-full&%73slmode=disable"),
        ),
        (
            "fragment",
            format!("{base}?sslmode=disable#x&sslmode=verify-full"),
        ),
        (
            "tab in key",
            format!("{base}?sslmode=verify-full&ss\tlmode=disable"),
        ),
    ]
}

fn run(args: &[&str], url: &str, home: &std::path::Path) -> String {
    let keys = home.join("keys");
    std::fs::create_dir_all(&keys).expect("keys dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let out = assert_cmd::Command::cargo_bin("ai-memory")
        .expect("ai-memory binary")
        .env("HOME", home)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_STORE_URL", url)
        .args(args)
        .output()
        .expect("run ai-memory");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains(SECRET),
        "output must never carry the DSN password"
    );
    text
}

#[test]
fn a_build_without_sal_postgres_never_reports_a_pin_4434() {
    for (kind, url) in shapes() {
        assert!(
            !matches!(dsn_floor_verdict(&url), SslmodeFloor::Pinned { .. }),
            "{kind}: the verdict must never be Pinned without sal-postgres"
        );
        assert!(!dsn_pins_sslmode_verify_full(&url), "{kind}");
    }
    // Named by its Debug label so the cell compiles (and fails) on a base
    // that predates the variant.
    assert!(
        format!("{:?}", dsn_floor_verdict(&shapes()[0].1)).contains("Unverifiable"),
        "a plain verify-full DSN is Unverifiable in this build"
    );
}

#[test]
fn doctor_transit_and_posture_15_fail_closed_without_sal_postgres_4434() {
    for (kind, url) in shapes() {
        let home = tempfile::tempdir().expect("scratch HOME");
        let doctor = run(&["doctor", "--json"], &url, home.path());
        let report: serde_json::Value = serde_json::from_str(&doctor)
            .unwrap_or_else(|e| panic!("{kind}: doctor --json: {e}\n{doctor}"));
        let transit = report["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .find(|s| {
                s["name"]
                    .as_str()
                    .is_some_and(|n| n.contains("Transit encryption"))
            })
            .unwrap_or_else(|| panic!("{kind}: no Transit section"));
        let text = transit.to_string();
        assert!(
            text.contains("UNVERIFIABLE") && text.contains("REFUSES"),
            "{kind}: Transit must say unverifiable / refuses: {transit}"
        );
        assert!(
            !text.contains("verify-full pinned"),
            "{kind}: never pinned: {transit}"
        );
        assert!(
            transit["severity"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case("critical")),
            "{kind}: critical (the daemon refuses this store at boot): {transit}"
        );

        let posture = run(
            &["doctor", "--posture", "enterprise-federation", "--json"],
            &url,
            home.path(),
        );
        assert!(
            posture.contains("sslmode=verify-full=false")
                && !posture.contains("sslmode=verify-full=true"),
            "{kind}: posture #15 must FAIL: {posture}"
        );
    }
}
