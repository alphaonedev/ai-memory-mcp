// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6096 (WP-SECRETS umbrella #6052) — a store DSN whose userinfo holds an
//! UNENCODED `/`, `?` or `#` must reach no display sink with any credential
//! byte. The WHATWG parser ends the authority at the delimiter and reads the
//! credential remainder as host / port / path; `store_url_display` used to
//! render exactly those. It now renders `scheme://<redacted-authority>`.
//!
//! Each cell plants the secret marker in one (delimiter, position) shape and
//! asserts by ABSENCE over the whole sink, the family idiom of
//! `credential_to_sink_3711.rs`.

#![cfg(feature = "sal")]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::path::Path;

use tempfile::TempDir;

/// The credential marker every shape carries.
const MARKER: &str = "SECRET6096";

/// One DSN per (delimiter, position): leading-delimiter password,
/// numeric-prefix password, delimiter in the username.
fn ambiguous_dsns() -> Vec<String> {
    let mut out = Vec::new();
    for d in ['/', '?', '#'] {
        out.push(format!("postgres://svc:{d}{MARKER}pw@127.0.0.1:9/mem"));
        out.push(format!("postgres://svc:123{d}{MARKER}pw@127.0.0.1:9/mem"));
        out.push(format!("postgres://svc{d}{MARKER}user:pw@127.0.0.1:9/mem"));
    }
    out.extend(normalised_ambiguous_dsns());
    out
}

/// r2 (security review of #6099): shapes the parser NORMALISES - tab / LF /
/// CR inside the separator (stripped before the authority is read), a
/// secret BEFORE the delimiter (the parsed HOST is then credential bytes),
/// `\` and missing slashes on a special scheme.
fn normalised_ambiguous_dsns() -> Vec<String> {
    let m = MARKER;
    vec![
        format!("postgres:\t//svc:a@{m}/x@127.0.0.1/mem?sslmode=verify-full"),
        format!("postgres:/\n/svc:a@{m}/x@127.0.0.1/mem?sslmode=verify-full"),
        format!("postgres:/\r/svc:/{m}pw@127.0.0.1/mem"),
        format!("postgres://svc:a@{m}?x@127.0.0.1/mem"),
        format!("postgres://{m}user/x:pw@127.0.0.1/mem?sslmode=verify-full"),
        format!("POSTGRES://svc:a@{m}/x@127.0.0.1/mem"),
        format!("postgresql://svc:a@{m}/x@127.0.0.1/mem"),
        format!("https://svc:a@{m}\\x@127.0.0.1/mem"),
        format!("https://svc:\\{m}@127.0.0.1/mem"),
        format!("http:svc:a@{m}/x@127.0.0.1/mem"),
        format!("postgres:/svc:/{m}pw@127.0.0.1/mem"),
        format!("postgres:/\t/svc:/{m}pw@127.0.0.1/mem"),
    ]
}

/// #6100: a libpq key/value DSN whose password precedes a `://` option.
const KV_MARKER: &str = "SECRETKV6100";
fn kv_dsn() -> String {
    format!("host=db password={KV_MARKER} sslrootcert=file://ca")
}

fn assert_clean(sink: &str, what: &str, dsn: &str) {
    assert!(
        !sink
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase()),
        "#6096: credential bytes reached {what} for DSN shape {dsn:?}:\n{sink}"
    );
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("store-url-ambiguous-6096");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn run_bin(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (String, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "trace");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn ai-memory");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn display_renderer_redacts_every_ambiguous_shape_6096() {
    for dsn in ambiguous_dsns() {
        let r = ai_memory::url_display::store_url_display(&dsn);
        assert_clean(&r, "store_url_display", &dsn);
        assert!(r.ends_with("://<redacted-authority>"), "{dsn:?} -> {r:?}");
    }
}

#[test]
fn well_formed_dsn_still_names_the_host_6096() {
    let r = ai_memory::url_display::store_url_display(&format!(
        "postgres://svc:%2F{MARKER}pw@127.0.0.1:9/mem?sslmode=verify-full"
    ));
    assert_eq!(r, "postgres://127.0.0.1:9/mem");
}

#[test]
fn migrate_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("migrate");
    let src = dir.path().join("src.db");
    let _ = ai_memory::db::open(&src).expect("seed source");
    let from = format!("sqlite://{}", src.display());
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["migrate", "--from", &from, "--to", &dsn, "--json"],
            &[],
        );
        assert_clean(&out, "migrate --json stdout", &dsn);
        assert_clean(&err, "migrate stderr", &dsn);
    }
}

#[test]
fn schema_init_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("schema-init");
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["schema-init", "--store-url", &dsn, "--json"],
            &[],
        );
        assert_clean(&out, "schema-init --json stdout", &dsn);
        assert_clean(&err, "schema-init stderr", &dsn);
    }
}

#[test]
fn boot_conflict_refusal_carries_no_ambiguous_credential_6096() {
    let dir = scratch("conflict");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["--db", &db_s, "serve", "--store-url", &dsn, "--port", "0"],
            &[],
        );
        assert_clean(&out, "serve stdout", &dsn);
        assert_clean(&err, "serve stderr", &dsn);
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn doctor_sink_carries_no_ambiguous_credential_6096() {
    let dir = scratch("doctor");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for dsn in ambiguous_dsns() {
        let (out, err) = run_bin(
            dir.path(),
            &["--db", &db_s, "doctor"],
            &[("AI_MEMORY_STORE_URL", dsn.as_str())],
        );
        assert_clean(&out, "doctor stdout", &dsn);
        assert_clean(&err, "doctor stderr", &dsn);
        let (jout, jerr) = run_bin(
            dir.path(),
            &["--db", &db_s, "doctor", "--json"],
            &[("AI_MEMORY_STORE_URL", dsn.as_str())],
        );
        assert_clean(&jout, "doctor --json stdout", &dsn);
        assert_clean(&jerr, "doctor --json stderr", &dsn);
    }
}

/// The `FlooredConnectError` text (the `Parse` and `Refused` arms) is a
/// display sink too: it is what `PostgresStore::connect` surfaces.
#[cfg(feature = "sal-postgres")]
#[test]
fn floored_connect_error_carries_no_ambiguous_credential_6096() {
    for dsn in ambiguous_dsns() {
        match ai_memory::store::postgres::dsn::floored_connect_options(&dsn) {
            Ok(o) => panic!(
                "#6096: floor accepted ambiguous {dsn:?} host={}",
                o.get_host().len()
            ),
            Err(e) => assert_clean(&format!("{e} / {e:?}"), "FlooredConnectError", &dsn),
        }
    }
}

#[test]
fn kv_dsn_with_a_url_valued_option_is_never_echoed_6100() {
    let dsn = kv_dsn();
    let r = ai_memory::url_display::store_url_display(&dsn);
    assert!(!r.contains(KV_MARKER), "{r:?}");
    let dir = scratch("kv");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    for args in [
        vec!["schema-init", "--store-url", dsn.as_str(), "--json"],
        vec![
            "--db",
            db_s.as_str(),
            "serve",
            "--store-url",
            dsn.as_str(),
            "--port",
            "0",
        ],
    ] {
        let (out, err) = run_bin(dir.path(), &args, &[]);
        assert!(
            !out.contains(KV_MARKER) && !err.contains(KV_MARKER),
            "#6100: key/value DSN password reached {args:?}:\n{out}\n{err}"
        );
    }
}

/// F2: the transit floor refuses an ambiguous DSN before any connection or
/// DNS lookup; it never returns `Pinned` with a credential as the host.
#[test]
fn floor_refuses_every_ambiguous_dsn_6096() {
    use ai_memory::transit_encryption::{
        DsnTransport, SslmodeFloor, dsn_floor_verdict, dsn_transport,
    };
    for dsn in ambiguous_dsns() {
        // Only postgres-scheme DSNs reach the transport classifier as TCP.
        assert!(
            !matches!(dsn_transport(&dsn), DsnTransport::Tcp { .. }),
            "#6096: ambiguous DSN classified as TCP: {dsn:?}"
        );
        let verdict = dsn_floor_verdict(&dsn);
        assert!(
            matches!(
                verdict,
                SslmodeFloor::Unparseable | SslmodeFloor::UnixSocket { .. }
            ),
            "#6096: floor did not refuse {dsn:?}: {verdict:?}"
        );
        assert_clean(&format!("{verdict:?}"), "floor verdict", &dsn);
    }
}

/// #6102 (review item 1): `config show --effective` routed a case-variant
/// store scheme (`POSTGRES://`) to `url_origin`, which printed the
/// credential bytes of an ambiguous DSN. It must reach `store_url_display`.
#[test]
fn config_show_effective_redacts_a_case_variant_store_scheme_6102() {
    for scheme in ["POSTGRES", "Postgres", "postgres"] {
        let root = tempfile::tempdir().expect("tempdir");
        let keys = root.path().join("keys");
        key_dir_sandbox::mkdir_0700(&keys);
        let xdg = root.path().join("home/.config");
        let dir = xdg.join("ai-memory");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join("config.toml"),
            format!("schema_version = 2\ndb = \"{scheme}://svc:/{MARKER}pw@db.example/mem\"\n"),
        )
        .expect("write config");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", root.path().join("home"))
            .env("XDG_CONFIG_HOME", &xdg)
            .env("AI_MEMORY_KEY_DIR", keys)
            .env("AI_MEMORY_DB", root.path().join("store.db"))
            .env("AI_MEMORY_AUDIT_DIR", root.path().join("audit"))
            .env("RUST_LOG", "error")
            .args(["config", "show", "--effective"])
            .output()
            .expect("spawn");
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !text
                .to_ascii_lowercase()
                .contains(&MARKER.to_ascii_lowercase()),
            "#6102: {scheme}:// credential bytes reached `config show --effective`:\n{text}"
        );
        assert!(text.contains("<redacted-authority>"), "{scheme}: {text}");
    }
}
