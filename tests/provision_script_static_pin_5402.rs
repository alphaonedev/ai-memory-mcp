// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Static pin for #5402 (PR 4810 round-4 security note): `scripts/postgres-droplet-reinit.sh`
//! must run `pg_dump` with `PGSSLMODE=verify-full` and a pinned local CA, and refuse (exit 7)
//! before the backup and the first DROP when that CA is not usable.

use std::path::PathBuf;
use std::process::{Command, Output};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read provisioning script {}: {e}", path.display()))
}

#[test]
fn reinit_pg_dump_pins_verify_full_and_refuses_before_the_backup_5402() {
    let script = read("scripts/postgres-droplet-reinit.sh");
    let code: Vec<(usize, &str)> = script
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#'))
        .collect();
    let dump_call = code
        .iter()
        .find(|(_, l)| l.contains("pg_dump -h \"$PG_HOST\""))
        .map(|(i, _)| *i)
        .expect("the live pg_dump call is present");
    let env_pin = script
        .lines()
        .nth(dump_call - 1)
        .expect("a line precedes the pg_dump call");
    assert!(
        env_pin.contains("PGSSLMODE=verify-full")
            && env_pin.contains("PGSSLROOTCERT=\"$PG_DUMP_SSLROOTCERT\""),
        "#5402: pg_dump must run with verify-full and the pinned CA: {env_pin}"
    );
    let check_call = code
        .iter()
        .find(|(_, l)| l.trim() == "require_dump_sslrootcert")
        .map(|(i, _)| *i)
        .expect("#5402: require_dump_sslrootcert is called in the preflight");
    assert!(
        check_call < dump_call,
        "#5402: the CA check must run before the backup"
    );
    let first_drop = code
        .iter()
        .find(|(_, l)| l.contains("psql_postgres -c \"DROP DATABASE"))
        .map(|(i, _)| *i)
        .expect("a DROP DATABASE statement is present");
    assert!(
        check_call < first_drop,
        "#5402: the CA check must run before the first DROP"
    );
}

/// Run the reinit script with `--dry-run` and a minimal valid environment plus `extra`.
/// No file is created: the password file is /dev/null and the CA paths are only
/// regex-checked in dry-run mode.
fn dry_run(extra: &[(&str, &str)]) -> Output {
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/postgres-droplet-reinit.sh");
    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .arg("--dry-run")
        .env_remove("AI_MEMORY_SSH_HOST")
        .env_remove("PG_DUMP_SSLROOTCERT")
        .env_remove("PG_PRIMARY_DB")
        .env("PG_PASSWORD_FILE", "/dev/null")
        .env("PG_SSLROOTCERT", "/nonexistent/ca.pem")
        .env("AI_MEMORY_BIN", "/bin/sh");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().expect("run bash on the reinit script")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// #5449: libpq ranks a connection string above PGSSLMODE/PGSSLROOTCERT, so a
/// PG_PRIMARY_DB that is a conninfo must be refused before anything runs.
#[test]
fn reinit_refuses_a_conninfo_primary_db_before_any_step_5449() {
    for bad in [
        "dbname=aimemory sslmode=disable",
        "aimemory sslmode=disable",
        "1aimemory",
        "ai memory",
        "aimemory;DROP",
        "service=evil",
    ] {
        let o = dry_run(&[("PG_PRIMARY_DB", bad)]);
        assert_eq!(
            o.status.code(),
            Some(7),
            "#5449: {bad:?} must exit 7: {}",
            stderr_of(&o)
        );
        assert!(
            stderr_of(&o).contains("PG_PRIMARY_DB must be a plain identifier"),
            "#5449: refusal text for {bad:?}: {}",
            stderr_of(&o)
        );
        assert!(
            !stdout_of(&o).contains("pg_dump"),
            "#5449: nothing may be planned for {bad:?}"
        );
    }
}

/// #5449: the verify-full pin and the CA travel IN the pg_dump connection string.
#[test]
fn reinit_pg_dump_pin_is_inside_the_connection_string_5449() {
    let o = dry_run(&[
        ("PG_PRIMARY_DB", "aimemory"),
        ("PG_DUMP_SSLROOTCERT", "/etc/ca/root.pem"),
    ]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "dry-run must pass: {}",
        stderr_of(&o)
    );
    let out = stdout_of(&o);
    assert!(
        out.contains("-d 'dbname=aimemory sslmode=verify-full sslrootcert=/etc/ca/root.pem'"),
        "#5449: the pin must be inside the -d connection string: {out}"
    );
}

/// #5449: the live call carries the pinned conninfo and unsets the service sources first.
#[test]
fn reinit_live_pg_dump_uses_pinned_conninfo_and_unsets_service_5449() {
    let script = read("scripts/postgres-droplet-reinit.sh");
    let code: Vec<&str> = script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let dump = code
        .iter()
        .position(|l| l.contains("pg_dump -h \"$PG_HOST\""))
        .expect("the live pg_dump call is present");
    let call = code[dump..dump + 3].join(" ");
    assert!(
        call.contains(
            "-d \"dbname=${PG_PRIMARY_DB} sslmode=verify-full sslrootcert=${PG_DUMP_SSLROOTCERT}\""
        ),
        "#5449: the live -d argument must carry the pin: {call}"
    );
    let unset = code
        .iter()
        .position(|l| l.trim() == "unset PGSERVICE PGSERVICEFILE")
        .expect("#5449: PGSERVICE and PGSERVICEFILE are unset before pg_dump");
    assert!(
        unset < dump,
        "#5449: the unset must precede the pg_dump call"
    );
    let ident = code
        .iter()
        .position(|l| l.trim() == "require_primary_db_identifier")
        .expect("#5449: the identifier check is called in the preflight");
    let password = code
        .iter()
        .position(|l| l.trim() == "require_password")
        .expect("require_password is called");
    assert!(
        ident < password && ident < dump,
        "#5449: the identifier check runs first"
    );
}
