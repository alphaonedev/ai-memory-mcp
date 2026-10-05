// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Static pin for #5402 (PR 4810 round-4 security note): `scripts/postgres-droplet-reinit.sh`
//! must run `pg_dump` with `PGSSLMODE=verify-full` and a pinned local CA, and refuse (exit 7)
//! before the backup and the first DROP when that CA is not usable.

use std::path::PathBuf;

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
