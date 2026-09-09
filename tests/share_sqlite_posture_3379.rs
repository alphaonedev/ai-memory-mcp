// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3379: a future PostgreSQL share dispatch must revisit source authorization.

#[test]
fn share_cli_refuses_postgres_before_opening_sqlite_3379() {
    let source = include_str!("../src/cli/share.rs");
    let dispatch = source
        .split_once("pub fn cmd_share(")
        .expect("CLI share entry point")
        .1;
    let refusal = dispatch
        .find("crate::cli::backup::refuse_pg_store(db_path, \"share\", out)?")
        .expect("share must refuse a PostgreSQL store URL");
    let open = dispatch.find("db::open(").expect("SQLite open");
    assert!(refusal < open, "refuse PostgreSQL before opening SQLite");
}
