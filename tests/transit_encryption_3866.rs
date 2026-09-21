// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3866 — the PostgreSQL DSN transit floor is a TRANSPORT decision,
//! not a query-string scan. A DSN whose transport is a Unix-domain socket
//! (`host=/…`, or an empty authority with no `host`/`hostaddr` parameter —
//! libpq's default socket directory) cannot satisfy `sslmode=verify-full`
//! by naming it: TLS does not run on a socket. Measured on the tip before
//! this change: sqlx refused the issue's DSN at connect with the opaque
//! "server does not support TLS", the floor predicate said `true`, and
//! doctor / posture check #15 rendered the floor as pinned for a
//! configuration the daemon cannot open. These pins hold the honest
//! reading: the predicate is false on a socket transport, and the connect
//! funnel refuses BY NAME before any socket is dialled — no live database
//! is needed for any test here. The in-kernel-IPC widening (accepting a
//! socket as encrypted-by-locality) is DEFERRED to v1.0.x together with
//! #3827; nothing here decides it.
//!
//! `sal-postgres`-gated: under default features this file compiles to zero
//! tests, so run it with `--features sal-postgres` and read the count.
#![cfg(feature = "sal-postgres")]

use ai_memory::store::PoolConfig;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::transit_encryption;

/// The DSN from the issue, verbatim.
const ISSUE_DSN: &str = "postgres:///mem?host=/var/run/postgresql&sslmode=verify-full";

/// The floor predicate the funnel, doctor and posture check #15 share must
/// be FALSE for a socket transport, whatever the query string says, and
/// stay TRUE for the TCP shape it was written for.
#[test]
fn socket_dsn_does_not_pin_the_floor_3866() {
    assert!(
        !transit_encryption::dsn_pins_sslmode_verify_full(ISSUE_DSN),
        "a Unix-socket DSN cannot satisfy a TLS floor by query parameter"
    );
    for socket in [
        "postgres:///mem?host=/var/run/postgresql&sslmode=verify-full",
        "postgres:///mem?sslmode=verify-full",
        "postgres:///mem?host=h&host=/tmp&sslmode=verify-full",
        "postgresql:///mem?host=%2Fvar%2Frun%2Fpostgresql&sslmode=verify-full",
    ] {
        assert!(
            !transit_encryption::dsn_pins_sslmode_verify_full(socket),
            "{socket}: socket transport must not pin the floor"
        );
    }
    for tcp in [
        "postgres://u@h/db?sslmode=verify-full",
        "postgres://u@h:5432/db?application_name=x&sslmode=Verify-Full&sslrootcert=/ca.crt",
        "postgres:///mem?host=db.example&sslmode=verify-full",
        "postgres:///mem?host=/tmp&host=db.example&sslmode=verify-full",
        "postgres:///mem?hostaddr=10.0.0.5&sslmode=verify-full",
    ] {
        assert!(
            transit_encryption::dsn_pins_sslmode_verify_full(tcp),
            "{tcp}: TCP transport with verify-full pins the floor"
        );
    }
    assert!(!transit_encryption::dsn_pins_sslmode_verify_full(
        "postgres://u@h/db?sslmode=require"
    ));
}

/// The connect funnel must refuse the issue's DSN BY NAME — the transport is
/// a Unix-domain socket — before any socket is dialled, instead of letting
/// the driver surface "server does not support TLS" (or, with no server
/// listening, a connection error) as the operator's only signal.
#[tokio::test]
async fn funnel_refuses_a_socket_dsn_by_name_3866() {
    for dsn in [
        ISSUE_DSN,
        "postgres:///mem?sslmode=verify-full",
        "postgres:///mem?host=/nonexistent-3866&sslmode=disable",
    ] {
        let err = PostgresStore::connect_with_dim_and_timeout(dsn, 384, 30, PoolConfig::default())
            .await
            .err()
            .expect("a socket DSN must not connect");
        let msg = err.to_string();
        assert!(
            msg.contains("Unix-domain socket"),
            "{dsn}: the refusal must name the transport: {msg}"
        );
        assert!(
            msg.contains("#3705"),
            "{dsn}: the refusal carries the transit-floor tag: {msg}"
        );
        assert!(
            !msg.contains("server does not support TLS") && !msg.contains("No such file"),
            "{dsn}: the driver's error must not be the operator's signal: {msg}"
        );
        assert!(
            !msg.contains("mem?"),
            "{dsn}: the refusal never echoes the DSN: {msg}"
        );
    }
}

/// Nothing that connects today stops connecting: a TCP DSN that pins the
/// floor passes the floor (and then fails on the network, which is the
/// driver's business, not the floor's).
#[tokio::test]
async fn tcp_verify_full_dsn_passes_the_floor_3866() {
    let err = PostgresStore::connect_with_dim_and_timeout(
        "postgres://u:p@127.0.0.1:1/db?sslmode=verify-full&sslrootcert=/nonexistent-3866.crt",
        384,
        1,
        PoolConfig::default(),
    )
    .await
    .err()
    .expect("port 1 is closed");
    let msg = err.to_string();
    assert!(
        !msg.contains("Unix-domain socket") && !msg.contains("does not pin"),
        "a pinned TCP DSN must get past the floor: {msg}"
    );
}
