// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3705 item 5 — PostgreSQL transport encryption is a FLOOR: a store DSN
//! that does not pin `sslmode=verify-full` is refused by the ONE connect
//! funnel BEFORE any socket is opened, with the remedy. Runs only with a
//! live database (`AI_MEMORY_TEST_POSTGRES_URL`, a FRESH `ai_memory_f2a_*`
//! db — never the operator's `ai_memory_test`); SKIP line otherwise.
//!
//! FAILS on the #3700 parent commit `4b7ddb963`: `sslmode` was consulted
//! only by the enterprise posture, so `connect` on a `sslmode=require` (or
//! sslmode-less) DSN opened a socket and either connected or failed with an
//! unrelated error — never `#3705`.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::time::{Duration, Instant};

use ai_memory::store::postgres::PostgresStore;

mod common;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";

fn pg_url() -> Option<String> {
    let url = std::env::var(PG_URL_ENV).ok();
    if url.is_none() {
        eprintln!("SKIP transit_encryption_3705_pg: {PG_URL_ENV} unset");
    }
    url
}

/// Rewrite the query string's `sslmode` (every occurrence, any case) to
/// `value`, or drop it entirely when `value` is `None`.
fn with_sslmode(url: &str, value: Option<&str>) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return match value {
            Some(v) => format!("{url}?sslmode={v}"),
            None => url.to_string(),
        };
    };
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter(|p| {
            !p.split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("sslmode"))
        })
        .map(str::to_string)
        .collect();
    if let Some(v) = value {
        pairs.push(format!("sslmode={v}"));
    }
    if pairs.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", pairs.join("&"))
    }
}

/// A DSN below the floor is refused before any socket is opened.
#[tokio::test(flavor = "multi_thread")]
async fn pg_dsn_without_verify_full_is_refused_before_connect_3705() {
    let Some(url) = pg_url() else { return };
    common::permissive_attestation_for_tests();
    for below in [
        with_sslmode(&url, Some("require")),
        with_sslmode(&url, None),
    ] {
        assert!(
            !below.to_ascii_lowercase().contains("sslmode=verify-full"),
            "fixture must be below the floor: {below}"
        );
        let started = Instant::now();
        let err = match PostgresStore::connect(&below).await {
            Ok(_) => panic!("#3705: a DSN without sslmode=verify-full must be refused"),
            Err(e) => e.to_string(),
        };
        let elapsed = started.elapsed();
        assert!(err.contains("#3705"), "{err}");
        assert!(err.contains("verify-full"), "{err}");
        assert!(
            err.contains("sslmode=verify-full&sslrootcert"),
            "the refusal must carry the remedy: {err}"
        );
        assert!(err.contains("`ai-memory db check-tls`"), "{err}");
        assert!(
            !err.contains("postgres://"),
            "the refusal must never echo the DSN: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "refused before connecting, not after a network round-trip: {elapsed:?}"
        );
    }
}

/// Positive control — the battery's `verify-full` DSN connects through the
/// same funnel.
#[tokio::test(flavor = "multi_thread")]
async fn pg_dsn_with_verify_full_connects_3705() {
    let Some(url) = pg_url() else { return };
    common::permissive_attestation_for_tests();
    assert!(
        url.to_ascii_lowercase().contains("sslmode=verify-full"),
        "the battery DSN must pin sslmode=verify-full"
    );
    let store = PostgresStore::connect(&url)
        .await
        .expect("a verify-full DSN connects");
    drop(store);
}

#[test]
fn with_sslmode_rewrites_every_occurrence_3705() {
    assert_eq!(
        with_sslmode("postgres://u@h/db?sslmode=verify-full&x=1", Some("require")),
        "postgres://u@h/db?x=1&sslmode=require"
    );
    assert_eq!(
        with_sslmode("postgres://u@h/db?sslmode=verify-full", None),
        "postgres://u@h/db"
    );
    assert_eq!(
        with_sslmode("postgres://u@h/db", Some("require")),
        "postgres://u@h/db?sslmode=require"
    );
}
