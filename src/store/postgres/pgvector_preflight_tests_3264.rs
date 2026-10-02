// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3264 — pgvector preflight decision-table unit tests, moved out of
//! `postgres.rs` (QUAL-10 headroom; behaviour-neutral).

use super::{
    PG_SQLSTATE_FEATURE_NOT_SUPPORTED, PG_SQLSTATE_INSUFFICIENT_PRIVILEGE, PgvectorPreflight,
    PgvectorPreflightFacts, classify_init_sql_error, classify_pgvector_preflight,
    render_database_for_operator,
};

/// The full 2^3 decision table, enumerated. `installed` wins outright:
/// an already-installed extension makes the bootstrap
/// `CREATE EXTENSION IF NOT EXISTS` privilege-free for ANY role, which
/// is exactly the supported managed-Postgres remedy.
#[test]
fn decision_table_is_exhaustive_and_installed_wins() {
    for rolsuper in [false, true] {
        for available in [false, true] {
            assert_eq!(
                classify_pgvector_preflight(available, true, rolsuper),
                PgvectorPreflight::Installed,
                "installed must win (available={available}, rolsuper={rolsuper})"
            );
        }
    }
    // Not installed, not available -> the #1065 image case, whatever
    // the role is: a superuser cannot create what the server does not
    // ship.
    assert_eq!(
        classify_pgvector_preflight(false, false, false),
        PgvectorPreflight::NotAvailableOnServer
    );
    assert_eq!(
        classify_pgvector_preflight(false, false, true),
        PgvectorPreflight::NotAvailableOnServer
    );
    // Available, not installed -> the role's superuser bit decides,
    // because pgvector is not a TRUSTED extension.
    assert_eq!(
        classify_pgvector_preflight(true, false, false),
        PgvectorPreflight::AvailableNeedsSuperuserCreate
    );
    assert_eq!(
        classify_pgvector_preflight(true, false, true),
        PgvectorPreflight::AvailableCreatableProceed
    );
}

/// Exactly the two FAULT classes carry a classified detail, and each
/// one names its remedy. The two healthy classes carry none — that is
/// what keeps the happy path byte-identical to the pre-#3264 bootstrap.
#[test]
fn only_the_two_fault_classes_carry_a_classified_detail() {
    assert!(
        PgvectorPreflight::Installed
            .classified_detail("db")
            .is_none()
    );
    assert!(
        PgvectorPreflight::AvailableCreatableProceed
            .classified_detail("db")
            .is_none()
    );

    let not_available = PgvectorPreflight::NotAvailableOnServer
        .classified_detail("aimemory")
        .expect("fault class must carry a detail");
    assert!(
        not_available.contains("0A000"),
        "must name the SQLSTATE: {not_available}"
    );
    assert!(
        not_available.contains("Dockerfile.pg-age-vector"),
        "must name the shipped remedy image: {not_available}"
    );
    assert!(
        not_available.contains("#1065"),
        "must cite the documented-unsupported case: {not_available}"
    );

    let needs_su = PgvectorPreflight::AvailableNeedsSuperuserCreate
        .classified_detail("aimemory")
        .expect("fault class must carry a detail");
    assert!(
        needs_su.contains("42501"),
        "must name the SQLSTATE: {needs_su}"
    );
    assert!(
        needs_su.contains("CREATE EXTENSION vector;"),
        "must name the one-time superuser command: {needs_su}"
    );
    assert!(
        needs_su.contains("postInitApplicationSQL"),
        "must name the CloudNativePG hook: {needs_su}"
    );
    assert!(
        needs_su.contains("rds_superuser"),
        "must name the RDS / Aurora path: {needs_su}"
    );
}

/// `{DATABASE}` is substituted everywhere it appears — the operator is
/// told the exact database to run the one-time create in, with no
/// placeholder left over.
#[test]
fn database_placeholder_is_substituted_everywhere() {
    let detail = PgvectorPreflight::AvailableNeedsSuperuserCreate
        .classified_detail("prod_mem")
        .expect("fault class must carry a detail");
    assert!(
        !detail.contains("{DATABASE}"),
        "placeholder left in: {detail}"
    );
    assert!(
        detail.matches("prod_mem").count() >= 3,
        "every placeholder site must be substituted: {detail}"
    );
}

/// The SQLSTATE mapping requires CORROBORATION. `42501` is NOT
/// pgvector-specific — on PG15+ a role without `CREATE` on schema
/// `public` gets the same code from `CREATE TABLE` — so when the
/// preflight says pgvector is fine, the opaque driver error is kept
/// rather than emitting a WRONG diagnosis.
#[test]
fn sqlstate_mapping_requires_corroboration() {
    // No preflight (probe failed, or the schema-AHEAD hatch skipped
    // it): the SQLSTATE is the only evidence there is.
    assert_eq!(
        classify_init_sql_error(Some(PG_SQLSTATE_INSUFFICIENT_PRIVILEGE), None),
        Some(PgvectorPreflight::AvailableNeedsSuperuserCreate)
    );
    assert_eq!(
        classify_init_sql_error(Some(PG_SQLSTATE_FEATURE_NOT_SUPPORTED), None),
        Some(PgvectorPreflight::NotAvailableOnServer)
    );
    // Preflight corroborates.
    assert_eq!(
        classify_init_sql_error(
            Some(PG_SQLSTATE_INSUFFICIENT_PRIVILEGE),
            Some(PgvectorPreflight::AvailableNeedsSuperuserCreate)
        ),
        Some(PgvectorPreflight::AvailableNeedsSuperuserCreate)
    );
    // Preflight CONTRADICTS -> stay opaque.
    for observed in [
        PgvectorPreflight::Installed,
        PgvectorPreflight::AvailableCreatableProceed,
        PgvectorPreflight::NotAvailableOnServer,
    ] {
        assert_eq!(
            classify_init_sql_error(Some(PG_SQLSTATE_INSUFFICIENT_PRIVILEGE), Some(observed)),
            None,
            "42501 with preflight {observed:?} is a different privilege fault"
        );
    }
    // Anything else keeps the historical opaque `init schema: {e}`.
    assert_eq!(classify_init_sql_error(Some("42P07"), None), None);
    assert_eq!(classify_init_sql_error(None, None), None);
    assert_eq!(
        classify_init_sql_error(None, Some(PgvectorPreflight::AvailableNeedsSuperuserCreate)),
        None,
        "a driverless error must never be classified from the preflight alone"
    );
}

/// #3264 review fix (B1) — ONLY the `0A000` class refuses bootstrap
/// before the DDL runs.
///
/// `pg_roles.rolsuper` is not the privilege oracle on managed
/// PostgreSQL (RDS `rds_superuser`, Cloud SQL `cloudsqlsuperuser`,
/// Azure `azure_pg_admin` all create extensions without it), so a
/// preemptive refusal on `AvailableNeedsSuperuserCreate` would
/// fail-close a fresh managed deployment that boots fine. That verdict
/// still CARRIES its classified detail — rendered only once the real
/// `CREATE EXTENSION` has actually returned `42501`.
#[test]
fn only_the_0a000_class_refuses_before_the_ddl_runs() {
    assert!(
        PgvectorPreflight::NotAvailableOnServer
            .preemptive_refusal_detail("aimemory")
            .is_some_and(|d| d.contains("0A000")),
        "the no-vector.so image must still refuse preemptively"
    );
    for proceeding in [
        PgvectorPreflight::Installed,
        PgvectorPreflight::AvailableCreatableProceed,
        PgvectorPreflight::AvailableNeedsSuperuserCreate,
    ] {
        assert_eq!(
            proceeding.preemptive_refusal_detail("aimemory"),
            None,
            "{proceeding:?} must let the real CREATE EXTENSION be the gate"
        );
    }
    // The 42501 remedy is intact for the SQLSTATE path that DOES fire.
    assert!(
        PgvectorPreflight::AvailableNeedsSuperuserCreate
            .classified_detail("aimemory")
            .is_some_and(|d| d.contains("42501")),
        "the classified 42501 remedy must survive the non-preemptive shape"
    );
}

/// #3264 review fix (S1) — a server-supplied `current_database()` is
/// escaped before it reaches the pasteable `psql` remedy and the log
/// lines. A quote, a semicolon, a newline or an ANSI escape in a
/// database name must not break out of the superuser one-liner the
/// operator is invited to paste.
#[test]
fn database_name_is_escaped_before_it_reaches_an_operator() {
    for plain in ["aimemory", "prod_mem_2", "A1", "<unknown>"] {
        assert_eq!(
            render_database_for_operator(plain),
            plain,
            "a legitimate name must reach the operator verbatim"
        );
    }
    let hostile = "mem'; DROP DATABASE mem; --\n\u{1b}[31mFORGED";
    let rendered = render_database_for_operator(hostile);
    assert!(
        !rendered.contains('\n') && !rendered.contains('\u{1b}'),
        "control characters must be escaped: {rendered}"
    );
    let detail = PgvectorPreflight::AvailableNeedsSuperuserCreate
        .classified_detail(hostile)
        .expect("fault class must carry a detail");
    assert!(
        !detail.contains('\n') && !detail.contains('\u{1b}'),
        "the pasteable remedy must carry no injected control characters: {detail}"
    );
    // An empty name is not "plain" either — it would silently produce
    // `psql -d  -c ...`, which targets the wrong database.
    assert_eq!(render_database_for_operator(""), "\"\"");
}

/// `PgvectorPreflightFacts::verdict` is the same pure table — the
/// live probe adds no second decision path.
#[test]
fn facts_verdict_matches_the_pure_table() {
    let facts = PgvectorPreflightFacts {
        available: true,
        installed: false,
        role_is_superuser: false,
        age_catalog_usage: false,
        database: "aimemory".to_string(),
    };
    assert_eq!(
        facts.verdict(),
        PgvectorPreflight::AvailableNeedsSuperuserCreate
    );
    assert_eq!(facts.verdict().label(), "available_needs_superuser_create");
}
