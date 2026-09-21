// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! #3573: fail-closed, engine-executed differential certification.
use std::{cell::RefCell, future::Future};

use sqlx::{Acquire, Execute, Postgres, Row, postgres::PgArguments};

mod fixture_tests;
mod inventory;
mod matrix;

#[derive(Debug)]
struct Plan {
    site: &'static str,
    sql: String,
    plan: serde_json::Value,
}

tokio::task_local! {
    static PLANS: RefCell<Vec<Plan>>;
}

// Scoped to the future, so unrelated concurrent tests cannot lend evidence.
async fn capture<T>(future: impl Future<Output = T>) -> (T, Vec<Plan>) {
    PLANS
        .scope(RefCell::new(Vec::new()), async {
            let result = future.await;
            (result, PLANS.with(|plans| plans.take()))
        })
        .await
}

pub(super) async fn fetch<'q>(
    mut query: sqlx::query::Query<'q, Postgres, PgArguments>,
    connection: &mut sqlx::PgConnection,
    site: &'static str,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    if PLANS.try_with(|_| ()).is_err() {
        return query.fetch_all(&mut *connection).await;
    }
    let sql = query.sql().to_owned();
    let args = query
        .take_arguments()
        .map_err(sqlx::Error::Encode)?
        .unwrap_or_default();
    // ANALYZE really executes writes too. A nested transaction rolls back
    // ONLY the measurement before the original statement executes once.
    let mut measurement = connection.begin().await?;
    let explain = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}");
    let row = sqlx::query_with(&explain, args.clone())
        .persistent(false)
        .fetch_one(&mut *measurement)
        .await?;
    let plan = row.try_get(0)?;
    measurement.rollback().await?;
    let rows = sqlx::query_with(&sql, args)
        .persistent(false)
        .fetch_all(&mut *connection)
        .await?;
    PLANS.with(|plans| plans.borrow_mut().push(Plan { site, sql, plan }));
    Ok(rows)
}

fn evidence(cell: &str, plans: &[Plan], required: &[&str]) {
    assert!(!plans.is_empty(), "{cell}: no executed plans");
    for site in required {
        assert!(
            plans.iter().any(|plan| plan.site == *site),
            "{cell}: missing {site}"
        );
    }
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/graph-conformance");
    std::fs::create_dir_all(&directory).expect("create plan directory");
    let mut output = String::new();
    for plan in plans {
        assert!(
            plan.plan[0]["Plan"]["Actual Loops"]
                .as_u64()
                .is_some_and(|n| n > 0),
            "{cell}: EXPLAIN was not executed"
        );
        if plan.site.starts_with("age/") {
            assert!(
                plan.sql.contains("cypher("),
                "{cell}: AGE label on relational SQL"
            );
        } else {
            assert!(
                !plan.sql.contains("cypher("),
                "{cell}: relational label on AGE SQL"
            );
        }
        output.push_str(&format!("PLAN {cell} {} {}\n", plan.site, plan.plan));
    }
    // Cell names are compile-time fixture labels, never user paths. No SQL
    // binds, connection strings, or caller data are written by this observer.
    std::fs::write(directory.join(format!("{cell}.jsonl")), output)
        .expect("persist executed plans");
    eprintln!("GRAPH_CELL {cell} plans={}", plans.len());
}
