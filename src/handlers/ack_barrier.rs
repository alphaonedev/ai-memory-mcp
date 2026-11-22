// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9864 — the acknowledgement barrier on `serve`: a response to a request
//! that can mutate leaves only once the forensic audit rows queued before it
//! are durable, or it is replaced by the named refusal (`503`, body
//! `{"error": "audit row not durable: ..."}`).
//!
//! Which requests wait: every request but `GET`, `HEAD` and `OPTIONS` and the
//! `POST` routes in [`READ_ONLY_POST_ROUTES`] (reads that take a JSON body).
//! A route outside that table waits, a new one included (fail closed).
//!
//! decision: a method plus route table over attributing rows to the request
//! (a task-local) because the store calls run on `spawn_blocking` threads,
//! which do not carry task-locals.
//!
//! The wait runs on the blocking pool ([`wait_off_worker`]), never on an async
//! worker thread, so N concurrent writes park N blocking threads on one
//! condition variable and the writer thread settles them with one sync.
//!
//! Known limit: on a barrier timeout the mutation may already be committed,
//! so the guarantee is "acknowledged implies row", not "mutated implies row";
//! K-2 (the refusal says the mutation may have been applied, and a retry
//! creates no second memory or link) and K-4 (the row stays queued and is
//! written once the writer recovers) bound that window.

use axum::Json;
use axum::extract::{MatchedPath, Request};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::time::Duration;

use crate::governance::audit::ack_barrier::{LEDGER, Ledger, ack_barrier_deadline};
use crate::governance::audit::{AckBarrierError, AckMark, AuditDurable};
use crate::handlers::routes as r;

/// The `POST` routes that never mutate. Written by hand; a route that is not
/// here waits.
pub const READ_ONLY_POST_ROUTES: [&str; 19] = [
    r::RECALL,
    r::EXPAND_QUERY,
    r::MEMORY_LOAD_FAMILY,
    r::CHECK_DUPLICATE,
    r::KG_QUERY,
    r::KG_FIND_PATHS,
    r::FIND_PATHS,
    r::LINKS_VERIFY,
    r::QUOTA_STATUS,
    r::MEMORY_SMART_LOAD,
    r::MEMORY_RECALL_OBSERVATIONS,
    r::MEMORY_REFLECTION_ORIGIN,
    r::MEMORY_DEPENDENTS_OF_INVALIDATED,
    r::MEMORY_EXPORT_REFLECTION,
    r::MEMORY_VERIFY,
    r::MEMORY_REPLAY,
    r::MEMORY_SUBSCRIPTION_DLQ_LIST,
    r::MEMORY_RULE_LIST,
    r::MEMORY_CHECK_AGENT_ACTION,
];

/// The HTTP status of the refusal.
pub const AUDIT_NOT_DURABLE_STATUS: StatusCode = StatusCode::SERVICE_UNAVAILABLE;

/// Whether a response to `method` on the matched `route` must wait.
#[must_use]
pub fn must_wait(method: &Method, route: Option<&str>) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    !(*method == Method::POST && route.is_some_and(|p| READ_ONLY_POST_ROUTES.contains(&p)))
}

/// The middleware: mark, run the request, wait, then answer.
pub async fn ack_barrier_layer(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    if !must_wait(req.method(), route) {
        return next.run(req).await;
    }
    let mark = LEDGER.mark();
    let resp = next.run(req).await;
    match wait_off_worker(&LEDGER, mark, ack_barrier_deadline()).await {
        Ok(proof) => durable(resp, proof),
        Err(e) => refusal(&e),
    }
}

/// A response whose audit rows are durable (the proof is required).
fn durable(resp: Response, _proof: AuditDurable) -> Response {
    resp
}

fn refusal(e: &AckBarrierError) -> Response {
    let body = serde_json::json!({ "error": e.to_string() });
    (AUDIT_NOT_DURABLE_STATUS, Json(body)).into_response()
}

/// Wait on the blocking pool. A wait that could not run (the pool shut down,
/// or the wait panicked) is a refusal at the deadline, counted like one.
pub(crate) async fn wait_off_worker(
    ledger: &'static Ledger,
    mark: AckMark,
    deadline: Duration,
) -> Result<AuditDurable, AckBarrierError> {
    match tokio::task::spawn_blocking(move || ledger.wait(mark, deadline)).await {
        Ok(outcome) => outcome,
        Err(_join) => {
            crate::metrics::inc_forensic_sink_unavailable();
            Err(AckBarrierError::NotDurable {
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_count() {}

    /// K-5 and the fail-closed default, row by row.
    #[test]
    fn only_safe_methods_and_read_only_post_routes_skip_the_wait_9864() {
        let rows: [(Method, Option<&str>, bool); 9] = [
            (Method::GET, Some(r::MEMORIES), false),
            (Method::HEAD, Some(r::HEALTH), false),
            (Method::OPTIONS, None, false),
            (Method::POST, Some(r::RECALL), false),
            (Method::POST, Some(r::MEMORY_CHECK_AGENT_ACTION), false),
            (Method::POST, Some(r::MEMORIES), true),
            (Method::PUT, Some(r::RECALL), true),
            (Method::DELETE, Some(r::LINKS), true),
            (Method::POST, None, true),
        ];
        for (method, route, want) in rows {
            assert_eq!(must_wait(&method, route), want, "{method} {route:?}");
        }
    }

    /// K-6: the wait runs off the async worker. On a current-thread runtime
    /// an inline wait would block the only worker, so the settling task could
    /// not run and the wait would time out. Red when the wait runs inline.
    #[test]
    fn the_serve_wait_runs_off_the_async_worker_9864() {
        let ledger: &'static Ledger = Box::leak(Box::new(Ledger::new(no_count)));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = rt.block_on(async move {
            let mark = ledger.mark();
            let mut seq = 0;
            ledger
                .enqueue(|s| {
                    seq = s;
                    Ok(())
                })
                .expect("enqueue");
            let waiter = tokio::spawn(wait_off_worker(ledger, mark, Duration::from_secs(2)));
            tokio::task::yield_now().await;
            ledger.settle(seq, &[]);
            waiter.await.expect("join").map(drop)
        });
        assert_eq!(outcome, Ok(()));
    }
}
