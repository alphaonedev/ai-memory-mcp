// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Receipt decoration shared by the explicitly covered HTTP write funnels.

use anyhow::{Context as _, Result};
use axum::{
    Json,
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};

use super::AppState;
use crate::write_receipt::WriteDurability;

/// The connection used by a SQLite funnel; PostgreSQL always uses SAL.
#[derive(Debug, Clone, Copy)]
pub(super) enum WriterConnection {
    Legacy,
    Store,
}

/// Attach local evidence after the handler releases its connection lock.
/// Quorum evidence, when present, was emitted by that operation's fanout.
pub(super) async fn complete(
    app: &AppState,
    response: Response,
    writer: WriterConnection,
) -> Response {
    if !response.status().is_success() {
        return response;
    }
    match decorate(app, response, writer).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "write receipt durability observation failed");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "durability receipt unavailable; write may have completed"})),
            )
                .into_response()
        }
    }
}

async fn decorate(
    app: &AppState,
    response: Response,
    writer: WriterConnection,
) -> Result<Response> {
    let (mut parts, body) = response.into_parts();
    // These are handler-produced finite JSON bodies, not request streams.
    let bytes = axum::body::to_bytes(body, usize::MAX).await?;
    let mut receipt: Value = serde_json::from_slice(&bytes)?;
    let mut durability = local(app, writer).await?;
    if let (Some(acks), Some(n), Some(required)) = (
        receipt.get("quorum_acks").and_then(Value::as_u64),
        receipt.get("quorum_n").and_then(Value::as_u64),
        receipt.get("quorum_required").and_then(Value::as_u64),
    ) {
        let backup = std::env::var(crate::write_receipt::BACKUP_ATTESTATION_ENV)
            .is_ok_and(|value| value == "attested");
        durability = durability.with_quorum(
            usize::try_from(required)?,
            usize::try_from(acks)?,
            usize::try_from(n)?,
            backup,
        )?;
    }
    durability.attach(&mut receipt)?;
    let body = serde_json::to_vec(&receipt)?;
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, axum::body::Body::from(body)))
}

async fn local(app: &AppState, writer: WriterConnection) -> Result<WriteDurability> {
    let _ = writer;
    #[cfg(feature = "sal")]
    if matches!(writer, WriterConnection::Store)
        || app.storage_backend == super::StorageBackend::Postgres
    {
        return app
            .store
            .write_durability()
            .await
            .context("read active store durability");
    }
    // A sal-only build must never observe PostgreSQL's SQLite sidecar.
    anyhow::ensure!(
        app.storage_backend == super::StorageBackend::Sqlite,
        "active backend durability is unavailable"
    );
    let db = app.db.lock().await;
    WriteDurability::sqlite(&db.0).context("read active SQLite durability")
}
