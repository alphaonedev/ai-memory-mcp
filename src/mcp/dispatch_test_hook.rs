// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — doc-hidden test entry into the REAL `tools/call` dispatch
//! arm. Not part of the production wire surface (the production call site is
//! the stdio loop in `run_mcp_server`); it exists so `tests/` can drive the
//! dispatch-level authority chokepoint with the caller principal steered by
//! the #3523 thread-local seam, which `src/` may never arm.

use std::path::Path;

use serde_json::Value;

use super::{RpcRequest, handle_request};

/// Dispatch one JSON-RPC request through the real `handle_request` with the
/// minimal scaffold (keyword tier, full profile, no LLM / embedder /
/// keypair / hooks) and return the wire response as JSON.
///
/// # Panics
/// Panics when `request` is not a well-formed JSON-RPC request object or the
/// response cannot be serialised — both are test-fixture errors.
#[doc(hidden)]
#[must_use]
pub fn handle_request_for_test(
    conn: &rusqlite::Connection,
    db_path: &Path,
    request: &Value,
) -> Value {
    let req: RpcRequest =
        serde_json::from_value(request.clone()).expect("well-formed JSON-RPC request");
    let tier_config = crate::config::FeatureTier::Keyword.config();
    let resolved_models = crate::config::ResolvedModels::from_tier_preset(&tier_config);
    let resolved_ttl = crate::config::ResolvedTtl::default();
    let resolved_scoring = crate::config::ResolvedScoring::default();
    let profile = crate::profile::Profile::full();
    let resp = handle_request(
        conn,
        db_path,
        &req,
        None,
        None,
        None,
        &tier_config,
        &resolved_models,
        None,
        &resolved_ttl,
        &resolved_scoring,
        true,
        false,
        None,
        &profile,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        "dispatch-test-hook",
    );
    serde_json::to_value(resp).expect("serialisable JSON-RPC response")
}
