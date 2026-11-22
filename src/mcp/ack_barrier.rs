// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9864 — the acknowledgement barrier on the `mcp` stdio loop: a reply to a
//! request that can mutate leaves only once the forensic audit rows queued
//! before it are durable ([`crate::governance::audit::wait_durable`]). The
//! only way to build a [`Reply`] for such a request is [`settle`], which either
//! holds the [`AuditDurable`] proof or replaces the reply with the named
//! refusal ([`jsonrpc::AUDIT_NOT_DURABLE`]), so a success reply without the
//! proof cannot be written.
//!
//! decision: the barrier on every reply of a non-read-only tool call, the
//! handler's own error replies included, over success replies only, because a
//! refusal also writes a forensic row.
//!
//! Known limit: on a barrier timeout the mutation may already be committed,
//! so the guarantee is "acknowledged implies row", not "mutated implies row";
//! K-2 (the refusal says the mutation may have been applied, and a retry
//! creates no second memory or link) and K-4 (the row stays queued and is
//! written once the writer recovers) bound that window.

use super::{RpcRequest, RpcResponse, err_response, jsonrpc};
use crate::governance::audit::{self, AckMark, AuditDurable};

/// The JSON-RPC methods that never mutate (a `tools/call` is judged by its
/// tool name). Every other method waits, an unknown one included.
const NON_MUTATING_METHODS: [&str; 7] = [
    jsonrpc::METHOD_INITIALIZE,
    jsonrpc::METHOD_PING,
    jsonrpc::METHOD_TOOLS_LIST,
    jsonrpc::METHOD_PROMPTS_LIST,
    jsonrpc::METHOD_PROMPTS_GET,
    jsonrpc::METHOD_RESOURCES_LIST,
    jsonrpc::METHOD_RESOURCES_READ,
];

/// Whether a reply to `req` must wait for its audit rows. Fail closed: a
/// `tools/call` without a string name, or with a name outside the read-only
/// table, waits.
pub(super) fn must_wait(req: &RpcRequest) -> bool {
    if req.method == jsonrpc::METHOD_TOOLS_CALL {
        return !req.params["name"]
            .as_str()
            .is_some_and(super::read_only_tools::mcp_tool_is_read_only);
    }
    !NON_MUTATING_METHODS.contains(&req.method.as_str())
}

/// Taken before the request runs.
#[must_use]
pub(super) enum Pending {
    /// A read-only request: its reply never waits (K-5).
    ReadOnly,
    /// The ledger position before the request ran.
    Wait(AckMark),
}

#[must_use]
pub(super) fn begin(req: &RpcRequest) -> Pending {
    if must_wait(req) {
        Pending::Wait(audit::ack_mark())
    } else {
        Pending::ReadOnly
    }
}

/// A reply that may be written. Its field is private: it is built only by
/// [`settle`], by [`Reply::durable`] (which needs the proof) or by
/// [`Reply::error`] (which never carries a success).
pub(super) struct Reply(RpcResponse);

impl Reply {
    /// An acknowledgement of a request whose audit rows are durable.
    fn durable(resp: RpcResponse, _proof: AuditDurable) -> Self {
        Self(resp)
    }

    /// An error reply that ran no request (parse errors, oversize lines). A
    /// response that is not an error is refused instead of written as a
    /// success.
    pub(super) fn error(resp: RpcResponse) -> Self {
        if resp.error.is_some() {
            return Self(resp);
        }
        Self(err_response(
            resp.id,
            jsonrpc::INTERNAL_ERROR,
            "internal error: a reply without a request was not an error (#9864)".to_string(),
        ))
    }

    pub(super) fn response(&self) -> &RpcResponse {
        &self.0
    }
}

/// Wait for the request's audit rows (when it can mutate) and give the reply
/// that may be written: the handler's reply with the proof, or the named
/// refusal in its place.
pub(super) fn settle(pending: Pending, resp: RpcResponse) -> Reply {
    match pending {
        Pending::ReadOnly => Reply(resp),
        Pending::Wait(mark) => match audit::wait_durable(mark) {
            Ok(proof) => Reply::durable(resp, proof),
            Err(e) => Reply(err_response(
                resp.id,
                jsonrpc::AUDIT_NOT_DURABLE,
                e.to_string(),
            )),
        },
    }
}
