// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3713 — the ONE place an error becomes text an MCP caller sees.
//!
//! The MCP dispatcher collapses every tool error into
//! `{"content":[{"type":"text","text": <String>}], "isError": true}` — a
//! deliberate, spec-load-bearing collapse (see `handle_request`), so the
//! funnel's return type is `String`, not an HTTP envelope. Before this
//! module, 237 sites under `src/mcp` built that string from a driver's /
//! `std::io`'s / a provider's / an `anyhow` chain's `Display` — SQL text
//! with table and column names, the operator's resolved filesystem path,
//! the LLM's failure body — and any MCP tenant received it verbatim.
//!
//! Three properties, none optional (the #3713 ruling):
//!
//! 1. **Closed vocabulary.** [`mcp_error_text`] renders from the
//!    [`MemoryError`] VARIANT plus constants. A foreign-class variant
//!    (`DatabaseError` / `Filesystem` / `Codec`) renders one of the
//!    `*_TEXT` constants below; its payload never enters the return value.
//! 2. **The detail still exists, for the operator.** [`log_foreign`] is the
//!    conversion, and the conversion OWNS the log line: a site cannot route
//!    an error through this module and forget the operator log, because
//!    there is no entry point that converts without logging. The two
//!    audiences are separated deliberately — the operator reading the log
//!    sees the driver text and the site's `context`; the caller sees the
//!    class.
//! 3. **Errors that are already a closed vocabulary pass through
//!    unchanged.** A refusal, a quota, a not-found, a governance verdict is
//!    OUR text and is what the caller needs; flattening it to a constant
//!    would trade a leak we do not have for a support ticket we would.
//!
//! No `From<String>` exists on [`MemoryError`], so a `format!("… {e}")`
//! cannot be smuggled through the typed conversion; a site that constructs
//! an own-vocabulary variant from foreign text is what gate 7
//! (`scripts/check-foreign-text-to-caller.py`) polices at the construction.

use crate::errors::MemoryError;

/// Rendered to the caller for every `MemoryError::DatabaseError`.
pub const DB_ERROR_TEXT: &str = "internal storage error";
/// Rendered to the caller for every `MemoryError::Filesystem`.
pub const FILESYSTEM_ERROR_TEXT: &str = "filesystem operation failed";
/// Rendered to the caller for every `MemoryError::Codec`.
pub const CODEC_ERROR_TEXT: &str = "encoding operation failed";

/// The `tracing` target every foreign detail is logged under, so an operator
/// can filter the OPERATOR-ONLY channel by name.
pub const TRACE_TARGET: &str = "mcp.tool.error";

/// Render a typed error as the text an MCP caller may see.
///
/// Own-vocabulary variants return their [`MemoryError::message`] verbatim
/// (property 3). Foreign-class variants return the matching constant
/// (property 1) — the payload is not masked or redacted, it is simply never
/// read here.
#[must_use]
pub fn mcp_error_text(e: &MemoryError) -> String {
    match e {
        MemoryError::DatabaseError(_) => DB_ERROR_TEXT.to_owned(),
        MemoryError::Filesystem(_) => FILESYSTEM_ERROR_TEXT.to_owned(),
        MemoryError::Codec(_) => CODEC_ERROR_TEXT.to_owned(),
        // `Llm` is BOUNDED own text (#3648 at the client boundary) and passes
        // through like every other own-vocabulary variant.
        MemoryError::Llm(_)
        | MemoryError::NotFound(_)
        | MemoryError::ValidationFailed(_)
        | MemoryError::Conflict(_)
        | MemoryError::ReflectionDepthExceeded { .. }
        | MemoryError::SynthesisDepthExceeded { .. }
        | MemoryError::ReflectionCycleDetected { .. }
        | MemoryError::RefusedByGovernance(_)
        | MemoryError::RefusedByGovernanceGate(_)
        | MemoryError::QuotaExceeded(_)
        | MemoryError::Refused(_) => e.message(),
    }
}

/// Convert a foreign error into the typed [`MemoryError`] AND put its detail
/// on the operator log — the conversion owns the log line (property 2).
///
/// `context` names the failing operation for the operator (the old
/// `"skill_list prepare: "` prefixes become this constant); it is a
/// `&'static str` so it can only ever be our own text. A foreign-class
/// result logs at `error` — the caller was told nothing useful, so the log
/// is the whole diagnosis on an MCP stdio daemon (no `/metrics` there). An
/// own-vocabulary result (a typed `StorageError` / governance refusal that
/// rode an `anyhow` chain) logs at `warn`, since the caller already has it.
pub fn log_foreign<E: Into<MemoryError>>(context: &'static str, e: E) -> MemoryError {
    let e = e.into();
    if e.is_foreign_class() {
        tracing::error!(
            target: TRACE_TARGET,
            context,
            code = e.code(),
            detail = %e.message(),
            "#3713: foreign error kept on the operator log; the caller receives the class"
        );
    } else {
        tracing::warn!(
            target: TRACE_TARGET,
            context,
            code = e.code(),
            detail = %e.message(),
            "#3713: typed refusal passed through to the caller"
        );
    }
    e
}

/// The one-token site edit: log the foreign detail for the operator and
/// return the caller-safe text — `.map_err(|e| mcp_foreign_err("ctx", e))?`.
pub fn mcp_foreign_err<E: Into<MemoryError>>(context: &'static str, e: E) -> String {
    mcp_error_text(&log_foreign(context, e))
}

/// Classify a provider / curator failure as the LLM class. The client's
/// `anyhow` chain has no typed root the `From<anyhow>` classifier can see —
/// left to the classifier it would fall through to `DatabaseError` and be
/// flattened to a constant — so an LLM site names its class explicitly:
/// `.map_err(|e| mcp_foreign_err("auto_tag", llm(e)))?`. The text is bounded
/// (#3648) and passes through to the caller.
///
/// Rendered with the ALTERNATE form (`{e:#}`): an `anyhow` chain's plain
/// `Display` is its outermost context only, so a transport or parse failure
/// read "Failed to send chat request" with the `provider <name>:
/// request_timeout` classification underneath it lost for BOTH audiences.
/// The chain is bounded end to end — the client boundary retains no
/// response body and no downstream error source (#3648, `llm::ProviderError`;
/// `tests/provider_error_redaction_3648.rs` asserts the `{:#}` render of
/// every arm) — so the whole of it is caller-safe.
pub fn llm(e: impl std::fmt::Display) -> MemoryError {
    MemoryError::Llm(format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_class_variants_render_the_constant_never_the_payload_3713() {
        let leak = "no such table: memories_secret_tenant";
        assert_eq!(
            mcp_error_text(&MemoryError::DatabaseError(leak.into())),
            DB_ERROR_TEXT
        );
        assert_eq!(
            mcp_error_text(&MemoryError::Filesystem(
                "/srv/tenant/skills: EACCES".into()
            )),
            FILESYSTEM_ERROR_TEXT
        );
        assert_eq!(
            mcp_error_text(&MemoryError::Codec(leak.into())),
            CODEC_ERROR_TEXT
        );
    }

    #[test]
    fn own_vocabulary_variants_pass_through_unchanged_3713() {
        let own = MemoryError::RefusedByGovernance("write requires owner".into());
        assert_eq!(mcp_error_text(&own), own.message());
        let nf = MemoryError::NotFound(crate::errors::msg::memory_not_found("abc"));
        assert_eq!(mcp_error_text(&nf), nf.message());
        let v = MemoryError::ValidationFailed("namespace is required".into());
        assert_eq!(mcp_error_text(&v), v.message());
    }

    #[test]
    fn an_llm_failure_is_bounded_own_text_and_passes_through_3713() {
        let bounded = "provider ollama: http 401";
        assert_eq!(mcp_foreign_err("auto_tag", llm(bounded)), bounded);
    }

    #[test]
    fn a_rusqlite_error_routes_to_the_storage_constant_3713() {
        let e = rusqlite::Error::QueryReturnedNoRows;
        assert_eq!(mcp_foreign_err("probe", e), DB_ERROR_TEXT);
    }

    #[test]
    fn an_io_error_routes_to_the_filesystem_constant_not_the_storage_one_3713() {
        let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "/srv/x: EACCES");
        let text = mcp_foreign_err("read skill", e);
        assert_eq!(text, FILESYSTEM_ERROR_TEXT);
        assert!(!text.contains("/srv"));
    }

    #[test]
    fn an_anyhow_chain_carrying_a_typed_refusal_keeps_its_message_3713() {
        // Property 3 through the anyhow classifier: our own typed
        // `StorageError` rides the chain and must reach the caller as itself.
        let e = anyhow::Error::new(crate::storage::StorageError::MemoryNotFound {
            id: "zzz".into(),
            role: None,
        });
        let text = mcp_foreign_err("get", e);
        assert!(text.contains("zzz"), "{text}");
        assert_ne!(text, DB_ERROR_TEXT);
    }

    #[test]
    fn an_anyhow_chain_without_a_typed_root_is_foreign_3713() {
        let e = anyhow::anyhow!("SQLITE_BUSY: database is locked (memories.db)");
        assert_eq!(mcp_foreign_err("insert", e), DB_ERROR_TEXT);
    }
}

/// pm-v3.1 hardcoded-literal ratchet — site names that are spelled in MORE
/// THAN ONE FILE live here, once. A per-file const cannot see repo-wide
/// duplication, and the ratchet counts repo-wide.
pub mod site {
    pub const LIST_AGENTS: &str = "list_agents";
    pub const RESOLVE_ID: &str = "resolve_id";
}
