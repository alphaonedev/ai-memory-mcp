// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2402] — `ai-memory quarantine list | release <id>`: the OPERATOR
//! surface for the quarantine route-OUT.
//!
//! # The gap this closes
//!
//! [#1948] shipped quarantine as a federation containment posture: an inbound
//! memory whose author cannot be attributed is written with
//! `lifecycle_state = 'quarantined'`, which
//! [`crate::models::lifecycle_visible_clause`] hides from EVERY lane — `get`,
//! `list`, `recall`, and onward federation relay. The route OUT was documented
//! as "dequarantine-on-attest, OR operator dequarantine", and the SAL
//! `dequarantine` primitive was implemented on both backends — with ZERO
//! operator callers. No CLI verb, no HTTP route, no MCP tool.
//!
//! Under the `asi-hard` security profile,
//! `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` is PINNED on, so the containment
//! cannot be turned off; and dequarantine-on-attest only fires if the author's
//! key is enrolled AND the author re-sends the same memory. Enrol the key
//! out-of-band with no re-receive — the realistic operator sequence — and the
//! row is black-holed permanently, invisible to the very operator who is meant
//! to adjudicate it. That is not containment, it is unmanaged data
//! unavailability, and it is the North-Star "manageable at scale" clause
//! failing closed in the wrong direction.
//!
//! # The two verbs
//!
//! * `quarantine list` — what is being held. Identifying metadata only, never
//!   `content` (see [`crate::models::QuarantinedMemory`] for why).
//! * `quarantine release <id>` — the sanctioned, AUDITED route out. Routes
//!   through [`crate::store::MemoryStore::operator_dequarantine`], which
//!   clears the row and appends a `memory.dequarantined` signed-chain row in
//!   ONE transaction on BOTH backends, so a release always leaves a signed
//!   trace naming who released what.
//!
//! There is deliberately no `re-quarantine` verb. A release makes a row
//! VISIBLE again; it destroys nothing and loses nothing, so the reverse is a
//! containment preference rather than a data-integrity need, and the ordinary
//! lanes (`forget`, `delete`, the #1948 route-IN on a fresh unattributed
//! receive) already cover what an operator would reach for. Adding a hide-verb
//! to this surface would also hand an operator a way to make arbitrary rows
//! invisible, which is a materially larger blast radius than the one this
//! module exists to close.
//!
//! # Why this is admin-gated by construction
//!
//! Both verbs run against the LOCAL database (or a `--store-url` the operator
//! supplies), i.e. they require filesystem/credential access to the substrate
//! itself — the same gate every other operator verb (`gc`, `backup`,
//! `schema-init`, `undo-edit`) rests on. The HTTP twin, which is reachable
//! over the network, carries the explicit admin authorization check instead.
//!
//! **Stated precisely, so the guarantee is not overread:** the release is
//! ATTRIBUTED, not operator-key-ATTESTED. The `memory.dequarantined` row is
//! signed with the DAEMON key (`SignedEvent::with_daemon_signature`) and its
//! `agent_id` is the resolved CLI principal — so the chain proves THIS daemon
//! performed the release and records who it believed the actor was, not that
//! the actor held the operator keypair. `ai-memory rules` mutation verbs do
//! demand the operator key; matching that here would be a strictly stronger
//! posture and is a reasonable v1.x hardening, but it is a NEW gate the #2402
//! contract did not ask for, and adding it silently would make the verb
//! unusable on nodes that have no operator key — turning the black-hole this
//! module removes back on for exactly the fleets that need it most.
//!
//! [#2402]: https://github.com/alphaonedev/ai-memory-mcp/issues/2402
//! [#1948]: https://github.com/alphaonedev/ai-memory-mcp/issues/1948

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::CliOutput;

/// Default page size for `quarantine list`. A quarantine backlog under a
/// federation storm can be large, and an unbounded operator read is its own
/// availability hazard; the operator raises it with `--limit` when needed.
pub const DEFAULT_LIST_LIMIT: i64 = 100;

/// `ai-memory quarantine` — operator inspection + release of quarantined rows.
#[derive(Args)]
pub struct QuarantineArgs {
    /// Operate against a `postgres://…` SAL store instead of the local
    /// sqlite `--db` path, so an enterprise-tier deployment has the same
    /// verb. Requires a binary built with `--features sal`.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
    #[command(subcommand)]
    pub action: QuarantineAction,
}

/// `ai-memory quarantine` sub-subcommands.
#[derive(Subcommand)]
pub enum QuarantineAction {
    /// List the memories currently held in quarantine. Read-only.
    List {
        /// Restrict the listing to one namespace.
        #[arg(long)]
        namespace: Option<String>,
        /// Maximum rows to return.
        #[arg(long, default_value_t = DEFAULT_LIST_LIMIT)]
        limit: i64,
    },
    /// Release one quarantined memory back to `open`, restoring it to every
    /// read lane. Appends a `memory.dequarantined` signed audit row.
    /// Idempotent: releasing a row that is not quarantined changes nothing
    /// and writes no audit row.
    Release {
        /// Memory id to release.
        id: String,
    },
}

/// Render a listing as the CLI result payload.
fn list_payload(rows: &[crate::models::QuarantinedMemory]) -> serde_json::Value {
    json!({
        "count": rows.len(),
        (crate::models::field_names::QUARANTINED): rows,
    })
}

/// Render a release outcome as the CLI result payload.
///
/// `released = false` is the HONEST answer for "not found" and for "not
/// quarantined" alike: the verb's guard is `lifecycle_state = 'quarantined'`,
/// so a released row cannot be re-released and a tombstoned row cannot be
/// revived, and the operator is told which of those happened by the note
/// rather than by an ambiguous success.
fn release_payload(id: &str, released: bool) -> serde_json::Value {
    json!({
        "id": id,
        "released": released,
        "note": if released {
            "released to lifecycle_state=open; a memory.dequarantined signed audit row was appended"
        } else {
            "no change: that id is not currently quarantined (already released, never quarantined, or unknown id)"
        },
    })
}

/// Run the verb against the LOCAL sqlite database.
///
/// # Errors
///
/// Bubbles a database open / query failure, or a write failure from the
/// audited release path.
pub fn run(
    db_path: &Path,
    args: &QuarantineArgs,
    cli_agent_id: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // The audit actor is the RESOLVED principal (`--agent-id` /
    // AI_MEMORY_AGENT_ID / the NHI-hardened synthesised default), never a
    // free-text string: a release audit row that cannot be attributed is not
    // an audit row.
    let agent_id = crate::identity::resolve_agent_id(cli_agent_id, None)
        .context("quarantine: resolve caller agent id")?;
    let agent_id = agent_id.as_str();
    // Open through the migrating funnel so a fresh database carries the v64
    // `lifecycle_state` column — same discipline as `cli::rules::run`.
    let mut conn = crate::db::open(db_path)
        .with_context(|| format!("quarantine: open db at {}", db_path.display()))?;
    match &args.action {
        QuarantineAction::List { namespace, limit } => {
            let rows = crate::db::list_quarantined(&conn, namespace.as_deref(), *limit)
                .context("quarantine: list quarantined memories")?;
            crate::cli::rules::emit_ok(json_out, out, "quarantine.list", &list_payload(&rows))
        }
        QuarantineAction::Release { id } => {
            let released = crate::db::operator_dequarantine(&mut conn, id, agent_id)
                .context("quarantine: release quarantined memory")?;
            crate::cli::rules::emit_ok(
                json_out,
                out,
                "quarantine.release",
                &release_payload(id, released),
            )
        }
    }
}

/// Run the verb against a SAL store (the `--store-url postgres://…` path), so
/// the enterprise tier has the SAME operator surface as sqlite. Both branches
/// land the same audit row, on their own backend, inside the same transaction
/// as the state change.
///
/// # Errors
///
/// Bubbles the adapter error.
#[cfg(feature = "sal")]
pub async fn run_store(
    store: &dyn crate::store::MemoryStore,
    args: &QuarantineArgs,
    cli_agent_id: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let agent_id = crate::identity::resolve_agent_id(cli_agent_id, None)
        .context("quarantine: resolve caller agent id")?;
    match &args.action {
        QuarantineAction::List { namespace, limit } => {
            let rows = store
                .list_quarantined(namespace.as_deref(), *limit)
                .await
                .context("quarantine: list quarantined memories")?;
            crate::cli::rules::emit_ok(json_out, out, "quarantine.list", &list_payload(&rows))
        }
        QuarantineAction::Release { id } => {
            // The operator lane is an ADMIN lane: quarantined rows are hidden
            // from tenant visibility, so the release context bypasses the
            // scope filter. `for_admin` (not `for_admin_checked`) because the
            // admin posture here is STRUCTURAL — reaching this verb already
            // required filesystem/credential access to the substrate — rather
            // than request-gated, which is the same split the constructor's
            // own doc draws for the background paths. The recorded actor is
            // the resolved CLI principal, never a value read off a request.
            let ctx = crate::store::CallerContext::for_admin(agent_id.clone());
            let released = store
                .operator_dequarantine(&ctx, id)
                .await
                .context("quarantine: release quarantined memory")?;
            crate::cli::rules::emit_ok(
                json_out,
                out,
                "quarantine.release",
                &release_payload(id, released),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_payload_distinguishes_a_real_release_from_a_no_op() {
        let released = release_payload("m1", true);
        assert_eq!(released["released"], json!(true));
        assert!(
            released["note"].as_str().unwrap().contains("audit"),
            "a real release must tell the operator an audit row was written"
        );
        let noop = release_payload("m1", false);
        assert_eq!(noop["released"], json!(false));
        assert!(
            noop["note"]
                .as_str()
                .unwrap()
                .contains("not currently quarantined"),
            "a no-op must not read as a success"
        );
    }

    #[test]
    fn list_payload_reports_a_count_alongside_the_rows() {
        let rows = vec![crate::models::QuarantinedMemory {
            id: "m1".into(),
            namespace: "global".into(),
            title: "unattributed inbound".into(),
            source: "federation".into(),
            memory_kind: "observation".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-02T00:00:00Z".into(),
        }];
        let payload = list_payload(&rows);
        assert_eq!(payload["count"], json!(1));
        assert_eq!(payload["quarantined"][0]["id"], json!("m1"));
        assert!(
            payload["quarantined"][0].get("content").is_none(),
            "the listing must never project the (untrusted, possibly sealed) content"
        );
    }

    #[test]
    fn an_empty_listing_is_an_explicit_zero_not_a_silent_omission() {
        let payload = list_payload(&[]);
        assert_eq!(payload["count"], json!(0));
        assert_eq!(payload["quarantined"], json!([]));
    }
}
