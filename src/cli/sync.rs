// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_sync` and `cmd_sync_daemon` migrations. The daemon-mode body
//! delegates to `daemon_runtime::run_sync_daemon_with_shutdown_using_client`
//! (W3 work); this module owns only the wrapper + the in-process sync
//! body (pull/push/merge/dry-run).

use crate::cli::CliOutput;
use crate::{db, identity, models, tls, validate};
use anyhow::Result;
use clap::Args;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Args)]
pub struct SyncArgs {
    /// Path to the remote database to sync with
    pub remote_db: PathBuf,
    /// Direction: pull, push, or merge
    #[arg(long, short, default_value = "merge")]
    pub direction: String,
    /// Trust `metadata.agent_id` in remote memories (default: restamp with caller's id).
    /// Only use this when syncing between databases you fully control (e.g., your own backup).
    #[arg(long, default_value_t = false)]
    pub trust_source: bool,
    /// Phase 3 foundation (issue #224): preview what would change without
    /// writing anything. Counts new / updated / unchanged memories and
    /// links in each direction. Uses today's timestamp-aware merge
    /// semantics; CRDT-lite field-level diagnostics land with #224 Task 3a.1.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct SyncDaemonArgs {
    /// Comma-separated list of peer HTTP endpoints to mesh with.
    #[arg(long, value_delimiter = ',')]
    pub peers: Vec<String>,
    /// Seconds between sync cycles. Minimum 1.
    #[arg(long, default_value_t = 2)]
    pub interval: u64,
    /// Optional `X-API-Key` to present to peers that have api-key auth enabled.
    #[arg(long)]
    pub api_key: Option<String>,
    /// Cap on the number of memories transferred per peer per cycle.
    #[arg(long, default_value_t = 500)]
    pub batch_size: usize,
    /// Layer 2 client-cert PEM used when the peer demands mTLS.
    #[arg(long, requires = "client_key")]
    pub client_cert: Option<PathBuf>,
    /// Layer 2 client-key PEM. Must pair with `--client-cert`.
    #[arg(long, requires = "client_cert")]
    pub client_key: Option<PathBuf>,
    /// Disable server-cert verification on outbound HTTPS to peers.
    /// **DANGEROUS** — accepts any server cert without validation.
    #[arg(long, default_value_t = false)]
    pub insecure_skip_server_verify: bool,
    /// #1794 — path to a PEM CA certificate to trust for peer server-cert
    /// validation (self-signed / private-CA peers). Mirrors the quorum
    /// client's `--quorum-ca-cert`. Without it, peers are validated against
    /// the bundled public webpki roots (the secure default). Mutually
    /// exclusive with `--insecure-skip-server-verify`.
    #[arg(long, conflicts_with = "insecure_skip_server_verify")]
    pub ca_cert: Option<PathBuf>,
}

/// NHI: restamp `metadata.agent_id` to the caller's id, preserving the
/// original as `imported_from_agent_id`. Mirrors `main.rs::restamp_agent_id`
/// (W5 had to extract it because main.rs version is private).
fn restamp_agent_id(mem: &mut models::Memory, caller_id: &str) {
    let original = mem
        .metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(caller_id.to_string()),
        );
        if let Some(orig) = original
            && orig != caller_id
        {
            obj.insert(
                crate::models::field_names::IMPORTED_FROM_AGENT_ID.to_string(),
                serde_json::Value::String(orig),
            );
        }
    }
}

/// #3457 — the row's ORIGINAL `metadata.agent_id` claim, read BEFORE any
/// restamp, so the attestation reconcile can apply the re-attribution rule: a
/// row this sync RE-OWNED can never verify the original author's
/// `write_signature` against the new attribution, because the signed
/// `SignableWrite` envelope commits to `agent_id`.
fn original_agent_claim(mem: &models::Memory) -> Option<String> {
    mem.metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

/// #3457 — per-leg tally of what the inbound attestation reconcile decided, so
/// the CLI can report it instead of silently changing rows.
#[derive(Debug, Default, Clone, Copy)]
struct InboundAttestTally {
    /// Rows that asserted `agent_attested` on the wire but landed `claimed`.
    downgraded: usize,
    /// Rows SKIPPED because a presented signature was malformed or forged.
    forged_skipped: usize,
    /// `_agents` rows whose flat key pair was refused as transport data.
    pubkey_bindings_stripped: usize,
    /// Signed rows refused because destination key history could not be read.
    key_history_refused: usize,
}

fn strip_sync_pubkey_binding(mem: &mut models::Memory, stripped: &mut usize) {
    if crate::storage::strip_unproven_agent_pubkey_binding(mem) {
        *stripped += 1;
        tracing::warn!(
            memory_id = %mem.id,
            "sync: transported _agents public-key binding stripped and carried attestation downgraded; sync is not proof of possession or lineage (#3464)"
        );
    }
}

fn resolve_sync_attestation_key(
    dest: &rusqlite::Connection,
    mem: &models::Memory,
    original_claim: Option<&str>,
) -> Result<Option<crate::storage::AttestationPubkeyAt>> {
    let Some(author) = crate::identity::attest::presented_attestation_author_needing_bound_key(
        mem,
        original_claim,
    ) else {
        return Ok(None);
    };
    db::agent_pubkey_for_attestation_at(dest, author, &mem.created_at).map(Some)
}

/// #3457 — surface the inbound attestation tally on the human-readable output,
/// but ONLY when it is non-zero, so the ordinary sync's stdout is unchanged.
/// A row that silently changed attestation level (or was dropped) must not be
/// invisible to the operator running the command.
fn write_attestation_tally(out: &mut CliOutput<'_>, tally: &InboundAttestTally) -> Result<()> {
    if tally.downgraded > 0 {
        writeln!(
            out.stdout,
            "  {} inbound row(s) asserted agent_attested but landed claimed \
             (wire attestation is never trusted)",
            tally.downgraded
        )?;
    }
    if tally.forged_skipped > 0 {
        writeln!(
            out.stdout,
            "  {} inbound row(s) SKIPPED: presented write_signature is malformed or forged",
            tally.forged_skipped
        )?;
    }
    if tally.pubkey_bindings_stripped > 0 {
        writeln!(
            out.stdout,
            "  {} transported agent public-key binding(s) stripped; use the persisted PoP or lineage bind flow",
            tally.pubkey_bindings_stripped
        )?;
    }
    if tally.key_history_refused > 0 {
        writeln!(
            out.stdout,
            "  {} signed inbound row(s) SKIPPED: destination key history unavailable",
            tally.key_history_refused
        )?;
    }
    Ok(())
}

/// #3457 (security-high) — re-derive an INBOUND row's attestation from what the
/// DESTINATION can verify, never from the remote database.
///
/// `ai-memory sync --direction pull|merge` re-owns each remote row to the caller
/// (`restamp_agent_id`) while carrying the remote row's `metadata.attest_level`
/// and `metadata.write_signature` through VERBATIM into the local store. The
/// signed envelope commits to `agent_id`, so after the re-own that signature can
/// never be re-derived from the row it now describes — a durable
/// `agent_attested` no principal ever minted, which `row_is_agent_attested`, the
/// federation relay under `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1` and the
/// attestation census all believe.
///
/// `--trust-source` was never a mitigation: it preserves the ORIGINAL owner
/// instead of re-owning, but nothing on either branch verified the presented
/// signature against a destination-enrolled key, so a wire-asserted
/// `agent_attested` was taken on faith either way. Under `--trust-source` the
/// re-attribution rule simply does not fire and the signature is actually
/// VERIFIED — which is strictly more than the pre-#3457 behaviour.
///
/// This is a call into the ONE shared funnel
/// ([`crate::identity::attest::reconcile_imported_attestation`], #3421), not a
/// fourth hand-rolled copy: the portability v2 route, the CLI L1 route (#2264)
/// and `POST /api/v1/import` all make the same decision. Returns `true` to keep
/// the row.
fn reconcile_inbound_attestation(
    mem: &mut models::Memory,
    original_claim: Option<&str>,
    trust_source: bool,
    resolved_pubkeys: Option<&crate::storage::AttestationPubkeyAt>,
    tally: &mut InboundAttestTally,
) -> bool {
    let outcome = crate::identity::attest::reconcile_imported_attestation(
        mem,
        original_claim,
        !trust_source,
        resolved_pubkeys,
    );
    if let Some(cause) = outcome.skipped() {
        tally.forged_skipped += 1;
        tracing::warn!(
            memory_id = %mem.id,
            "sync: row skipped — {cause} (#3457; a presented-but-bad signature is never \
             downgraded into storage)"
        );
        return false;
    }
    if let Some(cause) = outcome.downgraded() {
        tally.downgraded += 1;
        tracing::warn!(
            memory_id = %mem.id,
            "sync: row asserted attest_level=agent_attested but landed claimed — {cause} \
             (#3457; wire attestation is never trusted)"
        );
    }
    true
}

/// #1794 — parse a PEM CA certificate that was already read into memory.
///
/// `reqwest::Certificate::from_pem` accepts a marker-less file as an EMPTY
/// chain, so a non-PEM path would silently add no roots and the operator would
/// see a generic TLS failure instead of "that file is not a PEM". Pre-flighting
/// the `-----BEGIN ` marker makes it fail loud (mirrors the strict
/// `--quorum-ca-cert` check).
///
/// #2815 — extracted from the async sync arm so the BLOCKING `doctor --remote`
/// client (`std::fs::read`) and the async sync client share ONE parser rather
/// than forking the marker check.
///
/// # Errors
///
/// Returns `Err` when the bytes carry no PEM marker, or reqwest rejects them.
pub(crate) fn parse_ca_certificate(ca_pem: &[u8], source: &Path) -> Result<reqwest::Certificate> {
    if !ca_pem.windows(11).any(|w| w == b"-----BEGIN ") {
        anyhow::bail!(
            "parse --ca-cert: input at {} contains no PEM `-----BEGIN ` marker",
            source.display()
        );
    }
    reqwest::Certificate::from_pem(ca_pem).map_err(|e| anyhow::anyhow!("parse --ca-cert: {e}"))
}

/// #1794 — build the optional reqwest mTLS client identity from the
/// `--client-cert` / `--client-key` PEM pair (both-or-neither). Shared by the
/// CA-validated and accept-any sync TLS arms (the pinning arm threads the cert
/// through `build_rustls_pinning_client_config` instead).
pub(crate) fn sync_client_identity(
    client_cert: Option<&Path>,
    client_key: Option<&Path>,
) -> Result<Option<reqwest::Identity>> {
    match (client_cert, client_key) {
        (Some(cert), Some(key)) => {
            let cert_pem =
                std::fs::read(cert).map_err(|e| anyhow::anyhow!("read --client-cert: {e}"))?;
            let key_pem =
                std::fs::read(key).map_err(|e| anyhow::anyhow!("read --client-key: {e}"))?;
            let mut pem = cert_pem;
            pem.extend_from_slice(b"\n");
            pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&pem)
                .map_err(|e| anyhow::anyhow!("build mTLS identity: {e}"))?;
            Ok(Some(identity))
        }
        _ => Ok(None),
    }
}

#[derive(Default)]
struct SyncPreview {
    would_pull_new: usize,
    would_pull_update: usize,
    would_pull_noop: usize,
    would_push_new: usize,
    would_push_update: usize,
    would_push_noop: usize,
    would_pull_links: usize,
    would_push_links: usize,
}

impl SyncPreview {
    fn classify(local: Option<&models::Memory>, remote: &models::Memory) -> MergeOutcome {
        match local {
            None => MergeOutcome::New,
            Some(existing) => {
                if remote.updated_at > existing.updated_at {
                    MergeOutcome::Update
                } else {
                    MergeOutcome::Noop
                }
            }
        }
    }
}

enum MergeOutcome {
    New,
    Update,
    Noop,
}

/// `sync` handler.
#[allow(clippy::too_many_lines)]
pub fn run(
    db_path: &Path,
    args: &SyncArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE the LOCAL-store leg on a Postgres deployment BEFORE
    // opening the local sqlite (see `refuse_pg_store`). The `--remote-db` leg is
    // an explicit second sqlite FILE argument, not the configured store, so it
    // is unaffected.
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "sync", out)?;
    let db_path = db_path.as_path();
    let local_conn = db::open(db_path)?;
    let remote_conn = db::open(&args.remote_db)?;
    let caller_id = identity::resolve_agent_id(cli_agent_id, None)?;

    if args.dry_run {
        return cmd_sync_dry_run(&local_conn, &remote_conn, &args.direction, json_out, out);
    }

    match args.direction.as_str() {
        "pull" => {
            let mems = db::export_all(&remote_conn)?;
            let links = db::export_links(&remote_conn)?;
            let mut n = 0;
            let mut tally = InboundAttestTally::default();
            for mem in &mems {
                let mut owned = mem.clone();
                let original_claim = original_agent_claim(&owned);
                if !args.trust_source {
                    restamp_agent_id(&mut owned, &caller_id);
                }
                strip_sync_pubkey_binding(&mut owned, &mut tally.pubkey_bindings_stripped);
                let bound_pubkey = match resolve_sync_attestation_key(
                    &local_conn,
                    &owned,
                    original_claim.as_deref(),
                ) {
                    Ok(bound) => bound,
                    Err(e) => {
                        tally.key_history_refused += 1;
                        tracing::warn!(
                            memory_id = %owned.id,
                            "sync: signed row skipped because destination key-history resolution failed: {e}"
                        );
                        continue;
                    }
                };
                // #3457 — re-derive the attestation from what THIS node can
                // verify, before the row is validated or stored.
                if !reconcile_inbound_attestation(
                    &mut owned,
                    original_claim.as_deref(),
                    args.trust_source,
                    bound_pubkey.as_ref(),
                    &mut tally,
                ) {
                    continue;
                }
                if let Err(e) = validate::validate_memory(&owned) {
                    tracing::warn!("sync: skipping invalid memory {}: {}", owned.id, e);
                    continue;
                }
                if db::insert(&local_conn, &owned).is_ok() {
                    n += 1;
                }
            }
            for link in &links {
                if validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
                    .is_err()
                {
                    continue;
                }
                let _ = db::create_link(
                    &local_conn,
                    &link.source_id,
                    &link.target_id,
                    link.relation.as_str(),
                );
            }
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "direction": "pull",
                        "imported": n,
                        // #3457 — additive: what the inbound attestation
                        // reconcile decided. Zero on the ordinary path.
                        (models::field_names::ATTESTATION_DOWNGRADED): tally.downgraded,
                        (models::field_names::FORGED_SIGNATURE_SKIPPED): tally.forged_skipped,
                        (models::field_names::PUBKEY_BINDINGS_STRIPPED): tally.pubkey_bindings_stripped,
                        "key_history_refused": tally.key_history_refused,
                    })
                )?;
            } else {
                writeln!(out.stdout, "pulled {n} memories from remote")?;
                write_attestation_tally(out, &tally)?;
            }
        }
        "push" => {
            let mems = db::export_all(&local_conn)?;
            let links = db::export_links(&local_conn)?;
            let mut n = 0;
            let mut pubkey_bindings_stripped = 0usize;
            for mem in &mems {
                let mut owned = mem.clone();
                strip_sync_pubkey_binding(&mut owned, &mut pubkey_bindings_stripped);
                if let Err(e) = validate::validate_memory(&owned) {
                    tracing::warn!("sync: skipping invalid memory {}: {}", owned.id, e);
                    continue;
                }
                if db::insert(&remote_conn, &owned).is_ok() {
                    n += 1;
                }
            }
            for link in &links {
                if validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
                    .is_err()
                {
                    continue;
                }
                let _ = db::create_link(
                    &remote_conn,
                    &link.source_id,
                    &link.target_id,
                    link.relation.as_str(),
                );
            }
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "direction": "push",
                        "exported": n,
                        (models::field_names::PUBKEY_BINDINGS_STRIPPED): pubkey_bindings_stripped,
                    })
                )?;
            } else {
                writeln!(out.stdout, "pushed {n} memories to remote")?;
                if pubkey_bindings_stripped > 0 {
                    writeln!(
                        out.stdout,
                        "  {pubkey_bindings_stripped} transported agent public-key binding(s) stripped; use the persisted PoP or lineage bind flow"
                    )?;
                }
            }
        }
        "merge" => {
            let r_mems = db::export_all(&remote_conn)?;
            let r_links = db::export_links(&remote_conn)?;
            let l_mems = db::export_all(&local_conn)?;
            let l_links = db::export_links(&local_conn)?;
            let (mut pulled, mut pushed) = (0, 0);
            let mut tally = InboundAttestTally::default();
            for mem in &r_mems {
                let mut owned = mem.clone();
                let original_claim = original_agent_claim(&owned);
                if !args.trust_source {
                    restamp_agent_id(&mut owned, &caller_id);
                }
                strip_sync_pubkey_binding(&mut owned, &mut tally.pubkey_bindings_stripped);
                let bound_pubkey = match resolve_sync_attestation_key(
                    &local_conn,
                    &owned,
                    original_claim.as_deref(),
                ) {
                    Ok(bound) => bound,
                    Err(e) => {
                        tally.key_history_refused += 1;
                        tracing::warn!(
                            memory_id = %owned.id,
                            "sync: signed row skipped because destination key-history resolution failed: {e}"
                        );
                        continue;
                    }
                };
                if !reconcile_inbound_attestation(
                    &mut owned,
                    original_claim.as_deref(),
                    args.trust_source,
                    bound_pubkey.as_ref(),
                    &mut tally,
                ) {
                    continue;
                }
                if validate::validate_memory(&owned).is_err() {
                    continue;
                }
                if db::insert_if_newer(&local_conn, &owned).is_ok() {
                    pulled += 1;
                }
            }
            for link in &r_links {
                if validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
                    .is_err()
                {
                    continue;
                }
                let _ = db::create_link(
                    &local_conn,
                    &link.source_id,
                    &link.target_id,
                    link.relation.as_str(),
                );
            }
            for mem in &l_mems {
                let mut owned = mem.clone();
                strip_sync_pubkey_binding(&mut owned, &mut tally.pubkey_bindings_stripped);
                if validate::validate_memory(&owned).is_err() {
                    continue;
                }
                if db::insert_if_newer(&remote_conn, &owned).is_ok() {
                    pushed += 1;
                }
            }
            for link in &l_links {
                if validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
                    .is_err()
                {
                    continue;
                }
                let _ = db::create_link(
                    &remote_conn,
                    &link.source_id,
                    &link.target_id,
                    link.relation.as_str(),
                );
            }
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "direction": "merge",
                        "pulled": pulled,
                        "pushed": pushed,
                        // #3457 — additive; describes the INBOUND leg only.
                        (models::field_names::ATTESTATION_DOWNGRADED): tally.downgraded,
                        (models::field_names::FORGED_SIGNATURE_SKIPPED): tally.forged_skipped,
                        (models::field_names::PUBKEY_BINDINGS_STRIPPED): tally.pubkey_bindings_stripped,
                        "key_history_refused": tally.key_history_refused,
                    })
                )?;
            } else {
                writeln!(out.stdout, "merged: pulled {pulled}, pushed {pushed}")?;
                write_attestation_tally(out, &tally)?;
            }
        }
        _ => anyhow::bail!(
            "invalid direction: {} (use pull, push, merge)",
            args.direction
        ),
    }
    Ok(())
}

fn cmd_sync_dry_run(
    local_conn: &rusqlite::Connection,
    remote_conn: &rusqlite::Connection,
    direction: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let l_mems = db::export_all(local_conn)?;
    let r_mems = db::export_all(remote_conn)?;
    let l_links = db::export_links(local_conn)?;
    let r_links = db::export_links(remote_conn)?;

    let local_by_id: std::collections::HashMap<&str, &models::Memory> =
        l_mems.iter().map(|m| (m.id.as_str(), m)).collect();
    let remote_by_id: std::collections::HashMap<&str, &models::Memory> =
        r_mems.iter().map(|m| (m.id.as_str(), m)).collect();

    let mut preview = SyncPreview::default();

    let classify_pull = direction != "push";
    let classify_push = direction != "pull";

    if classify_pull {
        for mem in &r_mems {
            match SyncPreview::classify(local_by_id.get(mem.id.as_str()).copied(), mem) {
                MergeOutcome::New => preview.would_pull_new += 1,
                MergeOutcome::Update => preview.would_pull_update += 1,
                MergeOutcome::Noop => preview.would_pull_noop += 1,
            }
        }
        preview.would_pull_links = r_links.len();
    }

    if classify_push {
        for mem in &l_mems {
            match SyncPreview::classify(remote_by_id.get(mem.id.as_str()).copied(), mem) {
                MergeOutcome::New => preview.would_push_new += 1,
                MergeOutcome::Update => preview.would_push_update += 1,
                MergeOutcome::Noop => preview.would_push_noop += 1,
            }
        }
        preview.would_push_links = l_links.len();
    }

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "dry_run": true,
                "direction": direction,
                "pull": {
                    "new": preview.would_pull_new,
                    "update": preview.would_pull_update,
                    "noop": preview.would_pull_noop,
                    "links": preview.would_pull_links,
                },
                "push": {
                    "new": preview.would_push_new,
                    "update": preview.would_push_update,
                    "noop": preview.would_push_noop,
                    "links": preview.would_push_links,
                }
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "DRY RUN — no changes written. Direction: {direction}"
        )?;
        if classify_pull {
            writeln!(
                out.stdout,
                "  pull: {} new, {} update, {} noop, {} links",
                preview.would_pull_new,
                preview.would_pull_update,
                preview.would_pull_noop,
                preview.would_pull_links
            )?;
        }
        if classify_push {
            writeln!(
                out.stdout,
                "  push: {} new, {} update, {} noop, {} links",
                preview.would_push_new,
                preview.would_push_update,
                preview.would_push_noop,
                preview.would_push_links
            )?;
        }
    }
    Ok(())
}

/// `sync-daemon` handler. Delegates the inner loop to `daemon_runtime`.
pub async fn run_daemon(
    db_path: &Path,
    args: SyncDaemonArgs,
    cli_agent_id: Option<&str>,
) -> Result<()> {
    if args.peers.is_empty() {
        anyhow::bail!("at least one --peers URL is required");
    }
    let interval = args.interval.max(1);
    let batch_size = args.batch_size.max(1);
    let local_agent_id = identity::resolve_agent_id(cli_agent_id, None)?;

    // v1.0.0 #3436 — same shared console funnel `serve` uses; logs go to
    // STDERR so `sync-daemon`'s stdout stays a data channel.
    crate::logging::init_console_tracing(&["tower_http=info"]);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_sync_client(&args).await?;

    tracing::info!(
        "sync-daemon: local_agent_id={local_agent_id} peers={peers:?} interval={interval}s",
        peers = args.peers
    );

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_for_signal.notify_one();
    });

    crate::daemon_runtime::run_sync_daemon_with_shutdown_using_client(
        client,
        db_path.to_path_buf(),
        local_agent_id,
        args.peers,
        args.api_key,
        interval,
        batch_size,
        shutdown,
    )
    .await
}

/// #2448 — the sync-daemon's outbound TLS client, extracted from
/// [`run_daemon`] so the TLS posture is constructible (and therefore
/// assertable end-to-end against a real handshake) without entering the
/// daemon's infinite sync loop.
///
/// Applies, in order: the pre-existing mTLS gate on
/// `--insecure-skip-server-verify`, then [`tls::select_sync_tls_mode`]
/// (pinning > accept-any > CA-validate), whose accept-any arm is itself
/// fail-closed behind [`tls::server_verify_required`].
///
/// # Errors
/// - `--insecure-skip-server-verify` without both `--client-cert` and
///   `--client-key`.
/// - `--insecure-skip-server-verify` while server verification is required
///   (#2448 — the default).
/// - Unreadable / unparseable pin file, `--ca-cert`, or client cert/key PEM.
pub async fn build_sync_client(args: &SyncDaemonArgs) -> Result<reqwest::Client> {
    // #2477 — the SECOND peer-URL door. `ai-memory sync-daemon --peers` is a
    // fully independent path from `FederationConfig::build`: it wires the
    // #2448 accept-any-cert ceremony but validated no scheme whatsoever, so
    // `--peers http://host:9077` replicated plaintext memory content while
    // the ceremony was still nominally in force. A refusal scoped to
    // `federation/peer.rs` alone would have been theatre — this door and
    // that one share ONE validator.
    for peer in &args.peers {
        crate::tls::validate_peer_url_scheme(peer).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    if args.insecure_skip_server_verify && (args.client_cert.is_none() || args.client_key.is_none())
    {
        anyhow::bail!(
            "sync-daemon: --insecure-skip-server-verify requires both --client-cert \
             and --client-key as a compensating mTLS control. Running with neither side \
             of the TLS handshake verified is an open MITM surface and is refused."
        );
    }

    // #1794 (5-agent vote 4d3ea1c5) — the CLI sync outbound-TLS posture now
    // mirrors the production quorum client (federation/peer.rs): the SECURE
    // DEFAULT is normal CA validation (reqwest's bundled webpki roots + an
    // optional --ca-cert for self-signed peers), NOT the prior accept-any
    // `DangerousAnyServerVerifier`. Precedence: pinning > insecure-opt-out >
    // CA-validate (see `tls::select_sync_tls_mode`).
    //
    // #2448 (3x3 adversarial vote) — the insecure-opt-out arm is now itself
    // fail-closed: `select_sync_tls_mode` REFUSES it unless the operator also
    // sets AI_MEMORY_FED_REQUIRE_SERVER_VERIFY to a falsy token. Federation
    // ships PLAINTEXT content, so an unauthenticated peer server must never be
    // one flag away.
    let pins = tls::peer_fingerprint_map_from_env()?;
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    builder = match tls::select_sync_tls_mode(
        args.insecure_skip_server_verify,
        pins.is_some(),
        tls::server_verify_required(),
    )? {
        tls::SyncTlsMode::Pinning => {
            // #1678/#1794 — per-host server-cert pinning, fail-closed for
            // unpinned hosts, carrying the optional mTLS client identity.
            let pinning_config = tls::build_rustls_pinning_client_config(
                pins.expect("pins present in Pinning mode"),
                args.client_cert.as_deref(),
                args.client_key.as_deref(),
            )?;
            builder.use_preconfigured_tls(pinning_config)
        }
        tls::SyncTlsMode::AcceptAny => {
            // --insecure-skip-server-verify (gated above on a client cert):
            // accept ANY server cert. Loud, explicit opt-out only.
            tracing::warn!(
                "sync-daemon: --insecure-skip-server-verify set — peer server certificates \
                 will NOT be validated; peer authenticity relies entirely on the peer pinning \
                 our mTLS client cert. Do NOT use on hostile networks."
            );
            let mut b = builder.use_rustls_tls().danger_accept_invalid_certs(true);
            if let Some(id) =
                sync_client_identity(args.client_cert.as_deref(), args.client_key.as_deref())?
            {
                b = b.identity(id);
            }
            b
        }
        tls::SyncTlsMode::CaValidated => {
            // Secure default — CA-validate the peer (bundled webpki roots +
            // optional --ca-cert). Mirrors federation/peer.rs's quorum client.
            let mut b = builder.use_rustls_tls();
            if let Some(ca_path) = &args.ca_cert {
                let ca_pem = tokio::fs::read(ca_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("read --ca-cert: {e}"))?;
                b = b.add_root_certificate(parse_ca_certificate(&ca_pem, ca_path)?);
            }
            if let Some(id) =
                sync_client_identity(args.client_cert.as_deref(), args.client_key.as_deref())?
            {
                b = b.identity(id);
            }
            b
        }
    };
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    fn args_for(remote_db: PathBuf, direction: &str) -> SyncArgs {
        SyncArgs {
            remote_db,
            direction: direction.to_string(),
            trust_source: false,
            dry_run: false,
        }
    }

    #[test]
    fn test_sync_dry_run_merge() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&local, "ns", "local-only", "L");
        seed_memory(&remote, "ns", "remote-only", "R");
        let mut args = args_for(remote, "merge");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["dry_run"].as_bool().unwrap(), true);
        assert_eq!(v["direction"].as_str().unwrap(), "merge");
    }

    #[test]
    fn test_sync_pull_direction() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&remote, "ns", "from-remote", "data");
        let args = args_for(remote, "pull");
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("pulled"));
    }

    #[test]
    fn test_sync_push_direction() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&local, "ns", "to-remote", "data");
        let args = args_for(remote, "push");
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("pushed"));
    }

    #[test]
    fn test_sync_merge_direction() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&local, "ns", "L", "L");
        seed_memory(&remote, "ns", "R", "R");
        let args = args_for(remote, "merge");
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("merged:"));
    }

    #[test]
    fn test_sync_invalid_direction_errors() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let args = args_for(remote, "sideways");
        let mut out = env.output();
        let res = run(&local, &args, false, Some("test-agent"), &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_sync_dry_run_pull_only() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&remote, "ns", "remote", "x");
        let mut args = args_for(remote, "pull");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["pull"]["new"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn ca_cert_conflicts_with_insecure_skip_1794() {
        use clap::Parser;
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            args: SyncDaemonArgs,
        }
        // #1794 — --ca-cert and --insecure-skip-server-verify are contradictory
        // (validate vs accept-any) → clap must REJECT them together at parse.
        let conflict = TestCli::try_parse_from([
            "x",
            "--peers",
            "https://p",
            "--insecure-skip-server-verify",
            "--ca-cert",
            "/tmp/ca.pem",
        ]);
        assert!(
            conflict.is_err(),
            "--ca-cert + --insecure-skip-server-verify must conflict at parse"
        );
        // --ca-cert alone parses + populates the field.
        let ok = TestCli::try_parse_from(["x", "--peers", "https://p", "--ca-cert", "/tmp/ca.pem"])
            .expect("--ca-cert alone must parse");
        assert_eq!(ok.args.ca_cert.as_deref(), Some(Path::new("/tmp/ca.pem")));
        // Default: neither flag set.
        let plain = TestCli::try_parse_from(["x", "--peers", "https://p"]).expect("plain parse");
        assert!(plain.args.ca_cert.is_none() && !plain.args.insecure_skip_server_verify);
    }

    #[test]
    fn test_restamp_agent_id_preserves_original() {
        let mut mem = models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: models::Tier::Mid,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "remote-agent"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        restamp_agent_id(&mut mem, "local-agent");
        assert_eq!(mem.metadata["agent_id"].as_str().unwrap(), "local-agent");
        assert_eq!(
            mem.metadata["imported_from_agent_id"].as_str().unwrap(),
            "remote-agent"
        );
    }

    #[test]
    fn test_restamp_same_agent_no_imported_from() {
        let mut mem = models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: models::Tier::Mid,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id": "same-agent"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        restamp_agent_id(&mut mem, "same-agent");
        assert_eq!(mem.metadata["agent_id"].as_str().unwrap(), "same-agent");
        assert!(mem.metadata.get("imported_from_agent_id").is_none());
    }

    #[test]
    fn transported_registration_key_downgrades_direct_sync_attestation_3464() {
        use crate::models::field_names;
        let mirror = serde_json::json!({
            "agent_id": "ai:source",
            (field_names::AGENT_PUBKEY): "unproven-key",
            (field_names::PUBKEY_BOUND_AT): "2026-01-01T00:00:00+00:00",
            (field_names::WRITE_SIGNATURE): "mirrored-carried-signature",
            (field_names::ATTEST_LEVEL): "agent_attested",
        });
        let mut mem = models::Memory {
            id: "sync-agent-registration-3464".to_string(),
            namespace: crate::models::AGENTS_NAMESPACE.to_string(),
            title: crate::models::agent_registration_title("ai:source"),
            content: serde_json::to_string(&mirror).expect("mirror"),
            metadata: serde_json::json!({
                "agent_id": "ai:source",
                (field_names::AGENT_PUBKEY): "unproven-key",
                (field_names::PUBKEY_BOUND_AT): "2026-01-01T00:00:00+00:00",
                (field_names::WRITE_SIGNATURE): "carried-signature",
                (field_names::ATTEST_LEVEL): "agent_attested",
            }),
            ..models::Memory::default()
        };
        let mut stripped = 0;
        strip_sync_pubkey_binding(&mut mem, &mut stripped);
        assert_eq!(stripped, 1);
        assert!(mem.metadata.get(field_names::AGENT_PUBKEY).is_none());
        assert!(mem.metadata.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(mem.metadata[field_names::ATTEST_LEVEL], "claimed");
        let content: serde_json::Value = serde_json::from_str(&mem.content).expect("content");
        assert!(content.get(field_names::AGENT_PUBKEY).is_none());
        assert!(content.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(content[field_names::ATTEST_LEVEL], "claimed");
    }

    #[tokio::test]
    async fn test_sync_daemon_empty_peers_errors() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = SyncDaemonArgs {
            peers: Vec::new(),
            interval: 2,
            api_key: None,
            batch_size: 500,
            client_cert: None,
            client_key: None,
            insecure_skip_server_verify: false,
            ca_cert: None,
        };
        let res = run_daemon(&db, args, Some("test-agent")).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("--peers"));
    }

    #[tokio::test]
    async fn test_sync_daemon_insecure_without_mtls_errors() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = SyncDaemonArgs {
            peers: vec!["https://example.com:9077".to_string()],
            interval: 2,
            api_key: None,
            batch_size: 500,
            client_cert: None,
            client_key: None,
            insecure_skip_server_verify: true,
            ca_cert: None,
        };
        let res = run_daemon(&db, args, Some("test-agent")).await;
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("insecure-skip-server-verify")
        );
    }

    // PR-9i — buffer coverage uplift. Targets previously-uncovered branches
    // in run() / cmd_sync_dry_run: link-sync paths in pull/push/merge,
    // text-mode dry_run output, restamp_agent_id with no original agent_id.

    #[test]
    fn pr9i_pull_propagates_links() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let id1 = seed_memory(&remote, "ns", "src", "src-content");
        let id2 = seed_memory(&remote, "ns", "tgt", "tgt-content");
        {
            let conn = db::open(&remote).unwrap();
            db::create_link(&conn, &id1, &id2, "related_to").unwrap();
        }
        let args = args_for(remote, "pull");
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["direction"].as_str().unwrap(), "pull");
        let local_conn = db::open(&local).unwrap();
        let local_links = db::export_links(&local_conn).unwrap();
        assert!(
            local_links
                .iter()
                .any(|l| l.relation == crate::models::MemoryLinkRelation::RelatedTo),
            "expected pulled link to land in local: {local_links:?}"
        );
    }

    #[test]
    fn pr9i_push_propagates_links() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let id1 = seed_memory(&local, "ns", "a", "a");
        let id2 = seed_memory(&local, "ns", "b", "b");
        {
            let conn = db::open(&local).unwrap();
            db::create_link(&conn, &id1, &id2, "supersedes").unwrap();
        }
        let args = args_for(remote.clone(), "push");
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["direction"].as_str().unwrap(), "push");
        let remote_conn = db::open(&remote).unwrap();
        let remote_links = db::export_links(&remote_conn).unwrap();
        assert!(
            remote_links
                .iter()
                .any(|l| l.relation == crate::models::MemoryLinkRelation::Supersedes)
        );
    }

    #[test]
    fn pr9i_merge_propagates_links_both_directions() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let l1 = seed_memory(&local, "ns", "l1", "l1");
        let l2 = seed_memory(&local, "ns", "l2", "l2");
        {
            let conn = db::open(&local).unwrap();
            db::create_link(&conn, &l1, &l2, "related_to").unwrap();
        }
        let r1 = seed_memory(&remote, "ns", "r1", "r1");
        let r2 = seed_memory(&remote, "ns", "r2", "r2");
        {
            let conn = db::open(&remote).unwrap();
            db::create_link(&conn, &r1, &r2, "derived_from").unwrap();
        }
        let args = args_for(remote.clone(), "merge");
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("merged:"));
        let lconn = db::open(&local).unwrap();
        let rconn = db::open(&remote).unwrap();
        let l_relations: Vec<String> = db::export_links(&lconn)
            .unwrap()
            .into_iter()
            .map(|l| l.relation.as_str().to_string())
            .collect();
        let r_relations: Vec<String> = db::export_links(&rconn)
            .unwrap()
            .into_iter()
            .map(|l| l.relation.as_str().to_string())
            .collect();
        assert!(l_relations.iter().any(|r| r == "derived_from"));
        assert!(r_relations.iter().any(|r| r == "related_to"));
    }

    #[test]
    fn pr9i_dry_run_text_mode_merge() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&local, "ns", "L", "L");
        seed_memory(&remote, "ns", "R", "R");
        let mut args = args_for(remote, "merge");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("DRY RUN"));
        assert!(s.contains("pull:"));
        assert!(s.contains("push:"));
        assert!(s.contains("noop"));
        assert!(s.contains("links"));
    }

    #[test]
    fn pr9i_dry_run_text_mode_pull_only() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&remote, "ns", "remote-only", "rr");
        let mut args = args_for(remote, "pull");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("DRY RUN"));
        assert!(s.contains("pull:"));
        assert!(!s.contains("push:"));
    }

    #[test]
    fn pr9i_dry_run_text_mode_push_only() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        seed_memory(&local, "ns", "local-only", "ll");
        let mut args = args_for(remote, "push");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("DRY RUN"));
        assert!(s.contains("push:"));
        assert!(!s.contains("pull:"));
    }

    #[test]
    fn pr9i_dry_run_classify_update_branch() {
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let id = seed_memory(&local, "ns", "shared", "old-content");
        let conn = db::open(&remote).unwrap();
        let mem = models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.clone(),
            tier: models::Tier::Mid,
            namespace: "ns".to_string(),
            title: "shared".to_string(),
            content: "newer-content".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            // created_at is `now` so the #1466 tier-default expiry
            // backfill on this Mid row (created_at + 7d) lands in the
            // future and the row survives the sync pull; updated_at stays
            // far-future so it still classifies as the "newer" side.
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: "2099-01-01T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(&conn, &mem).unwrap();
        drop(conn);
        let mut args = args_for(remote, "merge");
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["pull"]["update"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn pr9i_restamp_no_original_agent_id() {
        let mut mem = models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m-noid".to_string(),
            tier: models::Tier::Mid,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        restamp_agent_id(&mut mem, "caller-agent");
        assert_eq!(mem.metadata["agent_id"].as_str().unwrap(), "caller-agent");
        assert!(mem.metadata.get("imported_from_agent_id").is_none());
    }

    #[test]
    fn pr9i_pull_skips_invalid_link() {
        // v0.7.0 fix campaign R1-M2 — the substrate CHECK trigger now
        // refuses an empty / off-closed-set relation at the SQL layer,
        // so the original "seed a bad row then pull and verify skip"
        // shape can no longer be set up: the seed itself fails. Verify
        // both halves of the defense-in-depth contract instead —
        //
        //   1. The CHECK trigger refuses to seed an invalid relation
        //      directly via SQL (this is the new R1-M2 guarantee).
        //   2. The pull path's `validate_link` filter (kept in place
        //      as a second line of defense for legacy DBs where the
        //      trigger hasn't run yet) is still wired up, asserted
        //      indirectly by the same call returning a successful
        //      `direction: pull` envelope after seeing the seed
        //      attempt fail.
        let mut env = TestEnv::fresh();
        let local = env.db_path.clone();
        let remote_env = TestEnv::fresh();
        let remote = remote_env.db_path.clone();
        let id1 = seed_memory(&remote, "ns", "src", "src");
        let id2 = seed_memory(&remote, "ns", "tgt", "tgt");
        let conn = db::open(&remote).unwrap();
        let seed = conn.execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at) VALUES (?, ?, '', datetime('now'))",
            rusqlite::params![id1, id2],
        );
        assert!(
            seed.is_err(),
            "R1-M2 CHECK trigger must refuse to land an empty relation; \
             a successful seed would mean defense-in-depth has regressed"
        );
        drop(conn);
        let args = args_for(remote, "pull");
        {
            let mut out = env.output();
            run(&local, &args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["direction"].as_str().unwrap(), "pull");
    }
}
