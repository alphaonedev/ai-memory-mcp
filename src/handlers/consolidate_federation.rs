// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2860 (federation data-integrity, 5-agent vote `4d3ea1c5`, decision memory
//! `8b428944`) — helpers that make a TENANT-facing federated consolidation
//! CONVERGE across a strict-write-sig mesh.
//!
//! **The gap.** `POST /api/v1/consolidate` mints a NEW substrate-derived memory
//! (an LLM summary or a deterministic title-concat produced by the origin
//! DAEMON) and — pre-#2860 — stamped `metadata.agent_id = <tenant>` with NO
//! `metadata.write_signature`. The origin daemon CANNOT produce the tenant's
//! Ed25519 signature, so under the v1.0.0-default strict
//! `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1` the receiver's per-write attestation gate
//! refused it as an unsigned HONORED third-party relay (`attribute != sender`)
//! → it committed on the origin but NEVER converged to peers (#2856 filed the
//! silent divergence; #2861 shipped the loud-202 floor; THIS closes the gap).
//!
//! **The fix (Option A — substrate-authored self-relay + emit-sig).** On the
//! FEDERATED path the consolidated row is authored as the origin daemon's
//! federation identity ([`crate::federation::FederationConfig::sender_agent_id`])
//! — the substrate node that ACTUALLY derived the bytes and that HOLDS the key
//! it signs with. That makes the receive gate's `require = require_write_sig &&
//! (attribute != sender)` structurally FALSE (self-relay), so the row converges
//! at EVERY peer regardless of key enrollment; and a best-effort daemon
//! `write_signature` over the standard 6-field `SignableWrite` envelope upgrades
//! it to `attest_level=agent_attested` wherever the daemon key is enrolled (the
//! posture the hardened `asi-hard` profile, which pins
//! `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1`, requires for a VISIBLE, non-
//! quarantined convergence). Authoring as the sender is crypto-honest
//! (`agent_id == signer == sender`, no CWE-346 decoupling) and matches the
//! already-converging curator `ConsolidationPass` (author = `AI_CURATOR`
//! substrate sentinel). The invoking tenant + source authors are retained as
//! UNTRUSTED provenance ([`META_CONSOLIDATOR_TENANT`] + the existing
//! `consolidated_from_agents`), and the content-authorship truth of a
//! caller-SUPPLIED summary is preserved in [`META_SUMMARY_SOURCE`].

use crate::models::{Memory, MemoryLink, MemoryLinkRelation, field_names};

/// `metadata.consolidator_tenant` — the tenant that INVOKED a substrate-authored
/// federated consolidation. **UNTRUSTED provenance** (rides unsigned metadata):
/// nothing may authorize, isolate, quota, bill, or delete off this key (the
/// #2860 security-lens ruling — the instant something does, the CWE-345 honesty
/// guarantee lapses). The signed authorship (`metadata.agent_id`) is the
/// substrate; this only records "on whose behalf".
pub(crate) const META_CONSOLIDATOR_TENANT: &str = "consolidator_tenant";

/// `metadata.summary_source` — `"caller"` when the consolidation's `content` is
/// the VERBATIM tenant-supplied summary (genuinely tenant-authored bytes) or
/// `"substrate"` when the daemon derived it (LLM / deterministic concat). Keeps
/// the row's authorship record truthful even though `agent_id` names the
/// substrate that assembled + signs the row (#2860 truthfulness lens).
pub(crate) const META_SUMMARY_SOURCE: &str = "summary_source";
/// [`META_SUMMARY_SOURCE`] value: caller supplied the summary bytes verbatim.
pub(crate) const SUMMARY_SOURCE_CALLER: &str = "caller";
/// [`META_SUMMARY_SOURCE`] value: the substrate (daemon) derived the summary.
pub(crate) const SUMMARY_SOURCE_SUBSTRATE: &str = "substrate";

/// Classify the consolidation's content authorship from the request's raw
/// `summary` field: a non-empty caller-supplied summary is genuinely
/// tenant-authored CONTENT ([`SUMMARY_SOURCE_CALLER`]); an absent / empty one
/// means the daemon derived it (LLM or deterministic concat,
/// [`SUMMARY_SOURCE_SUBSTRATE`]). Keeps the row's authorship record truthful
/// even though `agent_id` names the substrate that assembled + signs the row.
#[must_use]
pub(crate) fn summary_source_of(raw_summary: Option<&str>) -> &'static str {
    if raw_summary.is_some_and(|s| !s.trim().is_empty()) {
        SUMMARY_SOURCE_CALLER
    } else {
        SUMMARY_SOURCE_SUBSTRATE
    }
}

/// Finalize a substrate-authored consolidated row's metadata for federation:
/// take the read-back row's metadata (whose `agent_id` is already the substrate
/// author == `author_agent_id`) and additively stamp the [`META_CONSOLIDATOR_TENANT`]
/// + [`META_SUMMARY_SOURCE`] provenance keys, then BEST-EFFORT sign the row with
/// the daemon's `author_agent_id` keypair, persisting `metadata.write_signature`
/// + `metadata.attest_level = agent_attested`.
///
/// Returns the FULL replacement metadata `Value` and whether a signature was
/// emitted. When no daemon signing key is enrolled the row converges as
/// `claimed` (still fixes the divergence); no fields other than the two
/// provenance keys are added in that case. The signature commits ONLY to the
/// 6-field `SignableWrite` envelope (`agent_id + namespace + title + kind +
/// created_at + sha256(content)`), which excludes `metadata`, so stamping the
/// provenance keys never invalidates it, and it is computed over the PLAINTEXT
/// `content` the broadcast + receiver see (never an at-rest ciphertext).
#[must_use]
pub(crate) fn finalize_consolidation_metadata(
    mem: &Memory,
    author_agent_id: &str,
    signing_keypair: Option<&crate::identity::keypair::AgentKeypair>,
    consolidator_tenant: &str,
    summary_source: &str,
) -> (serde_json::Value, bool) {
    let mut meta = mem.metadata.clone();
    if let Some(obj) = meta.as_object_mut() {
        if !consolidator_tenant.is_empty() {
            obj.insert(
                META_CONSOLIDATOR_TENANT.to_string(),
                serde_json::Value::String(consolidator_tenant.to_string()),
            );
        }
        obj.insert(
            META_SUMMARY_SOURCE.to_string(),
            serde_json::Value::String(summary_source.to_string()),
        );
    }
    let signed = match signing_keypair {
        Some(kp) => sign_into_metadata(&mut meta, mem, author_agent_id, kp),
        None => false,
    };
    (meta, signed)
}

/// Best-effort load of the daemon's signing keypair for the federation identity
/// that will AUTHOR (and self-attest) a consolidated row. Returns `None` when no
/// private key is enrolled on disk — the consolidation then converges `claimed`
/// (still fixed; only the `agent_attested` upgrade is skipped). The daemon HOLDS
/// this key (it is the same identity it signs the `/sync/push` envelope with),
/// so signing as it is honest self-attestation, never a CWE-346 decoupling.
#[must_use]
pub(crate) fn load_author_signing_keypair(
    author_agent_id: &str,
) -> Option<crate::identity::keypair::AgentKeypair> {
    let dir = crate::identity::keypair::default_key_dir().ok()?;
    let kp = crate::identity::keypair::load(author_agent_id, &dir).ok()?;
    if kp.private.is_none() {
        return None;
    }
    Some(kp)
}

/// Sign `mem`'s 6-field `SignableWrite` with `keypair` (whose identity is
/// `author_agent_id == mem.metadata.agent_id`) and stamp
/// `metadata.write_signature` (base64) + `metadata.attest_level=agent_attested`.
/// The envelope excludes `metadata`, so stamping these keys never invalidates
/// the signature, and it commits over the PLAINTEXT `content` the broadcast +
/// receiver see. Returns `false` on a signing failure (e.g. a public-only key).
fn sign_into_metadata(
    meta: &mut serde_json::Value,
    mem: &Memory,
    author_agent_id: &str,
    keypair: &crate::identity::keypair::AgentKeypair,
) -> bool {
    use base64::Engine as _;
    let Ok(sig) = crate::identity::attest::sign_memory_write(keypair, mem, author_agent_id) else {
        return false;
    };
    let Some(obj) = meta.as_object_mut() else {
        return false;
    };
    obj.insert(
        field_names::WRITE_SIGNATURE.to_string(),
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&sig)),
    );
    obj.insert(
        field_names::ATTEST_LEVEL.to_string(),
        serde_json::Value::String(
            crate::identity::verify::AttestLevel::AgentAttested
                .as_str()
                .to_string(),
        ),
    );
    true
}

/// Build the navigable `derived_from` edges (`C -> source`, one per source)
/// that must converge to peers alongside the consolidated row when the sources
/// are TOMBSTONED (retained) rather than hard-deleted — mirroring the origin's
/// `db::consolidate` edge writes. Unsigned advisory provenance edges (the
/// `source_cid`/`target_cid` mirror is repopulated by the receiver's link-apply
/// path). Empty under the legacy hard-delete disposition (the edges would be
/// cascade-deleted on both ends, so `metadata.derived_from` carries provenance
/// instead).
#[must_use]
pub(crate) fn derived_from_edges(consolidated: &Memory, source_ids: &[String]) -> Vec<MemoryLink> {
    source_ids
        .iter()
        .map(|source_id| MemoryLink {
            source_id: consolidated.id.clone(),
            target_id: source_id.clone(),
            relation: MemoryLinkRelation::DerivedFrom,
            created_at: consolidated.created_at.clone(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        })
        .collect()
}

/// The broadcast disposition for a federated consolidation: the source ids to
/// hard-DELETE at peers (legacy), the RETAINED tombstoned source rows to
/// re-broadcast (tombstone disposition), and the `derived_from` edges to ship.
pub(crate) struct FanoutDisposition {
    pub deletions: Vec<String>,
    pub tombstoned_sources: Vec<Memory>,
    pub derived_edges: Vec<MemoryLink>,
}

/// SQLITE federated-consolidate finalize + disposition (shared, testable). On
/// the read-back consolidated row `mem` (already authored as `author_id` == the
/// federation sender): stamp the substrate `write_signature` + tenant/summary
/// provenance (persisting it in place so the stored origin row byte-matches the
/// broadcast copy), mutate `mem.metadata` to the finalized value, then compute
/// the source disposition — under the v1.0.0-default tombstone posture the
/// RETAINED tombstoned source rows are re-broadcast (no `deletions`) alongside
/// the navigable `derived_from` edges; otherwise the legacy `deletions` list is
/// returned. All reads/writes go through the caller's already-open connection.
pub(crate) fn sqlite_finalize_and_disposition(
    conn: &rusqlite::Connection,
    mem: &mut Memory,
    source_ids: &[String],
    author_id: &str,
    consolidator_tenant: &str,
    raw_summary: Option<&str>,
) -> FanoutDisposition {
    let summary_source = summary_source_of(raw_summary);
    let author_kp = load_author_signing_keypair(author_id);
    let (final_meta, _signed) = finalize_consolidation_metadata(
        mem,
        author_id,
        author_kp.as_ref(),
        consolidator_tenant,
        summary_source,
    );
    if let Ok(js) = serde_json::to_string(&final_meta) {
        if let Err(e) = crate::db::set_row_metadata(conn, &mem.id, &js) {
            tracing::warn!(
                "consolidate: failed to persist federated attestation metadata for {}: {e}",
                mem.id
            );
        }
    }
    mem.metadata = final_meta;
    if crate::config::consolidate_tombstone_sources_enabled() {
        let tombstoned_sources = source_ids
            .iter()
            .filter_map(|id| crate::db::get(conn, id).ok().flatten())
            .collect();
        let derived_edges = derived_from_edges(mem, source_ids);
        FanoutDisposition {
            deletions: Vec::new(),
            tombstoned_sources,
            derived_edges,
        }
    } else {
        FanoutDisposition {
            deletions: source_ids.to_vec(),
            tombstoned_sources: Vec::new(),
            derived_edges: Vec::new(),
        }
    }
}

/// SAL-store (postgres) twin of [`sqlite_finalize_and_disposition`] — identical
/// finalize + disposition logic routed through the `MemoryStore` trait so the
/// two backends cannot drift. `ctx` is the SOURCE-read context (the invoking
/// tenant, who owns the sources); `set_row_metadata` ignores it (in-place
/// by-id). `mem` is the read-back consolidated row (already authored as
/// `author_id`).
#[cfg(feature = "sal")]
pub(crate) async fn store_finalize_and_disposition(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    mem: &mut Memory,
    source_ids: &[String],
    author_id: &str,
    consolidator_tenant: &str,
    raw_summary: Option<&str>,
) -> FanoutDisposition {
    let summary_source = summary_source_of(raw_summary);
    let author_kp = load_author_signing_keypair(author_id);
    let (final_meta, _signed) = finalize_consolidation_metadata(
        mem,
        author_id,
        author_kp.as_ref(),
        consolidator_tenant,
        summary_source,
    );
    if let Ok(js) = serde_json::to_string(&final_meta) {
        if let Err(e) = store.set_row_metadata(ctx, &mem.id, &js).await {
            tracing::warn!(
                "consolidate(pg): failed to persist federated attestation metadata for {}: {e}",
                mem.id
            );
        }
    }
    mem.metadata = final_meta;
    if crate::config::consolidate_tombstone_sources_enabled() {
        let mut tombstoned_sources = Vec::with_capacity(source_ids.len());
        for id in source_ids {
            if let Ok(src) = store.get(ctx, id).await {
                tombstoned_sources.push(src);
            }
        }
        let derived_edges = derived_from_edges(mem, source_ids);
        FanoutDisposition {
            deletions: Vec::new(),
            tombstoned_sources,
            derived_edges,
        }
    } else {
        FanoutDisposition {
            deletions: source_ids.to_vec(),
            tombstoned_sources: Vec::new(),
            derived_edges: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! #2860 regression — pins that a substrate-authored (self-relayed)
    //! consolidation CONVERGES under the v1.0.0-default strict
    //! `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1`, both as a signed `agent_attested`
    //! row (daemon key enrolled) and as an unsigned `claimed` self-relay
    //! (structurally accepted because `attribute == sender`) — the exact gap
    //! #2856/#2860 filed. Complements the live 2-node pg+AGE convergence repro.
    use super::*;
    use crate::identity::verify::AttestLevel;
    use crate::identity::{attest, keypair};
    use crate::models::Memory;

    /// The daemon federation identity that authors a federated consolidation.
    const SENDER: &str = "ai:node1";
    /// The invoking tenant (retained only as untrusted provenance).
    const TENANT: &str = "tenant:alice";

    fn pk_b64(kp: &keypair::AgentKeypair) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes())
    }

    /// A consolidated row as `db::consolidate` mints it on the FEDERATED path:
    /// `metadata.agent_id` already the substrate sender.
    fn consolidated_mem() -> Memory {
        Memory {
            id: "c-2860".to_string(),
            namespace: "team/alpha".to_string(),
            title: "merged deployment notes".to_string(),
            content: "scale to three replicas; use the blue-green rollout".to_string(),
            created_at: "2026-08-10T12:00:00+00:00".to_string(),
            metadata: serde_json::json!({
                "agent_id": SENDER,
                "consolidated_from_agents": ["tenant:alice", "tenant:bob"],
            }),
            ..Memory::default()
        }
    }

    #[test]
    fn finalize_with_daemon_key_lands_agent_attested_and_verifies() {
        let kp = keypair::generate(SENDER).expect("gen daemon key");
        let mem = consolidated_mem();
        let (meta, signed) = finalize_consolidation_metadata(
            &mem,
            SENDER,
            Some(&kp),
            TENANT,
            SUMMARY_SOURCE_SUBSTRATE,
        );
        assert!(signed, "a daemon key must produce a write_signature");
        let obj = meta.as_object().unwrap();
        // Provenance stamped.
        assert_eq!(obj[META_CONSOLIDATOR_TENANT], serde_json::json!(TENANT));
        assert_eq!(
            obj[META_SUMMARY_SOURCE],
            serde_json::json!(SUMMARY_SOURCE_SUBSTRATE)
        );
        assert_eq!(
            obj[field_names::ATTEST_LEVEL],
            serde_json::json!(AttestLevel::AgentAttested.as_str())
        );
        // The emitted signature must actually VERIFY at a receiver: recompute
        // the attestation over the SAME row + the sender's enrolled pubkey.
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(obj[field_names::WRITE_SIGNATURE].as_str().unwrap())
            .expect("decode write_signature");
        let mut verify_mem = consolidated_mem();
        let level = attest::stamp_attestation(
            &mut verify_mem,
            SENDER,
            Some(&pk_b64(&kp)),
            Some(&sig),
            true, // strict — this is the honored self-relay lane's verify
        )
        .expect("substrate-signed consolidation must verify under strict");
        assert_eq!(
            level,
            AttestLevel::AgentAttested,
            "a daemon-signed consolidation converges agent_attested where the key is enrolled"
        );
    }

    #[test]
    fn self_relay_converges_claimed_without_a_key() {
        // No daemon key on disk: finalize adds only provenance, no signature.
        let mem = consolidated_mem();
        let (meta, signed) =
            finalize_consolidation_metadata(&mem, SENDER, None, TENANT, SUMMARY_SOURCE_CALLER);
        assert!(!signed);
        let obj = meta.as_object().unwrap();
        assert!(!obj.contains_key(field_names::WRITE_SIGNATURE));
        assert_eq!(
            obj[META_SUMMARY_SOURCE],
            serde_json::json!(SUMMARY_SOURCE_CALLER)
        );
        // The receiver gate computes `require = strict && (attribute != sender)`;
        // for a self-relay (author == sender) that is FALSE, so an UNSIGNED
        // consolidation is still ACCEPTED (lands `claimed`) — the structural
        // reason authoring-as-sender converges at EVERY peer regardless of key
        // enrollment. Mirror that self-relay verify here (require = false).
        let mut verify_mem = consolidated_mem();
        let level = attest::stamp_attestation(&mut verify_mem, SENDER, None, None, false)
            .expect("self-relay accepts unsigned");
        assert_eq!(level, AttestLevel::Claimed);
    }

    #[test]
    fn tenant_authored_unsigned_is_refused_under_strict_honored_relay() {
        // The PRE-#2860 shape: a TENANT-attributed consolidation relayed by the
        // daemon (attribute=tenant != sender) with no verifiable signature is
        // REFUSED under strict — the exact divergence #2860 closes by moving
        // authorship to the sender (above).
        let mut mem = consolidated_mem();
        mem.metadata
            .as_object_mut()
            .unwrap()
            .insert("agent_id".to_string(), serde_json::json!("tenant:alice"));
        // Honored third-party relay verify: no bound key, no signature, strict.
        let err = attest::stamp_attestation(&mut mem, "tenant:alice", None, None, true);
        assert!(
            err.is_err(),
            "an unsigned honored third-party (tenant) relay must be refused under strict"
        );
    }

    #[test]
    fn summary_source_classification() {
        assert_eq!(
            summary_source_of(Some("a real summary")),
            SUMMARY_SOURCE_CALLER
        );
        assert_eq!(summary_source_of(Some("   ")), SUMMARY_SOURCE_SUBSTRATE);
        assert_eq!(summary_source_of(None), SUMMARY_SOURCE_SUBSTRATE);
    }

    #[test]
    fn derived_from_edges_point_from_consolidation_to_each_source() {
        let mem = consolidated_mem();
        let sources = vec!["src-a".to_string(), "src-b".to_string()];
        let edges = derived_from_edges(&mem, &sources);
        assert_eq!(edges.len(), 2);
        for (edge, src) in edges.iter().zip(sources.iter()) {
            assert_eq!(
                edge.source_id, mem.id,
                "edge originates at the consolidation"
            );
            assert_eq!(&edge.target_id, src, "edge targets the source");
            assert_eq!(
                edge.relation,
                crate::models::MemoryLinkRelation::DerivedFrom
            );
            assert_eq!(edge.created_at, mem.created_at);
        }
    }

    // ---- finalize+disposition helper coverage (both backend twins) ----

    use std::sync::Mutex;
    /// Serializes the tombstone/lineage process-global flag flips.
    static FLAG_LOCK: Mutex<()> = Mutex::new(());

    fn seed_mem(id: &str, ns: &str, title: &str, author: &str) -> Memory {
        Memory {
            id: id.to_string(),
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("content for {title} alpha beta gamma"),
            created_at: "2026-08-10T12:00:00+00:00".to_string(),
            updated_at: "2026-08-10T12:00:00+00:00".to_string(),
            metadata: serde_json::json!({ "agent_id": author }),
            ..Memory::default()
        }
    }

    /// SQLITE twin: `sqlite_finalize_and_disposition` under the tombstone
    /// disposition stamps the provenance, persists it in place, and returns the
    /// retained tombstoned sources + navigable edges (no `deletions`).
    #[test]
    fn sqlite_finalize_and_disposition_tombstone_disposition() {
        let _g = FLAG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::config::set_lineage_dag(true);
        crate::config::set_consolidate_tombstone_sources(true);

        let dir = tempfile::tempdir().expect("tempdir");
        let conn = crate::db::open(&dir.path().join("t.db")).expect("open");
        let ns = "fed-consolidate-2860";
        crate::db::insert(&conn, &seed_mem("src-a", ns, "A", "tenant:alice")).expect("a");
        crate::db::insert(&conn, &seed_mem("src-b", ns, "B", "tenant:alice")).expect("b");
        let mut consolidated = seed_mem("c-2860", ns, "merged", SENDER);
        crate::db::insert(&conn, &consolidated).expect("c");

        let disp = sqlite_finalize_and_disposition(
            &conn,
            &mut consolidated,
            &["src-a".to_string(), "src-b".to_string()],
            SENDER,
            TENANT,
            Some("a caller summary"),
        );

        crate::config::set_lineage_dag(false);
        crate::config::set_consolidate_tombstone_sources(false);

        assert!(
            disp.deletions.is_empty(),
            "tombstone mode ships no hard deletions"
        );
        assert_eq!(
            disp.tombstoned_sources.len(),
            2,
            "both retained sources re-broadcast"
        );
        assert_eq!(
            disp.derived_edges.len(),
            2,
            "one derived_from edge per source"
        );
        // Provenance stamped on the in-memory row AND persisted.
        assert_eq!(
            consolidated.metadata[META_CONSOLIDATOR_TENANT],
            serde_json::json!(TENANT)
        );
        assert_eq!(
            consolidated.metadata[META_SUMMARY_SOURCE],
            serde_json::json!(SUMMARY_SOURCE_CALLER)
        );
        let persisted = crate::db::get(&conn, "c-2860")
            .expect("get")
            .expect("present");
        assert_eq!(
            persisted.metadata[META_CONSOLIDATOR_TENANT],
            serde_json::json!(TENANT),
            "finalize metadata persisted to the origin row (byte-matches broadcast)"
        );
    }

    /// SQLITE twin, legacy hard-delete disposition: `deletions` carries the
    /// source ids and no tombstoned rows / edges are shipped.
    #[test]
    fn sqlite_finalize_and_disposition_legacy_delete_disposition() {
        let _g = FLAG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::config::set_lineage_dag(false);
        crate::config::set_consolidate_tombstone_sources(false);

        let dir = tempfile::tempdir().expect("tempdir");
        let conn = crate::db::open(&dir.path().join("t.db")).expect("open");
        let mut consolidated = seed_mem("c-legacy", "ns", "merged", SENDER);
        crate::db::insert(&conn, &consolidated).expect("c");
        let disp = sqlite_finalize_and_disposition(
            &conn,
            &mut consolidated,
            &["src-a".to_string(), "src-b".to_string()],
            SENDER,
            TENANT,
            None,
        );
        assert_eq!(
            disp.deletions.len(),
            2,
            "legacy disposition hard-deletes sources"
        );
        assert!(disp.tombstoned_sources.is_empty());
        assert!(disp.derived_edges.is_empty());
        assert_eq!(
            consolidated.metadata[META_SUMMARY_SOURCE],
            serde_json::json!(SUMMARY_SOURCE_SUBSTRATE)
        );
    }

    /// SAL twin: `store_finalize_and_disposition` runs the IDENTICAL body
    /// through the `MemoryStore` trait — exercised here with a `SqliteStore`
    /// (so the postgres branch's finalize logic is covered without a live pg).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn store_finalize_and_disposition_matches_sqlite_twin() {
        use crate::store::{CallerContext, MemoryStore};
        let _g = FLAG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::config::set_lineage_dag(true);
        crate::config::set_consolidate_tombstone_sources(true);

        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::store::sqlite::SqliteStore::open(dir.path().join("s.db")).expect("open");
        let tenant_ctx = CallerContext::for_agent(TENANT);
        store
            .store(&tenant_ctx, &seed_mem("s-a", "ns", "A", TENANT))
            .await
            .expect("a");
        store
            .store(&tenant_ctx, &seed_mem("s-b", "ns", "B", TENANT))
            .await
            .expect("b");
        let mut consolidated = seed_mem("s-c", "ns", "merged", SENDER);
        store
            .store(&CallerContext::for_agent(SENDER), &consolidated)
            .await
            .expect("c");

        let disp = store_finalize_and_disposition(
            &store,
            &tenant_ctx,
            &mut consolidated,
            &["s-a".to_string(), "s-b".to_string()],
            SENDER,
            TENANT,
            Some("caller text"),
        )
        .await;

        crate::config::set_lineage_dag(false);
        crate::config::set_consolidate_tombstone_sources(false);

        assert!(disp.deletions.is_empty());
        assert_eq!(disp.tombstoned_sources.len(), 2);
        assert_eq!(disp.derived_edges.len(), 2);
        assert_eq!(
            consolidated.metadata[META_CONSOLIDATOR_TENANT],
            serde_json::json!(TENANT)
        );
        assert_eq!(
            consolidated.metadata[META_SUMMARY_SOURCE],
            serde_json::json!(SUMMARY_SOURCE_CALLER)
        );
    }
}
