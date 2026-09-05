// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Schema-v97 public-key enrollment, history, and attestation resolution.

use super::{agent_pubkey, connection};
use crate::models::{AGENTS_NAMESPACE, Memory, field_names};
use anyhow::{Context as _, Result};
use chrono::Utc;
use rusqlite::{Connection, params};

/// Strip an unproven public-key binding from both `_agents` JSON mirrors.
/// History is authoritative; generic/import/federation writes carry no PoP or
/// lineage witness. Because stripping changes signed bytes, it also removes
/// `write_signature` and forces `claimed`. Malformed opaque content remains
/// untouched (it is not a trust input), while metadata is still downgraded.
///
/// Returns `true` when at least one field was removed.
pub(crate) fn strip_unproven_agent_pubkey_binding(mem: &mut Memory) -> bool {
    if mem.namespace != AGENTS_NAMESPACE {
        return false;
    }

    fn strip_pair(value: &mut serde_json::Value) -> bool {
        let Some(obj) = value.as_object_mut() else {
            return false;
        };
        let key = obj.remove(field_names::AGENT_PUBKEY).is_some();
        let bound = obj.remove(field_names::PUBKEY_BOUND_AT).is_some();
        key || bound
    }

    let mut stripped = strip_pair(&mut mem.metadata);
    let mut mirrored = serde_json::from_str::<serde_json::Value>(&mem.content).ok();
    if let Some(mirrored) = mirrored.as_mut() {
        if strip_pair(mirrored) {
            stripped = true;
        }
    }
    if stripped {
        downgrade_registration_attestation(&mut mem.metadata);
        if let Some(mirrored) = mirrored.as_mut() {
            downgrade_registration_attestation(mirrored);
            if let Ok(encoded) = serde_json::to_string(mirrored) {
                mem.content = encoded;
            }
        }
    }
    stripped
}

/// Clear a stale registration signature after bind/rotate/revoke changes its
/// signed bytes. Called inside the history/projection transaction.
pub(crate) fn downgrade_registration_attestation(value: &mut serde_json::Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    obj.remove(field_names::WRITE_SIGNATURE);
    obj.insert(
        field_names::ATTEST_LEVEL.to_string(),
        serde_json::Value::String(
            crate::identity::verify::AttestLevel::Claimed
                .as_str()
                .to_string(),
        ),
    );
}

/// Bind (or rotate) an agent's Ed25519 public key into its `_agents`
/// registration row metadata (#626 Layer-3, Task 1.3 / C3).
///
/// The pubkey is the anchor the write-path attestation gate verifies
/// against: a signed write claiming `agent_id` is upgraded from *claimed*
/// to *attested* only when its signature verifies under the key bound
/// here. Stored under `metadata.agent_pubkey` (URL-safe-no-pad base64)
/// alongside a `pubkey_bound_at` RFC3339 timestamp for rotation
/// provenance.
///
/// The live-key mirror still rides in the registration row's JSON, while
/// schema v97 makes the append-only `agent_pubkey_history` ledger the trust
/// authority. `json_set` updates `metadata` and mirrored `content` only after
/// that ledger admits the binding in the same transaction; the v97 trigger
/// prevents any generic row write from creating an independent flat binding.
///
/// The agent MUST already be registered (`register_agent`) — binding a
/// key to an unregistered id is rejected so a stray pubkey can never
/// shadow a future legitimate registration.
///
/// # v1.0.0 #3464 — proof of possession, and the append-only history
///
/// The `proof` witness is the control. Pre-#3464 this funnel took a
/// SELF-ASSERTED key: admin-gated, curve-validated and audited, but with
/// nothing proving the caller held the matching private key. Anyone with the
/// admin role could bind a key they owned to another agent's id and then mint
/// `agent_attested` writes as that agent — the substrate's strongest
/// provenance claim, forgeable from a role claim.
/// [`crate::identity::pubkey_bind::PossessionProof`] has no
/// public constructor, so requiring one here makes the unproven bind
/// UNREPRESENTABLE on every present and future surface rather than merely
/// guarded at the ones that exist today (rust-1.98 ERRORS-09).
///
/// Re-binding no longer DESTROYS the previous key. Every distinct key is
/// appended to `agent_pubkey_history` with a dense 1-based `version` and a
/// `[bound_at, superseded_at)` window, so an `agent_attested` row signed under
/// an older key stays verifiable against the key that actually signed it (see
/// [`agent_pubkey_for_attestation_at`]). Re-binding the SAME key is idempotent:
/// it retains the history row's original `bound_at`/flat projection and
/// appends no version, so a `register_agent` refresh or retried bind cannot
/// move the validity boundary or inflate the ledger.
///
/// The history append and flat binding commit in one `BEGIN IMMEDIATE`
/// transaction. [`super::append_lineage_record`] calls the private no-transaction
/// helper while it already owns that transaction, avoiding a nested begin
/// without weakening atomicity.
///
/// # Errors
///
/// - the agent is not registered (no `_agents` row for `agent_id`)
/// - the history append or the underlying `UPDATE` fails
pub fn bind_agent_pubkey(
    conn: &Connection,
    agent_id: &str,
    pubkey_b64: &str,
    proof: crate::identity::pubkey_bind::PossessionProof,
) -> Result<()> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let pubkey_b64 = crate::identity::keypair::canonical_public_base64(pubkey_b64)
        .context("canonicalizing agent pubkey for bind")?;
    let write_txn = connection::WriteTxn::begin(conn).context("bind_agent_pubkey: begin tx")?;
    let result = bind_agent_pubkey_no_tx(conn, agent_id, &pubkey_b64, &proof);
    match result {
        Ok(()) => {
            write_txn.commit().context("bind_agent_pubkey: commit tx")?;
            Ok(())
        }
        Err(error) => {
            write_txn.rollback();
            Err(error)
        }
    }
}

/// In-transaction implementation shared with [`super::append_lineage_record`].
pub(super) fn bind_agent_pubkey_no_tx(
    conn: &Connection,
    agent_id: &str,
    pubkey_b64: &str,
    proof: &crate::identity::pubkey_bind::PossessionProof,
) -> Result<()> {
    use rusqlite::OptionalExtension as _;
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let title = crate::models::agent_registration_title(agent_id);
    let now = Utc::now().to_rfc3339();
    // Fail-closed BEFORE any ledger append: an unregistered agent must not
    // leave a history row behind (the flat UPDATE below is what has always
    // enforced this, and it still does — this probe only moves the refusal
    // ahead of the append so the two cannot disagree).
    let registered: i64 = conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
        params![AGENTS_NAMESPACE, &title],
        |r| r.get(0),
    )?;
    if registered == 0 {
        return Err(anyhow::anyhow!(
            crate::errors::msg::pubkey_bind_agent_not_registered(agent_id)
        ));
    }
    let flat_pubkey = agent_pubkey(conn, agent_id)?;
    let latest_history: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT pubkey_b64, superseded_at FROM agent_pubkey_history
             WHERE agent_id = ?1 ORDER BY version DESC LIMIT 1",
            params![agent_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    proof
        .authorize_storage_state(
            agent_id,
            pubkey_b64,
            flat_pubkey.as_deref(),
            latest_history
                .as_ref()
                .map(|(key, superseded)| (key.as_str(), superseded.is_none())),
        )
        .map_err(anyhow::Error::new)?;
    append_agent_pubkey_version(conn, agent_id, pubkey_b64, proof, &now)?;
    let affected = conn.execute(
        "UPDATE memories SET
            metadata = json_set(
                json_remove(metadata, '$.write_signature'),
                '$.agent_pubkey', ?3,
                '$.pubkey_bound_at', ?4,
                '$.attest_level', 'claimed'),
            content  = json_set(
                json_remove(content, '$.write_signature'),
                '$.agent_pubkey', ?3,
                '$.pubkey_bound_at', ?4,
                '$.attest_level', 'claimed'),
            updated_at = ?4
         WHERE namespace = ?1 AND title = ?2",
        params![AGENTS_NAMESPACE, &title, pubkey_b64, &now],
    )?;
    if affected == 0 {
        return Err(anyhow::anyhow!(
            crate::errors::msg::pubkey_bind_agent_not_registered(agent_id)
        ));
    }
    // APPEND-ONLY-SANCTIONED (#1823 G6) — COW SUPERSEDE: the in-place
    // pubkey-bind UPDATE rewrites the registration row's content; append
    // ONE identity-only SUPERSEDE leaf in the same connection. Gated so
    // flag-OFF skips even the id lookup (byte-identical legacy path).
    if crate::config::append_only_enabled() {
        let mid: String = conn.query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            params![AGENTS_NAMESPACE, &title],
            |r| r.get(0),
        )?;
        crate::revisions::emit_revision_leaf_if_enabled(
            conn,
            &mid,
            crate::revisions::RecordKind::Supersede,
            None,
            AGENTS_NAMESPACE,
            None,
            &now,
        )?;
    }
    Ok(())
}

/// v1.0.0 #3464 — mint and PERSIST a proof-of-possession bind challenge.
///
/// The row is the source of truth, not an in-process cache: the certified
/// postgres tier supports several daemons on one SHARED store, so issuing the
/// challenge on one replica and answering it on another is a supported shape.
/// It also survives a restart, so a rolling deploy does not silently void
/// every outstanding enrolment.
///
/// `pubkey_b64` is pinned by the ISSUER here and re-checked at consume time,
/// so a live challenge can never be retargeted at a different candidate key.
///
/// # Errors
///
/// Surfaces the underlying `INSERT` failure.
pub fn issue_pubkey_bind_challenge(
    conn: &Connection,
    agent_id: &str,
    pubkey_b64: &str,
    issuer_daemon_id: &str,
) -> Result<crate::identity::pubkey_bind::BindChallenge> {
    use crate::identity::pubkey_bind as pb;
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let pubkey_b64 = crate::identity::keypair::canonical_public_base64(pubkey_b64)
        .context("canonicalizing candidate pubkey for bind challenge")?;
    let now = Utc::now();
    let challenge = pb::BindChallenge {
        nonce_b64: pb::new_challenge_nonce(),
        agent_id: agent_id.to_string(),
        pubkey_b64,
        // Canonical fixed-UTC rendering on BOTH the stored bound and every
        // comparison against it, so the TEXT `expires_at > ?` predicate is
        // exactly instant comparison rather than a byte comparison (#3279).
        expires_at: crate::validate::canonical_rfc3339(
            &(now + chrono::Duration::seconds(pb::BIND_CHALLENGE_TTL_SECS)).to_rfc3339(),
        ),
    };
    conn.execute(
        "INSERT INTO agent_pubkey_challenges
            (challenge_id, agent_id, pubkey_b64, nonce, issued_at, expires_at,
             consumed_at, issuer_daemon_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            pb::new_challenge_id(),
            challenge.agent_id,
            challenge.pubkey_b64,
            challenge.nonce_b64,
            crate::validate::canonical_rfc3339(&now.to_rfc3339()),
            challenge.expires_at,
            issuer_daemon_id,
        ],
    )?;
    Ok(challenge)
}

/// v1.0.0 #3464 — atomically CONSUME the challenge `nonce_b64` was issued for.
///
/// Single use is the `consumed_at IS NULL` predicate of this one conditional
/// `UPDATE`: the storage engine's row-level write IS the admit-once decision,
/// never a check-then-act read, so two concurrent submissions of the same
/// captured answer can never BOTH be admitted (the v95 `attested_write_ledger`
/// discipline, where the constraint is the decision). The same `UPDATE` also
/// enforces expiry and binds the row to `agent_id`, so a challenge minted for
/// one agent cannot admit another.
///
/// Returns `Ok(None)` when the nonce is unknown, already consumed, expired, or
/// belongs to a different agent — the caller must treat all four alike and
/// refuse opaquely.
///
/// # Errors
///
/// Surfaces underlying query failures. A backend fault must NEVER flatten to
/// `Ok(None)`: that is indistinguishable from "no such challenge" and would
/// turn a transient error into a silent enrolment refusal.
pub fn consume_pubkey_bind_challenge(
    conn: &Connection,
    agent_id: &str,
    nonce_b64: &str,
) -> Result<Option<crate::identity::pubkey_bind::ConsumedBindChallenge>> {
    use rusqlite::OptionalExtension as _;
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let now = crate::validate::canonical_rfc3339(&Utc::now().to_rfc3339());
    let claimed = conn.execute(
        "UPDATE agent_pubkey_challenges SET consumed_at = ?3
         WHERE nonce = ?1 AND agent_id = ?2 AND consumed_at IS NULL AND expires_at > ?3",
        params![nonce_b64, agent_id, &now],
    )?;
    if claimed == 0 {
        return Ok(None);
    }
    // Only the winner of the conditional UPDATE reaches here, so this read
    // cannot race a second consumer.
    let row = conn
        .query_row(
            "SELECT nonce, agent_id, pubkey_b64, expires_at
             FROM agent_pubkey_challenges WHERE nonce = ?1",
            params![nonce_b64],
            |r| {
                Ok(crate::identity::pubkey_bind::BindChallenge {
                    nonce_b64: r.get(0)?,
                    agent_id: r.get(1)?,
                    pubkey_b64: r.get(2)?,
                    expires_at: r.get(3)?,
                })
            },
        )
        .optional()
        .with_context(|| format!("reading consumed bind challenge for {agent_id}"))?;
    Ok(row.map(crate::identity::pubkey_bind::ConsumedBindChallenge::from_storage))
}

/// v1.0.0 #3464 — reap bind challenges past their expiry.
///
/// Retention is bounded by the challenge TTL, never by history: the table
/// holds only short-lived enrolment state. Called from [`super::gc`]. Consumed rows
/// are reaped on the same expiry clock — the `consumed_at` stamp is forensic,
/// not a durable claim, and the single-use decision has already been made.
///
/// # Errors
///
/// Surfaces the underlying `DELETE` failure.
pub fn reap_expired_pubkey_bind_challenges(conn: &Connection) -> Result<usize> {
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let now = crate::validate::canonical_rfc3339(&Utc::now().to_rfc3339());
    let removed = conn.execute(
        "DELETE FROM agent_pubkey_challenges WHERE expires_at <= ?1",
        params![now],
    )?;
    Ok(removed)
}

/// v1.0.0 #3464 — the whole bind handshake in one call, for a caller that
/// HOLDS the candidate private key.
///
/// Issues a challenge, answers it with `signing_key`, and binds. The public
/// key is DERIVED from `signing_key`, so this entry point structurally cannot
/// bind a key the caller does not hold — it is a convenience, never a bypass.
/// Used by the CLI `agents bind-key` when the operator supplies the key file,
/// by provisioning helpers, and by tests.
///
/// # Errors
///
/// Propagates [`bind_agent_pubkey`]'s errors, plus a proof-verification
/// failure (which can only mean a broken crypto stack, since the proof is
/// minted here from the same key it is checked against).
pub fn bind_agent_pubkey_with_signing_key(
    conn: &Connection,
    agent_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let pubkey_b64 = crate::identity::keypair::encode_public_base64(&signing_key.verifying_key());
    let proof = prove_possession_with_conn(conn, agent_id, signing_key)?;
    bind_agent_pubkey(conn, agent_id, &pubkey_b64, proof)
}

/// v1.0.0 #3464 — run the full DURABLE handshake for a caller that HOLDS the
/// candidate private key, on a direct connection: issue a challenge, sign it,
/// consume it, verify.
///
/// Not a bypass: the public key is DERIVED from `signing_key`, so this can
/// only ever mint a proof for a key the caller actually holds. It is the path
/// the CLI takes when the operator supplies the key file, and the path any
/// in-process provisioning helper should take.
///
/// # Errors
///
/// Propagates the challenge INSERT/UPDATE failures, and fails closed if the
/// freshly-issued challenge cannot be consumed (in practice only a clock jump
/// past the TTL between issue and consume).
pub fn prove_possession_with_conn(
    conn: &Connection,
    agent_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<crate::identity::pubkey_bind::PossessionProof> {
    use crate::identity::pubkey_bind::{PossessionProof, sign_bind_challenge};
    let pubkey_b64 = crate::identity::keypair::encode_public_base64(&signing_key.verifying_key());
    let issued = issue_pubkey_bind_challenge(
        conn,
        agent_id,
        &pubkey_b64,
        crate::identity::sentinels::DAEMON_PRINCIPAL,
    )?;
    let signature = sign_bind_challenge(signing_key, &issued);
    let taken = consume_pubkey_bind_challenge(conn, agent_id, &issued.nonce_b64)?
        .ok_or_else(|| anyhow::anyhow!("bind challenge expired before it could be answered"))?;
    PossessionProof::verify_challenge_response(taken, agent_id, &pubkey_b64, &signature)
        .map_err(|e| anyhow::anyhow!(crate::errors::msg::pubkey_bind_refused(e)))
}

/// v1.0.0 #3464 — [`bind_agent_pubkey_with_signing_key`] for a loaded
/// [`crate::identity::keypair::AgentKeypair`].
///
/// # Errors
///
/// Refuses a PUBLIC-ONLY keypair: without the private half there is nothing to
/// prove possession with, and admitting the bind anyway would restore exactly
/// the #3464 defect.
pub fn bind_agent_pubkey_with_keypair(
    conn: &Connection,
    agent_id: &str,
    keypair: &crate::identity::keypair::AgentKeypair,
) -> Result<()> {
    let signing = keypair.private.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot bind pubkey for '{agent_id}': the loaded keypair is PUBLIC-ONLY, so \
             possession of the private key cannot be proven"
        )
    })?;
    bind_agent_pubkey_with_signing_key(conn, agent_id, signing)
}

/// v1.0.0 #3464 — one row of the append-only `agent_pubkey_history` ledger:
/// a key an agent was bound to, and the window over which it was the live
/// binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPubkeyVersion {
    /// The agent this key was bound to.
    pub agent_id: String,
    /// Dense, 1-based version. Also the stable handle a delegation or
    /// capability grant cites to say WHICH key issued it.
    pub version: i64,
    /// The bound key (URL-safe-no-pad base64), never rewritten.
    pub pubkey_b64: String,
    /// Which authority admitted the binding — see
    /// [`crate::identity::pubkey_bind::BindAuthority`], plus the
    /// `legacy_unproven` token the v97 backfill stamps on bindings that
    /// predate the proof-of-possession gate.
    pub bind_authority: String,
    /// The consumed challenge nonce, when the authority was a possession
    /// proof.
    pub proof_nonce: Option<String>,
    /// RFC3339 instant the key became live (window start, inclusive).
    pub bound_at: String,
    /// RFC3339 instant the key stopped being live (window end, EXCLUSIVE);
    /// `None` while the key is the current binding.
    pub superseded_at: Option<String>,
}

/// Backend-blind historical candidates. With history, never fall back to a
/// current/unversioned key; cryptography must select exactly one. Without
/// history, the sole candidate may be the permitted legacy flat binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPubkeyAt {
    /// Timestamp-eligible history keys, or at most one legacy flat key when no
    /// history exists at all.
    pub candidate_pubkeys_b64: Vec<String>,
    /// Whether the durable history ledger contains any row for this agent.
    pub history_exists: bool,
}

fn map_agent_pubkey_version(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentPubkeyVersion> {
    Ok(AgentPubkeyVersion {
        agent_id: row.get(0)?,
        version: row.get(1)?,
        pubkey_b64: row.get(2)?,
        bind_authority: row.get(3)?,
        proof_nonce: row.get(4)?,
        bound_at: row.get(5)?,
        superseded_at: row.get(6)?,
    })
}

const SQL_SELECT_AGENT_PUBKEY_HISTORY: &str =
    "SELECT agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at
     FROM agent_pubkey_history WHERE agent_id = ?1 ORDER BY version";

/// v1.0.0 #3464 — append `pubkey_b64` as the agent's next key version, closing
/// the window on the key it supersedes.
///
/// Idempotent on the CURRENT key: if the still-open row already carries
/// `pubkey_b64` this is a no-op, so a repeated bind (or a `register_agent`
/// refresh that re-asserts the same key) cannot inflate the ledger or record a
/// rotation that did not happen.
///
/// APPEND-ONLY: no row is ever deleted and no `pubkey_b64` is ever rewritten.
/// The single mutation is stamping `superseded_at` on the one row whose window
/// is open, and it is guarded by `superseded_at IS NULL` so a concurrent
/// rotation cannot close the same window twice.
fn append_agent_pubkey_version(
    conn: &Connection,
    agent_id: &str,
    pubkey_b64: &str,
    proof: &crate::identity::pubkey_bind::PossessionProof,
    now: &str,
) -> Result<()> {
    use rusqlite::OptionalExtension as _;
    crate::storage::record_stop::gate_storage_conn(conn)?;
    let latest: Option<(i64, String, String, Option<String>)> = conn
        .query_row(
            "SELECT version, pubkey_b64, bound_at, superseded_at
             FROM agent_pubkey_history WHERE agent_id = ?1
             ORDER BY version DESC LIMIT 1",
            params![agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let mut keys =
        conn.prepare("SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = ?1")?;
    let rows = keys
        .query_map(params![agent_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if crate::identity::keypair::canonical_history_contains(pubkey_b64, &rows)? {
        if latest
            .as_ref()
            .is_some_and(|(_, live, _, end)| end.is_none() && live == pubkey_b64)
        {
            return Ok(());
        }
        anyhow::bail!("refusing to reactivate a superseded or revoked agent pubkey");
    }
    if let Some((_, _, bound_at, superseded_at)) = latest.as_ref() {
        validate_agent_pubkey_transition_time(bound_at, superseded_at.as_deref(), now)?;
    }
    if latest
        .as_ref()
        .is_some_and(|(_, _, _, superseded_at)| superseded_at.is_none())
    {
        conn.execute(
            "UPDATE agent_pubkey_history SET superseded_at = ?2
             WHERE agent_id = ?1 AND superseded_at IS NULL",
            params![agent_id, now],
        )?;
    }
    // The next dense version. MAX over ALL rows (not just open ones), so a
    // revoked-then-rebound agent keeps a strictly increasing version sequence
    // and the composite PK can never collide.
    let next: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM agent_pubkey_history WHERE agent_id = ?1",
        params![agent_id],
        |r| r.get(0),
    )?;
    conn.execute(
        "INSERT INTO agent_pubkey_history
            (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            agent_id,
            next,
            pubkey_b64,
            proof.authority().as_str(),
            proof.nonce_b64(),
            now,
        ],
    )?;
    Ok(())
}

/// v1.0.0 #3464 — every key `agent_id` has ever been bound to, oldest first.
///
/// The append-only anchor set. An `agent_attested` row can be re-verified
/// against the key that actually signed it instead of only against whatever
/// key happens to be live today.
///
/// # Errors
///
/// Surfaces underlying query failures. NEVER flattens a backend fault into an
/// empty history: "this agent has no prior keys" is a durable provenance
/// claim, and a swallowed error would make old attested rows look unanchored
/// (the #3145 lesson on [`agent_pubkey`]).
pub fn agent_pubkey_versions(conn: &Connection, agent_id: &str) -> Result<Vec<AgentPubkeyVersion>> {
    let mut stmt = conn.prepare(SQL_SELECT_AGENT_PUBKEY_HISTORY)?;
    let rows = stmt.query_map(params![agent_id], map_agent_pubkey_version)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.with_context(|| format!("reading pubkey history for {agent_id}"))?);
    }
    Ok(out)
}

/// v1.0.0 #3464 — the key that was live for `agent_id` at `at_rfc3339`.
///
/// Uses strict half-open `[bound_at, superseded_at)` windows; the handoff
/// instant belongs to the successor. RFC3339 values compare by instant.
///
/// # Errors
///
/// Surfaces underlying query failures and refuses malformed, missing-version,
/// backwards, or overlapping history (never flattened to `Ok(None)`).
pub fn agent_pubkey_at(
    conn: &Connection,
    agent_id: &str,
    at_rfc3339: &str,
) -> Result<Option<AgentPubkeyVersion>> {
    let versions = agent_pubkey_versions(conn, agent_id)?;
    Ok(select_agent_pubkey_version_at(&versions, at_rfc3339)?.cloned())
}

/// Select one strict-window row after validating dense, chronological,
/// non-overlapping history. Revocation gaps are valid; corruption fails closed.
pub(crate) fn select_agent_pubkey_version_at<'a>(
    versions: &'a [AgentPubkeyVersion],
    at_rfc3339: &str,
) -> Result<Option<&'a AgentPubkeyVersion>> {
    let selected = select_agent_pubkey_versions_at_with_skew(versions, at_rfc3339, 0)?;
    if selected.len() > 1 {
        anyhow::bail!("ambiguous pubkey history: multiple keys cover the signed timestamp");
    }
    Ok(selected.into_iter().next())
}

/// Select skew-eligible re-verification candidates from a still-strict ledger;
/// the signature verifier must select exactly one.
pub(crate) fn select_agent_pubkey_versions_for_attestation<'a>(
    versions: &'a [AgentPubkeyVersion],
    at_rfc3339: &str,
) -> Result<Vec<&'a AgentPubkeyVersion>> {
    select_agent_pubkey_versions_at_with_skew(
        versions,
        at_rfc3339,
        crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS,
    )
}

fn select_agent_pubkey_versions_at_with_skew<'a>(
    versions: &'a [AgentPubkeyVersion],
    at_rfc3339: &str,
    skew_secs: i64,
) -> Result<Vec<&'a AgentPubkeyVersion>> {
    let at = chrono::DateTime::parse_from_rfc3339(at_rfc3339)
        .with_context(|| "parsing signed envelope timestamp for pubkey-history lookup")?;
    let skew = chrono::Duration::seconds(skew_secs);
    let mut previous_bound: Option<chrono::DateTime<chrono::FixedOffset>> = None;
    let mut previous_end: Option<Option<chrono::DateTime<chrono::FixedOffset>>> = None;
    let mut selected = Vec::new();

    for (index, row) in versions.iter().enumerate() {
        if crate::identity::keypair::canonical_public_base64(&row.pubkey_b64)? != row.pubkey_b64 {
            anyhow::bail!("noncanonical agent pubkey history for {}", row.agent_id);
        }
        let expected_version = i64::try_from(index + 1)
            .context("pubkey history contains more versions than i64 can represent")?;
        if row.version != expected_version {
            anyhow::bail!(
                "pubkey history has a missing or out-of-order version for {}",
                row.agent_id
            );
        }
        let bound = chrono::DateTime::parse_from_rfc3339(&row.bound_at)
            .with_context(|| format!("parsing pubkey history bound_at for {}", row.agent_id))?;
        let end = row
            .superseded_at
            .as_deref()
            .map(chrono::DateTime::parse_from_rfc3339)
            .transpose()
            .with_context(|| {
                format!("parsing pubkey history superseded_at for {}", row.agent_id)
            })?;
        if end.as_ref().is_some_and(|end| end <= &bound) {
            anyhow::bail!("invalid pubkey history window for {}", row.agent_id);
        }
        if previous_bound.as_ref().is_some_and(|prior| &bound < prior) {
            anyhow::bail!(
                "pubkey history versions are not chronological for {}",
                row.agent_id
            );
        }
        if let Some(prior_end) = previous_end.as_ref() {
            match prior_end {
                None => anyhow::bail!(
                    "ambiguous pubkey history: an open window precedes another version for {}",
                    row.agent_id
                ),
                Some(prior_end) if prior_end > &bound => anyhow::bail!(
                    "ambiguous overlapping pubkey history windows for {}",
                    row.agent_id
                ),
                Some(_) => {}
            }
        }
        let eligible_from = bound
            .checked_sub_signed(skew)
            .context("pubkey history lower eligibility bound overflow")?;
        let eligible_until = end
            .as_ref()
            .map(|end| {
                end.checked_add_signed(skew)
                    .context("pubkey history upper eligibility bound overflow")
            })
            .transpose()?;
        if eligible_from <= at && eligible_until.as_ref().is_none_or(|end| &at < end) {
            selected.push(row);
        }
        previous_bound = Some(bound);
        previous_end = Some(end);
    }
    Ok(selected)
}

/// Refuse a key-history transition whose wall-clock stamp would make the
/// append-only ledger non-monotonic. Callers hold their backend serialization
/// lock and invoke this before closing or inserting any history row.
pub(crate) fn validate_agent_pubkey_transition_time(
    bound_at: &str,
    superseded_at: Option<&str>,
    proposed_at: &str,
) -> Result<()> {
    let bound = chrono::DateTime::parse_from_rfc3339(bound_at)
        .context("parsing latest pubkey history bound_at")?;
    let proposed = chrono::DateTime::parse_from_rfc3339(proposed_at)
        .context("parsing proposed pubkey history transition time")?;
    if proposed <= bound {
        anyhow::bail!("pubkey history transition time must be after the latest bound_at");
    }
    if let Some(superseded_at) = superseded_at {
        let superseded = chrono::DateTime::parse_from_rfc3339(superseded_at)
            .context("parsing latest pubkey history superseded_at")?;
        if superseded <= bound {
            anyhow::bail!("latest pubkey history row has a non-positive validity window");
        }
        if proposed < superseded {
            anyhow::bail!("pubkey history recovery time precedes the latest revocation");
        }
    }
    Ok(())
}

/// Resolve skew-eligible keys for PERSISTED re-verification. History misses
/// never fall through to the current flat key; only zero-history identities
/// may use the legacy fallback. Live admission must call [`agent_pubkey`].
///
/// # Errors
///
/// Fails closed on malformed, overlapping, or otherwise ambiguous history,
/// and propagates backend lookup errors.
pub fn agent_pubkey_for_attestation_at(
    conn: &Connection,
    agent_id: &str,
    at_rfc3339: &str,
) -> Result<AttestationPubkeyAt> {
    let title = crate::models::agent_registration_title(agent_id);
    // History and flat fallback come from ONE SQLite statement snapshot. This
    // function is also used on direct CLI connections without `SqliteStore`'s
    // mutex, and may run inside an existing portability transaction, so neither
    // two independent SELECTs nor an internally-started transaction is safe.
    let mut statement = conn.prepare(
        "SELECT history.agent_id, history.version, history.pubkey_b64,
                history.bind_authority, history.proof_nonce,
                history.bound_at, history.superseded_at,
                (SELECT json_extract(metadata, '$.agent_pubkey')
                 FROM memories WHERE namespace = ?2 AND title = ?3 LIMIT 1)
         FROM (SELECT 1) AS snapshot
         LEFT JOIN agent_pubkey_history AS history ON history.agent_id = ?1
         ORDER BY history.version",
    )?;
    let rows = statement.query_map(params![agent_id, AGENTS_NAMESPACE, title], |row| {
        let history_agent_id: Option<String> = row.get(0)?;
        let version = match history_agent_id {
            Some(history_agent_id) => Some(AgentPubkeyVersion {
                agent_id: history_agent_id,
                version: row.get(1)?,
                pubkey_b64: row.get(2)?,
                bind_authority: row.get(3)?,
                proof_nonce: row.get(4)?,
                bound_at: row.get(5)?,
                superseded_at: row.get(6)?,
            }),
            None => None,
        };
        Ok((version, row.get::<_, Option<String>>(7)?))
    })?;
    let mut versions = Vec::new();
    let mut legacy_flat = None;
    for row in rows {
        let (version, flat) = row
            .with_context(|| format!("reading timestamp-specific pubkey history for {agent_id}"))?;
        if legacy_flat.is_none() {
            legacy_flat = flat;
        }
        if let Some(version) = version {
            versions.push(version);
        }
    }
    if versions.is_empty() {
        return Ok(AttestationPubkeyAt {
            candidate_pubkeys_b64: legacy_flat.into_iter().collect(),
            history_exists: false,
        });
    }
    Ok(AttestationPubkeyAt {
        candidate_pubkeys_b64: select_agent_pubkey_versions_for_attestation(&versions, at_rfc3339)?
            .into_iter()
            .map(|version| version.pubkey_b64.clone())
            .collect(),
        history_exists: true,
    })
}
