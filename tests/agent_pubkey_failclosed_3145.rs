// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3145 (v1.0.0, data-integrity / security) — a backend fault while
//! resolving an agent's BOUND public key must FAIL, never flatten into
//! "no bound key".
//!
//! `crate::db::agent_pubkey` used to collapse its `query_row` with
//! `.ok().flatten()`, so `SQLITE_BUSY` / lock timeout / I/O error / corrupt
//! page all became `Ok(None)` = "this agent has no bound key". The callers
//! (`identity::attest::stamp_attestation_sync` → the CLI/direct-connection
//! write funnel, and `store::sqlite::SqliteStore::agent_pubkey` → the SAL +
//! sync funnels) then stamped a genuinely-signed write as bare `claimed`, or
//! under required attestation flipped it to `AttestationRequired`.
//!
//! Stamping `claimed` on a signed write is not a DEGRADED result — it is a
//! WRONG one, written durably into the row's provenance. The fix is
//! `.optional()` (only the no-row case is `None`), matching the `#2095`
//! precedent 30 lines below it in the same module and the Postgres
//! `fetch_optional` + `map_err` twin.
//!
//! ## Fault injection
//!
//! `db::open` puts the database in WAL, where a `BEGIN EXCLUSIVE` on another
//! connection does NOT block readers. These tests therefore flip the probe
//! connection back to the rollback journal (`PRAGMA journal_mode = DELETE`,
//! legal because no other connection holds the WAL index at that moment) and
//! then have a second connection hold `BEGIN EXCLUSIVE`. With
//! `busy_timeout = 0` on the probe, the read is refused immediately with
//! `SQLITE_BUSY` — a real, deterministic backend fault, no sleeps, no races.

use ai_memory::identity::attest::{WriteSurface, stamp_attestation_sync};
use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::Memory;
use rusqlite::Connection;

const AGENT: &str = "ai:locked-db-3145";

/// Create a schema-initialised database with `AGENT`'s public key bound,
/// then hand back the path plus the agent's keypair. Every connection is
/// closed so the caller can safely change the journal mode.
fn seed(
    dir: &std::path::Path,
) -> (
    std::path::PathBuf,
    ai_memory::identity::keypair::AgentKeypair,
) {
    let path = dir.join("db.sqlite");
    let kp = ai_memory::identity::keypair::generate(AGENT).expect("generate keypair");
    {
        let conn = ai_memory::db::open(&path).expect("db::open");
        ai_memory::db::register_agent(&conn, AGENT, "nhi", &[]).expect("register");
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    }
    (path, kp)
}

/// A memory + its detached signature over the canonical `SignableWrite`
/// envelope, exactly as the HTTP/CLI write funnels present it.
fn signed_memory(kp: &ai_memory::identity::keypair::AgentKeypair) -> (Memory, Vec<u8>) {
    let created_at = "2026-08-22T00:00:00+00:00".to_string();
    let content = "A body long enough to be meaningful prose for the attestation envelope.";
    let mem = Memory {
        id: "mem-3145".to_string(),
        namespace: "test-ns".to_string(),
        title: "locked-db-signed-write".to_string(),
        content: content.to_string(),
        created_at: created_at.clone(),
        ..Memory::default()
    };
    let content_hash = ai_memory::identity::attest::content_sha256(&mem.content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: AGENT,
        namespace: &mem.namespace,
        title: &mem.title,
        kind: mem.memory_kind.as_str(),
        created_at: &mem.created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign");
    (mem, sig)
}

/// Open a probe connection on `path` in rollback-journal mode with no busy
/// backoff, so a competing `BEGIN EXCLUSIVE` refuses its reads immediately.
fn probe_conn(path: &std::path::Path) -> Connection {
    let conn = ai_memory::db::open(path).expect("db::open probe");
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .expect("flip to rollback journal");
    assert_eq!(mode, "delete", "probe connection must leave WAL");
    conn.busy_timeout(std::time::Duration::ZERO)
        .expect("busy_timeout 0");
    conn
}

/// The regression: a genuinely-signed write over a LOCKED database must be
/// an `Err`, never `Ok(AttestLevel::Claimed)`.
#[test]
fn locked_db_makes_stamp_attestation_sync_fail_not_demote_to_claimed_3145() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, kp) = seed(dir.path());
    let probe = probe_conn(&path);

    // Control: with no lock held, the signed write attests.
    let (mut mem, sig) = signed_memory(&kp);
    let level = stamp_attestation_sync(&probe, &mut mem, AGENT, Some(&sig), WriteSurface::Cli)
        .expect("unlocked control must succeed");
    assert_eq!(
        level,
        AttestLevel::AgentAttested,
        "control: a signed write against a bound key is agent_attested"
    );

    // Now hold the database exclusively from a second connection.
    let blocker = Connection::open(&path).expect("blocker connection");
    blocker
        .busy_timeout(std::time::Duration::ZERO)
        .expect("blocker busy_timeout");
    blocker.execute_batch("BEGIN EXCLUSIVE").expect("lock db");
    blocker
        .execute_batch("CREATE TABLE IF NOT EXISTS lock_probe_3145 (v INTEGER)")
        .expect("take the write lock");

    let (mut mem, sig) = signed_memory(&kp);
    let err = stamp_attestation_sync(&probe, &mut mem, AGENT, Some(&sig), WriteSurface::Cli)
        .expect_err("a locked database must FAIL the bound-key lookup, not report 'no key'");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(AGENT),
        "the error must name the agent whose key could not be resolved, got: {rendered}"
    );
    assert!(
        !mem.metadata
            .get("attest_level")
            .is_some_and(|v| v == "claimed"),
        "a failed lookup must NOT stamp a provenance level at all, got {:?}",
        mem.metadata.get("attest_level")
    );

    blocker.execute_batch("ROLLBACK").expect("release lock");
}

/// The same fault under REQUIRED attestation: the pre-fix code turned a
/// transient lock into a hard `AttestationRequired` rejection of a write that
/// was, in fact, correctly signed. Post-fix the caller sees the real cause.
#[test]
fn locked_db_error_names_the_db_fault_not_attestation_required_3145() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, kp) = seed(dir.path());
    let probe = probe_conn(&path);

    let blocker = Connection::open(&path).expect("blocker connection");
    blocker
        .busy_timeout(std::time::Duration::ZERO)
        .expect("blocker busy_timeout");
    blocker.execute_batch("BEGIN EXCLUSIVE").expect("lock db");
    blocker
        .execute_batch("CREATE TABLE IF NOT EXISTS lock_probe_3145b (v INTEGER)")
        .expect("take the write lock");

    let (mut mem, sig) = signed_memory(&kp);
    let err = stamp_attestation_sync(
        &probe,
        &mut mem,
        AGENT,
        Some(&sig),
        WriteSurface::HttpDirect,
    )
    .expect_err("locked database under HttpDirect must FAIL loudly");
    let rendered = format!("{err:#}").to_lowercase();
    assert!(
        rendered.contains("lock") || rendered.contains("busy"),
        "the operator must see the DB fault, not a bogus attestation verdict; got: {rendered}"
    );
    assert!(
        !rendered.contains("attestation failed"),
        "a DB fault must not be reported as an attestation verdict; got: {rendered}"
    );

    blocker.execute_batch("ROLLBACK").expect("release lock");
}

/// The raw storage-layer contract, stated as the three-row table both
/// backends share (see `tests/agent_pubkey_error_parity_3145.rs` for the
/// SAL/postgres twin):
///
/// | state                        | result        |
/// |------------------------------|---------------|
/// | agent registered + bound key | `Ok(Some(k))` |
/// | no such agent / no bound key | `Ok(None)`    |
/// | backend fault                | `Err(_)`      |
#[test]
fn agent_pubkey_contract_bound_unbound_and_fault_3145() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, kp) = seed(dir.path());
    let probe = probe_conn(&path);

    assert_eq!(
        ai_memory::db::agent_pubkey(&probe, AGENT).expect("bound lookup"),
        Some(kp.public_base64()),
        "bound agent resolves to its key"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey(&probe, "ai:never-registered-3145").expect("unbound lookup"),
        None,
        "an unregistered agent is Ok(None), not an error"
    );

    let blocker = Connection::open(&path).expect("blocker connection");
    blocker
        .busy_timeout(std::time::Duration::ZERO)
        .expect("blocker busy_timeout");
    blocker.execute_batch("BEGIN EXCLUSIVE").expect("lock db");
    blocker
        .execute_batch("CREATE TABLE IF NOT EXISTS lock_probe_3145c (v INTEGER)")
        .expect("take the write lock");
    assert!(
        ai_memory::db::agent_pubkey(&probe, AGENT).is_err(),
        "a backend fault is Err — NEVER Ok(None)"
    );
    blocker.execute_batch("ROLLBACK").expect("release lock");
}

/// Guard the shape of the fix itself: the public key round-trips through the
/// standard base64 the registry stores, so `.optional()` did not change the
/// success path.
#[test]
fn bound_key_roundtrip_unchanged_3145() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (path, kp) = seed(dir.path());
    let conn = ai_memory::db::open(&path).expect("db::open");
    let stored = ai_memory::db::agent_pubkey(&conn, AGENT)
        .expect("lookup")
        .expect("bound");
    let decoded = ai_memory::identity::keypair::decode_public_base64(&stored)
        .expect("registry key decodes through the house base64 accepter");
    assert_eq!(decoded.to_bytes(), kp.public.to_bytes());
}
