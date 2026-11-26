//! #10108 (GA standard 3) — every agent-row writer, driven with and without
//! a signature, stores a TRUTHFUL `(attest_level, signature)` pair:
//!
//! * I1: an agent label (`self_signed`, `signed_by_peer`, `peer_attested`)
//!   only with a 64-byte signature; otherwise `unsigned` with NULL.
//! * I2 (D2): a `memory_link.invalidated` row stores a NULL signature.
//!
//! The expected pair of each leg is WRITTEN OUT in [`WRITERS`] (never computed
//! from the code under test). Every leg runs on its own throwaway SQLite file
//! under the worktree's `.local-runs/`, and each database is then walked by
//! [`verify_chain`]: zero `agent_signature_missing` / `agent_signature_malformed`.

use super::{SignatureFailure, event_types, verify_chain};
use crate::identity::keypair::AgentKeypair;
use crate::models::{Memory, MemoryKind, MemoryLink, Tier};
use crate::storage as db;
use rusqlite::Connection;

/// Byte length of an Ed25519 signature (written out, not taken from the fix).
const ED25519_SIG_LEN: usize = 64;
/// The agent every leg writes as.
const AGENT: &str = "ai:writer-10108";
/// The namespace every seeded memory lives in.
const NS: &str = "t10108";

/// One stored row: `(attest_level, signature length or None for NULL)`.
type Row = (&'static str, Option<usize>);

/// What one leg must leave behind.
#[derive(Clone, Copy)]
enum Outcome {
    /// The writer succeeds and stores exactly these rows.
    Rows(&'static [Row]),
    /// The writer refuses with an error whose text contains this phrase, and
    /// stores no row of its event type.
    Refused(&'static str),
}

/// One writer under test.
struct WriterCase {
    /// Table key, quoted in every failure.
    name: &'static str,
    /// The `signed_events.event_type` the writer appends.
    event_type: &'static str,
    /// Drive the writer once; `Some(kp)` is the signed leg.
    drive: fn(&Connection, Option<&AgentKeypair>) -> anyhow::Result<()>,
    /// Outcome of the signed leg (`None` = no signed leg).
    signed: Option<Outcome>,
    /// Outcome of the unsigned leg.
    unsigned: Outcome,
}

const SELF_SIGNED_ROW: Outcome = Outcome::Rows(&[("self_signed", Some(ED25519_SIG_LEN))]);
const PEER_ATTESTED_ROW: Outcome = Outcome::Rows(&[("peer_attested", Some(ED25519_SIG_LEN))]);
const UNSIGNED_ROW: Outcome = Outcome::Rows(&[("unsigned", None)]);
const NO_ROW: Outcome = Outcome::Rows(&[]);
/// The `memory_links` CHECK trigger refusing an agent label without 64
/// signature bytes (written out from the trigger text,
/// migrations/sqlite/0054_v65_restore_memory_links_signature_triggers.sql).
const LINK_SIG_CHECK_REFUSAL: Outcome =
    Outcome::Refused("attest_level=self_signed/peer_attested requires 64-byte signature");

/// Every agent-row writer on the SQLite backend (#10108 sibling sweep).
const WRITERS: &[WriterCase] = &[
    WriterCase {
        name: "atomisation_complete",
        event_type: event_types::ATOMISATION_COMPLETE,
        drive: drive_atomisation,
        signed: Some(SELF_SIGNED_ROW),
        unsigned: UNSIGNED_ROW,
    },
    WriterCase {
        name: "context_offloaded",
        event_type: "context_offloaded",
        drive: drive_offload,
        signed: Some(SELF_SIGNED_ROW),
        unsigned: UNSIGNED_ROW,
    },
    WriterCase {
        name: "skill_registered",
        event_type: event_types::SKILL_REGISTERED,
        drive: drive_skill_register,
        signed: Some(SELF_SIGNED_ROW),
        unsigned: UNSIGNED_ROW,
    },
    WriterCase {
        name: "persona_generated",
        event_type: event_types::PERSONA_GENERATED,
        drive: drive_persona,
        signed: Some(SELF_SIGNED_ROW),
        unsigned: UNSIGNED_ROW,
    },
    WriterCase {
        name: "memory_link_created",
        event_type: event_types::MEMORY_LINK_CREATED,
        drive: drive_link_created,
        signed: Some(SELF_SIGNED_ROW),
        unsigned: UNSIGNED_ROW,
    },
    // The signed leg of the capture row (`signed_by_peer` + 64 bytes) is
    // `signed_path_enrolled_pubkey_verifies_signed_by_peer` in
    // src/mcp/tools/capture_turn.rs: it needs that module's env-allowlist lock.
    WriterCase {
        name: "memory_capture_turn",
        event_type: event_types::MEMORY_CAPTURE_TURN,
        drive: drive_capture_turn,
        signed: None,
        unsigned: UNSIGNED_ROW,
    },
    WriterCase {
        name: "memory_link_inbound_peer_attested",
        event_type: event_types::MEMORY_LINK_CREATED,
        drive: drive_link_inbound_peer_attested,
        signed: Some(PEER_ATTESTED_ROW),
        unsigned: LINK_SIG_CHECK_REFUSAL,
    },
    WriterCase {
        name: "memory_link_inbound_short_signature",
        event_type: event_types::MEMORY_LINK_CREATED,
        drive: drive_link_inbound_short_signature,
        signed: Some(LINK_SIG_CHECK_REFUSAL),
        unsigned: LINK_SIG_CHECK_REFUSAL,
    },
    WriterCase {
        name: "memory_link_invalidated",
        event_type: event_types::MEMORY_LINK_INVALIDATED,
        drive: drive_link_invalidated,
        signed: Some(UNSIGNED_ROW),
        unsigned: NO_ROW,
    },
];

/// A throwaway database file under `<worktree>/.local-runs/` (never /tmp).
fn scratch_db() -> (Connection, tempfile::TempDir) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/agent-row-10108");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch root");
    let dir = tempfile::Builder::new()
        .prefix("db-")
        .tempdir_in(&root)
        .expect("scratch dir");
    let conn = db::open(&dir.path().join("ai-memory.db")).expect("open scratch db");
    (conn, dir)
}

/// The module path the isolated child runs each test under.
const MODULE: &str = "signed_events::agent_row_10108_tests::";

/// Run the test body in an env-isolated child whose witness custody points
/// at an ABSENT scratch path, so `db::open` never reads (and no commit ever
/// appends to) the host's real `~/.config/ai-memory/witness-keys` anchor log
/// (#10117 class). `Some(guards)` = child role: keep them alive for the body.
/// `None` = parent role: the child already ran the body; return.
fn hermetic_child(
    name: &str,
) -> Option<(
    std::sync::MutexGuard<'static, ()>,
    crate::test_support::EnvGuard,
)> {
    if crate::test_support::run_env_isolated_child_or_spawn(&format!("{MODULE}{name}")) {
        return None;
    }
    let lock = crate::test_support::env_lock();
    let witness =
        crate::test_support::EnvGuard::capture(crate::governance::audit::WITNESS_KEY_DIR_ENV);
    let absent = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs/agent-row-10108/no-witness-custody");
    assert!(!absent.exists(), "witness scratch path must stay absent");
    witness.set(absent.to_str().expect("utf-8 scratch path"));
    Some((lock, witness))
}

fn keypair() -> AgentKeypair {
    crate::identity::keypair::generate(AGENT).expect("generate keypair")
}

fn seed_memory(
    conn: &Connection,
    title: &str,
    kind: MemoryKind,
    metadata: serde_json::Value,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{title} body about alice"),
        tags: vec!["reflection".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        reflection_depth: 1,
        memory_kind: kind,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory")
}

fn seed_pair(conn: &Connection) -> (String, String) {
    let meta = serde_json::json!({"agent_id": AGENT});
    (
        seed_memory(conn, "src", MemoryKind::Observation, meta.clone()),
        seed_memory(conn, "dst", MemoryKind::Observation, meta),
    )
}

fn drive_atomisation(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    crate::atomisation::emit_atomisation_complete_event(
        conn,
        "src-10108",
        &["atom-1".to_string()],
        1,
        AGENT,
        &chrono::Utc::now().to_rfc3339(),
        kp,
        "stub-model",
    )
}

fn drive_offload(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    let off =
        crate::offload::ContextOffloader::new(conn, kp, crate::offload::OffloadConfig::default());
    off.offload("payload for #10108", NS, None, AGENT)
        .map(|_| ())
}

fn drive_skill_register(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    let md =
        "---\nnamespace: testns\nname: skill-10108\ndescription: A demo skill.\n---\n\nBody.\n";
    crate::mcp::handle_skill_register(conn, &serde_json::json!({"inline_skill": md}), kp)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("skill register: {e}"))
}

struct StubLlm;

impl crate::autonomy::AutonomyLlm for StubLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> anyhow::Result<String> {
        Ok(format!("persona from {} sources", memories.len()))
    }
}

fn drive_persona(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    for i in 0..2 {
        seed_memory(
            conn,
            &format!("obs-{i} about alice"),
            MemoryKind::Reflection,
            serde_json::json!({"agent_id": AGENT, "entity_id": "alice"}),
        );
    }
    let llm = StubLlm;
    crate::persona::PersonaGenerator::new(conn, &llm, kp, crate::persona::PersonaConfig::default())
        .generate("alice", NS)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("persona generate: {e}"))
}

fn drive_link_created(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    let (s, t) = seed_pair(conn);
    db::create_link_signed(conn, &s, &t, "related_to", kp).map(|_| ())
}

fn drive_capture_turn(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    assert!(kp.is_none(), "capture_turn has no keypair-signed leg");
    let req: crate::mcp::MemoryCaptureTurnRequest = serde_json::from_value(serde_json::json!({
        "host_session_id": "sess-10108",
        "host_turn_index": 0,
        "role": "user",
        "content": "an unsigned host turn",
    }))?;
    let write = crate::mcp::prepare_capture_turn(&req, AGENT).map_err(|e| anyhow::anyhow!(e))?;
    super::append_signed_event(conn, &write.signed_event)
}

fn inbound_link(
    s: String,
    t: String,
    signature: Option<Vec<u8>>,
    attest_level: &str,
) -> MemoryLink {
    let now = chrono::Utc::now().to_rfc3339();
    MemoryLink {
        source_id: s,
        target_id: t,
        relation: crate::models::link::MemoryLinkRelation::default(),
        created_at: now.clone(),
        signature,
        observed_by: Some("ai:peer-10108".to_string()),
        valid_from: Some(now),
        valid_until: None,
        attest_level: Some(attest_level.to_string()),
        source_cid: None,
        target_cid: None,
    }
}

/// A peer-attested inbound link; the signed leg carries 64 signature bytes,
/// the unsigned leg the bare label (the forged shape #10108 forbids).
fn drive_link_inbound_peer_attested(
    conn: &Connection,
    kp: Option<&AgentKeypair>,
) -> anyhow::Result<()> {
    let (s, t) = seed_pair(conn);
    let sig = kp.map(|_| vec![7u8; ED25519_SIG_LEN]);
    let level = crate::models::AttestLevel::PeerAttested.as_str();
    db::create_link_inbound(conn, &inbound_link(s, t, sig, level), level)
}

/// A self-signed inbound link whose signature is NOT 64 bytes (signed leg)
/// or absent (unsigned leg): both are refused, and no row carries the label.
fn drive_link_inbound_short_signature(
    conn: &Connection,
    kp: Option<&AgentKeypair>,
) -> anyhow::Result<()> {
    let (s, t) = seed_pair(conn);
    let sig = kp.map(|_| vec![7u8; 10]);
    let level = crate::models::AttestLevel::SelfSigned.as_str();
    db::create_link_inbound(conn, &inbound_link(s, t, sig, level), level)
}

fn drive_link_invalidated(conn: &Connection, kp: Option<&AgentKeypair>) -> anyhow::Result<()> {
    let (s, t) = seed_pair(conn);
    db::create_link_signed(conn, &s, &t, "related_to", kp)?;
    db::invalidate_link(
        conn,
        &s,
        &t,
        "related_to",
        None,
        Some("ai:invalidator-10108"),
    )
    .map(|_| ())
}

fn stored_rows(conn: &Connection, event_type: &str) -> Vec<(String, Option<usize>)> {
    let mut stmt = conn
        .prepare("SELECT attest_level, signature FROM signed_events WHERE event_type = ?1 ORDER BY sequence")
        .expect("prepare");
    stmt.query_map([event_type], |r| {
        let level: String = r.get(0)?;
        let sig: Option<Vec<u8>> = r.get(1)?;
        Ok((level, sig.map(|s| s.len())))
    })
    .expect("query")
    .collect::<Result<_, _>>()
    .expect("rows")
}

/// Run one leg and return the mismatch, if any.
fn run_leg(case: &WriterCase, signed: bool, outcome: Outcome) -> Option<String> {
    let (conn, _dir) = scratch_db();
    let kp = keypair();
    let leg = if signed { "signed" } else { "unsigned" };
    let result = (case.drive)(&conn, signed.then_some(&kp));
    let expected: &[Row] = match (outcome, result) {
        (Outcome::Rows(rows), Ok(())) => rows,
        (Outcome::Rows(_), Err(e)) => {
            return Some(format!("{} [{leg}]: writer failed: {e:#}", case.name));
        }
        (Outcome::Refused(phrase), Ok(())) => {
            return Some(format!(
                "{} [{leg}]: writer succeeded, expected refusal {phrase:?}",
                case.name
            ));
        }
        (Outcome::Refused(phrase), Err(e)) => {
            let text = format!("{e:#}");
            if !text.contains(phrase) {
                return Some(format!(
                    "{} [{leg}]: refused with {text:?}, expected {phrase:?}",
                    case.name
                ));
            }
            &[]
        }
    };
    let got = stored_rows(&conn, case.event_type);
    let want: Vec<(String, Option<usize>)> = expected
        .iter()
        .map(|(l, n)| ((*l).to_string(), *n))
        .collect();
    if got != want {
        return Some(format!(
            "{} [{leg}]: stored {got:?}, expected {want:?}",
            case.name
        ));
    }
    let report = verify_chain(&conn, None, None).expect("verify_chain");
    let missing = report
        .agent_signature_defects
        .iter()
        .filter(|(_, f)| *f == SignatureFailure::AgentSignatureMissing)
        .count();
    let malformed = report
        .agent_signature_defects
        .iter()
        .filter(|(_, f)| *f == SignatureFailure::AgentSignatureMalformed)
        .count();
    if missing != 0 || malformed != 0 {
        return Some(format!(
            "{} [{leg}]: verify_chain agent_signature_missing={missing} agent_signature_malformed={malformed}",
            case.name
        ));
    }
    None
}

#[test]
fn agent_row_writer_table_stores_truthful_label_and_signature_10108() {
    let Some(_hermetic) =
        hermetic_child("agent_row_writer_table_stores_truthful_label_and_signature_10108")
    else {
        return;
    };
    let mut failures = Vec::new();
    for case in WRITERS {
        if let Some(expected) = case.signed {
            failures.extend(run_leg(case, true, expected));
        }
        failures.extend(run_leg(case, false, case.unsigned));
    }
    assert!(
        failures.is_empty(),
        "#10108 untruthful agent rows:\n{}",
        failures.join("\n")
    );
}

/// I1 at the constructor: every agent level keeps its label only with exactly
/// 64 signature bytes. The writer table cannot reach a wrong length through
/// the link writers (their own 64-byte check refuses first), so the
/// constructor is pinned directly over the boundary lengths.
#[test]
fn agent_row_signature_keeps_label_only_with_64_bytes_10108() {
    use super::{AgentAttestation, AgentRowSignature};
    const LENGTHS: [usize; 7] = [0, 1, 32, 63, 65, 96, 128];
    let levels = [
        (AgentAttestation::SelfSigned, "self_signed"),
        (AgentAttestation::SignedByPeer, "signed_by_peer"),
        (AgentAttestation::PeerAttested, "peer_attested"),
    ];
    let mut failures = Vec::new();
    for (level, label) in levels {
        let sig = [9u8; ED25519_SIG_LEN];
        let row = AgentRowSignature::from_signature(level, Some(&sig));
        if row.attest_level().as_str() != label || row.signature_bytes() != Some(&sig[..]) {
            failures.push(format!("{label} with 64 bytes lost its label or bytes"));
        }
        let none = AgentRowSignature::from_signature(level, None);
        if none.attest_level().as_str() != "unsigned" || none.signature().is_some() {
            failures.push(format!("{label} with no signature kept a label or bytes"));
        }
        for len in LENGTHS {
            let bytes = vec![9u8; len];
            let row = AgentRowSignature::from_signature(level, Some(&bytes));
            if row.attest_level().as_str() != "unsigned" || row.signature().is_some() {
                failures.push(format!("{label} with {len} bytes kept a label or bytes"));
            }
            let labelled = AgentRowSignature::from_label(label, Some(&bytes));
            if labelled.attest_level().as_str() != "unsigned" || labelled.signature().is_some() {
                failures.push(format!("from_label({label}) with {len} bytes kept a label"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "#10108 agent label without a 64-byte signature:\n{}",
        failures.join("\n")
    );
}

/// D2 / I2 on its own: the invalidated row of a SIGNED link has a NULL
/// signature (it used to carry the prior link signature under `unsigned`).
#[test]
fn link_invalidated_row_signature_is_null_10108() {
    let Some(_hermetic) = hermetic_child("link_invalidated_row_signature_is_null_10108") else {
        return;
    };
    let (conn, _dir) = scratch_db();
    let kp = keypair();
    drive_link_invalidated(&conn, Some(&kp)).expect("drive");
    let rows = stored_rows(&conn, event_types::MEMORY_LINK_INVALIDATED);
    assert_eq!(rows, vec![("unsigned".to_string(), None)]);
}
