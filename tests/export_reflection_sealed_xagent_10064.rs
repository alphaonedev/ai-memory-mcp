// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10064 — `memory_export_reflection` decides visibility before the
//! sealed-row refusal, for the reflection AND for every source it reflects
//! on, and never decrypts a sealed source.
//!
//! Two properties, each per member (the reflection R and its source S):
//! * a caller who may not see a sealed member learns nothing from it: the
//!   error is the same `reflection not found: <R>` an absent or hidden
//!   unsealed member gives, so there is no sealed-or-not oracle;
//! * a caller who may see a sealed member is refused with the exact
//!   `SEALED_EXPORT_REFUSED` text naming that member, before any decrypt
//!   (before #10064 a sealed visible SOURCE was decrypted by the edge loop
//!   and the export succeeded).
//!
//! The caller is installed with the thread-local test seam
//! (`identity::test_agent_id::AgentIdOverride`), so no process environment is
//! mutated.

use ai_memory::db;
use ai_memory::identity::test_agent_id::AgentIdOverride;
use ai_memory::models::{Memory, MemoryKind, Tier};

/// Namespace of every seeded row.
const NS: &str = "sealed-xagent-10064";

/// Owner of the private rows.
const ALICE: &str = "ai:alice";

/// A caller who is not the owner.
const BOB: &str = "ai:bob";

/// The plaintext a member is sealed from. It must reach no response or error.
const SEALED_MARKER: &str = "sealed xagent marker 10064 \u{1f512}";

/// Agent id the encryption keypair is minted for.
const KEY_AGENT: &str = "ai:xagent-sealed-10064";

/// The exact sealed-row refusal for one row, written out here.
fn expected_refusal(id: &str) -> String {
    format!(
        "SEALED_EXPORT_REFUSED: 1 row(s) of memories are sealed at rest (first id {id}); no \
         export format carries the at-rest envelope, so the export is refused and nothing was \
         written. Move an encrypted store with backup/restore (#10028)"
    )
}

/// The exact not-found answer, written out here.
fn expected_not_found(reflection_id: &str) -> String {
    format!("reflection not found: {reflection_id}")
}

/// Who may see a row.
#[derive(Clone, Copy, Debug)]
enum Seen {
    /// `scope: collective`: every caller.
    ByAll,
    /// `scope: private`, owned by alice: alice only.
    ByAliceOnly,
}

/// How a member is stored.
#[derive(Clone, Copy, Debug)]
struct Member {
    seen: Seen,
    sealed: bool,
}

const fn member(seen: Seen, sealed: bool) -> Member {
    Member { seen, sealed }
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    reflection_id: String,
    source_id: String,
}

fn metadata(seen: Seen) -> serde_json::Value {
    match seen {
        Seen::ByAll => serde_json::json!({"agent_id": ALICE, "scope": "collective"}),
        Seen::ByAliceOnly => serde_json::json!({"agent_id": ALICE, "scope": "private"}),
    }
}

fn sealed_envelope() -> Vec<u8> {
    let _ = ai_memory::identity::test_key_dir::install();
    let kp = ai_memory::encryption::get_or_create_keypair(KEY_AGENT).expect("x25519 keypair");
    ai_memory::encryption::encrypt(SEALED_MARKER, &kp.public)
        .expect("seal marker")
        .to_bytes()
}

impl Fixture {
    /// A reflection R that reflects on one source S.
    fn new(reflection: Member, source: Member) -> Self {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("memory.db");
        let conn = db::open(&db_path).expect("open db");
        let now = chrono::Utc::now().to_rfc3339();
        let source_row = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NS.into(),
            tier: Tier::Long,
            memory_kind: MemoryKind::Observation,
            title: "source".into(),
            content: SEALED_MARKER.into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: metadata(source.seen),
            ..Default::default()
        };
        let source_id = db::insert(&conn, &source_row).expect("insert source");
        let reflection_row = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NS.into(),
            tier: Tier::Mid,
            memory_kind: MemoryKind::Reflection,
            title: "reflection".into(),
            content: SEALED_MARKER.into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: metadata(reflection.seen),
            reflection_depth: 1,
            ..Default::default()
        };
        let reflection_id = db::insert(&conn, &reflection_row).expect("insert reflection");
        conn.execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
             VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
            rusqlite::params![reflection_id, source_id, now],
        )
        .expect("link reflection to source");
        for (id, m) in [(&reflection_id, reflection), (&source_id, source)] {
            if m.sealed {
                let changed = conn
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![sealed_envelope(), id],
                    )
                    .expect("seal a member");
                assert_eq!(changed, 1, "one row sealed");
            }
        }
        db::checkpoint(&conn).expect("checkpoint");
        Self {
            _dir: dir,
            db_path,
            reflection_id,
            source_id,
        }
    }

    fn export_as(&self, caller: &str, memory_id: &str) -> Result<serde_json::Value, String> {
        let _caller = AgentIdOverride::set(caller);
        let conn = db::open(&self.db_path).expect("open db");
        ai_memory::mcp::handle_export_reflection(
            &conn,
            &serde_json::json!({"memory_id": memory_id, "format": "md"}),
        )
    }

    fn export(&self, caller: &str) -> Result<serde_json::Value, String> {
        self.export_as(caller, &self.reflection_id)
    }
}

fn assert_no_marker(err: &str, cell: &str) {
    assert!(
        !err.contains(SEALED_MARKER),
        "{cell}: the error carried the sealed plaintext"
    );
}

/// (1) R sealed and hidden from bob: the same answer as an id that does not
/// exist, so bob cannot tell a sealed hidden row from a missing one.
#[test]
fn hidden_sealed_reflection_is_indistinguishable_from_absent_10064() {
    let fx = Fixture::new(member(Seen::ByAliceOnly, true), member(Seen::ByAll, false));
    let err = fx.export(BOB).expect_err("bob may not see R");
    assert_eq!(
        err,
        expected_not_found(&fx.reflection_id),
        "hidden sealed R"
    );
    assert_no_marker(&err, "hidden sealed R");
    let absent = "00000000-0000-4000-8000-000000010064";
    let absent_err = fx.export_as(BOB, absent).expect_err("absent id");
    assert_eq!(absent_err, expected_not_found(absent), "absent id");
}

/// (2) R visible, its source S sealed and visible to bob: refused with the
/// exact sealed-export text naming S, never rendered.
#[test]
fn visible_sealed_source_is_refused_naming_the_source_10064() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, true));
    let err = fx
        .export(BOB)
        .expect_err("a visible sealed source must refuse the export");
    assert_eq!(err, expected_refusal(&fx.source_id), "visible sealed S");
    assert_no_marker(&err, "visible sealed S");
}

/// (3) R visible, S sealed but hidden from bob: the same answer as S hidden
/// and unsealed, so bob learns nothing about S.
#[test]
fn hidden_sealed_source_is_indistinguishable_from_hidden_plain_source_10064() {
    let sealed = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAliceOnly, true));
    let err = sealed.export(BOB).expect_err("bob may not see S");
    assert_eq!(
        err,
        expected_not_found(&sealed.reflection_id),
        "hidden sealed S"
    );
    assert_no_marker(&err, "hidden sealed S");

    let plain = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAliceOnly, false));
    let plain_err = plain.export(BOB).expect_err("bob may not see S");
    assert_eq!(
        plain_err,
        expected_not_found(&plain.reflection_id),
        "hidden plain S"
    );
}

/// (4) The owner of a sealed R is refused with the exact text naming R; the
/// owner of a sealed private S is refused naming S.
#[test]
fn owner_of_a_sealed_member_is_refused_10064() {
    let fx = Fixture::new(member(Seen::ByAliceOnly, true), member(Seen::ByAll, false));
    let err = fx.export(ALICE).expect_err("sealed R refuses its owner");
    assert_eq!(err, expected_refusal(&fx.reflection_id), "owner sealed R");
    assert_no_marker(&err, "owner sealed R");

    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAliceOnly, true));
    let err = fx.export(ALICE).expect_err("sealed S refuses its owner");
    assert_eq!(err, expected_refusal(&fx.source_id), "owner sealed S");
    assert_no_marker(&err, "owner sealed S");
}

/// Control: nothing sealed, every member visible: the export renders.
#[test]
fn unsealed_visible_members_export_10064() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
    let out = fx.export(BOB).expect("an unsealed export renders");
    let content = out["content"].as_str().expect("content is a string");
    assert!(
        content.contains(&fx.reflection_id),
        "the rendered payload names the reflection"
    );
}
