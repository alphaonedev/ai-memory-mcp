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

/// Agent id the encryption keypair is minted for: matches the row owner (`ALICE`)
/// so `db::get` / `read_reflection_member` genuinely decrypts the envelope on the
/// read path (#10082 r1 item 7, never masking behavior behind a decrypt error).
const KEY_AGENT: &str = ALICE;

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

/// #10082 — when a source row becomes sealed INSIDE the injected read step
/// (closing the window between the pre-read classification and the read
/// return), the post-read re-check MUST refuse with the exact
/// `SEALED_EXPORT_REFUSED` text naming the source, and export nothing.
#[test]
fn source_sealed_inside_injected_read_is_refused_10082() {
    for seal_before_inner_read in [false, true] {
        let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
        let conn = db::open(&fx.db_path).expect("open db");
        let source_id = fx.source_id.clone();
        let mut sealed_fired = false;
        let err = ai_memory::mcp::handle_export_reflection_with_reader(
            &conn,
            &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
            Some(BOB),
            |c, member_id, reflection_id, caller| {
                if member_id == source_id && seal_before_inner_read {
                    let changed = c
                        .execute(
                            "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                            rusqlite::params![sealed_envelope(), member_id],
                        )
                        .expect("seal source before inner read");
                    assert_eq!(changed, 1);
                    sealed_fired = true;
                }
                let mem =
                    ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)?;
                if member_id == source_id && !seal_before_inner_read {
                    let changed = c
                        .execute(
                            "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                            rusqlite::params![sealed_envelope(), member_id],
                        )
                        .expect("seal source after inner read");
                    assert_eq!(changed, 1);
                    sealed_fired = true;
                }
                Ok(mem)
            },
        )
        .expect_err("#10082: source sealed inside read must refuse export");
        assert!(
            sealed_fired,
            "#10082: injected read seam must execute and seal the source row"
        );
        assert_eq!(
            err,
            expected_refusal(&fx.source_id),
            "#10082: post-read re-check must emit exact SEALED_EXPORT_REFUSED naming source"
        );
        assert_no_marker(&err, "post-read sealed source 10082");
    }
}

/// #10082 — sibling in the same handler: when the reflection row itself
/// becomes sealed INSIDE the injected read step, the post-read re-check MUST
/// refuse with `SEALED_EXPORT_REFUSED` naming the reflection.
#[test]
fn reflection_sealed_inside_injected_read_is_refused_10082() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
    let conn = db::open(&fx.db_path).expect("open db");
    let reflection_id_target = fx.reflection_id.clone();
    let mut sealed_fired = false;
    let err = ai_memory::mcp::handle_export_reflection_with_reader(
        &conn,
        &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
        Some(BOB),
        |c, member_id, reflection_id, caller| {
            let mem = ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)?;
            if member_id == reflection_id_target {
                let changed = c
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![sealed_envelope(), member_id],
                    )
                    .expect("seal reflection inside read");
                assert_eq!(changed, 1);
                sealed_fired = true;
            }
            Ok(mem)
        },
    )
    .expect_err("#10082: reflection sealed inside read must refuse export");
    assert!(
        sealed_fired,
        "#10082: injected read seam must execute and seal the reflection row"
    );
    assert_eq!(
        err,
        expected_refusal(&fx.reflection_id),
        "#10082: post-read re-check must emit exact SEALED_EXPORT_REFUSED naming reflection"
    );
    assert_no_marker(&err, "post-read sealed reflection 10082");
}

/// #10082 — pre-read check proof: a source that is ALREADY sealed before the
/// read MUST be refused BEFORE the injected decrypting reader is ever called
/// (kills the "pre-read check removed" mutant even on visible sealed rows).
#[test]
fn pre_read_sealed_source_never_invokes_decrypting_reader_10082() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, true));
    let conn = db::open(&fx.db_path).expect("open db");
    let source_id = fx.source_id.clone();
    let mut source_reader_invoked = false;
    let mut reflection_reader_invoked = false;
    let err = ai_memory::mcp::handle_export_reflection_with_reader(
        &conn,
        &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
        Some(BOB),
        |c, member_id, reflection_id, caller| {
            if member_id == source_id {
                source_reader_invoked = true;
            } else {
                reflection_reader_invoked = true;
            }
            ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)
        },
    )
    .expect_err("#10082: already-sealed visible source must be refused");
    assert!(
        reflection_reader_invoked,
        "#10082: unsealed reflection must still pass through injected reader"
    );
    assert!(
        !source_reader_invoked,
        "#10082: pre-read check must refuse already-sealed source before calling reader"
    );
    assert_eq!(err, expected_refusal(&fx.source_id));
    assert_no_marker(&err, "pre-read sealed source 10082");
}

/// #10082 r1 item 7: prove the test fixture seals with the row owner's key
/// (`ALICE`) so `db::get` genuinely decrypts the at-rest envelope to
/// `SEALED_MARKER` — yet `memory_export_reflection` still refuses without
/// leaking plaintext.
#[test]
fn owner_key_sealed_fixture_genuinely_decrypts_on_direct_get_10082() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, true));
    let conn = db::open(&fx.db_path).expect("open db");
    let direct = db::get(&conn, &fx.source_id)
        .expect("db::get with owner key must decrypt")
        .expect("source exists");
    assert_eq!(
        direct.content, SEALED_MARKER,
        "fixture envelope must genuinely decrypt under owner key ALICE"
    );
    let err = fx
        .export(ALICE)
        .expect_err("export must still refuse decryptable owner-sealed source");
    assert_eq!(err, expected_refusal(&fx.source_id));
    assert_no_marker(&err, "decryptable owner-sealed source 10082");
}

/// #10180 (F1): seal-then-unseal inside the read window (Probe P1).
/// A row starts unsealed ("public v1"), is sealed with the owner's key before
/// the inner decrypting read (so the reader genuinely decrypts `SEALED_MARKER`),
/// and is then unsealed back to "public v1" (with the exact same `updated_at`
/// and `version`) before the post-read check runs. Comparing the same row version
/// (id, owner, updated_at, version, content/seal digest) across pre-check, read,
/// and post-check MUST refuse and never export `SEALED_MARKER`.
#[test]
fn seal_then_unseal_inside_injected_read_is_refused_10180() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
    let conn = db::open(&fx.db_path).expect("open db");
    let updated_rfl = conn
        .execute(
            "UPDATE memories SET content = 'public reflection v1' WHERE id = ?1",
            rusqlite::params![&fx.reflection_id],
        )
        .expect("set plain reflection content");
    assert_eq!(updated_rfl, 1);
    let rfl_id = fx.reflection_id.clone();
    let mut decrypted_sealed = false;

    let res = ai_memory::mcp::handle_export_reflection_with_reader(
        &conn,
        &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
        Some(ALICE),
        |c, member_id, reflection_id, caller| {
            if member_id == rfl_id {
                let changed = c
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![sealed_envelope(), member_id],
                    )
                    .expect("seal reflection before read");
                assert_eq!(changed, 1);
            }
            let mem = ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)?;
            if member_id == rfl_id {
                assert_eq!(
                    mem.content, SEALED_MARKER,
                    "#10180: inner read must genuinely decrypt the sealed owner envelope"
                );
                decrypted_sealed = true;
                // Unseal back to the exact prior plaintext, preserving updated_at and version.
                let unsealed = c
                    .execute(
                        "UPDATE memories SET content = 'public reflection v1', encrypted_envelope = NULL WHERE id = ?1",
                        rusqlite::params![member_id],
                    )
                    .expect("unseal reflection after read");
                assert_eq!(unsealed, 1);
            }
            Ok(mem)
        },
    );
    assert!(
        decrypted_sealed,
        "#10180: injected reader must have executed and decrypted the sealed envelope"
    );
    let err = res.expect_err("#10180: seal-then-unseal inside read window must refuse export");
    assert_no_marker(&err, "seal-then-unseal 10180");
}

/// #10180: single SQLite read snapshot pins concurrent connections' view across
/// reflection + source reads so a concurrent writer sealing the row after the
/// export starts cannot interleave a sealed version into the read.
#[test]
fn concurrent_connection_seal_after_snapshot_start_sees_consistent_view_10180() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
    let conn_export = db::open(&fx.db_path).expect("open export conn");
    let conn_writer = db::open(&fx.db_path).expect("open concurrent writer conn");
    let set_plain = conn_writer
        .execute(
            "UPDATE memories SET content = 'consistent plain snapshot v1' WHERE id = ?1",
            rusqlite::params![&fx.reflection_id],
        )
        .expect("seed plain reflection");
    assert_eq!(set_plain, 1);
    let rfl_id = fx.reflection_id.clone();
    let src_id = fx.source_id.clone();
    let mut writer_committed = false;

    let out = ai_memory::mcp::handle_export_reflection_with_reader(
        &conn_export,
        &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
        Some(ALICE),
        |c, member_id, reflection_id, caller| {
            if member_id == rfl_id && !writer_committed {
                // Concurrent connection seals BOTH reflection and source after
                // export's pre-check already pinned its WAL read snapshot.
                let env = sealed_envelope();
                let c1 = conn_writer
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![&env, &rfl_id],
                    )
                    .expect("writer seal reflection");
                let c2 = conn_writer
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![&env, &src_id],
                    )
                    .expect("writer seal source");
                assert_eq!(c1, 1);
                assert_eq!(c2, 1);
                writer_committed = true;
            }
            ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)
        },
    )
    .expect("#10180: single WAL read snapshot must observe consistent pre-seal state across pre-check, read, and post-check");
    assert!(writer_committed, "concurrent writer must have committed");
    let content = out["content"].as_str().expect("content string");
    assert!(
        content.contains("consistent plain snapshot v1"),
        "snapshot export must render the consistent pre-seal plaintext, got: {content}"
    );
    assert_no_marker(content, "snapshot export 10180");
}

/// #10082 r1 item 6(a): a row that becomes hidden AND sealed inside the read
/// window makes the post-read `classify_visible_sealed_state` return
/// `Err(ReflectionNotFound)` while `read_member` returned `Ok(mem)`. Ignoring
/// the post-read error would leak the plaintext — this test kills that mutant.
#[test]
fn row_hidden_and_sealed_inside_injected_read_is_not_found_10082() {
    let fx = Fixture::new(member(Seen::ByAll, false), member(Seen::ByAll, false));
    let conn = db::open(&fx.db_path).expect("open db");
    let source_id = fx.source_id.clone();
    let mut hid_and_sealed = false;
    let err = ai_memory::mcp::handle_export_reflection_with_reader(
        &conn,
        &serde_json::json!({"memory_id": fx.reflection_id, "format": "md"}),
        Some(BOB),
        |c, member_id, reflection_id, caller| {
            let mem = ai_memory::mcp::read_reflection_member(c, member_id, reflection_id, caller)?;
            if member_id == source_id {
                let changed = c
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1, \
                         metadata = ?2 WHERE id = ?3",
                        rusqlite::params![
                            sealed_envelope(),
                            serde_json::json!({"agent_id": ALICE, "scope": "private"}).to_string(),
                            member_id
                        ],
                    )
                    .expect("hide and seal source inside read");
                assert_eq!(changed, 1);
                hid_and_sealed = true;
            }
            Ok(mem)
        },
    )
    .expect_err("#10082 item 6a: row hidden and sealed inside read must fail closed");
    assert!(hid_and_sealed, "injected mutation must have executed");
    assert_eq!(
        err,
        expected_not_found(&fx.reflection_id),
        "#10082 item 6a: hidden sealed source must return ReflectionNotFound"
    );
    assert_no_marker(&err, "hidden-and-sealed inside read 10082");
}
