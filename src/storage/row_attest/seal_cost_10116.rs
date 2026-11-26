//! #10116 lane 2: the seal and arm cost. The arm computes the seal marks by
//! a streaming fold (J1), a snapshot check reads the attestations once
//! (J2), a seal equal to what a clean verify saw is not rewritten (J3, in
//! `seal.rs`) and the live accumulator folds over streamed rows (J4). Every
//! verdict, refusal text and seal byte is unchanged (J5).

use super::*;
use crate::storage::row_attest::seal::{self, SealRecord};
use crate::storage::row_attest::sqlite::{self as sq, MIGRATION_V103_SQLITE, SnapshotVerdict};
use std::collections::BTreeMap;

/// A database holding only the v103 side table (no base table).
fn side_table_db(dir: &std::path::Path, name: &str) -> rusqlite::Connection {
    let conn = crate::storage::open_unmigrated(&dir.join(name)).expect("open");
    conn.execute_batch(MIGRATION_V103_SQLITE).expect("v103 ddl");
    conn
}

/// Insert a bare attestation row: only `id`, `table_name` and `table_seq`
/// matter to the seal marks.
fn put_mark(conn: &rusqlite::Connection, id: i64, table: &str, table_seq: i64) {
    conn.execute(
        "INSERT INTO row_attestations (id, table_name, row_key, seq, op, row_digest, \
         prior_digest, agent_id, key_id, attested_at, format_version, covered_columns, \
         store_id, table_seq, table_acc, signature, attestation_digest) \
         VALUES (?1, ?2, ?3, 1, 'insert', NULL, x'', 'a', 'k', 't', 1, '', 's', ?4, x'', NULL, x'')",
        rusqlite::params![id, table, id.to_be_bytes().to_vec(), table_seq],
    )
    .expect("insert attestation");
}

fn marks(high_water: i64, heads: &[(&str, i64)]) -> SealRecord {
    SealRecord {
        high_water,
        heads: heads
            .iter()
            .map(|(t, s)| ((*t).to_string(), *s))
            .collect::<BTreeMap<_, _>>(),
    }
}

/// J1: the arm's seal marks are a streaming fold equal to
/// `SealRecord::of` over the whole slice, for every row of a table whose
/// expected marks are written out (empty, single, ids out of order, a
/// table sequence that falls as the id rises, the zero sequence of a
/// cutover). No `Vec` of all attestations is gathered; each row is read
/// once.
#[test]
fn seal_marks_fold_equals_the_slice_form_j1_10116() {
    let dir = anchor_dir();
    type Row = (i64, &'static str, i64);
    let cases: [(&str, &[Row], SealRecord); 5] = [
        ("empty", &[], marks(0, &[])),
        (
            "single",
            &[(7, "memories", 3)],
            marks(7, &[("memories", 3)]),
        ),
        (
            "ids out of order",
            &[(5, "memories", 4), (2, "leases", 6), (9, "memories", 2)],
            marks(9, &[("leases", 6), ("memories", 4)]),
        ),
        (
            "sequence falls as the id rises",
            &[(1, "memories", 9), (2, "memories", 8), (3, "memories", 7)],
            marks(3, &[("memories", 9)]),
        ),
        (
            "cutover and store rows",
            &[
                (1, STORE_ROW_TABLE, 0),
                (2, "memories", 0),
                (3, "leases", 0),
            ],
            marks(3, &[(STORE_ROW_TABLE, 0), ("leases", 0), ("memories", 0)]),
        ),
    ];
    for (i, (name, rows, want)) in cases.into_iter().enumerate() {
        let conn = side_table_db(dir.path(), &format!("marks_{i}.db"));
        for (id, table, seq) in rows {
            put_mark(&conn, *id, table, *seq);
        }
        let slice = SealRecord::of(&sq::read_attestations(&conn).expect("read"));
        probe::reset();
        let got = sq::seal_marks(&conn).expect("seal marks");
        assert_eq!(got, want, "{name}: written-out marks");
        assert_eq!(got, slice, "{name}: equal to the slice form");
        assert_eq!(probe::get(Count::Gather), 0, "{name}: no gathered Vec");
        assert_eq!(
            probe::get(Count::AttRead),
            count_of(rows.len()),
            "{name}: one read per attestation"
        );
    }
}

/// J1 + J3 on the arm path: `seal_at_arm` streams (no gathered `Vec`),
/// writes a missing seal once, does not rewrite a seal equal to its marks
/// (same bytes, inode and mtime), writes again when a mark advances, and
/// writes nothing inside a caller's transaction or for an unsealed file.
#[test]
fn seal_at_arm_streams_and_writes_only_on_advance_j1_j3_10116() {
    let dir = anchor_dir();
    let conn = side_table_db(dir.path(), "arm.db");
    put_mark(&conn, 1, "memories", 1);
    put_mark(&conn, 2, "leases", 1);
    let path = dir.path().join(seal::SEAL_DIR).join("arm-seal");

    probe::reset();
    sq::seal_at_arm(&conn, None).expect("no seal file");
    assert_eq!(probe::get(Count::SealWrite), 0, "no seal file, no write");
    assert_eq!(probe::get(Count::AttRead), 0, "no seal file, no read");

    probe::reset();
    sq::seal_at_arm(&conn, Some(&path)).expect("first arm");
    assert_eq!(probe::get(Count::Gather), 0, "the arm gathers no Vec");
    assert_eq!(probe::get(Count::AttRead), 2, "one read per attestation");
    assert_eq!(probe::get(Count::SealWrite), 1, "a missing seal is written");
    assert_eq!(
        seal::read(&path),
        seal::SealState::Sealed(marks(2, &[("leases", 1), ("memories", 1)]))
    );
    let before = file_id(&path);

    probe::reset();
    sq::seal_at_arm(&conn, Some(&path)).expect("second arm");
    assert_eq!(
        probe::get(Count::SealWrite),
        0,
        "an equal seal is not rewritten"
    );
    assert_eq!(file_id(&path), before, "same bytes, inode and mtime");

    put_mark(&conn, 3, "memories", 2);
    conn.execute_batch("BEGIN").expect("begin");
    probe::reset();
    sq::seal_at_arm(&conn, Some(&path)).expect("arm in a transaction");
    assert_eq!(
        probe::get(Count::SealWrite),
        0,
        "no write inside a transaction"
    );
    conn.execute_batch("COMMIT").expect("commit");

    probe::reset();
    sq::seal_at_arm(&conn, Some(&path)).expect("advancing arm");
    assert_eq!(
        probe::get(Count::SealWrite),
        1,
        "an advanced mark is written"
    );
    assert_eq!(
        seal::read(&path),
        seal::SealState::Sealed(marks(3, &[("leases", 1), ("memories", 2)]))
    );
}

/// The bytes, inode and mtime of `path`.
fn file_id(path: &std::path::Path) -> (Vec<u8>, u64, std::time::SystemTime) {
    let meta = std::fs::metadata(path).expect("seal metadata");
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let ino = 0;
    (
        std::fs::read(path).expect("seal bytes"),
        ino,
        meta.modified().expect("seal mtime"),
    )
}

/// One base table per spec with its covered columns (no triggers).
fn base_tables(conn: &rusqlite::Connection) {
    for s in TABLES {
        let cols = s
            .cols
            .iter()
            .map(|(c, _)| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_batch(&format!("CREATE TABLE \"{}\" ({cols});", s.table))
            .expect("base table");
    }
}

fn value_of(c: &Cell) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match c {
        Cell::Null => Value::Null,
        Cell::Int(i) => Value::Integer(*i),
        Cell::Real(f) => Value::Real(*f),
        Cell::Text(s) => Value::Text(s.clone()),
        Cell::Blob(b) => Value::Blob(b.clone()),
        Cell::Bool(b) => Value::Integer(i64::from(*b)),
        Cell::Json(j) => Value::Text(j.to_string()),
    }
}

/// Insert `cells` into the first covered columns of `table` (the rest NULL,
/// as a missing cell reads in the canonical form).
fn insert_cells(conn: &rusqlite::Connection, table: &str, cells: &[Cell]) {
    let cols = spec(table).cols[..cells.len()]
        .iter()
        .map(|(c, _)| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let marks = vec!["?"; cells.len()].join(", ");
    let values: Vec<rusqlite::types::Value> = cells.iter().map(value_of).collect();
    conn.execute(
        &format!("INSERT INTO \"{table}\" ({cols}) VALUES ({marks})"),
        rusqlite::params_from_iter(values),
    )
    .expect("insert base row");
}

fn insert_att(conn: &rusqlite::Connection, a: &Attestation) {
    conn.execute(
        "INSERT INTO row_attestations (id, table_name, row_key, seq, op, row_digest, \
         prior_digest, agent_id, key_id, attested_at, format_version, covered_columns, \
         store_id, table_seq, table_acc, signature, attestation_digest) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        rusqlite::params![
            a.id,
            a.table,
            a.row_key,
            a.seq,
            a.op,
            a.row_digest,
            a.prior_digest,
            a.agent_id,
            a.key_id,
            a.attested_at,
            a.format_version,
            a.covered_columns,
            a.store_id,
            a.table_seq,
            a.table_acc,
            a.signature,
            a.attestation_digest,
        ],
    )
    .expect("insert attestation");
}

/// Memory cells as `Fixture::put_memory` writes them.
fn memory_cells(id: &str, content: &str) -> [Cell; 5] {
    [t(id), t("[]"), Cell::Int(5), t("long"), t(content)]
}

/// A snapshot database with `memories` signed memories, written from the
/// in-memory fixture (the same attestations and live rows).
fn snapshot_db(
    dir: &std::path::Path,
    name: &str,
    memories: usize,
) -> (rusqlite::Connection, Fixture) {
    let mut f = Fixture::new();
    let conn = side_table_db(dir, name);
    base_tables(&conn);
    for n in 0..memories {
        let id = format!("m{n}");
        f.put_memory(&id, "snapshot");
        insert_cells(&conn, "memories", &memory_cells(&id, "snapshot"));
    }
    for a in &f.atts {
        insert_att(&conn, a);
    }
    (conn, f)
}

/// Memories in the counted snapshot (J2).
const SNAPSHOT_MEMORIES_10116: usize = 3;

/// J2: a snapshot check of a clean signed store reads each attestation
/// exactly once per call and gathers no `Vec`; its verdict is the marks of
/// the whole store, as before.
#[test]
fn check_snapshot_reads_the_attestations_once_j2_10116() {
    let dir = anchor_dir();
    let (conn, f) = snapshot_db(dir.path(), "snap.db", SNAPSHOT_MEMORIES_10116);
    let anchor = f.anchor_for_snapshot();
    let target = dir.path().join("target.db");
    probe::reset();
    let verdict = sq::check_snapshot_with(&conn, &target, &anchor).expect("verified snapshot");
    assert_eq!(verdict, SnapshotVerdict::Verified(SealRecord::of(&f.atts)));
    assert_eq!(
        probe::get(Count::AttRead),
        count_of(f.atts.len()),
        "one read per attestation per call"
    );
    assert_eq!(probe::get(Count::Gather), 0, "no gathered Vec");
    assert_eq!(
        probe::get(Count::SealWrite),
        0,
        "a snapshot check writes no seal"
    );
}

impl Fixture {
    fn anchor_for_snapshot(&self) -> anchor::AnchorLoad {
        anchored(&[(AGENT, self.signing.verifying_key(), None, None)])
    }
}

fn refused(why: &str) -> String {
    format!("{} {why}", sq::SNAPSHOT_REFUSAL_PREFIX)
}

/// J5 on the snapshot check: every refusal keeps its exact text and its
/// order (the table check, the store count, the first table with no
/// cutover, the unanchored verdict, a defect), and a never-armed store is
/// still `NeverArmed`.
#[test]
fn check_snapshot_refusals_keep_their_text_and_order_j5_10116() {
    let dir = anchor_dir();
    let target = dir.path().join("target.db");
    let first = TABLES.first().expect("a spec").table;

    let bare = crate::storage::open_unmigrated(&dir.path().join("bare.db")).expect("open");
    let err = sq::check_snapshot_with(&bare, &target, &unanchored_10116()).expect_err("no table");
    assert_eq!(err.to_string(), refused("it has no row_attestations table"));

    let (none, f) = snapshot_db(dir.path(), "no_store.db", 1);
    none.execute(
        "DELETE FROM row_attestations WHERE table_name = ?1",
        [STORE_ROW_TABLE],
    )
    .expect("drop the store row");
    let err = sq::check_snapshot_with(&none, &target, &f.anchor_for_snapshot()).expect_err("0");
    assert_eq!(
        err.to_string(),
        refused("it holds 0 store-identity rows, not one")
    );

    let (two, f) = snapshot_db(dir.path(), "two_stores.db", 1);
    let mut extra = f.atts[0].clone();
    extra.id = f.next_id;
    extra.row_key = vec![1];
    insert_att(&two, &extra);
    let err = sq::check_snapshot_with(&two, &target, &f.anchor_for_snapshot()).expect_err("2");
    assert_eq!(
        err.to_string(),
        refused("it holds 2 store-identity rows, not one")
    );

    let (cut, f) = snapshot_db(dir.path(), "no_cutover.db", 1);
    cut.execute(
        "DELETE FROM row_attestations WHERE table_name = ?1 AND op = 'cutover'",
        [first],
    )
    .expect("drop a cutover");
    let err = sq::check_snapshot_with(&cut, &target, &f.anchor_for_snapshot()).expect_err("cut");
    assert_eq!(
        err.to_string(),
        refused(&format!("{first} has no cutover watermark"))
    );

    let (unsigned, _f) = snapshot_db(dir.path(), "unsigned.db", 1);
    unsigned
        .execute_batch("UPDATE row_attestations SET signature = NULL")
        .expect("strip signatures");
    assert_eq!(
        sq::check_snapshot_with(&unsigned, &target, &unanchored_10116()).expect("never armed"),
        SnapshotVerdict::NeverArmed
    );

    let (signed, _f) = snapshot_db(dir.path(), "unanchored.db", 1);
    let err = sq::check_snapshot_with(&signed, &target, &unanchored_10116()).expect_err("unanch");
    assert_eq!(
        err.to_string(),
        refused(&format!(
            "its row attestations cannot be verified: unanchored ({})",
            unanchored_reason()
        ))
    );

    let (drift, f) = snapshot_db(dir.path(), "drift.db", 1);
    drift
        .execute_batch("UPDATE memories SET content = 'changed'")
        .expect("drift a row");
    let err =
        sq::check_snapshot_with(&drift, &target, &f.anchor_for_snapshot()).expect_err("drift");
    // The drifted row and its table accumulator are the two defects; the
    // first names the row's latest attestation (the last one written).
    let latest = f.next_id - 1;
    assert_eq!(
        err.to_string(),
        refused(&format!(
            "its row attestations do not verify (2 defects; first: memories: live row \
             differs from its latest attestation {latest})"
        ))
    );
}

/// The reason text of [`unanchored_10116`], from the verifier itself.
fn unanchored_reason() -> String {
    let f = Fixture::new();
    match f.report_with(&unanchored_10116()).outcome() {
        super::super::Outcome::Unanchored(why) => why.to_string(),
        other => panic!("not unanchored: {other:?}"),
    }
}

/// J4: the live accumulator folds over streamed rows (no gathered `Vec`,
/// one read per row) and equals the fold over the parsed rows; a row with
/// no canonical form ends it with the same error text.
#[test]
fn live_acc_folds_streamed_rows_j4_10116() {
    let dir = anchor_dir();
    let conn = side_table_db(dir.path(), "live.db");
    base_tables(&conn);
    let s = spec("memories");
    let mut want = ZERO_DIGEST;
    for n in 0..3 {
        let cells = memory_cells(&format!("l{n}"), "live");
        insert_cells(&conn, "memories", &cells);
        want = acc_add(
            &want,
            &acc_term("memories", &encode_key(s, &cells), &row_digest(s, &cells)),
        );
    }
    probe::reset();
    assert_eq!(sq::live_acc(&conn, s).expect("live acc"), want);
    assert_eq!(probe::get(Count::Gather), 0, "no gathered Vec");
    assert_eq!(probe::get(Count::RowRead), 3, "one read per row");

    // A duplicate JSON key is the stored value with no single meaning
    // (#10092): `CanonicalRow::parse` refuses it.
    let bad = [
        t("bad"),
        t(r#"{"a":1,"a":2}"#),
        Cell::Int(5),
        t("long"),
        t("x"),
    ];
    let why = CanonicalRow::parse(s, &bad)
        .expect_err("no canonical form")
        .to_string();
    insert_cells(&conn, "memories", &bad);
    let err = sq::live_acc(&conn, s).expect_err("non-canonical row");
    assert_eq!(err.to_string(), why);
}

/// One byte over the seal read bound of `seal.rs` (64 KiB).
const OVERSIZE_SEAL_BYTES_10116: usize = 64 * 1024 + 1;

/// What a stored seal is before `advance`.
enum Stored {
    Missing,
    Marks(SealRecord),
    Directory,
    Text(String),
}

/// J3 on `seal::advance`, one row per stored state: a write happens only
/// when the merged marks differ from a readable stored seal (or none is
/// stored); an equal or higher seal keeps its bytes, inode and mtime; an
/// unreadable seal (directory, malformed, oversize) is never "equal": it is
/// refused with its exact reason and left as it was.
#[test]
fn seal_advance_writes_only_when_a_mark_moves_j3_10116() {
    let dir = anchor_dir();
    let rec = marks(5, &[("leases", 2), ("memories", 4)]);
    let oversize = format!("{}\n", "x".repeat(OVERSIZE_SEAL_BYTES_10116));
    // (name, stored, Ok(marks after) or Err(reason), writes)
    let cases: [(&str, Stored, Result<SealRecord, String>, u64); 9] = [
        ("missing", Stored::Missing, Ok(rec.clone()), 1),
        ("equal", Stored::Marks(rec.clone()), Ok(rec.clone()), 0),
        (
            "higher everywhere",
            Stored::Marks(marks(9, &[("leases", 3), ("memories", 8)])),
            Ok(marks(9, &[("leases", 3), ("memories", 8)])),
            0,
        ),
        (
            "lower high water",
            Stored::Marks(marks(4, &[("leases", 2), ("memories", 4)])),
            Ok(rec.clone()),
            1,
        ),
        (
            "one head lower, one higher",
            Stored::Marks(marks(5, &[("leases", 1), ("memories", 6)])),
            Ok(marks(5, &[("leases", 2), ("memories", 6)])),
            1,
        ),
        (
            "a table the seal has not seen",
            Stored::Marks(marks(5, &[("memories", 4)])),
            Ok(rec.clone()),
            1,
        ),
        (
            "directory",
            Stored::Directory,
            Err("not a regular file".to_string()),
            0,
        ),
        (
            "malformed",
            Stored::Text("ai-memory row-attest seal v0\nhigh_water 5\n".to_string()),
            Err("the header line is not the seal header".to_string()),
            0,
        ),
        (
            "oversize",
            Stored::Text(oversize.clone()),
            Err(format!("{} bytes, over 65536", oversize.len())),
            0,
        ),
    ];
    std::fs::create_dir_all(dir.path().join(seal::SEAL_DIR)).expect("seal dir");
    for (i, (name, stored, want, writes)) in cases.into_iter().enumerate() {
        let path = dir.path().join(seal::SEAL_DIR).join(format!("advance-{i}"));
        match &stored {
            Stored::Missing => {}
            Stored::Marks(m) => seal::replace(&path, m).expect("stored seal"),
            Stored::Directory => std::fs::create_dir(&path).expect("directory seal"),
            Stored::Text(s) => std::fs::write(&path, s).expect("stored text"),
        }
        let before = matches!(stored, Stored::Marks(_) | Stored::Text(_)).then(|| file_id(&path));
        probe::reset();
        let got = seal::advance(&path, &rec);
        assert_eq!(probe::get(Count::SealWrite), writes, "{name}: writes");
        match want {
            Ok(after) => {
                assert!(got.is_ok(), "{name}: {got:?}");
                assert_eq!(seal::read(&path), seal::SealState::Sealed(after), "{name}");
                if writes == 0 {
                    assert_eq!(Some(file_id(&path)), before, "{name}: bytes, inode, mtime");
                }
            }
            Err(why) => {
                let err = got.expect_err(name);
                assert_eq!(
                    err.to_string(),
                    format!("the anchored seal {} cannot be read: {why}", path.display()),
                    "{name}"
                );
                if let Some(b) = before {
                    assert_eq!(file_id(&path), b, "{name}: left as it was");
                }
                assert!(
                    matches!(seal::read(&path), seal::SealState::Unreadable { .. }),
                    "{name}: still unreadable"
                );
            }
        }
    }
}
