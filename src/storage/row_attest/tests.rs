//! Unit tests for the #10040 row-attestation core (3-agent vote (71472661)
//! V1-10040): golden vectors (C-2), the accumulator, preimage binding (C-1)
//! and the completeness verifier (C-5, E-2, E-3).

use super::*;

/// Golden digests computed by an independent reference encoder written from
/// the format description (`.local-runs` scratch `golden.py`, Python
/// `hashlib`), never from this module.
/// Eight covered columns (NOTICE 4a adds metadata, `expires_at`,
/// confidence; scope rides in `metadata.scope`), computed independently by
/// `.local-runs/lane/golden.py` from the written spec. #10092: a timestamp
/// is digested as its exact stored text (`.local-runs/lane/golden10092.py`,
/// which first reproduces the earlier normalised goldens as a self-check).
const GOLDEN_MEMORIES: &str = "349167ea4fed8fdd3ef74fc16234c8ad2f051b0cf94d7f48662123e5d5a222cc";
const GOLDEN_RECALL_OBS: &str = "802b98db419706ffeafd221138eea9fe128aefb408c7bf795fa6b0dd15a89816";
const GOLDEN_ACTION_EDGES: &str =
    "e6067df81f1117e9bfa5b0dfd56c19c457513d923f619242119f97b4ec66401b";
const GOLDEN_ACTION_EDGES_KEY: &str = "03000000026131030000000261320300000006626c6f636b73";

fn spec(table: &str) -> &'static TableSpec {
    spec_for(table).unwrap_or_else(|| panic!("no spec for {table}"))
}

fn t(s: &str) -> Cell {
    Cell::Text(s.to_string())
}

/// The digest of a canonical row (#10092: [`super::row_digest`] takes only a
/// [`CanonicalRow`]); panics on a row with no canonical form.
fn row_digest(s: &TableSpec, cells: &[Cell]) -> [u8; 32] {
    super::row_digest(&CanonicalRow::parse(s, cells).expect("canonical row"))
}

#[test]
fn every_attested_table_has_a_spec_and_its_key_columns() {
    let expected = [
        "memories",
        "entity_aliases",
        "namespace_meta",
        "pending_actions",
        "subscriptions",
        "subscription_events",
        "subscription_dlq",
        "memory_transcripts",
        "memory_transcript_links",
        "recall_observations",
        "actions",
        "action_edges",
        "leases",
        "routine_runs",
    ];
    let names: Vec<&str> = TABLES.iter().map(|s| s.table).collect();
    assert_eq!(names, expected);
    for s in TABLES {
        for k in s.key {
            assert!(s.index_of(k).is_some(), "{}: key {k} not covered", s.table);
        }
        if let Some(col) = s.transition {
            assert!(s.index_of(col).is_some(), "{}: transition {col}", s.table);
        }
    }
}

#[test]
fn retention_rule_per_table_c8() {
    // Hand-written: only the three operational tables supersede.
    let supersede = ["subscription_dlq", "recall_observations", "leases"];
    for s in TABLES {
        let want = if supersede.contains(&s.table) {
            Retention::Supersede
        } else {
            Retention::Append
        };
        assert_eq!(s.retention, want, "{}", s.table);
    }
}

#[test]
fn golden_memories_digest_sqlite_and_pg_forms_c2() {
    let s = spec("memories");
    let sqlite = [
        t("m1"),
        t(r#"["b","a"]"#),
        Cell::Int(5),
        t("long"),
        t("hello"),
        t(r#"{"scope": "team", "b": 1}"#),
        t("2026-11-23T10:00:00+02:00"),
        Cell::Real(0.5),
    ];
    let pg = [
        t("m1"),
        Cell::Json(serde_json::json!(["a", "b"])),
        Cell::Int(5),
        t("long"),
        t("hello"),
        Cell::Json(serde_json::json!({"b": 1, "scope": "team"})),
        t("2026-11-23T10:00:00+02:00"),
        Cell::Real(0.5),
    ];
    assert_eq!(hex::encode(row_digest(s, &sqlite)), GOLDEN_MEMORIES);
    assert_eq!(hex::encode(row_digest(s, &pg)), GOLDEN_MEMORIES);
}

#[test]
fn golden_composite_key_nulls_timestamps_bools_c2() {
    let s = spec("recall_observations");
    let sqlite = [
        t("r1"),
        t("m1"),
        t("fts"),
        Cell::Int(1),
        Cell::Real(0.5),
        Cell::Int(0),
        t("2026-11-23T10:00:00+02:00"),
        Cell::Null,
        Cell::Null,
        Cell::Int(1),
        t("ai:a"),
        t("ns"),
    ];
    let pg = [
        t("r1"),
        t("m1"),
        t("fts"),
        Cell::Int(1),
        Cell::Real(0.5),
        Cell::Bool(false),
        t("2026-11-23T10:00:00+02:00"),
        Cell::Null,
        Cell::Null,
        Cell::Bool(true),
        t("ai:a"),
        t("ns"),
    ];
    assert_eq!(hex::encode(row_digest(s, &sqlite)), GOLDEN_RECALL_OBS);
    assert_eq!(hex::encode(row_digest(s, &pg)), GOLDEN_RECALL_OBS);
}

#[test]
fn golden_three_column_key_c2() {
    let s = spec("action_edges");
    let row = [t("a1"), t("a2"), t("blocks"), Cell::Int(1_700_000_000)];
    assert_eq!(hex::encode(encode_key(s, &row)), GOLDEN_ACTION_EDGES_KEY);
    assert_eq!(hex::encode(row_digest(s, &row)), GOLDEN_ACTION_EDGES);
}

#[test]
fn null_differs_from_empty_and_tags_order_is_canonical_e4() {
    let s = spec("memories");
    let base = [t("m1"), t("[]"), Cell::Int(5), t("long"), t("x")];
    let null_tags = [t("m1"), Cell::Null, Cell::Int(5), t("long"), t("x")];
    let empty_text = [t("m1"), t(""), Cell::Int(5), t("long"), t("x")];
    assert_ne!(row_digest(s, &base), row_digest(s, &null_tags));
    assert_ne!(row_digest(s, &base), row_digest(s, &empty_text));
    assert_ne!(row_digest(s, &null_tags), row_digest(s, &empty_text));
    let ab = [t("m1"), t(r#"["a","b"]"#), Cell::Int(5), t("long"), t("x")];
    let ba = [
        t("m1"),
        t(r#"[ "b", "a" ]"#),
        Cell::Int(5),
        t("long"),
        t("x"),
    ];
    assert_eq!(row_digest(s, &ab), row_digest(s, &ba));
}

#[test]
fn each_memory_field_changes_the_digest_e1() {
    let s = spec("memories");
    // Expected covered set written out (NOTICE 4a): not derived from TABLES.
    let base = [
        t("m1"),
        t(r#"["a"]"#),
        Cell::Int(5),
        t("long"),
        t("x"),
        t(r#"{"scope":"team"}"#),
        t("2099-01-01T00:00:00Z"),
        Cell::Real(1.0),
    ];
    let mutants: [(&str, Cell); 10] = [
        ("id", t("m2")),
        ("tags", t(r#"["a","c"]"#)),
        ("priority", Cell::Int(6)),
        ("tier", t("mid")),
        ("content", t("y")),
        ("metadata", t(r#"{"scope":"other"}"#)),
        ("metadata", t(r#"{"scope":"team","k":1}"#)),
        ("expires_at", t("2098-01-01T00:00:00Z")),
        ("expires_at", Cell::Null),
        ("confidence", Cell::Real(0.5)),
    ];
    for (name, cell) in mutants {
        let i = s
            .index_of(name)
            .unwrap_or_else(|| panic!("memories: {name} is not a covered column"));
        let mut row = base.clone();
        row[i] = cell;
        assert_ne!(row_digest(s, &row), row_digest(s, &base), "{name}");
    }
}

/// NOTICE 4a / E-4: NULL is distinct from empty for every added field, and
/// metadata has one canonical byte form (sorted keys, no whitespace).
#[test]
fn added_fields_null_differs_from_empty_and_metadata_is_canonical_4a() {
    let s = spec("memories");
    let at = |col: &str| {
        s.index_of(col)
            .unwrap_or_else(|| panic!("{col} not covered"))
    };
    let mut row: Vec<Cell> = vec![Cell::Null; s.cols.len()];
    row[0] = t("m1");
    for (col, empty) in [
        ("metadata", t("{}")),
        ("expires_at", t("")),
        ("confidence", Cell::Real(0.0)),
    ] {
        let mut null = row.clone();
        null[at(col)] = Cell::Null;
        let mut filled = row.clone();
        filled[at(col)] = empty;
        assert_ne!(row_digest(s, &null), row_digest(s, &filled), "{col}");
    }
    let mut a = row.clone();
    a[at("metadata")] = t(r#"{ "scope" : "team", "b" : [1, 2] }"#);
    let mut b = row.clone();
    b[at("metadata")] = Cell::Json(serde_json::json!({"b": [1, 2], "scope": "team"}));
    assert_eq!(row_digest(s, &a), row_digest(s, &b));
}

#[test]
fn mistyped_cell_never_collides_with_well_typed() {
    let s = spec("memories");
    let int_prio = [t("m1"), t("[]"), Cell::Int(5), t("long"), t("x")];
    let text_prio = [t("m1"), t("[]"), t("5"), t("long"), t("x")];
    assert_ne!(row_digest(s, &int_prio), row_digest(s, &text_prio));
}

#[test]
fn json_key_order_and_whitespace_are_canonical() {
    let s = spec("pending_actions");
    let mut a: Vec<Cell> = vec![Cell::Null; s.cols.len()];
    a[0] = t("p1");
    let mut b = a.clone();
    a[4] = t(r#"{"b":1,"a":[1,2]}"#);
    b[4] = Cell::Json(serde_json::json!({"a": [1, 2], "b": 1}));
    assert_eq!(row_digest(s, &a), row_digest(s, &b));
}

#[test]
fn accumulator_add_sub_inverse_and_wrap() {
    let a = [0xff_u8; 32];
    let mut one = [0_u8; 32];
    one[31] = 1;
    assert_eq!(acc_add(&a, &one), ZERO_DIGEST);
    assert_eq!(acc_sub(&ZERO_DIGEST, &one), a);
    let x = acc_term("memories", b"k1", &[7_u8; 32]);
    let y = acc_term("memories", b"k2", &[9_u8; 32]);
    let sum = acc_add(&acc_add(&ZERO_DIGEST, &x), &y);
    assert_eq!(acc_sub(&sum, &x), y);
    assert_eq!(acc_add(&x, &y), acc_add(&y, &x));
    assert_ne!(
        acc_term("memories", b"k1", &[7_u8; 32]),
        acc_term("leases", b"k1", &[7_u8; 32])
    );
}

#[test]
fn op_spelling_table() {
    let want = [
        (Op::Insert, "insert"),
        (Op::Update, "update"),
        (Op::Transition, "transition"),
        (Op::Delete, "delete"),
        (Op::Cutover, "cutover"),
        (Op::Baseline, "baseline"),
        (Op::Store, "store"),
    ];
    assert_eq!(want.len(), Op::ALL.len());
    for (op, s) in want {
        assert_eq!(op.as_str(), s);
        assert_eq!(Op::parse(s), Some(op));
    }
    assert_eq!(Op::parse("INSERT"), None);
    assert_eq!(Op::parse(""), None);
}

#[test]
fn memory_id_of_key_round_trip() {
    let s = spec("memories");
    let key = encode_key(s, &[t("abc-1")]);
    assert_eq!(memory_id_of_key(&key).as_deref(), Some("abc-1"));
    assert_eq!(memory_id_of_key(&[]), None);
    assert_eq!(memory_id_of_key(&[TAG_INT, 0, 0, 0, 1, b'a']), None);
    assert_eq!(memory_id_of_key(&[TAG_TEXT, 0, 0, 0, 5, b'a']), None);
}

// ---- verifier fixtures -------------------------------------------------

const STORE: &str = "store-a";
const AGENT: &str = "ai:attester";

fn keypair() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
}

struct Fixture {
    signing: ed25519_dalek::SigningKey,
    atts: Vec<Attestation>,
    live: Vec<LiveRow>,
    next_id: i64,
}

impl Fixture {
    fn new() -> Self {
        let mut f = Self {
            signing: keypair(),
            atts: Vec::new(),
            live: Vec::new(),
            next_id: 1,
        };
        let store = f.att(
            STORE_ROW_TABLE,
            Vec::new(),
            0,
            Op::Store,
            None,
            0,
            ZERO_DIGEST,
        );
        f.atts.push(store);
        for s in TABLES {
            let c = f.att(s.table, Vec::new(), 0, Op::Cutover, None, 0, ZERO_DIGEST);
            f.atts.push(c);
        }
        f
    }

    #[allow(clippy::too_many_arguments)]
    fn att(
        &mut self,
        table: &str,
        key: Vec<u8>,
        seq: i64,
        op: Op,
        digest: Option<[u8; 32]>,
        table_seq: i64,
        acc: [u8; 32],
    ) -> Attestation {
        let covered = spec_for(table).map(TableSpec::covered).unwrap_or_default();
        let prior = self
            .atts
            .iter()
            .filter(|a| a.table == table && a.row_key == key && a.seq > 0)
            .max_by_key(|a| a.seq)
            .map_or_else(|| ZERO_DIGEST.to_vec(), |a| a.attestation_digest.clone());
        let mut a = Attestation {
            id: self.next_id,
            table: table.to_string(),
            row_key: key,
            seq,
            op: op.as_str().to_string(),
            row_digest: digest.map(|d| d.to_vec()),
            prior_digest: if seq > 0 { prior } else { ZERO_DIGEST.to_vec() },
            agent_id: AGENT.to_string(),
            key_id: key_id_of(&self.signing.verifying_key()),
            attested_at: "2026-11-23T00:00:00.000000Z".to_string(),
            format_version: FORMAT_VERSION,
            covered_columns: covered,
            store_id: STORE.to_string(),
            table_seq,
            table_acc: acc.to_vec(),
            signature: None,
            attestation_digest: Vec::new(),
        };
        self.next_id += 1;
        sign(&mut a, &self.signing);
        a
    }

    /// Write memory row `id` (insert or update) with `content`.
    fn put_memory(&mut self, id: &str, content: &str) {
        let s = spec("memories");
        let cells = [t(id), t("[]"), Cell::Int(5), t("long"), t(content)];
        let key = encode_key(s, &cells);
        let digest = row_digest(s, &cells);
        let old = self
            .live
            .iter()
            .position(|r| r.table == "memories" && r.key == key);
        let mut acc = self.head_acc("memories");
        if let Some(i) = old {
            acc = acc_sub(&acc, &acc_term("memories", &key, &self.live[i].digest));
            self.live.remove(i);
        }
        acc = acc_add(&acc, &acc_term("memories", &key, &digest));
        let seq = self.next_seq("memories", &key);
        let table_seq = self.head_seq("memories") + 1;
        let op = if old.is_some() {
            Op::Update
        } else {
            Op::Insert
        };
        let a = self.att(
            "memories",
            key.clone(),
            seq,
            op,
            Some(digest),
            table_seq,
            acc,
        );
        self.atts.push(a);
        self.live.push(LiveRow {
            table: "memories".to_string(),
            key,
            digest,
        });
    }

    fn head_acc(&self, table: &str) -> [u8; 32] {
        self.atts
            .iter()
            .filter(|a| a.table == table)
            .max_by_key(|a| a.table_seq)
            .and_then(|a| <[u8; 32]>::try_from(a.table_acc.as_slice()).ok())
            .unwrap_or(ZERO_DIGEST)
    }

    fn head_seq(&self, table: &str) -> i64 {
        self.atts
            .iter()
            .filter(|a| a.table == table)
            .map(|a| a.table_seq)
            .max()
            .unwrap_or(0)
    }

    fn next_seq(&self, table: &str, key: &[u8]) -> i64 {
        self.atts
            .iter()
            .filter(|a| a.table == table && a.row_key == key)
            .map(|a| a.seq)
            .max()
            .unwrap_or(0)
            + 1
    }

    fn report(&self) -> Report {
        self.report_with(&anchored(&[(
            AGENT,
            self.signing.verifying_key(),
            None,
            None,
        )]))
    }

    fn report_with(&self, anchor: &anchor::AnchorLoad) -> Report {
        let high = self.atts.iter().map(|a| a.id).max();
        verify(&VerifyInput {
            live: &self.live,
            attestations: &self.atts,
            anchor,
            id_high_water: high,
            memory_id_of_key: &memory_id_of_key,
            non_canonical: &[],
            seal: &super::seal::SealState::NotSealed,
        })
    }
}

fn assert_defect(report: &Report, needle: &str) {
    assert!(
        report.defects.iter().any(|d| d.contains(needle)),
        "no defect containing {needle:?} in {:?}",
        report.defects
    );
}

#[test]
fn verify_clean_store_passes_c5() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    f.put_memory("m1", "one-b");
    let r = f.report();
    assert!(r.ok(), "{:?}", r.defects);
    assert_eq!(r.tables["memories"].verified, 2);
    assert_eq!(r.tables["memories"].attestations, 4);
    assert!(r.unverified_memories.is_empty());
}

#[test]
fn verify_append_keeps_every_attestation_e2() {
    let mut f = Fixture::new();
    for n in 0..5 {
        f.put_memory("m1", &format!("v{n}"));
    }
    let r = f.report();
    assert!(r.ok(), "{:?}", r.defects);
    // 1 cutover + 5 changes of one row: append retention keeps all.
    assert_eq!(r.tables["memories"].attestations, 6);
}

#[test]
fn verify_detects_deleted_attestation_c5() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    // Raw delete of m1's attestation (id is not the newest, so the
    // high-water check alone cannot be what fails).
    let idx = f
        .atts
        .iter()
        .position(|a| a.table == "memories" && a.op == "insert")
        .unwrap_or(usize::MAX);
    f.atts.remove(idx);
    let r = f.report();
    assert!(!r.ok());
    assert_defect(&r, "memories: live row has no attestation");
    assert_defect(&r, "table sequence breaks");
    assert!(r.unverified_memories.contains("m1"));
}

#[test]
fn verify_detects_mutated_base_row_c5_e1() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let s = spec("memories");
    f.live[0].digest = row_digest(
        s,
        &[t("m1"), t(r#"["evil"]"#), Cell::Int(5), t("long"), t("one")],
    );
    let r = f.report();
    assert_defect(&r, "memories: live row differs from its latest attestation");
    assert_defect(&r, "memories: live rows do not match the signed table head");
    assert!(r.unverified_memories.contains("m1"));
}

/// #10094: a row drift fails only the row it names; an unexplained or
/// store-wide defect, or no anchor, fails every row.
#[test]
fn row_drift_fails_only_its_row_store_defects_fail_all_10094() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    let s = spec("memories");
    let key = encode_key(s, &[t("m1")]);
    let i = f
        .live
        .iter()
        .position(|r| r.key == key)
        .unwrap_or(usize::MAX);
    f.live[i].digest = row_digest(
        s,
        &[t("m1"), t(r#"["evil"]"#), Cell::Int(5), t("long"), t("one")],
    );
    let r = f.report();
    assert_defect(&r, "memories: live rows do not match the signed table head");
    assert!(r.store_defects.is_empty(), "{:?}", r.store_defects);
    assert!(!r.memory_verified("m1"), "the drifted row fails");
    assert!(r.memory_verified("m2"), "the untouched row verifies");
    // No anchor: no row verifies.
    let why = anchor::Unanchored::Missing {
        path: "/nonexistent-10094".into(),
    };
    let r = f.report_with(&anchor::AnchorLoad::Unanchored(why));
    assert!(!r.memory_verified("m2"), "no signature was checked");
    // A store-wide defect (an unsigned attestation) fails every row.
    let last = f.atts.len() - 1;
    f.atts[last].signature = None;
    let r = f.report();
    assert!(!r.store_defects.is_empty(), "{:?}", r.defects);
    assert!(!r.memory_verified("m2"), "a store defect fails every row");
}

/// #10094: a table-head mismatch is row-local only when the signed head
/// equals the attested state of the live rows. A row drift alongside a
/// signed head that matches neither the live rows nor their attested state
/// leaves the head mismatch unexplained, so it stays store-wide and fails
/// every row, the untouched one included.
#[test]
fn unexplained_head_mismatch_beside_a_row_drift_fails_every_row_10094() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    let s = spec("memories");
    let key_m2 = encode_key(s, &[t("m2")]);
    let m2_digest = f
        .live
        .iter()
        .find(|r| r.key == key_m2)
        .map_or(ZERO_DIGEST, |r| r.digest);
    // A signed head for m2 (its row digest is right) whose accumulator also
    // counts a row that never existed: matches neither acc nor attested_acc.
    let ghost = acc_term("memories", b"ghost-10094", &[7_u8; 32]);
    let bogus = acc_add(&f.head_acc("memories"), &ghost);
    let seq = f.next_seq("memories", &key_m2);
    let table_seq = f.head_seq("memories") + 1;
    let head = f.att(
        "memories",
        key_m2,
        seq,
        Op::Update,
        Some(m2_digest),
        table_seq,
        bogus,
    );
    f.atts.push(head);
    // Row drift on m1.
    let key_m1 = encode_key(s, &[t("m1")]);
    let i = f
        .live
        .iter()
        .position(|r| r.key == key_m1)
        .unwrap_or(usize::MAX);
    f.live[i].digest = row_digest(
        s,
        &[t("m1"), t(r#"["evil"]"#), Cell::Int(5), t("long"), t("one")],
    );
    let r = f.report();
    let head_defect =
        format!("memories: live rows do not match the signed table head (table_seq {table_seq})");
    assert_eq!(
        r.store_defects,
        vec![head_defect],
        "only the unexplained head mismatch is store-wide: {:?}",
        r.defects
    );
    assert!(!r.memory_verified("m1"), "the drifted row fails");
    assert!(
        !r.memory_verified("m2"),
        "an unexplained head mismatch fails the untouched row too"
    );
}

#[test]
fn verify_detects_row_and_attestations_deleted_together_c5() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    f.live
        .retain(|r| memory_id_of_key(&r.key).as_deref() != Some("m1"));
    let k = encode_key(spec("memories"), &[t("m1")]);
    f.atts
        .retain(|a| !(a.table == "memories" && a.row_key == k));
    let r = f.report();
    assert!(!r.ok());
    assert_defect(&r, "table sequence breaks");
}

#[test]
fn verify_detects_tail_truncation_e2() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m1", "two");
    let public = f.signing.verifying_key();
    let high = f.atts.iter().map(|a| a.id).max();
    f.atts.pop();
    // Roll the live row back too: only the high-water mark can tell.
    let s = spec("memories");
    f.live[0].digest = row_digest(s, &[t("m1"), t("[]"), Cell::Int(5), t("long"), t("one")]);
    let anchor = anchored(&[(AGENT, public, None, None)]);
    let r = verify(&VerifyInput {
        live: &f.live,
        attestations: &f.atts,
        anchor: &anchor,
        id_high_water: high,
        memory_id_of_key: &memory_id_of_key,
        non_canonical: &[],
        seal: &super::seal::SealState::NotSealed,
    });
    assert_defect(&r, "row_attestations tail truncated");
}

/// #10087: the anchored seal catches a self-consistent rollback (counter
/// lowered with the tail) and a per-table head moved back; a seal at the
/// current marks adds no defect; an unreadable seal is a defect.
#[test]
fn verify_checks_the_anchored_seal_10087() {
    use super::seal::{SealRecord, SealState};
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let public = f.signing.verifying_key();
    let anchor = anchored(&[(AGENT, public, None, None)]);
    let current = SealRecord::of(&f.atts);
    let run = |seal: &SealState| {
        verify(&VerifyInput {
            live: &f.live,
            attestations: &f.atts,
            anchor: &anchor,
            id_high_water: f.atts.iter().map(|a| a.id).max(),
            memory_id_of_key: &memory_id_of_key,
            non_canonical: &[],
            seal,
        })
    };
    assert!(
        run(&SealState::Sealed(current.clone())).ok(),
        "current seal"
    );
    let mut ahead = current.clone();
    ahead.high_water += 1;
    assert_defect(
        &run(&SealState::Sealed(ahead)),
        super::DEFECT_SEAL_ROLLED_BACK,
    );
    let mut head = current;
    *head.heads.get_mut("memories").expect("memories head") += 1;
    assert_defect(
        &run(&SealState::Sealed(head)),
        &format!("memories: {}", super::DEFECT_SEAL_HEAD_ROLLED_BACK),
    );
    assert_defect(
        &run(&SealState::Unreadable {
            path: std::path::PathBuf::from("seal-x"),
            why: "bad".to_string(),
        }),
        "the anchored seal seal-x cannot be read: bad",
    );
}

#[test]
fn verify_detects_replay_of_older_attestation_c1_e2() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m1", "two");
    // Restore the old row content: the latest attestation names "two".
    let s = spec("memories");
    f.live[0].digest = row_digest(s, &[t("m1"), t("[]"), Cell::Int(5), t("long"), t("one")]);
    let r = f.report();
    assert_defect(&r, "memories: live row differs from its latest attestation");
}

#[test]
fn verify_detects_transplant_to_other_row_table_store_c1() {
    let cases: [(&str, fn(&mut Attestation)); 3] = [
        ("row", |a| {
            a.row_key = encode_key(spec("memories"), &[t("m9")])
        }),
        ("table", |a| a.table = "leases".to_string()),
        ("store", |a| a.store_id = "store-b".to_string()),
    ];
    for (name, mutate) in cases {
        let mut f = Fixture::new();
        f.put_memory("m1", "one");
        let i = f.atts.len() - 1;
        mutate(&mut f.atts[i]);
        let r = f.report();
        assert_defect(&r, "signature does not verify");
        assert!(!r.ok(), "{name}");
    }
}

#[test]
fn verify_detects_unsigned_and_unknown_agent() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let i = f.atts.len() - 1;
    f.atts[i].signature = None;
    assert_defect(&f.report(), "is unsigned");
    let mut g = Fixture::new();
    g.put_memory("m1", "one");
    let j = g.atts.len() - 1;
    g.atts[j].agent_id = "ai:other".to_string();
    assert_defect(
        &g.report(),
        "is anchored to agent ai:attester, not ai:other",
    );
    g.atts[j].key_id = key_id_of(&other_key());
    assert_defect(
        &g.report(),
        "names agent ai:other with no key in the trust anchor",
    );
}

#[test]
fn verify_detects_missing_store_and_cutover_c6() {
    let mut f = Fixture::new();
    f.atts.retain(|a| a.table != STORE_ROW_TABLE);
    assert_defect(&f.report(), "no store-identity row");
    let mut g = Fixture::new();
    g.atts
        .retain(|a| !(a.table == "leases" && a.op == "cutover"));
    assert_defect(&g.report(), "leases: no cutover watermark");
}

/// #10095: a live row of a side table (Supersede retention) whose
/// attestation was removed is a defect with the exact reason, never a
/// silent `legacy` count: attribution of every attested row is checked.
#[test]
fn stripped_non_head_supersede_attestation_is_a_defect_10095() {
    let mut f = Fixture::new();
    let s = spec("leases");
    let mut acc = f.head_acc("leases");
    for (n, act) in ["act1", "act2"].into_iter().enumerate() {
        let cells = [t(act), t("h"), Cell::Int(1), Cell::Int(2), Cell::Int(1)];
        let key = encode_key(s, &cells);
        let digest = row_digest(s, &cells);
        acc = acc_add(&acc, &acc_term("leases", &key, &digest));
        let table_seq = i64::try_from(n).unwrap_or(i64::MAX) + 1;
        let a = f.att(
            "leases",
            key.clone(),
            1,
            Op::Insert,
            Some(digest),
            table_seq,
            acc,
        );
        f.atts.push(a);
        f.live.push(LiveRow {
            table: "leases".to_string(),
            key,
            digest,
        });
    }
    assert!(f.report().ok(), "{:?}", f.report().defects);
    // The attacker deletes the first (non-head) lease attestation.
    let first = f
        .atts
        .iter()
        .position(|a| a.table == "leases" && a.op == Op::Insert.as_str())
        .unwrap_or(usize::MAX);
    f.atts.remove(first);
    let r = f.report();
    assert_eq!(
        r.defects,
        vec!["leases: live row has no attestation".to_string()],
        "{r:?}"
    );
    assert!(!r.ok());
}

/// #10095: a side-table row with no attestation of its own is a defect
/// even when the cutover accumulator covers it (the arm baselines every
/// pre-existing row of every attested table, so none is left `legacy`).
#[test]
fn a_side_row_covered_only_by_the_cutover_is_a_defect_10095() {
    let mut f = Fixture::new();
    // A pre-existing leases row: covered by the cutover accumulator.
    let s = spec("leases");
    let cells = [t("act1"), t("h"), Cell::Int(1), Cell::Int(2), Cell::Int(1)];
    let key = encode_key(s, &cells);
    let digest = row_digest(s, &cells);
    let acc = acc_add(&ZERO_DIGEST, &acc_term("leases", &key, &digest));
    let idx = f
        .atts
        .iter()
        .position(|a| a.table == "leases")
        .unwrap_or(usize::MAX);
    let id = f.atts[idx].id;
    let mut c = f.att("leases", Vec::new(), 0, Op::Cutover, None, 0, acc);
    c.id = id;
    sign(&mut c, &keypair());
    f.atts[idx] = c;
    f.live.push(LiveRow {
        table: "leases".to_string(),
        key,
        digest,
    });
    let r = f.report();
    assert_eq!(
        r.defects,
        vec!["leases: live row has no attestation".to_string()],
        "{r:?}"
    );
}

#[test]
fn preimage_binds_every_field_c1() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let base = f.atts[f.atts.len() - 1].clone();
    let mutants: [(&str, fn(&mut Attestation)); 14] = [
        ("format_version", |a| a.format_version += 1),
        ("covered_columns", |a| a.covered_columns.push('x')),
        ("store_id", |a| a.store_id.push('x')),
        ("table", |a| a.table.push('x')),
        ("row_key", |a| a.row_key.push(0)),
        ("op", |a| a.op = "update".to_string()),
        ("row_digest", |a| a.row_digest = None),
        ("agent_id", |a| a.agent_id.push('x')),
        ("key_id", |a| a.key_id.push('x')),
        ("attested_at", |a| a.attested_at.push('x')),
        ("seq", |a| a.seq += 1),
        ("prior_digest", |a| a.prior_digest[0] ^= 1),
        ("table_seq", |a| a.table_seq += 1),
        ("table_acc", |a| a.table_acc[0] ^= 1),
    ];
    for (name, mutate) in mutants {
        let mut a = base.clone();
        mutate(&mut a);
        assert_ne!(preimage(&a), preimage(&base), "{name} not bound");
    }
}

/// NOTICE 4b: the verifier uses `verify_strict`. A small-order bound key
/// (the identity point) with `R` = identity and `S` = 0 passes the plain
/// cofactorless `verify` for every message; the strict check refuses it.
#[test]
fn small_order_key_signature_is_refused_by_strict_verify_10040() {
    // The identity point, compressed: y = 1, sign bit 0.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let weak = ed25519_dalek::VerifyingKey::from_bytes(&identity).expect("identity decompresses");
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let honest = f.atts[f.atts.len() - 1].clone();
    let mut a = honest.clone();
    a.key_id = key_id_of(&weak);
    let mut forged = [0_u8; 64];
    forged[0] = 1; // R = identity, S = 0
    a.signature = Some(forged.to_vec());
    a.attestation_digest = attestation_digest(&a);
    let expected = format!("attestation {} signature does not verify", a.id);
    assert_eq!(
        sig_defect(&a, &anchored(&[(AGENT, weak, None, None)])).as_deref(),
        Some(expected.as_str()),
        "a small-order key signature must be refused"
    );
    // Control: the honest signature by the fixture key still verifies.
    let good = f.signing.verifying_key();
    assert_eq!(
        sig_defect(&honest, &anchored(&[(AGENT, good, None, None)])),
        None
    );
}

// ---------------------------------------------------------------------------
// #10086: the out-of-database trust anchor (3-agent vote (71472661)
// V2-ROW-ATTEST-ANCHOR, conditions A-3, A-6, A-7, A-9)
// ---------------------------------------------------------------------------

/// The fixture's attestation instant, unix seconds.
fn fixture_at() -> i64 {
    chrono::DateTime::parse_from_rfc3339("2026-11-23T00:00:00.000000Z")
        .expect("fixture timestamp")
        .timestamp()
}

fn anchored(
    keys: &[(&str, ed25519_dalek::VerifyingKey, Option<i64>, Option<i64>)],
) -> anchor::AnchorLoad {
    anchor::AnchorLoad::Anchored(anchor::TrustAnchor::for_test("test-anchor", keys))
}

fn other_key() -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key()
}

/// A-3: no anchor is the distinct `Unanchored` outcome, never clean, and
/// a defect still outranks it.
#[test]
fn unanchored_is_never_clean_and_defects_outrank_it_10086() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let why = anchor::Unanchored::Missing {
        path: "/nonexistent-10086".into(),
    };
    let r = f.report_with(&anchor::AnchorLoad::Unanchored(why.clone()));
    assert_eq!(r.outcome(), Outcome::Unanchored(why.clone()));
    assert_eq!(r.outcome().kind(), "unanchored");
    assert!(!r.ok(), "unanchored is never ok");
    assert_eq!(r.anchor, AnchorStatus::Unanchored(why.clone()));
    // An unsigned attestation is a defect even without an anchor.
    let i = f.atts.len() - 1;
    f.atts[i].signature = None;
    let r = f.report_with(&anchor::AnchorLoad::Unanchored(why));
    assert_eq!(r.outcome().kind(), "defective");
    // Control: anchored and untouched is Clean.
    let mut g = Fixture::new();
    g.put_memory("m1", "one");
    assert_eq!(g.report().outcome(), Outcome::Clean);
}

/// A-6: a retired key verifies inside its validity window and is a named
/// defect outside it.
#[test]
fn retired_key_verifies_only_inside_its_window_10086() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let key = f.signing.verifying_key();
    let at = fixture_at();
    let inside = f.report_with(&anchored(&[
        (AGENT, key, None, Some(at + 1)),
        (AGENT, other_key(), Some(at + 1), None),
    ]));
    assert_eq!(inside.outcome(), Outcome::Clean, "{:?}", inside.defects);
    let after = f.report_with(&anchored(&[
        (AGENT, key, None, Some(at - 1)),
        (AGENT, other_key(), Some(at - 1), None),
    ]));
    assert_defect(&after, "used outside its anchored validity");
    let before = f.report_with(&anchored(&[(AGENT, key, Some(at + 1), None)]));
    assert_defect(&before, "used outside its anchored validity");
}

/// A-7: a key missing from the anchor is a named defect, with no fallback;
/// a key anchored to another agent is a named defect.
#[test]
fn key_missing_from_anchor_or_owned_by_another_agent_is_named_10086() {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    let key = f.signing.verifying_key();
    let missing = f.report_with(&anchored(&[(AGENT, other_key(), None, None)]));
    let kid = key_id_of(&key);
    assert_defect(
        &missing,
        &format!("key_id {kid} of agent {AGENT} is not in the trust anchor"),
    );
    let foreign = f.report_with(&anchored(&[("ai:other", key, None, None)]));
    assert_defect(
        &foreign,
        &format!("key_id {kid} is anchored to agent ai:other, not {AGENT}"),
    );
}

/// Scratch directory for the loader tests (never /tmp).
fn anchor_dir() -> tempfile::TempDir {
    let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/anchor_10086");
    std::fs::create_dir_all(&scratch).expect("scratch");
    let mut b = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        b.permissions(std::fs::Permissions::from_mode(0o700));
    }
    b.prefix("anchor-")
        .tempdir_in(&scratch)
        .expect("anchor dir")
}

fn write_key(dir: &std::path::Path, name: &str, seed: u8) -> ed25519_dalek::VerifyingKey {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    std::fs::write(dir.join(name), key.to_bytes()).expect("write key");
    key
}

fn unanchored_kind(load: &anchor::AnchorLoad) -> &'static str {
    match load {
        anchor::AnchorLoad::Anchored(_) => "anchored",
        anchor::AnchorLoad::Unanchored(why) => why.kind(),
    }
}

/// A-3: every unusable anchor is its own reason, never a fallback.
#[test]
fn unusable_anchor_dirs_are_each_a_named_unanchored_reason_10086() {
    let d = anchor_dir();
    let missing = d.path().join("absent");
    assert_eq!(
        anchor::TrustAnchor::load_dir(&missing),
        anchor::AnchorLoad::Unanchored(anchor::Unanchored::Missing { path: missing })
    );
    assert_eq!(
        unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
        "empty"
    );
    let cases: [(&str, &[u8]); 4] = [
        ("ai:a.pub", b"short"),
        ("ai:a.pub.notatime", &[1; 32]),
        ("ai:a.pub.100-x", &[1; 32]),
        ("ai:a.pub.-1", &[1; 32]),
    ];
    for (name, bytes) in cases {
        let d = anchor_dir();
        std::fs::write(d.path().join(name), bytes).expect("write");
        assert_eq!(
            unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
            "malformed",
            "{name}"
        );
    }
    let d = anchor_dir();
    write_key(d.path(), "ai:a.pub", 1);
    std::fs::write(d.path().join(anchor::ANCHOR_MARKER_FILE), "2\n").expect("marker");
    assert_eq!(
        unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
        "malformed",
        "marker 2"
    );
    let d = anchor_dir();
    write_key(d.path(), "ai:a.pub", 1);
    write_key(d.path(), "ai:a.pub.100", 1);
    assert_eq!(
        unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
        "malformed",
        "duplicate"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let d = anchor_dir();
        write_key(d.path(), "ai:a.pub", 1);
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert_eq!(
            unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
            "unreadable",
            "0777"
        );
    }
}

/// A-5: a real deployment's key directory also holds the governance
/// operator key (`rules keygen`, base64 text), X25519 escrow keys and
/// private keys. They are not row signers: the directory loads anchored
/// with exactly the agent's key, and a corrupt agent `.pub` stays a
/// malformed anchor (fail closed).
#[test]
fn populated_key_dir_with_non_signer_files_loads_anchored_10086() {
    let d = anchor_dir();
    let agent = write_key(d.path(), "ai:a.pub", 1);
    std::fs::write(
        d.path()
            .join(crate::governance::rules_store::OPERATOR_PUBKEY_KEYGEN_FILE),
        "bm90IGEgcmF3IGVkMjU1MTkga2V5IGF0IGFsbA==\n",
    )
    .expect("operator key");
    std::fs::write(d.path().join("recovery.x25519.pub"), [7u8; 32]).expect("x25519");
    std::fs::write(d.path().join("daemon.x25519.pub"), b"short").expect("x25519 short");
    std::fs::write(d.path().join("ai:a.priv"), [9u8; 32]).expect("priv");
    let anchor::AnchorLoad::Anchored(a) = anchor::TrustAnchor::load_dir(d.path()) else {
        panic!("a populated key dir must load anchored");
    };
    assert_eq!(
        a.fingerprints(),
        vec![("ai:a".to_string(), key_id_of(&agent), false)],
        "only the agent key is anchored"
    );
    let d = anchor_dir();
    write_key(d.path(), "ai:a.pub", 1);
    std::fs::write(d.path().join("ai:b.pub"), "not raw\n").expect("corrupt");
    assert_eq!(
        unanchored_kind(&anchor::TrustAnchor::load_dir(d.path())),
        "malformed",
        "a corrupt agent key is never skipped"
    );
}

/// A-6, A-9: archives become retired keys with validity windows, the
/// output names the source, the layout version and every fingerprint, and
/// a nested (slashed) agent id is followed.
#[test]
fn key_dir_archives_load_as_retired_windows_10086() {
    let d = anchor_dir();
    let first = write_key(d.path(), "ai:a.pub.100", 1);
    let second = write_key(d.path(), "ai:a.pub.200-1", 2);
    let current = write_key(d.path(), "ai:a.pub", 3);
    std::fs::create_dir(d.path().join("ns")).expect("nested");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(d.path().join("ns"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod nested");
    }
    let nested = write_key(&d.path().join("ns"), "b.pub", 4);
    std::fs::write(d.path().join(anchor::ANCHOR_MARKER_FILE), "1\n").expect("marker");
    std::fs::write(d.path().join("ai:a.priv"), [9; 32]).expect("private file ignored");
    let a = match anchor::TrustAnchor::load_dir(d.path()) {
        anchor::AnchorLoad::Anchored(a) => a,
        anchor::AnchorLoad::Unanchored(why) => panic!("anchored, got {why}"),
    };
    assert_eq!(a.source(), d.path());
    let mut want = vec![
        ("ai:a".to_string(), key_id_of(&first), true),
        ("ai:a".to_string(), key_id_of(&second), true),
        ("ai:a".to_string(), key_id_of(&current), false),
        ("ns/b".to_string(), key_id_of(&nested), false),
    ];
    want.sort_by(|x, y| x.1.cmp(&y.1));
    assert_eq!(a.fingerprints(), want);
    let at = |s: i64| {
        chrono::DateTime::from_timestamp(s, 0)
            .expect("ts")
            .to_rfc3339()
    };
    assert_eq!(a.key_for("ai:a", &key_id_of(&first), &at(50)), Ok(&first));
    assert_eq!(a.key_for("ai:a", &key_id_of(&first), &at(100)), Ok(&first));
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&first), &at(101)),
        Err(anchor::KeyRefusal::OutOfRange {
            valid_from: None,
            valid_to: Some(100)
        })
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&second), &at(150)),
        Ok(&second)
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&second), &at(99)),
        Err(anchor::KeyRefusal::OutOfRange {
            valid_from: Some(100),
            valid_to: Some(200)
        })
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&current), &at(300)),
        Ok(&current)
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&current), &at(150)),
        Err(anchor::KeyRefusal::OutOfRange {
            valid_from: Some(200),
            valid_to: None
        })
    );
    assert_eq!(a.key_for("ns/b", &key_id_of(&nested), &at(1)), Ok(&nested));
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&nested), &at(1)),
        Err(anchor::KeyRefusal::OtherAgent("ns/b".to_string()))
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&other_key()), &at(1)),
        Err(anchor::KeyRefusal::UnknownKey)
    );
    assert_eq!(
        a.key_for("ai:z", &key_id_of(&other_key()), &at(1)),
        Err(anchor::KeyRefusal::UnknownAgent)
    );
    assert_eq!(
        a.key_for("ai:a", &key_id_of(&current), "not a time"),
        Err(anchor::KeyRefusal::BadTime)
    );
    let r = Fixture::new().report_with(&anchor::AnchorLoad::Anchored(a));
    let AnchorStatus::Anchored {
        source,
        layout_version,
        keys,
    } = r.anchor
    else {
        panic!("anchored status");
    };
    assert_eq!(source, d.path());
    assert_eq!(layout_version, anchor::ANCHOR_LAYOUT_VERSION);
    assert_eq!(keys.len(), 4);
}

/// A-2 source ratchet (allowlist over the whole source tree): `VerifyInput`
/// is built only in the allowlisted files, and nothing under
/// `src/storage/row_attest/` reads a key from the database except the
/// allowlisted arm-time identity check (which compares the session key it
/// signs with; it is not a verify path).
#[test]
fn no_verify_path_reads_a_key_from_the_database_ratchet_10086() {
    const CONSTRUCTS_VERIFY_INPUT: &[&str] = &[
        "src/storage/row_attest/sqlite.rs",
        "src/storage/row_attest/tests.rs",
    ];
    /// The DB key readers: `agent_pubkey` (both backends), the base64 key
    /// decoder and the key history table reader.
    const DB_KEY_READERS: &[&str] = &["agent_pubkey", "decode_public_base64", "pubkey_history"];
    /// `(file, reader, count)` allowed under row_attest/: the arm-time
    /// `session_identity`.
    const ARM_SITE: &[(&str, &str, usize)] = &[
        ("src/storage/row_attest/sqlite.rs", "agent_pubkey", 1),
        (
            "src/storage/row_attest/sqlite.rs",
            "decode_public_base64",
            1,
        ),
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut stack = vec![
        root.join("src"),
        root.join("tests"),
        root.join("benches"),
        root.join("examples"),
    ];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                files.push(path);
            }
        }
    }
    assert!(
        files.len() > 100,
        "the scan saw the tree ({} files)",
        files.len()
    );
    let mut builders = Vec::new();
    let mut readers = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(path).expect("read source");
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("VerifyInput{") && !CONSTRUCTS_VERIFY_INPUT.contains(&rel.as_str()) {
            builders.push(rel.clone());
        }
        if rel.starts_with("src/storage/row_attest/") && rel != "src/storage/row_attest/tests.rs" {
            for reader in DB_KEY_READERS {
                let n = compact.matches(reader).count();
                let allowed = ARM_SITE
                    .iter()
                    .find(|(f, r, _)| *f == rel && r == reader)
                    .map_or(0, |(_, _, c)| *c);
                if n != allowed {
                    readers.push(format!("{rel}: {reader} x{n} (allowed {allowed})"));
                }
            }
        }
    }
    assert!(
        builders.is_empty(),
        "VerifyInput built outside the allowlist: {builders:?}"
    );
    assert!(
        readers.is_empty(),
        "DB key reader in row_attest: {readers:?}"
    );
}

// ---------------------------------------------------------------------------
// #10092 (class C): one canonical preimage, the bytes the product acts on
// ---------------------------------------------------------------------------

/// The exact reason a duplicated `scope` key is refused for (#10092).
const DUP_SCOPE_REASON: &str = "duplicate JSON key \"scope\"";

/// One expected canonical cell: tag byte, then the big-endian u32 length
/// and the bytes, all WRITTEN OUT here from the format description, never
/// produced by the encoder under test.
fn framed(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&u32::try_from(bytes.len()).expect("short").to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// #10092: the canonical encoding of each logical type, as bytes. A
/// timestamp keeps its exact stored spelling (`SQLite` compares `expires_at`
/// as text, so two spellings of one instant are two different values to the
/// product); JSON keys are sorted and whitespace dropped; a duplicated JSON
/// key has no canonical form and is refused with its exact reason.
#[test]
fn canonical_cell_bytes_are_written_out_10092() {
    let ok: [(Ty, Cell, Vec<u8>); 12] = [
        (Ty::Text, Cell::Null, vec![0x00]),
        (Ty::Text, t("hi"), vec![0x03, 0, 0, 0, 2, b'h', b'i']),
        (Ty::Int, Cell::Int(5), vec![0x01, 0, 0, 0, 0, 0, 0, 0, 5]),
        (
            Ty::Real,
            Cell::Int(1),
            vec![0x02, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
        ),
        (
            Ty::Ts,
            t("2026-11-23T10:00:00+02:00"),
            framed(0x05, b"2026-11-23T10:00:00+02:00"),
        ),
        (
            Ty::Ts,
            t("2026-11-23T08:00:00Z"),
            framed(0x05, b"2026-11-23T08:00:00Z"),
        ),
        (
            Ty::Ts,
            t("2026-11-23 08:00:00"),
            framed(0x05, b"2026-11-23 08:00:00"),
        ),
        (Ty::Ts, t("soon"), framed(0x09, b"t:soon")),
        (
            Ty::Json,
            t(r#"{ "scope" : "team", "b" : [1, 2.5, null] }"#),
            framed(0x06, br#"{"b":[1,2.5,null],"scope":"team"}"#),
        ),
        (Ty::Json, t("{not json"), framed(0x09, b"t:{not json")),
        (
            Ty::Tags,
            t(r#"[ "b", "a" ]"#),
            framed(0x07, br#"["a","b"]"#),
        ),
        (Ty::Tags, t(r#"{"a":1}"#), framed(0x09, br#"t:{"a":1}"#)),
    ];
    for (ty, cell, want) in ok {
        let mut got = Vec::new();
        let r = encode_cell(ty, &cell, &mut got);
        assert_eq!(r, Ok(()), "{ty:?} {cell:?}");
        assert_eq!(hex::encode(&got), hex::encode(&want), "{ty:?} {cell:?}");
    }
    let refused: [(Ty, Cell, &str); 4] = [
        (
            Ty::Json,
            t(r#"{"scope":"org","scope":"team"}"#),
            DUP_SCOPE_REASON,
        ),
        (
            Ty::Json,
            t(r#"{"a":{"scope":1,"b":2,"scope":3}}"#),
            DUP_SCOPE_REASON,
        ),
        (
            Ty::Json,
            t(r#"[{"k":1},{"k":2,"k":2}]"#),
            "duplicate JSON key \"k\"",
        ),
        (
            Ty::Tags,
            t(r#"[{"k":1,"k":2}]"#),
            "duplicate JSON key \"k\"",
        ),
    ];
    for (ty, cell, want) in refused {
        let mut got = Vec::new();
        assert_eq!(
            encode_cell(ty, &cell, &mut got),
            Err(want.to_string()),
            "{ty:?} {cell:?}"
        );
    }
}

/// #10092: a row whose metadata repeats `scope` has no canonical form: the
/// canonicalising parser refuses it naming the table, column and reason, so
/// no digest (and no signature) can ever be computed over it.
#[test]
fn duplicate_key_row_has_no_canonical_row_10092() {
    let s = spec("memories");
    let mut row: Vec<Cell> = vec![Cell::Null; s.cols.len()];
    row[0] = t("m1");
    let at = s.index_of("metadata").expect("metadata covered");
    row[at] = t(r#"{"scope":"org","agent_id":"ai:a","scope":"team"}"#);
    let err = CanonicalRow::parse(s, &row).expect_err("a duplicated key is refused");
    assert_eq!(
        err,
        NonCanonical {
            table: "memories",
            column: "metadata",
            reason: DUP_SCOPE_REASON.to_string(),
        }
    );
    assert_eq!(
        err.to_string(),
        "memories.metadata is not canonical: duplicate JSON key \"scope\""
    );
    row[at] = t(r#"{"agent_id":"ai:a","scope":"team"}"#);
    let ok = CanonicalRow::parse(s, &row).expect("canonical");
    assert_eq!(ok.key(), encode_key(s, &row).as_slice());
}

/// L-3 (PR 10083): the `EXPLAIN QUERY PLAN` detail rows of `sql` on `conn`.
fn query_plan(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .expect("prepare plan");
    let mut rows = stmt.raw_query();
    let mut out = Vec::new();
    while let Some(r) = rows.next().expect("plan row") {
        out.push(r.get::<_, String>(3).expect("plan detail"));
    }
    out
}

/// L-3 (PR 10083): every statement that filters `row_attestations` on `op`
/// is an index search on the v103 schema, never a scan of the side table
/// (the Supersede prunes run on every attested write, the cutover probes on
/// every arm). The expected plans are written out, not derived.
#[test]
fn query_plans_of_op_filters_are_index_searches_l3() {
    use super::sqlite::{
        MIGRATION_V103_SQLITE, PRUNE_SUPERSEDED_SQL, PRUNE_TOMBSTONES_SQL, SIGNED_CUTOVER_SQL,
        TABLE_UNSIGNED_CUTOVER_SQL, UNSIGNED_CUTOVER_SQL,
    };
    const AUTO: &str = "sqlite_autoindex_row_attestations_1";
    const OP_TABLE: &str = "idx_row_attestations_op_table";
    let dir = anchor_dir();
    let conn = crate::storage::open_unmigrated(&dir.path().join("plan_l3.db")).expect("open");
    conn.execute_batch(MIGRATION_V103_SQLITE).expect("v103 ddl");
    let cases: [(&str, &str, Vec<String>); 5] = [
        (
            "prune superseded",
            PRUNE_SUPERSEDED_SQL,
            vec![format!(
                "SEARCH row_attestations USING INDEX {AUTO} (table_name=? AND row_key=? AND seq<?)"
            )],
        ),
        (
            "prune tombstones",
            PRUNE_TOMBSTONES_SQL,
            vec![format!(
                "SEARCH row_attestations USING INDEX {OP_TABLE} (op=? AND table_name=?)"
            )],
        ),
        (
            "signed cutover",
            SIGNED_CUTOVER_SQL,
            vec![format!(
                "SEARCH row_attestations USING INDEX {OP_TABLE} (op=?)"
            )],
        ),
        (
            "unsigned cutover",
            UNSIGNED_CUTOVER_SQL,
            vec![
                format!("SEARCH row_attestations USING INDEX {OP_TABLE} (op=?)"),
                "USE TEMP B-TREE FOR ORDER BY".to_string(),
            ],
        ),
        (
            "table unsigned cutover",
            TABLE_UNSIGNED_CUTOVER_SQL,
            vec![format!(
                "SEARCH row_attestations USING INDEX {OP_TABLE} (op=? AND table_name=?)"
            )],
        ),
    ];
    let mut wrong = Vec::new();
    for (name, sql, want) in cases {
        let got = query_plan(&conn, sql);
        if got.iter().any(|d| d.starts_with("SCAN row_attestations")) || got != want {
            wrong.push(format!("{name}: got {got:?}, want {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "plans: {wrong:#?}");
}

// ---------------------------------------------------------------------------
// #10116: the verifier handles each attestation, live row and signature
// once (I2), its row-local filter is a set lookup, and its verdicts equal
// the base verdicts (I3).
// ---------------------------------------------------------------------------

use super::stream::{self as probe, Count};

/// Memories written for the counted-operation test (#10116).
const COUNTED_MEMORIES_10116: usize = 64;
/// Memories in the all-drifted store (#10116): 100K+.
const DRIFTED_MEMORIES_10116: usize = 100_000;
/// Defect-index comparisons allowed per defect by a set-lookup filter
/// (#10116); a `Vec::contains` filter needs about one per earlier defect.
const DEFECT_EQ_PER_DEFECT_CEILING: u64 = 4;

fn count_of(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// I2: a clean store of N memories costs exactly A attestation visits,
/// N live-row visits and A - 1 signature checks (the store-identity row
/// carries no checked signature), never tables x A.
#[test]
fn verify_visits_each_attestation_row_and_signature_once_10116() {
    let mut f = Fixture::new();
    for n in 0..COUNTED_MEMORIES_10116 {
        f.put_memory(&format!("m{n}"), "counted");
    }
    probe::reset();
    let r = f.report();
    assert!(r.ok(), "{:?}", r.defects);
    let atts = count_of(f.atts.len());
    assert_eq!(probe::get(Count::AttVisit), atts, "attestation visits");
    assert_eq!(
        probe::get(Count::RowVisit),
        count_of(COUNTED_MEMORIES_10116),
        "live-row visits"
    );
    assert_eq!(probe::get(Count::Sig), atts - 1, "signature checks");
    assert_eq!(probe::get(Count::DefectEq), 0, "no defect, no comparison");
    assert_eq!(probe::get(Count::ChainRead), 0, "chains stored in order");
}

/// The all-drifted store: `n` memories, each attested once and each live
/// row changed behind the funnel's back. Unanchored (no signature is
/// checked), so the build is linear.
fn drifted_store(n: usize) -> Fixture {
    let mut f = Fixture::new();
    let s = spec("memories");
    let covered = s.covered();
    let key_id = key_id_of(&f.signing.verifying_key());
    let mut acc = f.head_acc("memories");
    f.atts.reserve(n);
    f.live.reserve(n);
    for i in 0..n {
        let cells = [
            t(&format!("d{i}")),
            t("[]"),
            Cell::Int(5),
            t("long"),
            t("x"),
        ];
        let key = encode_key(s, &cells);
        let digest = row_digest(s, &cells);
        acc = acc_add(&acc, &acc_term("memories", &key, &digest));
        let mut a = Attestation {
            id: f.next_id,
            table: "memories".to_string(),
            row_key: key.clone(),
            seq: 1,
            op: Op::Insert.as_str().to_string(),
            row_digest: Some(digest.to_vec()),
            prior_digest: ZERO_DIGEST.to_vec(),
            agent_id: AGENT.to_string(),
            key_id: key_id.clone(),
            attested_at: "2026-11-23T00:00:00.000000Z".to_string(),
            format_version: FORMAT_VERSION,
            covered_columns: covered.clone(),
            store_id: STORE.to_string(),
            table_seq: i64::try_from(i).unwrap_or(i64::MAX) + 1,
            table_acc: acc.to_vec(),
            signature: Some(vec![0_u8; 64]),
            attestation_digest: Vec::new(),
        };
        a.attestation_digest = attestation_digest(&a);
        f.next_id += 1;
        f.atts.push(a);
        f.live.push(LiveRow {
            table: "memories".to_string(),
            key,
            digest: [9_u8; 32],
        });
    }
    f
}

fn unanchored_10116() -> anchor::AnchorLoad {
    anchor::AnchorLoad::Unanchored(anchor::Unanchored::Missing {
        path: "/nonexistent-10116".into(),
    })
}

/// I1/I2: 100K drifted rows are N + 1 row-local defects, found under
/// linear op-count ceilings (one visit per attestation and row, a bounded
/// number of defect-index comparisons per defect).
#[test]
fn all_drifted_100k_store_verifies_under_linear_ceilings_10116() {
    let f = drifted_store(DRIFTED_MEMORIES_10116);
    let n = count_of(DRIFTED_MEMORIES_10116);
    probe::reset();
    probe::set_ceiling(Count::AttVisit, count_of(f.atts.len()));
    probe::set_ceiling(Count::RowVisit, n);
    probe::set_ceiling(Count::Sig, count_of(f.atts.len()));
    probe::set_ceiling(Count::DefectEq, DEFECT_EQ_PER_DEFECT_CEILING * (n + 1));
    let r = f.report_with(&unanchored_10116());
    probe::reset();
    assert_eq!(
        r.defects.len(),
        DRIFTED_MEMORIES_10116 + 1,
        "{:?}",
        r.defects.first()
    );
    assert!(r.store_defects.is_empty(), "{:?}", r.store_defects.first());
    assert_eq!(r.unverified_memories.len(), DRIFTED_MEMORIES_10116);
    assert_eq!(r.tables["memories"].attestations, n + 1);
    assert_eq!(r.tables["memories"].verified, 0);
    let head = format!("memories: live rows do not match the signed table head (table_seq {n})");
    assert_eq!(r.defects.last(), Some(&head));
    assert_eq!(
        r.defects.first().map(String::as_str),
        Some("memories: live row differs from its latest attestation 16")
    );
}

/// One oracle row: the defects, the store-wide defects, the unverified
/// memories and `verified/attestations` per table in [`TABLES`] order.
type OracleRow = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    &'static str,
);

fn oracle_tables(r: &Report) -> String {
    TABLES
        .iter()
        .map(|s| {
            r.tables.get(s.table).map_or_else(
                || "-".to_string(),
                |v| format!("{}/{}", v.verified, v.attestations),
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn oracle_report(
    f: &Fixture,
    anchor: &anchor::AnchorLoad,
    high: Option<i64>,
    non_canonical: &[NonCanonical],
    seal: &super::seal::SealState,
) -> Report {
    let input = VerifyInput {
        live: &f.live,
        attestations: &f.atts,
        anchor,
        id_high_water: high,
        memory_id_of_key: &memory_id_of_key,
        non_canonical,
        seal,
    };
    let report = verify(&input);
    // I3 (#10116): the slice adapter and the per-query streaming source
    // give the same report and the same seal marks on every scenario.
    let ctx = probe::Ctx {
        anchor,
        memory_id_of_key: &memory_id_of_key,
        seal,
    };
    let Ok(slice) = probe::run(&mut probe::SliceSource::new(&input), &ctx);
    assert_eq!(report, slice.0, "verify() is the slice adapter");
    let streamed = probe::run(&mut FilterSource::new(&input), &ctx);
    assert_eq!(
        streamed,
        Ok(slice),
        "streaming source differs from the slice adapter"
    );
    report
}

fn fixture_anchor(f: &Fixture) -> anchor::AnchorLoad {
    anchored(&[(AGENT, f.signing.verifying_key(), None, None)])
}

fn fixture_report(f: &Fixture) -> Report {
    let high = f.atts.iter().map(|a| a.id).max();
    oracle_report(
        f,
        &fixture_anchor(f),
        high,
        &[],
        &super::seal::SealState::NotSealed,
    )
}

fn two_memories() -> Fixture {
    let mut f = Fixture::new();
    f.put_memory("m1", "one");
    f.put_memory("m2", "two");
    f.put_memory("m1", "one-b");
    f
}

fn drift_m1(f: &mut Fixture) {
    let s = spec("memories");
    let key = encode_key(s, &[t("m1")]);
    if let Some(r) = f.live.iter_mut().find(|r| r.key == key) {
        r.digest = row_digest(
            s,
            &[t("m1"), t(r#"["evil"]"#), Cell::Int(5), t("long"), t("one")],
        );
    }
}

fn resign_last(f: &mut Fixture, mutate: fn(&mut Attestation)) {
    let i = f.atts.len() - 1;
    mutate(&mut f.atts[i]);
    let signing = f.signing.clone();
    sign(&mut f.atts[i], &signing);
}

/// The scenario reports of the oracle table, in its order.
#[allow(clippy::too_many_lines)]
fn oracle_scenarios() -> Vec<(&'static str, Report)> {
    use super::seal::{SealRecord, SealState};
    let mut out = Vec::new();
    let f = two_memories();
    out.push(("clean", fixture_report(&f)));
    out.push((
        "unanchored",
        oracle_report(
            &f,
            &unanchored_10116(),
            f.atts.iter().map(|a| a.id).max(),
            &[],
            &SealState::NotSealed,
        ),
    ));
    let mut g = two_memories();
    if let Some(i) = g
        .atts
        .iter()
        .position(|a| a.table == "memories" && a.op == "insert")
    {
        g.atts.remove(i);
    }
    out.push(("attestation deleted", fixture_report(&g)));
    let mut g = two_memories();
    drift_m1(&mut g);
    out.push(("row drift", fixture_report(&g)));
    let mut g = two_memories();
    let s = spec("memories");
    let key = encode_key(s, &[t("m1")]);
    if let Some(r) = g.live.iter_mut().find(|r| r.key == key) {
        r.digest = row_digest(s, &[t("m1"), t("[]"), Cell::Int(5), t("long"), t("one")]);
    }
    out.push(("replay of older content", fixture_report(&g)));
    let mut g = two_memories();
    let high = g.atts.iter().map(|a| a.id).max();
    g.atts.pop();
    out.push((
        "tail truncated",
        oracle_report(&g, &fixture_anchor(&g), high, &[], &SealState::NotSealed),
    ));
    let mut g = two_memories();
    let i = g.atts.len() - 1;
    g.atts[i].signature = None;
    out.push(("unsigned", fixture_report(&g)));
    let mut g = two_memories();
    resign_last(&mut g, |a| a.store_id = "store-b".to_string());
    out.push(("names another store", fixture_report(&g)));
    let mut g = two_memories();
    resign_last(&mut g, |a| a.covered_columns.push('x'));
    out.push(("covered columns differ", fixture_report(&g)));
    let mut g = two_memories();
    resign_last(&mut g, |a| a.op = "bogus".to_string());
    out.push(("unknown op", fixture_report(&g)));
    let mut g = two_memories();
    resign_last(&mut g, |a| a.prior_digest[0] ^= 1);
    out.push(("row chain breaks", fixture_report(&g)));
    let mut g = two_memories();
    g.atts.retain(|a| a.table != STORE_ROW_TABLE);
    out.push(("no store identity", fixture_report(&g)));
    let mut g = two_memories();
    let store = g.atts[0].clone();
    g.atts.push(store);
    out.push(("two store identities", fixture_report(&g)));
    let mut g = two_memories();
    g.atts
        .retain(|a| !(a.table == "leases" && a.op == "cutover"));
    out.push(("no leases cutover", fixture_report(&g)));
    let mut g = two_memories();
    g.live
        .retain(|r| memory_id_of_key(&r.key).as_deref() != Some("m2"));
    let k = encode_key(spec("memories"), &[t("m2")]);
    g.atts
        .retain(|a| !(a.table == "memories" && a.row_key == k));
    out.push(("row and attestations deleted", fixture_report(&g)));
    let mut g = two_memories();
    g.live
        .retain(|r| memory_id_of_key(&r.key).as_deref() != Some("m2"));
    out.push(("attested row gone", fixture_report(&g)));
    let mut g = two_memories();
    let cells = [t("m9"), t("[]"), Cell::Int(5), t("long"), t("raw")];
    g.live.push(LiveRow {
        table: "memories".to_string(),
        key: encode_key(s, &cells),
        digest: row_digest(s, &cells),
    });
    out.push(("unattested row inserted", fixture_report(&g)));
    let mut g = two_memories();
    drift_m1(&mut g);
    let cells = [t("m9"), t("[]"), Cell::Int(5), t("long"), t("raw")];
    g.live.push(LiveRow {
        table: "memories".to_string(),
        key: encode_key(s, &cells),
        digest: row_digest(s, &cells),
    });
    out.push(("drift beside an unattested row", fixture_report(&g)));
    let mut g = two_memories();
    let key_m2 = encode_key(s, &[t("m2")]);
    let m2 = g
        .live
        .iter()
        .find(|r| r.key == key_m2)
        .map_or(ZERO_DIGEST, |r| r.digest);
    let bogus = acc_add(
        &g.head_acc("memories"),
        &acc_term("memories", b"ghost-10116", &[7_u8; 32]),
    );
    let seq = g.next_seq("memories", &key_m2);
    let table_seq = g.head_seq("memories") + 1;
    let head = g.att(
        "memories",
        key_m2,
        seq,
        Op::Update,
        Some(m2),
        table_seq,
        bogus,
    );
    g.atts.push(head);
    drift_m1(&mut g);
    out.push(("unexplained head mismatch", fixture_report(&g)));
    let g = two_memories();
    let nc = [NonCanonical {
        table: "memories",
        column: "content",
        reason: "not utf-8".to_string(),
    }];
    out.push((
        "non-canonical",
        oracle_report(
            &g,
            &fixture_anchor(&g),
            g.atts.iter().map(|a| a.id).max(),
            &nc,
            &SealState::NotSealed,
        ),
    ));
    let current = SealRecord::of(&g.atts);
    let high = g.atts.iter().map(|a| a.id).max();
    let anchor = fixture_anchor(&g);
    let mut ahead = current.clone();
    ahead.high_water += 1;
    out.push((
        "seal rolled back",
        oracle_report(&g, &anchor, high, &[], &SealState::Sealed(ahead)),
    ));
    let mut head = current.clone();
    if let Some(h) = head.heads.get_mut("memories") {
        *h += 1;
    }
    out.push((
        "seal head rolled back",
        oracle_report(&g, &anchor, high, &[], &SealState::Sealed(head)),
    ));
    out.push((
        "seal unreadable",
        oracle_report(
            &g,
            &anchor,
            high,
            &[],
            &SealState::Unreadable {
                path: std::path::PathBuf::from("seal-10116"),
                why: "bad".to_string(),
            },
        ),
    ));
    out.push((
        "seal current",
        oracle_report(&g, &anchor, high, &[], &SealState::Sealed(current)),
    ));
    out
}

/// I3: the verdicts captured at base 9b5953c1 (written out, never derived
/// from the code under test). Every field of every report must match.
const ORACLE_10116: &[OracleRow] = &[
    (
        "clean",
        &[],
        &[],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "unanchored",
        &[],
        &[],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "attestation deleted",
        &[
            "memories: table sequence breaks between attestations 2 and 17",
            "memories: row chain breaks at attestation 18",
        ],
        &[
            "memories: table sequence breaks between attestations 2 and 17",
            "memories: row chain breaks at attestation 18",
        ],
        &[],
        "2/3 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "row drift",
        &[
            "memories: live row differs from its latest attestation 18",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        &["m1"],
        "1/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "replay of older content",
        &[
            "memories: live row differs from its latest attestation 18",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        &["m1"],
        "1/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "tail truncated",
        &[
            "row_attestations tail truncated: newest id Some(17), high-water Some(18)",
            "memories: live row differs from its latest attestation 16",
            "memories: live rows do not match the signed table head (table_seq 2)",
        ],
        &["row_attestations tail truncated: newest id Some(17), high-water Some(18)"],
        &["m1"],
        "1/3 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "unsigned",
        &["memories: attestation 18 (memories) is unsigned"],
        &["memories: attestation 18 (memories) is unsigned"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "names another store",
        &["memories: attestation 18 names another store"],
        &["memories: attestation 18 names another store"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "covered columns differ",
        &["memories: attestation 18 format or covered columns differ"],
        &["memories: attestation 18 format or covered columns differ"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "unknown op",
        &["memories: attestation 18 has unknown op bogus"],
        &["memories: attestation 18 has unknown op bogus"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "row chain breaks",
        &["memories: row chain breaks at attestation 18"],
        &["memories: row chain breaks at attestation 18"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "no store identity",
        &["row_attestations has no store-identity row"],
        &["row_attestations has no store-identity row"],
        &[],
        "- - - - - - - - - - - - - -",
    ),
    (
        "two store identities",
        &["row_attestations has more than one store-identity row"],
        &["row_attestations has more than one store-identity row"],
        &[],
        "- - - - - - - - - - - - - -",
    ),
    (
        "no leases cutover",
        &["leases: no cutover watermark"],
        &["leases: no cutover watermark"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/0 0/1",
    ),
    (
        "row and attestations deleted",
        &[
            "memories: table sequence breaks between attestations 16 and 18",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[
            "memories: table sequence breaks between attestations 16 and 18",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        "1/3 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "attested row gone",
        &[
            "memories: attested row is gone without a delete attestation",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[
            "memories: attested row is gone without a delete attestation",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        "1/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "unattested row inserted",
        &[
            "memories: live row has no attestation",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        &["m9"],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "drift beside an unattested row",
        &[
            "memories: live row differs from its latest attestation 18",
            "memories: live row has no attestation",
            "memories: live rows do not match the signed table head (table_seq 3)",
        ],
        &[],
        &["m1", "m9"],
        "1/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "unexplained head mismatch",
        &[
            "memories: live row differs from its latest attestation 18",
            "memories: live rows do not match the signed table head (table_seq 4)",
        ],
        &["memories: live rows do not match the signed table head (table_seq 4)"],
        &["m1"],
        "1/5 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "non-canonical",
        &["memories.content is not canonical: not utf-8"],
        &["memories.content is not canonical: not utf-8"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "seal rolled back",
        &["row_attestations rolled back below the anchored seal: newest id Some(18), sealed 19"],
        &["row_attestations rolled back below the anchored seal: newest id Some(18), sealed 19"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "seal head rolled back",
        &["memories: table sequence rolled back below the anchored seal: head 3, sealed 4"],
        &["memories: table sequence rolled back below the anchored seal: head 3, sealed 4"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "seal unreadable",
        &["the anchored seal seal-10116 cannot be read: bad"],
        &["the anchored seal seal-10116 cannot be read: bad"],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
    (
        "seal current",
        &[],
        &[],
        &[],
        "2/4 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1 0/1",
    ),
];

fn oracle_render(name: &str, r: &Report) -> String {
    format!(
        "    ({name:?}, &{:?}, &{:?}, &{:?}, {:?}),",
        r.defects,
        r.store_defects,
        r.unverified_memories.iter().collect::<Vec<_>>(),
        oracle_tables(r)
    )
}

#[test]
fn verify_matches_the_base_verdicts_10116() {
    let got = oracle_scenarios();
    let rendered: Vec<String> = got.iter().map(|(n, r)| oracle_render(n, r)).collect();
    let mut wrong = Vec::new();
    for (i, (name, r)) in got.iter().enumerate() {
        let Some(&(want_name, defects, store, unverified, tables)) = ORACLE_10116.get(i) else {
            wrong.push(format!("{name}: no oracle row"));
            continue;
        };
        let ok = want_name == *name
            && r.defects == defects
            && r.store_defects == store
            && r.unverified_memories
                .iter()
                .map(String::as_str)
                .eq(unverified.iter().copied())
            && oracle_tables(r) == tables
            && r.anchor
                == AnchorStatus::of(&if *name == "unanchored" {
                    unanchored_10116()
                } else {
                    anchored(&[(AGENT, keypair().verifying_key(), None, None)])
                });
        if !ok {
            wrong.push(format!("{name}: {}", rendered[i]));
        }
    }
    assert_eq!(
        got.len(),
        ORACLE_10116.len(),
        "oracle rows:\n{}",
        rendered.join("\n")
    );
    assert!(wrong.is_empty(), "verdicts differ from base: {wrong:#?}");
}

/// Files allowed to hold a verify-path collect form, with their counts of
/// `(read_attestations, read_rows, [Attestation|LiveRow] containers,
/// collect inside row_attest/)` (#10116). Every other tracked `.rs` file
/// must hold none of them; left out: `target`, `.git`, `.local-runs`,
/// `.codegraph`, `node_modules` (build and scratch output, never source).
const VERIFY_COLLECT_SITES_10116: &[(&str, [usize; 4])] = &[
    // Two `collect`s that build the anchor key list (no row read).
    ("src/storage/row_attest/anchor.rs", [0, 0, 0, 2]),
    // The `VerifyInput` slices, imports and tag or key `collect`s (no row read).
    ("src/storage/row_attest/mod.rs", [0, 0, 4, 4]),
    // `SealRecord::of` takes a slice; one `collect` parses a seal line.
    ("src/storage/row_attest/seal.rs", [0, 0, 2, 1]),
    // The two readers and their callers outside the verifier (live_acc, arm, check_snapshot).
    ("src/storage/row_attest/sqlite.rs", [3, 3, 4, 6]),
    // The slice adapter buckets an in-memory store (never the SQLite path).
    ("src/storage/row_attest/stream.rs", [0, 0, 3, 6]),
    // This file names the two readers in the ratchet itself.
    ("src/storage/row_attest/tests.rs", [1, 1, 2, 0]),
    ("tests/agent_key_stale_refresh_4066.rs", [0, 6, 0, 0]),
    ("tests/row_attestations_10040.rs", [7, 2, 5, 0]),
];

/// Directories never scanned by the #10116 ratchet (not source).
const RATCHET_SKIP_10116: &[&str] = &[
    "target",
    ".git",
    ".local-runs",
    ".codegraph",
    "node_modules",
];
const RATCHET_DIR_10116: &str = "src/storage/row_attest/";
const RATCHET_TESTS_10116: &str = "src/storage/row_attest/tests.rs";

fn ratchet_word(text: &str, w: &str, after: Option<&str>) -> usize {
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut n = 0;
    let mut from = 0;
    while let Some(j) = text[from..].find(w).map(|j| j + from) {
        from = j + w.len();
        let pre = text[..j].chars().next_back().unwrap_or(' ');
        let next = text[from..].chars().next().unwrap_or(' ');
        if is_word(pre) || is_word(next) {
            continue;
        }
        if after.is_some_and(|a| !a.contains(next)) {
            continue;
        }
        n += 1;
    }
    n
}

fn ratchet_sites(rel: &str, text: &str) -> [usize; 4] {
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let compact: String = code.split_whitespace().collect();
    let containers = ["Attestation", "LiveRow"]
        .iter()
        .map(|w| ratchet_word(&compact, w, Some(">,];")))
        .sum();
    let collect = if rel.starts_with(RATCHET_DIR_10116) && rel != RATCHET_TESTS_10116 {
        ratchet_word(&code, "collect", None)
    } else {
        0
    };
    [
        ratchet_word(&code, "read_attestations", None),
        ratchet_word(&code, "read_rows", None),
        containers,
        collect,
    ]
}

/// I1 ratchet: an allowlist of every file that reads all attestations or
/// all rows into memory, over the whole source tree. A new call, an alias,
/// a `collect::<Vec<_>>()` on the verify path or a file outside
/// `row_attest/` turns it red.
#[test]
fn verify_path_collect_sites_are_allowlisted_10116() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![root.to_path_buf()];
    let mut found = Vec::new();
    let mut scanned = 0_usize;
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("read source dir")
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for p in entries {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let meta = std::fs::symlink_metadata(&p).expect("stat source path");
            if meta.is_dir() {
                if !RATCHET_SKIP_10116.contains(&name) {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|e| e == "rs") {
                scanned += 1;
                let rel = p
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = std::fs::read_to_string(&p).expect("read source");
                let sites = ratchet_sites(&rel, &text);
                if sites != [0; 4] {
                    found.push((rel, sites));
                }
            }
        }
    }
    found.sort();
    assert!(scanned > 1000, "the scan reached {scanned} files");
    let want: Vec<(String, [usize; 4])> = VERIFY_COLLECT_SITES_10116
        .iter()
        .map(|(f, s)| ((*f).to_string(), *s))
        .collect();
    assert_eq!(found, want, "verify-path collect sites changed");
}

// ---- #10116 streaming sources ---------------------------------------------

/// The read-cut error of [`CutSource`].
const READ_CUT_10116: &str = "read cut after";
/// The high-water read error of [`CutSource`].
const HIGH_WATER_FAILED_10116: &str = "high-water read failed";
/// The count read error of [`CutSource`].
const COUNT_FAILED_10116: &str = "count read failed";
/// Clean memories streamed by the one-shot source (#10116): 100K+.
const ONE_SHOT_MEMORIES_10116: usize = 100_000;
/// Memories of the timed verify (#10116).
const TIMED_MEMORIES_10116: usize = 10_000;
/// Wall-clock ceiling of the timed all-drifted verify of
/// [`TIMED_MEMORIES_10116`] memories in a debug build (#10116).
const TIMED_VERIFY_CEILING_10116: std::time::Duration = std::time::Duration::from_secs(20);

/// A [`probe::Source`] over a held store that answers each call the way
/// the `SQLite` source queries it: it filters and orders the whole input
/// per call (by id, by table sequence then id, by row sequence then table
/// sequence then id) and refuses a run that did not see every attestation.
/// It shares no bucketing with [`probe::SliceSource`] (#10116, I3).
struct FilterSource<'a> {
    input: &'a VerifyInput<'a>,
    /// A table whose attestations are never streamed (a dropped-table read).
    skip: Option<&'static str>,
}

impl<'a> FilterSource<'a> {
    fn new(input: &'a VerifyInput<'a>) -> Self {
        Self { input, skip: None }
    }

    fn ordered<K: Ord>(
        &self,
        keep: impl Fn(&Attestation) -> bool,
        key: impl Fn(&Attestation) -> K,
        f: &mut dyn FnMut(&Attestation),
    ) {
        let mut v: Vec<_> = self.input.attestations.iter().filter(|a| keep(a)).collect();
        v.sort_by_key(|a| key(a));
        for a in v {
            f(a);
        }
    }
}

impl probe::Source for FilterSource<'_> {
    type Error = String;

    fn other_atts(&mut self, f: &mut dyn FnMut(&Attestation)) -> Result<(), String> {
        self.ordered(|a| !TABLES.iter().any(|s| s.table == a.table), |a| a.id, f);
        Ok(())
    }

    fn table_atts(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), String> {
        if self.skip != Some(spec.table) {
            self.ordered(|a| a.table == spec.table, |a| (a.table_seq, a.id), f);
        }
        Ok(())
    }

    fn key_chain(
        &mut self,
        spec: &'static TableSpec,
        key: &[u8],
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), String> {
        self.ordered(
            |a| a.table == spec.table && a.row_key == key && a.op != Op::Cutover.as_str(),
            |a| (a.seq, a.table_seq, a.id),
            f,
        );
        Ok(())
    }

    fn live_rows(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&LiveRow),
    ) -> Result<(), String> {
        for r in self.input.live.iter().filter(|r| r.table == spec.table) {
            f(r);
        }
        Ok(())
    }

    fn non_canonical(&mut self, f: &mut dyn FnMut(String)) {
        for nc in self.input.non_canonical {
            f(nc.to_string());
        }
    }

    fn id_high_water(&mut self) -> Result<Option<i64>, String> {
        Ok(self.input.id_high_water)
    }

    fn finish(&mut self, atts_seen: u64) -> Result<(), String> {
        let total = self.input.attestations.len();
        if count_of(total) == atts_seen {
            Ok(())
        } else {
            Err(format!(
                "row attestation read covered {atts_seen} of {total} rows"
            ))
        }
    }
}

/// Pass one streamed item on unless the read is cut: after `left` items the
/// next one cuts it and nothing more is passed.
fn cut_step(left: &mut Option<usize>, cut: &mut bool, pass: impl FnOnce()) {
    if *cut {
        return;
    }
    match left {
        Some(0) => *cut = true,
        Some(n) => {
            *n -= 1;
            pass();
        }
        None => pass(),
    }
}

/// How a [`CutSource`] read fails (#10116, I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CutAt {
    /// After this many streamed attestations and live rows.
    Items(usize),
    /// At the id high-water read.
    HighWater,
    /// At the closing count.
    Finish,
}

/// A [`probe::SliceSource`] whose read fails mid-stream (I4: a cut read is
/// an error, never a clean verdict). With `once` the failure is transient:
/// the failing call drops the rest of its items and later calls read
/// normally, so an error the verifier swallows is not masked by a later one.
struct CutSource<'a> {
    inner: probe::SliceSource<'a>,
    at: CutAt,
    left: Option<usize>,
    cut: bool,
    once: bool,
}

impl<'a> CutSource<'a> {
    fn new(input: &'a VerifyInput<'a>, at: CutAt) -> Self {
        let left = match at {
            CutAt::Items(k) => Some(k),
            CutAt::HighWater | CutAt::Finish => None,
        };
        Self {
            inner: probe::SliceSource::new(input),
            at,
            left,
            cut: false,
            once: false,
        }
    }

    fn checked(&mut self) -> Result<(), String> {
        match (self.cut, self.at) {
            (true, CutAt::Items(k)) => {
                if self.once {
                    self.cut = false;
                    self.left = None;
                }
                Err(format!("{READ_CUT_10116} {k} items"))
            }
            _ => Ok(()),
        }
    }
}

impl probe::Source for CutSource<'_> {
    type Error = String;

    fn other_atts(&mut self, f: &mut dyn FnMut(&Attestation)) -> Result<(), String> {
        let (left, cut) = (&mut self.left, &mut self.cut);
        let Ok(()) = self.inner.other_atts(&mut |a| cut_step(left, cut, || f(a)));
        self.checked()
    }

    fn table_atts(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), String> {
        let (left, cut) = (&mut self.left, &mut self.cut);
        let Ok(()) = self
            .inner
            .table_atts(spec, &mut |a| cut_step(left, cut, || f(a)));
        self.checked()
    }

    fn key_chain(
        &mut self,
        spec: &'static TableSpec,
        key: &[u8],
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), String> {
        let (left, cut) = (&mut self.left, &mut self.cut);
        let Ok(()) = self
            .inner
            .key_chain(spec, key, &mut |a| cut_step(left, cut, || f(a)));
        self.checked()
    }

    fn live_rows(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&LiveRow),
    ) -> Result<(), String> {
        let (left, cut) = (&mut self.left, &mut self.cut);
        let Ok(()) = self
            .inner
            .live_rows(spec, &mut |r| cut_step(left, cut, || f(r)));
        self.checked()
    }

    fn non_canonical(&mut self, f: &mut dyn FnMut(String)) {
        self.inner.non_canonical(f);
    }

    fn id_high_water(&mut self) -> Result<Option<i64>, String> {
        if self.at == CutAt::HighWater {
            return Err(HIGH_WATER_FAILED_10116.to_string());
        }
        let Ok(high) = self.inner.id_high_water();
        Ok(high)
    }

    fn finish(&mut self, atts_seen: u64) -> Result<(), String> {
        if self.at == CutAt::Finish {
            return Err(COUNT_FAILED_10116.to_string());
        }
        let Ok(()) = self.inner.finish(atts_seen);
        Ok(())
    }
}

fn fixture_input<'a>(f: &'a Fixture, anchor: &'a anchor::AnchorLoad) -> VerifyInput<'a> {
    VerifyInput {
        live: &f.live,
        attestations: &f.atts,
        anchor,
        id_high_water: f.atts.iter().map(|a| a.id).max(),
        memory_id_of_key: &memory_id_of_key,
        non_canonical: &[],
        seal: &super::seal::SealState::NotSealed,
    }
}

/// I4: a read that fails after k streamed items (lasting or transient), at
/// the high-water read or at the closing count ends the run with that exact
/// error, for every cut
/// point of a store (never a clean or partial verdict); a read that is
/// never cut gives the clean verdict.
#[test]
fn verify_fails_closed_on_a_cut_read_10116() {
    let f = two_memories();
    let anchor = fixture_anchor(&f);
    let input = fixture_input(&f, &anchor);
    let ctx = probe::Ctx {
        anchor: &anchor,
        memory_id_of_key: &memory_id_of_key,
        seal: &super::seal::SealState::NotSealed,
    };
    let items = f.atts.len() + f.live.len();
    for once in [false, true] {
        for k in 0..items {
            let mut src = CutSource::new(&input, CutAt::Items(k));
            src.once = once;
            let got = probe::run(&mut src, &ctx);
            assert_eq!(
                got.map(|(r, _)| r),
                Err(format!("read cut after {k} items")),
                "cut after {k} of {items} (transient: {once})"
            );
        }
    }
    for (at, want) in [
        (CutAt::HighWater, "high-water read failed"),
        (CutAt::Finish, "count read failed"),
    ] {
        let got = probe::run(&mut CutSource::new(&input, at), &ctx);
        assert_eq!(got.map(|(r, _)| r), Err(want.to_string()), "{at:?}");
    }
    let whole = probe::run(&mut CutSource::new(&input, CutAt::Items(items)), &ctx);
    let whole = whole.map(|(r, _)| r);
    assert_eq!(whole.as_ref().map(Report::ok), Ok(true), "{whole:?}");
    assert_eq!(whole, Ok(fixture_report(&f)));
}

/// I4/I2: a source that never streams one table's attestations is refused
/// by the closing count with its exact reason (a dropped table is never a
/// clean verdict).
#[test]
fn verify_refuses_a_read_that_skipped_a_table_10116() {
    let f = two_memories();
    let anchor = fixture_anchor(&f);
    let input = fixture_input(&f, &anchor);
    let ctx = probe::Ctx {
        anchor: &anchor,
        memory_id_of_key: &memory_id_of_key,
        seal: &super::seal::SealState::NotSealed,
    };
    let mut src = FilterSource::new(&input);
    src.skip = Some("memories");
    assert_eq!(
        probe::run(&mut src, &ctx).map(|(r, _)| r),
        Err("row attestation read covered 14 of 18 rows".to_string())
    );
}

/// A store of `n` clean memories generated as it is streamed, over the
/// store row and cutovers of [`Fixture::new`]. It holds no row list and
/// panics on a second read of the memories attestations or rows, or on a
/// chain re-read (I1: the verifier is single pass).
struct OneShotSource {
    base: Fixture,
    n: usize,
    att_reads: usize,
    row_reads: usize,
}

impl OneShotSource {
    fn new(n: usize) -> Self {
        Self {
            base: Fixture::new(),
            n,
            att_reads: 0,
            row_reads: 0,
        }
    }

    fn cells(i: usize) -> [Cell; 5] {
        [
            t(&format!("c{i}")),
            t("[]"),
            Cell::Int(5),
            t("long"),
            t("clean"),
        ]
    }

    fn high_water(&self) -> i64 {
        self.base.next_id - 1 + i64::try_from(self.n).unwrap_or(i64::MAX)
    }
}

impl probe::Source for OneShotSource {
    type Error = std::convert::Infallible;

    fn other_atts(&mut self, f: &mut dyn FnMut(&Attestation)) -> Result<(), Self::Error> {
        for a in self
            .base
            .atts
            .iter()
            .filter(|a| spec_for(&a.table).is_none())
        {
            f(a);
        }
        Ok(())
    }

    fn table_atts(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error> {
        for a in self.base.atts.iter().filter(|a| a.table == spec.table) {
            f(a);
        }
        if spec.table != "memories" {
            return Ok(());
        }
        self.att_reads += 1;
        assert_eq!(self.att_reads, 1, "memories attestations read twice");
        let key_id = key_id_of(&self.base.signing.verifying_key());
        let covered = spec.covered();
        let mut acc = self.base.head_acc("memories");
        for i in 0..self.n {
            let cells = Self::cells(i);
            let key = encode_key(spec, &cells);
            let digest = row_digest(spec, &cells);
            acc = acc_add(&acc, &acc_term("memories", &key, &digest));
            let ix = i64::try_from(i).unwrap_or(i64::MAX);
            let mut a = Attestation {
                id: self.base.next_id + ix,
                table: "memories".to_string(),
                row_key: key,
                seq: 1,
                op: Op::Insert.as_str().to_string(),
                row_digest: Some(digest.to_vec()),
                prior_digest: ZERO_DIGEST.to_vec(),
                agent_id: AGENT.to_string(),
                key_id: key_id.clone(),
                attested_at: "2026-11-23T00:00:00.000000Z".to_string(),
                format_version: FORMAT_VERSION,
                covered_columns: covered.clone(),
                store_id: STORE.to_string(),
                table_seq: ix + 1,
                table_acc: acc.to_vec(),
                signature: Some(vec![0_u8; 64]),
                attestation_digest: Vec::new(),
            };
            a.attestation_digest = attestation_digest(&a);
            f(&a);
        }
        Ok(())
    }

    fn key_chain(
        &mut self,
        spec: &'static TableSpec,
        _key: &[u8],
        _f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error> {
        panic!("{}: chain re-read of an in-order store", spec.table);
    }

    fn live_rows(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&LiveRow),
    ) -> Result<(), Self::Error> {
        if spec.table != "memories" {
            return Ok(());
        }
        self.row_reads += 1;
        assert_eq!(self.row_reads, 1, "memories rows read twice");
        for i in 0..self.n {
            let cells = Self::cells(i);
            f(&LiveRow {
                table: "memories".to_string(),
                key: encode_key(spec, &cells),
                digest: row_digest(spec, &cells),
            });
        }
        Ok(())
    }

    fn non_canonical(&mut self, _f: &mut dyn FnMut(String)) {}

    fn id_high_water(&mut self) -> Result<Option<i64>, Self::Error> {
        Ok(Some(self.high_water()))
    }

    fn finish(&mut self, atts_seen: u64) -> Result<(), Self::Error> {
        assert_eq!(
            atts_seen,
            count_of(self.base.atts.len() + self.n),
            "every attestation streamed once"
        );
        Ok(())
    }
}

/// I1/I2: 100K clean memories streamed from a source that holds no row
/// list and refuses a second pass verify clean, with one visit per
/// attestation and row.
#[test]
fn one_shot_100k_clean_store_verifies_in_one_pass_10116() {
    let mut src = OneShotSource::new(ONE_SHOT_MEMORIES_10116);
    let n = count_of(ONE_SHOT_MEMORIES_10116);
    let atts = count_of(src.base.atts.len()) + n;
    let anchor = unanchored_10116();
    let ctx = probe::Ctx {
        anchor: &anchor,
        memory_id_of_key: &memory_id_of_key,
        seal: &super::seal::SealState::NotSealed,
    };
    probe::reset();
    probe::set_ceiling(Count::AttVisit, atts);
    probe::set_ceiling(Count::RowVisit, n);
    let Ok((r, _)) = probe::run(&mut src, &ctx);
    let visits = (probe::get(Count::AttVisit), probe::get(Count::RowVisit));
    probe::reset();
    assert!(r.defects.is_empty(), "{:?}", r.defects.first());
    assert!(r.store_defects.is_empty(), "{:?}", r.store_defects.first());
    assert!(r.unverified_memories.is_empty());
    assert_eq!(r.tables["memories"].verified, n);
    assert_eq!(r.tables["memories"].attestations, n + 1);
    assert_eq!(visits, (atts, n));
    assert_eq!((src.att_reads, src.row_reads), (1, 1));
}

/// The timed all-drifted verify of [`TIMED_MEMORIES_10116`] memories, under
/// a wall-clock ceiling (the elapsed time is printed for the record).
#[test]
fn timed_10k_drifted_verify_10116() {
    let f = drifted_store(TIMED_MEMORIES_10116);
    let start = std::time::Instant::now();
    let r = f.report_with(&unanchored_10116());
    let took = start.elapsed();
    eprintln!("timed_10k_drifted_verify_10116: {took:?}");
    assert_eq!(r.defects.len(), TIMED_MEMORIES_10116 + 1);
    assert!(took < TIMED_VERIFY_CEILING_10116, "{took:?}");
}
