//! Unit tests for the #10040 row-attestation core (3-agent vote (71472661)
//! V1-10040): golden vectors (C-2), the accumulator, preimage binding (C-1)
//! and the completeness verifier (C-5, E-2, E-3).

use super::*;

/// Golden digests computed by an independent reference encoder written from
/// the format description (`.local-runs` scratch `golden.py`, Python
/// `hashlib`), never from this module.
/// Eight covered columns (NOTICE 4a adds metadata, `expires_at`,
/// confidence; scope rides in `metadata.scope`), computed independently by
/// `.local-runs/lane/golden.py` from the written spec.
const GOLDEN_MEMORIES: &str = "eae7d1588770bfd17819619f1a0e1b8ebab4197fc8651df9c9222c845a4ddb45";
const GOLDEN_RECALL_OBS: &str = "96acbd93e3ed42c41e11f190f069f52df0cdd50be787fe9275f5c591004a8cfc";
const GOLDEN_ACTION_EDGES: &str =
    "e6067df81f1117e9bfa5b0dfd56c19c457513d923f619242119f97b4ec66401b";
const GOLDEN_ACTION_EDGES_KEY: &str = "03000000026131030000000261320300000006626c6f636b73";

fn spec(table: &str) -> &'static TableSpec {
    spec_for(table).unwrap_or_else(|| panic!("no spec for {table}"))
}

fn t(s: &str) -> Cell {
    Cell::Text(s.to_string())
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
        t("2026-11-23 08:00:00"),
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
        t("2026-11-23 08:00:00"),
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
    });
    assert_defect(&r, "row_attestations tail truncated");
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

#[test]
fn verify_legacy_side_rows_report_as_legacy_c6() {
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
    assert!(r.ok(), "{:?}", r.defects);
    assert_eq!(r.tables["leases"].legacy, 1);
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
