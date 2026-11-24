//! `SQLite` half of #10040: the v103 migration, the attestation funnel (TEMP
//! triggers that call one scalar function) and the reader that feeds the
//! backend-neutral verifier in the parent module.
//!
//! The funnel is armed only when the stdio `mcp` session signer (#9926) is
//! installed. With it armed, every insert, covered update, state transition
//! and delete of an attested table writes one signed attestation per
//! affected row key inside the statement that changed the row, or the
//! statement aborts (the scalar function returns an error) and nothing is
//! stored (C-4).

use super::{
    Attestation, Cell, FORMAT_VERSION, LiveRow, Op, Report, Retention, STORE_ROW_TABLE, TABLES,
    TableSpec, VerifyInput, ZERO_DIGEST, acc_add, acc_sub, acc_term, attestation_digest,
    encode_key, key_id_of, row_digest, sign, spec_for,
};
use anyhow::{Context as _, Result};
use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};

/// The v103 DDL (additive: one new table and its index).
pub const MIGRATION_V103_SQLITE: &str =
    include_str!("../../../migrations/sqlite/0087_v103_row_attestations.sql");

/// Name of the scalar function the TEMP triggers call.
pub const ATTEST_FN: &str = "ai_memory_row_attest_10040";

/// Prefix of every refusal the funnel returns (C-4 exact error).
pub const ROW_ATTEST_REFUSAL_PREFIX: &str =
    "ATTESTATION_FAILED: row attestation (#10040) refused this write";

/// Refusal: the database has no `row_attestations` cutover for the table.
pub const REFUSE_NO_CUTOVER: &str = "the table has no cutover watermark";
/// Refusal: the session key no longer matches the agent's bound key.
pub const REFUSE_KEY_MISMATCH: &str = "the session key is not the agent's bound key";
/// Refusal: no session signer is installed.
pub const REFUSE_NO_SIGNER: &str = "no session signer is installed";
/// Refusal: the row changed outside the funnel since its last attestation.
pub const REFUSE_ROW_DRIFT: &str =
    "the row changed outside the funnel since its latest attestation";

/// How [`install`] left the connection.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmState {
    /// Triggers and function installed; cutovers signed.
    Armed,
    /// No session signer: nothing installed (writes are not attested).
    NoSigner,
}

fn refusal(reason: &str) -> String {
    format!("{ROW_ATTEST_REFUSAL_PREFIX}: {reason}")
}

/// Why the attestation funnel refused a write. Its text is exactly the
/// refusal the SQL function reports and the write's caller sees (QUAL-7: a
/// typed error, not a bare string error).
#[derive(Debug)]
struct FunnelRefusal(String);

impl From<String> for FunnelRefusal {
    fn from(reason: String) -> Self {
        Self(reason)
    }
}

impl std::fmt::Display for FunnelRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FunnelRefusal {}

fn cell_of(v: ValueRef<'_>) -> Cell {
    match v {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(i) => Cell::Int(i),
        ValueRef::Real(f) => Cell::Real(f),
        ValueRef::Text(t) => match std::str::from_utf8(t) {
            Ok(s) => Cell::Text(s.to_string()),
            Err(_) => Cell::Blob(t.to_vec()),
        },
        ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
    }
}

fn now_ts() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// Every live row of `spec` as cells in spec order.
///
/// # Errors
///
/// Surfaces the query failure.
pub fn read_rows(conn: &Connection, spec: &TableSpec) -> Result<Vec<Vec<Cell>>> {
    let cols = spec
        .cols
        .iter()
        .map(|(c, _)| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {cols} FROM main.\"{}\"", spec.table);
    let mut stmt = conn
        .prepare(&sql)
        .with_context(|| format!("row attestation read of {}", spec.table))?;
    let n = spec.cols.len();
    let rows = stmt.query_map([], |r| {
        let mut cells = Vec::with_capacity(n);
        for i in 0..n {
            cells.push(cell_of(r.get_ref(i)?));
        }
        Ok(cells)
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .with_context(|| format!("row attestation read of {}", spec.table))
}

fn live_acc(conn: &Connection, spec: &TableSpec) -> Result<[u8; 32]> {
    let mut acc = ZERO_DIGEST;
    for cells in read_rows(conn, spec)? {
        let key = encode_key(spec, &cells);
        acc = acc_add(&acc, &acc_term(spec.table, &key, &row_digest(spec, &cells)));
    }
    Ok(acc)
}

fn insert_row(conn: &Connection, a: &Attestation) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO row_attestations (table_name, row_key, seq, op, row_digest, prior_digest, \
         agent_id, key_id, attested_at, format_version, covered_columns, store_id, table_seq, \
         table_acc, signature, attestation_digest) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
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
    )?;
    Ok(conn.last_insert_rowid())
}

/// v103 (#10040): create `row_attestations`, its store-identity row and one
/// unsigned cutover watermark per attested table over the rows that exist
/// now. Additive: no existing table or row is touched (C-6).
///
/// # Errors
///
/// Surfaces DDL, read and insert failures.
pub(crate) fn migrate_v103(conn: &Connection) -> Result<()> {
    conn.execute_batch(MIGRATION_V103_SQLITE)
        .context("v103 row_attestations DDL")?;
    let existing: Option<String> = conn
        .query_row(
            "SELECT store_id FROM row_attestations WHERE table_name = ?1",
            [STORE_ROW_TABLE],
            |r| r.get(0),
        )
        .optional()?;
    if existing.is_none() {
        write_identity_and_cutovers(conn)?;
    }
    conn.execute(super::super::migrations::SQL_CLEAR_SCHEMA_VERSION, [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (103)", [])?;
    Ok(())
}

fn write_identity_and_cutovers(conn: &Connection) -> Result<()> {
    let store_id = uuid::Uuid::new_v4().to_string();
    let mut store = blank(STORE_ROW_TABLE, Op::Store, &store_id, "");
    store.attestation_digest = attestation_digest(&store);
    insert_row(conn, &store).context("v103 store-identity row")?;
    for spec in TABLES {
        let mut cut = blank(spec.table, Op::Cutover, &store_id, &spec.covered());
        cut.table_acc = live_acc(conn, spec)?.to_vec();
        cut.attestation_digest = attestation_digest(&cut);
        insert_row(conn, &cut).with_context(|| format!("v103 cutover of {}", spec.table))?;
    }
    Ok(())
}

fn blank(table: &str, op: Op, store_id: &str, covered: &str) -> Attestation {
    Attestation {
        id: 0,
        table: table.to_string(),
        row_key: Vec::new(),
        seq: 0,
        op: op.as_str().to_string(),
        row_digest: None,
        prior_digest: ZERO_DIGEST.to_vec(),
        agent_id: String::new(),
        key_id: String::new(),
        attested_at: now_ts(),
        format_version: FORMAT_VERSION,
        covered_columns: covered.to_string(),
        store_id: store_id.to_string(),
        table_seq: 0,
        table_acc: ZERO_DIGEST.to_vec(),
        signature: None,
        attestation_digest: Vec::new(),
    }
}

/// The signing identity of this session, checked against the bound key.
struct Signer {
    agent_id: String,
    key_id: String,
    signing: ed25519_dalek::SigningKey,
}

fn session_identity(conn: &Connection) -> Result<Signer, String> {
    let signer = crate::identity::session_signer::session_signer()
        .ok_or_else(|| refusal(REFUSE_NO_SIGNER))?;
    let keypair = crate::identity::session_signer::session_keypair()
        .ok_or_else(|| refusal(REFUSE_NO_SIGNER))?;
    let signing = keypair.private.ok_or_else(|| refusal(REFUSE_NO_SIGNER))?;
    let agent_id = signer.agent_id().to_string();
    let bound = crate::db::agent_pubkey(conn, &agent_id)
        .map_err(|_| refusal(REFUSE_KEY_MISMATCH))?
        .ok_or_else(|| refusal(REFUSE_KEY_MISMATCH))?;
    let bound = crate::identity::keypair::decode_public_base64(&bound)
        .map_err(|_| refusal(REFUSE_KEY_MISMATCH))?;
    if bound != signing.verifying_key() {
        return Err(refusal(REFUSE_KEY_MISMATCH));
    }
    Ok(Signer {
        agent_id,
        key_id: key_id_of(&bound),
        signing,
    })
}

fn store_id(conn: &Connection) -> Result<String, String> {
    conn.query_row(
        "SELECT store_id FROM row_attestations WHERE table_name = ?1",
        [STORE_ROW_TABLE],
        |r| r.get(0),
    )
    .map_err(|e| refusal(&format!("store identity unreadable: {e}")))
}

struct Latest {
    seq: i64,
    op: String,
    row_digest: Option<Vec<u8>>,
    digest: Vec<u8>,
}

fn latest_for(conn: &Connection, table: &str, key: &[u8]) -> rusqlite::Result<Option<Latest>> {
    conn.query_row(
        "SELECT seq, op, row_digest, attestation_digest FROM row_attestations \
         WHERE table_name = ?1 AND row_key = ?2 AND op NOT IN ('cutover', 'store') \
         ORDER BY seq DESC LIMIT 1",
        params![table, key],
        |r| {
            Ok(Latest {
                seq: r.get(0)?,
                op: r.get(1)?,
                row_digest: r.get(2)?,
                digest: r.get(3)?,
            })
        },
    )
    .optional()
}

fn head_for(conn: &Connection, table: &str) -> rusqlite::Result<Option<(i64, Vec<u8>)>> {
    conn.query_row(
        "SELECT table_seq, table_acc FROM row_attestations WHERE table_name = ?1 \
         ORDER BY table_seq DESC LIMIT 1",
        [table],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

fn to32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into()
        .map_err(|_| refusal("a stored accumulator is not 32 bytes"))
}

/// One row-key change to attest.
struct Change<'a> {
    spec: &'a TableSpec,
    key: Vec<u8>,
    op: Op,
    old: Option<[u8; 32]>,
    new: Option<[u8; 32]>,
}

/// A memory row that changed outside both funnels is refused by the #10012
/// seal check with its exact tamper text; SQLite does not fix which TEMP
/// trigger of one table fires first, so the drift refusal defers to that
/// text when the seal funnel is armed on this connection and would refuse.
/// Any failure of the probe (funnel not armed, a driver error) leaves the
/// drift refusal in place: the write is refused either way (fail closed).
fn seal_refusal_first(conn: &Connection, ch: &Change<'_>) -> Option<String> {
    if ch.spec.table != "memories" {
        return None;
    }
    let id = super::memory_id_of_key(&ch.key)?;
    let sql = format!("SELECT {}(?1)", crate::identity::session_signer::PEEK_FN);
    conn.query_row(&sql, [id], |r| r.get::<_, Option<String>>(0))
        .ok()
        .flatten()
}

fn append(
    conn: &Connection,
    who: &Signer,
    store: &str,
    ch: &Change<'_>,
) -> Result<(), FunnelRefusal> {
    let db = |e: rusqlite::Error| refusal(&e.to_string());
    let (head_seq, head_acc) = head_for(conn, ch.spec.table)
        .map_err(db)?
        .ok_or_else(|| refusal(REFUSE_NO_CUTOVER))?;
    let latest = latest_for(conn, ch.spec.table, &ch.key).map_err(db)?;
    let live_latest = latest.as_ref().filter(|l| l.op != Op::Delete.as_str());
    let mut old = ch.old;
    match (old, live_latest) {
        (Some(o), Some(l)) if l.row_digest.as_deref() != Some(&o[..]) => {
            return Err(seal_refusal_first(conn, ch)
                .unwrap_or_else(|| refusal(REFUSE_ROW_DRIFT))
                .into());
        }
        // An insert over a live attested key (REPLACE without delete
        // triggers): the replaced row is the attested one.
        (None, Some(l)) => {
            old = Some(to32(l.row_digest.as_deref().unwrap_or(&[]))?);
        }
        _ => {}
    }
    let mut acc = to32(&head_acc)?;
    if let Some(o) = old {
        acc = acc_sub(&acc, &acc_term(ch.spec.table, &ch.key, &o));
    }
    if let Some(n) = ch.new {
        acc = acc_add(&acc, &acc_term(ch.spec.table, &ch.key, &n));
    }
    let mut a = Attestation {
        id: 0,
        table: ch.spec.table.to_string(),
        row_key: ch.key.clone(),
        seq: latest.as_ref().map_or(1, |l| l.seq.saturating_add(1)),
        op: ch.op.as_str().to_string(),
        row_digest: ch.new.map(|d| d.to_vec()),
        prior_digest: latest
            .as_ref()
            .map_or_else(|| ZERO_DIGEST.to_vec(), |l| l.digest.clone()),
        agent_id: who.agent_id.clone(),
        key_id: who.key_id.clone(),
        attested_at: now_ts(),
        format_version: FORMAT_VERSION,
        covered_columns: ch.spec.covered(),
        store_id: store.to_string(),
        table_seq: head_seq.saturating_add(1),
        table_acc: acc.to_vec(),
        signature: None,
        attestation_digest: Vec::new(),
    };
    sign(&mut a, &who.signing);
    insert_row(conn, &a).map_err(db)?;
    if ch.spec.retention == Retention::Supersede {
        conn.execute(
            "DELETE FROM row_attestations WHERE table_name = ?1 AND row_key = ?2 AND seq < ?3",
            params![a.table, a.row_key, a.seq],
        )
        .map_err(db)?;
        conn.execute(
            "DELETE FROM row_attestations WHERE table_name = ?1 AND op = 'delete' \
             AND row_key <> ?2",
            params![a.table, a.row_key],
        )
        .map_err(db)?;
    }
    Ok(())
}

/// Translate one trigger call into the row-key changes it attests.
fn changes<'a>(spec: &'a TableSpec, kind: &str, vals: &[Cell]) -> Result<Vec<Change<'a>>, String> {
    let n = spec.cols.len();
    let one = |cells: &[Cell]| (encode_key(spec, cells), row_digest(spec, cells));
    match (kind, vals.len()) {
        ("I", len) if len == n => {
            let (key, d) = one(vals);
            Ok(vec![Change {
                spec,
                key,
                op: Op::Insert,
                old: None,
                new: Some(d),
            }])
        }
        ("D", len) if len == n => {
            let (key, d) = one(vals);
            Ok(vec![Change {
                spec,
                key,
                op: Op::Delete,
                old: Some(d),
                new: None,
            }])
        }
        ("U", len) if len == 2 * n => {
            let (old_cells, new_cells) = vals.split_at(n);
            let (ok, od) = one(old_cells);
            let (nk, nd) = one(new_cells);
            if ok != nk {
                return Ok(vec![
                    Change {
                        spec,
                        key: ok,
                        op: Op::Delete,
                        old: Some(od),
                        new: None,
                    },
                    Change {
                        spec,
                        key: nk,
                        op: Op::Insert,
                        old: None,
                        new: Some(nd),
                    },
                ]);
            }
            if od == nd {
                return Ok(Vec::new());
            }
            let transition = spec
                .transition
                .and_then(|c| spec.index_of(c))
                .is_some_and(|i| old_cells.get(i) != new_cells.get(i));
            let op = if transition {
                Op::Transition
            } else {
                Op::Update
            };
            Ok(vec![Change {
                spec,
                key: ok,
                op,
                old: Some(od),
                new: Some(nd),
            }])
        }
        _ => Err(refusal("malformed trigger call")),
    }
}

fn attest_call(conn: &Connection, args: &[Cell]) -> Result<(), FunnelRefusal> {
    let (Some(Cell::Text(table)), Some(Cell::Text(kind))) = (args.first(), args.get(1)) else {
        return Err(refusal("malformed trigger call").into());
    };
    let spec = spec_for(table).ok_or_else(|| refusal("unknown attested table"))?;
    let todo = changes(spec, kind, &args[2..])?;
    if todo.is_empty() {
        return Ok(());
    }
    let who = session_identity(conn)?;
    let store = store_id(conn)?;
    for ch in &todo {
        append(conn, &who, &store, ch)?;
    }
    Ok(())
}

fn trigger_sql(spec: &TableSpec) -> String {
    let t = spec.table;
    let list = |p: &str| {
        spec.cols
            .iter()
            .map(|(c, _)| format!("{p}.\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let changed = spec
        .cols
        .iter()
        .map(|(c, _)| format!("OLD.\"{c}\" IS NOT NEW.\"{c}\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "CREATE TEMP TRIGGER IF NOT EXISTS ra10040_{t}_ins AFTER INSERT ON main.\"{t}\" BEGIN \
         SELECT {ATTEST_FN}('{t}', 'I', {new}); END;\
         CREATE TEMP TRIGGER IF NOT EXISTS ra10040_{t}_upd AFTER UPDATE ON main.\"{t}\" \
         WHEN {changed} BEGIN SELECT {ATTEST_FN}('{t}', 'U', {old}, {new}); END;\
         CREATE TEMP TRIGGER IF NOT EXISTS ra10040_{t}_del AFTER DELETE ON main.\"{t}\" BEGIN \
         SELECT {ATTEST_FN}('{t}', 'D', {old}); END;",
        new = list("NEW"),
        old = list("OLD"),
    )
}

/// Sign every unsigned cutover with the session key (the watermark records
/// the live state this first signing session observed) and write a signed
/// `baseline` attestation for each memory row that has none (E-1).
fn sign_cutovers(conn: &Connection, who: &Signer) -> Result<()> {
    let store = store_id(conn).map_err(anyhow::Error::msg)?;
    for spec in TABLES {
        let unsigned: Option<i64> = conn
            .query_row(
                "SELECT id FROM row_attestations WHERE table_name = ?1 AND op = 'cutover' \
                 AND signature IS NULL",
                [spec.table],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = unsigned else { continue };
        let mut cut = blank(spec.table, Op::Cutover, &store, &spec.covered());
        cut.id = id;
        cut.agent_id.clone_from(&who.agent_id);
        cut.key_id.clone_from(&who.key_id);
        let acc = live_acc(conn, spec)?;
        cut.table_acc = acc.to_vec();
        sign(&mut cut, &who.signing);
        conn.execute(
            "UPDATE row_attestations SET agent_id = ?1, key_id = ?2, attested_at = ?3, \
             table_acc = ?4, signature = ?5, attestation_digest = ?6 WHERE id = ?7",
            params![
                cut.agent_id,
                cut.key_id,
                cut.attested_at,
                cut.table_acc,
                cut.signature,
                cut.attestation_digest,
                id
            ],
        )?;
        if spec.table != "memories" {
            continue;
        }
        let mut table_seq = 0_i64;
        for cells in read_rows(conn, spec)? {
            let key = encode_key(spec, &cells);
            if latest_for(conn, spec.table, &key)?.is_some() {
                continue;
            }
            table_seq = table_seq.saturating_add(1);
            let mut b = blank(spec.table, Op::Baseline, &store, &spec.covered());
            b.row_key = key;
            b.seq = 1;
            b.row_digest = Some(row_digest(spec, &cells).to_vec());
            b.agent_id.clone_from(&who.agent_id);
            b.key_id.clone_from(&who.key_id);
            b.table_seq = table_seq;
            b.table_acc = acc.to_vec();
            sign(&mut b, &who.signing);
            insert_row(conn, &b)?;
        }
    }
    Ok(())
}

/// Arm the row-attestation funnel on `conn` when a session signer exists.
///
/// # Errors
///
/// A bound-key mismatch, a missing v103 table, or a failure to register
/// the function or create the triggers. The caller refuses to open the
/// connection (fail closed).
pub fn install(conn: &Connection) -> Result<ArmState> {
    if crate::identity::session_signer::session_signer().is_none() {
        return Ok(ArmState::NoSigner);
    }
    let who = match session_identity(conn) {
        Ok(who) => who,
        // An unbound or mismatched key refuses every write at write time
        // with the exact reason; arming still installs the triggers.
        Err(_) => {
            register(conn)?;
            return Ok(ArmState::Armed);
        }
    };
    // The cutover read and its signed insert run in one BEGIN IMMEDIATE
    // write transaction (#5084): a DEFERRED one read the watermarks under
    // a shared lock and could fail its write upgrade against a concurrent
    // opener. Inside a caller's transaction the work joins it, and an
    // error is returned for that caller to roll back; either way the
    // connection is not armed (fail closed).
    crate::storage::connection::in_write_txn(conn, || sign_cutovers(conn, &who))
        .map_err(|e| e.context("row attestation cutover signing (#10040)"))?;
    register(conn)?;
    Ok(ArmState::Armed)
}

fn register(conn: &Connection) -> Result<()> {
    conn.create_scalar_function(ATTEST_FN, -1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let args: Vec<Cell> = (0..ctx.len()).map(|i| cell_of(ctx.get_raw(i))).collect();
        // SAFETY: the connection handle is used only inside this call, on
        // the thread that runs the triggering statement, and is not kept.
        let inner = unsafe { ctx.get_connection() }?;
        attest_call(&inner, &args)
            .map_err(|reason| rusqlite::Error::UserFunctionError(reason.into()))?;
        Ok(rusqlite::types::Null)
    })?;
    for spec in TABLES {
        conn.execute_batch(&trigger_sql(spec))
            .with_context(|| format!("row attestation triggers on {}", spec.table))?;
    }
    Ok(())
}

/// Every `row_attestations` row.
///
/// # Errors
///
/// Surfaces the query failure.
pub fn read_attestations(conn: &Connection) -> Result<Vec<Attestation>> {
    let mut stmt = conn.prepare(
        "SELECT id, table_name, row_key, seq, op, row_digest, prior_digest, agent_id, key_id, \
         attested_at, format_version, covered_columns, store_id, table_seq, table_acc, \
         signature, attestation_digest FROM row_attestations ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Attestation {
            id: r.get(0)?,
            table: r.get(1)?,
            row_key: r.get(2)?,
            seq: r.get(3)?,
            op: r.get(4)?,
            row_digest: r.get(5)?,
            prior_digest: r.get(6)?,
            agent_id: r.get(7)?,
            key_id: r.get(8)?,
            attested_at: r.get(9)?,
            format_version: r.get(10)?,
            covered_columns: r.get(11)?,
            store_id: r.get(12)?,
            table_seq: r.get(13)?,
            table_acc: r.get(14)?,
            signature: r.get(15)?,
            attestation_digest: r.get(16)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The completeness verifier over a `SQLite` store (C-5).
///
/// # Errors
///
/// Surfaces read failures (a missing `row_attestations` table included);
/// defects in the data are reported in the [`Report`], not as errors.
pub fn verify_sqlite(conn: &Connection) -> Result<Report> {
    let mut live = Vec::new();
    for spec in TABLES {
        for cells in read_rows(conn, spec)? {
            live.push(LiveRow {
                table: spec.table.to_string(),
                key: encode_key(spec, &cells),
                digest: row_digest(spec, &cells),
            });
        }
    }
    let attestations = read_attestations(conn)?;
    let id_high_water: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'row_attestations'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let pubkey = |agent: &str| -> Option<ed25519_dalek::VerifyingKey> {
        let b64 = crate::db::agent_pubkey(conn, agent).ok()??;
        crate::identity::keypair::decode_public_base64(&b64).ok()
    };
    Ok(super::verify(&VerifyInput {
        live: &live,
        attestations: &attestations,
        pubkey: &pubkey,
        id_high_water,
        memory_id_of_key: &super::memory_id_of_key,
    }))
}

/// Refusal prefix of [`check_snapshot`] (C-7, E-6).
pub const SNAPSHOT_REFUSAL_PREFIX: &str = "row attestation (#10040): snapshot refused because";

/// The restore catalog ratchet (C-7, E-6): a snapshot stamped v103 or later
/// must carry `row_attestations` with its store-identity row and one cutover
/// watermark per attested table. A snapshot whose watermarks are all signed
/// (a store a session signer armed) must also pass [`verify_sqlite`] in full;
/// a store no signer ever armed holds unsigned watermarks only and is checked
/// for shape alone.
///
/// # Errors
///
/// The exact reason, prefixed with [`SNAPSHOT_REFUSAL_PREFIX`].
pub fn check_snapshot(conn: &Connection) -> Result<()> {
    let refuse = |why: &str| anyhow::anyhow!("{SNAPSHOT_REFUSAL_PREFIX} {why}");
    let present: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'row_attestations'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if present.is_none() {
        return Err(refuse("it has no row_attestations table"));
    }
    let attestations = read_attestations(conn)?;
    let stores = attestations
        .iter()
        .filter(|a| a.table == STORE_ROW_TABLE)
        .count();
    if stores != 1 {
        return Err(refuse(&format!(
            "it holds {stores} store-identity rows, not one"
        )));
    }
    let mut all_signed = true;
    for spec in TABLES {
        let cut = attestations
            .iter()
            .find(|a| a.table == spec.table && a.op == Op::Cutover.as_str());
        let Some(cut) = cut else {
            return Err(refuse(&format!("{} has no cutover watermark", spec.table)));
        };
        all_signed &= cut.signature.is_some();
    }
    if all_signed {
        let report = verify_sqlite(conn)?;
        if let Some(first) = report.defects.first() {
            return Err(refuse(&format!(
                "its row attestations do not verify ({} defects; first: {first})",
                report.defects.len()
            )));
        }
    }
    Ok(())
}
