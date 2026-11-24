//! #10040 (GA standard 3, "every write is signed and attributable"): the
//! `row_attestations` side table, its canonical row encoding, the signed
//! attestation preimage and the one completeness verifier.
//!
//! 3-agent vote (71472661) V1-10040: ONE additive side table on both
//! backends, ONE seal funnel, ONE verifier; insert, update, state transition
//! and delete are each attested and no base table gets a signature column.
//! 3-agent vote (71472661) V1-10052-ENVELOPE: memory rows are attested over
//! (id, tags, priority, tier, content digest, and per NOTICE 4a metadata
//! (which carries scope), `expires_at` and confidence), with a `baseline`
//! attestation for rows that exist at cutover.
//!
//! Backend-neutral by construction: the encoder takes [`Cell`] values (the
//! storage class a backend read), the verifier takes [`LiveRow`] and
//! [`Attestation`] lists, so `SQLite` and `PostgreSQL` share every byte of
//! the format. The `SQLite` funnel (TEMP triggers plus one scalar function)
//! lives in [`sqlite`].

pub mod sqlite;

use sha2::{Digest, Sha256};

/// Domain tag of every attestation preimage (C-1).
pub const DOMAIN_TAG: &[u8] = b"ai-memory/row-attestation\0";
/// Digest-format version bound into every preimage (C-1, C-3).
pub const FORMAT_VERSION: i64 = 1;

/// The schema version that introduced `row_attestations` (v103).
pub const ROW_ATTEST_SCHEMA_VERSION: i64 = 103;
/// The `table_name` of the one store-identity row.
pub const STORE_ROW_TABLE: &str = "__store__";
/// Zero digest: the `prior_digest` of a row's first attestation.
pub const ZERO_DIGEST: [u8; 32] = [0_u8; 32];

/// C-8: attestation rows allowed per 10,000 `memory_recall` calls. Each
/// recall writes at most one observation per returned memory and the
/// supersede rule keeps one attestation per live observation key, so the
/// table grows by at most the live observation count (one per key) plus the
/// table head; the bound is that count for a default `limit` of 10.
pub const MAX_ATTESTATIONS_PER_10K_RECALLS: u64 = 100_000;
/// C-8: p95 budget (microseconds) the funnel may add to one `memory_recall`.
pub const RECALL_ATTEST_P95_BUDGET_US: u64 = 25_000;
/// C-8: p95 budget (microseconds) the funnel may add to one lease renew.
pub const LEASE_RENEW_ATTEST_P95_BUDGET_US: u64 = 5_000;

/// Logical column type: how a stored cell is canonicalized (C-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    /// UTF-8 text.
    Text,
    /// 64-bit integer.
    Int,
    /// IEEE-754 double (canonical by bit pattern).
    Real,
    /// Boolean stored as 0/1 (`SQLite`) or BOOLEAN (`PostgreSQL`).
    Bool,
    /// Opaque bytes.
    Blob,
    /// RFC 3339 timestamp, canonical UTC microseconds.
    Ts,
    /// JSON document, canonical sorted keys.
    Json,
    /// JSON array of tag strings, canonical sorted (E-4).
    Tags,
    /// Text represented by its SHA-256 (the memory content digest).
    Sha,
}

/// How a table's attestations are kept (C-8, E-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Every attestation is kept; the per-row chain is contiguous.
    Append,
    /// Only the latest attestation per row key is kept (operational rows).
    Supersede,
}

/// One attested table: its columns (key columns included), key and policy.
#[derive(Debug)]
pub struct TableSpec {
    /// Table name.
    pub table: &'static str,
    /// Covered columns in canonical order with their logical type.
    pub cols: &'static [(&'static str, Ty)],
    /// Primary-key columns, in canonical order.
    pub key: &'static [&'static str],
    /// Column whose change makes an update a `transition`.
    pub transition: Option<&'static str>,
    /// Retention rule.
    pub retention: Retention,
}

impl TableSpec {
    /// The covered column list as bound into the preimage.
    #[must_use]
    pub fn covered(&self) -> String {
        self.cols
            .iter()
            .map(|(c, _)| *c)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Index of `col` in [`Self::cols`].
    #[must_use]
    pub fn index_of(&self, col: &str) -> Option<usize> {
        self.cols.iter().position(|(c, _)| *c == col)
    }
}

use Retention::{Append, Supersede};
use Ty::{Blob, Bool, Int, Json, Real, Sha, Tags, Text, Ts};

/// The 13 side tables of #10012 plus `memories` (14 attested tables).
pub const TABLES: &[TableSpec] = &[
    TableSpec {
        table: "memories",
        cols: &[
            ("id", Text),
            ("tags", Tags),
            ("priority", Int),
            ("tier", Text),
            ("content", Sha),
            // NOTICE 4a: scope rides in `metadata.scope` (`scope_idx` is its
            // generated projection), so covering metadata covers scope.
            // Canonical byte form: `canonical_json` (sorted keys, no
            // whitespace, serde_json scalar spelling); NULL keeps TAG_NULL.
            ("metadata", Json),
            ("expires_at", Ts),
            ("confidence", Real),
        ],
        key: &["id"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "entity_aliases",
        cols: &[("entity_id", Text), ("alias", Text), ("created_at", Ts)],
        key: &["entity_id", "alias"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "namespace_meta",
        cols: &[
            ("namespace", Text),
            ("standard_id", Text),
            ("updated_at", Ts),
            ("parent_namespace", Text),
        ],
        key: &["namespace"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "pending_actions",
        cols: &[
            ("id", Text),
            ("action_type", Text),
            ("memory_id", Text),
            ("namespace", Text),
            ("payload", Json),
            ("requested_by", Text),
            ("requested_at", Ts),
            ("status", Text),
            ("decided_by", Text),
            ("decided_at", Ts),
            ("approvals", Json),
            ("default_timeout_seconds", Int),
            ("expired_at", Ts),
        ],
        key: &["id"],
        transition: Some("status"),
        retention: Append,
    },
    TableSpec {
        table: "subscriptions",
        cols: &[
            ("id", Text),
            ("url", Text),
            ("events", Text),
            ("secret_hash", Text),
            ("namespace_filter", Text),
            ("agent_filter", Text),
            ("created_by", Text),
            ("created_at", Ts),
            ("last_dispatched_at", Ts),
            ("dispatch_count", Int),
            ("failure_count", Int),
            ("event_types", Json),
        ],
        key: &["id"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "subscription_events",
        cols: &[
            ("id", Int),
            ("subscription_id", Text),
            ("correlation_id", Text),
            ("event_type", Text),
            ("payload", Json),
            ("delivered_at", Ts),
            ("delivery_status", Text),
        ],
        key: &["id"],
        transition: Some("delivery_status"),
        retention: Append,
    },
    TableSpec {
        table: "subscription_dlq",
        cols: &[
            ("id", Int),
            ("subscription_id", Text),
            ("correlation_id", Text),
            ("event_type", Text),
            ("payload", Json),
            ("retry_count", Int),
            ("last_error", Text),
            ("first_failed_at", Ts),
            ("last_failed_at", Ts),
        ],
        key: &["id"],
        transition: None,
        retention: Supersede,
    },
    TableSpec {
        table: "memory_transcripts",
        cols: &[
            ("id", Text),
            ("namespace", Text),
            ("created_at", Ts),
            ("expires_at", Ts),
            ("compressed_size", Int),
            ("original_size", Int),
            ("zstd_level", Int),
            ("content_blob", Blob),
            ("archived_at", Ts),
        ],
        key: &["id"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "memory_transcript_links",
        cols: &[
            ("memory_id", Text),
            ("transcript_id", Text),
            ("span_start", Int),
            ("span_end", Int),
        ],
        key: &["memory_id", "transcript_id"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "recall_observations",
        cols: &[
            ("recall_id", Text),
            ("memory_id", Text),
            ("retriever", Text),
            ("rank", Int),
            ("score", Real),
            ("consumed", Bool),
            ("observed_at", Ts),
            ("consumed_at", Ts),
            ("consumed_by_memory_id", Text),
            ("folded", Bool),
            ("agent_id", Text),
            ("namespace", Text),
        ],
        key: &["recall_id", "memory_id"],
        transition: None,
        retention: Supersede,
    },
    TableSpec {
        table: "actions",
        cols: &[
            ("id", Text),
            ("namespace", Text),
            ("kind", Text),
            ("state", Text),
            ("title", Text),
            ("payload", Json),
            ("priority", Int),
            ("agent_id", Text),
            ("claimed_by", Text),
            ("vector_clock", Json),
            ("metadata", Json),
            ("created_at", Int),
            ("updated_at", Int),
        ],
        key: &["id"],
        transition: Some("state"),
        retention: Append,
    },
    TableSpec {
        table: "action_edges",
        cols: &[
            ("from_action", Text),
            ("to_action", Text),
            ("edge_type", Text),
            ("created_at", Int),
        ],
        key: &["from_action", "to_action", "edge_type"],
        transition: None,
        retention: Append,
    },
    TableSpec {
        table: "leases",
        cols: &[
            ("action_id", Text),
            ("holder", Text),
            ("acquired_at", Int),
            ("expires_at", Int),
            ("heartbeat_at", Int),
        ],
        key: &["action_id"],
        transition: None,
        retention: Supersede,
    },
    TableSpec {
        table: "routine_runs",
        cols: &[
            ("id", Text),
            ("routine_id", Text),
            ("namespace", Text),
            ("arguments", Json),
            ("state", Text),
            ("created_action_ids", Json),
            ("started_at", Int),
            ("finished_at", Int),
            ("error", Text),
            ("metadata", Json),
        ],
        key: &["id"],
        transition: Some("state"),
        retention: Append,
    },
];

/// The spec of `table`, if it is attested.
#[must_use]
pub fn spec_for(table: &str) -> Option<&'static TableSpec> {
    TABLES.iter().find(|s| s.table == table)
}

/// One stored cell as a backend read it, before canonicalization.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// SQL NULL.
    Null,
    /// Integer storage class.
    Int(i64),
    /// Real storage class.
    Real(f64),
    /// Text storage class.
    Text(String),
    /// Blob storage class.
    Blob(Vec<u8>),
    /// A boolean (`PostgreSQL` BOOLEAN).
    Bool(bool),
    /// A JSON value read natively (`PostgreSQL` JSONB).
    Json(serde_json::Value),
}

// Canonical value tags. A value whose storage class does not fit its logical
// type keeps a distinct tag, so it can never collide with a well-typed one.
const TAG_NULL: u8 = 0;
const TAG_INT: u8 = 1;
const TAG_REAL: u8 = 2;
const TAG_TEXT: u8 = 3;
const TAG_BLOB: u8 = 4;
const TAG_TS: u8 = 5;
const TAG_JSON: u8 = 6;
const TAG_TAGS: u8 = 7;
const TAG_SHA: u8 = 8;
const TAG_RAW_TEXT: u8 = 9;

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    // A cell larger than u32::MAX bytes cannot be stored by either backend;
    // saturate rather than wrap so the encoding stays injective in practice.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical UTC-microsecond spelling of an RFC 3339 / `SQLite` timestamp.
#[must_use]
pub fn canonical_ts(raw: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(raw)
        .map(|d| d.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f").map(|n| n.and_utc())
        })
        .ok()?;
    Some(parsed.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

/// Canonical JSON: objects with sorted keys, no whitespace.
#[must_use]
pub fn canonical_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                if let Some(child) = map.get(*k) {
                    write_json(child, out);
                }
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn json_of(cell: &Cell) -> Option<serde_json::Value> {
    match cell {
        Cell::Text(t) => serde_json::from_str(t).ok(),
        Cell::Json(v) => Some(v.clone()),
        _ => None,
    }
}

/// Append the canonical encoding of `cell` read as logical type `ty`.
pub fn encode_cell(ty: Ty, cell: &Cell, out: &mut Vec<u8>) {
    if matches!(cell, Cell::Null) {
        out.push(TAG_NULL);
        return;
    }
    match ty {
        Ty::Text => match cell {
            Cell::Text(t) => {
                out.push(TAG_TEXT);
                put_len_bytes(out, t.as_bytes());
            }
            other => encode_raw(other, out),
        },
        Ty::Int | Ty::Bool => match cell {
            Cell::Int(i) => {
                out.push(TAG_INT);
                out.extend_from_slice(&i.to_be_bytes());
            }
            Cell::Bool(b) => {
                out.push(TAG_INT);
                out.extend_from_slice(&i64::from(*b).to_be_bytes());
            }
            other => encode_raw(other, out),
        },
        Ty::Real => match cell {
            Cell::Real(f) => {
                out.push(TAG_REAL);
                out.extend_from_slice(&f.to_bits().to_be_bytes());
            }
            Cell::Int(i) => {
                // SQLite REAL affinity stores an integral score as an integer.
                #[allow(clippy::cast_precision_loss)]
                let f = *i as f64;
                out.push(TAG_REAL);
                out.extend_from_slice(&f.to_bits().to_be_bytes());
            }
            other => encode_raw(other, out),
        },
        Ty::Blob => match cell {
            Cell::Blob(b) => {
                out.push(TAG_BLOB);
                put_len_bytes(out, b);
            }
            other => encode_raw(other, out),
        },
        Ty::Ts => match cell {
            Cell::Text(t) => match canonical_ts(t) {
                Some(ts) => {
                    out.push(TAG_TS);
                    put_len_bytes(out, ts.as_bytes());
                }
                None => encode_raw(cell, out),
            },
            other => encode_raw(other, out),
        },
        Ty::Json => match json_of(cell) {
            Some(v) => {
                out.push(TAG_JSON);
                put_len_bytes(out, canonical_json(&v).as_bytes());
            }
            None => encode_raw(cell, out),
        },
        Ty::Tags => match json_of(cell) {
            Some(serde_json::Value::Array(items))
                if items.iter().all(serde_json::Value::is_string) =>
            {
                let mut tags: Vec<String> = items
                    .iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect();
                tags.sort();
                let canon = serde_json::Value::Array(
                    tags.into_iter().map(serde_json::Value::String).collect(),
                );
                out.push(TAG_TAGS);
                put_len_bytes(out, canonical_json(&canon).as_bytes());
            }
            _ => encode_raw(cell, out),
        },
        Ty::Sha => match cell {
            Cell::Text(t) => {
                out.push(TAG_SHA);
                out.extend_from_slice(&Sha256::digest(t.as_bytes()));
            }
            other => encode_raw(other, out),
        },
    }
}

/// A cell whose storage class does not match its logical type.
fn encode_raw(cell: &Cell, out: &mut Vec<u8>) {
    out.push(TAG_RAW_TEXT);
    let text = match cell {
        Cell::Null => String::new(),
        Cell::Int(i) => format!("i:{i}"),
        Cell::Real(f) => format!("r:{:016x}", f.to_bits()),
        Cell::Text(t) => format!("t:{t}"),
        Cell::Blob(b) => format!("b:{}", hex::encode(b)),
        Cell::Bool(b) => format!("o:{b}"),
        Cell::Json(v) => format!("j:{}", canonical_json(v)),
    };
    put_len_bytes(out, text.as_bytes());
}

/// Canonical encoding of the key columns of a row (`cells` in spec order).
#[must_use]
pub fn encode_key(spec: &TableSpec, cells: &[Cell]) -> Vec<u8> {
    let mut out = Vec::new();
    for k in spec.key {
        if let Some(i) = spec.index_of(k) {
            let (_, ty) = spec.cols[i];
            encode_cell(ty, cells.get(i).unwrap_or(&Cell::Null), &mut out);
        }
    }
    out
}

/// Canonical digest of a full row (`cells` in spec order, C-2).
#[must_use]
pub fn row_digest(spec: &TableSpec, cells: &[Cell]) -> [u8; 32] {
    let mut enc = Vec::new();
    for (i, (_, ty)) in spec.cols.iter().enumerate() {
        encode_cell(*ty, cells.get(i).unwrap_or(&Cell::Null), &mut enc);
    }
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"row\0");
    let mut framed = Vec::new();
    put_len_bytes(&mut framed, spec.table.as_bytes());
    put_len_bytes(&mut framed, spec.covered().as_bytes());
    put_len_bytes(&mut framed, &enc);
    h.update(&framed);
    h.finalize().into()
}

/// The accumulator term of one live row.
#[must_use]
pub fn acc_term(table: &str, key: &[u8], digest: &[u8; 32]) -> [u8; 32] {
    let mut framed = Vec::new();
    put_len_bytes(&mut framed, table.as_bytes());
    put_len_bytes(&mut framed, key);
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"acc\0");
    h.update(&framed);
    h.update(digest);
    h.finalize().into()
}

/// `a + b mod 2^256` (big-endian).
#[must_use]
pub fn acc_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut carry = 0_u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s.to_be_bytes()[1];
        carry = s >> 8;
    }
    out
}

/// `a - b mod 2^256` (big-endian).
#[must_use]
pub fn acc_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = u8::try_from(d).unwrap_or(0);
    }
    out
}

/// What an attestation records (C-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// A row was inserted.
    Insert,
    /// A covered column changed.
    Update,
    /// The table's state column changed.
    Transition,
    /// A row was deleted (tombstone, no row digest).
    Delete,
    /// The signed per-table watermark at cutover (C-6).
    Cutover,
    /// State observed at cutover for a memory row (E-1), never authorship.
    Baseline,
    /// The store-identity row.
    Store,
}

impl Op {
    /// Every variant (exhaustive tables in tests).
    pub const ALL: [Self; 7] = [
        Self::Insert,
        Self::Update,
        Self::Transition,
        Self::Delete,
        Self::Cutover,
        Self::Baseline,
        Self::Store,
    ];

    /// Stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Transition => "transition",
            Self::Delete => "delete",
            Self::Cutover => "cutover",
            Self::Baseline => "baseline",
            Self::Store => "store",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.as_str() == s)
    }
}

/// One `row_attestations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Row id (insertion order).
    pub id: i64,
    /// Attested table.
    pub table: String,
    /// Canonical row key.
    pub row_key: Vec<u8>,
    /// Per-row sequence (1-based; 0 for cutover and store rows).
    pub seq: i64,
    /// Operation.
    pub op: String,
    /// Canonical row digest (None for a delete, cutover or store row).
    pub row_digest: Option<Vec<u8>>,
    /// Digest of the previous attestation of the same row key.
    pub prior_digest: Vec<u8>,
    /// The acting agent (E-4), never the row owner.
    pub agent_id: String,
    /// SHA-256 (hex) of the acting agent's public key.
    pub key_id: String,
    /// Attestation time (canonical UTC).
    pub attested_at: String,
    /// Digest-format version.
    pub format_version: i64,
    /// Covered column list.
    pub covered_columns: String,
    /// Store identity.
    pub store_id: String,
    /// Per-table sequence (the table head is the max).
    pub table_seq: i64,
    /// Per-table accumulator over live rows after this attestation.
    pub table_acc: Vec<u8>,
    /// Ed25519 signature over [`preimage`] (None while a cutover is unsigned).
    pub signature: Option<Vec<u8>>,
    /// SHA-256 of preimage plus signature.
    pub attestation_digest: Vec<u8>,
}

/// SHA-256 (hex) of a public key: the `key_id` bound into a preimage.
#[must_use]
pub fn key_id_of(public: &ed25519_dalek::VerifyingKey) -> String {
    hex::encode(Sha256::digest(public.to_bytes()))
}

/// The signed bytes of one attestation (C-1).
#[must_use]
pub fn preimage(a: &Attestation) -> Vec<u8> {
    let mut out = Vec::from(DOMAIN_TAG);
    out.extend_from_slice(&a.format_version.to_be_bytes());
    put_len_bytes(&mut out, a.covered_columns.as_bytes());
    put_len_bytes(&mut out, a.store_id.as_bytes());
    put_len_bytes(&mut out, a.table.as_bytes());
    put_len_bytes(&mut out, &a.row_key);
    put_len_bytes(&mut out, a.op.as_bytes());
    put_len_bytes(&mut out, a.row_digest.as_deref().unwrap_or(&[]));
    put_len_bytes(&mut out, a.agent_id.as_bytes());
    put_len_bytes(&mut out, a.key_id.as_bytes());
    put_len_bytes(&mut out, a.attested_at.as_bytes());
    out.extend_from_slice(&a.seq.to_be_bytes());
    put_len_bytes(&mut out, &a.prior_digest);
    out.extend_from_slice(&a.table_seq.to_be_bytes());
    put_len_bytes(&mut out, &a.table_acc);
    out
}

/// SHA-256 over the preimage and the signature.
#[must_use]
pub fn attestation_digest(a: &Attestation) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(preimage(a));
    h.update(a.signature.as_deref().unwrap_or(&[]));
    h.finalize().to_vec()
}

/// Sign `a` in place with `signing` (sets signature and digest).
pub fn sign(a: &mut Attestation, signing: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer;
    let sig = signing.sign(&preimage(a));
    a.signature = Some(sig.to_bytes().to_vec());
    a.attestation_digest = attestation_digest(a);
}

/// One live base-table row as the verifier sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRow {
    /// Table.
    pub table: String,
    /// Canonical key.
    pub key: Vec<u8>,
    /// Canonical row digest.
    pub digest: [u8; 32],
}

/// Per-table outcome of [`verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableVerdict {
    /// Live rows whose latest attestation verifies.
    pub verified: u64,
    /// Live rows covered only by the signed cutover watermark (side tables).
    pub legacy: u64,
    /// Attestation rows held.
    pub attestations: u64,
}

/// The completeness verifier's report (C-5, E-3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Per-table counts, keyed by table name.
    pub tables: std::collections::BTreeMap<String, TableVerdict>,
    /// Every defect found, one line each; empty means the store verifies.
    pub defects: Vec<String>,
    /// Memory ids whose attestation does not verify (E-3).
    pub unverified_memories: std::collections::BTreeSet<String>,
}

impl Report {
    /// True when no defect was found.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.defects.is_empty()
    }
}

/// Inputs the verifier needs beside rows and attestations.
pub struct VerifyInput<'a> {
    /// Every live row of every attested table.
    pub live: &'a [LiveRow],
    /// Every `row_attestations` row, any order.
    pub attestations: &'a [Attestation],
    /// Resolve an agent id to its bound public key (`None` = unbound).
    pub pubkey: &'a dyn Fn(&str) -> Option<ed25519_dalek::VerifyingKey>,
    /// The id high-water mark of `row_attestations` (`SQLite`
    /// `sqlite_sequence`, `PostgreSQL` sequence `last_value`); `None` when
    /// the table never held a row.
    pub id_high_water: Option<i64>,
    /// Decode a memories key to its id (for [`Report::unverified_memories`]).
    pub memory_id_of_key: &'a dyn Fn(&[u8]) -> Option<String>,
}

fn sig_defect(
    a: &Attestation,
    pubkey: &dyn Fn(&str) -> Option<ed25519_dalek::VerifyingKey>,
) -> Option<String> {
    let Some(sig) = a.signature.as_deref() else {
        return Some(format!("attestation {} ({}) is unsigned", a.id, a.table));
    };
    let Some(public) = pubkey(&a.agent_id) else {
        return Some(format!(
            "attestation {} names agent {} with no bound key",
            a.id, a.agent_id
        ));
    };
    if key_id_of(&public) != a.key_id {
        return Some(format!(
            "attestation {} key_id is not {}'s bound key",
            a.id, a.agent_id
        ));
    }
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
        return Some(format!("attestation {} signature is malformed", a.id));
    };
    // verify_strict refuses small-order keys and a non-canonical signature
    // (NOTICE 4b); the plain `verify` accepts both.
    if public.verify_strict(&preimage(a), &sig).is_err() {
        return Some(format!("attestation {} signature does not verify", a.id));
    }
    if attestation_digest(a) != a.attestation_digest {
        return Some(format!("attestation {} digest does not recompute", a.id));
    }
    None
}

/// The ONE completeness verifier (C-5): every attestation signature, the
/// store identity, every per-row chain, every live row against its latest
/// attestation, every table head against the recomputed accumulator, and the
/// id high-water mark (tail truncation).
#[must_use]
pub fn verify(input: &VerifyInput<'_>) -> Report {
    use std::collections::BTreeMap;
    let mut defects: Vec<String> = Vec::new();
    let mut tables: BTreeMap<String, TableVerdict> = BTreeMap::new();
    let mut unverified = std::collections::BTreeSet::new();
    let d = &mut defects;
    let stores: Vec<&Attestation> = input
        .attestations
        .iter()
        .filter(|a| a.table == STORE_ROW_TABLE)
        .collect();
    let store_id = match stores.as_slice() {
        [one] => one.store_id.clone(),
        [] => {
            d.push("row_attestations has no store-identity row".to_string());
            return Report {
                tables,
                defects,
                unverified_memories: unverified,
            };
        }
        _ => {
            d.push("row_attestations has more than one store-identity row".to_string());
            return Report {
                tables,
                defects,
                unverified_memories: unverified,
            };
        }
    };
    let max_id = input.attestations.iter().map(|a| a.id).max();
    if max_id != input.id_high_water {
        d.push(format!(
            "row_attestations tail truncated: newest id {max_id:?}, high-water {:?}",
            input.id_high_water
        ));
    }
    for spec in TABLES {
        let mut atts: Vec<&Attestation> = input
            .attestations
            .iter()
            .filter(|a| a.table == spec.table)
            .collect();
        atts.sort_by_key(|a| a.table_seq);
        let verdict = tables.entry(spec.table.to_string()).or_default();
        verdict.attestations = u64::try_from(atts.len()).unwrap_or(u64::MAX);
        let cutover = atts.iter().find(|a| a.op == Op::Cutover.as_str());
        let Some(cutover) = cutover else {
            d.push(format!("{}: no cutover watermark", spec.table));
            continue;
        };
        // Signatures, store and format binding.
        for a in &atts {
            if let Some(defect) = sig_defect(a, input.pubkey) {
                d.push(format!("{}: {defect}", spec.table));
            }
            if a.store_id != store_id {
                d.push(format!(
                    "{}: attestation {} names another store",
                    spec.table, a.id
                ));
            }
            if a.format_version != FORMAT_VERSION || a.covered_columns != spec.covered() {
                d.push(format!(
                    "{}: attestation {} format or covered columns differ",
                    spec.table, a.id
                ));
            }
            if Op::parse(&a.op).is_none() {
                d.push(format!(
                    "{}: attestation {} has unknown op {}",
                    spec.table, a.id, a.op
                ));
            }
        }
        // Table sequence: contiguous from the cutover (append) or strictly
        // increasing (supersede).
        for w in atts.windows(2) {
            let ok = match spec.retention {
                Retention::Append => w[0].table_seq.checked_add(1) == Some(w[1].table_seq),
                Retention::Supersede => w[1].table_seq > w[0].table_seq,
            };
            if !ok {
                d.push(format!(
                    "{}: table sequence breaks between attestations {} and {}",
                    spec.table, w[0].id, w[1].id
                ));
            }
        }
        if cutover.table_seq != 0 {
            d.push(format!(
                "{}: cutover is not the first table sequence",
                spec.table
            ));
        }
        // Per-row chains.
        let mut by_key: BTreeMap<&[u8], Vec<&Attestation>> = BTreeMap::new();
        for a in atts.iter().filter(|a| a.op != Op::Cutover.as_str()) {
            by_key.entry(a.row_key.as_slice()).or_default().push(a);
        }
        for chain in by_key.values_mut() {
            chain.sort_by_key(|a| a.seq);
            if spec.retention == Retention::Append {
                for (i, a) in chain.iter().enumerate() {
                    let want_seq = i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1);
                    let want_prior = if i == 0 {
                        ZERO_DIGEST.to_vec()
                    } else {
                        chain[i.saturating_sub(1)].attestation_digest.clone()
                    };
                    if a.seq != want_seq || a.prior_digest != want_prior {
                        d.push(format!(
                            "{}: row chain breaks at attestation {}",
                            spec.table, a.id
                        ));
                    }
                }
            }
        }
        // Live rows against their latest attestation, and the accumulator.
        let live: Vec<&LiveRow> = input
            .live
            .iter()
            .filter(|r| r.table == spec.table)
            .collect();
        let mut acc = ZERO_DIGEST;
        for row in &live {
            acc = acc_add(&acc, &acc_term(spec.table, &row.key, &row.digest));
            match by_key.get(row.key.as_slice()).and_then(|c| c.last()) {
                Some(latest) if latest.op == Op::Delete.as_str() => {
                    d.push(format!(
                        "{}: live row has a delete as latest attestation",
                        spec.table
                    ));
                    mark_memory(&mut unverified, spec, row, input);
                }
                Some(latest) if latest.row_digest.as_deref() == Some(&row.digest[..]) => {
                    verdict.verified += 1;
                }
                Some(latest) => {
                    d.push(format!(
                        "{}: live row differs from its latest attestation {}",
                        spec.table, latest.id
                    ));
                    mark_memory(&mut unverified, spec, row, input);
                }
                None if spec.table == "memories" => {
                    d.push(format!("{}: live row has no attestation", spec.table));
                    mark_memory(&mut unverified, spec, row, input);
                }
                None => verdict.legacy += 1,
            }
        }
        for (key, chain) in &by_key {
            let latest = chain.last();
            if latest.is_some_and(|l| l.op != Op::Delete.as_str())
                && !live.iter().any(|r| r.key.as_slice() == *key)
            {
                d.push(format!(
                    "{}: attested row is gone without a delete attestation",
                    spec.table
                ));
            }
        }
        if let Some(head) = atts.last() {
            if head.table_acc != acc.to_vec() {
                d.push(format!(
                    "{}: live rows do not match the signed table head (table_seq {})",
                    spec.table, head.table_seq
                ));
            }
        }
    }
    Report {
        tables,
        defects,
        unverified_memories: unverified,
    }
}

fn mark_memory(
    set: &mut std::collections::BTreeSet<String>,
    spec: &TableSpec,
    row: &LiveRow,
    input: &VerifyInput<'_>,
) {
    if spec.table == "memories" {
        if let Some(id) = (input.memory_id_of_key)(&row.key) {
            set.insert(id);
        }
    }
}

/// Decode a memories key (one canonical Text cell) to the id.
#[must_use]
pub fn memory_id_of_key(key: &[u8]) -> Option<String> {
    let (&tag, rest) = key.split_first()?;
    if tag != TAG_TEXT || rest.len() < 4 {
        return None;
    }
    let (len, body) = rest.split_at(4);
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    (body.len() == len).then(|| String::from_utf8(body.to_vec()).ok())?
}

#[cfg(test)]
mod tests;
