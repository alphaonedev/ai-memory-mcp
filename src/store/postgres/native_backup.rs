// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10021 (GA standard 4) — PostgreSQL-native backup and restore.
//!
//! The dump runs in ONE `REPEATABLE READ READ ONLY` transaction (one
//! snapshot): it walks the catalog, refuses a column type with no handler,
//! orders the tables by their foreign keys and streams each table with
//! `COPY (SELECT <columns> ... ORDER BY row::text COLLATE "C") TO STDOUT
//! (FORMAT binary)` into the data file, hashing every segment and the whole
//! file. Binary COPY keeps every typed value, `bytea`, `jsonb` and `vector`
//! byte-exact.
//!
//! The restore takes a [`VerifiedPgBackup`] (the signature and every digest
//! were checked before any write, against a trust anchor outside the
//! artifact) and runs in ONE transaction: schema version check, catalog
//! check, `ACCESS EXCLUSIVE` locks, the emptiness check, every segment loaded
//! with user triggers off (re-hashed while it is read, so a file swapped after
//! verification is refused), the row count of every table checked, the
//! sequences set, unexpired leases clamped to expired-at-restore, user
//! triggers back on, every `memory_links` row re-projected into AGE, commit.
//! Any refusal rolls the whole transaction back: the target stays empty.

use std::collections::{BTreeMap, BTreeSet};
use std::io::SeekFrom;

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::{project_link_into_age, to_store_err};
use crate::store::native_backup::{
    ColumnSpec, Exclusion, NativeBackupError, NativeDumpBody, NativeRestoreReport,
    PG_BACKUP_BACKEND, PG_BACKUP_CHUNK_BYTES, PG_BACKUP_DOMAIN, PG_BACKUP_LAYOUT_VERSION,
    SEEK_DATA_CONTEXT, SequenceValue, TableSegment, VerifiedPgBackup,
};
use crate::store::{StoreError, StoreResult};

/// Error context of every `COPY ... FROM STDIN` step of the restore.
const COPY_IN_CONTEXT: &str = "native restore: copy in";

/// Column types with a backup handler (binary COPY round-trips each exactly).
pub(crate) const HANDLED_TYPES: [&str; 9] = [
    "bool",
    "bytea",
    "float8",
    "int4",
    "int8",
    "jsonb",
    "text",
    "timestamptz",
    "vector",
];

/// Exclusion reason: a view or materialised view.
pub(crate) const REASON_VIEW: &str = "view: holds no rows";
/// Exclusion reason: a relation owned by an extension.
pub(crate) const REASON_EXTENSION: &str =
    "owned by extension; created by CREATE EXTENSION / target migration";
/// Exclusion reason: a relation of an AGE graph schema.
pub(crate) const REASON_AGE: &str =
    "AGE projection of public.memory_links; restore re-projects every memory_links row";
/// Exclusion reason: the migration ledger.
pub(crate) const REASON_LEDGER: &str =
    "target's own migration ledger; restore requires equal MAX(version)";
/// Exclusion reason: a generated column.
pub(crate) const REASON_GENERATED: &str = "generated; recomputed";

/// The migration ledger, never dumped (restore requires equal versions).
const LEDGER_SCHEMA: &str = "public";
const LEDGER_TABLE: &str = "schema_version";
/// The AGE extension's own catalog schema.
const AGE_CATALOG_SCHEMA: &str = "ag_catalog";
/// The table whose rows AGE projects.
const LINKS_TABLE: (&str, &str) = ("public", "memory_links");
/// The table whose unexpired leases a restore clamps.
const LEASES_TABLE: (&str, &str) = ("public", "leases");

/// Every relation of the catalog, as the dump and the restore see it.
const SQL_RELATIONS: &str = "SELECT n.nspname::text, c.relname::text, c.relkind::text, \
       c.relispartition, \
       EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass \
               AND d.objid = c.oid AND d.deptype = 'e') \
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('r','p','S','v','m','f') \
       AND n.nspname NOT IN ('pg_catalog','information_schema') \
       AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' \
     ORDER BY 1, 2";

/// Every column of every ordinary table, in `attnum` order.
const SQL_COLUMNS: &str = "SELECT n.nspname::text, c.relname::text, a.attname::text, \
       t.typname::text, a.attgenerated::text \
     FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
     JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_type t ON t.oid = a.atttypid \
     WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped \
       AND n.nspname NOT IN ('pg_catalog','information_schema') \
       AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' \
     ORDER BY n.nspname, c.relname, a.attnum";

/// Every foreign key (child, parent).
const SQL_FOREIGN_KEYS: &str = "SELECT sn.nspname::text, sc.relname::text, \
       tn.nspname::text, tc.relname::text \
     FROM pg_constraint k JOIN pg_class sc ON sc.oid = k.conrelid \
     JOIN pg_namespace sn ON sn.oid = sc.relnamespace \
     JOIN pg_class tc ON tc.oid = k.confrelid \
     JOIN pg_namespace tn ON tn.oid = tc.relnamespace \
     WHERE k.contype = 'f'";

/// The schemas that hold AGE graphs (empty when AGE is not installed).
const SQL_AGE_GRAPH_SCHEMAS: &str = "SELECT n.nspname::text FROM ag_catalog.ag_graph g \
     JOIN pg_namespace n ON n.oid = g.namespace::oid";

/// Whether the AGE catalog exists on this database.
const SQL_AGE_PRESENT: &str = "SELECT to_regclass('ag_catalog.ag_graph') IS NOT NULL";

/// The store's schema version.
const SQL_SCHEMA_VERSION: &str = "SELECT MAX(version)::int8 FROM public.schema_version";

/// The name of the AGE graph a restore re-projects into.
const AGE_GRAPH_NAME: &str = "memory_graph";

/// Every label table of the AGE graph `$1` (#10045: the graph schema is
/// excluded from the dump, so its emptiness is checked on its own).
const SQL_AGE_LABEL_TABLES: &str = "SELECT n.nspname::text, c.relname::text \
     FROM ag_catalog.ag_label l JOIN ag_catalog.ag_graph g ON g.graphid = l.graph \
     JOIN pg_class c ON c.oid = l.relation JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE g.name = $1 ORDER BY 1, 2";

/// Every user trigger that `session_replication_role = replica` leaves on
/// (`ENABLE ALWAYS` = 'A', `ENABLE REPLICA` = 'R') and every rewrite rule
/// other than a view's `_RETURN`, on any table (#10048).
const SQL_ACTIVE_TRIGGERS_AND_RULES: &str = "SELECT n.nspname::text, c.relname::text, \
       'trigger'::text, t.tgname::text \
     FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
     JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE NOT t.tgisinternal AND t.tgenabled IN ('A', 'R') \
     UNION ALL \
     SELECT n.nspname::text, c.relname::text, 'rule'::text, r.rulename::text \
     FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class \
     JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE r.rulename <> '_RETURN' \
     ORDER BY 1, 2, 3, 4";

/// SQLSTATE `insufficient_privilege`.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// Rows of `memory_links` read per keyset page during the AGE re-projection
/// (#10046: memory stays bounded whatever the link count).
pub(crate) const LINK_PAGE_ROWS: i64 = 1000;

/// One `memory_links` row as the AGE re-projection reads it.
type LinkRow = (
    String,
    String,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

const SQL_LINKS_FIRST_PAGE: &str = "SELECT source_id, target_id, relation, valid_from, \
       valid_until FROM public.memory_links \
     ORDER BY source_id, target_id, relation LIMIT $1";

const SQL_LINKS_NEXT_PAGE: &str = "SELECT source_id, target_id, relation, valid_from, \
       valid_until FROM public.memory_links \
     WHERE (source_id, target_id, relation) > ($1, $2, $3) \
     ORDER BY source_id, target_id, relation LIMIT $4";

/// `"schema"."name"` with every `"` doubled, safe for any catalog name.
fn quote_qualified(schema: &str, name: &str) -> String {
    format!(
        "\"{}\".\"{}\"",
        schema.replace('"', "\"\""),
        name.replace('"', "\"\"")
    )
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn qualified(schema: &str, name: &str) -> String {
    format!("{schema}.{name}")
}

fn catalog_err(detail: String) -> StoreError {
    NativeBackupError::CatalogMismatch { detail }.into()
}

fn io_store_err(context: &str, e: &std::io::Error) -> StoreError {
    NativeBackupError::Io {
        context: context.to_string(),
        detail: e.to_string(),
    }
    .into()
}

fn to_u64(n: i64, what: &str) -> StoreResult<u64> {
    u64::try_from(n).map_err(|_| catalog_err(format!("{what} is negative ({n})")))
}

/// One table the backup dumps.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TableSpec {
    schema: String,
    name: String,
    columns: Vec<ColumnSpec>,
}

impl TableSpec {
    fn qualified(&self) -> String {
        qualified(&self.schema, &self.name)
    }
}

/// The catalog as the backup sees it.
#[derive(Debug)]
struct Catalog {
    /// Dumped tables in restore order (parents first, ties by name).
    tables: Vec<TableSpec>,
    /// Dumped sequences, ordered by (schema, name).
    sequences: Vec<(String, String)>,
    /// Everything deliberately not dumped, sorted by relation.
    exclusions: Vec<Exclusion>,
}

/// Walk the catalog: classify every relation, refuse a relation kind or a
/// column type with no handler, order the tables by their foreign keys.
async fn read_catalog(tx: &mut Transaction<'_, Postgres>) -> StoreResult<Catalog> {
    let age_present: bool = sqlx::query_scalar(SQL_AGE_PRESENT)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| to_store_err("native backup: probe AGE catalog", e))?;
    let age_schemas: BTreeSet<String> = if age_present {
        sqlx::query_scalar::<_, String>(SQL_AGE_GRAPH_SCHEMAS)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| to_store_err("native backup: list AGE graph schemas", e))?
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    };
    let rels: Vec<(String, String, String, bool, bool)> = sqlx::query_as(SQL_RELATIONS)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| to_store_err("native backup: list relations", e))?;

    let mut exclusions = Vec::new();
    let mut table_names: Vec<(String, String)> = Vec::new();
    let mut sequences = Vec::new();
    for (schema, name, kind, is_partition, ext_owned) in rels {
        let rel = qualified(&schema, &name);
        let reason = if schema == AGE_CATALOG_SCHEMA || ext_owned {
            Some(REASON_EXTENSION)
        } else if age_schemas.contains(&schema) {
            Some(REASON_AGE)
        } else if schema == LEDGER_SCHEMA && name == LEDGER_TABLE {
            Some(REASON_LEDGER)
        } else if kind == "v" || kind == "m" {
            Some(REASON_VIEW)
        } else {
            None
        };
        if let Some(reason) = reason {
            exclusions.push(Exclusion {
                relation: rel,
                reason: reason.to_string(),
            });
            continue;
        }
        match (kind.as_str(), is_partition) {
            ("r", false) => table_names.push((schema, name)),
            ("S", _) => sequences.push((schema, name)),
            _ => {
                return Err(catalog_err(format!(
                    "relation {rel} has relkind {kind} with no backup handler"
                )));
            }
        }
    }

    let dumped: BTreeSet<(String, String)> = table_names.iter().cloned().collect();
    let cols: Vec<(String, String, String, String, String)> = sqlx::query_as(SQL_COLUMNS)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| to_store_err("native backup: list columns", e))?;
    let mut by_table: BTreeMap<(String, String), Vec<ColumnSpec>> = BTreeMap::new();
    for (schema, table, col, type_name, generated) in cols {
        let key = (schema, table);
        if !dumped.contains(&key) {
            continue;
        }
        if !generated.is_empty() {
            exclusions.push(Exclusion {
                relation: format!("{}.{}.{col}", key.0, key.1),
                reason: REASON_GENERATED.to_string(),
            });
            continue;
        }
        if !HANDLED_TYPES.contains(&type_name.as_str()) {
            return Err(catalog_err(format!(
                "column {}.{}.{col} has type {type_name} with no backup handler",
                key.0, key.1
            )));
        }
        by_table.entry(key).or_default().push(ColumnSpec {
            name: col,
            type_name,
        });
    }

    let fks: Vec<(String, String, String, String)> = sqlx::query_as(SQL_FOREIGN_KEYS)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| to_store_err("native backup: list foreign keys", e))?;
    let order = fk_order(&table_names, &fks)?;
    let mut tables = Vec::with_capacity(order.len());
    for (schema, name) in order {
        let columns = by_table
            .remove(&(schema.clone(), name.clone()))
            .unwrap_or_default();
        if columns.is_empty() {
            return Err(catalog_err(format!(
                "table {} has no column to back up",
                qualified(&schema, &name)
            )));
        }
        tables.push(TableSpec {
            schema,
            name,
            columns,
        });
    }
    exclusions.sort_by(|a, b| a.relation.cmp(&b.relation));
    Ok(Catalog {
        tables,
        sequences,
        exclusions,
    })
}

/// A relation's catalog key: `(schema, name)`. A tuple, never the joined
/// display text, so `a.b`/`c` and `a`/`b.c` are two keys (#10051).
type RelKey = (String, String);

/// Kahn's order over the foreign keys among `tables`: a parent before its
/// children, ties by `(schema, name)`, self references ignored. Linear in
/// tables plus edges (with a log factor for the ready set).
fn fk_order(
    tables: &[RelKey],
    fks: &[(String, String, String, String)],
) -> StoreResult<Vec<RelKey>> {
    let known: BTreeSet<RelKey> = tables.iter().cloned().collect();
    let mut parents_left: BTreeMap<RelKey, usize> = known.iter().map(|k| (k.clone(), 0)).collect();
    let mut children: BTreeMap<RelKey, BTreeSet<RelKey>> = BTreeMap::new();
    for (cs, cn, ps, pn) in fks {
        let (child, parent) = ((cs.clone(), cn.clone()), (ps.clone(), pn.clone()));
        if child == parent || !known.contains(&child) || !known.contains(&parent) {
            continue;
        }
        if children.entry(parent).or_default().insert(child.clone()) {
            if let Some(n) = parents_left.get_mut(&child) {
                *n = n.saturating_add(1);
            }
        }
    }
    let mut ready: BTreeSet<RelKey> = parents_left
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(k, _)| k.clone())
        .collect();
    let mut out = Vec::with_capacity(tables.len());
    while let Some(next) = ready.pop_first() {
        if let Some(kids) = children.get(&next) {
            for kid in kids {
                if let Some(n) = parents_left.get_mut(kid) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        ready.insert(kid.clone());
                    }
                }
            }
        }
        out.push(next);
    }
    if out.len() != known.len() {
        let placed: BTreeSet<&RelKey> = out.iter().collect();
        let cycle: Vec<String> = known
            .iter()
            .filter(|k| !placed.contains(k))
            .map(|(s, n)| qualified(s, n))
            .collect();
        return Err(catalog_err(format!(
            "foreign keys form a cycle among {}",
            cycle.join(", ")
        )));
    }
    Ok(out)
}

async fn schema_version(tx: &mut Transaction<'_, Postgres>) -> StoreResult<i64> {
    let v: Option<i64> = sqlx::query_scalar(SQL_SCHEMA_VERSION)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| to_store_err("native backup: read schema version", e))?;
    v.ok_or_else(|| catalog_err("public.schema_version holds no rows".to_string()))
}

fn column_list(columns: &[ColumnSpec]) -> String {
    columns
        .iter()
        .map(|c| quote_ident(&c.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Dump every table and sequence of the store into `data` in one snapshot.
pub(super) async fn native_backup_pg(
    pool: &PgPool,
    data: std::fs::File,
) -> StoreResult<NativeDumpBody> {
    let mut file = tokio::fs::File::from_std(data);
    file.set_len(0)
        .await
        .map_err(|e| io_store_err("truncating the data file", &e))?;
    file.seek(SeekFrom::Start(0))
        .await
        .map_err(|e| io_store_err(SEEK_DATA_CONTEXT, &e))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| to_store_err("native backup: begin", e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("native backup: snapshot", e))?;
    let version = schema_version(&mut tx).await?;
    let catalog = read_catalog(&mut tx).await?;

    let mut whole = Sha256::new();
    let mut offset = 0_u64;
    let mut segments = Vec::with_capacity(catalog.tables.len());
    for t in catalog.tables {
        let target = quote_qualified(&t.schema, &t.name);
        let rows: i64 = sqlx::query_scalar(&format!("SELECT count(1) FROM {target}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| to_store_err("native backup: count rows", e))?;
        let rows = to_u64(rows, "row count")?;
        let stmt = format!(
            "COPY (SELECT {} FROM {target} x ORDER BY x::text COLLATE \"C\") \
             TO STDOUT (FORMAT binary)",
            column_list(&t.columns)
        );
        let mut seg = Sha256::new();
        let mut len = 0_u64;
        {
            let mut stream = tx
                .copy_out_raw(&stmt)
                .await
                .map_err(|e| to_store_err("native backup: copy out", e))?;
            while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                let chunk = chunk.map_err(|e| to_store_err("native backup: copy out", e))?;
                file.write_all(&chunk)
                    .await
                    .map_err(|e| io_store_err("writing the data file", &e))?;
                seg.update(&chunk);
                whole.update(&chunk);
                let n = u64::try_from(chunk.len())
                    .map_err(|_| catalog_err("copy chunk length does not fit u64".to_string()))?;
                len = len
                    .checked_add(n)
                    .ok_or_else(|| catalog_err("data length overflows u64".to_string()))?;
            }
        }
        segments.push(TableSegment {
            schema: t.schema,
            name: t.name,
            columns: t.columns,
            rows,
            offset,
            len,
            sha256: hex::encode(seg.finalize()),
        });
        offset = offset
            .checked_add(len)
            .ok_or_else(|| catalog_err("data length overflows u64".to_string()))?;
    }

    let mut sequences = Vec::with_capacity(catalog.sequences.len());
    for (schema, name) in catalog.sequences {
        let (last_value, is_called): (i64, bool) = sqlx::query_as(&format!(
            "SELECT last_value, is_called FROM {}",
            quote_qualified(&schema, &name)
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| to_store_err("native backup: read sequence", e))?;
        sequences.push(SequenceValue {
            schema,
            name,
            last_value,
            is_called,
        });
    }
    tx.commit()
        .await
        .map_err(|e| to_store_err("native backup: end snapshot", e))?;

    file.flush()
        .await
        .map_err(|e| io_store_err("flushing the data file", &e))?;
    file.sync_all()
        .await
        .map_err(|e| io_store_err("syncing the data file", &e))?;
    Ok(NativeDumpBody {
        domain: PG_BACKUP_DOMAIN.to_string(),
        backend: PG_BACKUP_BACKEND.to_string(),
        layout_version: PG_BACKUP_LAYOUT_VERSION,
        schema_version: version,
        tables: segments,
        sequences,
        exclusions: catalog.exclusions,
        data_len: offset,
        data_sha256: hex::encode(whole.finalize()),
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

/// Refuse unless the target's tables, columns and sequences are exactly the
/// artifact's, both ways, keyed by `(schema, name)` (#10044, #10051).
fn check_catalog(body: &NativeDumpBody, target: &Catalog) -> StoreResult<()> {
    let target_tables: BTreeMap<(&str, &str), &TableSpec> = target
        .tables
        .iter()
        .map(|t| ((t.schema.as_str(), t.name.as_str()), t))
        .collect();
    let mut seen = BTreeSet::new();
    for seg in &body.tables {
        let key = (seg.schema.as_str(), seg.name.as_str());
        let q = seg.qualified();
        if !seen.insert(key) {
            return Err(catalog_err(format!(
                "table {q} appears twice in the artifact"
            )));
        }
        let Some(t) = target_tables.get(&key) else {
            return Err(catalog_err(format!(
                "table {q} does not exist on the target"
            )));
        };
        if t.columns != seg.columns {
            return Err(catalog_err(format!(
                "columns of table {q} differ from the target"
            )));
        }
    }
    for (key, t) in &target_tables {
        if !seen.contains(key) {
            return Err(catalog_err(format!(
                "table {} exists on the target but not in the artifact",
                t.qualified()
            )));
        }
    }
    let target_seqs: BTreeSet<(&str, &str)> = target
        .sequences
        .iter()
        .map(|(s, n)| (s.as_str(), n.as_str()))
        .collect();
    let mut seen_seqs = BTreeSet::new();
    for s in &body.sequences {
        let key = (s.schema.as_str(), s.name.as_str());
        let q = qualified(&s.schema, &s.name);
        if !seen_seqs.insert(key) {
            return Err(catalog_err(format!(
                "sequence {q} appears twice in the artifact"
            )));
        }
        if !target_seqs.contains(&key) {
            return Err(catalog_err(format!(
                "sequence {q} does not exist on the target"
            )));
        }
    }
    for key in &target_seqs {
        if !seen_seqs.contains(key) {
            return Err(catalog_err(format!(
                "sequence {} exists on the target but not in the artifact",
                qualified(key.0, key.1)
            )));
        }
    }
    Ok(())
}

/// Stream one segment of the data file into an open `COPY FROM STDIN`,
/// re-hashing it as it is read.
async fn feed_segment(
    copy: &mut sqlx::postgres::PgCopyIn<&mut sqlx::PgConnection>,
    file: &mut tokio::fs::File,
    seg: &TableSegment,
    buf: &mut [u8],
) -> StoreResult<()> {
    file.seek(SeekFrom::Start(seg.offset))
        .await
        .map_err(|e| io_store_err(SEEK_DATA_CONTEXT, &e))?;
    let mut hash = Sha256::new();
    let mut left = seg.len;
    while left > 0 {
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| catalog_err("chunk buffer too small".to_string()))?;
        file.read_exact(chunk)
            .await
            .map_err(|e| io_store_err("reading the data file", &e))?;
        hash.update(&*chunk);
        copy.send(&*chunk)
            .await
            .map_err(|e| to_store_err(COPY_IN_CONTEXT, e))?;
        let n = u64::try_from(want)
            .map_err(|_| catalog_err("chunk length does not fit u64".to_string()))?;
        left = left.saturating_sub(n);
    }
    if hex::encode(hash.finalize()) != seg.sha256 {
        return Err(NativeBackupError::DigestMismatch {
            table: seg.qualified(),
        }
        .into());
    }
    Ok(())
}

/// Map a failed `SET LOCAL session_replication_role`: SQLSTATE 42501 is the
/// exact [`NativeBackupError::InsufficientPrivilege`] (#10047), anything
/// else keeps its context.
fn replica_role_err(e: sqlx::Error, context: &str) -> StoreError {
    match &e {
        sqlx::Error::Database(db)
            if db.code().as_deref() == Some(SQLSTATE_INSUFFICIENT_PRIVILEGE) =>
        {
            NativeBackupError::InsufficientPrivilege.into()
        }
        _ => to_store_err(context, e),
    }
}

/// Refuse unless every label table of the AGE graph is empty (#10045).
/// `ONLY` so a row is attributed to the label table that holds it, not to
/// the parent label it inherits from.
async fn check_age_graph_empty(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    let labels: Vec<(String, String)> = sqlx::query_as(SQL_AGE_LABEL_TABLES)
        .bind(AGE_GRAPH_NAME)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| to_store_err("native restore: list AGE labels", e))?;
    for (schema, name) in labels {
        // Locked like the dumped tables, so no writer can add a vertex or an
        // edge between this check and the re-projection.
        sqlx::query(&format!(
            "LOCK TABLE ONLY {} IN ACCESS EXCLUSIVE MODE",
            quote_qualified(&schema, &name)
        ))
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("native restore: lock AGE labels", e))?;
        let any: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM ONLY {})",
            quote_qualified(&schema, &name)
        ))
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| to_store_err("native restore: AGE emptiness check", e))?;
        if any {
            return Err(NativeBackupError::TargetNotEmpty {
                table: qualified(&schema, &name),
            }
            .into());
        }
    }
    Ok(())
}

/// Refuse when a dumped table carries a trigger that replica mode leaves on
/// or a rewrite rule (#10048): the load must not run any user code.
async fn check_no_active_triggers_or_rules(
    tx: &mut Transaction<'_, Postgres>,
    body: &NativeDumpBody,
) -> StoreResult<()> {
    let dumped: BTreeSet<(&str, &str)> = body
        .tables
        .iter()
        .map(|t| (t.schema.as_str(), t.name.as_str()))
        .collect();
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(SQL_ACTIVE_TRIGGERS_AND_RULES)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| to_store_err("native restore: list triggers and rules", e))?;
    match rows
        .into_iter()
        .find(|(s, n, _, _)| dumped.contains(&(s.as_str(), n.as_str())))
    {
        Some((schema, name, kind, rule)) => Err(NativeBackupError::ActiveTriggerOrRule {
            table: qualified(&schema, &name),
            kind,
            name: rule,
        }
        .into()),
        None => Ok(()),
    }
}

/// Re-project every `memory_links` row into AGE in keyset pages of
/// [`LINK_PAGE_ROWS`] (#10046), the stamps rendered by the live writers'
/// SSOT (#10049). Fails closed: a link that cannot be projected refuses the
/// restore rather than leaving the graph behind the relational rows.
async fn reproject_links(tx: &mut Transaction<'_, Postgres>) -> StoreResult<u64> {
    let mut projected = 0_u64;
    let mut after: Option<(String, String, String)> = None;
    loop {
        let page: Vec<LinkRow> = match &after {
            None => {
                sqlx::query_as(SQL_LINKS_FIRST_PAGE)
                    .bind(LINK_PAGE_ROWS)
                    .fetch_all(&mut **tx)
                    .await
            }
            Some((s, t, r)) => {
                sqlx::query_as(SQL_LINKS_NEXT_PAGE)
                    .bind(s)
                    .bind(t)
                    .bind(r)
                    .bind(LINK_PAGE_ROWS)
                    .fetch_all(&mut **tx)
                    .await
            }
        }
        .map_err(|e| to_store_err("native restore: read links", e))?;
        let full = i64::try_from(page.len()).is_ok_and(|n| n == LINK_PAGE_ROWS);
        for (src, tgt, rel, vf, vu) in page {
            project_link_into_age(tx, &src, &tgt, &rel, vf, vu).await?;
            projected = projected.saturating_add(1);
            after = Some((src, tgt, rel));
        }
        if !full {
            return Ok(projected);
        }
    }
}

/// Restore a verified backup into an empty, freshly migrated store, in one
/// transaction.
pub(super) async fn native_restore_pg(
    pool: &PgPool,
    backup: VerifiedPgBackup,
) -> StoreResult<NativeRestoreReport> {
    let (body, data) = backup.into_parts();
    let mut file = tokio::fs::File::from_std(data);
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| to_store_err("native restore: begin", e))?;

    let target_version = schema_version(&mut tx).await?;
    if target_version != body.schema_version {
        return Err(NativeBackupError::SchemaMismatch {
            artifact: body.schema_version,
            target: target_version,
        }
        .into());
    }
    check_catalog(&body, &read_catalog(&mut tx).await?)?;

    if !body.tables.is_empty() {
        let list: Vec<String> = body
            .tables
            .iter()
            .map(|t| quote_qualified(&t.schema, &t.name))
            .collect();
        sqlx::query(&format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
            list.join(", ")
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("native restore: lock tables", e))?;
    }
    // Re-read under the locks: no DDL can have slipped in between.
    check_catalog(&body, &read_catalog(&mut tx).await?)?;

    for seg in &body.tables {
        let any: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {})",
            quote_qualified(&seg.schema, &seg.name)
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| to_store_err("native restore: emptiness check", e))?;
        if any {
            return Err(NativeBackupError::TargetNotEmpty {
                table: seg.qualified(),
            }
            .into());
        }
    }

    let age_present: bool = sqlx::query_scalar(SQL_AGE_PRESENT)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| to_store_err("native restore: probe AGE catalog", e))?;
    if age_present {
        check_age_graph_empty(&mut tx).await?;
    }
    check_no_active_triggers_or_rules(&mut tx, &body).await?;

    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .map_err(|e| replica_role_err(e, "native restore: triggers off"))?;
    let mut buf = vec![0_u8; PG_BACKUP_CHUNK_BYTES];
    let mut rows_total = 0_u64;
    for seg in &body.tables {
        let stmt = format!(
            "COPY {} ({}) FROM STDIN (FORMAT binary)",
            quote_qualified(&seg.schema, &seg.name),
            column_list(&seg.columns)
        );
        let mut copy = tx
            .copy_in_raw(&stmt)
            .await
            .map_err(|e| to_store_err(COPY_IN_CONTEXT, e))?;
        if let Err(e) = feed_segment(&mut copy, &mut file, seg, &mut buf).await {
            if let Err(abort) = copy.abort("ai-memory native restore refused").await {
                tracing::warn!(error = %abort, "native restore: copy abort after refusal");
            }
            return Err(e);
        }
        let loaded = copy
            .finish()
            .await
            .map_err(|e| to_store_err(COPY_IN_CONTEXT, e))?;
        if loaded != seg.rows {
            return Err(NativeBackupError::RowCountMismatch {
                table: seg.qualified(),
                expected: seg.rows,
                actual: loaded,
            }
            .into());
        }
        rows_total = rows_total.saturating_add(loaded);
    }

    for s in &body.sequences {
        sqlx::query("SELECT setval($1::regclass, $2, $3)")
            .bind(quote_qualified(&s.schema, &s.name))
            .bind(s.last_value)
            .bind(s.is_called)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("native restore: set sequence", e))?;
    }

    let has = |t: (&str, &str)| body.tables.iter().any(|s| s.schema == t.0 && s.name == t.1);
    let leases_clamped = if has(LEASES_TABLE) {
        sqlx::query(
            "UPDATE public.leases \
             SET expires_at = extract(epoch FROM clock_timestamp())::bigint \
             WHERE expires_at > extract(epoch FROM clock_timestamp())::bigint",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("native restore: clamp leases", e))?
        .rows_affected()
    } else {
        0
    };

    sqlx::query("SET LOCAL session_replication_role = origin")
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("native restore: triggers on", e))?;

    let age_edges_projected = if age_present && has(LINKS_TABLE) {
        reproject_links(&mut tx).await?
    } else {
        0
    };

    tx.commit()
        .await
        .map_err(|e| to_store_err("native restore: commit", e))?;
    Ok(NativeRestoreReport {
        tables: u64::try_from(body.tables.len()).unwrap_or(u64::MAX),
        rows: rows_total,
        sequences: u64::try_from(body.sequences.len()).unwrap_or(u64::MAX),
        leases_clamped,
        age_edges_projected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str, n: &str) -> (String, String) {
        (s.to_string(), n.to_string())
    }

    fn fk(c: &str, p: &str) -> (String, String, String, String) {
        (
            "public".to_string(),
            c.to_string(),
            "public".to_string(),
            p.to_string(),
        )
    }

    #[test]
    fn fk_order_parents_first_ties_by_name_self_ignored_10021() {
        let tables = [t("public", "c"), t("public", "b"), t("public", "a")];
        let fks = [fk("a", "c"), fk("b", "b"), fk("a", "b")];
        let got = fk_order(&tables, &fks).expect("order");
        assert_eq!(
            got,
            vec![t("public", "b"), t("public", "c"), t("public", "a")]
        );
    }

    #[test]
    fn fk_order_refuses_a_cycle_exactly_10021() {
        let tables = [t("public", "a"), t("public", "b"), t("public", "z")];
        let fks = [fk("a", "b"), fk("b", "a")];
        let err = fk_order(&tables, &fks).expect_err("cycle");
        assert_eq!(
            err.to_string(),
            StoreError::from(NativeBackupError::CatalogMismatch {
                detail: "foreign keys form a cycle among public.a, public.b".to_string()
            })
            .to_string()
        );
    }

    /// #10051: `a.b`/`c` and `a`/`b.c` share the display text `a.b.c` but are
    /// two relations; neither the order nor the catalog check may merge them.
    #[test]
    fn catalog_keys_never_collide_on_dotted_names_10051() {
        let tables = [t("a.b", "c"), t("a", "b.c")];
        let fks = [(
            "a.b".to_string(),
            "c".to_string(),
            "a".to_string(),
            "b.c".to_string(),
        )];
        let got = fk_order(&tables, &fks).expect("order");
        assert_eq!(got, vec![t("a", "b.c"), t("a.b", "c")]);

        let spec = |s: &str, n: &str| TableSpec {
            schema: s.to_string(),
            name: n.to_string(),
            columns: vec![ColumnSpec {
                name: "id".to_string(),
                type_name: "text".to_string(),
            }],
        };
        let seg = |s: &str, n: &str| TableSegment {
            schema: s.to_string(),
            name: n.to_string(),
            columns: spec(s, n).columns,
            rows: 0,
            offset: 0,
            len: 0,
            sha256: String::new(),
        };
        let body = |tables: Vec<TableSegment>| NativeDumpBody {
            domain: PG_BACKUP_DOMAIN.to_string(),
            backend: PG_BACKUP_BACKEND.to_string(),
            layout_version: PG_BACKUP_LAYOUT_VERSION,
            schema_version: 1,
            tables,
            sequences: Vec::new(),
            exclusions: Vec::new(),
            data_len: 0,
            data_sha256: String::new(),
            created_at: String::new(),
        };
        let target = Catalog {
            tables: vec![spec("a.b", "c"), spec("a", "b.c")],
            sequences: Vec::new(),
            exclusions: Vec::new(),
        };
        check_catalog(&body(vec![seg("a.b", "c"), seg("a", "b.c")]), &target)
            .expect("both relations match");
        let err = check_catalog(&body(vec![seg("a.b", "c")]), &target).expect_err("one missing");
        assert_eq!(
            err.to_string(),
            StoreError::from(NativeBackupError::CatalogMismatch {
                detail: "table a.b.c exists on the target but not in the artifact".to_string()
            })
            .to_string()
        );
    }

    #[test]
    fn quote_qualified_doubles_every_quote_10021() {
        assert_eq!(
            quote_qualified("pu\"b", "t\"\"x"),
            "\"pu\"\"b\".\"t\"\"\"\"x\""
        );
    }
}
