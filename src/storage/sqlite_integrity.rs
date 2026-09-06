// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3510, extracted from the #3508 hotfix) — the ONE whole-database
//! integrity verdict for a SQLite corpus.
//!
//! # The fail-open this module closes
//!
//! `PRAGMA integrity_check` answering the single word `ok` no longer means
//! "every page in this file was examined".
//!
//! SQLite builds the root-page list for the check from the schema's table
//! hash. Every schema object with NO root page of its own — a `VIEW`, a
//! `VIRTUAL TABLE` — still contributes an entry, and that entry is root page
//! **0** (bundled SQLite 3.46.0, `pragma.c`:
//! `if( HasRowid(pTab) ) aRoot[++cnt] = pTab->tnum;` — `HasRowid` is true for
//! a view, whose `tnum` is 0). When such an entry lands FIRST, `btree.c`
//! reads it as "the list of root pages is incomplete":
//!
//! ```text
//! /* aRoot[0]==0 means this is a partial check */
//! if( aRoot[0]==0 ){
//!   assert( nRoot>1 );
//!   bPartial = 1;
//!   if( aRoot[1]!=1 ) bCkFreelist = 0;
//! }
//! ```
//!
//! and then SKIPS both the freelist scan (`if( bCkFreelist ){ … }`) and the
//! "make sure every page in the file is referenced" pass
//! (`if( !bPartial ){ … "Page %u: never used" … }`) — while still answering
//! `ok`. Which object heads the list is decided by SQLite's schema hash, not
//! by us: the schema v98 `inbox_namespace_aliases` VIEW (#3401) moved a
//! zero-root entry to the head of the ai-memory schema, and the consequence
//! was not cosmetic — `restore` PUBLISHED a snapshot carrying unaccounted
//! pages over the live corpus and the #3131 gate reported nothing.
//! `memories_fts` (FTS5) is a second, older zero-root entry, so any future
//! `CREATE VIEW` / virtual table can re-trigger this. It is a STANDING
//! hazard, which is why the control lives here — one implementation, shared
//! by every product surface that asks SQLite whether a database is sound.
//!
//! # The control
//!
//! When the schema carries a root-less object, re-assert the whole-file page
//! accounting SQLite skipped. Every page of a sound database is exactly one
//! of:
//!
//! * reachable from a b-tree — one `dbstat` row per page, overflow and FTS5
//!   shadow-table pages included;
//! * on the freelist (`PRAGMA freelist_count`);
//! * a pointer-map page (auto-vacuum databases only — see
//!   [`pointer_map_pages`]);
//! * the reserved pending-byte / lock-byte page, which exists only in
//!   databases larger than 1 GiB and never stores content.
//!
//! A file that DECLARES more pages than that carries content SQLite cannot
//! account for — the class `VACUUM INTO` can never produce and the class a
//! truncated, extended or bit-rotted snapshot does.
//!
//! # Posture
//!
//! FAIL CLOSED, and never guess. [`check`] returns
//! [`Soundness::Unsound`] with an operator-facing diagnosis when the file is
//! demonstrably not sound, and an `Err` when the check could not be
//! COMPLETED (a PRAGMA failed, `dbstat` is missing from this build, the
//! per-page reserved-byte count could not be read). "Cannot verify" is never
//! reported as "verified": a caller that `?`s the result therefore refuses
//! rather than publishing a replacement it could not check.
//!
//! This module reads PRAGMAs, `sqlite_master` and `dbstat`, and issues no DDL
//! and no DML. It can neither lose nor corrupt data.
//!
//! # NOT this module
//!
//! [`crate::storage::fts_integrity_check`] is a DIFFERENT mechanism — the
//! FTS5 `integrity-check` command, which validates the full-text index
//! against the `memories` table. It does not go through
//! `PRAGMA integrity_check`, is not affected by the partial-check hazard, and
//! is deliberately left alone (#3510).

use anyhow::{Context, Result};
use rusqlite::Connection;

/// The one verdict `PRAGMA integrity_check` reports for an undamaged
/// database. Anything else is a refusal.
pub const SQLITE_INTEGRITY_OK: &str = "ok";

/// SQLite reserves the page holding byte offset `0x4000_0000` (the "pending
/// byte" / lock-byte page). It exists only in databases larger than 1 GiB,
/// never stores content, and therefore appears neither in `dbstat` nor on the
/// freelist. Mirrors `PENDING_BYTE` in the bundled amalgamation, whose page
/// number is `(PENDING_BYTE/pageSize)+1`.
const SQLITE_PENDING_BYTE: i64 = 0x4000_0000;

/// SQLite refuses to open a database whose USABLE page size (page size minus
/// the per-page reserved bytes) is below this. Used as a sanity floor before
/// any division: an implausible value means we misread the geometry, and a
/// control that misreads the geometry must refuse rather than compute a
/// wrong answer.
const SQLITE_MIN_USABLE_SIZE: i64 = 480;

/// The per-page reserved-byte count is a single unsigned byte in the database
/// header (offset 20), so it can never exceed this.
const SQLITE_MAX_RESERVED_BYTES: i64 = 255;

/// Bytes one pointer-map ENTRY occupies (a 1-byte type plus a 4-byte parent
/// page number), so a pointer-map page describes `usable/5 + 1` pages —
/// `nPagesPerMapPage = (pBt->usableSize/5)+1` in `ptrmapPageno`.
const PTRMAP_BYTES_PER_ENTRY: i64 = 5;

/// The schema whose geometry is being accounted. Every connection this module
/// sees is opened directly on the file under test, so the main schema is the
/// only one in play.
const MAIN_SCHEMA: &std::ffi::CStr = c"main";

/// How much of the file the `ok` verdict returned by [`check`] actually
/// covers. Reported (rather than swallowed) so a caller on an operator
/// surface can SAY which control did the work — the #3508 residual was a
/// `tracing::warn!` no CLI could see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The schema carries no root-less object, so SQLite's own
    /// `integrity_check` ran its freelist scan and its every-page-referenced
    /// pass over the whole file. Nothing to re-assert.
    WholeFileBySqlite,
    /// The schema carries a root-less object, so SQLite's pass may have been
    /// downgraded to a PARTIAL check. This crate re-asserted the skipped
    /// whole-file page accounting, and it holds.
    WholeFileByPageAccounting(PageAccounting),
}

/// The whole-file page census behind [`Coverage::WholeFileByPageAccounting`].
/// Carried out of the check so an operator surface can print the evidence
/// instead of a bare "verified".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageAccounting {
    /// `PRAGMA page_count` — how many pages the file DECLARES.
    pub page_count: i64,
    /// Pages reachable from a b-tree (`SELECT COUNT(*) FROM dbstat`).
    pub reachable: i64,
    /// Pages on the freelist (`PRAGMA freelist_count`).
    pub freelist: i64,
    /// Pointer-map pages (auto-vacuum only; 0 otherwise).
    pub pointer_map: i64,
    /// 1 when the file is large enough to contain the reserved pending-byte
    /// page, 0 otherwise.
    pub pending_byte: i64,
}

impl PageAccounting {
    /// Pages this census can account for. Equals [`Self::page_count`] on a
    /// sound database.
    #[must_use]
    pub fn accounted(&self) -> i64 {
        // Every term is a non-negative page count bounded by the file size,
        // so this cannot overflow an i64; saturate anyway rather than let a
        // hostile header produce a wrapped comparison (PERF-03).
        self.reachable
            .saturating_add(self.freelist)
            .saturating_add(self.pointer_map)
            .saturating_add(self.pending_byte)
    }
}

/// The answer [`check`] gives about a database it COULD examine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Soundness {
    /// The database is sound, and this is how much of it was covered.
    Sound(Coverage),
    /// The database is NOT sound. Carries a self-contained diagnosis clause
    /// — no leading capital, no file name, no consequence — so each surface
    /// can frame it in its own sentence while the DIAGNOSIS has exactly one
    /// implementation.
    Unsound(String),
}

/// Verify that `conn`'s main database is structurally sound, re-asserting the
/// whole-file passes SQLite skips whenever a root-less schema object may have
/// downgraded `PRAGMA integrity_check` to a PARTIAL check (#3508 / #3510).
///
/// This is the ONE integrity verdict in the product: every
/// `PRAGMA integrity_check` call site routes through here (structurally
/// pinned by `tests/sqlite_integrity_call_site_gate_3510.rs`), so a surface
/// cannot accidentally ship the pre-#3508 fail-open again.
///
/// # Errors
/// The check could not be COMPLETED: a PRAGMA or `sqlite_master` query
/// failed, this build has no `dbstat` virtual table, or the geometry needed
/// for the auto-vacuum pointer-map arithmetic could not be read. Never
/// confused with a clean verdict — a caller that `?`s this refuses.
pub fn check(conn: &Connection) -> Result<Soundness> {
    let verdict: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .context("running PRAGMA integrity_check")?;
    if verdict != SQLITE_INTEGRITY_OK {
        return Ok(Soundness::Unsound(format!(
            "FAILED PRAGMA integrity_check ({verdict})"
        )));
    }
    if !has_root_less_schema_object(conn)? {
        // SQLite's own pass cannot have been downgraded, so it already did
        // the freelist scan and the every-page-referenced pass.
        return Ok(Soundness::Sound(Coverage::WholeFileBySqlite));
    }
    let census = page_accounting(conn)?;
    let accounted = census.accounted();
    if accounted != census.page_count {
        return Ok(Soundness::Unsound(format!(
            "declares {declared} pages but only {accounted} are accounted for \
             (b-tree {reachable} + freelist {freelist} + pointer-map \
             {pointer_map} + pending-byte {pending_byte}) — its PRAGMA \
             integrity_check answered `ok` only because a root-less object in \
             the schema downgrades it to a PARTIAL check that skips the \
             freelist scan and the unreferenced-page pass (#3508/#3510)",
            declared = census.page_count,
            reachable = census.reachable,
            freelist = census.freelist,
            pointer_map = census.pointer_map,
            pending_byte = census.pending_byte,
        )));
    }
    Ok(Soundness::Sound(Coverage::WholeFileByPageAccounting(
        census,
    )))
}

/// Does the schema carry an object with NO root page of its own — a `VIEW` or
/// a `VIRTUAL TABLE`? Such an object contributes root page 0 to the
/// `integrity_check` root list and can therefore downgrade the check.
///
/// Deliberately broader than "heads the list": which entry lands first is
/// decided by SQLite's schema hash, which we neither control nor observe. A
/// database whose check was NOT downgraded still satisfies the page-accounting
/// identity, so the conservative reading can only cost a few PRAGMAs — never
/// a false refusal.
fn has_root_less_schema_object(conn: &Connection) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type IN ('view', 'table') AND COALESCE(rootpage, 0) = 0",
            [],
            |r| r.get(0),
        )
        .context("counting the root-less schema objects (#3508)")?;
    Ok(count > 0)
}

/// Take the whole-file page census.
///
/// # Errors
/// Any PRAGMA failure, a missing `dbstat` virtual table (a build without
/// `SQLITE_ENABLE_DBSTAT_VTAB`; every shipped bundle sets it, so its absence
/// means this binary cannot verify what it was asked to verify), an
/// implausible page size, or an unreadable auto-vacuum geometry.
fn page_accounting(conn: &Connection) -> Result<PageAccounting> {
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .context("reading PRAGMA page_count (#3508)")?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .context("reading PRAGMA page_size (#3508)")?;
    let freelist: i64 = conn
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .context("reading PRAGMA freelist_count (#3508)")?;
    let auto_vacuum: i64 = conn
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .context("reading PRAGMA auto_vacuum (#3508)")?;
    let reachable: i64 = conn
        .query_row("SELECT COUNT(*) FROM dbstat", [], |r| r.get(0))
        .context(
            "this build cannot page-account a SQLite database (no dbstat \
             virtual table) and its PRAGMA integrity_check may have run as a \
             PARTIAL check because the schema carries a root-less object \
             (#3508)",
        )?;
    if page_size < SQLITE_MIN_USABLE_SIZE {
        anyhow::bail!(
            "PRAGMA page_size answered {page_size}, below SQLite's minimum of \
             {SQLITE_MIN_USABLE_SIZE} — refusing to page-account a database \
             whose geometry cannot be read (#3510)"
        );
    }
    // `PENDING_BYTE_PAGE(pBt)` is `(PENDING_BYTE/pageSize)+1` — the FULL page
    // size, not the usable size. The page exists only once the file is large
    // enough to contain it.
    let pending_page = SQLITE_PENDING_BYTE / page_size + 1;
    let pending_byte = i64::from(page_count >= pending_page);
    let pointer_map = if auto_vacuum == 0 {
        0
    } else {
        pointer_map_pages(conn, page_size, page_count, pending_page)?
    };
    Ok(PageAccounting {
        page_count,
        reachable,
        freelist,
        pointer_map,
        pending_byte,
    })
}

/// How many of the first `page_count` pages are pointer-map pages?
///
/// Auto-vacuum databases interleave pointer-map pages that belong to no
/// b-tree, are not on the freelist, and therefore appear in neither `dbstat`
/// nor `freelist_count`. Before #3510 this branch degraded to a
/// `tracing::warn!` that no CLI surface could see, which left the restore
/// gate silently uncovered on such a file. The arithmetic is well-defined, so
/// the branch is now a REAL check.
///
/// Derived verbatim from the bundled SQLite 3.46.0 amalgamation
/// (`libsqlite3-sys-0.30.1/sqlite3/sqlite3.c`), `ptrmapPageno`:
///
/// ```text
/// static Pgno ptrmapPageno(BtShared *pBt, Pgno pgno){
///   int nPagesPerMapPage;
///   Pgno iPtrMap, ret;
///   if( pgno<2 ) return 0;
///   nPagesPerMapPage = (pBt->usableSize/5)+1;
///   iPtrMap = (pgno-2)/nPagesPerMapPage;
///   ret = (iPtrMap*nPagesPerMapPage) + 2;
///   if( ret==PENDING_BYTE_PAGE(pBt) ){
///     ret++;
///   }
///   return ret;
/// }
/// ```
///
/// and the pass in `sqlite3BtreeIntegrityCheck` that consumes it
/// (`PTRMAP_PAGENO(pBt, i)==i && pBt->autoVacuum` marks page `i` as a
/// pointer-map page rather than an unused one). A page `p` is a pointer-map
/// page exactly when `ptrmapPageno(p) == p`, i.e. when it is one of
/// `2, 2+N, 2+2N, …` for `N = usable/5 + 1`, with the single entry that would
/// land on the pending-byte page shifted one page later.
///
/// `usableSize` is `pageSize - <reserved bytes>` (`pBt->usableSize =
/// pBt->pageSize - nReserve`), and the reserved-byte count is read from the
/// connection rather than from the file header, so the arithmetic stays exact
/// on the SQLCipher bundle too (whose page 1 is ciphertext on disk).
///
/// # Errors
/// The reserved-byte count could not be read, or the resulting usable size is
/// implausible. Fail closed: an auto-vacuum database whose geometry we cannot
/// read is one we cannot verify.
fn pointer_map_pages(
    conn: &Connection,
    page_size: i64,
    page_count: i64,
    pending_page: i64,
) -> Result<i64> {
    let reserved = reserved_bytes(conn)?;
    let usable = page_size - reserved;
    if usable < SQLITE_MIN_USABLE_SIZE {
        anyhow::bail!(
            "usable page size {usable} (page_size {page_size} - reserved \
             {reserved}) is below SQLite's minimum of \
             {SQLITE_MIN_USABLE_SIZE} — refusing to page-account an \
             auto_vacuum database whose pointer-map geometry cannot be \
             derived (#3510)"
        );
    }
    let pages_per_map_page = usable / PTRMAP_BYTES_PER_ENTRY + 1;
    let mut count = 0_i64;
    let mut base = 2_i64;
    while base <= page_count {
        // The pending-byte page is never a pointer map; SQLite moves that
        // group's pointer map one page later.
        let ptrmap = if base == pending_page { base + 1 } else { base };
        if ptrmap <= page_count {
            count += 1;
        }
        base = base.saturating_add(pages_per_map_page);
    }
    Ok(count)
}

/// The per-page reserved-byte count of the open main database.
///
/// Read through `sqlite3_file_control(SQLITE_FCNTL_RESERVE_BYTES)` rather
/// than from the file header, because a SQLCipher database's page 1 is
/// ciphertext on disk while the connection knows the codec-adjusted geometry
/// (`pBt->usableSize` is set by the codec, not by parsing header byte 20).
///
/// Passing a NEGATIVE value IN means "report, do not change". The bundled
/// amalgamation's handler is unambiguous about it
/// (`libsqlite3-sys-0.30.1/sqlite3/sqlite3.c:183868`):
///
/// ```text
/// }else if( op==SQLITE_FCNTL_RESERVE_BYTES ){
///   int iNew = *(int*)pArg;
///   *(int*)pArg = sqlite3BtreeGetRequestedReserve(pBtree);
///   if( iNew>=0 && iNew<=255 ){
///     sqlite3BtreeSetPageSize(pBtree, 0, iNew, 0);
///   }
///   rc = SQLITE_OK;
/// }
/// ```
///
/// The out-value is written FIRST and the mutating branch is guarded on
/// `iNew >= 0`, so a `-1` in-value is a pure READ — safe on the read-only
/// connection the restore gate uses, and it cannot alter the file this
/// function exists to verify.
///
/// # Errors
/// The file control returned anything other than `SQLITE_OK`, or answered a
/// value outside the 0..=255 range the single header byte can hold. Either
/// way the geometry is UNKNOWN, and unknown is not zero: falling back to a
/// zero reserve would compute a pointer-map count for a geometry this
/// database may not have and turn a fail-closed control into a wrong answer.
/// The caller refuses instead.
fn reserved_bytes(conn: &Connection) -> Result<i64> {
    // Negative in = query only. Never changed, never written back.
    let mut requested: std::ffi::c_int = -1;
    // SAFETY (UNSAFE-01/02/03): `conn` is a live, open `Connection` borrowed
    // for the whole call, so `handle()` yields a valid `*mut sqlite3` that
    // outlives this statement; `MAIN_SCHEMA` is a `'static` NUL-terminated C
    // string; `requested` is a stack `c_int` and its address is exactly the
    // `int*` out-parameter `SQLITE_FCNTL_RESERVE_BYTES` documents. SQLite
    // writes one `int` through that pointer and, because the value passed in
    // is negative, changes nothing. No aliasing (the borrow of `requested`
    // ends with the block), no ownership transfer, and no panic can unwind
    // into C.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            conn.handle(),
            MAIN_SCHEMA.as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
            std::ptr::from_mut(&mut requested).cast::<std::ffi::c_void>(),
        )
    };
    // Unreadable geometry is NOT a zero reserve: refuse rather than compute a
    // pointer-map count for a page layout this database may not have.
    if rc != rusqlite::ffi::SQLITE_OK {
        anyhow::bail!(
            "SQLITE_FCNTL_RESERVE_BYTES answered {rc} (not SQLITE_OK) — \
             refusing to page-account an auto_vacuum database whose per-page \
             reserved-byte count cannot be read (#3510)"
        );
    }
    let reserved = i64::from(requested);
    if !(0..=SQLITE_MAX_RESERVED_BYTES).contains(&reserved) {
        anyhow::bail!(
            "SQLITE_FCNTL_RESERVE_BYTES answered {reserved}, outside the \
             0..={SQLITE_MAX_RESERVED_BYTES} range a single header byte can \
             hold — refusing to page-account an auto_vacuum database whose \
             geometry cannot be trusted (#3510)"
        );
    }
    Ok(reserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly bootstrapped ai-memory database is sound, and — because its
    /// schema carries root-less objects (`memories_fts`, the v98
    /// `inbox_namespace_aliases` view) — the verdict is carried by the
    /// page-accounting control rather than by SQLite's own pass. This is the
    /// positive control: the gate may never refuse a sound corpus.
    #[test]
    fn a_fresh_corpus_is_sound_and_page_accounted_3510() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = crate::db::open(tmp.path()).expect("open");
        match check(&conn).expect("the check must complete") {
            Soundness::Sound(Coverage::WholeFileByPageAccounting(census)) => {
                assert_eq!(
                    census.accounted(),
                    census.page_count,
                    "a sound corpus must account for every declared page"
                );
                assert!(census.reachable > 0, "dbstat must report b-tree pages");
                assert_eq!(census.pointer_map, 0, "ai-memory never enables auto_vacuum");
            }
            Soundness::Sound(Coverage::WholeFileBySqlite) => panic!(
                "the ai-memory schema carries root-less objects, so the \
                 page-accounting control must be the one that answered"
            ),
            Soundness::Unsound(reason) => {
                panic!("a fresh corpus must be sound, got: {reason}")
            }
        }
    }

    /// The negative control on the SAME shape the #3508 defect had: pages
    /// appended past the b-trees and the header's page count raised to match.
    /// Asserts against the OBSERVED `integrity_check` verdict so a future
    /// SQLite that restores the full pass still passes this test — the file
    /// is refused either way, which is the invariant.
    #[test]
    fn unaccounted_pages_are_refused_however_sqlite_answers_3510() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        {
            let conn = crate::db::open(tmp.path()).expect("open");
            assert!(matches!(check(&conn).expect("check"), Soundness::Sound(_)));
        }
        append_unreferenced_pages(tmp.path(), 5);
        let conn = crate::db::open_read_only(tmp.path()).expect("reopen read-only");
        match check(&conn).expect("the check must complete") {
            Soundness::Unsound(reason) => {
                assert!(
                    reason.contains("integrity_check"),
                    "the diagnosis must name the control that failed; got: {reason}"
                );
            }
            Soundness::Sound(coverage) => panic!(
                "a database carrying unreferenced pages must be refused; the \
                 check answered Sound({coverage:?})"
            ),
        }
    }

    /// `PageAccounting::accounted` is the identity the refusal is derived
    /// from; pinned directly so a term can never be dropped silently.
    #[test]
    fn accounted_sums_every_term_3510() {
        let census = PageAccounting {
            page_count: 10,
            reachable: 6,
            freelist: 2,
            pointer_map: 1,
            pending_byte: 1,
        };
        assert_eq!(census.accounted(), 10);
    }

    /// v1.0.0 #3131/#3508 — make a real SQLite file carry unreferenced pages
    /// while still opening and answering schema queries: append whole pages
    /// and raise the header's page-count field (offset 28), stamping the
    /// "version-valid-for" counter (offset 92) to match the change counter
    /// (offset 24) so SQLite trusts the declared size.
    fn append_unreferenced_pages(path: &std::path::Path, pages: usize) {
        let mut bytes = std::fs::read(path).expect("read db file");
        let page_size = match u16::from_be_bytes([bytes[16], bytes[17]]) {
            1 => 65_536_usize,
            n => usize::from(n),
        };
        let declared = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        bytes.extend(std::iter::repeat_n(0u8, page_size * pages));
        let grown = declared + u32::try_from(pages).expect("page delta fits u32");
        bytes[28..32].copy_from_slice(&grown.to_be_bytes());
        let change_counter = [bytes[24], bytes[25], bytes[26], bytes[27]];
        bytes[92..96].copy_from_slice(&change_counter);
        std::fs::write(path, &bytes).expect("write damaged db file");
    }
}
