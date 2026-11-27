//! The anchored seal (#10087, #10088): the highest `row_attestations` id and
//! the highest table sequence of every attested table that a signing session
//! or a clean verify has seen for one database file, kept beside the trust
//! anchor and outside the database.
//!
//! A direct writer of the database file holds no signing key and cannot
//! write the anchor's key directory (the threat model of #10040). Every
//! element it could remove, replay or roll back inside the file (the
//! `sqlite_sequence` counter, the newest attestations, a superseded
//! attestation, the signature of a cutover) is then compared with marks it
//! cannot lower. The seal also records that the file was armed, so an
//! unsigned cutover in a sealed file is a removed signature and never a
//! pristine watermark to sign (nothing unsigned decides what must be signed).
//!
//! One file per database, named by the SHA-256 of the database's canonical
//! path, under [`SEAL_DIR`] in the anchor directory. The anchor loader skips
//! dot-prefixed names, so the seals are never read as keys.

use super::Attestation;
use super::anchor::AnchorLoad;
use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Directory of the seals inside the anchor directory.
pub const SEAL_DIR: &str = ".row-attest-seals";
/// First line of every seal file.
const SEAL_HEADER: &str = "ai-memory row-attest seal v1";
/// Key of the id high-water line.
const HIGH_WATER_KEY: &str = "high_water";
/// Key of a per-table head line.
const HEAD_KEY: &str = "head";
/// Upper bound on a seal file read (a seal is a few hundred bytes).
const SEAL_MAX_BYTES: u64 = 64 * 1024;

/// The marks one seal records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealRecord {
    /// Highest `row_attestations` id seen.
    pub high_water: i64,
    /// Highest table sequence seen, per attested table.
    pub heads: BTreeMap<String, i64>,
}

impl SealRecord {
    /// The marks of `attestations`.
    #[must_use]
    pub fn of(attestations: &[Attestation]) -> Self {
        let mut rec = Self::default();
        for a in attestations {
            rec.high_water = rec.high_water.max(a.id);
            let head = rec.heads.entry(a.table.clone()).or_insert(a.table_seq);
            *head = (*head).max(a.table_seq);
        }
        rec
    }

    /// The field-wise maximum of `self` and `other` (a seal never moves back).
    #[must_use]
    pub fn merged(mut self, other: &Self) -> Self {
        self.high_water = self.high_water.max(other.high_water);
        for (t, s) in &other.heads {
            let head = self.heads.entry(t.clone()).or_insert(*s);
            *head = (*head).max(*s);
        }
        self
    }

    fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("{SEAL_HEADER}\n{HIGH_WATER_KEY} {}\n", self.high_water);
        for (t, s) in &self.heads {
            let _ = writeln!(out, "{HEAD_KEY} {t} {s}");
        }
        out
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        if lines.next() != Some(SEAL_HEADER) {
            return Err("the header line is not the seal header".to_string());
        }
        let mut high_water = None;
        let mut heads = BTreeMap::new();
        for line in lines {
            let parts: Vec<&str> = line.split(' ').collect();
            match parts.as_slice() {
                [HIGH_WATER_KEY, n] if high_water.is_none() => {
                    high_water = Some(n.parse::<i64>().map_err(|e| format!("{line:?}: {e}"))?);
                }
                [HEAD_KEY, t, n] if !t.is_empty() && !heads.contains_key(*t) => {
                    let n = n.parse::<i64>().map_err(|e| format!("{line:?}: {e}"))?;
                    heads.insert((*t).to_string(), n);
                }
                _ => return Err(format!("unexpected line {line:?}")),
            }
        }
        let high_water = high_water.ok_or_else(|| "no high_water line".to_string())?;
        Ok(Self { high_water, heads })
    }
}

/// What the anchor holds for one database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealState {
    /// No seal: no signing session or clean verify has seen this file, or
    /// the run is unanchored (and so never clean).
    NotSealed,
    /// The recorded marks.
    Sealed(SealRecord),
    /// A seal exists and cannot be read; a defect, never `NotSealed`.
    Unreadable {
        /// The seal file.
        path: PathBuf,
        /// Why it cannot be read.
        why: String,
    },
}

/// The canonical form of a database path: the file itself when it exists,
/// else its canonical parent joined with its name, else the path as given.
fn canonical_db(db: &Path) -> PathBuf {
    if let Ok(p) = db.canonicalize() {
        return p;
    }
    match (db.parent(), db.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            parent
                .canonicalize()
                .map_or_else(|_| db.to_path_buf(), |p| p.join(name))
        }
        _ => db.to_path_buf(),
    }
}

/// The seal file of `db` under the anchor directory `anchor_dir`.
#[must_use]
pub fn seal_path(anchor_dir: &Path, db: &Path) -> PathBuf {
    let digest = Sha256::digest(canonical_db(db).as_os_str().as_encoded_bytes());
    anchor_dir.join(SEAL_DIR).join(hex::encode(digest))
}

/// The seal file of `db` when `anchor` is anchored and `db` names a file
/// (`None` for an unanchored run or an in-memory database).
#[must_use]
pub fn path_for(anchor: &AnchorLoad, db: Option<&Path>) -> Option<PathBuf> {
    let AnchorLoad::Anchored(anchor) = anchor else {
        return None;
    };
    let db = db.filter(|p| !p.as_os_str().is_empty())?;
    Some(seal_path(anchor.source(), db))
}

/// The database file behind `conn` (`None` for an in-memory or temporary one).
#[must_use]
pub fn db_of(conn: &rusqlite::Connection) -> Option<PathBuf> {
    conn.path().filter(|p| !p.is_empty()).map(PathBuf::from)
}

/// Read the seal at `path`.
#[must_use]
pub fn read(path: &Path) -> SealState {
    let unreadable = |why: String| SealState::Unreadable {
        path: path.to_path_buf(),
        why,
    };
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SealState::NotSealed,
        Err(e) => return unreadable(e.to_string()),
        Ok(m) if !m.file_type().is_file() => return unreadable("not a regular file".to_string()),
        Ok(m) if m.len() > SEAL_MAX_BYTES => {
            return unreadable(format!("{} bytes, over {SEAL_MAX_BYTES}", m.len()));
        }
        Ok(_) => {}
    }
    match std::fs::read_to_string(path) {
        Ok(text) => SealRecord::parse(&text).map_or_else(unreadable, SealState::Sealed),
        Err(e) => unreadable(e.to_string()),
    }
}

/// The seal of `db` under `anchor` ([`SealState::NotSealed`] when
/// [`path_for`] is `None`).
#[must_use]
pub fn state_for(anchor: &AnchorLoad, db: Option<&Path>) -> SealState {
    path_for(anchor, db).map_or(SealState::NotSealed, |p| read(&p))
}

fn write_atomic(path: &Path, rec: &SealRecord) -> Result<()> {
    let dir = path
        .parent()
        .context("a seal path always has a parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    // #8950: stage in a private directory and rename, refusing a symlink at
    // the seal name (never a by-name write that could follow one).
    crate::storage::snapshot_file::write_replacing(path, SEAL_WHAT, rec.render().as_bytes())
}

/// What a seal write names in its errors.
const SEAL_WHAT: &str = "row-attestation seal";

/// Move the seal at `path` up to `rec` (field-wise maximum with what it
/// holds; it never moves back).
///
/// # Errors
///
/// An unreadable seal (it is never overwritten) or a write failure.
pub fn advance(path: &Path, rec: &SealRecord) -> Result<()> {
    let next = match read(path) {
        SealState::NotSealed => rec.clone(),
        SealState::Sealed(old) => old.merged(rec),
        SealState::Unreadable { path, why } => {
            anyhow::bail!("the anchored seal {} cannot be read: {why}", path.display())
        }
    };
    write_atomic(path, &next)
}

/// Replace the seal at `path` with `rec` (a verified restore publishes an
/// older, verified store at this path: an explicit order).
///
/// # Errors
///
/// A write failure.
pub fn replace(path: &Path, rec: &SealRecord) -> Result<()> {
    write_atomic(path, rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trips_and_parse_is_strict_10087() {
        let mut rec = SealRecord {
            high_water: 42,
            heads: BTreeMap::new(),
        };
        rec.heads.insert("memories".to_string(), 7);
        rec.heads.insert("leases".to_string(), 3);
        assert_eq!(SealRecord::parse(&rec.render()), Ok(rec.clone()));
        for (text, why) in [
            ("", "the header line is not the seal header"),
            (SEAL_HEADER, "no high_water line"),
            (
                "ai-memory row-attest seal v1\nhigh_water 1\nhigh_water 2",
                "unexpected line \"high_water 2\"",
            ),
            (
                "ai-memory row-attest seal v1\nhigh_water 1\nhead memories 1\nhead memories 2",
                "unexpected line \"head memories 2\"",
            ),
            (
                "ai-memory row-attest seal v1\nhigh_water 1\nextra",
                "unexpected line \"extra\"",
            ),
        ] {
            assert_eq!(SealRecord::parse(text), Err(why.to_string()), "{text:?}");
        }
    }

    #[test]
    fn merged_never_moves_back_10087() {
        let mut low = SealRecord {
            high_water: 5,
            heads: BTreeMap::new(),
        };
        low.heads.insert("memories".to_string(), 9);
        let mut high = SealRecord {
            high_water: 8,
            heads: BTreeMap::new(),
        };
        high.heads.insert("memories".to_string(), 2);
        high.heads.insert("leases".to_string(), 4);
        let m = low.merged(&high);
        assert_eq!(m.high_water, 8);
        assert_eq!(m.heads.get("memories"), Some(&9));
        assert_eq!(m.heads.get("leases"), Some(&4));
    }

    /// #8950: a seal write never follows a symlink planted at the seal name;
    /// it refuses with the exact symlink reason and leaves the link and its
    /// target as they were. A regular seal is still replaced.
    #[cfg(unix)]
    #[test]
    fn seal_write_refuses_a_planted_symlink_8950() {
        let dir = tempfile::tempdir_in(
            std::env::var_os("TMPDIR")
                .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from),
        )
        .expect("tempdir");
        let rec = |hw: i64| SealRecord {
            high_water: hw,
            heads: BTreeMap::new(),
        };
        let target = dir.path().join("outside");
        replace(&target, &rec(1)).expect("seal a regular file");
        let before = std::fs::read_to_string(&target).expect("read target");
        let link = dir.path().join("seal");
        std::os::unix::fs::symlink(&target, &link).expect("plant symlink");
        let rows: [(fn(&Path, &SealRecord) -> Result<()>, String); 2] = [
            (
                replace,
                crate::storage::snapshot_file::symlink_refusal(&link),
            ),
            (
                advance,
                format!(
                    "the anchored seal {} cannot be read: not a regular file",
                    link.display()
                ),
            ),
        ];
        for (write, why) in rows {
            let err = write(&link, &rec(9)).expect_err("a symlinked seal is refused");
            assert_eq!(err.to_string(), why);
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link stays")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_to_string(&target).expect("read"), before);
        }
        replace(&target, &rec(5)).expect("a regular seal is replaced");
        assert_eq!(read(&target), SealState::Sealed(rec(5)));
    }
}
