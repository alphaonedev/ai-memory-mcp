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

/// Suffix of the lock file beside each seal (#10193).
const SEAL_LOCK_SUFFIX: &str = ".lock";
/// Mode of a seal lock file (owner only, like the seal itself).
#[cfg(unix)]
const SEAL_LOCK_MODE: u32 = 0o600;

/// The exclusive lock on one seal (#10193): an advisory `flock` on the
/// sibling file `<seal>.lock`, held for the whole read-merge-write of an
/// advance or the write of a replace. Every seal write takes a
/// `&SealLock`, and [`SealLock::acquire`] is its only constructor, so a seal
/// write without the lock does not compile. The lock is released when the
/// guard drops (the file closes). `flock` locks an open file description,
/// so two opens in one process exclude each other as two processes do.
#[derive(Debug)]
pub struct SealLock {
    /// The open lock file; holding it holds the lock.
    _file: std::fs::File,
    /// The seal this lock guards.
    seal: PathBuf,
}

impl SealLock {
    /// Take the exclusive lock on the seal at `seal`, waiting for any other
    /// holder. Precedent: the scope-key store lock
    /// (`encryption::scope::store`, `open_lock_file` and `lock`).
    ///
    /// # Errors
    ///
    /// The seal directory cannot be created, the lock file cannot be opened
    /// (a symlink, a directory or any other open failure), it is not a
    /// regular file, or the lock cannot be taken. Each refuses the write: a
    /// seal is never written unlocked.
    pub fn acquire(seal: &Path) -> Result<Self> {
        let dir = seal
            .parent()
            .context("a seal path always has a parent directory")?;
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let lock = lock_path(seal);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(SEAL_LOCK_MODE);
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(&lock)
            .with_context(|| format!("opening the {SEAL_WHAT} lock {}", lock.display()))?;
        let meta = file
            .metadata()
            .with_context(|| format!("reading the {SEAL_WHAT} lock {}", lock.display()))?;
        if !meta.file_type().is_file() {
            anyhow::bail!(
                "the {SEAL_WHAT} lock {} is not a regular file",
                lock.display()
            );
        }
        lock_exclusive(&file).with_context(|| {
            format!(
                "locking the {SEAL_WHAT} lock {} exclusively",
                lock.display()
            )
        })?;
        Ok(Self {
            _file: file,
            seal: seal.to_path_buf(),
        })
    }
}

/// The lock file of the seal at `seal`: `<seal>.lock`.
fn lock_path(seal: &Path) -> PathBuf {
    let mut name = seal.as_os_str().to_os_string();
    name.push(SEAL_LOCK_SUFFIX);
    PathBuf::from(name)
}

#[cfg(test)]
thread_local! {
    /// Test seam (#10193): make the lock step fail on this thread.
    static REFUSE_SEAL_LOCK_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Take the exclusive `flock` on `file`.
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if REFUSE_SEAL_LOCK_FOR_TEST.with(std::cell::Cell::get) {
        return Err(std::io::Error::other("refused by the test seam"));
    }
    file.lock()
}

fn write_atomic(lock: &SealLock, rec: &SealRecord) -> Result<()> {
    // #8950: stage in a private directory and rename, refusing a symlink at
    // the seal name (never a by-name write that could follow one). The
    // caller holds the seal lock (#10193).
    crate::storage::snapshot_file::write_replacing(&lock.seal, SEAL_WHAT, rec.render().as_bytes())
}

/// What a seal write names in its errors.
const SEAL_WHAT: &str = "row-attestation seal";

/// Move the seal at `path` up to `rec` (field-wise maximum with what it
/// holds; it never moves back). The read and the write run under one
/// [`SealLock`], so a concurrent advance never writes a seal built from a
/// stale read (#10193).
///
/// # Errors
///
/// The seal lock cannot be taken, an unreadable seal (it is never
/// overwritten) or a write failure.
pub fn advance(path: &Path, rec: &SealRecord) -> Result<()> {
    let lock = SealLock::acquire(path)?;
    let next = match read(&lock.seal) {
        SealState::NotSealed => rec.clone(),
        SealState::Sealed(old) => old.merged(rec),
        SealState::Unreadable { path, why } => {
            anyhow::bail!("the anchored seal {} cannot be read: {why}", path.display())
        }
    };
    write_atomic(&lock, &next)
}

/// Replace the seal at `path` with `rec` (a verified restore publishes an
/// older, verified store at this path: an explicit order). It holds the
/// [`SealLock`], so no advance interleaves with it (#10193).
///
/// # Errors
///
/// The seal lock cannot be taken, or a write failure.
pub fn replace(path: &Path, rec: &SealRecord) -> Result<()> {
    let lock = SealLock::acquire(path)?;
    write_atomic(&lock, rec)
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

    /// Writers per round of the #10193 concurrency test.
    const WRITERS_10193: usize = 16;
    /// Rounds of the #10193 concurrency test.
    const ROUNDS_10193: i64 = 12;
    /// How long a seal write is given to (wrongly) finish while another
    /// holder has the seal lock.
    const HELD_PROBE_10193: std::time::Duration = std::time::Duration::from_millis(400);
    /// Upper bound on a seal write once the lock is free.
    const FREE_BOUND_10193: std::time::Duration = std::time::Duration::from_secs(30);

    fn scratch_10193() -> tempfile::TempDir {
        tempfile::tempdir_in(
            std::env::var_os("TMPDIR")
                .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from),
        )
        .expect("tempdir")
    }

    /// The lock file beside a seal: `<seal>.lock` (#10193).
    fn lock_name_10193(seal: &Path) -> std::path::PathBuf {
        let mut name = seal.as_os_str().to_os_string();
        name.push(".lock");
        std::path::PathBuf::from(name)
    }

    /// #10193: many writers advance one seal at once, each with its own table
    /// and a distinct high-water id, released together by a barrier every
    /// round. After every round the seal verifies (it parses) and holds every
    /// writer's mark of that round: no advance lowers or drops another's.
    #[test]
    fn concurrent_advances_never_lose_a_mark_10193() {
        let dir = scratch_10193();
        let seal = dir.path().join(SEAL_DIR).join("db");
        let seal = std::sync::Arc::new(seal);
        let start = std::sync::Arc::new(std::sync::Barrier::new(WRITERS_10193));
        let done = std::sync::Arc::new(std::sync::Barrier::new(WRITERS_10193));
        let lost = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let writers: Vec<_> = (0..WRITERS_10193)
            .map(|i| {
                let (seal, start, done, lost) = (
                    std::sync::Arc::clone(&seal),
                    std::sync::Arc::clone(&start),
                    std::sync::Arc::clone(&done),
                    std::sync::Arc::clone(&lost),
                );
                std::thread::spawn(move || {
                    let width = i64::try_from(WRITERS_10193).expect("writers fit i64");
                    let me = i64::try_from(i).expect("index fits i64");
                    for round in 0..ROUNDS_10193 {
                        let mut rec = SealRecord {
                            high_water: round * width + me,
                            heads: BTreeMap::new(),
                        };
                        rec.heads.insert(format!("t{i:02}"), round);
                        start.wait();
                        let wrote = advance(&seal, &rec);
                        if done.wait().is_leader() {
                            let mut want = SealRecord {
                                high_water: round * width + width - 1,
                                heads: BTreeMap::new(),
                            };
                            for w in 0..WRITERS_10193 {
                                want.heads.insert(format!("t{w:02}"), round);
                            }
                            let got = read(&seal);
                            if got != SealState::Sealed(want.clone()) {
                                lost.lock()
                                    .expect("lost list")
                                    .push(format!("round {round}: {got:?}, want {want:?}"));
                            }
                        }
                        wrote.expect("an advance succeeds");
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer thread");
        }
        let lost = lost.lock().expect("lost list");
        assert!(lost.is_empty(), "lost seal marks: {lost:#?}");
    }

    /// #10193: while another holder has the seal lock, neither `advance` nor
    /// `replace` writes; each completes once the lock is released.
    #[cfg(unix)]
    #[test]
    fn seal_writes_wait_for_the_seal_lock_10193() {
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        for (name, write) in rows {
            let dir = scratch_10193();
            let seal = dir.path().join(SEAL_DIR).join("db");
            let rec = |hw: i64| SealRecord {
                high_water: hw,
                heads: BTreeMap::new(),
            };
            replace(&seal, &rec(1)).expect("first seal");
            let held = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_name_10193(&seal))
                .expect("open the lock file");
            held.lock().expect("hold the seal lock");
            let (tx, rx) = std::sync::mpsc::channel();
            let probe_seal = seal.clone();
            let writer = std::thread::spawn(move || {
                let out = write(&probe_seal, &rec(9)).map_err(|e| e.to_string());
                tx.send(out).expect("report");
            });
            assert_eq!(
                rx.recv_timeout(HELD_PROBE_10193),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                "{name} wrote while the seal lock was held"
            );
            assert_eq!(read(&seal), SealState::Sealed(rec(1)), "{name}");
            drop(held);
            assert_eq!(rx.recv_timeout(FREE_BOUND_10193), Ok(Ok(())), "{name}");
            writer.join().expect("writer thread");
            assert_eq!(read(&seal), SealState::Sealed(rec(9)), "{name}");
        }
    }

    /// #10193: a seal lock that cannot be taken (a directory or a symlink at
    /// the lock name) refuses the write with the exact reason and leaves the
    /// seal as it was: never an unlocked write.
    #[cfg(unix)]
    #[test]
    fn seal_lock_failure_refuses_the_write_10193() {
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        let plants: [(&str, fn(&Path, &Path)); 2] = [
            ("directory", |lock, _| {
                std::fs::create_dir(lock).expect("plant a directory");
            }),
            ("symlink", |lock, target| {
                std::os::unix::fs::symlink(target, lock).expect("plant a symlink");
            }),
        ];
        for (name, write) in rows {
            for (plant_name, plant) in plants {
                let dir = scratch_10193();
                let seal = dir.path().join(SEAL_DIR).join("db");
                let rec = |hw: i64| SealRecord {
                    high_water: hw,
                    heads: BTreeMap::new(),
                };
                replace(&seal, &rec(1)).expect("first seal");
                let lock = lock_name_10193(&seal);
                let _ = std::fs::remove_file(&lock);
                plant(&lock, &dir.path().join("elsewhere"));
                let err = write(&seal, &rec(9)).expect_err("no lock, no write");
                assert_eq!(
                    err.to_string(),
                    format!("opening the row-attestation seal lock {}", lock.display()),
                    "{name} / {plant_name}"
                );
                assert_eq!(
                    read(&seal),
                    SealState::Sealed(rec(1)),
                    "{name} / {plant_name}"
                );
                assert!(
                    !dir.path().join("elsewhere").exists(),
                    "{name} / {plant_name}: the lock open followed a link"
                );
            }
        }
    }

    /// #10193: when the `flock` itself fails, `advance` and `replace` refuse
    /// with the exact reason and leave the seal as it was.
    #[test]
    fn seal_flock_failure_refuses_the_write_10193() {
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        for (name, write) in rows {
            let dir = scratch_10193();
            let seal = dir.path().join(SEAL_DIR).join("db");
            let rec = |hw: i64| SealRecord {
                high_water: hw,
                heads: BTreeMap::new(),
            };
            replace(&seal, &rec(1)).expect("first seal");
            REFUSE_SEAL_LOCK_FOR_TEST.with(|c| c.set(true));
            let out = write(&seal, &rec(9));
            REFUSE_SEAL_LOCK_FOR_TEST.with(|c| c.set(false));
            let err = out.expect_err("no lock, no write");
            assert_eq!(
                err.to_string(),
                format!(
                    "locking the row-attestation seal lock {} exclusively",
                    lock_name_10193(&seal).display()
                ),
                "{name}"
            );
            assert_eq!(read(&seal), SealState::Sealed(rec(1)), "{name}");
        }
    }

    /// #10193: a lock name that opens but is not a regular file (a FIFO)
    /// refuses the write with the exact reason.
    #[cfg(unix)]
    #[test]
    fn seal_lock_not_a_regular_file_refuses_the_write_10193() {
        let dir = scratch_10193();
        let seal = dir.path().join(SEAL_DIR).join("db");
        let rec = |hw: i64| SealRecord {
            high_water: hw,
            heads: BTreeMap::new(),
        };
        replace(&seal, &rec(1)).expect("first seal");
        let lock = lock_name_10193(&seal);
        std::fs::remove_file(&lock).expect("remove the lock file");
        let cstr = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).expect("no NUL");
        // SAFETY: a valid NUL-terminated path in a scratch directory this
        // test owns (UNSAFE-01).
        let rc = unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo");
        for (name, write) in [
            ("advance", advance as fn(&Path, &SealRecord) -> Result<()>),
            ("replace", replace),
        ] {
            let err = write(&seal, &rec(9)).expect_err("no lock, no write");
            assert_eq!(
                err.to_string(),
                format!(
                    "the row-attestation seal lock {} is not a regular file",
                    lock.display()
                ),
                "{name}"
            );
            assert_eq!(read(&seal), SealState::Sealed(rec(1)), "{name}");
        }
    }

    /// A seal record with one table head (#10205, #10206).
    fn rec_10205(high_water: i64, head: i64) -> SealRecord {
        let mut rec = SealRecord {
            high_water,
            heads: BTreeMap::new(),
        };
        rec.heads.insert("memories".to_string(), head);
        rec
    }

    /// The permission bits of `path`, following a symlink.
    #[cfg(unix)]
    fn mode_10205(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    /// Set the permission bits of `path`.
    #[cfg(unix)]
    fn set_mode_10205(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Mode of every seal directory a seal write creates (#10205): the
    /// precedent's key-directory mode.
    #[cfg(unix)]
    const SEAL_DIR_MODE_10205: u32 = 0o700;

    /// Run `f` on a thread of its own whose umask is `mask`. `unshare
    /// (CLONE_FS)` gives that thread its own umask, so no other test thread
    /// sees the change.
    #[cfg(target_os = "linux")]
    fn under_umask_10205<T: Send + 'static>(
        mask: libc::mode_t,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        std::thread::spawn(move || {
            // SAFETY: integer-only flag; it unshares this thread's own
            // filesystem attributes (umask, cwd, root) and nothing else
            // (UNSAFE-01).
            let rc = unsafe { libc::unshare(libc::CLONE_FS) };
            assert_eq!(
                rc,
                0,
                "unshare(CLONE_FS): {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: integer-only call; after the unshare it changes the
            // umask of this thread alone (UNSAFE-01).
            unsafe { libc::umask(mask) };
            f()
        })
        .join()
        .expect("umask thread")
    }

    /// #10205: under umask 000 and under 022, the seal directory a seal
    /// write creates is owner-only (0700) and the lock file 0600, as the
    /// scope-store precedent demands. A plain directory created on the same
    /// thread shows that the umask took effect.
    #[cfg(target_os = "linux")]
    #[test]
    fn seal_dir_is_owner_only_under_every_umask_10205() {
        const UMASKS: [libc::mode_t; 2] = [0o000, 0o022];
        for mask in UMASKS {
            let scratch = scratch_10193();
            let anchor = scratch.path().to_path_buf();
            let seal = anchor.join(SEAL_DIR).join("db");
            let probe = anchor.join("probe");
            let (thread_seal, thread_probe) = (seal.clone(), probe.clone());
            let out = under_umask_10205(mask, move || {
                std::fs::create_dir(&thread_probe).expect("probe dir");
                advance(&thread_seal, &rec_10205(1, 1)).map_err(|e| format!("{e:#}"))
            });
            assert_eq!(out, Ok(()), "umask {mask:03o}");
            assert_eq!(
                mode_10205(&probe),
                0o777 & !u32::from(mask),
                "umask {mask:03o} took effect"
            );
            let dir = anchor.join(SEAL_DIR);
            assert_eq!(
                mode_10205(&dir),
                SEAL_DIR_MODE_10205,
                "seal dir, umask {mask:03o}"
            );
            assert_eq!(
                mode_10205(&lock_name_10193(&seal)),
                SEAL_LOCK_MODE,
                "lock, umask {mask:03o}"
            );
            assert_eq!(read(&seal), SealState::Sealed(rec_10205(1, 1)));
        }
    }

    /// #10205: a seal directory another user can write (group or world
    /// write bit) refuses `advance` and `replace` with the exact reason, and
    /// neither the seal nor the lock file is created there.
    #[cfg(unix)]
    #[test]
    fn writable_seal_dir_refuses_the_write_10205() {
        const MODES: [u32; 4] = [0o777, 0o775, 0o770, 0o702];
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        for (name, write) in rows {
            for mode in MODES {
                let scratch = scratch_10193();
                let dir = scratch.path().join(SEAL_DIR);
                std::fs::create_dir(&dir).expect("seal dir");
                set_mode_10205(&dir, mode);
                let seal = dir.join("db");
                let err = write(&seal, &rec_10205(1, 1)).expect_err("a writable seal dir");
                assert_eq!(
                    err.to_string(),
                    format!(
                        "securing the row-attestation seal directory {}",
                        dir.display()
                    ),
                    "{name} / {mode:o}"
                );
                let cause = format!("{:#}", err.root_cause());
                assert!(
                    cause.starts_with(&format!(
                        "key directory {} is group- or world-writable (mode {mode:o}); refusing",
                        dir.display()
                    )),
                    "{name} / {mode:o}: {cause}"
                );
                assert!(!seal.exists(), "{name} / {mode:o}: a seal was written");
                assert!(
                    !lock_name_10193(&seal).exists(),
                    "{name} / {mode:o}: a lock file was created"
                );
                assert_eq!(
                    mode_10205(&dir),
                    mode,
                    "{name} / {mode:o}: no silent repair"
                );
            }
        }
    }

    /// #10205: an owner-only seal directory under an anchor directory another
    /// user can write is refused by the path-chain check, with the exact
    /// reason; nothing is written.
    #[cfg(unix)]
    #[test]
    fn writable_anchor_dir_refuses_the_write_10205() {
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        for (name, write) in rows {
            let scratch = scratch_10193();
            let anchor = scratch.path().join("anchor");
            std::fs::create_dir(&anchor).expect("anchor dir");
            let dir = anchor.join(SEAL_DIR);
            std::fs::create_dir(&dir).expect("seal dir");
            set_mode_10205(&dir, SEAL_DIR_MODE_10205);
            set_mode_10205(&anchor, 0o775);
            let seal = dir.join("db");
            let lock = lock_name_10193(&seal);
            let err = write(&seal, &rec_10205(1, 1)).expect_err("a writable anchor dir");
            assert_eq!(
                err.to_string(),
                format!(
                    "checking the key directories of the row-attestation seal lock {}",
                    lock.display()
                ),
                "{name}"
            );
            let cause = format!("{:#}", err.root_cause());
            assert!(
                cause.starts_with(&format!(
                    "key directory {} is group- or world-writable (mode 775); refusing",
                    anchor.display()
                )),
                "{name}: {cause}"
            );
            assert!(!seal.exists(), "{name}: a seal was written");
            assert!(!lock.exists(), "{name}: a lock file was created");
        }
    }

    /// #10205: a symlink in the path chain that leads to a directory another
    /// user can write (at the seal directory, or at the anchor directory) is
    /// refused with the exact reason; nothing is written behind the link.
    #[cfg(unix)]
    #[test]
    fn symlink_to_a_writable_dir_in_the_chain_refuses_the_write_10205() {
        let rows: [(&str, fn(&Path, &SealRecord) -> Result<()>); 2] =
            [("advance", advance), ("replace", replace)];
        for (name, write) in rows {
            // The seal directory is a link to a world-writable directory.
            let scratch = scratch_10193();
            let open = scratch.path().join("open");
            std::fs::create_dir(&open).expect("open dir");
            set_mode_10205(&open, 0o777);
            let dir = scratch.path().join(SEAL_DIR);
            std::os::unix::fs::symlink(&open, &dir).expect("plant the seal dir link");
            let seal = dir.join("db");
            let err = write(&seal, &rec_10205(1, 1)).expect_err("a linked writable seal dir");
            assert_eq!(
                err.to_string(),
                format!(
                    "securing the row-attestation seal directory {}",
                    dir.display()
                ),
                "{name} / seal dir link"
            );
            assert_eq!(
                std::fs::read_dir(&open).expect("list").count(),
                0,
                "{name} / seal dir link: nothing written behind the link"
            );

            // The anchor directory is a link to a world-writable directory
            // that holds an owner-only seal directory.
            let scratch = scratch_10193();
            let open = scratch.path().join("open");
            std::fs::create_dir(&open).expect("open dir");
            std::fs::create_dir(open.join(SEAL_DIR)).expect("seal dir");
            set_mode_10205(&open.join(SEAL_DIR), SEAL_DIR_MODE_10205);
            set_mode_10205(&open, 0o777);
            let anchor = scratch.path().join("anchor");
            std::os::unix::fs::symlink(&open, &anchor).expect("plant the anchor link");
            let seal = anchor.join(SEAL_DIR).join("db");
            let lock = lock_name_10193(&seal);
            let err = write(&seal, &rec_10205(1, 1)).expect_err("a linked writable anchor");
            assert_eq!(
                err.to_string(),
                format!(
                    "checking the key directories of the row-attestation seal lock {}",
                    lock.display()
                ),
                "{name} / anchor link"
            );
            assert_eq!(
                std::fs::read_dir(open.join(SEAL_DIR))
                    .expect("list")
                    .count(),
                0,
                "{name} / anchor link: nothing written behind the link"
            );
        }
    }

    /// The inode and modification time of the file at `path`.
    #[cfg(unix)]
    fn stamp_10206(path: &Path) -> (u64, std::time::SystemTime) {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path).expect("stat the seal");
        (meta.ino(), meta.modified().expect("mtime"))
    }

    /// #10206: an advance with nothing new (an equal record, a lower one, a
    /// subset of the heads) leaves the seal file as it was: the same inode
    /// and the same modification time, no rewrite. A real advance still
    /// writes.
    #[cfg(unix)]
    #[test]
    fn advance_with_nothing_new_writes_nothing_10206() {
        let scratch = scratch_10193();
        let seal = scratch.path().join(SEAL_DIR).join("db");
        let mut full = rec_10205(5, 7);
        full.heads.insert("leases".to_string(), 3);
        advance(&seal, &full).expect("first seal");
        let before = stamp_10206(&seal);
        let lower = rec_10205(2, 1);
        let none = SealRecord::default();
        for (name, rec) in [("equal", &full), ("lower", &lower), ("empty", &none)] {
            advance(&seal, rec).expect("an advance with nothing new");
            assert_eq!(stamp_10206(&seal), before, "{name}: the seal was rewritten");
            assert_eq!(read(&seal), SealState::Sealed(full.clone()), "{name}");
        }
        let higher = rec_10205(9, 7);
        advance(&seal, &higher).expect("a real advance");
        assert_ne!(stamp_10206(&seal).0, before.0, "a real advance writes");
        assert_eq!(read(&seal), SealState::Sealed(full.merged(&higher)));
    }

    /// #10206: an advance with nothing new still reads and compares under
    /// the seal lock. While another holder has the lock it waits; the holder
    /// lowers the seal (as a restore does) and releases; the advance then
    /// sees the lowered seal and writes its mark, so no mark is lost.
    #[cfg(unix)]
    #[test]
    fn advance_compares_under_the_seal_lock_10206() {
        let scratch = scratch_10193();
        let seal = scratch.path().join(SEAL_DIR).join("db");
        advance(&seal, &rec_10205(5, 5)).expect("first seal");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_name_10193(&seal))
            .expect("open the lock file");
        held.lock().expect("hold the seal lock");
        let (tx, rx) = std::sync::mpsc::channel();
        let probe_seal = seal.clone();
        let writer = std::thread::spawn(move || {
            let out = advance(&probe_seal, &rec_10205(5, 5)).map_err(|e| e.to_string());
            tx.send(out).expect("report");
        });
        assert_eq!(
            rx.recv_timeout(HELD_PROBE_10193),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "an advance with nothing new finished while the seal lock was held"
        );
        std::fs::write(&seal, rec_10205(1, 1).render()).expect("lower the seal under the lock");
        drop(held);
        assert_eq!(rx.recv_timeout(FREE_BOUND_10193), Ok(Ok(())));
        writer.join().expect("writer thread");
        assert_eq!(read(&seal), SealState::Sealed(rec_10205(5, 5)));
    }
}
