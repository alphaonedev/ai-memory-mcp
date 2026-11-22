// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9954 — the shared table of peer server-cert pin-file forms.
//!
//! One table drives both the runtime-loader test (`tls::tests`) and the
//! `doctor --posture enterprise-federation` row tests
//! (`enterprise_federation_posture::peer_pins::tests`), so the doctor
//! verdict and the runtime verdict are checked over the SAME inputs. The
//! expected reasons are written out by hand here, never derived from the
//! loader under test. Every value is generated: no real node fingerprint.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::PEER_FP_FILE_MAX_BYTES;

/// Per-row deadline. A loader that blocks (for example on a FIFO with no
/// writer) fails its row instead of hanging the test binary.
pub(crate) const ROW_DEADLINE: Duration = Duration::from_secs(10);

/// The 100K+ input of the size bound (engineering-process front-load 2).
pub(crate) const OVERSIZE_100K_BYTES: usize = 128 * 1024;

/// Wall-clock ceiling for refusing the 100K+ input.
pub(crate) const OVERSIZE_REFUSAL_CEILING: Duration = Duration::from_secs(2);

/// Rows [`build_cases`] builds: 4 accepted forms and 20 refused forms. A
/// table that loses a row fails the loader test instead of passing smaller.
pub(crate) const CASE_ROWS: usize = 24;

/// The reason text of a deadline miss.
pub(crate) const DEADLINE_MISS: &str = "loader did not return within the row deadline";

/// What the runtime loader (and therefore the doctor row) must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    /// The file parses: `hosts` distinct hosts, `pins` fingerprints.
    Accept { hosts: usize, pins: usize },
    /// The file is refused with exactly this `{e:#}` text.
    Refuse(String),
}

/// One row: a name, the path the env var names, and the expected verdict.
#[derive(Debug, Clone)]
pub(crate) struct PinCase {
    pub(crate) name: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) expect: Expect,
}

/// A generated SHA-256 fingerprint (64 lowercase hex chars) of `seed`.
pub(crate) fn generated_fp_hex(seed: &[u8]) -> String {
    hex::encode(Sha256::digest(seed))
}

/// One valid pin line with a generated fingerprint, for the hardened-env
/// fixtures (`set_fully_hardened_env`, the doctor end-to-end test).
pub(crate) fn valid_pin_line() -> String {
    format!(
        "peer.example {}\n",
        generated_fp_hex(b"9954-hardened-fixture")
    )
}

/// Run `f` on a helper thread and give up after [`ROW_DEADLINE`].
pub(crate) fn with_deadline<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(ROW_DEADLINE).ok()
}

/// The runtime loader's observed verdict on `path`, in the table's own
/// shape: `Accept` with the loaded host and pin counts, or `Refuse` with the
/// `{e:#}` text. A loader that does not return within [`ROW_DEADLINE`] is
/// `Refuse(DEADLINE_MISS)`.
pub(crate) fn loader_verdict(path: &Path) -> Expect {
    let path = path.to_path_buf();
    with_deadline(move || match super::load_peer_fingerprint_map(&path) {
        Ok(pins) => Expect::Accept {
            hosts: pins.host_count(),
            pins: pins.pin_count(),
        },
        Err(e) => Expect::Refuse(format!("{e:#}")),
    })
    .unwrap_or_else(|| Expect::Refuse(DEADLINE_MISS.to_string()))
}

fn no_entries(p: &Path) -> Expect {
    Expect::Refuse(format!(
        "peer fingerprint file {} contained no entries — peer-fingerprint pinning is \
         fail-closed and would reject every peer; add `<host> <sha256-hex>` lines \
         or unset AI_MEMORY_FED_PEER_FINGERPRINTS",
        p.display()
    ))
}

fn not_found(p: &Path) -> Expect {
    Expect::Refuse(format!(
        "failed to read peer fingerprint file from {}: No such file or directory (os error 2)",
        p.display()
    ))
}

fn over_cap(p: &Path) -> Expect {
    Expect::Refuse(format!(
        "peer fingerprint file {} exceeds the 65536-byte cap",
        p.display()
    ))
}

fn write(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write case file");
    p
}

/// `len` bytes: one valid pin line plus one comment line padding to `len`.
fn padded_valid(len: usize) -> Vec<u8> {
    let line = format!("peer.example {}\n", generated_fp_hex(b"9954-padded"));
    let pad = len - line.len();
    let mut body = Vec::with_capacity(len);
    body.push(b'#');
    body.extend(std::iter::repeat_n(b'x', pad - 2));
    body.push(b'\n');
    body.extend_from_slice(line.as_bytes());
    assert_eq!(body.len(), len, "padded body length");
    body
}

/// Build every row under `dir` (a fresh temp dir the caller owns).
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub(crate) fn build_cases(dir: &Path) -> Vec<PinCase> {
    use std::os::unix::fs::PermissionsExt as _;

    let cap = usize::try_from(PEER_FP_FILE_MAX_BYTES).expect("cap fits usize");
    assert_eq!(
        cap, 65_536,
        "the expected reasons below are written for a 64 KiB cap"
    );
    let fp = generated_fp_hex(b"9954-valid");
    let fp2 = generated_fp_hex(b"9954-rotation");
    let mut out = Vec::new();

    let valid = write(dir, "valid", format!("peer.example {fp}\n").as_bytes());
    out.push(PinCase {
        name: "valid one line",
        path: valid.clone(),
        expect: Expect::Accept { hosts: 1, pins: 1 },
    });
    let rotation = write(
        dir,
        "rotation",
        format!("# c\nPeer.Example sha256:{fp}  # note\npeer.example {fp2}\nb.example {fp}\n")
            .as_bytes(),
    );
    out.push(PinCase {
        name: "two hosts, rotation, comments",
        path: rotation,
        expect: Expect::Accept { hosts: 2, pins: 3 },
    });
    let link_ok = dir.join("link-to-valid");
    std::os::unix::fs::symlink(&valid, &link_ok).expect("symlink");
    out.push(PinCase {
        name: "symlink to a valid file",
        path: link_ok,
        expect: Expect::Accept { hosts: 1, pins: 1 },
    });
    let at_cap = write(dir, "at-cap", &padded_valid(cap));
    out.push(PinCase {
        name: "exactly at the cap",
        path: at_cap,
        expect: Expect::Accept { hosts: 1, pins: 1 },
    });

    for (name, body) in [
        ("empty", ""),
        ("whitespace only", "   \n\t\n  \n"),
        ("comment only", "# one\n   # two\n#peer.example deadbeef\n"),
    ] {
        let p = write(dir, name, body.as_bytes());
        let expect = no_entries(&p);
        out.push(PinCase {
            name,
            path: p,
            expect,
        });
    }

    let short = &fp[..63];
    let long = format!("{fp}ab");
    for (name, body, reason) in [
        (
            "wrong length 63",
            format!("peer.example {short}\n"),
            "peer fingerprint file line 1: expected 64 hex chars (optionally with `:` separators), got 63"
                .to_string(),
        ),
        (
            "wrong length 66",
            format!("peer.example {long}\n"),
            "peer fingerprint file line 1: expected 64 hex chars (optionally with `:` separators), got 66"
                .to_string(),
        ),
        (
            "wrong alphabet ascii",
            format!("peer.example {short}g\n"),
            "peer fingerprint file line 1: unexpected character 'g' — entries must be 64 hex chars \
             with optional `:` separators"
                .to_string(),
        ),
        (
            "wrong alphabet multibyte",
            format!("peer.example {short}\u{e9}\n"),
            "peer fingerprint file line 1: unexpected character '\u{e9}' — entries must be 64 hex \
             chars with optional `:` separators"
                .to_string(),
        ),
        (
            "md5 prefix",
            format!("peer.example md5:{}\n", &fp[..32]),
            "peer fingerprint file line 1: unexpected character 'm' — entries must be 64 hex chars \
             with optional `:` separators"
                .to_string(),
        ),
        (
            "sha1 prefix",
            format!("peer.example sha1:{}\n", &fp[..40]),
            "peer fingerprint file line 1: unexpected character 's' — entries must be 64 hex chars \
             with optional `:` separators"
                .to_string(),
        ),
        (
            "sha512 prefix on 64 hex",
            format!("peer.example sha512:{fp}\n"),
            "peer fingerprint file line 1: unexpected character 's' — entries must be 64 hex chars \
             with optional `:` separators"
                .to_string(),
        ),
        (
            "host only",
            "peer.example\n".to_string(),
            "peer fingerprint file line 1: expected `<host> <sha256-hex>`, got only `peer.example`"
                .to_string(),
        ),
        (
            "bad line after a good one",
            format!("peer.example {fp}\nb.example {short}\n"),
            "peer fingerprint file line 2: expected 64 hex chars (optionally with `:` separators), got 63"
                .to_string(),
        ),
    ] {
        let p = write(dir, name, body.as_bytes());
        out.push(PinCase { name, path: p, expect: Expect::Refuse(reason) });
    }

    let missing = dir.join("absent");
    out.push(PinCase {
        name: "missing",
        path: missing.clone(),
        expect: not_found(&missing),
    });
    let dangling = dir.join("dangling");
    std::os::unix::fs::symlink(dir.join("absent-target"), &dangling).expect("symlink");
    out.push(PinCase {
        name: "dangling symlink",
        path: dangling.clone(),
        expect: not_found(&dangling),
    });

    let sub = dir.join("pins.d");
    std::fs::create_dir(&sub).expect("mkdir");
    out.push(PinCase {
        name: "directory",
        path: sub.clone(),
        expect: Expect::Refuse(format!(
            "peer fingerprint file {} is a directory, not a pin file",
            sub.display()
        )),
    });

    let fifo = dir.join("fifo");
    let c_path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(fifo.as_os_str()))
        .expect("no NUL in temp path");
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the
    // call; mkfifo only reads it.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo");
    out.push(PinCase {
        name: "fifo",
        path: fifo.clone(),
        expect: Expect::Refuse(format!(
            "peer fingerprint file {} is not a regular file",
            fifo.display()
        )),
    });

    let bad_utf8 = write(dir, "non-utf8", b"peer.example \xff\xfe\n");
    out.push(PinCase {
        name: "non-UTF-8 bytes",
        path: bad_utf8.clone(),
        expect: Expect::Refuse(format!(
            "peer fingerprint file {} is not valid UTF-8",
            bad_utf8.display()
        )),
    });

    let over = write(dir, "cap-plus-one", &padded_valid(cap + 1));
    out.push(PinCase {
        name: "cap plus one byte",
        path: over.clone(),
        expect: over_cap(&over),
    });
    let big = write(dir, "over-100k", &padded_valid(OVERSIZE_100K_BYTES));
    out.push(PinCase {
        name: "100K+ input",
        path: big.clone(),
        expect: over_cap(&big),
    });

    let unreadable = write(dir, "unreadable", format!("peer.example {fp}\n").as_bytes());
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    // A privileged runner (root, CAP_DAC_OVERRIDE) reads a mode-000 file; then
    // the content verdict applies. Both arms are exact.
    let expect = if std::fs::File::open(&unreadable).is_ok() {
        Expect::Accept { hosts: 1, pins: 1 }
    } else {
        Expect::Refuse(format!(
            "failed to read peer fingerprint file from {}: Permission denied (os error 13)",
            unreadable.display()
        ))
    };
    out.push(PinCase {
        name: "unreadable (mode 000)",
        path: unreadable,
        expect,
    });

    out
}
