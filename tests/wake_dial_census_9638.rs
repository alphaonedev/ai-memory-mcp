//! #9638 — every wake-plane client dials the hub socket through ONE preflight.
//!
//! A `UnixStream::connect` in `src` that does not go through
//! `ai_memory::wake_client::dial` is a dialer that can hand a frame to a socket
//! another local user owns or can write to. This census fails on any such
//! site, and on a growth of the two reviewed exceptions.

use std::fs;
use std::path::{Path, PathBuf};

/// The constructs that open a client stream to a Unix socket.
const DIAL_PATTERNS: [&str; 3] = [
    "UnixStream::connect",
    "UnixStream::from_std",
    "UnixSocket::new",
];

/// The one file that may dial: the shared preflight helper.
const HELPER: &str = "src/wake_client/dial.rs";

/// Reviewed exceptions: (file, exact count). Each opens a connection to a hub
/// socket and sends NOTHING on it (a liveness probe), so the preflight has no
/// frame to protect.
const SEND_NOTHING_PROBES: [(&str, usize); 2] = [
    // The health probe: connect, then drop (`src/wake_hub/health.rs`).
    ("src/wake_hub/health.rs", 1),
    // The hub's own stale-socket probe before it unlinks (`startup.rs`).
    ("src/wake_hub/startup.rs", 1),
];

/// Count dial constructs outside comment lines.
fn dial_sites(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            DIAL_PATTERNS
                .iter()
                .filter(|pattern| line.contains(**pattern))
                .count()
        })
        .sum()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).expect("read_dir");
    for entry in entries {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_census_scan_sees_a_dial_and_ignores_a_comment_9638() {
    assert_eq!(dial_sites("let s = UnixStream::connect(p).await?;"), 1);
    assert_eq!(
        dial_sites("let s = std::os::unix::net::UnixStream::connect(p)?;"),
        1
    );
    assert_eq!(dial_sites("let s = UnixStream::from_std(raw)?;"), 1);
    assert_eq!(
        dial_sites("let s = tokio::net::UnixSocket::new_stream()?;"),
        1
    );
    assert_eq!(dial_sites("SslmodeFloor::UnixSocket { dir } => {"), 0);
    assert_eq!(
        dial_sites("    // UnixStream::connect is only named here"),
        0
    );
    assert_eq!(dial_sites("let ok = 1;"), 0);
}

#[test]
fn every_wake_plane_dialer_goes_through_the_shared_preflight_9638() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 100, "the scan must really walk src");

    let mut offenders = Vec::new();
    let mut helper_sites = 0;
    for file in files {
        let rel = file
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let count = dial_sites(&fs::read_to_string(&file).expect("read"));
        if count == 0 {
            continue;
        }
        if rel == HELPER {
            helper_sites = count;
            continue;
        }
        let allowed = SEND_NOTHING_PROBES
            .iter()
            .find(|(path, _)| *path == rel)
            .map_or(0, |(_, n)| *n);
        if count != allowed {
            offenders.push(format!("{rel}: {count} dial site(s), {allowed} allowed"));
        }
    }
    assert!(
        offenders.is_empty(),
        "a Unix-socket dial outside {HELPER}: {offenders:?}"
    );
    assert!(
        helper_sites >= 1,
        "{HELPER} must hold the dial, so the census cannot pass by deleting it"
    );
}
