//! #9509 class cell - the offline embedder prerequisite gives the same verdict
//! on a host with a real cache, a staged cache and no cache, whatever an
//! earlier test did to `HOME`.
//!
//! CI run 44385237399 (PR 9531): b3 failed with "prerequisite missing: offline
//! embedder cache" because an earlier lib test had changed `HOME`; CI run
//! 44466391332 then showed the first form of this cell reading the RUNNER: its
//! child inherited `XDG_CONFIG_HOME`, so the config test it ran found the file
//! the parent run of the same test had left there (src/config.rs:11697).
//!
//! Ruling b29 127a16a7 (1): the child runs with a `HOME`, a config directory
//! and a cache directory that the cell builds complete, and reads nothing of
//! the host or the runner. Both child tests live in this module and depend on
//! no file outside what the cell wrote:
//! - `embeddings::offline_home_9509_leaker::home_leaker_9509` changes `HOME`
//!   to a deleted directory (in the child it leaves it changed, the order of
//!   the CI red); it lives in src/embeddings.rs so its write goes through that
//!   file's one env writer (`apply_env`) and this file mutates no env at all
//!   (test-env-lock arm (d), #3475);
//! - [`staged_cache_probe_9509`] runs next (libtest sorts by name: `leaker`
//!   before `tests`) and reports
//!   every path it reads plus the prerequisite verdict of
//!   `with_offline_staged_embedder`, and asserts that verdict equals the cache
//!   on disk at the pinned `HOME` / `HF_HOME`.
//!
//! The cell runs the pair once per row of a table: host state (ambient, real
//! cache, staged cache, no cache: written into the child's inherited
//! environment before the isolation, so the isolation must remove it) times
//! the cell's own cache (staged or none). The cell mutates no process
//! environment itself (the child gets its environment from the spawn).

use super::test_support::{OFFLINE_CACHE_MISS_PREFIX, offline_staged_cache_check};
use super::{HF_CONFIG_FILE, HF_HUB_OFFLINE_ENV, HF_TOKENIZER_FILE, HF_WEIGHTS_FILE};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The module the child filters on.
const CELL_MODULE: &str = "embeddings::offline_home_9509_tests";
/// Child test 1: changes `HOME` to a deleted directory.
const LEAKER: &str = "embeddings::offline_home_9509_leaker::home_leaker_9509";
/// Child test 2: reports the paths it reads and the prerequisite verdict.
const PROBE: &str = "embeddings::offline_home_9509_tests::staged_cache_probe_9509";
/// Set by the cell on its child only: the leaker then leaves `HOME` changed.
pub(super) const CHILD_ROLE_ENV: &str = "CELL_9509_CHILD_ROLE";
/// Probe report prefixes (stderr, one line each).
const PROBE_PATH: &str = "9509-probe path ";
const PROBE_PRESENT: &str = "9509-probe verdict present ";
const PROBE_MISSING: &str = "9509-probe verdict missing: ";
/// The paths the probe reports, sorted.
const PROBE_PATH_NAMES: [&str; 3] = ["config", "home", "temp"];
/// The `refs/main` commit of the hf-hub online layout of the host real cache.
const FAKE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
/// What the parent run of the config write-default test leaves behind.
const EDITED_CONFIG: &str = "# user-edited\n";

fn model_repo(hub: &Path) -> PathBuf {
    hub.join(format!(
        "models--{}",
        super::MINILM_MODEL_ID.replace('/', "--")
    ))
}

fn home_hub(home: &Path) -> PathBuf {
    home.join(".cache")
        .join(crate::config::HF_CACHE_DIR_NAME)
        .join("hub")
}

fn write_model_files(snap: &Path) {
    std::fs::create_dir_all(snap).expect("mk snapshot dir");
    for name in [HF_CONFIG_FILE, HF_TOKENIZER_FILE, HF_WEIGHTS_FILE] {
        std::fs::write(snap.join(name), "{}").expect("write model file");
    }
}

/// The `scripts/ci/stage_hf_cache.py` / air-gap layout: `snapshots/main`.
fn stage_main_layout(hub: &Path) -> PathBuf {
    let snap = model_repo(hub).join("snapshots").join("main");
    write_model_files(&snap);
    snap
}

/// The hf-hub online layout: `refs/main` names `snapshots/<commit>`.
fn stage_commit_layout(hub: &Path) {
    let repo = model_repo(hub);
    write_model_files(&repo.join("snapshots").join(FAKE_COMMIT));
    std::fs::create_dir_all(repo.join("refs")).expect("mk refs dir");
    std::fs::write(repo.join("refs").join("main"), FAKE_COMMIT).expect("write refs/main");
}

/// Oracle of the probe: the model files exist at the pinned process-start
/// `HOME` / `HF_HOME` (the resolver order of `staged_model_snapshot_dir`).
fn pinned_cache_present() -> bool {
    let (home, hf_home) = crate::test_support::pristine_home_env();
    let hub = match hf_home
        .as_ref()
        .and_then(|h| h.to_str())
        .filter(|h| !h.trim().is_empty())
    {
        Some(h) => PathBuf::from(h).join("hub"),
        None => home_hub(Path::new(
            home.as_deref().and_then(|h| h.to_str()).unwrap_or("/root"),
        )),
    };
    let repo = model_repo(&hub);
    let snap = std::fs::read_to_string(repo.join("refs").join("main"))
        .ok()
        .map(|commit| repo.join("snapshots").join(commit.trim()))
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| repo.join("snapshots").join("main"));
    [HF_CONFIG_FILE, HF_TOKENIZER_FILE, HF_WEIGHTS_FILE]
        .iter()
        .all(|name| snap.join(name).exists())
}

/// Reports every path it reads and the prerequisite verdict, and asserts the
/// verdict equals the cache on disk at the pinned `HOME` / `HF_HOME`.
#[test]
fn staged_cache_probe_9509() {
    let paths: [(&str, PathBuf); 3] = {
        let _lock = crate::config::test_env_lock();
        [
            (
                "config",
                crate::config::AppConfig::config_path().unwrap_or_default(),
            ),
            (
                "home",
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default(),
            ),
            ("temp", std::env::temp_dir()),
        ]
    };
    for (name, path) in &paths {
        eprintln!("{PROBE_PATH}{name}={}", path.display());
    }
    let expected = pinned_cache_present();
    let verdict = offline_staged_cache_check();
    match &verdict {
        Ok(config) => eprintln!("{PROBE_PRESENT}{}", config.display()),
        Err(e) => eprintln!("{PROBE_MISSING}{e}"),
    }
    assert_eq!(
        verdict.is_ok(),
        expected,
        "the offline prerequisite must read the cache at the pinned HOME/HF_HOME: {verdict:?}"
    );
}

#[derive(Clone, Copy, Debug)]
enum Host {
    /// The parent's environment as it is.
    Ambient,
    /// A complete hf-hub cache under `HF_HOME`, the edited config file under
    /// `XDG_CONFIG_HOME`, the offline knobs set.
    RealCache,
    /// A complete `snapshots/main` cache under `HOME`, the edited config.
    StagedCache,
    /// `HOME` and `HF_HOME` at empty directories.
    NoCache,
}

#[derive(Clone, Copy, Debug)]
enum CellCache {
    Staged,
    None,
}

const ROWS: [(Host, CellCache); 8] = [
    (Host::Ambient, CellCache::Staged),
    (Host::Ambient, CellCache::None),
    (Host::RealCache, CellCache::Staged),
    (Host::RealCache, CellCache::None),
    (Host::StagedCache, CellCache::Staged),
    (Host::StagedCache, CellCache::None),
    (Host::NoCache, CellCache::Staged),
    (Host::NoCache, CellCache::None),
];

/// The directories the cell builds for its child, all under one root.
struct CellDirs {
    root: tempfile::TempDir,
}

impl CellDirs {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("cell root");
        for name in ["home", "config", "cache", "data", "state", "tmp"] {
            std::fs::create_dir_all(root.path().join(name)).expect("mk cell dir");
        }
        Self { root }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
}

/// Write the host state under `dir` and return the variables a process on
/// that host inherits.
fn host_env(host: Host, dir: &Path) -> Vec<(&'static str, OsString)> {
    let edited_config = |xdg: &Path| {
        let cfg = xdg.join("ai-memory");
        std::fs::create_dir_all(&cfg).expect("mk host config dir");
        std::fs::write(cfg.join("config.toml"), EDITED_CONFIG).expect("write host config");
    };
    let path = |name: &str| {
        let p = dir.join(name);
        std::fs::create_dir_all(&p).expect("mk host dir");
        p.into_os_string()
    };
    match host {
        Host::Ambient => Vec::new(),
        Host::RealCache => {
            stage_commit_layout(&dir.join("hf").join("hub"));
            edited_config(&dir.join("xdg"));
            vec![
                ("HOME", path("home")),
                ("HF_HOME", path("hf")),
                ("XDG_CONFIG_HOME", path("xdg")),
                ("XDG_CACHE_HOME", path("xdg-cache")),
                ("TMPDIR", path("tmp")),
                ("AI_MEMORY_NO_CONFIG", "1".into()),
                (HF_HUB_OFFLINE_ENV, "1".into()),
            ]
        }
        Host::StagedCache => {
            stage_main_layout(&home_hub(&dir.join("home")));
            edited_config(&dir.join("xdg"));
            vec![
                ("HOME", path("home")),
                ("XDG_CONFIG_HOME", path("xdg")),
                ("TMPDIR", path("tmp")),
            ]
        }
        Host::NoCache => vec![
            ("HOME", path("home")),
            ("HF_HOME", path("no-hf")),
            ("TMPDIR", path("tmp")),
        ],
    }
}

/// The child: the leaker and the probe, one thread, with the cell's dirs.
fn child_command(cell: &CellDirs, host: &[(&'static str, OsString)]) -> std::process::Command {
    let mut cmd = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("current_exe"),
        CELL_MODULE,
    );
    cmd.args(["--exact", LEAKER, PROBE, "--nocapture", "--test-threads=1"]);
    // What the child would inherit on that host.
    cmd.envs(host.iter().map(|(k, v)| (*k, v)));
    cmd.env("HOME", cell.dir("home"))
        .env_remove("HF_HOME")
        .env_remove(HF_HUB_OFFLINE_ENV)
        .env_remove("AI_MEMORY_EMBED_OFFLINE")
        .env(CHILD_ROLE_ENV, "1");
    cmd
}

/// Run one row; return its failures (empty = the row holds).
fn run_row(host: Host, cache: CellCache) -> Vec<String> {
    let host_dir = tempfile::tempdir().expect("host dir");
    let cell = CellDirs::new();
    let cell_home = cell.dir("home");
    let snapshot_main = model_repo(&home_hub(&cell_home))
        .join("snapshots")
        .join("main");
    if matches!(cache, CellCache::Staged) {
        stage_main_layout(&home_hub(&cell_home));
    }
    let output = child_command(&cell, &host_env(host, host_dir.path()))
        .output()
        .expect("spawn child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut fails = Vec::new();
    let mut need = |ok: bool, what: String| {
        if !ok {
            fails.push(format!("[{host:?} x {cache:?}] {what}"));
        }
    };
    need(
        output.status.success(),
        format!("child exit: {}", output.status),
    );
    need(
        stdout.contains("running 2 tests"),
        "the child must run exactly the leaker and the probe".to_owned(),
    );
    for test in [LEAKER, PROBE] {
        need(
            stdout.contains(&format!("test {test} ... ok")),
            format!("child test {test} must pass"),
        );
    }
    let mut paths: Vec<(&str, &str)> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix(PROBE_PATH)?.split_once('='))
        .collect();
    paths.sort_unstable();
    let names: Vec<&str> = paths.iter().map(|(n, _)| *n).collect();
    need(
        names == PROBE_PATH_NAMES,
        format!("the probe must report the paths {PROBE_PATH_NAMES:?}, got {names:?}"),
    );
    for (name, path) in &paths {
        need(
            Path::new(path).starts_with(cell.root.path()),
            format!(
                "child path {name}={path} is outside the cell root {}",
                cell.root.path().display()
            ),
        );
    }
    need(
        paths
            .iter()
            .any(|(n, p)| *n == "home" && Path::new(p) != cell_home),
        "the leaker must have changed HOME before the probe ran".to_owned(),
    );
    let verdict = match cache {
        CellCache::Staged => format!(
            "{PROBE_PRESENT}{}",
            snapshot_main.join(HF_CONFIG_FILE).display()
        ),
        CellCache::None => format!(
            "{PROBE_MISSING}{OFFLINE_CACHE_MISS_PREFIX}: {}",
            snapshot_main.display()
        ),
    };
    need(
        stderr.lines().any(|l| l.starts_with(&verdict)),
        format!("the probe verdict must be `{verdict}`"),
    );
    if !fails.is_empty() {
        fails.push(format!(
            "--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
        ));
    }
    fails
}

#[test]
fn staged_cache_verdict_is_host_independent_9509() {
    let failures: Vec<String> = ROWS
        .iter()
        .flat_map(|&(host, cache)| run_row(host, cache))
        .collect();
    assert!(
        failures.is_empty(),
        "#9509 ruling (1): the child reads only what the cell built:\n{}",
        failures.join("\n")
    );
}
