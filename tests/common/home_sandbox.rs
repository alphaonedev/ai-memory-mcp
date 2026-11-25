// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10007 — test isolation from the operator's HOME.
//!
//! Include with `#[path = "common/home_sandbox.rs"] mod home_sandbox;`.
//!
//! [`real_home`] records the HOME this test process started with, once, before
//! anything rebinds it. [`assert_outside_real_home`] is the guard: it panics
//! when a path the product resolves (the witness key directory, the key
//! directory, the temporary root) lies under that HOME, lexically or through a
//! symlink.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The HOME (and its canonical form) this process started with.
pub struct RealHome {
    /// `$HOME` as the process received it.
    pub lexical: PathBuf,
    /// `$HOME` canonicalized, when it exists.
    pub canonical: Option<PathBuf>,
}

static REAL_HOME: OnceLock<RealHome> = OnceLock::new();

/// The HOME this process started with. The first call records it; every
/// sandbox in this module calls this before rebinding `HOME`.
pub fn real_home() -> &'static RealHome {
    REAL_HOME.get_or_init(|| {
        let lexical = PathBuf::from(std::env::var_os("HOME").expect("#10007 HOME is set"));
        let canonical = std::fs::canonicalize(&lexical).ok();
        RealHome { lexical, canonical }
    })
}

/// #10007 guard — panic when `path` resolves under the real HOME.
pub fn assert_outside_real_home(what: &str, path: &Path) {
    let home = real_home();
    assert!(
        !path.starts_with(&home.lexical),
        "#10007 {what} resolves under the real HOME: {}",
        path.display()
    );
    let resolved = deepest_existing_canonical(path);
    for root in [Some(&home.lexical), home.canonical.as_ref()]
        .into_iter()
        .flatten()
    {
        assert!(
            !resolved.starts_with(root),
            "#10007 {what} resolves under the real HOME through a link: {}",
            resolved.display()
        );
    }
}

/// Canonicalize the deepest existing ancestor of `path` and re-append the
/// rest, so a not-yet-created path is still checked through its links.
fn deepest_existing_canonical(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            return tail.iter().rev().fold(c, |acc, part| acc.join(part));
        }
        match (cur.file_name().map(ToOwned::to_owned), cur.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                cur = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// The process sandbox: a private root outside the real HOME holding the
/// test HOME, its config home and the witness key directory.
pub struct HomeSandbox {
    root: tempfile::TempDir,
}

impl HomeSandbox {
    /// The sandbox root (outside the real HOME).
    pub fn root(&self) -> &Path {
        self.root.path()
    }
    /// The HOME this process now runs under.
    pub fn home(&self) -> PathBuf {
        self.root.path().join(HOME_DIR)
    }
    /// The witness key directory (head-anchor log) of this process.
    pub fn witness_dir(&self) -> PathBuf {
        self.root.path().join(WITNESS_DIR)
    }
}

const HOME_DIR: &str = "home";
const CONFIG_DIR: &str = ".config";
const WITNESS_DIR: &str = "witness-keys";
/// Product env var naming the witness key directory (head-anchor log).
pub const WITNESS_KEY_DIR_ENV: &str = ai_memory::governance::audit::WITNESS_KEY_DIR_ENV;

static SANDBOX: OnceLock<HomeSandbox> = OnceLock::new();

/// `create_dir_all` + `chmod 0700`.
pub fn mkdir_0700(p: &Path) {
    std::fs::create_dir_all(p).expect("#10007 mkdir sandbox dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
            .expect("#10007 chmod 0700 sandbox dir");
    }
}

/// #10007 — install the process sandbox once and return it. Every test and
/// helper of a binary that includes this module calls it FIRST, before any
/// product call that resolves a key, witness or config path.
///
/// It records the real HOME, arms the key-directory sandbox
/// (`test_key_dir::install`, which binds `AI_MEMORY_KEY_DIR`), then binds
/// `HOME`, `XDG_CONFIG_HOME` and the witness key directory env to private
/// directories under a root allocated outside the real HOME.
pub fn install() -> &'static HomeSandbox {
    SANDBOX.get_or_init(|| {
        let _ = real_home();
        let _ = ai_memory::identity::test_key_dir::install();
        let root = tempfile::Builder::new()
            .prefix("home-sandbox-10007-")
            .tempdir_in(ai_memory::identity::test_key_dir::isolated_temp_root())
            .expect("#10007 sandbox root");
        let sandbox = HomeSandbox { root };
        mkdir_0700(sandbox.root());
        let config = sandbox.home().join(CONFIG_DIR);
        mkdir_0700(&config);
        mkdir_0700(&sandbox.witness_dir());
        assert_outside_real_home("sandbox root", sandbox.root());
        // SAFETY: the 2024 edition marks `set_var` unsafe because the
        // environment is process-global. This runs once per process inside the
        // OnceLock initializer, and every test of the including binary calls
        // `install()` before any code that reads these variables, so no thread
        // reads them while they change. Values are sandbox paths only.
        unsafe {
            std::env::set_var("HOME", sandbox.home());
            std::env::set_var("XDG_CONFIG_HOME", &config);
            std::env::set_var(WITNESS_KEY_DIR_ENV, sandbox.witness_dir());
        }
        sandbox
    })
}

/// A private per-test directory under the sandbox root (0700).
pub fn per_test_dir(prefix: &str) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(install().root())
        .expect("#10007 per-test dir");
    mkdir_0700(dir.path());
    dir
}

/// The env a child `ai-memory` process needs so it, too, resolves no path
/// under the real HOME: its own HOME, config home, key dir and witness dir,
/// all under `dir`. Apply after `env_clear()` or on an inheriting command.
pub fn child_env(dir: &Path) -> Vec<(&'static str, PathBuf)> {
    let home = dir.join(HOME_DIR);
    let config = home.join(CONFIG_DIR);
    let keys = dir.join("keys");
    let witness = dir.join(WITNESS_DIR);
    for p in [&config, &keys, &witness] {
        mkdir_0700(p);
    }
    for (what, p) in [("child home", &home), ("child witness dir", &witness)] {
        assert_outside_real_home(what, p);
    }
    vec![
        ("HOME", home),
        ("XDG_CONFIG_HOME", config),
        ("AI_MEMORY_KEY_DIR", keys),
        (WITNESS_KEY_DIR_ENV, witness),
    ]
}

/// #10007 — assert every product path a test process can write resolves
/// outside the real HOME: the witness key directory (head-anchor log), the
/// default key directory and the temporary root.
pub fn assert_process_isolated() {
    let witness = ai_memory::governance::audit::witness_key_dir().expect("#10007 witness dir");
    assert_outside_real_home("witness key directory", &witness);
    let keys = ai_memory::identity::keypair::default_key_dir().expect("#10007 key dir");
    assert_outside_real_home("key directory", &keys);
    assert_outside_real_home("temporary root", &std::env::temp_dir());
}
