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
