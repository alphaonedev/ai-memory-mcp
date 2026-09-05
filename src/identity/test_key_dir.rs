// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared key-directory sandbox for unit and integration tests.
//! Test builds use it as their default; an explicit environment override is still
//! checked and panics if it resolves under HOME.
//! Child processes must receive `AI_MEMORY_KEY_DIR` with [`install`] as its value.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

static DIRECTORY: OnceLock<tempfile::TempDir> = OnceLock::new();

/// Arm the process sandbox without mutating the process environment.
///
/// # Panics
/// Panics if a private temporary directory cannot be allocated outside HOME.
#[must_use]
pub fn install() -> &'static Path {
    DIRECTORY
        .get_or_init(|| {
            let root = std::env::temp_dir()
                .canonicalize()
                .expect("#3355 resolve temporary root");
            let dir = tempfile::tempdir_in(root).expect("#3355 allocate isolated key directory");
            assert_isolated(dir.path());
            dir
        })
        .path()
}

// Lexical normalization happens BEFORE any filesystem access: a rejected path
// must not even stat the operator's keys. Existing isolated paths are then
// canonicalized to reject aliases into HOME, including macOS's /var alias.
fn absolute(path: &Path) -> PathBuf {
    let path = std::path::absolute(path).expect("#3355 resolve absolute test key path");
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

pub(crate) fn assert_isolated(path: &Path) {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .or_else(|| dirs::home_dir().map(PathBuf::into_os_string))
        .expect("#3355 test key isolation requires an identifiable home directory");
    let home = absolute(Path::new(&home));
    let path = absolute(path);
    assert!(
        !path.starts_with(&home),
        "#3355 test key directory resolves under HOME; use identity::test_key_dir::install() or an isolated AI_MEMORY_KEY_DIR"
    );
    let canonical_home = home.canonicalize().unwrap_or(home);
    let mut ancestor = path.as_path();
    loop {
        if let Ok(canonical) = ancestor.canonicalize() {
            assert!(
                !canonical.starts_with(&canonical_home),
                "#3355 test key directory resolves under HOME through an alias"
            );
            break;
        }
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
}
