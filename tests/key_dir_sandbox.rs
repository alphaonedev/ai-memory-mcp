// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3198 — integration-test keystore sandbox.
//!
//! `default_key_dir` refuses a group/world-writable key directory. Self-hosted
//! CI (umask 0002) has a real `~/.config/ai-memory/keys` at `0o775`, so any
//! integration binary that resolves the production default dir fails closed
//! against the host keystore. Pin `AI_MEMORY_KEY_DIR` at a 0700 tempdir
//! instead. Never chmod the operator's real keys.
//!
//! Include with `#[path = "key_dir_sandbox.rs"] mod key_dir_sandbox;` and
//! call [`pin`] once per binary (OnceLock). For `assert_cmd` children, also
//! `.env("AI_MEMORY_KEY_DIR", key_dir_sandbox::pin())`.

#![allow(dead_code)]

use std::sync::OnceLock;

/// Process-wide 0700 key directory + `AI_MEMORY_KEY_DIR` pin. Idempotent.
pub fn pin() -> &'static std::path::Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let tmp = tempfile::tempdir().expect("#3198 key-dir sandbox");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
                .expect("#3198 chmod 0700 sandbox key dir");
        }
        // SAFETY: OnceLock init runs once per integration binary, before
        // parallel tests that read the var (the same Once pattern as
        // `ensure_no_config_env`).
        unsafe {
            std::env::set_var("AI_MEMORY_KEY_DIR", tmp.path());
        }
        tmp
    })
    .path()
}

/// `create_dir_all` + `chmod 0700`. tempfile / umask 0002 otherwise
/// yields `0o775`, which `#3198` correctly refuses.
pub fn mkdir_0700(p: &std::path::Path) {
    std::fs::create_dir_all(p).expect("#3198 mkdir key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
            .expect("#3198 chmod 0700 key dir");
    }
}
