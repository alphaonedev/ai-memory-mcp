// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared integration-test keystore sandbox (#3198, #3355).
//!
//! Include with `#[path = "common/key_dir_sandbox.rs"] mod key_dir_sandbox;`
//! and call [`pin`] before accessing default keys. This arms the library's
//! test-support override without modifying the process environment.
//! For child processes also pass `.env("AI_MEMORY_KEY_DIR", pin())`.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

/// Shared process-wide sandbox. Pass this path explicitly to child commands.
pub fn pin() -> &'static std::path::Path {
    ai_memory::identity::test_key_dir::install()
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
