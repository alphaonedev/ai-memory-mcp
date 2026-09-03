// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3198 / #3355 — integration-test keystore sandbox.
//!
//! `default_key_dir` refuses a group/world-writable key directory. Self-hosted
//! CI (umask 0002) has a real `~/.config/ai-memory/keys` at `0o775`, so any
//! integration binary that resolves the production default dir fails closed
//! against the host keystore. Pin `AI_MEMORY_KEY_DIR` at a 0700 tempdir
//! instead. Never chmod the operator's real keys.
//!
//! Include with `#[path = "common/key_dir_sandbox.rs"] mod key_dir_sandbox;`
//! (a subdirectory so cargo does not treat this file as its own test crate)
//! and call [`pin`] once per binary (`OnceLock`). For `assert_cmd` children,
//! also `.env("AI_MEMORY_KEY_DIR", key_dir_sandbox::pin())`.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::sync::OnceLock;

/// Process-wide 0700 key directory + `AI_MEMORY_KEY_DIR` pin. Idempotent.
///
/// #3355 — this now DELEGATES to
/// `ai_memory::identity::keypair::install_test_key_dir_sandbox`, the single
/// cross-crate mechanism, instead of keeping a second copy of the same
/// tempdir-and-pin logic here. Two implementations of "the sandbox" is how
/// #3355 happened in the first place: the library had one (behind
/// `cfg(test)`, invisible to integration tests) and the test tree had
/// another, and neither knew about the other. There is exactly one now, and
/// it verifies at arm time that the pin actually took effect.
pub fn pin() -> &'static std::path::Path {
    static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    DIR.get_or_init(ai_memory::identity::keypair::install_test_key_dir_sandbox)
        .as_path()
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
