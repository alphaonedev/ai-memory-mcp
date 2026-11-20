// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Root-independent unix-socket path for hub test fixtures (#9562).
//!
//! `AF_UNIX` `sun_path` is 104 bytes on macOS and 108 on Linux, and the product
//! refuses a longer path (`MAX_SOCKET_PATH_BYTES`, 100). A fixture that
//! builds the socket path under the workspace root therefore fails on a
//! runner whose checkout path is long. This helper makes the length a
//! constant instead: the socket lives in a directory the test creates inside
//! its own scratch tree (so no file leaves the checkout and it is removed with
//! the scratch tree), the product is handed the RELATIVE path
//! [`SOCKET_ARG`], and every child that binds or connects is started with that
//! directory as its working directory.
//!
//! The test process itself NEVER changes its own working directory (it is
//! process-wide and tests run in parallel); only children get
//! [`set_socket_cwd`].
//!
//! The argument carries a directory component on purpose: the product's
//! `prepare_socket_path` takes `path.parent()`, and a bare file name has the
//! parent `""`, which cannot be stat'ed. `./wake-hub.sock` has the parent `.`,
//! the owner-only socket directory.
//!
//! Take it with the `#[path]` leaf idiom:
//!
//! ```ignore
//! #[path = "common/short_sock.rs"]
//! mod short_sock;
//! ```

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The socket path handed to the product: relative, constant length.
pub const SOCKET_ARG: &str = "./wake-hub.sock";

/// The directory name of the socket directory inside the runtime directory.
pub const SOCKET_DIR_NAME: &str = "hub";

/// Create (0700) the socket directory under `run` and return it.
pub fn create_socket_dir(run: &Path) -> PathBuf {
    let dir = socket_dir(run);
    std::fs::create_dir_all(&dir).expect("create the socket dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("chmod the socket dir 0700");
    dir
}

/// The socket directory under `run` (not created).
#[must_use]
pub fn socket_dir(run: &Path) -> PathBuf {
    run.join(SOCKET_DIR_NAME)
}

/// The path handed to the product: [`SOCKET_ARG`] for any `run`.
#[must_use]
pub fn socket_arg(_run: &Path) -> PathBuf {
    PathBuf::from(SOCKET_ARG)
}

/// Where the socket file really is (for assertions on the file system only,
/// never handed to a child).
#[must_use]
pub fn socket_file(run: &Path) -> PathBuf {
    socket_dir(run).join(&SOCKET_ARG[2..])
}

/// Start `cmd` with the socket directory as its working directory.
pub fn set_socket_cwd(cmd: &mut Command, run: &Path) {
    cmd.current_dir(socket_dir(run));
}
