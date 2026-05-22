// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1070 — pin the no-openssl-sys invariant on the
//! Android transitive graph.
//!
//! Pre-#1070 `hf-hub`'s default features chain
//! (`default = [default-tls, tokio, ureq]` → `default-tls =
//! [native-tls]` → `openssl-sys`) pulled openssl-sys into every
//! build. The Android NDK ships no libssl by default, so the
//! mobile-runtime CI workflow's Android emulator job failed at
//! `cargo test --no-run` with `failed to run custom build command
//! for openssl-sys v0.9.113`.
//!
//! The #1070 fix declares
//! `hf-hub = { default-features = false, features = ["tokio",
//! "ureq", "rustls-tls"] }` in Cargo.toml so the native-tls chain
//! is never enabled. This test shells out to `cargo tree -i
//! openssl-sys --target x86_64-linux-android --no-default-features
//! --features sqlite-bundled` and asserts the package is NOT in the
//! resolved graph for the Android target — a future regression that
//! re-introduces native-tls (via hf-hub defaults or a new
//! native-tls-pinning dep) will fail this pin loudly with a
//! reproducer command in the failure message.
//!
//! Why shell-out vs reading Cargo.lock: `Cargo.lock` records every
//! OPTIONAL dep that COULD activate under some feature/target
//! combination — including `openssl-sys` as a conditional dep of
//! `libsqlite3-sys` when `bundled-sqlcipher-vendored-openssl` is
//! enabled. A Cargo.lock scan would false-positive even when the
//! Android build never compiles openssl-sys. `cargo tree`'s
//! platform-filtered resolution is the load-bearing check.

#[test]
fn android_transitive_graph_has_no_openssl_sys_1070() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "-e",
            "normal",
            "--target",
            "x86_64-linux-android",
            "--no-default-features",
            "--features",
            "sqlite-bundled",
            "-i",
            "openssl-sys",
        ])
        .current_dir(manifest_dir)
        .output()
        .expect("invoke `cargo tree` — required for this test");

    // `cargo tree -i <pkg>` exits with status 101 when the package
    // is NOT in the graph (the desired post-#1070 state).
    // Exit 0 with a printable tree means openssl-sys IS in the
    // graph — that's the regression case.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        panic!(
            "#1070 regression: openssl-sys is in the Android transitive \
             graph. The Android NDK ships no libssl by default so the \
             mobile-runtime CI workflow's emulator job will fail at \
             `cargo test --no-run`.\n\n\
             Offending chain (stdout):\n{stdout}\n\n\
             Reproducer:\n  \
             cargo tree -e normal --target x86_64-linux-android \
             --no-default-features --features sqlite-bundled \
             -i openssl-sys\n\n\
             Common causes: (a) hf-hub default-features re-enabled \
             (default-tls → native-tls); (b) a new dep with \
             native-tls enabled. Use rustls-tls everywhere."
        );
    }

    // `cargo tree -i` with no match emits a 'did not match any packages'
    // error on stderr. Anything else is unexpected — surface it.
    assert!(
        stderr.contains("did not match any packages"),
        "#1070 test environment problem: unexpected `cargo tree -i` failure shape. \
         stdout=<{stdout}>, stderr=<{stderr}>"
    );
}
