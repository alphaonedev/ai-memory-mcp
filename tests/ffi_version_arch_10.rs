// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-10 (FX-C4-batch2, 2026-05-26) — FFI self-identification stub.
//!
//! Pins the `ai_memory_version()` extern "C" symbol that the
//! mobile-cross-compile artifacts ship. Before ARCH-10, the
//! `.xcframework` / `.aar` artifacts contained zero callable
//! `extern "C"` symbols — operators linking the artifact would
//! find no entrypoints. The symbol returns the substrate's
//! Cargo.toml version string so consumers can link-and-validate the
//! symbol table before the broader C ABI surface lands in v0.7.x.
//!
//! This test calls the FFI symbol through a `'static` lifetime
//! C-string pointer and asserts the returned string matches
//! `CARGO_PKG_VERSION`.

#[test]
fn arch_10_ai_memory_version_returns_cargo_version() {
    let ptr = ai_memory::ai_memory_version();
    assert!(!ptr.is_null(), "ai_memory_version returned a null pointer");

    // SAFETY: the symbol contract documents the pointer as
    // 'static-lived, NUL-terminated, immutable UTF-8.
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    let s = cstr
        .to_str()
        .expect("ai_memory_version returned non-UTF-8 bytes");
    assert_eq!(
        s,
        env!("CARGO_PKG_VERSION"),
        "ai_memory_version FFI symbol drift: returned `{s}`, expected `{}`",
        env!("CARGO_PKG_VERSION"),
    );
}

#[test]
fn arch_10_ai_memory_version_pointer_is_stable_across_calls() {
    // The contract is 'static — the pointer must not change between
    // calls (no per-call allocation, no heap escape).
    let p1 = ai_memory::ai_memory_version();
    let p2 = ai_memory::ai_memory_version();
    assert_eq!(p1, p2, "ai_memory_version returned a non-stable pointer");
}
