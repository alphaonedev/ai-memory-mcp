# Build-script vetting record

This record corrects the earlier statement that `reed-solomon-simd` had no
install/build script. Cargo build scripts execute with the builder's authority,
so their presence and build-dependency closure must be established mechanically
and their pinned source reviewed before authorization.

## `reed-solomon-simd` 3.1.0

- Cargo.lock checksum: `cffef0520d30fbd4151fb20e262947ae47fb0ab276a744a19b6398438105a072`.
- Reviewed registry files: `build.rs`, `Cargo.toml.orig`, and the complete build
  dependency declaration.
- `build.rs` reads only the packaged `README.md` plus Cargo-provided package
  name/version environment variables, calls `readme_rustdocifier::rustdocify`,
  and writes `README-rustdocified.md` under Cargo's `OUT_DIR`.
- It performs no network access, process execution, CPU probing, native
  compilation, unsafe operation, or writes outside `OUT_DIR`.
- Its sole build dependency is `readme-rustdocifier` 0.1.1.

Disposition: accepted documentation-only code generation under the exact pin.
Any checksum, custom-build-target, or build-dependency-closure change invalidates
this record and fails the mechanical gate.

## `readme-rustdocifier` 0.1.1

- Cargo.lock checksum: `08ad765b21a08b1a8e5cdce052719188a23772bcbefb3c439f0baaf62c56ceac`.
- Reviewed registry files: `build.rs`, `Cargo.toml.orig`, `src/lib.rs`, and the
  complete `src/inner.rs` implementation.
- Its build script applies its in-tree Markdown transformation to its packaged
  `README.md` and writes the generated documentation under `OUT_DIR`.
- The transformation is string parsing/rewriting only. The crate has no build
  dependencies and the reviewed code performs no network access, process
  execution, unsafe operation, or writes outside `OUT_DIR`.

Disposition: accepted documentation-only build helper under the exact pin.

## Mechanical checklist

Run `python3 scripts/check-build-script-vetting.py`. It fails closed unless the
ledgered packages remain in `Cargo.lock` at the reviewed checksums and Cargo's
resolved metadata still reports the recorded custom-build targets and exact
build-dependency closures. CI runs the same check after dependency resolution.

The ledger is intentionally explicit rather than a claim that every dependency
is build-script-free. Adding or changing a reviewed build-script dependency
requires source review plus a matching ledger update in the same change.
