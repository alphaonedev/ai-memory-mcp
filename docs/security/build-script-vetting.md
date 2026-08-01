# Build-script vetting record

A cargo build script (`build.rs`) executes arbitrary code with the **builder's
authority**, at compile time, on every CI runner and every operator machine. It
is the highest-leverage supply-chain injection point in a Rust project. The
mechanical gate is `scripts/check-build-script-vetting.py`; this file is the
human record it anchors to.

## What the gate attests, and what it does not

Read this before citing a green gate as evidence of anything.

`cargo metadata` currently resolves **547** packages, of which **90** carry a
`custom-build` target. The gate walks that resolved graph and **fails closed on
any build-script package with no record in the ledger**
(`supply-chain/build-script-vetting.json`). The ledger is an allowlist that must
cover reality.

Each record carries one of two dispositions:

| disposition | meaning | count |
|---|---|---|
| `reviewed` | the build script's source **was read**; requires a dated anchor into this file and a pinned build-dependency closure | 2 |
| `inventoried` | present, content-pinned and dated; **NOT source-reviewed** | 88 |

**A PASS attests:** every build script in the resolved graph has an in-repo,
dated, content-pinned record, and none has changed since that record was
written. A new build-script crate — introduced by `cargo add`, by a transitive
bump, or by a cargo-squat — cannot enter without a visible ledger line in the
same pull request.

**A PASS does NOT attest** that the 88 `inventoried` build scripts are safe.
They execute with builder authority and **have not been read**. The gate prints
both counts on every run, deliberately, so the pass line cannot be quoted as
"90 build scripts reviewed".

The 88 are burned down by **promotion** — reading a build script and giving it a
`reviewed` record here — never by relabelling. The gate refuses a `reviewed`
disposition that carries no `review_record` anchor and no `reviewed_on` date, so
a bulk relabel is a large, loud diff rather than a one-word edit.

`inventoried_ceiling` in the ledger is a monotone ratchet in the same shape as
`scripts/qc-allowlists/hardcoded-literals-baseline.txt`: the count may never
exceed it, and lowering it is the only sanctioned edit. It is the second lock.
Without it, admitting an unreviewed build script costs a one-line append that
can ride along unnoticed in a large PR; with it, the same act also requires
raising a number that exists for no other purpose, in a diff whose only reading
is "we are adding an unreviewed build script". Dependency additions already
require operator authorization (`CLAUDE.md` §"Dependencies"), so that red is the
policy gate firing where policy already said it must.

## Pinning, per source kind

- **registry** packages are pinned by their `Cargo.lock` checksum.
- **vendored** packages are pinned by `tree_sha256`, a SHA-256 over every
  git-tracked file under `vendored_path`, recomputed on every run.

The vendored branch exists because `vendor/paste` is the one package in the
graph with no source and therefore **no lockfile checksum** — and it is
simultaneously the highest-risk build script present: in-tree, editable in any
PR, with no upstream to diff against. Treating "no checksum" as "skip it" would
be the same fail-open this gate was rewritten to close. A registry package may
never be pinned by a tree digest; the gate rejects that shape explicitly, so
"declare it vendored" cannot become a universal checksum bypass.

## `reed-solomon-simd` 3.1.0 — `reviewed` (2026-07-19)

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
Any checksum, custom-build-target, or build-dependency-closure change
invalidates this record and fails the mechanical gate.

## `readme-rustdocifier` 0.1.1 — `reviewed` (2026-07-19)

- Cargo.lock checksum: `08ad765b21a08b1a8e5cdce052719188a23772bcbefb3c439f0baaf62c56ceac`.
- Reviewed registry files: `build.rs`, `Cargo.toml.orig`, `src/lib.rs`, and the
  complete `src/inner.rs` implementation.
- Its build script applies its in-tree Markdown transformation to its packaged
  `README.md` and writes the generated documentation under `OUT_DIR`.
- The transformation is string parsing/rewriting only. The crate has no build
  dependencies and the reviewed code performs no network access, process
  execution, unsafe operation, or writes outside `OUT_DIR`.

Disposition: accepted documentation-only build helper under the exact pin.

## `paste` 1.0.15 (`vendor/paste`) — `inventoried`, with an observation

Recorded honestly as `inventoried` rather than `reviewed`, because the review is
partial. What **was** read, in full, is `vendor/paste/build.rs` (37 lines): it
shells out to `Command::new($RUSTC).arg("--version")`, parses the minor version,
and emits `cargo:rustc-check-cfg` / `cargo:rustc-cfg` lines. It writes nothing,
fetches nothing, and its only process execution is the compiler the build is
already running under.

What was **not** line-audited is `vendor/paste/src/` (~1000 lines). That matters
here and is why the disposition stays `inventoried`: `paste` is a **proc-macro**,
so its `src/` is *also* compile-time-executed code, on a broader surface than the
build script. The `tree_sha256` pin covers **both** — it digests every
git-tracked file under `vendor/paste`, so an edit to either surface fails the
gate and must be re-read in the diff that makes it.

Provenance: vendored under #2050 after the upstream `alphaonedev/paste` fork was
deleted and its rev became unfetchable; `paste` 1.x is unmaintained
(RUSTSEC-2024-0436) and the migration to `pastey` is tracked in `Cargo.toml`
§C1. No first-party code in this repo invokes `paste::paste!`; the substitution
only feeds transitive dependents.

## Mechanical checklist

```bash
python3 scripts/check-build-script-vetting.py                    # the gate
python3 scripts/check-build-script-vetting.py --self-test        # prove it is load-bearing
python3 scripts/check-build-script-vetting.py --update-checksums # refresh EXISTING pins only
```

CI runs the gate and the self-test in the dedicated `Build-script custom-build
ledger gate (#2635)` job in `.github/workflows/ci.yml`. That job carries **no
job-level `if:`**, deliberately: until #2635 the gate was a *step* inside
`Lint (fmt + clippy)`, which carries `if: needs.classify.outputs.docs_only !=
'true'` and therefore reports `skipped` on a docs-only pull request — and branch
protection **counts `skipped` as satisfied**. A supply-chain gate that a
docs-only diff can switch off is not a gate.

`--update-checksums` is maintenance-only: it refreshes the pins of records that
already exist and is structurally incapable of adding, removing or re-disposing
one, so it can service a routine dependency bump without ever being the thing
that admits a new build script.

### Adding or bumping a build-script dependency

1. Run the gate. It names the package and prints a paste-ready ledger record.
2. **Read the build script.** If you read it, add a `reviewed` record plus a
   section in this file, and leave `inventoried_ceiling` alone.
3. If you did not read it, add an `inventoried` record **and** raise
   `inventoried_ceiling` by one. Both edits are required, by design.
4. Dependency additions require operator authorization (`CLAUDE.md`
   §"Dependencies"). This gate is where that requirement becomes mechanical.
