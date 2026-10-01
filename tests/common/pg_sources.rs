// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared source loader for the Postgres-adapter structural scanners (#4023).
//!
//! The Postgres adapter is `src/store/postgres.rs` PLUS every child module
//! under `src/store/postgres/`. Moving a method body into a child module (as
//! #4023 did for `pg_merge_inbound`) must not hide it from a text scanner:
//! the #3175 record-stop parity scan, the B9 write-gate scan and the
//! #2393/#2397 write-funnel scan all read their source through THIS ONE
//! loader (#4198 lesson: one helper, not three hand-rolled `read_to_string`
//! calls that each silently go stale when code moves).
//!
//! Fail closed (ERRORS-09): the loader panics rather than return a short
//! set. It asserts that
//!   - `postgres.rs` itself is present and non-empty,
//!   - the child set is non-empty and contains the pinned children in
//!     [`EXPECTED_CHILDREN`] (so a scanner can never silently scan nothing),
//!   - every `mod <name>;` that `postgres.rs` declares at column 0 has a
//!     loaded file, and every loaded child is declared (no orphan, no
//!     undiscovered module).
//!
//! Leaf module, `std` only; take it with the `#[path]` idiom:
//!
//! ```ignore
//! #[path = "common/pg_sources.rs"]
//! mod pg_sources;
//! ```

#![allow(dead_code, clippy::missing_panics_doc)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The adapter root file, relative to the crate root.
pub const PG_ROOT_REL: &str = "src/store/postgres.rs";
/// The adapter child-module directory, relative to the crate root.
pub const PG_CHILD_DIR_REL: &str = "src/store/postgres";

/// Child modules that MUST be discovered. Pins the discovery itself: if the
/// directory walk ever returned a subset, the scanners would silently stop
/// seeing these bodies. `merge_inbound_4023.rs` is the module the #4023 move
/// created; the rest are long-standing children that hold write paths.
pub const EXPECTED_CHILDREN: &[&str] = &[
    "src/store/postgres/merge_inbound_4023.rs",
    "src/store/postgres/reown_3124.rs",
    "src/store/postgres/federation_3075.rs",
    "src/store/postgres/lifecycle_tx_3152.rs",
    "src/store/postgres/swarm_rewind.rs",
];

/// One adapter source file: crate-relative path (forward slashes) + LF text.
#[derive(Debug, Clone)]
pub struct PgSource {
    pub rel: String,
    pub text: String,
}

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_lf(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("pg_sources: read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let rd = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("pg_sources: read_dir {}: {e}", dir.display()));
    for entry in rd {
        let entry = entry.unwrap_or_else(|e| panic!("pg_sources: dir entry: {e}"));
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn rel_of(path: &Path) -> String {
    path.strip_prefix(crate_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// A `mod <name>;` declaration in `postgres.rs`: the module name and, when a
/// `#[path = "..."]` attribute precedes it, that path (relative to the
/// directory holding `postgres.rs`).
struct DeclaredMod {
    name: String,
    path_attr: Option<String>,
}

/// Modules declared as `mod <name>;` / `pub mod <name>;` at column 0.
fn declared_children(root_text: &str) -> Vec<DeclaredMod> {
    let mut out = Vec::new();
    let mut pending_path: Option<String> = None;
    for line in root_text.lines() {
        if let Some(rest) = line.strip_prefix("#[path = \"") {
            if let Some(p) = rest.strip_suffix("\"]") {
                pending_path = Some(p.to_string());
            }
            continue;
        }
        let rest = line
            .strip_prefix("pub(crate) mod ")
            .or_else(|| line.strip_prefix("pub(super) mod "))
            .or_else(|| line.strip_prefix("pub mod "))
            .or_else(|| line.strip_prefix("mod "));
        let Some(rest) = rest else {
            if !line.starts_with("#[") && !line.trim().is_empty() && !line.starts_with("//") {
                pending_path = None;
            }
            continue;
        };
        if let Some(name) = rest.strip_suffix(';') {
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                out.push(DeclaredMod {
                    name: name.to_string(),
                    path_attr: pending_path.take(),
                });
            }
        }
        pending_path = None;
    }
    out
}

/// Every adapter source file: `postgres.rs` first, then each child module in
/// sorted path order. Panics (fail closed) on any non-vacuity violation.
#[must_use]
pub fn pg_adapter_sources() -> Vec<PgSource> {
    let root_path = crate_root().join(PG_ROOT_REL);
    let root_text = read_lf(&root_path);
    assert!(
        root_text.contains("impl PostgresStore") || root_text.contains("PostgresStore"),
        "pg_sources: {PG_ROOT_REL} does not look like the adapter root"
    );

    let mut paths = Vec::new();
    collect_rs(&crate_root().join(PG_CHILD_DIR_REL), &mut paths);
    paths.sort();
    assert!(
        !paths.is_empty(),
        "pg_sources: no child modules found under {PG_CHILD_DIR_REL} — a scanner \
         built on this loader would silently scan only {PG_ROOT_REL}"
    );

    let mut out = vec![PgSource {
        rel: PG_ROOT_REL.to_string(),
        text: root_text.clone(),
    }];
    for p in &paths {
        let text = read_lf(p);
        assert!(
            !text.trim().is_empty(),
            "pg_sources: {} is empty",
            rel_of(p)
        );
        out.push(PgSource {
            rel: rel_of(p),
            text,
        });
    }

    let have: BTreeSet<&str> = out.iter().map(|s| s.rel.as_str()).collect();
    for want in EXPECTED_CHILDREN {
        assert!(
            have.contains(want),
            "pg_sources: expected child module {want} was not discovered \
             (loaded: {have:?})"
        );
    }

    // Declared <-> loaded must agree, so a child wired in with a `#[path]`
    // rename or an undeclared file cannot hide from the scanners. A module
    // with a `#[path]` attribute (the `hub` module) is loaded from that path
    // and added to the set.
    let declared = declared_children(&root_text);
    let mut dir_declared: BTreeSet<String> = BTreeSet::new();
    for d in &declared {
        if let Some(rel_attr) = &d.path_attr {
            let rel = format!("src/store/{rel_attr}");
            let text = read_lf(&crate_root().join(&rel));
            assert!(!text.trim().is_empty(), "pg_sources: {rel} is empty");
            out.push(PgSource { rel, text });
        } else {
            dir_declared.insert(d.name.clone());
        }
    }
    let loaded: BTreeSet<String> = paths
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    for name in &dir_declared {
        assert!(
            loaded.contains(name),
            "pg_sources: {PG_ROOT_REL} declares `mod {name};` but no \
             {PG_CHILD_DIR_REL}/{name}.rs was loaded"
        );
    }
    for name in &loaded {
        assert!(
            dir_declared.contains(name),
            "pg_sources: {PG_CHILD_DIR_REL}/{name}.rs is not declared by \
             {PG_ROOT_REL} (undeclared or #[path]-renamed module)"
        );
    }
    out
}

/// All adapter sources joined into one LF string, `postgres.rs` first.
/// Each file is terminated by a newline so no span can bleed across files.
#[must_use]
pub fn pg_adapter_concat() -> String {
    let mut s = String::new();
    for f in pg_adapter_sources() {
        s.push_str(&f.text);
        if !s.ends_with('\n') {
            s.push('\n');
        }
    }
    s
}
