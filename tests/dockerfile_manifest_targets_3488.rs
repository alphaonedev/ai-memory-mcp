// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3488 — keep manifest-declared test targets in the Docker builder context.
//!
//! #3870 widened the pin from `[[test]]` to EVERY manifest target kind. The Dockerfile stages a
//! PARTIAL tree (explicit `COPY` lines) and cargo resolves every declared target's source at
//! manifest load, so a `[[example]]` / `[[bench]]` / `[[bin]]` whose directory is not copied
//! fails the image build with cargo's own "can't find `x` example" text — exactly what #3858's
//! explicit `[[example]] fed_issue` did on a tree where this file pinned only `[[test]]`. An
//! instrument narrower than the class it measures reports green on the failure it exists to
//! catch; the class is "manifest target kinds", not "tests".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn copied_directories(dockerfile: &str) -> BTreeSet<&str> {
    dockerfile
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "COPY" {
                return None;
            }
            let source = fields.next()?;
            source.strip_suffix('/')
        })
        .collect()
}

/// Every manifest target kind cargo resolves at manifest load, with the directory an
/// unpathed target of that kind defaults to (cargo's auto-discovery roots).
const TARGET_KINDS: [(&str, &str); 4] = [
    ("test", "tests"),
    ("example", "examples"),
    ("bench", "benches"),
    ("bin", "src/bin"),
];

fn declared_target_paths(manifest: &toml::Value, kind: &str, default_dir: &str) -> Vec<PathBuf> {
    let targets = match manifest.get(kind).and_then(toml::Value::as_array) {
        Some(targets) => targets,
        // `[[test]]` is the array #3488 pinned as always-present; the other kinds are
        // covered whenever they are declared and simply contribute nothing when absent.
        None if kind == "test" => panic!("Cargo.toml must retain its explicit test target array"),
        None => return Vec::new(),
    };
    targets
        .iter()
        .map(|target| {
            let table = target.as_table().expect("each target is a table");
            if let Some(path) = table.get("path").and_then(toml::Value::as_str) {
                return PathBuf::from(path);
            }
            let name = table
                .get("name")
                .and_then(toml::Value::as_str)
                .expect("each target has a name or explicit path");
            PathBuf::from(default_dir).join(format!("{name}.rs"))
        })
        .collect()
}

fn declared_target_paths_all_kinds(manifest: &toml::Value) -> Vec<(&'static str, PathBuf)> {
    TARGET_KINDS
        .iter()
        .flat_map(|(kind, default_dir)| {
            declared_target_paths(manifest, kind, default_dir)
                .into_iter()
                .map(move |path| (*kind, path))
        })
        .collect()
}

#[test]
fn docker_builder_copies_every_manifest_declared_target_3488_3870() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_text = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let manifest: toml::Value = toml::from_str(&manifest_text).expect("parse Cargo.toml");
    let dockerfile = std::fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");
    let dockerignore =
        std::fs::read_to_string(root.join(".dockerignore")).expect("read .dockerignore");
    let copied = copied_directories(&dockerfile);

    let cargo_build = dockerfile
        .find("RUN cargo build --release")
        .expect("Dockerfile retains its release build");
    let declared = declared_target_paths_all_kinds(&manifest);
    assert!(
        declared.iter().any(|(kind, _)| *kind == "example"),
        "Cargo.toml declares no [[example]] target: the #3870 regression shape is no longer exercised"
    );
    for (kind, relative) in declared {
        assert!(
            root.join(&relative).is_file(),
            "manifest-declared {kind} target is absent: {}",
            relative.display()
        );
        let source_root = relative
            .components()
            .next()
            .expect("target has a source root")
            .as_os_str()
            .to_str()
            .expect("source root is UTF-8");
        assert!(
            copied.contains(source_root),
            "Dockerfile must COPY {source_root}/ before cargo validates {kind} target {}",
            relative.display()
        );
        let copy_line = format!("COPY {source_root}/ {source_root}/");
        let copy_position = dockerfile
            .find(&copy_line)
            .expect("copied source root has a canonical COPY instruction");
        assert!(
            copy_position < cargo_build,
            "{copy_line} must precede the release build"
        );
        assert!(
            !dockerignore.lines().any(|line| {
                let pattern = line.trim().trim_start_matches('/');
                pattern.strip_suffix('/').unwrap_or(pattern) == source_root
            }),
            ".dockerignore must not exclude {source_root}/"
        );
    }
}
