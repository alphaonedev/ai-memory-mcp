// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3488 — keep manifest-declared test targets in the Docker builder context.

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

fn declared_test_paths(manifest: &toml::Value) -> Vec<PathBuf> {
    manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .expect("Cargo.toml must retain its explicit test target array")
        .iter()
        .map(|target| {
            let table = target.as_table().expect("each test target is a table");
            if let Some(path) = table.get("path").and_then(toml::Value::as_str) {
                return PathBuf::from(path);
            }
            let name = table
                .get("name")
                .and_then(toml::Value::as_str)
                .expect("each test target has a name or explicit path");
            PathBuf::from("tests").join(format!("{name}.rs"))
        })
        .collect()
}

#[test]
fn docker_builder_copies_every_manifest_declared_test_target_3488() {
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
    for relative in declared_test_paths(&manifest) {
        assert!(
            root.join(&relative).is_file(),
            "manifest-declared target is absent: {}",
            relative.display()
        );
        let source_root = relative
            .components()
            .next()
            .expect("test target has a source root")
            .as_os_str()
            .to_str()
            .expect("source root is UTF-8");
        assert!(
            copied.contains(source_root),
            "Dockerfile must COPY {source_root}/ before cargo validates target {}",
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
