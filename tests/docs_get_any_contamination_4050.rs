// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4050 (residual of #3925) — the `PostgresStore::get_any` docstring said
//! no Postgres path writes `contaminated`, but `link_signed` calls the
//! reflection-supersedes stamper and `swarm_rewind_pg` stamps the cascade.
//! The test first checks both code facts still hold, so it cannot pass
//! vacuously after a refactor. RED at 57014b067.

use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The body of the first `fn <name>` in `src`, up to the next `fn ` at
/// the same or lower indentation (good enough for a stable anchor).
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("signature not found: {signature}"));
    let rest = &src[start + signature.len()..];
    let end = rest.find("\n    async fn ").unwrap_or(rest.len());
    &rest[..end]
}

/// The contiguous `///` doc block immediately above `signature`.
fn doc_above(src: &str, signature: &str) -> String {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("signature not found: {signature}"));
    src[..start]
        .lines()
        .rev()
        .skip_while(|l| l.trim().is_empty())
        .take_while(|l| l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn issue_4050_get_any_docstring_matches_pg_contamination_writers() {
    let pg = read("src/store/postgres.rs");
    // Code fact: PG `link_signed` calls the reflection-supersedes stamper.
    let link_signed = fn_body(&pg, "async fn link_signed(");
    assert!(
        link_signed.contains("stamp_on_reflection_supersedes_pg("),
        "precondition: PG link_signed no longer calls the stamper; re-verify #4050"
    );
    // Code fact: the PG rewind stamps `Contaminated`.
    let rewind = read("src/store/postgres/swarm_rewind.rs");
    assert!(
        rewind.contains(".bind(LifecycleState::Contaminated.as_str())"),
        "precondition: PG swarm_rewind no longer binds Contaminated; re-verify #4050"
    );
    let doc = doc_above(&pg, "pub async fn get_any(");
    assert!(!doc.is_empty(), "get_any docstring not found");
    for stale in [
        "no path WRITES `contaminated`",
        "`link_signed` stamp nothing",
        "the only #3324 stamper is the SQLite",
    ] {
        assert!(
            !doc.contains(stale),
            "#4050: get_any docstring still says {stale:?}:\n{doc}"
        );
    }
    assert!(
        doc.contains("link_signed") && doc.contains("rewind"),
        "#4050: get_any docstring must name the PG writers (link_signed, rewind):\n{doc}"
    );
}
