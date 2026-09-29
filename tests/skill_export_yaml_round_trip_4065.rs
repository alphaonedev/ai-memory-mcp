// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4065 — `memory_skill_export` advertises "re-register produces identical
//! digest". The exporter hand-quoted YAML and escaped `"` but not `\`, so a
//! description holding a literal backslash (`'Use C:\new'`, single-quoted in
//! the original SKILL.md) was exported as the double-quoted `"Use C:\new"`,
//! re-parsed with a NEWLINE, and re-registered under a different digest. It
//! also emitted only STRING metadata, silently dropping the composition
//! declaration and the parameters schema.
//!
//! Driven end-to-end through two real `ai-memory mcp` children: register on
//! store A → export → re-register the exported folder on a fresh store B.
//!
//! Cells:
//!   * RED on the untouched tip — backslash / escape-sequence descriptions
//!     keep byte-equal description + body and an EQUAL digest.
//!   * control — a plain description round-trips (it always did).
//!   * structured metadata — `composes_with_reflections` and
//!     `parameters_schema` survive export → re-import.

use rusqlite::OptionalExtension as _;
use serde_json::{Value, json};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

struct Row {
    description: String,
    metadata: Value,
    body: Vec<u8>,
}

fn skill_row(fixture: &Fixture, id: &str) -> Row {
    let conn = rusqlite::Connection::open(&fixture.db).expect("open");
    let (description, metadata, blob): (String, String, Vec<u8>) = conn
        .query_row(
            "SELECT description, metadata, body_blob FROM skills WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .expect("query skill")
        .expect("skill row present");
    Row {
        description,
        metadata: serde_json::from_str(&metadata).expect("metadata json"),
        body: zstd::decode_all(blob.as_slice()).expect("body"),
    }
}

/// Register `skill_md` on a fresh store A, export it, re-register the
/// exported folder on a fresh store B; returns (A digest, B digest, A row,
/// B row).
fn round_trip(skill_md: &str, extra: &Value) -> (String, String, Row, Row) {
    let a = Fixture::new();
    let mut mcp_a = Mcp::start(&a, None);
    let mut args = json!({"inline_skill": skill_md});
    if let (Some(dst), Some(src)) = (args.as_object_mut(), extra.as_object()) {
        dst.extend(src.clone());
    }
    let reg = mcp_a.call_ok("memory_skill_register", &args);
    let id_a = reg["id"].as_str().expect("id").to_string();
    let digest_a = reg["digest"].as_str().expect("digest").to_string();

    let target = a.dir.path().join("skills-export").join("out");
    let exported = mcp_a.call_ok(
        "memory_skill_export",
        &json!({"skill_id": id_a, "target_folder": target.to_string_lossy()}),
    );
    assert_eq!(exported["exported"], true, "export: {exported}");
    let row_a = skill_row(&a, &id_a);
    drop(mcp_a);

    let b = Fixture::new();
    let mut mcp_b = Mcp::start(&b, None);
    let rereg = mcp_b.call_ok(
        "memory_skill_register",
        &json!({"folder_path": target.to_string_lossy()}),
    );
    let id_b = rereg["id"].as_str().expect("id").to_string();
    let digest_b = rereg["digest"].as_str().expect("digest").to_string();
    let row_b = skill_row(&b, &id_b);
    (digest_a, digest_b, row_a, row_b)
}

fn skill_md(description_yaml: &str) -> String {
    format!(
        "---\nnamespace: yaml4065\nname: round-trip-4065\ndescription: {description_yaml}\n---\n\nStep 1: run C:\\new\\tool.exe\n"
    )
}

#[test]
fn backslash_descriptions_round_trip_to_an_identical_digest_4065() {
    // (YAML as authored, the string it denotes)
    let cases = [
        (r"'Use C:\new'", r"Use C:\new"),
        (
            r"'tab \t and unicode \u0041 and \\ pair'",
            r"tab \t and unicode \u0041 and \\ pair",
        ),
        (r#"'quote " then C:\x41'"#, r#"quote " then C:\x41"#),
    ];
    for (authored, expected) in cases {
        let (digest_a, digest_b, row_a, row_b) = round_trip(&skill_md(authored), &json!({}));
        assert_eq!(
            row_a.description, expected,
            "registration parsed {authored}"
        );
        assert_eq!(
            row_b.description, row_a.description,
            "{authored}: exported description must re-parse byte-equal"
        );
        assert_eq!(row_b.body, row_a.body, "{authored}: body byte-equal");
        assert_eq!(
            digest_b, digest_a,
            "{authored}: export → re-register must reproduce the digest"
        );
    }
}

#[test]
fn plain_description_round_trip_control_4065() {
    let (digest_a, digest_b, row_a, row_b) =
        round_trip(&skill_md("A plain description."), &json!({}));
    assert_eq!(row_b.description, row_a.description);
    assert_eq!(digest_b, digest_a);
}

#[test]
fn composition_and_parameters_schema_survive_export_4065() {
    let md = "---\nnamespace: yaml4065\nname: structured-4065\ndescription: Structured metadata.\n\
              composes_with_reflections:\n  - namespace: refl-4065\n    min_depth: 1\n\
              owner: team-4065\n---\n\nBody.\n";
    let schema = json!({
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"],
    });
    let (digest_a, digest_b, row_a, row_b) = round_trip(md, &json!({"parameters_schema": schema}));
    assert_eq!(digest_b, digest_a);
    for key in ["composes_with_reflections", "parameters_schema", "owner"] {
        assert!(
            row_a.metadata.get(key).is_some(),
            "fixture sanity: store A carries {key}: {}",
            row_a.metadata
        );
        assert_eq!(
            row_b.metadata.get(key),
            row_a.metadata.get(key),
            "metadata {key} must survive export → re-import"
        );
    }
}
