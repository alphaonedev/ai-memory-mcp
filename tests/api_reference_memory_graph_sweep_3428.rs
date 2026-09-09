// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3428 — `docs/API_REFERENCE.md` memory/graph sweep: the live
//! surface is the SSOT, the doc must not invent counts or omit kinds.
//!
//! Denied path (the 2026-09-02 HTTP-sweep findings, re-verified on
//! `origin/chain/next` = 050f0ffd after #3416):
//! - POST /memories `kind` prose listing only the 10 Form-6 variants
//!   (missing Goal/Plan/Step + Told/Instruction/Intervention)
//! - bulk warning block claiming the endpoint is always HTTP 200 and
//!   that #2588 has not landed
//! - DELETE /api/v1/links documented as `{"deleted": N}` (a count)
//!   when the handler returns `{"deleted": bool}`
//! - `/api/v1/cluster`, `/api/v1/memories/{id}/grant`,
//!   `/api/v1/memories/{id}/revoke` named as live routes (SDK C-19
//!   ghosts; zero hits in `src/handlers/routes.rs`)
//!
//! Allowed path: the 16 `MemoryKind` slugs, the live #2588 200/207/202
//! contract, `{"deleted": true}` as a bool, and `###` request/response
//! sections for `DELETE /links`, `POST /links/verify`,
//! `POST /kg/find_paths`, `GET /memories/{id}/lineage`.

use std::fs;
use std::path::PathBuf;

use ai_memory::models::MemoryKind;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn api_reference() -> String {
    fs::read_to_string(repo_root().join("docs/API_REFERENCE.md"))
        .expect("read docs/API_REFERENCE.md")
}

fn cli_reference() -> String {
    fs::read_to_string(repo_root().join("docs/CLI_REFERENCE.md"))
        .expect("read docs/CLI_REFERENCE.md")
}

fn section_after<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(heading)
        .unwrap_or_else(|| panic!("missing heading: {heading}"));
    let rest = &doc[start..];
    let next = rest[heading.len()..]
        .find("\n### ")
        .map_or(rest.len(), |i| heading.len() + i);
    &rest[..next]
}

#[test]
fn api_reference_kind_vocab_lists_all_sixteen_memory_kinds_3428() {
    let doc = api_reference();
    let kinds = MemoryKind::all();
    assert_eq!(
        kinds.len(),
        16,
        "MemoryKind::all() moved; update this pin and the docs together"
    );
    let create = section_after(&doc, "### `POST /api/v1/memories` — create");
    for kind in kinds {
        let slug = kind.as_str();
        assert!(
            create.contains(&format!("`{slug}`")),
            "POST /memories kind prose must name `{slug}` (MemoryKind::all())"
        );
    }
    // Denied: the pre-#1709/#1945 10-variant closed list as the whole set.
    assert!(
        !create.contains(
            "`observation`, `reflection`, `persona`, `concept`, `entity`,\n`claim`, `relation`, `event`, `conversation`, `decision`"
        ) && !create.contains(
            "(`observation`, `reflection`, `persona`, `concept`, `entity`, `claim`, `relation`, `event`, `conversation`, `decision`)"
        ),
        "stale 10-variant kind list must not survive as the closed set"
    );
}

#[test]
fn cli_and_user_guide_kind_flag_lists_all_sixteen_memory_kinds_3428() {
    let cli = cli_reference();
    let guide = fs::read_to_string(repo_root().join("docs/USER_GUIDE.md"))
        .expect("read docs/USER_GUIDE.md");
    let kinds = MemoryKind::all();
    for kind in kinds {
        let slug = kind.as_str();
        let wrapped = format!("`{slug}`");
        assert!(
            cli.contains(&wrapped),
            "CLI_REFERENCE --kind row must name `{slug}`"
        );
        assert!(
            guide.contains(&wrapped),
            "USER_GUIDE kind row must name `{slug}`"
        );
    }
}

#[test]
fn api_reference_bulk_status_is_live_2588_not_always_200_3428() {
    let doc = api_reference();
    let bulk = section_after(&doc, "### `POST /api/v1/memories/bulk` — batch create");
    assert!(
        bulk.contains("207 Multi-Status"),
        "bulk section must document live 207 Multi-Status:\n{bulk}"
    );
    assert!(
        bulk.contains("#2588") && bulk.to_ascii_lowercase().contains("shipped"),
        "bulk section must treat #2588 as shipped, not pending:\n{bulk}"
    );
    assert!(
        !bulk.contains("no status code override"),
        "stale 'always HTTP 200 / no status code override' warning must not survive:\n{bulk}"
    );
    assert!(
        !bulk.contains("Until\n> that lands") && !bulk.contains("Until that lands"),
        "stale #2588 'until that lands' warning must not survive:\n{bulk}"
    );
    assert!(
        bulk.contains("429"),
        "wholly quota-rejected bulk batch is 429, must be documented:\n{bulk}"
    );
}

#[test]
fn api_reference_delete_links_returns_bool_not_count_3428() {
    let doc = api_reference();
    let heading = "### `DELETE /api/v1/links`";
    assert!(
        doc.contains(heading),
        "DELETE /api/v1/links must have a request/response section"
    );
    let section = section_after(&doc, heading);
    assert!(
        section.contains("`{\"deleted\": true}`") || section.contains("\"deleted\": true"),
        "DELETE /links must document deleted as a bool true:\n{section}"
    );
    assert!(
        section.contains("bool"),
        "DELETE /links must say deleted is a bool:\n{section}"
    );
    assert!(
        !section.contains("{\"deleted\": N}") && !section.contains("`{\"deleted\": N}`"),
        "DELETE /links must not document a count N:\n{section}"
    );
    // Table row in the v0.7 inventory.
    assert!(
        !doc.contains("| Delete a link. Returns `{\"deleted\": N}`. |"),
        "v0.7 inventory table must not claim deleted is a count"
    );
}

#[test]
fn api_reference_four_graph_routes_have_request_response_sections_3428() {
    let doc = api_reference();
    for heading in [
        "### `DELETE /api/v1/links`",
        "### `POST /api/v1/links/verify`",
        "### `POST /api/v1/kg/find_paths`",
        "### `GET /api/v1/memories/{id}/lineage`",
    ] {
        assert!(
            doc.contains(heading),
            "missing request/response heading: {heading}"
        );
        let section = section_after(&doc, heading);
        assert!(
            section.contains("```json") || section.contains("Response"),
            "{heading} must carry a request or response contract:\n{section}"
        );
    }
    assert!(
        doc.contains("`POST /api/v1/find_paths` is a registered alias"),
        "find_paths alias (#934) must be documented as registered, not missing"
    );
}

#[test]
fn api_reference_does_not_register_sdk_ghost_routes_3428() {
    let doc = api_reference();
    for ghost in [
        "### `POST /api/v1/cluster`",
        "### `GET /api/v1/cluster`",
        "### `POST /api/v1/memories/{id}/grant`",
        "### `POST /api/v1/memories/{id}/revoke`",
    ] {
        assert!(
            !doc.contains(ghost),
            "SDK C-19 ghost must not be documented as a live heading: {ghost}"
        );
    }
}

#[test]
fn api_reference_entities_document_no_entity_type_field_3428() {
    let doc = api_reference();
    let section = section_after(&doc, "### `POST /api/v1/entities`");
    assert!(
        section.contains("no `entity_type` field") || section.contains("no entity_type field"),
        "POST /entities must disclose there is no entity_type field:\n{section}"
    );
}
