// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_skill_resource` handler (L1-5 Agent Skills substrate).
//!
//! Returns the decompressed content of a `skill_resources` row. #8834: the
//! row is served only through the verified skill read path
//! ([`super::skill_integrity::load_verified_skill`]), so the resource digest,
//! every sibling resource digest, the skill digest and any signature are all
//! checked on every fetch, and #8832's scope binding gates the caller.

use rusqlite::Connection;
use serde_json::{Value, json};

/// MCP `memory_skill_resource` substrate handler.
///
/// Promoted to `pub` for v0.7.0 Cluster E API-2 (issue #767) so the
/// CLI `ai-memory skill resource` and HTTP routes can dispatch into
/// the same implementation.
///
/// #8832 — `read_caller` is the resolved read principal (MCP:
/// `Authority::read_caller`; CLI: the process identity). `None` is the
/// single-operator / admin-gated posture and reads every skill.
///
/// # Errors
/// Returns a substrate error string when `skill_id` / `resource_path`
/// are missing, the skill or row is not found (or not visible), zstd
/// decompression fails, or any integrity check fails (#8834).
pub fn handle_skill_resource(
    conn: &Connection,
    params: &Value,
    read_caller: Option<&str>,
) -> Result<Value, String> {
    let skill_id = params["skill_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("memory_skill_resource requires 'skill_id'")?;

    let resource_path = params[crate::models::field_names::RESOURCE_PATH]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(crate::errors::msg::SKILL_RESOURCE_PATH_REQUIRED)?;

    let skill = super::skill_integrity::load_verified_skill(conn, skill_id, read_caller)?;
    let Some(resource) = skill
        .resources
        .into_iter()
        .find(|r| r.path == resource_path)
    else {
        return Err(crate::errors::msg::skill_resource_not_found(
            skill_id,
            resource_path,
        ));
    };

    let content_bytes = resource
        .content
        .ok_or_else(|| crate::errors::msg::skill_resource_reference_only(resource_path))?;

    // Return as UTF-8 text if possible, else base64.
    let (content_value, encoding) = match String::from_utf8(content_bytes) {
        Ok(text) => (json!(text), "utf-8"),
        Err(err) => {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(err.as_bytes());
            (json!(b64), "base64")
        }
    };

    Ok(json!({
        "skill_id": skill_id,
        (crate::models::field_names::RESOURCE_PATH): resource_path,
        "resource_kind": resource.kind,
        "content": content_value,
        "encoding": encoding,
        "digest": hex_encode(&resource.digest),
        "digest_verified": true,
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- D1.5 (#986): per-tool McpTool impl for memory_skill_resource ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_skill_resource`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SkillResourceRequest {
    /// Parent skill UUID.
    pub skill_id: String,

    /// Relative path (e.g. 'scripts/run.sh').
    pub resource_path: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_skill_resource`.
#[allow(dead_code)]
pub struct SkillResourceTool;

impl McpTool for SkillResourceTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SKILL_RESOURCE
    }
    fn description() -> &'static str {
        "Fetch + digest-verify a skill resource."
    }
    fn docs() -> &'static str {
        "L1-5: SHA-256-verified resource fetch. Errors on mismatch."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SkillResourceRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Other.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_skill_resource`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn skill_resource_parity_986() {
        let derived = derived_props_for::<SkillResourceRequest>();
        assert_property_set_parity("memory_skill_resource", &derived);
        assert_descriptions_match("memory_skill_resource", &derived);
    }

    #[test]
    fn skill_resource_tool_metadata_986() {
        assert_eq!(SkillResourceTool::name(), "memory_skill_resource");
        assert_eq!(SkillResourceTool::family(), "other");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use sha2::Digest as _;

    /// #8834 — recompute the hand-inserted fixture's digests so the verified
    /// read path serves it.
    fn reseal(conn: &rusqlite::Connection, id: &str) {
        crate::mcp::reseal_skill_digest_for_tests(conn, id).expect("reseal");
    }

    fn open_db() -> rusqlite::Connection {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let conn = crate::db::open(&path).expect("db::open");
        std::mem::forget(dir);
        conn
    }

    fn insert_min_skill(conn: &rusqlite::Connection, id: &str) {
        let body_blob = zstd::encode_all(b"body".as_slice(), 3).unwrap();
        let digest = vec![0u8; 32];
        conn.execute(
            "INSERT INTO skills (id, namespace, name, description, metadata, body_blob, digest, created_at) \
             VALUES (?1, 'ns', 'skill', 'D', '{}', ?2, ?3, 0)",
            params![id, body_blob, digest],
        )
        .unwrap();
    }

    fn insert_resource(
        conn: &rusqlite::Connection,
        skill_id: &str,
        path: &str,
        kind: &str,
        content: &[u8],
        digest: Option<&[u8]>,
    ) {
        let blob = zstd::encode_all(content, 3).unwrap();
        let dig_opt: Option<Vec<u8>> = digest.map(<[u8]>::to_vec);
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![skill_id, path, kind, blob, dig_opt],
        )
        .unwrap();
    }

    #[test]
    fn rejects_missing_skill_id() {
        let conn = open_db();
        let err = handle_skill_resource(&conn, &json!({"resource_path": "x"}), None).unwrap_err();
        assert!(err.contains("requires 'skill_id'"));
    }

    #[test]
    fn rejects_empty_skill_id() {
        let conn = open_db();
        let err =
            handle_skill_resource(&conn, &json!({"skill_id": "", "resource_path": "x"}), None)
                .unwrap_err();
        assert!(err.contains("requires 'skill_id'"));
    }

    #[test]
    fn rejects_missing_resource_path() {
        let conn = open_db();
        let err = handle_skill_resource(&conn, &json!({"skill_id": "sk"}), None).unwrap_err();
        assert!(err.contains("requires 'resource_path'"));
    }

    #[test]
    fn rejects_empty_resource_path() {
        let conn = open_db();
        let err =
            handle_skill_resource(&conn, &json!({"skill_id": "sk", "resource_path": ""}), None)
                .unwrap_err();
        assert!(err.contains("requires 'resource_path'"));
    }

    #[test]
    fn returns_not_found_for_missing_resource() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        reseal(&conn, "sk1");
        let err = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "no-such.sh"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("resource not found"));
        assert!(err.contains("sk1"));
        assert!(err.contains("no-such.sh"));
    }

    #[test]
    fn rejects_resource_without_content_blob() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        // Insert resource with NULL content_blob (reference-only).
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES ('sk1', 'ref.md', 'reference', NULL, NULL)",
            [],
        )
        .unwrap();
        reseal(&conn, "sk1");
        let err = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "ref.md"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("no inline content"));
    }

    #[test]
    fn returns_utf8_content_with_verified_digest() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        let content = b"#!/bin/bash\necho hello\n";
        let mut h = sha2::Sha256::new();
        h.update(content);
        let dig: Vec<u8> = h.finalize().to_vec();
        insert_resource(
            &conn,
            "sk1",
            "scripts/run.sh",
            "script",
            content,
            Some(&dig),
        );
        reseal(&conn, "sk1");

        let v = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "scripts/run.sh"}),
            None,
        )
        .unwrap();
        assert_eq!(v["skill_id"], json!("sk1"));
        assert_eq!(v["resource_path"], json!("scripts/run.sh"));
        assert_eq!(v["resource_kind"], json!("script"));
        assert_eq!(v["encoding"], json!("utf-8"));
        assert_eq!(v["content"].as_str().unwrap(), "#!/bin/bash\necho hello\n");
        assert_eq!(v["digest_verified"], json!(true));
        let hex_dig = v["digest"].as_str().unwrap();
        assert_eq!(hex_dig.len(), 64);
    }

    #[test]
    fn returns_base64_for_binary_content() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        // Invalid UTF-8 bytes.
        let content: Vec<u8> = vec![0xff, 0xfe, 0xfd, 0x00, 0x01];
        let mut h = sha2::Sha256::new();
        h.update(&content);
        let dig: Vec<u8> = h.finalize().to_vec();
        insert_resource(&conn, "sk1", "asset.bin", "asset", &content, Some(&dig));
        reseal(&conn, "sk1");

        let v = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "asset.bin"}),
            None,
        )
        .unwrap();
        assert_eq!(v["encoding"], json!("base64"));
        // Decode and verify round-trip.
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v["content"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn detects_digest_mismatch() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        let content = b"original";
        let wrong_dig = vec![0u8; 32]; // wrong digest
        insert_resource(&conn, "sk1", "x.txt", "asset", content, Some(&wrong_dig));

        let err = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "x.txt"}),
            None,
        )
        .unwrap_err();
        // #8834 — exact, fail-closed; no stored/computed digest disclosure.
        assert_eq!(
            err,
            crate::errors::msg::skill_resource_digest_mismatch("x.txt", "sk1")
        );
    }

    #[test]
    fn no_digest_fails_closed_8834() {
        // #8834 — pre-fix a NULL digest served the content unverified.
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        let content = b"unsigned content";
        insert_resource(&conn, "sk1", "u.txt", "asset", content, None);

        let err = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "u.txt"}),
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            crate::errors::msg::skill_resource_digest_missing("u.txt", "sk1")
        );
    }

    #[test]
    fn rejects_corrupt_content_blob() {
        let conn = open_db();
        insert_min_skill(&conn, "sk1");
        let bogus: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        conn.execute(
            "INSERT INTO skill_resources (skill_id, resource_path, resource_kind, content_blob, digest) \
             VALUES ('sk1', 'bad.bin', 'asset', ?1, zeroblob(32))",
            params![bogus],
        )
        .unwrap();
        let err = handle_skill_resource(
            &conn,
            &json!({"skill_id": "sk1", "resource_path": "bad.bin"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("zstd decompress resource"));
    }

    #[test]
    fn hex_encode_round_trip() {
        // Tests the small hex_encode helper directly.
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab, 0x12]), "00ffab12");
    }
}
