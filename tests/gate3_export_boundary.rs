// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Gate-3 (#1838/G28 + #1844) — export/egress confidentiality-boundary
//! regression pins.
//!
//! The confidentiality invariant: forbidden export CLASSES (private-key
//! material, master/threshold secrets, policy-rule signing keys,
//! biometric/behavioral embeddings) plus raw credential VALUES must NEVER
//! cross an export boundary in the clear. This suite pins that invariant on
//! all THREE egress paths that were previously gated inconsistently:
//!
//!   1. the shared SSOT `export_taxonomy::screen_memories_for_export`, which
//!      the CLI `export` (`cli::io::export`) and the HTTP admin export
//!      (`handlers::admin::export_memories`) both delegate to;
//!   2. the CLI `export` command end-to-end (the documented
//!      `ai-memory export > backup.json` operator-backup path — the
//!      GA-blocker: it previously bypassed the gate entirely); and
//!   3. the forensic bundle (`forensic::bundle::build_files`).
//!
//! Everything lives under `mod tests` so the repo's hardcoded-literal /
//! vendor-literal CI gates treat the fixtures as test code.

#[cfg(test)]
mod tests {
    use ai_memory::db;
    use ai_memory::export_taxonomy::screen_memories_for_export;
    use ai_memory::models::field_names;
    use ai_memory::models::{Memory, Tier};
    use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
    use ai_memory::signed_events::event_types::EXPORT_FORBIDDEN_CLASS_REFUSED;
    use rusqlite::params;
    use serde_json::Value;

    // A canonical AWS access-key-id example (a raw credential VALUE the
    // secret-screen `AKIA…` detector fires on). Defined once so the literal
    // never repeats across sites.
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    // A mis-stored PEM private key (forbidden CLASS = private-key material).
    const PEM_CONTENT: &str = "leaked:\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END";
    // The redaction placeholder the secret-screen substitutes for a hit.
    const REDACTED: &str = "REDACTED";

    /// Seed the process-wide screen mode to `Redact` so the credential-VALUE
    /// screen is active (idempotent — `OnceLock` first-writer-wins; every test
    /// in this binary wants `Redact`).
    fn seed_redact() {
        set_screen_mode(SecretScreenMode::Redact);
    }

    /// Build an insertable, non-expiring (`long`-tier) memory.
    fn memory(id: &str, title: &str, content: &str, metadata: Value) -> Memory {
        Memory {
            id: id.to_string(),
            namespace: "gate3".to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tier: Tier::Long,
            expires_at: None,
            metadata,
            ..Memory::default()
        }
    }

    fn refusal_count(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            params![EXPORT_FORBIDDEN_CLASS_REFUSED],
            |r| r.get(0),
        )
        .expect("count refusal rows")
    }

    // ── Path 1 — the shared SSOT (CLI + HTTP both delegate here) ──────────

    #[test]
    fn helper_drops_every_forbidden_class_and_emits_signed_refusals() {
        seed_redact();
        let conn = db::open(std::path::Path::new(":memory:")).expect("open");

        let corpus = vec![
            memory("clean-1", "standup", "an ordinary note", Value::Null),
            // (a) PEM private-key material in content.
            memory("pem", "t", PEM_CONTENT, Value::Null),
            // (b) producer-tagged biometric embedding.
            memory(
                "bio",
                "t",
                "c",
                serde_json::json!({"embedding_class": "biometric"}),
            ),
            // (c) a threshold / Shamir key share (field-name marker).
            memory(
                "thr",
                "t",
                "c",
                serde_json::json!({"threshold_share": "1-abc"}),
            ),
            // (d) the governance rule private signing key (field-name marker).
            memory(
                "gov",
                "t",
                "c",
                serde_json::json!({"operator_signing_key": "AAAA"}),
            ),
            memory("clean-2", "retro", "another ordinary note", Value::Null),
        ];

        let kept = screen_memories_for_export(corpus, Some(&conn));

        // Only the two clean rows survive; each of the four forbidden rows is
        // dropped fail-closed and witnessed by exactly one signed refusal.
        let kept_ids: Vec<&str> = kept.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(kept.len(), 2, "kept: {kept_ids:?}");
        assert!(kept_ids.contains(&"clean-1") && kept_ids.contains(&"clean-2"));
        assert!(
            !kept_ids
                .iter()
                .any(|id| ["pem", "bio", "thr", "gov"].contains(id)),
            "no forbidden-class row may survive: {kept_ids:?}"
        );
        assert_eq!(
            refusal_count(&conn),
            4,
            "one signed export.forbidden_class_refused per dropped forbidden row"
        );
    }

    #[test]
    fn helper_redacts_credential_value_in_title_and_metadata_not_just_content() {
        seed_redact();
        // A clean-CLASS row (no forbidden class) that nonetheless stashes a raw
        // credential VALUE in its title AND a nested metadata field — the #1844
        // gap where the screen historically masked `content` alone.
        let row = memory(
            "cred",
            AWS_KEY,
            "body has one too: {AWS_KEY}",
            serde_json::json!({"note": AWS_KEY, "nested": {"deep": AWS_KEY}}),
        );
        let out = screen_memories_for_export(vec![row], None);
        assert_eq!(out.len(), 1, "a clean-class row must survive (redacted)");
        let m = &out[0];

        // The verbatim credential must appear in NONE of title / metadata.
        assert!(
            !m.title.contains(AWS_KEY),
            "title still verbatim: {}",
            m.title
        );
        let meta = serde_json::to_string(&m.metadata).unwrap();
        assert!(!meta.contains(AWS_KEY), "metadata still verbatim: {meta}");
        // And it was actually masked (not merely dropped from the fields).
        assert!(
            m.title.contains(REDACTED),
            "title not redacted: {}",
            m.title
        );
        assert!(meta.contains(REDACTED), "metadata not redacted: {meta}");
    }

    #[test]
    fn helper_passes_a_clean_row_through_unchanged() {
        seed_redact();
        let row = memory(
            "ok",
            "clean title",
            "clean body",
            serde_json::json!({"k": "v"}),
        );
        let out = screen_memories_for_export(vec![row.clone()], None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, row.title);
        assert_eq!(out[0].content, row.content);
        assert_eq!(out[0].metadata, row.metadata);
    }

    // ── Path 2 — the CLI `export` command end-to-end (the GA-blocker) ─────

    /// Drive `cli::io::export` against a file-backed DB and capture stdout.
    fn run_cli_export(db_path: &std::path::Path) -> String {
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            ai_memory::cli::io::export(db_path, &mut out).expect("cli export");
        }
        String::from_utf8(stdout).expect("stdout is utf8")
    }

    #[test]
    fn cli_export_drops_forbidden_class_keeps_clean_and_preserves_1944_markers() {
        seed_redact();
        let dir = tempfile::tempdir().unwrap();
        let dbp = dir.path().join("g3.db");
        {
            let conn = db::open(&dbp).expect("open");
            db::insert(&conn, &memory("keep", "meeting", "ordinary", Value::Null))
                .expect("insert clean");
            // A biometric-tagged row survives the write funnel (the tag is not a
            // credential VALUE) — so the EXPORT gate is what must drop it.
            db::insert(
                &conn,
                &memory(
                    "bio",
                    "t",
                    "c",
                    serde_json::json!({"embedding_class": "biometric"}),
                ),
            )
            .expect("insert biometric");
        }

        let stdout = run_cli_export(&dbp);
        // stdout MUST be valid JSON (a piped `export > backup.json` stays parseable).
        let v: Value = serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");

        // Forbidden row dropped; clean row present; count reflects survivors.
        let mems = v["memories"].as_array().expect("memories array");
        let ids: Vec<&str> = mems.iter().filter_map(|m| m["id"].as_str()).collect();
        assert!(ids.contains(&"keep"), "clean row must export: {ids:?}");
        assert!(
            !ids.contains(&"bio"),
            "biometric row must be dropped: {ids:?}"
        );
        assert_eq!(
            v["count"].as_u64(),
            Some(1),
            "count is post-screen survivors"
        );

        // #1944 in-band scope markers must remain intact (do NOT regress them).
        assert!(v[field_names::EXPORTED_AT].is_string());
        assert_eq!(
            v[field_names::EXPORT_SCOPE].as_str(),
            Some(ai_memory::export_scope::SCOPE_MEMORIES_LINKS)
        );
        assert_eq!(
            v[field_names::PORTABILITY_COMPLETE].as_bool(),
            Some(ai_memory::export_scope::PORTABILITY_COMPLETE)
        );
        assert!(
            v[field_names::EXCLUDES].is_array(),
            "excludes marker present"
        );
    }

    #[test]
    fn cli_export_redacts_a_pre_screen_credential_in_title_and_metadata() {
        seed_redact();
        let dir = tempfile::tempdir().unwrap();
        let dbp = dir.path().join("g3c.db");
        {
            let conn = db::open(&dbp).expect("open");
            db::insert(
                &conn,
                &memory("legacy", "clean", "clean", serde_json::json!({"k": "v"})),
            )
            .expect("insert");
            // Inject a verbatim credential via a RAW UPDATE (bypasses the write
            // screen) to simulate a row that PRE-DATES the screen. Only the
            // EXPORT-time screen can catch it now.
            conn.execute(
                "UPDATE memories SET title = ?1, metadata = json_set(metadata, '$.note', ?2) WHERE id = 'legacy'",
                params![AWS_KEY, AWS_KEY],
            )
            .expect("raw update inject");
        }

        let stdout = run_cli_export(&dbp);
        assert!(
            !stdout.contains(AWS_KEY),
            "CLI export leaked a verbatim credential in title/metadata"
        );
        let v: Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
        let m = &v["memories"].as_array().unwrap()[0];
        assert!(m["title"].as_str().unwrap().contains(REDACTED));
        assert!(m["metadata"]["note"].as_str().unwrap().contains(REDACTED));
    }

    // ── Path 3 — the forensic bundle ─────────────────────────────────────

    fn bundle_args(memory_id: &str) -> ai_memory::forensic::bundle::ExportForensicBundleArgs {
        ai_memory::forensic::bundle::ExportForensicBundleArgs {
            memory_id: memory_id.to_string(),
            include_reflections: false,
            include_transcripts: false,
            output: None,
            include_atomisation_chain: false,
        }
    }

    #[test]
    fn forensic_bundle_drops_forbidden_class_and_emits_refusal() {
        seed_redact();
        let dir = tempfile::tempdir().unwrap();
        let dbp = dir.path().join("g3f.db");
        let conn = db::open(&dbp).expect("open");
        db::insert(
            &conn,
            &memory(
                "bio",
                "t",
                "c",
                serde_json::json!({"embedding_class": "biometric"}),
            ),
        )
        .expect("insert biometric");

        let files = ai_memory::forensic::bundle::build_files(
            &conn,
            &bundle_args("bio"),
            Some("2026-01-01T00:00:00Z"),
        )
        .expect("build_files");

        // The forbidden row's envelope must NOT be in the bundle, and a signed
        // refusal must witness the drop.
        assert!(
            !files.contains_key("memories/bio.json"),
            "biometric envelope must not be bundled: {:?}",
            files.keys().collect::<Vec<_>>()
        );
        assert_eq!(refusal_count(&conn), 1, "one signed refusal for the drop");
    }

    #[test]
    fn forensic_bundle_redacts_a_pre_screen_credential_in_title_and_metadata() {
        seed_redact();
        let dir = tempfile::tempdir().unwrap();
        let dbp = dir.path().join("g3fr.db");
        let conn = db::open(&dbp).expect("open");
        db::insert(
            &conn,
            &memory(
                "legacy",
                "clean",
                "clean body",
                serde_json::json!({"k": "v"}),
            ),
        )
        .expect("insert");
        // Simulate a pre-screen row via a raw UPDATE (bypasses the write screen).
        conn.execute(
            "UPDATE memories SET title = ?1, metadata = json_set(metadata, '$.note', ?2) WHERE id = 'legacy'",
            params![AWS_KEY, AWS_KEY],
        )
        .expect("raw update inject");

        let files = ai_memory::forensic::bundle::build_files(
            &conn,
            &bundle_args("legacy"),
            Some("2026-01-01T00:00:00Z"),
        )
        .expect("build_files");

        let bytes = files
            .get("memories/legacy.json")
            .expect("clean-class envelope must be bundled (redacted)");
        let env: Value = serde_json::from_slice(bytes).expect("envelope JSON");
        // Verbatim credential must be masked across title AND metadata.
        assert!(
            !env["title"].as_str().unwrap().contains(AWS_KEY),
            "forensic bundle leaked a verbatim credential in title"
        );
        let meta = serde_json::to_string(&env["metadata"]).unwrap();
        assert!(
            !meta.contains(AWS_KEY),
            "forensic bundle leaked a verbatim credential in metadata"
        );
        assert!(env["title"].as_str().unwrap().contains(REDACTED));
        assert!(meta.contains(REDACTED));
    }
}
