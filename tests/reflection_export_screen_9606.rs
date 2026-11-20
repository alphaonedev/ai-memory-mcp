// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9606 — every file-writing reflection export path runs the export
//! taxonomy screen (`export_taxonomy::screen_memories_for_export_audited`).
//!
//! Invariant, for all inputs: no memory row leaves the database through a
//! reflection export file unless it passed the screen. A row that
//! `classify_memory` places in ANY `ForbiddenExportClass` (the closed set is
//! iterated, never re-listed) is never written, in markdown or JSON, by the
//! CLI `export-reflections` or by the post-reflect auto-export hook, and it
//! leaves exactly one signed `export.forbidden_class_refused` row bound to
//! its class token. A clean row is written byte-identical to the chain-tip
//! renderer. A row the secret screen alters is written redacted.
//!
//! Fixtures follow the #8598 / Gate-3 precedent: rows are inserted clean and
//! the class-specific content or metadata is injected with a raw UPDATE, the
//! shape of a durable row that predates the ingestion screen.
//!
//! Everything lives under `mod tests` so the repository literal gates treat
//! the fixtures as test code (the Gate-3 precedent).

#[path = "common/cfg_test_modules.rs"]
mod cfg_test_modules;

#[cfg(test)]
mod tests {
    use super::cfg_test_modules::production_sources;
    use ai_memory::autonomy::AutonomyLlm;
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::commands::export_reflections::{self, ExportFormat, ExportReflectionsArgs};
    use ai_memory::db;
    use ai_memory::export_scope::{EXIT_EXPORT_INCOMPLETE, EXPORT_REPORT_EVENT};
    use ai_memory::export_taxonomy::{
        ALL_FORBIDDEN_EXPORT_CLASSES, ForbiddenExportClass, classify_memory,
        screen_memories_for_export_audited,
    };
    use ai_memory::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};
    use ai_memory::hooks::post_reflect::auto_persona::{AutoPersonaConfig, run_auto_persona};
    use ai_memory::models::{
        ExportPolicy, GovernancePolicy, Memory, MemoryKind, PersonaPolicy, Tier,
    };
    use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
    use ai_memory::signed_events::event_types::EXPORT_FORBIDDEN_CLASS_REFUSED;
    use ai_memory::signed_events::payload_hash;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const NAMESPACE: &str = "reflection-screen-9606";
    const CLEAN_ID: &str = "clean-9606";
    const FORBIDDEN_ID: &str = "forbidden-9606";
    const REDACT_ID: &str = "redact-9606";
    const FIXED_CREATED_AT: &str = "2026-01-01T00:00:00+00:00";
    const CLEAN_TITLE: &str = "clean reflection";
    const CLEAN_CONTENT: &str = "a clean reflection body";
    const CLEAN_METADATA: &str = r#"{"agent_id":"agent-9606"}"#;
    // A mis-stored PEM private key (forbidden CLASS = private-key material).
    // Same fixture as tests/gate3_export_boundary.rs.
    const PEM_CONTENT: &str = "leaked:\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END";
    // The canonical AWS documentation example key id (a credential VALUE the
    // secret screen masks). Same fixture as tests/gate3_export_boundary.rs.
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    // The redaction placeholder the secret screen substitutes for a hit.
    const REDACTED: &str = "REDACTED";
    // The armor token of PEM_CONTENT that must never reach a persona file.
    const PEM_PRIVATE_KEY_MARKER: &str = "PRIVATE KEY";
    const AUDIT_FAIL_TRIGGER: &str = "CREATE TRIGGER refuse_audit_9606 BEFORE INSERT ON \
         signed_events BEGIN SELECT RAISE(ABORT, 'audit append refused 9606'); END";

    /// Chain-tip (fd43a727) renderer output for the clean fixture, markdown.
    const CLEAN_MD_BYTES: &str = "---\n\
        memory_id: clean-9606\n\
        namespace: reflection-screen-9606\n\
        title: clean reflection\n\
        reflection_depth: 0\n\
        attest_level: unsigned\n\
        created_at: 2026-01-01T00:00:00+00:00\n\
        agent_id: agent-9606\n\
        reflects_on:\n  []\n\
        ---\n\n\
        a clean reflection body\n";
    /// Chain-tip (fd43a727) renderer output for the clean fixture, JSON.
    const CLEAN_JSON_BYTES: &str = "{\n  \"memory_id\": \"clean-9606\",\n  \
        \"namespace\": \"reflection-screen-9606\",\n  \
        \"title\": \"clean reflection\",\n  \
        \"reflection_depth\": 0,\n  \
        \"attest_level\": \"unsigned\",\n  \
        \"created_at\": \"2026-01-01T00:00:00+00:00\",\n  \
        \"agent_id\": \"agent-9606\",\n  \
        \"reflects_on\": [],\n  \
        \"content\": \"a clean reflection body\"\n}";

    /// CLI corpus: reflections exported by ONE CLI run. Each file is a
    /// durable private write (fsync per file), so the end-to-end run is
    /// bounded by the disk, not the screen; the wall-clock bound sits on the
    /// screen itself (`SCREEN_SCALE_ROWS`).
    const SCALE_REFLECTIONS: usize = 200;
    /// Every Nth CLI row carries a forbidden-class marker.
    const SCALE_FORBIDDEN_EVERY: usize = 20;
    /// Rows screened in ONE in-process `screen_memories_for_export_audited`
    /// call (the scanner bound).
    const SCREEN_SCALE_ROWS: usize = 20_000;
    /// Every Nth screened row carries a forbidden-class marker.
    const SCREEN_FORBIDDEN_EVERY: usize = 100;
    /// One extra row whose body is this many bytes (the 100K+ input).
    const SCREEN_LARGE_BODY_BYTES: usize = 256 * 1024;
    /// Wall-clock ceiling for screening `SCREEN_SCALE_ROWS` rows plus the
    /// large body in an unoptimised test build. The screen is one serialize,
    /// classify and secret scan per row, so the cost is linear; a quadratic
    /// regression over 20,000 rows blows far past this.
    const SCREEN_WALL_CLOCK_CEILING: Duration = Duration::from_secs(60);

    /// Production prefixes whose files write reflection-derived bytes.
    const CENSUS_PREFIXES: [&str; 2] = [
        "src/cli/commands/export_reflections",
        "src/hooks/post_reflect/",
    ];
    /// The private-file writer primitive: it never sees a `Memory`.
    const CENSUS_PRIMITIVE_PREFIX: &str = "src/cli/commands/export_reflections/private_file";
    /// Tokens that open or write a file.
    const CENSUS_SINKS: [&str; 4] = [
        ".write(",
        "fs::write(",
        "File::create(",
        "OpenOptions::new(",
    ];
    /// The screen every sink-bearing file must call before its first sink.
    const CENSUS_SCREEN: &str = "screen_memories_for_export_audited(";
    /// Sink-bearing files at the chain tip (the measured census).
    const CENSUS_KNOWN_WRITERS: [&str; 3] = [
        "src/cli/commands/export_reflections.rs",
        "src/hooks/post_reflect/auto_export.rs",
        "src/hooks/post_reflect/auto_persona.rs",
    ];

    #[derive(Clone, Copy, Debug)]
    enum Writer {
        Cli,
        Auto,
    }

    fn seed_redact() {
        set_screen_mode(SecretScreenMode::Redact);
    }

    fn extension(format: ExportFormat) -> &'static str {
        match format {
            ExportFormat::Markdown => "md",
            ExportFormat::Json => "json",
        }
    }

    fn format_flag(format: ExportFormat) -> String {
        extension(format).to_string()
    }

    /// Open the fixture db with the namespace auto-export policy enabled.
    fn fixture_db(db_path: &Path) -> rusqlite::Connection {
        let conn = db::open(db_path).unwrap();
        let policy = GovernancePolicy {
            export: ExportPolicy {
                auto_export_reflections_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: "namespace standard".into(),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({"governance": policy}),
            ..Default::default()
        };
        let standard_id = db::insert(&conn, &standard).unwrap();
        db::set_namespace_standard(&conn, NAMESPACE, &standard_id, None).unwrap();
        conn
    }

    /// Insert a clean row, then raw-UPDATE it into the stored reflection shape.
    fn put_reflection(
        conn: &rusqlite::Connection,
        id: &str,
        title: &str,
        content: &str,
        metadata: &str,
    ) {
        let placeholder = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: format!("placeholder {id}"),
            content: format!("placeholder body {id}"),
            created_at: FIXED_CREATED_AT.into(),
            updated_at: FIXED_CREATED_AT.into(),
            ..Default::default()
        };
        let original = db::insert(conn, &placeholder).unwrap();
        conn.execute(
            "UPDATE memories SET id = ?1, title = ?2, content = ?3, metadata = ?4, \
             memory_kind = 'reflection', created_at = ?5, updated_at = ?5 WHERE id = ?6",
            rusqlite::params![id, title, content, metadata, FIXED_CREATED_AT, original],
        )
        .unwrap();
    }

    /// Exhaustive over the closed set: a new class fails to compile here.
    fn forbidden_shape(class: ForbiddenExportClass) -> (&'static str, Value) {
        match class {
            ForbiddenExportClass::PrivateKeyMaterial => (PEM_CONTENT, json!({})),
            ForbiddenExportClass::MasterThresholdSecret => {
                ("c", json!({"threshold_share": "1-abc"}))
            }
            ForbiddenExportClass::SignedPolicyRuleSigningKey => {
                ("c", json!({"operator_signing_key": "AAAA"}))
            }
            ForbiddenExportClass::BiometricBehavioralEmbedding => {
                ("c", json!({"embedding_class": "biometric"}))
            }
        }
    }

    fn put_forbidden(conn: &rusqlite::Connection, id: &str, class: ForbiddenExportClass) {
        let (content, metadata) = forbidden_shape(class);
        put_reflection(
            conn,
            id,
            "forbidden reflection",
            content,
            &metadata.to_string(),
        );
        let stored = db::get(conn, id).unwrap().unwrap();
        assert_eq!(
            classify_memory(&stored),
            Some(class),
            "fixture for {} must classify as that class",
            class.as_str()
        );
    }

    fn put_clean(conn: &rusqlite::Connection) {
        put_reflection(conn, CLEAN_ID, CLEAN_TITLE, CLEAN_CONTENT, CLEAN_METADATA);
        assert_eq!(
            classify_memory(&db::get(conn, CLEAN_ID).unwrap().unwrap()),
            None
        );
    }

    fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        let mut result = BTreeMap::new();
        if !root.exists() {
            return result;
        }
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                if entry.file_type().unwrap().is_dir() {
                    result.insert(relative, None);
                    pending.push(path);
                } else {
                    result.insert(relative, Some(fs::read(path).unwrap()));
                }
            }
        }
        result
    }

    fn file_names(root: &Path) -> BTreeSet<PathBuf> {
        tree(root)
            .into_iter()
            .filter_map(|(path, bytes)| bytes.map(|_| path))
            .collect()
    }

    struct CliRun {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn run_cli(db_path: &Path, out_dir: &Path, format: ExportFormat, quiet: bool) -> CliRun {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = export_reflections::run(
            db_path,
            &ExportReflectionsArgs {
                namespace: Some(NAMESPACE.into()),
                out_dir: Some(out_dir.to_path_buf()),
                format: format_flag(format),
                since: None,
                quiet,
            },
            &mut CliOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
        )
        .unwrap();
        CliRun {
            code,
            stdout: String::from_utf8(stdout).unwrap(),
            stderr: String::from_utf8(stderr).unwrap(),
        }
    }

    fn run_auto(db_path: &Path, id: &str, out_dir: &Path, format: ExportFormat) {
        run_auto_export(
            db_path,
            id,
            NAMESPACE,
            &AutoExportConfig {
                out_dir: out_dir.to_path_buf(),
                format,
            },
        )
        .unwrap();
    }

    fn refusal_hashes(conn: &rusqlite::Connection) -> Vec<Vec<u8>> {
        let mut stmt = conn
            .prepare("SELECT payload_hash FROM signed_events WHERE event_type = ?1")
            .unwrap();
        stmt.query_map(rusqlite::params![EXPORT_FORBIDDEN_CLASS_REFUSED], |r| {
            r.get(0)
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<Vec<u8>>>>()
        .unwrap()
    }

    /// The payload hash the screen commits for `id` refused as `class`.
    fn expected_refusal_hash(id: &str, class: ForbiddenExportClass) -> Vec<u8> {
        let reason = format!(
            "export refused: memory classified {} ({}) — dropped from export artifact",
            class.as_str(),
            class.description()
        );
        let preimage = format!(
            "export-forbidden|class={}|artifact=memories/{id}.json|reason={reason}",
            class.as_str()
        );
        payload_hash(preimage.as_bytes())
    }

    fn report_line(stderr: &str) -> Value {
        stderr
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["event"] == EXPORT_REPORT_EVENT)
            .unwrap_or_else(|| panic!("no {EXPORT_REPORT_EVENT} line on stderr: {stderr:?}"))
    }

    /// One (class, writer, format) cell of the table.
    fn assert_forbidden_cell(class: ForbiddenExportClass, writer: Writer, format: ExportFormat) {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("cell.db");
        let out_dir = tmp.path().join("exports");
        let conn = fixture_db(&db_path);
        put_forbidden(&conn, FORBIDDEN_ID, class);
        let cell = format!("{} {writer:?} {format:?}", class.as_str());
        match writer {
            Writer::Cli => {
                put_clean(&conn);
                db::checkpoint(&conn).unwrap();
                let run = run_cli(&db_path, &out_dir, format, false);
                let expected: BTreeSet<PathBuf> =
                    [Path::new(NAMESPACE).join(format!("{CLEAN_ID}.{}", extension(format)))]
                        .into_iter()
                        .collect();
                assert_eq!(file_names(&out_dir), expected, "{cell}: exact ids written");
                assert_eq!(run.code, EXIT_EXPORT_INCOMPLETE, "{cell}: exit code");
                let report = report_line(&run.stderr);
                assert_eq!(report["withheld"], json!(1), "{cell}: {report}");
                assert_eq!(report["exported"], json!(1), "{cell}: {report}");
                assert_eq!(
                    report["withheld_by_class"],
                    json!({ class.as_str(): 1 }),
                    "{cell}: {report}"
                );
                assert!(
                    run.stdout.contains("exported 1 reflection(s)"),
                    "{cell}: {}",
                    run.stdout
                );
                assert!(!run.stdout.contains(FORBIDDEN_ID), "{cell}: {}", run.stdout);
            }
            Writer::Auto => {
                db::checkpoint(&conn).unwrap();
                run_auto(&db_path, FORBIDDEN_ID, &out_dir, format);
                assert!(
                    !out_dir.exists(),
                    "{cell}: no directory, file or staging file: {:?}",
                    tree(&out_dir)
                );
            }
        }
        assert_eq!(
            refusal_hashes(&conn),
            vec![expected_refusal_hash(FORBIDDEN_ID, class)],
            "{cell}: exactly one signed refusal bound to the class token"
        );
    }

    fn assert_forbidden_table(writer: Writer, format: ExportFormat) {
        seed_redact();
        for class in ALL_FORBIDDEN_EXPORT_CLASSES {
            assert_forbidden_cell(class, writer, format);
        }
    }

    #[test]
    fn cli_md_drops_every_forbidden_class_9606() {
        assert_forbidden_table(Writer::Cli, ExportFormat::Markdown);
    }

    #[test]
    fn cli_json_drops_every_forbidden_class_9606() {
        assert_forbidden_table(Writer::Cli, ExportFormat::Json);
    }

    #[test]
    fn auto_md_drops_every_forbidden_class_9606() {
        assert_forbidden_table(Writer::Auto, ExportFormat::Markdown);
    }

    #[test]
    fn auto_json_drops_every_forbidden_class_9606() {
        assert_forbidden_table(Writer::Auto, ExportFormat::Json);
    }

    fn assert_clean_bytes(writer: Writer, format: ExportFormat, expected: &str) {
        seed_redact();
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("clean.db");
        let out_dir = tmp.path().join("exports");
        let conn = fixture_db(&db_path);
        put_clean(&conn);
        db::checkpoint(&conn).unwrap();
        match writer {
            Writer::Cli => {
                let run = run_cli(&db_path, &out_dir, format, true);
                assert_eq!(run.code, 0);
                assert_eq!(run.stderr, "", "a clean export reports nothing");
            }
            Writer::Auto => run_auto(&db_path, CLEAN_ID, &out_dir, format),
        }
        let path = out_dir
            .join(NAMESPACE)
            .join(format!("{CLEAN_ID}.{}", extension(format)));
        assert_eq!(fs::read_to_string(path).unwrap(), expected);
        assert_eq!(refusal_hashes(&conn), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn clean_bytes_identical_to_chain_tip_9606() {
        for writer in [Writer::Cli, Writer::Auto] {
            assert_clean_bytes(writer, ExportFormat::Markdown, CLEAN_MD_BYTES);
            assert_clean_bytes(writer, ExportFormat::Json, CLEAN_JSON_BYTES);
        }
    }

    fn assert_redacted(writer: Writer, format: ExportFormat) {
        seed_redact();
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("redact.db");
        let out_dir = tmp.path().join("exports");
        let conn = fixture_db(&db_path);
        let metadata = json!({"agent_id": "agent-9606", "note": format!("key {AWS_KEY}")});
        put_reflection(
            &conn,
            REDACT_ID,
            &format!("creds {AWS_KEY}"),
            &format!("the key is {AWS_KEY}"),
            &metadata.to_string(),
        );
        db::checkpoint(&conn).unwrap();
        let cell = format!("{writer:?} {format:?}");
        match writer {
            Writer::Cli => {
                let run = run_cli(&db_path, &out_dir, format, true);
                assert_eq!(run.code, 0, "{cell}: redaction alone is not partial");
                let report = report_line(&run.stderr);
                assert_eq!(report["redacted"], json!(1), "{cell}: {report}");
                assert_eq!(report["withheld"], json!(0), "{cell}: {report}");
            }
            Writer::Auto => run_auto(&db_path, REDACT_ID, &out_dir, format),
        }
        let path = out_dir
            .join(NAMESPACE)
            .join(format!("{REDACT_ID}.{}", extension(format)));
        let written = fs::read_to_string(path).unwrap();
        assert!(
            !written.contains(AWS_KEY),
            "{cell}: credential written: {written}"
        );
        assert!(
            written.contains(REDACTED),
            "{cell}: redacted form: {written}"
        );
    }

    #[test]
    fn secret_values_written_redacted_9606() {
        for writer in [Writer::Cli, Writer::Auto] {
            assert_redacted(writer, ExportFormat::Markdown);
            assert_redacted(writer, ExportFormat::Json);
        }
    }

    /// Fail closed: an audit append failure is a WARN and the row is STILL
    /// dropped; the writer itself does not error.
    #[test]
    fn audit_append_failure_still_drops_9606() {
        seed_redact();
        for writer in [Writer::Cli, Writer::Auto] {
            let tmp = TempDir::new().unwrap();
            let db_path = tmp.path().join("audit.db");
            let out_dir = tmp.path().join("exports");
            let conn = fixture_db(&db_path);
            put_forbidden(
                &conn,
                FORBIDDEN_ID,
                ForbiddenExportClass::MasterThresholdSecret,
            );
            conn.execute_batch(AUDIT_FAIL_TRIGGER).unwrap();
            db::checkpoint(&conn).unwrap();
            match writer {
                Writer::Cli => {
                    let run = run_cli(&db_path, &out_dir, ExportFormat::Markdown, true);
                    assert_eq!(run.code, EXIT_EXPORT_INCOMPLETE, "{writer:?}");
                }
                Writer::Auto => {
                    run_auto(&db_path, FORBIDDEN_ID, &out_dir, ExportFormat::Markdown);
                }
            }
            assert!(
                file_names(&out_dir).is_empty(),
                "{writer:?}: {:?}",
                tree(&out_dir)
            );
            assert!(
                refusal_hashes(&conn).is_empty(),
                "{writer:?}: trigger refused it"
            );
        }
    }

    /// The curator stub returns a body carrying private-key material, the
    /// shape of an LLM summary that echoed a mis-stored key.
    struct PemCurator;
    impl AutonomyLlm for PemCurator {
        fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn summarize_memories(&self, _memories: &[(String, String)]) -> anyhow::Result<String> {
            Ok(PEM_CONTENT.to_string())
        }
    }

    /// Sibling writer in the same hook family: the persona export writes
    /// a memory row (the persona) to disk and must run the same screen
    /// over the STORED row. Storage redacts the curator's key material,
    /// so the file must hold the redacted stored form, never the raw
    /// in-memory curator body, and no refusal is owed for a clean row.
    #[test]
    fn auto_persona_export_writes_screened_stored_persona_9606() {
        seed_redact();
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("persona.db");
        let out_dir = tmp.path().join("personas");
        let conn = db::open(&db_path).unwrap();
        let policy = GovernancePolicy {
            persona: PersonaPolicy {
                auto_persona_trigger_every_n_memories: Some(1),
                auto_export_personas_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: "persona standard".into(),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: json!({"governance": policy}),
            ..Default::default()
        };
        let standard_id = db::insert(&conn, &standard).unwrap();
        db::set_namespace_standard(&conn, NAMESPACE, &standard_id, None).unwrap();
        let reflection = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: "obs about alice".into(),
            content: "alice did X".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({"agent_id": "agent-9606", "entity_id": "alice"}),
            memory_kind: MemoryKind::Reflection,
            reflection_depth: 1,
            ..Default::default()
        };
        let reflection_id = db::insert(&conn, &reflection).unwrap();
        db::checkpoint(&conn).unwrap();
        run_auto_persona(
            &db_path,
            &reflection_id,
            NAMESPACE,
            &AutoPersonaConfig {
                out_dir: out_dir.clone(),
            },
            &PemCurator,
            None,
        )
        .unwrap();
        let persona_id: String = conn
            .query_row(
                "SELECT id FROM memories WHERE memory_kind = 'persona'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let persona = db::get(&conn, &persona_id).unwrap().unwrap();
        assert_eq!(
            classify_memory(&persona),
            None,
            "fixture: storage redacts the curator key material"
        );
        let written: BTreeMap<PathBuf, Vec<u8>> = tree(&out_dir)
            .into_iter()
            .filter_map(|(path, bytes)| bytes.map(|b| (path, b)))
            .collect();
        assert_eq!(written.len(), 1, "one persona file: {:?}", written.keys());
        for (path, body) in &written {
            let text = String::from_utf8_lossy(body);
            assert!(
                !text.contains(PEM_PRIVATE_KEY_MARKER),
                "{}: key material written: {text}",
                path.display()
            );
            assert!(text.contains(REDACTED), "{}: {text}", path.display());
        }
        assert!(refusal_hashes(&conn).is_empty(), "clean persona refused");
    }

    /// Source pin over the production view of `src/` (shared cfg(test)
    /// finder): every reflection-export file that opens or writes a file
    /// calls the screen, and calls it before its first sink.
    #[test]
    fn census_every_reflection_writer_screens_9606() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut writers = BTreeSet::new();
        let mut unscreened = Vec::new();
        for (rel, text) in production_sources(root) {
            if !CENSUS_PREFIXES.iter().any(|p| rel.starts_with(p)) {
                continue;
            }
            if rel.starts_with(CENSUS_PRIMITIVE_PREFIX) {
                assert!(
                    !text.contains("Memory"),
                    "{rel}: the private-file primitive must never take a memory row"
                );
                continue;
            }
            let Some(first_sink) = CENSUS_SINKS.iter().filter_map(|s| text.find(s)).min() else {
                continue;
            };
            writers.insert(rel.clone());
            match text.find(CENSUS_SCREEN) {
                Some(at) if at < first_sink => {}
                _ => unscreened.push(rel),
            }
        }
        let known: BTreeSet<String> = CENSUS_KNOWN_WRITERS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(
            known.is_subset(&writers),
            "census lost a known writer: known={known:?} found={writers:?}"
        );
        assert!(
            unscreened.is_empty(),
            "reflection export writers without the export taxonomy screen: {unscreened:?}"
        );
    }

    /// `SCREEN_SCALE_ROWS` rows plus one 256 KiB body through the screen in
    /// ONE call: exact survivor ids in order, exact refusal count, under a
    /// named wall-clock ceiling.
    #[test]
    fn screen_scale_linear_bound_9606() {
        seed_redact();
        let tmp = TempDir::new().unwrap();
        let conn = fixture_db(&tmp.path().join("screen-scale.db"));
        let forbidden = json!({"threshold_share": "1-abc"});
        let mut rows = Vec::with_capacity(SCREEN_SCALE_ROWS + 1);
        let mut expected_ids = Vec::with_capacity(SCREEN_SCALE_ROWS + 1);
        for i in 0..SCREEN_SCALE_ROWS {
            let id = format!("screen-{i:05}");
            let refused = i % SCREEN_FORBIDDEN_EVERY == 0;
            if !refused {
                expected_ids.push(id.clone());
            }
            rows.push(Memory {
                id,
                tier: Tier::Long,
                namespace: NAMESPACE.into(),
                title: format!("screen reflection {i}"),
                content: format!("screen body {i}"),
                metadata: if refused {
                    forbidden.clone()
                } else {
                    json!({})
                },
                created_at: FIXED_CREATED_AT.into(),
                updated_at: FIXED_CREATED_AT.into(),
                ..Default::default()
            });
        }
        let large_body = "a".repeat(SCREEN_LARGE_BODY_BYTES);
        rows.push(Memory {
            id: "screen-large".into(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: "screen large body".into(),
            content: large_body.clone(),
            metadata: json!({}),
            created_at: FIXED_CREATED_AT.into(),
            updated_at: FIXED_CREATED_AT.into(),
            ..Default::default()
        });
        expected_ids.push("screen-large".into());
        let refused = SCREEN_SCALE_ROWS.div_ceil(SCREEN_FORBIDDEN_EVERY);
        let started = Instant::now();
        let (survivors, ledger) = screen_memories_for_export_audited(rows, Some(&conn));
        let elapsed = started.elapsed();
        assert!(
            elapsed < SCREEN_WALL_CLOCK_CEILING,
            "{SCREEN_SCALE_ROWS} rows took {elapsed:?} (ceiling {SCREEN_WALL_CLOCK_CEILING:?})"
        );
        let ids: Vec<String> = survivors.iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, expected_ids);
        assert_eq!(ledger.withheld_total(), refused);
        assert_eq!(refusal_hashes(&conn).len(), refused);
        assert_eq!(
            survivors.last().map(|m| m.content.as_str()),
            Some(large_body.as_str())
        );
    }

    /// `SCALE_REFLECTIONS` reflections in ONE CLI run: exact written and
    /// refused counts and the operator signal.
    #[test]
    fn scale_cli_reflections_9606() {
        seed_redact();
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("scale.db");
        let out_dir = tmp.path().join("exports");
        let conn = fixture_db(&db_path);
        for i in 0..SCALE_REFLECTIONS {
            let row = Memory {
                id: format!("scale-{i:05}"),
                tier: Tier::Long,
                namespace: NAMESPACE.into(),
                title: format!("scale reflection {i}"),
                content: format!("scale body {i}"),
                created_at: FIXED_CREATED_AT.into(),
                updated_at: FIXED_CREATED_AT.into(),
                ..Default::default()
            };
            db::insert(&conn, &row).unwrap();
        }
        conn.execute(
            "UPDATE memories SET memory_kind = 'reflection' WHERE id LIKE 'scale-%'",
            [],
        )
        .unwrap();
        let forbidden = json!({"threshold_share": "1-abc"}).to_string();
        let mut refused = 0usize;
        for i in (0..SCALE_REFLECTIONS).step_by(SCALE_FORBIDDEN_EVERY) {
            conn.execute(
                "UPDATE memories SET metadata = ?1 WHERE id = ?2",
                rusqlite::params![forbidden, format!("scale-{i:05}")],
            )
            .unwrap();
            refused += 1;
        }
        db::checkpoint(&conn).unwrap();
        let run = run_cli(&db_path, &out_dir, ExportFormat::Markdown, true);
        let written = SCALE_REFLECTIONS - refused;
        assert_eq!(file_names(&out_dir).len(), written);
        assert_eq!(run.code, EXIT_EXPORT_INCOMPLETE);
        assert_eq!(report_line(&run.stderr)["withheld"], json!(refused));
        assert_eq!(refusal_hashes(&conn).len(), refused);
        assert!(
            run.stdout
                .contains(&format!("exported {written} reflection(s)")),
            "{}",
            run.stdout
        );
    }
}
