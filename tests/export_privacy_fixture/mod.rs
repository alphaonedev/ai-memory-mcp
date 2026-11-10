// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Real export entry points sharing a scratch-only SQLite fixture.
#![allow(dead_code)]

use std::path::PathBuf;

use ai_memory::autonomy::AutonomyLlm;
use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::export_reflections::{self, ExportFormat, ExportReflectionsArgs};
use ai_memory::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};
use ai_memory::hooks::post_reflect::auto_persona::{AutoPersonaConfig, run_auto_persona};
use ai_memory::models::{ExportPolicy, GovernancePolicy, Memory, MemoryKind, PersonaPolicy, Tier};

pub const PRIVATE_FILE: u32 = 0o600;
pub const PRIVATE_DIR: u32 = 0o700;
pub const BROAD_DIR: u32 = 0o755;
pub const MODE_MASK: u32 = 0o777;
pub const OLD_CONTENT: &[u8] = b"existing operator data";

#[derive(Clone, Copy, Debug)]
pub enum Writer {
    Cli,
    ReflectionHook,
    PersonaHook,
}

struct StubLlm;

impl AutonomyLlm for StubLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, _memories: &[(String, String)]) -> anyhow::Result<String> {
        Ok("private persona export payload".to_string())
    }
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub out: PathBuf,
    pub namespace: String,
    pub entity: String,
    pub reflection: String,
    db_path: PathBuf,
}

impl Fixture {
    pub fn new(namespace: &str, entity: &str) -> Self {
        let root = PathBuf::from(".local-runs/export-privacy-8592-8593");
        std::fs::create_dir_all(&root).expect("scratch root");
        let dir = tempfile::tempdir_in(root).expect("scratch dir");
        let db_path = dir.path().join("memory.db");
        let conn = ai_memory::db::open(&db_path).expect("database");
        let now = chrono::Utc::now().to_rfc3339();
        let policy = GovernancePolicy {
            export: ExportPolicy {
                auto_export_reflections_to_filesystem: Some(true),
            },
            persona: PersonaPolicy {
                auto_persona_trigger_every_n_memories: Some(1),
                auto_export_personas_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: namespace.to_string(),
            tier: Tier::Long,
            title: "export policy".to_string(),
            content: "private export fixture".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({"agent_id": "ai:test", "governance": policy}),
            ..Default::default()
        };
        let standard_id = ai_memory::db::insert(&conn, &standard).expect("standard");
        ai_memory::db::set_namespace_standard(&conn, namespace, &standard_id, None)
            .expect("install policy");
        let memory = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: namespace.to_string(),
            tier: Tier::Mid,
            memory_kind: MemoryKind::Reflection,
            reflection_depth: 1,
            title: format!("reflection about {entity}"),
            content: "private reflection export payload".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id": "ai:test", "entity_id": entity}),
            ..Default::default()
        };
        let reflection = ai_memory::db::insert(&conn, &memory).expect("reflection");
        let out = dir.path().join("exports");
        Self {
            dir,
            out,
            namespace: namespace.to_string(),
            entity: entity.to_string(),
            reflection,
            db_path,
        }
    }

    pub fn namespace_dir(&self, writer: Writer) -> PathBuf {
        self.out.join(match writer {
            Writer::PersonaHook => self.namespace.replace('/', "_"),
            Writer::Cli | Writer::ReflectionHook => self.namespace.clone(),
        })
    }

    pub fn destination(&self, writer: Writer) -> PathBuf {
        self.namespace_dir(writer).join(format!(
            "{}.md",
            match writer {
                Writer::PersonaHook => self.entity.replace('/', "_"),
                Writer::Cli | Writer::ReflectionHook => self.reflection.clone(),
            }
        ))
    }

    pub fn export(&self, writer: Writer) -> anyhow::Result<()> {
        match writer {
            Writer::Cli => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut output = CliOutput {
                    stdout: &mut stdout,
                    stderr: &mut stderr,
                };
                let args = ExportReflectionsArgs {
                    namespace: Some(self.namespace.clone()),
                    out_dir: Some(self.out.clone()),
                    format: "md".to_string(),
                    since: None,
                    quiet: true,
                };
                assert_eq!(
                    export_reflections::run(&self.db_path, &args, &mut output)?,
                    0
                );
                Ok(())
            }
            Writer::ReflectionHook => run_auto_export(
                &self.db_path,
                &self.reflection,
                &self.namespace,
                &AutoExportConfig {
                    out_dir: self.out.clone(),
                    format: ExportFormat::Markdown,
                },
            ),
            Writer::PersonaHook => run_auto_persona(
                &self.db_path,
                &self.reflection,
                &self.namespace,
                &AutoPersonaConfig {
                    out_dir: self.out.clone(),
                },
                &StubLlm,
                None,
            ),
        }
    }

    #[cfg(unix)]
    pub fn prepare_private_parent(&self, writer: Writer) {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = self.namespace_dir(writer);
        std::fs::create_dir_all(&parent).expect("parent");
        let mut current = parent.as_path();
        loop {
            std::fs::set_permissions(current, std::fs::Permissions::from_mode(PRIVATE_DIR))
                .expect("mode");
            if current == self.out {
                break;
            }
            current = current.parent().expect("within export root");
        }
    }
}
