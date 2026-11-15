// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use tempfile::TempDir;

use crate::cli::CliOutput;
use crate::cli::commands::export_reflections::{self, ExportFormat, ExportReflectionsArgs};
use crate::db;
use crate::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};
use crate::models::{ExportPolicy, GovernancePolicy, Memory, MemoryKind, Tier};

const NAMESPACE: &str = "private-export-8369";
const CONTENT: &str = "new reflection export content";
const OLD_CONTENT: &[u8] = b"old destination content";
const PRIVATE_MODE: u32 = 0o600;
const LOOSE_MODE: u32 = 0o644;
const MODE_MASK: u32 = 0o777;

#[derive(Clone, Copy)]
enum Writer {
    Cli,
    Auto,
}

struct Fixture {
    _dir: TempDir,
    db_path: PathBuf,
    out_dir: PathBuf,
    destination: PathBuf,
    memory_id: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("memory.db");
        let conn = db::open(&db_path).unwrap();
        let now = Utc::now().to_rfc3339();
        let policy = GovernancePolicy {
            export: ExportPolicy {
                auto_export_reflections_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NAMESPACE.into(),
            tier: Tier::Long,
            title: "export standard".into(),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({"agent_id": "ai:test", "governance": policy}),
            ..Default::default()
        };
        let standard_id = db::insert(&conn, &standard).unwrap();
        db::set_namespace_standard(&conn, NAMESPACE, &standard_id, None).unwrap();
        let reflection = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NAMESPACE.into(),
            tier: Tier::Mid,
            memory_kind: MemoryKind::Reflection,
            title: "private export".into(),
            content: CONTENT.into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            ..Default::default()
        };
        let memory_id = db::insert(&conn, &reflection).unwrap();
        let out_dir = dir.path().join("out");
        let ns_dir = out_dir.join(NAMESPACE);
        PrivateExportDir::open(&out_dir)
            .unwrap()
            .namespace(Path::new(NAMESPACE))
            .unwrap();
        let destination = ns_dir.join(format!("{memory_id}.md"));
        Self {
            _dir: dir,
            db_path,
            out_dir,
            destination,
            memory_id,
        }
    }

    fn export(&self, writer: Writer) -> Result<()> {
        match writer {
            Writer::Cli => {
                let args = ExportReflectionsArgs {
                    namespace: Some(NAMESPACE.into()),
                    out_dir: Some(self.out_dir.clone()),
                    format: "md".into(),
                    since: None,
                    quiet: true,
                };
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut output = CliOutput {
                    stdout: &mut stdout,
                    stderr: &mut stderr,
                };
                assert_eq!(
                    export_reflections::run(&self.db_path, &args, &mut output)?,
                    0
                );
                Ok(())
            }
            Writer::Auto => run_auto_export(
                &self.db_path,
                &self.memory_id,
                NAMESPACE,
                &AutoExportConfig {
                    out_dir: self.out_dir.clone(),
                    format: ExportFormat::Markdown,
                },
            ),
        }
    }

    fn assert_private_content(&self) {
        assert_eq!(
            fs::metadata(&self.destination).unwrap().mode() & MODE_MASK,
            PRIVATE_MODE
        );
        assert!(
            fs::read_to_string(&self.destination)
                .unwrap()
                .contains(CONTENT)
        );
        self.assert_no_staging();
    }

    fn assert_no_staging(&self) {
        for entry in fs::read_dir(self.destination.parent().unwrap()).unwrap() {
            assert_eq!(
                entry.unwrap().path(),
                self.destination,
                "staging file leaked"
            );
        }
    }
}

struct InjectFailure;

impl InjectFailure {
    fn new() -> Self {
        super::FAIL_BEFORE_RENAME.set(true);
        Self
    }
}

impl Drop for InjectFailure {
    fn drop(&mut self) {
        super::FAIL_BEFORE_RENAME.set(false);
    }
}

fn creates_private_file(writer: Writer) {
    let fixture = Fixture::new();
    fixture.export(writer).unwrap();
    fixture.assert_private_content();
}

fn refuses_symlink(writer: Writer) {
    let fixture = Fixture::new();
    let target = fixture.out_dir.join("target");
    fs::write(&target, OLD_CONTENT).unwrap();
    symlink(&target, &fixture.destination).unwrap();
    let result = fixture.export(writer);
    assert_eq!(
        fs::read(&target).unwrap(),
        OLD_CONTENT,
        "symlink target changed"
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("private_export_symlink_refused"));
    assert!(
        fs::symlink_metadata(&fixture.destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fixture.assert_no_staging();
}

fn replaces_loose_regular_file(writer: Writer) {
    let fixture = Fixture::new();
    fs::write(&fixture.destination, OLD_CONTENT).unwrap();
    fs::set_permissions(&fixture.destination, fs::Permissions::from_mode(LOOSE_MODE)).unwrap();
    let mut old_inode = fs::File::open(&fixture.destination).unwrap();
    let old_ino = old_inode.metadata().unwrap().ino();
    fixture.export(writer).unwrap();
    fixture.assert_private_content();
    assert_ne!(fs::metadata(&fixture.destination).unwrap().ino(), old_ino);
    let mut original = Vec::new();
    old_inode.read_to_end(&mut original).unwrap();
    assert_eq!(original, OLD_CONTENT);
}

fn cleans_staging_on_failure(writer: Writer) {
    let fixture = Fixture::new();
    fs::write(&fixture.destination, OLD_CONTENT).unwrap();
    let injection = InjectFailure::new();
    let result = fixture.export(writer);
    drop(injection);
    assert!(format!("{:#}", result.unwrap_err()).contains("before rename injected failure"));
    assert_eq!(fs::read(&fixture.destination).unwrap(), OLD_CONTENT);
    fixture.assert_no_staging();
}

fn refuses_non_regular_file(writer: Writer) {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.destination).unwrap();
    let error = fixture.export(writer).unwrap_err();
    assert!(format!("{error:#}").contains("private_export_non_regular_refused"));
    assert!(fixture.destination.is_dir());
    fixture.assert_no_staging();
}

#[test]
fn cli_creates_private_file_8369() {
    creates_private_file(Writer::Cli);
}
#[test]
fn auto_creates_private_file_8369() {
    creates_private_file(Writer::Auto);
}
#[test]
fn cli_refuses_symlink_8369() {
    refuses_symlink(Writer::Cli);
}
#[test]
fn auto_refuses_symlink_8369() {
    refuses_symlink(Writer::Auto);
}
#[test]
fn cli_replaces_loose_regular_file_8369() {
    replaces_loose_regular_file(Writer::Cli);
}
#[test]
fn auto_replaces_loose_regular_file_8369() {
    replaces_loose_regular_file(Writer::Auto);
}
#[test]
fn cli_cleans_staging_on_failure_8369() {
    cleans_staging_on_failure(Writer::Cli);
}
#[test]
fn auto_cleans_staging_on_failure_8369() {
    cleans_staging_on_failure(Writer::Auto);
}
#[test]
fn cli_refuses_non_regular_file_8369() {
    refuses_non_regular_file(Writer::Cli);
}
#[test]
fn auto_refuses_non_regular_file_8369() {
    refuses_non_regular_file(Writer::Auto);
}

struct InjectFlag(&'static std::thread::LocalKey<std::cell::Cell<bool>>);

impl InjectFlag {
    fn new(flag: &'static std::thread::LocalKey<std::cell::Cell<bool>>) -> Self {
        flag.set(true);
        Self(flag)
    }
}

impl Drop for InjectFlag {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

fn set_stale(path: &std::path::Path) {
    let age = std::time::Duration::from_hours(2);
    fs::File::open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - age)
        .unwrap();
}

fn syncs_published_directory(writer: Writer) {
    let fixture = Fixture::new();
    super::DIRECTORY_SYNC_CALLED.set(false);
    fixture.export(writer).unwrap();
    assert!(
        super::DIRECTORY_SYNC_CALLED.get(),
        "directory was not synced"
    );
    fixture.assert_private_content();
}

fn directory_sync_failure_keeps_published_file(writer: Writer) {
    let fixture = Fixture::new();
    let injection = InjectFlag::new(&super::FAIL_DIRECTORY_SYNC);
    let error = fixture.export(writer).unwrap_err();
    drop(injection);
    assert!(format!("{error:#}").contains("directory sync injected failure"));
    fixture.assert_private_content();
}

fn sweeps_only_stale_regular_staging(writer: Writer) {
    let fixture = Fixture::new();
    let parent = fixture.destination.parent().unwrap();
    let stale = parent.join(".private-export-stale.stage");
    let fresh = parent.join(".private-export-fresh.stage");
    let future = parent.join(".private-export-future.stage");
    let link = parent.join(".private-export-link.stage");
    let directory = parent.join(".private-export-directory.stage");
    let unrelated = parent.join("unrelated.stage");
    let target = fixture.out_dir.join("symlink-target");
    for path in [&stale, &fresh, &future, &unrelated, &target] {
        fs::write(path, OLD_CONTENT).unwrap();
    }
    for path in [&stale, &unrelated, &target] {
        set_stale(path);
    }
    fs::File::open(&future)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_hours(2))
        .unwrap();
    fs::create_dir(&directory).unwrap();
    set_stale(&directory);
    symlink(&target, &link).unwrap();
    fixture.export(writer).unwrap();
    assert!(!stale.exists(), "old regular staging file was retained");
    assert_eq!(
        fs::read(&fresh).unwrap(),
        OLD_CONTENT,
        "fresh staging changed"
    );
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&target).unwrap(),
        OLD_CONTENT,
        "symlink target changed"
    );
    assert_eq!(
        fs::read(&future).unwrap(),
        OLD_CONTENT,
        "future staging changed"
    );
    assert!(directory.is_dir(), "staging-shaped directory changed");
    assert_eq!(fs::read(&unrelated).unwrap(), OLD_CONTENT);
    assert!(
        fs::read_to_string(&fixture.destination)
            .unwrap()
            .contains(CONTENT)
    );
    assert_eq!(
        fs::metadata(&fixture.destination).unwrap().mode() & MODE_MASK,
        PRIVATE_MODE
    );
}

#[derive(Clone)]
struct WarningCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for WarningCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn stale_removal_failure_keeps_export_working(writer: Writer) {
    let fixture = Fixture::new();
    let stale = fixture
        .destination
        .parent()
        .unwrap()
        .join(".private-export-stale.stage");
    fs::write(&stale, OLD_CONTENT).unwrap();
    set_stale(&stale);
    super::STALE_REMOVAL_ATTEMPTED.set(false);
    let injection = InjectFlag::new(&super::FAIL_STALE_REMOVAL);
    let warnings = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = std::sync::Arc::clone(&warnings);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || WarningCapture(std::sync::Arc::clone(&capture)))
        .finish();
    tracing::subscriber::with_default(subscriber, || fixture.export(writer)).unwrap();
    drop(injection);
    let warning_bytes = warnings.lock().unwrap();
    let warning_text = String::from_utf8_lossy(&warning_bytes);
    assert!(warning_text.contains("private_export_stale_stage_cleanup_failed"));
    assert!(
        super::STALE_REMOVAL_ATTEMPTED.get(),
        "stale cleanup was not attempted"
    );
    assert_eq!(fs::read(&stale).unwrap(), OLD_CONTENT);
    assert!(
        fs::read_to_string(&fixture.destination)
            .unwrap()
            .contains(CONTENT)
    );
}

#[test]
fn cli_syncs_published_directory_r2_8369() {
    syncs_published_directory(Writer::Cli);
}
#[test]
fn auto_syncs_published_directory_r2_8369() {
    syncs_published_directory(Writer::Auto);
}
#[test]
fn cli_directory_sync_failure_keeps_published_file_r2_8369() {
    directory_sync_failure_keeps_published_file(Writer::Cli);
}
#[test]
fn auto_directory_sync_failure_keeps_published_file_r2_8369() {
    directory_sync_failure_keeps_published_file(Writer::Auto);
}
#[test]
fn cli_sweeps_only_stale_regular_staging_r2_8369() {
    sweeps_only_stale_regular_staging(Writer::Cli);
}
#[test]
fn auto_sweeps_only_stale_regular_staging_r2_8369() {
    sweeps_only_stale_regular_staging(Writer::Auto);
}
#[test]
fn cli_stale_removal_failure_keeps_export_working_r2_8369() {
    if crate::config::run_env_isolated_child_or_spawn(
        "cli::commands::export_reflections::private_file::tests::cli_stale_removal_failure_keeps_export_working_r2_8369",
    ) {
        return;
    }
    stale_removal_failure_keeps_export_working(Writer::Cli);
}
#[test]
fn auto_stale_removal_failure_keeps_export_working_r2_8369() {
    if crate::config::run_env_isolated_child_or_spawn(
        "cli::commands::export_reflections::private_file::tests::auto_stale_removal_failure_keeps_export_working_r2_8369",
    ) {
        return;
    }
    stale_removal_failure_keeps_export_working(Writer::Auto);
}

#[test]
fn cli_sweeps_once_per_destination_directory_per_run_8595() {
    const SECOND_NAMESPACE: &str = "second-export-8595";
    let fixture = Fixture::new();
    let conn = db::open(&fixture.db_path).unwrap();
    let template = db::get(&conn, &fixture.memory_id).unwrap().unwrap();
    let mut destinations = vec![fixture.destination.clone()];
    for namespace in [NAMESPACE, NAMESPACE, SECOND_NAMESPACE, SECOND_NAMESPACE] {
        let mut reflection = template.clone();
        reflection.id = uuid::Uuid::new_v4().to_string();
        reflection.title = format!("sweep-fixture-{}", reflection.id);
        reflection.content = format!("{CONTENT} sweep-fixture-{}", reflection.id);
        reflection.namespace = namespace.into();
        let id = db::insert(&conn, &reflection).unwrap();
        destinations.push(fixture.out_dir.join(namespace).join(format!("{id}.md")));
    }
    let mut args = ExportReflectionsArgs {
        namespace: Some(NAMESPACE.into()),
        out_dir: Some(fixture.out_dir.clone()),
        format: "md".into(),
        since: None,
        quiet: true,
    };
    for (expected_sweeps, expected_exports) in [(1, 3), (2, 5), (2, 5)] {
        super::STAGING_SWEEP_COUNT.set(0);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        assert_eq!(
            export_reflections::run(&fixture.db_path, &args, &mut output).unwrap(),
            0
        );
        assert!(
            String::from_utf8(stdout)
                .unwrap()
                .contains(&format!("exported {expected_exports} reflection(s)"))
        );
        assert_eq!(
            super::STAGING_SWEEP_COUNT.get(),
            expected_sweeps,
            "each destination directory must be swept once on every CLI run"
        );
        args.namespace = None;
    }
    for destination in destinations {
        assert!(fs::read_to_string(&destination).unwrap().contains(CONTENT));
        assert_eq!(
            fs::metadata(destination).unwrap().mode() & MODE_MASK,
            PRIVATE_MODE
        );
    }
    for _ in 0..2 {
        super::STAGING_SWEEP_COUNT.set(0);
        fixture.export(Writer::Auto).unwrap();
        assert_eq!(
            super::STAGING_SWEEP_COUNT.get(),
            1,
            "each auto-export must sweep"
        );
    }
}
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

fn scratch() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/private-export-8592-8593");
    fs::create_dir_all(&root).unwrap();
    tempfile::tempdir_in(root).unwrap()
}

#[test]
fn pre_rename_failure_removes_only_owned_stage_8592() {
    let scratch = scratch();
    let path = scratch.path().join("root");
    let root = PrivateExportDir::open(&path).unwrap();
    root.write("entity.md", b"old private").unwrap();
    fs::write(path.join("unrelated.stage"), b"unrelated").unwrap();
    let injection = InjectFlag::new(&FAIL_BEFORE_RENAME);
    let error = root.write("entity.md", b"new private").unwrap_err();
    drop(injection);
    assert!(error.to_string().contains("before rename injected failure"));
    assert_eq!(fs::read(path.join("entity.md")).unwrap(), b"old private");
    assert_eq!(
        fs::read(path.join("unrelated.stage")).unwrap(),
        b"unrelated"
    );
    assert_eq!(fs::read_dir(path).unwrap().count(), 2);
}

#[test]
fn stage_cleanup_failure_retains_original_error_8592() {
    let scratch = scratch();
    let path = scratch.path().join("root");
    let root = PrivateExportDir::open(&path).unwrap();
    let before = InjectFlag::new(&FAIL_BEFORE_RENAME);
    let cleanup = InjectFlag::new(&FAIL_STAGE_CLEANUP);
    let error = root.write("entity.md", b"private").unwrap_err();
    drop(cleanup);
    drop(before);
    let message = error.to_string();
    assert!(message.contains("before rename injected failure"));
    assert!(message.contains("stage cleanup injected failure"));
    assert!(!path.join("entity.md").exists());
    let entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    let stage = &entries[0];
    assert!(
        stage
            .file_name()
            .to_str()
            .unwrap()
            .starts_with(".private-export-")
    );
    assert_eq!(
        stage.metadata().unwrap().mode() & MODE_MASK,
        PRIVATE_FILE_MODE
    );
    assert_eq!(fs::read(stage.path()).unwrap(), b"private");
}

#[test]
fn directory_sync_failure_keeps_published_private_file_8592() {
    let scratch = scratch();
    let path = scratch.path().join("root");
    let root = PrivateExportDir::open(&path).unwrap();
    let injection = InjectFlag::new(&FAIL_DIRECTORY_SYNC);
    let error = root.write("entity.md", b"private").unwrap_err();
    drop(injection);
    assert!(
        error
            .to_string()
            .contains("directory sync injected failure")
    );
    assert_eq!(fs::read(path.join("entity.md")).unwrap(), b"private");
    assert_eq!(
        fs::metadata(path.join("entity.md")).unwrap().mode() & MODE_MASK,
        PRIVATE_FILE_MODE
    );
    assert_eq!(fs::read_dir(path).unwrap().count(), 1);
}

#[test]
fn namespace_creation_sync_failure_is_reported_8593() {
    let scratch = scratch();
    let path = scratch.path().join("root");
    let root = PrivateExportDir::open(&path).unwrap();
    let injection = InjectFlag::new(&FAIL_DIRECTORY_SYNC);
    let error = root.namespace(Path::new("team")).map(|_| ()).unwrap_err();
    drop(injection);
    assert!(
        error
            .to_string()
            .contains("directory sync injected failure")
    );
    assert_eq!(
        fs::metadata(path.join("team")).unwrap().mode() & MODE_MASK,
        PRIVATE_DIRECTORY_MODE
    );
    assert_eq!(fs::read_dir(path.join("team")).unwrap().count(), 0);
    root.namespace(Path::new("team"))
        .unwrap()
        .write("entity.md", b"private")
        .unwrap();
    assert_eq!(fs::read(path.join("team/entity.md")).unwrap(), b"private");
}

#[test]
fn publication_stays_in_opened_directory_after_root_and_namespace_replacement() {
    let scratch = scratch();
    let root_path = scratch.path().join("root");
    let root = PrivateExportDir::open(&root_path).unwrap();
    let namespace = root.namespace(Path::new("team")).unwrap();
    let outside = scratch.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let moved_root = scratch.path().join("moved-root");
    fs::rename(&root_path, &moved_root).unwrap();
    symlink(&outside, &root_path).unwrap();
    fs::rename(moved_root.join("team"), moved_root.join("moved-team")).unwrap();
    symlink(&outside, moved_root.join("team")).unwrap();
    namespace.write("entity.md", b"private").unwrap();
    assert_eq!(
        fs::read(moved_root.join("moved-team/entity.md")).unwrap(),
        b"private"
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert!(root.namespace(Path::new("team")).is_err());
}

#[test]
fn root_symlinks_with_trailing_separators_are_refused() {
    let scratch = scratch();
    let outside = scratch.path().join("outside");
    PrivateExportDir::open(&outside).unwrap();
    let link = scratch.path().join("link");
    symlink(&outside, &link).unwrap();
    for suffix in ["", "/", "/."] {
        assert!(PrivateExportDir::open(Path::new(&format!("{}{suffix}", link.display()))).is_err());
    }
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}

#[test]
fn nonregular_destination_and_unsafe_names_are_refused_without_staging() {
    let scratch = scratch();
    let root_path = scratch.path().join("root");
    let root = PrivateExportDir::open(&root_path).unwrap();
    fs::create_dir(root_path.join("directory.md")).unwrap();
    for name in ["directory.md", "", ".", "..", "../outside", "nul\0name"] {
        assert!(root.write(name, b"private").is_err());
    }
    assert_eq!(fs::read_dir(root_path).unwrap().count(), 1);
}

#[test]
fn hardlinked_existing_file_is_replaced_without_modifying_the_other_link() {
    let scratch = scratch();
    let root_path = scratch.path().join("root");
    let root = PrivateExportDir::open(&root_path).unwrap();
    let outside = scratch.path().join("operator-file");
    fs::write(&outside, b"operator content").unwrap();
    fs::hard_link(&outside, root_path.join("entity.md")).unwrap();
    root.write("entity.md", b"private").unwrap();
    assert_eq!(fs::read(outside).unwrap(), b"operator content");
    assert_eq!(
        fs::metadata(root_path.join("entity.md")).unwrap().mode() & MODE_MASK,
        PRIVATE_FILE_MODE
    );
    assert_eq!(fs::read_dir(root_path).unwrap().count(), 1);
}

#[test]
fn existing_private_directory_can_be_reopened_without_permission_changes() {
    let scratch = scratch();
    let path = scratch.path().join("root");
    PrivateExportDir::open(&path).unwrap();
    let permissions = fs::metadata(&path).unwrap().permissions().mode();
    let root = PrivateExportDir::open(&path).unwrap();
    root.namespace(Path::new("team/alpha"))
        .unwrap()
        .write("reflection.md", b"private")
        .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode(),
        permissions
    );
}

#[test]
fn stale_sweep_stays_in_opened_directory_after_namespace_replacement_8602() {
    let scratch = scratch();
    let root_path = scratch.path().join("root");
    let root = PrivateExportDir::open(&root_path).unwrap();
    let namespace = root.namespace(Path::new("team")).unwrap();
    let stage_name = ".private-export-stale.stage";
    let original = root_path.join("team").join(stage_name);
    fs::write(&original, OLD_CONTENT).unwrap();
    set_stale(&original);
    let outside = scratch.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let outside_stage = outside.join(stage_name);
    fs::write(&outside_stage, OLD_CONTENT).unwrap();
    set_stale(&outside_stage);
    let moved = root_path.join("moved-team");
    fs::rename(root_path.join("team"), &moved).unwrap();
    symlink(&outside, root_path.join("team")).unwrap();
    namespace.sweep_stale_staging();
    assert!(!moved.join(stage_name).exists());
    assert_eq!(fs::read(outside_stage).unwrap(), OLD_CONTENT);
    namespace.write("entity.md", CONTENT.as_bytes()).unwrap();
    assert_eq!(
        fs::read_to_string(moved.join("entity.md")).unwrap(),
        CONTENT
    );
    assert!(!outside.join("entity.md").exists());
}
