// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Private filesystem publication shared by reflection export writers.

#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::time::{Duration, SystemTime};
use std::{io, path::Path};

#[cfg(unix)]
const PRIVATE_EXPORT_MODE: u32 = 0o600;
#[cfg(unix)]
const STAGING_PREFIX: &str = ".private-export-";
#[cfg(unix)]
const STAGING_SUFFIX: &str = ".stage";
#[cfg(unix)]
const STALE_STAGE_AGE: Duration = Duration::from_hours(1);
#[cfg(unix)]
const STALE_CLEANUP_WARNING: &str = "private_export_stale_stage_cleanup_failed";

#[cfg(unix)]
fn check_destination(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private_export_symlink_refused",
        )),
        Ok(metadata) if !metadata.is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private_export_non_regular_refused",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn remove_stale_staging_entry(entry: &fs::DirEntry, now: SystemTime) -> io::Result<()> {
    if !entry
        .file_name()
        .to_str()
        .is_some_and(|name| name.starts_with(STAGING_PREFIX) && name.ends_with(STAGING_SUFFIX))
    {
        return Ok(());
    }
    let path = entry.path();
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.is_file()
        && now
            .duration_since(metadata.modified()?)
            .is_ok_and(|age| age > STALE_STAGE_AGE)
    {
        #[cfg(test)]
        {
            STALE_REMOVAL_ATTEMPTED.set(true);
            if FAIL_STALE_REMOVAL.get() {
                return Err(io::Error::other("private_export_stale_removal_injected"));
            }
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sweep_stale_staging(parent: &Path) {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(error = %error, message = STALE_CLEANUP_WARNING);
            return;
        }
    };
    let now = SystemTime::now();
    for entry in entries {
        if let Err(error) = entry.and_then(|entry| remove_stale_staging_entry(&entry, now)) {
            // Cleanup is best effort; a leftover private inode must not stop
            // the next export. No payload or destination name is logged.
            tracing::warn!(error = %error, message = STALE_CLEANUP_WARNING);
        }
    }
}

#[cfg(unix)]
fn stage_and_publish(
    mut file: File,
    staging: &Path,
    path: &Path,
    payload: &[u8],
) -> io::Result<()> {
    file.write_all(payload)?;
    file.sync_all()?;
    // Single-owner close before rename follows OWNERSHIP-24.
    drop(file);
    #[cfg(test)]
    if FAIL_BEFORE_RENAME.get() {
        return Err(io::Error::other("private_export_injected_failure"));
    }
    check_destination(path)?;
    // Same-directory rename replaces the entry without following a symlink.
    fs::rename(staging, path)
}

#[cfg(unix)]
fn sync_directory(parent: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        DIRECTORY_SYNC_CALLED.set(true);
        if FAIL_DIRECTORY_SYNC.get() {
            return Err(io::Error::other("private_export_directory_sync_failed"));
        }
    }
    // Same directory durability step as cli::backup::sync_dir and
    // governance::deferred_audit::sync_directory (ERRORS-02).
    File::open(parent)?.sync_all()
}

/// Publish plaintext through a private inode without opening the destination.
/// Existing regular files are replaced atomically; symlinks and other types
/// are refused. The caller owns the destination directory. Stale regular
/// staging files older than one hour are swept before publication.
///
/// # Errors
/// Validation and staging errors remove the owned staging file. A directory
/// sync error is returned after publication without unlinking the new export.
#[cfg(unix)]
pub(crate) fn write_private_export(path: &Path, payload: &[u8]) -> io::Result<()> {
    check_destination(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private_export_parent_required",
        )
    })?;
    sweep_stale_staging(parent);
    let staging = parent.join(format!(
        "{STAGING_PREFIX}{}{STAGING_SUFFIX}",
        uuid::Uuid::new_v4()
    ));
    // create_new refuses an existing staging entry, including a symlink.
    // Mode 0600 is applied before the first plaintext byte.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_EXPORT_MODE)
        .open(&staging)?;
    if let Err(error) = stage_and_publish(file, &staging, path, payload) {
        return match fs::remove_file(&staging) {
            Ok(()) => Err(error),
            Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
            Err(cleanup) => Err(io::Error::new(
                error.kind(),
                format!("private_export_cleanup_failed: {cleanup}; original: {error}"),
            )),
        };
    }
    // Publication succeeded: sync failure must not enter staging cleanup or
    // unlink the published destination. The caller receives the durability error.
    sync_directory(parent)
}

/// Refuse filesystem publication where Unix mode-0600 protection is unavailable.
///
/// # Errors
/// Always returns `Unsupported`; plaintext is never written with weaker modes.
#[cfg(not(unix))]
pub(crate) fn write_private_export(_path: &Path, _payload: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private_export_unix_permissions_required",
    ))
}

#[cfg(all(test, unix))]
thread_local! {
    static DIRECTORY_SYNC_CALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_STALE_REMOVAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STALE_REMOVAL_ATTEMPTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix))]
mod tests {
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
            fs::create_dir_all(&ns_dir).unwrap();
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
        assert!(format!("{:#}", result.unwrap_err()).contains("private_export_injected_failure"));
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
        assert!(format!("{error:#}").contains("private_export_directory_sync_failed"));
        fixture.assert_private_content();
    }

    fn sweeps_only_stale_regular_staging(writer: Writer) {
        let fixture = Fixture::new();
        let parent = fixture.destination.parent().unwrap();
        let stale = parent.join(".private-export-stale.stage");
        let fresh = parent.join(".private-export-fresh.stage");
        let link = parent.join(".private-export-link.stage");
        let directory = parent.join(".private-export-directory.stage");
        let unrelated = parent.join("unrelated.stage");
        let target = fixture.out_dir.join("symlink-target");
        for path in [&stale, &fresh, &unrelated, &target] {
            fs::write(path, OLD_CONTENT).unwrap();
        }
        for path in [&stale, &unrelated, &target] {
            set_stale(path);
        }
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
}
