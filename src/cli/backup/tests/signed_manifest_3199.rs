// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3199 — operator-signed backup manifests: the cert battery.
//!
//! Every attack here is one a writer of the backup directory can mount with
//! no key: swap the snapshot, rewrite its manifest, rename an older signed
//! pair, sign with a key of their own, drop half the signature, plant a
//! sha256-only manifest beside a `.bak`. Each must be refused with the live
//! database untouched, and each honest path (a signed backup, an unsigned one
//! the operator explicitly accepts under the standard posture) must restore.
//! Keys are fixed seeds (`test_operator_key` in the parent module); nothing
//! reads the operator's real key directory.

// File-level `cfg(test)` so the repo's source gates classify this file as
// test code (it is only ever compiled inside `backup::tests`).
#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;

/// The substring of the refusal for a signature that does not verify.
const DOES_NOT_VERIFY: &str = "does NOT verify";
/// The substring of the refusal for an unverified manifest.
const NOT_VERIFIED: &str = "is not verified";
/// The stderr marker of a restore no verified manifest vouches for.
const UNVERIFIED_WARNING: &str = "WITHOUT a verified manifest";
/// `manifest_verification` field of the `--json` envelope.
const VERIFICATION: &str = "manifest_verification";
/// Planted snapshot ids, a January backup and a June one.
const JANUARY: &str = "ai-memory-2026-01-01T000000Z";
const JUNE: &str = "ai-memory-2026-06-01T000000Z";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A key that is NOT the operator's.
fn foreign_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn args_for(from: PathBuf) -> RestoreArgs {
    RestoreArgs {
        from,
        snapshot: None,
        latest: false,
        skip_verify: false,
        allow_unsigned_manifest: false,
        store_url: None,
        yes: true,
    }
}

/// Restore with `policy`, `--json`, capturing into fresh buffers.
fn restore(env: &mut TestEnv, db: &Path, args: &RestoreArgs, policy: RestorePolicy) -> Result<()> {
    env.stdout.clear();
    env.stderr.clear();
    let mut out = env.output();
    run_restore_with(db, args, true, &mut out, policy, &mut RealPublishIo)
}

fn envelope(env: &TestEnv) -> serde_json::Value {
    serde_json::from_str(env.stdout_str().trim()).expect("--json envelope")
}

fn rows(path: &Path) -> i64 {
    db::open_read_only(path)
        .expect("database must open")
        .query_row(
            crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
            [],
            |r| r.get(0),
        )
        .expect("count memories")
}

fn sha(path: &Path) -> String {
    sha256_hex(&std::fs::File::open(path).expect("open")).expect("hash")
}

/// A live database with 2 rows and a signed backup of it holding 1.
/// Returns `(db, snapshot, manifest path)`.
fn fixture(env: &mut TestEnv, tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "in-the-snapshot", "a");
    let dir = db.parent().unwrap().join(format!("backups-3199-{tag}"));
    let taken = take_backup(env, &db, &dir);
    seed_memory(&db, "ns", "added-after-the-backup", "b");
    let snapshot = dir.join(&taken.snapshot);
    let manifest_path = manifest_path_for(&dir, &taken.snapshot);
    (db, snapshot, manifest_path)
}

fn read_manifest(path: &Path) -> BackupManifest {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read manifest")).expect("json")
}

fn write_manifest(path: &Path, m: &BackupManifest) {
    std::fs::write(path, serde_json::to_string(m).expect("json")).expect("write manifest");
}

/// Re-sign the manifest's own payload with `key` (e.g. an attacker's key).
fn resign_with(path: &Path, key: &SigningKey) {
    use base64::Engine;
    let mut m = read_manifest(path);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(m.signed_payload.as_deref().expect("a signed manifest"))
        .expect("payload base64");
    let payload: manifest::SignedPayload = serde_json::from_slice(&bytes).expect("payload json");
    manifest::sign_into(&mut m, &payload, key).expect("sign");
    write_manifest(path, &m);
}

/// Turn a signed manifest into an unsigned (legacy-shaped) one.
fn strip_signature(path: &Path) {
    let mut m = read_manifest(path);
    m.manifest_version = None;
    m.signed_payload = None;
    m.signature = None;
    m.signer = None;
    write_manifest(path, &m);
}

fn assert_refused(res: Result<()>, needle: &str) {
    let err = res.expect_err("must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains(needle), "expected {needle:?} in: {msg}");
}

/// The signed bytes are the manifest format: pin them, and prove a signed
/// manifest verifies under its key and under no other.
#[test]
fn signed_payload_encoding_is_pinned_3199() {
    let payload = manifest::SignedPayload {
        dst: manifest::MANIFEST_DOMAIN.to_owned(),
        v: manifest::PAYLOAD_VERSION,
        snapshot: format!("{JANUARY}.db"),
        sha256: "ab".repeat(32),
        bytes: 4096,
        source_db: "/srv/ai-memory.db".to_owned(),
        version: "1.0.0".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        backend: BACKEND_SQLITE.to_owned(),
        schema_version: 98,
        memory_count: 3,
    };
    let expected = format!(
        "{{\"dst\":\"ai-memory/backup-manifest/v1\",\"v\":1,\"snapshot\":\"{JANUARY}.db\",\
         \"sha256\":\"{}\",\"bytes\":4096,\"source_db\":\"/srv/ai-memory.db\",\
         \"version\":\"1.0.0\",\"created_at\":\"2026-01-01T00:00:00+00:00\",\
         \"backend\":\"sqlite\",\"schema_version\":98,\"memory_count\":3}}",
        "ab".repeat(32)
    );
    assert_eq!(serde_json::to_string(&payload).expect("encode"), expected);

    let mut m = BackupManifest {
        snapshot: payload.snapshot.clone(),
        sha256: payload.sha256.clone(),
        bytes: payload.bytes,
        source_db: payload.source_db.clone(),
        version: payload.version.clone(),
        created_at: payload.created_at.clone(),
        backend: None,
        schema_version: None,
        memory_count: None,
        manifest_version: None,
        signed_payload: None,
        signature: None,
        signer: None,
    };
    manifest::sign_into(&mut m, &payload, &test_operator_key()).expect("sign");
    assert_eq!(m.manifest_version, Some(manifest::MANIFEST_VERSION_SIGNED));
    let text = serde_json::to_string(&m).expect("json");
    let anchor = test_operator_key().verifying_key();
    match manifest::verify(&text, Some(&anchor)).expect("verifies under its own key") {
        manifest::ManifestVerdict::Signed(back) => assert_eq!(back, payload),
        manifest::ManifestVerdict::Unverified { reason, .. } => panic!("unverified: {reason:?}"),
    }
    let other = foreign_key().verifying_key();
    let err = manifest::verify(&text, Some(&other)).expect_err("another key must refuse");
    assert!(format!("{err:#}").contains(DOES_NOT_VERIFY), "{err:#}");
}

/// The honest path: `backup` signs, reports it, and `restore` verifies it.
#[test]
fn a_signed_backup_restores_and_says_so_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "in-the-snapshot", "a");
    let dir = db.parent().unwrap().join("backups-3199-honest");
    {
        let mut out = env.output();
        run_backup(
            &db,
            &BackupArgs {
                to: dir.clone(),
                keep: 48,
                store_url: None,
            },
            true,
            &mut out,
        )
        .expect("backup");
    }
    let v = envelope(&env);
    assert_eq!(v["signed"], serde_json::json!(true));
    assert_eq!(
        v["manifest_version"],
        serde_json::json!(manifest::MANIFEST_VERSION_SIGNED)
    );
    assert_eq!(
        v["signer"],
        serde_json::json!(manifest::fingerprint(&test_operator_key().verifying_key()))
    );
    let snapshot = dir.join(v["snapshot"].as_str().expect("snapshot name"));
    seed_memory(&db, "ns", "added-after-the-backup", "b");

    restore(
        &mut env,
        &db,
        &args_for(snapshot),
        test_restore_policy(false),
    )
    .expect("a signed backup restores");
    let e = envelope(&env);
    assert_eq!(e[VERIFICATION], serde_json::json!("signed"));
    assert!(e["audit_sink"].is_null(), "nothing to audit: {e}");
    assert!(!env.stderr_str().contains(UNVERIFIED_WARNING));
    assert_eq!(rows(&db), 1, "the snapshot is what was published");
}

/// Swap the snapshot for another database and rewrite the PLAIN sha256 to
/// match: the signed payload still carries the real digest, so it is refused.
#[test]
fn a_swapped_snapshot_under_a_signed_manifest_is_refused_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "swap");
    let mut attacker = TestEnv::fresh();
    let attacker_db = attacker.db_path.clone();
    for i in 0..5 {
        seed_memory(&attacker_db, "ns", &format!("planted-{i}"), "x");
    }
    let attacker_dir = attacker_db.parent().unwrap().join("attacker");
    let theirs = take_backup(&mut attacker, &attacker_db, &attacker_dir);
    std::fs::copy(attacker_dir.join(&theirs.snapshot), &snapshot).expect("swap bytes in");
    let mut m = read_manifest(&manifest_path);
    m.sha256 = sha(&snapshot);
    write_manifest(&manifest_path, &m);

    let live = sha(&db);
    assert_refused(
        restore(
            &mut env,
            &db,
            &args_for(snapshot),
            test_restore_policy(false),
        ),
        "sha256 mismatch",
    );
    assert_eq!(sha(&db), live, "the live database is untouched");
}

/// Swap the snapshot and write a fresh UNSIGNED manifest for it: refused by
/// default (it is exactly what a writer of the directory can produce).
#[test]
fn an_attacker_regenerated_unsigned_manifest_is_refused_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "regen");
    strip_signature(&manifest_path);
    let live = sha(&db);
    assert_refused(
        restore(
            &mut env,
            &db,
            &args_for(snapshot),
            test_restore_policy(false),
        ),
        NOT_VERIFIED,
    );
    assert_eq!(sha(&db), live, "the live database is untouched");
}

/// Rename an older signed pair to look like a newer backup: the signed name
/// does not match, so it is refused.
#[test]
fn a_renamed_signed_pair_is_refused_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "rename");
    let dir = snapshot.parent().unwrap().to_path_buf();
    let renamed = dir.join(format!("{JUNE}.{SNAPSHOT_FILE_EXT}"));
    std::fs::rename(&snapshot, &renamed).expect("rename snapshot");
    std::fs::rename(&manifest_path, dir.join(manifest_file_name(JUNE))).expect("rename manifest");
    let live = sha(&db);
    assert_refused(
        restore(
            &mut env,
            &db,
            &args_for(renamed),
            test_restore_policy(false),
        ),
        "cannot be renamed",
    );
    assert_eq!(sha(&db), live, "the live database is untouched");
}

/// A signature made with some other key is refused, and no flag accepts it.
#[test]
fn a_foreign_key_signature_is_refused_even_with_the_flag_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "foreign");
    resign_with(&manifest_path, &foreign_key());
    let mut args = args_for(snapshot);
    assert_refused(
        restore(&mut env, &db, &args, test_restore_policy(false)),
        DOES_NOT_VERIFY,
    );
    args.allow_unsigned_manifest = true;
    assert_refused(
        restore(&mut env, &db, &args, test_restore_policy(false)),
        DOES_NOT_VERIFY,
    );
    assert_eq!(rows(&db), 2, "the live database is untouched");
}

/// Half a signature is not an unsigned manifest: refused, flag or not.
#[test]
fn a_half_signed_manifest_is_refused_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "half");
    let mut m = read_manifest(&manifest_path);
    m.signature = None;
    write_manifest(&manifest_path, &m);
    let mut args = args_for(snapshot);
    args.allow_unsigned_manifest = true;
    assert_refused(
        restore(&mut env, &db, &args, test_restore_policy(false)),
        "half a signature",
    );
    assert_eq!(rows(&db), 2, "the live database is untouched");
}

/// An unsigned manifest restores only with `--allow-unsigned-manifest`, and
/// then loudly: stderr WARN, `unsigned_allowed`, and where the audit row went.
#[test]
fn an_unsigned_manifest_restores_only_with_the_flag_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "unsigned");
    strip_signature(&manifest_path);
    let mut args = args_for(snapshot);
    let res = restore(&mut env, &db, &args, test_restore_policy(false));
    assert_refused(res, "--allow-unsigned-manifest");
    args.allow_unsigned_manifest = true;
    restore(&mut env, &db, &args, test_restore_policy(false)).expect("explicitly accepted");
    let e = envelope(&env);
    assert_eq!(e[VERIFICATION], serde_json::json!("unsigned_allowed"));
    assert!(
        e["audit_sink"].is_string(),
        "the audit sink is reported: {e}"
    );
    assert!(
        env.stderr_str().contains(UNVERIFIED_WARNING),
        "{}",
        env.stderr_str()
    );
    assert_eq!(rows(&db), 1);
}

/// `--skip-verify` under the standard posture: restores, WARNs, reports.
#[test]
fn skip_verify_warns_and_reports_skipped_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, _) = fixture(&mut env, "skip");
    let mut args = args_for(snapshot);
    args.skip_verify = true;
    restore(&mut env, &db, &args, test_restore_policy(false)).expect("standard allows it");
    assert_eq!(envelope(&env)[VERIFICATION], serde_json::json!("skipped"));
    assert!(
        env.stderr_str().contains(UNVERIFIED_WARNING),
        "{}",
        env.stderr_str()
    );
}

/// Under asi-hard nothing unverified restores: both escapes are refused, and
/// so is an unsigned manifest.
#[test]
fn asi_hard_refuses_every_unverified_restore_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, manifest_path) = fixture(&mut env, "hard");
    let live = sha(&db);
    for (skip_verify, allow_unsigned_manifest) in [(true, false), (false, true)] {
        let mut args = args_for(snapshot.clone());
        args.skip_verify = skip_verify;
        args.allow_unsigned_manifest = allow_unsigned_manifest;
        assert_refused(
            restore(&mut env, &db, &args, test_restore_policy(true)),
            "asi-hard",
        );
    }
    strip_signature(&manifest_path);
    assert_refused(
        restore(
            &mut env,
            &db,
            &args_for(snapshot),
            test_restore_policy(true),
        ),
        NOT_VERIFIED,
    );
    assert_eq!(sha(&db), live, "the live database is untouched");
}

/// With no operator public key on the host, a signed manifest cannot be
/// checked: it is treated as unverified, never as verified.
#[test]
fn a_signed_manifest_with_no_key_to_check_it_is_unverified_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, _) = fixture(&mut env, "noanchor");
    let no_anchor = RestorePolicy {
        asi_hard: false,
        anchor: None,
    };
    let mut args = args_for(snapshot);
    assert_refused(
        restore(&mut env, &db, &args, no_anchor),
        "no operator public key",
    );
    args.allow_unsigned_manifest = true;
    restore(&mut env, &db, &args, no_anchor).expect("explicitly accepted");
    assert_eq!(
        envelope(&env)[VERIFICATION],
        serde_json::json!("unsigned_allowed")
    );
}

/// `--latest` refuses to choose while one candidate's signature fails, and
/// names it.
#[test]
fn latest_refuses_a_forged_candidate_naming_it_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "live", "l");
    let dir = db.parent().unwrap().join("backups-3199-latest-forged");
    std::fs::create_dir_all(&dir).expect("mkdir");
    super::publish_3550::plant_snapshot(&mut env, &dir, JANUARY, 1);
    super::publish_3550::plant_snapshot(&mut env, &dir, JUNE, 2);
    resign_with(&dir.join(manifest_file_name(JUNE)), &foreign_key());
    let mut args = args_for(dir);
    args.latest = true;
    let live = sha(&db);
    let err = restore(&mut env, &db, &args, test_restore_policy(false))
        .expect_err("a forged candidate must refuse --latest");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(JUNE) && msg.contains("fails verification"),
        "{msg}"
    );
    assert_eq!(sha(&db), live, "the live database is untouched");
}

/// `--latest` skips (and lists) candidates it cannot verify, picks among the
/// verified, and refuses when none verifies.
#[test]
fn latest_skips_unverified_candidates_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "live", "l");
    let dir = db.parent().unwrap().join("backups-3199-latest-skip");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let january = super::publish_3550::plant_snapshot(&mut env, &dir, JANUARY, 3);
    super::publish_3550::plant_snapshot(&mut env, &dir, JUNE, 2);
    strip_signature(&dir.join(manifest_file_name(JUNE)));
    let mut args = args_for(dir.clone());
    args.latest = true;
    restore(&mut env, &db, &args, test_restore_policy(false)).expect("the signed one");
    assert_eq!(envelope(&env)["selected_by"], serde_json::json!("latest"));
    assert_eq!(sha(&db), sha(&january), "the newest VERIFIED backup");
    assert!(
        env.stderr_str().contains("skipped") && env.stderr_str().contains(JUNE),
        "{}",
        env.stderr_str()
    );

    strip_signature(&dir.join(manifest_file_name(JANUARY)));
    assert_refused(
        restore(&mut env, &db, &args, test_restore_policy(false)),
        "no backup in",
    );
}

/// asi-hard never takes a backup this host could not restore, and writes
/// nothing when it refuses.
#[test]
fn asi_hard_backup_refuses_what_it_could_not_verify_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let cases = [
        (
            Err("no key here".to_owned()),
            Some(test_operator_key().verifying_key()),
            "no operator signing key",
        ),
        (Ok(test_operator_key()), None, "no operator public key"),
        (
            Ok(test_operator_key()),
            Some(foreign_key().verifying_key()),
            "not the public key restore verifies against",
        ),
    ];
    for (i, (signer, anchor, needle)) in cases.into_iter().enumerate() {
        let dir = db.parent().unwrap().join(format!("backups-3199-hard-{i}"));
        let policy = backup_policy(true, signer, anchor);
        let res = {
            let mut out = env.output();
            run_backup_with(
                &db,
                &BackupArgs {
                    to: dir.clone(),
                    keep: 48,
                    store_url: None,
                },
                true,
                &mut out,
                &policy,
            )
        };
        assert_refused(res, needle);
        assert!(!dir.exists(), "case {i}: nothing may be written");
    }
}

/// Under the standard posture a host without the key still backs up, but the
/// manifest is unsigned and everyone is told: stderr, `signed: false`, and a
/// restore that refuses it by default.
#[test]
fn standard_backup_without_a_key_is_unsigned_and_says_so_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let dir = db.parent().unwrap().join("backups-3199-nokey");
    let policy = backup_policy(false, Err("no key here".to_owned()), None);
    {
        let mut out = env.output();
        run_backup_with(
            &db,
            &BackupArgs {
                to: dir.clone(),
                keep: 48,
                store_url: None,
            },
            true,
            &mut out,
            &policy,
        )
        .expect("standard still backs up");
    }
    let v = envelope(&env);
    assert_eq!(v["signed"], serde_json::json!(false));
    assert!(v.get("signature").is_none(), "{v}");
    assert!(
        env.stderr_str().contains("UNSIGNED"),
        "{}",
        env.stderr_str()
    );
    let snapshot = dir.join(v["snapshot"].as_str().expect("name"));
    assert_refused(
        restore(
            &mut env,
            &db,
            &args_for(snapshot),
            test_restore_policy(false),
        ),
        NOT_VERIFIED,
    );
}

/// A sha256-only manifest planted beside a manifest-less `.bak` no longer
/// makes it restorable without a flag; `--skip-verify` is the documented
/// standard-posture way through.
#[test]
fn a_planted_sha_only_manifest_beside_a_bak_is_refused_3199() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let (db, snapshot, _) = fixture(&mut env, "bak");
    let bak = db.with_extension("db.bak");
    std::fs::copy(&snapshot, &bak).expect("make the .bak");
    let stem = bak.file_stem().and_then(|s| s.to_str()).expect("stem");
    let planted = serde_json::json!({
        "snapshot": bak.file_name().and_then(|n| n.to_str()).expect("name"),
        "sha256": sha(&bak),
        "bytes": std::fs::metadata(&bak).expect("stat").len(),
        "source_db": "planted",
        "version": "0.9.0",
        "created_at": "2026-01-01T00:00:00+00:00",
    });
    std::fs::write(
        bak.parent().unwrap().join(manifest_file_name(stem)),
        planted.to_string(),
    )
    .expect("plant");
    let mut args = args_for(bak);
    assert_refused(
        restore(&mut env, &db, &args, test_restore_policy(false)),
        NOT_VERIFIED,
    );
    args.skip_verify = true;
    restore(&mut env, &db, &args, test_restore_policy(false)).expect("the --skip-verify escape");
    assert_eq!(envelope(&env)[VERIFICATION], serde_json::json!("skipped"));
}

// ---------------------------------------------------------------------------
// #3605 — a backup is durable before anything older is rotated away.
// #3604 — rotation orders by the SIGNED creation time and never deletes a
//         backup it cannot verify.
// ---------------------------------------------------------------------------

fn failing_sync(_: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("injected fsync failure"))
}

fn failing_remove(_: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("injected unlink failure"))
}

/// `backup --json` into `dir` with `policy`; the envelope is returned even
/// when the command then fails (it is written first).
fn backup_json(
    env: &mut TestEnv,
    db: &Path,
    dir: &Path,
    keep: usize,
    policy: &BackupPolicy,
) -> (Result<()>, serde_json::Value) {
    env.stdout.clear();
    env.stderr.clear();
    let res = {
        let mut out = env.output();
        run_backup_with(
            db,
            &BackupArgs {
                to: dir.to_path_buf(),
                keep,
                store_url: None,
            },
            true,
            &mut out,
            policy,
        )
    };
    (res, envelope(env))
}

/// A directory fsync that fails: `durable: false`, a WARN, and NO rotation
/// (the older backup survives); asi-hard additionally exits non-zero.
#[test]
fn a_non_durable_backup_is_reported_and_rotates_nothing_3605() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    for asi_hard in [false, true] {
        let dir = db
            .parent()
            .unwrap()
            .join(format!("backups-3605-{asi_hard}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let older = super::publish_3550::plant_snapshot(&mut env, &dir, JANUARY, 1);
        let mut policy = test_backup_policy();
        policy.asi_hard = asi_hard;
        policy.sync_dir = failing_sync;
        let (res, v) = backup_json(&mut env, &db, &dir, 1, &policy);
        if asi_hard {
            assert_refused(res, "not durable");
        } else {
            res.expect("standard reports, does not fail");
        }
        assert_eq!(v["durable"], serde_json::json!(false), "{v}");
        assert!(v["rotation"].is_null(), "rotation must be skipped: {v}");
        assert!(
            env.stderr_str().contains("NOT durable"),
            "{}",
            env.stderr_str()
        );
        assert!(
            older.exists(),
            "asi_hard={asi_hard}: nothing older was rotated"
        );
    }
}

/// Planted future-dated junk neither counts toward `--keep` nor is deleted;
/// real backups rotate by their SIGNED time.
#[test]
fn rotation_orders_by_signed_time_and_keeps_what_it_cannot_verify_3604() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let dir = db.parent().unwrap().join("backups-3604-order");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let january = super::publish_3550::plant_snapshot(&mut env, &dir, JANUARY, 1);
    let june = super::publish_3550::plant_snapshot(&mut env, &dir, JUNE, 1);
    let future = std::time::SystemTime::now()
        + std::time::Duration::from_secs(
            u64::try_from(crate::SECS_PER_DAY).expect("positive const"),
        );
    let mut junk = Vec::new();
    for month in 1..=3 {
        let path = dir.join(format!("ai-memory-2099-0{month}-01T000000Z.db"));
        std::fs::write(&path, b"not a backup").expect("plant junk");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(future))
            .expect("future mtime");
        junk.push(path);
    }
    let (res, v) = backup_json(&mut env, &db, &dir, 2, &test_backup_policy());
    res.expect("backup");
    assert_eq!(v["durable"], serde_json::json!(true), "{v}");
    let removed = v["rotation"]["removed"].as_array().expect("removed list");
    assert_eq!(
        removed,
        &vec![serde_json::json!(format!("{JANUARY}.db"))],
        "only the oldest SIGNED backup rotates: {v}"
    );
    assert_eq!(
        v["rotation"]["kept_unverified"]
            .as_array()
            .expect("kept list")
            .len(),
        3,
        "{v}"
    );
    assert!(!january.exists(), "rotated");
    assert!(june.exists(), "within --keep 2");
    assert!(
        junk.iter().all(|p| p.exists()),
        "never deletes what it cannot verify"
    );
    assert!(
        env.stderr_str().contains("never deletes"),
        "{}",
        env.stderr_str()
    );
}

/// A removal that fails is reported, not swallowed, and the file stays.
#[test]
fn rotation_reports_a_removal_it_could_not_make_3604() {
    let _g = lock();
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let dir = db.parent().unwrap().join("backups-3604-fail");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let january = super::publish_3550::plant_snapshot(&mut env, &dir, JANUARY, 1);
    let mut policy = test_backup_policy();
    policy.remove_file = failing_remove;
    let (res, v) = backup_json(&mut env, &db, &dir, 1, &policy);
    res.expect("a failed removal does not fail the backup");
    let failures = v["rotation"]["remove_failures"]
        .as_array()
        .expect("failures list");
    assert_eq!(failures.len(), 1, "{v}");
    assert!(
        failures[0].as_str().unwrap_or_default().contains(JANUARY),
        "{v}"
    );
    assert!(
        january.exists(),
        "the file it could not remove is still there"
    );
    assert!(
        env.stderr_str().contains("could not remove"),
        "{}",
        env.stderr_str()
    );
}

/// The `doctor --posture` check #21 predicate: the anchor must resolve, and a
/// local signing key must be its private half. A node with no usable key
/// passes (it restores signed backups; it does not need to take them).
#[test]
fn backup_signing_posture_row_3199() {
    let operator = test_operator_key();
    let anchor = operator.verifying_key();
    let foreign = foreign_key();
    let missing = "governance.no_operator_key: none".to_string();

    let (pass, actual) = signing_posture_of(None, Ok(&operator));
    assert!(
        !pass && actual.contains("no operator public key"),
        "{actual}"
    );
    let (pass, actual) = signing_posture_of(Some(&anchor), Ok(&operator));
    assert!(pass && actual.contains("matches"), "{actual}");
    let (pass, actual) = signing_posture_of(Some(&anchor), Ok(&foreign));
    assert!(!pass && actual.contains("does NOT match"), "{actual}");
    let (pass, actual) = signing_posture_of(Some(&anchor), Err(&missing));
    assert!(
        pass && actual.contains("no usable local signing key"),
        "{actual}"
    );
}
