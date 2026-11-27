// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10112 (Option B, 3-agent vote `V1-RECOVER-REBIND-ATTEST`, R-1..R-14) —
//! Comprehensive integration suite proving every binding condition for armed
//! guardian-quorum key recovery rebind.
//!
//! Separate test binary (own process) so `AI_MEMORY_KEY_DIR`,
//! `AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS`, and `AI_MEMORY_RECOVERY_THRESHOLD`
//! stay strictly isolated from parallel library unit tests and live host state.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::cli::CliOutput;
use ai_memory::cli::audit_verify_rows::{self, VerifyRowsArgs};
use ai_memory::cli::identity::{IdentityAction, IdentityArgs, run as run_identity};
use ai_memory::db;
use ai_memory::identity::keypair::{self, AgentKeypair};
use ai_memory::identity::lineage::{
    LineageReason, RECOVERY_GUARDIAN_PUBKEYS_ENV, RECOVERY_THRESHOLD_ENV, RecoveryAttestation,
    RecoveryPolicy, encode_recovery_quorum,
};
use ai_memory::models::Memory;
use ai_memory::portability::emit::build_full_envelope_audited;
use ai_memory::portability::import::{ImportOptions, import_full_envelope};
use ai_memory::storage::recovery_rebind::{
    RecoveryArm, RecoveryFaultPoint, RecoveryRequest, execute_recovery_rebind,
    execute_recovery_rebind_with_fault, recovery_preconditions, verify_anchor_against_lineage,
};
use ai_memory::storage::row_attest::Outcome;
use ai_memory::storage::row_attest::anchor::{AnchorLoad, KeyRefusal, TrustAnchor};
use ai_memory::storage::row_attest::key_id_of;
use ai_memory::storage::row_attest::seal::{self, SealState};
use ai_memory::storage::row_attest::sqlite::{
    REFUSE_ANCHOR_UNATTESTED_KEY_SWAP, REFUSE_KEY_MISMATCH, REFUSE_RECOVERY_KEY_MISMATCH,
    REFUSE_RECOVERY_MISSING_PRIV, REFUSE_RECOVERY_QUORUM_DRIFT, REFUSE_RECOVERY_REPLAY,
    REFUSE_RECOVERY_VERIFY_ONLY, SnapshotVerdict, arm_with_key, check_snapshot, seal_restored,
    verify_sqlite_with,
};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use rusqlite::Connection;
use tempfile::TempDir;

/// Serializes every test in this binary that mutates process env vars.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvRestore {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl EnvRestore {
    fn apply(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut saved = Vec::with_capacity(pairs.len());
        for &(k, v) in pairs {
            saved.push((k, std::env::var_os(k)));
            // SAFETY: serialized by ENV_LOCK inside this dedicated integration
            // test binary (never linked into the library unit-test binary).
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        Self {
            saved,
            _guard: guard,
        }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (k, prev) in self.saved.iter().rev() {
            // SAFETY: serialized by ENV_LOCK held until self drops.
            unsafe {
                match prev {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}

fn private_dir() -> TempDir {
    let mut b = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        b.permissions(fs::Permissions::from_mode(0o700));
    }
    b.tempdir().expect("create 0700 tempdir")
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(base: &Path, cur: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(cur).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let p = entry.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if p.is_file() {
                let rel = p.strip_prefix(base).expect("strip_prefix").to_path_buf();
                out.insert(rel, fs::read(&p).expect("read file"));
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

struct RecoveryFixture {
    root: TempDir,
    db_path: PathBuf,
    anchor_dir: PathBuf,
    witness_dir: PathBuf,
    home_dir: PathBuf,
    agent: String,
    k_old: AgentKeypair,
    guardians: [AgentKeypair; 3],
    pre_mem_id: String,
    _env: EnvRestore,
}

impl RecoveryFixture {
    fn new(agent: &str) -> Self {
        let root = private_dir();
        let anchor_dir = root.path().join("keys");
        let witness_dir = root.path().join("witness");
        let home_dir = root.path().join("home");
        for d in [&anchor_dir, &witness_dir, &home_dir] {
            fs::create_dir_all(d).expect("mkdir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(d, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
            }
        }
        let db_path = root.path().join("store.db");

        let g0 = keypair::generate("g0").expect("g0");
        let g1 = keypair::generate("g1").expect("g1");
        let g2 = keypair::generate("g2").expect("g2");
        let gpubs = format!(
            "{},{},{}",
            g0.public_base64(),
            g1.public_base64(),
            g2.public_base64()
        );

        let anchor_str = anchor_dir.to_string_lossy().into_owned();
        let witness_str = witness_dir.to_string_lossy().into_owned();
        let home_str = home_dir.to_string_lossy().into_owned();
        let env = EnvRestore::apply(&[
            ("HOME", Some(&home_str)),
            ("AI_MEMORY_NO_CONFIG", Some("1")),
            ("AI_MEMORY_KEY_DIR", Some(&anchor_str)),
            ("AI_MEMORY_WITNESS_KEY_DIR", Some(&witness_str)),
            (RECOVERY_GUARDIAN_PUBKEYS_ENV, Some(&gpubs)),
            (RECOVERY_THRESHOLD_ENV, Some("2")),
            ("AI_MEMORY_STORE_URL", None),
        ]);

        let k_old = keypair::generate(agent).expect("k_old");
        keypair::save(&k_old, &anchor_dir).expect("save k_old");
        let cold = keypair::generate("cold-rec").expect("cold");

        let conn = db::open(&db_path).expect("open db");
        db::register_agent(&conn, agent, "ai:test", &[]).expect("register");
        db::enroll_lineage(&conn, agent, &k_old, Some(&cold.public_base64())).expect("genesis");
        arm_with_key(&conn, agent, k_old.private.as_ref().expect("k_old priv"))
            .expect("arm with k_old");

        let mem = Memory {
            namespace: "recovery-10112".to_string(),
            title: "pre-loss".to_string(),
            content: "attested under K_old before loss".to_string(),
            ..Memory::default()
        };
        db::insert(&conn, &mem).expect("insert pre-recovery memory");
        let pre_mem_id = mem.id;

        let anchor = TrustAnchor::load_dir(&anchor_dir);
        let pre = verify_sqlite_with(&conn, &anchor).expect("verify pre");
        assert!(
            matches!(pre.outcome(), Outcome::Clean),
            "pre-recovery fixture must be Clean, got: {:?}",
            pre.outcome()
        );
        drop(conn);

        // Simulate key loss of K_old: remove `<agent>.priv`, retaining `<agent>.pub`.
        fs::remove_file(anchor_dir.join(format!("{agent}.priv"))).expect("lose k_old.priv");

        Self {
            root,
            db_path,
            anchor_dir,
            witness_dir,
            home_dir,
            agent: agent.to_string(),
            k_old,
            guardians: [g0, g1, g2],
            pre_mem_id,
            _env: env,
        }
    }

    fn prepare_and_sign(
        &self,
        k_new: &AgentKeypair,
        guardian_indices: &[usize],
    ) -> (String, Vec<RecoveryAttestation>) {
        let conn = db::open(&self.db_path).expect("open for prepare");
        let not_before = chrono::Utc::now().to_rfc3339();
        let (record, signing_input) = db::prepare_recovery_challenge(
            &conn,
            &self.agent,
            &k_new.public_base64(),
            None,
            None,
            &not_before,
        )
        .expect("prepare_recovery_challenge");
        let mut atts = Vec::new();
        for &idx in guardian_indices {
            let g = &self.guardians[idx];
            let sig = g
                .private
                .as_ref()
                .expect("guardian priv")
                .sign(&signing_input)
                .to_bytes()
                .to_vec();
            atts.push(RecoveryAttestation {
                guardian_pubkey_b64: g.public_base64(),
                signature: sig,
            });
        }
        (record.not_before, atts)
    }

    fn run_cli(&self, action: IdentityAction, json_out: bool) -> anyhow::Result<(String, String)> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        {
            let mut out = CliOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            };
            run_identity(
                &self.db_path,
                IdentityArgs {
                    key_dir: Some(self.anchor_dir.clone()),
                    action,
                },
                json_out,
                &mut out,
            )?;
        }
        Ok((
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        ))
    }

    fn verify_clean(&self) {
        let conn = db::open(&self.db_path).expect("open for verify");
        let anchor = TrustAnchor::load_dir(&self.anchor_dir);
        let report = verify_sqlite_with(&conn, &anchor).expect("verify_sqlite_with");
        assert!(
            matches!(report.outcome(), Outcome::Clean),
            "expected Outcome::Clean, got: {:?}",
            report.outcome()
        );
    }

    fn seal_state(&self) -> SealState {
        let anchor = TrustAnchor::load_dir(&self.anchor_dir);
        assert!(
            matches!(anchor, AnchorLoad::Anchored(_)),
            "anchor must be Anchored, got: {anchor:?}"
        );
        let path = seal::path_for(&anchor, Some(&self.db_path)).expect("seal path");
        seal::read(&path)
    }
}

/// R-1: Guardian M-of-N signatures over `(agent_id, epoch, K_old, K_new)` are
/// verified FIRST before any `K_new` signature or state change; `K_new` never
/// substitutes for the guardian quorum.
#[test]
fn r1_guardian_quorum_verified_before_k_new_and_never_substituted_10112() {
    let fx = RecoveryFixture::new("r1-agent");
    let k_new = keypair::generate("r1-new").expect("k_new");
    let (not_before, one_att) = fx.prepare_and_sign(&k_new, &[0]);

    let db_before = fs::read(&fx.db_path).expect("db before");
    let dir_before = snapshot_tree(&fx.anchor_dir);

    let conn = db::open(&fx.db_path).expect("open");

    // 1a. Quorum shortfall with valid Signing(K_new) is refused by quorum check.
    let req_short = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &one_att,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &not_before,
        staged_key_label: None,
    };
    let err_short = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req_short,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .err()
    .expect("1-of-2 quorum must be refused even with valid K_new signing key");
    let msg_short = format!("{err_short:#}");
    assert!(
        msg_short.contains("met only 1 of 2")
            || msg_short.contains("distinct enrolled recovery guardians"),
        "expected guardian quorum refusal, got: {msg_short}"
    );

    // 1b. K_new signing the recovery challenge itself NEVER substitutes for a guardian.
    let nb_sub = chrono::Utc::now().to_rfc3339();
    let (sub_rec, sub_input) = db::prepare_recovery_challenge(
        &conn,
        &fx.agent,
        &k_new.public_base64(),
        None,
        None,
        &nb_sub,
    )
    .expect("prepare");
    let k_new_self_sig = k_new
        .private
        .as_ref()
        .expect("k_new priv")
        .sign(&sub_input)
        .to_bytes()
        .to_vec();
    let g0_sub_sig = fx.guardians[0]
        .private
        .as_ref()
        .expect("g0 priv")
        .sign(&sub_input)
        .to_bytes()
        .to_vec();
    let substituted = vec![
        RecoveryAttestation {
            guardian_pubkey_b64: fx.guardians[0].public_base64(),
            signature: g0_sub_sig,
        },
        RecoveryAttestation {
            guardian_pubkey_b64: k_new.public_base64(),
            signature: k_new_self_sig,
        },
    ];
    let req_sub = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &substituted,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &sub_rec.not_before,
        staged_key_label: None,
    };
    let err_sub = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req_sub,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .err()
    .expect("K_new signature must never substitute for a guardian");
    let msg_sub = format!("{err_sub:#}");
    assert!(
        !msg_sub.contains(REFUSE_RECOVERY_KEY_MISMATCH)
            && (msg_sub.contains("quorum")
                || msg_sub.contains("guardian")
                || msg_sub.contains("unverifiable")),
        "expected guardian quorum refusal for K_new substitution, got: {msg_sub}"
    );

    // 1c. Quorum shortfall with VerifyOnly OR MissingPrivateKey STILL fires the
    // guardian quorum refusal FIRST (never masked by arm-mode refusal).
    let err_order_vo =
        recovery_preconditions(&conn, &fx.anchor_dir, &req_short, RecoveryArm::VerifyOnly)
            .err()
            .expect("quorum shortfall under verify-only must fail on quorum first");
    let msg_order_vo = format!("{err_order_vo:#}");
    assert!(
        !msg_order_vo.contains(REFUSE_RECOVERY_VERIFY_ONLY),
        "R-1: guardian quorum must be checked BEFORE verify-only arm check, got: {msg_order_vo}"
    );

    let err_order_miss = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req_short,
        RecoveryArm::MissingPrivateKey,
    )
    .err()
    .expect("quorum shortfall under missing-priv must fail on quorum first");
    let msg_order_miss = format!("{err_order_miss:#}");
    assert!(
        !msg_order_miss.contains(REFUSE_RECOVERY_MISSING_PRIV),
        "R-1: guardian quorum must be checked BEFORE missing-priv arm check, got: {msg_order_miss}"
    );

    drop(conn);
    assert_eq!(fs::read(&fx.db_path).expect("db after"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);
}

/// R-2: Second recovery reads `(guardian_set_id, recovery_threshold)` from the
/// prior signed lineage record, NEVER from lowered env/CLI arguments.
#[test]
fn r2_second_recovery_pins_quorum_from_prior_signed_lineage_record_10112() {
    let fx = RecoveryFixture::new("r2-agent");

    // First recovery: 2-of-3 commits (guardian_set_id, threshold=2) on epoch 1.
    let k1 = keypair::generate("r2-k1").expect("k1");
    let (nb1, atts1) = fx.prepare_and_sign(&k1, &[0, 1]);
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k1.public_base64(),
            quorum: &atts1,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb1,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k1.private.as_ref().expect("k1 priv")),
        )
        .expect("first recovery preconditions");
        execute_recovery_rebind(&conn, checked).expect("first recovery execute");
    }
    fx.verify_clean();

    // Lower AI_MEMORY_RECOVERY_THRESHOLD from 2 -> 1 in env and attempt a
    // second recovery with only 1 signature: MUST BE REFUSED because epoch 1
    // committed recovery_threshold = 2!
    let k2 = keypair::generate("r2-k2").expect("k2");
    // SAFETY: serialized by ENV_LOCK held inside `fx._env`.
    unsafe {
        std::env::set_var(RECOVERY_THRESHOLD_ENV, "1");
    }
    let (nb2, one_att2) = fx.prepare_and_sign(&k2, &[0]);
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k2.public_base64(),
            quorum: &one_att2,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb2,
            staged_key_label: None,
        };
        let err = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k2.private.as_ref().expect("k2 priv")),
        )
        .err()
        .expect("1 signature must be refused when prior recovery committed threshold=2");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("quorum") || msg.contains("threshold") || msg.contains("unverifiable"),
            "expected committed-threshold refusal, got: {msg}"
        );
    }

    // Swap guardian set in env -> MUST BE REFUSED with REFUSE_RECOVERY_QUORUM_DRIFT.
    let rogue_g = keypair::generate("rogue-g").expect("rogue");
    // SAFETY: serialized by ENV_LOCK held inside `fx._env`.
    unsafe {
        std::env::set_var(RECOVERY_GUARDIAN_PUBKEYS_ENV, rogue_g.public_base64());
    }
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k2.public_base64(),
            quorum: &one_att2,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb2,
            staged_key_label: None,
        };
        let err = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k2.private.as_ref().expect("k2 priv")),
        )
        .err()
        .expect("drifted guardian set must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(REFUSE_RECOVERY_QUORUM_DRIFT),
            "expected REFUSE_RECOVERY_QUORUM_DRIFT, got: {msg}"
        );
    }

    // Restore original guardian set (still with env threshold = 1!) and present
    // 2 valid guardian signatures -> SUCCEEDS using committed threshold=2.
    let orig_gpubs = format!(
        "{},{},{}",
        fx.guardians[0].public_base64(),
        fx.guardians[1].public_base64(),
        fx.guardians[2].public_base64()
    );
    // SAFETY: serialized by ENV_LOCK held inside `fx._env`.
    unsafe {
        std::env::set_var(RECOVERY_GUARDIAN_PUBKEYS_ENV, &orig_gpubs);
    }
    let (nb2_ok, two_atts2) = fx.prepare_and_sign(&k2, &[1, 2]);
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k2.public_base64(),
            quorum: &two_atts2,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb2_ok,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k2.private.as_ref().expect("k2 priv")),
        )
        .expect("2-of-3 under committed threshold=2 must succeed");
        let outcome = execute_recovery_rebind(&conn, checked).expect("second recovery execute");
        assert_eq!(outcome.record.epoch, 2);
        assert_eq!(outcome.record.recovery_threshold, Some(2));
    }
    fx.verify_clean();
}

/// R-4: `--successor-pubkey` must equal BOTH the guardian-signed key AND the
/// signing arm's `K_new`; each mismatch is a named refusal with zero state change.
#[test]
fn r4_successor_pubkey_mismatch_against_guardians_or_arm_refused_zero_change_10112() {
    let fx = RecoveryFixture::new("r4-agent");
    let k_new = keypair::generate("r4-new").expect("k_new");
    let k_wrong = keypair::generate("r4-wrong").expect("k_wrong");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

    let db_before = fs::read(&fx.db_path).expect("db before");
    let dir_before = snapshot_tree(&fx.anchor_dir);

    let conn = db::open(&fx.db_path).expect("open");

    // 4a. `--successor-pubkey` != guardian-signed key (arm matches wrong key).
    let req_wrong_pub = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_wrong.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &not_before,
        staged_key_label: None,
    };
    let err_g = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req_wrong_pub,
        RecoveryArm::Signing(k_wrong.private.as_ref().expect("priv")),
    )
    .err()
    .expect("mismatch against guardian-signed successor key must be refused");
    let msg_g = format!("{err_g:#}");
    assert!(
        msg_g.contains("unverifiable") || msg_g.contains("signature") || msg_g.contains("quorum"),
        "expected guardian verification mismatch refusal, got: {msg_g}"
    );

    // 4b. `--successor-pubkey` == guardian-signed key, but signing arm holds `K_wrong`.
    let req_right_pub = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &not_before,
        staged_key_label: None,
    };
    let err_arm = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req_right_pub,
        RecoveryArm::Signing(k_wrong.private.as_ref().expect("priv")),
    )
    .err()
    .expect("mismatch against signing arm's K_new must be refused");
    let msg_arm = format!("{err_arm:#}");
    assert!(
        msg_arm.contains(REFUSE_RECOVERY_KEY_MISMATCH),
        "expected REFUSE_RECOVERY_KEY_MISMATCH, got: {msg_arm}"
    );

    drop(conn);
    assert_eq!(fs::read(&fx.db_path).expect("db after"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);

    // 4c. CLI `--successor-key-id wrong-key` pointing at K_wrong also refuses with REFUSE_RECOVERY_KEY_MISMATCH.
    keypair::save(&k_wrong, &fx.anchor_dir).expect("save wrong key");
    let db_before_cli = fs::read(&fx.db_path).expect("db before cli");
    let dir_before_cli = snapshot_tree(&fx.anchor_dir);
    let cli_atts: Vec<String> = atts
        .iter()
        .map(|a| {
            format!(
                "{}:{}",
                a.guardian_pubkey_b64,
                base64::engine::general_purpose::STANDARD.encode(&a.signature)
            )
        })
        .collect();
    let err_cli = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before,
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: Some("r4-wrong".to_string()),
                verify_only: false,
                attestations: cli_atts,
            },
            true,
        )
        .expect_err("CLI --successor-key-id pointing to K_wrong must refuse");
    let msg_cli = format!("{err_cli:#}");
    assert!(
        msg_cli.contains(REFUSE_RECOVERY_KEY_MISMATCH),
        "expected REFUSE_RECOVERY_KEY_MISMATCH from CLI, got: {msg_cli}"
    );
    assert_eq!(fs::read(&fx.db_path).expect("db after cli"), db_before_cli);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before_cli);
}

/// R-5: `agent_lineage`, `agent_pubkey_history`, `_agents` UPDATE, and
/// `row_attestations` commit in ONE transaction; any failure rolls back ALL FOUR.
#[test]
fn r5_single_tx_rollback_on_before_db_commit_fault_10112() {
    let fx = RecoveryFixture::new("r5-agent");
    let k_new = keypair::generate("r5-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

    let conn = db::open(&fx.db_path).expect("open");
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).expect("count") };
    let lin_before = count("SELECT COUNT(*) FROM agent_lineage");
    let hist_before = count("SELECT COUNT(*) FROM agent_pubkey_history");
    let att_before = count("SELECT COUNT(*) FROM row_attestations");
    let pub_before = db::agent_pubkey(&conn, &fx.agent)
        .expect("agent_pubkey before")
        .expect("agent_pubkey set");
    let dir_before = snapshot_tree(&fx.anchor_dir);

    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &not_before,
        staged_key_label: None,
    };
    let checked = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .expect("preconditions");
    let err =
        execute_recovery_rebind_with_fault(&conn, checked, RecoveryFaultPoint::BeforeDbCommit)
            .expect_err("BeforeDbCommit fault must abort");
    assert!(
        format!("{err:#}").contains("BeforeDbCommit"),
        "got: {err:#}"
    );

    assert_eq!(count("SELECT COUNT(*) FROM agent_lineage"), lin_before);
    assert_eq!(
        count("SELECT COUNT(*) FROM agent_pubkey_history"),
        hist_before
    );
    assert_eq!(count("SELECT COUNT(*) FROM row_attestations"), att_before);
    let pub_after = db::agent_pubkey(&conn, &fx.agent)
        .expect("agent_pubkey after")
        .expect("agent_pubkey still set");
    assert_eq!(pub_after, pub_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);
    drop(conn);
    fx.verify_clean();
}

/// R-6: Fault injection at EVERY post-commit step followed by an idempotent
/// re-run converges cleanly to `Outcome::Clean` with zero duplicate archives,
/// zero duplicate `key_id`, and zero leftover staging files.
#[test]
fn r6_fault_injection_every_step_converges_cleanly_on_rerun_10112() {
    let points = [
        (
            "after_db_commit",
            RecoveryFaultPoint::AfterDbCommitBeforeArchive,
        ),
        (
            "after_archive",
            RecoveryFaultPoint::AfterArchiveBeforePrivInstall,
        ),
        (
            "after_priv",
            RecoveryFaultPoint::AfterPrivInstallBeforePubInstall,
        ),
        (
            "after_pub_before_cleanup",
            RecoveryFaultPoint::AfterPubInstallBeforeStagedCleanup,
        ),
        (
            "after_pub_before_seal",
            RecoveryFaultPoint::AfterPubInstallBeforeSealAdvance,
        ),
    ];

    for (label, fault) in points {
        let agent = format!("r6-{label}");
        let fx = RecoveryFixture::new(&agent);
        let staged_label = format!("{agent}-staged");
        let k_new = keypair::generate(&staged_label).expect("k_new");
        keypair::save(&k_new, &fx.anchor_dir).expect("save staged k_new");
        let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &not_before,
            staged_key_label: Some(&staged_label),
        };

        // First run: crash at `fault`.
        {
            let conn = db::open(&fx.db_path).expect("open crash run");
            let checked = recovery_preconditions(
                &conn,
                &fx.anchor_dir,
                &req,
                RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
            )
            .expect("preconditions run 1");
            let err = execute_recovery_rebind_with_fault(&conn, checked, fault)
                .expect_err("injected fault must fail");
            assert!(
                format!("{err:#}").contains("injected fault"),
                "{label}: got {err:#}"
            );
        }

        // Second run: idempotent re-run MUST converge cleanly.
        {
            let conn = db::open(&fx.db_path).expect("open resume run");
            let checked = recovery_preconditions(
                &conn,
                &fx.anchor_dir,
                &req,
                RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
            )
            .unwrap_or_else(|e| panic!("{label}: resume preconditions failed: {e:#}"));
            let outcome = execute_recovery_rebind(&conn, checked)
                .unwrap_or_else(|e| panic!("{label}: resume execute failed: {e:#}"));
            assert!(
                outcome.resumed_from_committed_db,
                "{label}: re-run after DB commit must report resumed_from_committed_db=true"
            );
        }

        // Assert Clean verification, 1 archive, 0 staged siblings, 0 .recover-*.tmp.
        fx.verify_clean();
        let entries: Vec<String> = fs::read_dir(&fx.anchor_dir)
            .expect("read anchor dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let archives: Vec<_> = entries
            .iter()
            .filter(|n| n.starts_with(&format!("{agent}.pub.")))
            .collect();
        assert_eq!(
            archives.len(),
            1,
            "{label}: expected 1 archive, got {archives:?}"
        );
        assert!(
            !entries.iter().any(|n| n.starts_with(".recover-")),
            "{label}: leftover temp file in {entries:?}"
        );
        assert!(
            !entries.iter().any(|n| n.starts_with(&staged_label)),
            "{label}: staged sibling not cleaned up in {entries:?}"
        );

        // Third run (after full convergence): MUST be refused as replay (R-9).
        {
            let conn = db::open(&fx.db_path).expect("open replay check");
            let err = recovery_preconditions(
                &conn,
                &fx.anchor_dir,
                &req,
                RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
            )
            .err()
            .expect("replay after convergence must be refused");
            assert!(
                format!("{err:#}").contains(REFUSE_RECOVERY_REPLAY),
                "{label}: expected REFUSE_RECOVERY_REPLAY, got {err:#}"
            );
        }
    }
}

/// R-7: Swapping `<agent>.pub` in the anchor directory alone (without a
/// quorum-verified recovery lineage record) is refused.
#[test]
fn r7_bare_anchor_swap_without_quorum_verified_lineage_refused_10112() {
    let fx = RecoveryFixture::new("r7-agent");
    let k_attacker = keypair::generate(&fx.agent).expect("k_attacker");

    // Archive K_old and swap `<agent>.pub` on disk WITHOUT any recovery record.
    fs::write(
        fx.anchor_dir.join(format!("{}.pub.1700000000", fx.agent)),
        fx.k_old.public.to_bytes(),
    )
    .expect("write fake archive");
    fs::write(
        fx.anchor_dir.join(format!("{}.pub", fx.agent)),
        k_attacker.public.to_bytes(),
    )
    .expect("swap pub file");

    let conn = db::open(&fx.db_path).expect("open");
    let AnchorLoad::Anchored(anchor) = TrustAnchor::load_dir(&fx.anchor_dir) else {
        panic!("expected Anchored");
    };
    let err = verify_anchor_against_lineage(&conn, &anchor, &fx.agent)
        .expect_err("bare anchor swap without quorum-verified lineage record must be refused");
    assert!(
        format!("{err:#}").contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP, got: {err:#}"
    );

    // Attempting to arm with K_attacker is also refused with REFUSE_KEY_MISMATCH.
    let err_arm = arm_with_key(&conn, &fx.agent, k_attacker.private.as_ref().expect("priv"))
        .expect_err("arm_with_key with swapped attacker key must refuse");
    assert!(
        format!("{err_arm:#}").contains(REFUSE_KEY_MISMATCH),
        "expected REFUSE_KEY_MISMATCH, got: {err_arm:#}"
    );
    drop(conn);

    // Even if an attacker with raw DB write access inserts a forged recovery
    // lineage record without valid guardian quorum, verification still refuses!
    let raw = Connection::open(&fx.db_path).expect("raw open");
    let (head, _) = db::lineage_head(&raw, &fx.agent)
        .expect("head")
        .expect("head exists");
    let policy = RecoveryPolicy::from_env().expect("policy");
    let forged = ai_memory::identity::lineage::LineageRecord::recovery(
        &head,
        &k_attacker.public_base64(),
        None,
        head.recovery_pubkey_b64.clone(),
        policy.guardian_set_id(),
        2,
        "2026-11-26T00:00:00Z",
    )
    .expect("build forged recovery");
    let forged_bytes = forged.canonical_bytes().expect("cbor");
    let empty_quorum = encode_recovery_quorum(&[]).expect("empty quorum");
    raw.execute(
        "INSERT INTO agent_lineage \
            (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, recovery_pubkey, \
             not_before, prev_record_hash, signature, record_bytes, created_at, custody_class, \
             suspected_compromise_from_seq, guardian_set_id, recovery_threshold) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            forged.agent_id,
            i64::try_from(forged.epoch).unwrap(),
            forged.reason.as_str(),
            forged.predecessor_pubkey_b64,
            forged.successor_pubkey_b64,
            forged.recovery_pubkey_b64,
            forged.not_before,
            forged.prev_record_hash,
            empty_quorum,
            forged_bytes,
            "2026-11-26T00:00:00Z",
            forged.custody_class.as_str(),
            Option::<i64>::None,
            forged.guardian_set_id.as_deref(),
            Some(2_i64),
        ],
    )
    .expect("insert forged recovery row");
    drop(raw);

    let conn2 = db::open(&fx.db_path).expect("reopen");
    let err2 = verify_anchor_against_lineage(&conn2, &anchor, &fx.agent)
        .expect_err("forged recovery lineage record without guardian quorum must be refused");
    assert!(
        format!("{err2:#}").contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP on forged lineage, got: {err2:#}"
    );
}

/// R-8: Verify-only arm, missing `K_new.priv`, and quorum shortfall are EACH
/// preflight named refusals leaving the DB file and anchor directory byte-identical.
#[test]
fn r8_three_preflight_refusals_leave_db_and_anchor_byte_identical_10112() {
    let fx = RecoveryFixture::new("r8-agent");
    let k_new = keypair::generate("r8-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);
    let cli_atts: Vec<String> = atts
        .iter()
        .map(|a| {
            format!(
                "{}:{}",
                a.guardian_pubkey_b64,
                base64::engine::general_purpose::STANDARD.encode(&a.signature)
            )
        })
        .collect();

    let db_before = fs::read(&fx.db_path).expect("db before");
    let dir_before = snapshot_tree(&fx.anchor_dir);

    // 8a. Verify-only arm via CLI `--verify-only` (even if K_new were present).
    let err_vo = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before: not_before.clone(),
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: None,
                verify_only: true,
                attestations: cli_atts.clone(),
            },
            true,
        )
        .expect_err("verify-only arm must refuse");
    assert!(
        format!("{err_vo:#}").contains(REFUSE_RECOVERY_VERIFY_ONLY),
        "expected REFUSE_RECOVERY_VERIFY_ONLY, got: {err_vo:#}"
    );
    assert_eq!(fs::read(&fx.db_path).expect("db after vo"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);

    // 8b. Missing K_new private key.
    let err_mp = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before: not_before.clone(),
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: None,
                verify_only: false,
                attestations: cli_atts.clone(),
            },
            true,
        )
        .expect_err("missing K_new.priv must refuse");
    assert!(
        format!("{err_mp:#}").contains(REFUSE_RECOVERY_MISSING_PRIV),
        "expected REFUSE_RECOVERY_MISSING_PRIV, got: {err_mp:#}"
    );
    assert_eq!(fs::read(&fx.db_path).expect("db after mp"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);

    // 8c. Quorum shortfall (only 1 of 2 attestations).
    let err_qs = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before,
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: None,
                verify_only: false,
                attestations: vec![cli_atts[0].clone()],
            },
            true,
        )
        .expect_err("quorum shortfall must refuse");
    let msg_qs = format!("{err_qs:#}");
    assert!(
        msg_qs.contains("quorum")
            || msg_qs.contains("threshold")
            || msg_qs.contains("unverifiable"),
        "expected quorum shortfall refusal, got: {msg_qs}"
    );
    assert_eq!(fs::read(&fx.db_path).expect("db after qs"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);
}

/// R-9: ONE timestamp `ts` for `K_old.valid_to`, `K_new.valid_from`, and the
/// rebind `row_attestations.attested_at`; `K_old` cannot attest at or after `ts`;
/// pre-`ts` rows verify under `K_old` and rebind verifies under `K_new`;
/// replaying a recovery record or reusing an epoch/key is refused.
#[test]
fn r9_single_timestamp_window_k_old_refusal_and_replay_refused_10112() {
    let fx = RecoveryFixture::new("r9-agent");
    let k_new = keypair::generate("r9-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

    let outcome = {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &not_before,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .expect("preconditions");
        execute_recovery_rebind(&conn, checked).expect("execute")
    };

    let conn = db::open(&fx.db_path).expect("open verify");
    // 9a. Single timestamp across archive filename, K_old.superseded_at,
    // K_new.bound_at, and _agents rebind row_attestations.attested_at.
    assert!(
        outcome
            .archived_pub
            .file_name()
            .expect("name")
            .to_string_lossy()
            .contains(&format!(".pub.{}", outcome.ts_secs)),
        "archive path must carry ts_secs {}: {}",
        outcome.ts_secs,
        outcome.archived_pub.display()
    );
    let k_old_sup: String = conn
        .query_row(
            "SELECT superseded_at FROM agent_pubkey_history WHERE agent_id = ?1 AND version = 1",
            [&fx.agent],
            |r| r.get(0),
        )
        .expect("k_old superseded_at");
    let k_new_bound: String = conn
        .query_row(
            "SELECT bound_at FROM agent_pubkey_history WHERE agent_id = ?1 AND version = 2",
            [&fx.agent],
            |r| r.get(0),
        )
        .expect("k_new bound_at");
    let (rebind_att_ts, rebind_key_id): (String, String) = conn
        .query_row(
            "SELECT attested_at, key_id FROM row_attestations
             WHERE table_name = 'memories' AND op = 'update' ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("rebind attestation");
    assert_eq!(k_old_sup, outcome.ts_rfc, "K_old superseded_at == ts_rfc");
    assert_eq!(k_new_bound, outcome.ts_rfc, "K_new bound_at == ts_rfc");
    assert_eq!(
        rebind_att_ts, outcome.ts_rfc,
        "rebind row_attestations.attested_at == ts_rfc"
    );
    assert_eq!(
        rebind_key_id,
        key_id_of(&k_new.public),
        "rebind row must be attested by K_new"
    );

    // Pre-recovery memory row is attested by K_old.
    let pre_key_id: String = conn
        .query_row(
            "SELECT key_id FROM row_attestations
             WHERE table_name = 'memories' AND op = 'insert' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("pre-recovery memory attestation");
    assert_eq!(
        pre_key_id,
        key_id_of(&fx.k_old.public),
        "pre-recovery row must be attested by K_old"
    );

    // 9b. K_old CANNOT attest at or after `ts`:
    // - `arm_with_key(K_old)` refuses with REFUSE_KEY_MISMATCH
    // - `TrustAnchor::key_for(K_old, ts + 1)` refuses with OutOfRange
    let err_old_arm = arm_with_key(
        &conn,
        &fx.agent,
        fx.k_old.private.as_ref().expect("k_old priv in mem"),
    )
    .expect_err("retired K_old must not arm after recovery");
    assert!(
        format!("{err_old_arm:#}").contains(REFUSE_KEY_MISMATCH),
        "expected REFUSE_KEY_MISMATCH, got: {err_old_arm:#}"
    );
    let AnchorLoad::Anchored(anchor) = TrustAnchor::load_dir(&fx.anchor_dir) else {
        panic!("expected Anchored");
    };
    let after_ts = chrono::DateTime::from_timestamp(outcome.ts_secs + 1, 0)
        .expect("ts+1")
        .to_rfc3339();
    let old_after = anchor.key_for(&fx.agent, &key_id_of(&fx.k_old.public), &after_ts);
    assert!(
        matches!(old_after, Err(KeyRefusal::OutOfRange { .. })),
        "K_old at ts+1 must be OutOfRange, got: {old_after:?}"
    );
    assert!(
        anchor
            .key_for(&fx.agent, &key_id_of(&k_new.public), &outcome.ts_rfc)
            .is_ok(),
        "K_new must be valid at ts"
    );

    // 9c. Replaying the converged recovery record OR trying to recover back to
    // retired K_old is refused with REFUSE_RECOVERY_REPLAY.
    let replay_req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &not_before,
        staged_key_label: None,
    };
    let err_replay = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &replay_req,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .err()
    .expect("replaying converged recovery must be refused");
    assert!(
        format!("{err_replay:#}").contains(REFUSE_RECOVERY_REPLAY),
        "expected REFUSE_RECOVERY_REPLAY, got: {err_replay:#}"
    );

    let (nb_reuse, atts_reuse) = fx.prepare_and_sign(&fx.k_old, &[0, 1]);
    let reuse_req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &fx.k_old.public_base64(),
        quorum: &atts_reuse,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb_reuse,
        staged_key_label: None,
    };
    let err_reuse = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &reuse_req,
        RecoveryArm::Signing(fx.k_old.private.as_ref().expect("priv")),
    )
    .err()
    .expect("reusing retired K_old in a new recovery must be refused");
    assert!(
        format!("{err_reuse:#}").contains(REFUSE_RECOVERY_REPLAY),
        "expected REFUSE_RECOVERY_REPLAY for retired-key reuse, got: {err_reuse:#}"
    );

    drop(conn);
    fx.verify_clean();
}

/// R-10: After recovery, `audit verify-rows` exits `0` (`clean`), the anchored
/// seal advances, and BOTH a later `identity succeed` AND a later
/// `bind_agent_pubkey` pass without `REFUSE_ROW_DRIFT`.
#[test]
fn r10_post_recovery_verify_rows_seal_advance_succeed_and_bind_10112() {
    let fx = RecoveryFixture::new("r10-agent");
    let SealState::Sealed(seal_before) = fx.seal_state() else {
        panic!("expected pre-recovery seal to be Sealed");
    };

    let k_new = keypair::generate("r10-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &not_before,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .expect("preconditions");
        execute_recovery_rebind(&conn, checked).expect("execute");
    }

    // 10a. `audit verify-rows --json` exits 0 (`clean`).
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        audit_verify_rows::run(&VerifyRowsArgs { json: true }, &fx.db_path, &mut out)
            .expect("audit verify-rows")
    };
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("parse verify-rows json");
    assert_eq!(code, 0, "audit verify-rows must exit 0, got: {report}");
    assert_eq!(report["outcome"], "clean", "got: {report}");
    assert_eq!(report["signatures_checked"], true, "got: {report}");

    // 10b. Anchored seal strictly advanced.
    let SealState::Sealed(seal_after) = fx.seal_state() else {
        panic!("expected post-recovery seal to be Sealed");
    };
    assert!(
        seal_after.high_water > seal_before.high_water,
        "seal high_water must strictly advance ({} -> {})",
        seal_before.high_water,
        seal_after.high_water
    );

    // 10c. Later `bind_agent_pubkey` (idempotent same-key reassertion under K_new)
    // passes without REFUSE_ROW_DRIFT.
    {
        let conn = db::open(&fx.db_path).expect("open for bind");
        arm_with_key(
            &conn,
            &fx.agent,
            k_new.private.as_ref().expect("k_new priv"),
        )
        .expect("arm with k_new");
        db::bind_agent_pubkey_with_keypair(&conn, &fx.agent, &k_new)
            .expect("later bind_agent_pubkey must pass without REFUSE_ROW_DRIFT");
    }

    // 10d. Later `identity succeed` passes without REFUSE_ROW_DRIFT and verifies Clean.
    fx.run_cli(
        IdentityAction::Succeed {
            agent_id: Some(fx.agent.clone()),
        },
        true,
    )
    .expect("later identity succeed after recovery must pass");
    fx.verify_clean();
}

/// R-12: Backup & restore of recovered store, pre-recovery backup restored under
/// post-recovery anchor, portability `--full` export & import round-trip, and
/// `#10110` retired-key import refusal all round-trip Clean.
#[test]
fn r12_backup_restore_pre_recovery_backup_portability_and_10110_import_10112() {
    let fx = RecoveryFixture::new("r12-agent");

    // Snapshot pre-recovery DB BEFORE recovery.
    let pre_backup_path = fx.root.path().join("pre-recovery-backup.db");
    fs::copy(&fx.db_path, &pre_backup_path).expect("copy pre-recovery backup");

    // Execute recovery K_old -> K_new.
    let k_new = keypair::generate("r12-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &not_before,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .expect("preconditions");
        execute_recovery_rebind(&conn, checked).expect("execute");
    }
    fx.verify_clean();

    // 12a. Backup & restore of the RECOVERED store verifies Clean.
    let post_backup_path = fx.root.path().join("post-recovery-backup.db");
    fs::copy(&fx.db_path, &post_backup_path).expect("copy post-recovery backup");
    let post_restored_target = fx.root.path().join("post-restored.db");
    {
        let snap_conn = Connection::open(&post_backup_path).expect("open post snapshot");
        let verdict = check_snapshot(&snap_conn, &post_restored_target)
            .expect("post-recovery snapshot must verify");
        let SnapshotVerdict::Verified(rec) = verdict else {
            panic!("expected SnapshotVerdict::Verified, got: {verdict:?}");
        };
        fs::copy(&post_backup_path, &post_restored_target).expect("publish restored");
        seal_restored(&post_restored_target, &rec).expect("seal_restored");
        let restored_conn = db::open(&post_restored_target).expect("open restored");
        let anchor = TrustAnchor::load_dir(&fx.anchor_dir);
        let rep = verify_sqlite_with(&restored_conn, &anchor).expect("verify restored");
        assert!(
            matches!(rep.outcome(), Outcome::Clean),
            "restored post-recovery store must be Clean: {:?}",
            rep.outcome()
        );
    }

    // 12b. PRE-recovery backup restored under the POST-recovery anchor verifies Clean
    // (because retired K_old is archived at `<agent>.pub.<ts>` with valid_to = ts).
    let pre_restored_target = fx.root.path().join("pre-restored-under-post-anchor.db");
    {
        let pre_conn = Connection::open(&pre_backup_path).expect("open pre snapshot");
        let verdict = check_snapshot(&pre_conn, &pre_restored_target)
            .expect("pre-recovery snapshot must verify under post-recovery anchor");
        let SnapshotVerdict::Verified(rec) = verdict else {
            panic!("expected SnapshotVerdict::Verified for pre-recovery backup, got: {verdict:?}");
        };
        fs::copy(&pre_backup_path, &pre_restored_target).expect("publish pre restored");
        seal_restored(&pre_restored_target, &rec).expect("seal_restored pre");
        let restored_conn = db::open(&pre_restored_target).expect("open pre restored");
        let anchor = TrustAnchor::load_dir(&fx.anchor_dir);
        let rep = verify_sqlite_with(&restored_conn, &anchor).expect("verify pre restored");
        assert!(
            matches!(rep.outcome(), Outcome::Clean),
            "pre-recovery backup restored under post-recovery anchor must be Clean: {:?}",
            rep.outcome()
        );
    }

    // 12c. Portability `--full` export & import round-trip preserves memory & lineage.
    let imported_db = fx.root.path().join("portability-imported.db");
    {
        let src_conn = db::open(&fx.db_path).expect("open src for export");
        let (envelope, _ledger) =
            build_full_envelope_audited(&src_conn, "r12-source", "2026-11-26T12:00:00Z")
                .expect("build_full_envelope_audited");
        let dst_conn = db::open(&imported_db).expect("open dst for import");
        // #3464: destination establishes target-agent possession of K_new and
        // arms its funnel before importing the recovered bundle's lineage chain.
        db::register_agent(&dst_conn, &fx.agent, "ai:test", &[]).expect("register dst");
        db::bind_agent_pubkey_with_keypair(&dst_conn, &fx.agent, &k_new)
            .expect("bind K_new on dst");
        arm_with_key(&dst_conn, &fx.agent, k_new.private.as_ref().expect("priv"))
            .expect("arm imported store with K_new");
        let imp = import_full_envelope(&dst_conn, &envelope, &ImportOptions::default())
            .expect("import_full_envelope");
        assert!(
            imp.memories >= 1,
            "imported store must contain the pre-recovery memory: {imp:?}"
        );
        assert_eq!(
            imp.agent_lineage, 2,
            "imported store must carry genesis + recovery lineage records: {imp:?}"
        );
        let anchor = TrustAnchor::load_dir(&fx.anchor_dir);
        let rep = verify_sqlite_with(&dst_conn, &anchor).expect("verify imported");
        assert!(
            matches!(rep.outcome(), Outcome::Clean),
            "portability round-trip store must verify Clean: {:?}",
            rep.outcome()
        );
    }

    // 12d. `#10110` retired-key import path: importing retired K_old over active
    // K_new is refused with `IMPORT_REFUSED_DIFFERENT_KEY`, leaving store Clean;
    // importing identical K_new is a no-op.
    let k_old_pub_file = fx.root.path().join("k_old_import.pub");
    fs::write(&k_old_pub_file, fx.k_old.public.to_bytes()).expect("write k_old pub");
    let err_imp = fx
        .run_cli(
            IdentityAction::Import {
                agent_id: fx.agent.clone(),
                public: k_old_pub_file,
                private: None,
            },
            false,
        )
        .expect_err("importing retired K_old over active K_new must be refused (#10110)");
    assert!(
        format!("{err_imp:#}")
            .contains("refusing to overwrite existing keypair with a different key"),
        "expected #10110 IMPORT_REFUSED_DIFFERENT_KEY refusal, got: {err_imp:#}"
    );
    fx.verify_clean();

    let k_new_pub_file = fx.root.path().join("k_new_import.pub");
    fs::write(&k_new_pub_file, k_new.public.to_bytes()).expect("write k_new pub");
    fx.run_cli(
        IdentityAction::Import {
            agent_id: fx.agent.clone(),
            public: k_new_pub_file,
            private: None,
        },
        false,
    )
    .expect("importing identical K_new pub must succeed as no-op (#10110)");
    fx.verify_clean();
}

/// R-14: `K_new` private key bytes/base64 are NEVER printed, logged, or written
/// outside the key directory, and `<agent>.priv` has mode `0o600` on Unix.
#[test]
fn r14_k_new_private_key_never_leaks_and_mode_0600_10112() {
    let fx = RecoveryFixture::new("r14-agent");
    let staged_label = "r14-staged-new";
    let k_new = keypair::generate(staged_label).expect("k_new");
    keypair::save(&k_new, &fx.anchor_dir).expect("stage k_new");

    let priv_bytes = k_new.private.as_ref().expect("priv").to_bytes();
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(priv_bytes);
    let priv_hex = hex::encode(priv_bytes);

    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);
    let cli_atts: Vec<String> = atts
        .iter()
        .map(|a| {
            format!(
                "{}:{}",
                a.guardian_pubkey_b64,
                base64::engine::general_purpose::STANDARD.encode(&a.signature)
            )
        })
        .collect();

    let (stdout, stderr) = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before,
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: Some(staged_label.to_string()),
                verify_only: false,
                attestations: cli_atts,
            },
            true,
        )
        .expect("CLI recovery must succeed");

    for (stream_name, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.contains(&priv_b64),
            "R-14: K_new private key base64 leaked in {stream_name}"
        );
        assert!(
            !text.contains(&priv_hex),
            "R-14: K_new private key hex leaked in {stream_name}"
        );
    }

    // Confirm K_new.priv is ONLY inside `anchor_dir/<agent>.priv` (never copied
    // to witness_dir, home_dir, or anywhere else under root) and has mode 0600.
    let installed_priv = fx.anchor_dir.join(format!("{}.priv", fx.agent));
    assert_eq!(
        fs::read(&installed_priv).expect("read installed priv"),
        priv_bytes.as_slice()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&installed_priv)
            .expect("stat priv")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "R-14: <agent>.priv must be mode 0600");
    }

    for outside in [&fx.witness_dir, &fx.home_dir] {
        for (rel, bytes) in snapshot_tree(outside) {
            assert!(
                !bytes.windows(priv_bytes.len()).any(|w| w == priv_bytes),
                "R-14: K_new private key bytes written outside anchor_dir at {}/{}",
                outside.display(),
                rel.display()
            );
        }
    }
    // DB file itself never stores K_new private key bytes or base64.
    let db_bytes = fs::read(&fx.db_path).expect("read db");
    assert!(
        !db_bytes.windows(priv_bytes.len()).any(|w| w == priv_bytes),
        "R-14: K_new raw private key bytes found in SQLite DB"
    );
    assert!(
        !db_bytes
            .windows(priv_b64.len())
            .any(|w| w == priv_b64.as_bytes()),
        "R-14: K_new private key base64 found in SQLite DB"
    );
    // Lineage record carries expected Recovery reason and pre_mem_id still intact.
    let conn = db::open(&fx.db_path).expect("open");
    let (head, _) = db::lineage_head(&conn, &fx.agent)
        .expect("head")
        .expect("head exists");
    assert_eq!(head.reason, LineageReason::Recovery);
    let _ = db::get(&conn, &fx.pre_mem_id).expect("pre_mem intact");
}

/// Self-review security & code pins (S-2 path traversal, S-3 CLI R-1 ordering on
/// missing `--successor-key-id`, C-1 direct `db::append_recovery` refusal on armed store).
#[test]
fn self_review_pins_path_escape_cli_r1_order_and_direct_append_recovery_refused_10112() {
    let fx = RecoveryFixture::new("sr-agent");
    let k_new = keypair::generate("sr-new").expect("k_new");
    let (not_before, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);
    let cli_att0 = format!(
        "{}:{}",
        atts[0].guardian_pubkey_b64,
        base64::engine::general_purpose::STANDARD.encode(&atts[0].signature)
    );

    let db_before = fs::read(&fx.db_path).expect("db before");
    let dir_before = snapshot_tree(&fx.anchor_dir);

    // S-2: path-traversal `staged_key_label` is refused preflight with zero changes.
    {
        let conn = db::open(&fx.db_path).expect("open");
        let req_escape = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &not_before,
            staged_key_label: Some("../escape"),
        };
        let err = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req_escape,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .err()
        .expect("path-traversal staged_key_label must be refused");
        assert!(
            format!("{err:#}").contains("invalid")
                || format!("{err:#}").contains("agent_id")
                || format!("{err:#}").contains("path")
                || format!("{err:#}").contains(".."),
            "expected shape-validation refusal for ../escape, got: {err:#}"
        );
    }

    // S-3 / R-1: CLI `--successor-key-id missing-key` with quorum shortfall MUST
    // still fail on guardian quorum FIRST (not missing key).
    let err_r1_cli = fx
        .run_cli(
            IdentityAction::Recover {
                agent_id: Some(fx.agent.clone()),
                successor_pubkey: k_new.public_base64(),
                not_before: not_before.clone(),
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: Some("does-not-exist".to_string()),
                verify_only: false,
                attestations: vec![cli_att0],
            },
            true,
        )
        .expect_err("short quorum with missing --successor-key-id must refuse on quorum first");
    let msg_r1_cli = format!("{err_r1_cli:#}");
    assert!(
        msg_r1_cli.contains("met only 1 of 2")
            && !msg_r1_cli.contains(REFUSE_RECOVERY_MISSING_PRIV),
        "S-3/R-1: quorum refusal must fire before missing-key refusal, got: {msg_r1_cli}"
    );

    // C-1: Direct `db::append_recovery` on an armed SQLite store (even via a raw
    // `rusqlite::Connection` without TEMP triggers!) refuses with REFUSE_RECOVERY_VERIFY_ONLY.
    {
        let raw = Connection::open(&fx.db_path).expect("raw open");
        let err_raw = db::append_recovery(
            &raw,
            &fx.agent,
            &k_new.public_base64(),
            &atts,
            None,
            None,
            &not_before,
        )
        .expect_err("direct append_recovery on armed store must be refused");
        assert!(
            format!("{err_raw:#}").contains(REFUSE_RECOVERY_VERIFY_ONLY),
            "C-1: expected REFUSE_RECOVERY_VERIFY_ONLY from direct append_recovery, got: {err_raw:#}"
        );
    }

    assert_eq!(fs::read(&fx.db_path).expect("db after"), db_before);
    assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);
}

/// Helper: execute a valid 2-of-3 recovery so a store carries a committed
/// epoch-1 `Recovery` record before round-1 security probes tamper with raw rows.
fn run_valid_recovery(fx: &RecoveryFixture, k_new: &AgentKeypair) {
    let (nb, atts) = fx.prepare_and_sign(k_new, &[0, 1]);
    let conn = db::open(&fx.db_path).expect("open");
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb,
        staged_key_label: None,
    };
    let checked = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .expect("valid preconditions");
    execute_recovery_rebind(&conn, checked).expect("valid execute");
}

/// S-F1 (#10159) form 1: unsigned edit of `agent_lineage.recovery_threshold`
/// (2 -> 1) must be refused by `recovery_preconditions` before resolving quorum.
#[test]
fn sf1_forged_threshold_column_refused_10159() {
    let fx = RecoveryFixture::new("sf1-thr-agent");
    let k1 = keypair::generate("sf1-thr-k1").expect("k1");
    run_valid_recovery(&fx, &k1);

    // Unsigned raw SQL edit lowers recovery_threshold from 2 -> 1 on epoch 1.
    let raw = Connection::open(&fx.db_path).expect("raw open");
    raw.execute(
        "UPDATE agent_lineage SET recovery_threshold = 1 WHERE agent_id = ?1 AND epoch = 1",
        [&fx.agent],
    )
    .expect("tamper threshold");
    drop(raw);

    let k2 = keypair::generate("sf1-thr-k2").expect("k2");
    let conn = db::open(&fx.db_path).expect("open");
    let (head, _) = db::lineage_head(&conn, &fx.agent)
        .expect("head")
        .expect("head exists");
    let policy = RecoveryPolicy::from_env().expect("policy");
    let nb = chrono::Utc::now().to_rfc3339();
    let rec = ai_memory::identity::lineage::LineageRecord::recovery(
        &head,
        &k2.public_base64(),
        None,
        head.recovery_pubkey_b64.clone(),
        policy.guardian_set_id(),
        1,
        &nb,
    )
    .expect("build forged-threshold rec");
    let sig_input = rec.signing_input().expect("signing_input");
    let one_att = vec![RecoveryAttestation {
        guardian_pubkey_b64: fx.guardians[0].public_base64(),
        signature: fx.guardians[0]
            .private
            .as_ref()
            .expect("g0 priv")
            .sign(&sig_input)
            .to_bytes()
            .to_vec(),
    }];
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k2.public_base64(),
        quorum: &one_att,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb,
        staged_key_label: None,
    };
    let err = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k2.private.as_ref().expect("k2 priv")),
    )
    .err()
    .expect("S-F1: forged recovery_threshold column must be refused");
    assert!(
        format!("{err:#}").contains("unverified lineage"),
        "expected unverified-lineage refusal, got: {err:#}"
    );
}

/// S-F1 (#10159) form 2: unsigned edit of `agent_lineage.guardian_set_id` must
/// be refused by `recovery_preconditions`.
#[test]
fn sf1_forged_guardian_set_id_column_refused_10159() {
    let fx = RecoveryFixture::new("sf1-gid-agent");
    let k1 = keypair::generate("sf1-gid-k1").expect("k1");
    run_valid_recovery(&fx, &k1);

    let attacker_g = keypair::generate("sf1-attacker-g").expect("attacker g");
    let attacker_gid = ai_memory::identity::lineage::guardian_set_id_digest(&[attacker_g.public]);

    let raw = Connection::open(&fx.db_path).expect("raw open");
    raw.execute(
        "UPDATE agent_lineage SET guardian_set_id = ?1, recovery_threshold = 1 \
         WHERE agent_id = ?2 AND epoch = 1",
        rusqlite::params![attacker_gid, &fx.agent],
    )
    .expect("tamper guardian_set_id");
    drop(raw);

    // SAFETY: serialized by ENV_LOCK held inside `fx._env`.
    unsafe {
        std::env::set_var(RECOVERY_GUARDIAN_PUBKEYS_ENV, attacker_g.public_base64());
        std::env::set_var(RECOVERY_THRESHOLD_ENV, "1");
    }

    let k2 = keypair::generate("sf1-gid-k2").expect("k2");
    let conn = db::open(&fx.db_path).expect("open");
    let (head, _) = db::lineage_head(&conn, &fx.agent)
        .expect("head")
        .expect("head exists");
    let nb = chrono::Utc::now().to_rfc3339();
    let rec = ai_memory::identity::lineage::LineageRecord::recovery(
        &head,
        &k2.public_base64(),
        None,
        head.recovery_pubkey_b64.clone(),
        attacker_gid,
        1,
        &nb,
    )
    .expect("build rec");
    let sig_input = rec.signing_input().expect("signing_input");
    let att = vec![RecoveryAttestation {
        guardian_pubkey_b64: attacker_g.public_base64(),
        signature: attacker_g
            .private
            .as_ref()
            .expect("priv")
            .sign(&sig_input)
            .to_bytes()
            .to_vec(),
    }];
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k2.public_base64(),
        quorum: &att,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb,
        staged_key_label: None,
    };
    let err = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k2.private.as_ref().expect("k2 priv")),
    )
    .err()
    .expect("S-F1: forged guardian_set_id column must be refused");
    assert!(
        format!("{err:#}").contains("unverified lineage"),
        "expected unverified-lineage refusal, got: {err:#}"
    );
}

/// S-F1 (#10159) form 3: extra unsigned/forged `Recovery` row inserted in
/// `agent_lineage` with lowered threshold must be refused before quorum resolution.
#[test]
fn sf1_forged_extra_recovery_row_refused_10159() {
    let fx = RecoveryFixture::new("sf1-extra-agent");
    let k_decoy = keypair::generate("sf1-decoy").expect("decoy");
    let k_takeover = keypair::generate("sf1-takeover").expect("takeover");

    let policy = RecoveryPolicy::from_env().expect("policy");
    let raw = Connection::open(&fx.db_path).expect("raw open");
    let (head, _) = db::lineage_head(&raw, &fx.agent)
        .expect("head")
        .expect("head exists");
    let forged = ai_memory::identity::lineage::LineageRecord::recovery(
        &head,
        &k_decoy.public_base64(),
        None,
        head.recovery_pubkey_b64.clone(),
        policy.guardian_set_id(),
        1,
        "2026-11-26T00:00:00Z",
    )
    .expect("forged");
    let forged_bytes = forged.canonical_bytes().expect("cbor");
    let empty_q = encode_recovery_quorum(&[]).expect("empty q");
    raw.execute(
        "INSERT INTO agent_lineage \
            (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, recovery_pubkey, \
             not_before, prev_record_hash, signature, record_bytes, created_at, custody_class, \
             suspected_compromise_from_seq, guardian_set_id, recovery_threshold) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            forged.agent_id,
            i64::try_from(forged.epoch).unwrap(),
            forged.reason.as_str(),
            forged.predecessor_pubkey_b64,
            forged.successor_pubkey_b64,
            forged.recovery_pubkey_b64,
            forged.not_before,
            forged.prev_record_hash,
            empty_q,
            forged_bytes,
            "2026-11-26T00:00:00Z",
            forged.custody_class.as_str(),
            Option::<i64>::None,
            forged.guardian_set_id.as_deref(),
            Some(1_i64),
        ],
    )
    .expect("insert extra forged recovery row");
    drop(raw);

    let conn = db::open(&fx.db_path).expect("open");
    let nb = chrono::Utc::now().to_rfc3339();
    let rec2 = ai_memory::identity::lineage::LineageRecord::recovery(
        &forged,
        &k_takeover.public_base64(),
        None,
        forged.recovery_pubkey_b64.clone(),
        policy.guardian_set_id(),
        1,
        &nb,
    )
    .expect("rec2");
    let sig_input = rec2.signing_input().expect("signing_input");
    let one_att = vec![RecoveryAttestation {
        guardian_pubkey_b64: fx.guardians[0].public_base64(),
        signature: fx.guardians[0]
            .private
            .as_ref()
            .expect("g0 priv")
            .sign(&sig_input)
            .to_bytes()
            .to_vec(),
    }];
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_takeover.public_base64(),
        quorum: &one_att,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb,
        staged_key_label: None,
    };
    let err = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k_takeover.private.as_ref().expect("priv")),
    )
    .err()
    .expect("S-F1: extra forged Recovery row must be refused");
    assert!(
        format!("{err:#}").contains("unverified lineage"),
        "expected unverified-lineage refusal, got: {err:#}"
    );
}

/// S-F1 (#10159) form 4: forged `Recovery` head matching candidate `K_new` and
/// `not_before` must NEVER enter `ResumeAnchor`.
#[test]
fn sf1_forged_resume_head_refused_10159() {
    let fx = RecoveryFixture::new("sf1-resume-agent");
    let k_attacker = keypair::generate("sf1-resume-attacker").expect("k_attacker");
    let policy = RecoveryPolicy::from_env().expect("policy");
    let nb = "2026-11-26T15:00:00Z";

    let raw = Connection::open(&fx.db_path).expect("raw open");
    let (head, _) = db::lineage_head(&raw, &fx.agent)
        .expect("head")
        .expect("head exists");
    let forged = ai_memory::identity::lineage::LineageRecord::recovery(
        &head,
        &k_attacker.public_base64(),
        None,
        head.recovery_pubkey_b64.clone(),
        policy.guardian_set_id(),
        1,
        nb,
    )
    .expect("forged resume head");
    let sig_input = forged.signing_input().expect("signing_input");
    let one_att = vec![RecoveryAttestation {
        guardian_pubkey_b64: fx.guardians[0].public_base64(),
        signature: fx.guardians[0]
            .private
            .as_ref()
            .expect("g0 priv")
            .sign(&sig_input)
            .to_bytes()
            .to_vec(),
    }];
    let forged_q = encode_recovery_quorum(&one_att).expect("encode q");
    let forged_bytes = forged.canonical_bytes().expect("cbor");
    raw.execute(
        "INSERT INTO agent_lineage \
            (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, recovery_pubkey, \
             not_before, prev_record_hash, signature, record_bytes, created_at, custody_class, \
             suspected_compromise_from_seq, guardian_set_id, recovery_threshold) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            forged.agent_id,
            i64::try_from(forged.epoch).unwrap(),
            forged.reason.as_str(),
            forged.predecessor_pubkey_b64,
            forged.successor_pubkey_b64,
            forged.recovery_pubkey_b64,
            forged.not_before,
            forged.prev_record_hash,
            forged_q,
            forged_bytes,
            nb,
            forged.custody_class.as_str(),
            Option::<i64>::None,
            forged.guardian_set_id.as_deref(),
            Some(1_i64),
        ],
    )
    .expect("insert forged resume head");
    raw.execute(
        "UPDATE agent_pubkey_history SET superseded_at = ?2 \
         WHERE agent_id = ?1 AND superseded_at IS NULL",
        rusqlite::params![&fx.agent, nb],
    )
    .expect("close prior history row");
    raw.execute(
        "INSERT INTO agent_pubkey_history \
            (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at) \
         VALUES (?1, 2, ?2, 'guardian_recovery', NULL, ?3, NULL)",
        rusqlite::params![&fx.agent, &k_attacker.public_base64(), nb],
    )
    .expect("insert forged history row");
    drop(raw);

    let conn = db::open(&fx.db_path).expect("open");
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_attacker.public_base64(),
        quorum: &one_att,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &forged.not_before,
        staged_key_label: None,
    };
    let err = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k_attacker.private.as_ref().expect("priv")),
    )
    .err()
    .expect("S-F1: forged ResumeAnchor head must be refused");
    assert!(
        format!("{err:#}").contains("unverified lineage"),
        "expected unverified-lineage refusal, got: {err:#}"
    );
}

/// C-F1 / S-F2 (#10160): bare anchor swap MUST be refused by production
/// `verify_sqlite_with`, `audit verify-rows`, and `arm_with_key` (both with
/// enrolled lineage AND with zero lineage), and missing `anchor_dir` on an
/// armed store must be refused by `recovery_preconditions`.
#[test]
fn cf1_sf2_bare_anchor_swap_refused_by_production_verify_and_arm_10160() {
    // Part A: lineage-enrolled store with bare anchor swap.
    let fx = RecoveryFixture::new("cf1-lin-agent");
    let k_attacker = keypair::generate(&fx.agent).expect("k_attacker");
    let future_ts = chrono::Utc::now().timestamp() + 5;
    fs::write(
        fx.anchor_dir.join(format!("{}.pub.{future_ts}", fx.agent)),
        fx.k_old.public.to_bytes(),
    )
    .expect("archive k_old");
    fs::write(
        fx.anchor_dir.join(format!("{}.pub", fx.agent)),
        k_attacker.public.to_bytes(),
    )
    .expect("swap pub");

    let conn = db::open(&fx.db_path).expect("open");
    let anchor = TrustAnchor::load_dir(&fx.anchor_dir);
    let rep = verify_sqlite_with(&conn, &anchor).expect("verify_sqlite_with");
    assert!(
        matches!(rep.outcome(), Outcome::Defective { .. }),
        "C-F1/S-F2: verify_sqlite_with must return Defective after bare anchor swap, got: {:?}",
        rep.outcome()
    );
    assert!(
        rep.defects
            .iter()
            .any(|d| d.contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP)),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP defect, got: {:?}",
        rep.defects
    );

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = {
        let mut out = CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        audit_verify_rows::run(&VerifyRowsArgs { json: true }, &fx.db_path, &mut out)
            .expect("audit verify-rows")
    };
    assert_eq!(
        code,
        2,
        "audit verify-rows must exit 2 after bare swap: {}",
        String::from_utf8_lossy(&stdout)
    );

    // Production `arm_with_key` even with K_old must refuse when anchor was swapped!
    let err_arm = arm_with_key(
        &conn,
        &fx.agent,
        fx.k_old.private.as_ref().expect("k_old priv"),
    )
    .expect_err("arm_with_key must refuse on bare-swapped anchor");
    assert!(
        format!("{err_arm:#}").contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP from arm_with_key, got: {err_arm:#}"
    );
    drop(conn);

    // Part B: zero-lineage store with bare archive+swap (exact code-reviewer R-7 probe).
    let root2 = private_dir();
    let keys2 = root2.path().join("keys");
    fs::create_dir_all(&keys2).expect("mkdir keys2");
    let db2 = root2.path().join("store2.db");
    let agent2 = "cf1-nolin-agent";
    let k0 = keypair::generate(agent2).expect("k0");
    keypair::save(&k0, &keys2).expect("save k0");
    let conn2 = db::open(&db2).expect("open db2");
    db::register_agent(&conn2, agent2, "ai:test", &[]).expect("register");
    db::bind_agent_pubkey_with_keypair(&conn2, agent2, &k0).expect("bind");
    let keys2_s = keys2.to_string_lossy().into_owned();
    // SAFETY: serialized by ENV_LOCK held in `fx._env`.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", &keys2_s);
    }
    arm_with_key(&conn2, agent2, k0.private.as_ref().expect("k0 priv")).expect("arm db2");
    let k_foreign = keypair::generate(agent2).expect("k_foreign");
    fs::write(
        keys2.join(format!("{agent2}.pub.{future_ts}")),
        k0.public.to_bytes(),
    )
    .expect("archive k0");
    fs::write(
        keys2.join(format!("{agent2}.pub")),
        k_foreign.public.to_bytes(),
    )
    .expect("swap pub");
    let rep2 = verify_sqlite_with(&conn2, &TrustAnchor::load_dir(&keys2)).expect("verify db2");
    assert!(
        matches!(rep2.outcome(), Outcome::Defective { .. }),
        "C-F1/S-F2: zero-lineage bare anchor swap must be Defective, got: {:?}",
        rep2.outcome()
    );
    assert!(
        rep2.defects
            .iter()
            .any(|d| d.contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP)),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP defect on zero-lineage swap, got: {:?}",
        rep2.defects
    );
    drop(conn2);
    drop(fx);

    // Part C: missing anchor_dir on an armed store must be refused in recovery_preconditions.
    let fx3 = RecoveryFixture::new("cf1-missing-dir");
    let k_new3 = keypair::generate("cf1-missing-new").expect("k_new3");
    let (nb3, atts3) = fx3.prepare_and_sign(&k_new3, &[0, 1]);
    let missing_dir = fx3.root.path().join("does-not-exist");
    let conn3 = db::open(&fx3.db_path).expect("open db3");
    let req3 = RecoveryRequest {
        agent_id: &fx3.agent,
        successor_pubkey_b64: &k_new3.public_base64(),
        quorum: &atts3,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb3,
        staged_key_label: None,
    };
    let err_missing = recovery_preconditions(
        &conn3,
        &missing_dir,
        &req3,
        RecoveryArm::Signing(k_new3.private.as_ref().expect("priv")),
    )
    .err()
    .expect("missing anchor_dir on armed store must be refused");
    assert!(
        format!("{err_missing:#}").contains(REFUSE_ANCHOR_UNATTESTED_KEY_SWAP),
        "expected REFUSE_ANCHOR_UNATTESTED_KEY_SWAP for missing anchor_dir, got: {err_missing:#}"
    );
}

/// C-F6: corrupt RFC3339 timestamp in `agent_pubkey_history` or `row_attestations`
/// must be refused by `recovery_preconditions` instead of silently ignored.
#[test]
fn cf6_corrupt_timestamp_in_history_refused_10112() {
    let fx = RecoveryFixture::new("cf6-ts-agent");
    let k_new = keypair::generate("cf6-ts-new").expect("k_new");
    let (nb, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

    let raw = Connection::open(&fx.db_path).expect("raw open");
    raw.execute(
        "UPDATE agent_pubkey_history SET bound_at = 'not-a-valid-rfc3339' WHERE agent_id = ?1",
        [&fx.agent],
    )
    .expect("corrupt bound_at");
    drop(raw);

    let conn = db::open(&fx.db_path).expect("open");
    let req = RecoveryRequest {
        agent_id: &fx.agent,
        successor_pubkey_b64: &k_new.public_base64(),
        quorum: &atts,
        suspected_compromise_from_seq: None,
        recovery_pubkey_b64: None,
        not_before: &nb,
        staged_key_label: None,
    };
    let err = recovery_preconditions(
        &conn,
        &fx.anchor_dir,
        &req,
        RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
    )
    .err()
    .expect("C-F6: corrupt bound_at timestamp must be refused");
    assert!(
        format!("{err:#}").contains("malformed") || format!("{err:#}").contains("timestamp"),
        "expected malformed timestamp refusal, got: {err:#}"
    );
}

/// C-F14: direct `db::append_recovery` on an armed SQLite store with
/// `AI_MEMORY_KEY_DIR` unset must refuse with its own accurate armed-store
/// refusal constant (not `REFUSE_RECOVERY_VERIFY_ONLY`).
#[test]
fn cf14_direct_append_recovery_refused_when_key_dir_unset_10112() {
    let fx = RecoveryFixture::new("cf14-agent");
    let k_new = keypair::generate("cf14-new").expect("k_new");
    let (nb, atts) = fx.prepare_and_sign(&k_new, &[0, 1]);

    // SAFETY: serialized by ENV_LOCK held in `fx._env`.
    unsafe {
        std::env::remove_var("AI_MEMORY_KEY_DIR");
    }

    let raw_conn = Connection::open(&fx.db_path).expect("raw open");
    let err = db::append_recovery(
        &raw_conn,
        &fx.agent,
        &k_new.public_base64(),
        &atts,
        None,
        None,
        &nb,
    )
    .expect_err("direct append_recovery on armed store with unset KEY_DIR must refuse");
    assert_eq!(
        format!("{err:#}"),
        "armed store: use `ai-memory identity recover` with a signing arm instead of direct `append_recovery` (#10112 R-8)",
        "C-F14: expected exact armed-store refusal"
    );
}
