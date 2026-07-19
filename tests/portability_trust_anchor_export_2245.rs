// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2245 — portability-v2 exports custody-file role anchors, not only env keys.

mod common;

use std::collections::BTreeMap;

use ai_memory::governance::audit::{
    JUDGE_KEY_DIR_ENV, JUDGE_KEY_LABEL, JUDGE_PUBKEY_ENV, RECORDER_KEY_DIR_ENV, RECORDER_KEY_LABEL,
    RECORDER_PUBKEY_ENV, STOPPER_KEY_DIR_ENV, STOPPER_KEY_LABEL, STOPPER_PUBKEY_ENV,
};
use ai_memory::identity::keypair;
use ai_memory::portability::emit::build_full_envelope;
use common::MultiEnvVarGuard;

#[test]
fn full_export_includes_custody_file_role_pubkeys_2245() {
    let scratch = std::env::current_dir().expect("cwd").join(".local-runs");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let root = tempfile::Builder::new()
        .prefix("trust-anchor-2245-")
        .tempdir_in(&scratch)
        .expect("scratch dir");

    let roles = [
        ("recorder", RECORDER_KEY_LABEL, RECORDER_KEY_DIR_ENV),
        ("judge", JUDGE_KEY_LABEL, JUDGE_KEY_DIR_ENV),
        ("stopper", STOPPER_KEY_LABEL, STOPPER_KEY_DIR_ENV),
    ];
    let mut expected = BTreeMap::new();
    let mut role_dirs = Vec::new();
    for (role, label, _) in roles {
        let dir = root.path().join(role);
        let keypair = keypair::generate(label).expect("generate role key");
        keypair::save_public_only(&keypair, &dir).expect("save role public key");
        expected.insert(role, keypair.public_base64());
        role_dirs.push(dir);
    }

    let recorder_dir = role_dirs[0].to_string_lossy().into_owned();
    let judge_dir = role_dirs[1].to_string_lossy().into_owned();
    let stopper_dir = role_dirs[2].to_string_lossy().into_owned();
    let _env = MultiEnvVarGuard::apply(&[
        (RECORDER_PUBKEY_ENV, None),
        (JUDGE_PUBKEY_ENV, None),
        (STOPPER_PUBKEY_ENV, None),
        (RECORDER_KEY_DIR_ENV, Some(recorder_dir.as_str())),
        (JUDGE_KEY_DIR_ENV, Some(judge_dir.as_str())),
        (STOPPER_KEY_DIR_ENV, Some(stopper_dir.as_str())),
    ]);

    let db_path = root.path().join("export.db");
    let conn = ai_memory::db::open(&db_path).expect("open database");
    let envelope = build_full_envelope(&conn, "test", "2026-07-19T00:00:00Z").expect("export");
    let exported: BTreeMap<&str, &str> = envelope
        .trust_anchors
        .iter()
        .map(|anchor| (anchor.role.as_str(), anchor.pubkey_b64.as_str()))
        .collect();

    for (role, want) in expected {
        assert_eq!(
            exported.get(role).copied(),
            Some(want.as_str()),
            "custody-only {role} anchor must be exported"
        );
    }
}
