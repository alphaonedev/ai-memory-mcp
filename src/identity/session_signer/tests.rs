// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Lib tests of the MCP session signer (#9926, #10012). They live in their
//! own file so the #8950 raw-write census counts only production sites.

use super::*;

/// Per-session key isolation: the signer covers exactly its own agent.
/// No stdio funnel reaches `covers` with a foreign agent (the identity
/// layer refuses the mismatch first), so this guard is pinned here.
#[test]
fn signer_covers_only_its_session_agent_9926() {
    let signer = SessionSigner {
        agent_id: "agent-a-9926".to_string(),
        keypair: crate::identity::keypair::generate("agent-a-9926").expect("keypair"),
    };
    assert!(signer.covers("agent-a-9926"));
    for other in [
        "agent-b-9926",
        "agent-a-9926x",
        "agent-a-992",
        "",
        "AGENT-A-9926",
    ] {
        assert!(!signer.covers(other), "signer must not cover {other:?}");
    }
}

#[test]
fn open_refusal_maps_each_kind_9926() {
    let rows: [(std::io::Error, &str); 3] = [
        (
            std::io::Error::from(std::io::ErrorKind::NotFound),
            REFUSE_MISSING,
        ),
        (
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            REFUSE_OPEN,
        ),
        (
            std::io::Error::from_raw_os_error(libc::ELOOP),
            REFUSE_SYMLINK,
        ),
    ];
    for (error, expected) in rows {
        assert_eq!(open_refusal(&error), expected);
    }
}

#[test]
fn read_session_key_refuses_wrong_lengths_9926() {
    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR")
            .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from),
    )
    .expect("tempdir");
    for len in [0usize, 1, 31, 33, 64, 4096] {
        let path = dir.path().join(format!("k{len}"));
        std::fs::write(&path, vec![7u8; len]).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            read_session_key(&path).err(),
            Some(REFUSE_LENGTH),
            "len {len}"
        );
    }
    let ok = dir.path().join("k32");
    std::fs::write(&ok, [7u8; 32]).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    assert!(read_session_key(&ok).is_ok());
    assert_eq!(read_session_key(dir.path()).err(), Some(REFUSE_NOT_REGULAR));
}

/// #8950 census guard: the one `OpenOptions` site of this file is a
/// read-only, no-follow open. An owner-read-only (0400) key opens, so the
/// open asks for no write access; a symlink at the key name is refused with
/// the exact reason; neither read changes the key file.
#[cfg(unix)]
#[test]
fn key_file_open_is_read_only_and_no_follow_8950() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR")
            .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from),
    )
    .expect("tempdir");
    let key = dir.path().join("k32");
    std::fs::write(&key, [9u8; 32]).expect("write");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).expect("chmod");
    assert!(read_session_key(&key).is_ok(), "a 0400 key opens read-only");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&key, &link).expect("plant symlink");
    assert_eq!(read_session_key(&link).err(), Some(REFUSE_SYMLINK));
    assert_eq!(std::fs::read(&key).expect("read key"), [9u8; 32]);
    let mode = std::fs::metadata(&key).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o400);
}

const SIDE_SESSION_AGENT_10012: &str = "agent-side-session-10012";
const SIDE_OTHER_AGENT_10012: &str = "agent-side-other-10012";

/// The decision a side-row signer test row expects (#10012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SideExpect {
    NoSession,
    SessionKey,
    NotCoveredPermissive,
    Refused,
}

/// #10012: the full truth table of the side-row signer decision over
/// (signer installed?, side row's agent, strict mode). The expected column
/// is written by hand; the refusal is the exact text.
#[test]
fn side_row_decision_truth_table_10012() {
    const ROWS: [(bool, &str, bool, SideExpect); 8] = [
        (
            false,
            SIDE_SESSION_AGENT_10012,
            false,
            SideExpect::NoSession,
        ),
        (false, SIDE_SESSION_AGENT_10012, true, SideExpect::NoSession),
        (false, SIDE_OTHER_AGENT_10012, false, SideExpect::NoSession),
        (false, SIDE_OTHER_AGENT_10012, true, SideExpect::NoSession),
        (
            true,
            SIDE_SESSION_AGENT_10012,
            false,
            SideExpect::SessionKey,
        ),
        (true, SIDE_SESSION_AGENT_10012, true, SideExpect::SessionKey),
        (
            true,
            SIDE_OTHER_AGENT_10012,
            false,
            SideExpect::NotCoveredPermissive,
        ),
        (true, SIDE_OTHER_AGENT_10012, true, SideExpect::Refused),
    ];
    let kp = crate::identity::keypair::generate(SIDE_SESSION_AGENT_10012).expect("keypair");
    let signer = SessionSigner {
        agent_id: SIDE_SESSION_AGENT_10012.to_string(),
        keypair: kp.clone(),
    };
    let session_public = encode_public_base64(&kp.public);
    for (installed, agent, strict, expected) in ROWS {
        let what = format!("installed={installed} agent={agent} strict={strict}");
        let got = side_row_decision(installed.then_some(&signer), agent, strict);
        let observed = match got {
            Ok(SideRowSigner::NoSession) => SideExpect::NoSession,
            Ok(SideRowSigner::Session(used)) => {
                assert_eq!(
                    encode_public_base64(&used.public),
                    session_public,
                    "{what}: signs with the session key"
                );
                SideExpect::SessionKey
            }
            Ok(SideRowSigner::NotCoveredPermissive) => SideExpect::NotCoveredPermissive,
            Err(text) => {
                assert_eq!(text, SIDE_ROW_STRICT_REFUSAL, "{what}: exact refusal");
                SideExpect::Refused
            }
        };
        assert_eq!(observed, expected, "{what}");
    }
}

const OPEN_ARM_AGENT_10012: &str = "agent-open-arm-10012";

/// #10012: a connection opened AFTER the signer is installed (the
/// governance and backfill connections of the stdio server, any later
/// `db::open`) is armed by `storage::connection::open` itself, so a
/// session-agent row written through it is stored sealed. Runs alone in a
/// child process because the signer is process-wide.
#[test]
fn every_later_db_open_seals_session_rows_10012() {
    use base64::Engine as _;
    if crate::test_support::run_env_isolated_child_or_spawn_home(
        "identity::session_signer::tests::every_later_db_open_seals_session_rows_10012",
    ) {
        return;
    }
    // Security LOW-1: the child never sees the operator's home.
    let home = std::path::PathBuf::from(std::env::var_os("HOME").expect("child HOME"));
    let config = std::path::PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").expect("child XDG"));
    assert!(
        home.starts_with(std::env::temp_dir()) && config == home.join(".config"),
        "child HOME {home:?} / XDG_CONFIG_HOME {config:?} are not the isolated per-run dir"
    );
    crate::identity::attest::permissive_attestation_for_lib_tests();
    let kp = crate::identity::keypair::generate(OPEN_ARM_AGENT_10012).expect("keypair");
    // Registered and bound before the signer exists, as the stdio boot
    // requires (REFUSE_UNBOUND); the write goes through a LATER open.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("open-arm-10012.db");
    {
        let boot = crate::db::open(&path).expect("boot open");
        crate::db::register_agent(&boot, OPEN_ARM_AGENT_10012, "nhi", &[]).expect("register");
        crate::db::bind_agent_pubkey_with_keypair(&boot, OPEN_ARM_AGENT_10012, &kp).expect("bind");
    }
    assert_eq!(
        install_for_lib_test(OPEN_ARM_AGENT_10012, kp.clone()),
        OPEN_ARM_AGENT_10012
    );
    let conn = crate::db::open(&path).expect("open after install");
    let now = crate::identity::attest::now_attestable_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "open-arm-10012".to_string(),
        title: "open arm 10012".to_string(),
        content: "written through a later connection".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ crate::META_KEY_AGENT_ID: OPEN_ARM_AGENT_10012 }),
        ..Memory::default()
    };
    let id = crate::db::insert(&conn, &mem).expect("insert");
    let row = crate::db::get(&conn, &id).expect("read").expect("row");
    assert_eq!(
        row.metadata[crate::models::field_names::ATTEST_LEVEL].as_str(),
        Some("agent_attested"),
        "attest_level of a row written through a later db::open"
    );
    let stored = row.metadata[crate::models::field_names::WRITE_SIGNATURE]
        .as_str()
        .expect("write_signature");
    let stored = base64::engine::general_purpose::STANDARD
        .decode(stored)
        .expect("base64 signature");
    let expected = crate::identity::attest::sign_memory_write(&kp, &row, OPEN_ARM_AGENT_10012)
        .expect("re-sign stored row");
    assert_eq!(stored, expected, "signature over the stored row");
}
