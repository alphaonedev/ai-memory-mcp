// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3555: classes depend on real counts, never configuration alone.
use ai_memory::write_receipt::WriteDurability;
use serde_json::json;

#[test]
fn sqlite_replication_models_3555() -> anyhow::Result<()> {
    let root = std::env::var("CARGO_TARGET_DIR")?;
    let scratch = tempfile::tempdir_in(root)?;
    let conn = ai_memory::db::open(&scratch.path().join("models.db"))?;
    for (sync, fsync) in [("NORMAL", "per-checkpoint"), ("FULL", "per-commit")] {
        conn.pragma_update(None, "synchronous", sync)?;
        assert_replication_models(&WriteDurability::sqlite(&conn)?, fsync)?;
    }
    Ok(())
}

#[test]
fn postgres_replication_models_3555() -> anyhow::Result<()> {
    for (fsync, sync, cadence) in [
        ("on", "on", "per-commit"),
        ("on", "off", "asynchronous WAL flush"),
        ("off", "on", "never (OS write-back only)"),
    ] {
        assert_replication_models(&WriteDurability::postgres(fsync, sync)?, cadence)?;
    }
    assert!(WriteDurability::postgres("unknown", "on").is_err());
    assert!(WriteDurability::postgres("on", "unknown").is_err());
    assert!(WriteDurability::postgres("off", "unknown").is_err());
    Ok(())
}

fn assert_replication_models(local: &WriteDurability, fsync: &str) -> anyhow::Result<()> {
    let mut receipt = json!({"id": "operation3555"});
    local.attach(&mut receipt)?;
    assert_eq!(receipt["durability_class"], "local-only");
    assert_eq!(receipt["fsync"], fsync);
    for (acks, n) in [(2, 3), (3, 5)] {
        local
            .clone()
            .with_quorum(2, acks, n, false)?
            .attach(&mut receipt)?;
        assert_eq!(receipt["durability_class"], format!("quorum {acks}-of-{n}"));
        assert_eq!(receipt["quorum_acks"], acks);
        assert_eq!(receipt["quorum_n"], n);
        local
            .clone()
            .with_quorum(2, acks, n, true)?
            .attach(&mut receipt)?;
        assert_eq!(receipt["durability_class"], "replicated+backup");
        assert_eq!(receipt["fsync"], fsync);
    }
    local
        .clone()
        .with_quorum(1, 1, 3, true)?
        .attach(&mut receipt)?;
    assert_eq!(receipt["durability_class"], "local-only");
    assert_eq!(receipt["id"], "operation3555");
    assert!(local.clone().with_quorum(2, 1, 3, false).is_err());
    assert!(local.clone().with_quorum(2, 4, 3, false).is_err());
    assert!(local.clone().with_quorum(0, 1, 3, false).is_err());
    assert!(local.attach(&mut json!(null)).is_err());
    Ok(())
}
