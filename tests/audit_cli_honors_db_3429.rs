// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3429 — every `ai-memory audit` verb that touches a store must
//! honour the operator-resolved `--db` / `AI_MEMORY_DB`, for READS and for
//! WRITES.
//!
//! `run_show` / `run_restore_attest` / `run_re_anchor` / `run_bootstrap_node`
//! (`src/cli/audit.rs`) each recomputed
//! `app_config.effective_db(Path::new(DEFAULT_DB))` at their own `db::open`
//! call site. `effective_db` only honours a `cli_db` that DIFFERS from the
//! `"ai-memory.db"` literal, so handing it that same literal discarded a
//! non-default `--db` entirely: with a `config.toml` that sets `db = …` the
//! verbs read AND wrote the CONFIG store, and with no config at all they
//! materialised a stray `./ai-memory.db` in the process CWD. This is the same
//! misfiling class #1991 closed in `build_embedder` / `build_llm_client`; the
//! #3429 control threads the ONE `db_path` the top-level parser already
//! resolved (`daemon_runtime::run`) into `cli::audit::run`, and the
//! store-touching verbs now take a `&Path` instead of an `&AppConfig` so they
//! structurally cannot re-resolve a store of their own.
//!
//! Each test runs the SHIPPED binary with a `config.toml` naming a DIFFERENT
//! (`decoy`) store — the pre-fix winner — and a process CWD distinct from both
//! stores, which is where the no-config pre-fix variant dropped its orphan
//! `./ai-memory.db`. Each then asserts the ALLOWED path (the resolved `--db`
//! is the store that was opened / read / written) together with the DENIED
//! path (the decoy store is byte-identical afterwards and no orphan CWD store
//! exists).
//!
//! sqlite-only by construction: every one of these verbs is a local-sqlite
//! ceremony (`bootstrap-node` FAIL-CLOSES on a postgres store — its pg
//! spine-write twin is deferred, #2217-class — and `re-anchor`'s pg twin is
//! #2217 itself), so there is no postgres path to pin here.

#![allow(clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const AGENT: &str = "audit-db-3429";

/// Project HARD RULE: scratch lives under `.local-runs/`, never `/tmp`.
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3429-audit-db");
    std::fs::create_dir_all(&root).ok();
    root
}

/// A node whose `config.toml` names the DECOY store, with a CWD that is
/// neither store's directory and a separate operator-chosen `--db`.
struct Sandbox {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
    /// The store `--db` names (the one the operator asked for).
    resolved_db: PathBuf,
    /// The store `config.toml` names (the pre-fix winner — must stay untouched).
    decoy_db: PathBuf,
    key_dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("{label}-"))
            .tempdir_in(scratch_root())
            .expect("tempdir under .local-runs");
        let home = dir.path().join("home");
        let cwd = dir.path().join("cwd");
        let stores = dir.path().join("stores");
        let key_dir = dir.path().join("keys");
        std::fs::create_dir_all(home.join(".config").join("ai-memory")).expect("mkdir home config");
        for d in [&cwd, &stores, &key_dir] {
            std::fs::create_dir_all(d).expect("mkdir sandbox dir");
        }
        // #3198 — the key dir must not be group/world-writable or the
        // keypair store refuses to use it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod 0700 key dir");
        }
        let sb = Self {
            _dir: dir,
            home,
            cwd,
            resolved_db: stores.join("operator-chosen.db"),
            decoy_db: stores.join("from-config.db"),
            key_dir,
        };
        // The deployment's config.toml sets `db =` — the #3429 repro shape.
        std::fs::write(
            sb.home
                .join(".config")
                .join("ai-memory")
                .join("config.toml"),
            format!("db = \"{}\"\ntier = \"keyword\"\n", sb.decoy_db.display()),
        )
        .expect("write config.toml");
        sb
    }

    /// The orphan store a pre-fix run creates when no config names one:
    /// `effective_db` falls back to the RELATIVE `ai-memory.db`, resolved
    /// against the process working directory.
    fn orphan_db(&self) -> PathBuf {
        self.cwd.join("ai-memory.db")
    }

    /// `ai-memory --db <resolved_db> <args…>` under this sandbox's HOME / CWD,
    /// with the config file DELIBERATELY live (`AI_MEMORY_NO_CONFIG` removed)
    /// and `AI_MEMORY_DB` cleared so `--db` is the only store channel.
    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.current_dir(&self.cwd)
            .arg("--db")
            .arg(&self.resolved_db)
            .args(args)
            .env("HOME", &self.home)
            // `config_path()` resolves through `dirs::config_dir()`, which
            // honours XDG_CONFIG_HOME — pin it so the ambient host value
            // cannot redirect the child away from the sandbox config.toml.
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("AI_MEMORY_KEY_DIR", &self.key_dir)
            .env_remove("AI_MEMORY_NO_CONFIG")
            .env_remove("AI_MEMORY_DB")
            .env_remove("AI_MEMORY_STORE_URL")
            .env_remove("AI_MEMORY_STORE_URL_FILE");
        cmd.output().expect("spawn ai-memory")
    }
}

fn bytes_of(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn signed_event_count(p: &Path) -> i64 {
    let conn = ai_memory::db::open(p).expect("open store for assertion");
    conn.query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
        .expect("count signed_events")
}

/// The DENIED path, asserted identically for every verb: the config-named
/// store is byte-for-byte what it was, and no orphan `./ai-memory.db` was
/// materialised in the process CWD.
fn assert_decoy_untouched(sb: &Sandbox, before: &[u8], verb: &str) {
    assert_eq!(
        bytes_of(&sb.decoy_db),
        before,
        "#3429: `audit {verb}` must not touch the config-resolved store ({})",
        sb.decoy_db.display()
    );
    assert!(
        !sb.orphan_db().exists(),
        "#3429: `audit {verb}` must not misfile an orphan store into CWD ({})",
        sb.orphan_db().display()
    );
}

/// Seed a store with one capability-expansion row so `audit show` renders a
/// distinguishable principal from whichever store it actually read.
fn seed_expansion(db: &Path, principal: &str) {
    let conn = ai_memory::db::open(db).expect("open + migrate");
    ai_memory::db::record_capability_expansion(&conn, Some(principal), "graph", true, None);
}

// ---------------------------------------------------------------------------
// READ path — `audit show`
// ---------------------------------------------------------------------------

/// The #3429 headline repro: `--db <scratch> audit show` returned rows from
/// the config store. ALLOWED: the resolved store's row is rendered. DENIED:
/// the config store's row never appears and its file is untouched.
#[test]
fn audit_show_reads_the_resolved_db_not_the_config_store_3429() {
    let sb = Sandbox::new("show");
    seed_expansion(&sb.resolved_db, "resolved-principal");
    seed_expansion(&sb.decoy_db, "decoy-principal");
    let decoy_before = bytes_of(&sb.decoy_db);

    let out = sb.run(&["audit", "show", "--limit", "3", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "audit show must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("audit show --json must emit JSON ({e}): {stdout}"));
    let rows = v.as_array().expect("array");
    assert_eq!(rows.len(), 1, "exactly the resolved store's row: {stdout}");
    assert_eq!(
        rows[0]["agent_id"], "resolved-principal",
        "#3429: `audit show` must READ the resolved --db: {stdout}"
    );
    assert_decoy_untouched(&sb, &decoy_before, "show");
}

// ---------------------------------------------------------------------------
// WRITE path — `audit bootstrap-node`
// ---------------------------------------------------------------------------

/// The #3429 write repro: `--db <scratch> audit bootstrap-node` printed
/// `db: <config path>` and landed the identity-lineage genesis + its signed
/// event in the CONFIG store. ALLOWED: both land in the resolved store.
/// DENIED: the config store gains nothing and stays byte-identical.
#[test]
fn audit_bootstrap_node_writes_the_resolved_db_not_the_config_store_3429() {
    let sb = Sandbox::new("bootstrap");

    // Fixture: the resolved store is a store-only-migrated node (registry
    // populated, audit spine EMPTY), and the agent + recovery keys exist.
    {
        let conn = ai_memory::db::open(&sb.resolved_db).expect("open + migrate resolved");
        ai_memory::db::register_agent(&conn, AGENT, "ai:test", &[]).expect("register agent");
    }
    let kp = ai_memory::identity::keypair::generate(AGENT).expect("gen agent key");
    ai_memory::identity::keypair::save(&kp, &sb.key_dir).expect("save agent key");
    let recovery = ai_memory::identity::keypair::generate("audit-db-3429-recovery")
        .expect("gen recovery key")
        .public_base64();

    // The decoy store is a real migrated store too, so "unchanged" is a
    // meaningful assertion rather than "was never created".
    {
        let _ = ai_memory::db::open(&sb.decoy_db).expect("open + migrate decoy");
    }
    let decoy_before = bytes_of(&sb.decoy_db);
    assert_eq!(
        signed_event_count(&sb.resolved_db),
        0,
        "empty spine fixture"
    );

    // `--recovery-pubkey=<value>`, never the two-token form: `recovery` is
    // freshly generated URL-safe base64, so roughly one key in 64 starts with
    // `-` and clap parsed it as a flag ("unexpected argument '-3' found") —
    // a ~1/64 flake in this test. The `=` form binds the value to the option
    // whatever its first byte is. (The CLI arg also carries
    // `allow_hyphen_values` now, so the positional form works for operators;
    // this keeps the test independent of that.)
    let recovery_arg = format!("--recovery-pubkey={recovery}");
    let out = sb.run(&[
        "audit",
        "bootstrap-node",
        "--agent-id",
        AGENT,
        "--key-dir",
        sb.key_dir.to_str().expect("utf8 key dir"),
        &recovery_arg,
        "--json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("bootstrap-node --json must emit JSON ({e}): {stdout} {stderr}")
    });
    // The verdict itself (certified-ready vs still-dirty) is #3016/#3067's
    // subject; #3429 pins WHICH store the ceremony named and wrote.
    assert_eq!(
        v["db"].as_str(),
        sb.resolved_db.to_str(),
        "#3429: bootstrap-node must name the resolved --db: {stdout}"
    );
    assert_eq!(
        v["lineage_genesis"], "enrolled",
        "the ceremony must have minted the genesis in the resolved store: {stdout}"
    );
    assert!(
        signed_event_count(&sb.resolved_db) > 0,
        "#3429: the signed bring-up event must land in the resolved --db"
    );
    assert!(
        ai_memory::db::lineage_head(
            &ai_memory::db::open(&sb.resolved_db).expect("open resolved"),
            AGENT,
        )
        .expect("read lineage head")
        .is_some(),
        "#3429: the identity-lineage genesis must land in the resolved --db"
    );
    assert_decoy_untouched(&sb, &decoy_before, "bootstrap-node");
}

// ---------------------------------------------------------------------------
// OPEN path — `audit re-anchor` / `audit restore-attest`
// ---------------------------------------------------------------------------

/// `re-anchor` and `restore-attest` both `db::open` before any ceremony
/// decision, so the store they OPEN is the discriminator: post-fix the
/// resolved `--db` is created/migrated (ALLOWED) and the config store is
/// untouched (DENIED). Pre-fix it was exactly inverted — the resolved path
/// was never opened at all.
#[test]
fn audit_re_anchor_and_restore_attest_open_the_resolved_db_3429() {
    for verb in ["re-anchor", "restore-attest"] {
        let sb = Sandbox::new(verb);
        {
            let _ = ai_memory::db::open(&sb.decoy_db).expect("open + migrate decoy");
        }
        let decoy_before = bytes_of(&sb.decoy_db);
        assert!(
            !sb.resolved_db.exists(),
            "fixture: the resolved store must not exist yet"
        );

        // Neither verb can complete its ceremony on a bare node (nothing
        // enrolled / no anchor to attest against); both nonetheless open the
        // store FIRST, which is the store-selection behaviour under test.
        let out = sb.run(&["audit", verb]);
        assert!(
            sb.resolved_db.exists(),
            "#3429: `audit {verb}` must open the RESOLVED --db ({}); stderr={}",
            sb.resolved_db.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_decoy_untouched(&sb, &decoy_before, verb);
    }
}
