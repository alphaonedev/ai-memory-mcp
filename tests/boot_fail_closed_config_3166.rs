// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3166 / #3167 — boot must FAIL CLOSED on a config it cannot honour, and
//! the `AI_MEMORY_NO_CONFIG` escape hatch must obey its documented "set to
//! `1`" contract.
//!
//! Pre-fix, `src/main.rs` called the non-propagating `AppConfig::load()`,
//! which swallowed a TOML syntax error, a secret-validation rejection, and
//! EVERY io error (`ErrorKind` was discarded, so `EACCES`/`EIO` were
//! indistinguishable from the documented `ENOENT`) and returned
//! `AppConfig::default()`. `effective_db` then resolved the RELATIVE
//! `ai-memory.db`, so a one-character typo in a config carrying
//! `db = "/var/lib/ai-memory/prod.db"` made the daemon open/create a fresh
//! empty database in `$PWD`, report healthy, and accept writes into that
//! orphan — corpus split-brain. `[storage].append_only`,
//! `[governance].require_operator_pubkey` and `[[permissions.rules]]`
//! reverted in the same stroke.
//!
//! Every cell here drives the REAL binary in a subprocess with its own
//! `$HOME` and its own working directory (never `std::env::set_var` in this
//! process — the `deferred_audit` / #2905 env-leak precedent), so the pins
//! cover the shipped entry point rather than a library re-implementation of
//! it.

use std::path::PathBuf;
use std::process::{Command, Output};

/// `sysexits.h` `EX_CONFIG` — mirrored here on purpose: the test asserts the
/// externally-observable contract, so it must not import the constant it is
/// pinning.
const EX_CONFIG: i32 = 78;

/// Scratch root under the repo's gitignored `.local-runs/` (project no-`/tmp`
/// HARD RULE), mirroring `tests/security_profile_prerun_2386.rs`.
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3166-boot-fail-closed");
    std::fs::create_dir_all(&root).ok();
    root
}

/// A fresh `(home, cwd)` pair. `home` receives the `config.toml`; `cwd` is
/// where a fail-OPEN boot would drop its orphan `./ai-memory.db`.
struct Sandbox {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
    /// #3002 — when `Some`, the child's `XDG_CONFIG_HOME`. Defaults to
    /// `<home>/.config`, i.e. the XDG root and the legacy root coincide.
    xdg_root: Option<PathBuf>,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
        let home = dir.path().join("home");
        let cwd = dir.path().join("cwd");
        std::fs::create_dir_all(home.join(".config").join("ai-memory")).expect("mkdir home config");
        std::fs::create_dir_all(&cwd).expect("mkdir cwd");
        Self {
            _dir: dir,
            home,
            cwd,
            xdg_root: None,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.home
            .join(".config")
            .join("ai-memory")
            .join("config.toml")
    }

    fn write_config(&self, body: &str) {
        std::fs::write(self.config_path(), body).expect("write config.toml");
    }

    /// The orphan database a fail-OPEN boot creates: `effective_db` falls
    /// back to the RELATIVE `ai-memory.db`, resolved against the process
    /// working directory.
    fn orphan_db(&self) -> PathBuf {
        self.cwd.join("ai-memory.db")
    }

    /// Run the shipped binary with this sandbox's `$HOME` / working
    /// directory. `no_config` is applied verbatim when `Some` and REMOVED
    /// when `None` (the suite is commonly run under
    /// `AI_MEMORY_NO_CONFIG=1`, which the child would otherwise inherit).
    fn run(&self, args: &[&str], no_config: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.args(args)
            .current_dir(&self.cwd)
            .env("HOME", &self.home)
            // #3002 — `config_path()` resolves through `dirs::config_dir()`,
            // which honors `XDG_CONFIG_HOME`. Pin it at the sandbox root so
            // the ambient host value cannot redirect the child away from the
            // config.toml this sandbox wrote.
            .env(
                "XDG_CONFIG_HOME",
                self.xdg_root
                    .clone()
                    .unwrap_or_else(|| self.home.join(".config")),
            )
            // `--db` carries `env = "AI_MEMORY_DB"`, which would pre-empt the
            // config-resolved path this suite is pinning.
            .env_remove("AI_MEMORY_DB");
        match no_config {
            Some(v) => cmd.env("AI_MEMORY_NO_CONFIG", v),
            None => cmd.env_remove("AI_MEMORY_NO_CONFIG"),
        };
        cmd.output().expect("spawn ai-memory")
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// #3166 — fail-closed boot
// ---------------------------------------------------------------------------

/// A TOML syntax error in a config that names a `db` must REFUSE the boot
/// with `EX_CONFIG`, and must not create the orphan `./ai-memory.db` that the
/// fail-OPEN default resolution would have opened.
#[test]
fn typo_in_config_refuses_boot_and_creates_no_orphan_db_3166() {
    let sb = Sandbox::new();
    let configured_db = sb.cwd.join("configured").join("prod.db");
    sb.write_config(&format!(
        "db = \"{}\"\ntier = \"keyword\"\nthis is not valid toml\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], None);

    assert_eq!(
        out.status.code(),
        Some(EX_CONFIG),
        "#3166: a malformed config must refuse the boot with EX_CONFIG (78); \
         stderr={}",
        stderr_of(&out)
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("UNUSABLE") && stderr.contains("boot REFUSED"),
        "expected the boot-refusal banner naming the unusable config; stderr={stderr}"
    );
    assert!(
        !sb.orphan_db().exists(),
        "#3166 PRIME DIRECTIVE: the refusal must fire before any database is \
         opened — found an orphan at {}",
        sb.orphan_db().display()
    );
    assert!(
        !configured_db.exists(),
        "the configured db must not be created either — nothing was started"
    );
}

/// An UNREADABLE config (`EACCES`) is not the documented "missing file"
/// case: it must be surfaced, not flattened into compiled defaults.
#[cfg(unix)]
#[test]
fn unreadable_config_refuses_boot_with_the_io_error_3166() {
    use std::os::unix::fs::PermissionsExt as _;

    let sb = Sandbox::new();
    sb.write_config("db = \"/var/lib/ai-memory/prod.db\"\n");
    std::fs::set_permissions(sb.config_path(), std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000");

    // A root (or CAP_DAC_OVERRIDE) test runner bypasses the mode bits
    // entirely; there is no EACCES to observe, so this cell has nothing to
    // pin. Probe rather than guess at the uid.
    if std::fs::read_to_string(sb.config_path()).is_ok() {
        eprintln!("skipping: this runner can read a mode-000 file (root?)");
        return;
    }

    let out = sb.run(&["stats", "--json"], None);

    assert_eq!(
        out.status.code(),
        Some(EX_CONFIG),
        "#3166: an EACCES on the config must refuse the boot, not fall back to \
         compiled defaults; stderr={}",
        stderr_of(&out)
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("reading config"),
        "expected the io error to be surfaced with its context; stderr={stderr}"
    );
    assert!(
        !sb.orphan_db().exists(),
        "the refusal must fire before any database is opened"
    );
}

/// The documented "missing config file -> compiled defaults" contract is
/// UNCHANGED: the boot proceeds and resolves the relative `ai-memory.db`.
#[test]
fn missing_config_still_boots_on_compiled_defaults_3166() {
    let sb = Sandbox::new();
    assert!(!sb.config_path().exists());

    let out = sb.run(&["stats", "--json"], None);

    assert!(
        out.status.success(),
        "#3166: a MISSING config must remain the documented defaults case; \
         exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        sb.orphan_db().exists(),
        "compiled-default `db` resolution should have opened ./ai-memory.db"
    );
}

/// A VALID config is honoured end-to-end: the configured `db` is opened and
/// the relative fallback is never touched. The control for the cells above.
#[test]
fn valid_config_boots_and_opens_the_configured_db_3166() {
    let sb = Sandbox::new();
    let configured_db = sb.cwd.join("configured.db");
    sb.write_config(&format!(
        "db = \"{}\"\ntier = \"keyword\"\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], None);

    assert!(
        out.status.success(),
        "a valid config must boot; exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        configured_db.exists(),
        "the CONFIGURED db must be the one opened"
    );
    assert!(
        !sb.orphan_db().exists(),
        "the relative fallback must never be opened when `db` is configured"
    );
}

/// `--version` is argv-only and must stay usable on a broken config: #3166
/// parses argv BEFORE resolving the config, so clap's own exit happens first.
#[test]
fn version_still_works_on_a_broken_config_3166() {
    let sb = Sandbox::new();
    sb.write_config("this is not valid toml\n");

    let out = sb.run(&["--version"], None);

    assert!(
        out.status.success(),
        "`--version` must not be taken down by a broken config; exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
}

/// `doctor` is one of the few subcommands allowed to keep running on compiled
/// defaults — and it must REPORT the broken config rather than hide it.
#[test]
fn doctor_reports_the_broken_config_instead_of_refusing_3166() {
    let sb = Sandbox::new();
    sb.write_config("db = \"/var/lib/ai-memory/prod.db\"\nnot valid toml\n");

    let out = sb.run(&["doctor", "--json"], None);

    assert_ne!(
        out.status.code(),
        Some(EX_CONFIG),
        "doctor must not be refused by the very fault it exists to diagnose; \
         stderr={}",
        stderr_of(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Configuration") && stdout.contains("UNUSABLE"),
        "doctor must carry a Configuration section naming the broken config; \
         stdout={stdout} stderr={}",
        stderr_of(&out)
    );
}

/// Structural pin: `fn main()` resolves the config through the PROPAGATING
/// `load_for_boot`, never the lenient `AppConfig::load()`, and does so AFTER
/// `Cli::parse()` so `--version` / `--help` cannot be taken down by a
/// malformed config.
#[test]
fn main_uses_the_propagating_loader_after_argv_parse_3166() {
    const MAIN_SRC: &str = include_str!("../src/main.rs");
    let parse = MAIN_SRC
        .find("let cli = Cli::parse();")
        .expect("fn main() parses argv");
    let load = MAIN_SRC
        .find("config::AppConfig::load_for_boot()")
        .expect("#3166: fn main() must use the propagating AppConfig::load_for_boot");
    assert!(
        parse < load,
        "#3166: argv must be parsed BEFORE the config is resolved (parse at \
         byte {parse}, load at byte {load})"
    );
    assert!(
        !MAIN_SRC.contains("config::AppConfig::load()"),
        "#3166: fn main() must never use the lenient, fail-OPEN AppConfig::load()"
    );
    assert!(
        MAIN_SRC.contains("config::EX_CONFIG"),
        "#3166: the boot refusal must use the single-sourced EX_CONFIG constant"
    );
}

// ---------------------------------------------------------------------------
// #3167 — AI_MEMORY_NO_CONFIG grammar
// ---------------------------------------------------------------------------

/// `AI_MEMORY_NO_CONFIG=` (an empty placeholder export in a compose / unit
/// file) is NOT the documented `1`: the config must still be loaded, and the
/// operator must be told once.
#[test]
fn empty_no_config_still_loads_the_config_3167() {
    let sb = Sandbox::new();
    let configured_db = sb.cwd.join("configured.db");
    sb.write_config(&format!(
        "db = \"{}\"\ntier = \"keyword\"\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], Some(""));

    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        configured_db.exists(),
        "#3167: AI_MEMORY_NO_CONFIG= (empty) must NOT disable the config file"
    );
    assert!(
        !sb.orphan_db().exists(),
        "#3167: the configured `db` must win, not the relative fallback"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("AI_MEMORY_NO_CONFIG is set to")
            && stderr.contains("the config file IS being loaded"),
        "expected the present-but-not-truthy WARN; stderr={stderr}"
    );
}

/// `AI_MEMORY_NO_CONFIG=0` is an explicit opt-OUT of the skip, so the config
/// must load.
#[test]
fn zero_no_config_still_loads_the_config_3167() {
    let sb = Sandbox::new();
    let configured_db = sb.cwd.join("configured.db");
    sb.write_config(&format!(
        "db = \"{}\"\ntier = \"keyword\"\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], Some("0"));

    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        configured_db.exists(),
        "#3167: AI_MEMORY_NO_CONFIG=0 must NOT disable the config file"
    );
}

/// `AI_MEMORY_NO_CONFIG=1` — the documented value, and the one every CI
/// runner sets — is BYTE-IDENTICAL to the pre-#3167 behaviour: the config is
/// skipped entirely, even a malformed one.
#[test]
fn one_no_config_skips_the_config_entirely_3167() {
    let sb = Sandbox::new();
    let configured_db = sb.cwd.join("configured.db");
    sb.write_config(&format!(
        "db = \"{}\"\nthis is not valid toml\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], Some("1"));

    assert!(
        out.status.success(),
        "#3167: AI_MEMORY_NO_CONFIG=1 must skip the config (and therefore also \
         skip the #3166 boot refusal); exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        !configured_db.exists(),
        "the skipped config's `db` must not be honoured"
    );
    assert!(
        sb.orphan_db().exists(),
        "with the config skipped, `db` resolves to the compiled relative default"
    );
}

/// The other truthy tokens in the substrate-wide grammar are honoured too.
#[test]
fn truthy_tokens_skip_the_config_3167() {
    for token in ["true", "YES", " on "] {
        let sb = Sandbox::new();
        sb.write_config("this is not valid toml\n");
        let out = sb.run(&["stats", "--json"], Some(token));
        assert!(
            out.status.success(),
            "#3167: `{token}` is a truthy token and must skip the config; \
             exit={:?} stderr={}",
            out.status.code(),
            stderr_of(&out)
        );
    }
}

/// Structural pin: all three production presence checks route through the one
/// shared `skip_config()` helper.
#[test]
fn all_sites_share_one_skip_config_helper_3167() {
    for (path, src) in [
        ("src/config.rs", include_str!("../src/config.rs") as &str),
        ("src/mcp/mod.rs", include_str!("../src/mcp/mod.rs")),
    ] {
        assert!(
            !src.contains("var(\"AI_MEMORY_NO_CONFIG\").is_ok()"),
            "#3167: {path} still uses the bare presence check instead of skip_config()"
        );
    }
    assert!(
        include_str!("../src/config.rs").contains("pub fn skip_config() -> bool"),
        "#3167: config::skip_config must be the one shared resolver"
    );
}

// ---------------------------------------------------------------------------
// #3002 — the XDG move must not orphan an existing config
// ---------------------------------------------------------------------------

/// #3002 + #3166 (migration safety) — #3002 moved `config.toml` from the
/// hardcoded `$HOME/.config` to `dirs::config_dir()`. On a host that sets
/// `XDG_CONFIG_HOME` elsewhere, the XDG path does not exist, and a MISSING
/// config is the documented "compiled defaults" arm — so the #3166 boot
/// refusal does NOT fire and the daemon would silently open the relative
/// `./ai-memory.db` instead of the configured `db`. That is the corpus
/// split-brain this whole PR exists to prevent, arriving through the front
/// door. `config_path()` therefore keeps honouring the legacy file.
#[test]
fn legacy_home_config_survives_the_xdg_move_3002() {
    let mut sb = Sandbox::new();
    // An XDG root that exists but carries NO ai-memory config.
    let xdg = sb.home.parent().expect("sandbox root").join("xdg");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg root");
    sb.xdg_root = Some(xdg);

    // The operator's real config, still at the pre-#3002 legacy location.
    let configured_db = sb.cwd.join("legacy-configured.db");
    sb.write_config(&format!(
        "db = \"{}\"\ntier = \"keyword\"\n",
        configured_db.display()
    ));

    let out = sb.run(&["stats", "--json"], None);

    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
    assert!(
        configured_db.exists(),
        "#3002: the legacy `$HOME/.config` config must still be honoured after \
         the XDG move — otherwise `db` silently reverts to the relative default"
    );
    assert!(
        !sb.orphan_db().exists(),
        "#3166 PRIME DIRECTIVE: no orphan ./ai-memory.db may be created"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("LEGACY config path"),
        "the operator must be told once that the legacy root is in use; stderr={stderr}"
    );
}
