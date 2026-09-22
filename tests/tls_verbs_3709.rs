// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3709 item 2 — `ai-memory tls init | import | status` through the REAL
//! binary (env supplied ONLY to the child, `env_clear`).
//!
//! FAILS ON THE PARENT (a5628e4c4): the binary has no `tls` command, so every
//! cell here stops at clap's `unrecognized subcommand 'tls'` (exit 2) — that
//! is the RED leg, captured verbatim in the report. On the fix each cell
//! pins one population on one sink:
//!
//! - the key directory (`<key_dir>/tls/`): `import` of a valid pair WRITES
//!   the pair (presence); `import` of a mismatched key, an expired leaf or a
//!   leaf that does not cover `--host` REFUSES naming the property and writes
//!   NOTHING (absence + control); `init` on a fleet shape REFUSES naming
//!   `tls import` and writes nothing, `init` on the singleton shape mints;
//! - stdout of `status`: the verdict names the declared shape and says
//!   "encrypted as required" (serves) or "REFUSES" with the fix, never both.
//!
//! Fixtures are minted with `rcgen` from a CA that is NOT the local CA, so
//! the artefact itself (its issuer) marks the material as operator-supplied.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const TLS_SUBDIR: &str = "tls";
const SERVER_CERT_FILE: &str = "server.pem";
const SERVER_KEY_FILE: &str = "server.key";
const LOCAL_CA_KEY_FILE: &str = "local-ca.key";
const TEAM_CONFIG: &str = "[deployment]\nshape = \"team\"\n";

/// The child's key directory: 0700 through the shared sandbox helper.
fn key_dir(root: &Path) -> PathBuf {
    let keys = root.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    keys
}

fn tls_dir(root: &Path) -> PathBuf {
    key_dir(root).join(TLS_SUBDIR)
}

fn tls_listing(root: &Path) -> Vec<String> {
    let dir = tls_dir(root);
    if !dir.exists() {
        return Vec::new();
    }
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A child with an optional `config.toml` (the way a shape is DECLARED);
/// `None` sets `AI_MEMORY_NO_CONFIG=1` (declared shape = singleton).
fn command_with_config(root: &Path, config_body: Option<&str>) -> Command {
    let keys = key_dir(root);
    let xdg = root.join("home/.config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("RUST_LOG", "error");
    match config_body {
        Some(body) => {
            let dir = xdg.join("ai-memory");
            std::fs::create_dir_all(&dir).expect("mkdir config dir");
            std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
        }
        None => {
            cmd.env("AI_MEMORY_NO_CONFIG", "1");
        }
    }
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn ai-memory")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// An operator PKI: a CA that is NOT `ai-memory local CA`, and leaves it
/// issues. Files are written under `dir`.
struct OperatorPki {
    ca_pem: String,
    ca_key_pem: String,
}

impl OperatorPki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example Corp Issuing CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_pem = params.self_signed(&key).unwrap().pem();
        Self {
            ca_pem,
            ca_key_pem: key.serialize_pem(),
        }
    }

    /// Write a leaf for `sans` with the given `days` of validity (negative =
    /// already expired) and return `(cert_path, key_path)`.
    fn leaf(&self, dir: &Path, name: &str, sans: &[&str], days: i64) -> (PathBuf, PathBuf) {
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            &self.ca_pem,
            rcgen::KeyPair::from_pem(&self.ca_key_pem).unwrap(),
        )
        .unwrap();
        let mut params = rcgen::CertificateParams::new(
            sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "memory.example.test");
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(30);
        params.not_after = now + time::Duration::days(days);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        let cert_path = dir.join(format!("{name}.pem"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    fn ca_file(&self, dir: &Path) -> PathBuf {
        let p = dir.join("example-ca.pem");
        std::fs::write(&p, &self.ca_pem).unwrap();
        p
    }
}

/// The verb exists and answers (the RED cell on the parent: clap exit 2,
/// `unrecognized subcommand 'tls'`).
#[test]
fn tls_status_is_a_real_verb_3709() {
    let root = tempfile::tempdir().unwrap();
    let out = run(command_with_config(root.path(), None).args(["tls", "status"]));
    let t = text(&out);
    assert!(out.status.success(), "exit {:?}: {t}", out.status.code());
    assert!(!t.contains("unrecognized subcommand"), "{t}");
    assert!(t.contains("source:      absent"), "{t}");
    assert!(t.contains("shape:       singleton"), "{t}");
    assert!(t.contains("mints a local CA"), "{t}");
    assert!(!t.contains("REFUSES"), "{t}");
}

/// `import`: a valid operator pair installs (presence); mismatched key,
/// expired leaf and uncovered host each REFUSE naming the property and
/// write nothing (absence + control); `status` then names the operator
/// issuer and the team-shape verdict "encrypted as required".
#[test]
fn tls_import_two_populations_on_the_key_dir_3709() {
    let root = tempfile::tempdir().unwrap();
    let fixtures = root.path().join("fixtures");
    std::fs::create_dir_all(&fixtures).unwrap();
    let pki = OperatorPki::new();
    let (cert, key) = pki.leaf(&fixtures, "good", &["memory.example.test"], 200);
    let (_expired_cert, expired_key) = pki.leaf(&fixtures, "expired", &["memory.example.test"], -3);
    let (_other_cert, other_key) = pki.leaf(&fixtures, "other", &["memory.example.test"], 200);
    let expired_cert = fixtures.join("expired.pem");

    // Absence 1: mismatched key.
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args([
        "tls",
        "import",
        "--cert",
        cert.to_str().unwrap(),
        "--key",
        other_key.to_str().unwrap(),
    ]));
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("does not match the certificate"), "{t}");
    assert!(t.contains("nothing installed"), "{t}");
    assert!(tls_listing(root.path()).is_empty(), "{t}");

    // Absence 2: expired leaf.
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args([
        "tls",
        "import",
        "--cert",
        expired_cert.to_str().unwrap(),
        "--key",
        expired_key.to_str().unwrap(),
    ]));
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("EXPIRED"), "{t}");
    assert!(t.contains("nothing installed"), "{t}");
    assert!(tls_listing(root.path()).is_empty(), "{t}");

    // Absence 3: the host is not covered.
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args([
        "tls",
        "import",
        "--cert",
        cert.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--host",
        "other.example.test",
    ]));
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(
        t.contains("does not cover host \"other.example.test\""),
        "{t}"
    );
    assert!(tls_listing(root.path()).is_empty(), "{t}");

    // The fleet-shape verdict before anything is installed: REFUSES, naming
    // the verb that fixes it.
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args(["tls", "status"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("shape:       team"), "{t}");
    assert!(t.contains("next boot:   REFUSES"), "{t}");
    assert!(t.contains("`ai-memory tls import"), "{t}");
    assert!(!t.contains("encrypted as required"), "{t}");

    // Presence: the valid pair, the host it covers, and the issuing CA.
    let ca = pki.ca_file(&fixtures);
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args([
        "tls",
        "import",
        "--cert",
        cert.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--ca",
        ca.to_str().unwrap(),
        "--host",
        "memory.example.test",
    ]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("tls import: installed"), "{t}");
    assert!(
        t.contains("issuer:      \"Example Corp Issuing CA\""),
        "{t}"
    );
    assert!(t.contains("verified for --host memory.example.test"), "{t}");
    assert_eq!(
        tls_listing(root.path()),
        vec!["operator-ca.pem", SERVER_KEY_FILE, SERVER_CERT_FILE]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(tls_dir(root.path()).join(SERVER_KEY_FILE)), 0o600);
        assert_eq!(mode(tls_dir(root.path())), 0o700);
    }

    // The same sink, read back: operator-supplied, the team shape serves.
    let out =
        run(command_with_config(root.path(), Some(TEAM_CONFIG)).args(["--json", "tls", "status"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {t}"));
    assert_eq!(v["source"], "operator-supplied", "{t}");
    assert_eq!(v["issuer"], "Example Corp Issuing CA", "{t}");
    assert_eq!(v["boot_would_refuse"], false, "{t}");
    assert_eq!(v["operator_ca_installed"], true, "{t}");
    assert!(
        v["verdict"]
            .as_str()
            .unwrap()
            .contains("encrypted as required for shape team"),
        "{t}"
    );

    // `init` over operator material mints nothing (the material is kept).
    let before = std::fs::read(tls_dir(root.path()).join(SERVER_CERT_FILE)).unwrap();
    let out = run(command_with_config(root.path(), None).args(["tls", "init"]));
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("mints nothing over it"), "{t}");
    assert_eq!(
        std::fs::read(tls_dir(root.path()).join(SERVER_CERT_FILE)).unwrap(),
        before
    );
    assert!(!tls_dir(root.path()).join(LOCAL_CA_KEY_FILE).exists());
}

/// `init`: a fleet shape REFUSES naming `tls import` and writes nothing
/// (absence + control); the singleton shape mints the local CA + leaf
/// (presence), a second `init` reuses it, and `status` reports the local CA
/// as serving under singleton and as REFUSING under a declared team shape.
#[test]
fn tls_init_two_populations_by_declared_shape_3709() {
    let root = tempfile::tempdir().unwrap();
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args(["tls", "init"]));
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("FLEET-shaped"), "{t}");
    assert!(t.contains("`ai-memory tls import"), "{t}");
    assert!(tls_listing(root.path()).is_empty(), "{t}");

    let out =
        run(command_with_config(root.path(), None).args(["tls", "init", "--host", "10.1.2.3"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("tls init: generated"), "{t}");
    assert!(t.contains("10.1.2.3"), "{t}");
    assert_eq!(
        tls_listing(root.path()),
        vec![
            "local-ca.key",
            "local-ca.pem",
            SERVER_KEY_FILE,
            SERVER_CERT_FILE
        ]
    );
    let first = std::fs::read(tls_dir(root.path()).join(SERVER_CERT_FILE)).unwrap();

    let out = run(command_with_config(root.path(), None)
        .args(["--json", "tls", "init", "--host", "10.1.2.3"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {t}"));
    assert_eq!(v["outcome"], "reused", "{t}");
    assert_eq!(
        std::fs::read(tls_dir(root.path()).join(SERVER_CERT_FILE)).unwrap(),
        first
    );

    let out = run(command_with_config(root.path(), None).args(["tls", "status"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("source:      local-ca"), "{t}");
    assert!(t.contains("issuer:      \"ai-memory local CA\""), "{t}");
    assert!(
        t.contains("encrypted as required for shape singleton"),
        "{t}"
    );
    assert!(!t.contains("REFUSES"), "{t}");

    // The SAME material under a declared team shape is the refusing verdict.
    let out = run(command_with_config(root.path(), Some(TEAM_CONFIG)).args(["tls", "status"]));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("next boot:   REFUSES"), "{t}");
    assert!(t.contains("minted by the local CA"), "{t}");
    assert!(t.contains("`ai-memory tls import"), "{t}");
    assert!(!t.contains("encrypted as required"), "{t}");
}
