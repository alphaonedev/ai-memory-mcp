// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3715 items 3 + 4 — `ai-memory config show --effective [--provenance]`
//! and the key deprecation lifecycle, through the REAL binary (env supplied
//! ONLY to the child, `env_clear`).
//!
//! FAILS ON THE PARENT (a5628e4c4): `config show` has no `--effective`
//! flag, so the first cell stops at clap's `unexpected argument` (exit 2);
//! the boot-loader cell sees the legacy key accepted with the old prose WARN
//! and no per-key replacement.
//!
//! Sinks and populations:
//! - stdout of `config show --effective --provenance`: the file's value is
//!   printed and attributed to the file (presence); a credential's key is
//!   listed and its bytes are absent (absence, same sink); an unset leaf is
//!   listed as unset (absence);
//! - the loader's stderr on boot-class verbs: a deprecated key WARNs naming
//!   its replacement and still applies (control); an unknown key REFUSES
//!   with `EX_CONFIG` and the unknown-key text, nothing printed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const EX_CONFIG: i32 = 78;

fn command_with_config(root: &Path, config_body: &str) -> (Command, PathBuf) {
    let keys = root.join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let xdg = root.join("home/.config");
    let dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&dir).expect("mkdir config dir");
    let path = dir.join("config.toml");
    std::fs::write(&path, config_body).expect("write config.toml");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("RUST_LOG", "error");
    (cmd, path)
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn ai-memory")
}

fn out_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `config show --effective --provenance` on a file with one set leaf, one
/// legacy (deprecated) key and one inline credential.
#[test]
fn config_show_effective_provenance_two_populations_3715() {
    let root = tempfile::tempdir().unwrap();
    let (mut cmd, path) = command_with_config(
        root.path(),
        "schema_version = 2\nllm_model = \"legacy-m\"\napi_key = \"sk-PLAINTEXT-CREDENTIAL-3715\"\n\
         [llm]\nmodel = \"AKIAEXAMPLE3715AAAAB\"\n\
         [storage]\ndefault_namespace = \"team-x\"\n",
    );
    let out = run(cmd.args(["config", "show", "--effective", "--provenance"]));
    let text = out_str(&out);
    let err = err_str(&out);
    assert!(
        out.status.success(),
        "exit {:?}\n{text}\n{err}",
        out.status.code()
    );
    assert!(!err.contains("unexpected argument"), "{err}");
    let file_origin = format!("# file {}", path.display());
    // Presence: the value the file set, attributed to the file.
    assert!(text.contains("default_namespace = \"team-x\""), "{text}");
    assert!(
        text.contains(&format!(
            "storage.default_namespace = \"team-x\"  {file_origin}"
        )),
        "{text}"
    );
    // The deprecated key: still applies, replacement named.
    assert!(
        text.contains(&format!(
            "llm_model = \"legacy-m\"  {file_origin}  # DEPRECATED since 0.7.0 — use [llm].model"
        )),
        "{text}"
    );
    // Absence on the same sink: an unset leaf is unset, not invented.
    assert!(
        text.contains("storage.archive_on_gc = (unset: the compiled default applies at use)  # compiled-default"),
        "{text}"
    );
    // The credential: its key is attributed to the file, its bytes are absent
    // from BOTH streams.
    assert!(!text.contains("sk-PLAINTEXT-CREDENTIAL-3715"), "{text}");
    assert!(!err.contains("sk-PLAINTEXT-CREDENTIAL-3715"), "{err}");
    assert!(
        text.contains(&format!("api_key = \"<redacted>\"  {file_origin}")),
        "{text}"
    );
    // A credential parked in an innocent field: the #3432 funnel's
    // value-shape backstop masks it in the document and the manifest (the
    // real process default screen mode; bypassing the funnel prints it).
    assert!(!text.contains("AKIAEXAMPLE3715AAAAB"), "{text}");
    assert!(!err.contains("AKIAEXAMPLE3715AAAAB"), "{err}");
    assert!(text.contains("model = \"[REDACTED:secret]\""), "{text}");
    assert!(
        text.contains(&format!("llm.model = \"[REDACTED:secret]\"  {file_origin}")),
        "{text}"
    );
    // The loader's WARN for the deprecated key reached stderr, naming the
    // replacement and the (unscheduled) removal.
    assert!(err.contains("`llm_model`"), "{err}");
    assert!(err.contains("replacement: [llm].model"), "{err}");
    assert!(err.contains("removal: not scheduled"), "{err}");
    // Environment: names only. AI_MEMORY_DB is set for this child; its
    // VALUE (the store path) must not appear in that section.
    // Escaped (G2): the name renders as a quoted string.
    assert!(text.contains("#   \"AI_MEMORY_DB\""), "{text}");
    let env_section = text.split("# environment:").nth(1).unwrap_or("");
    assert!(!env_section.contains("store.db"), "{env_section}");
}

/// The refusal population, through the same verb: an unknown key exits
/// `EX_CONFIG` with the unknown-key text and prints no document; the
/// plain `config show` (the #3714 shape table) is unchanged (control).
#[test]
fn config_show_effective_refuses_an_unknown_key_like_boot_3715() {
    let root = tempfile::tempdir().unwrap();
    let (mut cmd, _path) =
        command_with_config(root.path(), "[storage]\ndefault_namespac = \"x\"\n");
    let out = run(cmd.args(["config", "show", "--effective"]));
    assert_eq!(out.status.code(), Some(EX_CONFIG), "{}", err_str(&out));
    let err = err_str(&out);
    assert!(err.contains("unknown key"), "{err}");
    assert!(err.contains("default_namespac"), "{err}");
    assert!(
        !out_str(&out).contains("default_namespac"),
        "{}",
        out_str(&out)
    );

    let (mut cmd, _path) = command_with_config(root.path(), "[deployment]\nshape = \"team\"\n");
    let out = run(cmd.args(["config", "show"]));
    assert!(out.status.success(), "{}", err_str(&out));
    assert!(
        out_str(&out).contains("[deployment] shape = \"team\""),
        "{}",
        out_str(&out)
    );
}
