// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3197 — `entrypoint.plan-c.sh` must not interpolate `AI_MEMORY_API_KEY`
//! raw into TOML. A `"`, `\`, or trailing newline used to produce invalid
//! TOML; `AppConfig::load_from` then fail-opened to a KEYLESS daemon.
//!
//! Pins: (a) the entrypoint sources `config-emit.sh` and validates with
//! `ai-memory config check`; (b) the helper escapes quote/backslash,
//! strips trailing newlines, and refuses other control characters
//! (EX_CONFIG 78). Rendered documents are parsed with the toml crate.

#![allow(clippy::doc_markdown)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn entrypoint_path() -> PathBuf {
    repo_root().join("entrypoint.plan-c.sh")
}

fn config_emit_path() -> PathBuf {
    repo_root().join("infra/plan-c/config-emit.sh")
}

fn scratch_dir() -> PathBuf {
    let p = repo_root().join(".local-runs").join("scratch-3197-emit");
    fs::create_dir_all(&p).expect("mkdir .local-runs/scratch-3197-emit");
    p
}

#[test]
fn entrypoint_does_not_interpolate_api_key_raw_3197() {
    let contents = fs::read_to_string(entrypoint_path()).expect("read entrypoint");
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        assert!(
            !line.contains("${AI_MEMORY_API_KEY}"),
            "issue #3197: entrypoint.plan-c.sh line {} interpolates \
             AI_MEMORY_API_KEY raw into TOML. Offending line: {raw:?}",
            lineno + 1
        );
        assert!(
            !line.contains("API_KEY_TOML="),
            "issue #3197: the pre-fix API_KEY_TOML assignment must stay gone; \
             line {}: {raw:?}",
            lineno + 1
        );
    }
    assert!(
        contents.contains("config-emit.sh"),
        "entrypoint must source infra/plan-c/config-emit.sh"
    );
    assert!(
        contents.contains("config check"),
        "entrypoint must validate the rendered file with `ai-memory config check`"
    );
    assert!(
        contents.contains("plan_c_render_config"),
        "entrypoint must render via plan_c_render_config"
    );
}

#[test]
fn dockerfiles_copy_config_emit_helper_3197() {
    for rel in ["Dockerfile.plan-c", "Dockerfile.tier2-trackb"] {
        let path = repo_root().join(rel);
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            body.contains("infra/plan-c/config-emit.sh"),
            "{rel} must COPY config-emit.sh into the runtime image"
        );
        assert!(
            body.contains("/usr/local/lib/ai-memory/config-emit.sh"),
            "{rel} must land the helper where the entrypoint sources it"
        );
    }
}

fn render_with_key(key: &str) -> (i32, String, String) {
    let helper = config_emit_path();
    assert!(helper.is_file(), "missing {}", helper.display());
    let scratch = scratch_dir();
    let out_path = scratch.join(format!("rendered-{}.toml", uuid::Uuid::new_v4()));
    let status = Command::new("bash")
        .args([
            "-c",
            "set -euo pipefail; . \"$1\"; plan_c_render_config > \"$2\"",
            "render-3197",
            helper.to_str().expect("utf8 helper path"),
            out_path.to_str().expect("utf8 out path"),
        ])
        .env("AI_MEMORY_API_KEY", key)
        .env("TIER", "keyword")
        .env("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        .env("LLM_MODEL", "x")
        .env("AUTO_TAG_MODEL", "y")
        .output()
        .expect("run plan_c_render_config");
    let code = status.status.code().unwrap_or(255);
    let rendered = fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = String::from_utf8_lossy(&status.stderr).into_owned();
    let _ = fs::remove_file(&out_path);
    (code, rendered, stderr)
}

#[test]
fn config_emit_escapes_quote_and_backslash_3197() {
    let (code, body, err) = render_with_key(r#"say "hi"\path"#);
    assert_eq!(code, 0, "render must succeed, stderr={err}");
    assert!(
        body.contains(r#"api_key = "say \"hi\"\\path""#),
        "quote and backslash must be TOML-basic-string escaped; got:\n{body}"
    );
    let parsed: toml::Value = toml::from_str(&body).expect("rendered document must be valid TOML");
    let key = parsed
        .get("api_key")
        .and_then(toml::Value::as_str)
        .expect("api_key present");
    assert_eq!(key, r#"say "hi"\path"#);
}

#[test]
fn config_emit_strips_trailing_newlines_only_3197() {
    let (code, body, err) = render_with_key("sekrit\n\n");
    assert_eq!(
        code, 0,
        "trailing-newline docker-secret must boot, stderr={err}"
    );
    assert!(
        err.contains("stripped trailing newline"),
        "must WARN that it stripped, got: {err}"
    );
    let parsed: toml::Value = toml::from_str(&body).expect("valid TOML after strip");
    let key = parsed
        .get("api_key")
        .and_then(toml::Value::as_str)
        .expect("api_key present");
    assert_eq!(key, "sekrit");
}

#[test]
fn config_emit_refuses_control_character_3197() {
    let (code, body, err) = render_with_key("sekrit\twith-tab");
    assert_eq!(
        code, 78,
        "EX_CONFIG 78 on remaining control chars, stderr={err}"
    );
    assert!(
        err.contains("control character"),
        "refusal must name the control-char reason, got: {err}"
    );
    assert!(
        body.is_empty() || !body.contains("api_key"),
        "must not emit a keyless-looking config on refuse; got:\n{body}"
    );
}
