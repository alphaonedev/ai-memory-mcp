// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10103 / #10104 — CLI children for the legacy cutoff mint and helpers over
//! the forensic anchor lines they write. Every child runs in the per-test
//! sandbox of `home_sandbox` (HOME, config, key and witness directories) with
//! its forensic sink in an explicit per-test directory, so two children of
//! one test can share a key and a database while seeing different sinks: the
//! state a crash between the database commit and the anchor write leaves.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::home_sandbox;

/// `ForensicDecision.kind` of the anchor, written out.
pub const ANCHOR_KIND: &str = "signed_events_legacy_cutoff";
/// The CLI environment variable that names the forensic sink directory.
pub const AUDIT_DIR_ENV: &str = "AI_MEMORY_AUDIT_DIR";

/// One child of the test: exit code and stdout followed by stderr.
pub struct CliRun {
    pub code: Option<i32>,
    pub text: String,
}

/// Run `ai-memory <args>` with the sandbox of `root`, database `db`, agent
/// `agent`, the forensic sink in `audit` and `extra` variables.
pub fn run(
    root: &Path,
    db: &Path,
    agent: &str,
    audit: &Path,
    extra: &[(&str, &OsStr)],
    args: &[&str],
) -> CliRun {
    let child_env = home_sandbox::child_env(root);
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(child_env.iter().map(|(k, v)| (*k, v.as_os_str())))
        .env("AI_MEMORY_DB", db)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", agent)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env(AUDIT_DIR_ENV, audit)
        .envs(extra.iter().copied())
        .args(args)
        .output()
        .expect("run ai-memory");
    CliRun {
        code: out.status.code(),
        text: String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr),
    }
}

/// A fresh per-test sink directory under `root`.
pub fn sink_dir(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("create sink dir");
    dir
}

/// The forensic files of `dir`, in name order.
pub fn forensic_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read sink dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| {
            let jsonl = p.extension().and_then(OsStr::to_str) == Some("jsonl");
            jsonl
                && p.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|n| n.starts_with("forensic-"))
        })
        .collect();
    files.sort();
    files
}

/// Every anchor line of `dir`, parsed.
pub fn anchor_lines(dir: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for file in forensic_files(dir) {
        let text = std::fs::read_to_string(&file).expect("read forensic file");
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v["kind"] == ANCHOR_KIND {
                out.push(v);
            }
        }
    }
    out
}

/// `(cutoff_sequence, cutoff_payload_hash)` of an anchor line.
pub fn anchor_fields(v: &serde_json::Value) -> (i64, String) {
    (
        v["payload"]["cutoff_sequence"]
            .as_i64()
            .expect("cutoff_sequence"),
        v["payload"]["cutoff_payload_hash"]
            .as_str()
            .expect("cutoff_payload_hash")
            .to_string(),
    )
}

/// One way to forge an anchor line from a genuine one, without the key.
#[derive(Clone, Copy, Debug)]
pub enum Forgery {
    /// The signature removed.
    Unsigned,
    /// One character of the signature changed.
    SignatureFlipped,
    /// `cutoff_sequence` changed, the genuine signature kept.
    SequenceChanged,
}

/// Every forgery, written out.
pub const FORGERIES: &[Forgery] = &[
    Forgery::Unsigned,
    Forgery::SignatureFlipped,
    Forgery::SequenceChanged,
];

impl Forgery {
    /// The words the refusal must carry for this forgery.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unsigned => "is unsigned",
            Self::SignatureFlipped | Self::SequenceChanged => "signature does not verify",
        }
    }

    /// The forged copy of `genuine`.
    #[must_use]
    pub fn apply(self, genuine: &serde_json::Value) -> serde_json::Value {
        let mut v = genuine.clone();
        match self {
            Self::Unsigned => v["sig"] = serde_json::Value::String(String::new()),
            Self::SignatureFlipped => {
                let sig = v["sig"].as_str().expect("signed").to_string();
                let first = if sig.starts_with('A') { "B" } else { "A" };
                v["sig"] = serde_json::Value::String(format!("{first}{}", &sig[1..]));
            }
            Self::SequenceChanged => {
                let seq = v["payload"]["cutoff_sequence"].as_i64().expect("seq");
                v["payload"]["cutoff_sequence"] = serde_json::Value::from(seq + 1);
            }
        }
        v
    }
}

/// A sink directory holding a copy of every forensic file of `genuine_dir`
/// plus one forged anchor line appended to the newest file.
pub fn forged_sink(root: &Path, name: &str, genuine_dir: &Path, forgery: Forgery) -> PathBuf {
    let dir = sink_dir(root, name);
    let files = forensic_files(genuine_dir);
    let genuine = anchor_lines(genuine_dir)
        .into_iter()
        .next()
        .expect("a genuine anchor line");
    for file in &files {
        let target = dir.join(file.file_name().expect("file name"));
        std::fs::copy(file, &target).expect("copy forensic file");
    }
    let newest = dir.join(
        files
            .last()
            .expect("a forensic file")
            .file_name()
            .expect("file name"),
    );
    let mut text = std::fs::read_to_string(&newest).expect("read newest");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&forgery.apply(&genuine).to_string());
    text.push('\n');
    std::fs::write(&newest, text).expect("write forged line");
    dir
}
