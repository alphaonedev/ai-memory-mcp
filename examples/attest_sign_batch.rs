// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `attest_sign_batch` — single-process batch Ed25519 signer for the
//! store-path agent-attestation gate (#626 Layer-3), built for the Atlas
//! Corpus scale ingest (#1535).
//!
//! The maximum-secure fleet runs with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`,
//! so an UNSIGNED `POST /api/v1/memories` is refused `403 ATTESTATION_FAILED`.
//! [`attest_sign`](attest_sign.rs) signs ONE write per process invocation — too
//! slow for the 7912-record corpus (one cargo-spawned signer per record would
//! dominate wall-clock). This tool reads the WHOLE corpus JSONL + the agent's
//! raw 32-byte Ed25519 seed ONCE, signs every record in-process with the SAME
//! crate code the verifier runs ([`ai_memory::identity::sign::sign_write`] over
//! [`ai_memory::identity::sign::SignableWrite`]), and emits one ready-to-POST
//! attested request body per input line on stdout (NDJSON). The harness then
//! POSTs the emitted bodies in parallel over mTLS with `X-Agent-Id`.
//!
//! INPUT (one JSON object per line) — each line is a COMPLETE memory body:
//! `{title, content, namespace, scope, tier, kind, source, source_uri,
//!  tags:[...], metadata:{...}}`
//!
//! OUTPUT (one JSON object per line) — the SAME fields PLUS the attestation
//! envelope the receive path verifies:
//! `{... , signature:"<std-b64 Ed25519>", created_at:"<RFC3339>"}`
//!
//! The signature commits to exactly `SignableWrite { agent_id, namespace,
//! title, kind, created_at, content_sha256 = sha256(content) }` — the field
//! contract pinned by `attest::sign_memory_write`. The `kind` signed is the
//! record's own `kind` (claim/concept), so the row's verified kind matches the
//! provenance metadata. `created_at` is stamped ONCE at batch start (RFC3339,
//! within the ±300s freshness window) and signed verbatim per record; the
//! harness POSTs promptly so every body lands inside the window.
//!
//! The private seed is NEVER echoed. `--agent-id` MUST be the id the requests
//! authenticate as (X-Agent-Id) AND whose pubkey is bound on the write peer.

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::Parser;
use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};
use serde_json::Value;

use ai_memory::identity::attest::content_sha256;
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::identity::sign::{SignableWrite, sign_write};

#[derive(Parser)]
#[command(
    name = "attest_sign_batch",
    about = "Sign every record in a corpus JSONL and emit ready-to-POST attested request bodies (NDJSON)"
)]
struct Cli {
    /// The claiming agent id (the field the attestation gate binds). MUST be
    /// the same id the requests authenticate as (X-Agent-Id) AND the id whose
    /// public key is bound on the write peer.
    #[arg(long)]
    agent_id: String,
    /// Path to the agent's raw 32-byte Ed25519 private seed (`<agent_id>.priv`).
    #[arg(long)]
    priv_file: PathBuf,
    /// Path to the corpus JSONL (one complete memory body per line). `-` reads
    /// from stdin.
    #[arg(long)]
    corpus: PathBuf,
    /// RFC3339 creation timestamp the signatures commit to, stamped once for the
    /// whole batch. When omitted the tool stamps `now()` in UTC. The caller MUST
    /// POST the emitted bodies promptly so every `created_at` lands inside the
    /// server's ±300s freshness window.
    #[arg(long)]
    created_at: Option<String>,
    /// Remap the emitted top-level `source` to this value. The substrate's
    /// `POST /api/v1/memories` validator rejects any `source` outside
    /// `VALID_SOURCES` (user/nhi/claude/hook/api/cli/import/consolidation/
    /// system/chaos/notify) with `400`. The Atlas corpus carries
    /// `source:"atlas-knowledge-card"` (provenance metadata, not a substrate
    /// source-enum value), so the harness passes `--source import` to land a
    /// valid bulk-load source. The ORIGINAL corpus source is preserved verbatim
    /// under `metadata.<source-meta-key>` so no provenance is lost. `source` is
    /// NOT part of the signed `SignableWrite` envelope, so this remap never
    /// invalidates the attestation. When omitted the corpus `source` passes
    /// through unchanged.
    #[arg(long)]
    source: Option<String>,
    /// Metadata key under which to preserve the original corpus `source` when
    /// `--source` remaps the top-level value (default `original_source`). Keeps
    /// the `atlas-knowledge-card` provenance recoverable on the stored row.
    #[arg(long, default_value = "original_source")]
    source_meta_key: String,
    /// Collision policy injected into every emitted body (`error` | `merge` |
    /// `version`). The HTTP write path defaults to `error`, which 409s on a
    /// re-ingest of an already-present `(title, namespace)`; the harness passes
    /// `merge` so the ingest is idempotent (re-runnable) without spurious row
    /// errors. When omitted no `on_conflict` is injected (handler default).
    #[arg(long)]
    on_conflict: Option<String>,
    /// Scheme to prefix onto a bare `source_uri` that lacks a valid substrate
    /// scheme (default `uri:`). The Form-4 `validate_source_uri` requires every
    /// `source_uri` to start with one of `uri:` / `doc:` / `file:`; the Atlas
    /// corpus carries bare `https://www.youtube.com/...` provenance URLs, so the
    /// harness prefixes `uri:` to land `uri:https://...` (the documented HTTP(S)
    /// form). `source_uri` is NOT in the signed envelope, so the prefix never
    /// invalidates the attestation. A `source_uri` that already carries a valid
    /// scheme is left unchanged.
    #[arg(long, default_value = "uri:")]
    source_uri_scheme: String,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("attest_sign_batch: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let keypair = load_signing_keypair(&cli.agent_id, &cli.priv_file)?;
    let created_at = cli.created_at.clone().unwrap_or_else(rfc3339_now_utc);

    let reader: Box<dyn BufRead> = if cli.corpus.as_os_str() == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            std::fs::File::open(&cli.corpus)
                .with_context(|| format!("opening corpus {}", cli.corpus.display()))?,
        ))
    };

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut emitted: u64 = 0;
    let mut skipped: u64 = 0;
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading corpus line {}", lineno + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match sign_record(
            &keypair,
            &created_at,
            trimmed,
            cli.source.as_deref(),
            &cli.source_meta_key,
            cli.on_conflict.as_deref(),
            &cli.source_uri_scheme,
        ) {
            Ok(body) => {
                out.write_all(body.as_bytes())
                    .context("writing attested body")?;
                out.write_all(b"\n").context("writing newline")?;
                emitted += 1;
            }
            Err(e) => {
                // Emit a diagnostic to stderr and keep going so one malformed
                // record never aborts the whole batch; the harness asserts the
                // emitted count equals the corpus line count, so any skip is
                // caught as a row error rather than silently swallowed.
                eprintln!("attest_sign_batch: line {} skipped: {e:#}", lineno + 1);
                skipped += 1;
            }
        }
    }
    out.flush().context("flushing stdout")?;
    eprintln!("attest_sign_batch: emitted={emitted} skipped={skipped} created_at={created_at}");
    if skipped > 0 {
        bail!("{skipped} record(s) failed to sign — see stderr above");
    }
    Ok(())
}

/// Sign one corpus record and return a ready-to-POST attested request body.
/// The output preserves every input field and injects `signature` +
/// `created_at`; the signature commits to the record's own namespace / title /
/// kind so the verified kind matches the row's provenance.
fn sign_record(
    keypair: &AgentKeypair,
    created_at: &str,
    line: &str,
    source_override: Option<&str>,
    source_meta_key: &str,
    on_conflict: Option<&str>,
    source_uri_scheme: &str,
) -> Result<String> {
    let mut obj: Value = serde_json::from_str(line).context("parsing record JSON")?;
    let map = obj
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("record is not a JSON object"))?;

    let title = str_field(map, "title")?;
    let namespace = str_field(map, "namespace")?;
    let content = str_field(map, "content")?;
    // Kind drives both the signed envelope and the stored row. The corpus uses
    // claim/concept; default to the substrate default kind only if absent.
    let kind = map
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("observation")
        .to_string();

    let content_hash = content_sha256(&content);
    let write = SignableWrite {
        agent_id: &keypair.agent_id,
        namespace: &namespace,
        title: &title,
        kind: &kind,
        created_at,
        content_sha256: &content_hash,
    };
    let sig = sign_write(keypair, &write).context("signing the write envelope")?;
    // STANDARD base64 — `attest::prepare_signed_store` decodes the wire
    // `signature` with the standard alphabet.
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);

    // Remap `source` to a VALID_SOURCES value, preserving the original under a
    // metadata key. `source` is NOT in the signed envelope, so this is safe to
    // do after signing without invalidating the attestation.
    if let Some(new_source) = source_override {
        let original = map
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(orig) = original
            && orig != new_source
        {
            let meta = map
                .entry("metadata".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(mobj) = meta.as_object_mut() {
                mobj.insert(source_meta_key.to_string(), Value::String(orig));
            }
        }
        map.insert("source".to_string(), Value::String(new_source.to_string()));
    }
    // Prefix a bare `source_uri` with a valid Form-4 scheme so the provenance
    // URL survives `validate_source_uri`. Not in the signed envelope.
    if let Some(uri) = map.get("source_uri").and_then(Value::as_str) {
        let uri = uri.to_string();
        let has_scheme = ["uri:", "doc:", "file:"].iter().any(|p| uri.starts_with(p));
        if !uri.is_empty() && !has_scheme {
            let prefixed = format!("{source_uri_scheme}{uri}");
            map.insert("source_uri".to_string(), Value::String(prefixed));
        }
    }
    // Idempotent re-ingest: inject the collision policy so a re-run merges
    // rather than 409-ing on an already-present (title, namespace).
    if let Some(oc) = on_conflict {
        map.insert("on_conflict".to_string(), Value::String(oc.to_string()));
    }

    map.insert("signature".to_string(), Value::String(sig_b64));
    map.insert(
        "created_at".to_string(),
        Value::String(created_at.to_string()),
    );
    serde_json::to_string(&obj).context("serializing attested body")
}

fn str_field(map: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("record missing required string field `{key}`"))
}

/// RFC3339 UTC `now()` with a `+00:00` offset — the exact shape the bash
/// `attested_body` helper stamps (`date -u +%Y-%m-%dT%H:%M:%S+00:00`), so the
/// freshness window and signature contract match the single-record path. Uses
/// the project's `chrono` dependency (the same crate `attest::sign_memory_write`
/// stamps `created_at` with) so the timestamp shape is identical to the
/// verifier's reference path.
fn rfc3339_now_utc() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// Read the raw 32-byte Ed25519 seed and build a sign-capable [`AgentKeypair`].
/// The seed format matches the `.priv` files `keypair::save` writes; the secret
/// never lands on stdout/stderr.
fn load_signing_keypair(agent_id: &str, priv_file: &std::path::Path) -> Result<AgentKeypair> {
    let bytes = std::fs::read(priv_file)
        .with_context(|| format!("reading private key {}", priv_file.display()))?;
    let seed: [u8; SECRET_KEY_LENGTH] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "private key {} is {} bytes, expected {SECRET_KEY_LENGTH} raw Ed25519 seed bytes",
            priv_file.display(),
            bytes.len()
        )
    })?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();
    Ok(AgentKeypair {
        agent_id: agent_id.to_string(),
        public,
        private: Some(signing),
    })
}
