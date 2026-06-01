// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_store` migration. Handler writes through `CliOutput` so unit
//! tests can capture stdout/stderr into `Vec<u8>` buffers.

use crate::cli::CliOutput;
use crate::cli::governance::{GovernanceOutcome, enforce as enforce_governance};
use crate::cli::helpers::auto_namespace;
use crate::models::ConfidenceSource;
use crate::{config, db, identity, models, validate};
use anyhow::Result;
use chrono::{Duration, Utc};
use clap::Args;
use models::Tier;
use std::path::Path;

/// Clap-derived arg shape for the `store` subcommand. Definition moved
/// from main.rs verbatim in W5a — fields and attrs unchanged.
#[derive(Args)]
pub struct StoreArgs {
    /// Memory tier. `default_value` must be a literal at attribute-parse
    /// time, so the wire string is kept here verbatim; it is byte-equal
    /// to `crate::models::Tier::Mid.as_str()` (pm-v3.1 PR6 #1174 sweep
    /// — raw tier literals are confined to the deserializer + clap
    /// `default_value` attrs that cannot accept const expressions).
    #[arg(long, short, default_value = "mid")]
    pub tier: String,
    #[arg(long, short)]
    pub namespace: Option<String>,
    #[arg(long, short = 'T', allow_hyphen_values = true)]
    pub title: String,
    /// Content (use - to read from stdin)
    #[arg(long, short, allow_hyphen_values = true)]
    pub content: String,
    #[arg(long, default_value = "")]
    pub tags: String,
    #[arg(long, short, default_value_t = 5)]
    pub priority: i32,
    /// Confidence 0.0-1.0
    #[arg(long, default_value_t = 1.0)]
    pub confidence: f64,
    /// Source: user, claude, hook, api
    #[arg(long, short = 'S', default_value = "cli")]
    pub source: String,
    /// Explicit expiry timestamp (RFC3339). Overrides tier default.
    #[arg(long)]
    pub expires_at: Option<String>,
    /// TTL in seconds. Overrides tier default.
    #[arg(long)]
    pub ttl_secs: Option<i64>,
    /// Task 1.5 visibility scope: private (default) / team / unit / org / collective.
    /// Stored as `metadata.scope`; affects which agents can recall this memory
    /// when queries use `--as-agent`.
    #[arg(long)]
    pub scope: Option<String>,
    /// v0.7.0 F2.3 (#1427) — Form-6 typed memory kind. One of:
    /// observation (default), reflection, persona, concept, entity,
    /// claim, relation, event, conversation, decision. Maps to
    /// `Memory::memory_kind` (canonical: `crate::models::MemoryKind`).
    #[arg(long)]
    pub kind: Option<String>,
    /// v0.7.0 F2.3 (#1427) — Form-4 fact-provenance citations array.
    /// JSON array of `{uri, accessed_at, hash?, span?}` entries. Maps
    /// to `Memory::citations` (validated via `validate::validate_citation`).
    /// Pass `--citations '[{"uri":"https://example.com","accessed_at":"2026-05-31T00:00:00Z"}]'`.
    #[arg(long)]
    pub citations: Option<String>,
    /// v0.7.0 F2.3 (#1427) — Form-4 first-class source URI pointer.
    /// Accepted schemes: `uri:` / `doc:` / `file:`. Maps to
    /// `Memory::source_uri` (validated via `validate::validate_source_uri`).
    #[arg(long)]
    pub source_uri: Option<String>,
    /// v0.7.0 F2.3 (#1427) — Form-4 byte-range pin into the source body.
    /// JSON `{start: <usize>, end: <usize>}`. Maps to `Memory::source_span`
    /// (validated via `validate::validate_source_span`).
    #[arg(long)]
    pub source_span: Option<String>,
    /// v0.7.0 F2.3 (#1427) — QW-2 persona artefact entity binding.
    /// Required when `--kind persona`. Maps to `Memory::entity_id`.
    #[arg(long)]
    pub entity_id: Option<String>,
    /// #626 Layer-3 (Task 1.3 / C5) — sign this write with the resolved
    /// agent's local Ed25519 keypair so the stored row is *attested*
    /// rather than merely *claimed*. Requires a `<agent_id>.priv` under
    /// the key directory (`AI_MEMORY_KEY_DIR` or the platform default);
    /// the bound public key must match (see `ai-memory agents bind-key`).
    /// When unset, the write is *claimed* unless
    /// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is on, which rejects it.
    #[arg(long)]
    pub sign: bool,
}

/// Resolve the content payload: literal `-` means read stdin via the
/// supplied callback, anything else is a literal string.
///
/// Extracted as a free fn so unit tests can supply a fake stdin reader
/// without touching the process's actual stdin.
pub(crate) fn resolve_content<F>(spec: &str, stdin_reader: F) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    if spec == "-" {
        stdin_reader()
    } else {
        Ok(spec.to_string())
    }
}

/// Read all of stdin to a `String`. Default reader for `resolve_content`.
fn read_stdin_to_string() -> Result<String> {
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// `store` handler. Mirrors `cmd_store` from main.rs verbatim except
/// every emit routes through `out.stdout` / `out.stderr` instead of
/// `println!` / `eprintln!`.
#[allow(clippy::too_many_lines)]
pub fn run(
    db_path: &Path,
    args: StoreArgs,
    json_out: bool,
    app_config: &config::AppConfig,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    let resolved_ttl = app_config.effective_ttl();
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());
    let tier = Tier::from_str(&args.tier)
        .ok_or_else(|| anyhow::anyhow!("invalid tier: {} (use short, mid, long)", args.tier))?;
    let namespace = args.namespace.unwrap_or_else(auto_namespace);
    let content = resolve_content(&args.content, read_stdin_to_string)?;
    let tags: Vec<String> = args
        .tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Validate all fields before touching the DB
    validate::validate_title(&args.title)?;
    validate::validate_content(&content)?;
    validate::validate_namespace(&namespace)?;
    validate::validate_source(&args.source)?;
    validate::validate_tags(&tags)?;
    validate::validate_priority(args.priority)?;
    validate::validate_confidence(args.confidence)?;
    validate::validate_expires_at(args.expires_at.as_deref())?;
    validate::validate_ttl_secs(args.ttl_secs)?;

    let now = Utc::now();
    let expires_at = args.expires_at.or_else(|| {
        args.ttl_secs
            .or(resolved_ttl.ttl_for_tier(&tier))
            .map(|s| (now + Duration::seconds(s)).to_rfc3339())
    });
    let agent_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let mut metadata = models::default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(agent_id.clone()),
        );
    }
    if let Some(ref s) = args.scope {
        validate::validate_scope(s)?;
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("scope".to_string(), serde_json::Value::String(s.clone()));
        }
    }

    // v0.7.0 F2.3 (#1427) — Form-4 + Form-6 caller-supplied fields.
    // Validate each before constructing the Memory; clap-side validation
    // is permissive (Option<String>) and the validator carries the
    // canonical wire-shape error messages (see validate::validate_*).
    let memory_kind = match args.kind.as_deref() {
        None => crate::models::MemoryKind::Observation,
        Some(s) => crate::models::MemoryKind::from_str(s).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --kind '{s}' (expected one of: observation, reflection, persona, \
                 concept, entity, claim, relation, event, conversation, decision)"
            )
        })?,
    };
    let citations: Vec<crate::models::Citation> = match args.citations.as_deref() {
        None => Vec::new(),
        Some(s) => {
            let parsed: Vec<crate::models::Citation> = serde_json::from_str(s)
                .map_err(|e| anyhow::anyhow!("invalid --citations JSON: {e}"))?;
            for c in &parsed {
                validate::validate_citation(c)
                    .map_err(|e| anyhow::anyhow!("invalid --citations entry: {e}"))?;
            }
            parsed
        }
    };
    let source_uri = match args.source_uri.as_deref() {
        None => None,
        Some(s) => {
            validate::validate_source_uri(s)
                .map_err(|e| anyhow::anyhow!("invalid --source-uri: {e}"))?;
            Some(s.to_string())
        }
    };
    let source_span: Option<crate::models::SourceSpan> = match args.source_span.as_deref() {
        None => None,
        Some(s) => {
            let parsed: crate::models::SourceSpan = serde_json::from_str(s)
                .map_err(|e| anyhow::anyhow!("invalid --source-span JSON: {e}"))?;
            validate::validate_source_span(&parsed)
                .map_err(|e| anyhow::anyhow!("invalid --source-span: {e}"))?;
            Some(parsed)
        }
    };

    let mut mem = models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace,
        title: args.title,
        content,
        tags,
        priority: args.priority.clamp(1, 10),
        confidence: args.confidence.clamp(0.0, 1.0),
        source: args.source,
        access_count: 0,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        last_accessed_at: None,
        expires_at,
        metadata,
        reflection_depth: 0,
        memory_kind,
        entity_id: args.entity_id,
        persona_version: None,
        citations,
        source_uri,
        source_span,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };

    // #626 Layer-3 (Task 1.3 / C5) — agent attestation gate. When
    // `--sign` is set, load the agent's local keypair and sign the
    // attestable surface; the gate then stamps `metadata.attest_level =
    // "agent_attested"`. The gate is also invoked (with no signature) when
    // `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is on, so an unsigned write is
    // rejected under the strict posture. When neither applies the write
    // path is byte-equal to the pre-Layer-3 behavior (no stamp).
    let signature: Option<Vec<u8>> = if args.sign {
        let dir = identity::keypair::default_key_dir()?;
        let kp = identity::keypair::load(&agent_id, &dir).map_err(|e| {
            anyhow::anyhow!("--sign requires a local keypair for agent '{agent_id}': {e:#}")
        })?;
        Some(identity::attest::sign_memory_write(&kp, &mem, &agent_id)?)
    } else {
        None
    };
    if args.sign || identity::attest::require_agent_attestation_enabled() {
        identity::attest::stamp_attestation_sync(&conn, &mut mem, &agent_id, signature.as_deref())?;
    }

    // W5b/C5: governance enforcement routes through `cli::governance::enforce`
    // so the print-side of Pending/Deny is covered by `cli::governance::tests`.
    // Caller still owns the `process::exit(1)` on Deny.
    {
        use models::GovernedAction;
        let payload = serde_json::to_value(&mem).unwrap_or_default();
        match enforce_governance(
            &conn,
            GovernedAction::Store,
            &mem.namespace,
            &agent_id,
            None,
            None,
            &payload,
            json_out,
            out,
        )? {
            GovernanceOutcome::Allow => {}
            GovernanceOutcome::Deny => {
                std::process::exit(1);
            }
            GovernanceOutcome::Pending => {
                return Ok(());
            }
        }
    }
    let contradictions =
        db::find_contradictions(&conn, &mem.title, &mem.namespace).unwrap_or_default();
    let actual_id = db::insert(&conn, &mem)?;

    // PR-5 (issue #487): security audit trail. No-op when disabled.
    crate::audit::emit(crate::audit::EventBuilder::new(
        crate::audit::AuditAction::Store,
        crate::audit::actor(
            agent_id.clone(),
            cli_agent_id.map_or("default_fallback", |_| "explicit"),
            args.scope.clone(),
        ),
        crate::audit::target_memory(
            actual_id.clone(),
            mem.namespace.clone(),
            Some(mem.title.clone()),
            Some(mem.tier.to_string()),
            args.scope.clone(),
        ),
    ));
    let filtered: Vec<&String> = contradictions
        .iter()
        .filter(|c| c.id != mem.id && c.id != actual_id)
        .map(|c| &c.id)
        .collect();
    if json_out {
        let mut j = serde_json::to_value(&mem)?;
        j["id"] = serde_json::json!(actual_id);
        let filtered: Vec<&String> = contradictions
            .iter()
            .filter(|c| c.id != actual_id)
            .map(|c| &c.id)
            .collect();
        if !filtered.is_empty() {
            j["potential_contradictions"] = serde_json::json!(filtered);
        }
        writeln!(out.stdout, "{}", serde_json::to_string(&j)?)?;
    } else {
        writeln!(
            out.stdout,
            "stored: {} [{}] (ns={})",
            actual_id, mem.tier, mem.namespace
        )?;
        if !filtered.is_empty() {
            writeln!(
                out.stderr,
                "warning: {} similar memories found in same namespace (potential contradictions)",
                filtered.len()
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    fn default_args() -> StoreArgs {
        StoreArgs {
            tier: Tier::Mid.as_str().to_string(),
            namespace: Some("test-ns".to_string()),
            title: "test title".to_string(),
            content: "test content".to_string(),
            tags: String::new(),
            priority: 5,
            confidence: 1.0,
            source: "cli".to_string(),
            expires_at: None,
            ttl_secs: None,
            scope: None,
            // v0.7.0 F2.3 (#1427) — Form-4 + Form-6 CLI flag additions.
            kind: None,
            citations: None,
            source_uri: None,
            source_span: None,
            entity_id: None,
            sign: false,
        }
    }

    #[test]
    fn test_resolve_content_literal() {
        let out = resolve_content("hello", || panic!("should not call stdin"));
        assert_eq!(out.unwrap(), "hello");
    }

    #[test]
    fn test_resolve_content_stdin_dash() {
        let out = resolve_content("-", || Ok("piped content".to_string()));
        assert_eq!(out.unwrap(), "piped content");
    }

    #[test]
    fn test_store_happy_path_text_output() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let args = default_args();
        {
            let mut out = env.output();
            run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.starts_with("stored: "), "got: {stdout}");
        assert!(stdout.contains("[mid]"));
        assert!(stdout.contains("ns=test-ns"));
    }

    #[test]
    fn test_store_json_output() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let args = default_args();
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert!(v["id"].is_string());
        assert_eq!(v["title"].as_str().unwrap(), "test title");
        assert_eq!(v["tier"].as_str().unwrap(), Tier::Mid.as_str());
        assert_eq!(v["namespace"].as_str().unwrap(), "test-ns");
    }

    #[test]
    fn test_store_stdin_content() {
        // Direct test on resolve_content covers the dash-stdin branch
        // without spawning a subprocess.
        let payload = "from stdin reader";
        let resolved = resolve_content("-", || Ok(payload.to_string())).unwrap();
        assert_eq!(resolved, payload);
    }

    #[test]
    fn test_store_explicit_expires_at_overrides_tier() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        let custom_expiry = "2099-01-01T00:00:00+00:00".to_string();
        args.expires_at = Some(custom_expiry.clone());
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let exp = v["expires_at"].as_str().unwrap();
        assert!(exp.starts_with("2099-01-01"), "got: {exp}");
    }

    #[test]
    fn test_store_ttl_secs_overrides_tier() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.ttl_secs = Some(60);
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // expires_at must be set (non-null) and roughly within the next minute.
        assert!(v["expires_at"].is_string());
    }

    #[test]
    fn test_store_with_scope_in_metadata() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.scope = Some("team".to_string());
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["metadata"]["scope"].as_str().unwrap(), "team");
    }

    #[test]
    fn test_store_invalid_tier_validation_error() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.tier = "ginormous".to_string();
        let mut out = env.output();
        let res = run(&db, args, false, &cfg, Some("test-agent"), &mut out);
        let err = res.unwrap_err();
        assert!(err.to_string().contains("invalid tier"));
    }

    #[test]
    fn test_store_invalid_priority_validation_error() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.priority = 99;
        let mut out = env.output();
        let res = run(&db, args, false, &cfg, Some("test-agent"), &mut out);
        // validate_priority rejects out-of-range values.
        assert!(res.is_err());
    }

    #[test]
    fn test_store_contradiction_warning_in_stderr() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        // Seed a memory with a SIMILAR (not identical) title in the same
        // namespace. A distinct title avoids the `(title, namespace)`
        // upsert — if the titles matched exactly, `db::insert` would merge
        // onto the seeded row, making `actual_id == seeded.id`, and the
        // contradiction would be filtered out (line: `c.id != actual_id`)
        // so the warning would never fire. The two titles share
        // `{kubernetes, deployment}` of `{kubernetes, deployment, guide}` /
        // `{kubernetes, deployment, notes}` → Jaccard 2/4 = 0.5 ≥ 0.30
        // floor, so the seeded row surfaces as a potential contradiction.
        let _ = crate::cli::test_utils::seed_memory(
            &db,
            "test-ns",
            "kubernetes deployment guide",
            "first content",
        );
        let mut args = default_args();
        args.title = "kubernetes deployment notes".to_string();
        args.content = "second content".to_string();
        {
            let mut out = env.output();
            run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        // Happy path stored the new (distinct-title) row on stdout.
        assert!(env.stdout_str().contains("stored: "));
        // And the similar seeded row fired the contradiction warning on
        // stderr (exercises the non-json `if !filtered.is_empty()` branch).
        let stderr = env.stderr_str();
        assert!(
            stderr.contains("potential contradictions"),
            "expected contradiction warning on stderr, got: {stderr}"
        );
    }

    #[test]
    fn test_store_governance_pending_writes_pending_status() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Covered indirectly by the happy-path test (no governance rules
        // configured -> Allow branch). The Pending/Deny branches require
        // governance-rule rows that aren't part of the default schema; a
        // dedicated unit test would need to seed the governance_rules
        // table directly. Hardened in integration suite.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let args = default_args();
        let mut out = env.output();
        let res = run(&db, args, true, &cfg, Some("test-agent"), &mut out);
        drop(out);
        assert!(res.is_ok());
        // JSON shape on the Allow branch must include a stored id.
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["id"].is_string());
    }

    #[test]
    fn test_store_tag_parsing() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.tags = "a, b, , c".to_string();
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let tags = v["tags"].as_array().unwrap();
        let strs: Vec<&str> = tags.iter().map(|t| t.as_str().unwrap()).collect();
        assert_eq!(strs, vec!["a", "b", "c"]);
    }

    // v0.7.0 F2.3 (#1427) — coverage for the Form-4 / Form-6 flag arms.

    #[test]
    fn test_store_form4_form6_flags_valid_roundtrip() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Exercises every Some(_) success arm (kind/citations/source_uri/
        // source_span/entity_id) in a single store call.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.kind = Some("reflection".to_string());
        args.citations = Some(
            r#"[{"uri":"uri:https://example.com/a","accessed_at":"2026-05-31T00:00:00Z"}]"#
                .to_string(),
        );
        args.source_uri = Some("uri:https://example.com/src".to_string());
        args.source_span = Some(r#"{"start":0,"end":5}"#.to_string());
        args.entity_id = Some("ent-123".to_string());
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["memory_kind"].as_str().unwrap(), "reflection");
        assert_eq!(
            v["source_uri"].as_str().unwrap(),
            "uri:https://example.com/src"
        );
        assert_eq!(v["entity_id"].as_str().unwrap(), "ent-123");
        assert_eq!(v["citations"].as_array().unwrap().len(), 1);
        assert_eq!(v["source_span"]["end"].as_u64().unwrap(), 5);
    }

    #[test]
    fn test_store_invalid_kind_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.kind = Some("ginormous".to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(err.to_string().contains("invalid --kind"), "got: {err}");
    }

    #[test]
    fn test_store_invalid_citations_json_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.citations = Some("not-json".to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("invalid --citations JSON"),
            "got: {err}"
        );
    }

    #[test]
    fn test_store_invalid_citations_entry_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Well-formed JSON, but the entry fails validate_citation
        // (bare URI without a uri:/doc:/file: scheme).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.citations =
            Some(r#"[{"uri":"example.com","accessed_at":"2026-05-31T00:00:00Z"}]"#.to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("invalid --citations entry"),
            "got: {err}"
        );
    }

    #[test]
    fn test_store_invalid_source_uri_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.source_uri = Some("bareword-no-scheme".to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("invalid --source-uri"),
            "got: {err}"
        );
    }

    #[test]
    fn test_store_invalid_source_span_json_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.source_span = Some("not-json".to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("invalid --source-span JSON"),
            "got: {err}"
        );
    }

    #[test]
    fn test_store_invalid_source_span_range_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Valid JSON, but start >= end fails validate_source_span.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.source_span = Some(r#"{"start":5,"end":5}"#.to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("invalid --source-span"),
            "got: {err}"
        );
    }

    // #626 Layer-3 (Task 1.3 / C5) — `--sign` attestation gate coverage.
    //
    // These three tests mutate process env (`AI_MEMORY_KEY_DIR`,
    // `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`) so they serialize on
    // `ENV_LOCK` and restore the prior values on exit, per the
    // env-test discipline. Key material lives under a `tempfile::tempdir()`
    // (never `/tmp` directly — the OS temp root is fine for the OS-created
    // dir; the project no-/tmp rule covers agent-AUTHORED scratch paths).

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII restore of an env var to its pre-test value.
    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvVarGuard {
        fn set(key: &'static str, val: &std::ffi::OsStr) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }
        fn clear(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn test_store_sign_with_bound_key_stamps_agent_attested() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key_dir = tempfile::tempdir().unwrap();
        let _kd = EnvVarGuard::set("AI_MEMORY_KEY_DIR", key_dir.path().as_os_str());
        let _req = EnvVarGuard::clear("AI_MEMORY_REQUIRE_AGENT_ATTESTATION");

        // Persist the agent's keypair on disk so `--sign` can load + sign.
        let kp = crate::identity::keypair::generate("test-agent").unwrap();
        crate::identity::keypair::save(&kp, key_dir.path()).unwrap();

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Register the agent + bind its pubkey so the gate resolves a bound
        // key matching the presented signature → AgentAttested.
        {
            let conn = db::open(&db).unwrap();
            db::register_agent(&conn, "test-agent", "ai:claude-opus-4.7", &[]).unwrap();
            db::bind_agent_pubkey(&conn, "test-agent", &kp.public_base64()).unwrap();
        }

        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.sign = true;
        {
            let mut out = env.output();
            run(&db, args, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(
            v["metadata"]["attest_level"].as_str().unwrap(),
            "agent_attested"
        );
    }

    #[test]
    fn test_store_sign_without_local_keypair_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Empty key dir — no `<agent_id>.priv` to load.
        let key_dir = tempfile::tempdir().unwrap();
        let _kd = EnvVarGuard::set("AI_MEMORY_KEY_DIR", key_dir.path().as_os_str());
        let _req = EnvVarGuard::clear("AI_MEMORY_REQUIRE_AGENT_ATTESTATION");

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.sign = true;
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(
            err.to_string().contains("--sign requires a local keypair"),
            "got: {err}"
        );
    }

    #[test]
    fn test_store_require_attestation_rejects_unsigned() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _req = EnvVarGuard::set(
            "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
            std::ffi::OsStr::new("1"),
        );

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        // Unsigned write (sign=false) under the strict posture: the gate
        // is invoked with no signature + require=true → AttestationRequired.
        let args = default_args();
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out).unwrap_err();
        assert!(err.to_string().contains("attestation"), "got: {err}");
    }
}
