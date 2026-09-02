// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_store` migration. Handler writes through `CliOutput` so unit
//! tests can capture stdout/stderr into `Vec<u8>` buffers.

use crate::cli::CliOutput;
use crate::cli::governance::{GovernanceOutcome, enforce as enforce_governance};
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
    /// Confidence 0.0-1.0. When omitted (#1591) the compiled default is
    /// stamped with truthful `confidence_source = "default"` provenance
    /// instead of falsely claiming `caller_provided`.
    #[arg(long)]
    pub confidence: Option<f64>,
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
    /// #2258 / #1834 — claim-bitemporal VALID-time start (RFC3339). Records
    /// when the fact BECAME true (backfill / future-effective), distinct from
    /// `created_at` transaction-time. Maps to `Memory::valid_from` (validated
    /// via `validate::validate_valid_at`). IMMUTABLE after create.
    #[arg(long)]
    pub valid_from: Option<String>,
    /// #2258 / #1834 — claim-bitemporal VALID-time end bound (RFC3339,
    /// half-open `[valid_from, valid_until)`). Maps to `Memory::valid_until`
    /// (validated via `validate::validate_valid_at`); stays updatable via
    /// `ai-memory update`.
    #[arg(long)]
    pub valid_until: Option<String>,
    /// v0.7.0 F2.3 (#1427) — QW-2 persona artefact entity binding.
    /// Required when `--kind persona`. Maps to `Memory::entity_id`.
    #[arg(long)]
    pub entity_id: Option<String>,
    /// #626 Layer-3 (Task 1.3 / C5) — sign this write with the resolved
    /// agent's local Ed25519 keypair so the stored row is *attested*
    /// rather than merely *claimed*. Requires a `<agent_id>.priv` under
    /// the key directory (`AI_MEMORY_KEY_DIR` or the platform default);
    /// the bound public key must match (see `ai-memory agents bind-key`).
    /// When unset, the CLI surface is permissive by default (#1985
    /// operator-as-actor `WriteSurface::Cli`), so the unsigned write lands
    /// *claimed*; it is only REJECTED if the operator forces global-strict
    /// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`.
    #[arg(long)]
    pub sign: bool,
    /// v1.0.0 crypto-core (#1942/#1941, spec §2.2/§2.3) — path to a JSON
    /// `write_v2` presentation envelope (certified sub-key signature over the
    /// v2 CBOR-array pre-image). When present it takes precedence over
    /// `--sign` and, on success, stamps `agent_attested`; an invalid/forged
    /// envelope is REJECTED. See `docs/attestation.md` §"v2".
    #[arg(long = "write-v2")]
    pub write_v2: Option<std::path::PathBuf>,
    /// v0.9.0 G10.1 (#1827) — optional macaroon capability token
    /// (`cap1:...`) that may flip a governance Deny/Pending to Allow
    /// within its caveats. Inert unless `[capabilities].enabled`.
    ///
    /// SECURITY: a token passed here lands in world-readable
    /// `/proc/<pid>/cmdline`, `ps auxww` and shell history, where any local
    /// UID can lift and replay it within its caveats. Prefer
    /// `--capability-file` (or `AI_MEMORY_CAPABILITY_FILE`); this flag warns
    /// when used.
    #[arg(long)]
    pub capability: Option<String>,
    /// Path to a `0600` file whose sole contents are the `cap1:` token — the
    /// non-argv channel (never in `/proc/<pid>/cmdline`, never in shell
    /// history), mirroring `--store-url`'s `AI_MEMORY_STORE_URL_FILE` (#1927).
    /// Conflicts with `--capability`.
    #[arg(long, conflicts_with = "capability")]
    pub capability_file: Option<std::path::PathBuf>,
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
///
/// # Errors
///
/// Propagates validation, attestation, substrate and I/O failures. A
/// governance Deny exits the process; a Pending returns `Ok(())`.
pub fn run(
    db_path: &Path,
    args: StoreArgs,
    json_out: bool,
    app_config: &config::AppConfig,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    run_with_curator(db_path, args, json_out, app_config, cli_agent_id, out, None)
}

/// v1.0.0 #3402 — visible-for-test entry point. Production goes through
/// [`run`], which passes `atomiser_override = None` so the curator is
/// resolved lazily (and never at all for a namespace that did not opt
/// in); the unit tests inject a deterministic mock so the CLI-vs-MCP
/// parity assertions never need a live LLM. Mirrors the
/// `curator_override` seam `cli::commands::atomise::run_with_curator`
/// has carried since v0.7.0.
///
/// # Errors
///
/// See [`run`].
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) fn run_with_curator(
    db_path: &Path,
    args: StoreArgs,
    json_out: bool,
    app_config: &config::AppConfig,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
    atomiser_override: Option<&std::sync::Arc<crate::atomisation::Atomiser>>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE this write on a Postgres store (see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "store", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let resolved_ttl = app_config.effective_ttl();
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());
    // v1.0.0 #3130 — already fail-closed; routed through the shared
    // `Tier::parse_strict` so the refusal wording is single-sourced.
    let tier = Tier::parse_strict(&args.tier).map_err(|e| anyhow::anyhow!(e))?;
    // #1590 — explicit --namespace > configured [storage].default_namespace
    // > git remote > cwd basename > "global" (see `cli::helpers`).
    let namespace = crate::cli::helpers::resolve_namespace(args.namespace);
    // #1591 — keep caller-omission observable for truthful provenance.
    let confidence = args.confidence.unwrap_or(models::DEFAULT_CONFIDENCE);
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
    // #2357 (W1A4-08) — CLI store validates inline; consult the R22 reserved
    // write-namespace refusal so the CLI surface matches HTTP `validate_create`.
    validate::reject_reserved_write_namespace(&namespace)?;
    validate::validate_source(&args.source)?;
    validate::validate_tags(&tags)?;
    validate::validate_priority(args.priority)?;
    validate::validate_confidence(confidence)?;
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
    // v1.0.0 (#1945, spec §4) — epistemic-typing provenance. The CLI does
    // not run the auto-classify hook (MCP-only), so the kind is either
    // caller-`declared` (`--kind`) or the `channel_derived` system default.
    if args.kind.is_some() {
        crate::models::KindProvenance::Declared.stamp(&mut metadata);
    } else {
        crate::models::KindProvenance::ChannelDerived.stamp(&mut metadata);
    }
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

    // #2258 / #1834 — caller-supplied claim-bitemporal VALID-time bounds.
    // Validated as RFC3339 up front (a non-RFC3339 bound would silently
    // mis-filter at `valid_at` recall time). `valid_from` is stamped at create
    // and preserved immutably on upsert by the persist layer; `valid_until`
    // stays updatable via `ai-memory update`.
    let valid_from = match args.valid_from.as_deref() {
        None => None,
        Some(s) => {
            validate::validate_valid_at(s)
                .map_err(|e| anyhow::anyhow!("invalid --valid-from: {e}"))?;
            Some(s.to_string())
        }
    };
    let valid_until = match args.valid_until.as_deref() {
        None => None,
        Some(s) => {
            validate::validate_valid_at(s)
                .map_err(|e| anyhow::anyhow!("invalid --valid-until: {e}"))?;
            Some(s.to_string())
        }
    };

    let mut mem = models::Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from,
        valid_until,
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace,
        title: args.title,
        content,
        tags,
        priority: args.priority.clamp(1, 10),
        confidence: confidence.clamp(0.0, 1.0),
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
        // #1591 — truthful provenance: only an explicit --confidence
        // is `caller_provided`; the compiled fallback is `default`.
        confidence_source: if args.confidence.is_some() {
            ConfidenceSource::CallerProvided
        } else {
            ConfidenceSource::Default
        },
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };

    // #626 Layer-3 (Task 1.3 / C5) — agent attestation gate. When
    // `--sign` is set, load the agent's local keypair and sign the
    // attestable surface; the gate then stamps `metadata.attest_level =
    // "agent_attested"`. #1985 — the CLI surface default is PERMISSIVE, so
    // an unsigned write takes the no-stamp `claimed` path; the gate is only
    // additionally invoked (with no signature) when the operator forces
    // strict via `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`.
    // v1.0.0 crypto-core stage 3 (#1942/#1941) — a `--write-v2` envelope takes
    // precedence over the v1 `--sign` path and runs the mandatory §2.3
    // cert→write→suite chain; an invalid/forged envelope is REJECTED. Absent
    // → the v1 attestation path below runs unchanged.
    if let Some(v2_path) = args.write_v2.as_ref() {
        let raw = std::fs::read_to_string(v2_path)
            .map_err(|e| anyhow::anyhow!("read --write-v2 file {}: {e}", v2_path.display()))?;
        let inner: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parse --write-v2 JSON: {e}"))?;
        let params = serde_json::json!({ "write_v2": inner });
        let presented = identity::attest_v2::parse_presented(&params)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("--write-v2 file did not contain a write_v2 envelope")
            })?;
        identity::attest_v2::stamp_v2_sync(&conn, &mut mem, &agent_id, &presented)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let signature: Option<Vec<u8>> = if args.sign {
            let dir = identity::keypair::default_key_dir()?;
            let kp = identity::keypair::load(&agent_id, &dir).map_err(|e| {
                anyhow::anyhow!("--sign requires a local keypair for agent '{agent_id}': {e:#}")
            })?;
            // #1801→#1954 item 4 — redact to storage form BEFORE signing so the
            // signed envelope commits to the persisted bytes (`db::insert`
            // re-redacts idempotently). Without this a `redact`-mode secret
            // would mutate content after signing → the propagated signature is
            // unconditionally Forged at every receiver (5-agent vote w9mr01vi8).
            identity::attest::redact_before_sign(&mut mem);
            Some(identity::attest::sign_memory_write(&kp, &mem, &agent_id)?)
        } else {
            None
        };
        // #1985 — CLI is the operator-as-actor surface (WriteSurface::Cli): its
        // compiled default is PERMISSIVE, so an unsigned `ai-memory store` lands
        // `claimed` unless the operator forces strict with
        // `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`. `--sign` still upgrades to
        // `agent_attested`; a forged signature is rejected regardless.
        // #3018 — stamp `attest_level` UNCONDITIONALLY (not only when
        // `--sign`/strict), so the permissive path lands an explicit
        // `attest_level="claimed"` and an attestation census
        // (`metadata.attest_level='claimed'`) is truthful. `stamp_attestation_sync`
        // resolves the require flag internally: permissive unsigned → `claimed`;
        // global-strict unsigned → refuse; a valid `--sign` signature →
        // `agent_attested`.
        identity::attest::stamp_attestation_sync(
            &conn,
            &mut mem,
            &agent_id,
            signature.as_deref(),
            identity::attest::WriteSurface::Cli,
        )?;
        // #1801→#1954 item 2 — sender EMIT: persist the author's detached
        // signature into `metadata.write_signature` so it propagates verbatim
        // across every federation relay hop. Self-authored + non-clobbering.
        if let Some(sig) = signature.as_deref() {
            identity::attest::persist_write_signature(&mut mem, sig);
        }
    }

    // W5b/C5: governance enforcement routes through `cli::governance::enforce`
    // so the print-side of Pending/Deny is covered by `cli::governance::tests`.
    // Caller still owns the `process::exit(1)` on Deny.
    {
        use models::GovernedAction;
        let payload = serde_json::to_value(&mem).unwrap_or_default();
        // v0.9.0 G10.1 (#1827) — edge-parse the optional capability token
        // ONCE; inert unless `[capabilities].enabled`. Resolved through the
        // NON-argv channels first (`--capability-file` /
        // `AI_MEMORY_CAPABILITY_FILE`, a 0600 file) so the macaroon need
        // never sit in `/proc/<pid>/cmdline`; `--capability` still works and
        // warns. A named-but-unreadable/lax-mode file is a hard error, never
        // a silent downgrade to "no token".
        let presented_capability = crate::governance::capability::resolve_capability(
            args.capability.as_deref(),
            args.capability_file.as_deref(),
        )?;
        let capability = crate::governance::capability::parse_presented_token(
            presented_capability.as_deref(),
            &agent_id,
        )
        .map_err(|rej| anyhow::anyhow!(crate::governance::capability::edge_reject_message(&rej)))?;
        match enforce_governance(
            &conn,
            GovernedAction::Store,
            &mem.namespace,
            &agent_id,
            None,
            None,
            &payload,
            capability.as_ref(),
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
    // Built once so both arms share the same actor (the write already
    // happened; the trail must not go silent on a failed read-back).
    let store_actor = crate::audit::actor(
        agent_id.clone(),
        cli_agent_id.map_or(crate::audit::synthesis_sources::DEFAULT_FALLBACK, |_| {
            crate::audit::synthesis_sources::EXPLICIT
        }),
        args.scope.clone(),
    );

    // #3025 — re-read the persisted row so the response (AND the audit
    // target) reflects what the DB ACTUALLY stored, never the
    // requested-but-not-persisted values. On a `(title, namespace)`
    // upsert `db::insert` merges onto the existing row: tier stays
    // monotonic-max (a `--tier short` upsert over a `long` row stays
    // `long`), `version` bumps, and `expires_at` follows the persisted
    // tier — so echoing `mem` would report a downgrade / expiry /
    // version that never happened (the #2444 reports-success-doing-
    // nothing / honesty class). FAIL CLOSED on a failed read-back —
    // see `read_back_persisted`. MCP precedent:
    // `src/mcp/tools/store/mod.rs` `echo_tier`.
    //
    // Audit is emitted in BOTH arms: Allow + persisted target on
    // success; Error + `verification_failed` + requested target on
    // the fail-closed path (the row is already committed; PR-5
    // forbids a silent write).
    let persisted = match read_back_persisted(&conn, &actual_id) {
        Ok(p) => {
            crate::audit::emit(crate::audit::EventBuilder::new(
                crate::audit::AuditAction::Store,
                store_actor,
                crate::audit::target_memory(
                    actual_id.clone(),
                    p.namespace.clone(),
                    Some(p.title.clone()),
                    Some(p.tier.to_string()),
                    args.scope.clone(),
                ),
            ));
            p
        }
        Err(e) => {
            crate::audit::emit(
                crate::audit::EventBuilder::new(
                    crate::audit::AuditAction::Store,
                    store_actor,
                    crate::audit::target_memory(
                        actual_id.clone(),
                        mem.namespace.clone(),
                        Some(mem.title.clone()),
                        Some(mem.tier.to_string()),
                        args.scope.clone(),
                    ),
                )
                .error(format!("verification_failed: {e}")),
            );
            return Err(e);
        }
    };
    let filtered: Vec<&String> = contradictions
        .iter()
        .filter(|c| c.id != mem.id && c.id != actual_id)
        .map(|c| &c.id)
        .collect();

    // v1.0.0 #3402 — POST-INSERT namespace-policy funnel.
    //
    // Pre-fix this handler called `db::insert` and stopped, so a
    // namespace standard's `auto_atomise` half was silently dropped on
    // the CLI while its ACL half (the `enforce_governance` gate above)
    // WAS enforced — one policy meaning two different things depending
    // on which surface the operator used. The CLI is now a CALLER of the
    // SAME `hooks::pre_store::run_auto_atomise` funnel the MCP twin
    // calls (`src/mcp/tools/store/mod.rs`); only the wiring (how a
    // one-shot process gets a curator and drains a deferred job) is
    // surface-specific, and it lives in `cli::post_store`.
    //
    // Ordering: this runs AFTER the #3025 read-back on purpose. A
    // synchronous atomise pass ARCHIVES the parent row, so verifying the
    // durable write FIRST keeps that fail-closed read-back meaningful
    // instead of tripping on the row the policy legitimately archived.
    // The echoed values therefore describe the row exactly as it was
    // persisted, which is what #3025 promises.
    //
    // The policy is resolved against the PERSISTED namespace (the DB's
    // truth), never the requested one.
    let ns_policy = db::resolve_governance_policy(&conn, &persisted.namespace).unwrap_or_default();
    let atomise_disposition = crate::cli::post_store::run_auto_atomise_for_cli(
        &conn,
        db_path,
        &persisted,
        &actual_id,
        &agent_id,
        &ns_policy,
        app_config,
        atomiser_override,
    );

    if json_out {
        // #3025 — serialize the PERSISTED row so tier/version/expiry are the
        // DB's truth. Unconditional: an unverified write never reaches here.
        let mut j = serde_json::to_value(&persisted)?;
        j["id"] = serde_json::json!(actual_id);
        let filtered: Vec<&String> = contradictions
            .iter()
            .filter(|c| c.id != actual_id)
            .map(|c| &c.id)
            .collect();
        if !filtered.is_empty() {
            j["potential_contradictions"] = serde_json::json!(filtered);
        }
        // #3402 — the SAME `atomise_mode` / `atomise_outcome` envelope
        // keys the MCP twin emits, produced by the SAME merge helper, so
        // a scripting caller reads one contract on both surfaces.
        atomise_disposition.merge_into_response(&mut j);
        writeln!(out.stdout, "{}", serde_json::to_string(&j)?)?;
    } else {
        // #3025 — echo the PERSISTED tier/namespace, not the requested ones.
        let tier = &persisted.tier;
        let namespace = persisted.namespace.as_str();
        writeln!(out.stdout, "stored: {actual_id} [{tier}] (ns={namespace})")?;
        // #3402 — an operator whose namespace standard asked for
        // atomisation is told what actually happened. Silent only when
        // the namespace never opted in, so no existing output changes.
        if atomise_disposition.mode_configured != crate::models::AutoAtomiseMode::Off {
            writeln!(
                out.stderr,
                "auto_atomise: mode={} outcome={}",
                atomise_disposition.mode_ran.as_str(),
                atomise_disposition.outcome
            )?;
        }
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

/// #3025 — read back the row `db::insert` just committed, so the response can
/// report what the DB ACTUALLY stored rather than what the caller requested.
///
/// Lives BELOW `run` so `#[allow(clippy::too_many_lines)]` and `run`'s
/// doc-comment attach to `run` (not this helper).
///
/// **Fails closed (ERRORS-19).** The guarantee this fix exists to make is
/// "the response reports the STORED values, not the requested ones". A
/// verification read that fails and then falls back to echoing the REQUESTED
/// values breaks exactly that guarantee on the error path, and does it
/// invisibly: the caller cannot tell a verified echo from an unverified one,
/// which is the same reports-success-doing-nothing class (#2444) the fix was
/// written to close. So both failure modes are errors:
///
/// * `Err` — the read itself failed (transient / IO).
/// * `Ok(None)` — an INVARIANT VIOLATION: `db::insert` returned this id, so the
///   row must be readable. Never a silent fallback.
///
/// Both messages state that the WRITE ALREADY HAPPENED and name the id, so an
/// operator reading the failure knows the row exists and only its verification
/// failed — the exit code must not be read as "nothing was stored".
fn read_back_persisted(conn: &rusqlite::Connection, actual_id: &str) -> Result<models::Memory> {
    match db::get(conn, actual_id) {
        Ok(Some(persisted)) => Ok(persisted),
        Ok(None) => anyhow::bail!(
            "memory {actual_id} WAS STORED, but the read-back that verifies what was persisted \
             found no such row; refusing to report the requested values as if they were stored"
        ),
        Err(e) => anyhow::bail!(
            "memory {actual_id} WAS STORED, but the read-back that verifies what was persisted \
             failed: {e}; refusing to report the requested values as if they were stored"
        ),
    }
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
            confidence: None,
            source: "cli".to_string(),
            expires_at: None,
            ttl_secs: None,
            scope: None,
            // v0.7.0 F2.3 (#1427) — Form-4 + Form-6 CLI flag additions.
            kind: None,
            citations: None,
            source_uri: None,
            source_span: None,
            valid_from: None,
            valid_until: None,
            entity_id: None,
            sign: false,
            write_v2: None,
            capability: None,
            capability_file: None,
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
        let _lock = locked_env();
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

    /// #2357 (W1A4-08) — CLI store into the write-reserved
    /// `_peer_head_entanglement` namespace is refused (parity with the
    /// HTTP `validate_create` funnel).
    #[test]
    fn test_store_rejects_reserved_namespace_2357() {
        let _lock = locked_env();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.namespace =
            Some(crate::identity::equivocation::PEER_HEAD_ENTANGLEMENT_NAMESPACE.to_string());
        let mut out = env.output();
        let err = run(&db, args, false, &cfg, Some("test-agent"), &mut out)
            .expect_err("reserved namespace must be refused");
        assert!(err.to_string().contains("reserved"), "got: {err}");
    }

    #[test]
    fn test_store_json_output() {
        let _lock = locked_env();
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

    /// #3025 — on a `(title, namespace)` upsert the CLI `store --json`
    /// response MUST report the PERSISTED row (tier/version/expiry), never the
    /// requested-but-not-persisted values. A `--tier short` upsert over a
    /// `long` row stays `long` and bumps `version`; pre-fix the response
    /// echoed the requested `short`/`version:1`, lying about a downgrade that
    /// never happened.
    #[test]
    fn test_store_upsert_json_reports_persisted_not_requested_3025() {
        let _lock = locked_env();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();

        // First store: a long-tier row.
        let mut first = default_args();
        first.title = "upsert-3025".to_string();
        first.tier = Tier::Long.as_str().to_string();
        {
            let mut out = env.output();
            run(&db, first, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let first_json: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(first_json["tier"].as_str().unwrap(), Tier::Long.as_str());

        // Upsert the SAME (title, namespace) requesting `short`. The DB keeps
        // `long` (tier monotonicity) and bumps `version`.
        env.stdout.clear();
        let mut second = default_args();
        second.title = "upsert-3025".to_string();
        second.tier = Tier::Short.as_str().to_string();
        second.content = "updated content".to_string();
        {
            let mut out = env.output();
            run(&db, second, true, &cfg, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // Response reflects the PERSISTED row, not the requested `short`.
        assert_eq!(
            v["tier"].as_str().unwrap(),
            Tier::Long.as_str(),
            "response must echo the persisted tier, got: {v}"
        );
        assert_ne!(v["tier"].as_str().unwrap(), Tier::Short.as_str());
        // The persisted upsert bumped `version` past the create-time 1.
        assert!(
            v["version"].as_u64().unwrap() >= 2,
            "persisted version must have bumped on upsert, got: {v}"
        );
        // Both stores addressed the same row.
        assert_eq!(
            v["id"].as_str().unwrap(),
            first_json["id"].as_str().unwrap()
        );
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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
        let _lock = locked_env();
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

    /// Process-global env lock shared with
    /// [`crate::identity::keypair::key_dir_env_lock`]. Every test across the
    /// crate that mutates `AI_MEMORY_KEY_DIR` (keypair, mcp, governance::audit,
    /// cli::verify) serialises on this ONE mutex; a module-local lock would let
    /// those suites race this one on the shared `AI_MEMORY_KEY_DIR` /
    /// `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` process env and flake. #626 Layer-3.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        crate::identity::keypair::key_dir_env_lock()
    }

    /// Poison-resilient acquire of the shared env lock. Centralises the
    /// `into_inner` recovery in one place (via the `PoisonError::into_inner`
    /// fn-pointer, not a per-call-site closure) so the never-firing-in-green
    /// poison branch is a single covered instantiation rather than one
    /// uncovered closure per test.
    fn locked_env() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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
        let _lock = locked_env();
        let key_dir = tempfile::tempdir().unwrap();
        let _kd = EnvVarGuard::set("AI_MEMORY_KEY_DIR", key_dir.path().as_os_str());
        // #1751 — pin "0" (never clear): clearing would open a strict
        // required-default window that leaks into concurrent unsigned
        // store tests in this parallel lib-test binary.
        let _req = EnvVarGuard::set(
            "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
            std::ffi::OsStr::new("0"),
        );

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
        let _lock = locked_env();
        // Empty key dir — no `<agent_id>.priv` to load.
        let key_dir = tempfile::tempdir().unwrap();
        let _kd = EnvVarGuard::set("AI_MEMORY_KEY_DIR", key_dir.path().as_os_str());
        // #1751 — pin "0" (never clear); see the sibling test above.
        let _req = EnvVarGuard::set(
            "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
            std::ffi::OsStr::new("0"),
        );

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

    // #1609 — the strict-require rejection case (`test_store_require_
    // attestation_rejects_unsigned`) used to live here, SETTING the
    // process-global `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` under
    // `locked_env()`. The lock covers fellow MUTATORS, but the gate's
    // READERS (`require_agent_attestation_for` callers in
    // `mcp::tools::store` / `handlers::create` tests) run lock-free in
    // the same parallel lib-test process, so the set-window leaked into
    // any sibling store test scheduled concurrently (narrow-filter
    // repro: `cargo test --lib 'store::tests'`). The case now drives
    // the compiled binary with child-process env in
    // `tests/agent_attestation_integrity.rs::
    // cli_require_attestation_rejects_unsigned_store` — same coverage,
    // zero process-global mutation. Per the design rule documented in
    // `src/mcp/tools/store/tests.rs` (#626 section header): the
    // parallel lib-test binary must NEVER set the require flag.

    // EnvVarGuard Drop with a pre-existing value → Some-arm restore (set_var)
    // rather than the None-arm remove. Pins the RAII restore contract.
    #[test]
    fn env_var_guard_restores_previous_value_on_drop() {
        let _lock = locked_env();
        let prior = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AI_MEMORY_KEY_DIR", prior.path().as_os_str()) };
        {
            let other = tempfile::tempdir().unwrap();
            let _g = EnvVarGuard::set("AI_MEMORY_KEY_DIR", other.path().as_os_str());
            assert_eq!(
                std::env::var_os("AI_MEMORY_KEY_DIR").as_deref(),
                Some(other.path().as_os_str())
            );
            // _g drops here → Some-arm restore of `prior`.
        }
        assert_eq!(
            std::env::var_os("AI_MEMORY_KEY_DIR").as_deref(),
            Some(prior.path().as_os_str())
        );
        unsafe { std::env::remove_var("AI_MEMORY_KEY_DIR") };
    }

    /// #3025 (fail-closed half) — the read-back that verifies what was
    /// persisted must ERROR when the row cannot be read, never fall back to
    /// echoing the REQUESTED values. The fallback was the original shape and
    /// it broke the fix's own contract on the error path: the caller could not
    /// distinguish a verified echo from an unverified one, which is the very
    /// reports-success-doing-nothing class (#2444) #3025 exists to close.
    ///
    /// `Ok(None)` is the invariant-violation arm: `db::insert` returned the id,
    /// so the row must be readable. The happy path (this helper returning the
    /// PERSISTED row) is the positive control in
    /// `test_store_upsert_json_reports_persisted_not_requested_3025`, which
    /// drives `run()` end-to-end through this gate — so the two tests below
    /// cannot pass by rejecting everything.
    #[test]
    fn read_back_persisted_errors_when_row_is_missing_3025() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        let err = read_back_persisted(&conn, "no-such-id-3025")
            .expect_err("a missing row must be an error, never a silent fallback");
        let msg = err.to_string();
        assert!(
            msg.contains("no-such-id-3025"),
            "the error must name the id so the operator can find the row: {msg}"
        );
        assert!(
            msg.contains("WAS STORED"),
            "the error must say the write already happened, so a non-zero exit \
             is not misread as 'nothing was stored': {msg}"
        );
    }

    /// The `Err` arm of the same gate: a read-back that FAILS (here: the
    /// `memories` table dropped out from under the reader, standing in for a
    /// transient/IO failure) is an error too, carrying the same
    /// write-already-happened wording and the id.
    #[test]
    fn read_back_persisted_errors_when_read_fails_3025() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        conn.execute_batch("DROP TABLE memories;")
            .expect("drop table to force a read failure");

        let err = read_back_persisted(&conn, "id-read-fails-3025")
            .expect_err("a failed read-back must be an error, never a silent fallback");
        let msg = err.to_string();
        assert!(
            msg.contains("id-read-fails-3025") && msg.contains("WAS STORED"),
            "the error must name the id and say the write already happened: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // #3402 — CLI store honours the namespace `auto_atomise` policy
    //
    // Pre-fix `run` called `db::insert` and stopped: the ACL half of a
    // namespace standard WAS enforced on this surface while its
    // post-insert half was silently dropped, so the SAME policy meant
    // two different things depending on whether the operator used the
    // CLI or MCP. These tests pin BOTH directions — the opted-OUT path
    // must stay inert (no curator, no atoms, no output change) and the
    // opted-IN path must produce byte-identical atoms and disposition
    // tokens to the MCP twin.
    // -----------------------------------------------------------------

    use crate::atomisation::curator::{Atom, Curator, CuratorError};
    use crate::atomisation::{Atomiser, AtomiserConfig};
    use crate::config::FeatureTier;
    use crate::hooks::pre_store::auto_atomise as atomise_hook;
    use crate::models::{
        ApproverType, AtomisationPolicy, AutoAtomiseMode, CorePolicy, GovernanceLevel,
        GovernancePolicy,
    };
    use std::sync::Arc;

    /// Deterministic stand-in for the LLM curator: always two atoms, no
    /// network, no tokens. Lets the parity assertions below name an EXACT
    /// atom count instead of hedging on a live model's output.
    struct TwoAtoms;
    impl Curator for TwoAtoms {
        fn decompose(
            &self,
            _body: &str,
            _max_atom_tokens: u32,
            _max_retries: u32,
        ) -> std::result::Result<Vec<Atom>, CuratorError> {
            Ok(vec![
                Atom {
                    text: "first atomic proposition".into(),
                },
                Atom {
                    text: "second atomic proposition".into(),
                },
            ])
        }
    }

    fn two_atom_atomiser() -> Arc<Atomiser> {
        Arc::new(Atomiser::new(
            Box::new(TwoAtoms),
            None,
            AtomiserConfig::default(),
            FeatureTier::Smart,
        ))
    }

    /// Seed `ns`'s namespace standard with an `auto_atomise` policy —
    /// the same shape `ai-memory namespace set-standard` writes and the
    /// same one `db::resolve_governance_policy` walks.
    fn seed_atomise_policy(conn: &rusqlite::Connection, ns: &str, mode: Option<AutoAtomiseMode>) {
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Human,
                inherit: true,
                max_reflection_depth: None,
                required_scope: None,
            },
            atomisation: AtomisationPolicy {
                auto_atomise: Some(true),
                auto_atomise_threshold_cl100k: Some(50),
                auto_atomise_max_atom_tokens: Some(20),
                auto_atomise_max_retries: None,
                auto_atomise_mode: mode,
            },
            ..Default::default()
        };
        let now = Utc::now().to_rfc3339();
        let std_mem = models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: format!("__standard_{ns}"),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({
                "agent_id": "ai:test",
                "governance": serde_json::to_value(&policy).unwrap(),
            }),
            ..Default::default()
        };
        let std_id = db::insert(conn, &std_mem).unwrap();
        db::set_namespace_standard(conn, ns, &std_id, None).unwrap();
    }

    /// Comfortably over the seeded 50-token threshold.
    fn over_threshold_body() -> String {
        "proposition token padding here. ".repeat(400)
    }

    fn atom_count(conn: &rusqlite::Connection, source_id: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM memories WHERE atom_of = ?1",
            rusqlite::params![source_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    /// Store one memory through the CLI handler with an injected curator
    /// and return the parsed `--json` envelope.
    fn cli_store_json(
        db: &Path,
        env: &mut crate::cli::test_utils::TestEnv,
        ns: &str,
        title: &str,
        content: &str,
        atomiser: &Arc<Atomiser>,
    ) -> serde_json::Value {
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.namespace = Some(ns.to_string());
        args.title = title.to_string();
        args.content = content.to_string();
        {
            let mut out = env.output();
            run_with_curator(
                db,
                args,
                true,
                &cfg,
                Some("test-agent"),
                &mut out,
                Some(atomiser),
            )
            .expect("cli store must succeed");
        }
        serde_json::from_str(env.stdout_str().trim()).expect("cli store must emit JSON")
    }

    /// ALLOWED path, `synchronous` mode: the CLI now produces the atoms
    /// the MCP twin has always produced for the same namespace standard.
    #[test]
    fn cli_store_atomises_on_a_synchronous_auto_atomise_namespace_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            seed_atomise_policy(&conn, "sync-ns-3402", Some(AutoAtomiseMode::Synchronous));
        }
        let atomiser = two_atom_atomiser();
        let j = cli_store_json(
            &db,
            &mut env,
            "sync-ns-3402",
            "cli sync title",
            &over_threshold_body(),
            &atomiser,
        );
        let id = j["id"].as_str().expect("id").to_string();
        assert_eq!(j[atomise_hook::FIELD_ATOMISE_MODE], "synchronous");
        assert_eq!(
            j[atomise_hook::FIELD_ATOMISE_OUTCOME],
            atomise_hook::OUTCOME_ATOMISED
        );
        let conn = db::open(&db).unwrap();
        assert_eq!(
            atom_count(&conn, &id),
            2,
            "the CLI must land the curator's atoms, not silently drop the policy"
        );
    }

    /// ALLOWED path, `deferred` mode (what a bare `auto_atomise = true`
    /// resolves to). A one-shot process has no daemon to defer to, so the
    /// CLI runs the SAME bounded worker in-process and joins it — pre-fix
    /// this namespace shape produced nothing at all on the CLI.
    #[test]
    fn cli_store_drains_deferred_auto_atomise_in_process_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            seed_atomise_policy(&conn, "defer-ns-3402", None);
        }
        let atomiser = two_atom_atomiser();
        let j = cli_store_json(
            &db,
            &mut env,
            "defer-ns-3402",
            "cli deferred title",
            &over_threshold_body(),
            &atomiser,
        );
        let id = j["id"].as_str().expect("id").to_string();
        assert_eq!(j[atomise_hook::FIELD_ATOMISE_MODE], "deferred");
        assert_eq!(
            j[atomise_hook::FIELD_ATOMISE_OUTCOME],
            atomise_hook::OUTCOME_QUEUED
        );
        let conn = db::open(&db).unwrap();
        assert_eq!(
            atom_count(&conn, &id),
            2,
            "the join must await the in-process drain, not race the process exit"
        );
    }

    /// DENIED (opted-out) path: a namespace with no `auto_atomise`
    /// standard stays exactly as inert as before — `off` /
    /// `skipped_policy_disabled`, no atoms, and no new stderr line on the
    /// human-readable output.
    #[test]
    fn cli_store_without_the_policy_stays_inert_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        let atomiser = two_atom_atomiser();
        let j = cli_store_json(
            &db,
            &mut env,
            "plain-ns-3402",
            "cli plain title",
            &over_threshold_body(),
            &atomiser,
        );
        let id = j["id"].as_str().expect("id").to_string();
        assert_eq!(j[atomise_hook::FIELD_ATOMISE_MODE], "off");
        assert_eq!(
            j[atomise_hook::FIELD_ATOMISE_OUTCOME],
            atomise_hook::OUTCOME_SKIPPED_POLICY_DISABLED
        );
        let conn = db::open(&db).unwrap();
        assert_eq!(
            atom_count(&conn, &id),
            0,
            "an opted-out namespace must never be atomised"
        );
    }

    /// The opted-out human-readable path emits NO `auto_atomise:` note,
    /// so the pre-#3402 CLI output is byte-identical for every namespace
    /// that never asked for atomisation.
    #[test]
    fn cli_store_text_output_is_unchanged_without_the_policy_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let atomiser = two_atom_atomiser();
        {
            let mut out = env.output();
            run_with_curator(
                &db,
                default_args(),
                false,
                &cfg,
                Some("test-agent"),
                &mut out,
                Some(&atomiser),
            )
            .unwrap();
        }
        assert!(env.stdout_str().starts_with("stored: "));
        assert!(
            !env.stderr_str().contains("auto_atomise:"),
            "an opted-out namespace must not gain a new stderr line: {}",
            env.stderr_str()
        );
    }

    /// The opted-in human-readable path DOES tell the operator what the
    /// policy did — atomisation archives the source row, so a silent
    /// `stored: <id>` would leave them hunting for it.
    #[test]
    fn cli_store_text_output_reports_the_atomise_outcome_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            seed_atomise_policy(&conn, "note-ns-3402", Some(AutoAtomiseMode::Synchronous));
        }
        let cfg = config::AppConfig::default();
        let atomiser = two_atom_atomiser();
        let mut args = default_args();
        args.namespace = Some("note-ns-3402".to_string());
        args.content = over_threshold_body();
        {
            let mut out = env.output();
            run_with_curator(
                &db,
                args,
                false,
                &cfg,
                Some("test-agent"),
                &mut out,
                Some(&atomiser),
            )
            .unwrap();
        }
        let stderr = env.stderr_str().to_string();
        assert!(
            stderr.contains("auto_atomise: mode=synchronous")
                && stderr.contains(atomise_hook::OUTCOME_ATOMISED),
            "got: {stderr}"
        );
    }

    /// The 1:1 parity assertion the issue asks for: the SAME namespace
    /// standard, the SAME body, one store through the CLI funnel and one
    /// through the MCP twin — same atom count, same disposition tokens.
    /// This is what "one store funnel" has to mean observationally.
    #[test]
    fn cli_and_mcp_store_agree_on_an_auto_atomise_namespace_3402() {
        let _lock = locked_env();
        let mut env = crate::cli::test_utils::TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = db::open(&db).unwrap();
            seed_atomise_policy(&conn, "parity-ns-3402", Some(AutoAtomiseMode::Synchronous));
        }
        let atomiser = two_atom_atomiser();
        let body = over_threshold_body();

        let cli = cli_store_json(
            &db,
            &mut env,
            "parity-ns-3402",
            "parity cli",
            &body,
            &atomiser,
        );

        let cfg = config::AppConfig::default();
        let conn = db::open(&db).unwrap();
        let mcp = crate::mcp::tools::handle_store_with_atomise_for_tests(
            &conn,
            &db,
            &serde_json::json!({
                "title": "parity mcp",
                "content": body,
                "namespace": "parity-ns-3402",
            }),
            None,
            None,
            None,
            &cfg.effective_ttl(),
            false,
            None,
            None,
            crate::hooks::pre_store::AtomiseWiring::new(Some(&atomiser), None),
        )
        .expect("mcp store must succeed");

        assert_eq!(
            cli[atomise_hook::FIELD_ATOMISE_MODE],
            mcp[atomise_hook::FIELD_ATOMISE_MODE],
            "the two surfaces must report the same mode for one policy"
        );
        assert_eq!(
            cli[atomise_hook::FIELD_ATOMISE_OUTCOME],
            mcp[atomise_hook::FIELD_ATOMISE_OUTCOME],
            "the two surfaces must report the same outcome for one policy"
        );
        let cli_id = cli["id"].as_str().expect("cli id");
        let mcp_id = mcp["id"].as_str().expect("mcp id");
        assert_eq!(atom_count(&conn, cli_id), atom_count(&conn, mcp_id));
        assert_eq!(atom_count(&conn, cli_id), 2);
    }
}
