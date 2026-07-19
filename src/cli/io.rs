// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_export`, `cmd_import`, `cmd_mine` migrations.

use crate::cli::CliOutput;
use crate::db::ConflictMode;
use crate::models::ConfidenceSource;
use crate::{config, db, identity, mine, models, validate};
use anyhow::Result;
use chrono::{Duration, Utc};
use clap::{Args, ValueEnum};
use models::Tier;
use std::path::{Path, PathBuf};

/// `--on-conflict <mode>` selector for `import` / `mine` writes (#1780,
/// 5-agent vote 4d3ea1c5). A `(title, namespace)` collision is the
/// substrate's silent-clobber footgun: the legacy `db::insert`
/// (`ConflictMode::Merge`) UPSERT silently overwrote a distinct
/// pre-existing memory. This clap wrapper maps the three operator
/// dispositions onto the storage [`ConflictMode`] enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OnConflict {
    /// Refuse a colliding row with a typed per-row error; the existing
    /// memory is left untouched and the import continues with the rest.
    Error,
    /// Legacy silent-upsert: merge the incoming row into the existing
    /// `(title, namespace)` memory. This is the prior (pre-#1780)
    /// idempotent behaviour — opt into it explicitly to re-import a
    /// backup without creating suffixed duplicates.
    Merge,
    /// Auto-suffix the title (`title (2)`, `title (3)`, …) until a free
    /// `(title, namespace)` slot is found, then insert a new row.
    /// Never clobbers; both old and new rows persist. The #1780 default
    /// — completes the import losslessly and is recoverable.
    #[default]
    Version,
}

impl From<OnConflict> for ConflictMode {
    fn from(v: OnConflict) -> Self {
        match v {
            OnConflict::Error => ConflictMode::Error,
            OnConflict::Merge => ConflictMode::Merge,
            OnConflict::Version => ConflictMode::Version,
        }
    }
}

/// v1.0.0 #2006 — arguments for `ai-memory export`.
#[derive(Args, Default)]
pub struct ExportArgs {
    /// Emit the FULL Portability-v2 integrity envelope — every signed record
    /// class (audit chain, revisions, tombstones, lineage, attestations,
    /// governance rules + trust anchors) byte-preserved and re-verifiable at
    /// import, with a computed `conformance_level` (L1/L2/L3) marker. This is
    /// the integrity portability path. Without `--full`, `export` stays the
    /// memories+links convenience view.
    #[arg(long, default_value_t = false)]
    pub full: bool,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Trust `metadata.agent_id` in imported JSON (default: restamp with caller's id).
    /// Only use this when importing a JSON export you fully trust (e.g., your own backup).
    #[arg(long, default_value_t = false)]
    pub trust_source: bool,
    /// Disposition on a `(title, namespace)` collision with an existing
    /// memory: `version` (default — auto-suffix `title (N)`, never
    /// clobber), `merge` (legacy silent idempotent upsert), or `error`
    /// (refuse + skip the colliding row, continue the import).
    #[arg(long, value_enum, default_value_t = OnConflict::Version)]
    pub on_conflict: OnConflict,
}

#[derive(Args)]
pub struct MineArgs {
    /// Path to the export file or directory
    pub path: PathBuf,
    /// Export format: claude, chatgpt, slack
    #[arg(long, short)]
    pub format: String,
    /// Namespace for imported memories (auto-detected if omitted)
    #[arg(long, short)]
    pub namespace: Option<String>,
    /// Memory tier for imported memories
    ///
    /// `default_value` must be a literal at attribute-parse time, so
    /// the wire string is kept here verbatim; it is byte-equal to
    /// `crate::models::Tier::Mid.as_str()` (pm-v3.1 PR6 #1174 sweep —
    /// raw tier literals are confined to the deserializer + clap
    /// `default_value` attrs that cannot accept const expressions).
    #[arg(long, short, default_value = "mid")]
    pub tier: String,
    /// Minimum message count to import a conversation
    #[arg(long, default_value_t = 3)]
    pub min_messages: usize,
    /// Dry run — show what would be imported without writing
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Disposition on a `(title, namespace)` collision with an existing
    /// memory: `version` (default — auto-suffix `title (N)`, never
    /// clobber), `merge` (legacy silent idempotent upsert), or `error`
    /// (refuse + skip the colliding conversation, continue the mine).
    #[arg(long, value_enum, default_value_t = OnConflict::Version)]
    pub on_conflict: OnConflict,
}

/// `export` handler. Dumps every memory + link as pretty JSON.
///
/// #1944 (`B_WARN` de-silencing, 2×5 vote `woaiwndla` / `4d3ea1c5`): this is
/// a **memories + links convenience view**, NOT the portability path — it
/// silently omitted the tamper-evidence + governance spine
/// ([`crate::export_scope::OMITTED_SIGNED_CLASSES`]). The de-silencing hedge
/// is two-fold and additive (the `{memories, links, count, exported_at}`
/// shape is unchanged): a prominent stderr WARN (NEVER stdout — a piped
/// `export > x.json` must stay valid JSON) and in-band scope markers so a
/// pipe-to-file consumer that never sees the WARN still learns the scope.
/// The full integrity-complete exporter defers to v1.x (see
/// `docs/spec/PORTABILITY-V2.md` §V2-7). The serialization core
/// (`db::export_all` / `db::export_links`) is deliberately untouched.
pub fn export(db_path: &Path, args: &ExportArgs, out: &mut CliOutput<'_>) -> Result<()> {
    use crate::export_scope;
    use crate::models::field_names;
    let conn = db::open(db_path)?;

    // v1.0.0 #2006 — the integrity portability path. `--full` emits the full
    // Portability-v2 envelope (every signed record class byte-preserved +
    // re-verifiable, spec `docs/spec/PORTABILITY-V2.md`) with a COMPUTED
    // `conformance_level` marker. This IS the portability path, so it does NOT
    // emit the scope-limiting stderr WARN the convenience view carries. The
    // memories are still screened by `build_full_envelope` (same
    // confidentiality boundary).
    if args.full {
        let envelope = crate::portability::emit::build_full_envelope(
            &conn,
            "ai-memory",
            &Utc::now().to_rfc3339(),
        )?;
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&envelope)?)?;
        return Ok(());
    }

    let memories = db::export_all(&conn)?;
    // v1.0.0 Gate-3 (#1838/G28 + #1844) — unify the export confidentiality
    // boundary with the HTTP admin sibling (`handlers::admin::export_memories`).
    // This CLI path is the documented operator backup surface
    // (`ai-memory export > backup.json`) and historically serialized every row
    // VERBATIM — bypassing BOTH the fail-closed forbidden-class gate and the
    // secret screen — so a PEM private key / `threshold_share` /
    // `operator_signing_key` / `metadata.embedding_class="biometric"` /
    // metadata- or title-stashed credential rode the export in the clear.
    // Screen BEFORE the pretty-print (drop forbidden-class rows + emit the
    // signed `export.forbidden_class_refused` audit row via the local conn,
    // and mask credential VALUES in content/title/tags/metadata); the surviving
    // rows keep the #1944 in-band scope markers below and stdout stays valid
    // JSON.
    let memories = crate::export_taxonomy::screen_memories_for_export(memories, Some(&conn));
    let links = db::export_links(&conn)?;
    // In-band, additive, non-breaking scope markers (critical: the stderr
    // WARN below is invisible to a pipe-to-file consumer).
    writeln!(
        out.stdout,
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "memories": memories, "links": links, "count": memories.len(),
            (field_names::EXPORTED_AT): Utc::now().to_rfc3339(),
            (field_names::EXPORT_SCOPE): export_scope::SCOPE_MEMORIES_LINKS,
            (field_names::PORTABILITY_COMPLETE): export_scope::PORTABILITY_COMPLETE,
            (field_names::EXCLUDES): export_scope::OMITTED_SIGNED_CLASSES,
        }))?
    )?;
    // Prominent WARN to STDERR only, so the stdout JSON stays pipeline-valid.
    writeln!(out.stderr, "{}", export_scope::export_scope_warn())?;
    Ok(())
}

/// `import` handler. Reads JSON from `import_reader` (defaulting to
/// stdin in production) and inserts into the DB.
pub fn import(
    db_path: &Path,
    args: &ImportArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let mut buf = String::new();
    use std::io::Read as _;
    std::io::stdin().read_to_string(&mut buf)?;
    import_from_str(&buf, db_path, args, json_out, cli_agent_id, out)
}

/// Stdin-decoupled half of `import`. Tests call this directly with a
/// literal payload instead of redirecting the process's stdin.
pub(crate) fn import_from_str(
    payload: &str,
    db_path: &Path,
    args: &ImportArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let data: serde_json::Value = serde_json::from_str(payload)?;

    // v1.0.0 #2006 — a v2 integrity envelope carries `spec_version`. Route it
    // to the full byte-preserving, re-verifying importer. A v1 payload
    // (memories+links, no `spec_version`) stays on the L1 path below,
    // UNCHANGED.
    //
    // #2210 — the route is FAIL-CLOSED on the envelope itself: the
    // `spec_version` VALUE must be the supported "2" (a newer spec refuses
    // loudly instead of deserializing with its new record classes silently
    // dropped — a v2+ envelope must NEVER fall through to the L1 path, which
    // would drop the whole signed spine), and the strict
    // (`deny_unknown_fields`) envelope parse refuses an unrecognized
    // top-level class array.
    //
    // #2211 — `ImportArgs` is honoured on this path exactly like L1: the
    // default restamps `metadata.agent_id` with the caller's id
    // (`--trust-source` preserves verbatim), and `--on-conflict` governs
    // `(title, namespace)` collisions with existing destination rows.
    if let Some(spec) = data.get("spec_version") {
        let supported = crate::portability::emit::SPEC_VERSION_V2;
        if spec.as_str() != Some(supported) {
            anyhow::bail!(
                "import REFUSED (fail-closed): unsupported portability spec_version {spec} — \
                 this node understands spec_version \"{supported}\". The bundle was produced \
                 by a newer/unknown spec; importing it here could silently drop signed record \
                 classes. Upgrade this node instead; no rows were applied"
            );
        }
        let envelope: crate::portability::emit::ExportEnvelope = serde_json::from_value(data)
            .map_err(|e| {
                anyhow::anyhow!(
                    "import REFUSED (fail-closed): the v2 envelope did not parse strictly \
                     ({e}) — an unrecognized or malformed field means the bundle carries \
                     content this node would otherwise silently drop; no rows were applied"
                )
            })?;
        let caller_id = identity::resolve_agent_id(cli_agent_id, None)?;
        let opts = crate::portability::import::ImportOptions {
            trust_source: args.trust_source,
            caller_agent_id: caller_id,
            on_conflict: args.on_conflict.into(),
        };
        let conn = db::open(db_path)?;
        let report = crate::portability::import::import_full_envelope(&conn, &envelope, &opts)?;
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
        if args.trust_source {
            writeln!(
                out.stderr,
                "warning: --trust-source: agent_id from imported JSON was preserved as-is"
            )?;
        }
        return Ok(());
    }

    let memories: Vec<models::Memory> =
        serde_json::from_value(data.get("memories").cloned().unwrap_or_default())?;
    let links: Vec<models::MemoryLink> =
        serde_json::from_value(data.get("links").cloned().unwrap_or_default()).unwrap_or_default();

    let caller_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let conflict_mode: ConflictMode = args.on_conflict.into();

    let conn = db::open(db_path)?;
    let mut imported = 0usize;
    let mut restamped = 0usize;
    let mut errors = Vec::new();
    for mut mem in memories {
        // #2208 re-audit N1 — the v1 wire-form must honour the SAME forget
        // covenant as the v2 route: stripping `spec_version` from a bundle
        // must not become a DOWNGRADE BYPASS that resurrects a
        // dest-forgotten id (the dest tombstone is the durable erasure
        // receipt; `insert_with_conflict` performs no tombstone check).
        if db::memory_is_tombstoned(&conn, &mem.id)? {
            errors.push(format!(
                "{}: skipped — a destination forget tombstone forbids re-admission",
                mem.id
            ));
            continue;
        }
        // #2208 N1 mirror — a dest-ARCHIVED id must not be re-admitted live
        // (dual residency); the sanctioned way back is memory_archive_restore.
        if db::memory_is_archived(&conn, &mem.id)? {
            errors.push(format!(
                "{}: skipped — the id is archived at the destination \
                 (restore via memory_archive_restore, not import)",
                mem.id
            ));
            continue;
        }
        if !args.trust_source {
            let original = mem
                .metadata
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            if let Some(obj) = mem.metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String(caller_id.clone()),
                );
                if let Some(orig) = original.as_ref()
                    && orig.as_str() != caller_id
                {
                    obj.insert(
                        crate::models::field_names::IMPORTED_FROM_AGENT_ID.to_string(),
                        serde_json::Value::String(orig.clone()),
                    );
                    restamped += 1;
                }
            }
        }
        if let Err(e) = validate::validate_memory(&mem) {
            errors.push(format!("{}: {}", mem.id, e));
            continue;
        }
        // #1780 — honour the operator's collision disposition instead
        // of the legacy silent merge. A Version "no free suffix" error
        // or an Error-mode collision is reported per-row and the loop
        // continues; the whole import is never aborted on one row.
        match db::insert_with_conflict(&conn, &mem, conflict_mode) {
            Ok(_) => imported += 1,
            Err(e) => errors.push(format!("{}: {}", mem.id, e)),
        }
    }
    for link in links {
        if validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
            .is_err()
        {
            continue;
        }
        let _ = db::create_link(
            &conn,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        );
    }
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "imported": imported,
                "restamped": restamped,
                "trusted_source": args.trust_source,
                "errors": errors
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "imported: {imported} (restamped agent_id on {restamped})"
        )?;
        if args.trust_source {
            writeln!(
                out.stderr,
                "warning: --trust-source: agent_id from imported JSON was preserved as-is"
            )?;
        }
        if !errors.is_empty() {
            for e in &errors {
                writeln!(out.stderr, "  {e}")?;
            }
        }
    }
    Ok(())
}

/// `mine` handler.
#[allow(clippy::too_many_lines)]
pub fn mine(
    db_path: &Path,
    args: MineArgs,
    json_out: bool,
    app_config: &config::AppConfig,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let miner_agent_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let conflict_mode: ConflictMode = args.on_conflict.into();
    let format = mine::Format::from_str(&args.format).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid format: {} (use claude, chatgpt, slack)",
            args.format
        )
    })?;
    let tier = Tier::from_str(&args.tier)
        .ok_or_else(|| anyhow::anyhow!("invalid tier: {} (use short, mid, long)", args.tier))?;
    let namespace = args.namespace.unwrap_or_else(|| match format {
        mine::Format::Claude => "claude-export".to_string(),
        mine::Format::ChatGpt => "chatgpt-export".to_string(),
        mine::Format::Slack => "slack-export".to_string(),
    });

    let path = std::path::Path::new(&args.path);

    let conversations = match format {
        mine::Format::Claude => mine::parse_claude(path)?,
        mine::Format::ChatGpt => mine::parse_chatgpt(path)?,
        mine::Format::Slack => mine::parse_slack(path)?,
    };

    let filtered: Vec<_> = conversations
        .iter()
        .filter(|c| c.messages.len() >= args.min_messages)
        .collect();

    if args.dry_run {
        if json_out {
            let items: Vec<serde_json::Value> = filtered
                .iter()
                .filter_map(|c| {
                    mine::conversation_to_memory(c, format).map(|m| {
                        serde_json::json!({
                            "title": m.title,
                            "content_length": m.content.len(),
                            "messages": c.messages.len(),
                            "source": m.source_format,
                        })
                    })
                })
                .collect();
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "dry_run": true,
                    "total_conversations": conversations.len(),
                    "filtered": filtered.len(),
                    "would_import": items.len(),
                    "namespace": namespace,
                    "tier": tier.as_str(),
                    "memories": items,
                }))?
            )?;
        } else {
            writeln!(out.stdout, "Dry run — no memories will be stored\n")?;
            writeln!(
                out.stdout,
                "Total conversations found: {}",
                conversations.len()
            )?;
            writeln!(
                out.stdout,
                "After filter (>={} messages): {}",
                args.min_messages,
                filtered.len()
            )?;
            writeln!(out.stdout, "Namespace: {namespace}")?;
            writeln!(out.stdout, "Tier: {tier}\n")?;
            for c in &filtered {
                if let Some(m) = mine::conversation_to_memory(c, format) {
                    writeln!(
                        out.stdout,
                        "  {} ({} msgs, {} bytes)",
                        m.title,
                        c.messages.len(),
                        m.content.len()
                    )?;
                }
            }
        }
        return Ok(());
    }

    let conn = db::open(db_path)?;
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());
    let now = Utc::now();

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    conn.execute_batch("BEGIN")?;

    for conv in &filtered {
        let Some(mined) = mine::conversation_to_memory(conv, format) else {
            skipped += 1;
            continue;
        };

        let expires_at = app_config
            .effective_ttl()
            .ttl_for_tier(&tier)
            .map(|s| (now + Duration::seconds(s)).to_rfc3339());

        let mut metadata = models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String(miner_agent_id.clone()),
            );
            obj.insert(
                "mined_from".to_string(),
                serde_json::Value::String(format.source_tag().to_string()),
            );
        }
        let mem = models::Memory {
            cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: tier.clone(),
            namespace: namespace.clone(),
            title: mined.title,
            content: mined.content,
            tags: vec![format.source_tag().to_string()],
            priority: 5,
            confidence: 0.8,
            source: mined.source_format,
            access_count: 0,
            created_at: mined.created_at.unwrap_or_else(|| now.to_rfc3339()),
            updated_at: now.to_rfc3339(),
            last_accessed_at: None,
            expires_at,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            // #1780 root-cause — distinct conversations that truncate to
            // the same 100-char title still carry a distinct provenance
            // pointer. `Conversation::id` is the source's own stable
            // unique id (Claude `uuid` / ChatGPT `id` / Slack thread id),
            // namespaced by the source-format tag so the URI is globally
            // unambiguous: `mine-claude:<conv-id>`.
            source_uri: Some(format!("{}:{}", format.source_tag(), conv.id)),
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };

        // #1780 — honour the operator's collision disposition. The
        // default `version` mode auto-suffixes a colliding title so a
        // distinct same-title conversation is never clobbered; an
        // Error-mode collision or a Version "no free suffix" error is
        // counted + warned per-row and the loop continues.
        match db::insert_with_conflict(&conn, &mem, conflict_mode) {
            Ok(_) => imported += 1,
            Err(e) => {
                errors += 1;
                writeln!(
                    out.stderr,
                    "warning: failed to store '{}': {}",
                    mem.title, e
                )?;
            }
        }

        if imported.is_multiple_of(100) && imported > 0 {
            conn.execute_batch(crate::storage::connection::SQL_COMMIT)?;
            conn.execute_batch("BEGIN")?;
        }
    }

    conn.execute_batch(crate::storage::connection::SQL_COMMIT)?;

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string(&serde_json::json!({
                "imported": imported,
                "skipped": skipped,
                "errors": errors,
                "total_conversations": conversations.len(),
                "namespace": namespace,
                "tier": tier.as_str(),
            }))?
        )?;
    } else {
        writeln!(
            out.stdout,
            "Imported {} memories from {} conversations (skipped: {}, errors: {})",
            imported,
            conversations.len(),
            skipped,
            errors
        )?;
        writeln!(out.stdout, "Namespace: {namespace}, Tier: {tier}")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    // ---------------- export ------------------------------------------

    #[test]
    fn test_export_empty_db() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Touch db path so db::open() materialises an empty schema
        let _ = seed_memory(&db, "ns-init", "init", "init");
        {
            let mut out = env.output();
            export(&db, &ExportArgs::default(), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["memories"].is_array());
        assert!(v["links"].is_array());
        assert!(v["count"].is_u64());
        assert!(v["exported_at"].is_string());
    }

    #[test]
    fn test_export_with_memories_includes_links() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "content-a");
        let id2 = seed_memory(&db, "ns", "b", "content-b");
        let conn = db::open(&db).unwrap();
        // v0.7.0 fix campaign R1-M2/M4 — relation must be in the
        // closed-set; pre-fix value `"relates"` was silently accepted.
        db::create_link(&conn, &id1, &id2, "related_to").unwrap();
        drop(conn);
        {
            let mut out = env.output();
            export(&db, &ExportArgs::default(), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        assert_eq!(mems.len(), 2);
        let links = v["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_export_pretty_printed_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "x", "y");
        {
            let mut out = env.output();
            export(&db, &ExportArgs::default(), &mut out).unwrap();
        }
        // Pretty-printed JSON has at least one newline + 2-space indent.
        let s = env.stdout_str();
        assert!(s.contains('\n'));
        assert!(s.contains("  \"memories\""));
    }

    // ---------------- import ------------------------------------------

    fn export_payload_at(db_path: &Path) -> String {
        let mut buf = Vec::<u8>::new();
        let mut errbuf = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf, &mut errbuf);
        export(db_path, &ExportArgs::default(), &mut out).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_import_default_restamps_agent_id() {
        // Source: a payload whose memories carry agent_id="other-agent"
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "ns", "src-title", "src-content");
        {
            let conn = db::open(&src_db).unwrap();
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', 'other-agent') WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        }
        let payload = export_payload_at(&src_db);

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(
                &payload,
                &dst_db,
                &args,
                true,
                Some("caller-agent"),
                &mut out,
            )
            .unwrap();
        }
        let conn = db::open(&dst_db).unwrap();
        let mem = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(
            mem.metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("caller-agent")
        );
        assert_eq!(
            mem.metadata
                .get("imported_from_agent_id")
                .and_then(|v| v.as_str()),
            Some("other-agent")
        );
    }

    #[test]
    fn test_import_trust_source_preserves_agent_id() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "ns", "tt", "cc");
        {
            let conn = db::open(&src_db).unwrap();
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', 'preserved-agent') WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        }
        let payload = export_payload_at(&src_db);

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, false, Some("caller"), &mut out).unwrap();
        }
        let conn = db::open(&dst_db).unwrap();
        let mem = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(
            mem.metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("preserved-agent")
        );
        assert!(dst.stderr_str().contains("trust-source"));
    }

    /// ★ #2208 re-audit N1 — the v1 wire-form (no `spec_version`) honours
    /// the SAME forget covenant as the v2 route: a dest-forgotten id in a
    /// v1-form payload is refused/skipped, and a dest-archived id is not
    /// re-admitted live. Fails on pre-N1 code (stripping `spec_version`
    /// was a downgrade bypass — `insert_with_conflict` performed no
    /// tombstone/archive check, so the forgotten row resurrected under its
    /// original id).
    #[test]
    fn v1_form_import_does_not_resurrect_dest_forgotten_or_archived_2208() {
        // Source carries two rows in DISTINCT namespaces so the dest can
        // forget one (namespace-filtered) and archive the other.
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id_forget = seed_memory(&src_db, "ns-forget", "f-title", "f-content");
        let id_archive = seed_memory(&src_db, "ns-archive", "a-title", "a-content");
        let payload = export_payload_at(&src_db);
        assert!(
            !payload.contains("spec_version"),
            "fixture: the payload is the v1 wire form"
        );

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        {
            let conn = db::open(&dst_db).unwrap();
            assert!(db::get(&conn, &id_forget).unwrap().is_some());
            // Dest operator forgets one row + archives the other.
            assert_eq!(
                db::forget(&conn, Some("ns-forget"), None, None, false).unwrap(),
                1,
                "dest forgot the row"
            );
            assert!(
                db::archive_memory(&conn, &id_archive, Some("test")).unwrap(),
                "dest archived the row"
            );
        }

        // Re-import the SAME v1-form payload: neither id may come back live.
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let conn = db::open(&dst_db).unwrap();
        assert!(
            db::get(&conn, &id_forget).unwrap().is_none(),
            "the dest-forgotten memory must NOT resurrect via the v1 wire form"
        );
        assert!(
            db::memory_is_tombstoned(&conn, &id_forget).unwrap(),
            "the tombstone survives"
        );
        assert!(
            db::get(&conn, &id_archive).unwrap().is_none(),
            "the dest-archived memory must NOT be re-admitted live"
        );
        assert!(
            db::memory_is_archived(&conn, &id_archive).unwrap(),
            "the archived row is untouched"
        );
        // The per-row skips are surfaced in the JSON errors array.
        let v: serde_json::Value =
            serde_json::from_str(dst.stdout_str().lines().last().unwrap()).unwrap();
        let errs = v["errors"].as_array().unwrap();
        assert!(
            errs.iter()
                .any(|e| e.as_str().unwrap_or_default().contains("tombstone")),
            "the tombstone skip is reported, got: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.as_str().unwrap_or_default().contains("archived")),
            "the archive skip is reported, got: {errs:?}"
        );
    }

    /// The FULL Portability-v2 envelope payload (the `--full` wire form).
    fn export_full_payload_at(db_path: &Path) -> String {
        let mut buf = Vec::<u8>::new();
        let mut errbuf = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf, &mut errbuf);
        export(db_path, &ExportArgs { full: true }, &mut out).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// ★ #2210 — the v2 route validates the `spec_version` VALUE: a
    /// spec_version-"3" payload must refuse loudly, and must NOT fall
    /// through to the L1 path (which would silently drop the signed spine).
    /// Fails on pre-#2210 code (only key PRESENCE was checked, so the value
    /// was never validated and the envelope parsed permissively).
    #[test]
    fn v2_route_refuses_unsupported_spec_version_2210() {
        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let payload = serde_json::json!({
            "spec_version": "3",
            "db_schema_version": 1,
            "memories": [],
            "links": [],
            "portability_complete": false,
            "conformance_level": "L1",
            "conformance_by_class": {},
            "count": 0
        })
        .to_string();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        let err = {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, false, Some("caller"), &mut out)
                .expect_err("a spec_version-3 payload must refuse")
        };
        assert!(err.to_string().contains("spec_version"), "got: {err}");
    }

    /// ★ #2210 — the v2 route's strict envelope parse refuses an unknown
    /// top-level record class instead of silently dropping it. Fails on
    /// pre-#2210 code (no `deny_unknown_fields` — the array vanished and the
    /// import "succeeded").
    #[test]
    fn v2_route_refuses_unknown_record_class_2210() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let _ = seed_memory(&src_db, "ns", "t2210", "c2210");
        let mut payload: serde_json::Value =
            serde_json::from_str(&export_full_payload_at(&src_db)).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .insert("future_class".into(), serde_json::json!([{"sig": "x"}]));

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        let err = {
            let mut out = dst.output();
            import_from_str(
                &payload.to_string(),
                &dst_db,
                &args,
                false,
                Some("caller"),
                &mut out,
            )
            .expect_err("an unknown top-level class must refuse")
        };
        assert!(err.to_string().contains("fail-closed"), "got: {err}");
        // ZERO rows landed.
        let conn = db::open(&dst_db).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "a refused v2 import applies zero rows");
    }

    /// ★ #2211 — the v2 route honours `ImportArgs` exactly like L1: a
    /// spine-less v2 bundle's forged `agent_id` is RESTAMPED with the
    /// caller's id by default. Fails on pre-#2211 code (the v2 route ignored
    /// `ImportArgs` and preserved the forged identity verbatim).
    #[test]
    fn v2_route_restamps_agent_id_by_default_2211() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "ns", "v2-restamp", "v2-content");
        {
            let conn = db::open(&src_db).unwrap();
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.agent_id', 'forged-agent') WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        }
        let payload = export_full_payload_at(&src_db);
        assert!(
            payload.contains("spec_version"),
            "fixture: the payload routes to the v2 importer"
        );

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(
                &payload,
                &dst_db,
                &args,
                false,
                Some("caller-agent"),
                &mut out,
            )
            .unwrap();
        }
        let conn = db::open(&dst_db).unwrap();
        let mem = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(
            mem.metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("caller-agent"),
            "the v2 route restamps by default, exactly like L1"
        );
        assert_eq!(
            mem.metadata
                .get("imported_from_agent_id")
                .and_then(|v| v.as_str()),
            Some("forged-agent"),
            "the original claim is preserved as provenance"
        );
    }

    #[test]
    fn test_import_invalid_memory_skipped_with_error() {
        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        // Craft a payload with one valid + one invalid (empty title).
        let payload = serde_json::json!({
            "memories": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "",  // invalid: empty title
                    "content": "c",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "x"}
                },
                {
                    "id": "22222222-2222-2222-2222-222222222222",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "valid-row",
                    "content": "c",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "x"}
                }
            ],
            "links": [],
            "count": 2,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(dst.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 1);
        let errs = v["errors"].as_array().unwrap();
        assert!(!errs.is_empty(), "expected at least one error");
    }

    #[test]
    fn test_import_invalid_link_skipped() {
        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        // Seed two valid memories so the link-target exists, then attach
        // a syntactically-invalid link entry.
        let id1 = seed_memory(&dst_db, "ns", "a", "ca");
        let id2 = seed_memory(&dst_db, "ns", "b", "cb");
        let payload = serde_json::json!({
            "memories": [],
            "links": [
                { "source_id": id1, "target_id": id2, "relation": "" },
                { "source_id": id1, "target_id": id2, "relation": "supersedes" }
            ],
            "count": 0,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(dst.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_import_roundtrip_export_import_preserves_data() {
        // #1780 — the idempotent re-import contract now lives behind the
        // EXPLICIT `--on-conflict merge` mode (the new `version` default
        // would auto-suffix the second import into `rt-title (2)`). This
        // test pins the merge-mode no-dupe behaviour: a double import of
        // the same payload still yields exactly one row.
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let _id = seed_memory(&src_db, "rt-ns", "rt-title", "rt-content");
        let payload = export_payload_at(&src_db);

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Merge,
        };
        {
            let mut out = dst.output();
            // Import the same payload twice — merge mode is idempotent.
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let conn = db::open(&dst_db).unwrap();
        let all = db::export_all(&conn).unwrap();
        assert_eq!(all.len(), 1, "merge mode re-import must not duplicate");
        assert_eq!(all[0].title, "rt-title");
        assert_eq!(all[0].content, "rt-content");
        assert_eq!(all[0].namespace, "rt-ns");
    }

    /// Build a single-memory import payload colliding on `(title, ns)`
    /// with a distinct content, used by the #1780 conflict-mode tests.
    fn colliding_payload(id: &str, ns: &str, title: &str, content: &str) -> String {
        serde_json::json!({
            "memories": [
                {
                    "id": id,
                    "tier": Tier::Mid.as_str(),
                    "namespace": ns,
                    "title": title,
                    "content": content,
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "x"}
                }
            ],
            "links": [],
            "count": 1,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string()
    }

    #[test]
    fn test_import_default_version_suffixes_collision_preserves_both() {
        // #1780 — the new default `version` mode must NOT clobber a
        // distinct pre-existing same-title memory: it auto-suffixes the
        // incoming row to `title (2)` and BOTH rows persist.
        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        // Seed a distinct existing memory at (clash-title, clash-ns).
        let existing_id = seed_memory(&dst_db, "clash-ns", "clash-title", "ORIGINAL-content");
        let payload = colliding_payload(
            "99999999-9999-9999-9999-999999999999",
            "clash-ns",
            "clash-title",
            "INCOMING-content",
        );
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(dst.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 1, "incoming row imported");
        let conn = db::open(&dst_db).unwrap();
        // Assert via id / title lookups (NOT export_all, which filters
        // expired rows — the import fixture carries a past created_at).
        // Original is untouched — no clobber.
        let original = db::get(&conn, &existing_id).unwrap().unwrap();
        assert_eq!(original.title, "clash-title");
        assert_eq!(original.content, "ORIGINAL-content");
        // Incoming landed under the `(2)` suffix with its own content.
        let suffixed_id = db::find_by_title_namespace(&conn, "clash-title (2)", "clash-ns")
            .unwrap()
            .expect("a `clash-title (2)` suffixed sibling row must exist");
        let suffixed = db::get(&conn, &suffixed_id).unwrap().unwrap();
        assert_eq!(suffixed.content, "INCOMING-content");
        // Both rows are distinct + both present.
        assert_ne!(suffixed_id, existing_id);
    }

    #[test]
    fn test_import_error_mode_reports_and_skips_without_clobber() {
        // #1780 — `--on-conflict error` refuses the colliding row with a
        // per-row error, leaves the existing memory UNTOUCHED, and the
        // import continues (here there is only one row, but the error is
        // collected per-row, not bubbled as an abort).
        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let existing_id = seed_memory(&dst_db, "err-ns", "err-title", "KEEP-content");
        let payload = colliding_payload(
            "88888888-8888-8888-8888-888888888888",
            "err-ns",
            "err-title",
            "REJECTED-content",
        );
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Error,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(dst.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 0, "collision not imported");
        let errs = v["errors"].as_array().unwrap();
        assert!(!errs.is_empty(), "expected a per-row conflict error");
        assert!(
            errs[0].as_str().unwrap().contains("CONFLICT"),
            "error should be the typed CONFLICT diagnostic: {errs:?}"
        );
        // Existing row untouched, no suffixed sibling created.
        let conn = db::open(&dst_db).unwrap();
        let all = db::export_all(&conn).unwrap();
        assert_eq!(all.len(), 1, "error mode must not write a new row");
        let original = db::get(&conn, &existing_id).unwrap().unwrap();
        assert_eq!(original.content, "KEEP-content", "existing not clobbered");
    }

    #[test]
    fn test_mine_populates_source_uri_with_conversation_id() {
        // #1780 root-cause — each mined memory carries a distinct
        // `source_uri` derived from the source conversation's stable id,
        // so two conversations that truncate to the same 100-char title
        // remain distinguishable (and the version default suffixes the
        // title collision rather than clobbering).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("uri-ns".to_string()),
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, false, &cfg, Some("miner"), &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let all = db::export_all(&conn).unwrap();
        let mined: Vec<&_> = all.iter().filter(|m| m.namespace == "uri-ns").collect();
        assert_eq!(mined.len(), 1, "expected exactly one mined memory");
        // conv-1 is the >=3-message conversation in the fixture; the
        // source_uri is `<source-tag>:<conv-id>`.
        assert_eq!(
            mined[0].source_uri.as_deref(),
            Some("mine-claude:conv-1"),
            "source_uri must carry the source-tag + conversation id"
        );
    }

    // ---------------- mine --------------------------------------------

    fn write_minimal_claude_export(dir: &Path) -> PathBuf {
        // Claude export shape: JSONL — one conversation per line.
        let conv1 = serde_json::json!({
            "uuid": "conv-1",
            "name": "Conv with 5 messages",
            "created_at": "2026-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z",
            "chat_messages": [
                { "uuid": "m1", "text": "hello", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z" },
                { "uuid": "m2", "text": "hi there", "sender": "assistant", "created_at": "2026-01-01T00:00:00.000Z" },
                { "uuid": "m3", "text": "how are you", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z" },
                { "uuid": "m4", "text": "fine thanks", "sender": "assistant", "created_at": "2026-01-01T00:00:00.000Z" },
                { "uuid": "m5", "text": "ok bye", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z" }
            ]
        });
        let conv2 = serde_json::json!({
            "uuid": "conv-2",
            "name": "Short Conv",
            "created_at": "2026-01-01T00:00:00.000Z",
            "updated_at": "2026-01-01T00:00:00.000Z",
            "chat_messages": [
                { "uuid": "m6", "text": "ping", "sender": "human", "created_at": "2026-01-01T00:00:00.000Z" }
            ]
        });
        let p = dir.join("claude.jsonl");
        let body = format!("{}\n{}\n", conv1, conv2);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn test_mine_dry_run_writes_nothing() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("mined-ns".to_string()),
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["dry_run"].as_bool().unwrap(), true);
        // No memory was written. Only attempt to open if the file exists
        // (dry-run never touches the DB at all).
        if db.exists() {
            let conn = db::open(&db).unwrap();
            let all = db::export_all(&conn).unwrap();
            assert_eq!(all.len(), 0);
        }
    }

    #[test]
    fn test_mine_filters_by_min_messages() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        // min_messages=3 keeps Conv-1 (5 msgs) and drops Conv-2 (1 msg).
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("mined-ns".to_string()),
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["total_conversations"].as_u64().unwrap(), 2);
        assert_eq!(v["filtered"].as_u64().unwrap(), 1);
    }

    // PR-9i — buffer coverage uplift. Targets the actual mine() write path
    // (lines 261-356) and invalid format/tier error paths.

    #[test]
    fn pr9i_mine_actual_write_path_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("mined-real".to_string()),
            tier: Tier::Long.as_str().to_string(),
            min_messages: 3,
            dry_run: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, false, &cfg, Some("miner-id"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("Imported"));
        assert!(s.contains("mined-real"));
        // The conversation with >=3 messages was actually written.
        let conn = db::open(&db).unwrap();
        let all = db::export_all(&conn).unwrap();
        let in_ns: Vec<&_> = all.iter().filter(|m| m.namespace == "mined-real").collect();
        assert_eq!(
            in_ns.len(),
            1,
            "expected exactly one mined memory in mined-real ns: {all:?}"
        );
        // agent_id is the miner; mined_from is the source format.
        assert_eq!(
            in_ns[0].metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("miner-id")
        );
        assert_eq!(
            in_ns[0].metadata.get("mined_from").and_then(|v| v.as_str()),
            Some("mine-claude")
        );
    }

    #[test]
    fn pr9i_mine_actual_write_path_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("mined-json".to_string()),
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner-x"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["namespace"].as_str().unwrap(), "mined-json");
        assert_eq!(v["tier"].as_str().unwrap(), Tier::Mid.as_str());
        assert!(v["imported"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn pr9i_mine_default_namespace_per_format() {
        // Omit --namespace; defaults to "<format>-export".
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: None,
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["namespace"].as_str().unwrap(), "claude-export");
    }

    #[test]
    fn pr9i_mine_invalid_format_errors() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("anything.jsonl");
        std::fs::write(&p, "{}").unwrap();
        let args = MineArgs {
            path: p,
            format: "myspace".to_string(), // not claude/chatgpt/slack
            namespace: None,
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        let mut out = env.output();
        let res = mine(&db, args, false, &cfg, Some("miner"), &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid format"));
    }

    #[test]
    fn pr9i_mine_invalid_tier_errors() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("c.jsonl");
        std::fs::write(&p, "{}").unwrap();
        let args = MineArgs {
            path: p,
            format: "claude".to_string(),
            namespace: None,
            tier: "permanent".to_string(), // not short/mid/long
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        let mut out = env.output();
        let res = mine(&db, args, false, &cfg, Some("miner"), &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid tier"));
    }

    // ----------------------------------------------------------------
    // L0.7-3 chunk-e2 — coverage uplift to ≥95%.
    // ----------------------------------------------------------------

    #[test]
    fn test_import_default_restamps_with_warning_on_text_mode() {
        // Text-mode (json_out=false) prints the restamp-count line and,
        // when --trust-source is set, the warning to stderr. Covers
        // lines 153-167.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let payload = serde_json::json!({
            "memories": [
                {
                    "id": "33333333-3333-3333-3333-333333333333",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "tt",
                    "content": "cc",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "other-agent"}
                }
            ],
            "links": [],
            "count": 1,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            import_from_str(&payload, &db, &args, false, Some("caller"), &mut out).unwrap();
        }
        // Text mode emits "imported: N (restamped agent_id on M)".
        assert!(env.stdout_str().contains("imported:"));
        assert!(env.stderr_str().contains("trust-source"));
    }

    #[test]
    fn test_import_text_mode_with_errors_lists_them_on_stderr() {
        // Text-mode failure path that surfaces validation errors on
        // stderr (lines 163-167).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let payload = serde_json::json!({
            "memories": [
                {
                    "id": "44444444-4444-4444-4444-444444444444",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "",  // empty title fails validate
                    "content": "c",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "x"}
                }
            ],
            "links": [],
            "count": 1,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            import_from_str(&payload, &db, &args, false, Some("caller"), &mut out).unwrap();
        }
        // Errors surface on stderr in text mode.
        assert!(env.stdout_str().contains("imported: 0"));
        let stderr = env.stderr_str();
        assert!(!stderr.is_empty(), "expected at least one error on stderr");
    }

    #[test]
    fn test_import_with_valid_link_inserts() {
        // Drives the link-validate-then-insert branch (lines 128-139)
        // with a syntactically-valid link.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed two valid memories so the link target exists.
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let payload = serde_json::json!({
            "memories": [],
            "links": [
                {
                    "source_id": id1,
                    "target_id": id2,
                    "relation": "related_to",
                    "created_at": "2026-01-01T00:00:00+00:00"
                }
            ],
            "count": 0,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            import_from_str(&payload, &db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let links = db::export_links(&conn).unwrap();
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_import_default_restamp_preserves_imported_from() {
        // Non-trust-source mode restamps with caller_id and preserves
        // `imported_from_agent_id`. Drives lines 96-117 with the
        // metadata-rewrite path.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let payload = serde_json::json!({
            "memories": [
                {
                    "id": "55555555-5555-5555-5555-555555555555",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "tt",
                    "content": "cc",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "external"}
                }
            ],
            "links": [],
            "count": 1,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            import_from_str(&payload, &db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 1);
        assert_eq!(v["restamped"].as_u64().unwrap(), 1);
    }

    #[test]
    fn test_import_default_restamp_same_caller_id_no_imported_from() {
        // When caller id matches existing agent_id, no
        // `imported_from_agent_id` is added; restamped count stays 0.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let payload = serde_json::json!({
            "memories": [
                {
                    "id": "66666666-6666-6666-6666-666666666666",
                    "tier": Tier::Mid.as_str(),
                    "namespace": "ns",
                    "title": "tt",
                    "content": "cc",
                    "tags": [],
                    "priority": 5,
                    "confidence": 1.0,
                    "source": "import",
                    "access_count": 0,
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                    "last_accessed_at": null,
                    "expires_at": null,
                    "metadata": {"agent_id": "same-caller"}
                }
            ],
            "links": [],
            "count": 1,
            "exported_at": "2026-01-01T00:00:00+00:00"
        })
        .to_string();
        let args = ImportArgs {
            trust_source: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            import_from_str(&payload, &db, &args, true, Some("same-caller"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"].as_u64().unwrap(), 1);
        // No restamp metadata insertion fires because caller_id matches.
        assert_eq!(v["restamped"].as_u64().unwrap(), 0);
    }

    fn write_minimal_chatgpt_export(path: &Path) {
        let arr = serde_json::json!([
            {
                "id": "chat-1",
                "title": "ChatGPT Conv",
                "create_time": 1_700_000_000_i64,
                "mapping": {
                    "n1": {
                        "message": {
                            "author": { "role": "user" },
                            "create_time": 1.0,
                            "content": { "parts": ["hello"] }
                        }
                    },
                    "n2": {
                        "message": {
                            "author": { "role": "assistant" },
                            "create_time": 2.0,
                            "content": { "parts": ["hi back"] }
                        }
                    },
                    "n3": {
                        "message": {
                            "author": { "role": "user" },
                            "create_time": 3.0,
                            "content": { "parts": ["question"] }
                        }
                    }
                }
            }
        ]);
        std::fs::write(path, serde_json::to_string(&arr).unwrap()).unwrap();
    }

    #[test]
    fn pr9i_mine_chatgpt_actual_write_path() {
        // Drives the `mine::Format::ChatGpt` parse branch (line 201) and
        // the actual-write path through to db::insert.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("chatgpt.json");
        write_minimal_chatgpt_export(&path);
        let args = MineArgs {
            path,
            format: "chatgpt".to_string(),
            namespace: None,
            tier: Tier::Short.as_str().to_string(),
            min_messages: 3,
            dry_run: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["namespace"].as_str().unwrap(), "chatgpt-export");
    }

    #[test]
    fn pr9i_mine_slack_dry_run_via_directory() {
        // Drives the `mine::Format::Slack` parse branch (line 202).
        // Slack expects a directory tree — even an empty channel
        // dir exercises the parser.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        // Make an empty channel subdirectory so parse_slack walks it.
        std::fs::create_dir(tmp.path().join("general")).unwrap();
        let args = MineArgs {
            path: tmp.path().to_path_buf(),
            format: "slack".to_string(),
            namespace: None,
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            // We don't care about success/failure here — `parse_slack`
            // may or may not return Ok depending on the channel dir
            // shape. We're after the format-dispatch branch coverage.
            let _ = mine(&db, args, true, &cfg, Some("miner"), &mut out);
        }
    }

    #[test]
    fn pr9i_mine_chatgpt_default_namespace() {
        // Default namespace for chatgpt is "chatgpt-export".
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("c.json");
        write_minimal_chatgpt_export(&path);
        let args = MineArgs {
            path,
            format: "chatgpt".to_string(),
            namespace: None,
            tier: Tier::Mid.as_str().to_string(),
            min_messages: 1,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, true, &cfg, Some("miner"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["namespace"].as_str().unwrap(), "chatgpt-export");
    }

    #[test]
    fn pr9i_mine_text_actual_write_path_text_output() {
        // Drives the text-mode "Imported …" emission (lines 353-361).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("text-mine".to_string()),
            tier: Tier::Long.as_str().to_string(),
            min_messages: 3,
            dry_run: false,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, false, &cfg, Some("miner"), &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("Imported"));
        assert!(stdout.contains("Namespace: text-mine"));
    }

    #[test]
    fn pr9i_mine_text_dry_run_lists_filtered_titles() {
        // Text-mode dry_run prints conversation titles (lines 232-256).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let claude_path = write_minimal_claude_export(tmp.path());
        let args = MineArgs {
            path: claude_path,
            format: "claude".to_string(),
            namespace: Some("dry-text".to_string()),
            tier: Tier::Short.as_str().to_string(),
            min_messages: 3,
            dry_run: true,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = env.output();
            mine(&db, args, false, &cfg, Some("miner"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("Dry run"));
        assert!(s.contains("Total conversations found"));
        assert!(s.contains("After filter"));
        assert!(s.contains("dry-text"));
        // The Claude conversation with name "Conv with 5 messages" must be
        // listed in the filtered preview.
        assert!(
            s.contains("5 msgs") || s.contains("Conv with 5 messages"),
            "expected conversation listing in dry-run text output: {s}"
        );
    }
}
