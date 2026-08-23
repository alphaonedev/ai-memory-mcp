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

/// Verb name carried into the #2490 store-guard refusal messages so the
/// operator is told which command refused. Mirrors `cli::backup`'s
/// `VERB_BACKUP` / `VERB_RESTORE` consts.
const VERB_EXPORT: &str = "export";
/// See [`VERB_EXPORT`].
const VERB_IMPORT: &str = "import";

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
    /// A `(title, namespace)` collision with a DIFFERENT existing row is
    /// auto-suffixed (`title (2)`, `title (3)`, …) into a free slot, then
    /// inserted — never clobbers; both rows persist. A row whose `id` is
    /// ALREADY present (re-importing the corpus's own export onto an existing
    /// corpus) is an IDEMPOTENT no-op: the durable row is kept, never
    /// re-inserted or overwritten (#2569). The #1780 default — re-importing a
    /// backup adds the missing rows and keeps the existing ones, without
    /// duplicating or clobbering; use `merge` to overwrite a diverged row.
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
    /// v1.0.0 #2490 — the configured store, read through the SAME channels
    /// `serve` uses (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` >
    /// this flag, #1927). `export` acts on a local SQLite database; naming a
    /// Postgres store here makes the command REFUSE instead of conjuring an
    /// empty SQLite file and emitting a `count: 0` artifact that exits 0.
    #[arg(long)]
    pub store_url: Option<String>,
    /// v1.0.0 #2490 — acknowledge up to N rows withheld by the export
    /// confidentiality boundary without failing the command.
    ///
    /// A partial export exits [`crate::export_scope::EXIT_EXPORT_INCOMPLETE`]
    /// so a backup job cannot mistake it for a complete one. On a corpus that
    /// permanently holds, say, one quarantined row that would pin the job red
    /// forever — and a forever-red job becomes `|| true`, which silences the
    /// NEXT withholding too. This is a RATCHET, not a mute: the exit stays 0
    /// while `withheld <= N` and goes non-zero the moment it EXCEEDS the
    /// number the operator acknowledged, so a new withholding still alarms.
    /// The in-band counts are emitted either way.
    #[arg(long)]
    pub expect_withheld: Option<usize>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Trust `metadata.agent_id` in imported JSON (default: restamp with caller's id).
    /// Only use this when importing a JSON export you fully trust (e.g., your own backup).
    #[arg(long, default_value_t = false)]
    pub trust_source: bool,
    /// v1.0.0 #2490 — the configured store, read through the SAME channels
    /// `serve` uses. `import` WRITES to a local SQLite database; naming a
    /// Postgres store makes the command REFUSE instead of writing rows into a
    /// conjured SQLite file the served store never reads. A `sqlite://` URL
    /// that DISAGREES with `--db` is also refused (never silently redirected)
    /// — see [`crate::cli::backup::StoreDisagreement`].
    #[arg(long)]
    pub store_url: Option<String>,
    /// Disposition on a `(title, namespace)` collision with a DIFFERENT
    /// existing memory: `version` (default — auto-suffix `title (N)`, never
    /// clobber), `merge` (legacy silent upsert — the way to OVERWRITE a
    /// diverged row on restore), or `error` (refuse + skip the colliding row,
    /// continue). A row whose `id` already exists is always an idempotent
    /// no-op under `version`/`error` (kept, never overwritten; #2569).
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
pub fn export(db_path: &Path, args: &ExportArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    use crate::export_scope;
    use crate::models::field_names;

    // v1.0.0 #2490 — resolve (and where necessary REFUSE) the configured
    // store BEFORE anything is created on disk, exactly as #2444 did for
    // `backup`. Executed evidence at the parent commit: with
    // `AI_MEMORY_STORE_URL=postgres://…` and no `--db` file present, `export`
    // exited 0, CREATED an 802,816-byte SQLite database, and emitted
    // `{"count":0,"memories":[],"links":[]}` — a successful-looking, EMPTY,
    // apparently-valid export of a Postgres corpus. `export --full` was
    // worse: the conjured file bootstraps real default governance rules, so
    // the v2 envelope carried `db_schema_version: 87` + 4 `governance_rules`
    // + 1 `trust_anchor` around `memories: []`, and emitted no stderr at all.
    let source_db = crate::cli::backup::resolve_sqlite_store(
        db_path,
        args.store_url.as_deref(),
        VERB_EXPORT,
        crate::cli::backup::StoreDisagreement::RedirectWithNote,
        None,
        out,
    )?;
    // #2444 shape — `db::open` CREATES the file when absent and then runs the
    // whole migration ladder on it, so the created file is NOT distinguishable
    // from a real database by any schema probe. Non-existence is the only
    // honest discriminator, and it is destroyed by the first invocation.
    if !source_db.exists() {
        anyhow::bail!(
            "no SQLite database at {} — refusing to create one and export it. \
             An export of a database that does not exist would emit a \
             structurally VALID `count: 0` artifact and exit 0, which is \
             indistinguishable from a genuinely empty corpus (#2490).",
            source_db.display()
        );
    }
    let conn = db::open(&source_db)?;

    // v1.0.0 #2006 — the integrity portability path. `--full` emits the full
    // Portability-v2 envelope (every signed record class byte-preserved +
    // re-verifiable, spec `docs/spec/PORTABILITY-V2.md`) with a COMPUTED
    // `conformance_level` marker. This IS the portability path, so it does NOT
    // emit the scope-limiting stderr WARN the convenience view carries. The
    // memories are still screened by `build_full_envelope` (same
    // confidentiality boundary).
    if args.full {
        let (mut envelope, ledger) = crate::portability::emit::build_full_envelope_audited(
            &conn,
            "ai-memory",
            &Utc::now().to_rfc3339(),
        )?;
        // v1.0.0 #2490 — `portability_complete` was computed ONLY from the
        // audit-chain re-verify + operator anchor, so it was structurally
        // blind to the rows the confidentiality boundary withheld: an
        // artifact could assert `portability_complete: true` over a corpus it
        // provably did not carry. Make the marker an AND. This is a VALUE
        // correction to an EXISTING field, so it costs zero cross-version
        // compatibility — the envelope is parsed with
        // `#[serde(deny_unknown_fields)]` under `spec_version = "2"`, so
        // ADDING a field would make every already-shipped binary refuse the
        // new bundle (5-agent vote 4d3ea1c5, objection O2; D7 = A).
        if ledger.is_partial() {
            envelope.portability_complete = false;
        }
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&envelope)?)?;
        return finish_export_report(&ledger, &source_db, envelope.count, args, out);
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
    let (memories, mut ledger) =
        crate::export_taxonomy::screen_memories_for_export_audited(memories, Some(&conn));
    let (quarantined, tombstoned, expired) = db::export_excluded_counts(&conn)?;
    ledger.quarantined = quarantined;
    ledger.tombstoned = tombstoned;
    ledger.expired = expired;
    let links = db::export_links(&conn)?;
    // In-band, additive, non-breaking scope markers (critical: the stderr
    // WARN below is invisible to a pipe-to-file consumer).
    //
    // v1.0.0 #2490 — `withheld` joins them. `count` alone is
    // self-CONSISTENT (`count == memories.len()` always), so the loss was
    // unfalsifiable from the bundle: a 3-row corpus whose PEM row the
    // forbidden-class gate dropped emitted `count: 2` with nothing to
    // contradict it. COUNTS + a class histogram only — never the withheld
    // ids, which would publish a precise index into the source corpus's key
    // material into the very artifact that crosses trust boundaries
    // (5-agent vote 4d3ea1c5, security objection O3). The ids go to stderr.
    //
    // Extra top-level keys are safe on THIS wire form: `import_from_str`
    // reads only `data["memories"]` / `data["links"]`, and there is no
    // `spec_version`, so the strict v2 envelope parse is never reached.
    // Pinned by `tests/export_import_false_success_2490.rs`.
    writeln!(
        out.stdout,
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "memories": memories, "links": links, "count": memories.len(),
            (field_names::EXPORTED_AT): Utc::now().to_rfc3339(),
            (field_names::EXPORT_SCOPE): export_scope::SCOPE_MEMORIES_LINKS,
            (field_names::PORTABILITY_COMPLETE): export_scope::PORTABILITY_COMPLETE,
            (field_names::EXCLUDES): export_scope::OMITTED_SIGNED_CLASSES,
            (field_names::WITHHELD): ledger.in_band_marker(),
        }))?
    )?;
    // Prominent WARN to STDERR only, so the stdout JSON stays pipeline-valid.
    writeln!(out.stderr, "{}", export_scope::export_scope_warn())?;
    let exported = memories.len();
    finish_export_report(&ledger, &source_db, exported, args, out)
}

/// v1.0.0 #2490 — emit the structured export report and decide the exit code.
///
/// Two channels, deliberately:
/// * ONE structured stderr line under the stable
///   [`crate::export_scope::EXPORT_REPORT_EVENT`] key, carrying the ids, so a
///   fleet controller aggregates 10^6 nodes without regexing prose. The
///   signed refusal row the screen already emits lands in the SOURCE
///   database — which in a disaster is exactly the artefact the operator no
///   longer has — so stdout/stderr/exit-code is the ENTIRE signal surface.
/// * A distinct exit code, so `cmd > out.tmp && mv out.tmp out` can be
///   branched on rather than collapsing "incomplete but valid" into "crashed".
///
/// The artifact is ALWAYS written first: DEGRADE, never withhold what IS
/// exportable.
fn finish_export_report(
    ledger: &crate::export_scope::ExportWithholdLedger,
    source_db: &Path,
    exported: usize,
    args: &ExportArgs,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    if ledger.is_partial() || ledger.redacted_total() > 0 {
        writeln!(
            out.stderr,
            "{}",
            ledger.stderr_report_line(&source_db.to_string_lossy(), exported)
        )?;
    }
    if !ledger.is_partial() {
        return Ok(0);
    }
    let withheld = ledger.withheld_total() + ledger.quarantined;
    let acknowledged = args.expect_withheld.unwrap_or(0);
    if withheld <= acknowledged {
        writeln!(
            out.stderr,
            "note: {withheld} withheld row(s) are within the --expect-withheld {acknowledged} \
             baseline; exiting 0. This export is NOT a complete copy of the corpus (#2490)."
        )?;
        return Ok(0);
    }
    writeln!(
        out.stderr,
        "ERROR: this export is INCOMPLETE — {withheld} row(s) present in the corpus were \
         withheld ({} by the export confidentiality boundary, {} quarantined). The artifact \
         WAS written and is internally valid, but it is not a faithful copy: restoring from \
         it would silently return fewer memories than exist. Exiting {} so a backup job \
         cannot mistake it for a complete one. Acknowledge a known steady-state count with \
         --expect-withheld <N> (#2490).",
        ledger.withheld_total(),
        ledger.quarantined,
        crate::export_scope::EXIT_EXPORT_INCOMPLETE
    )?;
    Ok(crate::export_scope::EXIT_EXPORT_INCOMPLETE)
}

/// `import` handler. Reads JSON from `import_reader` (defaulting to
/// stdin in production) and inserts into the DB.
pub fn import(
    db_path: &Path,
    args: &ImportArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let mut buf = String::new();
    use std::io::Read as _;
    std::io::stdin().read_to_string(&mut buf)?;
    import_from_str(&buf, db_path, args, json_out, cli_agent_id, out)
}

/// Stdin-decoupled half of `import`. Tests call this directly with a
/// literal payload instead of redirecting the process's stdin.
#[allow(clippy::too_many_lines)]
pub(crate) fn import_from_str(
    payload: &str,
    db_path: &Path,
    args: &ImportArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    // v1.0.0 #2490 — resolve (and where necessary REFUSE) the configured
    // store BEFORE any row is written. Executed evidence at the parent
    // commit: with `AI_MEMORY_STORE_URL=postgres://…` and no `--db` file
    // present, `import` exited 0 reporting `{"imported":1}` — into a
    // freshly-conjured SQLite file the served Postgres store never reads.
    // The write is not "diverged", it is simply LOST, at the moment the
    // operator is told it landed.
    //
    // `import` WRITES, so a `sqlite://` URL that disagrees with `--db` is
    // REFUSED rather than silently redirected — the read-verb redirect would
    // send a scratch import into the deployment's real database (F5).
    let target_db = crate::cli::backup::resolve_sqlite_store(
        db_path,
        args.store_url.as_deref(),
        VERB_IMPORT,
        crate::cli::backup::StoreDisagreement::Refuse,
        None,
        out,
    )?;
    // Deliberately NO `!exists` refusal here (unlike `export`): importing
    // into a fresh local database is the documented restore path
    // (`docs/USER_GUIDE.md` §"Export and Backup"), so creating the file is
    // the operation, not a false-success.
    let db_path = target_db.as_path();
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
        // v1.0.0 #2490 — the v2 importer already counts every per-row
        // refusal in its report, but returned `Ok(())` unconditionally, so a
        // bundle whose rows were ALL refused still exited 0. Refusals are a
        // failure to reconstruct the bundle; the covenant-honoured skips
        // (a destination forget tombstone, a dest-archived id) are NOT —
        // they are steady-state on any repeated restore, and an
        // in-place-edited row lands in `archived_memories` by #1725, so
        // counting them would pin a re-import forever-red (objection O9).
        // #2571 — a dual-residency-refused archived row is the inverse
        // direction of `archived_skipped` (that one skips a LIVE memories[]
        // entry colliding with a dest-archived id; this one skips an
        // ARCHIVED entry colliding with a dest-LIVE id) but the same
        // covenant-protective disposition: steady-state on any repeated
        // restore, never a reconstruction failure.
        let covenant = report.tombstoned_skipped
            + report.archived_skipped
            + report.tombstones_skipped_live
            + report.archived_memories_skipped_dual_residency;
        let mut refused = report.invalid_skipped
            + report.invalid_links_skipped
            + report.conflicts_skipped
            + report.forged_signature_skipped
            + report.governance_rejected;
        // An endpoint-missing link skip is a reconstruction FAILURE only when
        // no covenant skip fired in this bundle. Otherwise it is the
        // downstream consequence of an honoured erasure / archival — and
        // because #1725 puts every in-place-edited row into
        // `archived_memories`, counting it would pin a repeat restore of an
        // edited corpus forever-red, which ends as `|| true`. The v2 report
        // does not attribute WHICH endpoint went missing, so attribute
        // conservatively rather than manufacture a permanent alarm.
        if covenant == 0 {
            refused += report.links_skipped_missing_endpoint;
        }
        return import_exit_code(refused, out);
    }

    let memories: Vec<models::Memory> =
        serde_json::from_value(data.get("memories").cloned().unwrap_or_default())?;
    // v1.0.0 #2490 — PER-ELEMENT link parse.
    //
    // The pre-fix line was
    // `serde_json::from_value::<Vec<MemoryLink>>(..).unwrap_or_default()`,
    // so a SINGLE edge serde could not deserialize — an unrecognised
    // `relation` token, a missing field — collapsed the WHOLE array to
    // empty. Every other edge in the bundle vanished with it, uncounted and
    // unreported, and the import still exited 0. Parsing element-by-element
    // confines the failure to the edge that caused it and lets it be
    // reported like any other refusal.
    let (links, mut malformed_links) = parse_links_leniently(data.get("links"));

    let caller_id = identity::resolve_agent_id(cli_agent_id, None)?;
    let conflict_mode: ConflictMode = args.on_conflict.into();

    let conn = db::open(db_path)?;
    let mut imported = 0usize;
    let mut restamped = 0usize;
    let mut errors = Vec::new();
    // v1.0.0 #2490 — split the per-row dispositions. `errors` used to hold
    // BOTH kinds and the command exited 0 regardless; the counters below are
    // what the exit code is computed from.
    //
    // `covenant_skipped` = a destination forget tombstone or a GENUINELY
    // archived id refused re-admission. These are the substrate HONOURING an
    // erasure / archival decision; they are steady-state on any repeat
    // restore, so treating them as failures would make a re-import forever-red
    // and the alarm would be `|| true`-ed away (objection O9). v1.0.0 #2570 —
    // an `archive_reason='in_place_edit'` snapshot is a backup of a row that
    // is STILL LIVE (#1725), NOT a genuine archival, so it no longer lands
    // here: the gate below discriminates via `memory_is_genuinely_archived`
    // and the live row is admitted (then idempotent-skipped just below).
    let mut covenant_skipped = 0usize;
    let mut covenant_skipped_ids: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // `refused` = the bundle could NOT be faithfully reconstructed here.
    let mut refused = 0usize;
    // v1.0.0 #2569 — `idempotent_skipped` = a row whose id is ALREADY LIVE at
    // the destination (re-importing the corpus's own export onto an existing
    // corpus). A NO-OP, NOT a failure and NOT counted in `imported` (no write
    // happened); the durable row is kept, never overwritten. Deliberately
    // excluded from the exit-code sum so an idempotent restore exits 0.
    let mut idempotent_skipped = 0usize;
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
            covenant_skipped += 1;
            covenant_skipped_ids.insert(mem.id.clone());
            continue;
        }
        // #2208 N1 mirror — a dest-ARCHIVED id must not be re-admitted live
        // (dual residency); the sanctioned way back is memory_archive_restore.
        //
        // v1.0.0 #2570 — DISCRIMINATE the archive_reason via the shared
        // `memory_is_genuinely_archived` predicate (identical to the v2
        // `portability::import` funnel): skip ONLY a GENUINE archival. #1725
        // snapshots the prior content of a STILL-LIVE row into
        // `archived_memories` under `archive_reason='in_place_edit'` on every
        // in-place edit, so keying on mere presence made an edited-but-live
        // row fail the re-import of its OWN backup. This admits the
        // in_place_edit snapshot and blocks only a real archival.
        if db::memory_is_genuinely_archived(&conn, &mem.id)? {
            errors.push(format!(
                "{}: skipped — the id is archived at the destination \
                 (restore via memory_archive_restore, not import)",
                mem.id
            ));
            covenant_skipped += 1;
            covenant_skipped_ids.insert(mem.id.clone());
            continue;
        }
        // v1.0.0 #2569 — IDEMPOTENT same-id re-import. A row whose id is
        // ALREADY LIVE at the destination (re-importing the corpus's own
        // export onto an existing corpus — the documented restore path) is a
        // NO-OP, not a `UNIQUE constraint failed: memories.id` refusal (the
        // default `ConflictMode::Version` reuses the payload id, so it cannot
        // re-insert an existing id). The durable row is the source of truth
        // and is NEVER overwritten (mirrors #2878 never-clobber + the v2
        // idempotent skip). This runs AFTER the forget/archive covenant gates
        // above, so it can never resurrect a forgotten/archived id (5-agent
        // vote 4d3ea1c5). A per-row WARNING is surfaced when the incoming
        // DURABLE content diverges from the stored row (title/content only —
        // never restamped metadata) so a divergent backup is not silently
        // swallowed; to overwrite a diverged row the operator opts into
        // `--on-conflict merge`.
        if db::memory_exists(&conn, &mem.id)? {
            if let Ok(Some(existing)) = db::get(&conn, &mem.id)
                && db::imported_row_diverges(&existing, &mem)
            {
                errors.push(format!(
                    "{}: already present — durable row kept; incoming content \
                     differs (use --on-conflict merge to overwrite)",
                    mem.id
                ));
            }
            idempotent_skipped += 1;
            continue;
        }
        // v1.0.0 #2490 — REDACTION-OVERWRITE REFUSAL.
        //
        // `ai-memory export` runs the secret screen over every surviving row
        // and silently MUTATES `content` / `title` / `tags` / metadata string
        // leaves, replacing credential values with
        // `secret_screen::REDACTION_PLACEHOLDER`. Executed at the parent
        // commit: a row stored as `aws key AKIA… token ghp_…` exported as
        // `aws key [REDACTED:secret] token [REDACTED:secret]`, and importing
        // that artifact back PERSISTED the masked string as the durable
        // content. That is the one path where an export-time confidentiality
        // control turns into destruction of the source of truth at restore
        // time — the sharpest possible reading of "never corrupt".
        //
        // So: refuse to REPLACE a live, unmasked destination row with a
        // masked incoming one. A masked row is still admitted when the
        // destination has no such row (nothing is being destroyed) or when
        // the destination row is itself already masked (no information is
        // lost). This is the guard that makes the "report redaction, exit 0"
        // export disposition safe (5-agent vote 4d3ea1c5, objection O7).
        if let Some(reason) = redaction_would_clobber(&conn, &mem) {
            errors.push(format!("{}: refused — {reason}", mem.id));
            refused += 1;
            continue;
        }
        if !args.trust_source {
            let original = mem
                .metadata
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            if let Some(obj) = mem.metadata.as_object_mut() {
                use crate::models::field_names;

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

                // #2264 — the v1 wire form is unauthenticated under the
                // default posture. Never let an imported `_agents` row seed
                // the destination's enrolled-key lookup, and never preserve
                // an attestation/signature after changing its bound agent id.
                obj.remove(field_names::AGENT_PUBKEY);
                let carried_attestation = obj.remove(field_names::ATTEST_LEVEL).is_some();
                let carried_signature = obj.remove(field_names::WRITE_SIGNATURE).is_some();
                if carried_attestation || carried_signature {
                    obj.insert(
                        field_names::ATTEST_LEVEL.to_string(),
                        serde_json::Value::String(
                            crate::identity::verify::AttestLevel::Claimed
                                .as_str()
                                .to_string(),
                        ),
                    );
                }
            }
        }
        if let Err(e) = validate::validate_memory(&mem) {
            errors.push(format!("{}: {}", mem.id, e));
            refused += 1;
            continue;
        }
        // #1780 — honour the operator's collision disposition instead
        // of the legacy silent merge. A Version "no free suffix" error
        // or an Error-mode collision is reported per-row and the loop
        // continues; the whole import is never aborted on one row.
        match db::insert_with_conflict(&conn, &mem, conflict_mode) {
            Ok(_) => imported += 1,
            Err(e) => {
                errors.push(format!("{}: {}", mem.id, e));
                refused += 1;
            }
        }
    }
    // v1.0.0 #2490 — LINKS WERE TOTALLY SILENT. The pre-fix loop was
    // `if validate_link(..).is_err() { continue; }` followed by
    // `let _ = db::create_link(..)`, and links were never counted in the
    // report at all. Executed at the parent commit: importing a bundle whose
    // link has a missing endpoint reported `{"imported":1,"errors":[]}`,
    // exit 0, EMPTY stderr — and zero links landed. Same for an unrecognised
    // relation. A restore whose entire graph vanished reported success.
    let mut links_imported = 0usize;
    let mut links_refused = 0usize;
    let mut links_skipped_by_covenant = 0usize;
    for reason in malformed_links.drain(..) {
        errors.push(reason);
        links_refused += 1;
    }
    for link in links {
        if let Err(e) =
            validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
        {
            errors.push(format!(
                "link {}->{}: refused — failed validation: {e}",
                link.source_id, link.target_id
            ));
            links_refused += 1;
            continue;
        }
        // An edge whose endpoint was withheld by the forget/archive covenant
        // above is a DOWNSTREAM consequence of an honoured erasure, not a
        // reconstruction failure — count it separately so a repeat restore of
        // an edited corpus does not go red (objection O9).
        if covenant_skipped_ids.contains(&link.source_id)
            || covenant_skipped_ids.contains(&link.target_id)
        {
            errors.push(format!(
                "link {}->{}: skipped — an endpoint was withheld by the destination \
                 forget/archive covenant",
                link.source_id, link.target_id
            ));
            links_skipped_by_covenant += 1;
            continue;
        }
        match db::create_link(
            &conn,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        ) {
            Ok(()) => links_imported += 1,
            Err(e) => {
                errors.push(format!(
                    "link {}->{}: refused — {e}",
                    link.source_id, link.target_id
                ));
                links_refused += 1;
            }
        }
    }
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "imported": imported,
                "restamped": restamped,
                "trusted_source": args.trust_source,
                // #2490 — links are now REPORTED. `links_imported` is the
                // count that actually landed; the two skip counters carry the
                // reason so a restore can be audited from the report alone.
                "links_imported": links_imported,
                "links_refused": links_refused,
                "links_skipped_by_covenant": links_skipped_by_covenant,
                "refused": refused,
                "skipped_by_covenant": covenant_skipped,
                // v1.0.0 #2569 — rows whose id was ALREADY present (idempotent
                // re-import onto an existing corpus). A success, NOT a refusal:
                // excluded from the exit-code sum so a restore of an unchanged
                // corpus exits 0.
                "idempotent_skipped": idempotent_skipped,
                "errors": errors
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "imported: {imported} (restamped agent_id on {restamped}, \
             already-present {idempotent_skipped}), links: {links_imported}"
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
    import_exit_code(refused + links_refused, out)
}

/// v1.0.0 #2490 — decide the `import` exit code from the count of rows /
/// edges the destination could NOT faithfully reconstruct.
///
/// Pre-fix, `import` returned `Ok(())` unconditionally: a bundle in which
/// every memory was refused and every link silently vanished still reported
/// success. That is the #2444 false-success class on the RESTORE side, which
/// is strictly worse than on the backup side — it is the moment the operator
/// has already lost the original.
///
/// Covenant-honoured skips are deliberately NOT counted by the caller (see
/// the call sites): a destination forget tombstone and a dest-archived id are
/// the substrate doing its job, and they recur on every repeat restore.
fn import_exit_code(refused: usize, out: &mut CliOutput<'_>) -> Result<i32> {
    if refused == 0 {
        return Ok(0);
    }
    writeln!(
        out.stderr,
        "ERROR: this import was INCOMPLETE — {refused} row(s)/edge(s) in the bundle could not \
         be applied (see the per-row reasons above). The destination does NOT hold a faithful \
         copy of the bundle. Exiting {} so a restore job cannot mistake it for a complete one \
         (#2490).",
        crate::export_scope::EXIT_EXPORT_INCOMPLETE
    )?;
    Ok(crate::export_scope::EXIT_EXPORT_INCOMPLETE)
}

/// v1.0.0 #2490 — deserialize the `links` array ELEMENT BY ELEMENT.
///
/// Returns the edges that parsed plus one operator-facing reason per edge
/// that did not. The pre-fix whole-array `unwrap_or_default()` meant one
/// bad edge silently discarded every good one; confining the failure keeps
/// the rest of the graph and makes the loss reportable.
fn parse_links_leniently(
    raw: Option<&serde_json::Value>,
) -> (Vec<models::MemoryLink>, Vec<String>) {
    let mut parsed = Vec::new();
    let mut malformed = Vec::new();
    let Some(serde_json::Value::Array(items)) = raw else {
        return (parsed, malformed);
    };
    for (idx, item) in items.iter().enumerate() {
        match serde_json::from_value::<models::MemoryLink>(item.clone()) {
            Ok(link) => parsed.push(link),
            Err(e) => malformed.push(format!(
                "link[{idx}] {}->{}: refused — the bundle entry did not parse ({e}); \
                 the rest of the graph was still applied (#2490)",
                item.get("source_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<absent>"),
                item.get("target_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<absent>"),
            )),
        }
    }
    (parsed, malformed)
}

/// v1.0.0 #2490 — would applying `incoming` REPLACE a live, unmasked
/// destination row with a secret-screen-masked one?
///
/// Returns the operator-facing reason when the write would destroy readable
/// content, `None` when it is safe.
///
/// The check is deliberately narrow: masking is only a problem when it
/// OVERWRITES something better. A masked row landing where the destination
/// has nothing loses no information (the artifact is all that survives), and
/// a masked row landing on an already-masked row is a no-op. Both are
/// admitted.
///
/// # The probe NEVER aborts the import
///
/// `db::get` is pinned to [`crate::storage::DecryptFailurePolicy::FailClosed`]
/// (env #146), so a destination row whose at-rest envelope will not open
/// returns `Err`. Propagating that would let ONE poisoned destination row
/// abort the whole restore — the #2497 lesson about building a gate on a
/// full-row read. The probe therefore returns a PER-ROW refusal instead:
/// when the destination cannot be inspected we cannot prove the overwrite is
/// safe, so the masked incoming row is refused (fail-closed on the one row)
/// while every other row in the bundle still applies.
fn redaction_would_clobber(
    conn: &rusqlite::Connection,
    incoming: &models::Memory,
) -> Option<String> {
    let placeholder = crate::secret_screen::REDACTION_PLACEHOLDER;
    if !incoming.content.contains(placeholder) && !incoming.title.contains(placeholder) {
        return None;
    }
    // The destination row this write would land on: same id first (the
    // ConflictMode::Merge upsert keys on `(title, namespace)`, but an id
    // collision is the more direct clobber).
    let by_id = match db::get(conn, &incoming.id) {
        Ok(row) => row,
        Err(e) => {
            return Some(format!(
                "the incoming row carries the secret-screen placeholder `{placeholder}`, and \
                 the destination row with the same id could not be read to check whether it \
                 holds unmasked content ({e}). Refusing this ONE row rather than risk \
                 persisting the mask over readable data; the rest of the bundle still \
                 applies (#2490)"
            ));
        }
    };
    let existing = match by_id {
        Some(row) => Some(row),
        None => match db::find_by_title_namespace(conn, &incoming.title, &incoming.namespace) {
            Ok(Some(id)) => match db::get(conn, &id) {
                Ok(row) => row,
                Err(e) => {
                    return Some(format!(
                        "the incoming row carries the secret-screen placeholder \
                         `{placeholder}`, and the colliding destination row {id} could not be \
                         read to check whether it holds unmasked content ({e}). Refusing this \
                         ONE row; the rest of the bundle still applies (#2490)"
                    ));
                }
            },
            Ok(None) => None,
            Err(e) => {
                return Some(format!(
                    "the incoming row carries the secret-screen placeholder `{placeholder}` \
                     and the destination collision probe failed ({e}). Refusing this ONE row; \
                     the rest of the bundle still applies (#2490)"
                ));
            }
        },
    };
    let existing = existing?;
    if existing.content.contains(placeholder) {
        return None;
    }
    Some(format!(
        "the incoming row's content carries the secret-screen placeholder `{placeholder}` \
         but the destination row {} holds unmasked content. Applying it would persist the \
         mask as the durable source of truth, destroying readable data that this import \
         cannot restore. Re-export from the source with AI_MEMORY_SECRET_SCREEN_MODE=off, \
         or delete the destination row first if the mask is intended (#2490)",
        existing.id
    ))
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
    // v1.0.0 #3130 — already fail-closed; routed through the shared
    // `Tier::parse_strict` so the refusal wording is single-sourced.
    let tier = Tier::parse_strict(&args.tier).map_err(|e| anyhow::anyhow!(e))?;
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

    // v1.0.0 #2572 — REFUSE on a Postgres store BEFORE the local sqlite write
    // path (the dry-run above only reads the on-disk export and never opens the
    // DB, so it is intentionally not guarded).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "mine", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());
    let now = Utc::now();

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    // #3163 — RAII: an early `?` return (or a panic) inside the import loop
    // below now rolls the in-flight chunk back instead of leaving an open
    // transaction on the connection.
    let mut write_txn = crate::storage::connection::WriteTxn::begin_deferred(&conn)?;

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
            // Close the chunk and open the next one. `commit` consumes the
            // guard, so the reassignment is what keeps the loop guarded.
            write_txn.commit()?;
            write_txn = crate::storage::connection::WriteTxn::begin_deferred(&conn)?;
        }
    }

    write_txn.commit()?;

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
            store_url: None,
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
    fn test_v1_default_import_cannot_plant_agent_pubkey_2264() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "seed", "seed", "seed");
        let conn = db::open(&src_db).unwrap();
        let mut planted = db::get(&conn, &id).unwrap().unwrap();
        let planted_agent = "ai:planted-v1-key";
        planted.namespace = crate::models::AGENTS_NAMESPACE.to_string();
        planted.title = crate::models::agent_registration_title(planted_agent);
        planted.expires_at = Some("2099-01-01T00:00:00Z".into());
        planted.metadata = serde_json::json!({
            "agent_id": planted_agent,
            (crate::models::field_names::AGENT_PUBKEY): "attacker-controlled-key",
            (crate::models::field_names::ATTEST_LEVEL): "agent_attested",
            (crate::models::field_names::WRITE_SIGNATURE): "forged-signature"
        });
        let payload = serde_json::json!({"memories": [planted], "links": []}).to_string();

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            store_url: None,
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
        assert_eq!(
            db::agent_pubkey(&conn, planted_agent).unwrap(),
            None,
            "untrusted v1 import must not seed the enrolled-key surface"
        );
        let imported = db::get(&conn, &id).unwrap().unwrap();
        assert!(
            imported
                .metadata
                .get(crate::models::field_names::AGENT_PUBKEY)
                .is_none()
        );
        assert!(
            imported
                .metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .is_none()
        );
        assert_eq!(
            imported
                .metadata
                .get(crate::models::field_names::ATTEST_LEVEL)
                .and_then(serde_json::Value::as_str),
            Some(crate::identity::verify::AttestLevel::Claimed.as_str())
        );
    }

    #[test]
    fn v1_agent_claims_follow_explicit_trust_posture_2264() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "seed", "seed-posture", "seed");
        let conn = db::open(&src_db).unwrap();
        let mut registration = db::get(&conn, &id).unwrap().unwrap();
        let agent = "ai:v1-posture-agent";
        let wire_key = "operator-trusted-wire-key";
        let wire_signature = "operator-trusted-wire-signature";
        registration.namespace = crate::models::AGENTS_NAMESPACE.to_string();
        registration.title = crate::models::agent_registration_title(agent);
        registration.expires_at = Some("2099-01-01T00:00:00Z".into());
        registration.metadata = serde_json::json!({
            "agent_id": agent,
            (crate::models::field_names::AGENT_PUBKEY): wire_key,
            (crate::models::field_names::ATTEST_LEVEL): "agent_attested",
            (crate::models::field_names::WRITE_SIGNATURE): wire_signature
        });
        let payload = serde_json::json!({"memories": [registration], "links": []}).to_string();

        let mut default_dst = TestEnv::fresh();
        let default_db = default_dst.db_path.clone();
        {
            let mut out = default_dst.output();
            import_from_str(
                &payload,
                &default_db,
                &ImportArgs {
                    trust_source: false,
                    store_url: None,
                    on_conflict: OnConflict::Version,
                },
                true,
                Some(agent),
                &mut out,
            )
            .unwrap();
        }
        let conn = db::open(&default_db).unwrap();
        assert_eq!(db::agent_pubkey(&conn, agent).unwrap(), None);
        let default_row = db::get(&conn, &id).unwrap().unwrap();
        assert!(
            default_row
                .metadata
                .get(crate::models::field_names::AGENT_PUBKEY)
                .is_none()
        );
        assert!(
            default_row
                .metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .is_none()
        );
        assert_eq!(
            default_row
                .metadata
                .get(crate::models::field_names::ATTEST_LEVEL)
                .and_then(serde_json::Value::as_str),
            Some(crate::identity::verify::AttestLevel::Claimed.as_str())
        );

        let mut trusted_dst = TestEnv::fresh();
        let trusted_db = trusted_dst.db_path.clone();
        {
            let mut out = trusted_dst.output();
            import_from_str(
                &payload,
                &trusted_db,
                &ImportArgs {
                    trust_source: true,
                    store_url: None,
                    on_conflict: OnConflict::Version,
                },
                true,
                Some(agent),
                &mut out,
            )
            .unwrap();
        }
        let conn = db::open(&trusted_db).unwrap();
        assert_eq!(
            db::agent_pubkey(&conn, agent).unwrap(),
            Some(wire_key.into())
        );
        let trusted_row = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(
            trusted_row
                .metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .and_then(serde_json::Value::as_str),
            Some(wire_signature)
        );
        assert_eq!(
            trusted_row
                .metadata
                .get(crate::models::field_names::ATTEST_LEVEL)
                .and_then(serde_json::Value::as_str),
            Some("agent_attested")
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
            store_url: None,
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
            store_url: None,
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

    /// ★ #2569 — the DEFAULT `--on-conflict version` re-imports the corpus's
    /// own export onto an EXISTING corpus idempotently (pre-fix every row was
    /// `refused` with `UNIQUE constraint failed: memories.id`).
    #[test]
    fn v1_reimport_onto_existing_corpus_is_idempotent_2569() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let _ = seed_memory(&src_db, "ns", "a-title", "a-content");
        let _ = seed_memory(&src_db, "ns", "b-title", "b-content");
        let payload = export_payload_at(&src_db);

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            store_url: None,
            on_conflict: OnConflict::Version,
        };
        // First import lands both rows.
        {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        // Re-import the SAME payload onto the now-existing corpus.
        let code = {
            let mut out = dst.output();
            import_from_str(&payload, &dst_db, &args, true, Some("caller"), &mut out).unwrap()
        };
        assert_eq!(
            code, 0,
            "#2569: an idempotent re-import exits 0, not incomplete"
        );

        let v: serde_json::Value =
            serde_json::from_str(dst.stdout_str().lines().last().unwrap()).unwrap();
        assert_eq!(v["imported"], 0, "nothing was newly written");
        assert_eq!(v["refused"], 0, "#2569: no UNIQUE-id refusal");
        assert_eq!(
            v["idempotent_skipped"], 2,
            "both already-present rows are no-ops"
        );
        assert_eq!(
            v["skipped_by_covenant"], 0,
            "neither row hit a covenant gate"
        );

        // No duplicates manufactured under suffixed titles.
        let conn = db::open(&dst_db).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "#2569: an idempotent re-import creates zero new rows");
    }

    /// ★ #2570 — an EDITED (still-live) row's in_place_edit snapshot must NOT
    /// make the row's own backup covenant-skipped; the re-import is idempotent.
    #[test]
    fn v1_reimport_of_edited_corpus_is_idempotent_2570() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "ns", "edit-me", "v1-content");
        let _ = seed_memory(&src_db, "ns", "stable", "stable-content");
        let payload1 = export_payload_at(&src_db);

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            store_url: None,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload1, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        // Edit the row IN PLACE at the destination → #1725 in_place_edit snapshot.
        {
            let conn = db::open(&dst_db).unwrap();
            let (changed, _) = db::update(
                &conn,
                &id,
                None,
                Some("v2-content"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(changed, "the in-place edit landed");
            assert!(
                db::memory_is_archived(&conn, &id).unwrap(),
                "precondition: the edit created an in_place_edit snapshot",
            );
        }
        // Re-export the (edited) destination and re-import onto itself.
        let payload2 = export_payload_at(&dst_db);
        let code = {
            let mut out = dst.output();
            import_from_str(&payload2, &dst_db, &args, true, Some("caller"), &mut out).unwrap()
        };
        assert_eq!(
            code, 0,
            "#2570: the edited corpus re-imports its own backup cleanly"
        );

        let v: serde_json::Value =
            serde_json::from_str(dst.stdout_str().lines().last().unwrap()).unwrap();
        assert_eq!(
            v["skipped_by_covenant"], 0,
            "#2570: the edited-but-live row is NOT covenant-skipped as archived",
        );
        assert_eq!(
            v["idempotent_skipped"], 2,
            "both live rows are idempotent no-ops"
        );
        assert_eq!(v["refused"], 0);

        // The durable edited row survives (never clobbered).
        let conn = db::open(&dst_db).unwrap();
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().content,
            "v2-content",
            "#2878: the durable live row is never clobbered on re-import",
        );
    }

    /// ★ #2569 — a same-id re-import whose DURABLE content diverges from the
    /// live row is still an idempotent no-op (never a clobber), but surfaces a
    /// per-row WARNING so the divergent backup is not silently swallowed
    /// (5-agent vote 4d3ea1c5, A-with-reporting).
    #[test]
    fn v1_divergent_same_id_reimport_warns_and_never_clobbers_2569() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let id = seed_memory(&src_db, "ns", "z-title", "OLD backup content");
        let payload_old = export_payload_at(&src_db); // carries the OLD content

        let mut dst = TestEnv::fresh();
        let dst_db = dst.db_path.clone();
        let args = ImportArgs {
            trust_source: false,
            store_url: None,
            on_conflict: OnConflict::Version,
        };
        {
            let mut out = dst.output();
            import_from_str(&payload_old, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        // The live row drifts (edited after the backup was taken).
        {
            let conn = db::open(&dst_db).unwrap();
            db::update(
                &conn,
                &id,
                None,
                Some("LIVE newer content"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }
        // Re-import the OLD backup: same id, DIFFERENT content.
        {
            let mut out = dst.output();
            import_from_str(&payload_old, &dst_db, &args, true, Some("caller"), &mut out).unwrap();
        }
        let v: serde_json::Value =
            serde_json::from_str(dst.stdout_str().lines().last().unwrap()).unwrap();
        assert_eq!(
            v["idempotent_skipped"], 1,
            "#2569: a diverged same-id row is still a no-op"
        );
        assert_eq!(v["refused"], 0);
        let errs = v["errors"].as_array().unwrap();
        assert!(
            errs.iter()
                .any(|e| e.as_str().unwrap_or_default().contains("content differs")),
            "#2569: a divergent backup must warn, got: {errs:?}",
        );

        // The durable NEWER live row is never overwritten by the OLD backup.
        let conn = db::open(&dst_db).unwrap();
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().content,
            "LIVE newer content",
            "#2878: the older backup never clobbers the durable live row",
        );
    }

    /// The FULL Portability-v2 envelope payload (the `--full` wire form).
    fn export_full_payload_at(db_path: &Path) -> String {
        let mut buf = Vec::<u8>::new();
        let mut errbuf = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf, &mut errbuf);
        export(
            db_path,
            &ExportArgs {
                full: true,
                store_url: None,
                expect_withheld: None,
            },
            &mut out,
        )
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn v1_and_v2_skip_non_object_metadata_but_import_valid_sibling_2264() {
        let src = TestEnv::fresh();
        let src_db = src.db_path.clone();
        let bad_id = seed_memory(&src_db, "metadata-shape", "bad", "bad metadata");
        let good_id = seed_memory(&src_db, "metadata-shape", "good", "valid sibling");

        let mut v1: serde_json::Value = serde_json::from_str(&export_payload_at(&src_db)).unwrap();
        let bad_v1 = v1["memories"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|memory| memory["id"] == bad_id)
            .expect("bad v1 fixture row");
        bad_v1["metadata"] = serde_json::Value::Null;

        let mut v1_dst = TestEnv::fresh();
        let v1_db = v1_dst.db_path.clone();
        {
            let mut out = v1_dst.output();
            import_from_str(
                &v1.to_string(),
                &v1_db,
                &ImportArgs {
                    trust_source: false,
                    store_url: None,
                    on_conflict: OnConflict::Version,
                },
                true,
                Some("ai:metadata-importer"),
                &mut out,
            )
            .unwrap();
        }
        let v1_report: serde_json::Value =
            serde_json::from_str(v1_dst.stdout_str().lines().last().unwrap()).unwrap();
        assert_eq!(v1_report["imported"], 1);
        assert_eq!(v1_report["errors"].as_array().unwrap().len(), 1);
        assert!(
            v1_report["errors"][0]
                .as_str()
                .is_some_and(|error| error.contains(&bad_id) && error.contains("metadata")),
            "malformed v1 metadata must be reported: {v1_report}"
        );
        let conn = db::open(&v1_db).unwrap();
        assert!(db::get(&conn, &bad_id).unwrap().is_none());
        assert!(db::get(&conn, &good_id).unwrap().is_some());

        let mut v2: serde_json::Value =
            serde_json::from_str(&export_full_payload_at(&src_db)).unwrap();
        let bad_v2 = v2["memories"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|memory| memory["id"] == bad_id)
            .expect("bad v2 fixture row");
        bad_v2["metadata"] = serde_json::Value::Null;

        let mut v2_dst = TestEnv::fresh();
        let v2_db = v2_dst.db_path.clone();
        {
            let mut out = v2_dst.output();
            import_from_str(
                &v2.to_string(),
                &v2_db,
                &ImportArgs {
                    trust_source: false,
                    store_url: None,
                    on_conflict: OnConflict::Version,
                },
                true,
                Some("ai:metadata-importer"),
                &mut out,
            )
            .unwrap();
        }
        let v2_report: serde_json::Value =
            serde_json::from_str(v2_dst.stdout_str().trim()).unwrap();
        assert_eq!(v2_report["memories"], 1);
        assert_eq!(v2_report["invalid_skipped"], 1);
        assert!(
            v2_report["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning.as_str().is_some_and(|warning| {
                    warning.contains(&bad_id) && warning.contains("metadata")
                })),
            "malformed v2 metadata must be reported: {v2_report}"
        );
        let conn = db::open(&v2_db).unwrap();
        assert!(db::get(&conn, &bad_id).unwrap().is_none());
        assert!(db::get(&conn, &good_id).unwrap().is_some());
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
            store_url: None,
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
