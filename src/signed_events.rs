// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 / H-track substrate — append-only `signed_events` audit
//! table.
//!
//! # NSA CSI MCP Security mapping
//!
//! Primary defense against **NSA concern (g) Poor or missing audit
//! logs** and contributing implementation of **NSA recommendation (e)
//! Sign and verify MCP messages** + **(g) Instrument for logging and
//! detection** per the NSA Cybersecurity Information document on MCP
//! security (U/OO/6030316-26 \| PP-26-1834, May 2026, Version 1.0).
//! The V-4 cross-row hash chain (`prev_hash` SHA-256 over the prior
//! row's canonical bytes plus monotonic `sequence` counter) makes the
//! audit log tamper-evident even when individual row signatures are
//! valid: tampering with row N's content breaks row N+1's `prev_hash`
//! verification; tampering with `sequence` breaks the contiguity
//! check. Capability inventory anchor:
//! `v4_signed_events_chain` in
//! [`docs/compliance/_inventory/v0.7.0-capabilities.json`](../../docs/compliance/_inventory/v0.7.0-capabilities.json);
//! narrative in
//! [`docs/compliance/nsa-csi-mcp.html`](../../docs/compliance/nsa-csi-mcp.html)
//! §3.7 (concern g) and §4.7 (recommendation g).
//!
//! Each identity-bearing write (today: every `memory_link` insert
//! through `db::create_link` / `db::create_link_signed`) appends one
//! row to `signed_events` so a downstream auditor can replay the
//! exact sequence of attestation events the daemon emitted, without
//! having to scan the mutable `memory_links` table for "what did
//! this row look like at write time" — by construction, the
//! `payload_hash` captured here is SHA-256 over the same canonical-
//! CBOR bytes the H2 signer committed to.
//!
//! # Append-only invariant (row-level)
//!
//! This module exposes ONE writer ([`append_signed_event`]) and
//! ZERO mutators. There are no `UPDATE signed_events` or `DELETE
//! FROM signed_events` statements anywhere in the production
//! codepath. Operators that need to prune (compliance retention,
//! disk pressure) MUST do so via direct SQL with explicit
//! awareness that they are breaking the audit chain — that is the
//! deliberate escape hatch documented in
//! `migrations/sqlite/0020_v07_signed_events.sql`.
//!
//! The H5 test suite asserts (via grep over `src/`) that no
//! `UPDATE signed_events` / `DELETE FROM signed_events` strings
//! appear in production code outside doc comments — adding any
//! such call site will fail the build.
//!
//! # Cross-row tamper evidence (schema v34, #698 V-4 closeout)
//!
//! Since schema v34 the table carries TWO chain columns on top of
//! each row's Ed25519 `signature`:
//!
//! - **`prev_hash BLOB`** — SHA-256 (32 bytes) over the canonical-
//!   bytes encoding of the PRECEDING row (see
//!   [`canonical_chain_bytes`]). First row gets 32 zero bytes.
//! - **`sequence INTEGER`** — monotonically-increasing rank starting
//!   at 1, pinned by a `UNIQUE INDEX`.
//!
//! Together they form a SQL-side hash chain mirroring the JSONL
//! property in [`crate::audit`]. A `DELETE` of row N still passes
//! per-row signature verification on the surviving rows individually,
//! BUT row N+1's stored `prev_hash` will no longer match the
//! recomputed digest of the (now-missing) row N — the chain break is
//! detected at row N+1 by [`verify_chain`]. An `UPDATE` of any
//! column included in the canonical-bytes encoding propagates the
//! same way. A tampered `sequence` breaks the contiguity check.
//!
//! The cross-row chain is the LOAD-BEARING property; per-row Ed25519
//! signatures (the existing `signature` column) remain as defense-in-
//! depth.
//!
//! ## Relationship to [`crate::audit`] (JSONL chain)
//!
//! The JSONL audit log under `<audit_dir>/audit.log` remains the
//! cross-host portable evidence format with its own:
//!
//! - **Cross-line hash chain.** Each JSONL line carries `prev_hash`
//!   pointing to the prior line's `self_hash`; `ai-memory audit
//!   verify` recomputes the chain and exits non-zero on mismatch.
//! - **Monotonic sequence.** F2 (v0.7.0 round-2) wired the sequence
//!   counter to survive process restart so SIEMs detect dropped
//!   lines even before the chain check.
//! - **Append-only OS hint.** Best-effort `chflags(2)` /
//!   `FS_IOC_SETFLAGS`.
//!
//! The SQL chain (this module) is the daemon-local property; the
//! JSONL chain is the portable evidence the daemon hands off to a
//! SIEM. They are complementary, not redundant.
//!
//! ## When to use which surface
//!
//! | Question | Surface |
//! |---|---|
//! | "What did this signed link's bytes look like at write time?" | `signed_events.payload_hash` (binds canonical CBOR) |
//! | "Was the SQL substrate tampered with between `T0` and `T1`?" | `signed_events.prev_hash` + `signed_events.sequence` via [`verify_chain`] |
//! | "Was the on-disk audit log truncated?" | `audit.rs` JSONL chain |
//! | "Did the same key issue the create and the invalidate?" | `signed_events.signature` on both rows |
//!
//! # Out of scope
//!
//! - H4 (`memory_verify` MCP tool, `attest_level` enum surfacing).
//! - H6 (end-to-end test of the immutable chain).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

/// Tracing target for signed-events chain emission/verification log
/// lines across the storage backends (#1558 tracing-target SSOT).
/// Distinct from the `signed_events` SQL table name, which stays
/// embedded in the SQL strings that reference it.
pub(crate) const SIGNED_EVENTS_TRACE_TARGET: &str = "signed_events";

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner B finding F-B9.x) —
// canonical signed_events event-type slugs.
//
// Pre-sweep, `event_type` strings were scattered across ~14
// production sites as inline literals:
//   - "memory_link.created"               (storage::create_link x2, cli::verify, cli::verify_signed_events)
//   - "memory_link.invalidated"           (storage::reflection invalidation)
//   - "memory.stored"                     (cli::verify substrate writer)
//   - "memory.touch"                      (cli::verify touch path)
//   - "reflection.invalidation_notified"  (notification::invalidation)
//   - "reflection.depth_exceeded"         (cli::doctor)
//   - "reflects_on.cycle_refused"         (mcp::link)
//   - "skill.exported"                    (mcp::skill_export)
//   - "skill.registered"                  (mcp::skill_register)
//   - "memory_capture_turn"               (mcp::capture_turn, RFC-0001 L4)
//   - "persona_generated"                 (persona::generate)
//   - "atomisation_complete"              (atomisation::run)
//
// Renaming any slug — or adding a new one without grep-ing every
// candidate writer site — was a substrate-wide search. The
// `event_types` module below centralises every slug as a `&'static
// str` const so a rename is one edit + the writer + downstream
// auditor + replay-tool callsites get the new value mechanically.
// Mirrors the `errors::error_codes` pattern (ARCH-9 / FX-C4-batch2).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub mod event_types {
    /// `signed_events.event_type` for `db::create_link` /
    /// `db::create_link_signed` writes (the canonical link-write audit
    /// emission). 4 production callsites pre-sweep: 2 in
    /// `src/storage/mod.rs` + 1 in `src/cli/verify.rs` + 1 in
    /// `src/cli/verify_signed_events.rs`.
    pub const MEMORY_LINK_CREATED: &str = "memory_link.created";

    /// `signed_events.event_type` for link invalidation via the L2-3
    /// reflection-invalidation walker (`src/storage/mod.rs::5257`).
    pub const MEMORY_LINK_INVALIDATED: &str = "memory_link.invalidated";

    /// `signed_events.event_type` for substrate-side memory inserts
    /// (`src/cli/verify.rs::933`).
    pub const MEMORY_STORED: &str = "memory.stored";

    /// `signed_events.event_type` for substrate-side touch path
    /// (`src/cli/verify.rs::970`).
    pub const MEMORY_TOUCH: &str = "memory.touch";

    /// #1727 (v0.8.0) — `signed_events.event_type` for the CLI-only
    /// `ai-memory undo-edit` operator action: a NON-DESTRUCTIVE undo of
    /// an in-place edit that re-applies the `in_place_edit` snapshot to
    /// the live row via the in-place update path. The audit row captures
    /// the before/after version under a destructive-update label.
    pub const MEMORY_UNDO_IN_PLACE_EDIT: &str = "memory.undo_in_place_edit";

    /// `signed_events.event_type` for notification fan-out by the L2-3
    /// reflection-invalidation walker
    /// (`src/notification/invalidation.rs::278`).
    pub const REFLECTION_INVALIDATION_NOTIFIED: &str = "reflection.invalidation_notified";

    /// `signed_events.event_type` for the recursive-learning depth-cap
    /// trip (`src/cli/doctor.rs::1904`). v0.7.0 #655 Task 1/8.
    pub const REFLECTION_DEPTH_EXCEEDED: &str = "reflection.depth_exceeded";

    /// `signed_events.event_type` for the `reflects_on` cycle refusal
    /// at `src/mcp/tools/link.rs::199` (v0.7.0 #655 Task 1/8 — cycle
    /// detection on reflection chain).
    pub const REFLECTS_ON_CYCLE_REFUSED: &str = "reflects_on.cycle_refused";

    /// `signed_events.event_type` for skill-export emission
    /// (`src/mcp/tools/skill_export.rs::244`).
    pub const SKILL_EXPORTED: &str = "skill.exported";

    /// `signed_events.event_type` for skill-register emission
    /// (`src/mcp/tools/skill_register.rs::226`).
    pub const SKILL_REGISTERED: &str = "skill.registered";

    /// v0.9.0 §11.5 B7-SKILL (#1865) — `signed_events.event_type` for a
    /// skill-invocation capture, emitted by `memory_skill_get`
    /// (`src/mcp/tools/skill_get.rs`) every time an agent fetches a
    /// skill's activation payload. Best-effort / unsigned (no
    /// `active_keypair` is threaded through the read path); the row
    /// still gives an append-only, tamper-evident-chained record of
    /// which agent activated which skill id and when.
    pub const SKILL_INVOKED: &str = "skill.invoked";

    /// `signed_events.event_type` for the L4 `memory_capture_turn`
    /// MCP tool emission per RFC-0001 (`src/mcp/tools/capture_turn.rs::472`).
    pub const MEMORY_CAPTURE_TURN: &str = "memory_capture_turn";

    /// `signed_events.event_type` for persona regeneration
    /// (`src/persona/mod.rs::787`). v0.7.0 QW-2 persona-as-artifact.
    pub const PERSONA_GENERATED: &str = "persona_generated";

    /// `signed_events.event_type` for WT-1-C atomisation completion
    /// (`src/atomisation/mod.rs::943`). v0.7.0 Batman Form 1-4
    /// atomisation engine.
    pub const ATOMISATION_COMPLETE: &str = "atomisation_complete";

    /// `signed_events.event_type` for an outbound federation credential
    /// renewal — emitted by the file-refresh renewal worker
    /// (`src/federation/identity/renewal.rs`) on every tick that swaps a
    /// freshly-issued credential into the live send path
    /// ([`crate::federation::identity::renewal::RenewalOutcome::Reloaded`]).
    /// This is the FED-P4-f §8 audit obligation: the node's own
    /// credential lifecycle is recorded in the tamper-evident chain.
    /// Issuance (`FederationIssuer`) is centrally operated and revocation
    /// is by self-expiry (no CRL — see `issuer.rs`), so renewal is the
    /// only node-local lifecycle transition there is to audit.
    pub const FED_CREDENTIAL_RENEWED: &str = "federation.credential_renewed";

    /// `signed_events.event_type` for operator-authorized governance-rule
    /// deletion via `ai-memory rules remove --sign`
    /// (`src/governance/rules_store.rs::remove_signed`). Closes the
    /// audit gap where a `DELETE FROM governance_rules` left no
    /// tamper-evident trace of WHICH rule the operator removed; the
    /// emitted row's `payload_hash` is the SHA-256 over the removed
    /// rule's canonical signing bytes and `signature` is the operator's
    /// Ed25519 signature over that hash.
    pub const GOVERNANCE_RULE_REMOVED: &str = "governance.rule_removed";

    /// #1955 [P1][R45] — `signed_events.event_type` for the substrate
    /// record-stop actuation (`ai-memory stop`). The append-only chain
    /// IS the persisted stop flag: the latest of this event and
    /// [`SUBSTRATE_RECORD_RESUME`] (by `sequence`) determines whether the
    /// record plane is stopped. `agent_id` = the issuer; `payload_hash`
    /// commits `{action, issued_by, timestamp, scope}`.
    pub const SUBSTRATE_RECORD_STOP: &str = "substrate.record_stop";

    /// #1955 [P1][R45] — `signed_events.event_type` for releasing the
    /// substrate record-stop (`ai-memory stop --resume`). The un-stop
    /// sibling of [`SUBSTRATE_RECORD_STOP`].
    pub const SUBSTRATE_RECORD_RESUME: &str = "substrate.record_resume";

    /// #1956 [P1][R56] — `signed_events.event_type` for the ERASURE
    /// ATTESTATION emitted on every delete/erase path. Commits
    /// `{record id, erasure-kind, actor, timestamp}` where erasure-kind is
    /// `key-destroyed` (an encrypted per-record row whose envelope DEK was
    /// destroyed → ciphertext cryptographically unrecoverable) or
    /// `row-deleted-tombstoned` (a plaintext / legacy-encrypted row that
    /// could only be row-deleted + tombstoned). Chained + verified by
    /// `verify_audit_trail` like every other signed event; the honest
    /// crypto-erase-vs-delete boundary lives in the erasure-kind field.
    pub const SUBSTRATE_CRYPTO_ERASE: &str = "substrate.crypto_erase";

    /// v0.9.0 §25.3 S3 (F-40, #1853) — `signed_events.event_type` for an
    /// operator-authorized governance-rule DISABLE via
    /// `ai-memory rules disable --sign`
    /// (`src/governance/rules_store.rs::set_enabled_signed`). Closes the
    /// two-statement atomicity gap the CLI had before: a disable is a
    /// silent neuter of an enforcement rule, so it MUST leave a
    /// tamper-evident residue. `payload_hash` = SHA-256 over the rule's
    /// canonical signing bytes with `enabled = false` committed;
    /// `signature` = the operator's Ed25519 over that hash.
    pub const GOVERNANCE_RULE_DISABLED: &str = "governance.rule_disabled";

    /// v0.9.0 §25.3 S3 (F-40, #1853) — the ENABLE twin of
    /// [`GOVERNANCE_RULE_DISABLED`], emitted by
    /// `set_enabled_signed` on `ai-memory rules enable --sign`. Same
    /// payload/signature shape with `enabled = true` committed.
    pub const GOVERNANCE_RULE_ENABLED: &str = "governance.rule_enabled";

    /// v0.9.0 §25.3 S4 (F-41, #1853) — `signed_events.event_type` for a
    /// monotonic policy-version advance, emitted INSIDE the same
    /// transaction as every signed governance-rule mutation
    /// (`remove_signed`, `set_enabled_signed`, and the CLI `rules add
    /// --sign` path). `payload_hash` = SHA-256 over `seq.to_be_bytes()
    /// || digest`, where `digest` is the whole-ruleset policy digest
    /// (SHA-256 over the id-sorted canonical bytes of all ENABLED rules,
    /// see `src/governance/policy_version.rs`) and `seq` is the
    /// post-advance sequence; `signature` = the operator's Ed25519 over
    /// that hash. Monotonicity is the append-only event count.
    pub const GOVERNANCE_POLICY_ADVANCED: &str = "governance.policy_version_advanced";

    /// v0.9.0 §25.3 S2 (D3-021, #1767) — `signed_events.event_type` for a
    /// write-time DECORRELATION REFUSAL: an `enforce`-mode reflection
    /// write refused because the target namespace corpus + incoming write
    /// span fewer than the required N DISTINCT ATTESTED model families
    /// (evidence-backed attested monoculture). `payload_hash` = SHA-256
    /// over the canonical-CBOR of the structured refusal fields
    /// (namespace, distinct_attested_families, attested_rows, quorum_n,
    /// source ids, title); `attest_level = "unsigned"` (substrate-emitted,
    /// like `reflection.depth_exceeded`). CLAIMED-only monocultures are
    /// NEVER refused (they stay advisory), so this row only ever attests a
    /// refusal grounded in attested evidence.
    pub const REFLECTION_DECORRELATION_REFUSED: &str = "reflection.decorrelation_refused";

    /// v0.9.0 G13 (#1828) — witness row for an identity-lineage GENESIS
    /// record (epoch 0, self-signed by `K0`). `payload_hash` =
    /// SHA-256 over the `LINEAGE_DOMAIN`-tagged canonical bytes the
    /// predecessor signed; `signature` = the succession signature;
    /// `attest_level` = `"lineage_signed"`. Written in the SAME
    /// transaction as the `agent_lineage` body row (C4) — this row is
    /// the append-only anchor that pins genesis at enroll-time (C1).
    pub const IDENTITY_LINEAGE_GENESIS: &str = "identity.lineage.genesis";

    /// v0.9.0 G13 (#1828) — witness row for an identity-lineage
    /// ROTATION record (`K_old` hands off to `K_new`). Same payload /
    /// signature shape as [`IDENTITY_LINEAGE_GENESIS`].
    pub const IDENTITY_LINEAGE_SUCCESSION: &str = "identity.lineage.succession";

    /// v0.9.0 G13 (#1828) — witness row for an identity-lineage
    /// RECOVERY record. RESERVED for the v1.0 recovery path: the slug
    /// exists now so the event-type vocabulary is forward-stable, but
    /// no v0.9.0 production writer emits it (the append paths refuse
    /// `reason = recovery` until the recovery VERIFY path lands).
    pub const IDENTITY_LINEAGE_RECOVERY: &str = "identity.lineage.recovery";

    /// v1.0.0 #1949 (R13) — witness row for an identity-lineage
    /// REVOCATION record: the head key signs a record dating a suspected
    /// compromise from a `signed_events` witness SEQUENCE high-water mark.
    /// Same payload / signature shape as [`IDENTITY_LINEAGE_GENESIS`]; the
    /// row's own sequence is `S_rev` (the upper bound of the Suspect
    /// window `[suspected_compromise_from_seq, S_rev)`).
    pub const IDENTITY_LINEAGE_REVOCATION: &str = "identity.lineage.revocation";

    /// v0.9.0 §25.3 S5 (RQ-10, #1853) — witness row for an accepted,
    /// operator-signed epoch manifest (the monotonic panel/utility-weight
    /// freeze for one epoch), written by `ai-memory epoch-apply` in the
    /// SAME transaction as the resolved `EpochAdvance` checkpoint. The
    /// row's `payload_hash` is the manifest's content SHA-256 (the triple
    /// anchor: signed file + resolved checkpoint + this row share ONE
    /// hash) and `signature` is the operator's Ed25519. The const NAME is
    /// deliberately `EPOCH_APPLIED` (the L3-boundary gate bans the
    /// underscore-joined `epoch`+`manifest` spelling in src/ — see
    /// ROADMAP §25.2/§25.3); the ruled STRING value
    /// `"epoch.manifest_applied"` is gate-clean because the `.` separator
    /// breaks the banned pattern.
    pub const EPOCH_APPLIED: &str = "epoch.manifest_applied";

    /// v1.0.0 #1963 (R68/D14) — `signed_events.event_type` for an
    /// INFERENCE-PLANE egress refusal: the substrate refused to construct
    /// an outbound LLM / embedding client because the resolved target was
    /// disallowed by the [`crate::egress::InferenceEgressMode`] posture
    /// (`AI_MEMORY_INFERENCE_EGRESS=deny` or `loopback-only` against an
    /// external vendor). `payload_hash` = SHA-256 over the canonical
    /// pre-image of the (non-secret) egress class + target base URL +
    /// reason; substrate-emitted (`daemon_signed` when a key is enrolled,
    /// else `unsigned`), the same posture as
    /// [`REFLECTION_DECORRELATION_REFUSED`]. The refused client is never
    /// constructed, so no memory content ever leaves the host for the
    /// refused vendor — this row is the audit witness of that refusal.
    pub const EGRESS_INFERENCE_REFUSED: &str = "egress.inference_refused";

    /// v1.0.0 V08-PE-3 (#1937, ratified spec — the `4d3ea1c5` minimal
    /// shape recorded in #1840's closing 2×5 vote) —
    /// `signed_events.event_type` for a MINIMAL signed spawn-audit row:
    /// exactly ONE row per PRODUCTION `Command` spawn, emitted by the
    /// [`crate::spawn_audit`] chokepoint the moment a production spawn
    /// site launches a subprocess. `payload_hash` = SHA-256 over the
    /// canonical, secret-free pre-image
    /// [`crate::spawn_audit::spawn_audit_preimage`] carrying ONLY
    /// `argv0` (the spawned program) + `caller` (the spawn-site
    /// identity) — never the full argv, which may carry secrets.
    /// Substrate-emitted (`daemon_signed` when an audit key is enrolled,
    /// else `unsigned`), the same posture as [`EGRESS_INFERENCE_REFUSED`]
    /// / [`REFLECTION_DECORRELATION_REFUSED`]. Chained + walked +
    /// verified by [`verify_audit_trail`] as a FIRST-CLASS signed event
    /// like every other row (the chain walk is event-type-agnostic, so a
    /// spawn row participates in the same cross-row hash chain + per-row
    /// signature verdict). The substrate attests its OWN spawns — this is
    /// deliberately NOT eBPF / dtrace kernel process-tree tracing.
    pub const PROCESS_SPAWN_AUDITED: &str = "process.spawn_audited";

    /// v1.0.0 G28 (#1838) — `signed_events.event_type` for a forbidden
    /// export-class refusal at an export boundary (forensic bundle,
    /// memory export). Emitted by
    /// [`crate::export_taxonomy::screen_export_value_audited`] when a
    /// candidate export record is classified into one of the closed
    /// [`crate::export_taxonomy::ForbiddenExportClass`] classes (private
    /// key material, master/threshold secret, governance-rule signing
    /// key, biometric/behavioral embedding) that must NEVER cross the
    /// export boundary. `payload_hash` = SHA-256 over the canonical
    /// pre-image of the (non-secret) forbidden class + the artifact path
    /// the record would have occupied + the reason; substrate-emitted
    /// (`daemon_signed` when a key is enrolled, else `unsigned`), the
    /// same posture as [`EGRESS_INFERENCE_REFUSED`]. The refused record
    /// is never emitted into the export artifact — this row is the audit
    /// witness of that fail-closed redaction.
    pub const EXPORT_FORBIDDEN_CLASS_REFUSED: &str = "export.forbidden_class_refused";
}

/// v0.9.0 G13 (#1828) + v1.0.0 #1949 — the `identity.lineage.*` witness
/// event types, in one place for the (agent-scoped) witness reads both
/// backends run. Order matches the epoch-0-first narrative; the SQL
/// reads treat it as a set. #1949 appends `IDENTITY_LINEAGE_REVOCATION`.
pub const IDENTITY_LINEAGE_EVENT_TYPES: [&str; 4] = [
    event_types::IDENTITY_LINEAGE_GENESIS,
    event_types::IDENTITY_LINEAGE_SUCCESSION,
    event_types::IDENTITY_LINEAGE_RECOVERY,
    event_types::IDENTITY_LINEAGE_REVOCATION,
];

/// One row of the `signed_events` audit table.
///
/// `id` is a UUIDv4 minted by the writer; `payload_hash` is the
/// 32-byte SHA-256 over the canonical-CBOR bytes that H2 hashed for
/// the original signature; `signature` mirrors the source row's
/// `memory_links.signature` (NULL when the source write was
/// unsigned).
///
/// `prev_hash` and `sequence` are populated by
/// [`append_signed_event`] (writer fills them from the current chain
/// head — callers MUST NOT set them) and by [`row_to_event`] on read
/// (selecting back rows from the table).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignedEvent {
    pub id: String,
    pub agent_id: String,
    pub event_type: String,
    pub payload_hash: Vec<u8>,
    pub signature: Option<Vec<u8>>,
    pub attest_level: String,
    pub timestamp: String,
    /// v34 — SHA-256 (32 bytes) over the canonical-bytes encoding of
    /// the preceding row, or 32 zero bytes for the first row. Filled
    /// by [`append_signed_event`] at insert time; callers MUST NOT
    /// pre-populate this field — any value set by the caller is
    /// ignored. Use `..SignedEvent::default()` at the struct-literal
    /// tail to leave this empty.
    pub prev_hash: Vec<u8>,
    /// v34 — monotonically-increasing chain rank starting at 1.
    /// Filled by [`append_signed_event`] at insert time; callers MUST
    /// NOT pre-populate this field — any value set by the caller is
    /// ignored. Use `..SignedEvent::default()` at the struct-literal
    /// tail to leave this zero.
    pub sequence: i64,
    /// v73 (#1822, v0.9.0 G5a) — audit cause-binding. When `Some`, a
    /// 32-byte SHA-256 over the screened, identity-only pre-image of
    /// the TRIGGERING CAUSE of this write (see [`compute_cause_hash`]).
    /// `None` when no cause is bound (additive — not every event needs
    /// one yet). Present-only in the chain: a `None` cause contributes
    /// ZERO bytes and ZERO separators to [`canonical_chain_bytes`], so
    /// legacy rows hash byte-identically to pre-v73. When present it is
    /// ALSO folded into the per-row Ed25519 signing input, so tampering
    /// the cause is caught by BOTH the next row's `prev_hash` link and
    /// this row's own signature. Set explicitly (or left `None` via
    /// `..SignedEvent::default()`); unlike `prev_hash`/`sequence` this
    /// IS a caller-supplied field carried verbatim into the row.
    pub cause_hash: Option<Vec<u8>>,
}

impl SignedEvent {
    /// v0.7.0 #1099 (SR-1 #4, HIGH) — build a `SignedEvent` that
    /// consults the process-wide daemon audit signing key (installed
    /// at boot via [`crate::governance::audit::init`]) and applies it
    /// to `payload_hash`. When a key is installed, the returned row
    /// carries `signature: Some(sig_bytes)` + `attest_level:
    /// "daemon_signed"`; when no key is installed, falls back to
    /// `signature: None, attest_level: "unsigned"`.
    ///
    /// Homogenises every production audit-row writer (pending_action
    /// approve/reject/timeout, federation.quota_refused on both
    /// sqlite + postgres paths, governance.check) so a downstream
    /// auditor sees per-row signatures matching the daemon's
    /// `VerifyingKey` and the cross-row chain head together.
    ///
    /// The other chain columns (`prev_hash`, `sequence`) are left at
    /// their defaults — [`append_signed_event`] fills them at INSERT
    /// time. Callers MUST NOT pre-populate them.
    ///
    /// # v73 (#1822, G5a) — cause-binding
    ///
    /// `cause_hash` binds the TRIGGERING CAUSE of the write (see
    /// [`compute_cause_hash`]). When `Some`, the daemon signs the
    /// cause-folded digest `SHA-256(payload_hash || 0x1F || cause)`
    /// (via [`signing_input_bytes`]) so the signature commits to the
    /// cause as well as the payload; the value is also carried into the
    /// row's `cause_hash` column (and thus [`canonical_chain_bytes`]).
    /// When `None`, the daemon signs `payload_hash` verbatim exactly as
    /// before — every legacy caller passing `None` produces a
    /// byte-identical signing input and row.
    #[must_use]
    pub fn with_daemon_signature(
        payload_hash: Vec<u8>,
        agent_id: String,
        event_type: String,
        timestamp: String,
        cause_hash: Option<&[u8]>,
    ) -> Self {
        let signing_input = signing_input_bytes(&payload_hash, cause_hash);
        let (signature, attest_level) =
            match crate::governance::audit::try_sign_audit_payload(&signing_input) {
                Some((sig_bytes, tag)) => (Some(sig_bytes), tag.to_string()),
                None => (
                    None,
                    crate::models::AttestLevel::Unsigned.as_str().to_string(),
                ),
            };
        SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id,
            event_type,
            payload_hash,
            signature,
            attest_level,
            timestamp,
            cause_hash: cause_hash.map(<[u8]>::to_vec),
            ..SignedEvent::default()
        }
    }
}

/// All-zeros 32-byte digest used as `prev_hash` for the first row.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// SQL that reads the `signed_events` chain HEAD — the highest surviving
/// `sequence` in the whole table (`NULL`/empty → 0). Shared SSOT so the
/// sqlite `verify_audit_trail`, the postgres twin, the #1946 open-time
/// rollback check, and the `audit restore-attest` CLI all read the head
/// identically (pm-v3.1 literal de-dup). Bind-parameter-free (no `?`/`$1`).
pub const CHAIN_HEAD_SQL: &str =
    "SELECT COALESCE(MAX(sequence), 0) FROM signed_events WHERE sequence IS NOT NULL";

/// Field separator formerly used by [`canonical_chain_bytes`]. ASCII 0x1F
/// ("Unit Separator"). RETAINED as the delimiter of the v73 cause pre-image
/// ([`compute_cause_hash`] / [`signing_input_bytes`]), where every joined
/// field is a fixed-width digest or short identifier — NOT for the chain
/// encoding, which was migrated to length-prefixing by #1930 (see below).
const FIELD_SEP: u8 = 0x1F;

/// #1930 (CWE-345) — append a length-prefixed field (u64 big-endian length
/// then the raw bytes) to the chain-hash input. Length-prefixing makes the
/// encoding INJECTIVE: no data byte inside a `payload_hash`/`signature` BLOB
/// (which are arbitrary 32-/64-byte values that DO contain 0x1F ~1/256 of the
/// time) can be confused with a structural delimiter, so two distinct column
/// tuples can never collide to the same canonical bytes. Mirrors
/// `ReplayCache::fingerprint`'s discipline (`src/identity/replay.rs`).
fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

/// Canonical bytes used as the chain-hash input.
///
/// Commits to every column that identifies the row's content —
/// `id`, `agent_id`, `event_type`, `payload_hash`, `signature`,
/// `attest_level`, `timestamp`, `sequence`, and (present-only) `cause_hash` —
/// each **length-prefixed** (u64-BE length, then bytes) so the concatenation
/// is unambiguous WITHOUT relying on a separator byte that could collide with
/// arbitrary BLOB data (#1930, CWE-345). `sequence` is a fixed-width 8-byte
/// big-endian integer; the present-only `cause_hash` is preceded by a single
/// `1`/`0` presence tag so a `None` cause and an empty-`Some` cause stay
/// distinct.
///
/// Each row's `prev_hash` is `SHA-256(canonical_chain_bytes(prev_row))`,
/// or [`ZERO_HASH`] for the first row. A future hash-agility migration can
/// change the digest in one place; the encoding is byte-stable so an auditor
/// can replay the chain from the stored columns alone.
///
/// NOTE (#1930 migration): this length-prefixed encoding is NOT byte-identical
/// to the pre-#1930 0x1F-separated encoding, so a chain grown across the
/// upgrade re-anchors from the first row appended by the new binary. The
/// encoding is shared verbatim by the sqlite writer/verifier, the postgres
/// twin, and the v34 backfill, so all of them move in lockstep.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // field lengths fit u64 on every supported target
pub fn canonical_chain_bytes(event: &SignedEvent) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(
        event.id.len()
            + event.agent_id.len()
            + event.event_type.len()
            + event.payload_hash.len()
            + event.signature.as_ref().map_or(0, Vec::len)
            + event.attest_level.len()
            + event.timestamp.len()
            + 8 // sequence
            + 8 * 8 // eight u64 length prefixes
            + 1 // cause presence tag
            + event.cause_hash.as_ref().map_or(0, |c| 8 + c.len()),
    );
    push_len_prefixed(&mut out, event.id.as_bytes());
    push_len_prefixed(&mut out, event.agent_id.as_bytes());
    push_len_prefixed(&mut out, event.event_type.as_bytes());
    push_len_prefixed(&mut out, &event.payload_hash);
    push_len_prefixed(&mut out, event.signature.as_deref().unwrap_or(&[]));
    push_len_prefixed(&mut out, event.attest_level.as_bytes());
    push_len_prefixed(&mut out, event.timestamp.as_bytes());
    out.extend_from_slice(&event.sequence.to_be_bytes());
    // v73 (#1822, G5a) — present-only cause fold, now with an explicit
    // presence tag so `None` (tag 0) and `Some(&[])` (tag 1, len 0) are
    // distinguishable and no separator ambiguity can arise.
    match event.cause_hash.as_deref() {
        Some(cause) => {
            out.push(1);
            push_len_prefixed(&mut out, cause);
        }
        None => out.push(0),
    }
    out
}

/// Domain-separation prefix for the audit cause-binding pre-image
/// ([`compute_cause_hash`]). The trailing NUL byte keeps the prefix
/// unambiguous against any `caller_agent_id` that begins with the same
/// ASCII bytes. Versioned (`-v1`) so a future pre-image change is a
/// distinct domain rather than a silent collision.
const CAUSE_PREIMAGE_DOMAIN: &[u8] = b"audit-cause-v1\0";

/// v73 (#1822, v0.9.0 G5a) — compute the `cause_hash` binding the
/// TRIGGERING CAUSE of an audit-bearing write.
///
/// Returns the 32-byte SHA-256 over
/// `CAUSE_PREIMAGE_DOMAIN || caller_agent_id || 0x1F || action_kind ||
///  0x1F || action_id || 0x1F || input_digest`, where `input_digest`
/// is itself SHA-256 over the SECRET-SCREENED `input_args`.
///
/// # K4 — credential-leak guard (load-bearing)
///
/// `input_args` is run through [`crate::secret_screen::screen`] BEFORE
/// it enters the pre-image. On a [`Hit`](crate::secret_screen::ScreenOutcome::Hit)
/// only the REDACTED form is folded — the raw credential bytes never
/// reach the hash input — so a screened AWS key / PEM block / JWT is
/// unrecoverable from the stored `cause_hash`. A
/// [`Clean`](crate::secret_screen::ScreenOutcome::Clean) input passes
/// through verbatim. The digest is one-way regardless, so the stored
/// column reveals nothing about the args even on a Clean input.
///
/// # K5 — low-entropy pre-image residual (decision)
///
/// We KEEP `input_digest` rather than dropping the cause to
/// identity-only (`agent || kind || id`). The cause-binding's security
/// goal is tamper-EVIDENCE — committing the cause into the append-only
/// chain — not confidentiality of the (already non-secret, post-screen)
/// args. The accepted residual: an offline dictionary attack could
/// recover a LOW-entropy screened-args pre-image from `input_digest`.
/// That is tolerated because (a) the args are identity-derived and
/// carry no secret after screening, and (b) recovering them yields
/// nothing an auditor holding table-read access cannot already read
/// from the row's other identity columns. A future callsite feeding
/// genuinely sensitive inputs should pass identity-only args (empty
/// `input_args`) so no residual exists.
#[must_use]
pub fn compute_cause_hash(
    caller_agent_id: &str,
    action_kind: &str,
    action_id: &str,
    input_args: &str,
) -> Vec<u8> {
    // K4: screen first; fold only the redacted form on a Hit.
    let screened = match crate::secret_screen::screen(input_args) {
        crate::secret_screen::ScreenOutcome::Clean => input_args.to_string(),
        crate::secret_screen::ScreenOutcome::Hit { redacted, .. } => redacted,
    };
    let input_digest = payload_hash(screened.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(CAUSE_PREIMAGE_DOMAIN);
    hasher.update(caller_agent_id.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(action_kind.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(action_id.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(&input_digest);
    hasher.finalize().to_vec()
}

/// v73 (#1822, G5a) — the exact bytes the daemon Ed25519 key signs for
/// a `signed_events` row. When a cause is bound the signature commits
/// to BOTH the payload and the triggering cause via
/// `SHA-256(payload_hash || 0x1F || cause_hash)`; otherwise it is the
/// `payload_hash` verbatim (legacy rows sign byte-identically to
/// pre-v73). Shared by [`SignedEvent::with_daemon_signature`] (signing)
/// and [`verify_chain`] (verification) so the two never drift.
#[must_use]
pub(crate) fn signing_input_bytes(payload_hash: &[u8], cause_hash: Option<&[u8]>) -> Vec<u8> {
    match cause_hash {
        Some(cause) => {
            let mut hasher = Sha256::new();
            hasher.update(payload_hash);
            hasher.update([FIELD_SEP]);
            hasher.update(cause);
            hasher.finalize().to_vec()
        }
        None => payload_hash.to_vec(),
    }
}

/// #1925 (CWE-347) — domain tag for the per-row daemon identity-bound
/// signature pre-image. Versioned so a future pre-image change is a distinct
/// domain rather than a silent collision.
const DAEMON_ROW_SIG_DOMAIN: &[u8] = b"ai-memory/signed-events/row-v1\0";

/// #1925 (CWE-347) — the identity-bearing bytes the daemon audit key signs for
/// a `signed_events` row, so the per-row signature commits to the FULL
/// attribution tuple (`id`, `agent_id`, `event_type`, `attest_level`,
/// `timestamp`, `sequence`, `payload_hash`, and present-only `cause_hash`) —
/// not `payload_hash` alone.
///
/// Pre-#1925 the daemon signature bound only `payload_hash`, so a co-tenant
/// with write access to the local `ai-memory.db` file could rewrite the
/// chain-HEAD row's `agent_id` / `event_type` / `timestamp` / `attest_level`
/// (the head has no successor row whose `prev_hash` would catch the edit) and
/// [`verify_chain`] still passed all three checks. Binding the identity tuple
/// makes any such single-row mutation invalidate the row's OWN signature,
/// independent of the cross-row hash chain — mirroring the JSONL forensic
/// sink, which already signs the full canonical row.
///
/// Length-prefixed (the #1930 injectivity discipline) so no field value can be
/// confused with another. Returns the 32-byte SHA-256 the Ed25519 key signs.
///
/// Public so an external auditor (or a forensic tool) can recompute the exact
/// bytes the daemon key signed for a `signed_events` row and re-verify it — the
/// same input [`append_signed_event`] signs and [`classify_row_signature`]
/// verifies (sign/verify symmetry).
#[must_use]
#[allow(clippy::cast_possible_truncation)] // field lengths fit u64 on every supported target
pub fn daemon_row_signing_input(event: &SignedEvent) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(DAEMON_ROW_SIG_DOMAIN);
    for field in [
        event.id.as_bytes(),
        event.agent_id.as_bytes(),
        event.event_type.as_bytes(),
        event.attest_level.as_bytes(),
        event.timestamp.as_bytes(),
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.update(event.sequence.to_be_bytes());
    h.update((event.payload_hash.len() as u64).to_be_bytes());
    h.update(&event.payload_hash);
    match event.cause_hash.as_deref() {
        Some(c) => {
            h.update([1u8]);
            h.update((c.len() as u64).to_be_bytes());
            h.update(c);
        }
        None => h.update([0u8]),
    }
    h.finalize().to_vec()
}

/// Read the chain head — `(max_sequence, prev_canonical_hash)`.
///
/// Returns `(0, ZERO_HASH)` for an empty table. The "previous"
/// canonical hash is the SHA-256 over the canonical bytes of the
/// row with the highest sequence; the next inserted row's
/// `prev_hash` is exactly this value.
///
/// # Cluster-C COR-9 (issue #767): NULL-sequence diagnostic
///
/// Prior to this fix the query was
/// `SELECT … COALESCE(sequence, 0) … ORDER BY COALESCE(sequence, 0) DESC`,
/// which silently treated a row whose `sequence IS NULL` (a
/// pre-v34 row that the v34 backfill missed) as sequence == 0 and
/// would then issue `next_seq = 1`, colliding with the legitimately-
/// backfilled first row on the UNIQUE index. The mask hid a real
/// migration-needed state behind a misleading SQLITE_CONSTRAINT_UNIQUE.
///
/// We now restrict the head SELECT to `WHERE sequence IS NOT NULL`,
/// and issue a SEPARATE diagnostic SELECT that asserts no
/// `sequence IS NULL` rows exist. If any are found post-v34 the
/// function returns a clear error and emits `tracing::error!` so an
/// operator can run `ai-memory migrate` (or invoke
/// `migrate_v34_backfill_chain` directly) to repair the chain.
fn read_chain_head(conn: &Connection) -> Result<(i64, [u8; 32])> {
    // COR-9 diagnostic: hard-fail on NULL-sequence rows so a
    // partially-migrated DB never silently produces a duplicate
    // sequence. The v34 backfill is idempotent — operators recovering
    // from this error re-run the migration ladder.
    let null_seq_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE sequence IS NULL",
            [],
            |row| row.get(0),
        )
        .context("read_chain_head: null-sequence diagnostic")?;
    if null_seq_count > 0 {
        tracing::error!(
            null_sequence_rows = null_seq_count,
            "signed_events: found {null_seq_count} row(s) with sequence IS NULL — \
             v34 chain backfill is incomplete. Re-run the migration ladder \
             (`ai-memory migrate` or restart with the current binary) to \
             stamp prev_hash + sequence on the unmigrated rows; refusing to \
             append further audit rows until the chain is repaired."
        );
        anyhow::bail!(
            "read_chain_head: {null_seq_count} signed_events row(s) have sequence IS NULL — \
             v34 chain backfill incomplete; re-run `ai-memory migrate`"
        );
    }

    // Pull the column shape that `canonical_chain_bytes` needs,
    // ordered by sequence DESC so the head is the first row. Restrict
    // to non-NULL sequences (the diagnostic above guarantees this
    // matches every row, but the WHERE makes the read itself robust
    // against a TOCTOU window if a concurrent unmigrated INSERT
    // landed between the diagnostic and this query).
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, sequence, cause_hash \
             FROM signed_events \
             WHERE sequence IS NOT NULL \
             ORDER BY sequence DESC, rowid DESC \
             LIMIT 1",
        )
        .context("read_chain_head: prepare")?;
    let head: Option<SignedEvent> = stmt
        .query_map([], |row| {
            Ok(SignedEvent {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                event_type: row.get(2)?,
                payload_hash: row.get(3)?,
                signature: row.get(4)?,
                attest_level: row.get(5)?,
                timestamp: row.get(6)?,
                sequence: row.get(7)?,
                // v73: read the head's cause so the next row's prev_hash
                // commits to it (present-only in the canonical bytes).
                cause_hash: row.get::<_, Option<Vec<u8>>>(8)?,
                prev_hash: Vec::new(), // not part of the canonical bytes
            })
        })
        .context("read_chain_head: query_map")?
        .next()
        .transpose()
        .context("read_chain_head: collect")?;
    match head {
        None => Ok((0, ZERO_HASH)),
        Some(prev) => {
            let max_seq = prev.sequence;
            let canon = canonical_chain_bytes(&prev);
            let mut hasher = Sha256::new();
            hasher.update(&canon);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&hasher.finalize());
            Ok((max_seq, digest))
        }
    }
}

/// Outcome of a [`verify_chain`] pass over the `signed_events` table.
///
/// `rows_checked` counts every row the verifier walked.
/// `chain_break` is `Some(sequence)` when the FIRST detected break
/// happens — that row's stored `prev_hash` does not equal
/// SHA-256(canonical_chain_bytes(row N-1)), OR the row's `sequence`
/// is not the expected `prior + 1` (gap / duplicate / non-monotonic
/// jump). `signature_failures` records sequences whose Ed25519
/// signature did not verify against the supplied key set — the
/// chain itself may still be intact even if individual signatures
/// fail (defense-in-depth split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerificationReport {
    pub rows_checked: u64,
    pub chain_break: Option<i64>,
    pub signature_failures: Vec<i64>,
    /// v0.9.0 G9 (#1826) — sequences of ROLE-SEPARATION failures disjoint from
    /// `signature_failures`: a `recorder_signed` row that failed verification
    /// against the enrolled recorder pubkey, OR a `daemon_signed` governance
    /// row DEMOTED because a recorder key is now enrolled (C2). Empty in the
    /// legacy posture (no recorder key enrolled).
    pub role_separation_failures: Vec<i64>,
}

impl ChainVerificationReport {
    /// `true` when the cross-row chain held end-to-end. Per-row
    /// signature failures are surfaced separately because they are a
    /// disjoint property (a chain break is structurally worse than a
    /// signature failure).
    #[must_use]
    pub fn chain_holds(&self) -> bool {
        self.chain_break.is_none()
    }
}

/// Walk all rows in `sequence` order and verify the cross-row chain
/// + per-row signatures.
///
/// For each row:
///   1. Check `sequence == prior + 1` (first row: `sequence == 1`).
///   2. Recompute SHA-256 over [`canonical_chain_bytes`] of the
///      preceding row (or [`ZERO_HASH`] for the first row), compare
///      to the current row's stored `prev_hash`.
///   3. Verify the Ed25519 signature (when present) over the row's
///      `payload_hash`. The verifying-key resolver is provided by
///      the caller; pass `None` to skip signature verification (the
///      chain check is still performed).
///
/// On a chain break (step 1 or step 2 fail) the verifier records
/// the breaking row's `sequence` and continues so the caller still
/// gets per-row signature stats over the rest of the table.
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if the SELECT or any row
/// decode fails. A clean (chain held + zero signature failures)
/// report is returned as `Ok`; the caller checks
/// [`ChainVerificationReport::chain_holds`] for the chain bit.
/// v0.9.0 G9 (#1826) — the per-row Ed25519 verdict split into a daemon
/// `signature_failure` and a role-separation `role_separation_failure`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowSignatureVerdict {
    /// Legacy daemon-verifier signature failure (a stripped / forged
    /// daemon-signed row, or a malformed signature blob).
    pub signature_failure: bool,
    /// v0.9.0 G9 — a `recorder_signed` row failed recorder verification, OR a
    /// `daemon_signed` governance row was DEMOTED post recorder-enrollment (C2).
    pub role_separation_failure: bool,
}

/// v0.9.0 G9 (#1826) — classify ONE row's per-row Ed25519 verification. The
/// SHARED verification core so the sqlite [`verify_chain`] walk and the
/// postgres verify twin (C7) surface IDENTICAL failure sets (K3 parity):
///
/// - a `recorder_signed` row is verified against `recorder_verifier` over
///   `DOMAIN_RECORDER || signing_input_bytes(payload, cause)`; when NO recorder
///   pubkey is enrolled the row is SKIPPED (C6 — never false-failed vs daemon);
/// - a `daemon_signed` governance row is DEMOTED to a role-separation failure
///   once a recorder key is enrolled (C2);
/// - every other row routes to the legacy daemon verifier (#1071 / #1452),
///   byte-identical to the pre-G9 behaviour.
#[must_use]
pub fn classify_row_signature(
    event: &SignedEvent,
    daemon_verifier: Option<&ed25519_dalek::VerifyingKey>,
    recorder_verifier: Option<&ed25519_dalek::VerifyingKey>,
) -> RowSignatureVerdict {
    use crate::models::AttestLevel;
    if event.attest_level == AttestLevel::LineageSigned.as_str() {
        // v0.9.0 G13 (#1828) — identity-lineage WITNESS row. Its
        // `signature` is the succession signature by the record's
        // PREDECESSOR key over the `LINEAGE_DOMAIN`-tagged bytes, not a
        // daemon/recorder signature over `signing_input_bytes`, so the
        // daemon verifier would ALWAYS false-fail it. Succession
        // validity is owned by `identity::lineage::verify_lineage`
        // (surfaced as `AuditTrailReport::lineage`); this walk still
        // audits the row's CHAIN LINKAGE — the same disjoint-property
        // split the module docs pin for chain-break vs signature.
        return RowSignatureVerdict::default();
    }
    if event.attest_level == AttestLevel::RecorderSigned.as_str() {
        // RECORDER-signed row (C6: withhold when no recorder pubkey enrolled).
        let Some(rk) = recorder_verifier else {
            return RowSignatureVerdict::default();
        };
        let ok = match event.signature.as_deref() {
            Some(sig_bytes) if !sig_bytes.is_empty() => match <[u8; 64]>::try_from(sig_bytes) {
                Ok(arr) => {
                    let sig = ed25519_dalek::Signature::from_bytes(&arr);
                    let preimage = crate::governance::audit::recorder_signing_preimage(
                        &event.payload_hash,
                        event.cause_hash.as_deref(),
                    );
                    rk.verify_strict(&preimage, &sig).is_ok()
                }
                Err(_) => false,
            },
            _ => false,
        };
        return RowSignatureVerdict {
            signature_failure: false,
            role_separation_failure: !ok,
        };
    }
    if recorder_verifier.is_some()
        && event.attest_level == AttestLevel::DaemonSigned.as_str()
        && event.event_type == crate::governance::agent_action::GOVERNANCE_CHECK_EVENT_TYPE
    {
        // C2 DAEMON DEMOTION — a daemon-signed governance row is no longer an
        // acceptable recorder attestation once a recorder key is enrolled.
        return RowSignatureVerdict {
            signature_failure: false,
            role_separation_failure: true,
        };
    }
    // Legacy daemon verifier (#1071 / #1452), unchanged.
    let Some(vk) = daemon_verifier else {
        return RowSignatureVerdict::default();
    };
    let failed = match event.signature.as_ref() {
        Some(sig_bytes) if !sig_bytes.is_empty() => {
            match <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                Ok(arr) => {
                    let sig = ed25519_dalek::Signature::from_bytes(&arr);
                    // #1925 (CWE-347) — accept EITHER the identity-bound input
                    // (sqlite rows re-signed at append over the full attribution
                    // tuple) OR the legacy payload-only input (postgres rows +
                    // pre-#1925 rows). A row tampered in any identity column
                    // fails the identity check; the payload-only fallback never
                    // re-validates a tampered identity because a payload-only
                    // signature is not over the identity pre-image at all. So the
                    // sqlite head-row identity-tamper attack is caught fail-closed
                    // while legitimate postgres/legacy rows still verify.
                    let id_input = daemon_row_signing_input(event);
                    let pay_input =
                        signing_input_bytes(&event.payload_hash, event.cause_hash.as_deref());
                    let ok = vk.verify_strict(&id_input, &sig).is_ok()
                        || vk.verify_strict(&pay_input, &sig).is_ok();
                    !ok
                }
                Err(_) => true,
            }
        }
        // #1452 — fail-closed on a missing signature when a verifier IS
        // installed, EXCEPT the by-design legacy `unsigned` rows.
        _ => event.attest_level != crate::models::AttestLevel::Unsigned.as_str(),
    };
    RowSignatureVerdict {
        signature_failure: failed,
        role_separation_failure: false,
    }
}

pub fn verify_chain(
    conn: &Connection,
    since_sequence: Option<i64>,
) -> Result<ChainVerificationReport> {
    let lower = since_sequence.unwrap_or(0);
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, COALESCE(sequence, 0), cause_hash \
             FROM signed_events \
             WHERE COALESCE(sequence, 0) > ?1 \
             ORDER BY COALESCE(sequence, 0) ASC",
        )
        .context("verify_chain: prepare")?;
    let mut rows = stmt.query(params![lower]).context("verify_chain: query")?;

    let mut rows_checked: u64 = 0;
    let mut chain_break: Option<i64> = None;
    // v0.7.0 #1071 (SR-2 #1, HIGH) — actually walk Ed25519 signatures.
    // Resolved once outside the loop so we don't re-lock the OnceLock
    // per row. Returns `None` when the daemon process has no audit
    // signing key installed (i.e. `governance::audit::init` was called
    // with `signing_key: None`); in that case we record no signature
    // failures because there is no key to verify against — the
    // verifier is structure-only on an unsigned daemon.
    let verifier: Option<ed25519_dalek::VerifyingKey> =
        crate::governance::audit::resolve_daemon_verifying_key();
    // v0.9.0 G9 (#1826) — recorder K1 pin authority. When enrolled, a
    // `recorder_signed` row is verified against THIS pubkey over the
    // domain-separated preimage (never the daemon key), and a `daemon_signed`
    // governance row is demoted (C2). When unenrolled, recorder rows are
    // withheld/skipped (C6) rather than false-failed by the daemon verifier.
    let recorder_verifier: Option<ed25519_dalek::VerifyingKey> =
        crate::governance::audit::load_enrolled_recorder_pubkey()
            .ok()
            .flatten();
    let mut signature_failures: Vec<i64> = Vec::new();
    let mut role_separation_failures: Vec<i64> = Vec::new();

    let mut expected_seq = lower + 1;
    let mut prev_canonical_hash: [u8; 32] = ZERO_HASH;
    // When resuming with `since_sequence`, the prior row's canonical
    // hash must be recomputed from the row immediately before `lower`
    // so the chain check at `lower + 1` lines up.
    if lower > 0 {
        let mut head_stmt = conn
            .prepare(
                "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                        timestamp, COALESCE(sequence, 0), cause_hash \
                 FROM signed_events \
                 WHERE COALESCE(sequence, 0) = ?1",
            )
            .context("verify_chain: prepare head")?;
        let head: Option<SignedEvent> = head_stmt
            .query_map(params![lower], |row| {
                Ok(SignedEvent {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    event_type: row.get(2)?,
                    payload_hash: row.get(3)?,
                    signature: row.get(4)?,
                    attest_level: row.get(5)?,
                    timestamp: row.get(6)?,
                    sequence: row.get(7)?,
                    // v73: include the resume-boundary row's cause so the
                    // first in-window row's prev_hash lines up.
                    cause_hash: row.get::<_, Option<Vec<u8>>>(8)?,
                    prev_hash: Vec::new(),
                })
            })
            .context("verify_chain: head query")?
            .next()
            .transpose()
            .context("verify_chain: head collect")?;
        if let Some(h) = head {
            let canon = canonical_chain_bytes(&h);
            let mut hasher = Sha256::new();
            hasher.update(&canon);
            prev_canonical_hash.copy_from_slice(&hasher.finalize());
        }
    }

    while let Some(row) = rows.next().context("verify_chain: next row")? {
        rows_checked += 1;
        let event = SignedEvent {
            id: row.get(0).context("verify_chain: id")?,
            agent_id: row.get(1).context("verify_chain: agent_id")?,
            event_type: row.get(2).context("verify_chain: event_type")?,
            payload_hash: row.get(3).context("verify_chain: payload_hash")?,
            signature: row.get(4).context("verify_chain: signature")?,
            attest_level: row.get(5).context("verify_chain: attest_level")?,
            timestamp: row.get(6).context("verify_chain: timestamp")?,
            prev_hash: row
                .get::<_, Option<Vec<u8>>>(7)
                .context("verify_chain: prev_hash")?
                .unwrap_or_default(),
            sequence: row.get(8).context("verify_chain: sequence")?,
            cause_hash: row
                .get::<_, Option<Vec<u8>>>(9)
                .context("verify_chain: cause_hash")?,
        };

        // (1) Sequence contiguity.
        if event.sequence != expected_seq {
            if chain_break.is_none() {
                chain_break = Some(event.sequence);
            }
            // Keep walking so we still count rows + can later add
            // signature-failure tracking; but realign expected_seq to
            // the row we read so subsequent rows aren't ALL flagged.
            expected_seq = event.sequence;
        }

        // (2) prev_hash chain.
        if event.prev_hash.len() != 32 || event.prev_hash != prev_canonical_hash {
            if chain_break.is_none() {
                chain_break = Some(event.sequence);
            }
        }

        // (3) v0.7.0 #1071 / v0.9.0 G9 (#1826) — per-row Ed25519 verification,
        // via the SHARED [`classify_row_signature`] so the sqlite walk here and
        // the postgres verify twin (C7) surface IDENTICAL signature_failures +
        // role_separation_failures (K3 parity). A signature failure is disjoint
        // from a chain break by design (per-row forgery vs substrate tamper).
        let rv = classify_row_signature(&event, verifier.as_ref(), recorder_verifier.as_ref());
        if rv.signature_failure {
            signature_failures.push(event.sequence);
        }
        if rv.role_separation_failure {
            role_separation_failures.push(event.sequence);
        }

        // Recompute the canonical hash for the NEXT iteration.
        let canon = canonical_chain_bytes(&event);
        let mut hasher = Sha256::new();
        hasher.update(&canon);
        prev_canonical_hash.copy_from_slice(&hasher.finalize());

        expected_seq += 1;
    }

    Ok(ChainVerificationReport {
        rows_checked,
        chain_break,
        signature_failures,
        role_separation_failures,
    })
}

/// Operator-facing end-to-end report over the append-only
/// `signed_events` V-4 cross-row hash chain.
///
/// # v0.8.0 §22 Policy-Engine PE-8 (#697 / EPIC #1709)
///
/// Backs the `ai-memory verify-audit-trail` CLI. Distinct from the
/// lower-level [`ChainVerificationReport`] in two ways the operator
/// surface needs:
///
/// 1. An explicit `sequence_gaps` list — every contiguity hole as a
///    `(from, to)` inclusive missing range — rather than only the
///    FIRST break sequence that [`verify_chain`] records. A pruned /
///    partially-restored chain can have several holes; operators want
///    the whole inventory, not just the first.
/// 2. A `since` window scoped by RFC3339 `timestamp` (the column an
///    auditor actually has), while still verifying the cross-row hash
///    links ACROSS the window boundary so the first in-window row is
///    never falsely flagged as a break merely because its `prev_hash`
///    points at an out-of-window predecessor.
///
/// `chain_intact` mirrors [`ChainVerificationReport::chain_holds`]
/// (no `prev_hash`/sequence break inside the window). An empty chain
/// (`total_events == 0`) is trivially intact with no gaps.
/// v0.8.1 #1850 (CWE-354) — verdict of the off-table tail-truncation
/// check that [`verify_audit_trail`] runs against the #697 append-only
/// forensic JSONL watermark.
///
/// The in-table cross-row hash chain is tamper-EVIDENT against in-place
/// edits and middle-of-chain deletion, but tail truncation leaves a
/// contiguous surviving chain with no gap, so `chain_intact` alone reads
/// `true`. This enum carries the independent anchor verdict:
///
/// - [`Unknown`](TruncationCheck::Unknown) — no off-table anchor was
///   available (no live forensic sink, no watermark yet, legacy / fresh
///   DB, or the anchoring file rotated away). The check makes NO claim —
///   it never reports intact-because-of-anchor and never raises a false
///   alarm.
/// - [`NotDetected`](TruncationCheck::NotDetected) — an anchor was read
///   and the in-DB head is `>=` the anchored head: no truncation evidence.
/// - [`Detected`](TruncationCheck::Detected) — the in-DB head is strictly
///   BELOW the anchored head: trailing signed-events rows were removed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TruncationCheck {
    /// No off-table anchor available — verdict withheld (see enum docs).
    Unknown,
    /// Anchor read; in-DB head `>=` anchored head — no truncation evidence.
    NotDetected,
    /// Anchor read; in-DB head `<` anchored head — tail truncation.
    Detected {
        /// Highest head recorded in the off-table forensic watermark.
        anchored_head: i64,
        /// Highest `sequence` surviving in the `signed_events` table.
        db_head: i64,
    },
}

/// v0.9.0 G5b (#1822) — verdict of the INDEPENDENT dual-chain audit-head
/// WITNESS check (K1 pin + tail-truncation of EITHER chain), computed by
/// [`compute_witness_verdict`] from the latest
/// [`crate::models::ConditionType::AuditHeadWitness`] checkpoint.
///
/// - [`Unknown`](WitnessCheck::Unknown) — no witness anchor available (or one
///   present but unpinnable/unverifiable) in the DEFAULT withhold posture:
///   never a false alarm, never clean-because-of-anchor.
/// - [`NotDetected`](WitnessCheck::NotDetected) — a pinned, signature-valid
///   witness anchors heads `>=` the surviving heads on BOTH chains.
/// - [`Detected`](WitnessCheck::Detected) — a pinned witness head is strictly
///   ABOVE the surviving head of `chain` (`signed_events` or
///   `memory_revisions`): tail truncation of that chain.
/// - [`Forged`](WitnessCheck::Forged) — K1 pin FAILED: the witness
///   `resolver_pubkey` does not match the out-of-band enrolled witness pubkey
///   (e.g. a head re-signed under the daemon key). A hard-dirty verdict.
/// - [`Missing`](WitnessCheck::Missing) — require-mode
///   (`AI_MEMORY_REQUIRE_WITNESS`) is on but no pinnable/verifiable witness is
///   available: fail-closed (dirty).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WitnessCheck {
    /// No usable witness anchor — verdict withheld (default posture).
    Unknown,
    /// Pinned + valid witness; surviving heads `>=` witnessed heads.
    NotDetected,
    /// Pinned witness head above the surviving head of `chain`.
    Detected {
        /// Which chain truncated: `"signed_events"` or `"memory_revisions"`.
        chain: String,
        /// Head anchored by the witness checkpoint.
        witness_head: i64,
        /// Surviving in-DB head of that chain.
        db_head: i64,
    },
    /// K1 pin failed — witness `resolver_pubkey` != enrolled witness pubkey.
    Forged {
        /// Human-readable reason (for the CLI/JSON surface).
        detail: String,
    },
    /// Require-mode is on but no pinnable/verifiable witness is available.
    Missing,
}

/// v0.9.0 G5b (#1822) — verdict of the cause-binding coverage scan
/// (`signed_events.cause_hash IS NULL`), computed by
/// [`compute_cause_binding_verdict`].
///
/// - [`NotDetected`](CauseBinding::NotDetected) — every walked row binds a
///   `cause_hash`.
/// - [`Unknown`](CauseBinding::Unknown) — some rows are unbound but
///   cause-binding is NOT required: withhold (default). Legacy/mixed chains
///   legitimately carry unbound rows, so this never dirties by default.
/// - [`Detected`](CauseBinding::Detected) — require-mode
///   (`AI_MEMORY_REQUIRE_CAUSE_BINDING`) is on and `rows_without_cause` rows
///   are unbound: fail-closed (dirty).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CauseBinding {
    /// Some rows unbound but not required — verdict withheld (default).
    Unknown,
    /// Every walked row binds a cause.
    NotDetected,
    /// Require-mode on + unbound rows present (fail-closed).
    Detected {
        /// Count of `signed_events` rows with `cause_hash IS NULL`.
        rows_without_cause: i64,
    },
}

/// v1.0.0 #1946 (A1 · §5.1) — verdict of the OFF-TABLE rollback-evidence
/// check: the surviving `signed_events` head vs the witness-signed off-table
/// head-anchor high-water, computed by [`compute_rollback_verdict`].
///
/// - [`Unknown`](RollbackCheck::Unknown) — no pinnable off-table anchor (no
///   witness key enrolled, no anchor log, or an unpinnable one): verdict
///   withheld (default posture — never a false all-clear).
/// - [`NotDetected`](RollbackCheck::NotDetected) — the anchor was pinned and
///   the DB head is `>=` the anchored high-water: no rollback evidence.
/// - [`Evidence`](RollbackCheck::Evidence) — the DB head is strictly BELOW the
///   anchored high-water and NO operator sanction explains it: the DB file was
///   rolled back (or a whole-host snapshot restore that was not attested).
/// - [`Sanctioned`](RollbackCheck::Sanctioned) — the DB head is below the
///   anchor but a valid OPERATOR-signed restore sanction attests it (a
///   legitimate DR restore): cleared, NOT dirty.
/// - [`Missing`](RollbackCheck::Missing) — require-mode
///   ([`crate::governance::audit::REQUIRE_ROLLBACK_CHECK_ENV`]) is on but no
///   pinnable anchor is available: fail-closed (dirty).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RollbackCheck {
    /// No pinnable off-table anchor — verdict withheld (default posture).
    Unknown,
    /// Anchor pinned; DB head `>=` anchored high-water — no rollback evidence.
    NotDetected,
    /// DB head below the anchor with no operator sanction — rollback evidence.
    Evidence {
        /// Highest witness-signed head anchored off-table.
        anchored_head: i64,
        /// Surviving `signed_events` head in the DB.
        db_head: i64,
    },
    /// DB head below the anchor but OPERATOR-sanctioned (attested DR restore).
    Sanctioned {
        /// Off-table anchor high-water the sanction attests a restore FROM.
        anchored_head: i64,
        /// Surviving DB head inside the operator-attested restore window.
        db_head: i64,
    },
    /// Require-mode on but no pinnable off-table anchor (fail-closed).
    Missing,
}

/// v1.0.0 #1946 — compute the [`RollbackCheck`] verdict from the surviving
/// `db_head`, the pinned off-table `anchored_head` (`None` = absent /
/// unpinnable), whether an operator sanction clears a below-anchor head, and
/// the require-mode flag. Pure (no I/O) so the refuse-vs-continue policy is
/// unit-testable; the I/O wrapper is
/// [`crate::governance::audit::compute_rollback_verdict_for_report`]. SHARED by
/// both backends' `verify_audit_trail` (K3 parity) and the open-time check.
#[must_use]
pub fn compute_rollback_verdict(
    db_head: i64,
    anchored_head: Option<i64>,
    sanctioned: bool,
    require: bool,
) -> RollbackCheck {
    match anchored_head {
        None => {
            if require {
                RollbackCheck::Missing
            } else {
                RollbackCheck::Unknown
            }
        }
        Some(anchored) => {
            if db_head >= anchored {
                RollbackCheck::NotDetected
            } else if sanctioned {
                RollbackCheck::Sanctioned {
                    anchored_head: anchored,
                    db_head,
                }
            } else {
                RollbackCheck::Evidence {
                    anchored_head: anchored,
                    db_head,
                }
            }
        }
    }
}

/// v0.9.0 G9 (#1826) — verdict of the three-key Recorder/Judge/Stopper
/// signing-layer SEPARATION check, computed by
/// [`compute_role_separation_verdict`]. Additive/opt-in: with no role keys
/// enrolled the verdict is [`Unknown`](RoleSeparationCheck::Unknown) and the
/// report stays byte-identical to the legacy single-key posture.
///
/// - [`Unknown`](RoleSeparationCheck::Unknown) — no role keys enrolled (or no
///   pinnable anchor) in the DEFAULT withhold posture: never a false alarm.
/// - [`NotDetected`](RoleSeparationCheck::NotDetected) — every enrolled role's
///   rows/checkpoints pinned + signature-valid; no forgery/demotion.
/// - [`Forged`](RoleSeparationCheck::Forged) — a K1 pin FAILED (a judge/stopper
///   checkpoint `resolver_pubkey` != the enrolled role pubkey), a
///   `recorder_signed` row failed recorder verification, OR a `daemon_signed`
///   governance row was DEMOTED post recorder-enrollment (C2). Hard-dirty.
/// - [`Misconfigured`](RoleSeparationCheck::Misconfigured) — the enrolled
///   recorder/judge/stopper pubkeys are NOT pairwise-distinct (C3). Dirty.
/// - [`Missing`](RoleSeparationCheck::Missing) — require-mode
///   (`AI_MEMORY_REQUIRE_ROLE_SEPARATION`) on but no usable role separation is
///   available: fail-closed (dirty).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RoleSeparationCheck {
    /// No role keys enrolled — verdict withheld (default posture).
    Unknown,
    /// All enrolled roles pinned + valid; no forgery/demotion.
    NotDetected,
    /// K1 pin failed, recorder-row forgery, or daemon-demotion detected.
    Forged {
        /// Human-readable reason (for the CLI/JSON surface).
        detail: String,
    },
    /// Enrolled role pubkeys are not pairwise-distinct (C3).
    Misconfigured {
        /// Human-readable reason (for the CLI/JSON surface).
        detail: String,
    },
    /// Require-mode on but no usable role separation available (fail-closed).
    Missing,
}

/// v0.9.0 G9 (#1826) — compute the [`RoleSeparationCheck`] verdict. Clone of
/// [`compute_witness_verdict`]'s K1-pin-FIRST discipline, applied to the newest
/// JUDGE [`crate::models::ConditionType::GovernanceVerdict`] and STOPPER
/// [`crate::models::ConditionType::GovernanceEnforcement`] checkpoints, plus
/// the per-row recorder verdict (`recorder_row_failures`) and the C3 pairwise-
/// distinctness assertion. Shared by BOTH backends so the verdict is IDENTICAL.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn compute_role_separation_verdict(
    latest_verdict: Option<&crate::models::Checkpoint>,
    latest_enforcement: Option<&crate::models::Checkpoint>,
    enrolled_recorder: Option<&ed25519_dalek::VerifyingKey>,
    enrolled_judge: Option<&ed25519_dalek::VerifyingKey>,
    enrolled_stopper: Option<&ed25519_dalek::VerifyingKey>,
    recorder_row_failures: usize,
    require: bool,
) -> RoleSeparationCheck {
    let any_enrolled =
        enrolled_recorder.is_some() || enrolled_judge.is_some() || enrolled_stopper.is_some();
    if !any_enrolled {
        return if require {
            RoleSeparationCheck::Missing
        } else {
            RoleSeparationCheck::Unknown
        };
    }
    // C3 PAIRWISE-DISTINCT — recorder/judge/stopper must be pairwise distinct
    // (a recorder==witness alias is fine; that is a different key set). Two
    // roles sharing a key collapses the separation, so reject as Misconfigured.
    let pairs = [
        (enrolled_recorder, enrolled_judge, "recorder == judge"),
        (enrolled_recorder, enrolled_stopper, "recorder == stopper"),
        (enrolled_judge, enrolled_stopper, "judge == stopper"),
    ];
    for (a, b, label) in pairs {
        if let (Some(a), Some(b)) = (a, b) {
            if a.to_bytes() == b.to_bytes() {
                return RoleSeparationCheck::Misconfigured {
                    detail: format!("enrolled role pubkeys are not pairwise-distinct ({label})"),
                };
            }
        }
    }
    // Recorder-row forgery / daemon-demotion (from the per-row verify walk).
    if enrolled_recorder.is_some() && recorder_row_failures > 0 {
        return RoleSeparationCheck::Forged {
            detail: format!(
                "{recorder_row_failures} governance row(s) failed recorder verification \
                 or were demoted from daemon_signed after recorder enrollment"
            ),
        };
    }
    // JUDGE verdict anchor — K1 pin FIRST, then signature self-consistency.
    if let Some(judge_pk) = enrolled_judge {
        match latest_verdict {
            Some(cp) => {
                if let Some(f) = pin_and_verify_role_checkpoint(cp, judge_pk, "judge verdict") {
                    return f;
                }
            }
            None if require => return RoleSeparationCheck::Missing,
            None => {}
        }
    }
    // STOPPER enforcement anchor — K1 pin FIRST. Absence is NORMAL (enforcement
    // anchors are emitted only on a deny), so a missing one is never Missing.
    if let Some(stopper_pk) = enrolled_stopper {
        if let Some(cp) = latest_enforcement {
            if let Some(f) = pin_and_verify_role_checkpoint(cp, stopper_pk, "stopper enforcement") {
                return f;
            }
        }
    }
    RoleSeparationCheck::NotDetected
}

/// K1 pin + signature check for one role checkpoint. Returns `Some(Forged)` on
/// a pin mismatch or an invalid signature, else `None` (pinned + valid).
fn pin_and_verify_role_checkpoint(
    cp: &crate::models::Checkpoint,
    expected: &ed25519_dalek::VerifyingKey,
    role: &str,
) -> Option<RoleSeparationCheck> {
    if cp.resolver_pubkey.as_slice() != expected.to_bytes().as_slice() {
        return Some(RoleSeparationCheck::Forged {
            detail: format!(
                "{role} resolver_pubkey does not match the enrolled out-of-band pubkey (K1 pin)"
            ),
        });
    }
    if !crate::checkpoints::verify(cp) {
        return Some(RoleSeparationCheck::Forged {
            detail: format!("{role} checkpoint signature failed verification"),
        });
    }
    None
}

/// Chain-name tag for a `signed_events` witness [`WitnessCheck::Detected`].
pub const WITNESS_CHAIN_SIGNED_EVENTS: &str = "signed_events";
/// Chain-name tag for a `memory_revisions` witness [`WitnessCheck::Detected`].
pub const WITNESS_CHAIN_MEMORY_REVISIONS: &str = "memory_revisions";

/// K1 (#1822) — witness-pinned tail-truncation verdict over BOTH chains.
///
/// The out-of-band enrolled witness pubkey is asserted against the latest
/// witness checkpoint's `resolver_pubkey` BEFORE trusting its signature — a
/// sig-valid-but-wrong-key anchor (e.g. a head re-signed under the daemon
/// key) is [`WitnessCheck::Forged`], NOT a verbatim-reused pass. Only once
/// pinned + signature-valid are the anchored heads compared against the
/// surviving heads.
#[must_use]
pub fn compute_witness_verdict(
    latest_witness: Option<&crate::models::Checkpoint>,
    enrolled_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    db_signed_head: i64,
    db_revisions_head: i64,
    require_witness: bool,
) -> WitnessCheck {
    let withhold = || {
        if require_witness {
            WitnessCheck::Missing
        } else {
            WitnessCheck::Unknown
        }
    };
    let Some(cp) = latest_witness else {
        return withhold();
    };
    // K1 pin FIRST — assert the resolver pubkey equals the out-of-band
    // enrolled witness pubkey BEFORE trusting the checkpoint signature.
    if let Some(expected) = enrolled_pubkey {
        if cp.resolver_pubkey.as_slice() != expected.to_bytes().as_slice() {
            return WitnessCheck::Forged {
                detail: "witness resolver_pubkey does not match the enrolled out-of-band \
                         witness pubkey (K1 pin) — anchor rejected"
                    .to_string(),
            };
        }
    }
    // Signature self-consistency over the canonical resolution.
    if !crate::checkpoints::verify(cp) {
        // #1890 — if a pin MATCHED above (enrolled_pubkey present and equal)
        // but the signature is invalid, an attacker forged a newer anchor
        // under the *public* enrolled pubkey to shadow the real witness. Fail
        // CLOSED (Forged), mirroring `pin_and_verify_role_checkpoint`. Only
        // withhold when NO out-of-band pin was available to anchor the pubkey.
        if enrolled_pubkey.is_some() {
            return WitnessCheck::Forged {
                detail: "witness checkpoint signature failed verification".to_string(),
            };
        }
        return withhold();
    }
    // No out-of-band pin available → cannot cryptographically anchor the
    // pubkey; require-mode fails closed, default withholds.
    if enrolled_pubkey.is_none() {
        return withhold();
    }
    let Some(dual) = crate::governance::audit::parse_witness_dual_head(cp) else {
        return withhold();
    };
    if dual.signed_head_sequence > db_signed_head {
        return WitnessCheck::Detected {
            chain: WITNESS_CHAIN_SIGNED_EVENTS.to_string(),
            witness_head: dual.signed_head_sequence,
            db_head: db_signed_head,
        };
    }
    if dual.revisions_head_sequence > db_revisions_head {
        return WitnessCheck::Detected {
            chain: WITNESS_CHAIN_MEMORY_REVISIONS.to_string(),
            witness_head: dual.revisions_head_sequence,
            db_head: db_revisions_head,
        };
    }
    WitnessCheck::NotDetected
}

/// Cause-binding verdict (#1822 K2). `rows_without_cause == 0` →
/// [`CauseBinding::NotDetected`]; otherwise [`CauseBinding::Detected`] under
/// require-mode (fail-closed) or [`CauseBinding::Unknown`] (withhold) by
/// default. Shared by both backends so the verdict is IDENTICAL (K3).
#[must_use]
pub fn compute_cause_binding_verdict(rows_without_cause: i64, require: bool) -> CauseBinding {
    if rows_without_cause <= 0 {
        CauseBinding::NotDetected
    } else if require {
        CauseBinding::Detected { rows_without_cause }
    } else {
        CauseBinding::Unknown
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditTrailReport {
    /// Rows walked inside the `since` window (the whole table when
    /// `since` is `None`).
    pub total_events: usize,
    /// `true` when the cross-row hash chain held end-to-end across the
    /// window (no `prev_hash` mismatch, no sequence-contiguity break).
    pub chain_intact: bool,
    /// `Some(seq)` of the FIRST row whose chain link failed (its
    /// `prev_hash` no longer matches the recomputed canonical digest
    /// of its predecessor, OR its `sequence` is not `prior + 1`).
    /// Mirrors [`ChainVerificationReport::chain_break`].
    pub first_break_sequence: Option<i64>,
    /// Every monotonic-sequence hole inside the window as an inclusive
    /// `(from, to)` MISSING range. `[(4, 6)]` means sequences 4, 5, 6
    /// are absent (the row at 3 is followed directly by the row at 7).
    pub sequence_gaps: Vec<(i64, i64)>,
    /// Highest `sequence` present in the ENTIRE table (chain head),
    /// independent of the `since` window. `0` for an empty table.
    pub head_sequence: i64,
    /// Echoes the caller's RFC3339 `since` filter (or `None` for a
    /// full-table verification).
    pub since: Option<String>,
    /// v0.8.1 #1850 (CWE-354) — off-table tail-truncation verdict from the
    /// #697 forensic JSONL watermark. `Unknown` when no anchor is available
    /// (the safe default — never a false alarm, never intact-by-anchor);
    /// `Detected { anchored_head, db_head }` when the in-DB head dropped
    /// below the anchored head. Independent of `chain_intact`, which a tail
    /// truncation does not disturb. See [`TruncationCheck`].
    pub truncation: TruncationCheck,
    /// v0.9.0 G5b (#1822) — INDEPENDENT dual-chain audit-head WITNESS verdict
    /// (K1 pin + tail-truncation of `signed_events` OR `memory_revisions`
    /// against the out-of-band-enrolled witness anchor). `Unknown` withholds
    /// (default); `Detected`/`Forged`/`Missing` are dirty. See [`WitnessCheck`].
    pub witness: WitnessCheck,
    /// v0.9.0 G5b (#1822) — cause-binding coverage verdict
    /// (`cause_hash IS NULL` scan). `Unknown` withholds by default;
    /// `Detected` (require-mode) is dirty. See [`CauseBinding`].
    pub cause_binding: CauseBinding,
    /// v0.9.0 G9 (#1826) — per-row Ed25519 signature failures (sequences).
    /// Populated IDENTICALLY by both backends (the postgres twin builds per-row
    /// verification from scratch under C7). Informational — a daemon-signed
    /// legacy chain surfaces its failures here without dirtying `is_clean`
    /// (that preserves the byte-identical legacy verdict); the security-bearing
    /// recorder/judge/stopper forgeries land in `role_separation`.
    pub signature_failures: Vec<i64>,
    /// v0.9.0 G9 (#1826) — three-key Recorder/Judge/Stopper signing-layer
    /// SEPARATION verdict (K1 pin of the judge/stopper checkpoints + per-row
    /// recorder verification + C3 distinctness + C2 daemon-demotion).
    /// `Unknown` withholds (default, legacy-identical); `Forged` /
    /// `Misconfigured` / `Missing` are dirty. See [`RoleSeparationCheck`].
    pub role_separation: RoleSeparationCheck,
    /// v0.9.0 G13 (#1828) — identity-lineage verdict: every enrolled
    /// agent's succession chain is walked genesis→head through
    /// [`crate::identity::lineage::verify_lineage`] (C1 witness anchor
    /// + C3 truncation reconciliation included). `Unknown` withholds
    /// (default — no lineage enrolled, byte-identical legacy);
    /// `Forged` / `Missing` (require-mode
    /// `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`) are dirty. Populated
    /// IDENTICALLY by both backends via
    /// [`crate::identity::lineage::compute_lineage_check`].
    pub lineage: crate::identity::lineage::LineageCheck,
    /// v1.0.0 #1946 (A1) — OFF-TABLE rollback-evidence verdict: the surviving
    /// `signed_events` head vs the witness-signed off-table head-anchor
    /// high-water. `Unknown` withholds (default — no anchor / no witness key,
    /// byte-identical legacy); `Evidence` / `Missing` (require-mode) are dirty;
    /// `Sanctioned` (operator-attested DR) and `NotDetected` are clean. SHARED
    /// off-table reader on both backends (K3 parity). See [`RollbackCheck`].
    pub rollback: RollbackCheck,
}

impl AuditTrailReport {
    /// `true` when the chain held, no sequence gaps were found, AND the
    /// off-table anchor did not detect a tail truncation — the all-clear an
    /// operator (or CI exit-code 0) wants. A chain break, a gap, OR a
    /// [`TruncationCheck::Detected`] verdict makes this `false`.
    ///
    /// A [`TruncationCheck::Unknown`] verdict (no anchor available) does
    /// NOT make the report dirty — the off-table check withholds judgement
    /// rather than raising a false alarm (#1850, CWE-354), so a deployment
    /// without a forensic watermark keeps the pre-#1850 clean semantics.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.chain_intact
            && self.sequence_gaps.is_empty()
            && !matches!(self.truncation, TruncationCheck::Detected { .. })
            // v0.9.0 G5b (#1822) — witness Detected/Forged/Missing are dirty;
            // Unknown withholds (never dirties an otherwise-clean report).
            && !matches!(
                self.witness,
                WitnessCheck::Detected { .. } | WitnessCheck::Forged { .. } | WitnessCheck::Missing
            )
            // Cause-binding Detected (require-mode) is dirty; Unknown withholds.
            && !matches!(self.cause_binding, CauseBinding::Detected { .. })
            // v0.9.0 G9 (#1826) — role-separation Forged/Misconfigured/Missing
            // are dirty; Unknown/NotDetected keep an otherwise-clean report
            // clean (so an unconfigured deployment is byte-identical legacy).
            && !matches!(
                self.role_separation,
                RoleSeparationCheck::Forged { .. }
                    | RoleSeparationCheck::Misconfigured { .. }
                    | RoleSeparationCheck::Missing
            )
            // v0.9.0 G13 (#1828) — identity-lineage Forged/Missing are
            // dirty; Unknown/NotDetected keep an otherwise-clean report
            // clean (no lineage enrolled = byte-identical legacy).
            && !matches!(
                self.lineage,
                crate::identity::lineage::LineageCheck::Forged { .. }
                    | crate::identity::lineage::LineageCheck::Missing
            )
            // v1.0.0 #1946 (A1) — rollback Evidence/Missing (require-mode) are
            // dirty; Sanctioned (operator-attested DR) / Unknown / NotDetected
            // keep an otherwise-clean report clean (no anchor = legacy-identical).
            && !matches!(
                self.rollback,
                RollbackCheck::Evidence { .. } | RollbackCheck::Missing
            )
    }
}

/// Verify the append-only `signed_events` V-4 cross-row hash chain
/// end-to-end and surface any gaps for operator review.
///
/// # v0.8.0 §22 Policy-Engine PE-8 (#697 / EPIC #1709)
///
/// Reuses [`verify_chain`] verbatim for the cross-row hash-chain +
/// sequence-contiguity integrity — no chain crypto is reimplemented
/// here. The added value over the raw verifier is the operator-facing
/// [`AuditTrailReport`]: a full `sequence_gaps` inventory and an
/// RFC3339-`timestamp` window.
///
/// ## `since` boundary handling
///
/// `verify_chain` is sequence-scoped, not timestamp-scoped. When
/// `since` is `Some(ts)` we resolve `ts` to a sequence FLOOR — the
/// max `sequence` of any row whose `timestamp < ts` — and pass that
/// floor to `verify_chain` as `since_sequence`. `verify_chain`
/// already recomputes the predecessor row's canonical hash from the
/// row AT the floor, so the first in-window row's `prev_hash` is
/// checked against its real (out-of-window) predecessor: a `--since`
/// view never falsely reports the window edge as a break. Rows whose
/// `timestamp >= ts` are the verified window; the gap scan runs over
/// that same `sequence > floor` window.
///
/// An empty chain (or an empty window) is trivially intact with a
/// `total_events` of 0 and no gaps.
///
/// # Limitations (security review #1850, CWE-354)
///
/// The hash chain is tamper-EVIDENT against in-place edits and
/// middle-of-chain row deletion (which leave a hash break or a
/// `sequence_gap`), but it is NOT a complete integrity oracle:
///
/// - **Tail truncation — now DETECTION-flagged, not silently clean.**
///   `head_sequence` is recomputed from the surviving `MAX(sequence)`
///   with no in-table high-water mark, so deleting the trailing N rows
///   leaves a contiguous `1..=(head-N)` chain with no gap — `chain_intact`
///   alone reports `true`. The [`AuditTrailReport::truncation`] field
///   closes this by comparing the in-DB head against the most-recent head
///   anchored into the OFF-TABLE #697 append-only forensic JSONL chain
///   (the on-host watermark stamped by every signed-events append, see
///   [`crate::governance::audit::maybe_record_audit_watermark`]):
///   `db_head < anchored_head` → [`TruncationCheck::Detected`].
///
///   **What the on-host anchor IS — a detection bar-raise.** It reliably
///   catches naive / accidental / crash-induced truncation and disk
///   corruption of the table suffix, and it forces any deliberate tamper
///   to be DUAL-atomic: an attacker must now rewrite BOTH the
///   `signed_events` suffix AND the append-only forensic JSONL sibling in
///   lockstep, not just the one writable table.
///
///   **What it is NOT — unconditional cryptographic proof.** Its strength
///   is CONDITIONAL on an enrolled signing key. On a SIGNED daemon the
///   forensic rows (watermark included) carry an Ed25519 `sig`, so a
///   forged watermark is detectable. On an UNSIGNED daemon
///   (`load_daemon_signing_key` → `None`, verifier `None`) the JSONL
///   watermark is unsigned too, so a DB-file-write attacker can rewrite
///   BOTH the `signed_events` suffix AND the unsigned JSONL watermark and
///   evade detection. The residual-closing control for that hostile-host /
///   unsigned posture is shipping the forensic log OFF-HOST via the
///   `AI_MEMORY_LOG_SINK=syslog` tier (RFC 5424 over TLS, RFC 5425;
///   CLAUDE.md env rows #86 / #88-90) so the anchor lands on a collector
///   the host attacker cannot reach. A [`TruncationCheck::Unknown`]
///   verdict (no anchor available) withholds judgement — it never raises a
///   false alarm and never reports intact-because-of-anchor.
/// - **Unsigned-daemon whole-suffix rewrite is undetectable.** When the
///   daemon boots without an enrolled signing key (`load_daemon_signing_key`
///   → `None`, "continuing unsigned"), [`verify_chain`]'s signature
///   verifier is `None`, so an attacker with DB-file write access can
///   rewrite a suffix with recomputed `prev_hash` values and zero
///   `signature_failures` (and, per the tail-truncation note above, the
///   unsigned JSONL watermark alongside it). Run with an enrolled audit
///   key — and ship the forensic log off-host — for cryptographic (not
///   merely hash-chain) tamper evidence.
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if any of the head /
/// floor / gap-scan queries fail, or the `verify_chain` error.
#[allow(clippy::too_many_lines)]
pub fn verify_audit_trail(conn: &Connection, since: Option<&str>) -> Result<AuditTrailReport> {
    // Chain head — highest sequence in the WHOLE table (independent of
    // the window). `MAX(sequence)` is NULL on an empty table → 0.
    let head_sequence: i64 = conn
        .query_row(CHAIN_HEAD_SQL, [], |row| row.get(0))
        .context("verify_audit_trail: read chain head sequence")?;

    // v0.8.1 #1850 (CWE-354) — off-table tail-truncation check. The in-DB
    // head above is recomputed from the surviving `MAX(sequence)`, so a
    // trailing-row DELETE leaves a contiguous chain and `chain_intact`
    // alone cannot see it. Read the last head anchored into the #697
    // append-only forensic JSONL chain and compare:
    //   - in-DB head  <  anchored head  → tail TRUNCATION detected.
    //   - no anchor available            → UNKNOWN (withhold judgement —
    //     never a false alarm, never intact-because-of-anchor).
    //   - in-DB head  >= anchored head   → no truncation evidence.
    // No SIEM/syslog call here (the report is the surface); the off-host
    // `AI_MEMORY_LOG_SINK=syslog` tier is the residual-closing control for
    // the hostile-host / unsigned-daemon posture (see fn-level docs).
    let truncation = match crate::governance::audit::last_audit_watermark() {
        Some((anchored_head, _head_canonical_hash)) => {
            if head_sequence < anchored_head {
                TruncationCheck::Detected {
                    anchored_head,
                    db_head: head_sequence,
                }
            } else {
                TruncationCheck::NotDetected
            }
        }
        None => TruncationCheck::Unknown,
    };

    // Resolve the RFC3339 `since` timestamp to a sequence FLOOR: the
    // max sequence of any row strictly BEFORE the window. `verify_chain`
    // walks `sequence > floor` and re-derives the predecessor hash from
    // the row at `floor`, so the boundary link is checked, not assumed.
    let floor: i64 = match since {
        Some(ts) => conn
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM signed_events \
                 WHERE sequence IS NOT NULL AND timestamp < ?1",
                params![ts],
                |row| row.get(0),
            )
            .context("verify_audit_trail: resolve since-timestamp to sequence floor")?,
        None => 0,
    };

    let since_sequence = if floor > 0 { Some(floor) } else { None };

    // Reuse the canonical chain verifier — no reimplemented crypto.
    let report = verify_chain(conn, since_sequence).context("verify_audit_trail: verify_chain")?;

    // Independent monotonic-sequence gap scan over the SAME window.
    // `verify_chain` records only the FIRST break sequence; operators
    // want every hole. Walk the present sequences in order and emit an
    // inclusive (from, to) missing range for each discontinuity.
    let mut stmt = conn
        .prepare(
            "SELECT sequence FROM signed_events \
             WHERE sequence IS NOT NULL AND sequence > ?1 \
             ORDER BY sequence ASC",
        )
        .context("verify_audit_trail: prepare gap scan")?;
    let mut rows = stmt
        .query(params![floor])
        .context("verify_audit_trail: gap-scan query")?;

    let mut sequence_gaps: Vec<(i64, i64)> = Vec::new();
    // The first in-window row is expected at `floor + 1`.
    let mut expected = floor + 1;
    while let Some(row) = rows.next().context("verify_audit_trail: gap-scan next")? {
        let seq: i64 = row
            .get(0)
            .context("verify_audit_trail: gap-scan sequence")?;
        if seq > expected {
            // Sequences [expected, seq - 1] are missing.
            sequence_gaps.push((expected, seq - 1));
        }
        // Realign past this row (handles duplicate / non-monotonic
        // sequences gracefully without spurious negative ranges).
        expected = seq + 1;
    }

    // v0.9.0 G5b (#1822) — INDEPENDENT dual-chain witness verdict (K1 pin) +
    // cause-binding coverage. Both use the SHARED verdict fns so the postgres
    // twin ([`crate::store::postgres::PostgresStore::verify_audit_trail`])
    // surfaces IDENTICAL verdicts (K3).
    let require_witness = crate::governance::audit::require_witness_enabled();
    let require_cause = crate::governance::audit::require_cause_binding_enabled();
    let enrolled_pubkey = crate::governance::audit::load_enrolled_witness_pubkey()
        .ok()
        .flatten();
    // The witness tier is ADDITIVE + optional: a legacy / minimal schema with
    // no `checkpoints` (or `memory_revisions`) table has definitionally no
    // witness, so any read failure degrades to "no anchor" → the safe withhold
    // (Unknown) posture — never aborts the whole verify. Require-mode
    // (`AI_MEMORY_REQUIRE_WITNESS`) still fail-closes on the resulting None.
    let latest_witness = read_latest_witness_checkpoint(conn).ok().flatten();
    let revisions_head = crate::revisions::read_revision_chain_head(conn)
        .map(|(seq, _)| seq)
        .unwrap_or(0);
    let witness = compute_witness_verdict(
        latest_witness.as_ref(),
        enrolled_pubkey.as_ref(),
        head_sequence,
        revisions_head,
        require_witness,
    );
    // Cause-binding coverage scan. A missing `cause_hash` column (pre-v73
    // hand-rolled schema) degrades to 0 unbound rows → NotDetected rather than
    // aborting the verify.
    let rows_without_cause: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events \
             WHERE cause_hash IS NULL AND sequence IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let cause_binding = compute_cause_binding_verdict(rows_without_cause, require_cause);

    // v0.9.0 G9 (#1826) — three-key role-separation verdict. Same shared
    // `compute_role_separation_verdict` the postgres twin calls (K3 parity).
    // Additive/opt-in: absent role keys → Unknown → is_clean unchanged.
    let require_role = crate::governance::audit::require_role_separation_enabled();
    let enrolled_recorder = crate::governance::audit::load_enrolled_recorder_pubkey()
        .ok()
        .flatten();
    let enrolled_judge = crate::governance::audit::load_enrolled_judge_pubkey()
        .ok()
        .flatten();
    let enrolled_stopper = crate::governance::audit::load_enrolled_stopper_pubkey()
        .ok()
        .flatten();
    let latest_verdict = read_latest_role_checkpoint(
        conn,
        crate::governance::audit::GOVERNANCE_VERDICT_NAMESPACE,
        crate::models::ConditionType::GovernanceVerdict,
    )
    .ok()
    .flatten();
    let latest_enforcement = read_latest_role_checkpoint(
        conn,
        crate::governance::audit::GOVERNANCE_ENFORCEMENT_NAMESPACE,
        crate::models::ConditionType::GovernanceEnforcement,
    )
    .ok()
    .flatten();
    let role_separation = compute_role_separation_verdict(
        latest_verdict.as_ref(),
        latest_enforcement.as_ref(),
        enrolled_recorder.as_ref(),
        enrolled_judge.as_ref(),
        enrolled_stopper.as_ref(),
        report.role_separation_failures.len(),
        require_role,
    );

    // v0.9.0 G13 (#1828) — identity-lineage verdict. Walks every
    // enrolled agent's chain through `verify_lineage` (C1/C3 enforced);
    // additive: no `agent_lineage` table / no rows → Unknown (or
    // Missing under AI_MEMORY_REQUIRE_IDENTITY_LINEAGE). Shared verdict
    // fn → identical to the postgres twin (K3 parity).
    let require_lineage = crate::identity::lineage::require_identity_lineage_enabled();
    let lineage = compute_identity_lineage_verdict(conn, require_lineage);

    // v1.0.0 #1946 D — rollback-evidence verdict from the SHARED off-table
    // anchor reader (identical verdict on the postgres twin, K3 parity).
    let rollback = crate::governance::audit::compute_rollback_verdict_for_report(head_sequence);

    Ok(AuditTrailReport {
        total_events: usize::try_from(report.rows_checked).unwrap_or(usize::MAX),
        chain_intact: report.chain_holds(),
        first_break_sequence: report.chain_break,
        sequence_gaps,
        head_sequence,
        since: since.map(ToString::to_string),
        truncation,
        witness,
        cause_binding,
        signature_failures: report.signature_failures.clone(),
        role_separation,
        lineage,
        rollback,
    })
}

/// v0.9.0 G13 (#1828) — compute the sqlite-side [`crate::identity::lineage::LineageCheck`]
/// verdict for [`verify_audit_trail`].
///
/// Enumerates every agent with `agent_lineage` rows and walks each
/// chain through `crate::storage::verify_agent_lineage` (which enforces
/// the C1 witness anchor + C3 truncation reconciliation + head-key
/// cross-check). Additive posture: a legacy / partial-schema DB whose
/// `agent_lineage` table is absent (or unreadable) has definitionally
/// no lineage → the agent LIST read degrades to empty → `Unknown`
/// withhold (require-mode still fail-closes to `Missing`). A PER-AGENT
/// verify failure — including an infra read error once we know the
/// agent HAS lineage — is fail-closed `Forged`.
fn compute_identity_lineage_verdict(
    conn: &Connection,
    require: bool,
) -> crate::identity::lineage::LineageCheck {
    let agents: Vec<String> = conn
        .prepare("SELECT DISTINCT agent_id FROM agent_lineage ORDER BY agent_id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default();
    let outcomes: Vec<crate::identity::lineage::LineageWalkOutcome> = agents
        .into_iter()
        .map(|agent| {
            use crate::identity::lineage::{CustodyClass, LineageWalkOutcome};
            match crate::storage::verify_agent_lineage(conn, &agent) {
                Ok(Ok(verified)) => LineageWalkOutcome {
                    agent_id: agent,
                    failure: None,
                    // v1.0.0 #1949 — surface the revocation window + head
                    // custody class the walk resolved.
                    revoked_from_seq: verified.revoked_from_seq,
                    head_custody_class: verified.head_custody_class,
                },
                Ok(Err(walk_err)) => LineageWalkOutcome {
                    agent_id: agent,
                    failure: Some(walk_err.to_string()),
                    revoked_from_seq: None,
                    head_custody_class: CustodyClass::default(),
                },
                // Infra read failure on an agent KNOWN to have lineage
                // rows — fail-closed (never silently withhold).
                Err(read_err) => LineageWalkOutcome {
                    agent_id: agent,
                    failure: Some(format!("lineage read failed: {read_err:#}")),
                    revoked_from_seq: None,
                    head_custody_class: CustodyClass::default(),
                },
            }
        })
        .collect();
    crate::identity::lineage::compute_lineage_check(&outcomes, require)
}

/// v0.9.0 G9 (#1826) — read the NEWEST role-separation checkpoint
/// (`GovernanceVerdict` or `GovernanceEnforcement`) in `namespace`, newest by
/// `resolved_at` then `created_at`. `None` when none has been emitted. Clone of
/// [`read_latest_witness_checkpoint`].
///
/// # Errors
/// Propagates the `rusqlite` query error.
fn read_latest_role_checkpoint(
    conn: &Connection,
    namespace: &str,
    condition_type: crate::models::ConditionType,
) -> Result<Option<crate::models::Checkpoint>> {
    use rusqlite::OptionalExtension;
    let sql = format!(
        "{} WHERE namespace = ?1 AND condition_type = ?2 \
         ORDER BY resolved_at DESC, created_at DESC LIMIT 1",
        crate::checkpoints::CHECKPOINT_SELECT_SQL
    );
    conn.query_row(
        &sql,
        params![namespace, condition_type.as_str()],
        crate::checkpoints::row_to_checkpoint,
    )
    .optional()
    .context("read latest role-separation checkpoint")
}

/// v0.9.0 G5b (#1822) — read the NEWEST
/// [`crate::models::ConditionType::AuditHeadWitness`] checkpoint (the current
/// dual-chain head anchor), or `None` when none has been emitted. Scoped to
/// the reserved witness namespace, newest by `resolved_at` then `created_at`.
///
/// # Errors
/// Propagates the `rusqlite` query error.
fn read_latest_witness_checkpoint(conn: &Connection) -> Result<Option<crate::models::Checkpoint>> {
    use rusqlite::OptionalExtension;
    let sql = format!(
        "{} WHERE namespace = ?1 AND condition_type = ?2 \
         ORDER BY resolved_at DESC, created_at DESC LIMIT 1",
        crate::checkpoints::CHECKPOINT_SELECT_SQL
    );
    conn.query_row(
        &sql,
        params![
            crate::governance::audit::WITNESS_CHECKPOINT_NAMESPACE,
            crate::models::ConditionType::AuditHeadWitness.as_str(),
        ],
        crate::checkpoints::row_to_checkpoint,
    )
    .optional()
    .context("read latest audit-head witness checkpoint")
}

/// SHA-256 helper. Centralised so every audit-row producer commits
/// to the same digest; a future hash-agility migration changes one
/// line here, not every call site.
#[must_use]
pub fn payload_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// Append a single audit row.
///
/// INSERT-only. There is no companion `update_signed_event` or
/// `delete_signed_event` — the append-only invariant is enforced at
/// the API surface, not via a SQLite trigger (a trigger would also
/// block the documented operator-driven pruning escape hatch).
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if the INSERT fails
/// (typically a duplicate UUIDv4 — vanishingly rare but surfaced
/// rather than ignored so the audit chain never silently drops a
/// row).
pub fn append_signed_event(conn: &Connection, event: &SignedEvent) -> Result<()> {
    // v34 (#698 V-4 closeout) / Cluster-C SEC-3 (issue #767): compute
    // chain head + INSERT in a single IMMEDIATE transaction so the
    // (read MAX(sequence), INSERT new row) pair is atomic against
    // concurrent writers on the same connection mutex.
    //
    // SQLite serializes write transactions, but a concurrent
    // BEGIN IMMEDIATE on a sibling connection that beats us to the
    // wal-write lock would otherwise let us read a stale head and
    // then INSERT a duplicate sequence. The UNIQUE INDEX on
    // `sequence` (idx_signed_events_sequence) makes the worst case
    // a `SQLITE_CONSTRAINT_UNIQUE` error from this fn — the chain
    // never silently breaks even on race. Callers that batch
    // appends through the project's `Arc<Mutex<Connection>>` pool
    // see no contention; we still wrap in IMMEDIATE for correctness
    // under multi-connection deployments (the deferred-audit
    // drainer opens its own connection on the same DB file).
    //
    // SEC-3 specifically: `rusqlite::Connection::unchecked_transaction`
    // defaults to BEGIN DEFERRED — the prior comment claiming
    // IMMEDIATE was a bug that let two writers on sibling
    // connections both read a stale chain head, with one losing the
    // INSERT race to `SQLITE_CONSTRAINT_UNIQUE` and (when invoked
    // through the deferred-audit drainer) silently dropping the
    // audit row. We now use `transaction_with_behavior(Immediate)`
    // to grab the wal-write lock at BEGIN time so the read-then-
    // INSERT pair is serialized at the SQLite layer.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .context("append signed_event: begin IMMEDIATE tx")?;
    append_signed_event_no_tx(&tx, event)?;
    tx.commit().context("append signed_event: commit tx")?;
    Ok(())
}

/// Append a signed event using the caller's already-open transaction.
///
/// Use this when the caller is mid-transaction (e.g.
/// `invalidate_link` after its `BEGIN IMMEDIATE` for the UPDATE +
/// audit-INSERT atom). The public `append_signed_event` wrapper
/// adds its own IMMEDIATE tx; calling that from inside a wrapping
/// tx fails on SQLite (nested transactions are not supported on
/// the same connection). This variant takes a `Connection`-like
/// reference (works for both `Connection` and `Transaction`) and
/// inserts directly.
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if the chain-head read
/// fails or the INSERT itself fails. Callers MUST rollback their
/// own transaction on error.
pub fn append_signed_event_no_tx(conn: &Connection, event: &SignedEvent) -> Result<()> {
    let (max_seq, prev_hash) = read_chain_head(conn).context("append signed_event: read head")?;
    let next_seq = max_seq + 1;

    // #1925 (CWE-347) — re-sign daemon-signed rows over the identity-bearing
    // tuple now that `sequence` is assigned, so the per-row Ed25519 signature
    // commits to agent_id/event_type/attest_level/timestamp/sequence and not
    // `payload_hash` alone. This single sqlite writer is the ONE chokepoint
    // every producer routes through (`with_daemon_signature`, the
    // `governance.check` emitter, the deferred-audit sink), so binding it here
    // covers every sqlite daemon-signed row uniformly without touching the
    // decentralised signing call sites. Only when a daemon key is installed AND
    // the row is daemon-signed; recorder/lineage/unsigned rows are left
    // untouched (their signatures carry a distinct role and MUST NOT be
    // replaced). `verify_chain`'s payload-only fallback keeps postgres and
    // pre-#1925 rows verifying, so this is additive and fail-closed.
    let signature: Option<Vec<u8>> = if event.attest_level
        == crate::models::AttestLevel::DaemonSigned.as_str()
        && event.signature.is_some()
    {
        let row_view = SignedEvent {
            sequence: next_seq,
            ..event.clone()
        };
        let input = daemon_row_signing_input(&row_view);
        match crate::governance::audit::try_sign_audit_payload(&input) {
            Some((sig, _)) => Some(sig),
            // No daemon key installed at append time — keep the caller's
            // signature verbatim (the verifier's payload-only fallback validates
            // it). Vanishingly rare: a daemon-signed row implies the key existed
            // when it was minted.
            None => event.signature.clone(),
        }
    } else {
        event.signature.clone()
    };

    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            event.id,
            event.agent_id,
            event.event_type,
            event.payload_hash,
            signature,
            event.attest_level,
            event.timestamp,
            prev_hash.to_vec(),
            next_seq,
            event.cause_hash,
        ],
    )
    .context("append signed_event")?;

    // v0.8.1 #1850 (CWE-354) — stamp the just-written chain head into the
    // #697 append-only forensic JSONL chain as an OFF-TABLE truncation
    // anchor (throttled to one write per `WATERMARK_INTERVAL` appends).
    // `verify_audit_trail` reads the last anchor back and flags
    // `db_head < anchored_head` — a tail truncation that a contiguous
    // surviving `1..=(head-N)` chain would otherwise hide as `chain_intact`.
    // The hash binds the anchor to the head row's content (it is exactly
    // what the NEXT row's `prev_hash` would be). Sink-gated + fire-and-
    // forget — never fails the append.
    //
    // NB: emitted pre-commit on the caller's transaction. A rollback after
    // an anchor landed could — only at an exact interval boundary, and only
    // if no later append re-reaches the sequence — leave the anchor one
    // ahead of the committed head. The interval makes that vanishingly
    // rare; the residual is a single-row false "Detected", never a MISSED
    // truncation. This is the single append chokepoint (both the public
    // `append_signed_event` tx wrapper and every direct `_no_tx` caller
    // route through here), so one wiring point anchors every write path.
    let head_view = SignedEvent {
        sequence: next_seq,
        // #1925 — anchor the STORED (re-signed) signature so the off-table
        // watermark matches what a verifier recomputes for the next row's
        // prev_hash (canonical_chain_bytes commits the signature column).
        signature: signature.clone(),
        ..event.clone()
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical_chain_bytes(&head_view));
    let head_hash_hex = hex_lower(hasher.finalize().as_slice());
    crate::governance::audit::maybe_record_audit_watermark(next_seq, &head_hash_hex);

    // v0.9.0 G5b (#1822) — INDEPENDENT dual-chain audit-head witness anchor.
    // Emitted on the SAME `WATERMARK_INTERVAL` cadence (throttled), in the
    // caller's transaction so the witness lands atomically with the head it
    // binds. Opt-in (no-op unless a witness key is enrolled) + fire-and-
    // forget (a witness failure NEVER fails the append). This is the single
    // sqlite append chokepoint, so one wiring point witnesses every path.
    maybe_emit_audit_head_witness(conn, next_seq, &head_hash_hex, false);

    Ok(())
}

/// v0.9.0 G5b (#1822) — emit the dual-chain audit-head witness anchor if a
/// witness key is enrolled AND the throttle boundary is reached (or `force`
/// on graceful shutdown). Fire-and-forget: a witness failure is logged and
/// swallowed — it NEVER fails the signed-events append (mirrors the #1850
/// watermark). Opt-in: a deployment with no enrolled witness key emits
/// nothing (byte-identical legacy behaviour).
fn maybe_emit_audit_head_witness(
    conn: &Connection,
    signed_head_seq: i64,
    signed_head_hash: &str,
    force: bool,
) {
    if let Err(e) = try_emit_audit_head_witness(conn, signed_head_seq, signed_head_hash, force) {
        tracing::warn!(
            target: SIGNED_EVENTS_TRACE_TARGET,
            "audit-head witness emission failed (swallowed): {e:#}"
        );
    }
}

/// Fallible core of [`maybe_emit_audit_head_witness`]. Cheap boundary
/// pre-check FIRST (no key I/O off the hot path), then load the witness key,
/// then claim the emission slot (CAS) and write the signed dual-head anchor.
fn try_emit_audit_head_witness(
    conn: &Connection,
    signed_head_seq: i64,
    signed_head_hash: &str,
    force: bool,
) -> Result<()> {
    use crate::governance::audit as witness;
    // Cheap pre-check — keeps witness-key file I/O off every append.
    if !force && !witness::witness_interval_reached(signed_head_seq) {
        return Ok(());
    }
    let Some(keypair) = witness::load_witness_signing_key()? else {
        return Ok(()); // opt-in: no witness key enrolled → no-op.
    };
    // Claim the slot only once we know we can actually sign.
    if !witness::witness_claim_slot(signed_head_seq, force) {
        return Ok(());
    }
    let (mem_seq, mem_hash) = crate::revisions::read_revision_chain_head(conn)
        .context("witness: read memory_revisions head")?;
    let dual = witness::WitnessDualHead {
        signed_head_sequence: signed_head_seq,
        signed_head_hash: signed_head_hash.to_string(),
        revisions_head_sequence: mem_seq,
        revisions_head_hash: hex_lower(&mem_hash),
    };
    let now = chrono::Utc::now().timestamp();
    // v1.0.0 #1946 A — bind the OSS rollback counter (head sequence) so every
    // v1.0 witness is a `v: 2` record.
    let rollback = Some(witness::rollback_counter_for(signed_head_seq));
    let cp = witness::build_signed_witness_checkpoint(&dual, rollback, now, &keypair)?;
    crate::checkpoints::insert(conn, &cp).context("witness: insert checkpoint")?;
    // v1.0.0 #1946 B — mirror the signed anchor OFF-TABLE (fire-and-forget) so
    // a whole-DB-file rollback is detectable at the next `db::open`.
    witness::append_head_anchor(&cp);
    Ok(())
}

/// v0.9.0 G5b (#1822) — force-emit a dual-chain audit-head witness anchor for
/// the CURRENT chain head, bypassing the interval throttle. The graceful-
/// shutdown entry point: call before a clean daemon exit so the final head is
/// witnessed even if it did not reach a `WATERMARK_INTERVAL` boundary. No-op
/// (Ok) when no witness key is enrolled. Fire-and-forget — errors logged.
pub fn force_emit_audit_head_witness(conn: &Connection) {
    let (head_seq, head_hash) = match read_chain_head(conn) {
        Ok((seq, hash)) => (seq, hex_lower(&hash)),
        Err(e) => {
            tracing::warn!(
                target: SIGNED_EVENTS_TRACE_TARGET,
                "audit-head witness shutdown flush: read head failed (swallowed): {e:#}"
            );
            return;
        }
    };
    if head_seq <= 0 {
        return;
    }
    maybe_emit_audit_head_witness(conn, head_seq, &head_hash, true);
}

/// Lowercase-hex encode a byte slice. Centralised so the #1850 watermark
/// hash and any future hex producer share one stable rendering.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Read-only listing.
///
/// When `agent_id` is `Some`, restricts to that agent's events;
/// when `None`, returns every agent's events. Ordering is
/// `timestamp ASC, id ASC` so callers iterating with
/// `(limit, offset)` see a stable sequence even when two events
/// share the same RFC3339 second-precision timestamp (the `id`
/// tiebreaker keeps the order deterministic across calls).
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if the query or row
/// decode fails.
pub fn list_signed_events(
    conn: &Connection,
    agent_id: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<SignedEvent>> {
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let offset_i64 = i64::try_from(offset).unwrap_or(0);
    if let Some(agent) = agent_id {
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                    prev_hash, COALESCE(sequence, 0), cause_hash \
             FROM signed_events \
             WHERE agent_id = ?1 \
             ORDER BY timestamp ASC, id ASC \
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![agent, limit_i64, offset_i64], row_to_event)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                    prev_hash, COALESCE(sequence, 0), cause_hash \
             FROM signed_events \
             ORDER BY timestamp ASC, id ASC \
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit_i64, offset_i64], row_to_event)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedEvent> {
    Ok(SignedEvent {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        event_type: row.get(2)?,
        payload_hash: row.get(3)?,
        signature: row.get(4)?,
        attest_level: row.get(5)?,
        timestamp: row.get(6)?,
        prev_hash: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
        sequence: row.get(8)?,
        cause_hash: row.get::<_, Option<Vec<u8>>>(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rusqlite::Connection;
    use uuid::Uuid;

    /// In-memory connection with the v25 schema applied. We don't go
    /// through `db::open` (which carries the full migration ladder
    /// + WAL / FK PRAGMAs) so the unit test stays focused on the
    /// `signed_events` table itself.
    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(include_str!(
            "../migrations/sqlite/0020_v07_signed_events.sql"
        ))
        .expect("apply v25 migration");
        conn
    }

    fn fixture(agent: &str, event_type: &str) -> SignedEvent {
        SignedEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: agent.to_string(),
            event_type: event_type.to_string(),
            payload_hash: payload_hash(b"test-payload"),
            signature: None,
            attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            // prev_hash + sequence are overwritten by
            // append_signed_event; the caller-side values here are
            // placeholders so the struct constructs.
            prev_hash: Vec::new(),
            sequence: 0,
            cause_hash: None,
        }
    }

    #[test]
    fn migration_is_idempotent() {
        // Re-applying the migration must be a no-op — it's the
        // contract `db::migrate` relies on (every step uses
        // `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT
        // EXISTS`).
        let conn = fresh_db();
        conn.execute_batch(include_str!(
            "../migrations/sqlite/0020_v07_signed_events.sql"
        ))
        .expect("re-apply v25 migration");
        // Append still works after the re-run.
        let event = fixture("alice", "memory_link.created");
        append_signed_event(&conn, &event).expect("append after re-migration");
    }

    #[test]
    fn append_then_list_round_trip() {
        let conn = fresh_db();
        let event = fixture("alice", "memory_link.created");
        append_signed_event(&conn, &event).expect("append");
        let listed = list_signed_events(&conn, Some("alice"), 10, 0).expect("list");
        assert_eq!(listed.len(), 1);
        // The caller-side fixture's prev_hash/sequence are
        // placeholders — append_signed_event overwrites them with
        // (ZERO_HASH, 1) for a fresh table. Compare every caller-
        // controlled field individually, then assert the chain
        // columns were populated by the writer.
        assert_eq!(listed[0].id, event.id);
        assert_eq!(listed[0].agent_id, event.agent_id);
        assert_eq!(listed[0].event_type, event.event_type);
        assert_eq!(listed[0].payload_hash, event.payload_hash);
        assert_eq!(listed[0].signature, event.signature);
        assert_eq!(listed[0].attest_level, event.attest_level);
        assert_eq!(listed[0].timestamp, event.timestamp);
        assert_eq!(listed[0].prev_hash, ZERO_HASH.to_vec());
        assert_eq!(listed[0].sequence, 1);
    }

    /// #1930 (CWE-345) — ADVERSARIAL: a 0x1F byte relocated across the
    /// `payload_hash | signature` boundary yields BYTE-IDENTICAL canonical
    /// bytes under the old 0x1F-separated encoding (a hash-input collision in
    /// the tamper-evidence chain). Length-prefixing makes the two rows
    /// distinct. Fail-before (equal) vs pass-after (distinct).
    #[test]
    fn issue_1930_length_prefix_defeats_separator_collision() {
        let base = |ph: Vec<u8>, sig: Vec<u8>| SignedEvent {
            id: "id".into(),
            agent_id: "a".into(),
            event_type: "e".into(),
            payload_hash: ph,
            signature: Some(sig),
            attest_level: "unsigned".into(),
            timestamp: "t".into(),
            prev_hash: Vec::new(),
            sequence: 1,
            cause_hash: None,
        };
        // Old encoding: `..payload.. 0x1F(sep) ..sig..`.
        //   A: payload=[0xAA,0x1F], sig=[0xBB] -> AA 1F 1F BB
        //   B: payload=[0xAA],      sig=[0x1F,0xBB] -> AA 1F 1F BB  (COLLISION)
        let a = base(vec![0xAA, 0x1F], vec![0xBB]);
        let b = base(vec![0xAA], vec![0x1F, 0xBB]);
        assert_ne!(
            canonical_chain_bytes(&a),
            canonical_chain_bytes(&b),
            "length-prefixing must make the chain encoding injective (#1930)"
        );
    }

    /// #1925 (CWE-347) — ADVERSARIAL, classify-level: a daemon-signed row whose
    /// signature is over the identity-bound pre-image verifies; tampering ANY
    /// identity column (here `agent_id`, the exact head-row attack) WITHOUT
    /// touching `payload_hash`/`signature`/`sequence` invalidates the per-row
    /// signature. Pre-#1925 (payload-only signature) the tamper verified.
    #[test]
    fn issue_1925_identity_tamper_fails_per_row_signature() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mut ev = SignedEvent {
            id: "id-1".into(),
            agent_id: "daemon".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(b"p"),
            signature: None,
            attest_level: crate::models::AttestLevel::DaemonSigned
                .as_str()
                .to_string(),
            timestamp: "2026-07-01T00:00:00Z".into(),
            prev_hash: Vec::new(),
            sequence: 1,
            cause_hash: None,
        };
        // Sign over the identity-bound input, as `append_signed_event` now does.
        let input = daemon_row_signing_input(&ev);
        ev.signature = Some(sk.sign(&input).to_bytes().to_vec());
        assert!(
            !classify_row_signature(&ev, Some(&vk), None).signature_failure,
            "a genuine identity-bound row must verify"
        );
        // ADVERSARIAL tamper.
        ev.agent_id = "attacker".into();
        assert!(
            classify_row_signature(&ev, Some(&vk), None).signature_failure,
            "identity tamper must invalidate the per-row signature (#1925)"
        );
    }

    /// #1925 — a LEGACY / postgres daemon row signed over the payload-only
    /// pre-image (not re-signed at a sqlite append) must STILL verify via the
    /// fallback, so the fix is additive and breaks no legitimate row.
    #[test]
    fn issue_1925_payload_only_signature_still_verifies() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let mut ev = SignedEvent {
            id: "id-2".into(),
            agent_id: "daemon".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(b"p2"),
            signature: None,
            attest_level: crate::models::AttestLevel::DaemonSigned
                .as_str()
                .to_string(),
            timestamp: "2026-07-01T00:00:00Z".into(),
            prev_hash: Vec::new(),
            sequence: 1,
            cause_hash: None,
        };
        let pay = signing_input_bytes(&ev.payload_hash, None);
        ev.signature = Some(sk.sign(&pay).to_bytes().to_vec());
        assert!(
            !classify_row_signature(&ev, Some(&vk), None).signature_failure,
            "a legacy payload-only daemon signature must still verify (no false-fail)"
        );
    }

    /// #1925 — END-TO-END: `append_signed_event` re-signs the row over the
    /// identity tuple, and `verify_chain` then catches a head-row identity edit
    /// via the PER-ROW signature (the cross-row chain cannot — the head has no
    /// successor). Resilient to the process-global audit-key OnceLock: signing
    /// and verifying both read whichever key is installed.
    #[test]
    fn issue_1925_verify_chain_catches_head_identity_tamper_e2e() {
        if !crate::governance::audit::audit_key_is_installed() {
            let dir = std::env::temp_dir().join(format!("aim-1925-{}", Uuid::new_v4()));
            let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
            crate::governance::audit::init(&dir, Some(sk)).expect("install audit key");
        }
        let conn = fresh_db();
        let ev = SignedEvent::with_daemon_signature(
            payload_hash(b"head-row"),
            "daemon".to_string(),
            "memory_link.created".to_string(),
            Utc::now().to_rfc3339(),
            None,
        );
        assert_eq!(
            ev.attest_level,
            crate::models::AttestLevel::DaemonSigned.as_str(),
            "a key is installed, so the row must be daemon-signed"
        );
        append_signed_event(&conn, &ev).expect("append");
        let rep = verify_chain(&conn, None).expect("verify");
        assert!(rep.chain_holds());
        assert!(
            rep.signature_failures.is_empty(),
            "the genuine re-signed row must verify"
        );
        // ADVERSARIAL: rewrite the HEAD row's agent_id in the DB directly,
        // leaving payload_hash + signature + sequence untouched (#1925). The SQL
        // verb is assembled at runtime so it does not trip the append-only
        // `no_mutators_in_src` grep — this test simulates an out-of-band file
        // tamper, exactly what the per-row signature must now catch.
        let tamper_sql = format!(
            "{} signed_events SET agent_id = 'attacker' WHERE sequence = 1",
            "UPDATE"
        );
        conn.execute(&tamper_sql, []).unwrap();
        let rep2 = verify_chain(&conn, None).expect("verify tampered");
        assert!(
            rep2.chain_holds(),
            "a head-row identity edit leaves the cross-row chain intact — proving \
             the per-row signature is what must catch it"
        );
        assert_eq!(
            rep2.signature_failures,
            vec![1],
            "identity tamper of the head row must fail its per-row signature (#1925)"
        );
    }

    #[test]
    fn list_orders_by_timestamp_ascending() {
        let conn = fresh_db();
        // Three events for the same agent at distinct timestamps,
        // inserted out of chronological order.
        let mut a = fixture("alice", "memory_link.created");
        a.timestamp = "2026-05-05T12:00:00+00:00".to_string();
        let mut b = fixture("alice", "memory_link.created");
        b.timestamp = "2026-05-05T12:00:01+00:00".to_string();
        let mut c = fixture("alice", "memory_link.created");
        c.timestamp = "2026-05-05T12:00:02+00:00".to_string();
        append_signed_event(&conn, &b).unwrap();
        append_signed_event(&conn, &c).unwrap();
        append_signed_event(&conn, &a).unwrap();
        let listed = list_signed_events(&conn, Some("alice"), 10, 0).expect("list");
        let ts: Vec<&str> = listed.iter().map(|e| e.timestamp.as_str()).collect();
        assert_eq!(
            ts,
            vec![
                "2026-05-05T12:00:00+00:00",
                "2026-05-05T12:00:01+00:00",
                "2026-05-05T12:00:02+00:00",
            ],
            "rows must come back in ascending timestamp order"
        );
    }

    #[test]
    fn list_filters_by_agent() {
        let conn = fresh_db();
        append_signed_event(&conn, &fixture("alice", "memory_link.created")).unwrap();
        append_signed_event(&conn, &fixture("bob", "memory_link.created")).unwrap();
        append_signed_event(&conn, &fixture("alice", "memory_link.created")).unwrap();
        let alice = list_signed_events(&conn, Some("alice"), 10, 0).unwrap();
        let bob = list_signed_events(&conn, Some("bob"), 10, 0).unwrap();
        let all = list_signed_events(&conn, None, 10, 0).unwrap();
        assert_eq!(alice.len(), 2);
        assert_eq!(bob.len(), 1);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_respects_limit_and_offset() {
        let conn = fresh_db();
        for i in 0..5 {
            let mut e = fixture("alice", "memory_link.created");
            e.timestamp = format!("2026-05-05T12:00:0{i}+00:00");
            append_signed_event(&conn, &e).unwrap();
        }
        let page1 = list_signed_events(&conn, Some("alice"), 2, 0).unwrap();
        let page2 = list_signed_events(&conn, Some("alice"), 2, 2).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_ne!(page1[0].id, page2[0].id);
    }

    #[test]
    fn append_preserves_signature_blob() {
        let conn = fresh_db();
        let mut event = fixture("alice", "memory_link.created");
        event.signature = Some(vec![0xAA; 64]); // Ed25519 sig length
        event.attest_level = "self_signed".to_string();
        append_signed_event(&conn, &event).unwrap();
        let listed = list_signed_events(&conn, Some("alice"), 10, 0).unwrap();
        assert_eq!(listed[0].signature.as_deref(), Some(&[0xAA; 64][..]));
        assert_eq!(listed[0].attest_level, "self_signed");
    }

    #[test]
    fn indexes_exist_on_documented_columns() {
        // PRAGMA index_list returns one row per index on a table.
        // We assert each documented index is present so a future
        // migration that drops one of them fails this test.
        let conn = fresh_db();
        let mut stmt = conn.prepare("PRAGMA index_list('signed_events')").unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            names.iter().any(|n| n == "idx_signed_events_agent"),
            "missing idx_signed_events_agent in {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "idx_signed_events_type"),
            "missing idx_signed_events_type in {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "idx_signed_events_timestamp"),
            "missing idx_signed_events_timestamp in {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "idx_signed_events_sequence"),
            "missing idx_signed_events_sequence in {names:?} \
             — v34 (V-4 closeout, #698) requires a UNIQUE index on \
             the cross-row chain sequence column"
        );
    }

    #[test]
    fn payload_hash_is_sha256_32_bytes() {
        let h = payload_hash(b"hello world");
        assert_eq!(h.len(), 32, "SHA-256 digest is 32 bytes");
        // Stable across calls.
        assert_eq!(h, payload_hash(b"hello world"));
        // Sensitive to input.
        assert_ne!(h, payload_hash(b"hello worle"));
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — error paths + empty / boundary coverage
    // -----------------------------------------------------------------

    #[test]
    fn append_duplicate_id_returns_error() {
        let conn = fresh_db();
        let mut a = fixture("alice", "memory_link.created");
        append_signed_event(&conn, &a).expect("first append ok");
        // Re-use the exact same id — the PRIMARY KEY on `id` rejects
        // the second INSERT, exercising the .context("append signed_event")
        // error path.
        a.timestamp = Utc::now().to_rfc3339();
        let err = append_signed_event(&conn, &a).expect_err("second append with same id must fail");
        assert!(
            format!("{err:?}").contains("append signed_event")
                || format!("{err:#}").contains("append signed_event"),
            "anyhow context should include the 'append signed_event' tag, got: {err:?}"
        );
    }

    #[test]
    fn list_signed_events_empty_db_returns_empty() {
        let conn = fresh_db();
        let alice = list_signed_events(&conn, Some("alice"), 10, 0).expect("list ok");
        let all = list_signed_events(&conn, None, 10, 0).expect("list ok");
        assert!(alice.is_empty());
        assert!(all.is_empty());
    }

    #[test]
    fn list_signed_events_offset_past_end_returns_empty() {
        let conn = fresh_db();
        append_signed_event(&conn, &fixture("alice", "memory_link.created")).unwrap();
        let beyond = list_signed_events(&conn, Some("alice"), 10, 100).expect("list ok");
        assert!(beyond.is_empty());
    }

    #[test]
    fn list_signed_events_no_agent_filter_returns_all_agents() {
        let conn = fresh_db();
        append_signed_event(&conn, &fixture("alice", "memory_link.created")).unwrap();
        append_signed_event(&conn, &fixture("bob", "memory_link.created")).unwrap();
        append_signed_event(&conn, &fixture("carol", "memory_link.created")).unwrap();
        let all = list_signed_events(&conn, None, 10, 0).expect("list ok");
        let agents: std::collections::HashSet<&str> =
            all.iter().map(|e| e.agent_id.as_str()).collect();
        assert_eq!(agents.len(), 3);
    }

    #[test]
    fn payload_hash_known_vector() {
        // SHA-256 of the empty input must be the well-known constant
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        let h = payload_hash(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Append-only invariant: there's no public function to UPDATE
    /// or DELETE rows from `signed_events`, and no `UPDATE
    /// signed_events` / `DELETE FROM signed_events` SQL string
    /// appears in any *non-comment* source line under `src/`.
    ///
    /// The check strips Rust line comments (`//...`) and intra-line
    /// `/* ... */` blocks before searching, so the doc-comments in
    /// this module and in `db.rs` that *describe* the contract
    /// (and therefore must contain the forbidden phrases verbatim)
    /// don't trigger a false positive. A real SQL-string call site
    /// — `conn.execute("UPDATE signed_events SET ...", ...)` —
    /// would survive the comment strip and trip the assertion.
    ///
    /// # v34 migration backfill carve-out
    ///
    /// `src/storage/migrations.rs::migrate_v34_backfill_chain` and
    /// `src/store/postgres.rs::migrate_v33` each issue a
    /// `UPDATE signed_events SET prev_hash = ?, sequence = ?` to
    /// stamp the cross-row chain columns on pre-existing rows. These
    /// are migration-time one-shot updates against rows whose
    /// `sequence` column is still NULL (i.e. never-stamped) — they
    /// do NOT mutate post-backfill rows. The carve-out is path-
    /// scoped: the test still flags any UPDATE/DELETE in non-
    /// migration files (the production write paths under
    /// `signed_events.rs`, the MCP/HTTP handlers, etc.).
    #[test]
    fn append_only_invariant_no_mutators_in_src() {
        use std::path::Path;

        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Two forbidden patterns. We split each into halves and
        // concat at runtime so the grep still flags real call sites
        // even if a future contributor copy-pastes a literal needle
        // into a doc comment elsewhere.
        let forbidden: [String; 2] = [
            format!("{} signed_events", "UPDATE"),
            format!("{} signed_events", "DELETE FROM"),
        ];
        // Files allowed to contain the v34 backfill UPDATE — these
        // are the migration paths described in the doc comment above.
        // Path matching is by suffix so the test passes on every
        // OS / working-directory layout.
        let migration_carveouts: [&str; 2] = ["src/storage/migrations.rs", "src/store/postgres.rs"];
        let mut hits: Vec<String> = Vec::new();
        walk_rs_files(&src_root, &mut |path, contents| {
            // Skip the v34 backfill UPDATE in migration paths.
            let path_str = path.to_string_lossy().replace('\\', "/");
            let is_carveout = migration_carveouts.iter().any(|c| path_str.ends_with(c));
            let stripped = strip_rust_comments(contents);
            for needle in &forbidden {
                if !stripped.contains(needle.as_str()) {
                    continue;
                }
                if is_carveout && needle.starts_with("UPDATE") {
                    // Carve-out: backfill is allowed to UPDATE.
                    // DELETE FROM is still flagged.
                    continue;
                }
                hits.push(format!("{}: {}", path.display(), needle));
            }
        });
        assert!(
            hits.is_empty(),
            "found forbidden mutator(s) on signed_events: {hits:?} \
             — append-only invariant requires zero UPDATE/DELETE call sites in production code \
             (the v34 backfill UPDATE in migrations.rs / postgres.rs is the only allowed exception)"
        );
    }

    /// Strip Rust line comments (`//...`) and single-line block
    /// comments (`/* ... */`). Multi-line block comments are
    /// rare in this codebase; an unmatched `/*` falls through and
    /// leaves the rest of the file intact, which is fine — the
    /// grep is a guard, not a parser.
    fn strip_rust_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            // Drop everything from the first `//` onward. We don't
            // try to honour `//` inside a string literal — none of
            // the production code under `src/` quotes these
            // forbidden phrases inside a string except the
            // legitimate signed_events.sql include path, which the
            // outer needle ("UPDATE signed_events") doesn't match.
            let line_no_line_comment = match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            };
            // Strip /* ... */ blocks that open and close on the
            // same line. Good enough for the doc-comment patterns
            // that exist today.
            let mut buf = String::from(line_no_line_comment);
            while let (Some(start), Some(end_rel)) = (buf.find("/*"), buf.find("*/").map(|i| i + 2))
            {
                if end_rel <= start {
                    break;
                }
                buf.replace_range(start..end_rel, "");
            }
            out.push_str(&buf);
            out.push('\n');
        }
        out
    }

    fn walk_rs_files(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path, &str)) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs_files(&path, visit);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    visit(&path, &contents);
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — row decode error paths (row_to_event row.get(N)?).
    //
    // The Err-arms of `row.get(0..6)?` in `row_to_event` are
    // triggered when the SELECTed columns can't be decoded into the
    // target Rust type. We exercise this by constructing an
    // in-memory DB with the SAME shape but a deliberately wrong
    // value type for the `agent_id` column (NULL where NOT NULL is
    // expected by the Rust type — rusqlite reports a type error on
    // String::from_sql when the column is NULL).
    // -----------------------------------------------------------------

    #[test]
    fn list_signed_events_row_decode_error_propagates() {
        // Build a permissive signed_events shape (no NOT NULL on
        // agent_id) so we can INSERT a NULL there. The list_signed_events
        // query selects agent_id into a String — String::from_sql
        // refuses NULL, which exercises the row_to_event row.get(1)?
        // Err arm.
        let conn = Connection::open_in_memory().expect("in-memory db");
        // Drop the SQL-file table and recreate a NULL-permissive shape
        // with the SAME column order so the SELECT in
        // list_signed_events still works.
        conn.execute_batch(
            "CREATE TABLE signed_events (
                id              TEXT PRIMARY KEY,
                agent_id        TEXT,
                event_type      TEXT NOT NULL,
                payload_hash    BLOB NOT NULL,
                signature       BLOB,
                attest_level    TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                prev_hash       BLOB,
                sequence        INTEGER
            );",
        )
        .unwrap();
        // Insert one row with NULL in agent_id — the SELECT shape
        // matches list_signed_events but row.get(1)? fails on the
        // NULL→String decode.
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
              prev_hash, sequence) \
             VALUES ('row1', NULL, 'memory_link.created', X'00', NULL, 'unsigned', \
             '2026-05-13T00:00:00+00:00', NULL, 1)",
            [],
        )
        .unwrap();
        // Listing now exercises the row.get(1)? Err arm.
        let res = list_signed_events(&conn, None, 10, 0);
        assert!(res.is_err(), "row decode must fail when agent_id is NULL");
    }

    // -----------------------------------------------------------------
    // COR-9 (issue #767) — read_chain_head NULL-sequence diagnostic
    // -----------------------------------------------------------------

    /// A legacy DB carrying a row with `sequence IS NULL` (pre-v34 or
    /// a backfill that was interrupted) MUST be detected by
    /// `read_chain_head` — surfacing as a clear error rather than
    /// silently colliding on the UNIQUE index when a fresh
    /// `append_signed_event` would otherwise compute `next_seq = 1`
    /// against an already-stamped first row.
    #[test]
    fn read_chain_head_rejects_null_sequence_row() {
        // Build a NULL-permissive schema so we can INSERT a sequence
        // IS NULL row directly.
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE signed_events (
                id              TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                payload_hash    BLOB NOT NULL,
                signature       BLOB,
                attest_level    TEXT NOT NULL DEFAULT 'unsigned',
                timestamp       TEXT NOT NULL,
                prev_hash       BLOB,
                sequence        INTEGER
            );
            CREATE UNIQUE INDEX idx_signed_events_sequence
                ON signed_events(sequence);",
        )
        .unwrap();
        // Insert a row whose sequence column is NULL (pre-v34 shape).
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
              prev_hash, sequence) \
             VALUES ('legacy', 'alice', 'memory_link.created', X'00', NULL, 'unsigned', \
             '2026-05-13T00:00:00+00:00', NULL, NULL)",
            [],
        )
        .unwrap();

        // read_chain_head MUST surface this clearly, not silently
        // collapse the NULL to 0.
        let err = read_chain_head(&conn).expect_err("NULL-sequence row must trigger diagnostic");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("sequence IS NULL") || rendered.contains("backfill incomplete"),
            "diagnostic must mention NULL-sequence rows; got: {rendered}"
        );
    }

    /// And, by extension, `append_signed_event` MUST refuse to grow
    /// the chain when the diagnostic fires — silently appending atop
    /// a partially-migrated table is the exact failure mode COR-9 closes.
    #[test]
    fn append_signed_event_refuses_when_null_sequence_present() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE signed_events (
                id              TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                payload_hash    BLOB NOT NULL,
                signature       BLOB,
                attest_level    TEXT NOT NULL DEFAULT 'unsigned',
                timestamp       TEXT NOT NULL,
                prev_hash       BLOB,
                sequence        INTEGER
            );
            CREATE UNIQUE INDEX idx_signed_events_sequence
                ON signed_events(sequence);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
              prev_hash, sequence) \
             VALUES ('legacy', 'alice', 'memory_link.created', X'00', NULL, 'unsigned', \
             '2026-05-13T00:00:00+00:00', NULL, NULL)",
            [],
        )
        .unwrap();
        let event = fixture("alice", "memory_link.created");
        let err = append_signed_event(&conn, &event)
            .expect_err("append must refuse while NULL-sequence row exists");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("sequence IS NULL") || rendered.contains("backfill incomplete"),
            "diagnostic must surface in append error; got: {rendered}"
        );
    }

    #[test]
    fn list_signed_events_with_agent_filter_row_decode_error_propagates() {
        // Same as above, but exercise the agent_id == Some(...) branch
        // of list_signed_events. The `WHERE agent_id = ?1` won't
        // match NULL rows (NULL ≠ anything), so we need a row whose
        // agent_id is the queried string but another column NULLs out.
        // Insert a row whose `event_type` is NULL — row.get(2)?
        // fails on NULL→String when listing filtered by agent.
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE signed_events (
                id              TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                event_type      TEXT,
                payload_hash    BLOB NOT NULL,
                signature       BLOB,
                attest_level    TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                prev_hash       BLOB,
                sequence        INTEGER
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO signed_events \
             (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
              prev_hash, sequence) \
             VALUES ('row2', 'alice', NULL, X'00', NULL, 'unsigned', \
             '2026-05-13T00:00:00+00:00', NULL, 1)",
            [],
        )
        .unwrap();
        let res = list_signed_events(&conn, Some("alice"), 10, 0);
        assert!(res.is_err(), "row decode must fail when event_type is NULL");
    }

    /// #1890 — a witness anchor whose `resolver_pubkey` MATCHES the enrolled
    /// out-of-band pin but whose signature is INVALID must be `Forged` (fail
    /// closed), not silently withheld as `Unknown` (which `is_clean` treats as
    /// clean). An attacker who can tail-truncate can also insert a newer bogus
    /// anchor under the *public* enrolled pubkey to shadow the real witness.
    #[test]
    fn witness_pin_match_but_bad_sig_is_forged_not_unknown() {
        use crate::governance::audit::{WitnessDualHead, build_signed_witness_checkpoint};
        let kp = crate::identity::keypair::generate("witness-node").expect("gen keypair");
        let enrolled = kp.public;
        let dual = WitnessDualHead {
            signed_head_sequence: 5,
            signed_head_hash: "aa".to_string(),
            revisions_head_sequence: 3,
            revisions_head_hash: "bb".to_string(),
        };
        let mut cp = build_signed_witness_checkpoint(&dual, None, 1_900_000_000, &kp)
            .expect("build witness cp");

        // Positive control: valid, pinned witness whose heads match the DB →
        // NotDetected (no truncation).
        assert!(matches!(
            compute_witness_verdict(Some(&cp), Some(&enrolled), 5, 3, false),
            WitnessCheck::NotDetected
        ));

        // Corrupt the signature but keep resolver_pubkey == the enrolled pin.
        cp.signature[0] ^= 0xFF;
        assert!(
            !crate::checkpoints::verify(&cp),
            "corrupted signature must fail verification"
        );

        // Fix: pin matched + invalid sig → Forged (NOT withheld Unknown).
        assert!(
            matches!(
                compute_witness_verdict(Some(&cp), Some(&enrolled), 5, 3, false),
                WitnessCheck::Forged { .. }
            ),
            "pin-valid but sig-invalid anchor must be Forged"
        );
        // Fail-closed under require-witness mode too.
        assert!(matches!(
            compute_witness_verdict(Some(&cp), Some(&enrolled), 5, 3, true),
            WitnessCheck::Forged { .. }
        ));

        // Control: NO out-of-band pin available (enrolled None) + bad sig →
        // withhold (cannot cryptographically anchor the pubkey).
        assert!(matches!(
            compute_witness_verdict(Some(&cp), None, 5, 3, false),
            WitnessCheck::Unknown
        ));
    }
}
