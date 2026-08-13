// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2030 — the Portability-v2 §V2-6 export-envelope **L1/L2/L3 round-trip
//! conformance fixture** + its round-trip test.
//!
//! This closes the last conformance-corpus residue tracked in
//! `conformance/README.md` §"Corpus coverage" — the envelope-level round-trip
//! fixture that the #1837 CC0 corpus could not encoder-generate until the
//! #2006 Portability-v2 exporter/importer shipped (`src/portability/`). The
//! stale blocker was "#1944's v1.x v2-envelope producer"; #2006 landed that
//! producer on `release/v1.0.0`, so the fixture is now generable from a PINNED
//! PRODUCTION encoder under the same drift-gated discipline as its hex-vector
//! siblings.
//!
//! ## Two tests, one fixture
//! 1. [`fixture_matches_pinned_exporter`] — the drift gate: it regenerates the
//!    envelope from the pinned `emit::build_full_envelope` and byte-compares it
//!    against the committed golden
//!    `conformance/vectors/export/round_trip_l3.json`. Under
//!    `AI_MEMORY_REGEN_GOLDEN=1` it (re)writes the golden instead. This mirrors
//!    `tests/conformance_corpus.rs`'s regen/gate discipline so a stale fixture
//!    fails CI.
//! 2. [`committed_fixture_round_trips_through_production_importer`] — reads the
//!    COMMITTED golden and round-trips it through the production importer
//!    (`import::import_full_envelope`), asserting per-class byte-exact
//!    preservation of the signed spine (L2) + the source-of-truth memory TEXT
//!    (L1) + the governance rule / operator trust anchor (L3), per spec §V2-1.
//!
//! ## Determinism (no `Date::now`-style nondeterminism — every byte is fixed)
//! Every seeded row uses a FIXED id + FIXED RFC3339 timestamp, so the SHA-256
//! `signed_events` hash chain, the `memory_revisions` spine, the `cid`
//! content-address, and the whole serialized envelope reproduce byte-identically
//! on any host. `model_attestations` are RAW-inserted (the production
//! `record_loader_observed` helper mints a `uuid` + `Utc::now()` — unsuitable
//! for a golden). The L3 operator trust anchor is enrolled from a FIXED,
//! documented CC0 TEST public key that THIS test sets in the environment for
//! BOTH regen and the drift-gate (and scrubs every other role key + points the
//! key dirs at an empty temp dir), so `conformance_level` reaches L3
//! deterministically without depending on the host's ambient key enrolment. The
//! private seed NEVER crosses the envelope — only the PUBLIC anchor does (spec
//! §V2-2.6 / §V2-5a).
//!
//! ## Vector-clock actor pin (the machine-independence fix)
//! A memory's durable `metadata.version_vector` is keyed by the process
//! federation node identity, which defaults to `host:<hostname>` — a
//! machine-dependent value that would otherwise leak the generating host into
//! the committed golden (`host:host.example` vs a CI runner's `host:runnervm…`). We
//! PIN `AI_MEMORY_FED_IDENTITY` (env #61) to a FIXED, machine-independent id
//! (`conformance-fixture-writer`) before the FIRST DB write, so the vector-clock
//! actor key is stable in any environment. `local_node_identity()` caches its
//! resolution in a process `OnceLock` on first read, so the pin is forced once,
//! ordering-safe, before either test touches the insert path.

#![allow(clippy::missing_panics_doc)]
// `src_*` / `dst_*` and `dto`/`row` pairings are a deliberate
// source-vs-destination naming convention; the pedantic lint is noise here.
#![allow(clippy::similar_names)]
// The round-trip test asserts every class end-to-end in one body (byte-exact +
// semantic), which is clearer as one linear narrative than split apart.
#![allow(clippy::too_many_lines)]
// Prose-heavy module/fn docs cite spec identifiers (RFC3339, Portability-v2, …)
// that read naturally without per-token backticks.
#![allow(clippy::doc_markdown)]

mod common;

use std::path::PathBuf;

use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::models::{Memory, MemoryKind};
use ai_memory::portability::dto::{
    ForgetTombstoneDto, GovernanceRuleDto, ModelAttestationDto, RevisionDto, SignedEventDto,
};
use ai_memory::portability::{emit, import, read};
use ai_memory::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
use ai_memory::signed_events::{
    SignedEvent, append_signed_event, list_signed_events, payload_hash,
};
use ai_memory::storage::model_attest;
use base64::Engine;
use common::MultiEnvVarGuard;
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, params};

/// Regenerate-the-golden switch, matching `tests/conformance_corpus.rs`.
const REGEN_ENV: &str = "AI_MEMORY_REGEN_GOLDEN";
/// Committed golden path, relative to the crate manifest dir.
const FIXTURE_REL: &str = "conformance/vectors/export/round_trip_l3.json";
/// The one fixed timestamp every seeded row shares (no `Utc::now()` anywhere).
const FIXED_TS: &str = "2026-07-14T00:00:00Z";
/// Fixed producer label baked into the golden.
const FIXTURE_SOURCE: &str = "ai-memory-conformance-2030";
/// The seeded durable-memory id (the L1 source-of-truth TEXT lane).
const SEED_MEMORY_ID: &str = "mem-round-1";
/// Fixed, documented CC0 **TEST** operator seed — NEVER a production key. Only
/// its PUBLIC verifying key is enrolled (during generation) so the exporter's
/// COMPUTED conformance marker reaches L3 deterministically; the private seed
/// never crosses the envelope.
const FIXTURE_OPERATOR_SEED: [u8; 32] = [0x2a; 32];
/// Fixed, machine-INDEPENDENT federation node identity (env #61
/// `AI_MEMORY_FED_IDENTITY`). Pins the durable `metadata.version_vector` actor
/// key so it does not leak `host:<hostname>` into the committed golden.
const FIXTURE_NODE_IDENTITY: &str = "conformance-fixture-writer";

/// Pin the process federation node identity to [`FIXTURE_NODE_IDENTITY`] BEFORE
/// any DB write stamps a `metadata.version_vector`. `local_node_identity()`
/// resolves once (`OnceLock`) to `AI_MEMORY_FED_IDENTITY` → configured →
/// `host:<hostname>`; the host default is machine-dependent and would break the
/// golden's determinism. Set the env under the shared `ENV_LOCK`, FORCE the
/// resolution to cache the fixed id while the env is set, then release the guard
/// — the cached value persists process-wide, so every later insert (generation
/// AND round-trip import) stamps the same actor key regardless of test order.
fn ensure_fixed_node_identity() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _g =
            MultiEnvVarGuard::apply(&[("AI_MEMORY_FED_IDENTITY", Some(FIXTURE_NODE_IDENTITY))]);
        // Force the OnceLock to cache the fixed id while the env is set.
        let resolved = ai_memory::federation::identity::resolver::local_node_identity();
        assert_eq!(
            resolved, FIXTURE_NODE_IDENTITY,
            "node identity must pin to the fixed fixture writer (was a prior read already cached?)"
        );
    });
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL)
}

/// URL-safe-no-pad base64 of the fixed TEST operator PUBLIC key (the wire form
/// `resolve_operator_pubkey` / `collect_trust_anchors` use).
fn operator_pubkey_b64() -> String {
    let sk = SigningKey::from_bytes(&FIXTURE_OPERATOR_SEED);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes())
}

fn scratch_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2030-conformance")
}

fn fresh_db(tag: &str) -> Connection {
    let root = scratch_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    drop(ai_memory::db::open(&path).expect("init db"));
    std::mem::forget(dir); // keep the file alive for the connection's lifetime
    ai_memory::db::open(&path).expect("open db")
}

/// A fully-populated durable memory — the L1 source-of-truth TEXT lane. Fixed
/// id + timestamps + claim-bitemporal bounds so `cid` re-derives deterministically.
fn durable_memory() -> Memory {
    Memory {
        id: SEED_MEMORY_ID.into(),
        namespace: "portability".into(),
        title: "durable title".into(),
        content: "the durable source-of-truth text that must round-trip losslessly".into(),
        tags: vec!["alpha".into(), "beta".into()],
        priority: 7,
        confidence: 0.9,
        // Pre-ship 3x7 HIGH-2: must be a `validate::VALID_SOURCES` member —
        // the v2 importer now runs the L1-parity `validate_memory` gate, and
        // the historical `"test"` value was only importable because the v2
        // route ran zero validation.
        source: "system".into(),
        created_at: FIXED_TS.into(),
        updated_at: FIXED_TS.into(),
        // Keep the golden durable across wall-clock time. Relying on the Mid
        // tier's seven-day default made this fixture disappear after
        // 2026-07-21 UTC even though every encoded timestamp is intentionally
        // fixed for byte stability.
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        memory_kind: MemoryKind::Decision,
        metadata: serde_json::json!({ "agent_id": "alice" }),
        valid_from: Some("2026-01-01T00:00:00Z".into()),
        valid_until: Some("2027-01-01T00:00:00Z".into()),
        ..Memory::default()
    }
}

/// Seed one row in every record class the v2 exporter carries — all with FIXED
/// identifiers + timestamps so the serialized envelope is byte-stable.
fn seed_all_classes(conn: &Connection) {
    // memories — the durable source-of-truth TEXT lane (L1).
    ai_memory::db::insert(conn, &durable_memory()).expect("insert durable memory");

    // signed_events — a real hash-linked V-4 chain (L2). Fixed ids + payloads →
    // deterministic `prev_hash`/`sequence`.
    for i in 0..4 {
        let ev = SignedEvent {
            id: format!("evt-{i}"),
            agent_id: "alice".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(format!("p{i}").as_bytes()),
            attest_level: "unsigned".into(),
            timestamp: FIXED_TS.into(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append signed_event");
    }

    // memory_revisions — an append-only leaf (L2 spine).
    let leaf = RevisionLeaf::new(
        "rev-1",
        "mem-1",
        RecordKind::Supersede,
        Some(1),
        "ns",
        Some("alice".into()),
        FIXED_TS,
    );
    append_revision_leaf(conn, &leaf).expect("append revision leaf");

    // forget_tombstones — a signed erasure receipt (L2). Raw insert for the fixture.
    conn.execute(
        "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            "mem-forgotten",
            "ns",
            FIXED_TS,
            Some("alice"),
            Some(vec![0x11_u8; 64])
        ],
    )
    .expect("insert tombstone");

    // model_attestations — a loader-observed TOFU record (L2). RAW insert with a
    // FIXED id + created_at: the production `record_loader_observed` helper mints
    // a fresh `uuid` + `Utc::now()`, which would make the golden nondeterministic.
    conn.execute(
        "INSERT INTO model_attestations \
             (id, provider, model_ref, model_digest, model_family, \
              attest_level, agent_id, signature, created_at) \
         VALUES (?1, ?2, ?3, NULL, ?4, ?5, '', NULL, ?6)",
        params![
            "ma-1",
            "openrouter",
            "google/gemma-4-31b",
            "gemma",
            model_attest::ATTEST_LEVEL_LOADER_OBSERVED,
            FIXED_TS,
        ],
    )
    .expect("insert model attestation");

    // governance_rules — an unsigned policy rule (L3). Unsigned rules round-trip
    // as-is (verify-or-drop only fires on a present-but-invalid signature).
    rules_store::insert(
        conn,
        &Rule {
            id: "R-1".into(),
            kind: "namespace_deny".into(),
            matcher: "secret/*".into(),
            severity: "refuse".into(),
            reason: "no secrets".into(),
            namespace: "*".into(),
            created_by: "op".into(),
            created_at: 1_700_000_000,
            enabled: true,
            signature: None,
            attest_level: "unsigned".into(),
        },
    )
    .expect("insert governance rule");
}

/// Build the fixture envelope from the PINNED production exporter under a
/// controlled, environment-independent env: the FIXED test operator PUBLIC key
/// is enrolled (→ L3), every other role pubkey is scrubbed, and the key dirs
/// point at an empty temp dir — so the emitted bytes reproduce identically on
/// any host/CI environment regardless of ambient key enrolment.
fn build_fixture_envelope() -> emit::ExportEnvelope {
    let src = fresh_db("src-");
    seed_all_classes(&src);

    let empty = scratch_root().join("empty-keys");
    std::fs::create_dir_all(&empty).ok();
    let empty_str = empty.to_string_lossy().into_owned();
    let op = operator_pubkey_b64();

    // Serialized via the crate-canonical `ENV_LOCK` inside `MultiEnvVarGuard`.
    let _env = MultiEnvVarGuard::apply(&[
        ("AI_MEMORY_OPERATOR_PUBKEY", Some(op.as_str())),
        ("AI_MEMORY_RECORDER_PUBKEY", None),
        ("AI_MEMORY_JUDGE_PUBKEY", None),
        ("AI_MEMORY_STOPPER_PUBKEY", None),
        ("AI_MEMORY_WITNESS_PUBKEY", None),
        ("AI_MEMORY_KEY_DIR", Some(empty_str.as_str())),
        ("AI_MEMORY_WITNESS_KEY_DIR", Some(empty_str.as_str())),
    ]);
    emit::build_full_envelope(&src, FIXTURE_SOURCE, FIXED_TS).expect("build full v2 envelope")
}

/// Pretty JSON + trailing newline, matching the committed golden.
fn envelope_json(env: &emit::ExportEnvelope) -> String {
    let mut s = serde_json::to_string_pretty(env).expect("serialize envelope");
    s.push('\n');
    s
}

/// The drift gate: the committed golden MUST equal a fresh regeneration from the
/// pinned exporter. Under `AI_MEMORY_REGEN_GOLDEN=1` it rewrites the golden.
#[test]
fn fixture_matches_pinned_exporter() {
    ensure_fixed_node_identity();
    let env = build_fixture_envelope();
    let text = envelope_json(&env);
    let path = fixture_path();

    if std::env::var(REGEN_ENV).is_ok() {
        std::fs::create_dir_all(path.parent().expect("fixture path has a parent"))
            .expect("create fixture dir");
        std::fs::write(&path, &text).expect("write fixture");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing conformance fixture {}: {e}. Regenerate with `{REGEN_ENV}=1 cargo test \
             --test conformance_export_roundtrip_2030` and commit {FIXTURE_REL}.",
            path.display()
        )
    });
    assert_eq!(
        text, committed,
        "conformance export fixture drifted from the pinned exporter. If this is a DELIBERATE, \
         spec-approved change (e.g. a schema bump), regenerate with `{REGEN_ENV}=1 cargo test \
         --test conformance_export_roundtrip_2030` and commit {FIXTURE_REL}.",
    );

    // The fixture is the L1/L2/L3 envelope — assert the computed markers.
    assert_eq!(env.spec_version, "2", "spec_version stamp");
    assert_eq!(
        env.conformance_level, "L3",
        "the fixture is the L1/L2/L3 envelope (clean chain + operator anchor); by_class={:?}",
        env.conformance_by_class
    );
    assert!(env.portability_complete, "L3 ⇒ portability_complete");
    assert!(
        env.trust_anchors.iter().any(|a| a.role == "operator"),
        "the operator PUBLIC trust anchor rides the L3 envelope"
    );
    assert!(
        !env.trust_anchors.iter().any(|a| a.pubkey_b64.is_empty()),
        "trust anchors carry public keys, never empty/private material"
    );
}

/// Read the COMMITTED golden and round-trip it through the PRODUCTION importer,
/// asserting byte-exact preservation of the signed spine (L2) + the
/// source-of-truth memory TEXT (L1) + governance (L3), per spec §V2-1 / §V2-6.
#[test]
fn committed_fixture_round_trips_through_production_importer() {
    ensure_fixed_node_identity();
    let path = fixture_path();
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing conformance fixture {}: {e}. Regenerate with `{REGEN_ENV}=1 cargo test \
             --test conformance_export_roundtrip_2030`.",
            path.display()
        )
    });
    let fixture: emit::ExportEnvelope =
        serde_json::from_str(&committed).expect("deserialize committed fixture");

    // Committed markers (spec §V2-1 conformance levels).
    assert_eq!(fixture.spec_version, "2");
    assert_eq!(fixture.conformance_level, "L3");
    assert!(fixture.portability_complete);
    assert!(
        !fixture.trust_anchors.is_empty(),
        "L3 carries the operator trust anchor"
    );

    // Round-trip through the FAIL-CLOSED, ALL-OR-NOTHING production importer.
    // `trust_source: true` is the operator-trusted-backup posture (#2211) that
    // preserves `metadata.agent_id` verbatim so the identity round-trip is exact.
    let dst = fresh_db("dst-");
    let report = import::import_full_envelope(
        &dst,
        &fixture,
        &import::ImportOptions {
            trust_source: true,
            caller_agent_id: "importer".into(),
            ..import::ImportOptions::default()
        },
    )
    .expect("import committed fixture");

    // Every class landed inside the one committed transaction.
    assert!(report.committed, "the fail-closed import committed");
    assert!(
        report.reverify_chain_ok,
        "the imported signed audit spine re-verifies at the destination (L2)"
    );
    assert!(
        report.reverify_revisions_ok,
        "the imported memory_revisions spine re-verifies (L2)"
    );
    assert_eq!(report.memories, 1, "memories count");
    assert_eq!(report.signed_events, 4, "signed_events count");
    assert_eq!(report.memory_revisions, 1, "memory_revisions count");
    assert_eq!(report.forget_tombstones, 1, "forget_tombstones count");
    assert_eq!(report.model_attestations, 1, "model_attestations count");
    assert_eq!(report.governance_rules, 1, "governance_rules count");
    assert_eq!(report.governance_rejected, 0, "no rule dropped");
    assert_eq!(
        report.trust_anchors_seen,
        fixture.trust_anchors.len(),
        "trust anchors seen (advisory)"
    );

    // ── L2: every signed class landed BYTE-EXACT (fixture DTO == destination row) ──
    let dst_ev: Vec<SignedEventDto> = list_signed_events(&dst, None, usize::MAX, 0)
        .unwrap()
        .iter()
        .map(SignedEventDto::from)
        .collect();
    assert_eq!(
        dst_ev, fixture.signed_events,
        "signed_events byte-exact (payload_hash/prev_hash/sequence/signature preserved)"
    );

    let dst_rev: Vec<RevisionDto> = read::read_all_memory_revisions(&dst)
        .unwrap()
        .iter()
        .map(RevisionDto::from)
        .collect();
    assert_eq!(
        dst_rev, fixture.memory_revisions,
        "memory_revisions byte-exact"
    );

    let dst_tomb: Vec<ForgetTombstoneDto> = read::read_all_forget_tombstones(&dst)
        .unwrap()
        .iter()
        .map(ForgetTombstoneDto::from)
        .collect();
    assert_eq!(
        dst_tomb, fixture.forget_tombstones,
        "forget_tombstones byte-exact"
    );

    let dst_ma: Vec<ModelAttestationDto> = model_attest::list(&dst)
        .unwrap()
        .iter()
        .map(ModelAttestationDto::from)
        .collect();
    assert_eq!(
        dst_ma, fixture.model_attestations,
        "model_attestations byte-exact"
    );

    // ── L3: the governance rule round-trips ──
    let dst_rules: Vec<GovernanceRuleDto> = rules_store::list(&dst)
        .unwrap()
        .iter()
        .map(GovernanceRuleDto::from)
        .collect();
    assert_eq!(
        dst_rules, fixture.governance_rules,
        "governance_rules round-trip"
    );

    // ── L1: the source-of-truth memory TEXT round-trips losslessly ──
    let dst_mem = ai_memory::db::get(&dst, SEED_MEMORY_ID)
        .unwrap()
        .expect("dst memory present");
    let src_mem = &fixture.memories[0];
    assert_eq!(
        dst_mem.id, src_mem.id,
        "id preserved verbatim (uuid authority)"
    );
    assert_eq!(dst_mem.title, src_mem.title, "title preserved");
    assert_eq!(dst_mem.content, src_mem.content, "content preserved");
    assert_eq!(dst_mem.namespace, src_mem.namespace, "namespace preserved");
    assert_eq!(dst_mem.tags, src_mem.tags, "tags preserved");
    assert_eq!(dst_mem.priority, src_mem.priority, "priority preserved");
    assert_eq!(dst_mem.memory_kind, src_mem.memory_kind, "kind preserved");
    assert_eq!(
        dst_mem.created_at, src_mem.created_at,
        "created_at preserved"
    );
    assert_eq!(
        dst_mem.metadata["agent_id"], src_mem.metadata["agent_id"],
        "agent_id preserved verbatim under trust_source"
    );
    // #1834 claim-bitemporal VALID-time bounds are durable truth — must survive.
    assert_eq!(
        dst_mem.valid_from, src_mem.valid_from,
        "valid_from preserved"
    );
    assert!(src_mem.valid_from.is_some(), "fixture carries valid_from");
    assert_eq!(
        dst_mem.valid_until, src_mem.valid_until,
        "valid_until preserved"
    );
    assert!(src_mem.valid_until.is_some(), "fixture carries valid_until");
    // #1825 cid: content-addressed, DETERMINISTICALLY re-derived on import.
    assert!(src_mem.cid.is_some(), "fixture memory stamped a cid");
    assert_eq!(
        dst_mem.cid, src_mem.cid,
        "cid re-derives byte-identically on import"
    );
}
