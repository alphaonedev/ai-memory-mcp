// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3457 (security-high, v1.0.0) — `ai-memory sync --direction pull|merge` must
//! not land a wire-asserted attestation the destination cannot verify.
//!
//! Both inbound legs re-owned each remote row to the caller
//! (`restamp_agent_id` rewrites `metadata.agent_id`) while carrying the remote
//! row's `metadata.attest_level` and `metadata.write_signature` through
//! VERBATIM into the local store. The signed `SignableWrite` envelope commits
//! to `agent_id`, so after the re-own that signature can never be re-derived
//! from the row it now describes — a durable `agent_attested` no principal ever
//! minted, which `row_is_agent_attested`, the federation relay under
//! `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1` and the attestation census all believed.
//!
//! `--trust-source` was never a mitigation: it preserves the ORIGINAL owner
//! rather than re-owning, but neither branch verified the presented signature
//! against a destination-enrolled key, so a wire-asserted `agent_attested` was
//! taken on faith either way. Post-fix, `--trust-source` skips the
//! re-attribution rule and the signature is ACTUALLY VERIFIED — strictly more
//! than the pre-#3457 behaviour, which is what
//! `trust_source_still_verifies_the_signature_3457` pins.
//!
//! `cli::sync` is the FOURTH ingestion funnel; the fix is a call into the one
//! shared decision `identity::attest::reconcile_imported_attestation` (#3421)
//! that the portability v2 route, the CLI L1 route (#2264) and
//! `POST /api/v1/import` already make — not a fourth hand-rolled copy.
//!
//! The sync command is sqlite-to-sqlite by construction (`--remote-db` is a
//! second sqlite FILE, and the local leg REFUSES to run on a postgres
//! deployment — `cli::backup::refuse_pg_store`, #2572), so there is no postgres
//! lane on this surface to exercise. "Both backends" is therefore satisfied by
//! the sqlite lane here plus the postgres-lane coverage the shared funnel
//! already carries in `tests/import_attestation_3421.rs`. The pg REFUSAL itself
//! is not re-pinned here: `refuse_pg_store` is `pub(crate)` and so unreachable
//! from an integration test, and it is already asserted in-crate by
//! `cli::backup::refuse_pg_store_typed_refusal_on_postgres_url_2572` (typed
//! refusal on a `postgres://` store URL, byte-transparent pass-through
//! otherwise). Duplicating it here would add no coverage.

use ai_memory::cli::CliOutput;
use ai_memory::cli::sync::{SyncArgs, run};
use ai_memory::identity::verify::AttestLevel;
use ai_memory::models::field_names;
use ai_memory::{db, models};
use serde_json::{Value, json};
use std::path::PathBuf;

const CALLER: &str = "ai:local@node";
const OUTSIDER: &str = "ai:victim@elsewhere";
const NS: &str = "sync3457";

struct Env {
    // Held only to keep the temp dir alive for the test's duration (the same
    // `#[allow(dead_code)]` shape `tests/cli_sync_coverage.rs` uses).
    #[allow(dead_code)]
    tmp: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Env {
    fn fresh() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let local = tmp.path().join("local.db");
        let remote = tmp.path().join("remote.db");
        let _ = db::open(&local).expect("open local");
        let _ = db::open(&remote).expect("open remote");
        Self {
            tmp,
            local,
            remote,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
    fn output(&mut self) -> CliOutput<'_> {
        CliOutput::from_std(&mut self.stdout, &mut self.stderr)
    }
    fn stdout_json(&self) -> Value {
        let s = std::str::from_utf8(&self.stdout).expect("utf-8");
        serde_json::from_str(s.trim()).unwrap_or(Value::Null)
    }
}

fn fixture(id: &str, title: &str, author: &str) -> models::Memory {
    // #3422 — the CANONICAL storage-stable stamp. `Utc::now().to_rfc3339()`
    // renders NANOSECONDS on Linux, and `sign_memory_write` refuses to mint a
    // signature over a `created_at` postgres `TIMESTAMPTZ` could not return
    // byte-for-byte — so a naive `now()` fixture cannot even be signed.
    let now = ai_memory::identity::attest::now_attestable_rfc3339();
    models::Memory {
        id: id.to_string(),
        tier: models::Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "the remote body".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": author }),
        ..models::Memory::default()
    }
}

/// Seed a row into the REMOTE database with whatever metadata the caller wants,
/// bypassing nothing — this is exactly what an attacker-controlled remote db
/// looks like to `sync`.
fn seed_remote(env: &Env, mem: &models::Memory) {
    let conn = db::open(&env.remote).expect("open remote");
    db::insert(&conn, mem).expect("insert remote row");
}

/// Register `agent_id` on the DESTINATION and bind `kp`'s public key, so the
/// funnel has something to verify against. The bind REQUIRES an existing
/// registration row.
fn provision_local(env: &Env, agent_id: &str) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(agent_id).expect("keypair");
    let conn = db::open(&env.local).expect("open local");
    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &[]).expect("register");
    // #3464 — proof of possession; the fixture holds the private half.
    ai_memory::storage::bind_agent_pubkey_with_keypair(&conn, agent_id, &kp).expect("bind");
    kp
}

fn sign_b64(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    mem: &models::Memory,
    agent_id: &str,
) -> String {
    use base64::Engine as _;
    let sig = ai_memory::identity::attest::sign_memory_write(kp, mem, agent_id).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

fn sync(env: &mut Env, direction: &str, trust_source: bool) {
    let args = SyncArgs {
        remote_db: env.remote.clone(),
        direction: direction.to_string(),
        trust_source,
        dry_run: false,
    };
    let local = env.local.clone();
    let mut out = env.output();
    run(&local, &args, true, Some(CALLER), &mut out).expect("sync run");
}

fn local_row(env: &Env, id: &str) -> Option<models::Memory> {
    let conn = db::open(&env.local).expect("open local");
    db::get(&conn, id).expect("db::get")
}

fn level_of(mem: &models::Memory) -> Option<&str> {
    mem.metadata
        .get(field_names::ATTEST_LEVEL)
        .and_then(Value::as_str)
}

fn signature_of(mem: &models::Memory) -> Option<&str> {
    mem.metadata
        .get(field_names::WRITE_SIGNATURE)
        .and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// DENIED — a re-owned row cannot keep the original author's attestation
// ---------------------------------------------------------------------------

fn reowned_lands_claimed(direction: &str) {
    let mut env = Env::fresh();
    // The victim genuinely signed this row under their OWN id — the strongest
    // form: every byte of the signature is real, it simply does not belong to
    // the row once sync re-owns it to the caller.
    let victim = ai_memory::identity::keypair::generate(OUTSIDER).expect("victim keypair");
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "re-owned by sync", OUTSIDER);
    let sig = sign_b64(&victim, &mem, OUTSIDER);
    mem.metadata = json!({
        "agent_id": OUTSIDER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): sig,
        (field_names::AGENT_PUBKEY): victim.public_base64(),
    });
    seed_remote(&env, &mem);

    sync(&mut env, direction, false);

    let row = local_row(&env, &id).expect("row pulled");
    assert_eq!(
        level_of(&row),
        Some(AttestLevel::Claimed.as_str()),
        "a re-owned row must land claimed: {}",
        row.metadata
    );
    assert!(
        signature_of(&row).is_none(),
        "the stale signature must be dropped beside a new owner: {}",
        row.metadata
    );
    assert!(
        row.metadata.get(field_names::AGENT_PUBKEY).is_none(),
        "an unauthenticated wire identity-key claim must never seed the enrolled-key \
         surface: {}",
        row.metadata
    );
    assert_eq!(
        row.metadata
            .get(field_names::IMPORTED_FROM_AGENT_ID)
            .and_then(Value::as_str),
        Some(OUTSIDER),
        "provenance is preserved; only the unverifiable attestation is dropped: {}",
        row.metadata
    );
    let v = env.stdout_json();
    assert_eq!(v["attestation_downgraded"], json!(1), "{v}");
}

#[test]
fn pull_reowned_row_lands_claimed_3457() {
    reowned_lands_claimed("pull");
}

#[test]
fn merge_reowned_row_lands_claimed_3457() {
    reowned_lands_claimed("merge");
}

// ---------------------------------------------------------------------------
// DENIED — a presented-but-FORGED signature skips the row entirely
// ---------------------------------------------------------------------------

fn forged_signature_skips_row(direction: &str) {
    let mut env = Env::fresh();
    // The CALLER is enrolled and the row is already attributed to the caller,
    // so the re-attribution rule does not fire and the signature is actually
    // verified. It was minted by a DIFFERENT key, so it is forged.
    let _caller_kp = provision_local(&env, CALLER);
    let attacker = ai_memory::identity::keypair::generate(CALLER).expect("attacker keypair");
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "forged by remote", CALLER);
    let forged = sign_b64(&attacker, &mem, CALLER);
    mem.metadata = json!({
        "agent_id": CALLER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): forged,
    });
    seed_remote(&env, &mem);

    sync(&mut env, direction, false);

    assert!(
        local_row(&env, &id).is_none(),
        "a forged-signature row must never land — never downgraded into storage"
    );
    let v = env.stdout_json();
    assert_eq!(v["forged_signature_skipped"], json!(1), "{v}");
}

#[test]
fn pull_forged_signature_skips_row_3457() {
    forged_signature_skips_row("pull");
}

#[test]
fn merge_forged_signature_skips_row_3457() {
    forged_signature_skips_row("merge");
}

// ---------------------------------------------------------------------------
// ALLOWED — a genuine, destination-verifiable attestation survives
// ---------------------------------------------------------------------------

fn genuine_self_signed_survives(direction: &str) {
    let mut env = Env::fresh();
    let kp = provision_local(&env, CALLER);
    let id = uuid::Uuid::new_v4().to_string();
    let mut mem = fixture(&id, "genuinely signed by caller", CALLER);
    let sig = sign_b64(&kp, &mem, CALLER);
    mem.metadata = json!({
        "agent_id": CALLER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): sig.clone(),
    });
    seed_remote(&env, &mem);

    sync(&mut env, direction, false);

    let row = local_row(&env, &id).expect("row pulled");
    assert_eq!(
        level_of(&row),
        Some(AttestLevel::AgentAttested.as_str()),
        "a signature the destination CAN verify keeps its attestation: {}",
        row.metadata
    );
    assert_eq!(
        signature_of(&row),
        Some(sig.as_str()),
        "the verified signature is preserved verbatim: {}",
        row.metadata
    );
    let v = env.stdout_json();
    assert_eq!(v["attestation_downgraded"], json!(0), "{v}");
    assert_eq!(v["forged_signature_skipped"], json!(0), "{v}");
}

#[test]
fn pull_genuine_self_signed_survives_3457() {
    genuine_self_signed_survives("pull");
}

#[test]
fn merge_genuine_self_signed_survives_3457() {
    genuine_self_signed_survives("merge");
}

// ---------------------------------------------------------------------------
// ALLOWED — an ordinary unattested row is synced byte-for-byte as before
// ---------------------------------------------------------------------------

#[test]
fn pull_plain_row_is_unchanged_3457() {
    let mut env = Env::fresh();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = fixture(&id, "plain remote row", OUTSIDER);
    seed_remote(&env, &mem);

    sync(&mut env, "pull", false);

    let row = local_row(&env, &id).expect("row pulled");
    assert!(
        level_of(&row).is_none(),
        "a row that asserted nothing must not acquire an attest_level: {}",
        row.metadata
    );
    assert!(signature_of(&row).is_none(), "{}", row.metadata);
    assert_eq!(row.content, "the remote body");
    let v = env.stdout_json();
    assert_eq!(v["imported"], json!(1), "{v}");
    assert_eq!(v["attestation_downgraded"], json!(0), "{v}");
}

// ---------------------------------------------------------------------------
// `--trust-source` is NOT a bypass: the owner is preserved, and the signature
// is then actually VERIFIED (pre-#3457 nothing verified it on either branch).
// ---------------------------------------------------------------------------

#[test]
fn trust_source_still_verifies_the_signature_3457() {
    let mut env = Env::fresh();
    // The OUTSIDER is enrolled on the destination, so under --trust-source the
    // row keeps its owner AND its signature verifies → attestation survives.
    let victim = provision_local(&env, OUTSIDER);
    let good_id = uuid::Uuid::new_v4().to_string();
    let mut good = fixture(&good_id, "trusted and genuine", OUTSIDER);
    let good_sig = sign_b64(&victim, &good, OUTSIDER);
    good.metadata = json!({
        "agent_id": OUTSIDER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): good_sig.clone(),
    });
    seed_remote(&env, &good);

    // ... while a row whose signature is FORGED under the same enrolled author
    // is SKIPPED even though --trust-source was passed.
    let attacker = ai_memory::identity::keypair::generate(OUTSIDER).expect("attacker keypair");
    let bad_id = uuid::Uuid::new_v4().to_string();
    let mut bad = fixture(&bad_id, "trusted but forged", OUTSIDER);
    let bad_sig = sign_b64(&attacker, &bad, OUTSIDER);
    bad.metadata = json!({
        "agent_id": OUTSIDER,
        (field_names::ATTEST_LEVEL): AttestLevel::AgentAttested.as_str(),
        (field_names::WRITE_SIGNATURE): bad_sig,
    });
    seed_remote(&env, &bad);

    sync(&mut env, "pull", true);

    let kept = local_row(&env, &good_id).expect("the genuine row lands");
    assert_eq!(
        level_of(&kept),
        Some(AttestLevel::AgentAttested.as_str()),
        "--trust-source preserves the owner, so a genuine signature still verifies: {}",
        kept.metadata
    );
    assert_eq!(signature_of(&kept), Some(good_sig.as_str()));
    assert!(
        kept.metadata
            .get(field_names::IMPORTED_FROM_AGENT_ID)
            .is_none(),
        "--trust-source does not re-own, so no import provenance is stamped: {}",
        kept.metadata
    );
    assert!(
        local_row(&env, &bad_id).is_none(),
        "--trust-source is NOT a verification bypass: a forged signature is still skipped"
    );
    let v = env.stdout_json();
    assert_eq!(v["forged_signature_skipped"], json!(1), "{v}");
}
