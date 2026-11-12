// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4121 — `ai-memory doctor`'s LLM and embeddings reachability probes pass
//! inference-egress admission (and the internal-only endpoint pin) BEFORE any
//! connection is opened and before the API key is attached.
//!
//! Class invariant (Class B of the #4600/#4121/#4122 PR): every outbound
//! inference request — including a diagnostic probe — is admitted by
//! `crate::egress::admit_inference_target` under the operator's
//! `AI_MEMORY_INFERENCE_EGRESS` posture. A refused posture opens ZERO
//! connections, sends no key byte, and says so with an exact note.
//!
//! The matrix is every doctor probe x every posture. The endpoint is a raw
//! recording listener (`tests/common/recording_listener.rs`) that counts TCP
//! accepts, so a connect that never completes a request still counts.
//!
//! Red on the carrier: both probes built their own `reqwest::blocking`
//! client with no admission, so the `deny` cells saw a connection carrying
//! `Authorization: Bearer <key>`.
//!
//! Round 1 (PR #9175): a refused probe appends the signed refusal row
//! (C-L5), the admitted client follows no redirect (S-L6), and a local
//! embed lane is not probed at all (C-L6).

#![cfg(unix)]

#[path = "common/recording_listener.rs"]
mod recording_listener;

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use recording_listener::{RecordingListener, http_json_response};

/// Obvious fixture key; must never reach the endpoint under a refusal.
const API_KEY: &str = "doctor-probe-fixture-key-4121";
const POSTURE_VAR: &str = "AI_MEMORY_INFERENCE_EGRESS";
/// TEST-NET-1 (RFC 5737): never routed, never internal, never loopback.
const OFFHOST_HTTPS: &str = "https://192.0.2.1:9/v1";
const OFFHOST_HTTP: &str = "http://192.0.2.1:9/v1";
/// A refusal is decided before any connect, so it is fast; an un-gated probe
/// against TEST-NET-1 would sit in its 5 s connect timeout.
const REFUSAL_WALL_CEILING: Duration = Duration::from_secs(4);
const DOCTOR_CHILD_BUDGET: Duration = Duration::from_secs(120);
const DOCTOR_CHILD_POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug)]
enum Probe {
    Llm,
    Embeddings,
}

impl Probe {
    fn section(self) -> &'static str {
        match self {
            Probe::Llm => "LLM Reachability (#1146)",
            Probe::Embeddings => "Embeddings Reachability (#1598)",
        }
    }
    /// The noun the refusal note names.
    fn noun(self) -> &'static str {
        match self {
            Probe::Llm => "LLM",
            Probe::Embeddings => "embeddings",
        }
    }
    fn env_prefix(self) -> &'static str {
        match self {
            Probe::Llm => "AI_MEMORY_LLM",
            Probe::Embeddings => "AI_MEMORY_EMBED",
        }
    }
    /// The 200 body the probe accepts.
    fn ok_body(self) -> String {
        match self {
            Probe::Llm => r#"{"object":"list","data":[{"id":"fixture-model"}]}"#.to_string(),
            Probe::Embeddings => r#"{"data":[{"embedding":[0.5,0.5,0.5,0.5]}]}"#.to_string(),
        }
    }
}

const PROBES: [Probe; 2] = [Probe::Llm, Probe::Embeddings];

fn scratch(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("doctor-egress-4121-{tag}-"))
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("scratch dir under CARGO_TARGET_TMPDIR");
    let db = dir.path().join("doctor.db");
    // `doctor` is read-only and refuses a missing database; `stats` creates it.
    let seeded = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .current_dir(dir.path())
        .arg("--db")
        .arg(&db)
        .arg("stats")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", dir.path())
        .output()
        .expect("seed doctor db");
    assert!(
        seeded.status.success(),
        "seed db: {}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    (dir, db)
}

/// Run `ai-memory --db <db> doctor --json` with exactly one inference lane
/// (`probe`) pointed at `base_url` under `posture` (`None` = unset = allow).
fn run_doctor(
    dir: &Path,
    db: &Path,
    probe: Probe,
    base_url: &str,
    posture: Option<&str>,
) -> Output {
    let pre = probe.env_prefix();
    let lane = [
        (format!("{pre}_BACKEND"), "openai-compatible".to_string()),
        (format!("{pre}_BASE_URL"), base_url.to_string()),
        (format!("{pre}_API_KEY"), API_KEY.to_string()),
        (format!("{pre}_MODEL"), "fixture-model".to_string()),
    ];
    spawn_doctor(dir, db, &lane, posture)
}

/// Run `doctor --json` with every inference lane variable cleared, then
/// `lane` set, under `posture`.
fn spawn_doctor(dir: &Path, db: &Path, lane: &[(String, String)], posture: Option<&str>) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .arg("--db")
        .arg(db)
        .args(["doctor", "--json"])
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for p in PROBES {
        for k in ["BACKEND", "BASE_URL", "API_KEY", "MODEL"] {
            cmd.env_remove(format!("{}_{k}", p.env_prefix()));
        }
    }
    for (k, v) in lane {
        cmd.env(k, v);
    }
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(var);
    }
    match posture {
        Some(p) => cmd.env(POSTURE_VAR, p),
        None => cmd.env_remove(POSTURE_VAR),
    };
    let mut child = cmd.spawn().expect("spawn ai-memory doctor");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("poll doctor child").is_some() {
            break;
        }
        if started.elapsed() > DOCTOR_CHILD_BUDGET {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(DOCTOR_CHILD_POLL);
    }
    child.wait_with_output().expect("collect doctor output")
}

fn section(output: &Output, probe: Probe) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "doctor --json must print JSON ({e}); stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    v["sections"]
        .as_array()
        .expect("sections array")
        .iter()
        .find(|s| s["name"] == probe.section())
        .cloned()
        .unwrap_or_else(|| panic!("section {} missing", probe.section()))
}

fn fact(s: &serde_json::Value, key: &str) -> Option<String> {
    s["facts"]
        .as_array()?
        .iter()
        .find(|f| f[0] == key)
        .and_then(|f| f[1].as_str().map(str::to_string))
}

/// The exact refusal note the probe must emit.
fn expected_note(probe: Probe, origin: &str, mode: &str, reason: &str) -> String {
    format!(
        "probe NOT sent (#4121): inference-plane egress refused the {} target {origin} under \
         {POSTURE_VAR}={mode}; no connection was opened and no API key left the process. {reason}",
        probe.noun()
    )
}

fn assert_refused(output: &Output, probe: Probe, mode: &str) {
    let s = section(output, probe);
    let reason = fact(&s, "inference_egress")
        .unwrap_or_else(|| panic!("#4121 {probe:?}/{mode}: inference_egress fact missing: {s}"));
    assert_eq!(
        fact(&s, "inference_egress_mode").as_deref(),
        Some(mode),
        "#4121 {probe:?}/{mode}: posture fact: {s}"
    );
    let origin = fact(&s, "base_url").expect("base_url fact");
    assert_eq!(
        s["note"].as_str(),
        Some(expected_note(probe, &origin, mode, &reason).as_str()),
        "#4121 {probe:?}/{mode}: exact refusal note"
    );
    assert_eq!(s["severity"], "warning", "#4121 {probe:?}/{mode}: {s}");
    assert!(
        fact(&s, "http_status").is_none(),
        "#4121 {probe:?}/{mode}: a refused probe has no HTTP status: {s}"
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains(API_KEY),
        "#4121: the key must never be printed"
    );
}

// ─── refused postures: ZERO connections, no key bytes ──────────────────────

#[test]
fn deny_posture_refuses_every_probe_with_zero_connections_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("deny");
        let out = run_doctor(dir.path(), &db, probe, &listener.url(), Some("deny"));
        assert_refused(&out, probe, "deny");
        assert_eq!(
            listener.connections(),
            0,
            "#4121 {probe:?}/deny: the endpoint must see ZERO connections"
        );
        assert!(
            !listener.saw_bytes(API_KEY.as_bytes()),
            "#4121 {probe:?}/deny: no API-key byte may reach the endpoint"
        );
    }
}

#[test]
fn unrecognised_posture_fails_closed_to_deny_for_every_probe_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("typo");
        let out = run_doctor(dir.path(), &db, probe, &listener.url(), Some("deny-all"));
        assert_refused(&out, probe, "deny");
        assert_eq!(listener.connections(), 0, "#4121 {probe:?}/typo");
    }
}

#[test]
fn loopback_only_refuses_an_offhost_target_before_any_connect_4121() {
    for probe in PROBES {
        let (dir, db) = scratch("loopback-only");
        let started = Instant::now();
        let out = run_doctor(dir.path(), &db, probe, OFFHOST_HTTPS, Some("loopback-only"));
        let elapsed = started.elapsed();
        assert_refused(&out, probe, "loopback-only");
        assert!(
            elapsed < REFUSAL_WALL_CEILING,
            "#4121 {probe:?}/loopback-only: refusal must precede any connect ({elapsed:?})"
        );
    }
}

#[test]
fn internal_only_refuses_offhost_plaintext_before_any_connect_4121() {
    for probe in PROBES {
        let (dir, db) = scratch("internal-only-offhost");
        let started = Instant::now();
        let out = run_doctor(dir.path(), &db, probe, OFFHOST_HTTP, Some("internal-only"));
        let elapsed = started.elapsed();
        assert_refused(&out, probe, "internal-only");
        assert!(
            elapsed < REFUSAL_WALL_CEILING,
            "#4121 {probe:?}/internal-only: refusal must precede any connect ({elapsed:?})"
        );
    }
}

// ─── admitted postures: the probe still reaches the endpoint ───────────────

fn assert_probed(out: &Output, listener: &RecordingListener, probe: Probe, label: &str) {
    let s = section(out, probe);
    assert_eq!(
        fact(&s, "http_status").as_deref(),
        Some("200"),
        "#4121 {probe:?}/{label}: the admitted probe reaches the endpoint: {s}"
    );
    assert!(
        fact(&s, "inference_egress").is_none(),
        "#4121 {probe:?}/{label}: no refusal fact on an admitted probe: {s}"
    );
    assert!(listener.connections() >= 1, "#4121 {probe:?}/{label}");
}

#[test]
fn allow_control_probes_every_endpoint_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("allow");
        let out = run_doctor(dir.path(), &db, probe, &listener.url(), None);
        assert_probed(&out, &listener, probe, "allow");
    }
}

#[test]
fn internal_only_admits_and_pins_a_loopback_endpoint_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("internal-only");
        let out = run_doctor(
            dir.path(),
            &db,
            probe,
            &listener.url(),
            Some("internal-only"),
        );
        assert_probed(&out, &listener, probe, "internal-only");
    }
}

#[test]
fn loopback_only_admits_a_loopback_endpoint_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("loopback-only-ok");
        let out = run_doctor(
            dir.path(),
            &db,
            probe,
            &listener.url(),
            Some("loopback-only"),
        );
        assert_probed(&out, &listener, probe, "loopback-only");
    }
}

// ─── structural: no probe builds a client around the gate ──────────────────

/// The body of top-level `fn <name>(` in `src`, up to its closing `}` line.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found in doctor.rs"));
    let rest = &src[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 3);
    &rest[..end]
}

/// Neither inference reachability probe builds its own HTTP client: both go
/// through the admission funnel `crate::egress::admitted_blocking_client`.
/// (`http_get_json`, the `doctor --remote` fetch of the operator's own
/// daemon, is not an inference lane and keeps its own transport.)
#[test]
fn doctor_builds_no_inference_client_around_the_gate_4121() {
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/doctor.rs"))
            .expect("read doctor.rs");
    for probe_fn in [
        "section_llm_reachability_from_resolved",
        "section_embeddings_reachability_1598",
    ] {
        let body = fn_body(&src, probe_fn);
        assert!(
            !body.contains("Client::builder()"),
            "#4121: {probe_fn} must not build its own inference probe client"
        );
        assert!(
            body.contains("crate::egress::admitted_blocking_client("),
            "#4121: {probe_fn} builds its client through the admission funnel"
        );
    }
}

// ─── #4121 / #4122 r1: audit row, no redirect, local embed lane ────────────

/// `signed_events` rows of the inference-egress refusal type in `db`.
fn refusal_rows(db: &Path) -> i64 {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open doctor db read-only");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
        |r| r.get(0),
    )
    .expect("count refusal rows")
}

/// C-L5: a refused probe appends exactly one signed refusal row (the record
/// boot and `reembed` append); an admitted probe appends none.
#[test]
fn refused_probe_appends_one_signed_refusal_row_4121() {
    for probe in PROBES {
        let listener = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let (dir, db) = scratch("audit-deny");
        assert_eq!(
            refusal_rows(&db),
            0,
            "#4121 {probe:?}: seeded db has no refusal row"
        );
        let out = run_doctor(dir.path(), &db, probe, &listener.url(), Some("deny"));
        assert_refused(&out, probe, "deny");
        assert_eq!(
            refusal_rows(&db),
            1,
            "#4121 {probe:?}/deny: one signed refusal row per refused probe"
        );
        let (dir, db) = scratch("audit-allow");
        let out = run_doctor(dir.path(), &db, probe, &listener.url(), None);
        assert_probed(&out, &listener, probe, "allow");
        assert_eq!(
            refusal_rows(&db),
            0,
            "#4121 {probe:?}/allow: no refusal row"
        );
    }
}

/// A `302 Found` pointing at `target` with an empty body.
fn http_redirect_response(target: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {target}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// S-L6: the admitted client never follows a redirect, so an admitted
/// endpoint cannot bounce the probe (or its key) to a second host.
#[test]
fn admitted_probe_never_follows_a_redirect_4121() {
    for probe in PROBES {
        let second = RecordingListener::start(Some(http_json_response(&probe.ok_body())));
        let first = RecordingListener::start(Some(http_redirect_response(&format!(
            "{}/v1/bounced",
            second.url()
        ))));
        let (dir, db) = scratch("redirect");
        let out = run_doctor(dir.path(), &db, probe, &first.url(), None);
        let s = section(&out, probe);
        assert_eq!(
            fact(&s, "http_status").as_deref(),
            Some("302"),
            "#4121 {probe:?}: the probe reports the redirect it did not follow: {s}"
        );
        assert!(
            first.connections() >= 1,
            "#4121 {probe:?}: first endpoint probed"
        );
        assert_eq!(
            second.connections(),
            0,
            "#4121 {probe:?}: the redirect target must see ZERO connections"
        );
    }
}

/// C-L6 (a): an `ollama` backend on the semantic tier embeds in process
/// (local `MiniLM`), so the embed lane opens no socket (#3933). The probe is
/// not needed under any posture: no refusal, no connection, `embed_lane`
/// fact `local`.
#[test]
fn local_embed_lane_is_not_probed_under_any_posture_4121() {
    for posture in [Some("deny"), None] {
        let listener =
            RecordingListener::start(Some(http_json_response(&Probe::Embeddings.ok_body())));
        let (dir, db) = scratch("local-lane");
        let lane = [
            ("AI_MEMORY_EMBED_BACKEND".to_string(), "ollama".to_string()),
            ("AI_MEMORY_EMBED_BASE_URL".to_string(), listener.url()),
        ];
        let out = spawn_doctor(dir.path(), &db, &lane, posture);
        let s = section(&out, Probe::Embeddings);
        assert_eq!(
            fact(&s, "embed_lane").as_deref(),
            Some("local"),
            "#4121 {posture:?}: local lane fact: {s}"
        );
        assert!(
            fact(&s, "inference_egress").is_none(),
            "#4121 {posture:?}: a local lane is never refused: {s}"
        );
        // The section may append the host-dependent #1598 GPU-policy note
        // after "; ", so the lane note is pinned exactly as the leading part.
        let note = s["note"].as_str().unwrap_or_default();
        assert_eq!(
            note.split("; embeddings backend").next(),
            Some(
                "probe not needed: the embed lane is the local in-process embedder, which opens \
                 no network connection (#3933); nothing was sent"
            ),
            "#4121 {posture:?}: exact note: {note}"
        );
        assert_eq!(
            listener.connections(),
            0,
            "#4121 {posture:?}: no connection"
        );
        assert_eq!(refusal_rows(&db), 0, "#4121 {posture:?}: no refusal row");
    }
}
