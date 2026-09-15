// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3667 re-implemented in the #3711 idiom (the Conductor's design ruling on
//! #3330): every site #3667 wrapped in a userinfo MASKER now renders through
//! the ALLOWLIST renderer (`url_display::url_origin` / `url_origin_and_path`
//! / `store_url_display`). A masker is a denylist and can only hide the
//! credential shapes its author enumerated; the renderer shows scheme, host,
//! port (and a store's database name) and nothing else, so there is no
//! credential shape it can fail to recognise.
//!
//! These pins are the POSITIVE form: the sink must still NAME THE ENDPOINT an
//! operator needs (`scheme://host:port`), and must not carry the userinfo,
//! the query or the path token. An absence-only assertion would be satisfied
//! by an empty sink; the presence half is what makes it a rendering pin.
//!
//! Covered here (binary, hermetic HOME, closed loopback port so nothing is
//! ever dialled):
//! * `doctor` (text and `--json`) with a credentialed `[llm].base_url`
//!   (`AI_MEMORY_LLM_BASE_URL`): the `base_url` and `probe_url` facts render
//!   the origin (#3667's "provider" case, previously a report-wide masker).
//! * `doctor --db <postgres url>`: the URL-shaped `--db` refusal renders the
//!   store URL from the allowlist (#3667's "url-shaped db" case).
//!
//! The federation peer refusals, the sync-daemon boot line and the config
//! display are pinned as unit tests beside their sites (`federation::peer`,
//! `config_redact`, `store_url`).

use std::path::Path;

use tempfile::TempDir;

const USERINFO_PW: &str = "AUTH_CANARY_3667";
const QUERY_PW: &str = "QUERY_CANARY_3667";
const SECOND_PW: &str = "SECOND_CANARY_3667";
const SECRETS: [&str; 3] = [USERINFO_PW, QUERY_PW, SECOND_PW];

fn assert_clean(sink: &str, what: &str) {
    for s in SECRETS {
        assert!(!sink.contains(s), "#3667: {s:?} reached {what}:\n{sink}");
    }
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("url-allowlist-render-3667");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn run_bin(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).expect("scratch keys");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "trace");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn ai-memory");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// #3667 provider case — a credentialed OpenAI-compatible base URL (userinfo
/// password, `%70assword=` and `password=` query keys), pointed at the
/// loopback discard port so the probe fails before any credential could be
/// sent. The doctor's LLM section must still name `https://127.0.0.1:9`
/// (the endpoint the operator needs) in BOTH renderings, and nothing else
/// of the URL — across the WHOLE sink: stdout, stderr and the `--json`
/// document, including the connect-error `error` fact and the note.
///
/// The store is created first (`doctor` is read-only, #3434, and stops at
/// the Storage section when the file does not exist) so the run REACHES the
/// LLM section; a fixture that bails before the section proves nothing.
#[test]
fn doctor_llm_facts_render_the_base_url_from_the_allowlist_3667() {
    let dir = scratch("doctor-llm");
    let db = dir.path().join("d.db");
    let db_s = db.display().to_string();
    let url = format!(
        "https://svc:{USERINFO_PW}@127.0.0.1:9/v1?%70assword={QUERY_PW}&password={SECOND_PW}"
    );
    let (ok, out, err) = run_bin(
        dir.path(),
        &[
            "--db",
            db_s.as_str(),
            "store",
            "-T",
            "seed",
            "--content",
            "one row so doctor has a store to read (#3667)",
        ],
        &[],
    );
    assert!(ok, "seed store must succeed:\n{out}\n{err}");
    assert!(db.is_file(), "the seed created the store");
    for json in [false, true] {
        let mut args = vec!["--db", db_s.as_str(), "doctor"];
        if json {
            args.push("--json");
        }
        let (_ok, out, err) = run_bin(
            dir.path(),
            &args,
            &[
                ("AI_MEMORY_LLM_BASE_URL", url.as_str()),
                ("AI_MEMORY_LLM_BACKEND", "openai-compatible"),
                ("AI_MEMORY_LLM_MODEL", "synthetic-model"),
            ],
        );
        assert!(
            out.contains("LLM Reachability"),
            "doctor must reach the LLM section (json={json}):\n{out}\n{err}"
        );
        // Absence over the WHOLE sink first — both credential shapes, both
        // streams — so a leak fails as a leak, not as a rendering nit.
        assert_clean(&out, "doctor stdout");
        assert_clean(&err, "doctor stderr");
        assert!(
            out.contains("https://127.0.0.1:9"),
            "#3667: the LLM section must NAME the endpoint origin (json={json}):\n{out}"
        );
        if json {
            let parsed: serde_json::Value =
                serde_json::from_str(&out).expect("doctor --json is one JSON document");
            let facts = parsed.to_string();
            // The probe is `<base_url>/models` (the client's own join); a
            // base URL carrying a query puts `/models` after it, so the
            // allowlist rendering is the origin + the base path.
            assert!(
                facts.contains("\"probe_url\"") && facts.contains("https://127.0.0.1:9/v1"),
                "#3667: probe_url renders origin + path only:\n{facts}"
            );
            assert!(
                facts.contains("\"error\"") && facts.contains("network"),
                "the connect failure is reported as a classified fact:\n{facts}"
            );
            assert_clean(&facts, "doctor --json document");
        } else {
            assert!(
                out.contains("error contacting https://127.0.0.1:9/v1"),
                "the note names the probe from the allowlist:\n{out}"
            );
        }
    }
}

/// #3667 url-shaped db case — a Postgres URL handed to `--db` (which binds a
/// SQLite path) is refused; the refusal renders the store URL from the
/// allowlist (`postgres://127.0.0.1:9/m`) so the operator sees what they
/// typed where, and never the credential.
#[test]
fn url_shaped_db_refusal_renders_the_store_url_from_the_allowlist_3667() {
    let dir = scratch("db-url");
    let url = format!(
        "postgres://u:{USERINFO_PW}@127.0.0.1:9/m?%70assword={QUERY_PW}&password={SECOND_PW}"
    );
    let (ok, out, err) = run_bin(dir.path(), &["--db", url.as_str(), "doctor", "--json"], &[]);
    assert!(!ok, "a URL-shaped --db must be refused:\n{out}\n{err}");
    assert!(
        err.contains("postgres://127.0.0.1:9/m"),
        "#3667: the refusal must NAME the store from the allowlist:\n{err}"
    );
    assert_clean(&out, "refusal stdout");
    assert_clean(&err, "refusal stderr");
}
