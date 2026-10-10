// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4123 (WP-EGRESS #6053; GOD ruling, 5-agent vote 4d3ea1c5, 5/5 option A)
//! — a restricted `AI_MEMORY_INFERENCE_EGRESS` posture REFUSES the Hugging
//! Face Hub weight downloads of the in-process embedder (`MiniLM`) and the
//! cross-encoder reranker. Those models run cache-only under `loopback-only`
//! / `deny` / `internal-only`, exactly as under `AI_MEMORY_EMBED_OFFLINE`:
//! with no pre-staged cache the embedder fails closed (keyword recall,
//! #1593) and the reranker to lexical, each naming the posture. `allow`, the
//! default, is byte-identical.
//!
//! Before this fix both loaders called `hf_hub::api::sync::Api::new()` with
//! no admission at all: under `deny` — documented as "no inference egress at
//! all" — a cache miss still reached huggingface.co. `Api::new()` also read
//! neither `HF_ENDPOINT` nor `HF_HOME` (only the OFFLINE `MiniLM` loader
//! honoured `HF_HOME`, #3788), so the embedder's online fetch wrote its cache
//! under `$HOME` while its offline resolver read `HF_HOME`. The embedder now
//! builds through `ApiBuilder::from_env()` (the hf-hub documented way); the
//! reranker roots its online cache where ITS offline resolver reads (`$HOME`)
//! and honours `HF_ENDPOINT`. Honouring `HF_ENDPOINT` is also what lets this
//! test point the Hub at a local recorder.
//!
//! Cells (each posture × a recording local "hub" that answers 404, an EMPTY
//! `HF_HOME`, a scratch `HOME`, the offline knobs REMOVED so only the posture
//! can refuse, and no environment proxy):
//!
//! 1. deny / loopback-only / internal-only: the embedder errors naming the
//!    posture, the reranker degrades to lexical, and the recorder receives
//!    ZERO requests.
//! 2. `allow` control: the recorder receives the fetch attempts (the fixture
//!    can see a leak), both loaders fail on the 404s.
//! 3. A pre-staged cache under `deny` still loads: resolution reaches the
//!    staged files with zero requests (the load then fails on the fake
//!    `config.json`, which proves the cache-only path was taken).
//! 4. Structural: neither loader builds through `Api::new()`; each uses the
//!    `ApiBuilder` rooted at the cache its own offline resolver reads.
//!
//! OWN-BINARY on purpose: it mutates `HOME`, `HF_HOME`, `HF_ENDPOINT`, the
//! offline knobs, the posture and the proxy vars — never inside the shared
//! lib test binary (the `tests/hf_cache_staged_3788.rs` and
//! `tests/inference_egress_proxy_redirect_4193.rs` precedents; allowlisted in
//! `scripts/check-test-env-lock.sh`). A file-local mutex serialises the cells.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use ai_memory::embeddings::Embedder;
use ai_memory::reranker::CrossEncoder;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serialises every env-mutating cell in this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII scope: sets the given vars (`None` = unset) and restores the prior
/// values on drop, so a failing assertion cannot leak into a sibling.
struct EnvScope {
    _guard: MutexGuard<'static, ()>,
    prior: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut prior = Vec::with_capacity(vars.len());
        for (name, value) in vars {
            prior.push((*name, std::env::var(name).ok()));
            // SAFETY: serialised by `ENV_LOCK`; this binary's cells are the
            // only readers of these vars (own-binary test, see module doc).
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self {
            _guard: guard,
            prior,
        }
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (name, value) in self.prior.drain(..) {
            // SAFETY: still serialised by the held `ENV_LOCK` guard.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

const POSTURE_VAR: &str = "AI_MEMORY_INFERENCE_EGRESS";
const OFFLINE_KNOBS: [&str; 2] = ["AI_MEMORY_EMBED_OFFLINE", "HF_HUB_OFFLINE"];
const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];
const RESTRICTED: [&str; 3] = ["deny", "loopback-only", "internal-only"];

/// Scratch `HOME` + `HF_HOME` under the cargo target dir (never `/tmp`).
struct Scratch {
    _dir: tempfile::TempDir,
    home: PathBuf,
    hf_home: PathBuf,
}

fn scratch(tag: &str) -> Scratch {
    let target_root = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dir = tempfile::Builder::new()
        .prefix(&format!("hf-posture-4123-{tag}-"))
        .tempdir_in(target_root)
        .expect("scratch dir under the cargo target dir must be creatable");
    let home = dir.path().join("home");
    let hf_home = dir.path().join("hf-home");
    std::fs::create_dir_all(&home).expect("mk home");
    std::fs::create_dir_all(&hf_home).expect("mk hf-home");
    Scratch {
        _dir: dir,
        home,
        hf_home,
    }
}

/// The env table for one cell: the posture (`None` = unset = `allow`), the
/// local "hub", the scratch dirs, the offline knobs REMOVED and every proxy
/// var cleared.
fn cell_env<'a>(
    posture: Option<&'a str>,
    hub: &'a str,
    s: &'a Scratch,
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut vars: Vec<(&'static str, Option<&str>)> = vec![
        (POSTURE_VAR, posture),
        ("HF_ENDPOINT", Some(hub)),
        ("HF_HOME", s.hf_home.to_str()),
        ("HOME", s.home.to_str()),
    ];
    for knob in OFFLINE_KNOBS {
        vars.push((knob, None));
    }
    for var in PROXY_VARS {
        vars.push((var, None));
    }
    vars
}

/// A recording "hub": every request is answered 404, so a loader that
/// reaches it fails (and is counted).
async fn recorder() -> MockServer {
    let hub = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&hub)
        .await;
    hub
}

async fn requests(hub: &MockServer) -> usize {
    hub.received_requests().await.unwrap_or_default().len()
}

/// The full `anyhow` chain, outermost context first.
fn chain(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

// ─── 1. restricted postures: zero requests, the posture is named ─────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restricted_postures_refuse_the_hub_fetch_naming_the_posture_4123() {
    for posture in RESTRICTED {
        let hub = recorder().await;
        let s = scratch(posture);
        let (embedder, reranker_degraded) = {
            let _env = EnvScope::new(&cell_env(Some(posture), &hub.uri(), &s));
            let embedder = tokio::task::spawn_blocking(Embedder::new_local)
                .await
                .expect("loader thread");
            let reranker = tokio::task::spawn_blocking(CrossEncoder::new_neural)
                .await
                .expect("loader thread");
            (embedder, reranker.is_degraded_lexical())
        };
        let err = match embedder {
            Ok(_) => {
                panic!("#4123 ({posture}): an empty cache under a restricted posture must NOT load")
            }
            Err(e) => chain(&e),
        };
        assert!(
            err.contains(&format!("{POSTURE_VAR}={posture}")),
            "#4123 ({posture}): the embedder's refusal must name the posture knob; got: {err}"
        );
        assert!(
            reranker_degraded,
            "#4123 ({posture}): the cross-encoder degrades to lexical with no cache"
        );
        assert_eq!(
            requests(&hub).await,
            0,
            "#4123 ({posture}): the Hub must receive ZERO requests — a restricted posture \
             refuses the weight download outright"
        );
    }
}

// ─── 2. allow control: the recorder sees the fetch attempts ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_control_reaches_the_hub_endpoint_4123() {
    let hub = recorder().await;
    let s = scratch("allow");
    let (embedder, reranker_degraded) = {
        let _env = EnvScope::new(&cell_env(None, &hub.uri(), &s));
        let embedder = tokio::task::spawn_blocking(Embedder::new_local)
            .await
            .expect("loader thread");
        let reranker = tokio::task::spawn_blocking(CrossEncoder::new_neural)
            .await
            .expect("loader thread");
        (embedder, reranker.is_degraded_lexical())
    };
    assert!(
        embedder.is_err(),
        "control (allow): the 404-ing hub cannot serve the weights"
    );
    assert!(
        reranker_degraded,
        "control (allow): the reranker degrades on 404"
    );
    assert!(
        requests(&hub).await >= 2,
        "control (allow): the legacy posture fetches from the configured hub (HF_ENDPOINT), \
         once per loader at least — the fixture can see a leak"
    );
}

// ─── 3. a pre-staged cache still loads under deny ────────────────────────

/// Stage the hf-hub cache layout (`refs/main` -> `snapshots/<commit>/`,
/// the #3788 shape) with placeholder files for the `MiniLM` repo.
fn stage_minilm(hf_home: &Path) {
    let repo = hf_home.join("hub/models--sentence-transformers--all-MiniLM-L6-v2");
    let commit = "1110a243bcb1f321a9cf06d6e63c9bbd2f1b3a4c";
    std::fs::create_dir_all(repo.join("refs")).expect("mk refs");
    std::fs::write(repo.join("refs").join("main"), format!("{commit}\n")).expect("refs/main");
    let snap = repo.join("snapshots").join(commit);
    std::fs::create_dir_all(&snap).expect("mk snapshot");
    for f in ["config.json", "tokenizer.json", "model.safetensors"] {
        std::fs::write(snap.join(f), b"{}").expect("write placeholder");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_cache_still_loads_under_deny_with_zero_requests_4123() {
    let hub = recorder().await;
    let s = scratch("staged");
    stage_minilm(&s.hf_home);
    let embedder = {
        let _env = EnvScope::new(&cell_env(Some("deny"), &hub.uri(), &s));
        tokio::task::spawn_blocking(Embedder::new_local)
            .await
            .expect("loader thread")
    };
    // The placeholder config is not a BERT config: reaching the PARSE proves
    // the three staged files were resolved cache-only (a cache miss would
    // name the fallback dir instead; a fetch would hit the recorder).
    let err = match embedder {
        Ok(_) => panic!("#4123 (staged): placeholder weights cannot build a model"),
        Err(e) => chain(&e),
    };
    assert!(
        err.contains("parse config.json"),
        "#4123 (staged): the staged cache must be resolved under deny (load reaches the \
         config parse); got: {err}"
    );
    assert_eq!(
        requests(&hub).await,
        0,
        "#4123 (staged): a cache hit under deny makes no request"
    );
}

// ─── 4. structural: both loaders build the Hub client from the env ───────

fn read_src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn both_hub_loaders_build_from_env_and_consult_the_posture_4123() {
    // (file, loader, the builder it must use, what that builder honours)
    for (file, loader, builder, why) in [
        (
            "src/embeddings.rs",
            "fn download_via_hf_hub(",
            "ApiBuilder::from_env()",
            "HF_ENDPOINT + HF_HOME, the root the offline resolver reads (#3788)",
        ),
        (
            "src/reranker.rs",
            "fn resolve_cross_encoder_files(",
            "ApiBuilder::from_cache(",
            "the $HOME-rooted cache its offline resolver reads, plus HF_ENDPOINT",
        ),
    ] {
        let src = read_src(file);
        let start = src
            .find(loader)
            .unwrap_or_else(|| panic!("{file}: {loader} not found"));
        // Char-safe window over the loader body (the comments carry non-ASCII).
        let body: String = src[start..].chars().take(3000).collect();
        assert!(
            body.contains(builder),
            "#4123: {file} {loader} must build the Hub client through `{builder}` ({why}); \
             got:\n{body}"
        );
        assert!(
            !body.contains("Api::new()"),
            "#4123: {file} {loader} must not build through `Api::new()` (ignores \
             HF_ENDPOINT / HF_HOME); got:\n{body}"
        );
    }
    let rr = read_src("src/reranker.rs");
    assert!(
        rr.contains("\"HF_ENDPOINT\""),
        "#4123: the reranker's online fetch must honour HF_ENDPOINT"
    );
    let emb = read_src("src/embeddings.rs");
    assert!(
        emb.contains("fn hub_fetch_refused_by_posture("),
        "#4123: the posture predicate is the one composition point the offline guard consults"
    );
}

// ─── 5. docs pins (#6397 / #6398 / #6399) ────────────────────────────────

/// The row of `file` whose text contains `needle`.
fn doc_line(file: &str, needle: &str) -> String {
    read_src(file)
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("{file}: no line contains {needle:?}"))
        .to_string()
}

#[test]
fn security_md_model_weight_row_names_the_posture_6397() {
    let row = doc_line("SECURITY.md", "**Model-weight fetch**");
    assert!(
        !row.contains("**NOT `AI_MEMORY_INFERENCE_EGRESS`**"),
        "#6397: the posture DOES govern the model-weight lane since #4123:\n{row}"
    );
    assert!(
        row.contains("AI_MEMORY_INFERENCE_EGRESS") && row.contains("remote_fetch_disabled_reason"),
        "#6397: the row must name the posture and the live symbol:\n{row}"
    );
    assert!(
        !row.contains("remote_fetch_disabled]"),
        "#6397: the row cites a removed symbol:\n{row}"
    );
}

#[test]
fn telemetry_md_download_item_names_the_posture_6398() {
    let item = doc_line("docs/telemetry.md", "one-time embedder model download");
    assert!(
        item.contains("AI_MEMORY_INFERENCE_EGRESS"),
        "#6398: item (b) must list the restricted posture as a trigger:\n{item}"
    );
    assert!(
        !item.contains("remote_fetch_disabled`") && item.contains("remote_fetch_disabled_reason"),
        "#6398: item (b) must cite the live symbol:\n{item}"
    );
}

#[test]
fn architecture_row_58_scopes_hf_home_to_the_embedder_6399() {
    let row = doc_line(
        "docs/reference/ARCHITECTURE_REFERENCE.md",
        "`AI_MEMORY_EMBED_OFFLINE`",
    );
    assert!(
        row.contains("$HOME/.cache/huggingface/hub"),
        "#6399: row 58 must state the cross-encoder cache root:\n{row}"
    );
    assert!(
        !row.contains("are honoured. Source:"),
        "#6399: HF_HOME is honoured by the MiniLM embedder only:\n{row}"
    );
}
