// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #3436 — CLI stdout / `--json` hygiene, table-driven.
//!
//! # The defects these pin
//!
//! 1. **Logs on stdout.** `serve` and `sync-daemon` each built their own
//!    `tracing_subscriber::fmt()` without `.with_writer(...)`, and the
//!    crate default is STDOUT — so both long-running verbs wrote
//!    ANSI-coloured log lines onto the stream a caller pipes into `jq` or
//!    a log shipper. The MCP entrypoint had already worked this out and
//!    pinned stderr by hand, but the fix lived at that one call site
//!    instead of in a funnel, so its two siblings kept the bug.
//! 2. **`--json` accepted and ignored.** The flag is `global = true`, so
//!    clap takes it on all 94 subcommands while only some honour it.
//! 3. **`verify-reflection-chain <unknown-id>` reported `ok: true`,
//!    exit 0** — an empty walk satisfies the `ok` predicate vacuously, so
//!    the verifier certified a memory it had never found.
//!
//! Each is pinned in BOTH directions: the denied path refuses/reroutes,
//! and the allowed path still works.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Strip the `#[cfg(test)]` module and comment lines so a fixture or a
/// doc reference never counts as a production site. Same boundary
/// heuristic as `tests/atomise_funnel_ceiling_2984.rs`.
fn production_prefix(src: &str) -> String {
    let cut = src
        .find("\n#[cfg(test)]\nmod tests")
        .or_else(|| src.find("\n#[cfg(test)]\n#[path"))
        .unwrap_or(src.len());
    src[..cut]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// 1. Logs to stderr on every long-running verb
// ---------------------------------------------------------------------------

/// Every production surface that installs a CONSOLE tracing subscriber,
/// with the funnel it must route through.
const CONSOLE_SUBSCRIBER_SURFACES: &[(&str, &str)] = &[
    ("src/daemon_runtime.rs", "serve / boot posture reports"),
    ("src/cli/sync.rs", "sync-daemon"),
    (
        "src/mcp/mod.rs",
        "mcp stdio (stdout is the JSON-RPC channel)",
    ),
];

/// DENIED: no production file outside the funnel may build its own console
/// subscriber, because the writer would default to stdout again.
#[test]
fn no_production_file_builds_its_own_console_subscriber_3436() {
    let mut offenders = Vec::new();
    for (file, why) in CONSOLE_SUBSCRIBER_SURFACES {
        let src = production_prefix(&read(file));
        if src.contains("tracing_subscriber::fmt()") {
            offenders.push(format!(
                "{file} ({why}) still builds its own `tracing_subscriber::fmt()`. The \
                 crate default writer is STDOUT, so this reintroduces #3436 the moment \
                 someone forgets `.with_writer`. Route it through \
                 `crate::logging::init_console_tracing`, where the writer is not a \
                 parameter."
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "#3436:\n  - {}",
        offenders.join("\n  - ")
    );
}

/// ALLOWED: each surface really does call the funnel (a file that stopped
/// installing tracing at all would pass the test above vacuously).
#[test]
fn every_long_running_verb_routes_through_the_console_funnel_3436() {
    let mut missing = Vec::new();
    for (file, why) in CONSOLE_SUBSCRIBER_SURFACES {
        let src = production_prefix(&read(file));
        if !src.contains("init_console_tracing(") {
            missing.push(format!(
                "{file} ({why}) no longer calls init_console_tracing"
            ));
        }
    }
    assert!(missing.is_empty(), "#3436:\n  - {}", missing.join("\n  - "));
}

/// The funnel pins stderr, and does it exactly once — the guarantee is a
/// property of the funnel, not of its callers.
#[test]
fn the_console_funnel_pins_stderr_3436() {
    let src = production_prefix(&read("src/logging.rs"));
    let funnel = src
        .split("pub fn init_console_tracing")
        .nth(1)
        .expect("init_console_tracing must exist");
    let body = &funnel[..funnel.find("\npub fn ").unwrap_or(funnel.len())];
    assert!(
        body.contains(".with_writer(std::io::stderr)"),
        "the console funnel must pin STDERR; that is the whole control:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// 2. `--json` means JSON-only stdout, or it is refused
// ---------------------------------------------------------------------------

/// The verbs the issue named as accepting-and-ignoring `--json`, plus the
/// long-running ones. Each must now be classified `Unsupported` so the
/// dispatcher refuses instead of silently dropping the flag.
const MUST_REFUSE_JSON: &[(&str, &str)] = &[
    ("Install", "install prints a unified diff"),
    ("Wrap", "wrap is a passthrough around another process"),
    ("Man", "man emits a man page"),
    ("Config", "config check/migrate emit human reports"),
    (
        "ExportForensicBundle",
        "export-forensic-bundle writes a bundle",
    ),
    ("Serve", "serve is a daemon; stdout is not a report"),
    ("SyncDaemon", "sync-daemon is a daemon"),
    ("Mcp", "mcp stdio owns stdout for JSON-RPC"),
];

/// DENIED: every named verb is in the `Unsupported` arm of the exhaustive
/// classification.
#[test]
fn json_ignoring_verbs_are_classified_unsupported_3436() {
    let src = read("src/cli/json_contract.rs");
    // Slice from the LAST `JsonSupport::Local,` (the `sal`-gated arms each
    // carry one of their own, so an nth(1) split lands in the wrong place)
    // up to the Unsupported verdict. What is left is exactly the
    // Unsupported or-chain.
    let after_local = src
        .rfind("JsonSupport::Local,")
        .map(|at| &src[at..])
        .expect("the Local arm must exist");
    let unsupported = after_local
        .split("JsonSupport::Unsupported,")
        .next()
        .expect("the Unsupported arm must exist");
    let mut missing = Vec::new();
    for (variant, why) in MUST_REFUSE_JSON {
        if !unsupported.contains(&format!("Command::{variant}")) {
            missing.push(format!(
                "{variant} ({why}) is not in the Unsupported arm — `--json` would be \
                 accepted and ignored again"
            ));
        }
    }
    assert!(missing.is_empty(), "#3436:\n  - {}", missing.join("\n  - "));
}

/// The classification is EXHAUSTIVE — no `_` arm. That is what makes a new
/// subcommand fail to compile until someone decides what `--json` means
/// for it, instead of inheriting the flag by accident.
#[test]
fn the_json_classification_has_no_catch_all_arm_3436() {
    let src = production_prefix(&read("src/cli/json_contract.rs"));
    let body = src
        .split("pub fn json_support")
        .nth(1)
        .expect("json_support must exist");
    assert!(
        !body.contains("_ =>"),
        "a catch-all arm defeats the control: a new subcommand would silently \
         inherit whatever the wildcard says.\n{body}"
    );
}

/// The dispatcher actually consults the classification, and does it before
/// any work — the refusal claims NOTHING WAS EXECUTED.
#[test]
fn the_dispatcher_refuses_unsupported_json_before_any_work_3436() {
    let src = production_prefix(&read("src/daemon_runtime.rs"));
    assert!(
        src.contains("json_contract::json_support(&cli.command)"),
        "the dispatcher must consult the --json classification"
    );
    let gate_at = src
        .find("json_contract::json_support(&cli.command)")
        .expect("gate present");
    let dispatch_at = src.find("match cli.command {").unwrap_or(usize::MAX);
    assert!(
        gate_at < dispatch_at,
        "the gate must run BEFORE the command dispatch, or the refusal's \
         `NOTHING WAS EXECUTED` is a lie"
    );
}

/// `rules keygen` printed a human status line to stdout immediately before
/// its JSON envelope. It must route through the `--json` contract helper.
#[test]
fn rules_keygen_status_line_honours_the_json_contract_3436() {
    let src = production_prefix(&read("src/cli/rules.rs"));
    let keygen = src
        .split("fn keygen_operator")
        .nth(1)
        .expect("keygen_operator must exist");
    let body = &keygen[..keygen.find("\nfn ").unwrap_or(keygen.len())];
    assert!(
        body.contains("human_line("),
        "the fingerprint line must go through `CliOutput::human_line`, which sends it \
         to stderr under --json so stdout stays a single JSON document:\n{body}"
    );
    assert!(
        !body.contains("writeln!(\n        out.stdout,\n        \"Ed25519"),
        "the unconditional stdout write must be gone:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// 3. Unknown id -> NOT FOUND, exit 1
// ---------------------------------------------------------------------------

/// DENIED: an unresolvable root is refused with exit 1 before the chain is
/// built, instead of being certified by a vacuously-true empty walk.
#[test]
fn verify_reflection_chain_refuses_an_unknown_root_3436() {
    let src = production_prefix(&read("src/cli/verify.rs"));
    let run = src.split("pub fn run(").nth(1).expect("run must exist");
    let gate = run
        .find("is_none()")
        .expect("run must check that the root memory resolves");
    let build = run
        .find("build_chain_report(")
        .expect("run must build the report");
    assert!(
        gate < build,
        "the existence check must run BEFORE build_chain_report — after it, the empty \
         walk has already produced ok=true"
    );
    let head = &run[..build];
    assert!(
        head.contains("return Ok(1)"),
        "an unknown root must exit 1 (NOT FOUND), kept distinct from exit 2 \
         (verification FAILED):\n{head}"
    );
}
