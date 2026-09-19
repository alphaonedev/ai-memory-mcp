// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W1a, PIN (a) — **`[decision]` unset is byte-identical v1.0.0.**
//!
//! Two halves, because "byte-identical" has two failure modes:
//!
//! 1. A GOLDEN over the config resolution. The `[decision]` work moved
//!    the shared API-key ladder to an OPTIONAL primary env var and
//!    retired `resolve_llm_auto_tag`; if either perturbed `[llm]`
//!    resolution, this golden changes. It also pins that a config with
//!    no `[decision]` section resolves to NO provider.
//! 2. A STRUCTURAL pin that **every production site which can reach a
//!    decider obtains it only from the boot chokepoint**. W1a added the
//!    trait, the config and the resolver; W1b added the chokepoint and
//!    its ONE `bootstrap_serve` call site; W1c added the provider
//!    clients, which IMPLEMENT a provider rather than consult one.
//!
//!    #3826 replaced the predecessor `no_seam_consults_the_decider_yet`
//!    with that property. The predecessor asserted a fact with an
//!    expiry date — it would have had to be deleted by the first unit
//!    that wired a seam, and in the meantime it was red on the stacked
//!    integration base for a reason that was not a defect in any cut:
//!    W1b tightened the allowlist, W1c branched before the tightening,
//!    and the stack inherited a list that had never seen W1c's five
//!    provider modules. The successor still ratchets the allowlist —
//!    it grows only in lockstep with reviewed wiring — but what it
//!    PROVES is the monopoly, which does not expire when a seam lands.
//!
//! Both halves carry a PRESENCE control, so neither can pass vacuously.
//!
//! NOTE: the golden resolves `[llm]`, which reads `AI_MEMORY_LLM_*` from
//! the process environment by design. Run it with those unset (CI does);
//! a set variable fails the test loudly rather than silently.

use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::config::AppConfig;

/// A representative operator config that does NOT mention `[decision]`.
const CORPUS_WITHOUT_DECISION: &str = r#"
schema_version = 2
tier = "autonomous"

[llm]
backend = "openrouter"
model = "vendor/chat-1"
base_url = "https://chat.internal.example.net/v1"

[llm.auto_tag]
model = "gemma3:4b"

[storage]
default_namespace = "projects/atlas"
"#;

/// The same corpus, plus a `[decision]` section. The PRESENCE control.
const CORPUS_WITH_DECISION: &str = r#"
schema_version = 2
tier = "autonomous"

[llm]
backend = "openrouter"
model = "vendor/chat-1"
base_url = "https://chat.internal.example.net/v1"

[llm.auto_tag]
model = "gemma3:4b"

[storage]
default_namespace = "projects/atlas"

[decision]
provider = "systemone"
model = "vendor/decider-1"
base_url = "https://decide.internal.example.net"
"#;

/// The projection the golden pins: the resolved `[llm]` view (which this
/// commit refactored underneath) and the resolved decision posture.
fn render(cfg: &AppConfig) -> String {
    let llm = cfg.resolve_llm(None, None, None);
    let decision = cfg.resolve_decision();
    format!(
        "llm.backend={}\nllm.model={}\nllm.base_url={}\nllm.api_key={}\nllm.api_key_source={}\n\
         llm.source={}\ndecision={}\n",
        llm.backend,
        llm.model,
        llm.base_url,
        if llm.api_key().is_some() {
            "present"
        } else {
            "absent"
        },
        llm.api_key_source.as_str(),
        llm.source.as_str(),
        decision.as_ref().map_or_else(
            || "absent".to_string(),
            |d| format!(
                "{}|{}|{}|timeout={}|fallback={}",
                d.provider,
                d.model,
                d.base_url,
                d.timeout_secs,
                d.fallback.as_str()
            )
        ),
    )
}

const GOLDEN_WITHOUT_DECISION: &str = "\
llm.backend=openrouter
llm.model=vendor/chat-1
llm.base_url=https://chat.internal.example.net/v1
llm.api_key=absent
llm.api_key_source=none
llm.source=config
decision=absent
";

#[test]
fn decision_unset_is_byte_identical_v100() {
    for var in [
        "AI_MEMORY_LLM_BACKEND",
        "AI_MEMORY_LLM_MODEL",
        "AI_MEMORY_LLM_BASE_URL",
        "AI_MEMORY_LLM_API_KEY",
        "OPENROUTER_API_KEY",
    ] {
        assert!(
            std::env::var_os(var).is_none(),
            "{var} is set in this process environment; the golden resolves \
             [llm] through the real env ladder, so unset it before running"
        );
    }

    let cfg: AppConfig = toml::from_str(CORPUS_WITHOUT_DECISION).expect("corpus parses");
    assert!(
        cfg.decision.is_none(),
        "the corpus must carry no [decision] section"
    );
    assert_eq!(
        render(&cfg),
        GOLDEN_WITHOUT_DECISION,
        "resolving a config with no [decision] section must be unchanged"
    );
    assert!(
        format!("{cfg:?}").contains("decision: None"),
        "the section must render as absent in Debug, never be dropped from it"
    );

    // PRESENCE control — the golden is sensitive: the same corpus with a
    // [decision] section renders a DIFFERENT projection, and only the
    // decision line moves.
    let with: AppConfig = toml::from_str(CORPUS_WITH_DECISION).expect("corpus parses");
    let rendered = render(&with);
    assert_ne!(rendered, GOLDEN_WITHOUT_DECISION);
    assert_eq!(
        rendered.replace(
            "decision=systemone|vendor/decider-1|https://decide.internal.example.net\
             |timeout=2|fallback=abstain",
            "decision=absent"
        ),
        GOLDEN_WITHOUT_DECISION,
        "adding [decision] must change ONLY the decision line"
    );
}

/// Every token that would mean a file NAMES the decider surface.
///
/// Naming the surface is not the same as OBTAINING a decider. The
/// second, stronger property — a handle comes only from the boot
/// chokepoint — is pinned separately below.
const DECIDER_TOKENS: &[&str] = &[
    "DecisionProvider",
    "NullDecider",
    "decider_or_null",
    "resolve_decision",
    "decision_config",
    "crate::decision::",
    // #3806 W1b — the boot chokepoint module itself. Added so wiring a
    // seam to it is caught by this scan too: without this token W1b's
    // own `daemon_runtime` call site would have been invisible here.
    "decision_boot",
    // #3806 W2 — the seam module and the ONE attachment verb. Without
    // these two tokens a surface could reach a decider through
    // `decision_seams` without naming anything this scan looks for.
    "decision_seams",
    "attach_decider",
];

/// The files ALLOWED to name the decider surface. A change in this list
/// is a change someone reviewed.
///
/// These files declare the types (`src/decision.rs`), resolve the
/// config (`src/decision_config.rs`), gate the endpoint
/// (`src/decision_boot.rs`, `src/egress.rs`), wire the section and the
/// module list (`src/config.rs`, `src/lib.rs`), render the boot
/// snapshot (`src/mcp/tools/capabilities.rs`), run the chokepoint once
/// at boot (`src/daemon_runtime.rs`), or IMPLEMENT a provider for the
/// chokepoint to attach (the five `decision_clients` modules).
const DECIDER_ALLOWED: &[&str] = &[
    "src/decision.rs",
    "src/decision_config.rs",
    "src/config.rs",
    "src/lib.rs",
    // #3806 W1b — the boot chokepoint, its ONE `bootstrap_serve` call
    // site, the egress module that names the `InferenceDecision` class,
    // and the capability surface that renders the boot snapshot.
    "src/decision_boot.rs",
    "src/daemon_runtime.rs",
    "src/egress.rs",
    "src/mcp/tools/capabilities.rs",
    // #3806 W1c, admitted by #3826 — the provider CLIENTS. These five
    // are legitimate NON-call-sites: they IMPLEMENT `DecisionProvider`
    // and are constructed BY the chokepoint through
    // `decision_clients::construct`, which is handed an already-
    // resolved, already-egress-gated section and hands back a boxed
    // provider for the chokepoint to attach. Not one of them obtains a
    // decider from a production path, and none can — a
    // `DecisionProviderHandle` has private fields and exactly one
    // construction site (both pinned below), inside the chokepoint.
    //
    // They were missing from this list only because W1c branched from
    // W1a, before W1b tightened the scan, so the stacked integration
    // branch inherited a list that had never seen them (#3826).
    "src/decision_clients.rs",
    "src/decision_clients/calibration.rs",
    "src/decision_clients/chat.rs",
    "src/decision_clients/fallback.rs",
    "src/decision_clients/systemone.rs",
    // #3806 W2 — the reviewed SEAM wiring. `decision_seams.rs` owns the
    // two call positions and the attachment; `llm.rs` holds the opaque
    // attachment and the two seam branches; `reload.rs` (the MCP stdio
    // surface and its between-request reload) and `cli/curator.rs` (the
    // CLI one-shot surface) are the two surfaces the W1b ruling named as
    // W2's acceptance item, now routed through the same chokepoint the
    // HTTP daemon uses.
    "src/decision_seams.rs",
    "src/llm.rs",
    "src/reload.rs",
    "src/cli/curator.rs",
];

/// The chokepoint entry points (`build_decision_provider`,
/// `build_decision_provider_under`) share this prefix. A file that
/// names it in CODE is a file that can obtain a gated handle.
const CHOKEPOINT_TOKEN: &str = "build_decision_provider";

/// The file that DEFINES the chokepoint, and the one home of the gated
/// handle type. Excluded from the caller set below, because a
/// definition is not a call.
const CHOKEPOINT_HOME: &str = "src/decision_boot.rs";

/// THE property, and the reason this pin outlives "no seam is wired
/// yet": the ONLY way to obtain a `DecisionProviderHandle` is the boot
/// chokepoint, so these are the only production files that may reach
/// it. A surface wanting its own ungated decision endpoint would have
/// to appear here, which is a reviewable act rather than an oversight.
///
/// Asserted in BOTH directions: no file outside this list may call the
/// chokepoint, and every file in it must actually call it — so the list
/// cannot rot into a permission nobody exercises.
/// #3806 W2 moved this from `daemon_runtime.rs` to `decision_seams.rs`:
/// three surfaces now need a decider, and each of them obtaining its own
/// would be three chances to get the gate wrong. They reach the
/// chokepoint through ONE function instead — see [`ATTACH_CALLERS`].
const CHOKEPOINT_CALLERS: &[&str] = &["src/decision_seams.rs"];

/// The ONE verb that hands a surface a gated decider, and the complete
/// list of surfaces allowed to call it.
///
/// Asserted in BOTH directions, like the chokepoint itself. A surface
/// that APPEARS here is a new decision consumer someone reviewed; one
/// that VANISHES is a surface that silently stopped running the boot
/// chokepoint — which would take its `/capabilities` snapshot and its
/// signed egress-refusal row with it.
///
/// `src/cli/commands/expand.rs` and `src/cli/commands/atomise.rs`
/// deliberately do NOT appear: their `[llm]` clients reach
/// `expand_query` and `Curator::decompose`, neither of which is a seam,
/// so routing them would construct a decision provider nothing consumes
/// and write a refusal row per CLI invocation under a refusing posture.
const ATTACH_CALLERS: &[&str] = &[
    "src/cli/curator.rs",
    "src/daemon_runtime.rs",
    "src/reload.rs",
];

/// The verb [`ATTACH_CALLERS`] is asserted over.
const ATTACH_TOKEN: &str = "attach_decider(";

/// The gated handle type.
const HANDLE_TYPE: &str = "DecisionProviderHandle";

/// The files allowed to NAME the gated handle type: the chokepoint that
/// defines it, and the seam module that carries it. Nothing else can
/// build one — the type has all-private fields and exactly ONE struct
/// literal in the crate (both asserted below) — so this list is about
/// who may HOLD a handle, and it is short on purpose.
///
/// `src/llm.rs` is deliberately NOT here: a client carries the opaque
/// `decision_seams::DecisionSeams`, never the handle itself.
const HANDLE_CARRIERS: &[&str] = &["src/decision_boot.rs", "src/decision_seams.rs"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `true` when `line` is Rust code rather than a doc/comment line, so a
/// module header that MENTIONS the chokepoint is not counted as a call.
/// `src/decision.rs` and `src/egress.rs` both name it in prose.
fn is_code_line(line: &str) -> bool {
    let t = line.trim_start();
    !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
}

/// #3806 W1a/W1b, repaired by #3826 — the STRUCTURAL half of pin (a).
///
/// The predecessor asserted only "no seam consults the decider YET",
/// which expires the moment a seam is wired. This successor asserts the
/// property that does not expire: **every production site that can
/// reach a decider obtains it only from the boot chokepoint.**
///
/// Four properties, each paired with a control so none can pass
/// vacuously:
///
/// * the walk really saw the `src` tree (anti-vacuity);
/// * ABSENCE (a) — only reviewed files NAME the decider surface, and
///   PRESENCE (a) — every file on that list actually names it;
/// * ABSENCE (b) — only reviewed files CALL the boot chokepoint, and
///   PRESENCE (b) — every file on that list actually calls it;
/// * ABSENCE (c) — the gated handle type has one home, all-private
///   fields and exactly ONE construction site in the whole crate, which
///   is what makes "no public constructor" enforced by the compiler
///   rather than merely true today.
#[test]
fn every_decider_comes_from_the_boot_chokepoint_3806() {
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);
    // PRESENCE self-check #1 — the walk really saw the tree. An empty
    // offender list below can therefore never mean "the walk is broken".
    assert!(files.len() > 100, "the walk must see the whole src tree");

    let mut offenders: Vec<String> = Vec::new();
    let mut allowed_hits = 0usize;
    let mut named_by: Vec<String> = Vec::new();
    let mut chokepoint_callers: Vec<String> = Vec::new();
    let mut attach_callers: Vec<String> = Vec::new();
    let mut handle_sites: Vec<String> = Vec::new();

    for path in &files {
        let rel = path.to_string_lossy().replace('\\', "/");
        let body = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {rel}: {e}"));

        let mut names_a_token = false;
        for token in DECIDER_TOKENS {
            if !body.contains(token) {
                continue;
            }
            names_a_token = true;
            if DECIDER_ALLOWED.contains(&rel.as_str()) {
                allowed_hits += 1;
            } else {
                offenders.push(format!("{rel}: {token}"));
            }
        }
        if names_a_token {
            named_by.push(rel.clone());
        }

        if rel != CHOKEPOINT_HOME
            && body
                .lines()
                .filter(|l| is_code_line(l))
                .any(|l| l.contains(CHOKEPOINT_TOKEN))
        {
            chokepoint_callers.push(rel.clone());
        }

        if rel != CHOKEPOINT_CALLERS[0]
            && body
                .lines()
                .filter(|l| is_code_line(l))
                .any(|l| l.contains(ATTACH_TOKEN))
        {
            attach_callers.push(rel.clone());
        }

        if body.contains(HANDLE_TYPE) {
            handle_sites.push(rel.clone());
        }
    }

    // ABSENCE (a) — only reviewed files name the decider surface.
    assert!(
        offenders.is_empty(),
        "these files name the decider surface without being on the \
         reviewed allowlist. Either the wiring is unreviewed, or the \
         allowlist needs a reviewed entry saying why the file is a \
         legitimate non-call-site:\n  {}",
        offenders.join("\n  ")
    );
    // PRESENCE self-check #2 — the scan really does find the tokens
    // where they ARE, so the emptiness above is not a broken grep.
    assert!(
        allowed_hits >= 10,
        "the scan found only {allowed_hits} hits in the allowlisted \
         files; it is not actually matching the decider tokens"
    );
    // PRESENCE (a) — the allowlist cannot rot into a permission nobody
    // exercises: every entry must exist and must actually name a token.
    let mut stale: Vec<&str> = DECIDER_ALLOWED
        .iter()
        .copied()
        .filter(|a| !named_by.iter().any(|n| n.as_str() == *a))
        .collect();
    stale.sort_unstable();
    assert!(
        stale.is_empty(),
        "these allowlist entries no longer name the decider surface (or \
         no longer exist); a permission nobody exercises is a permission \
         nobody reviews:\n  {}",
        stale.join("\n  ")
    );

    // ABSENCE (b) + PRESENCE (b) — the chokepoint monopoly, both ways.
    chokepoint_callers.sort();
    let mut expected: Vec<String> = CHOKEPOINT_CALLERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    expected.sort();
    assert_eq!(
        chokepoint_callers, expected,
        "a DecisionProviderHandle is obtainable ONLY from the boot \
         chokepoint, so exactly these files may reach it. A file that \
         APPEARED is an ungated decision endpoint; a file that VANISHED \
         is a surface that lost its gate."
    );

    // ABSENCE (b2) + PRESENCE (b2) — the attachment verb, both ways.
    // This is the W1b ruling's acceptance item made mechanical: every
    // surface that can reach a decider obtains it from the chokepoint,
    // and the set of such surfaces is a reviewed list.
    attach_callers.sort();
    let mut expected_attach: Vec<String> =
        ATTACH_CALLERS.iter().map(|s| (*s).to_string()).collect();
    expected_attach.sort();
    assert_eq!(
        attach_callers, expected_attach,
        "exactly these surfaces may obtain a gated decider. A surface \
         that APPEARED is a new decision consumer nobody reviewed; one \
         that VANISHED stopped running the boot chokepoint, and took \
         its capability snapshot and its signed refusal row with it."
    );

    // ABSENCE (c) — a short, reviewed list of files may NAME the handle
    // type, which is what keeps 'private fields, no public constructor'
    // enforceable rather than merely true today.
    handle_sites.sort();
    let mut expected_handle: Vec<String> =
        HANDLE_CARRIERS.iter().map(|s| (*s).to_string()).collect();
    expected_handle.sort();
    assert_eq!(
        handle_sites, expected_handle,
        "only the chokepoint that defines the gated handle and the seam \
         module that carries it may name it; a third file naming it is a \
         third door"
    );

    assert_handle_is_unforgeable();
}

/// `true` when `line` opens a `struct` or `impl` item rather than
/// constructing a value, so the declaration and the inherent `impl`
/// block are not mistaken for construction sites.
fn is_item_header(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("impl")
        || t.starts_with("struct")
        || t.starts_with("pub struct")
        || t.starts_with("pub(crate) struct")
}

/// ABSENCE (c), the compiler-enforced half: inside its one home the
/// gated handle has ALL-PRIVATE fields (so no other module can build
/// one from parts, even in-crate) and exactly ONE struct-literal
/// construction site (so the chokepoint is the only door). Each is
/// paired with a presence control, so a parse that found nothing fails
/// loudly instead of passing.
fn assert_handle_is_unforgeable() {
    let body = fs::read_to_string(CHOKEPOINT_HOME)
        .unwrap_or_else(|e| panic!("read {CHOKEPOINT_HOME}: {e}"));

    // PRESENCE — this file really is the chokepoint's definition site.
    assert!(
        body.contains(&format!("fn {CHOKEPOINT_TOKEN}(")),
        "{CHOKEPOINT_HOME} must DEFINE `{CHOKEPOINT_TOKEN}`; if the \
         chokepoint moved, every assertion keyed to this file is vacuous"
    );

    let decl = format!("pub struct {HANDLE_TYPE} {{");
    let start = body
        .find(&decl)
        .unwrap_or_else(|| panic!("{CHOKEPOINT_HOME} must declare `{decl}`"));
    let mut fields = Vec::new();
    for line in body[start..].lines().skip(1) {
        if line.starts_with('}') {
            break;
        }
        let t = line.trim();
        if t.is_empty() || !is_code_line(line) || t.starts_with('#') {
            continue;
        }
        fields.push(t.to_string());
    }
    // PRESENCE — the field parse actually found the fields.
    assert!(
        fields.len() >= 3,
        "parsed only {} field(s) out of `{HANDLE_TYPE}`; the privacy \
         assertion below would be vacuous: {fields:?}",
        fields.len()
    );
    // ABSENCE — not one of them is `pub`.
    let public: Vec<&str> = fields
        .iter()
        .map(String::as_str)
        .filter(|f| f.starts_with("pub"))
        .collect();
    assert!(
        public.is_empty(),
        "`{HANDLE_TYPE}` must keep ALL fields private — a public field \
         lets any module assemble an UNGATED handle without ever \
         calling the chokepoint: {public:?}"
    );

    // ABSENCE — exactly one struct literal in the whole crate, and it
    // is the one inside the chokepoint (every other file is barred from
    // naming the type at all by the assertion above).
    let literal = format!("{HANDLE_TYPE} {{");
    let sites: Vec<&str> = body
        .lines()
        .filter(|l| is_code_line(l))
        .filter(|l| l.contains(&literal) && !is_item_header(l))
        .collect();
    assert_eq!(
        sites.len(),
        1,
        "a gated handle must have exactly ONE construction site, inside \
         the chokepoint; found {}: {sites:?}",
        sites.len()
    );
}
