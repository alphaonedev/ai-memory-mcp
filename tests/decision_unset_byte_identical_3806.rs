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
//! 2. A STRUCTURAL pin that no SEAM consults the decider. W1a added the
//!    trait, the config and the resolver and wired nothing; W1b adds the
//!    boot chokepoint and its ONE `bootstrap_serve` call site, and still
//!    wires no seam (the clients are W1c, the seams W2-W4). Until a seam
//!    is wired there is no observable output to diff, and this test is
//!    what makes that claim mechanical rather than asserted. The
//!    allowlist grows only in lockstep with reviewed wiring.
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

/// Every token that would mean "a call site consults the decider".
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
];

/// The files this commit is ALLOWED to mention the decider in: the two
/// new modules, the `config.rs` wiring (the section field, the `Debug`
/// line, the validator call, the resolver delegate) and the `lib.rs`
/// module declarations. Everything else is a seam, and W1a wires none.
const ALLOWED: &[&str] = &[
    "src/decision.rs",
    "src/decision_config.rs",
    "src/config.rs",
    "src/lib.rs",
    // #3806 W1b, extended in lockstep with the wiring it admits:
    // the boot chokepoint module, its ONE `bootstrap_serve` call site,
    // the egress module that now names the `InferenceDecision` class in
    // its docs, and the capability surface that renders the boot
    // snapshot. A change in this list is a change someone reviewed.
    "src/decision_boot.rs",
    "src/daemon_runtime.rs",
    "src/egress.rs",
    "src/mcp/tools/capabilities.rs",
];

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

#[test]
fn no_seam_consults_the_decider_yet() {
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);
    assert!(files.len() > 100, "the walk must see the whole src tree");

    let mut offenders: Vec<String> = Vec::new();
    let mut allowed_hits = 0usize;
    for path in &files {
        let rel = path.to_string_lossy().replace('\\', "/");
        let body = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for token in DECIDER_TOKENS {
            if !body.contains(token) {
                continue;
            }
            if ALLOWED.contains(&rel.as_str()) {
                allowed_hits += 1;
            } else {
                offenders.push(format!("{rel}: {token}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "W1b wires the BOOT CHOKEPOINT and no seam: the decider must not be \
         consulted from any seam yet (the clients are W1c, the seams W2-W4). \
         Offending sites:\n  {}",
        offenders.join("\n  ")
    );
    // PRESENCE control — the scan really does find the tokens where they
    // ARE, so the emptiness above is not a broken grep.
    assert!(
        allowed_hits >= 10,
        "the scan found only {allowed_hits} hits in the allowlisted files; \
         it is not actually matching the decider tokens"
    );
}
