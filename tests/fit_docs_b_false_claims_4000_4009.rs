//! FIT docs-B false claims, issues #4000-#4009: each cell pins one shipped
//! reference sentence to the behaviour the code has today.
//!
//! This file re-lands the #4006 row only (lost commit `ea27e5b0e9a8`, #9017);
//! the other rows re-land through their own lanes.

use std::path::PathBuf;

/// Repository root of the crate under test.
fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// `rel` read and whitespace-flattened, so a re-wrapped paragraph never
/// hides or forges a pinned phrase.
fn flat_text(rel: &str) -> String {
    let path = repo_path(rel);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whitespace-flatten a needle the same way as [`flat_text`].
fn flat_needle(needle: &str) -> String {
    needle.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_present(rel: &str, needle: &str, issue: &str) {
    let needle = flat_needle(needle);
    assert!(
        flat_text(rel).contains(&needle),
        "{issue}: {rel} must contain {needle:?}"
    );
}

fn assert_absent(rel: &str, needle: &str, issue: &str) {
    let needle = flat_needle(needle);
    assert!(
        !flat_text(rel).contains(&needle),
        "{issue}: {rel} must not contain {needle:?}"
    );
}

/// #4006 — `ai-memory tls init|import|status` ship in v1.0.0 (unconditionally
/// registered, `src/cli/tls.rs`); the references must not defer them to
/// v1.0.1, and must not tell operators rotation needs an unshipped verb.
#[test]
fn tls_verbs_are_not_deferred_to_v1_0_1_4006() {
    const ISSUE: &str = "#4006";
    // Premise anchor: the verbs exist.
    for verb in ["Init {", "Import {", "Status,"] {
        assert_present("src/cli/tls.rs", verb, ISSUE);
    }
    assert_absent(
        "docs/CLI_REFERENCE.md",
        "init|import|renew` and `ai-memory db check-tls` verbs are v1.0.1",
        ISSUE,
    );
    assert_absent(
        "docs/SECURITY.md",
        "init|import|renew` and `ai-memory db check-tls` verbs",
        ISSUE,
    );
    assert_absent(
        "docs/SECURITY.md",
        "an `ai-memory tls import` verb is #3709 item 2, v1.0.1",
        ISSUE,
    );
    for rel in ["docs/CLI_REFERENCE.md", "docs/SECURITY.md"] {
        assert_present(
            rel,
            "v1.0.0 ships `ai-memory tls init`, `tls import`, and `tls status`",
            ISSUE,
        );
    }
    assert_absent("src/daemon_runtime.rs", "flags = plain HTTP", ISSUE);
}

/// The two operator references the #9017 cells scan for false default claims.
const DEFAULT_CLAIM_DOCS: [&str; 2] = ["docs/SECURITY.md", "docs/CLI_REFERENCE.md"];

/// Forms of the false "authenticated / encrypted / hot-reloaded by default"
/// claim (#9017). Lowercased; each is scanned over both references after
/// whitespace flattening, so a re-wrap cannot hide one.
const FALSE_DEFAULT_CLAIM_FORMS: [&str; 10] = [
    "authentication is on by default",
    "trusts no one by default",
    "api key + mtls gate inbound",
    "is refused on every host",
    "falls back to plain http",
    "without a restart",
    "a peer without an authorised cert can't even open a tcp connection",
    // Amendment 2 (security r1 addendum): the sync gate is peer enrollment
    // (#1789), not the allowlist, and an unsigned write is refused.
    "trusts peers on the mtls allowlist",
    "accept any client",
    "can read and write",
];

/// Sentences `docs/SECURITY.md` must carry for the real default (#9017).
const SECURITY_MD_DEFAULT_SENTENCES: [&str; 16] = [
    "`resolve_tls_material` in `bootstrap_serve` (then `tls_bind_guard`)",
    "with neither flag a singleton serves the local-CA material it generates and renews, or \
     operator material installed by `ai-memory tls import`",
    "then restart `serve` (#4006): operator material is read once at boot",
    "Only the local-CA material of a singleton is renewed by the daemon itself",
    "`serve` binds `127.0.0.1` by default and demands an API key only when top-level `api_key` \
     is set in `config.toml`; nothing sets one by default.",
    "a keyless bind to a loopback address serves, and the boot logs these two WARN lines (verbatim):",
    "a keyless bind to a non-loopback address is refused at boot",
    "with `AI_MEMORY_REQUIRE_API_KEY=1` a keyless bind is refused on every address, loopback \
     included",
    "client certificates apply only when `--mtls-allowlist` is passed",
    // What an unauthenticated local client gets, as the E-e keyless loopback
    // probe recorded it (each status is a probe line in the PR body).
    "on the default configuration an unauthenticated local client can read: \
     `GET /api/v1/memories` answers 200 with no header at all.",
    "a local client that names an agent in the self-asserted `X-Agent-Id` header can also \
     link and delete that agent's memories (`POST /api/v1/links` 201, \
     `DELETE /api/v1/memories/{id}` 200)",
    "An unsigned `POST /api/v1/memories` is refused `403 ATTESTATION_FAILED`",
    "attestation and enrollment are not authentication; the default-on API key is #2046",
    // Peer sync: the default gate is enrollment (#1789), not the allowlist.
    "by default `/api/v1/sync/push` and `/api/v1/sync/since` refuse a peer that is not \
     enrolled (`401 peer_not_enrolled`, #1789; `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` \
     lifts that gate)",
    "With `--mtls-allowlist` set, the TLS handshake also refuses a client without an \
     allowlisted certificate; without it the TLS transport requests no client certificate",
    "When `api_key` is set, every HTTP endpoint except `/api/v1/health` enforces the key",
];

/// Sentences `docs/CLI_REFERENCE.md` `serve` must carry (#9017).
const CLI_REFERENCE_DEFAULT_SENTENCES: [&str; 7] = [
    "Without `api_key` the daemon authenticates no HTTP request: a keyless loopback bind serves \
     and logs a WARN, a keyless non-loopback bind is refused at boot (exit 75), and \
     `AI_MEMORY_REQUIRE_API_KEY=1` refuses a keyless bind on every address.",
    "On a declared non-singleton shape (`[deployment] shape` = team / production / federated / \
     hive, per #3700)",
    "the TLS handshake fails for a client without an allowlisted certificate; the gate is the \
     handshake, not TCP accept",
    "a non-loopback bind also needs top-level `api_key` in `config.toml` (without it `serve` \
     exits 75)",
    "--peers https://peer-a:9077,https://peer-b:9077",
    "Without it no client certificate is requested and `serve` logs a WARN; the sync \
     endpoints still refuse a peer that is not enrolled (#1789)",
    "The default-on API key is #2046",
];

/// #9017 — `docs/SECURITY.md` and `docs/CLI_REFERENCE.md` state the real
/// `serve` default: loopback, no API key unless `api_key` is set, keyless
/// loopback serves with a WARN, keyless non-loopback exits 75, mTLS only with
/// `--mtls-allowlist`, operator TLS material needs a restart.
#[test]
fn security_and_cli_reference_state_the_real_default_9017() {
    const ISSUE: &str = "#9017";
    for sentence in SECURITY_MD_DEFAULT_SENTENCES {
        assert_present("docs/SECURITY.md", sentence, ISSUE);
    }
    for sentence in CLI_REFERENCE_DEFAULT_SENTENCES {
        assert_present("docs/CLI_REFERENCE.md", sentence, ISSUE);
    }
    assert_absent(
        "docs/SECURITY.md",
        "a bind without `--tls-cert` + `--tls-key` is REFUSED on every host",
        ISSUE,
    );
    assert_absent(
        "docs/CLI_REFERENCE.md",
        "On a FLEET-shaped deployment (production / federated / hive",
        ISSUE,
    );
    assert_absent("docs/CLI_REFERENCE.md", "Axum-based HTTP daemon", ISSUE);
    for rel in DEFAULT_CLAIM_DOCS {
        let lowered = flat_text(rel).to_lowercase();
        for form in FALSE_DEFAULT_CLAIM_FORMS {
            assert!(
                !lowered.contains(form),
                "{ISSUE}: {rel} carries the false default claim form {form:?}"
            );
        }
    }
}

/// Finding id of the first false default claim form in `lowered` (already
/// lowercased and whitespace-flattened), or `None` when the text is clean.
fn false_claim_form(lowered: &str) -> Option<&'static str> {
    FALSE_DEFAULT_CLAIM_FORMS
        .into_iter()
        .find(|form| lowered.contains(form))
}

/// Verb inflections of "accept" the false claim "sync accepts any client"
/// must be caught in (R2-L1, class: a literal phrase list pins one inflection).
const ACCEPT_INFLECTIONS: [&str; 4] = ["accept", "accepts", "accepted", "accepting"];

/// Object nouns of the "accept any ..." claim with the form id each maps to.
const ACCEPT_OBJECTS: [(&str, &str); 4] = [
    ("client", "accept any client"),
    ("clients", "accept any client"),
    ("peer", "accept any peer"),
    ("peers", "accept any peer"),
];

/// Hand-written inflected mutants of the other forms: `(sentence, form id)`.
const FALSE_DEFAULT_CLAIM_MUTANTS: [(&str, &str); 11] = [
    (
        "The daemon trust no one by default.",
        "trusts no one by default",
    ),
    (
        "The daemon trusted no one by default.",
        "trusts no one by default",
    ),
    (
        "The daemon falls back to plain HTTP.",
        "falls back to plain http",
    ),
    (
        "The daemon is falling back to plain HTTP.",
        "falls back to plain http",
    ),
    (
        "A keyless bind is refusing on every host.",
        "is refused on every host",
    ),
    (
        "API key + mTLS gates inbound traffic.",
        "api key + mtls gate inbound",
    ),
    (
        "It trusted peers on the mTLS allowlist.",
        "trusts peers on the mtls allowlist",
    ),
    (
        "It trusts peer on the mTLS allowlist.",
        "trusts peers on the mtls allowlist",
    ),
    (
        "An API key is required on loopback.",
        "required on loopback",
    ),
    ("API keys are required on loopback.", "required on loopback"),
    ("A key is requiring on loopback.", "required on loopback"),
];

/// Sentences that must stay legal: the quoted WARN text and the true
/// sentences the references carry today (over-matching guard).
const LEGAL_DEFAULT_SENTENCES: [&str; 6] = [
    "Privileged endpoints (POST /memories, /links, /agents, /subscriptions) accept any caller \
     that reaches this listener.",
    "TLS enabled but mTLS NOT configured: no client certificate is requested, so the TLS \
     transport admits any client; the sync endpoints still refuse a peer that is not enrolled.",
    "serve never serves plaintext HTTP.",
    "a keyless bind to a non-loopback address is refused at boot",
    "with AI_MEMORY_REQUIRE_API_KEY=1 a keyless bind is refused on every address, loopback \
     included",
    "the TLS handshake also refuses a client without an allowlisted certificate",
];

/// Time ceiling for scanning a 1 MiB input (linear scan, generous for CI).
const SCAN_CEILING: std::time::Duration = std::time::Duration::from_secs(5);

/// Size of the scan-bound input, bytes.
const SCAN_INPUT_BYTES: usize = 1 << 20;

fn flat_lower(sentence: &str) -> String {
    flat_needle(sentence).to_lowercase()
}

/// R2-L1 — every inflection of every false-claim form is a finding with its
/// exact form id.
#[test]
fn false_default_claim_inflections_are_findings_r2_l1() {
    for verb in ACCEPT_INFLECTIONS {
        for (noun, form) in ACCEPT_OBJECTS {
            let sentence = format!("Without an allowlist, sync {verb} any {noun}.");
            assert_eq!(
                false_claim_form(&flat_lower(&sentence)),
                Some(form),
                "R2-L1: {sentence:?} must be a finding"
            );
        }
    }
    for (sentence, form) in FALSE_DEFAULT_CLAIM_MUTANTS {
        assert_eq!(
            false_claim_form(&flat_lower(sentence)),
            Some(form),
            "R2-L1: {sentence:?} must be a finding"
        );
    }
}

/// R2-L1 — the legal text stays legal, and the scan is linear on a 1 MiB input.
#[test]
fn legal_default_sentences_are_not_findings_and_scan_is_bounded_r2_l1() {
    for sentence in LEGAL_DEFAULT_SENTENCES {
        assert_eq!(
            false_claim_form(&flat_lower(sentence)),
            None,
            "R2-L1: {sentence:?} must stay legal"
        );
    }
    let unit = "the daemon accepts a signed request from an enrolled peer. ";
    let big = unit.repeat(SCAN_INPUT_BYTES / unit.len());
    let start = std::time::Instant::now();
    assert_eq!(false_claim_form(&big), None);
    let tail = format!("{big}sync accepts any client.");
    assert_eq!(false_claim_form(&tail), Some("accept any client"));
    assert!(
        start.elapsed() < SCAN_CEILING,
        "R2-L1: 1 MiB scan took {:?}",
        start.elapsed()
    );
}
