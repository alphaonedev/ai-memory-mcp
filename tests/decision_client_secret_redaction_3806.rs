// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(clippy::doc_markdown, clippy::field_reassign_with_default)]
//! #3806 W1c — the `[decision]` credential never reaches a `Debug`
//! render or a log line.
//!
//! **Why this lives in its own test binary.** `tracing` caches callsite
//! interest GLOBALLY per process. A sibling test that drives the same
//! `warn!` callsite with no subscriber installed can cache it as
//! "never", after which a thread-local `set_default` in this test
//! silently captures nothing and the assertions pass vacuously. One
//! process, one `set_global_default`, one test — so the presence control
//! ("the refusal IS observable") is real evidence rather than a race.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::AppConfig;
use ai_memory::decision::{AbstainReason, DecisionProvider};
use ai_memory::decision_clients::OutboundCheck;
use ai_memory::decision_clients::chat::OpenAiCompatibleDecider;
use ai_memory::decision_config::{DecisionFallback, DecisionSection, resolve_decision};

/// The credential this pin proves never escapes.
const SECRET: &str = "sk-w1c-integration-credential-3806";
/// A token in the URL query — the #3688 leak shape a plain
/// password-masking redactor would let through untouched.
const QUERY_TOKEN: &str = "leaky-query-3806";

#[derive(Clone, Default)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_credential_never_reaches_a_debug_render_or_a_log_line() {
    let sink = CapturedLog::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("one subscriber, installed once, in this binary");

    // A mode-0400 key file, so the real credential ladder resolves a real
    // secret rather than `None` (which would make every assertion below
    // vacuous).
    let mut key_file = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(key_file, "{SECRET}").expect("write key");
    key_file.flush().expect("flush key");
    std::fs::set_permissions(key_file.path(), std::fs::Permissions::from_mode(0o400))
        .expect("chmod 0400");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"role": "assistant", "content": "{\"verdict\":\"yes\"}"}}]
        })))
        .mount(&server)
        .await;

    let mut cfg = AppConfig::default();
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(format!("{}/v1?token={QUERY_TOKEN}", server.uri())),
        api_key_env: None,
        api_key_file: key_file.path().to_str().map(str::to_string),
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(DecisionFallback::Abstain),
    });
    let resolved = resolve_decision(&cfg).expect("a complete [decision] section resolves");

    // PRESENCE control: the ladder really did load the secret, so the
    // absence assertions below are about redaction and not about an
    // empty credential.
    assert_eq!(
        resolved.api_key(),
        Some(SECRET),
        "the key file must resolve, or this pin proves nothing"
    );

    let refusing: OutboundCheck = Arc::new(|_| Err(anyhow::anyhow!("egress posture refused")));
    let decider = OpenAiCompatibleDecider::new(&resolved, refusing).expect("client constructs");
    assert!(
        decider.has_credential(),
        "presence control: the client holds the credential"
    );

    let rendered = format!("{decider:?} {decider:#?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug leaked the credential: {rendered}"
    );
    assert!(
        !rendered.contains(QUERY_TOKEN),
        "Debug leaked the URL query: {rendered}"
    );
    assert!(
        rendered.contains(ai_memory::REDACTED_PLACEHOLDER),
        "Debug must still say a credential is present: {rendered}"
    );
    assert!(
        !format!("{resolved:?}").contains(SECRET),
        "the resolved section's Debug leaked the credential"
    );

    // The refusal log line: our own words, the redacted origin, and
    // nothing of the credential or of the query.
    let judgement = decider.judge("do these two records conflict?").await;
    assert_eq!(
        judgement.abstain_reason(),
        Some(AbstainReason::EgressRefused),
        "the refusal must have actually happened"
    );

    let logged = String::from_utf8(sink.0.lock().expect("log lock").clone()).expect("utf8 log");
    assert!(
        logged.contains("refused by the outbound egress check"),
        "presence control: the refusal must be OBSERVABLE, got {logged:?}"
    );
    assert!(
        !logged.contains(SECRET),
        "the log line leaked the credential: {logged}"
    );
    assert!(
        !logged.contains(QUERY_TOKEN),
        "the log line leaked the URL query: {logged}"
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("wiremock records requests")
            .len(),
        0,
        "and the refused call never reached the endpoint"
    );
}
