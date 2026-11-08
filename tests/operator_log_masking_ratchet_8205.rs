// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Seeded credential-class guard: new boundary findings extend this table.

#[allow(dead_code)]
#[path = "common/operator_log_capture.rs"]
mod operator_capture;

const CASE_COUNT: usize = 2_400;
const SECRET_WINDOW: usize = 4;
const SEED: u64 = 8_205;
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const LCG_INCREMENT: u64 = 1;
const FORM_COUNT: usize = 6;
const HOST: &str = "db.example.invalid";
const PREFIX: &str = "connection attempt: ";
const KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "pw",
    "secret",
    "token",
    "apikey",
    "apisecret",
    "credential",
    "authorization",
    "authtoken",
    "bearer",
    "accesskey",
    "secretkey",
    "privatekey",
    "clientsecret",
    "key",
    "auth",
];
const SEPARATORS: &[&str] = &[
    " ", "\t", "'", "\"", "(", ")", "<", ">", "\u{a0}", "\u{2003}",
];

fn captured_detail(detail: &str) -> String {
    operator_capture::captured(|| {
        ai_memory::mcp::error_text::log_foreign(
            "masking_class_8205",
            anyhow::anyhow!(detail.to_owned()),
        )
    })
    .1
}

fn assert_private(detail: &str, secret: &str, label: &str) -> String {
    let line = captured_detail(detail);
    assert!(line.contains(PREFIX), "{label}: diagnostic prefix lost");
    assert!(
        line.contains("****") || (detail.contains("://") && line.contains(HOST)),
        "{label}: neither a mask nor the retained URL origin is present"
    );
    for window in secret.as_bytes().windows(SECRET_WINDOW) {
        assert!(
            !line
                .as_bytes()
                .windows(SECRET_WINDOW)
                .any(|candidate| candidate == window),
            "{label}: four-byte secret window survived"
        );
    }
    line
}

#[test]
fn unterminated_and_unquoted_values_mask_complete_span_8205() {
    for value in [
        "credentialA tailSecret",
        "'credentialA tailSecret",
        "\"credentialA\ntailSecret",
        "credentialA x=tailSecret",
    ] {
        assert_private(&format!("{PREFIX}password={value}"), "tailSecret", "N1");
    }
}

#[test]
fn empty_account_lookahead_masks_secret_tail_8205() {
    let line = assert_private(
        &format!("{PREFIX}postgres://:credentialA tailSecret@{HOST}"),
        "tailSecret",
        "N2",
    );
    assert!(line.contains(HOST), "N2: host lost");
}

#[test]
fn normalized_compound_keys_and_colon_are_credentials_8205() {
    for key in [
        "DB-PassWord",
        "MY_CLIENT_SECRET",
        "Authorization",
        "token",
        "key",
        "auth",
    ] {
        for separator in [":", "="] {
            assert_private(
                &format!("{PREFIX}{key}{separator} credentialA tailSecret"),
                "tailSecret",
                "N3",
            );
        }
    }
    for key in ["sslkey", "author", "keyspace", "primary_key"] {
        let detail = format!("{PREFIX}{key}=diagnostic");
        assert!(
            captured_detail(&detail).contains(&detail),
            "N3: harmless key {key} changed"
        );
    }
}

#[test]
fn keyless_url_terminators_preserve_origin_8205() {
    for terminator in ['\'', ')', '>'] {
        let detail = format!("{PREFIX}https://{HOST}{terminator} later");
        let line = captured_detail(&detail);
        assert!(
            line.contains(&format!("https://{HOST}{terminator}")),
            "N4: URL terminator {terminator} lost its origin"
        );
        assert!(line.contains("later"), "N4: suffix lost");
    }
}

#[test]
fn ambiguous_agent_authority_stays_masked_8205() {
    let line = captured_detail(&format!("{PREFIX}ai:client@host"));
    assert!(line.contains("****"), "r4-1: settled authority mask absent");
    assert!(
        !line.contains("client@host"),
        "r4-1: authority exemption appeared"
    );
}

#[test]
fn seeded_masking_class_ratchet_8205() {
    let mut state = SEED;
    for case in 0..CASE_COUNT {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        let secret = format!("Q{:016x}Z", state);
        let split = SEPARATORS[(case / (KEYS.len() * FORM_COUNT)) % SEPARATORS.len()];
        let payload = format!("{secret}{split}{secret}");
        let key = KEYS[case % KEYS.len()];
        let separator = if case % 2 == 0 { '=' } else { ':' };
        let compound = if matches!(key, "key" | "auth") {
            key.to_owned()
        } else {
            format!("MY-{key}_VALUE")
        };
        let (detail, host_expected) = match (case / KEYS.len()) % FORM_COUNT {
            0 => (
                format!("{PREFIX}{compound}{separator}{payload} other=tail"),
                false,
            ),
            1 => (
                format!("{PREFIX}'{key}'{separator}'{secret}\n{secret}' after"),
                false,
            ),
            2 => (
                format!("{PREFIX}\"{key}\"{separator}\"{secret}\n{secret}\" after"),
                false,
            ),
            3 => (
                format!("{PREFIX}{key}{separator}'{}", payload.replace('\'', "\\'")),
                false,
            ),
            4 => (format!("{PREFIX}postgres://:{payload}@{HOST}"), true),
            _ => (format!("{PREFIX}postgres://account:{payload}"), false),
        };
        let line = assert_private(&detail, &secret, &format!("ratchet case {case}"));
        if host_expected {
            assert!(line.contains(HOST), "ratchet case {case}: URL host lost");
        }
    }
}
