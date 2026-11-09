// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Seeded credential-class guard: new boundary findings extend this table.

#[allow(dead_code)]
#[path = "common/operator_log_capture.rs"]
mod operator_capture;

const CASE_COUNT: usize = 3_960;
const SECRET_WINDOW: usize = 4;
const SEED: u64 = 8_205;
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const LCG_INCREMENT: u64 = 1;
const FORM_COUNT: usize = 9;
const HOST: &str = "db.example.invalid";
const PREFIX: &str = "connection attempt: ";
// Integration cost guard: gross absolute backstops only (>= 10x the measured
// debug cost), so host load cannot trip them while a rescan (about 20 s at 100K)
// still does. No clock ratio: under a parallel run it measures the scheduler.
// The x10 work ratio is pinned without clocks by the lib tests
// `logging::scan_work_tests` for every shape below (#8674).
const COST_SAMPLES: usize = 3;
const RUN_SMALL_BYTES_8674: usize = 100_000;
const RUN_LARGE_BYTES_8674: usize = 1_000_000;
const RUN_SMALL_CEILING_8674: std::time::Duration = std::time::Duration::from_millis(2_500);
const RUN_LARGE_CEILING_8674: std::time::Duration = std::time::Duration::from_secs(25);
const RUN_SHAPES_8674: &[&str] = &[
    "http://u@a)",
    "http://u:p@a)",
    "http://a)",
    "http://u@a'",
    "http://user@b)",
    "http://u@a>",
    "http://u@a:80)",
];
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
    "session",
    "cookie",
    "jwt",
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

fn minimum_masking_cost(detail: &str) -> std::time::Duration {
    (0..COST_SAMPLES)
        .map(|_| {
            let started = std::time::Instant::now();
            std::hint::black_box(captured_detail(std::hint::black_box(detail)));
            started.elapsed()
        })
        .min()
        .expect("the named cost sample count is positive")
}

#[test]
fn suppressed_foreign_log_url_cost_8674() {
    // No environment write or subscriber installation: the work before the
    // tracing macro must remain bounded even when that macro emits nothing.
    for shape in RUN_SHAPES_8674 {
        for bytes in [RUN_SMALL_BYTES_8674, RUN_LARGE_BYTES_8674] {
            let input = shape.repeat(bytes.div_ceil(shape.len()));
            let cost = (0..COST_SAMPLES)
                .map(|_| {
                    let error = anyhow::anyhow!(input.clone());
                    let started = std::time::Instant::now();
                    std::hint::black_box(ai_memory::mcp::error_text::log_foreign(
                        "url_cost_8674",
                        error,
                    ));
                    started.elapsed()
                })
                .min()
                .expect("positive cost sample count");
            let ceiling = if bytes == RUN_SMALL_BYTES_8674 {
                RUN_SMALL_CEILING_8674
            } else {
                RUN_LARGE_CEILING_8674
            };
            println!(
                "#8674 log_foreign shape={shape:?} bytes={} minimum={cost:?}",
                input.len()
            );
            assert!(
                cost < ceiling,
                "#8674: foreign log cost {cost:?} exceeds {ceiling:?}"
            );
        }
    }
}

/// One 1M-byte diagnostic through the captured operator line stays under the
/// gross backstop; its x10 work ratio is the lib op-count test of the same shape.
fn assert_masking_cost_bounded(label: &str, prefix: &str, piece: &str) {
    let count = RUN_LARGE_BYTES_8674.div_ceil(piece.len());
    let detail = format!("{PREFIX}{prefix}{}", piece.repeat(count));
    let cost = minimum_masking_cost(&detail);
    println!("{label}: bytes={}, minimum_time={cost:?}", detail.len());
    assert!(
        cost < RUN_LARGE_CEILING_8674,
        "{label}: masking cost {cost:?} exceeds {RUN_LARGE_CEILING_8674:?}"
    );
}

#[test]
fn url_cost_runtime_8205_r7() {
    assert_masking_cost_bounded("F5 URL authority", "https://", ":");
}

#[test]
fn credential_cost_runtime_8205_r7() {
    assert_masking_cost_bounded("F5 credential lines", "", "password=x\n");
}

#[test]
fn bare_target_cost_runtime_8205_r7() {
    assert_masking_cost_bounded("F5 bare-target control", "", "u:p@h x\n");
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
            "{label}: four-byte secret window survived: {window:?}"
        );
    }
    line
}

#[test]
fn unterminated_and_unquoted_values_mask_complete_span_8205() {
    for value in [
        "credentialA Z1Z2Z3Z4Z5",
        "'credentialA Z1Z2Z3Z4Z5",
        "\"credentialA\nZ1Z2Z3Z4Z5",
        "credentialA x=Z1Z2Z3Z4Z5",
    ] {
        assert_private(&format!("{PREFIX}password={value}"), "Z1Z2Z3Z4Z5", "N1");
    }
}

#[test]
fn empty_account_lookahead_masks_secret_tail_8205() {
    let line = assert_private(
        &format!("{PREFIX}postgres://:credentialA Z1Z2Z3Z4Z5@{HOST}"),
        "Z1Z2Z3Z4Z5",
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
                &format!("{PREFIX}{key}{separator} credentialA Z1Z2Z3Z4Z5"),
                "Z1Z2Z3Z4Z5",
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
    assert_eq!(
        CASE_COUNT,
        KEYS.len() * FORM_COUNT * SEPARATORS.len() * 2,
        "every key, form, separator and assignment operator must execute"
    );
    let mut state = SEED;
    for case in 0..CASE_COUNT {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        // Every four-byte window contains Z, absent from the captured-log framing.
        let secret: String = format!("{state:016x}")
            .chars()
            .flat_map(|ch| ['Z', ch])
            .collect();
        let split = SEPARATORS[(case / (KEYS.len() * FORM_COUNT)) % SEPARATORS.len()];
        let payload = format!("{secret}{split}{secret}");
        let key = KEYS[case % KEYS.len()];
        let separator = if (case / (KEYS.len() * FORM_COUNT * SEPARATORS.len())).is_multiple_of(2) {
            '='
        } else {
            ':'
        };
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
            5 => (format!("{PREFIX}postgres://account:{payload}"), false),
            6 => (format!("{PREFIX}postgres://account:{payload}@{HOST}"), true),
            7 => (format!("{PREFIX}postgres://:{payload}"), false),
            _ => (
                format!("{PREFIX}postgres://account:{secret}@middle{split}{secret}@{HOST}"),
                true,
            ),
        };
        let line = assert_private(&detail, &secret, &format!("ratchet case {case}"));
        if host_expected {
            assert!(line.contains(HOST), "ratchet case {case}: URL host lost");
        }
    }
}

#[test]
fn url_query_and_path_credential_tails_8205() {
    for location in ["?password=", "/token=", "#password="] {
        for separator in ["'", "\"", ")", ">", " ", "\t"] {
            assert_private(
                &format!("{PREFIX}https://{HOST}{location}credentialA{separator}Z1Z2Z3Z4Z5"),
                "Z1Z2Z3Z4Z5",
                "S1 URL credential boundary",
            );
        }
    }
}

#[test]
fn userinfo_at_sign_before_whitespace_tail_8205() {
    assert_private(
        &format!("{PREFIX}postgres://account:prefix@middle Z1Z2Z3Z4Z5@{HOST}"),
        "Z1Z2Z3Z4Z5",
        "C3 userinfo at-sign",
    );
}

#[test]
fn schemeless_whitespace_password_8205() {
    for account in ["account", "account@realm", ""] {
        assert_private(
            &format!("{PREFIX}{account}:credentialA Z1Z2Z3Z4Z5@{HOST} refused"),
            "Z1Z2Z3Z4Z5",
            "S3 bare authority",
        );
    }
}

#[test]
fn unicode_keys_and_session_nouns_8205() {
    for key in [
        "pass‐word",
        "pass‑word",
        "pass–word",
        "pass−word",
        "ｐａｓｓｗｏｒｄ",
        "session",
        "session_id",
        "cookie",
        "jwt",
    ] {
        for separator in ["=", ":", "＝", "："] {
            assert_private(
                &format!("{PREFIX}{key}{separator}Z1Z2Z3Z4Z5"),
                "Z1Z2Z3Z4Z5",
                "S4 normalized key",
            );
        }
    }
}

#[test]
fn hyphen_inside_credential_noun_is_normalized_8205() {
    for key in ["pass-word", "api-key", "creden-tial", "au-th"] {
        assert_private(
            &format!("{PREFIX}{key}=Z1Z2Z3Z4Z5"),
            "Z1Z2Z3Z4Z5",
            "S5 hyphen inside noun",
        );
    }
}

#[test]
fn credential_shaped_fragment_colon_owns_its_value_8205() {
    let detail = format!(
        "{PREFIX}https://{HOST}/x#fragment_credential_8205: connect https://inner.example.invalid/path"
    );
    let line = captured_detail(&detail);
    assert!(line.contains(HOST), "fragment origin must remain readable");
    assert!(
        !line.contains("inner.example.invalid"),
        "ruling 6717162013: a recognized credential key owns the rest of its line"
    );
}

#[test]
fn format_control_keys_are_private_8205_r7() {
    for key in [
        "pass\u{ad}word",
        "pass\u{200b}word",
        "pass\u{2060}word",
        "pass\u{feff}word",
    ] {
        assert_private(
            &format!("{PREFIX}{key}=Z1Z2Z3Z4Z5"),
            "Z1Z2Z3Z4Z5",
            &format!("F3 format-control key {key:?}"),
        );
    }
}

#[test]
fn mathematical_keys_are_private_8205_r7() {
    // Literal glyphs are independent of the production range arithmetic.
    for key in [
        "𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝",
        "𝑝𝑎𝑠𝑠𝑤𝑜𝑟𝑑",
        "𝒑𝒂𝒔𝒔𝒘𝒐𝒓𝒅",
        "𝓅𝒶𝓈𝓈𝓌ℴ𝓇𝒹",
        "𝓹𝓪𝓼𝓼𝔀𝓸𝓻𝓭",
        "𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡",
        "𝕡𝕒𝕤𝕤𝕨𝕠𝕣𝕕",
        "𝖕𝖆𝖘𝖘𝖜𝖔𝖗𝖉",
        "𝗉𝖺𝗌𝗌𝗐𝗈𝗋𝖽",
        "𝗽𝗮𝘀𝘀𝘄𝗼𝗿𝗱",
        "𝘱𝘢𝘴𝘴𝘸𝘰𝘳𝘥",
        "𝙥𝙖𝙨𝙨𝙬𝙤𝙧𝙙",
        "𝚙𝚊𝚜𝚜𝚠𝚘𝚛𝚍",
        "𝐏𝐀𝐒𝐒𝐖𝐎𝐑𝐃",
        "ℙ𝔸𝕊𝕊𝕎𝕆ℝ𝔻",
    ] {
        assert_private(
            &format!("{PREFIX}{key}=Z1Z2Z3Z4Z5"),
            "Z1Z2Z3Z4Z5",
            &format!("F3 mathematical key {key:?}"),
        );
    }
}

#[test]
fn quoted_url_value_does_not_own_the_next_key_8205_r7() {
    let detail = format!("{PREFIX}password=\"https://db.example.invalid:443\" token=Z1Z2Z3Z4Z5");
    let line = assert_private(&detail, "Z1Z2Z3Z4Z5", "quoted URL followed by credential");
    assert!(
        line.contains("password=**** token=****"),
        "both credential values must be independently masked: {line}"
    );
}
