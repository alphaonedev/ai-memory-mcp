// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator diagnostics retain causes while keeping caller text unchanged.

#[path = "common/operator_log_capture.rs"]
mod operator_capture;
use operator_capture::captured;

use ai_memory::mcp::error_text::{DB_ERROR_TEXT, log_foreign, mcp_error_text, mcp_foreign_err};

#[test]
fn operator_log_keeps_full_chain_6457() {
    const INNER: &str = "root storage failure 6457";
    const OUTER: &str = "loading reflection links";
    for direct in [false, true] {
        let error = anyhow::anyhow!(INNER).context(OUTER);
        let (wire, log) = captured(|| {
            if direct {
                mcp_error_text(&log_foreign("chain_probe", error))
            } else {
                mcp_foreign_err("chain_probe", error)
            }
        });
        assert_eq!(wire, DB_ERROR_TEXT);
        assert!(log.contains(OUTER), "outer context absent: {log}");
        assert!(log.contains(INNER), "inner cause absent: {log}");
    }
}

#[test]
fn operator_log_escapes_caller_controls_6822() {
    let hostile = operator_capture::hostile_detail();
    for foreign in [false, true] {
        let error = if foreign {
            ai_memory::errors::MemoryError::DatabaseError(hostile.clone())
        } else {
            ai_memory::errors::MemoryError::Refused(hostile.clone())
        };
        let (wire, log) = captured(|| mcp_foreign_err("control_probe", error));
        assert_eq!(wire, if foreign { DB_ERROR_TEXT } else { &hostile });
        assert_eq!(log.lines().count(), 1, "one operator event: {log:?}");
        let line = log.strip_suffix("\n").expect("text event newline");
        assert!(!line.chars().any(char::is_control), "raw control: {log:?}");
        for &(raw, control) in operator_capture::CONTROL_PAIRS {
            assert!(
                !line.contains(raw),
                "raw U+{:04X} in operator detail",
                u32::from(raw)
            );
            assert!(line.contains(control), "missing {control}: {log:?}");
        }
        assert!(
            !line.contains(operator_capture::FIXTURE_PASSWORD),
            "password reached operator detail"
        );
        assert!(
            !line.contains(operator_capture::FIXTURE_QUERY),
            "query credential reached operator detail"
        );
        assert!(
            !line.contains(operator_capture::FIXTURE_FRAGMENT),
            "fragment credential reached operator detail"
        );
        assert!(
            line.contains("https://example.invalid"),
            "URL origin absent"
        );
        assert!(!line.contains("/path"), "URL path reached operator detail");
    }
}

#[test]
fn operator_contexts_name_operations_6894() {
    let sites = [
        (
            include_str!("../src/mcp/tools/subscribe.rs"),
            "log_foreign(\"subscription_insert\"",
        ),
        (
            include_str!("../src/mcp/tools/kg_invalidate.rs"),
            "mcp_foreign_err(\"invalidate_link\"",
        ),
        (
            include_str!("../src/mcp/tools/action.rs"),
            "mcp_foreign_err(\"action_transition\"",
        ),
        (
            include_str!("../src/mcp/tools/store/validation.rs"),
            "mcp_foreign_err(\"find_by_title_namespace\"",
        ),
        (
            include_str!("../src/mcp/tools/get_taxonomy.rs"),
            "mcp_foreign_err(\"get_taxonomy\"",
        ),
        (
            include_str!("../src/mcp/tools/skill_promote.rs"),
            "mcp_foreign_err(\"skill_promote_from_reflection\"",
        ),
    ];
    for (source, expected) in sites {
        let source: String = source.split_whitespace().collect();
        assert!(
            source.contains(expected),
            "missing operation label {expected}"
        );
        assert!(
            !source.contains("foreign_err(\"as_deref\""),
            "generic foreign-error label remains"
        );
        assert!(
            !source.contains("log_foreign(\"as_deref\""),
            "generic log label remains"
        );
    }
}

#[test]
fn dlq_list_operator_label_identifies_failed_call_7745() {
    use ai_memory::mcp::handle_subscription_dlq_list_for;
    use serde_json::json;
    let conn = rusqlite::Connection::open_in_memory().expect("database");
    let (result, log) =
        captured(|| handle_subscription_dlq_list_for(&conn, &json!({}), "agent-7745", &[]));
    assert!(
        result.is_err(),
        "fixture must exercise the storage error path"
    );
    assert!(
        log.contains("context=\"list_dlq\""),
        "wrong list operation: {log}"
    );
}

#[test]
fn dlq_owner_operator_label_identifies_failed_call_7745() {
    use ai_memory::mcp::handle_subscription_dlq_list_for;
    use serde_json::json;
    let conn = dlq_without_owner_table();
    let (result, log) = captured(|| {
        handle_subscription_dlq_list_for(
            &conn,
            &json!({"subscription_id": "sub-7745"}),
            "agent-7745",
            &[],
        )
    });
    assert!(
        result.is_err(),
        "fixture must exercise the storage error path"
    );
    assert!(
        log.contains("context=\"get_owner\""),
        "wrong owner operation: {log}"
    );
}

#[test]
fn dlq_unfiltered_owner_label_identifies_failed_call_7745() {
    use ai_memory::mcp::handle_subscription_dlq_list_for;
    use serde_json::json;
    let conn = dlq_without_owner_table();
    conn.execute(
        "INSERT INTO subscription_dlq VALUES (1, 'sub-7745', 'correlation-7745',
         'memory.stored', '{}', 0, 'fixture', '2026-01-01T00:00:00Z',
         '2026-01-01T00:00:00Z')",
        [],
    )
    .expect("ordinary DLQ row for the unfiltered owner lookup");
    let (result, log) =
        captured(|| handle_subscription_dlq_list_for(&conn, &json!({}), "agent-7745", &[]));
    assert!(
        result.is_err(),
        "fixture must exercise the storage error path"
    );
    assert!(
        log.contains("context=\"get_owner\""),
        "wrong unfiltered owner operation: {log}"
    );
}

fn dlq_without_owner_table() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("database");
    conn.execute_batch("CREATE TABLE subscription_dlq (id INTEGER, subscription_id TEXT, correlation_id TEXT, event_type TEXT, payload TEXT, retry_count INTEGER, last_error TEXT, first_failed_at TEXT, last_failed_at TEXT);")
        .expect("DLQ exists but owner table does not");
    conn
}

#[test]
fn operator_log_renders_only_url_origins_6822() {
    const QUERY_SECRET: &str = "query_credential_8205";
    const FRAGMENT_SECRET: &str = "fragment_fixture_8205";
    const PATH_SECRET: &str = "path_credential_8205";
    let inner =
        format!("connect https://query.example.invalid/{PATH_SECRET}?password={QUERY_SECRET}");
    for port in ["", ":9443"] {
        let outer = format!("fallback https://fragment.example.invalid{port}/x#{FRAGMENT_SECRET}");
        let (wire, log) = captured(|| {
            mcp_foreign_err(
                "url_chain_probe",
                anyhow::anyhow!(inner.clone()).context(outer),
            )
        });
        assert_eq!(wire, DB_ERROR_TEXT);
        for secret in [QUERY_SECRET, FRAGMENT_SECRET, PATH_SECRET] {
            assert!(!log.contains(secret), "URL credential reached operator log");
        }
        if port.is_empty() {
            assert!(
                log.contains("connect https://query.example.invalid"),
                "inner origin absent"
            );
            assert!(
                log.contains("fallback https://fragment.example.invalid"),
                "outer origin absent"
            );
        } else {
            // The voted rule treats a colon authority without an at-sign as credentialed.
            assert!(
                log.contains("fallback https://****"),
                "ambiguous authority not masked"
            );
            assert!(
                !log.contains("connect https://query.example.invalid"),
                "end-of-line mask stopped early"
            );
        }
        assert!(!log.contains("?password="), "query syntax reached log");
        assert_eq!(log.lines().count(), 1, "one operator event");
    }
}

const BOUNDARY_SECRET_8205: &str = "fixture_boundary_8205";

fn assert_private_detail_is_absent_8205(detail: &str, secret: &str) {
    for foreign in [false, true] {
        let error = if foreign {
            ai_memory::errors::MemoryError::DatabaseError(detail.to_owned())
        } else {
            ai_memory::errors::MemoryError::Refused(detail.to_owned())
        };
        let (_, log) = captured(|| mcp_foreign_err("credential_boundary", error));
        assert!(
            !log.contains(secret),
            "credential tail reached operator log"
        );
        assert_eq!(log.lines().count(), 1, "one operator event");
    }
}

macro_rules! query_boundary_case_8205 {
    ($name:ident, $separator:literal) => {
        #[test]
        fn $name() {
            let detail = format!(
                "connect https://query.example.invalid/x?token=prefix{}{BOUNDARY_SECRET_8205}",
                $separator
            );
            assert_private_detail_is_absent_8205(&detail, BOUNDARY_SECRET_8205);
        }
    };
}

query_boundary_case_8205!(operator_semicolon_query_8205, ";");
query_boundary_case_8205!(operator_comma_query_8205, ",");
query_boundary_case_8205!(operator_quote_query_8205, "\"");
query_boundary_case_8205!(operator_paren_query_8205, "(");

macro_rules! userinfo_boundary_case_8205 {
    ($name:ident, $separator:literal) => {
        #[test]
        fn $name() {
            let user = "fixture_user";
            let detail = format!(
                "connect postgres://{user}:prefix{}{BOUNDARY_SECRET_8205}@db.example.invalid/data",
                $separator
            );
            assert_private_detail_is_absent_8205(&detail, BOUNDARY_SECRET_8205);
        }
    };
}

userinfo_boundary_case_8205!(operator_paren_userinfo_8205, "(");
userinfo_boundary_case_8205!(operator_space_userinfo_8205, " ");

#[test]
fn operator_schemeless_connection_details_8205() {
    const SECRET: &str = "fixture_schemeless_8205";
    for detail in [
        format!("connect db.example.invalid:5432/path?token={SECRET}"),
        format!("connect db.example.invalid:5432/{SECRET}#fragment"),
        format!("connect db.example.invalid:5432/path#{SECRET}"),
        format!("connect host:port/path?token={SECRET}"),
        format!("host=db password={SECRET} port=5432"),
        format!("host=db password='{SECRET} with spaces' port=5432"),
        format!(r#"host=db password="{SECRET} with spaces" port=5432"#),
        format!("host=db password = '{SECRET} with spaces' port=5432"),
        format!("host=db sslpassword={SECRET} port=5432"),
    ] {
        assert_private_detail_is_absent_8205(&detail, SECRET);
    }
}

#[test]
fn operator_capture_fixture_contains_nul_8205() {
    assert!(
        operator_capture::CONTROL_PAIRS.contains(&('\0', "\\0")),
        "NUL pair absent"
    );
    assert!(
        operator_capture::hostile_detail().contains('\0'),
        "NUL absent from hostile fixture"
    );
}

fn detail_lines_8205(detail: &str) -> [String; 2] {
    [false, true].map(|foreign| {
        let error = if foreign {
            ai_memory::errors::MemoryError::DatabaseError(detail.to_owned())
        } else {
            ai_memory::errors::MemoryError::Refused(detail.to_owned())
        };
        captured(|| mcp_foreign_err("round_four_context", error)).1
    })
}

#[test]
fn operator_bare_authority_credentials_8205() {
    const SECRET: &str = "authority_fixture_8205";
    for suffix in ["db.example.invalid", "db.example.invalid:5432"] {
        let detail = format!("connect user:{SECRET}@{suffix} refused");
        for line in detail_lines_8205(&detail) {
            assert!(
                !line.contains(SECRET),
                "bare authority credential reached the sink"
            );
            assert!(
                line.contains(ai_memory::logging::URL_PASSWORD_MASK),
                "credential mask absent"
            );
            assert!(line.contains("refused"), "connection context lost");
        }
    }
}

#[test]
fn operator_bare_authority_last_at_credentials_8205() {
    const SECRET: &str = "last_at_authority_fixture_8205";
    for suffix in ["db.example.invalid", "db.example.invalid:5432"] {
        let detail = format!("connect account@realm:{SECRET}@{suffix} refused");
        for line in detail_lines_8205(&detail) {
            assert!(
                !line.contains(SECRET),
                "credential after an account at-sign reached the sink"
            );
            assert!(
                line.contains(ai_memory::logging::URL_PASSWORD_MASK),
                "credential mask absent"
            );
            assert!(line.contains("refused"), "connection context lost");
        }
    }
}

#[test]
fn operator_trailing_handle_context_survives_8205() {
    const CONTEXT: &str = "failed for agent bot@node later";
    let detail = format!("connect postgres://db.example.invalid {CONTEXT}");
    for line in detail_lines_8205(&detail) {
        assert!(
            line.contains(CONTEXT),
            "trailing handle swallowed operator context"
        );
    }
}

#[test]
fn operator_harmless_assignments_survive_8205() {
    for detail in [
        "limit=10 id=42 not found",
        "limit must be <= 100",
        "left == right",
        "arbitrary_option=diagnostic_value",
    ] {
        for line in detail_lines_8205(detail) {
            assert!(
                line.contains(&detail.escape_debug().to_string()),
                "harmless diagnostic changed"
            );
        }
    }
}

#[test]
fn operator_quoted_credential_keys_8205() {
    const SECRET: &str = "quoted_key_fixture_8205";
    for detail in [
        format!(r#"{{"password":"{SECRET}"}}"#),
        format!("'password': '{SECRET}'"),
        format!(r#""sslpassword": "{SECRET}""#),
    ] {
        for line in detail_lines_8205(&detail) {
            assert!(
                !line.contains(SECRET),
                "quoted-key credential reached the sink"
            );
            assert!(
                line.contains(ai_memory::logging::URL_PASSWORD_MASK),
                "credential mask absent"
            );
        }
    }
}

#[test]
fn operator_ambiguous_userinfo_tail_is_private_8205() {
    const SECRET: &str = "userinfo_tail_fixture_8205";
    for separator in ['/', '?', '#'] {
        let detail = format!(
            "connect postgres://user:prefix{separator}ss {SECRET}@db.example.invalid refused"
        );
        assert_private_detail_is_absent_8205(&detail, SECRET);
    }
}

#[test]
fn operator_keyless_equal_error_chain_survives_8205() {
    const DETAIL: &str = "near \"=\": syntax error: parsing statement failed";
    for line in detail_lines_8205(DETAIL) {
        assert!(
            line.contains(&DETAIL.escape_debug().to_string()),
            "keyless equals lost error chain"
        );
    }
}

#[test]
fn operator_unterminated_secret_masks_complete_input_8205() {
    const SECRET: &str = "unterminated_fixture_8205";
    const CONTEXT: &str = "connection refused by database";
    let detail = format!("password='{SECRET} {CONTEXT}");
    for line in detail_lines_8205(&detail) {
        assert!(
            !line.contains(SECRET),
            "unterminated credential reached the sink"
        );
        assert!(
            !line.contains(CONTEXT),
            "unterminated value leaked its tail"
        );
    }
}

userinfo_boundary_case_8205!(operator_semicolon_userinfo_8205, ";");
userinfo_boundary_case_8205!(operator_comma_userinfo_8205, ",");
userinfo_boundary_case_8205!(operator_quote_userinfo_8205, "\"");
