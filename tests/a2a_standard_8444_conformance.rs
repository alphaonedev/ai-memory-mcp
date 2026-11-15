// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: upstream-derived conformance checklist for the first-party A2A S1
//! dispatch (SQLite backend; the PostgreSQL run goes through
//! `a2a_standard_8444_pg.rs`, which executes the same scenarios). One test per
//! checklist line, named `a2a_conformance_<upstream#>_<description>`.

mod a2a_standard_8444_common;

use a2a_standard_8444_common::conformance;
use a2a_standard_8444_common::{router, sqlite_app_state};
use ai_memory::handlers::AppState;

struct Fixture {
    router: axum::Router,
    app: AppState,
    global: String,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, std::path::PathBuf::from),
    )
    .expect("scratch dir");
    let app = sqlite_app_state(&dir.path().join("a2a-conformance.db"));
    let probe = app.clone();
    let (router, global) = router(app);
    Fixture {
        router,
        app: probe,
        global,
        _dir: dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_268_terminal_task_rejects_followup() {
    let f = fixture();
    conformance::followup_to_terminal_task_is_rejected(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_269_subscribe_is_unsupported_not_task_not_found() {
    let f = fixture();
    conformance::subscribe_is_unsupported_on_every_task(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_270_non_json_content_type_is_rejected() {
    let f = fixture();
    conformance::non_json_content_type_is_rejected(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_271_version_header_read_and_returned() {
    let f = fixture();
    conformance::version_header_rule_on_every_response(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_272_malformed_body_is_http_200_envelope() {
    let f = fixture();
    conformance::malformed_rpc_body_is_http_200_envelope(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_304_params_failure_is_invalid_params() {
    let f = fixture();
    conformance::params_decode_failure_is_invalid_params(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_273_next_page_token_always_present() {
    let f = fixture();
    conformance::list_always_serialises_next_page_token(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_274_every_status_has_timestamp() {
    let f = fixture();
    conformance::every_status_carries_a_timestamp(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_298_261_timestamps_are_rfc3339_z_and_range_checked() {
    let f = fixture();
    conformance::timestamps_are_rfc3339_z_and_range_checked(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_248_task_and_context_id_rules() {
    let f = fixture();
    conformance::task_and_context_id_rules(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_250_cancel_is_atomic_and_terminal_rejected() {
    let f = fixture();
    conformance::cancel_is_atomic_and_terminal_rejected(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_221_page_size_is_capped() {
    let f = fixture();
    conformance::page_size_is_capped(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_201_request_body_is_bounded() {
    let f = fixture();
    conformance::request_body_is_bounded(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_319_list_honours_status_timestamp_after() {
    let f = fixture();
    conformance::list_honours_status_timestamp_after(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_203_only_declared_capabilities_are_served() {
    let f = fixture();
    conformance::only_declared_capabilities_are_served(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_195_history_length_clamps_and_owner_check_fails_closed() {
    let f = fixture();
    conformance::history_length_and_owner_checks(&f.router, &f.app, &f.global).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_393_subscribe_on_input_required_is_unsupported() {
    let f = fixture();
    conformance::subscribe_is_unsupported_on_every_task(&f.router, &f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_391_invalid_message_leaves_no_task_row() {
    let f = fixture();
    conformance::invalid_message_leaves_no_task_row(&f.router).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_401_finished_tasks_are_bounded() {
    let f = fixture();
    conformance::finished_tasks_are_bounded(&f.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2a_conformance_224_223_push_delivery_is_not_supported() {
    let f = fixture();
    conformance::push_delivery_is_not_supported(&f.router).await;
}

#[test]
fn a2a_conformance_410_module_doc_states_json_rpc_only() {
    conformance::module_doc_states_json_rpc_only();
}
