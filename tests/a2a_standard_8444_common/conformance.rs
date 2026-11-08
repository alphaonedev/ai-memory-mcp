// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: upstream-derived conformance scenarios for the first-party A2A S1
//! dispatch. Each public function is one checklist line; the test binaries
//! name their tests `a2a_conformance_<upstream#>_<description>`.
//!
//! Scenarios use their own `contextId` and never count global rows, so the
//! PostgreSQL binary can run them all against one shared database.

use super::{
    ALICE, ALICE_KEY, BOB_KEY, Reply, SeedTask, error_code, link_history, message,
    receipt_memory_id, rpc, rpc_with, seed_task, seed_working_task, send, send_ok, state,
};
use ai_memory::a2a::{A2A_RPC_PATH, AGENT_CARD_PATH};
use ai_memory::handlers::AppState;
use ai_memory::storage::a2a_tasks::A2aHistoryEntry;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

fn msg_in(ctx: &str, text: &str) -> Value {
    let mut m = message(text, "ROLE_USER");
    m["contextId"] = json!(ctx);
    m
}

async fn total_in(router: &Router, ctx: &str) -> i64 {
    let r = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": ctx, "pageSize": 1}),
    )
    .await;
    r.json()["result"]["totalSize"].as_i64().expect("totalSize")
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

async fn send_msg(router: &Router, msg: Value) -> Reply {
    rpc(router, ALICE_KEY, "SendMessage", &json!({"message": msg})).await
}

/// Run every scenario once against one backend.
pub async fn run_all(router: &Router, app: &AppState, global: &str) {
    followup_to_terminal_task_is_rejected(router).await;
    subscribe_is_unsupported_on_every_task(router, app).await;
    non_json_content_type_is_rejected(router).await;
    version_header_rule_on_every_response(router).await;
    malformed_rpc_body_is_http_200_envelope(router).await;
    params_decode_failure_is_invalid_params(router).await;
    list_always_serialises_next_page_token(router).await;
    every_status_carries_a_timestamp(router, app).await;
    timestamps_are_rfc3339_z_and_range_checked(router).await;
    task_and_context_id_rules(router, app).await;
    cancel_is_atomic_and_terminal_rejected(router, app).await;
    page_size_is_capped(router).await;
    request_body_is_bounded(router).await;
    list_honours_status_timestamp_after(router, app).await;
    only_declared_capabilities_are_served(router).await;
    history_length_and_owner_checks(router, app, global).await;
    module_doc_states_json_rpc_only();
    invalid_message_leaves_no_task_row(router).await;
    finished_tasks_are_bounded(app).await;
    push_delivery_is_not_supported(router).await;
}

/// 268
pub async fn followup_to_terminal_task_is_rejected(router: &Router) {
    let ctx = unique("ctx-268");
    let first = send_msg(router, msg_in(&ctx, "first")).await;
    let task = first.json()["result"]["task"].clone();
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
    let before = total_in(router, &ctx).await;
    let mut follow = msg_in(&ctx, "again");
    follow["taskId"] = task["id"].clone();
    let r = send_msg(router, follow).await;
    assert!(
        r.json().get("error").is_some(),
        "terminal follow-up must be an error"
    );
    assert!(r.json().get("result").is_none());
    // The caller owns the task: a state error naming the state, not "not found".
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&r), -32004);
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("TASK_STATE_COMPLETED")),
        "{}",
        r.json()
    );
    assert_eq!(total_in(router, &ctx).await, before, "no silent new task");
}

/// 269, 393 and the subscribe half of 319 / 203
pub async fn subscribe_is_unsupported_on_every_task(router: &Router, app: &AppState) {
    let done = send_ok(router, ALICE_KEY, "sub", "ROLE_USER").await;
    let working = unique("w-269");
    seed_working_task(app, ALICE, &working).await;
    let input_required = unique("ir-393");
    seed_task(
        app,
        &SeedTask::new(
            ALICE,
            &input_required,
            "ctx-393",
            "TASK_STATE_INPUT_REQUIRED",
        ),
    )
    .await;
    for id in [
        done["id"].as_str().expect("id").to_string(),
        working,
        input_required,
        unique("unknown"),
    ] {
        let r = rpc(router, ALICE_KEY, "SubscribeToTask", &json!({"id": id})).await;
        assert_eq!(
            error_code(&r),
            -32004,
            "subscribe must be UnsupportedOperation for {id}"
        );
    }
}

/// 270
pub async fn non_json_content_type_is_rejected(router: &Router) {
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}))
            .expect("body");
    for ct in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ] {
        let r = send(
            router,
            "POST",
            A2A_RPC_PATH,
            &[("content-type", ct), (ai_memory::HEADER_API_KEY, ALICE_KEY)],
            body.clone(),
        )
        .await;
        assert_eq!(error_code(&r), -32005, "{ct}");
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{ct}");
    }
    let none = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[(ai_memory::HEADER_API_KEY, ALICE_KEY)],
        body.clone(),
    )
    .await;
    assert_eq!(error_code(&none), -32005);
    for ct in [
        "application/json; charset=utf-8",
        "APPLICATION/JSON",
        "application/a2a+json",
    ] {
        let r = send(
            router,
            "POST",
            A2A_RPC_PATH,
            &[("content-type", ct), (ai_memory::HEADER_API_KEY, ALICE_KEY)],
            body.clone(),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{ct}");
    }
    // Authentication still comes first.
    let anon = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[("content-type", "text/plain")],
        body,
    )
    .await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
}

/// 271 (S1 serves JSON-RPC only; every response of it carries the header)
pub async fn version_header_rule_on_every_response(router: &Router) {
    // Spec text: "Agents MUST interpret empty value as 0.3". An absent header is
    // served as 1.0 (the only version this binding implements), an explicit empty
    // value is the legacy 0.3 request and is refused with -32009 below.
    let ok = rpc(router, ALICE_KEY, "ListTasks", &json!({})).await;
    assert_eq!(ok.status, StatusCode::OK, "absent header is served as 1.0");
    assert_eq!(ok.version.as_deref(), Some("1.0"));
    let accepted = rpc_with(
        router,
        ALICE_KEY,
        &[("a2a-version", "1.0")],
        "ListTasks",
        &json!({}),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK);
    for bad in ["0.3", "", "2.0", "garbage"] {
        let r = rpc_with(
            router,
            ALICE_KEY,
            &[("a2a-version", bad)],
            "ListTasks",
            &json!({}),
        )
        .await;
        assert_eq!(error_code(&r), -32009, "version {bad:?}");
        assert_eq!(r.version.as_deref(), Some("1.0"));
    }
    let err = rpc(router, ALICE_KEY, "NoSuchMethod", &json!({})).await;
    assert_eq!(err.version.as_deref(), Some("1.0"));
    let anon = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[("content-type", "application/json")],
        b"{}".to_vec(),
    )
    .await;
    // The shared authentication layer answers before the A2A handler runs, so
    // its 401 carries no A2A header; only handler-produced responses do.
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let card = send(
        router,
        "GET",
        AGENT_CARD_PATH,
        &[(ai_memory::HEADER_API_KEY, ALICE_KEY)],
        Vec::new(),
    )
    .await;
    assert_eq!(card.version.as_deref(), Some("1.0"));
}

/// 272
pub async fn malformed_rpc_body_is_http_200_envelope(router: &Router) {
    let headers = [
        ("content-type", "application/json"),
        (ai_memory::HEADER_API_KEY, ALICE_KEY),
    ];
    let not_json = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &headers,
        b"{not json".to_vec(),
    )
    .await;
    assert_eq!(not_json.status, StatusCode::OK);
    assert_eq!(error_code(&not_json), -32700);
    assert_eq!(not_json.json()["jsonrpc"], "2.0");
    for body in [
        json!({"jsonrpc":"2.0","id":1}),
        json!({"jsonrpc":"2.0","id":1,"method":42}),
        json!({"jsonrpc":"1.0","id":1,"method":"ListTasks"}),
    ] {
        let r = send(
            router,
            "POST",
            A2A_RPC_PATH,
            &headers,
            serde_json::to_vec(&body).expect("body"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{body}");
        assert_eq!(error_code(&r), -32600, "{body}");
    }
}

/// 304
pub async fn params_decode_failure_is_invalid_params(router: &Router) {
    for (method, params) in [
        ("GetTask", json!({"id": 5})),
        ("GetTask", json!("not-an-object")),
        ("SendMessage", json!({"message": "text"})),
        ("ListTasks", json!({"pageSize": "x"})),
        ("CancelTask", json!({})),
    ] {
        let r = rpc(router, ALICE_KEY, method, &params).await;
        assert_eq!(error_code(&r), -32602, "{method} {params}");
    }
}

/// 273
pub async fn list_always_serialises_next_page_token(router: &Router) {
    let ctx = unique("ctx-273");
    for i in 0..3 {
        let r = send_msg(router, msg_in(&ctx, &format!("m{i}"))).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let page1 = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": ctx, "pageSize": 2}),
    )
    .await;
    let r1 = page1.json()["result"].clone();
    assert_eq!(r1["tasks"].as_array().expect("tasks").len(), 2);
    let token = r1["nextPageToken"]
        .as_str()
        .expect("nextPageToken present")
        .to_string();
    assert!(!token.is_empty());
    let page2 = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": ctx, "pageSize": 2, "pageToken": token}),
    )
    .await;
    let r2 = page2.json()["result"].clone();
    assert_eq!(r2["tasks"].as_array().expect("tasks").len(), 1);
    assert_eq!(
        r2["nextPageToken"],
        json!(""),
        "empty on the last page, never omitted"
    );
    let empty = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": unique("none")}),
    )
    .await;
    assert_eq!(empty.json()["result"]["nextPageToken"], json!(""));
}

/// 274
pub async fn every_status_carries_a_timestamp(router: &Router, app: &AppState) {
    let sent = send_ok(router, ALICE_KEY, "ts", "ROLE_USER").await;
    assert!(sent["status"]["timestamp"].is_string());
    let id = sent["id"].as_str().expect("id").to_string();
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert!(got.json()["result"]["status"]["timestamp"].is_string());
    let list = rpc(router, ALICE_KEY, "ListTasks", &json!({"pageSize": 100})).await;
    for t in list.json()["result"]["tasks"].as_array().expect("tasks") {
        assert!(t["status"]["timestamp"].is_string(), "{t}");
    }
    let cancel_id = unique("c-274");
    seed_working_task(app, ALICE, &cancel_id).await;
    let cancelled = rpc(router, ALICE_KEY, "CancelTask", &json!({"id": cancel_id})).await;
    assert!(cancelled.json()["result"]["status"]["timestamp"].is_string());
}

/// 298 and 261
pub async fn timestamps_are_rfc3339_z_and_range_checked(router: &Router) {
    let sent = send_ok(router, ALICE_KEY, "z", "ROLE_USER").await;
    let ts = sent["status"]["timestamp"].as_str().expect("timestamp");
    assert!(ts.ends_with('Z'), "{ts}");
    assert!(!ts.contains("+00:00"), "{ts}");
    assert!(chrono::DateTime::parse_from_rfc3339(ts).is_ok(), "{ts}");
    for bad in [
        "10000-01-01T00:00:00Z",
        "not-a-time",
        "2026-13-45T99:00:00Z",
    ] {
        let r = rpc(
            router,
            ALICE_KEY,
            "ListTasks",
            &json!({"statusTimestampAfter": bad}),
        )
        .await;
        assert_eq!(error_code(&r), -32602, "{bad}");
    }
}

/// 248
pub async fn task_and_context_id_rules(router: &Router, app: &AppState) {
    let mut unknown = msg_in("ctx-248", "x");
    unknown["taskId"] = json!(unique("no-such-task"));
    assert_eq!(error_code(&send_msg(router, unknown).await), -32001);

    let id = unique("t-248");
    seed_working_task(app, ALICE, &id).await; // context "ctx-seed-8444"
    let mut mismatch = msg_in("ctx-other-248", "x");
    mismatch["taskId"] = json!(id);
    assert_eq!(error_code(&send_msg(router, mismatch).await), -32602);
    let mut matching = msg_in("ctx-seed-8444", "x");
    matching["taskId"] = json!(id);
    let ok = send_msg(router, matching).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.json());
    assert_eq!(ok.json()["result"]["task"]["id"], json!(id));
    assert_eq!(ok.json()["result"]["task"]["contextId"], "ctx-seed-8444");

    let a = send_ok(router, ALICE_KEY, "n1", "ROLE_USER").await;
    let b = send_ok(router, ALICE_KEY, "n2", "ROLE_USER").await;
    assert_ne!(a["id"], b["id"]);
    assert_ne!(a["contextId"], b["contextId"]);
    assert!(!a["contextId"].as_str().expect("contextId").is_empty());
    let given = unique("ctx-248-given");
    let honoured = send_msg(router, msg_in(&given, "g")).await;
    assert_eq!(honoured.json()["result"]["task"]["contextId"], json!(given));
}

/// 250
pub async fn cancel_is_atomic_and_terminal_rejected(router: &Router, app: &AppState) {
    super::cancel_races_completion_once(router, app).await;
    let done = send_ok(router, ALICE_KEY, "t", "ROLE_USER").await;
    let id = done["id"].as_str().expect("id").to_string();
    let r = rpc(router, ALICE_KEY, "CancelTask", &json!({"id": id})).await;
    assert_eq!(error_code(&r), -32002);
    let got = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(
        got.json()["result"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );
}

/// 221
pub async fn page_size_is_capped(router: &Router) {
    for (asked, effective) in [(1_000_000_i64, 100), (101, 100), (100, 100), (7, 7)] {
        let r = rpc(router, ALICE_KEY, "ListTasks", &json!({"pageSize": asked})).await;
        assert_eq!(
            r.json()["result"]["pageSize"],
            json!(effective),
            "asked {asked}"
        );
        let rows = r.json()["result"]["tasks"].as_array().expect("tasks").len();
        assert!(rows <= effective, "page of {rows} exceeds {effective}");
    }
    for bad in [0_i64, -1] {
        let r = rpc(router, ALICE_KEY, "ListTasks", &json!({"pageSize": bad})).await;
        assert_eq!(error_code(&r), -32602, "pageSize {bad}");
    }
    let default = rpc(router, ALICE_KEY, "ListTasks", &json!({})).await;
    assert_eq!(default.json()["result"]["pageSize"], json!(50));
}

/// 201 (SSE is not served at all; the body bound is the existing constant)
pub async fn request_body_is_bounded(router: &Router) {
    let oversized = vec![b' '; ai_memory::HTTP_BODY_LIMIT_BYTES + 1];
    let r = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[
            ("content-type", "application/json"),
            (ai_memory::HEADER_API_KEY, ALICE_KEY),
        ],
        oversized,
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // A body of exactly the limit is read in full: a parse error envelope, not 413.
    let at_limit = vec![b' '; ai_memory::HTTP_BODY_LIMIT_BYTES];
    let r = send(
        router,
        "POST",
        A2A_RPC_PATH,
        &[
            ("content-type", "application/json"),
            (ai_memory::HEADER_API_KEY, ALICE_KEY),
        ],
        at_limit,
    )
    .await;
    assert_ne!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.status, StatusCode::OK);
    assert!(matches!(error_code(&r), -32700 | -32600));
    let stream = rpc(router, ALICE_KEY, "SendStreamingMessage", &json!({})).await;
    assert_eq!(error_code(&stream), -32004);
}

/// 319
pub async fn list_honours_status_timestamp_after(router: &Router, app: &AppState) {
    let ctx = unique("ctx-319");
    let mut ids = Vec::new();
    for (i, ts) in [
        "2026-01-01T00:00:01.000Z",
        "2026-01-01T00:00:02.000Z",
        "2026-01-01T00:00:03.000Z",
    ]
    .iter()
    .enumerate()
    {
        let id = unique(&format!("t319-{i}"));
        let mut seed = SeedTask::new(ALICE, &id, &ctx, state::COMPLETED);
        seed.timestamp = (*ts).to_string();
        seed_task(app, &seed).await;
        ids.push(id);
    }
    let r = rpc(
        router,
        ALICE_KEY,
        "ListTasks",
        &json!({"contextId": ctx, "statusTimestampAfter": "2026-01-01T00:00:01.500Z"}),
    )
    .await;
    let got: Vec<String> = r.json()["result"]["tasks"]
        .as_array()
        .expect("tasks")
        .iter()
        .map(|t| t["id"].as_str().expect("id").to_string())
        .collect();
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(got.contains(&ids[1]) && got.contains(&ids[2]));
    // A subscribe attempt never turns into a list/get fallback.
    let sub = rpc(router, ALICE_KEY, "SubscribeToTask", &json!({"id": ids[1]})).await;
    assert_eq!(error_code(&sub), -32004);
}

/// 203
pub async fn only_declared_capabilities_are_served(router: &Router) {
    let card = send(
        router,
        "GET",
        AGENT_CARD_PATH,
        &[(ai_memory::HEADER_API_KEY, ALICE_KEY)],
        Vec::new(),
    )
    .await;
    let caps = card.json()["capabilities"].clone();
    assert_eq!(caps["streaming"], false);
    assert_eq!(caps["pushNotifications"], false);
    assert_eq!(caps["extendedAgentCard"], false);
    for m in [
        "SendStreamingMessage",
        "SubscribeToTask",
        "GetExtendedAgentCard",
    ] {
        assert_eq!(
            error_code(&rpc(router, ALICE_KEY, m, &json!({})).await),
            -32004,
            "{m}"
        );
    }
}

/// 195
pub async fn history_length_and_owner_checks(router: &Router, app: &AppState, global: &str) {
    let id = unique("t-195");
    seed_task(app, &SeedTask::new(ALICE, &id, "ctx-195", state::WORKING)).await;
    // Three real inbox memories, linked to the task as content-free entries.
    let mut entries = Vec::new();
    for (name, text) in [("h1", "a"), ("h2", "b"), ("h3", "c")] {
        let sent = send_ok(router, ALICE_KEY, text, "ROLE_USER").await;
        entries.push(A2aHistoryEntry {
            message_id: name.to_string(),
            role: "ROLE_USER".to_string(),
            context_id: "ctx-195".to_string(),
            task_id: id.clone(),
            memory_id: receipt_memory_id(&sent),
        });
    }
    link_history(app, ALICE, &id, &entries).await;
    let history_len = |r: &Reply| {
        r.json()["result"]
            .get("history")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    let all = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(history_len(&all), 3);
    assert_eq!(all.json()["result"]["history"][0]["parts"][0]["text"], "a");
    let two = rpc(
        router,
        ALICE_KEY,
        "GetTask",
        &json!({"id": id, "historyLength": 2}),
    )
    .await;
    assert_eq!(history_len(&two), 2);
    assert_eq!(two.json()["result"]["history"][1]["messageId"], "h3");
    let zero = rpc(
        router,
        ALICE_KEY,
        "GetTask",
        &json!({"id": id, "historyLength": 0}),
    )
    .await;
    assert_eq!(history_len(&zero), 0);
    // A negative historyLength is invalid params (spec: non-negative integer).
    for method in ["GetTask", "ListTasks"] {
        let params = if method == "GetTask" {
            json!({"id": id, "historyLength": -5})
        } else {
            json!({"historyLength": -5})
        };
        let negative = rpc(router, ALICE_KEY, method, &params).await;
        assert_eq!(negative.status, StatusCode::BAD_REQUEST, "{method}");
        assert_eq!(error_code(&negative), -32602, "{method}");
    }

    // Every task-addressing method is owner-checked, fail closed.
    for (m, params) in [
        ("GetTask", json!({"id": id})),
        ("CancelTask", json!({"id": id})),
    ] {
        let r = rpc(router, BOB_KEY, m, &params).await;
        assert_eq!(error_code(&r), -32001, "{m}");
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{m}");
    }
    let mut hijack = msg_in("ctx-195", "x");
    hijack["taskId"] = json!(id);
    let r = rpc(router, BOB_KEY, "SendMessage", &json!({"message": hijack})).await;
    assert_eq!(error_code(&r), -32001);
    // No credential-bound principal: the shared key and a stranger are refused.
    let shared = rpc(router, global, "GetTask", &json!({"id": id})).await;
    assert_eq!(shared.status, StatusCode::UNAUTHORIZED);
    let stranger = rpc(router, "not-a-key", "GetTask", &json!({"id": id})).await;
    assert_eq!(stranger.status, StatusCode::UNAUTHORIZED);
    // The task is untouched.
    let still = rpc(router, ALICE_KEY, "GetTask", &json!({"id": id})).await;
    assert_eq!(
        still.json()["result"]["status"]["state"],
        "TASK_STATE_WORKING"
    );
}

/// 410
pub fn module_doc_states_json_rpc_only() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a2a.rs"))
        .expect("read src/a2a.rs");
    assert!(
        src.contains("S1 exposes the JSON-RPC binding ONLY"),
        "the module doc must state that S1 is JSON-RPC only"
    );
}

/// 391
pub async fn invalid_message_leaves_no_task_row(router: &Router) {
    let ctx = unique("ctx-391");
    let mut bad_role = msg_in(&ctx, "x");
    bad_role["role"] = json!("ROLE_BOGUS");
    assert_eq!(error_code(&send_msg(router, bad_role).await), -32602);
    let mut file = msg_in(&ctx, "x");
    file["parts"] = json!([{"raw": "AAAA", "mediaType": "image/png"}]);
    assert_eq!(error_code(&send_msg(router, file).await), -32005);
    let mut empty = msg_in(&ctx, "x");
    empty["parts"] = json!([]);
    assert_eq!(error_code(&send_msg(router, empty).await), -32602);
    assert_eq!(
        total_in(router, &ctx).await,
        0,
        "invalid messages persist no task row"
    );
    let ok = send_msg(router, msg_in(&ctx, "fine")).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(total_in(router, &ctx).await, 1);
}

/// 401: the store prunes an agent's oldest finished tasks beyond the bound
/// and never an active one.
pub async fn finished_tasks_are_bounded(app: &AppState) {
    use ai_memory::storage::a2a_tasks::A2A_TERMINAL_TASK_RETENTION;
    let agent = unique("ai:retention-401");
    let ctx = unique("ctx-401");
    let active = unique("active-401");
    seed_task(app, &SeedTask::new(&agent, &active, &ctx, state::WORKING)).await;
    let extra = 3;
    let mut first = String::new();
    for i in 0..(A2A_TERMINAL_TASK_RETENTION + extra) {
        let id = format!("fin-401-{}-{i:06}", uuid::Uuid::new_v4());
        if i == 0 {
            first.clone_from(&id);
        }
        let mut seed = SeedTask::new(&agent, &id, &ctx, state::COMPLETED);
        seed.timestamp = format!("2026-01-01T00:00:00.{i:06}Z");
        seed_task(app, &seed).await;
    }
    let (total, first_present, active_present) =
        super::storage_probe(app, &agent, &first, &active).await;
    assert_eq!(
        total,
        A2A_TERMINAL_TASK_RETENTION + 1,
        "bounded finished tasks plus the active one"
    );
    assert!(!first_present, "the oldest finished task is pruned");
    assert!(active_present, "an active task is never pruned");
}

/// 224 and 223: push delivery is not implemented, so every way of asking for
/// it is `-32003` (the card declares `pushNotifications: false`).
pub async fn push_delivery_is_not_supported(router: &Router) {
    let ctx = unique("ctx-224");
    let m = msg_in(&ctx, "x");
    let r = rpc(
        router,
        ALICE_KEY,
        "SendMessage",
        &json!({"message": m, "configuration": {"taskPushNotificationConfig": {"url": "https://hook.example/cb"}}}),
    )
    .await;
    assert_eq!(error_code(&r), -32003);
    assert_eq!(total_in(router, &ctx).await, 0);
    for method in [
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
    ] {
        assert_eq!(
            error_code(&rpc(router, ALICE_KEY, method, &json!({})).await),
            -32003,
            "{method}"
        );
    }
}
