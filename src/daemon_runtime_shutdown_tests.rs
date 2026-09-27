use super::*;

pub(super) fn bind_failure_args() -> ServeArgs {
    ServeArgs {
        host: "127.0.0.1".to_string(),
        port: 0,
        tls_cert: None,
        tls_key: None,
        mtls_allowlist: None,
        shutdown_grace_secs: 30,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2_000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 0,
        federation_identity: None,
        #[cfg(feature = "sal")]
        store_url: None,
    }
}

fn keyword_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.tier = Some("keyword".to_string());
    config
}

/// #3705/#3709 — with no `--tls-cert`/`--tls-key` the listener is STILL TLS:
/// the daemon issues its own local-CA certificate into the (armed, sandboxed)
/// key directory, so the occupied-port bind failure below is a TLS bind
/// failure on the zero-config path and must drain the writers exactly like
/// the operator-material twin. There is no plaintext listener to fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_bind_failure_drains_writers_before_returning_fatal_status() {
    let _sandbox = crate::identity::test_key_dir::install();
    let directory = tempfile::tempdir().expect("create bind-failure test directory");
    let db_path = directory.path().join("ai-memory.db");
    let mut args = bind_failure_args();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a loopback port for the bind-failure test");
    args.port = occupied.local_addr().expect("read reserved address").port();

    let error = serve(db_path, args, &keyword_config())
        .await
        .expect_err("an occupied bind address must stop the daemon");
    let fatal = error
        .downcast_ref::<FatalShutdownError>()
        .expect("bind failure must retain the service-manager marker");
    assert_eq!(fatal.reason, "daemon server setup failed");
    assert!(
        fatal
            .detail
            .as_deref()
            .is_some_and(|detail| !detail.is_empty()),
        "fatal detail must preserve the bind failure: {fatal}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_tls_bind_failure_uses_the_same_certified_shutdown_path() {
    let directory = tempfile::tempdir().expect("create TLS bind-failure test directory");
    let db_path = directory.path().join("ai-memory.db");
    let mut args = bind_failure_args();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a loopback port for the TLS bind-failure test");
    args.port = occupied.local_addr().expect("read reserved address").port();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    args.tls_cert = Some(fixtures.join("valid_cert.pem"));
    args.tls_key = Some(fixtures.join("valid_key_pkcs8.pem"));

    let error = serve(db_path, args, &keyword_config())
        .await
        .expect_err("an occupied TLS bind address must stop the daemon");
    let fatal = error
        .downcast_ref::<FatalShutdownError>()
        .expect("TLS bind failure must retain the service-manager marker");
    assert_eq!(fatal.reason, "daemon server setup failed");
    assert!(
        fatal
            .detail
            .as_deref()
            .is_some_and(|detail| !detail.is_empty())
    );
}

#[tokio::test]
async fn bootstrap_accounts_for_live_atomise_writer_4062() {
    let _no_pass = crate::test_support::no_passphrase_guard();
    let _sandbox = crate::identity::test_key_dir::install();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("atomise.db");
    let bs = bootstrap_serve(&path, &bind_failure_args(), &keyword_config())
        .await
        .unwrap();
    assert!(bs.app_state.atomise_queue.is_some());
    for task in bs.task_handles {
        task.abort();
        let _ = task.await;
    }
    // With all periodic tasks joined, the still-live atomise consumer must
    // remain accounted until admission closes and its buffered jobs drain.
    assert!(
        bs.blocking_tasks.load(Ordering::SeqCst) > 0,
        "live atomise worker is absent from the daemon writer barrier"
    );
}
