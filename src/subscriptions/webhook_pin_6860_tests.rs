// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6860 / #6866 (WP-EGRESS #6053) — the webhook dispatch client's DNS-rebind
//! pin (#1082) must be applied and keyed on the host string the client will
//! look up, and an IDN host must be accepted.
//!
//! `send()` shadows reqwest's resolver with `resolve(host, addr)` for the
//! guard-validated addresses. Nothing pinned that: deleting the override, or
//! changing how the key is derived from the parsed URL (a trailing-dot trim),
//! left every cell green while a rebind window re-opened. Each cell below
//! uses a host under the reserved `.invalid` TLD, which no resolver answers,
//! so the request reaches the loopback receiver ONLY through the pin.
//! Hermetic: no external resolver or network.

use super::*;
use std::io::{Read as _, Write as _};

/// A one-shot plaintext HTTP receiver on loopback. Returns its address and a
/// handle yielding whether a request arrived.
fn one_shot_receiver() -> (std::net::SocketAddr, std::thread::JoinHandle<bool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("non-blocking");
    let addr = listener.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_nonblocking(false);
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    });
    (addr, handle)
}

/// Build the dispatch client exactly as `send()` does for `raw` pinned to
/// `addr`, then POST to the parsed URL.
fn post_through_pin(raw: &str, addr: std::net::SocketAddr) -> Result<u16, String> {
    let parsed = ParsedWebhookUrl::parse(raw).map_err(|e| format!("parse: {e:?}"))?;
    let key = parsed.host().ok_or("no host")?;
    let url = parsed.url().clone();
    std::thread::spawn(move || {
        let client = webhook_url::pinned_client_builder(&key, &[addr])
            .build()
            .map_err(|e| format!("build: {e}"))?;
        client
            .post(url)
            .body("{}")
            .send()
            .map(|r| r.status().as_u16())
            .map_err(|e| format!("send: {e}"))
    })
    .join()
    .map_err(|_| "client thread panicked".to_string())?
}

fn assert_pin_reaches_receiver(host: &str) {
    let (addr, served) = one_shot_receiver();
    let raw = format!("http://{host}:{}/hook", addr.port());
    let res = post_through_pin(&raw, addr);
    assert_eq!(
        res,
        Ok(200),
        "#6860: the DNS pin must route {host} to the guard-validated address"
    );
    assert!(served.join().expect("receiver"), "receiver saw the request");
}

#[test]
fn dns_pin_is_applied_and_keyed_on_the_clients_host_6860() {
    // Mixed case: the pin key is the lowercased host the client looks up.
    assert_pin_reaches_receiver("Pin-6860.Invalid");
    // Trailing dot: the client looks up `pin-6860.invalid.`; the key keeps it.
    assert_pin_reaches_receiver("pin-6860.invalid.");
    // IDN: the key is the punycode form the client looks up.
    assert_pin_reaches_receiver("b\u{fc}cher-6860.invalid");
}

#[test]
fn without_a_pin_the_invalid_host_is_unreachable_6860() {
    // Control: the cells above would pass vacuously if `.invalid` resolved.
    let (addr, served) = one_shot_receiver();
    let parsed = ParsedWebhookUrl::parse(&format!("http://pin-6860.invalid:{}/hook", addr.port()))
        .expect("parse");
    let url = parsed.url().clone();
    let res = std::thread::spawn(move || {
        let client = webhook_url::pinned_client_builder("pin-6860.invalid", &[])
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .expect("client");
        client
            .post(url)
            .body("{}")
            .send()
            .map(|r| r.status().as_u16())
    })
    .join()
    .expect("client thread");
    assert!(
        res.is_err(),
        "#6860: an unpinned .invalid host must not resolve"
    );
    drop(served);
}

#[test]
fn host_keeps_the_trailing_dot_and_lowercases_6860() {
    let p = ParsedWebhookUrl::parse("https://Pin-6860.EXAMPLE./hook").expect("parse");
    assert_eq!(p.host().as_deref(), Some("pin-6860.example."));
}

#[test]
fn idn_host_is_accepted_as_punycode_6866() {
    let p = ParsedWebhookUrl::parse("https://b\u{fc}cher.example/hook").expect("IDN parses");
    assert_eq!(p.host().as_deref(), Some("xn--bcher-kva.example"));
    let p = ParsedWebhookUrl::parse("https://xn--bcher-kva.example/hook").expect("ACE parses");
    assert_eq!(p.host().as_deref(), Some("xn--bcher-kva.example"));
    assert!(validate_url_with("https://b\u{fc}cher.example/hook", false).is_ok());
    assert!(validate_url_with("https://xn--bcher-kva.example/hook", false).is_ok());
}
