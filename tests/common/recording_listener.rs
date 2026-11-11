// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! A loopback TCP listener that records EVERY inbound connection and every
//! byte it receives (#4121 / #4122 inference-egress invariant tests).
//!
//! The egress invariant is "a refused posture opens ZERO connections and no
//! API-key byte leaves the process". An HTTP mock server only sees requests it
//! could parse; this listener counts the TCP accept itself, so a client that
//! connects and then fails (TLS, malformed request, early drop) is still
//! caught. Standard library only.
//!
//! Load it with `#[path = "common/recording_listener.rs"] mod recording_listener;`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long one accepted connection may take to deliver its request.
const READ_BUDGET: Duration = Duration::from_secs(3);
/// Poll interval of the non-blocking accept loop.
const ACCEPT_POLL: Duration = Duration::from_millis(5);
/// Cap on the bytes kept per listener, so a runaway client cannot grow the
/// recording without bound.
const MAX_RECORDED_BYTES: usize = 4 * 1024 * 1024;
/// Read chunk size.
const CHUNK: usize = 8192;

/// A recording loopback listener. Dropping it stops the accept thread.
pub struct RecordingListener {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    recorded: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RecordingListener {
    /// Bind `127.0.0.1:0` and serve `response` (raw HTTP response bytes) to
    /// every connection after its request has been read. `None` closes the
    /// connection without answering.
    pub fn start(response: Option<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording listener");
        listener
            .set_nonblocking(true)
            .expect("non-blocking recording listener");
        let addr = listener.local_addr().expect("recording listener addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let connections = Arc::clone(&connections);
            let recorded = Arc::clone(&recorded);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections.fetch_add(1, Ordering::AcqRel);
                            serve_one(stream, &recorded, response.as_deref());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => std::thread::sleep(ACCEPT_POLL),
                    }
                }
            })
        };
        Self {
            addr,
            connections,
            recorded,
            stop,
            handle: Some(handle),
        }
    }

    /// `http://127.0.0.1:<port>` (no trailing slash).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The bound socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Number of TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    /// Every byte received so far, across all connections.
    pub fn recorded(&self) -> Vec<u8> {
        self.recorded.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// True when `needle` appears anywhere in the received bytes.
    pub fn saw_bytes(&self, needle: &[u8]) -> bool {
        let hay = self.recorded();
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }
}

impl Drop for RecordingListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Read one HTTP request (headers plus a `Content-Length` body) or until the
/// read budget runs out, record it, then answer with `response`.
fn serve_one(mut stream: TcpStream, recorded: &Mutex<Vec<u8>>, response: Option<&[u8]>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + READ_BUDGET;
    let mut request = Vec::new();
    let mut buf = [0_u8; CHUNK];
    while Instant::now() < deadline && !request_complete(&request) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => request.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    if let Ok(mut g) = recorded.lock() {
        let room = MAX_RECORDED_BYTES.saturating_sub(g.len());
        g.extend_from_slice(&request[..request.len().min(room)]);
    }
    if let Some(resp) = response {
        let _ = stream.write_all(resp);
        let _ = stream.flush();
    }
}

/// True once the headers are in and the declared body length has arrived.
fn request_complete(req: &[u8]) -> bool {
    let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
    let body_len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    req.len() >= end + 4 + body_len
}

/// A `200 OK` JSON response with `Connection: close`.
pub fn http_json_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
