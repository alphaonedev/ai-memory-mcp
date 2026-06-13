// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! Dependency-free load-test harness for the ai-memory HTTP daemon (`:9077`)
//! and the federated W=N quorum hive.
//!
//! Pure std: HTTP/1.1 over `TcpStream` with keep-alive, a fixed-size worker
//! pool (closed-loop) or a paced open-loop generator (`--rate`), latency
//! percentiles, and a reason-tagged error histogram (quota-429 / quorum-503 /
//! timeout / 5xx). No TLS — the hive speaks plain HTTP on the loopback /
//! private network.
//!
//! Scenarios:
//!   write   — POST /api/v1/memories with a unique title per request (measures
//!             insert throughput; on the quorum hive this includes the
//!             synchronous peer push that bounds write rate).
//!   read    — GET  /api/v1/memories?namespace=..&limit=.. (list hot path).
//!   recall  — POST /api/v1/recall (semantic/keyword recall hot path).
//!   mixed   — read/write blend governed by --read-ratio.
//!   quota   — write as a single agent to deliberately drive past the
//!             [limits] caps; the error histogram characterizes throttle
//!             behavior (clean 429 vs silent 503).
//!
//! Example:
//!   loadtest --target <http://127.0.0.1:9077> --api-key KEY \
//!            --scenario write --concurrency 64 --duration 60

// Latency/throughput reporting converts integer sample counters (`u64`/`usize`)
// into `f64` for percentile, mean, rate, and error-rate math. Every such value
// (microsecond latencies, request counts, percentile indices) is bounded well
// within f64's 2^52 exact-integer range by construction, and the percentile
// index is non-negative and in-range, so the precision/truncation/sign lints
// are inapplicable to this reporter.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_PORT: u16 = 9077;

/// Microseconds per millisecond — latency samples are captured in µs and
/// reported in ms.
const MICROS_PER_MILLI: f64 = 1_000.0;
/// Scale factor for percentile fractions and error-rate percentages.
const PERCENT_SCALE: f64 = 100.0;

/// HTTP success codes counted as "ok (2xx)" in the throughput tally.
const HTTP_OK: u16 = 200;
const HTTP_CREATED: u16 = 201;

// Deterministic mixed-scenario read/write interleave (no RNG dependency):
// Knuth multiplicative hash of the global request counter, masked to a bucket.
const HASH_MULTIPLIER: u64 = 2_654_435_761;
const HASH_SHIFT: u32 = 16;
const HASH_MASK: u32 = 0xFFFF;

// xorshift* payload PRNG (deterministic, JSON-safe filler).
const XORSHIFT_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const XORSHIFT_SHIFT_A: u64 = 12;
const XORSHIFT_SHIFT_B: u64 = 25;
const XORSHIFT_SHIFT_C: u64 = 27;
const XORSHIFT_MULT: u64 = 0x2545_f491_4f6c_dd1d;
const XORSHIFT_OUT_SHIFT: u32 = 33;

// CLI defaults.
const DEFAULT_AGENT_ID: &str = "loadtest";
const DEFAULT_NAMESPACE: &str = "loadtest";
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_READ_RATIO: f64 = 0.8;
const DEFAULT_PAYLOAD_BYTES: usize = 256;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_TIER: &str = "mid";
const DEFAULT_LIST_LIMIT: u32 = 20;

/// Backoff after a failed connect before the worker retries.
const CONN_RETRY_BACKOFF: Duration = Duration::from_millis(5);
/// Deadline-watch poll interval on the main thread (duration mode).
const DEADLINE_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Initial request-buffer reservation before the optional body.
const REQ_BUF_RESERVE: usize = 256;
/// Radix of HTTP/1.1 chunked-transfer chunk-size lines.
const CHUNK_SIZE_RADIX: u32 = 16;

#[derive(Clone)]
struct Config {
    host: String,
    port: u16,
    api_key: String,
    agent_id: String,
    namespace: String,
    scenario: Scenario,
    concurrency: usize,
    duration: Duration,
    max_requests: u64, // 0 = unlimited (duration-bound)
    rate: u64,         // 0 = closed-loop; >0 = open-loop target req/s (global)
    read_ratio: f64,   // mixed: fraction of reads
    payload_bytes: usize,
    timeout: Duration,
    tier: String,
    list_limit: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Write,
    Read,
    Recall,
    Mixed,
    Quota,
}

impl Scenario {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "write" | "write-heavy" => Scenario::Write,
            "read" | "read-heavy" => Scenario::Read,
            "recall" => Scenario::Recall,
            "mixed" => Scenario::Mixed,
            "quota" | "quota-probe" => Scenario::Quota,
            _ => return None,
        })
    }
    fn name(self) -> &'static str {
        match self {
            Scenario::Write => "write",
            Scenario::Read => "read",
            Scenario::Recall => "recall",
            Scenario::Mixed => "mixed",
            Scenario::Quota => "quota",
        }
    }
}

#[derive(Default)]
struct Stats {
    latencies_us: Vec<u64>,
    // status-code -> count
    codes: BTreeMap<u16, u64>,
    timeouts: u64,
    conn_errors: u64,
    bytes_sent: u64,
}

impl Stats {
    fn merge(&mut self, other: Stats) {
        self.latencies_us.extend(other.latencies_us);
        for (k, v) in other.codes {
            *self.codes.entry(k).or_insert(0) += v;
        }
        self.timeouts += other.timeouts;
        self.conn_errors += other.conn_errors;
        self.bytes_sent += other.bytes_sent;
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n");
            print_usage();
            std::process::exit(2);
        }
    };

    eprintln!(
        "loadtest -> {}:{}  scenario={}  concurrency={}  {}  rate={}  ns={}  agent={}",
        cfg.host,
        cfg.port,
        cfg.scenario.name(),
        cfg.concurrency,
        if cfg.max_requests > 0 {
            format!("requests={}", cfg.max_requests)
        } else {
            format!("duration={}s", cfg.duration.as_secs())
        },
        if cfg.rate > 0 {
            cfg.rate.to_string()
        } else {
            "closed-loop".to_string()
        },
        cfg.namespace,
        cfg.agent_id,
    );

    let stop = Arc::new(AtomicBool::new(false));
    let issued = Arc::new(AtomicU64::new(0)); // global request counter (open-loop pacing + max_requests)
    let seq = Arc::new(AtomicU64::new(0)); // global uniqueness counter for titles
    let start = Instant::now();
    let deadline = start + cfg.duration;

    let mut handles = Vec::with_capacity(cfg.concurrency);
    for wid in 0..cfg.concurrency {
        let cfg = cfg.clone();
        let stop = Arc::clone(&stop);
        let issued = Arc::clone(&issued);
        let seq = Arc::clone(&seq);
        handles.push(std::thread::spawn(move || {
            worker(wid, &cfg, &stop, &issued, &seq, start, deadline)
        }));
    }

    // Main thread watches the deadline (duration mode) and flips `stop`.
    // In requests mode, workers stop themselves when `issued >= max_requests`.
    if cfg.max_requests == 0 {
        while Instant::now() < deadline {
            std::thread::sleep(DEADLINE_POLL_INTERVAL);
        }
        stop.store(true, Ordering::Relaxed);
    }

    let mut agg = Stats::default();
    for h in handles {
        if let Ok(s) = h.join() {
            agg.merge(s);
        }
    }
    let elapsed = start.elapsed();
    report(&cfg, &agg, elapsed);
}

#[allow(clippy::too_many_arguments)]
fn worker(
    wid: usize,
    cfg: &Config,
    stop: &AtomicBool,
    issued: &AtomicU64,
    seq: &AtomicU64,
    start: Instant,
    deadline: Instant,
) -> Stats {
    let mut stats = Stats::default();
    let mut conn: Option<(TcpStream, BufReader<TcpStream>)> = None;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if cfg.max_requests == 0 && Instant::now() >= deadline {
            break;
        }
        // Reserve a request slot. In requests mode this also enforces the cap.
        let n = issued.fetch_add(1, Ordering::Relaxed);
        if cfg.max_requests > 0 && n >= cfg.max_requests {
            break;
        }

        // Open-loop pacing: target req number `n` should fire at start + n/rate.
        if cfg.rate > 0 {
            let target = start + Duration::from_secs_f64(n as f64 / cfg.rate as f64);
            let now = Instant::now();
            if target > now {
                std::thread::sleep(target - now);
            }
        }

        // (Re)establish connection if needed.
        if conn.is_none() {
            if let Ok(c) = connect(cfg) {
                conn = Some(c);
            } else {
                stats.conn_errors += 1;
                std::thread::sleep(CONN_RETRY_BACKOFF);
                continue;
            }
        }

        let is_read = match cfg.scenario {
            Scenario::Read | Scenario::Recall => true,
            Scenario::Write | Scenario::Quota => false,
            Scenario::Mixed => mixed_pick_read(seq, cfg.read_ratio),
        };
        let uniq = seq.fetch_add(1, Ordering::Relaxed);
        let req = if is_read {
            match cfg.scenario {
                Scenario::Recall => build_recall(cfg),
                _ => build_read(cfg),
            }
        } else {
            build_write(cfg, wid, uniq)
        };

        let (s, r) = conn.as_mut().unwrap();
        let t0 = Instant::now();
        match do_request(s, r, &req) {
            Ok(code) => {
                let us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
                stats.latencies_us.push(us);
                *stats.codes.entry(code).or_insert(0) += 1;
                stats.bytes_sent += req.len() as u64;
            }
            Err(kind) => {
                match kind {
                    ReqErr::Timeout => stats.timeouts += 1,
                    ReqErr::Io => stats.conn_errors += 1,
                }
                // Connection state is now indeterminate; drop + reconnect.
                conn = None;
            }
        }
    }
    stats
}

fn mixed_pick_read(seq: &AtomicU64, read_ratio: f64) -> bool {
    // Deterministic interleave without an RNG dependency: hash the counter.
    let n = seq.load(Ordering::Relaxed);
    let h = (n.wrapping_mul(HASH_MULTIPLIER) >> HASH_SHIFT) & u64::from(HASH_MASK);
    (h as f64 / f64::from(HASH_MASK)) < read_ratio
}

fn connect(cfg: &Config) -> std::io::Result<(TcpStream, BufReader<TcpStream>)> {
    let stream = TcpStream::connect((cfg.host.as_str(), cfg.port))?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(cfg.timeout))?;
    stream.set_write_timeout(Some(cfg.timeout))?;
    let reader = BufReader::new(stream.try_clone()?);
    Ok((stream, reader))
}

enum ReqErr {
    Timeout,
    Io,
}

fn do_request(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    req: &[u8],
) -> Result<u16, ReqErr> {
    if let Err(e) = stream.write_all(req).and_then(|()| stream.flush()) {
        return Err(classify(&e));
    }
    read_response(reader)
}

fn classify(e: &std::io::Error) -> ReqErr {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    match e.kind() {
        WouldBlock | TimedOut => ReqErr::Timeout,
        _ => ReqErr::Io,
    }
}

/// Read one HTTP/1.1 response, fully consuming the body so the connection can
/// be reused (keep-alive). Returns the numeric status code.
fn read_response(reader: &mut BufReader<TcpStream>) -> Result<u16, ReqErr> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return Err(ReqErr::Io), // peer closed
        Ok(_) => {}
        Err(e) => return Err(classify(&e)),
    }
    // "HTTP/1.1 201 Created"
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(ReqErr::Io)?;

    let mut content_length: usize = 0;
    let mut chunked = false;
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => return Err(ReqErr::Io),
            Ok(_) => {}
            Err(e) => return Err(classify(&e)),
        }
        let t = h.trim_end();
        if t.is_empty() {
            break; // end of headers
        }
        let lower = t.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }

    if chunked {
        loop {
            let mut sz = String::new();
            match reader.read_line(&mut sz) {
                Ok(0) => return Err(ReqErr::Io),
                Ok(_) => {}
                Err(e) => return Err(classify(&e)),
            }
            let size = usize::from_str_radix(
                sz.trim().split(';').next().unwrap_or("0").trim(),
                CHUNK_SIZE_RADIX,
            )
            .unwrap_or(0);
            if size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer); // final CRLF
                break;
            }
            let mut buf = vec![0u8; size + 2]; // chunk + CRLF
            if let Err(e) = reader.read_exact(&mut buf) {
                return Err(classify(&e));
            }
        }
    } else if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if let Err(e) = reader.read_exact(&mut buf) {
            return Err(classify(&e));
        }
    }
    Ok(code)
}

fn build_write(cfg: &Config, wid: usize, uniq: u64) -> Vec<u8> {
    let title = format!("lt-{}-{}-{}-{}", cfg.namespace, wid, uniq, now_nanos());
    let content = make_payload(cfg.payload_bytes, uniq);
    let body = format!(
        "{{\"namespace\":\"{}\",\"title\":\"{}\",\"content\":\"{}\",\"tier\":\"{}\",\"scope\":\"collective\",\"kind\":\"concept\"}}",
        cfg.namespace, title, content, cfg.tier
    );
    http_request("POST", "/api/v1/memories", cfg, Some(&body))
}

fn build_read(cfg: &Config) -> Vec<u8> {
    let path = format!(
        "/api/v1/memories?namespace={}&limit={}",
        cfg.namespace, cfg.list_limit
    );
    http_request("GET", &path, cfg, None)
}

fn build_recall(cfg: &Config) -> Vec<u8> {
    let body = format!(
        "{{\"namespace\":\"{}\",\"query\":\"concept relation entity knowledge\",\"limit\":{}}}",
        cfg.namespace, cfg.list_limit
    );
    http_request("POST", "/api/v1/recall", cfg, Some(&body))
}

fn http_request(method: &str, path: &str, cfg: &Config, body: Option<&str>) -> Vec<u8> {
    let mut req = String::with_capacity(REQ_BUF_RESERVE + body.map_or(0, str::len));
    req.push_str(method);
    req.push(' ');
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\n");
    req.push_str("Host: ");
    req.push_str(&cfg.host);
    req.push_str("\r\n");
    req.push_str("x-api-key: ");
    req.push_str(&cfg.api_key);
    req.push_str("\r\n");
    req.push_str("X-Agent-Id: ");
    req.push_str(&cfg.agent_id);
    req.push_str("\r\n");
    req.push_str("Connection: keep-alive\r\n");
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        let _ = write!(req, "Content-Length: {}", b.len());
        req.push_str("\r\n\r\n");
        req.push_str(b);
    } else {
        req.push_str("\r\n");
    }
    req.into_bytes()
}

fn make_payload(bytes: usize, salt: u64) -> String {
    // Deterministic alphanumeric filler of ~`bytes` length, JSON-safe.
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789 ";
    let mut s = String::with_capacity(bytes);
    let mut x = salt.wrapping_add(XORSHIFT_SEED);
    for _ in 0..bytes {
        x ^= x >> XORSHIFT_SHIFT_A;
        x ^= x << XORSHIFT_SHIFT_B;
        x ^= x >> XORSHIFT_SHIFT_C;
        let idx = (x.wrapping_mul(XORSHIFT_MULT) >> XORSHIFT_OUT_SHIFT) as usize % ALPHA.len();
        s.push(ALPHA[idx] as char);
    }
    s
}

fn report(cfg: &Config, s: &Stats, elapsed: Duration) {
    let total_ok: u64 = s
        .codes
        .iter()
        .filter(|(c, _)| **c == HTTP_OK || **c == HTTP_CREATED)
        .map(|(_, v)| *v)
        .sum();
    let total_resp: u64 = s.codes.values().sum();
    let total_attempts = total_resp + s.timeouts + s.conn_errors;
    let secs = elapsed.as_secs_f64();

    let mut lat = s.latencies_us.clone();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lat.is_empty() {
            return 0.0;
        }
        let idx = ((p / PERCENT_SCALE) * (lat.len() as f64 - 1.0)).round() as usize;
        lat[idx.min(lat.len() - 1)] as f64 / MICROS_PER_MILLI // ms
    };
    let mean_ms = if lat.is_empty() {
        0.0
    } else {
        lat.iter().sum::<u64>() as f64 / lat.len() as f64 / MICROS_PER_MILLI
    };

    println!("\n========== loadtest report ==========");
    println!(
        "target        : http://{}:{}  ({} scenario)",
        cfg.host,
        cfg.port,
        cfg.scenario.name()
    );
    println!(
        "concurrency   : {}   rate: {}",
        cfg.concurrency,
        if cfg.rate > 0 {
            format!("{} req/s (open-loop)", cfg.rate)
        } else {
            "closed-loop".into()
        }
    );
    println!("elapsed       : {secs:.3}s");
    println!(
        "requests      : {total_attempts} attempted, {total_resp} responded, {total_ok} ok (2xx)"
    );
    println!(
        "throughput    : {:.2} req/s (ok)   {:.2} req/s (all responded)",
        total_ok as f64 / secs,
        total_resp as f64 / secs
    );
    println!(
        "latency (ms)  : p50={:.2}  p90={:.2}  p99={:.2}  p99.9={:.2}  max={:.2}  mean={:.2}",
        pct(50.0),
        pct(90.0),
        pct(99.0),
        pct(99.9),
        lat.last().map_or(0.0, |v| *v as f64 / MICROS_PER_MILLI),
        mean_ms
    );
    println!("bytes sent    : {}", s.bytes_sent);
    println!("--- status histogram (reason-tagged) ---");
    for (code, n) in &s.codes {
        println!("  {} {:<22} {}", code, reason_tag(*code), n);
    }
    if s.timeouts > 0 {
        println!("  -   timeout                {}", s.timeouts);
    }
    if s.conn_errors > 0 {
        println!("  -   conn-error             {}", s.conn_errors);
    }
    let err = total_attempts.saturating_sub(total_ok);
    let err_pct = if total_attempts > 0 {
        PERCENT_SCALE * err as f64 / total_attempts as f64
    } else {
        0.0
    };
    println!("error rate    : {err_pct:.2}% ({err}/{total_attempts})");
    println!("=====================================");
}

fn reason_tag(code: u16) -> &'static str {
    match code {
        HTTP_OK | HTTP_CREATED => "ok",
        400 => "bad-request",
        401 | 403 => "auth",
        404 => "not-found",
        413 => "payload-too-large",
        429 => "quota-throttle",
        500 => "server-error",
        501 => "not-implemented",
        503 => "quorum/unavailable",
        _ => "other",
    }
}

fn parse_args() -> Result<Config, String> {
    let mut host = String::new();
    let mut port = DEFAULT_PORT;
    let mut api_key = std::env::var("LOADTEST_API_KEY").unwrap_or_default();
    let mut agent_id = DEFAULT_AGENT_ID.to_string();
    let mut namespace = DEFAULT_NAMESPACE.to_string();
    let mut scenario = Scenario::Write;
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut duration = DEFAULT_DURATION_SECS;
    let mut max_requests = 0u64;
    let mut rate = 0u64;
    let mut read_ratio = DEFAULT_READ_RATIO;
    let mut payload_bytes = DEFAULT_PAYLOAD_BYTES;
    let mut timeout = DEFAULT_TIMEOUT_SECS;
    let mut tier = DEFAULT_TIER.to_string();
    let mut list_limit = DEFAULT_LIST_LIMIT;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cursor = 0;
    while cursor < args.len() {
        let arg = &args[cursor];
        let mut next = || -> Result<String, String> {
            cursor += 1;
            args.get(cursor)
                .cloned()
                .ok_or_else(|| format!("missing value for {arg}"))
        };
        match arg.as_str() {
            "--target" | "-t" => {
                let val = next()?;
                let (parsed_host, parsed_port) = parse_target(&val)?;
                host = parsed_host;
                port = parsed_port;
            }
            "--port" => port = next()?.parse().map_err(|_| "bad --port")?,
            "--api-key" => api_key = next()?,
            "--agent-id" => agent_id = next()?,
            "--namespace" | "--ns" => namespace = next()?,
            "--scenario" | "-s" => {
                let val = next()?;
                scenario = Scenario::parse(&val).ok_or_else(|| format!("bad --scenario {val}"))?;
            }
            "--concurrency" | "-c" => {
                concurrency = next()?.parse().map_err(|_| "bad --concurrency")?;
            }
            "--duration" | "-d" => duration = next()?.parse().map_err(|_| "bad --duration")?,
            "--requests" | "-n" => max_requests = next()?.parse().map_err(|_| "bad --requests")?,
            "--rate" => rate = next()?.parse().map_err(|_| "bad --rate")?,
            "--read-ratio" => read_ratio = next()?.parse().map_err(|_| "bad --read-ratio")?,
            "--payload-bytes" => {
                payload_bytes = next()?.parse().map_err(|_| "bad --payload-bytes")?;
            }
            "--timeout" => timeout = next()?.parse().map_err(|_| "bad --timeout")?,
            "--tier" => tier = next()?,
            "--list-limit" => list_limit = next()?.parse().map_err(|_| "bad --list-limit")?,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        cursor += 1;
    }

    if host.is_empty() {
        return Err("--target is required (e.g. --target http://127.0.0.1:9077)".into());
    }
    if concurrency == 0 {
        return Err("--concurrency must be >= 1".into());
    }
    Ok(Config {
        host,
        port,
        api_key,
        agent_id,
        namespace,
        scenario,
        concurrency,
        duration: Duration::from_secs(duration),
        max_requests,
        rate,
        read_ratio,
        payload_bytes,
        timeout: Duration::from_secs(timeout),
        tier,
        list_limit,
    })
}

fn parse_target(s: &str) -> Result<(String, u16), String> {
    let s = s.trim();
    let s = s.strip_prefix("http://").unwrap_or(s);
    if s.starts_with("https://") {
        return Err("https not supported (hive speaks plain http)".into());
    }
    let s = s.trim_end_matches('/');
    if let Some((h, p)) = s.rsplit_once(':') {
        // Guard against accidentally splitting an IPv6 literal; the hive uses
        // IPv4 / hostnames, so a single trailing :port is the expected shape.
        if let Ok(port) = p.parse::<u16>() {
            return Ok((h.to_string(), port));
        }
    }
    Ok((s.to_string(), DEFAULT_PORT))
}

fn print_usage() {
    eprintln!(
        "loadtest — dependency-free ai-memory load tester\n\
\n\
USAGE:\n\
  loadtest --target http://HOST:9077 [options]\n\
\n\
OPTIONS:\n\
  -t, --target URL        target daemon, e.g. http://127.0.0.1:9077 (required)\n\
      --api-key KEY        x-api-key header (or env LOADTEST_API_KEY)\n\
      --agent-id ID        X-Agent-Id (default: loadtest)\n\
      --namespace NS       memory namespace (default: loadtest)\n\
  -s, --scenario S         write|read|recall|mixed|quota (default: write)\n\
  -c, --concurrency N      worker threads / closed-loop concurrency (default: 32)\n\
  -d, --duration SECS      run duration (default: 30; ignored if --requests)\n\
  -n, --requests N         stop after N requests (overrides --duration)\n\
      --rate RPS           open-loop global target req/s (default: closed-loop)\n\
      --read-ratio F       mixed: fraction of reads 0..1 (default: 0.8)\n\
      --payload-bytes N     write content size (default: 256)\n\
      --tier T             write tier short|mid|long (default: mid)\n\
      --list-limit N       read/recall limit (default: 20)\n\
      --timeout SECS       per-request socket timeout (default: 30)\n\
\n\
EXAMPLES:\n\
  # federated write throughput curve (run at c=1,8,32,64,128,256)\n\
  loadtest -t http://127.0.0.1:9077 --api-key KEY -s write -c 64 -d 60\n\
  # quota/limit boundary probe\n\
  loadtest -t http://127.0.0.1:9077 --api-key KEY -s quota -c 16 -n 50000\n\
  # read hot path under churn (run alongside a background write run)\n\
  loadtest -t http://127.0.0.1:9077 --api-key KEY -s recall -c 32 -d 60\n"
    );
}
