// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #703 — pin the `ai-memory serve --help` output so the
//! tier-resolution clarification can't silently regress.
//!
//! The brief for #700 originally listed `ai-memory serve --tier
//! autonomous` as a valid invocation. It isn't: the `serve`
//! subcommand has no `--tier` flag, and the daemon resolves its
//! effective feature tier from `config.toml` at startup. Per-
//! invocation tier overrides are only available on `mcp` /
//! `store` / `recall`. The help text must say so loudly enough
//! that an operator reading `--help` cannot miss it.

mod common;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;

/// `ai-memory serve --help` must mention:
/// 1. that `--tier` is NOT a serve flag,
/// 2. where the daemon resolves its tier from (`config.toml`),
/// 3. which subcommands DO accept `--tier` for per-invocation overrides.
///
/// Each assertion below is intentionally fragmented so a regression on
/// one phrase fails loudly with a clear diff, rather than a single
/// long-string match that obscures which phrase went missing.
#[test]
fn serve_help_documents_tier_resolution() {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("HF_HUB_OFFLINE", "1")
        .args(["serve", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // (1) Says explicitly that --tier is not accepted on serve.
    assert!(
        stdout.contains("does NOT accept a `--tier` flag"),
        "serve --help must state that --tier is not accepted; got:\n{stdout}"
    );

    // (2) Points operator at config.toml as the resolution source.
    assert!(
        stdout.contains("config.toml"),
        "serve --help must reference config.toml as the tier source; got:\n{stdout}"
    );

    // (3) Names the per-invocation subcommands that DO take --tier.
    assert!(
        stdout.contains("mcp") && stdout.contains("store") && stdout.contains("recall"),
        "serve --help must point at mcp/store/recall for per-invocation tier; got:\n{stdout}"
    );
}

/// Smoke: `ai-memory serve --tier autonomous` must fail at parse time
/// with a clap-style "unexpected argument" error, not silently accept
/// the flag and ignore it. Pins the negative half of #703.
#[test]
fn serve_rejects_tier_flag() {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("HF_HUB_OFFLINE", "1")
        .args(["serve", "--tier", "autonomous"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    // clap surfaces "unexpected argument" (or "found argument") when an
    // unrecognised long flag is passed. We accept either phrasing to
    // remain stable across clap minor versions.
    assert!(
        stderr.contains("unexpected argument")
            || stderr.contains("found argument")
            || stderr.contains("--tier"),
        "serve --tier must be rejected at parse time; stderr was:\n{stderr}"
    );
}

/// The `serve --help` text, whitespace-flattened so a clap line wrap never
/// splits a pinned phrase.
fn serve_help_flat() -> (String, String) {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("HF_HUB_OFFLINE", "1")
        .args(["serve", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let flat = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    (stdout, flat)
}

/// #4006 — `serve --help` promised "Absent both flags = plain HTTP (same as
/// every previous release)". Since #3705 the daemon never binds plaintext:
/// with no flags it uses installed or generated TLS material, or refuses.
/// The help must not advertise a plaintext listener and must say what the
/// no-flags path actually does.
#[test]
fn serve_help_does_not_promise_plain_http_4006() {
    let (stdout, flat) = serve_help_flat();
    assert!(
        !flat.contains("plain HTTP"),
        "serve --help must not promise a plaintext listener (#4006); got:\n{stdout}"
    );
    assert!(
        flat.contains("never serves plaintext HTTP") && flat.contains("ai-memory tls import"),
        "serve --help must say the no-flags path uses installed/generated TLS \
         material or refuses (#4006); got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// #4006 / #9017: the exact rendered paragraph of every auth / TLS flag, and a
// class scan of the whole help for plaintext claim forms.
// ---------------------------------------------------------------------------

/// The `serve` about line (first line of `serve --help`).
const HELP_ABOUT: &str = "Start the HTTPS memory daemon.";

/// `--host`, rendered and whitespace-flattened (clap default included).
const HELP_HOST_PARAGRAPH: &str = "Address to bind. Without top-level `api_key` in `config.toml` a \
     non-loopback address is refused at boot (exit 75) and a loopback address serves with no \
     API-key authentication and logs a WARN; `AI_MEMORY_REQUIRE_API_KEY=1` refuses a keyless \
     bind on every address [default: 127.0.0.1]";

/// `--tls-cert`, rendered and whitespace-flattened.
const HELP_TLS_CERT_PARAGRAPH: &str = "PEM TLS certificate (may include the full chain), paired \
     with `--tls-key`; rustls, no OpenSSL. Without these flags `serve` uses material installed by \
     `ai-memory tls import` or generated locally for a singleton, and refuses otherwise; it never \
     serves plaintext HTTP (#3705, #4006)";

/// `--tls-key`, rendered and whitespace-flattened.
const HELP_TLS_KEY_PARAGRAPH: &str = "PEM TLS private key (PKCS#8, PKCS#1 RSA or SEC1 EC), paired \
     with `--tls-cert`; one without the other is refused at parse time";

/// `--mtls-allowlist`, rendered and whitespace-flattened. The gate is the TLS
/// handshake (mandatory client auth), never TCP accept.
const HELP_MTLS_ALLOWLIST_PARAGRAPH: &str = "Path to a file containing SHA-256 fingerprints of \
     trusted client certificates, one per line (case-insensitive hex, optionally with `:` \
     separators; comments start with `#`). When set, `serve` requests a client certificate in \
     the TLS handshake of every connection and fails the handshake for a peer that presents none \
     or one whose fingerprint is not on the list, so that peer never reaches an HTTP route such \
     as `/sync/push`; the gate is the TLS handshake, not TCP accept. Requires `--tls-cert` and \
     `--tls-key`. Without this flag no client certificate is requested and `serve` logs a WARN; \
     the sync endpoints still refuse a peer that is not enrolled (#1789). Layer 2 of the \
     peer-mesh crypto stack; the \
     certificate-to-agent binding (`AI_MEMORY_MTLS_AGENT_BINDING`, #8357) builds on it";

/// `(flag, pinned paragraph)` for every auth / TLS flag of `serve`.
const PINNED_PARAGRAPHS: [(&str, &str); 4] = [
    ("--host", HELP_HOST_PARAGRAPH),
    ("--tls-cert", HELP_TLS_CERT_PARAGRAPH),
    ("--tls-key", HELP_TLS_KEY_PARAGRAPH),
    ("--mtls-allowlist", HELP_MTLS_ALLOWLIST_PARAGRAPH),
];

/// Plaintext claim forms (lowercase). None may appear anywhere in the
/// rendered `serve -h` or `serve --help`: the daemon has no plaintext
/// listener, and the mTLS gate is the TLS handshake (#3705, #4006, #9017).
const PLAINTEXT_CLAIM_FORMS: [&str; 10] = [
    "plain http",
    "to https",
    "switches",
    "http://",
    "without tls",
    "cleartext",
    "tcp connection",
    "http memory daemon",
    "falls back to",
    "unencrypted",
];

/// `serve <flag>` stdout (`-h` or `--help`) from the test binary.
fn serve_help_raw(flag: &str) -> String {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("HF_HUB_OFFLINE", "1")
        .args(["serve", flag])
        .assert()
        .success();
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
}

fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The flattened paragraph under `flag` in the long help: every line after
/// the `<flag> <VALUE>` line up to the next option line.
fn long_help_paragraph(help: &str, flag: &str) -> Option<String> {
    let head = format!("{flag} <");
    let mut lines = help.lines();
    lines.find(|line| line.trim_start().starts_with(&head))?;
    let body: Vec<&str> = lines
        .take_while(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("--") || trimmed.starts_with("-h,"))
        })
        .collect();
    Some(flatten(&body.join("\n")))
}

/// #9017 X-3a — each auth / TLS flag renders exactly its pinned paragraph in
/// `--help` (flattened equality), and the same text in `-h`.
#[test]
fn serve_help_auth_tls_paragraphs_are_exact_9017() {
    let long = serve_help_raw("--help");
    let short_flat = flatten(&serve_help_raw("-h"));
    assert_eq!(
        long.lines().next().map(str::trim),
        Some(HELP_ABOUT),
        "serve about line; got:\n{long}"
    );
    for (flag, pinned) in PINNED_PARAGRAPHS {
        let got = long_help_paragraph(&long, flag)
            .unwrap_or_else(|| panic!("{flag} missing from serve --help:\n{long}"));
        assert_eq!(got, flatten(pinned), "{flag}: serve --help paragraph");
        assert!(
            short_flat.contains(&flatten(pinned)),
            "{flag}: serve -h must render {pinned:?}; got:\n{short_flat}"
        );
    }
}

/// #9017 X-3b — no plaintext claim form anywhere in `serve -h` / `--help`.
#[test]
fn serve_help_has_no_plaintext_claim_form_9017() {
    for flag in ["-h", "--help"] {
        let help = flatten(&serve_help_raw(flag)).to_lowercase();
        for form in PLAINTEXT_CLAIM_FORMS {
            assert!(
                !help.contains(form),
                "serve {flag} carries the plaintext claim form {form:?}:\n{help}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #4006 break-it cell: help = behaviour, for every bind/TLS combination the
// help describes. Each row names the help phrase that describes it and the
// outcome of a REAL `serve` boot (own `--db`, own key dir, 127.0.0.1).
// ---------------------------------------------------------------------------

/// The listen line the daemon logs just before its TLS bind.
const LISTEN_SIGNAL_TLS: &str = "ai-memory listening on https://";
/// Any plaintext listener announcement; must never appear.
const LISTEN_SIGNAL_PLAIN: &str = "listening on http://";
/// Any listener announcement; a refusal must never print it.
const LISTEN_ANY: &str = "listening";
/// The loopback bind every row uses.
const BIND_HOST: &str = "127.0.0.1";
/// The least demanding non-singleton shape (`tests/tls_verbs_3709.rs`).
const TEAM_CONFIG: &str = "[deployment]\nshape = \"team\"\n";
/// clap's usage-error exit code.
const CLAP_USAGE_EXIT: i32 = 2;
/// Upper bound for one boot to listen or to refuse.
const BOOT_BUDGET: Duration = common::DAEMON_READY_TIMEOUT;
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
/// Validity of the operator leaf, in days.
const LEAF_DAYS: i64 = 200;
const LEAF_SANS: [&str; 2] = [BIND_HOST, "localhost"];

/// Help phrases, each the sentence that describes one row.
const HELP_PAIRED: &str = "paired with";
const HELP_INSTALLED: &str = "uses material installed by";
const HELP_SINGLETON: &str = "generated locally for a singleton";
const HELP_REFUSES: &str = "and refuses otherwise";
const HELP_NEVER_PLAIN: &str = "never serves plaintext HTTP";

/// Refusal texts the daemon prints (pinned elsewhere in
/// `tests/transit_encryption_3705.rs`; here they prove help = behaviour).
/// clap `requires` on each flag: the half pair is refused at parse time,
/// naming the missing partner.
const SAYS_NEEDS_KEY: &str = "--tls-key";
const SAYS_NEEDS_CERT: &str = "--tls-cert";
const SAYS_ENTERPRISE_PKI: &str = "enterprise PKI";
const SAYS_DOWNGRADE: &str = "downgrade path";
const SAYS_REQUIRE_TLS: &str = "unset AI_MEMORY_REQUIRE_TLS";
const SAYS_OPERATOR_MATERIAL: &str = "installed by `ai-memory tls import`";

/// A non-loopback bind address (#9017 rows).
const NONLOOPBACK_HOST: &str = "0.0.0.0";
/// Exit status of every fatal daemon bootstrap failure (`EX_TEMPFAIL`,
/// `FatalShutdownError` in `src/main.rs`).
const EXIT_BOOTSTRAP_FATAL: i32 = 75;
/// One syntactically valid allowlist entry (64 hex digits).
const ALLOWLIST_FINGERPRINT: &str =
    "abababababababababababababababababababababababababababababababab";
/// The trust-model document whose boot-log quotes must match the daemon.
const SECURITY_MD: &str = "docs/SECURITY.md";

/// Help phrases of the #9017 rows (from the pinned paragraphs above).
const HELP_NONLOOPBACK_REFUSED: &str = "a non-loopback address is refused at boot (exit 75)";
const HELP_KEYLESS_LOOPBACK: &str =
    "a loopback address serves with no API-key authentication and logs a WARN";
const HELP_REQUIRE_API_KEY: &str =
    "`AI_MEMORY_REQUIRE_API_KEY=1` refuses a keyless bind on every address";
const HELP_MTLS_ON: &str = "requests a client certificate in the TLS handshake of every connection";
const HELP_MTLS_OFF: &str = "Without this flag no client certificate is requested";

/// Boot texts of the #9017 rows (`api_key_bind_guard`, `serve` in
/// `src/daemon_runtime.rs`).
const SAYS_NONLOOPBACK: &str = "refusing to bind to non-loopback address";
const SAYS_REQUIRE_API_KEY: &str = "AI_MEMORY_REQUIRE_API_KEY is set";
const SAYS_KEYLESS_WARN: &str = "API key NOT configured";
const SAYS_MTLS_OFF_WARN: &str = "TLS enabled but mTLS NOT configured";
const SAYS_MTLS_ON: &str = "mTLS enabled — client certs required";
/// The mTLS-off WARN names the real sync gate, peer enrollment (#1789; the
/// security r1 probe got `401 peer_not_enrolled` with no client certificate).
const SAYS_SYNC_ENROLLMENT_GATE: &str = "the sync endpoints (/api/v1/sync/push, \
     /api/v1/sync/since) still refuse a peer that is not enrolled";
/// The retired false claim of that WARN: sync does not accept any client.
const SAYS_SYNC_ANY_CLIENT: &str = "accept any client";
/// The two boot WARN lines `docs/SECURITY.md` quotes verbatim.
const KEYLESS_DOC_QUOTES: [&str; 2] = [SAYS_KEYLESS_WARN, SAYS_MTLS_OFF_WARN];

#[derive(Clone, Copy, Debug)]
enum Setup {
    /// `--tls-cert` alone.
    CertOnly,
    /// `--tls-key` alone.
    KeyOnly,
    /// Declared team shape, no flags, nothing installed.
    TeamNoMaterial,
    /// Singleton (no config), no flags.
    SingletonNoFlags,
    /// Declared team shape, no flags, operator pair installed by `tls import`.
    TeamImported,
    /// The removed plaintext hatch armed.
    AllowPlaintextHatch,
    /// `AI_MEMORY_REQUIRE_TLS` falsy.
    RequireTlsOff,
    /// No `api_key`, non-loopback `--host`.
    NonLoopbackNoKey,
    /// No `api_key`, loopback `--host`, singleton, no flags.
    KeylessLoopback,
    /// No `api_key`, loopback, `AI_MEMORY_REQUIRE_API_KEY=1`.
    RequireApiKey,
    /// Operator pair flags plus `--mtls-allowlist`.
    MtlsOn,
    /// Operator pair flags, no `--mtls-allowlist`.
    MtlsOff,
}

#[derive(Clone, Copy, Debug)]
enum Expect {
    /// The boot exits nonzero (with `exit` when given), saying `says`, and
    /// never announces a listener.
    Refuses {
        exit: Option<i32>,
        says: &'static str,
    },
    /// The boot announces an https listener (and never a plaintext one),
    /// saying `says` when given and never `never` when given; each log line
    /// carrying a marker in `doc_quotes` is quoted verbatim in
    /// `docs/SECURITY.md`.
    ServesHttps {
        says: Option<&'static str>,
        never: Option<&'static str>,
        doc_quotes: &'static [&'static str],
    },
}

struct Row {
    setup: Setup,
    help: &'static str,
    expect: Expect,
}

const ROWS: [Row; 12] = [
    Row {
        setup: Setup::CertOnly,
        help: HELP_PAIRED,
        expect: Expect::Refuses {
            exit: Some(CLAP_USAGE_EXIT),
            says: SAYS_NEEDS_KEY,
        },
    },
    Row {
        setup: Setup::KeyOnly,
        help: HELP_PAIRED,
        expect: Expect::Refuses {
            exit: Some(CLAP_USAGE_EXIT),
            says: SAYS_NEEDS_CERT,
        },
    },
    Row {
        setup: Setup::TeamNoMaterial,
        help: HELP_REFUSES,
        expect: Expect::Refuses {
            exit: None,
            says: SAYS_ENTERPRISE_PKI,
        },
    },
    Row {
        setup: Setup::SingletonNoFlags,
        help: HELP_SINGLETON,
        expect: Expect::ServesHttps {
            says: None,
            never: None,
            doc_quotes: &[],
        },
    },
    Row {
        setup: Setup::TeamImported,
        help: HELP_INSTALLED,
        expect: Expect::ServesHttps {
            says: Some(SAYS_OPERATOR_MATERIAL),
            never: None,
            doc_quotes: &[],
        },
    },
    Row {
        setup: Setup::AllowPlaintextHatch,
        help: HELP_NEVER_PLAIN,
        expect: Expect::Refuses {
            exit: None,
            says: SAYS_DOWNGRADE,
        },
    },
    Row {
        setup: Setup::RequireTlsOff,
        help: HELP_NEVER_PLAIN,
        expect: Expect::Refuses {
            exit: None,
            says: SAYS_REQUIRE_TLS,
        },
    },
    Row {
        setup: Setup::NonLoopbackNoKey,
        help: HELP_NONLOOPBACK_REFUSED,
        expect: Expect::Refuses {
            exit: Some(EXIT_BOOTSTRAP_FATAL),
            says: SAYS_NONLOOPBACK,
        },
    },
    Row {
        setup: Setup::KeylessLoopback,
        help: HELP_KEYLESS_LOOPBACK,
        expect: Expect::ServesHttps {
            says: Some(SAYS_KEYLESS_WARN),
            never: Some(SAYS_SYNC_ANY_CLIENT),
            doc_quotes: &KEYLESS_DOC_QUOTES,
        },
    },
    Row {
        setup: Setup::RequireApiKey,
        help: HELP_REQUIRE_API_KEY,
        expect: Expect::Refuses {
            exit: Some(EXIT_BOOTSTRAP_FATAL),
            says: SAYS_REQUIRE_API_KEY,
        },
    },
    Row {
        setup: Setup::MtlsOn,
        help: HELP_MTLS_ON,
        expect: Expect::ServesHttps {
            says: Some(SAYS_MTLS_ON),
            never: Some(SAYS_MTLS_OFF_WARN),
            doc_quotes: &[],
        },
    },
    Row {
        setup: Setup::MtlsOff,
        help: HELP_MTLS_OFF,
        expect: Expect::ServesHttps {
            says: Some(SAYS_SYNC_ENROLLMENT_GATE),
            never: Some(SAYS_MTLS_ON),
            doc_quotes: &[],
        },
    },
];

/// A child `ai-memory` sandboxed under `root` (env cleared; own key dir,
/// own `--db`, own audit dir); `config_body` declares a shape.
fn sandboxed(root: &Path, config_body: Option<&str>) -> std::process::Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key sandbox");
    }
    let xdg = root.join("home/.config");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("RUST_LOG", "info");
    // #4166: one shared helper keeps every serve boot off the embedder.
    common::serve_test_env(&mut cmd);
    match config_body {
        Some(body) => {
            let dir = xdg.join("ai-memory");
            std::fs::create_dir_all(&dir).expect("mkdir config dir");
            std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
        }
        None => {
            cmd.env("AI_MEMORY_NO_CONFIG", "1");
        }
    }
    cmd.arg("--db").arg(root.join("store.db"));
    cmd
}

/// Mint an operator pair (a CA that is not the local CA, and a leaf for
/// [`LEAF_SANS`]) under `dir`; returns `(cert, key)`.
fn operator_pair(dir: &Path) -> (PathBuf, PathBuf) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Corp Issuing CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
    let mut params = rcgen::CertificateParams::new(
        LEAF_SANS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(LEAF_DAYS);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key, &issuer).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let cert_path = dir.join("operator.pem");
    let key_path = dir.join("operator.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// What one boot did: its exit status (None = still running when it
/// announced its listener, then killed) and everything it printed.
struct Boot {
    status: Option<ExitStatus>,
    log: String,
}

/// Build the `serve` command for `setup` under `root`.
fn serve_command(setup: Setup, root: &Path, port: u16) -> std::process::Command {
    let fixtures = root.join("fixtures");
    let mut cmd = match setup {
        Setup::TeamNoMaterial => sandboxed(root, Some(TEAM_CONFIG)),
        Setup::TeamImported => {
            let (cert, key) = operator_pair(&fixtures);
            let out = sandboxed(root, Some(TEAM_CONFIG))
                .args(["tls", "import", "--host", BIND_HOST, "--cert"])
                .arg(&cert)
                .arg("--key")
                .arg(&key)
                .output()
                .expect("run tls import");
            assert!(
                out.status.success(),
                "tls import must install the operator pair: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            sandboxed(root, Some(TEAM_CONFIG))
        }
        _ => sandboxed(root, None),
    };
    let host = match setup {
        Setup::NonLoopbackNoKey => NONLOOPBACK_HOST,
        _ => BIND_HOST,
    };
    cmd.args(["serve", "--host", host, "--port", &port.to_string()]);
    match setup {
        Setup::RequireApiKey => {
            cmd.env("AI_MEMORY_REQUIRE_API_KEY", "1");
        }
        Setup::MtlsOn | Setup::MtlsOff => {
            let (cert, key) = operator_pair(&fixtures);
            cmd.arg("--tls-cert").arg(cert).arg("--tls-key").arg(key);
            if matches!(setup, Setup::MtlsOn) {
                let allowlist = fixtures.join("allowlist.txt");
                std::fs::write(&allowlist, format!("{ALLOWLIST_FINGERPRINT}\n"))
                    .expect("write mtls allowlist");
                cmd.arg("--mtls-allowlist").arg(allowlist);
            }
        }
        Setup::CertOnly => {
            cmd.arg("--tls-cert").arg(fixtures.join("absent.pem"));
        }
        Setup::KeyOnly => {
            cmd.arg("--tls-key").arg(fixtures.join("absent.key"));
        }
        Setup::AllowPlaintextHatch => {
            cmd.env("AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK", "1");
        }
        Setup::RequireTlsOff => {
            cmd.env("AI_MEMORY_REQUIRE_TLS", "0");
        }
        _ => {}
    }
    cmd
}

/// Boot `cmd` with stdout and stderr in one file under `root`; return when
/// it exits, or kill it once it logs [`LISTEN_SIGNAL_TLS`] or a plaintext
/// announcement. Panics (after reaping) when neither happens in budget.
fn boot(mut cmd: std::process::Command, root: &Path) -> Boot {
    let log_path = root.join("serve.log");
    let log = File::create(&log_path).expect("create serve log");
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("clone log handle")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn ai-memory serve");
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let deadline = Instant::now() + BOOT_BUDGET;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait serve") {
            return Boot {
                status: Some(status),
                log: read_log(),
            };
        }
        let text = read_log();
        if text.contains(LISTEN_SIGNAL_TLS) || text.contains(LISTEN_SIGNAL_PLAIN) {
            let _ = child.kill();
            let _ = child.wait();
            return Boot {
                status: None,
                log: read_log(),
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "serve neither listened nor exited within {BOOT_BUDGET:?}; log:\n{}",
                read_log()
            );
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// #4006 — every bind/TLS combination the help describes behaves as the
/// help says: the describing phrase is in `serve --help`, and a real boot
/// either refuses (named reason, no listener) or serves https only.
#[test]
fn serve_help_matches_tls_behaviour_per_combination_4006() {
    let (stdout, flat) = serve_help_flat();
    for row in &ROWS {
        assert!(
            flat.contains(row.help),
            "{:?}: serve --help must describe this combination with {:?}; got:\n{stdout}",
            row.setup,
            row.help
        );
        let root = tempfile::tempdir().unwrap();
        let port = common::free_port();
        let got = boot(serve_command(row.setup, root.path(), port), root.path());
        assert!(
            !got.log.contains(LISTEN_SIGNAL_PLAIN),
            "{:?}: a plaintext listener was announced (#4006):\n{}",
            row.setup,
            got.log
        );
        match row.expect {
            Expect::Refuses { exit, says } => {
                let status = got.status.unwrap_or_else(|| {
                    panic!(
                        "{:?}: expected a refusal, got a listener:\n{}",
                        row.setup, got.log
                    )
                });
                assert!(!status.success(), "{:?}: {}", row.setup, got.log);
                if let Some(code) = exit {
                    assert_eq!(status.code(), Some(code), "{:?}: {}", row.setup, got.log);
                }
                assert!(
                    got.log.contains(says),
                    "{:?}: want {says:?}:\n{}",
                    row.setup,
                    got.log
                );
                assert!(
                    !got.log.contains(LISTEN_ANY),
                    "{:?}: a refusal must never announce a listener:\n{}",
                    row.setup,
                    got.log
                );
            }
            Expect::ServesHttps {
                says,
                never,
                doc_quotes,
            } => {
                assert!(
                    got.status.is_none() && got.log.contains(LISTEN_SIGNAL_TLS),
                    "{:?}: expected an https listener, status {:?}:\n{}",
                    row.setup,
                    got.status,
                    got.log
                );
                if let Some(says) = says {
                    assert!(
                        got.log.contains(says),
                        "{:?}: want {says:?}:\n{}",
                        row.setup,
                        got.log
                    );
                }
                if let Some(never) = never {
                    assert!(
                        !got.log.contains(never),
                        "{:?}: must not log {never:?}:\n{}",
                        row.setup,
                        got.log
                    );
                }
                assert_doc_quotes_log(row.setup, &got.log, doc_quotes);
            }
        }
    }
}

/// Strip ANSI CSI escape sequences (tracing colours) from `text`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// #9017 X-1 — every boot-log message carrying a marker in `markers` is
/// quoted verbatim (whitespace-flattened) in `docs/SECURITY.md`: the
/// message runs from the marker to the end of its log line.
fn assert_doc_quotes_log(setup: Setup, log: &str, markers: &[&str]) {
    if markers.is_empty() {
        return;
    }
    let doc = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(SECURITY_MD))
        .expect("read docs/SECURITY.md");
    let doc_flat = flatten(&doc);
    let plain = strip_ansi(log);
    for marker in markers {
        let line = plain
            .lines()
            .find(|line| line.contains(marker))
            .unwrap_or_else(|| panic!("{setup:?}: boot log lacks {marker:?}:\n{plain}"));
        let start = line.find(marker).unwrap_or_default();
        let message = flatten(&line[start..]);
        assert!(
            doc_flat.contains(&message),
            "{setup:?}: {SECURITY_MD} must quote the boot line verbatim: {message:?}"
        );
    }
}
