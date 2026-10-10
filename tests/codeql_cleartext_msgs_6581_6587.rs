// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Red guard for the `CodeQL` `rust/cleartext-logging` cluster
//! #6581 / #6583 / #6585 / #6586 / #6587 (Refs #6163 #6351 #6098).
//!
//! Every alert in this cluster sits inside a `#[cfg(test)]` module of a
//! `src/` file: an `assert!` / `panic!` failure message interpolates a
//! binding that the `CodeQL` dataflow treats as sensitive (a fixture secret,
//! a captured STDOUT/STDERR/on-disk body that would carry the secret on a
//! regression, a `Debug` dump of a `Result` whose taint source is a
//! passphrase fixture, a cert fixture path, or a peer id derived from
//! certificate material). The fix keeps every assertion CONDITION
//! byte-identical and changes only what the failure message prints.
//!
//! This guard reads each alerted source file, locates its `#[cfg(test)]`
//! module, finds every assertion whose text starts at a stable anchor,
//! takes the window from the anchor to the closing `);` of that
//! assertion, and fails when the window still interpolates the tainted
//! binding. One `#[test]` per issue so each fix commit turns exactly its
//! own cells green.

use std::path::PathBuf;

/// One guarded site: an anchor that starts inside the alerted assertion
/// and the interpolations its message must no longer carry.
struct Site {
    anchor: &'static str,
    forbidden: &'static [&'static str],
    /// Minimum number of anchor occurrences that must be found, so a
    /// rename of the anchor cannot turn the guard vacuously green.
    min_hits: usize,
}

fn read_src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("guard could not read {rel}: {e}"))
}

/// The text of the file from its `#[cfg(test)]` test module onward.
fn test_module(rel: &str, src: &str) -> String {
    let mut search_from = 0;
    while let Some(off) = src[search_from..].find("#[cfg(test)]") {
        let at = search_from + off;
        let tail = &src[at..];
        // The attribute must decorate a `mod` (not a single fn / impl).
        let head: String = tail.lines().take(3).collect::<Vec<_>>().join("\n");
        if head.contains("mod ") {
            return tail.to_string();
        }
        search_from = at + "#[cfg(test)]".len();
    }
    panic!("guard found no #[cfg(test)] module in {rel}");
}

/// Collect every `(site, offending token)` pair still present.
fn violations(rel: &str, sites: &[Site]) -> Vec<String> {
    let src = read_src(rel);
    let module = test_module(rel, &src);
    let mut out = Vec::new();
    for site in sites {
        let mut hits = 0usize;
        let mut from = 0usize;
        while let Some(off) = module[from..].find(site.anchor) {
            let start = from + off;
            let end = module[start..]
                .find(");")
                .map_or(module.len(), |e| start + e);
            let window = &module[start..end];
            hits += 1;
            for tok in site.forbidden {
                if window.contains(tok) {
                    out.push(format!(
                        "{rel}: assertion at anchor `{}` still interpolates `{tok}`",
                        site.anchor
                    ));
                }
            }
            from = start + site.anchor.len();
        }
        if hits < site.min_hits {
            out.push(format!(
                "{rel}: anchor `{}` found {hits} time(s), expected >= {}",
                site.anchor, site.min_hits
            ));
        }
    }
    out
}

fn assert_clean(rel: &str, sites: &[Site]) {
    let v = violations(rel, sites);
    assert!(
        v.is_empty(),
        "cleartext assertion-message sites remain:\n{}",
        v.join("\n")
    );
}

/// #6581 — alert 167: `{res:?}` Debug dump of the quorum-approval result.
#[test]
fn cleartext_msgs_6581_cli_agents() {
    assert_clean(
        "src/cli/agents.rs",
        &[Site {
            anchor: "a met signed quorum must approve on the CLI",
            forbidden: &["{res:?}", "{res}", "{res:#?}"],
            min_hits: 1,
        }],
    );
}

/// #6583 — alerts 168/169/170: fixture `{secret}` plus the captured
/// STDOUT / STDERR / on-disk body in the migrate redaction loop. Anchored
/// on the (unchanged) assertion conditions, because the message names the
/// secret before its own descriptive text.
#[test]
fn cleartext_msgs_6583_cli_commands_config() {
    assert_clean(
        "src/cli/commands/config.rs",
        &[
            Site {
                anchor: "!stdout.contains(secret),",
                forbidden: &["{secret}", "{stdout}"],
                min_hits: 1,
            },
            Site {
                anchor: "!stderr.contains(secret),",
                forbidden: &["{secret}", "{stderr}"],
                min_hits: 1,
            },
            Site {
                anchor: " on_disk.contains(secret),",
                forbidden: &["{secret}", "{on_disk}"],
                min_hits: 1,
            },
        ],
    );
}

/// #6585 — alert 171: `"leaked {secret} in:\n{rendered}"`. The anchor is
/// the (unchanged) assertion condition, so the sibling site with the
/// identical shape is held to the same rule.
#[test]
fn cleartext_msgs_6585_config_redact() {
    assert_clean(
        "src/config_redact.rs",
        &[Site {
            anchor: "!rendered.contains(secret),",
            forbidden: &["{secret}", "{rendered}"],
            min_hits: 2,
        }],
    );
}

/// #6586 — alerts 123..127: `api_key_bind_guard` warning text and the
/// `cert_peer_binding_boot_warnings` vectors.
#[test]
fn cleartext_msgs_6586_daemon_runtime() {
    assert_clean(
        "src/daemon_runtime.rs",
        &[
            Site {
                anchor: "warning.contains(\"reverse proxy\")",
                forbidden: &["{warning}", "{warning:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn mTLS-not-configured inert",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn no-binding-map inert",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must warn open window (mode",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
            Site {
                anchor: "enforce must NOT warn open window",
                forbidden: &["{w:?}", "{w:#?}"],
                min_hits: 1,
            },
        ],
    );
}

/// #6587 — alerts 172..175: peer ids derived from certificate material
/// and the cert fixture paths.
#[test]
fn cleartext_msgs_6587_federation_mod() {
    assert_clean(
        "src/federation/mod.rs",
        &[
            Site {
                anchor: "stable-identity prefix",
                forbidden: &["peer.id", "{peer:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "must never impersonate the legacy positional shape",
                forbidden: &["peer.id", "{peer:?}"],
                min_hits: 1,
            },
            Site {
                anchor: "cert.exists(),",
                forbidden: &["{cert:?}", "{cert}", "cert.display()"],
                min_hits: 2,
            },
            Site {
                anchor: "key.exists(),",
                forbidden: &["{key:?}", "{key}", "key.display()"],
                min_hits: 1,
            },
        ],
    );
}
