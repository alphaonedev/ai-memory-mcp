// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3705 — **only encrypted data in transit.**
//!
//! Operator mandate (2026-09-13, ranks with the North Star): *"there is to
//! never be any unencrypted data in transit anywhere in the ai-memory
//! architecture."* "Anywhere" is literal — no exemption for loopback,
//! localhost, a dev profile, a single-node install or a lab. Loopback is
//! shared by every local process on a multi-agent host; *peer is loopback*
//! is not *peer is trusted* (the #2502 ruling).
//!
//! This module is the ONE place the mandate is spelled out: the floor every
//! transit surface consults, the one truthy grammar, and the refusal text.
//! Transit encryption is a **floor, not a knob** — a deployment cannot fall
//! below it by omission, and it cannot be lowered by configuration either:
//! the former downgrade paths refuse boot when set, because an attacker
//! chooses when a downgrade path is taken.
//!
//! | surface | funnel | before #3705 |
//! |---|---|---|
//! | the daemon listener (every API route, MCP-over-HTTP, `/metrics`) | [`crate::daemon_runtime`] `tls_bind_guard` | plaintext by default; loopback exempt; `AI_MEMORY_REQUIRE_TLS` opt-in with a narrower grammar than its siblings |
//! | outbound federation peers (quorum, sync-daemon) | [`crate::tls::validate_peer_url_scheme`] | `http://` to loopback accepted; `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` hatch |
//! | webhook targets | [`crate::subscriptions::validate_url`] | `http://` to loopback accepted |
//! | PostgreSQL store DSN | [`crate::store::postgres::PostgresStore`] connect funnel | `sslmode=verify-full` consulted only by the enterprise posture |
//! | MCP → daemon forward URL | [`crate::config::AppConfig`] `mcp_federation_forward_url` | any scheme |
//!
//! Fail CLOSED throughout: absent, malformed or unrecognised configuration
//! REFUSES, never proceeds in cleartext. (Deliberately the opposite of #3701,
//! where entitlement fails OPEN: an entitlement failure must never cost a
//! customer their data; a transit-encryption failure must never expose it.)
//!
//! `ai-memory doctor` reports every surface's transit posture in its DEFAULT
//! report ("Transit encryption (#3705)") so a deployment that boots today
//! learns exactly what will refuse after the upgrade BEFORE it upgrades.

use anyhow::{Result, bail};

/// The issue tag every #3705 refusal and doctor line carries.
pub const ISSUE_TAG: &str = "#3705";
/// Tracing target of every transit-encryption event (listener material,
/// renewal, refusals) — one name, greppable.
pub const TRACING_TARGET: &str = "security.transit";

/// The ONE spelling of the mandate, for refusals and docs.
pub const MANDATE: &str = "only encrypted data in transit";

/// The daemon-listener requirement selector. Since #3705 it is a FLOOR:
/// unset and every canonical truthy token mean "required" (the only
/// posture); any other token — including a falsy one — refuses boot,
/// because plaintext must be impossible to select by configuration.
pub const ENV_REQUIRE_TLS: &str = "AI_MEMORY_REQUIRE_TLS";

/// Former downgrade paths. Each is now REFUSED when set to a truthy token:
/// a reachable downgrade path is the defect, not its default.
pub const REMOVED_DOWNGRADE_ENVS: &[&str] = &[
    "AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK",
    "AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS",
];

/// The only accepted `sslmode` for a PostgreSQL store DSN.
pub const PG_SSLMODE_FLOOR: &str = "verify-full";

/// #3709 item 5 — every fail-closed refusal names the command that resolves
/// it. These are the SEAM with the `ai-memory tls` subcommands (#3709 items
/// 2-4/6): the commands must satisfy the refusals exactly as spelled here.
pub const REMEDY_TLS_INIT: &str = "run `ai-memory tls init` (or let first boot generate the local certificate), or supply \
     --tls-cert/--tls-key";
pub const REMEDY_TLS_IMPORT: &str = "run `ai-memory tls import --cert <p> --key <p>`";
pub const REMEDY_TLS_RENEW: &str = "run `ai-memory tls renew`";
pub const REMEDY_PG_SSLMODE: &str = "append `?sslmode=verify-full&sslrootcert=<ca.crt>` to AI_MEMORY_STORE_URL, then run \
     `ai-memory db check-tls`";
pub const REMEDY_USE_HTTPS: &str = "change the URL to https://";
/// #3709 (3x7 audit ruling): a deployment whose DECLARED shape is not
/// `singleton` takes ENTERPRISE PKI — bring your own certificate; the
/// product never mints an unmanaged CA into an estate.
pub const REMEDY_ENTERPRISE_PKI: &str = "supply a certificate issued by your PKI: --tls-cert <fullchain.pem> --tls-key <key.pem> \
     (or `ai-memory tls import --cert <p> --key <p>`); see docs/SECURITY.md \
     \"Bring your own certificate\"";

/// Canonical falsy tokens (the substrate-wide grammar's negative half).
fn is_falsy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// How the daemon-listener selector resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequireTls {
    /// Unset: the floor applies.
    Floor,
    /// A canonical truthy token: the floor, stated.
    Affirmed,
    /// A canonical falsy token: a downgrade request — refused.
    DowngradeRequested(String),
    /// Anything else: refused, never silently widened (FBL-14).
    Unrecognised(String),
}

/// Resolve [`ENV_REQUIRE_TLS`] through the ONE truthy grammar
/// ([`crate::security_profile::is_truthy`]). Read-only.
#[must_use]
pub fn require_tls_token() -> RequireTls {
    match std::env::var(ENV_REQUIRE_TLS) {
        Err(_) => RequireTls::Floor,
        Ok(v) if v.trim().is_empty() => RequireTls::Floor,
        Ok(v) if crate::security_profile::is_truthy(&v) => RequireTls::Affirmed,
        Ok(v) if is_falsy(&v) => RequireTls::DowngradeRequested(v),
        Ok(v) => RequireTls::Unrecognised(v),
    }
}

/// The listener-TLS floor: `Ok(())` when TLS is required (always, since
/// #3705), the refusal otherwise.
///
/// # Errors
/// A falsy or unrecognised [`ENV_REQUIRE_TLS`] token: the floor cannot be
/// lowered and an unrecognised token never widens a control.
pub fn enforce_require_tls_token() -> Result<()> {
    match require_tls_token() {
        RequireTls::Floor | RequireTls::Affirmed => Ok(()),
        RequireTls::DowngradeRequested(v) => bail!(
            "{ISSUE_TAG}: {ENV_REQUIRE_TLS}={v:?} requests a plaintext listener, which the \
             mandate ({MANDATE}) makes impossible to select by configuration. Transit \
             encryption is a floor, not a knob — fix: `unset {ENV_REQUIRE_TLS}` (or set a \
             canonical truthy token); the listener then serves TLS ({REMEDY_TLS_INIT})."
        ),
        RequireTls::Unrecognised(v) => bail!(
            "{ISSUE_TAG}: {ENV_REQUIRE_TLS}={v:?} is not a recognised token (canonical truthy: \
             1/true/yes/on). An unrecognised token never widens a control, so boot is refused \
             rather than proceeding in cleartext — fix: `unset {ENV_REQUIRE_TLS}` or \
             `export {ENV_REQUIRE_TLS}=1`."
        ),
    }
}

/// The removed downgrade paths: each set to a truthy token refuses boot.
/// Returns the names that are armed (read-only).
#[must_use]
pub fn armed_downgrade_paths() -> Vec<&'static str> {
    REMOVED_DOWNGRADE_ENVS
        .iter()
        .copied()
        .filter(|env| {
            std::env::var(env)
                .ok()
                .is_some_and(|v| crate::security_profile::is_truthy(&v))
        })
        .collect()
}

/// Refuse boot when any removed downgrade path is armed.
///
/// # Errors
/// One or more of [`REMOVED_DOWNGRADE_ENVS`] is set to a truthy token.
pub fn enforce_no_downgrade_paths() -> Result<()> {
    let armed = armed_downgrade_paths();
    if armed.is_empty() {
        return Ok(());
    }
    bail!(
        "{ISSUE_TAG}: {} would select plaintext transit, a downgrade path the mandate \
         ({MANDATE}) removed: a reachable downgrade path is a defect even when never taken, \
         because an attacker chooses when it is taken — fix: `unset {}`; every listener and \
         peer carries TLS ({REMEDY_TLS_INIT}).",
        armed.join(", "),
        armed.join(" "),
    );
}

/// The refusal for a plaintext listener bind (the daemon's primary client
/// surface, `/metrics` included).
#[must_use]
pub fn plaintext_listener_refusal(host: &str, port: u16) -> String {
    format!(
        "{ISSUE_TAG}: refusing to bind http://{host}:{port}: TLS required and no certificate \
         configured — every client request, every MCP call, every response body and /metrics \
         would cross the wire unencrypted, loopback included ({MANDATE}). Fix: \
         {REMEDY_TLS_INIT}. There is no plaintext posture to select."
    )
}

/// The refusal for a plaintext URL on an outbound surface (`what` names the
/// surface: "federation peer", "webhook target", "MCP forward URL", …).
#[must_use]
pub fn plaintext_url_refusal(what: &str, url: &str) -> String {
    format!(
        "{ISSUE_TAG}: refusing {what} {url:?}: plaintext http:// would carry data in the clear \
         (loopback included — loopback is shared by every local process, and \"peer is \
         loopback\" is not \"peer is trusted\"; {MANDATE}). Fix: {REMEDY_USE_HTTPS}."
    )
}

/// Whether a URL names the plaintext `http` scheme (case-insensitive,
/// trimmed). A URL with no scheme is not "plaintext" by this predicate —
/// callers refuse it on their own terms.
#[must_use]
pub fn url_is_plaintext_http(url: &str) -> bool {
    url.trim()
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
}

/// Whether a PostgreSQL DSN pins `sslmode=verify-full`. libpq honours the
/// LAST occurrence of a repeated key, so a trailing `&sslmode=require`
/// cannot be masked by an earlier `verify-full`. Shared by the connect
/// funnel (the floor), the enterprise posture (check #15) and doctor.
#[must_use]
pub fn dsn_pins_sslmode_verify_full(dsn: &str) -> bool {
    let Some((_, query)) = dsn.split_once('?') else {
        return false;
    };
    let mut last_sslmode: Option<&str> = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k.trim().eq_ignore_ascii_case("sslmode")
        {
            last_sslmode = Some(v.trim());
        }
    }
    last_sslmode.is_some_and(|v| v.eq_ignore_ascii_case(PG_SSLMODE_FLOOR))
}

/// The refusal for a PostgreSQL DSN below the `sslmode` floor. Never echoes
/// the DSN (it may carry credentials).
#[must_use]
pub fn pg_sslmode_refusal() -> String {
    format!(
        "{ISSUE_TAG}: refusing the PostgreSQL store DSN: it does not pin \
         sslmode={PG_SSLMODE_FLOOR} (the last sslmode in the query string decides). Every row \
         of memory would cross the socket unencrypted or to an unauthenticated server \
         ({MANDATE}). Fix: {REMEDY_PG_SSLMODE}."
    )
}

/// The refusal for a deployment whose DECLARED shape is not `singleton` and
/// that has no operator-supplied certificate: the zero-config local CA is
/// for the singleton shape only (a product that mints an unmanaged CA into
/// an enterprise estate on first boot is an audit finding, not a feature —
/// #3709, 3x7 ruling). The shape named here is the operator's declaration
/// (`[deployment] shape`), never a runtime observation (#3700 ruling:
/// promotion is an operator act).
#[must_use]
pub fn fleet_needs_enterprise_pki_refusal(
    bind_host: &str,
    port: u16,
    declared: crate::config::shape::DeploymentShape,
) -> String {
    format!(
        "{ISSUE_TAG}: refusing to bind {bind_host}:{port}: this deployment declares \
         `{line}` (a FLEET-shaped estate) and no --tls-cert/--tls-key was given. The \
         zero-config local CA is minted for a SINGLETON install only; a team, production, \
         federated or hive estate takes enterprise PKI as the first-class path — a locally \
         minted CA would be an audit finding. Fix: {REMEDY_ENTERPRISE_PKI}. There is no \
         plaintext posture to select.",
        line = declared.config_line()
    )
}

/// Boot-time enforcement of the process-wide pieces of the mandate that do
/// not depend on a socket: the selector token and the removed downgrade
/// paths. Read-only; safe in the pre-runtime phase and on the live runtime.
///
/// # Errors
/// See [`enforce_require_tls_token`] and [`enforce_no_downgrade_paths`].
pub fn enforce_process_floor() -> Result<()> {
    enforce_require_tls_token()?;
    enforce_no_downgrade_paths()
}

/// Config-carried outbound URLs that must not be plaintext. Today: the MCP →
/// daemon forward URL (every MCP write fans out through it). Read-only.
///
/// # Errors
/// `mcp_federation_forward_url` names the plaintext `http` scheme.
pub fn enforce_config_urls(app_config: &crate::config::AppConfig) -> Result<()> {
    if let Some(url) = app_config.mcp_federation_forward_url.as_deref()
        && url_is_plaintext_http(url)
    {
        bail!(plaintext_url_refusal(
            "MCP forward URL (mcp_federation_forward_url)",
            url
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_floor_takes_the_last_sslmode_3705() {
        assert!(dsn_pins_sslmode_verify_full(
            "postgres://u@h/db?sslmode=verify-full"
        ));
        assert!(dsn_pins_sslmode_verify_full(
            "postgres://u@h/db?application_name=x&sslmode=Verify-Full&sslrootcert=/ca.crt"
        ));
        assert!(!dsn_pins_sslmode_verify_full("postgres://u@h/db"));
        assert!(!dsn_pins_sslmode_verify_full(
            "postgres://u@h/db?sslmode=require"
        ));
        assert!(!dsn_pins_sslmode_verify_full(
            "postgres://u@h/db?sslmode=verify-full&sslmode=require"
        ));
        assert!(!dsn_pins_sslmode_verify_full(
            "postgres://u@h/db?sslmode=verify-ca"
        ));
    }

    #[test]
    fn plaintext_scheme_predicate_3705() {
        assert!(url_is_plaintext_http("http://127.0.0.1:9077"));
        assert!(url_is_plaintext_http("  HTTP://localhost/x"));
        assert!(!url_is_plaintext_http("https://127.0.0.1:9077"));
        assert!(!url_is_plaintext_http("httpx://h"));
        assert!(!url_is_plaintext_http("peer.example:9077"));
    }

    /// #3709 item 5 — every refusal prints the command that resolves it.
    #[test]
    fn every_refusal_names_its_fix_3709() {
        assert!(plaintext_listener_refusal("127.0.0.1", 9077).contains(REMEDY_TLS_INIT));
        assert!(plaintext_url_refusal("webhook target", "http://x").contains(REMEDY_USE_HTTPS));
        assert!(pg_sslmode_refusal().contains(REMEDY_PG_SSLMODE));
        assert!(REMEDY_TLS_INIT.contains("`ai-memory tls init`"));
        assert!(REMEDY_TLS_INIT.contains("--tls-cert/--tls-key"));
    }

    #[test]
    fn refusals_name_the_surface_and_the_mandate_3705() {
        let r = plaintext_listener_refusal("127.0.0.1", 9077);
        assert!(r.contains(ISSUE_TAG) && r.contains("http://127.0.0.1:9077"));
        assert!(r.contains("loopback included") && r.contains(MANDATE));
        let r = plaintext_url_refusal("federation peer", "http://127.0.0.1:1");
        assert!(r.contains("federation peer") && r.contains("http://127.0.0.1:1"));
        assert!(r.contains("loopback included"));
        let r = pg_sslmode_refusal();
        assert!(r.contains(PG_SSLMODE_FLOOR) && !r.contains("postgres://"));
    }
}
