// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9954 — check #10 of the certified enterprise-federation posture: the
//! peer server-cert pin file (`AI_MEMORY_FED_PEER_FINGERPRINTS`).
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the `synchronous` / `backup_signing`
//! precedent).
//!
//! The row passes only when the file parses, through the SAME resolver the
//! runtime verifier uses (`tls::peer_fingerprint_map_from_env`), to the
//! typed non-empty [`crate::tls::PinnedFingerprints`]. A refusal names the
//! runtime's own reason, so doctor and runtime cannot disagree.

use super::{PostureCheck, check};
use crate::tls::FED_PEER_FINGERPRINTS_ENV;

const REQUIRED: &str = "<set> to a peer server-cert pin file that parses (non-empty `<host> \
                        <sha256-hex>` lines)";
const REMEDIATION: &str =
    "set AI_MEMORY_FED_PEER_FINGERPRINTS to a `<host> <sha256-hex>` pin file (#1678)";
const ACTUAL_UNSET: &str = "(unset)";

/// Check #10 — `AI_MEMORY_FED_PEER_FINGERPRINTS` names a pin file whose
/// content the runtime accepts (#9954).
pub(super) fn check_peer_fingerprints() -> PostureCheck {
    let raw = std::env::var_os(FED_PEER_FINGERPRINTS_ENV);
    let (actual, pass) = peer_pin_row(raw.as_deref());
    check(
        FED_PEER_FINGERPRINTS_ENV,
        REQUIRED,
        actual,
        pass,
        REMEDIATION,
    )
}

/// The row's `(actual, pass)` for one env value, read once by the caller:
/// the runtime resolver decides, and the path shown is the value it loaded.
fn peer_pin_row(raw: Option<&std::ffi::OsStr>) -> (String, bool) {
    match crate::tls::peer_fingerprint_map_from_value(raw) {
        Ok(Some(pins)) => (
            format!(
                "{}: {} host(s), {} pin(s)",
                std::path::Path::new(raw.unwrap_or_default()).display(),
                pins.len(),
                pins.pin_count()
            ),
            true,
        ),
        Ok(None) => (ACTUAL_UNSET.to_string(), false),
        Err(e) => (format!("{e:#}"), false),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::evaluate;
    use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
    use super::peer_pin_row;
    use crate::config::AppConfig;
    use crate::tls::FED_PEER_FINGERPRINTS_ENV;
    use crate::tls::pin_file_cases::{
        DEADLINE_MISS, Expect, build_cases, loader_verdict, with_deadline,
    };

    /// The doctor row's (pass, actual) for the env value `value`, bounded by
    /// the row deadline. The row takes the value its caller read once, so
    /// the table needs no process-environment mutation.
    fn doctor_row(value: &std::ffi::OsStr) -> (bool, String) {
        let value = value.to_os_string();
        with_deadline(move || {
            let (actual, pass) = peer_pin_row(Some(&value));
            (pass, actual)
        })
        .unwrap_or_else(|| (false, DEADLINE_MISS.to_string()))
    }

    /// The runtime resolver's acceptance of the env value `value`.
    fn runtime_accepts(value: &std::ffi::OsStr) -> Result<bool, String> {
        let value = value.to_os_string();
        with_deadline(move || {
            crate::tls::peer_fingerprint_map_from_value(Some(&value))
                .map(|o| o.is_some())
                .map_err(|e| format!("{e:#}"))
        })
        .unwrap_or_else(|| Err(DEADLINE_MISS.to_string()))
    }

    /// The doctor row's (pass, actual) through the full posture evaluation
    /// under the env as it stands.
    fn doctor_row_current() -> (bool, String) {
        with_deadline(|| {
            let checks = evaluate(&AppConfig::default());
            let c = find(&checks, FED_PEER_FINGERPRINTS_ENV);
            (c.pass, c.actual.clone())
        })
        .unwrap_or_else(|| (false, DEADLINE_MISS.to_string()))
    }

    /// #9954 — the doctor row passes only on content the runtime accepts,
    /// and names the exact runtime reason on every refusal: empty,
    /// whitespace-only, comment-only, wrong length, wrong alphabet, wrong
    /// algorithm prefix, unreadable, a directory, a dangling symlink, a
    /// FIFO, bad UTF-8 and an oversized file are each FAIL.
    #[test]
    fn peer_pin_row_degenerate_table_9954() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut wrong = Vec::new();
        for case in build_cases(dir.path()) {
            let (pass, actual) = doctor_row(case.path.as_os_str());
            let want = match &case.expect {
                Expect::Accept { hosts, pins } => (
                    true,
                    format!("{}: {hosts} host(s), {pins} pin(s)", case.path.display()),
                ),
                Expect::Refuse(reason) => (false, reason.clone()),
            };
            if (pass, actual.clone()) != want {
                wrong.push(format!(
                    "{}: got ({pass}, {actual:?}), want {want:?}",
                    case.name
                ));
            }
        }

        // The env value is used exactly as the runtime resolver uses it: an
        // exactly-empty value is unset; a blank or padded value is a path
        // (no trimming), so the doctor never passes a value the runtime
        // refuses.
        let valid = dir.path().join("valid");
        let padded = format!("  {}  ", valid.display());
        for (name, value, want) in [
            ("empty value", String::new(), (false, "(unset)".to_string())),
            (
                "blank value",
                "   ".to_string(),
                (
                    false,
                    "failed to read peer fingerprint file from    : No such file or directory \
                     (os error 2)"
                        .to_string(),
                ),
            ),
            (
                "padded path",
                padded.clone(),
                (
                    false,
                    format!(
                        "failed to read peer fingerprint file from {padded}: No such file or \
                         directory (os error 2)"
                    ),
                ),
            ),
        ] {
            let got = doctor_row(std::ffi::OsStr::new(&value));
            if got != want {
                wrong.push(format!("{name}: got {got:?}, want {want:?}"));
            }
        }
        let (actual, pass) = peer_pin_row(None);
        if (pass, actual.clone()) != (false, "(unset)".to_string()) {
            wrong.push(format!("unset: got ({pass}, {actual:?})"));
        }
        assert!(wrong.is_empty(), "doctor rows wrong:\n{}", wrong.join("\n"));
    }

    /// #9954 — agreement: over the same table, the doctor verdict equals
    /// the runtime loader's verdict equals the runtime resolver's verdict,
    /// row by row. Doctor and runtime never disagree.
    #[test]
    fn peer_pin_row_agrees_with_runtime_9954() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cases: Vec<(String, std::ffi::OsString)> = build_cases(dir.path())
            .into_iter()
            .map(|c| (c.name.to_string(), c.path.into_os_string()))
            .collect();
        let valid = dir.path().join("valid");
        cases.push(("blank value".into(), "   ".into()));
        cases.push((
            "padded path".into(),
            format!(" {} ", valid.display()).into(),
        ));
        let mut disagree = Vec::new();
        for (name, value) in cases {
            let (doctor_pass, actual) = doctor_row(&value);
            let runtime = runtime_accepts(&value);
            let loader = loader_verdict(std::path::Path::new(&value));
            let runtime_pass = runtime == Ok(true);
            let loader_pass = matches!(loader, Expect::Accept { .. });
            if doctor_pass != runtime_pass || doctor_pass != loader_pass {
                disagree.push(format!(
                    "{name}: doctor ({doctor_pass}, {actual:?}) runtime {runtime:?} loader {loader:?}"
                ));
            }
        }
        assert!(
            disagree.is_empty(),
            "doctor and runtime disagree:\n{}",
            disagree.join("\n")
        );
    }

    /// #9954 — wiring through the full evaluation: the hardened fixture's
    /// pin file is itself valid content (a generated fingerprint), so the
    /// fully-hardened posture passes on content, not on file existence;
    /// and with the knob cleared the same row reads `(unset)` and fails.
    #[test]
    fn hardened_fixture_pin_file_is_valid_9954() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::peer_pins::tests::hardened_fixture_pin_file_is_valid_9954",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let fp_file = set_fully_hardened_env();
        assert_eq!(
            loader_verdict(fp_file.path()),
            Expect::Accept { hosts: 1, pins: 1 }
        );
        assert_eq!(
            doctor_row_current(),
            (
                true,
                format!("{}: 1 host(s), 1 pin(s)", fp_file.path().display())
            )
        );
        // SAFETY: env_lock() is held in an env-isolated child.
        unsafe {
            clear_all();
        }
        assert_eq!(doctor_row_current(), (false, "(unset)".to_string()));
    }
}
