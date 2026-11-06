# Cargo audit fixtures for issue 8615

`cargo_audit_clean_8615.json` and `cargo_audit_advisory_8615.json` are minimal
constructed reports for the clean and vulnerable branches of the policy.
Their section shapes follow RustSec's `Report`, `VulnerabilityInfo`, and
`WarningInfo` definitions: <https://docs.rs/rustsec/latest/rustsec/report/>.

`cargo_audit_ignored_8615.json` and `cargo_audit_unfiltered_8615.json` were
recorded on 2026-11-05 with cargo-audit 0.22.2 against base
`83757aea937d4fa57c62663927ff0a7a3176354b`. Advisory descriptions and package
dependency lists were omitted; policy fields remain as reported. Both used
`cargo audit --json --deny warnings --db <external-advisory-db>`.

The ignored report ran in the repository and exited 0, with 565 crates,
zero reported findings, and two configured ignored advisories. The
unfiltered report ran from external scratch with `--file <worktree>/Cargo.lock`
and exited 1, with the same 565 crates, one vulnerability, and one warning.
The ignored report must fail the ratchet. The unfiltered report passes only
when both exact findings have matching unexpired tracked exceptions. These
captures do not establish an audit without findings.

The gate cross-checks the ignored IDs in `.cargo/audit.toml` against the
six-field entries in `.cargo/audit-exceptions.toml`. The former remains valid
cargo-audit configuration; the latter records exact versions, expiry dates,
reasons and tracking issues. Duplicate IDs, drift between the two files and
unknown exception fields fail the gate before any finding can be accepted.
