#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reconcile unfiltered Cargo advisories with dated tracked exceptions (#8615)."""

import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / ".cargo/audit.toml"
SCRATCH = ROOT / ".local-runs"
AUDIT_COMMAND = ["cargo", "audit", "--json", "--deny", "warnings"]
AUDIT_TIMEOUT_SECONDS = 300
MAX_EXCEPTION_DAYS = 90
LATEST_EXPIRY = date(2027, 2, 3)
EXCEPTION_FIELDS = {"id", "package", "version", "issue", "expires", "reason"}
WARNING_KINDS = {"unmaintained", "unsound", "notice"}
EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def today_utc():
    """Use one UTC calendar day for every exception in an invocation."""
    return datetime.now(timezone.utc).date()


def load_policy():
    """Read the sole policy file and require normal-audit ignores to agree."""
    policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
    entries = policy.get("exceptions")
    advisories = policy.get("advisories")
    if not isinstance(entries, list) or not isinstance(advisories, dict):
        raise ValueError("missing exception policy")
    ignored = advisories.get("ignore")
    if (not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored)
            or any(not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                   for entry in entries)):
        raise ValueError("invalid exception policy")
    if sorted(ignored) != sorted(entry["id"] for entry in entries):
        raise ValueError("audit ignores and tracked exceptions disagree")
    return entries


def exception_index(entries, today):
    """Validate metadata and expiry before using exact package/version identities."""
    if not isinstance(entries, list):
        raise ValueError("exceptions must be a list")
    indexed = {}
    for entry in entries:
        if not isinstance(entry, dict) or not EXCEPTION_FIELDS.issubset(entry):
            raise ValueError("missing exception fields")
        for field in ("id", "package", "version", "reason"):
            value = entry[field]
            if not isinstance(value, str) or not value.strip() or len(value.splitlines()) != 1:
                raise ValueError("invalid exception text")
        if not EXACT_VERSION.fullmatch(entry["version"]):
            raise ValueError("exception version must be exact")
        if type(entry["issue"]) is not int or entry["issue"] <= 0:
            raise ValueError("exception requires a tracking issue")
        expiry = entry["expires"]
        if type(expiry) is not date:
            raise ValueError("exception expiry must be an ISO TOML date")
        if expiry < today:
            raise ValueError("expired exception")
        if expiry > min(LATEST_EXPIRY, today + timedelta(days=MAX_EXCEPTION_DAYS)):
            raise ValueError("exception expiry exceeds allowed horizon")
        if entry["id"] in indexed:
            raise ValueError("duplicate exception")
        indexed[entry["id"]] = (entry["package"], entry["version"])
    return indexed


def validate_report(report, entries, today):
    """Return crate/vulnerability/warning counts after complete policy reconciliation."""
    allowed = exception_index(entries, today)
    if not isinstance(report, dict):
        raise ValueError("audit report must be an object")
    vulnerabilities = report.get("vulnerabilities")
    warnings = report.get("warnings")
    settings = report.get("settings")
    lockfile = report.get("lockfile")
    if not all(isinstance(section, dict) for section in
               (vulnerabilities, warnings, settings, lockfile)):
        raise ValueError("audit report is missing required sections")
    if settings.get("ignore") != [] or "severity" not in settings or settings["severity"] is not None:
        raise ValueError("audit report suppresses advisories or omits filter settings")
    if settings.get("target_arch") != [] or settings.get("target_os") != []:
        raise ValueError("audit report filters platform advisories")
    informational = settings.get("informational_warnings")
    if (not isinstance(informational, list) or not all(isinstance(kind, str) for kind in informational)
            or not WARNING_KINDS.issubset(informational)):
        raise ValueError("audit report omits informational warnings")
    count = vulnerabilities.get("count")
    found = vulnerabilities.get("found")
    findings = vulnerabilities.get("list")
    if (type(count) is not int or type(found) is not bool
            or not isinstance(findings, list) or count != len(findings)
            or found != bool(findings)):
        raise ValueError("invalid vulnerability summary")
    if any(not isinstance(entries, list) for entries in warnings.values()):
        raise ValueError("invalid warning summary")
    warning_count = sum(len(entries) for entries in warnings.values())
    reported = set()
    all_findings = findings + [finding for group in warnings.values() for finding in group]
    for finding in all_findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid advisory finding")
        advisory = finding.get("advisory")
        package = finding.get("package")
        if not isinstance(advisory, dict) or not isinstance(package, dict):
            raise ValueError("warning or vulnerability is missing advisory identity")
        identity = advisory.get("id")
        if not isinstance(identity, str) or identity not in allowed:
            raise ValueError("unlisted advisory")
        if (advisory.get("package") != package.get("name")
                or allowed[identity] != (package.get("name"), package.get("version"))):
            raise ValueError("stale exception package or version")
        reported.add(identity)
    if reported != set(allowed):
        raise ValueError("stale exception absent from report")
    crate_count = lockfile.get("dependency-count")
    if type(crate_count) is not int or crate_count <= 0:
        raise ValueError("audit report has no valid crate count")
    return crate_count, count, warning_count


def main(argv=None):
    """Run the auditor once; every malformed, missing, or failed input denies CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-root", type=Path, default=SCRATCH)
    parser.add_argument("--advisory-db", type=Path)
    args = parser.parse_args(argv)
    try:
        entries = load_policy()
        command = AUDIT_COMMAND + ["--file", str(ROOT / "Cargo.lock")]
        if args.advisory_db is not None:
            command += ["--db", str(args.advisory_db.resolve())]
        args.scratch_root.mkdir(parents=True, exist_ok=True)
        # cargo-audit loads .cargo/audit.toml relative to cwd. This empty cwd
        # exposes every advisory; validate_report also rejects suppressed output.
        with tempfile.TemporaryDirectory(prefix="cargo-audit-", dir=args.scratch_root) as workdir:
            result = subprocess.run(
                command, cwd=workdir, capture_output=True, text=True,
                check=False, timeout=AUDIT_TIMEOUT_SECONDS)
        crate_count, vulnerabilities, warnings = validate_report(json.loads(result.stdout), entries, today_utc())
        expected_status = EXIT_FAILURE if vulnerabilities or warnings else EXIT_SUCCESS
        if result.returncode != expected_status:
            raise ValueError(f"cargo audit exited {result.returncode}")
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        # Do not echo external stderr/report text: it may contain local configuration.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print(f"Cargo audit ratchet failed: {detail}", file=sys.stderr)
        return EXIT_FAILURE
    print(f"Cargo audit ratchet: {crate_count} crates; {vulnerabilities} vulnerabilities; "
          f"{warnings} warnings; {len(entries)} tracked exceptions; 0 unaccepted advisories")
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
