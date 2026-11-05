#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail CI on Cargo advisories, warnings, or incomplete audit evidence (#8615)."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path(__file__).with_name("cargo_audit_allowlist.json")
AUDIT_COMMAND = ["cargo", "audit", "--json", "--deny", "warnings"]
AUDIT_TIMEOUT_SECONDS = 300
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def validate_report(report):
    """Return the audited crate count only for complete, unfiltered clean reports."""
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
    if count or warning_count:
        raise ValueError(f"audit reported {count} vulnerabilities and {warning_count} warnings")
    crate_count = lockfile.get("dependency-count")
    if type(crate_count) is not int or crate_count <= 0:
        raise ValueError("audit report has no valid crate count")
    return crate_count


def main(argv=None):
    """Run the auditor once; every malformed, missing, or failed input denies CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        # No exceptions are approved. Adding one requires an explicit policy change.
        if json.loads(ALLOWLIST.read_text(encoding="utf-8")) != []:
            raise ValueError("Cargo audit allowlist must be empty")
        result = subprocess.run(
            AUDIT_COMMAND, cwd=ROOT, capture_output=True, text=True,
            check=False, timeout=AUDIT_TIMEOUT_SECONDS)
        crate_count = validate_report(json.loads(result.stdout))
        if result.returncode != EXIT_SUCCESS:
            raise ValueError(f"cargo audit exited {result.returncode}")
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        # Do not echo external stderr/report text: it may contain local configuration.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print(f"Cargo audit ratchet failed: {detail}", file=sys.stderr)
        return EXIT_FAILURE
    print(f"Cargo audit ratchet: {crate_count} crates; 0 vulnerabilities; 0 warnings")
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
