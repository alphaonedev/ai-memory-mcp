#!/usr/bin/env python3
"""Fail closed unless npm audit verifies the SDK has no low-or-higher advisory."""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
from pathlib import Path
import subprocess
import sys

DEFAULT_PREFIX = Path("sdk/typescript")
AUDIT_TIMEOUT_SECONDS = 120
AUDIT_REPORT_VERSION = 2
SEVERITIES = ("info", "low", "moderate", "high", "critical")
BLOCKING_SEVERITIES = SEVERITIES[1:]


class AuditError(ValueError):
    """The audit did not provide trustworthy clean evidence."""


def unique_object(pairs):
    """Reject duplicate keys instead of silently discarding audit evidence."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate JSON key")
        result[key] = value
    return result


def check_report(output):
    """Validate npm's v2 schema and inspect both details and summary counts."""
    report = json.loads(output, object_pairs_hook=unique_object)
    if not isinstance(report, dict) or "error" in report:
        raise AuditError("missing audit report or npm error")
    if type(report.get("auditReportVersion")) is not int or report["auditReportVersion"] != AUDIT_REPORT_VERSION:
        raise AuditError("unsupported audit report version")
    vulnerabilities = report.get("vulnerabilities")
    metadata = report.get("metadata")
    if not isinstance(vulnerabilities, dict) or not isinstance(metadata, dict):
        raise AuditError("missing vulnerability details or metadata")
    counts = metadata.get("vulnerabilities")
    if not isinstance(counts, dict) or set(counts) != {*SEVERITIES, "total"}:
        raise AuditError("invalid vulnerability counts")
    if any(type(count) is not int or count < 0 for count in counts.values()):
        raise AuditError("invalid vulnerability count")
    if sum(counts[severity] for severity in SEVERITIES) != counts["total"]:
        raise AuditError("inconsistent vulnerability total")
    observed = dict.fromkeys(SEVERITIES, 0)
    for advisory in vulnerabilities.values():
        if not isinstance(advisory, dict) or advisory.get("severity") not in SEVERITIES:
            raise AuditError("invalid advisory severity")
        observed[advisory["severity"]] += 1
    if any(observed[severity] != counts[severity] for severity in SEVERITIES):
        raise AuditError("vulnerability details disagree with summary")
    if any(counts[severity] for severity in BLOCKING_SEVERITIES):
        raise AuditError("low-or-higher npm advisories reported")


def main(argv=None):
    """Run the complete audit, including development and optional dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    args = parser.parse_args(argv)
    command = ["npm", "audit", "--json", "--audit-level=low", "--prefix", str(args.prefix)]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=AUDIT_TIMEOUT_SECONDS, check=False)
        check_report(result.stdout)
        if result.returncode != 0:
            raise AuditError("npm audit returned a nonzero exit status")
    except (OSError, UnicodeError, subprocess.TimeoutExpired, ValueError) as error:
        # Avoid echoing untrusted registry output or credentials from npm stderr.
        print(f"npm audit gate rejected report ({type(error).__name__})", file=sys.stderr)
        return 1
    print("npm audit gate: no low-or-higher vulnerabilities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
