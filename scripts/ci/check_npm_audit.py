#!/usr/bin/env python3
"""Accept npm advisories only through exact, unexpired, issue-tracked exceptions."""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0

import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

DEFAULT_PREFIX = Path("sdk/typescript")
AUDIT_TIMEOUT_SECONDS = 120
AUDIT_REPORT_VERSION = 2
SEVERITIES = ("info", "low", "moderate", "high", "critical")
BLOCKING_SEVERITIES = SEVERITIES[1:]
INCLUDED_DEPENDENCIES = ("dev", "optional", "peer")
DEFAULT_EXCEPTIONS = Path(__file__).with_name("npm-audit-exceptions.json")
EXCEPTION_FIELDS = {"advisory", "package", "version", "issue", "expires", "reason"}
MAX_EXCEPTION_DAYS = 90
ADVISORY_PATTERN = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")
ADVISORY_URL_PREFIX = "https://github.com/advisories/"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
PACKAGE_PATTERN = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*")


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
    return vulnerabilities


def validate_exceptions(entries, today):
    """Require complete exact entries and a bounded ISO expiry date."""
    if not isinstance(entries, list):
        raise AuditError("exception list must be an array")
    allowed = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != EXCEPTION_FIELDS:
            raise AuditError("exception fields missing or unknown")
        for field, pattern in (("advisory", ADVISORY_PATTERN),
                               ("package", PACKAGE_PATTERN), ("version", VERSION_PATTERN)):
            if not isinstance(entry[field], str) or not pattern.fullmatch(entry[field]):
                raise AuditError("invalid exception identity")
        if type(entry["issue"]) is not int or entry["issue"] <= 0:
            raise AuditError("exception needs a tracking issue")
        reason = entry["reason"]
        if not isinstance(reason, str) or not reason.strip() or not reason.isprintable():
            raise AuditError("exception needs a one-line reason")
        expiry_text = entry["expires"]
        if not isinstance(expiry_text, str):
            raise AuditError("invalid exception expiry")
        try:
            expiry = date.fromisoformat(expiry_text)
        except ValueError as error:
            raise AuditError("invalid exception expiry") from error
        if expiry.isoformat() != expiry_text or not 0 <= (expiry - today).days <= MAX_EXCEPTION_DAYS:
            raise AuditError("exception expired or exceeds ninety days")
        key = (entry["advisory"], entry["package"], entry["version"])
        if key in allowed:
            raise AuditError("duplicate exception")
        allowed[key] = entry
    return allowed


def node_path(node, package):
    """Accept only normalized npm node paths for this package."""
    if not isinstance(node, str) or not isinstance(package, str):
        raise AuditError("invalid package node")
    path = PurePosixPath(node)
    suffix = PurePosixPath("node_modules") / package
    if (not PACKAGE_PATTERN.fullmatch(package) or path.is_absolute()
            or str(path) != node or ".." in path.parts
            or not path.parts or path.parts[0] != "node_modules"
            or path.parts[-len(suffix.parts):] != suffix.parts):
        raise AuditError("package node does not match package")
    return path


def check_audit(output, entries, versions, today):
    """Resolve every reported via chain to exact authorized advisory leaves."""
    vulnerabilities = check_report(output)
    allowed = validate_exceptions(entries, today)
    found = set()
    dependencies = {}
    leaves = {}
    for package, item in vulnerabilities.items():
        if item.get("name") != package:
            raise AuditError("report package identity mismatch")
        via = item.get("via")
        nodes = item.get("nodes")
        if not isinstance(via, list) or not via or not isinstance(nodes, list) or not nodes:
            raise AuditError("missing advisory chain or package nodes")
        for node in nodes:
            node_path(node, package)
        dependencies[package] = set()
        leaves[package] = set()
        for source in via:
            if isinstance(source, str):
                if source not in vulnerabilities:
                    raise AuditError("unresolved advisory dependency")
                dependencies[package].add(source)
                continue
            if (not isinstance(source, dict) or source.get("name") != package
                    or source.get("dependency") != package or source.get("severity") not in SEVERITIES):
                raise AuditError("invalid direct advisory")
            url = source.get("url")
            if not isinstance(url, str) or not url.startswith(ADVISORY_URL_PREFIX):
                raise AuditError("invalid advisory URL")
            advisory_id = url.removeprefix(ADVISORY_URL_PREFIX)
            if not ADVISORY_PATTERN.fullmatch(advisory_id):
                raise AuditError("invalid advisory id")
            for node in nodes:
                key = (advisory_id, package, versions.get(node))
                if key not in allowed:
                    raise AuditError("unlisted advisory or stale package version")
                leaves[package].add(key)
                found.add(key)
    resolved = {}
    while len(resolved) != len(vulnerabilities):
        ready = [name for name in vulnerabilities if name not in resolved
                 and dependencies[name] <= resolved.keys()]
        if not ready:
            raise AuditError("cyclic advisory dependency")
        for name in ready:
            roots = set(leaves[name])
            for dependency in dependencies[name]:
                roots.update(resolved[dependency])
            if not roots:
                raise AuditError("advisory chain has no authorized root")
            resolved[name] = roots
    if found != allowed.keys():
        raise AuditError("stale exception absent from report")
    return len(found)


def load_exception_file(path):
    """Read the single policy file; duplicate JSON keys are invalid."""
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def read_versions(prefix, vulnerabilities):
    """Bind advisory nodes to matching lockfile and installed package versions."""
    lock = json.loads((prefix / "package-lock.json").read_text(encoding="utf-8"),
                      object_pairs_hook=unique_object)
    if not isinstance(lock, dict) or not isinstance(lock.get("packages"), dict):
        raise AuditError("missing lockfile packages")
    versions = {}
    for package, item in vulnerabilities.items():
        nodes = item.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise AuditError("missing installed package nodes")
        for node in nodes:
            relative = node_path(node, package)
            installed_path = prefix / relative / "package.json"
            if not installed_path.resolve().is_relative_to(prefix.resolve()):
                raise AuditError("package node escapes SDK prefix")
            installed = json.loads(installed_path.read_text(encoding="utf-8"),
                                   object_pairs_hook=unique_object)
            locked = lock["packages"].get(node)
            if (not isinstance(installed, dict) or installed.get("name") != package
                    or not isinstance(locked, dict)
                    or not isinstance(locked.get("version"), str)
                    or not VERSION_PATTERN.fullmatch(locked["version"])
                    or installed.get("version") != locked["version"]):
                raise AuditError("installed version does not match lockfile")
            versions[node] = locked["version"]
    return versions


def main(argv=None):
    """Run the complete audit, including development and optional dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--exceptions", type=Path, default=DEFAULT_EXCEPTIONS)
    args = parser.parse_args(argv)
    command = ["npm", "audit", "--json", "--audit-level=low"]
    command.extend(f"--include={kind}" for kind in INCLUDED_DEPENDENCIES)
    command.extend(["--prefix", str(args.prefix)])
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=AUDIT_TIMEOUT_SECONDS, check=False)
        vulnerabilities = check_report(result.stdout)
        entries = load_exception_file(args.exceptions)
        versions = read_versions(args.prefix, vulnerabilities)
        accepted = check_audit(result.stdout, entries, versions, datetime.now(timezone.utc).date())
        expected_status = int(any(item["severity"] in BLOCKING_SEVERITIES
                                  for item in vulnerabilities.values()))
        if result.returncode != expected_status:
            raise AuditError("unexpected npm audit exit status")
    except (OSError, UnicodeError, subprocess.TimeoutExpired, ValueError) as error:
        # Avoid echoing untrusted registry output or credentials from npm stderr.
        print(f"npm audit gate rejected report ({type(error).__name__})", file=sys.stderr)
        return 1
    print(f"npm audit gate: accepted {accepted} tracked advisories across {len(vulnerabilities)} reported packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
