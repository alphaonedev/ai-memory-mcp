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
MAX_PACKAGE_CHARS = 214
MAX_VERSION_CHARS = 256
MAX_ADVISORY_CHARS = 19
UNAVAILABLE = "unavailable"


def diagnostic_field(value, pattern, maximum):
    """Render only bounded public identifiers, never arbitrary registry text."""
    if isinstance(value, str) and len(value) <= maximum and pattern.fullmatch(value):
        return value
    return UNAVAILABLE


class AuditError(ValueError):
    """The audit did not provide trustworthy clean evidence."""

    def __init__(self, message, *, advisory=None, package=None, version=None):
        advisory = diagnostic_field(advisory, ADVISORY_PATTERN, MAX_ADVISORY_CHARS)
        package = diagnostic_field(package, PACKAGE_PATTERN, MAX_PACKAGE_CHARS)
        version = diagnostic_field(version, VERSION_PATTERN, MAX_VERSION_CHARS)
        # All callers supply fixed message text; identity fields are validated above.
        super().__init__(f"{message}; advisory={advisory} package={package} version={version}")


def item_identity(package, item, version=None):
    """Return the direct advisory identity only when the item identifies one."""
    ids = set()
    via = item.get("via") if isinstance(item, dict) else None
    if isinstance(via, list):
        for source in via:
            url = source.get("url") if isinstance(source, dict) else None
            if isinstance(url, str) and url.startswith(ADVISORY_URL_PREFIX):
                ids.add(diagnostic_field(url.removeprefix(ADVISORY_URL_PREFIX),
                                         ADVISORY_PATTERN, MAX_ADVISORY_CHARS))
    return {"advisory": next(iter(ids)) if len(ids) == 1 else None,
            "package": package, "version": version}


def report_identity(vulnerabilities, versions):
    """Identify a unique advisory for a global error without inventing identity."""
    identities = []
    for package, item in vulnerabilities.items():
        nodes = item.get("nodes", [])
        if not isinstance(nodes, list):
            nodes = []
        values = {versions[node] for node in nodes if isinstance(node, str)
                  and node in versions and isinstance(versions[node], str)}
        identity = item_identity(package, item, next(iter(values)) if len(values) == 1 else None)
        if identity["advisory"] not in (None, UNAVAILABLE):
            identities.append(identity)
    return identities[0] if len(identities) == 1 else {}


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
    try:
        report = json.loads(output, object_pairs_hook=unique_object)
    except AuditError:
        raise AuditError("malformed report: duplicate JSON key") from None
    if not isinstance(report, dict) or "error" in report:
        raise AuditError("malformed report: missing audit report or npm error")
    if type(report.get("auditReportVersion")) is not int or report["auditReportVersion"] != AUDIT_REPORT_VERSION:
        raise AuditError("malformed report: unsupported audit report version")
    vulnerabilities = report.get("vulnerabilities")
    metadata = report.get("metadata")
    if not isinstance(vulnerabilities, dict) or not isinstance(metadata, dict):
        raise AuditError("malformed report: missing vulnerability details or metadata")
    counts = metadata.get("vulnerabilities")
    if not isinstance(counts, dict) or set(counts) != {*SEVERITIES, "total"}:
        raise AuditError("malformed report: invalid vulnerability counts")
    if any(type(count) is not int or count < 0 for count in counts.values()):
        raise AuditError("malformed report: invalid vulnerability count")
    if sum(counts[severity] for severity in SEVERITIES) != counts["total"]:
        raise AuditError("malformed report: inconsistent vulnerability total")
    observed = dict.fromkeys(SEVERITIES, 0)
    for advisory in vulnerabilities.values():
        if not isinstance(advisory, dict) or advisory.get("severity") not in SEVERITIES:
            raise AuditError("malformed report: invalid advisory severity")
        observed[advisory["severity"]] += 1
    if any(observed[severity] != counts[severity] for severity in SEVERITIES):
        raise AuditError("malformed report: vulnerability details disagree with summary")
    return vulnerabilities


def validate_exceptions(entries, today):
    """Require complete exact entries and a bounded ISO expiry date."""
    if not isinstance(entries, list):
        raise AuditError("exception list must be an array")
    allowed = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AuditError("malformed exception entry")
        identity = {key: entry.get(key) for key in ("advisory", "package", "version")}
        if EXCEPTION_FIELDS - entry.keys():
            raise AuditError("missing exception field", **identity)
        if entry.keys() - EXCEPTION_FIELDS:
            raise AuditError("extra exception field", **identity)
        for field, pattern in (("advisory", ADVISORY_PATTERN),
                               ("package", PACKAGE_PATTERN), ("version", VERSION_PATTERN)):
            if not isinstance(entry[field], str) or not pattern.fullmatch(entry[field]):
                messages = {"advisory": "malformed advisory id", "package": "malformed package",
                            "version": "malformed version"}
                raise AuditError(messages[field], **identity)
        if type(entry["issue"]) is not int or entry["issue"] <= 0:
            raise AuditError("exception needs a tracking issue", **identity)
        reason = entry["reason"]
        if not isinstance(reason, str) or not reason.strip() or not reason.isprintable():
            raise AuditError("exception needs a one-line reason", **identity)
        expiry_text = entry["expires"]
        if not isinstance(expiry_text, str):
            raise AuditError("malformed expiry date", **identity)
        try:
            expiry = date.fromisoformat(expiry_text)
        except ValueError as error:
            raise AuditError("malformed expiry date", **identity) from error
        if expiry.isoformat() != expiry_text:
            raise AuditError("malformed expiry date", **identity)
        if expiry < today:
            raise AuditError("expired entry", **identity)
        if (expiry - today).days > MAX_EXCEPTION_DAYS:
            raise AuditError("entry beyond 90-day ceiling", **identity)
        key = (entry["advisory"], entry["package"], entry["version"])
        if key in allowed:
            raise AuditError("duplicate exception", **identity)
        allowed[key] = entry
    return allowed


def node_path(node, package, identity=None):
    """Accept only normalized npm node paths for this package."""
    identity = {"package": package} if identity is None else identity
    if not isinstance(node, str) or not isinstance(package, str):
        raise AuditError("invalid package node", **identity)
    path = PurePosixPath(node)
    suffix = PurePosixPath("node_modules") / package
    if (not PACKAGE_PATTERN.fullmatch(package) or path.is_absolute()
            or str(path) != node or ".." in path.parts
            or not path.parts or path.parts[0] != "node_modules"
            or path.parts[-len(suffix.parts):] != suffix.parts):
        raise AuditError("package node does not match package", **identity)
    return path


def check_audit(output, entries, versions, today):
    """Resolve every reported via chain to exact authorized advisory leaves."""
    vulnerabilities = check_report(output)
    allowed = validate_exceptions(entries, today)
    found = set()
    dependencies = {}
    leaves = {}
    for package, item in vulnerabilities.items():
        identity = item_identity(package, item)
        if item.get("name") != package:
            raise AuditError("report package identity mismatch", **identity)
        via = item.get("via")
        nodes = item.get("nodes")
        if not isinstance(via, list) or not via or not isinstance(nodes, list) or not nodes:
            raise AuditError("missing advisory chain or package nodes", **identity)
        for node in nodes:
            node_path(node, package, identity)
        dependencies[package] = set()
        leaves[package] = set()
        for source in via:
            if isinstance(source, str):
                if source not in vulnerabilities:
                    raise AuditError("unresolved advisory dependency", **identity)
                dependencies[package].add(source)
                continue
            if (not isinstance(source, dict) or source.get("name") != package
                    or source.get("dependency") != package or source.get("severity") not in SEVERITIES):
                raise AuditError("invalid direct advisory", **identity)
            url = source.get("url")
            node_versions = {versions[node] for node in nodes if node in versions}
            identity["version"] = next(iter(node_versions)) if len(node_versions) == 1 else None
            if not isinstance(url, str) or not url.startswith(ADVISORY_URL_PREFIX):
                raise AuditError("malformed advisory id", package=package, version=identity["version"])
            advisory_id = url.removeprefix(ADVISORY_URL_PREFIX)
            if not ADVISORY_PATTERN.fullmatch(advisory_id):
                raise AuditError("malformed advisory id", package=package, version=identity["version"])
            for node in nodes:
                key = (advisory_id, package, versions.get(node))
                if key not in allowed:
                    shape = "unlisted advisory"
                    if any(candidate[0] == advisory_id for candidate in allowed):
                        shape = "stale package"
                        if any(candidate[:2] == key[:2] for candidate in allowed):
                            shape = "stale version"
                    raise AuditError(shape, advisory=advisory_id, package=package, version=key[2])
                leaves[package].add(key)
                found.add(key)
    resolved = {}
    while len(resolved) != len(vulnerabilities):
        ready = [name for name in vulnerabilities if name not in resolved
                 and dependencies[name] <= resolved.keys()]
        if not ready:
            raise AuditError("cyclic advisory dependency", **report_identity(vulnerabilities, versions))
        for name in ready:
            roots = set(leaves[name])
            for dependency in dependencies[name]:
                roots.update(resolved[dependency])
            if not roots:
                raise AuditError("advisory chain has no authorized root", package=name)
            resolved[name] = roots
    if found != allowed.keys():
        advisory, package, version = next(key for key in allowed if key not in found)
        raise AuditError("seed entry absent from report", advisory=advisory, package=package, version=version)
    return len(found)


def load_exception_file(path):
    """Read the single policy file; duplicate JSON keys are invalid."""
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except ValueError:  # includes UnicodeError and duplicate keys; the text is never echoed
        raise AuditError("malformed exception file") from None


def load_lock_json(path):
    """Read one lockfile or installed package.json; the shape is named, the text is not."""
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except ValueError:  # includes UnicodeError and duplicate keys
        raise AuditError("malformed lockfile or installed package.json") from None


def read_versions(prefix, vulnerabilities):
    """Bind advisory nodes to matching lockfile and installed package versions."""
    lock = load_lock_json(prefix / "package-lock.json")
    if not isinstance(lock, dict) or not isinstance(lock.get("packages"), dict):
        raise AuditError("missing lockfile packages")
    versions = {}
    for package, item in vulnerabilities.items():
        identity = item_identity(package, item)
        nodes = item.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            raise AuditError("missing installed package nodes", **identity)
        for node in nodes:
            relative = node_path(node, package, identity)
            locked = lock["packages"].get(node)
            identity["version"] = locked.get("version") if isinstance(locked, dict) else None
            installed_path = prefix / relative / "package.json"
            if not installed_path.resolve().is_relative_to(prefix.resolve()):
                raise AuditError("package node escapes SDK prefix", **identity)
            installed = load_lock_json(installed_path)
            if (not isinstance(installed, dict) or installed.get("name") != package
                    or not isinstance(locked, dict)
                    or not isinstance(locked.get("version"), str)
                    or not VERSION_PATTERN.fullmatch(locked["version"])
                    or installed.get("version") != locked["version"]):
                raise AuditError("stale version: installed version does not match lockfile", **identity)
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
    identity = {}
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=AUDIT_TIMEOUT_SECONDS, check=False)
        vulnerabilities = check_report(result.stdout)
        identity = report_identity(vulnerabilities, {})
        identity = {}  # a policy or lock problem is not about this advisory
        entries = load_exception_file(args.exceptions)
        versions = read_versions(args.prefix, vulnerabilities)
        accepted = check_audit(result.stdout, entries, versions, datetime.now(timezone.utc).date())
        expected_status = int(any(item["severity"] in BLOCKING_SEVERITIES
                                  for item in vulnerabilities.values()))
        if result.returncode != expected_status:
            raise AuditError("unexpected npm rc", **report_identity(vulnerabilities, versions))
    except AuditError as error:
        print(f"npm audit gate rejected report: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, subprocess.TimeoutExpired, ValueError) as error:
        # External exception messages can contain registry data, paths or credentials.
        if isinstance(error, subprocess.TimeoutExpired):
            reason = "npm timeout (TimeoutExpired)"
        elif isinstance(error, OSError):
            reason = "npm or file I/O error (OSError)"
        elif isinstance(error, UnicodeError):
            reason = "malformed report encoding (UnicodeError)"
        else:
            reason = "malformed report (ValueError)"
        print(f"npm audit gate rejected report: {AuditError(reason, **identity)}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 - fail closed with one fixed line, no traceback
        reason = f"unexpected gate error ({type(error).__name__})"
        print(f"npm audit gate rejected report: {AuditError(reason, **identity)}", file=sys.stderr)
        return 1
    print(f"npm audit gate: accepted {accepted} tracked advisories across {len(vulnerabilities)} reported packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
