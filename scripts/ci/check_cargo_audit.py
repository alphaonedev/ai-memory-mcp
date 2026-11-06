#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Cross-check .cargo/audit.toml with .cargo/audit-exceptions.toml (#8615)."""

import argparse
from collections import Counter
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
EXCEPTIONS_POLICY = ROOT / ".cargo/audit-exceptions.toml"
CARGO_AUDIT_KEYS = {"advisories", "database", "output", "target", "yanked"}
SCRATCH = ROOT / ".local-runs"
AUDIT_COMMAND = ["cargo", "audit", "--json", "--deny", "warnings"]
AUDIT_TIMEOUT_SECONDS = 300
MAX_EXCEPTION_DAYS = 90
EXCEPTION_FIELDS = {"id", "package", "version", "issue", "expires", "reason"}
WARNING_KINDS = {"unmaintained", "unsound", "notice"}
EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def today_utc(now=datetime.now):
    """Read the UTC calendar day through a clock seam without global patches."""
    return now(timezone.utc).date()


def finding_identity(finding):
    """Extract only public advisory/package identity, never descriptive payloads."""
    finding = finding if isinstance(finding, dict) else {}
    advisory = finding.get("advisory")
    package = finding.get("package")
    advisory = advisory if isinstance(advisory, dict) else {}
    package = package if isinstance(package, dict) else {}
    return {"id": advisory.get("id"), "package": package.get("name"), "version": package.get("version")}


def identity_text(entry, findings=()):
    """Recover missing fields only from a uniquely matching reported identity."""
    entry = entry if isinstance(entry, dict) else {}
    candidates = [finding_identity(finding) for finding in findings]
    if isinstance(entry.get("id"), str):
        candidates = [candidate for candidate in candidates if candidate["id"] == entry["id"]]
    else:
        known = [field for field in ("package", "version") if isinstance(entry.get(field), str)]
        candidates = [candidate for candidate in candidates
                      if known and all(candidate[field] == entry[field] for field in known)]
    recovered = candidates[0] if len(candidates) == 1 else {}
    values = {field: entry.get(field) if isinstance(entry.get(field), str)
              else recovered.get(field) for field in ("id", "package", "version")}
    return " ".join(f"{field}={json.dumps(value if isinstance(value, str) else '<unavailable>')}"
                    for field, value in values.items())


def load_policy():
    """Cross-check audit.toml ignores and audit-exceptions.toml metadata once."""
    policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
    unknown = sorted(set(policy) - CARGO_AUDIT_KEYS)
    if unknown:
        raise ValueError("unknown cargo-audit fields: " + json.dumps(unknown))
    metadata = tomllib.loads(EXCEPTIONS_POLICY.read_text(encoding="utf-8"))
    entries = metadata.get("exceptions")
    advisories = policy.get("advisories")
    if not isinstance(entries, list) or not isinstance(advisories, dict):
        raise ValueError("missing exception policy")
    ignored = advisories.get("ignore")
    if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
        raise ValueError("invalid exception policy")
    malformed = [entry for entry in entries
                 if not isinstance(entry, dict) or not isinstance(entry.get("id"), str)]
    if malformed:
        raise ValueError("\n".join("missing exception fields: id; " + identity_text(entry)
                                   for entry in malformed))
    indexed = {entry["id"]: entry for entry in entries}
    messages = []
    for source, identities in (("audit ignores", ignored),
                               ("tracked exceptions", [entry["id"] for entry in entries])):
        for identity, count in sorted(Counter(identities).items()):
            if count > 1:
                messages.append(f"duplicate id in {source}; "
                                + identity_text(indexed.get(identity, {"id": identity})))
    for identity in sorted(set(ignored) ^ set(indexed)):
        messages.append("audit ignores and tracked exceptions disagree; "
                        + identity_text(indexed.get(identity, {"id": identity})))
    if messages:
        raise ValueError("\n".join(messages))
    return entries


def exception_index(entries, today, findings=(), errors=None):
    """Validate metadata and expiry before using exact package/version identities."""
    messages = [] if errors is None else errors
    if not isinstance(entries, list):
        raise ValueError("exceptions must be a list")
    indexed = {}
    for entry in entries:
        identity = identity_text(entry, findings)
        try:
            if not isinstance(entry, dict) or set(entry) != EXCEPTION_FIELDS:
                missing = sorted(EXCEPTION_FIELDS - entry.keys()) if isinstance(entry, dict) else sorted(EXCEPTION_FIELDS)
                unknown = sorted(entry.keys() - EXCEPTION_FIELDS) if isinstance(entry, dict) else []
                problems = []
                if missing:
                    problems.append("missing exception fields: " + ", ".join(missing))
                if unknown:
                    problems.append("unknown exception fields: " + json.dumps(unknown))
                raise ValueError("; ".join(problems))
            for field in ("id", "package", "version", "reason"):
                value = entry[field]
                if not isinstance(value, str) or not value.strip() or len(value.splitlines()) != 1:
                    raise ValueError(f"invalid exception text: {field}")
            if not EXACT_VERSION.fullmatch(entry["version"]):
                raise ValueError("exception version must be exact")
            if entry["id"] in indexed:
                raise ValueError("duplicate exception")
            indexed[entry["id"]] = (entry["package"], entry["version"])
            if type(entry["issue"]) is not int or entry["issue"] <= 0:
                raise ValueError("exception requires a tracking issue")
            expiry = entry["expires"]
            if type(expiry) is not date:
                raise ValueError("exception expiry must be an ISO TOML date")
            if expiry < today:
                raise ValueError(f"expired exception: expires={expiry.isoformat()} today={today.isoformat()}")
            ceiling = today + timedelta(days=MAX_EXCEPTION_DAYS)
            if expiry > ceiling:
                raise ValueError(f"exception expiry exceeds allowed horizon: expires={expiry.isoformat()} ceiling={ceiling.isoformat()}")
        except ValueError as error:
            messages.append(f"{error}; {identity}")
    if errors is None and messages:
        raise ValueError("\n".join(messages))
    return indexed


def validate_report(report, entries, today):
    """Return crate/vulnerability/warning counts after complete policy reconciliation."""
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
    messages = []
    allowed = exception_index(entries, today, all_findings, messages)
    for finding in all_findings:
        if not isinstance(finding, dict):
            messages.append("invalid advisory finding; " + identity_text({}))
            continue
        advisory = finding.get("advisory")
        package = finding.get("package")
        if not isinstance(advisory, dict) or not isinstance(package, dict):
            messages.append("warning or vulnerability is missing advisory identity; " + identity_text(finding_identity(finding)))
            continue
        identity = advisory.get("id")
        if not isinstance(identity, str) or identity not in allowed:
            messages.append("unlisted advisory; " + identity_text(finding_identity(finding)))
            continue
        if (advisory.get("package") != package.get("name")
                or allowed[identity] != (package.get("name"), package.get("version"))):
            expected = {"id": identity, "package": allowed[identity][0], "version": allowed[identity][1]}
            messages.append("stale exception package or version; reported " + identity_text(finding_identity(finding))
                            + "; configured " + identity_text(expected))
        reported.add(identity)
    for identity in sorted(set(allowed) - reported):
        entry = {"id": identity, "package": allowed[identity][0], "version": allowed[identity][1]}
        messages.append("stale exception absent from report; " + identity_text(entry))
    if messages:
        raise ValueError("\n".join(messages))
    crate_count = lockfile.get("dependency-count")
    if type(crate_count) is not int or crate_count <= 0:
        raise ValueError("audit report has no valid crate count")
    return crate_count, count, warning_count


def main(argv=None, *, today=None):
    """Run the auditor once; every malformed, missing, or failed input denies CI."""
    today = today_utc() if today is None else today
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-root", type=Path, default=SCRATCH)
    parser.add_argument("--advisory-db", type=Path)
    args = parser.parse_args(argv)
    try:
        if type(today) is not date:
            raise ValueError("today must be a date")
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
        crate_count, vulnerabilities, warnings = validate_report(json.loads(result.stdout), entries, today)
        expected_status = EXIT_FAILURE if vulnerabilities or warnings else EXIT_SUCCESS
        if result.returncode != expected_status:
            raise ValueError(f"cargo audit exited {result.returncode}")
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        # Do not echo external stderr/report text: it may contain local configuration.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        messages = detail.splitlines()
        print(f"Cargo audit ratchet: rejected; {len(messages)} diagnostic(s)", flush=True)
        for message in messages:
            print(f"Cargo audit ratchet failed: {message}", file=sys.stderr)
        return EXIT_FAILURE
    print(f"Cargo audit ratchet: {crate_count} crates; {vulnerabilities} vulnerabilities; "
          f"{warnings} warnings; {len(entries)} tracked exceptions; 0 unaccepted advisories")
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
