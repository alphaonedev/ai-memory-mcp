#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""npm audit gate for the TypeScript SDK lockfile (#7084).

`cargo audit` gates the Rust tree; this is the equivalent for
`sdk/typescript/package-lock.json`. It runs `npm audit --json` and exits 1
when the count of findings at or above --level is non-zero.

Exit codes: 0 clean (or npm absent, announced with a ::notice::), 1 findings,
2 usage / parse / npm failure. Fails closed: an unparseable report is never
treated as clean. `--json-file PATH` reads a canned report (used by the unit
test, no network).
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

LEVELS = ("info", "low", "moderate", "high", "critical")
DEFAULT_SDK_DIR = "sdk/typescript"
DEFAULT_LEVEL = "high"
NPM_BINARY = "npm"
REPORT_UNAVAILABLE = object()
KEY_METADATA = "metadata"
KEY_VULNERABILITIES = "vulnerabilities"
KEY_SEVERITY = "severity"
KEY_TOTAL = "total"
KEY_ERROR = "error"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
FULL_INCLUDE_CLASSES = ("dev", "optional", "peer")
RUNTIME_INCLUDE_CLASSES = ("optional", "peer")


def decode_report(raw):
    """Reject duplicate decoded member names before any report data is lost."""
    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                # Keys and values can contain credentials: never echo them.
                raise ValueError("duplicate audit report member")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_members)


def load_report(args):
    """Return report and process status, or the distinct announced-skip marker."""
    if args.json_file:
        return decode_report(Path(args.json_file).read_text(encoding="utf-8")), None
    if shutil.which(NPM_BINARY) is None:
        print("::notice::npm not found on PATH; skipping npm audit gate for "
              "%s (gate NOT evaluated)" % args.dir)
        return REPORT_UNAVAILABLE
    cmd = [NPM_BINARY, "audit", "--audit-level=%s" % args.level, "--json"]
    # CLI include policy overrides NODE_ENV, aliases and inherited .npmrc lists.
    # Supplying the runtime list also replaces inherited include=dev.
    classes = RUNTIME_INCLUDE_CLASSES if args.omit_dev else FULL_INCLUDE_CLASSES
    cmd.extend("--include=" + kind for kind in classes)
    if args.omit_dev:
        cmd.append("--omit=dev")
    proc = subprocess.run(
        cmd,
        cwd=args.dir, capture_output=True, text=True, check=False,
    )
    if proc.returncode not in (EXIT_CLEAN, EXIT_FINDINGS):
        raise ValueError("npm audit operational failure (rc=%d)" % proc.returncode)
    # Raw subprocess stderr may contain credentials; status and parser location
    # provide diagnostics without copying an untrusted operational payload.
    return decode_report(proc.stdout), proc.returncode


def validate_report(report):
    """Validate complete, nonnegative counts against the reported packages."""
    if not isinstance(report, dict) or KEY_ERROR in report:
        raise ValueError("expected an audit report without an error payload")
    metadata = report.get(KEY_METADATA)
    if not isinstance(metadata, dict):
        raise ValueError("missing audit metadata")
    counts = metadata.get(KEY_VULNERABILITIES)
    vulnerabilities = report.get(KEY_VULNERABILITIES)
    if not isinstance(counts, dict) or not isinstance(vulnerabilities, dict):
        raise ValueError("missing vulnerability counts or package entries")
    for field in (*LEVELS, KEY_TOTAL):
        value = counts.get(field)
        if type(value) is not int or value < 0:
            raise ValueError("vulnerability counts must be nonnegative integers")
    observed = dict.fromkeys(LEVELS, 0)
    for entry in vulnerabilities.values():
        if not isinstance(entry, dict) or entry.get(KEY_SEVERITY) not in LEVELS:
            raise ValueError("invalid vulnerability entry severity")
        observed[entry[KEY_SEVERITY]] += 1
    if any(counts[level] != observed[level] for level in LEVELS):
        raise ValueError("vulnerability counts disagree with package entries")
    if counts[KEY_TOTAL] != sum(observed.values()):
        raise ValueError("vulnerability total disagrees with severity counts")
    return counts, vulnerabilities


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=DEFAULT_SDK_DIR)
    ap.add_argument("--level", default=DEFAULT_LEVEL, choices=LEVELS)
    ap.add_argument("--json-file", default=None,
                    help="read a canned npm audit JSON instead of running npm")
    ap.add_argument("--omit-dev", action="store_true",
                    help="pass --omit=dev: gate the shipped runtime tree only")
    args = ap.parse_args(argv)
    try:
        result = load_report(args)
    except (OSError, ValueError) as exc:
        sys.stderr.write("check-npm-audit-sdk: cannot obtain report: %s\n" % exc)
        return EXIT_ERROR
    if result is REPORT_UNAVAILABLE:
        return EXIT_CLEAN
    try:
        report, process_status = result
        counts, vulns = validate_report(report)
        floor = LEVELS.index(args.level)
        failing = sum(counts[level] for level in LEVELS[floor:])
        expected_status = EXIT_FINDINGS if failing else EXIT_CLEAN
        if process_status is not None and process_status != expected_status:
            raise ValueError("npm audit process status disagrees with report")
    except (KeyError, TypeError, ValueError) as exc:
        sys.stderr.write("check-npm-audit-sdk: malformed report: %r\n" % (exc,))
        return EXIT_ERROR
    print("npm audit (%s): %s" % (args.dir, ", ".join(
        "%s=%s" % (lv, counts[lv]) for lv in LEVELS)))
    if failing > 0:
        for name, info in sorted(vulns.items()):
            sev = info[KEY_SEVERITY]
            if sev in LEVELS and LEVELS.index(sev) >= floor:
                rng = info.get("range", "?")
                print("FAIL: %s severity=%s range=%s" % (name, sev, rng))
        print("FAIL: %d finding(s) at or above %s" % (failing, args.level))
        return EXIT_FINDINGS
    print("OK: no findings at or above %s" % args.level)
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
