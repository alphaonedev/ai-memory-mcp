#!/usr/bin/env python3
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
import shutil
import subprocess
import sys

LEVELS = ("info", "low", "moderate", "high", "critical")


def load_report(args):
    """Return the parsed audit report, or None when npm is absent."""
    if args.json_file:
        with open(args.json_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    if shutil.which("npm") is None:
        print("::notice::npm not found on PATH; skipping npm audit gate for "
              "%s (gate NOT evaluated)" % args.dir)
        return None
    cmd = ["npm", "audit", "--audit-level=%s" % args.level, "--json"]
    if args.omit_dev:
        cmd.append("--omit=dev")
    proc = subprocess.run(
        cmd,
        cwd=args.dir, capture_output=True, text=True, check=False,
    )
    try:
        return json.loads(proc.stdout)
    except ValueError:
        sys.stderr.write("npm audit produced non-JSON output (rc=%d): %s\n"
                         % (proc.returncode, proc.stderr.strip()[:500]))
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default="sdk/typescript")
    ap.add_argument("--level", default="high", choices=LEVELS)
    ap.add_argument("--json-file", default=None,
                    help="read a canned npm audit JSON instead of running npm")
    ap.add_argument("--omit-dev", action="store_true",
                    help="pass --omit=dev: gate the shipped runtime tree only")
    args = ap.parse_args(argv)
    try:
        report = load_report(args)
    except (OSError, ValueError) as exc:
        sys.stderr.write("check-npm-audit-sdk: cannot obtain report: %s\n" % exc)
        return 2
    if report is None:
        return 0
    try:
        counts = report["metadata"]["vulnerabilities"]
        vulns = report.get("vulnerabilities", {})
        if not isinstance(counts, dict) or not isinstance(vulns, dict):
            raise TypeError("unexpected report shape")
        floor = LEVELS.index(args.level)
        failing = sum(int(counts.get(lv, 0)) for lv in LEVELS[floor:])
    except (KeyError, TypeError, ValueError) as exc:
        sys.stderr.write("check-npm-audit-sdk: malformed report: %r\n" % (exc,))
        return 2
    print("npm audit (%s): %s" % (args.dir, ", ".join(
        "%s=%s" % (lv, counts.get(lv, 0)) for lv in LEVELS)))
    if failing > 0:
        for name, info in sorted(vulns.items()):
            sev = info.get("severity", "?") if isinstance(info, dict) else "?"
            if sev in LEVELS and LEVELS.index(sev) >= floor:
                rng = info.get("range", "?")
                print("FAIL: %s severity=%s range=%s" % (name, sev, rng))
        print("FAIL: %d finding(s) at or above %s" % (failing, args.level))
        return 1
    print("OK: no findings at or above %s" % args.level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
