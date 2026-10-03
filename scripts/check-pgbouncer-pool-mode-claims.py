#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4667 - pin the documented PgBouncer pool_mode to infra/pgbouncer/pgbouncer.ini.

Why. docs/enterprise-deployment.md section 5.6 once called PgBouncer
`pool_mode = transaction` REQUIRED while the Postgres adapter keeps state on the
server session (migration advisory lock, search_path, statement_timeout) and is
not safe behind a transaction pooler (scripts/probe-pgbouncer-pool-mode.py).
The docs, the shipped template and the prose in ROADMAP.md drifted from the
adapter and nothing noticed. This gate makes the shipped template the single
source of truth and fails when an operator-facing document claims another mode.

What it checks (fail closed):

  1. infra/pgbouncer/pgbouncer.ini has exactly one active `pool_mode = <mode>`
     line, and the mode is one of transaction / session / statement.
  2. docs/enterprise-deployment.md contains at least one fenced `pool_mode =`
     line (an empty scan is a failure, not a pass), and every `pool_mode = X`
     line in a scanned document equals the template's mode, unless a
     retirement / not-supported marker sits within two lines of it.
  3. No scanned document recommends a pooler in another mode in prose
     (`... PgBouncer ... transaction mode`, `pooler in transaction mode`,
     `transaction pooling mode`), unless a retirement / not-supported marker
     (`#4667`, `#4679`, `not supported`, `UNSAFE`, `earlier revision`, ...)
     sits within two lines of it.

Scope: docs/**/*.md and *.html (frozen trees excluded: docs/v0.*/, docs/audit/,
docs/reviews/, docs/rfc/, docs/adr*, docs/internal/, docs/BASELINE-*),
infra/**/*.md, infra/**/*.html, ROADMAP.md, README.md.

Exit codes: 0 clean, 1 a claim disagrees with the template, 2 usage / fault /
self-test failure / empty scan.

Usage:
    scripts/check-pgbouncer-pool-mode-claims.py [--root DIR]
    scripts/check-pgbouncer-pool-mode-claims.py --self-test
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
INI_REL = Path("infra") / "pgbouncer" / "pgbouncer.ini"
GUIDE_REL = Path("docs") / "enterprise-deployment.md"
MODES = ("transaction", "session", "statement")
FROZEN_PREFIXES = (
    "docs/v0.",
    "docs/audit/",
    "docs/reviews/",
    "docs/rfc/",
    "docs/adr",
    "docs/internal/",
    "docs/BASELINE-",
)
EXIT_OK, EXIT_FINDING, EXIT_FAULT = 0, 1, 2

POOL_MODE_LINE = re.compile(r"\bpool_mode\s*=\s*([A-Za-z]+)")
INI_ACTIVE = re.compile(r"^\s*pool_mode\s*=\s*([A-Za-z]+)\s*(?:[;#].*)?$")
# A pooler recommended in another mode, in prose. Each alternative names the
# pooler and a mode word in one short span.
PROSE_CLAIM = re.compile(
    r"(?:pgbouncer|pooler)[^.\n]{0,50}\b(transaction|statement)[- ](?:mode|pooling|pool)\b"
    r"|\b(transaction|statement)[- ](?:mode|pooling)\s+(?:pgbouncer|pooler)"
    r"|\b(transaction|statement)\s+pooling\s+mode\b",
    re.IGNORECASE,
)
# Markers that a line is documenting the retirement / refusal of the mode.
RETIRED = re.compile(
    r"#4667|#4679|not supported|unsupported|UNSAFE|not safe|earlier (?:revision|text|campaign rounds?)"
    r"|as planned|no longer|forbidden|refuses?\b|returns? (?:to|only)",
    re.IGNORECASE,
)
WINDOW = 2


def read_template_mode(root: Path) -> str:
    """The single active pool_mode of the shipped template (fail closed)."""
    path = root / INI_REL
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(fault("cannot read %s: %s" % (INI_REL, exc)))
    modes = []
    for line in text.splitlines():
        match = INI_ACTIVE.match(line)
        if match:
            modes.append(match.group(1).lower())
    if len(modes) != 1:
        raise SystemExit(fault("%s must hold exactly one active pool_mode line, found %d" % (INI_REL, len(modes))))
    if modes[0] not in MODES:
        raise SystemExit(fault("%s pool_mode=%r is not one of %s" % (INI_REL, modes[0], "/".join(MODES))))
    return modes[0]


def fault(message: str) -> int:
    print("check-pgbouncer-pool-mode-claims: FAULT: %s" % message, file=sys.stderr)
    return EXIT_FAULT


def scanned_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for pattern, base in (("*.md", "docs"), ("*.html", "docs"), ("*.md", "infra"), ("*.html", "infra")):
        base_dir = root / base
        if base_dir.is_dir():
            files.extend(sorted(base_dir.rglob(pattern)))
    for name in ("ROADMAP.md", "README.md"):
        if (root / name).is_file():
            files.append(root / name)
    kept = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        if any(rel.startswith(prefix) for prefix in FROZEN_PREFIXES):
            continue
        kept.append(path)
    return kept


def retired_near(lines: List[str], index: int) -> bool:
    lo, hi = max(0, index - WINDOW), min(len(lines), index + WINDOW + 1)
    return any(RETIRED.search(lines[k]) for k in range(lo, hi))


def scan_file(path: Path, rel: str, template_mode: str) -> Tuple[List[str], int]:
    """Findings for one file and the count of `pool_mode =` lines it holds."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return (["%s: unreadable: %s" % (rel, exc)], 0)
    findings: List[str] = []
    mode_lines = 0
    for index, line in enumerate(lines):
        for match in POOL_MODE_LINE.finditer(line):
            mode_lines += 1
            mode = match.group(1).lower()
            if mode in MODES and mode != template_mode and not retired_near(lines, index):
                findings.append("%s:%d: documents pool_mode = %s but %s sets %s: %s" % (rel, index + 1, mode, INI_REL.as_posix(), template_mode, line.strip()[:160]))
        prose = PROSE_CLAIM.search(line)
        if prose:
            mode = next(g for g in prose.groups() if g).lower()
            if mode != template_mode and not retired_near(lines, index):
                findings.append("%s:%d: prose recommends a %s-mode pooler but %s sets %s: %s" % (rel, index + 1, mode, INI_REL.as_posix(), template_mode, line.strip()[:160]))
    return (findings, mode_lines)


def run(root: Path) -> int:
    template_mode = read_template_mode(root)
    files = scanned_files(root)
    if not files:
        return fault("no documents found under %s (an empty scan is a failure)" % root)
    findings: List[str] = []
    guide_mode_lines = 0
    for path in files:
        rel = path.relative_to(root).as_posix()
        found, mode_lines = scan_file(path, rel, template_mode)
        findings.extend(found)
        if Path(rel) == GUIDE_REL:
            guide_mode_lines = mode_lines
    if guide_mode_lines == 0:
        return fault("%s documents no `pool_mode =` line; the pin has nothing to compare (fail closed)" % GUIDE_REL)
    if findings:
        print("check-pgbouncer-pool-mode-claims: %d claim(s) disagree with %s (pool_mode = %s):" % (len(findings), INI_REL, template_mode))
        for finding in findings:
            print("  " + finding)
        return EXIT_FINDING
    print("check-pgbouncer-pool-mode-claims: OK (%d documents scanned; template pool_mode = %s; %d pool_mode line(s) in %s)" % (len(files), template_mode, guide_mode_lines, GUIDE_REL))
    return EXIT_OK


# ---------------------------------------------------------------- self-test


def write_tree(root: Path, ini_mode: str, guide: str, extra: Optional[dict] = None) -> None:
    (root / INI_REL).parent.mkdir(parents=True, exist_ok=True)
    (root / INI_REL).write_text("[pgbouncer]\n# pool_mode = transaction (comment, ignored)\npool_mode = %s\n" % ini_mode, encoding="utf-8")
    (root / GUIDE_REL).parent.mkdir(parents=True, exist_ok=True)
    (root / GUIDE_REL).write_text(guide, encoding="utf-8")
    for rel, body in (extra or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")


def self_test() -> int:
    scratch_base = os.environ.get("TMPDIR") or str(REPO_ROOT / ".local-runs")
    Path(scratch_base).mkdir(parents=True, exist_ok=True)
    good_guide = "```ini\npool_mode = session\n```\nSession mode is supported.\n"
    cases: List[Tuple[str, str, str, dict, int]] = [
        # (name, ini mode, guide, extra files, expected exit)
        ("agreeing docs pass", "session", good_guide, {}, EXIT_OK),
        ("the #4667 defect: guide says transaction, template says session",
         "session", "```ini\npool_mode = transaction          ; REQUIRED\n```\n", {}, EXIT_FINDING),
        ("template flipped, guide still session",
         "transaction", good_guide, {}, EXIT_FINDING),
        ("prose recommending a transaction-mode pooler",
         "session", good_guide, {"ROADMAP.md": "Front the primary with a pooler in transaction mode.\n"}, EXIT_FINDING),
        ("README recommending transaction pooling mode",
         "session", good_guide, {"infra/pgbouncer/README.md": "Use PgBouncer in transaction mode for fan-in.\n"}, EXIT_FINDING),
        ("a statement-mode ini line in another doc",
         "session", good_guide, {"docs/other.md": "pool_mode = statement\n"}, EXIT_FINDING),
        ("near miss: transaction mode named as not supported (#4667)",
         "session", good_guide + "Transaction mode is not supported (#4667): PgBouncer transaction mode shares backends.\n", {}, EXIT_OK),
        ("near miss: retirement note two lines away",
         "session", good_guide, {"docs/note.md": "An earlier revision said:\n\npool_mode = transaction\n"}, EXIT_OK),
        ("near miss: historical note about earlier campaign rounds",
         "session", good_guide, {"infra/do-hive/README.md": "Earlier campaign rounds ran the daemon through a transaction-pooling PgBouncer.\n"}, EXIT_OK),
        ("near miss: frozen tree is not scanned",
         "session", good_guide, {"docs/v0.7.0/old.md": "pool_mode = transaction ; REQUIRED\n"}, EXIT_OK),
        ("near miss: transaction word with no pooler named",
         "session", good_guide, {"docs/other.md": "Each write is one transaction mode of failure analysis.\n"}, EXIT_OK),
        ("fail closed: guide with no pool_mode line (empty pin)",
         "session", "No pooler section here.\n", {}, EXIT_FAULT),
        ("fail closed: template with two active pool_mode lines",
         "session", good_guide, {}, EXIT_FAULT),
        ("fail closed: template mode is not a PgBouncer mode",
         "bogus", good_guide, {}, EXIT_FAULT),
    ]
    failures = 0
    for name, ini_mode, guide, extra, want in cases:
        with tempfile.TemporaryDirectory(dir=scratch_base) as tmp:
            root = Path(tmp)
            write_tree(root, ini_mode, guide, extra)
            if name.startswith("fail closed: template with two"):
                ini = root / INI_REL
                ini.write_text(ini.read_text(encoding="utf-8") + "pool_mode = session\n", encoding="utf-8")
            got = run_quiet(root)
        status = "ok  " if got == want else "FAIL"
        if got != want:
            failures += 1
        print("self-test %s %-66s want=%d got=%d" % (status, name, want, got))
    if failures:
        print("check-pgbouncer-pool-mode-claims: SELF-TEST FAILED (%d case(s))" % failures, file=sys.stderr)
        return EXIT_FAULT
    print("check-pgbouncer-pool-mode-claims: self-test OK (%d cases)" % len(cases))
    return EXIT_OK


def run_quiet(root: Path) -> int:
    """run() with stdout/stderr discarded and SystemExit mapped to its code."""
    saved_out, saved_err = sys.stdout, sys.stderr
    sink = open(os.devnull, "w")
    sys.stdout = sys.stderr = sink
    try:
        try:
            return run(root)
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else EXIT_FAULT
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
        sink.close()


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(REPO_ROOT), help="repository root to scan")
    parser.add_argument("--self-test", action="store_true", help="plant defects and near misses and assert the verdicts")
    args = parser.parse_args(list(argv))
    if args.self_test:
        return self_test()
    try:
        return run(Path(args.root).resolve())
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_FAULT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
