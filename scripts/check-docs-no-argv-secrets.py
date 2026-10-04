#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4577 - no-credentials-on-argv gate for the store URL.

``ai-memory serve --store-url postgres://user:password@host/db`` puts the
database password in ``/proc/<pid>/cmdline`` and ``ps auxww``, readable by
every local UID, and (in a systemd ``ExecStart=``) in a unit file. The product
already has non-argv channels (``AI_MEMORY_STORE_URL_FILE`` first, then
``AI_MEMORY_STORE_URL``; ``src/store_url.rs`` ``resolve_store_url``), so a
tracked doc, unit, template or script must not recommend the argv form.

The gate fails when a tracked text file contains a ``--store-url`` argument
whose value carries an inline userinfo password (``scheme://user:pass@``),
unless:

  * the password is a redaction token (an ellipsis, asterisks, ``REDACTED``,
    ``<redacted>``); or
  * the command is a verb with no non-argv channel at all. ``schema-init``
    takes its URL ONLY on argv (``src/cli/schema_init.rs`` ``store_url:
    String``, required); tracked as #4600. Drop the entry from
    ``ARGV_ONLY_VERBS`` when #4600 lands.

A value such as ``"$DSN"`` is not flagged: no literal credential is tracked.
The gate looks only at what is written in tracked files; it cannot see a
runtime expansion.

Usage:
  scripts/check-docs-no-argv-secrets.py             exit 0 clean, 1 on a hit,
                                                    2 on a scanner fault
  scripts/check-docs-no-argv-secrets.py --self-test prove the rule is red on
                                                    probes and green on
                                                    near-misses
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Verbs that offer no non-argv channel. verb -> tracking issue.
ARGV_ONLY_VERBS = {"schema-init": "#4600"}

# Redaction tokens that are not a credential.
REDACTION_TOKENS = ("...", "…", "***", "redacted", "<redacted>", "xxxx")

# Files that quote the pattern on purpose: this gate and its own docs.
SELF_EXEMPT = {"scripts/check-docs-no-argv-secrets.py"}

# Historical or machine-generated trees where quoted old commands are a record,
# not a recommendation: the changelog fragments and the per-PR review evidence.
SKIP_PREFIXES = ("changelog.d/", "docs/reviews/", "docs/handoff/")
SKIP_FILES = {"CHANGELOG.md"}

# `--store-url`, optional `=` or whitespace / backslash-newline continuation,
# optional opening quote, then scheme://user:PASSWORD@ (userinfo cannot contain
# `/`, `@`, whitespace or a quote; a percent-encoded password is still literal).
ARG_RE = re.compile(
    r"--store-url(?:=|(?:\s|\\)+)"
    r"[\"']?"
    r"[A-Za-z][A-Za-z0-9+.\-]*://"
    r"[^\s/@\"':]+"  # user
    r":(?P<pw>[^\s/@\"']+)"  # password (non-empty)
    r"@"
)

TEXT_SUFFIXES = {
    ".md", ".html", ".yaml", ".yml", ".tpl", ".sh", ".py", ".toml", ".txt",
    ".service", ".conf", ".ini", ".tf", ".tfvars", ".json", ".env", ".rs",
    ".csv", ".cfg", "",
}
MAX_BYTES = 4 * 1024 * 1024


def is_redaction(pw: str) -> bool:
    low = pw.lower()
    return any(tok in low for tok in REDACTION_TOKENS)


def verb_allowed(text: str, start: int) -> str:
    """Return the tracking ref when the command owning this --store-url is an
    argv-only verb, else ''. The command is the text since the last blank line
    (or 400 characters), so a continuation line still sees its verb."""
    window = text[max(0, start - 400):start]
    window = window.rsplit("\n\n", 1)[-1]
    for verb, ref in ARGV_ONLY_VERBS.items():
        if re.search(r"(?<![\w-])" + re.escape(verb) + r"(?![\w-])", window):
            return ref
    return ""


def scan_text(rel: str, text: str) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    if rel in SELF_EXEMPT:
        return hits
    for m in ARG_RE.finditer(text):
        if is_redaction(m.group("pw")):
            continue
        if verb_allowed(text, m.start()):
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = text.splitlines()[line - 1].strip() if text else ""
        hits.append((rel, line, snippet[:140]))
    return hits


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("git ls-files failed: %s" % exc) from exc
    files = [f for f in out.decode("utf-8", "replace").split("\0") if f]
    if not files:
        raise RuntimeError("git ls-files returned no files; refusing to pass on an empty scan")
    return files


def scan_paths(root: Path, files: list[str]) -> tuple[list[tuple[str, int, str]], int]:
    hits: list[tuple[str, int, str]] = []
    scanned = 0
    for rel in files:
        if rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES):
            continue
        p = root / rel
        if p.suffix.lower() not in TEXT_SUFFIXES or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        hits.extend(scan_text(rel, text))
    return hits, scanned


def run() -> int:
    try:
        files = tracked_files()
        hits, scanned = scan_paths(ROOT, files)
    except (RuntimeError, OSError) as exc:
        print("FAIL: check-docs-no-argv-secrets: scanner fault: %s" % exc, file=sys.stderr)
        return 2
    if scanned == 0:
        print("FAIL: check-docs-no-argv-secrets: scanned 0 files; refusing to pass", file=sys.stderr)
        return 2
    if hits:
        for rel, line, snippet in hits:
            print("HIT %s:%d: %s" % (rel, line, snippet), file=sys.stderr)
        print(
            "FAIL: check-docs-no-argv-secrets: %d tracked --store-url argument(s) carry an inline "
            "password (#4577). Use AI_MEMORY_STORE_URL_FILE (a 0600 file); see docs/CLI_REFERENCE.md."
            % len(hits),
            file=sys.stderr,
        )
        return 1
    print("PASS: check-docs-no-argv-secrets: %d files scanned, 0 argv credentials" % scanned)
    return 0


RED_PROBES = {
    "inline": "ai-memory serve --store-url postgres://u:hunter2@h:5432/d",
    "equals": "ai-memory serve --store-url=postgres://u:hunter2@h/d",
    "quoted": 'ExecStart=/bin/ai-memory serve --store-url "postgres://u:${db_password}@h/d"',
    "single-quoted": "x serve --store-url 'postgresql://u:p%40ss@h/d?sslmode=require'",
    "shell-var": "ssh h \"ai-memory serve --store-url 'postgres://u:$PG_PW@h/d'\"",
    "continuation": "ai-memory serve \\\n  --store-url \\\n  postgres://u:hunter2@h/d",
    "other-verb": "ai-memory curator --store-url postgres://u:hunter2@h/d",
}
GREEN_PROBES = {
    "file-form": "AI_MEMORY_STORE_URL_FILE=/etc/ai-memory/store-url ai-memory serve",
    "no-password": "ai-memory serve --store-url postgres://u@h/d",
    "no-userinfo": "ai-memory serve --store-url postgres://h:5432/d",
    "shell-expansion": 'ai-memory keys --store-url "$AI_MEMORY_STORE_URL" prune',
    "ellipsis": "ai-memory serve --store-url postgres://aimemory:...@10.0.0.4:5432/db",
    "redacted": "ai-memory serve --store-url postgres://aimemory:REDACTED@h/db",
    "ellipsis-char": "ai-memory serve --store-url postgres://user:…@h/db",
    "lookalike-flag": "wake_abab.sh --store-url-src postgres://u:p@h/d",
    "prose-mention": "the `serve --store-url` connection URL (e.g. postgres://user:pass@host/db)",
    "argv-only-verb": "ai-memory schema-init --store-url postgres://u:hunter2@h/d",
    "argv-only-verb-continued": "ai-memory schema-init \\\n  --store-url postgres://u:hunter2@h/d",
}


def self_test() -> int:
    bad = 0
    for name, text in RED_PROBES.items():
        if not scan_text("probe.md", text):
            print("SELF-TEST FAIL: red probe %r was not flagged" % name, file=sys.stderr)
            bad += 1
    for name, text in GREEN_PROBES.items():
        got = scan_text("probe.md", text)
        if got:
            print("SELF-TEST FAIL: green probe %r was flagged: %r" % (name, got), file=sys.stderr)
            bad += 1
    if scan_text("scripts/check-docs-no-argv-secrets.py", RED_PROBES["inline"]):
        print("SELF-TEST FAIL: self-exempt path was flagged", file=sys.stderr)
        bad += 1
    # End to end through the file walker, in a scratch dir inside the repo.
    scratch_parent = ROOT / ".local-runs"
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(scratch_parent)) as td:
        root = Path(td)
        (root / "bad.md").write_text(RED_PROBES["inline"] + "\n", encoding="utf-8")
        (root / "ok.md").write_text(GREEN_PROBES["file-form"] + "\n", encoding="utf-8")
        hits, scanned = scan_paths(root, ["bad.md", "ok.md"])
        if scanned != 2 or [h[0] for h in hits] != ["bad.md"]:
            print("SELF-TEST FAIL: file walk gave hits=%r scanned=%d" % (hits, scanned), file=sys.stderr)
            bad += 1
        hits, scanned = scan_paths(root, [])
        if scanned != 0:
            print("SELF-TEST FAIL: empty file list scanned something", file=sys.stderr)
            bad += 1
    if bad:
        return 2
    print("PASS: check-docs-no-argv-secrets self-test: %d red probes flagged, %d green probes clean"
          % (len(RED_PROBES), len(GREEN_PROBES)))
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
