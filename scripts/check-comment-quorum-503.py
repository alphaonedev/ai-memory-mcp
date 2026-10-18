#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Doc-drift gate (#7278): no comment in src/ may pair a quorum miss with 503.

A federation quorum miss answers `202 Accepted` with `quorum_met:false` via
`handlers::parity::under_replicated_response` (src/handlers/parity.rs); the
old 503 contract was removed. Comments in src/federation/mod.rs and
src/handlers/archive.rs kept describing the 503 contract after the code
changed (#7278). This gate scans every contiguous `//`, `///` and `//!`
comment block under src/ and fails when a block mentions both "quorum" and
the status code 503.

Usage:
    python3 scripts/check-comment-quorum-503.py [--root DIR]
    python3 scripts/check-comment-quorum-503.py --self-test

Exit codes: 0 clean, 1 drift found, 2 usage or self-test failure.
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

COMMENT = re.compile(r"^\s*//")
# A block that states the OLD behaviour as history or negates it is accurate,
# not drift: "pre-v0.8.1 ... 503", "NOT a 503", "never 5xx".
HISTORICAL = re.compile(
    r"pre-v0\.8\.1|not a `?503|not the pre|never 5xx|misreported", re.IGNORECASE
)
CODE_503 = re.compile(r"(?<![\w.])503(?![\w.])")


def comment_blocks(text):
    """Yield (first_line_number, block_text) for each contiguous comment block."""
    start = None
    buf = []
    for number, line in enumerate(text.splitlines(), start=1):
        if COMMENT.match(line):
            if start is None:
                start = number
            buf.append(line)
        elif start is not None:
            yield start, "\n".join(buf)
            start, buf = None, []
    if start is not None:
        yield start, "\n".join(buf)


ALLOWLIST = Path("scripts/qc-allowlists/comment-quorum-503-allow.txt")


def load_allowlist(root):
    """Repo-relative paths whose stale comments wait on a cert-gated change."""
    path = Path(root) / ALLOWLIST
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def scan(root):
    """Return a list of 'path:line: message' findings for `root/src`.

    A file on the burn-down allowlist is exempt only while it still has a
    finding; once its comments are fixed the entry is STALE and fails, so the
    list can only shrink.
    """
    findings = []
    allow = load_allowlist(root)
    seen_allowed = set()
    src = Path(root) / "src"
    if not src.is_dir():
        raise SystemExit("check-comment-quorum-503: %s is not a directory" % src)
    files = sorted(src.rglob("*.rs"))
    if not files:
        raise SystemExit("check-comment-quorum-503: no .rs files under %s" % src)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for first, block in comment_blocks(text):
            if "quorum" not in block.lower() or not CODE_503.search(block):
                continue
            if HISTORICAL.search(block):
                continue
            rel = path.relative_to(root).as_posix()
            if rel in allow:
                seen_allowed.add(rel)
                continue
            for offset, line in enumerate(block.splitlines()):
                if CODE_503.search(line):
                    findings.append(
                        "%s:%d: comment pairs a quorum miss with 503 "
                        "(real contract: 202 Accepted + quorum_met:false via "
                        "under_replicated_response): %s"
                        % (path.relative_to(root), first + offset, line.strip())
                    )
    for rel in sorted(allow - seen_allowed):
        findings.append(
            "%s: STALE allowlist entry (no quorum+503 comment left); remove it from %s"
            % (rel, ALLOWLIST)
        )
    return findings


def self_test():
    """Plant the #7278 stale text and near-miss controls in a scratch tree."""
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        src.mkdir()
        (src / "stale.rs").write_text(
            "// on a quorum miss we short-circuit with 503 so\n// operators can retry.\nfn a() {}\n",
            encoding="utf-8",
        )
        (src / "good.rs").write_text(
            "// quorum miss answers 202 Accepted + quorum_met:false\nfn b() {}\n"
            "// service unavailable: 503 when the store is down\nfn c() {}\n"
            "const PORT_5030: u16 = 5030;\n"
            "// quorum miss is NOT a 503 any more (pre-v0.8.1 it was)\nfn d() {}\n",
            encoding="utf-8",
        )
        found = scan(tmp)
        if len(found) != 1 or "stale.rs:1" not in found[0]:
            print("self-test FAILED: expected exactly stale.rs:1, got %r" % (found,))
            return 2
        (Path(tmp) / ALLOWLIST.parent).mkdir(parents=True)
        (Path(tmp) / ALLOWLIST).write_text("src/stale.rs\n", encoding="utf-8")
        if scan(tmp):
            print("self-test FAILED: an allowlisted stale.rs must pass")
            return 2
        (src / "stale.rs").write_text("fn a() {}\n", encoding="utf-8")
        found = scan(tmp)
        if len(found) != 1 or "STALE allowlist" not in found[0]:
            print("self-test FAILED: a stale allowlist entry must fail, got %r" % (found,))
            return 2
    print("self-test OK: stale quorum+503 comment caught, allowlist both ways, near-misses pass")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    findings = scan(args.root)
    for finding in findings:
        print(finding)
    if findings:
        print("check-comment-quorum-503: FAIL (%d finding(s))" % len(findings))
        return 1
    print("check-comment-quorum-503: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
