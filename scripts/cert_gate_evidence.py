#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Print bounded, redacted cert-bootstrap gate evidence into the job log (#7181).

``scripts/check-bootstrap-cert-gate.sh`` writes its LEG B evidence
(``bring-up.out`` and the refusal outputs) under the evidence directory. That
directory lives in the runner workspace, so when a LEG B row failed the reason
was lost with the runner. This helper prints the last ``--tail`` lines of each
evidence file under a ``--- <name> ---`` header, after redacting anything that
looks like key material or a credential, so the job log alone explains the red.

Exit codes: 0 printed, 2 usage or unreadable evidence directory.
"""
import argparse
import re
import sys
from pathlib import Path
from typing import IO, Iterable, List

DEFAULT_TAIL_LINES = 200
REDACTED = "<redacted>"
DEFAULT_NAMES = (
    "bring-up.out",
    "refuse-no-keys.out",
    "refuse-unarmed.out",
    "witness-generate.out",
    "recorder-generate.out",
)
# Order matters: the PEM header goes first so the whole line is dropped.
PEM_LINE = re.compile(r"-----(BEGIN|END)[A-Z ]*PRIVATE KEY-----")
SECRET_KEY_VALUE = re.compile(
    r"(?i)\b([a-z0-9_.-]*(?:private[_-]?key|secret|token|password|passwd|seed|api[_-]?key|signing[_-]?key)"
    r"[a-z0-9_.-]*)(\s*[:=]\s*)\S+"
)
TOKEN_SHAPES = re.compile(r"\b(?:ghp_|gho_|ghs_|github_pat_|sk-)[A-Za-z0-9_\-]{8,}")
URL_CREDENTIALS = re.compile(r"(://)[^/@\s]*@")


def redact_line(line: str) -> str:
    """Return ``line`` with key material, secret values, tokens and URL credentials masked."""
    if PEM_LINE.search(line):
        return REDACTED
    out = SECRET_KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, line)
    out = TOKEN_SHAPES.sub(REDACTED, out)
    return URL_CREDENTIALS.sub(lambda m: m.group(1) + REDACTED + "@", out)


def _tail(path: Path, tail_lines: int) -> List[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-tail_lines:] if tail_lines > 0 else []


def evidence_names(evidence_dir: Path, names: Iterable[str]) -> List[str]:
    """The requested names followed by every other ``*.log`` / ``*.out`` file in the directory."""
    ordered = list(names)
    extra = sorted(
        p.name
        for p in evidence_dir.iterdir()
        if p.is_file() and p.suffix in (".log", ".out") and p.name not in ordered
    )
    return ordered + extra


def print_evidence(evidence_dir: Path, names: Iterable[str], tail_lines: int, stream: IO[str]) -> None:
    """Print the redacted last ``tail_lines`` lines of each named evidence file to ``stream``."""
    for name in names:
        path = Path(evidence_dir) / name
        stream.write("--- %s ---\n" % name)
        if not path.is_file():
            stream.write("(not present)\n")
            continue
        for line in _tail(path, tail_lines):
            stream.write(redact_line(line) + "\n")
    stream.flush()


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL_LINES)
    parser.add_argument("names", nargs="*", help="evidence file names (default: the standard set)")
    args = parser.parse_args(argv)
    if not args.evidence_dir.is_dir():
        sys.stderr.write("evidence dir not found: %s\n" % args.evidence_dir)
        return 2
    names = evidence_names(args.evidence_dir, args.names or DEFAULT_NAMES)
    print_evidence(args.evidence_dir, names, args.tail, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
