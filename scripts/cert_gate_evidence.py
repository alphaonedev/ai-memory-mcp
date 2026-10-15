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

Modes: the default prints evidence; ``--write-redacted OUT`` writes a fully
redacted copy for the CI failure artifact; ``--finalize STATE`` is the gate's
EXIT trap (report LEG B evidence on a LEG B failure, then clean up).

Exit codes: 0 done, 2 usage or unreadable evidence directory (the offending
argument is never echoed).
"""
import argparse
import re
import shutil
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
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]*-----")
# A secret-ish name, an optional closing quote, then ``:`` / ``=`` / whitespace,
# then an optionally quoted value. Covers ``k=v``, ``"k": "v"``, ``secret key: v``
# and ``token v``.
SECRET_KEY_VALUE = re.compile(
    r"(?i)(?<![a-z0-9])([a-z0-9_.-]*"
    r"(?:private[_ -]?key|secret|token|password|passwd|seed|api[_ -]?key|signing[_ -]?key|credential)"
    r"(?:[ _.-]?(?:key|b64|hex|value|id))?[a-z0-9_.-]*)"
    r"([\"']?(?:\s*[:=]\s*|\s+))(\"[^\"]*\"|'[^']*'|\S+)"
)
AUTHORIZATION = re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*).*")
BEARER = re.compile(r"(?i)\b(bearer\s+)\S+")
TOKEN_SHAPES = re.compile(r"\b(?:ghp_|gho_|ghs_|github_pat_|sk-)[A-Za-z0-9_\-]{8,}")
URL_CREDENTIALS = re.compile(r"(://)[^/@\s]*@")
# Long runs: 64+ hex chars (a 32-byte key or digest) and 43+ base64/base64url
# chars (a 32-byte key encodes to 43). Masked unless the line is allowlisted.
LONG_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64,}(?![0-9A-Za-z])")
LONG_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{43,}={0,2}")
# Explicit allowlist (public material only): a line whose key is one of these
# names keeps its long run, so a public key stays debuggable in the log.
PUBLIC_KEY_LINE = re.compile(
    r"(?i)^\s*[\"']?(?:pub_b64|pub_hex|pubkey|public_key|public_key_b64|public_key_hex)[\"']?\s*[:=]"
)
# Evidence files that may carry connection settings: never copied or uploaded.
EXCLUDED_PREFIXES = ("pg-posture-", "driverless-posture-")
USAGE_ERROR = "usage error (arguments not echoed)"


class Redactor:
    """Stateful line redactor: tracks whether we are inside a PEM block."""

    def __init__(self) -> None:
        self.in_pem = False

    def line(self, line: str) -> str:
        """Return ``line`` with key material, secret values, tokens and credentials masked."""
        if self.in_pem:
            if PEM_END.search(line):
                self.in_pem = False
            return REDACTED
        if PEM_BEGIN.search(line):
            self.in_pem = not PEM_END.search(line)
            return REDACTED
        out = AUTHORIZATION.sub(lambda m: m.group(1) + REDACTED, line)
        out = BEARER.sub(lambda m: m.group(1) + REDACTED, out)
        out = SECRET_KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)
        out = TOKEN_SHAPES.sub(REDACTED, out)
        out = URL_CREDENTIALS.sub(lambda m: m.group(1) + REDACTED + "@", out)
        if not PUBLIC_KEY_LINE.search(line):
            out = LONG_HEX.sub(REDACTED, out)
            out = LONG_B64.sub(REDACTED, out)
        return out


def redact_line(line: str) -> str:
    """Redact one standalone line (no PEM-block state)."""
    return Redactor().line(line)


def redact_lines(lines: Iterable[str]) -> List[str]:
    """Redact a sequence of lines, masking whole PEM blocks."""
    red = Redactor()
    return [red.line(x) for x in lines]


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
        full = path.read_text(encoding="utf-8", errors="replace").splitlines()
        masked = redact_lines(full)
        for line in masked[-tail_lines:] if tail_lines > 0 else []:
            stream.write(line + "\n")
    stream.flush()


def write_redacted(evidence_dir: Path, out_dir: Path) -> int:
    """Write a fully redacted copy of the evidence files to ``out_dir`` (replaced).

    Posture outputs are skipped. A missing evidence dir yields an empty copy.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.iterdir():
        if old.is_file():
            old.unlink()
    if not evidence_dir.is_dir():
        return 0
    for path in sorted(evidence_dir.iterdir()):
        if not path.is_file() or path.name.startswith(EXCLUDED_PREFIXES):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
        (out_dir / path.name).write_text("\n".join(redact_lines(text)) + "\n", encoding="utf-8")
    return 0


def _safe_remove(raw: str) -> None:
    target = Path(raw)
    if not raw or not target.is_absolute() or target == Path(target.anchor):
        return
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(str(target), ignore_errors=True)
    elif target.exists() or target.is_symlink():
        target.unlink()


def finalize(state_dir: Path, evidence_dir: Path, tail_lines: int, stream: IO[str]) -> int:
    """EXIT-trap body of the gate: report LEG B evidence on a LEG B failure, then clean up.

    ``state_dir/fail-rows`` holds ``<phase><TAB><message>`` per failed row and
    ``state_dir/cleanup-list`` one absolute path per line. Never raises: the
    shell trap keeps the gate's own exit status.
    """
    rows = state_dir / "fail-rows"
    try:
        leg_b = rows.is_file() and any(
            ln.split("\t", 1)[0] == "B"
            for ln in rows.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if leg_b and evidence_dir.is_dir():
            stream.write("\n== LEG B evidence (redacted, last %d lines per file; #7181) ==\n" % tail_lines)
            print_evidence(evidence_dir, evidence_names(evidence_dir, DEFAULT_NAMES), tail_lines, stream)
    except OSError:
        pass
    listing = state_dir / "cleanup-list"
    try:
        paths = listing.read_text(encoding="utf-8", errors="replace").splitlines() if listing.is_file() else []
    except OSError:
        paths = []
    for raw in paths:
        try:
            _safe_remove(raw.strip())
        except OSError:
            pass
    shutil.rmtree(str(state_dir), ignore_errors=True)
    return 0


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse hook: never echo the offending argument
        sys.stderr.write(USAGE_ERROR + "\n")
        raise SystemExit(2)


def main(argv: List[str]) -> int:
    parser = _QuietParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL_LINES)
    parser.add_argument("--write-redacted", type=Path, default=None, metavar="OUT_DIR",
                        help="write a fully redacted copy of the evidence files to OUT_DIR")
    parser.add_argument("--finalize", type=Path, default=None, metavar="STATE_DIR",
                        help="gate EXIT trap: report LEG B evidence if a LEG B row failed, then clean up")
    parser.add_argument("names", nargs="*", help="evidence file names (default: the standard set)")
    args = parser.parse_args(argv)
    if args.finalize is not None:
        return finalize(args.finalize, args.evidence_dir, args.tail, sys.stdout)
    if args.write_redacted is not None:
        return write_redacted(args.evidence_dir, args.write_redacted)
    if not args.evidence_dir.is_dir():
        sys.stderr.write("evidence dir not found\n")
        return 2
    names = evidence_names(args.evidence_dir, args.names or DEFAULT_NAMES)
    print_evidence(args.evidence_dir, names, args.tail, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
