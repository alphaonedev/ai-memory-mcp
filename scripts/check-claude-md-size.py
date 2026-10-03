#!/usr/bin/env python3
"""check-claude-md-size.py - issue #4507: keep the tracked CLAUDE.md small.

Claude Code loads the tracked CLAUDE.md in full into EVERY session and subagent
started in a checkout (measured: ~200k tokens on turn one at 448 KB, ~42k with a
slim copy). The Architecture and Code Style bodies therefore live in
docs/reference/ and CLAUDE.md keeps only rule sections plus pointers.

This gate fails when CLAUDE.md exceeds CLAUDE_MD_MAX_BYTES, or when a reference
file is missing, so the content cannot silently grow back (or be deleted rather
than moved). The ceiling only falls; raising it needs an explicit decision.

Usage:
  scripts/check-claude-md-size.py [ROOT]
  scripts/check-claude-md-size.py --self-test
"""
import argparse
import sys
import tempfile
from pathlib import Path

CLAUDE_MD_MAX_BYTES = 100_000
REFERENCE_FILES = (
    "docs/reference/ARCHITECTURE_REFERENCE.md",
    "docs/reference/CODE_STYLE.md",
)


def check(root: Path) -> list:
    """Return a list of failure messages (empty means pass)."""
    errors = []
    claude = root / "CLAUDE.md"
    try:
        size = claude.stat().st_size
    except OSError as exc:
        return [f"FAIL: cannot stat {claude}: {exc}"]
    if size > CLAUDE_MD_MAX_BYTES:
        errors.append(
            f"FAIL: CLAUDE.md is {size} bytes, over the {CLAUDE_MD_MAX_BYTES}-byte ceiling "
            "(CLAUDE_MD_MAX_BYTES). It loads eagerly into every agent session. Put "
            "reference material in " + " or ".join(REFERENCE_FILES) +
            " instead, and keep CLAUDE.md to operator rule sections and pointers (#4507)."
        )
    for rel in REFERENCE_FILES:
        if not (root / rel).is_file():
            errors.append(f"FAIL: reference file {rel} is missing (moved content must not be deleted)")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel in REFERENCE_FILES:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x\n", encoding="utf-8")
        (root / "CLAUDE.md").write_text("x" * (CLAUDE_MD_MAX_BYTES + 1), encoding="utf-8")
        if not check(root):
            print("FAIL: self-test - an oversized CLAUDE.md was NOT rejected", file=sys.stderr)
            return 1
        (root / "CLAUDE.md").write_text("x" * CLAUDE_MD_MAX_BYTES, encoding="utf-8")
        if check(root):
            print("FAIL: self-test - a CLAUDE.md at the ceiling was rejected", file=sys.stderr)
            return 1
        (root / REFERENCE_FILES[0]).unlink()
        if not check(root):
            print("FAIL: self-test - a missing reference file was NOT rejected", file=sys.stderr)
            return 1
    print("PASS: self-test #4507 - oversize and missing-reference are rejected, ceiling is inclusive")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    errors = check(Path(args.root))
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: CLAUDE.md within {CLAUDE_MD_MAX_BYTES} bytes; reference files present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
