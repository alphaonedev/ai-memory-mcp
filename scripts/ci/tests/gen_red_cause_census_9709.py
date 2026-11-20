#!/usr/bin/env python3
"""Write (or check) the #9709 census fixture: every Rust ``fn`` name under ``src/`` and ``tests/``.

The red-cause summary prints a failing test name unmasked only when it has the plain Rust path shape and no token
shape (scripts/ci/red_cause_summary.py, ``render_name``). The census proves that rule keeps real names readable:
``test_ci_red_cause_summary.Census`` asserts that at least 99% of these names print unmasked. The fixture is one name
per line, sorted and unique, so a regenerated file diffs cleanly.

Usage: ``python3 scripts/ci/tests/gen_red_cause_census_9709.py`` rewrites the fixture; ``--check`` exits 1 when the
tracked fixture differs from a fresh walk (exit 0 when it matches).
"""

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ROOTS = ("src", "tests")
SOURCE_SUFFIX = ".rs"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "red_cause_census_9709.txt"
FN_NAME = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
EXIT_OK = 0
EXIT_DIFFERS = 1


def walk_names(repo):
    """The sorted unique ``fn`` names of every ``.rs`` file under the census roots of ``repo``."""
    names = set()
    for root in ROOTS:
        for path in sorted((repo / root).rglob("*" + SOURCE_SUFFIX)):
            if path.is_symlink() or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            names.update(FN_NAME.findall(text))
    return sorted(names)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare with the tracked fixture instead of writing it")
    args = parser.parse_args(argv)
    text = "".join(name + "\n" for name in walk_names(REPO))
    if args.check:
        current = FIXTURE.read_text(encoding="utf-8") if FIXTURE.is_file() else ""
        if current != text:
            print("census fixture differs from a fresh walk: rerun without --check", file=sys.stderr)
            return EXIT_DIFFERS
        return EXIT_OK
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text, encoding="utf-8")
    print("wrote %d names to %s" % (text.count("\n"), FIXTURE.relative_to(REPO)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
