#!/usr/bin/env python3
"""Check current source anchors in the maintained debt register (#8599).

The existing doc anchor gate excludes frozen internal review records. This
companion checks only the maintained register, in the same CI job, without
reinterpreting citations in its historical siblings. Anchor grammar follows
the existing PATH, LINE, QUAL and MDLINK forms; bare prose is not a symbol claim.
"""
import argparse
import os
from pathlib import Path
import re
import sys

REGISTER = Path("docs/internal/v070-accepted-debt.md")
ROOT_ENV = "AI_MEMORY_SYMBOL_GATE_ROOT"
SOURCE_PATH = r"src/[A-Za-z0-9_/]+\.rs"
PATH_ANCHOR = re.compile(r"`(?:\.\./)*(" + SOURCE_PATH + r")`")
LINE_ANCHOR = re.compile(r"`(?:\.\./)*(" + SOURCE_PATH + r"):(\d+)")
QUALIFIED_ANCHOR = re.compile(
    r"`(?:\.\./)*(" + SOURCE_PATH + r")::(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_:]*))"
)
LINK_ANCHOR = re.compile(r"\[`([A-Za-z_][A-Za-z0-9_]*)`\]\((?:\.\./)*(" + SOURCE_PATH + r")[^)]*\)")
DEFINITION = re.compile(r"\b(?:fn|struct|enum|trait|type|const|static|mod|union)\s+([A-Za-z_][A-Za-z0-9_]*)")
MACRO = re.compile(r"macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*[,({=]", re.MULTILINE)
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def read_regular(root, relative):
    """Require actual, readable files rather than an omitted or redirected input."""
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"{relative}: symlink at {path.relative_to(root)}")
    if not path.is_file():
        raise ValueError(f"{relative}: expected a regular file")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"{relative}: cannot read source text ({type(error).__name__})") from error


def check(root):
    """Return diagnostics and anchor count for the single maintained register."""
    problems = []
    checked = 0
    try:
        document = read_regular(root, REGISTER)
    except ValueError as error:
        return [str(error)], checked
    sources = {}

    def verify(line_number, source, token, symbols=(), line=None):
        nonlocal checked
        checked += 1
        try:
            if source not in sources:
                text = read_regular(root, Path(source))
                names = {match.group(1) for pattern in (DEFINITION, MACRO, VARIANT) for match in pattern.finditer(text)}
                names.add(Path(source).stem)
                sources[source] = (names, len(text.splitlines()))
            names, line_count = sources[source]
            if line is not None and not 1 <= line <= line_count:
                raise ValueError(f"line is outside 1..{line_count}")
            for symbol in symbols:
                if symbol not in names and not (symbol.endswith("_") and any(name.startswith(symbol) for name in names)):
                    raise ValueError(f"symbol {symbol} is not defined in {source}")
        except ValueError as error:
            problems.append(f"{REGISTER}:{line_number}: {token}: {error}")

    for line_number, text in enumerate(document.splitlines(), 1):
        for match in PATH_ANCHOR.finditer(text):
            verify(line_number, match.group(1), match.group(1))
        for match in LINE_ANCHOR.finditer(text):
            verify(line_number, match.group(1), f"{match.group(1)}:{match.group(2)}", line=int(match.group(2)))
        for match in QUALIFIED_ANCHOR.finditer(text):
            raw = match.group(2) if match.group(2) is not None else match.group(3)
            symbols = [part for word in raw.replace(",", " ").split() for part in word.split("::") if IDENTIFIER.fullmatch(part)]
            verify(line_number, match.group(1), f"{match.group(1)}::{raw}", symbols=symbols)
        for match in LINK_ANCHOR.finditer(text):
            verify(line_number, match.group(2), f"{match.group(2)}::{match.group(1)}", symbols=(match.group(1),))
    if checked == 0:
        problems.append(f"{REGISTER}: no source anchors found; refusing an empty check")
    return problems, checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.environ.get(ROOT_ENV, Path(__file__).resolve().parents[2])))
    arguments = parser.parse_args()
    problems, checked = check(arguments.root)
    for problem in problems:
        print(f"debt-doc-anchors: {problem}", file=sys.stderr)
    print(f"debt-doc-anchors: problems={len(problems)} anchors={checked} document={REGISTER}")
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
