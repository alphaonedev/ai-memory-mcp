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
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
MAX_LINE_DIGITS = 9
SOURCE_ROOT = "src/"
RS_MARKER = ".rs"
UNCLASSIFIED = "unclassified anchor"
EMPTY_SYMBOLS = "empty symbol list"
SOURCE_PREFIXED = re.compile(r"(?:\.\./)*" + re.escape(SOURCE_ROOT))
SPAN = re.compile(r"`([^`\n]*)`")
PARENTS = r"(?:\.\./)*"
PATH_FORM = re.compile(PARENTS + "(" + SOURCE_PATH + ")")
MODULE_FORM = re.compile(r"[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\.rs")
LINE_FORM = re.compile(PARENTS + "(" + SOURCE_PATH + r"):(\d{1,%d})(?:-(\d{1,%d}))?" % (MAX_LINE_DIGITS, MAX_LINE_DIGITS))
QUALIFIED_FORM = re.compile(PARENTS + "(" + SOURCE_PATH + r")::(?:\{([^{}`]*)\}|(" + IDENT + "(?:::" + IDENT + ")*))")
SYMBOL_PATH = re.compile(IDENT + "(?:::" + IDENT + ")*")
LINK_ANCHOR = re.compile(r"\[`(" + IDENT + r")`\]\((?:\.\./)*(" + SOURCE_PATH + r")[^)]*\)")
DEFINITION = re.compile(r"\b(?:fn|struct|enum|trait|type|const|static|mod|union)\s+(" + IDENT + ")")
MACRO = re.compile(r"macro_rules!\s+(" + IDENT + ")")
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*[,({=]", re.MULTILINE)
COMMENT_START = re.compile(r"//|/\*")
BLOCK_TOKEN = re.compile(r"/\*|\*/")


def strip_comments(text):
    """Drop line and nested block comments in one linear pass, keeping newlines."""
    pieces = []
    position = 0
    while True:
        start = COMMENT_START.search(text, position)
        if start is None:
            pieces.append(text[position:])
            return "".join(pieces)
        pieces.append(text[position:start.start()])
        if start.group() == "//":
            newline = text.find("\n", start.end())
            position = len(text) if newline < 0 else newline
            continue
        depth = 1
        position = start.end()
        while depth:
            token = BLOCK_TOKEN.search(text, position)
            if token is None:
                position = len(text)
                break
            depth += 1 if token.group() == "/*" else -1
            position = token.end()
        pieces.append("\n" * text.count("\n", start.start(), position))


def read_regular(root, relative):
    """Require actual, readable files rather than an omitted or redirected input."""
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink at {path.relative_to(root)}")
    if not path.is_file():
        raise ValueError("expected a regular file")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read source text ({type(error).__name__})") from error


def classify(span):
    """Return (source, token, symbols, line_range) for a known anchor form, else None.

    A qualified anchor always carries a symbols tuple that is None only when
    the brace list is empty, so the caller can name that exact reason.
    """
    if (match := PATH_FORM.fullmatch(span)) is not None:
        return match.group(1), match.group(1), (), None
    if MODULE_FORM.fullmatch(span) is not None:
        return SOURCE_ROOT + span, SOURCE_ROOT + span, (), None
    if (match := LINE_FORM.fullmatch(span)) is not None:
        first = int(match.group(2))
        last = int(match.group(3)) if match.group(3) is not None else first
        token = f"{match.group(1)}:{match.group(2)}" + (f"-{match.group(3)}" if match.group(3) is not None else "")
        return match.group(1), token, (), (first, last)
    if (match := QUALIFIED_FORM.fullmatch(span)) is not None:
        path, braced, plain = match.groups()
        if plain is not None:
            return path, f"{path}::{plain}", tuple(plain.split("::")), None
        items = [item.strip() for item in braced.split(",") if item.strip()]
        if not all(SYMBOL_PATH.fullmatch(item) for item in items):
            return None
        symbols = tuple(part for item in items for part in item.split("::"))
        return path, f"{path}::{{{braced}}}", symbols or None, None
    return None


def check(root):
    """Return diagnostics and anchor count for the single maintained register."""
    problems = []
    checked = 0
    try:
        document = read_regular(root, REGISTER)
    except ValueError as error:
        return [f"{REGISTER}: {error}"], checked
    sources = {}

    def verify(line_number, source, token, symbols=(), line_range=None):
        nonlocal checked
        checked += 1
        try:
            if source not in sources:
                text = read_regular(root, Path(source))
                code = strip_comments(text)
                names = {match.group(1) for pattern in (DEFINITION, MACRO, VARIANT) for match in pattern.finditer(code)}
                names.add(Path(source).stem)
                sources[source] = (names, len(text.splitlines()))
            names, line_count = sources[source]
            if line_range is not None:
                first, last = line_range
                if not (1 <= first <= line_count and 1 <= last <= line_count):
                    raise ValueError(f"line is outside 1..{line_count}")
                if first > last:
                    raise ValueError(f"range start {first} is after end {last}")
            for symbol in symbols:
                if symbol not in names and not (symbol.endswith("_") and any(name.startswith(symbol) for name in names)):
                    raise ValueError(f"symbol {symbol} is not defined in {source}")
        except ValueError as error:
            problems.append(f"{REGISTER}:{line_number}: {token}: {error}")

    for line_number, text in enumerate(document.splitlines(), 1):
        for span_match in SPAN.finditer(text):
            span = span_match.group(1)
            if RS_MARKER not in span and SOURCE_PREFIXED.match(span) is None:
                continue
            anchor = classify(span)
            if anchor is None:
                checked += 1
                problems.append(f"{REGISTER}:{line_number}: {span}: {UNCLASSIFIED}")
                continue
            source, token, symbols, line_range = anchor
            if symbols is None:
                checked += 1
                problems.append(f"{REGISTER}:{line_number}: {token}: {EMPTY_SYMBOLS}")
                continue
            verify(line_number, source, token, symbols, line_range)
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
