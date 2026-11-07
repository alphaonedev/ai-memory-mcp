#!/usr/bin/env python3
"""Reject workflow Python script calls without explicit interpreter isolation.

The policy requires a standalone -I before the script or execution mode; an
argument passed to the program or consumed by -W/-X is not interpreter isolation.
Shell text is inspected, never executed.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import sys

PYTHON_NAME = re.compile(r"python(?:3(?:\.[0-9]+)?)?\Z")
OPTIONS_WITH_VALUE = frozenset(("-W", "-X", "--check-hash-based-pycs"))
COMMAND_END = frozenset((";", "&&", "||", "|", "&", "(", ")", "\n"))
LOOKUP_COMMANDS = frozenset(("which", "type"))
DATA_COMMANDS = frozenset(("echo", "printf", "test", "[", "[["))


@dataclass(frozen=True)
class Finding:
    line: int
    reason: str = "Python interpreter requires -I before the program"


def script_is_unisolated(arguments):
    """Inspect interpreter options without confusing their values with -I."""
    isolated = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-I":
            isolated = True
        elif argument in OPTIONS_WITH_VALUE:
            index += 1
        elif argument in ("-m", "-c", "-"):
            return False
        elif argument == "--":
            index += 1
            return index < len(arguments) and not isolated
        elif not argument.startswith("-"):
            return argument.endswith(".py") and not isolated
        index += 1
    return False


def shell_commands(text):
    """Tokenize shell words, retaining newline boundaries and quoted arguments."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
    lexer.whitespace = " \t\r"
    lexer.commenters = "#"
    words = []
    for token in lexer:
        if token in COMMAND_END:
            if words:
                yield words
                words = []
        else:
            words.append((token, lexer.lineno))
    if words:
        yield words


def scan_shell(text):
    """Return unsafe literal Python invocations in command text."""
    findings = []
    try:
        for words in shell_commands(text):
            values = [value for value, _ in words]
            if values[0] in DATA_COMMANDS | LOOKUP_COMMANDS:
                continue
            if values[:2] in (["command", "-v"], ["command", "-V"]):
                continue
            for index, (value, line) in enumerate(words):
                if PYTHON_NAME.fullmatch(value.rsplit("/", 1)[-1]):
                    if script_is_unisolated(values[index + 1:]):
                        findings.append(Finding(line))
    except ValueError:
        findings.append(Finding(1, "unparseable shell command"))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    count = 0
    for path in args.files:
        for finding in scan_shell(path.read_text(encoding="utf-8")):
            print(f"{path}:{finding.line}: {finding.reason}")
            count += 1
    print(f"python isolation: findings={count}")
    return int(count != 0)


if __name__ == "__main__":
    sys.exit(main())
