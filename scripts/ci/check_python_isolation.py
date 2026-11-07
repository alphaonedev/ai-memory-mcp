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
SHELLS = frozenset(("sh", "bash", "zsh"))
HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\2")
WRAPPER_REF = re.compile(r"scripts/[A-Za-z_0-9./-]+\.sh\b")
WORKFLOW_RUN = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
WORKFLOW_DIR = Path(".github/workflows")


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
        elif argument.startswith(("-m", "-c")) or argument == "-":
            return not isolated
        elif argument == "--":
            index += 1
            return index < len(arguments) and not isolated
        elif not argument.startswith("-"):
            return not isolated
        index += 1
    return not isolated


def mask_heredocs(text):
    """Keep shell headers, but not the data supplied to a heredoc's stdin."""
    pending = []
    result = []
    for line in text.splitlines(keepends=True):
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                pending.pop(0)
            result.append("\n" if line.endswith("\n") else "")
        else:
            result.append(line)
            if not line.lstrip().startswith("#"):
                pending.extend((match[3], bool(match[1])) for match in HEREDOC.finditer(line))
    if pending:
        raise ValueError("unterminated heredoc")
    return "".join(result)


def substitution_end(text, start):
    """Find a command substitution's close, respecting quotes and nested calls."""
    index = start
    quote = None
    depth = 1
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif char == quote:
                quote = None
        elif quote != "'" and text.startswith("$(", index):
            index = substitution_end(text, index + 2)
        elif quote is None:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise ValueError("unterminated command substitution")


def substitutions(text):
    """Extract executed $() bodies even inside double-quoted shell words."""
    parts = []
    children = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            parts.append(text[index:index + 2])
            index += 2
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        if quote != "'" and text.startswith("$(", index):
            end = substitution_end(text, index + 2)
            children.append((text[index + 2:end], text.count("\n", 0, index)))
            parts.append("SUBSTITUTION" + "\n" * text.count("\n", index, end))
            index = end + 1
            continue
        if quote is None and char == "#" and (index == 0 or text[index - 1].isspace()):
            end = text.find("\n", index)
            if end == -1:
                break
            parts.append("\n")
            index = end + 1
            continue
        parts.append(char)
        index += 1
    return "".join(parts), children


def shell_commands(text):
    """Tokenize shell words, retaining newline boundaries and quoted arguments."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace = " \t\r"
    lexer.commenters = "#"
    words = []
    for token in lexer:
        if token in COMMAND_END:
            if words:
                yield words
                words = []
        else:
            line = text[:lexer.instream.tell()].rstrip().count("\n") + 1
            words.append((token, line))
    if words:
        yield words


def scan_shell(text, *, masked=False):
    """Return unsafe literal Python invocations in command text."""
    findings = []
    try:
        text, children = substitutions(text if masked else mask_heredocs(text))
        for child, offset in children:
            findings.extend(Finding(item.line + offset, item.reason)
                            for item in scan_shell(child, masked=True))
        for words in shell_commands(text):
            values = [value for value, _ in words]
            if values[0] in DATA_COMMANDS | LOOKUP_COMMANDS:
                continue
            if values[:2] in (["command", "-v"], ["command", "-V"]):
                continue
            if values[0] in ("trap", "eval", "assert"):
                candidates = words[1:2] if values[0] == "trap" else words[1:]
                for candidate, line in candidates:
                    if "python" in candidate:
                        findings.extend(Finding(item.line + line - 1, item.reason)
                                        for item in scan_shell(candidate))
            if values[0] in SHELLS and "-c" in values:
                command_index = values.index("-c") + 1
                if command_index < len(values):
                    findings.extend(scan_shell(values[command_index]))
            for index, (value, line) in enumerate(words):
                if PYTHON_NAME.fullmatch(value.rsplit("/", 1)[-1]):
                    if "/" in value and index != 0 and "/bin/" not in value:
                        continue
                    if script_is_unisolated(values[index + 1:]):
                        findings.append(Finding(line))
    except ValueError:
        findings.append(Finding(1, "unparseable shell command"))
    return findings


def workflow_runs(text):
    """Yield run scalars with source line offsets; reject unsupported run scalars."""
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        match = WORKFLOW_RUN.match(lines[index].rstrip("\r\n"))
        index += 1
        if not match:
            continue
        indent = len(match[1])
        value = match[2]
        offset = index - 1
        if value.startswith(("|", ">")):
            body = []
            while index < len(lines):
                line = lines[index]
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                body.append(line)
                index += 1
            # Preserve line boundaries for shell heredocs and exact source diagnostics.
            import textwrap
            yield textwrap.dedent("".join(body)), offset + 1
        else:
            if value[:1] in ("'", '"'):
                # YAML single quotes double a literal quote; double quotes use JSON escapes.
                if value.startswith("'") and value.endswith("'"):
                    value = value[1:-1].replace("''", "'")
                elif value.startswith('"'):
                    import json
                    value = json.loads(value)
                else:
                    raise ValueError("unsupported multiline run scalar")
            yield value, offset


def workflow_files(root):
    return sorted(set((root / WORKFLOW_DIR).glob("*.yml"))
                  | set((root / WORKFLOW_DIR).glob("*.yaml")))


def wrapper_files(root):
    """Conservative transitive closure of repository shell references in workflows."""
    pending = workflow_files(root)
    seen = set(pending)
    wrappers = set()
    while pending:
        path = pending.pop()
        for match in WRAPPER_REF.finditer(path.read_text(encoding="utf-8")):
            candidate = root / match[0]
            if candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                wrappers.add(candidate)
                pending.append(candidate)
    return sorted(wrappers)


def scan_repository(root):
    """Inspect workflows and their transitive repository shell-wrapper references."""
    findings = []
    for path in workflow_files(root):
        try:
            for command, offset in workflow_runs(path.read_text(encoding="utf-8")):
                findings.extend((path, Finding(item.line + offset, item.reason))
                                for item in scan_shell(command))
        except ValueError:
            findings.append((path, Finding(1, "unsupported workflow run scalar")))
    for path in wrapper_files(root):
        findings.extend((path, item) for item in scan_shell(path.read_text(encoding="utf-8")))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    count = 0
    findings = ([(path, item) for path in args.files
                 for item in scan_shell(path.read_text(encoding="utf-8"))]
                if args.files else scan_repository(args.root))
    for path, finding in findings:
        print(f"{path}:{finding.line}: {finding.reason}")
        count += 1
    print(f"python isolation: findings={count}")
    return int(count != 0)


if __name__ == "__main__":
    sys.exit(main())
