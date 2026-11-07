#!/usr/bin/env python3
"""Reject workflow Python script calls without explicit interpreter isolation.

The policy requires -I (standalone or first in a flag bundle) before execution; an
argument passed to the program or consumed by -W/-X is not interpreter isolation.
Shell text is inspected, never executed. No invocation is exempt by default.
An actual shell comment '# isolation: exempt #1234' on the invocation line
records an issue-backed exception; each honoured exception is printed by the CLI.
Console launchers pip (including versioned names), pytest, pipx, uvx and uv run or
uv tool run are findings, including behind command prefixes: use an isolated
Python -m invocation. Python-named variable/expression interpreters and py need an
explicit issue exemption because their interpreter isolation cannot be established
here. Names containing python (including dynamic /python* paths) are matched case
insensitively. Other unresolved executables, such as $BIN or $PSQL, are left alone:
this is a lexical name scan, not whole-workflow variable binding analysis.
Exit codes: 0 clean, 1 findings, 2 unreadable or malformed input.
"""
import argparse
from bisect import bisect_right
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import sys
import textwrap

PYTHON_NAME = re.compile(r"python(?:3(?:\.[0-9]+)?)?\Z", re.IGNORECASE)
OPTIONS_WITH_VALUE = frozenset(("-W", "-X", "--check-hash-based-pycs"))
COMMAND_END = frozenset((";", "&&", "||", "|", "&", "(", ")", "\n"))
LOOKUP_COMMANDS = frozenset(("which", "type"))
DATA_COMMANDS = frozenset(("echo", "printf", "test", "[", "[["))
SHELLS = frozenset(("sh", "bash", "zsh", "dash"))
SHELL_COMMAND_OPTION = re.compile(r"-[a-zA-Z]*c[a-zA-Z]*\Z")
SHELL_STDIN_OPTION = re.compile(r"-[a-zA-Z]*s[a-zA-Z]*\Z")
SHELL_VALUE_OPTIONS = frozenset(("-o", "-O", "--rcfile", "--init-file"))
CONSOLE_LAUNCHERS = frozenset(("pip", "pip3", "pytest", "pipx", "uvx"))
VERSIONED_PIP = re.compile(r"pip3(?:\.(?:[0-9]+|x))?\Z")
UNISOLATED_UV_COMMANDS = (("run",), ("tool", "run"))
TOOL_PREFIXES = {"poetry": "run", "pyenv": "exec"}
COMMAND_PREFIXES = frozenset(("if", "then", "elif", "while", "until", "do", "!",
                              "command", "exec"))
PREFIX_VALUE_OPTIONS = {
    "env": frozenset(("-u", "--unset", "-C", "--chdir", "-S", "--split-string")),
    "sudo": frozenset(("-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
                       "-C", "--close-from", "-D", "--chdir", "-R", "--chroot", "-T",
                       "--command-timeout", "-r", "--role", "-t", "--type")),
    "nice": frozenset(("-n", "--adjustment")),
    "time": frozenset(("-f", "--format", "-o", "--output")),
    "timeout": frozenset(("-k", "--kill-after", "-s", "--signal")),
    "xargs": frozenset(("-I", "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs",
                        "-s", "--max-chars", "-E", "-d", "--delimiter", "-a", "--arg-file")),
    "nohup": frozenset(),
}
PREFIX_POSITIONAL_ARGUMENTS = {"timeout": 1}
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\2")
WRAPPER_REF = re.compile(r"scripts/[A-Za-z_0-9./-]+\.sh\b")
WORKFLOW_RUN = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
WORKFLOW_SHELL = re.compile(r"^\s*(?:-\s+)?shell:\s*(['\"]?)(.*)")
WORKFLOW_DIR = Path(".github/workflows")
EXEMPTION = re.compile(r"# isolation: exempt #([1-9][0-9]*)\s*\Z")


@dataclass(frozen=True)
class Finding:
    line: int
    reason: str = "Python interpreter requires -I before the program"
    malformed: bool = False


class InputError(ValueError):
    """A source cannot be read or interpreted; retain its path in the diagnostic."""


def read_source(path):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise InputError(f"{path}: unreadable input: {error}") from error


def script_is_unisolated(arguments):
    """Inspect interpreter options without confusing their values with -I."""
    isolated = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument.startswith("-I"):
            isolated = True
            if "c" in argument[2:] or "m" in argument[2:]:
                return False
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
    """Scan shell-program heredocs recursively; preserve line counts while masking data."""
    pending = []
    result = []
    for line in text.splitlines(keepends=True):
        if pending:
            delimiter, strip_tabs, program, body = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                content = "".join(body)
                result.append(mask_heredocs(content) if program else "\n" * content.count("\n"))
                result.append("\n" if line.endswith("\n") else "")
                pending.pop(0)
            else:
                body.append(line)
        else:
            result.append(line)
            if not line.lstrip().startswith("#"):
                for match in HEREDOC.finditer(line):
                    commands = list(shell_commands(line[:match.start()]))
                    values = [value for value, _ in commands[-1]] if commands else []
                    mode, _ = shell_input(values, executable_index(values))
                    pending.append((match[3], bool(match[1]), mode == "stdin", []))
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
        if quote != "'" and char == "`":
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == "`":
                    break
                else:
                    end += 1
            if end >= len(text):
                raise ValueError("unterminated backtick substitution")
            children.append((text[index + 1:end], text.count("\n", 0, index)))
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


def join_continuations(text):
    """Mask shell line continuations with equal-width spaces, retaining offsets."""
    result = list(text)
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            if text[index:index + 2] == "\\\n":
                result[index:index + 2] = "  "
            index += 2
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        index += 1
    return "".join(result)


def shell_commands(text):
    """Tokenize shell words, retaining newline boundaries and quoted arguments."""
    original_newlines = [index for index, char in enumerate(text) if char == "\n"]
    text = join_continuations(text)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
    lexer.wordchars += "${}:"
    lexer.whitespace = " \t\r"
    lexer.commenters = "#"
    words = []
    for token in lexer:
        if token in COMMAND_END:
            if words:
                yield words
                words = []
        else:
            position = lexer.instream.tell()
            while position and text[position - 1].isspace():
                position -= 1
            line = bisect_right(original_newlines, position - 1) + 1
            words.append((token, line))
    if words:
        yield words


def executable_index(values):
    """Walk command prefixes and their operands without inspecting operands as programs."""
    index = 0
    while index < len(values):
        value = values[index]
        name = value.rsplit("/", 1)[-1]
        if value in COMMAND_PREFIXES or ("=" in value and not value.startswith("$")):
            index += 1
            continue
        if name in TOOL_PREFIXES and values[index + 1:index + 2] == [TOOL_PREFIXES[name]]:
            index += 2
            continue
        if name not in PREFIX_VALUE_OPTIONS:
            break
        index += 1
        while index < len(values) and values[index].startswith("-"):
            option = values[index]
            index += 1
            if option == "--":
                break
            if option in PREFIX_VALUE_OPTIONS[name]:
                index += 1
        index += PREFIX_POSITIONAL_ARGUMENTS.get(name, 0)
    return index


def shell_input(values, executable):
    """Identify a shell's command string, stdin program, or script operand."""
    if executable >= len(values) or values[executable].rsplit("/", 1)[-1] not in SHELLS:
        return None, executable
    index = executable + 1
    stdin = False
    while index < len(values):
        option = values[index]
        if option == "--":
            index += 1
            break
        if not option.startswith("-"):
            break
        if SHELL_COMMAND_OPTION.fullmatch(option):
            return "command", index + 1
        stdin = stdin or bool(SHELL_STDIN_OPTION.fullmatch(option))
        index += 2 if option in SHELL_VALUE_OPTIONS else 1
    return ("stdin" if stdin or index >= len(values) else "file"), index


def scan_shell(text, *, masked=False):
    """Return unsafe literal Python invocations in command text."""
    findings = []
    try:
        text, children = substitutions(text if masked else mask_heredocs(text))
        for child, offset in children:
            findings.extend(Finding(item.line + offset, item.reason, item.malformed)
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
                        findings.extend(Finding(item.line + line - 1, item.reason, item.malformed)
                                        for item in scan_shell(candidate))
            executable = executable_index(values)
            shell_mode, command_index = shell_input(values, executable)
            if shell_mode == "command" and command_index < len(values):
                offset = words[command_index][1] - 1
                findings.extend(Finding(item.line + offset, item.reason, item.malformed)
                                for item in scan_shell(values[command_index]))
            if executable < len(values) and values[executable] in DATA_COMMANDS | LOOKUP_COMMANDS:
                continue
            for index, (value, line) in enumerate(words):
                if index < executable:
                    continue
                name = value.rsplit("/", 1)[-1]
                if index == executable and value.startswith("$"):
                    expression = " ".join(values[index:]).split("}}", 1)[0]
                    if ("python" in value.casefold()
                            or (value.startswith("${{") and "python" in expression.casefold())):
                        findings.append(Finding(line, "dynamic interpreter requires an issue exemption"))
                        break
                    # Leave this name alone; retain the existing scan for a literal
                    # interpreter invoked by a wrapper such as $TIMEOUT_BIN.
                    continue
                if PYTHON_NAME.fullmatch(name):
                    if "/" in value and index != 0 and "/bin/" not in value:
                        continue
                    if script_is_unisolated(values[index + 1:]):
                        findings.append(Finding(line))
                    # Everything after this interpreter is its argv, not another launcher.
                    break
                if index == executable:
                    if name == "py":
                        findings.append(Finding(line, "dynamic interpreter requires an issue exemption"))
                        break
                    if (name in CONSOLE_LAUNCHERS or VERSIONED_PIP.fullmatch(name)
                            or (name == "uv" and any(
                                tuple(values[index + 1:index + 1 + len(command)]) == command
                                for command in UNISOLATED_UV_COMMANDS))):
                        findings.append(Finding(line, "console launcher requires isolated Python -m"))
                        break
    except ValueError:
        findings.append(Finding(1, "unparseable shell command", True))
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
            yield textwrap.dedent("".join(body)), offset + 1
        else:
            if value[:1] in ("'", '"'):
                # YAML single quotes double a literal quote; double quotes use JSON escapes.
                if value.startswith("'") and value.endswith("'"):
                    value = value[1:-1].replace("''", "'")
                elif value.startswith('"'):
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
        for match in WRAPPER_REF.finditer(read_source(path)):
            candidate = root / match[0]
            if candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                wrappers.add(candidate)
                pending.append(candidate)
    return sorted(wrappers)


def exemption_comments(text):
    """Read real shell comments, not markers inside quoted program strings."""
    quote = None
    index = 0
    line = 1
    found = {}
    while index < len(text):
        char = text[index]
        if char == "\n":
            line += 1
        if char == "\\" and quote != "'":
            if index + 1 < len(text) and text[index + 1] == "\n":
                line += 1
            index += 2
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        if quote is None and char == "#" and (index == 0 or text[index - 1].isspace()):
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            match = EXEMPTION.fullmatch(text[index:end])
            if match:
                found[line] = match[1]
            index = end
            continue
        index += 1
    return found


def scan_source(text):
    """Separate violations from explicit, same-line issue exemptions."""
    comments = exemption_comments(text)
    findings = []
    exempt = []
    for item in scan_shell(text):
        if item.line in comments and not item.malformed:
            exempt.append((item.line, comments[item.line]))
        else:
            findings.append(item)
    return findings, exempt


def scan_repository(root, exemptions=None):
    """Inspect workflows and their transitive repository shell-wrapper references."""
    findings = []
    if exemptions is None:
        exemptions = []
    for path in workflow_files(root):
        text = read_source(path)
        try:
            commands = list(workflow_runs(text))
            for line, value in enumerate(text.splitlines()):
                match = WORKFLOW_SHELL.match(value)
                if match:
                    command = match[2]
                    if match[1] and command.endswith(match[1]):
                        command = command[:-1]
                    commands.append((command, line))
            for command, offset in commands:
                unsafe, exempt = scan_source(command)
                findings.extend((path, Finding(item.line + offset, item.reason, item.malformed))
                                for item in unsafe)
                exemptions.extend((path, line + offset, issue) for line, issue in exempt)
        except ValueError:
            findings.append((path, Finding(1, "unsupported workflow run scalar", True)))
    for path in wrapper_files(root):
        unsafe, exempt = scan_source(read_source(path))
        findings.extend((path, item) for item in unsafe)
        exemptions.extend((path, line, issue) for line, issue in exempt)
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    count = 0
    exemptions = []
    try:
        if args.files:
            findings = []
            for path in args.files:
                unsafe, exempt = scan_source(read_source(path))
                findings.extend((path, item) for item in unsafe)
                exemptions.extend((path, line, issue) for line, issue in exempt)
        else:
            findings = scan_repository(args.root, exemptions)
    except InputError as error:
        print(str(error).replace("\n", "\\n"), file=sys.stderr)
        return EXIT_INPUT
    if any(item.malformed for _, item in findings):
        path, item = next((path, item) for path, item in findings if item.malformed)
        print(f"{path}:{item.line}: {item.reason}", file=sys.stderr)
        return EXIT_INPUT
    for path, finding in findings:
        print(f"{path}:{finding.line}: {finding.reason}")
        count += 1
    for path, line, issue in exemptions:
        print(f"EXEMPT {path}:{line}: isolation: exempt #{issue}")
    print(f"python isolation: findings={count} exemptions={len(exemptions)}")
    return EXIT_FINDINGS if count else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
