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
here. Literal python/PyPy names accept versions, d/-dbg/t and .exe suffixes; dynamic
names containing python (including /python* paths) are matched case-insensitively,
as are literal names. Other unresolved executables, such as $BIN or $PSQL, are left alone:
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

PYTHON_NAME = re.compile(
    r"(?:python|pypy)(?:3(?:\.[0-9]+)?)?(?:d|-dbg|t)?(?:\.exe)?\Z", re.IGNORECASE)
PYTHON_NAME_MARKER = "python"
SUBSTITUTION_TOKEN = "SUBSTITUTION"
ENV_COMMAND = "env"
ENV_SPLIT_OPTIONS = frozenset(("-S", "--split-string"))
ENV_SPLIT_PREFIXES = ("-S", "--split-string=")
PYTHON_LAUNCHER = "py"
UV_LAUNCHER = "uv"
REENTRY_COMMANDS = frozenset(("trap", "eval", "assert"))
TRAP_COMMAND = "trap"
COMMAND_LOOKUPS = (("command", "-v"), ("command", "-V"))
DYNAMIC_REASON = "dynamic interpreter requires an issue exemption"
LAUNCHER_REASON = "console launcher requires isolated Python -m"
ISOLATION_REASON = "Python interpreter requires -I before the program"
MALFORMED_REASON = "unparseable shell command"
WORKFLOW_REASON = "unsupported workflow run scalar"
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
    "stdbuf": frozenset(("-i", "--input", "-o", "--output", "-e", "--error")),
    "setsid": frozenset(),
    "flock": frozenset(("-w", "--wait", "-E", "--conflict-exit-code")),
    "ionice": frozenset(("-c", "--class", "-n", "--classdata", "-p", "--pid",
                         "-P", "--pgid", "-u", "--uid")),
    "chrt": frozenset(("-T", "--sched-runtime", "-P", "--sched-period",
                       "-D", "--sched-deadline")),
    "taskset": frozenset(("-c", "--cpu-list")),
}
PREFIX_POSITIONAL_ARGUMENTS = {"timeout": 1, "flock": 1, "chrt": 1, "taskset": 1}
PREFIX_POSITIONAL_OPTIONS = {"taskset": frozenset(("-c", "--cpu-list"))}
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
    reason: str = ISOLATION_REASON
    malformed: bool = False


class InputError(ValueError):
    """A source cannot be read or interpreted; retain its path in the diagnostic."""


class ShellSyntaxError(ValueError):
    """A malformed shell construct with its source line retained."""

    def __init__(self, text, offset):
        super().__init__(MALFORMED_REASON)
        self.line = text.count("\n", 0, offset) + 1


@dataclass
class QuoteScanner:
    """Share shell quote and escape state across all lexical passes."""

    quote: str | None = None
    opening: int = 0

    def advance(self, text, index):
        """Return the next offset, consuming an escaped pair as one unit."""
        char = text[index]
        if char == "\\" and self.quote != "'":
            return min(index + 2, len(text))
        if char in ("'", '"'):
            if self.quote is None:
                self.quote = char
                self.opening = index
            elif self.quote == char:
                self.quote = None
        return index + 1


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
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if pending:
            delimiter, strip_tabs, program, body, _ = pending[0]
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
                    pending.append((match[3], bool(match[1]), mode == "stdin", [], number))
    if pending:
        offset = sum(len(line) for line in text.splitlines(keepends=True)[:pending[0][4] - 1])
        raise ShellSyntaxError(text, offset)
    return "".join(result)


def substitution_end(text, start):
    """Find a command substitution's close, respecting quotes and nested calls."""
    index = start
    quotes = QuoteScanner()
    depth = 1
    while index < len(text):
        char = text[index]
        next_index = quotes.advance(text, index)
        if next_index > index + 1:
            index = next_index
            continue
        if quotes.quote != "'" and text.startswith("$(", index):
            index = substitution_end(text, index + 2)
        elif quotes.quote is None:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise ShellSyntaxError(text, start - 2)


def substitutions(text):
    """Extract executed $() bodies even inside double-quoted shell words."""
    parts = []
    children = []
    quotes = QuoteScanner()
    index = 0
    while index < len(text):
        char = text[index]
        next_index = quotes.advance(text, index)
        if next_index > index + 1:
            parts.append(text[index:next_index])
            index = next_index
            continue
        if quotes.quote != "'" and text.startswith("$(", index):
            end = substitution_end(text, index + 2)
            children.append((text[index + 2:end], text.count("\n", 0, index)))
            parts.append(SUBSTITUTION_TOKEN + "\n" * text.count("\n", index, end))
            index = end + 1
            continue
        if quotes.quote != "'" and char == "`":
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                elif text[end] == "`":
                    break
                else:
                    end += 1
            if end >= len(text):
                raise ShellSyntaxError(text, index)
            children.append((text[index + 1:end], text.count("\n", 0, index)))
            parts.append(SUBSTITUTION_TOKEN + "\n" * text.count("\n", index, end))
            index = end + 1
            continue
        if quotes.quote is None and char == "#" and (index == 0 or text[index - 1].isspace()):
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
    quotes = QuoteScanner()
    index = 0
    while index < len(text):
        next_index = quotes.advance(text, index)
        if next_index == index + 2 and text[index:next_index] == "\\\n":
            result[index:next_index] = "  "
        index = next_index
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
    try:
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
    except ValueError as error:
        quotes = QuoteScanner()
        index = 0
        while index < len(text):
            index = quotes.advance(text, index)
        offset = quotes.opening if quotes.quote else max(0, lexer.instream.tell() - 1)
        problem = ShellSyntaxError(text, offset)
        problem.line = bisect_right(original_newlines, offset - 1) + 1
        raise problem from error
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
        prefix_index = index
        index += 1
        positional_options = PREFIX_POSITIONAL_OPTIONS.get(name, frozenset())
        positional_consumed = False
        while index < len(values) and values[index].startswith("-"):
            option = values[index]
            if name == ENV_COMMAND and option.startswith(ENV_SPLIT_PREFIXES):
                return prefix_index
            index += 1
            if option == "--":
                break
            if option in PREFIX_VALUE_OPTIONS[name]:
                index += 1
            positional_consumed |= option.split("=", 1)[0] in positional_options
        if not positional_consumed:
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


def offset_findings(findings, offset):
    """Translate recursively scanned lines into their containing source."""
    return [Finding(item.line + offset, item.reason, item.malformed) for item in findings]


def reentry_findings(words, executable):
    """Inspect evaluated strings and shell -c programs through the same scanner."""
    values = [value for value, _ in words]
    findings = []
    if executable < len(values) and values[executable].rsplit("/", 1)[-1] == ENV_COMMAND:
        for index in range(executable + 1, len(values)):
            option = values[index]
            if option in ENV_SPLIT_OPTIONS and index + 1 < len(values):
                program, tail = values[index + 1], index + 2
            elif option.startswith(ENV_SPLIT_PREFIXES):
                prefix = next(item for item in ENV_SPLIT_PREFIXES if option.startswith(item))
                program, tail = option[len(prefix):], index + 1
            else:
                continue
            command = program + " " + shlex.join(values[tail:])
            return offset_findings(scan_shell(command), words[index][1] - 1)
    if values[0] in REENTRY_COMMANDS:
        candidates = words[1:2] if values[0] == TRAP_COMMAND else words[1:]
        for candidate, line in candidates:
            if PYTHON_NAME_MARKER in candidate.casefold():
                findings.extend(offset_findings(scan_shell(candidate), line - 1))
    mode, index = shell_input(values, executable)
    if mode == "command" and index < len(values):
        findings.extend(offset_findings(scan_shell(values[index]), words[index][1] - 1))
    return findings


def dynamic_interpreter(values, index):
    """Recognize Python-named variables without resolving arbitrary executables."""
    value = values[index]
    expression = " ".join(values[index:]).split("}}", 1)[0]
    return (PYTHON_NAME_MARKER in value.casefold()
            or (value.startswith("${{") and PYTHON_NAME_MARKER in expression.casefold()))


def console_launcher(name, arguments):
    """Console scripts and UV program launches do not establish isolation."""
    return (name in CONSOLE_LAUNCHERS or bool(VERSIONED_PIP.fullmatch(name))
            or (name == UV_LAUNCHER and any(
                tuple(arguments[:len(command)]) == command for command in UNISOLATED_UV_COMMANDS)))


def invocation_findings(words, executable):
    """Classify a command after its wrappers; interpreter argv is never rescanned."""
    values = [value for value, _ in words]
    for index in range(executable, len(words)):
        value, line = words[index]
        name = value.rsplit("/", 1)[-1]
        if index == executable and SUBSTITUTION_TOKEN in value:
            return [Finding(line, DYNAMIC_REASON)]
        if index == executable and value.startswith("$"):
            if dynamic_interpreter(values, index):
                return [Finding(line, DYNAMIC_REASON)]
            # An unresolved wrapper may still invoke a literal interpreter.
            continue
        if PYTHON_NAME.fullmatch(name):
            if "/" in value and index != executable and "/bin/" not in value:
                continue
            return [Finding(line)] if script_is_unisolated(values[index + 1:]) else []
        if index == executable:
            if name == PYTHON_LAUNCHER:
                return [Finding(line, DYNAMIC_REASON)]
            if console_launcher(name, values[index + 1:]):
                return [Finding(line, LAUNCHER_REASON)]
    return []


def command_findings(words):
    """Separate data/lookups, evaluated programs and interpreter invocations."""
    values = [value for value, _ in words]
    if values[0] in DATA_COMMANDS | LOOKUP_COMMANDS or tuple(values[:2]) in COMMAND_LOOKUPS:
        return []
    executable = executable_index(values)
    findings = reentry_findings(words, executable)
    if executable < len(values) and values[executable] not in DATA_COMMANDS | LOOKUP_COMMANDS:
        findings.extend(invocation_findings(words, executable))
    return findings


def scan_shell(text, *, masked=False):
    """Return unsafe Python invocations and located malformed-command findings."""
    findings = []
    try:
        text, children = substitutions(text if masked else mask_heredocs(text))
    except ShellSyntaxError as error:
        prefix = "".join(text.splitlines(keepends=True)[:error.line - 1])
        return scan_shell(prefix, masked=masked) + [Finding(error.line, MALFORMED_REASON, True)]
    try:
        for child, offset in children:
            findings.extend(offset_findings(scan_shell(child, masked=True), offset))
        for words in shell_commands(text):
            findings.extend(command_findings(words))
    except ValueError as error:
        findings.append(Finding(getattr(error, "line", 1), MALFORMED_REASON, True))
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
    quotes = QuoteScanner()
    index = 0
    line = 1
    found = {}
    while index < len(text):
        char = text[index]
        next_index = quotes.advance(text, index)
        line += text.count("\n", index, next_index)
        if next_index > index + 1:
            index = next_index
            continue
        if quotes.quote is None and char == "#" and (index == 0 or text[index - 1].isspace()):
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
            findings.append((path, Finding(1, WORKFLOW_REASON, True)))
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
    for path, finding in findings:
        print(f"{path}:{finding.line}: {finding.reason}")
        count += 1
    for path, line, issue in exemptions:
        print(f"EXEMPT {path}:{line}: isolation: exempt #{issue}")
    print(f"python isolation: findings={count} exemptions={len(exemptions)}")
    if any(item.malformed for _, item in findings):
        return EXIT_INPUT
    return EXIT_FINDINGS if count else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
