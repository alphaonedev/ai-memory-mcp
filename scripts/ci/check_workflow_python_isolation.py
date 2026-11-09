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
Workflow scalars are decoded before scanning; YAML-side comments never exempt
shell calls. Unsupported scalar encodings fail closed at their source line.
Fail closed (option B): a shell or workflow form the checker cannot classify is a
finding that tells the author to write python3 -I explicitly. That covers unknown
wrappers before an interpreter-looking word, brace expansion or a glob in command
position, shell -c re-entry through an unknown shell or a dynamic program string,
eval of an expansion, complex parameter expansion in command position, unsupported
YAML run forms, nesting past MAX_NESTING_DEPTH and more than MAX_RECOVERIES
malformed commands in one input. An isolation exemption that matches no finding is
itself a finding.
Exit codes: 0 clean, 1 findings, 2 unreadable/malformed input or a repository with
no workflow files. Unreadable files stop the scan with a path message and no summary;
malformed constructs are located findings that keep every other finding and the summary.
"""
import argparse
from bisect import bisect_right
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import string
import sys
import textwrap

PYTHON_NAME = re.compile(
    r"(?:python|pypy)(?:3(?:\.[0-9]+)?)?(?:d|-dbg|t)?(?:\.exe)?\Z", re.IGNORECASE)
PYTHON_NAME_MARKER = "python"
SUBSTITUTION_TOKEN = "SUBSTITUTION"
EXPRESSION_OPEN = "${{"
EXPRESSION_CLOSE = "}}"
BIN_PATH_COMPONENT = "/bin/"
SUBSTITUTION_OPEN = "$("
ARITHMETIC_OPEN = "$(("
ARITHMETIC_PAREN = "(("
ARITHMETIC_TOKEN = "ARITHMETIC"
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
UNCLASSIFIED_REASON = "unclassifiable shell form: write python3 -I explicitly"
NESTING_REASON = "nesting too deep to classify: write python3 -I explicitly"
RECOVERY_REASON = "too many malformed commands to classify: write python3 -I explicitly"
STALE_EXEMPTION_REASON = "stale isolation exemption matches no finding"
MAX_NESTING_DEPTH = 32
MAX_RECOVERIES = 32
OTHER_SHELLS = frozenset(("ksh", "mksh", "ash", "csh", "tcsh", "fish", "yash", "rbash",
                          "busybox", "pwsh", "powershell", "nu", "xonsh", "elvish"))
OTHER_SHELL_COMMAND_OPTION = re.compile(r"-{1,2}[a-zA-Z]*c[a-zA-Z]*\Z", re.IGNORECASE)
EVAL_COMMAND = "eval"
PARAMETER_NAME = r"[A-Za-z_][A-Za-z_0-9]*"
PLAIN_PARAMETER = re.compile(
    rf"\$(?:{PARAMETER_NAME}|[0-9@*#?!$-]|\{{{PARAMETER_NAME}(?:\[[@*0-9]+\])?"
    r"(?::?[-=+][^${}`*?\[\]]*)?\})(?:/[^${}`*?\[]*)?\Z")
TEST_OPEN = "[["
TEST_CLOSE = "]]"
CASE_COMMAND = "case"
CASE_IN = "in"
CASE_ESAC = "esac"
CASE_BREAKS = frozenset((";;", ";&", ";;&"))
# A braced parameter expansion is one word even when its operator text holds blanks.
BRACED_PARAMETER = re.compile(r"\$\{(?!\{)[^}\n]*\}")
SPACE_PLACEHOLDER = "\x01"
# A hash inside a parameter expansion is an operator, never a comment.
HASH_PLACEHOLDER = "\x02"
# Quoted punctuation is hidden from the tokenizer so it cannot pose as a grouping token.
QUOTED_PUNCTUATION = {char: chr(0x10 + index) for index, char in enumerate(";&|()<>")}
QUOTED_RESTORE = {ord(mask): char for char, mask in QUOTED_PUNCTUATION.items()}
ARGUMENT_COUNT = "$#"
ARGUMENT_COUNT_MASKED = "$" + HASH_PLACEHOLDER
CASE_PATTERN = "pattern"
CASE_BODY = "body"
CASE_HEADER = (CASE_COMMAND, "subject", CASE_IN)
BRACE_EXPANSION = re.compile(r"(?<!\$)\{[^{}]*(?:,|\.\.)[^{}]*\}")
GLOB_CHARACTERS = frozenset("*?[")
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
LEXER_WORD_CHARACTERS = "".join(
    char for char in string.printable
    if not char.isspace() and char not in ";&|()<>'\"\\#")
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2
HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\2")
WRAPPER_REF = re.compile(r"scripts/[A-Za-z_0-9./-]+\.sh\b")
WORKFLOW_DIR = Path(".github/workflows")
RUN_KEY = "run"
SHELL_KEY = "shell"
WORKFLOW_KEYS = (RUN_KEY, SHELL_KEY)
KEY_FORMS = "|".join(f"{key}|'{key}'|\"{key}\"" for key in WORKFLOW_KEYS)
WORKFLOW_FIELD = re.compile(
    rf"^(?P<indent>\s*)(?P<item>-\s+)?(?P<key>{KEY_FORMS}):\s*(?P<value>.*)$")
FLOW_STEP = re.compile(r"^\s*-\s*\{")
FLOW_FIELD = re.compile(rf"^\s*({KEY_FORMS}):\s*(.*)$", re.DOTALL)
KEY_ANYWHERE = re.compile(rf"(?<![\w.-])(?:{KEY_FORMS})\s*:")
UNSUPPORTED_KEY_FORM = re.compile(
    r"^\s*(?:-\s+)?(?:\"[^\"]*\\[^\"]*\"\s*:|\?(?:\s|\Z)|<<\s*:)")
UNSUPPORTED_VALUE_START = ("*", "&", "!", "[", "{", "?")
GENERIC_BLOCK_FIELD = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?[^#\s][^:]*:\s*[|>][-+0-9]*\s*(?:#.*)?$")
EMPTY_REPOSITORY_REASON = "repository contains no workflow files"
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

    def __init__(self, text, offset, reason=MALFORMED_REASON):
        super().__init__(reason)
        self.reason = reason
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


def heredoc_openings(line, contexts, depth=0):
    """Recognize redirections outside quotes, comments and arithmetic expansions."""
    index = 0
    program_start = 0
    while index < len(line):
        quotes = contexts[-1][0]
        if quotes.quote != "'" and line.startswith(ARITHMETIC_OPEN, index):
            index = substitution_end(line, index + len(SUBSTITUTION_OPEN), depth) + 1
            continue
        if quotes.quote != "'" and line.startswith(SUBSTITUTION_OPEN, index):
            contexts.append([QuoteScanner(), 1])
            index += len(SUBSTITUTION_OPEN)
            program_start = index
            continue
        if quotes.quote is None:
            if line[index] == "#" and (index == 0 or line[index - 1].isspace()):
                break
            if len(contexts) > 1 and line[index] in "()":
                contexts[-1][1] += 1 if line[index] == "(" else -1
                if contexts[-1][1] == 0:
                    contexts.pop()
                index += 1
                continue
            match = HEREDOC.match(line, index)
            if match:
                yield match, program_start
                index = match.end()
                continue
        index = quotes.advance(line, index)


def mask_heredocs(text, depth=0):
    """Scan shell-program heredocs recursively; preserve line counts while masking data."""
    if depth > MAX_NESTING_DEPTH:
        raise ShellSyntaxError(text, 0, NESTING_REASON)
    pending = []
    result = []
    contexts = [[QuoteScanner(), 0]]
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if pending:
            delimiter, strip_tabs, program, body, opening = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                content = "".join(body)
                try:
                    result.append(mask_heredocs(content, depth + 1) if program
                                  else "\n" * content.count("\n"))
                except ShellSyntaxError as error:
                    error.line += opening
                    raise
                result.append("\n" if line.endswith("\n") else "")
                pending.pop(0)
            else:
                body.append(line)
        else:
            result.append(line)
            if not line.lstrip().startswith("#"):
                try:
                    for match, start in heredoc_openings(line, contexts, depth):
                        commands = list(shell_commands(line[start:match.start()]))
                        values = [value for value, _ in commands[-1]] if commands else []
                        mode, _ = shell_input(values, executable_index(values))
                        pending.append((match[3], bool(match[1]), mode == "stdin", [], number))
                except ShellSyntaxError as error:
                    error.line += number - 1
                    raise
    if pending:
        offset = sum(len(line) for line in text.splitlines(keepends=True)[:pending[0][4] - 1])
        raise ShellSyntaxError(text, offset)
    return "".join(result)


def substitution_end(text, start, nesting=0):
    """Find a command substitution's close, respecting quotes and nested calls."""
    if nesting > MAX_NESTING_DEPTH:
        raise ShellSyntaxError(text, start - len(SUBSTITUTION_OPEN), NESTING_REASON)
    index = start
    quotes = QuoteScanner()
    depth = 1
    while index < len(text):
        char = text[index]
        next_index = quotes.advance(text, index)
        if next_index > index + 1:
            index = next_index
            continue
        if quotes.quote != "'" and text.startswith(SUBSTITUTION_OPEN, index):
            index = substitution_end(text, index + len(SUBSTITUTION_OPEN), nesting + 1)
        elif quotes.quote is None:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise ShellSyntaxError(text, start - len(SUBSTITUTION_OPEN))


def substitutions(text, depth=0):
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
        if quotes.quote != "'" and text.startswith(SUBSTITUTION_OPEN, index):
            end = substitution_end(text, index + len(SUBSTITUTION_OPEN), depth)
            offset = text.count("\n", 0, index)
            if text.startswith(ARITHMETIC_OPEN, index):
                _, nested = substitutions(
                    text[index + len(ARITHMETIC_OPEN):end - 1], depth + 1)
                children.extend((child, line + offset) for child, line in nested)
                placeholder = ARITHMETIC_TOKEN
            else:
                body = text[index + len(SUBSTITUTION_OPEN):end]
                children.append((body, offset))
                placeholder = SUBSTITUTION_TOKEN + (
                    PYTHON_NAME_MARKER if PYTHON_NAME_MARKER in body.casefold() else "")
            parts.append(placeholder + "\n" * text.count("\n", index, end))
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
            body = text[index + 1:end]
            children.append((body, text.count("\n", 0, index)))
            placeholder = SUBSTITUTION_TOKEN + (
                PYTHON_NAME_MARKER if PYTHON_NAME_MARKER in body.casefold() else "")
            parts.append(placeholder + "\n" * text.count("\n", index, end))
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


def mask_quoted_punctuation(text):
    """Hide shell punctuation inside quotes so a quoted ')' is never a grouping token."""
    quotes = QuoteScanner()
    masked = list(text)
    index = 0
    while index < len(text):
        following = quotes.advance(text, index)
        if quotes.quote and text[index] in QUOTED_PUNCTUATION:
            masked[index] = QUOTED_PUNCTUATION[text[index]]
        index = following
    return "".join(masked)


def unmask_token(token):
    """Restore the characters the lexer pre-pass hid from the tokenizer."""
    token = token.replace(SPACE_PLACEHOLDER, " ").replace(HASH_PLACEHOLDER, "#")
    return token.translate(QUOTED_RESTORE)


def shell_commands(text):
    """Tokenize shell words, retaining newline boundaries and quoted arguments."""
    original_newlines = [index for index, char in enumerate(text) if char == "\n"]
    text = join_continuations(text)
    text = BRACED_PARAMETER.sub(
        lambda match: re.sub(r"[ \t]", SPACE_PLACEHOLDER, match.group()).replace(
            "#", HASH_PLACEHOLDER), text).replace(ARGUMENT_COUNT, ARGUMENT_COUNT_MASKED)
    text = mask_quoted_punctuation(text)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
    lexer.wordchars += LEXER_WORD_CHARACTERS + SPACE_PLACEHOLDER + HASH_PLACEHOLDER
    lexer.whitespace = " \t\r"
    lexer.commenters = "#"
    words = []
    array_depth = 0
    arithmetic_depth = 0
    group_depth = 0
    in_test = False
    case_modes = []
    try:
        for token in lexer:
            if in_test:
                in_test = token != TEST_CLOSE
                continue
            if token == TEST_OPEN and all(word in COMMAND_PREFIXES for word, _ in words):
                in_test = True
                continue
            if case_modes and case_modes[-1] == CASE_PATTERN:
                # Case patterns are data: skip them up to their closing parenthesis.
                if token == ")":
                    case_modes[-1] = CASE_BODY
                elif token == CASE_ESAC:
                    case_modes.pop()
                continue
            if case_modes and token == CASE_ESAC and not words:
                case_modes.pop()
                continue
            if token in CASE_BREAKS:
                if words:
                    yield words
                    words = []
                if case_modes:
                    case_modes[-1] = CASE_PATTERN
                continue
            if arithmetic_depth:
                arithmetic_depth += token.count("(") - token.count(")")
                continue
            if token == ARITHMETIC_PAREN:
                arithmetic_depth = 2
                continue
            if array_depth:
                array_depth += token.count("(") - token.count(")")
                continue
            if token == "(" and words and words[-1][0].endswith("="):
                array_depth = 1
                continue
            if token in COMMAND_END:
                if (len(words) >= len(CASE_HEADER) and words[0][0] == CASE_COMMAND
                        and words[2][0] == CASE_IN):
                    case_modes.append(CASE_BODY if token == ")" else CASE_PATTERN)
                    words = []
                    continue
                if token == "(":
                    group_depth += 1
                elif token == ")":
                    if group_depth == 0:
                        # A case pattern's closing parenthesis ends a pattern, not a command.
                        words = []
                        continue
                    group_depth -= 1
                if words:
                    yield words
                    words = []
            else:
                position = lexer.instream.tell()
                while position and text[position - 1].isspace():
                    position -= 1
                line = bisect_right(original_newlines, position - 1) + 1
                words.append((unmask_token(token), line))
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


def unclassified(line):
    return Finding(line, UNCLASSIFIED_REASON)


def dynamic_program(value):
    """A program string built by expansion cannot be classified lexically."""
    stripped = value.strip()
    return SUBSTITUTION_TOKEN in value or (stripped.startswith("$") and len(stripped.split()) == 1)


def reentry_findings(words, executable, depth=0):
    """Inspect evaluated strings and shell -c programs through the same scanner.

    Returns the findings and whether an env -S split already classified the command.
    """
    values = [value for value, _ in words]
    findings = []
    name = values[executable].rsplit("/", 1)[-1] if executable < len(values) else ""
    if name in OTHER_SHELLS and any(
            OTHER_SHELL_COMMAND_OPTION.fullmatch(item) or item in SHELLS
            for item in values[executable + 1:]):
        return [unclassified(words[executable][1])], True
    if name == EVAL_COMMAND and any(dynamic_program(item) for item in values[executable + 1:]):
        return [unclassified(words[executable][1])], True
    if name == ENV_COMMAND:
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
            return offset_findings(scan_shell(command, depth=depth + 1),
                                   words[index][1] - 1), True
    if values[0] in REENTRY_COMMANDS:
        candidates = words[1:2] if values[0] == TRAP_COMMAND else words[1:]
        for candidate, line in candidates:
            if values[0] == EVAL_COMMAND or PYTHON_NAME_MARKER in candidate.casefold():
                findings.extend(offset_findings(scan_shell(candidate, depth=depth + 1),
                                                line - 1))
    mode, index = shell_input(values, executable)
    if mode == "command" and index < len(values):
        if dynamic_program(values[index]):
            return [unclassified(words[index][1])], True
        findings.extend(offset_findings(scan_shell(values[index], depth=depth + 1),
                                        words[index][1] - 1))
    return findings, False


def dynamic_interpreter(values, index):
    """Recognize Python-named variables without resolving arbitrary executables."""
    value = values[index]
    expression = " ".join(values[index:]).split(EXPRESSION_CLOSE, 1)[0]
    return (PYTHON_NAME_MARKER in value.casefold()
            or (value.startswith(EXPRESSION_OPEN) and PYTHON_NAME_MARKER in expression.casefold()))


def console_launcher(name, arguments):
    """Console scripts and UV program launches do not establish isolation."""
    return (name in CONSOLE_LAUNCHERS or bool(VERSIONED_PIP.fullmatch(name))
            or (name == UV_LAUNCHER and any(
                tuple(arguments[:len(command)]) == command for command in UNISOLATED_UV_COMMANDS)))


def invocation_findings(words, executable):
    """Classify a command after its wrappers; interpreter argv is never rescanned."""
    values = [value for value, _ in words]
    operand = next((index for index in range(executable + 1, len(values))
                    if not values[index].startswith("-")), None)
    for index in range(executable, len(words)):
        value, line = words[index]
        name = value.rsplit("/", 1)[-1]
        if index == executable and SUBSTITUTION_TOKEN in value:
            return [Finding(line, DYNAMIC_REASON)]
        if index == executable and value.startswith("$"):
            if value != EXPRESSION_OPEN and not PLAIN_PARAMETER.fullmatch(value):
                return [unclassified(line)]
            if dynamic_interpreter(values, index):
                return [Finding(line, DYNAMIC_REASON)]
            # An unresolved wrapper may still invoke a literal interpreter.
            continue
        if index == executable and (BRACE_EXPANSION.search(value)
                                    or GLOB_CHARACTERS & set(value)):
            return [unclassified(line)]
        if index == operand and index > executable:
            # An unknown wrapper may hand its operand to an interpreter.
            if (SUBSTITUTION_TOKEN in value or value == EXPRESSION_OPEN) and dynamic_interpreter(
                    values, index):
                return [Finding(line, DYNAMIC_REASON)]
            if value.startswith("$") and PYTHON_NAME_MARKER in name.casefold():
                return [Finding(line, DYNAMIC_REASON)]
            if name == PYTHON_LAUNCHER:
                return [Finding(line, DYNAMIC_REASON)]
            if console_launcher(name, values[index + 1:]):
                return [Finding(line, LAUNCHER_REASON)]
        if PYTHON_NAME.fullmatch(name):
            if "/" in value and index != executable and BIN_PATH_COMPONENT not in value:
                continue
            return [Finding(line)] if script_is_unisolated(values[index + 1:]) else []
        if index == executable:
            if name == PYTHON_LAUNCHER:
                return [Finding(line, DYNAMIC_REASON)]
            if console_launcher(name, values[index + 1:]):
                return [Finding(line, LAUNCHER_REASON)]
    return []


def command_findings(words, depth=0):
    """Separate data/lookups, evaluated programs and interpreter invocations."""
    values = [value for value, _ in words]
    if values[0] in DATA_COMMANDS | LOOKUP_COMMANDS or tuple(values[:2]) in COMMAND_LOOKUPS:
        return []
    executable = executable_index(values)
    findings, handled = reentry_findings(words, executable, depth)
    if handled:
        return findings
    if executable < len(values) and values[executable] not in DATA_COMMANDS | LOOKUP_COMMANDS:
        findings.extend(invocation_findings(words, executable))
    return findings


def scan_segment(text, masked, depth):
    """Scan one text without recovery; raise ShellSyntaxError on malformed input."""
    findings = []
    text, children = substitutions(text if masked else mask_heredocs(text, depth), depth)
    for child, offset in children:
        findings.extend(offset_findings(scan_shell(child, masked=True, depth=depth + 1),
                                        offset))
    for words in shell_commands(text):
        findings.extend(command_findings(words, depth))
    return findings


def scan_shell(text, *, masked=False, depth=0):
    """Return unsafe Python invocations and located malformed-command findings.

    Recovery is iterative and bounded: each malformed command splits its text once, at
    most MAX_RECOVERIES times, so cost is linear and nothing recurses per malformed line.
    """
    if depth > MAX_NESTING_DEPTH:
        return [Finding(1, NESTING_REASON, True)]
    findings = []
    pending = [(text, 0)]
    recoveries = 0
    while pending:
        segment, offset = pending.pop()
        if recoveries > MAX_RECOVERIES:
            findings.append(Finding(offset + 1, RECOVERY_REASON, True))
            continue
        try:
            found = scan_segment(segment, masked, depth)
        except ShellSyntaxError as error:
            recoveries += 1
            lines = segment.splitlines(keepends=True)
            findings.append(Finding(offset + error.line, error.reason, True))
            pending.append(("".join(lines[error.line:]), offset + error.line))
            pending.append(("".join(lines[:error.line - 1]), offset))
            continue
        findings.extend(offset_findings(found, offset))
    return sorted(findings, key=lambda item: item.line)


def yaml_comment_free(text):
    """Drop YAML comments outside scalar quotes, using shared quote state."""
    quotes = QuoteScanner()
    index = 0
    while index < len(text):
        if quotes.quote is None and text[index] == "#" and (
                index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
        index = quotes.advance(text, index)
    return text.rstrip()


def decode_yaml_scalar(value):
    """Decode the supported quoted/plain scalar subset; unsupported input is an error."""
    value = yaml_comment_free(value).strip()
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ValueError(WORKFLOW_REASON)
        return value[1:-1].replace("''", "'")
    if value.startswith('"'):
        decoded = json.loads(value)
        if not isinstance(decoded, str):
            raise ValueError(WORKFLOW_REASON)
        return decoded
    return value


def flow_fields(text, offset):
    """Read fields of a flow-mapping step without splitting quoted values."""
    body = yaml_comment_free(text).strip()
    body = body[body.index("{") + 1:]
    if not body.endswith("}"):
        yield RUN_KEY, None, "", offset
        return
    body = body[:-1]
    quotes = QuoteScanner()
    index = start = depth = 0
    pieces = []
    while index < len(body):
        char = body[index]
        if quotes.quote is None:
            if char in "{[":
                depth += 1
            elif char in "}]":
                depth -= 1
            elif char == "," and depth == 0:
                pieces.append((body[start:index], offset + body.count("\n", 0, start)))
                start = index + 1
        index = quotes.advance(body, index)
    pieces.append((body[start:], offset + body.count("\n", 0, start)))
    for piece, line in pieces:
        match = FLOW_FIELD.match(piece)
        if match:
            try:
                command = decode_yaml_scalar(match[2])
            except ValueError:
                command = None
            yield match[1].strip("'\""), command, command or "", line


def fold_yaml_lines(lines):
    """Fold ordinary scalar lines; blank and more-indented lines retain breaks."""
    result = []
    for index, line in enumerate(lines):
        result.append(line)
        if index + 1 < len(lines):
            following = lines[index + 1]
            result.append("\n" if not line or not following or line[:1].isspace()
                          or following[:1].isspace() else " ")
    return "".join(result)


def workflow_fields(text):
    """Yield decoded run/shell fields, source views and located input errors."""
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        raw = lines[index].rstrip("\r\n")
        offset = index
        index += 1
        if FLOW_STEP.match(raw):
            yield from flow_fields(raw, offset)
            continue
        match = WORKFLOW_FIELD.match(raw)
        if not match:
            generic = GENERIC_BLOCK_FIELD.match(raw)
            if generic:
                # Other keys' block scalars are data: skip their bodies.
                while index < len(lines) and (not lines[index].strip() or len(
                        lines[index]) - len(lines[index].lstrip()) > len(generic["indent"])):
                    index += 1
            elif (KEY_ANYWHERE.search(yaml_comment_free(raw))
                  or UNSUPPORTED_KEY_FORM.match(raw)):
                # A run/shell key in a form the line reader cannot decode fails closed.
                yield RUN_KEY, None, "", offset
            continue
        key = match['key'].strip("'\"")
        indent = len(match['indent']) + len(match['item'] or '')
        value = yaml_comment_free(match['value'])
        if value.startswith(UNSUPPORTED_VALUE_START):
            yield key, None, "", offset
            continue
        body = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line)
            index += 1
        try:
            if value.startswith(("|", ">")):
                source = textwrap.dedent("".join(body))
                command = (fold_yaml_lines(source.splitlines()) if value.startswith(">")
                           else source)
                yield key, command, source, offset + 1
            else:
                parts = [value] if value else []
                parts.extend(yaml_comment_free(line.strip()) for line in body)
                command = decode_yaml_scalar(fold_yaml_lines(parts))
                source = "\n".join(parts)
                yield key, command, source, offset if value else offset + 1
        except ValueError:
            yield key, None, "", offset


def workflow_runs(text):
    """Compatibility iterator for decoded run scalars and their source offsets."""
    for key, command, _, offset in workflow_fields(text):
        if key == RUN_KEY and command is not None:
            yield command, offset


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
    used = {line for line, _ in exempt}
    findings.extend(Finding(line, STALE_EXEMPTION_REASON)
                    for line in sorted(set(comments) - used))
    return sorted(findings, key=lambda item: item.line), exempt


def scan_repository(root, exemptions=None):
    """Inspect workflows and their transitive repository shell-wrapper references."""
    findings = []
    if exemptions is None:
        exemptions = []
    paths = workflow_files(root)
    if not paths:
        return [(root, Finding(1, EMPTY_REPOSITORY_REASON, True))]
    for path in paths:
        text = read_source(path)
        for key, command, source, offset in workflow_fields(text):
            if command is None:
                findings.append((path, Finding(offset + 1, WORKFLOW_REASON, True)))
                continue
            # A shell template is an argv declaration, not shell program text.
            unsafe, exempt = (scan_source(command) if key == RUN_KEY
                              else (scan_shell(command), []))
            # Decoded text alone decides violations. The physical source view
            # supplies locations for folded scalar tokens, never extra findings.
            located = scan_shell(source) if source != command else list(unsafe)
            for item in unsafe:
                matching = next((part for part in located if part.reason == item.reason), item)
                if matching in located:
                    located.remove(matching)
                findings.append((path, Finding(matching.line + offset,
                                               item.reason, item.malformed)))
            exemptions.extend((path, line + offset, issue) for line, issue in exempt)
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
