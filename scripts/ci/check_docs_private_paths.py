"""Reject private account home prefixes in docs Markdown (#8493).

Generic names are explicit data in docs_private_path_allow.json. The fix mode
changes only matched prefix bytes; line endings and all other bytes survive.
Like the existing docs-vs-SSOT gate, root CHANGELOG.md is not in the scan.
Historical Markdown under docs/ is included because redacting a home prefix
does not change the recorded technical claim.
The placeholder <home> denotes the redacted account home directory.
docs_private_path_exceptions.json contains exact, hashed source-line exceptions
for diagram estimates. An exception must match its path, line number and text,
and suppress an actual class-(c) match; unused exceptions make the gate red.
The stored line text excludes its newline terminator.
"""

import argparse
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALLOW_FILE = Path(__file__).with_name("docs_private_path_allow.json")
DEFAULT_EXCEPTIONS_FILE = Path(__file__).with_name("docs_private_path_exceptions.json")
EXCEPTION_FIELDS = frozenset(("path", "line", "text", "sha256", "reason"))
PLACEHOLDER = "<home>"
ACCOUNT_NAME = r"[\w-]+(?:\.[\w-]+)*"
NAMED_ACCOUNT = r"[^\W\d][\w-]*(?:\.[\w-]+)*"
# Class (a): both raw and normalized components determine home membership.
LOCAL_PATH = re.compile(r"(?<![\w.%/-])(?:/|[\w.-]+/)[\w./%-]*")
PATH_COMPONENT = re.compile(r"[^/]+")
WEB_URL_SCHEMES = frozenset(("http", "https"))
# RFC 3986 unreserved, reserved and percent, minus the documented prose separators.
URL_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[@!$&(*+;=%"
)
# Preserve these established prefixes before splitting any other glued -letters switch.
PATH_SWITCHES = ("-I", "-L")
RELATIVE_SWITCH = re.compile(
    r"-[A-Za-z]+?(?=(?:home/|Users/|\./|\.\./|var/home/|mnt/c/Users/|~))"
)
SCHEME_HEADER = re.compile(r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]*://")
INVISIBLE = frozenset("\u200b\u200c\u200d\ufeff")
# Class (b): named-home paths anywhere; numeric ratios are approximations.
NAMED_HOME = re.compile(rf"~(?P<name>{NAMED_ACCOUNT})(?=/)")
# Class (c): bare names in code and prose; numeric approximations are not names.
BARE_HOME = re.compile(rf"~(?P<name>{NAMED_ACCOUNT})(?![\w/-]|\.[\w-])")
FENCE = re.compile(r"^ {0,3}(?P<marks>`{3,}|~{3,})(?P<info>[^\r\n]*)")
BACKTICKS = re.compile(r"`+")
SHELL_FENCES = frozenset(("", "sh", "bash", "zsh", "shell", "console"))
# Prose-only approximations: conductor rulings d08df0ec, 727df6e5, b5b0c768.
# These never exempt code tokens or named-home paths and are not account names.
PROSE_APPROXIMATIONS = frozenset((
    "Memory", "minutes", "seconds", "milliseconds", "tens", "LINEAR",
    "line", "all", "half-day", "loader-capped", "buildable", "CPU",
    "halved", "v78", "loader", "Peer",
))
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


@dataclass(frozen=True)
class Finding:
    """A replaceable home-prefix span in a single decoded document."""

    start: int
    end: int
    line: int
    prefix: str


@dataclass(frozen=True)
class LineException:
    """One reviewed source line whose code-shaped tilde tokens are estimates."""

    path: str
    line: int
    text: str


def line_exceptions(path: Path) -> list[LineException]:
    """Validate the separate exception policy, including hashes and unique sites."""
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("exceptions must be a list")
    result = []
    sites = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != EXCEPTION_FIELDS:
            raise ValueError("exception requires path, line, text, sha256 and reason")
        if (not all(isinstance(entry[key], str) for key in ("path", "text", "sha256", "reason"))
                or type(entry["line"]) is not int or entry["line"] < 1):
            raise ValueError("exception field types are invalid")
        relative = PurePosixPath(entry["path"])
        if (relative.is_absolute() or ".." in relative.parts
                or relative.as_posix() != entry["path"]
                or not entry["path"].startswith("docs/") or relative.suffix != ".md"):
            raise ValueError("exception path must be a relative docs Markdown path")
        if "\n" in entry["text"] or "\r" in entry["text"] or not entry["reason"].strip():
            raise ValueError("exception requires one exact line and a reason")
        digest = hashlib.sha256(entry["text"].encode("utf-8")).hexdigest()
        if entry["sha256"] != digest:
            raise ValueError("exception sha256 does not match its exact line text")
        site = (entry["path"], entry["line"])
        if site in sites:
            raise ValueError("duplicate exception site")
        sites.add(site)
        result.append(LineException(entry["path"], entry["line"], entry["text"]))
    return result


def allowed_names(path: Path) -> frozenset[str]:
    """Load an explicit, nonempty list of generic account names."""
    data = json.loads(path.read_text(encoding="utf-8"))
    names = data.get("allowed_names") if isinstance(data, dict) else None
    if not isinstance(names, list) or not names or not all(
        isinstance(name, str) and re.fullmatch(r"[\w.-]+", name) for name in names
    ):
        raise ValueError("allowed_names must be a nonempty list of account-name strings")
    return frozenset(name.casefold() for name in names)


def markdown_files(root: Path) -> list[Path]:
    """Enumerate docs Markdown without following symlinks or silently skipping errors."""
    docs = root / "docs"
    if docs.is_symlink():
        raise ValueError("docs directory is a symlink")
    if not docs.is_dir():
        raise ValueError("root must contain a docs directory")
    files = []

    def walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, names in os.walk(docs, followlinks=False, onerror=walk_error):
        parent = Path(directory)
        for name in dirs:
            if (parent / name).is_symlink():
                raise ValueError(
                    "docs directory contains a symlink: " + str((parent / name).relative_to(root))
                )
        for name in names:
            if not name.endswith(".md"):
                continue
            path = parent / name
            if path.is_symlink():
                raise ValueError("docs Markdown is a symlink: " + str(path.relative_to(root)))
            if not path.is_file():
                raise ValueError(
                    "docs Markdown is not a regular file: " + str(path.relative_to(root))
                )
            files.append(path)
    return sorted(files)


def inline_spans(text: str, offset: int) -> list[tuple[int, int]]:
    """Pair equal-width backtick runs without scanning each suffix again."""
    runs = list(BACKTICKS.finditer(text))
    following = {}
    next_run = {}
    for index in range(len(runs) - 1, -1, -1):
        width = len(runs[index].group())
        if width in following:
            next_run[index] = following[width]
        following[width] = index
    result = []
    index = 0
    while index < len(runs):
        start = runs[index].start()
        preceding = start
        while preceding and text[preceding - 1] == "\\":
            preceding -= 1
        closing = next_run.get(index)
        if (start - preceding) % 2 or closing is None:
            index += 1
            continue
        result.append((offset + runs[index].end(), offset + runs[closing].start()))
        index = closing + 1
    return result


def code_spans(text: str) -> list[tuple[int, int]]:
    """Locate inline code and permitted fenced content, excluding other fences."""
    result = []
    fence_marks = ""
    shell_fence = False
    paragraph = []
    paragraph_start = 0
    offset = 0

    def flush() -> None:
        if paragraph:
            result.extend(inline_spans("".join(paragraph), paragraph_start))
            paragraph.clear()

    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if fence_marks:
            if (match and match.group("marks")[0] == fence_marks[0]
                    and len(match.group("marks")) >= len(fence_marks)
                    and not match.group("info").strip()):
                fence_marks = ""
            elif shell_fence:
                result.append((offset, offset + len(line)))
        elif match:
            flush()
            fence_marks = match.group("marks")
            info = match.group("info").strip().split()
            shell_fence = (info[0].casefold() if info else "") in SHELL_FENCES
        elif not line.strip():
            flush()
        else:
            if not paragraph:
                paragraph_start = offset
            paragraph.append(line)
        offset += len(line)
    flush()
    return result


def prose_spans(text: str) -> list[tuple[int, int]]:
    """Locate prose lines, excluding all fenced blocks and their delimiters."""
    result = []
    fence_marks = ""
    offset = 0
    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if fence_marks:
            if (match and match.group("marks")[0] == fence_marks[0]
                    and len(match.group("marks")) >= len(fence_marks)
                    and not match.group("info").strip()):
                fence_marks = ""
        elif match:
            fence_marks = match.group("marks")
        else:
            result.append((offset, offset + len(line)))
        offset += len(line)
    return result


def normalized_source(text: str) -> tuple[str, list[int]]:
    """Remove account obfuscators for matching, retaining original span offsets."""
    chars = []
    offsets = []
    visible = []
    for index, char in enumerate(text):
        if char in INVISIBLE:
            # An erased URL delimiter must not glue its last word to a named tilde home.
            if text[index + 1:index + 2] == "~":
                visible.append((index, " "))
            continue
        visible.append((index, char))
    for position, (index, char) in enumerate(visible):
        following = visible[position + 1][1] if position + 1 < len(visible) else ""
        if char == "\\" and following in ("_", "-", "."):
            continue
        chars.append(char)
        offsets.append(index)
    offsets.append(len(text))
    return "".join(chars), offsets


def url_context(original: str, text: str,
                offsets: list[int]) -> tuple[str, list[tuple[int, int]]]:
    """Mask only public web URLs; retain authority boundaries solely for repair."""
    masked = list(text)
    contexts = []
    repair_starts = []
    # Original bytes define URL boundaries before invisible account obfuscators disappear.
    for match in SCHEME_HEADER.finditer(original):
        enclosing = [public for start, end, public in contexts if start < match.start() < end]
        if any(enclosing):
            continue
        nested = bool(enclosing) or original[match.start() - 1:match.start()] == "/"
        public = match.group()[:-len("://")].casefold() in WEB_URL_SCHEMES and not nested
        path = match.end()
        if not public:
            # Unlike a web token, an authority can contain ] and invisible host bytes.
            while path < len(original) and original[path] != "/":
                if original[path].isspace():
                    break
                path += 1
        end = match.end() if public else path
        while end < len(original) and original[end] in URL_TOKEN_CHARS:
            end += 1
        contexts.append((match.start(), end, public))
        left = bisect_left(offsets, match.start())
        if public:
            right = bisect_left(offsets, end)
            masked[left:right] = " " * (right - left)
        elif path < len(original) and original[path] == "/":
            # Nested URL repair retains its path separator as well as its authority.
            repair_starts.append((left, bisect_left(offsets, path + int(nested))))
    return "".join(masked), repair_starts


def path_switch_length(path: str) -> int:
    """Split glued options before selecting either raw or normalized home pairs."""
    relative = RELATIVE_SWITCH.match(path)
    if relative:
        return relative.end()
    boundaries = [index for index, char in enumerate(path) if char in "/~"]
    if path.startswith("-") and boundaries:
        return boundaries[0]
    for switch in PATH_SWITCHES:
        position = path.find(switch)
        if position >= 0:
            return position + len(switch)
    return 0


def tilde_start_allowed(text: str, start: int) -> bool:
    """Use the same option-prefix split for named homes and component paths."""
    if not start or not (text[start - 1].isalnum() or text[start - 1] in "_~"):
        return True
    left = start
    while left and (text[left - 1].isalnum() or text[left - 1] in "_.-"):
        left -= 1
    return left < start and path_switch_length(text[left:start + 1]) == start - left


def local_home_spans(text: str, allowed: frozenset[str],
                     repair_starts: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Select raw and resolved home pairs; URL and option bytes stay outside spans."""
    result = []
    for token in LOCAL_PATH.finditer(text):
        start = token.start()
        path = token.group()
        switch_length = path_switch_length(path)
        start += switch_length
        path = path[switch_length:]
        raw = [(part.group(), start + part.start())
               for part in PATH_COMPONENT.finditer(path)]
        pairs = list(zip(raw, raw[1:]))
        components = []
        for name, offset in raw:
            if name == ".":
                continue
            if name == ".." and components and components[-1][0] != "..":
                components.pop()
            else:
                components.append((name, offset))
                if len(components) >= 2:
                    # Retain a resolved pair even if a later parent segment pops it.
                    pairs.append((components[-2], components[-1]))
        end = None
        for (parent, _), (account, offset) in pairs:
            name = account.rstrip(".")
            if (parent in ("home", "Users") and re.fullmatch(ACCOUNT_NAME, name)
                    and name.casefold() not in allowed):
                end = max(end or 0, offset + len(name))
        if end is not None:
            for scheme, boundary in repair_starts:
                if scheme <= start < boundary < end:
                    start = boundary
            result.append((start, end))
    return result


def findings(text: str, allowed: frozenset[str],
             exceptions: dict[int, str] | None = None) -> tuple[list[Finding], set[int]]:
    """Return approved lexical classes mapped back to exact original spans."""
    original = text
    text, offsets = normalized_source(text)
    detection, repair_starts = url_context(original, text, offsets)
    spans = local_home_spans(detection, allowed, repair_starts)
    matches = list(NAMED_HOME.finditer(text))
    code = code_spans(text)
    starts = [start for start, _ in code]
    for start, end in code:
        matches.extend(BARE_HOME.finditer(text, start, end))
    for start, end in prose_spans(text):
        for match in BARE_HOME.finditer(text, start, end):
            index = bisect_right(starts, match.start()) - 1
            if index >= 0 and match.end() <= code[index][1]:
                continue
            if match.group("name") not in PROSE_APPROXIMATIONS:
                matches.append(match)
    newlines = [index for index, char in enumerate(text) if char == "\n"]
    result = []
    used = set()
    lines = original.split("\n")
    for match in sorted(matches, key=lambda value: value.start()):
        if not tilde_start_allowed(text, match.start()):
            continue
        if match.re in (NAMED_HOME, BARE_HOME) and match.group("name")[0].isnumeric():
            continue
        if match.group("name").casefold() not in allowed:
            number = bisect_left(newlines, match.start()) + 1
            if (match.re is BARE_HOME and exceptions and number in exceptions
                    and lines[number - 1].removesuffix("\r") == exceptions[number]):
                used.add(number)
                continue
            spans.append((match.start(), match.end()))
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in merged:
        number = bisect_left(newlines, start) + 1
        left, right = offsets[start], offsets[end]
        result.append(Finding(left, right, number, original[left:right]))
    return result, used


def redact(text: str, matches: list[Finding]) -> str:
    """Replace only the recorded spans, preserving every intervening character."""
    parts = []
    offset = 0
    for match in matches:
        parts.extend((text[offset:match.start], PLACEHOLDER))
        offset = match.end
    parts.append(text[offset:])
    return "".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--fix", action="store_true")
    parser.add_argument("--allow-file", type=Path, default=DEFAULT_ALLOW_FILE)
    parser.add_argument("--exceptions-file", type=Path, default=DEFAULT_EXCEPTIONS_FILE)
    args = parser.parse_args(argv)
    try:
        allowed = allowed_names(args.allow_file)
        exceptions = line_exceptions(args.exceptions_file)
        by_path = {}
        for entry in exceptions:
            by_path.setdefault(entry.path, {})[entry.line] = entry.text
        used = set()
        documents = markdown_files(args.root)
        changes = []
        total = 0
        for path in documents:
            raw = path.read_bytes()
            text = raw.decode("utf-8", "surrogateescape")
            relative = path.relative_to(args.root).as_posix()
            matches, used_lines = findings(text, allowed, by_path.get(relative))
            used.update((relative, number) for number in used_lines)
            if not matches:
                continue
            for match in matches:
                print(f"{relative}:{match.line}: private-home-prefix")
            total += len(matches)
            changes.append((path, redact(text, matches).encode("utf-8", "surrogateescape")))
        unused = [(entry.path, entry.line) for entry in exceptions
                  if (entry.path, entry.line) not in used]
        for relative, number in unused:
            print(f"{relative}:{number}: unused exact-line exception")
        if args.fix and not unused:
            for path, replacement in changes:
                path.write_bytes(replacement)
        label = "redacted" if args.fix and not unused else "findings"
        print(f"docs-private-paths: {label}={total} files={len(changes)} scanned={len(documents)} "
              f"exceptions_used={len(used)} exceptions_unused={len(unused)}")
        return EXIT_FINDINGS if unused or (total and not args.fix) else EXIT_CLEAN
    except (OSError, ValueError) as error:
        print(f"docs-private-paths: {error}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
