"""Independent full-document YAML reader used as an oracle for the strict reader (#9813).

Standard library only. It is written apart from the subset parser in scripts/ci/taint_boundary.py
(`parse_yaml`, which `workflow_text.read_document` uses) and shares no code with it, so the two can
be compared document by document: every key path and every scalar, with its type.

decision: a new independent full-document reader over reusing `workflow_text.read_jobs`, because
read_jobs reads job ids and three job keys only, so comparing with it cannot see a hidden step,
`with:` or `permissions:` value (the H1 probe of PR 9817: `hidden key not seen`).

What it reads (YAML 1.2, the part the guarded files use):
- block mappings and block sequences, including a compact `- key: value` item and a sequence written
  at the same indentation as its key;
- one-line plain, single-quoted and double-quoted scalars;
- literal and folded block scalars with the headers `|`, `|-`, `|+`, `>`, `>-`, `>+`;
- one-line flow sequences and flow mappings whose entries are scalars.

It splits lines on every YAML line break (CR LF, LF, CR, NEL, LS, PS), so a key written after a bare
CR or a NEL is a key here. Every form outside the list above raises `OracleError` with a line number
and a reason constant, never with document text. A plain scalar whose type differs between YAML 1.1
(PyYAML, docker compose) and YAML 1.2 (the forms `yes`, `no`, `on`, `off`, `y`, `n`, a leading zero,
hex, octal, an exponent, an underscore, `.inf`, `.nan`, a time `1:30`, a date) is refused as
ambiguous, as is a key that would not read as text (except `on`, read as text by GitHub Actions).
"""
from __future__ import annotations

import re
from pathlib import Path

LINE_BREAK_RE = re.compile(r"\r\n|[\n\r\x85  ]")
NESTING_LIMIT = 64

R_INDENT = "indentation outside the oracle grammar"
R_KEY = "key form outside the oracle grammar"
R_KEY_TYPE = "key that does not read as text"
R_DUPLICATE = "duplicate key"
R_QUOTED = "quoted scalar outside the oracle grammar"
R_BLOCK = "block scalar outside the oracle grammar"
R_FLOW = "flow collection outside the oracle grammar"
R_PLAIN = "plain scalar outside the oracle grammar"
R_AMBIGUOUS = "plain scalar whose type differs between YAML 1.1 and 1.2"
R_NESTING = "nesting deeper than the oracle limit"
R_DOCUMENT = "document structure outside the oracle grammar"
R_TAB = "tab outside a scalar"

BLOCK_HEADERS = frozenset({"|", "|-", "|+", ">", ">-", ">+"})
PLAIN_FORBIDDEN_LEAD = "&*!%@`|>'\"{}[],#"
NULL_WORDS = frozenset({"", "~", "null", "Null", "NULL"})
TRUE_WORDS = frozenset({"true", "True", "TRUE"})
FALSE_WORDS = frozenset({"false", "False", "FALSE"})
YAML11_WORDS = frozenset(w for base in ("yes", "no", "on", "off", "y", "n")
                         for w in (base, base.capitalize(), base.upper()))
INT_RE = re.compile(r"[-+]?(?:0|[1-9][0-9]*)")
FLOAT_RE = re.compile(r"[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)")
AMBIGUOUS_NUMBER_RE = re.compile(
    r"[-+]?0[0-9_]+(?:\.[0-9_]*)?"            # a leading zero (octal in YAML 1.1)
    r"|[-+]?0[xXoObB][0-9a-fA-F_]+"            # hex, octal, binary
    r"|[-+]?[0-9][0-9_]*_[0-9_]*(?:\.[0-9_]*)?"  # an underscore
    r"|[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)[eE][-+]?[0-9]+"  # an exponent
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
TIME_OR_DATE_RE = re.compile(r"[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}.*")
DQ_SIMPLE = {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r", "0": "\0",
             "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v", " ": " "}
DQ_HEX = {"x": 2, "u": 4, "U": 8}
HEX = frozenset("0123456789abcdefABCDEF")


class OracleError(Exception):
    """A form the oracle does not read; carries a line number and a reason constant only."""

    def __init__(self, line: int, reason: str) -> None:
        super().__init__("line %d: %s" % (line, reason))
        self.line = line
        self.reason = reason


def _type_plain(text: str, line: int) -> object:
    if text in NULL_WORDS:
        return None
    if text in TRUE_WORDS:
        return True
    if text in FALSE_WORDS:
        return False
    if text in YAML11_WORDS:
        raise OracleError(line, R_AMBIGUOUS)
    if INT_RE.fullmatch(text):
        return int(text)
    if FLOAT_RE.fullmatch(text):
        return float(text)
    if AMBIGUOUS_NUMBER_RE.fullmatch(text):
        raise OracleError(line, R_AMBIGUOUS)
    if TIME_OR_DATE_RE.fullmatch(text):
        raise OracleError(line, R_AMBIGUOUS)
    return text


def _cut_comment(text: str) -> str:
    """Drop a ` #` comment from a plain or flow text (quoted spans are skipped), then trailing blanks."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"" and (i == 0 or text[i - 1] in " [{,:"):
            quote = ch
        elif ch == "#" and i > 0 and text[i - 1] == " ":
            return text[:i].rstrip(" ")
    return text.rstrip(" ")


def _single(text: str, start: int, line: int) -> tuple[str, int]:
    out, i = [], start + 1
    while i < len(text):
        if text[i] == "'":
            if text[i + 1:i + 2] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        out.append(text[i])
        i += 1
    raise OracleError(line, R_QUOTED)


def _double(text: str, start: int, line: int) -> tuple[str, int]:
    out, i = [], start + 1
    while i < len(text):
        ch = text[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        esc = text[i + 1:i + 2]
        if esc in DQ_SIMPLE:
            out.append(DQ_SIMPLE[esc])
            i += 2
        elif esc in DQ_HEX:
            digits = text[i + 2:i + 2 + DQ_HEX[esc]]
            if len(digits) != DQ_HEX[esc] or not set(digits) <= HEX:
                raise OracleError(line, R_QUOTED)
            out.append(chr(int(digits, 16)))
            i += 2 + DQ_HEX[esc]
        else:
            raise OracleError(line, R_QUOTED)
    raise OracleError(line, R_QUOTED)


def _quoted(text: str, line: int) -> tuple[str, str]:
    """The quoted scalar at the start of `text` and the rest of the text after it."""
    value, end = (_single if text[0] == "'" else _double)(text, 0, line)
    return value, text[end:]


def _plain_or_quoted(text: str, line: int) -> object:
    if text[:1] in "'\"":
        value, rest = _quoted(text, line)
        rest = rest.strip(" ")
        if rest and not rest.startswith("#"):
            raise OracleError(line, R_QUOTED)
        return value
    if text[:1] in PLAIN_FORBIDDEN_LEAD or text[:2] in ("- ", "? ", ": ") or text in ("-", "?", ":"):
        raise OracleError(line, R_PLAIN)
    if ": " in text or text.endswith(":") or " #" in text or "\t" in text:
        raise OracleError(line, R_PLAIN)
    return _type_plain(text, line)


def _split_flow(body: str, line: int) -> list[str]:
    parts, current, quote, i = [], [], "", 0
    while i < len(body):
        ch = body[i]
        if quote:
            current.append(ch)
            if ch == quote:
                if quote == "'" and body[i + 1:i + 2] == "'":
                    current.append("'")
                    i += 2
                    continue
                quote = ""
            elif ch == "\\" and quote == '"':
                current.append(body[i + 1:i + 2])
                i += 2
                continue
            i += 1
            continue
        if ch in "'\"" and not "".join(current).strip():
            quote = ch
        elif ch in "[]{}":
            raise OracleError(line, R_FLOW)
        elif ch == ",":
            parts.append("".join(current).strip(" "))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    if quote:
        raise OracleError(line, R_FLOW)
    parts.append("".join(current).strip(" "))
    if parts == [""]:
        return []
    if any(not p for p in parts):
        raise OracleError(line, R_FLOW)
    return parts


def _flow_scalar(part: str, line: int) -> object:
    if part[:1] in "'\"":
        value, rest = _quoted(part, line)
        if rest.strip(" "):
            raise OracleError(line, R_FLOW)
        return value
    if part[:1] in PLAIN_FORBIDDEN_LEAD or part[:2] in ("- ", "? ") or ": " in part or part.endswith(":"):
        raise OracleError(line, R_FLOW)
    return _type_plain(part, line)


def _flow(text: str, line: int) -> object:
    close = "]" if text[0] == "[" else "}"
    if not text.endswith(close):
        raise OracleError(line, R_FLOW)
    parts = _split_flow(text[1:-1], line)
    if close == "]":
        return [_flow_scalar(p, line) for p in parts]
    mapping: dict = {}
    for part in parts:
        if part[:1] in "'\"":
            raise OracleError(line, R_FLOW)
        key, sep, value = part.partition(": ")
        if not sep:
            raise OracleError(line, R_FLOW)
        key = key.strip(" ")
        if not key or key in mapping or key[:1] in PLAIN_FORBIDDEN_LEAD or ":" in key:
            raise OracleError(line, R_FLOW)
        _check_key_type(key, line)
        mapping[key] = _flow_scalar(value.strip(" "), line)
    return mapping


def _check_key_type(key: str, line: int) -> None:
    if key == "on":
        return
    if key in YAML11_WORDS or key in NULL_WORDS or key in TRUE_WORDS or key in FALSE_WORDS:
        raise OracleError(line, R_KEY_TYPE)
    try:
        typed = _type_plain(key, line)
    except OracleError:
        raise OracleError(line, R_KEY_TYPE) from None
    if not isinstance(typed, str):
        raise OracleError(line, R_KEY_TYPE)


def _key_colon(text: str) -> int:
    for i, ch in enumerate(text):
        if ch == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            return i
        if ch == "#" and i > 0 and text[i - 1] == " ":
            return -1
    return -1


class _Reader:
    def __init__(self, text: str) -> None:
        self.raw = LINE_BREAK_RE.split(text)
        if self.raw and self.raw[-1] == "":
            self.raw.pop()
        self.view: dict[int, tuple[int, str]] = {}
        self.lines: dict[tuple, int] = {}
        self.pos = 0

    def indent_of(self, i: int) -> tuple[int, str]:
        if i in self.view:
            return self.view[i]
        line = self.raw[i]
        body = line.lstrip(" ")
        return len(line) - len(body), body

    def next_significant(self) -> int:
        i = self.pos
        while i < len(self.raw):
            _, body = self.indent_of(i)
            if body and not body.startswith("#"):
                if "\t" in self.raw[i][:len(self.raw[i]) - len(self.raw[i].lstrip(" \t"))]:
                    raise OracleError(i + 1, R_TAB)
                return i
            i += 1
        return len(self.raw)

    def document(self) -> object:
        i = self.next_significant()
        if i >= len(self.raw):
            raise OracleError(1, R_DOCUMENT)
        indent, _ = self.indent_of(i)
        if indent != 0:
            raise OracleError(i + 1, R_INDENT)
        self.pos = i
        value = self.node(0, (), 0)
        rest = self.next_significant()
        if rest < len(self.raw):
            raise OracleError(rest + 1, R_DOCUMENT)
        return value

    def node(self, indent: int, path: tuple, depth: int) -> object:
        if depth > NESTING_LIMIT:
            raise OracleError(self.pos + 1, R_NESTING)
        i = self.next_significant()
        _, body = self.indent_of(i)
        if body == "-" or body.startswith("- "):
            return self.sequence(indent, path, depth)
        return self.mapping(indent, path, depth)

    def mapping(self, indent: int, path: tuple, depth: int) -> dict:
        out: dict = {}
        while True:
            i = self.next_significant()
            if i >= len(self.raw):
                return out
            ind, body = self.indent_of(i)
            if ind < indent:
                return out
            if ind > indent:
                raise OracleError(i + 1, R_INDENT)
            if body == "-" or body.startswith("- "):
                return out
            if body[:1] in "'\"?&*!%@`{[|>,]}" or body.startswith("<<"):
                raise OracleError(i + 1, R_KEY)
            colon = _key_colon(body)
            if colon <= 0:
                raise OracleError(i + 1, R_KEY)
            key = body[:colon]
            if key != key.strip(" ") or not key.isascii():
                raise OracleError(i + 1, R_KEY)
            _check_key_type(key, i + 1)
            if key in out:
                raise OracleError(i + 1, R_DUPLICATE)
            rest = body[colon + 1:].lstrip(" ")
            self.pos = i + 1
            self.lines[path + (key,)] = i + 1
            out[key] = self.value(rest, indent, path + (key,), depth, i)

    def value(self, rest: str, indent: int, path: tuple, depth: int, i: int) -> object:
        if not rest or rest.startswith("#"):
            j = self.next_significant()
            if j >= len(self.raw):
                return None
            ind, body = self.indent_of(j)
            if ind > indent:
                return self.node(ind, path, depth + 1)
            if ind == indent and (body == "-" or body.startswith("- ")) and path and isinstance(path[-1], str):
                return self.sequence(ind, path, depth + 1)
            return None
        header = _cut_comment(rest)
        if header[:1] in "|>":
            if header not in BLOCK_HEADERS:
                raise OracleError(i + 1, R_BLOCK)
            return self.block(header, indent, i)
        if header[:1] in "[{":
            value = _flow(header, i + 1)
        else:
            value = _plain_or_quoted(header if header[:1] not in "'\"" else rest, i + 1)
        j = self.next_significant()
        if j < len(self.raw) and self.indent_of(j)[0] > indent:
            raise OracleError(j + 1, R_INDENT)
        return value

    def sequence(self, indent: int, path: tuple, depth: int) -> list:
        out: list = []
        while True:
            i = self.next_significant()
            if i >= len(self.raw):
                return out
            ind, body = self.indent_of(i)
            if ind != indent or not (body == "-" or body.startswith("- ")):
                if ind > indent:
                    raise OracleError(i + 1, R_INDENT)
                return out
            item = body[1:]
            stripped = item.lstrip(" ")
            col = ind + 1 + (len(item) - len(stripped))
            item_path = path + (len(out),)
            self.lines[item_path] = i + 1
            if not stripped or stripped.startswith("#"):
                self.pos = i + 1
                j = self.next_significant()
                if j < len(self.raw) and self.indent_of(j)[0] > indent:
                    out.append(self.node(self.indent_of(j)[0], item_path, depth + 1))
                else:
                    out.append(None)
                continue
            if stripped == "-" or stripped.startswith("- ") or (
                    stripped[:1] not in "'\"[{|>" and _key_colon(stripped) > 0):
                self.view[i] = (col, stripped)
                self.pos = i
                out.append(self.node(col, item_path, depth + 1))
                continue
            self.pos = i + 1
            out.append(self.value(stripped, indent, item_path, depth, i))

    def block(self, header: str, parent: int, i: int) -> str:
        j = i + 1
        body: list[str] = []
        content = None
        while j < len(self.raw):
            line = self.raw[j]
            stripped = line.lstrip(" ")
            ind = len(line) - len(stripped)
            if stripped == "" and line.strip(" \t") == "":
                if "\t" in line:
                    raise OracleError(j + 1, R_BLOCK)
                body.append(line)
                j += 1
                continue
            if ind <= parent:
                break
            if content is None:
                content = ind
            elif ind < content:
                raise OracleError(j + 1, R_BLOCK)
            body.append(line)
            j += 1
        self.pos = j
        if content is None:
            if any(body):
                raise OracleError(i + 1, R_BLOCK)
            lines: list[str] = []
            trailing = len(body)
        else:
            lines = []
            for k, line in enumerate(body):
                if line.strip(" ") == "":
                    if len(line) > content:
                        raise OracleError(i + 2 + k, R_BLOCK)
                    lines.append("")
                else:
                    lines.append(line[content:])
            trailing = 0
            while lines and lines[-1] == "":
                lines.pop()
                trailing += 1
        if header[0] == ">":
            if lines and lines[0] == "":
                raise OracleError(i + 2, R_BLOCK)
            text = self.fold(lines)
        else:
            text = "\n".join(lines)
        chomp = header[1:]
        if not lines:
            return "\n" * trailing if chomp == "+" else ""
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" + "\n" * trailing
        return text + "\n"

    @staticmethod
    def fold(lines: list[str]) -> str:
        out: list[str] = []
        previous = ""
        breaks = 0
        for line in lines:
            if line == "":
                breaks += 1
                continue
            kind = "more" if line[0] in " \t" else "normal"
            if out:
                if previous == "normal" and kind == "normal":
                    out.append(" " if breaks == 0 else "\n" * breaks)
                else:
                    out.append("\n" * (breaks + 1))
            out.append(line)
            previous, breaks = kind, 0
        return "".join(out)


def read(text: str) -> tuple[object, dict[tuple, int]]:
    """The document of `text` and the line of every key path, or OracleError."""
    reader = _Reader(text)
    return reader.document(), reader.lines


def first_difference(left: object, right: object, path: tuple = ()) -> tuple | None:
    """The first key path where `left` and `right` differ in value or type, else None."""
    if type(left) is not type(right):
        return path
    if isinstance(left, dict):
        if list(left) != list(right):
            for key in list(left) + list(right):
                if key not in left or key not in right:
                    return path + (key,)
            return path
        for key in left:
            found = first_difference(left[key], right[key], path + (key,))
            if found is not None:
                return found
        return None
    if isinstance(left, list):
        for index, (a, b) in enumerate(zip(left, right)):
            found = first_difference(a, b, path + (index,))
            if found is not None:
                return found
        return None if len(left) == len(right) else path + (min(len(left), len(right)),)
    return None if left == right else path


def line_of(lines: dict[tuple, int], path: tuple) -> int:
    """The line of the deepest recorded prefix of `path` (1 for the document)."""
    while path:
        if path in lines:
            return lines[path]
        path = path[:-1]
    return 1


def guarded_files(repo: Path) -> list[Path]:
    """Every workflow file, every action file under .github and the pgbouncer compose file."""
    workflows = sorted(p for p in (repo / ".github" / "workflows").iterdir()
                       if p.suffix in (".yml", ".yaml") and p.is_file())
    actions = sorted(p for p in (repo / ".github").rglob("*") if p.name in ("action.yml", "action.yaml"))
    return workflows + actions + [repo / "infra" / "pgbouncer" / "docker-compose.yml"]
