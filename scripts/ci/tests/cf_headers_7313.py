"""The ONE reader of the Cloudflare Pages `_headers` file for every check and test server in this change (#7685 #7686).

It fails closed. A file it cannot prove it understands is REFUSED with the line number, never skipped or guessed at:

  * any character outside printable ASCII (plus tab and newline): a look-alike space or an invisible character can
    change what a browser reads without changing what a reviewer sees;
  * any `!` line, the header-removal syntax, which detaches a header another rule attached;
  * any rule whose pattern is not a plain URL path (a host or scheme pattern such as `https://*.example.com/*`):
    this reader matches the served path only, so it cannot say whether such a rule applies;
  * a comment line, a header before any rule, a header line without `name: value`, a bad header name, an empty value;
  * a second `Content-Security-Policy` anywhere in the file: two policies intersect in a browser, so a looser one
    hidden among them cannot be reasoned about from this file.

The CSP value is split into directives, and a directive into tokens, only on the ASCII whitespace of the CSP grammar
(`CSP_WHITESPACE`), never on `str.split()` (which also splits on no-break space and other Unicode spaces)."""
import re
from pathlib import Path

PLAIN_PATH = re.compile(r"^/[A-Za-z0-9/_.*:~%+@-]*$")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]+$")
CSP_NAME = "content-security-policy"
CSP_WHITESPACE = "[\t\n\f\r ]"
_CSP_WHITESPACE_RE = re.compile(CSP_WHITESPACE + "+")


class HeadersError(ValueError):
    """The `_headers` text is not one this reader can prove it understands. The message starts `line N:`."""


class Rule:
    def __init__(self, pattern, line):
        self.pattern = pattern
        self.line = line
        self.headers = []  # (name, value, line)


def csp_tokens(text):
    """Split on ASCII whitespace only, dropping empties: the CSP grammar's own separator set."""
    return [t for t in _CSP_WHITESPACE_RE.split(text) if t]


def _check_chars(line, number):
    for ch in line:
        code = ord(ch)
        if code > 126:
            raise HeadersError("line %d: non-ASCII byte U+%04X is refused" % (number, code))
        if code < 32 and ch != "\t":
            raise HeadersError("line %d: control character U+%04X is refused" % (number, code))


def parse(text):
    """The rules of a `_headers` text, in file order. Raises HeadersError on anything not understood."""
    rules, current, csp_line = [], None, None
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        _check_chars(line, number)
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            raise HeadersError("line %d: a `!` header-removal line is refused (it can detach the CSP): %r"
                               % (number, stripped))
        if stripped.startswith("#"):
            raise HeadersError("line %d: a comment line is refused: %r" % (number, stripped))
        if line[0] not in " \t":
            if not PLAIN_PATH.match(stripped) or stripped.startswith("//"):
                raise HeadersError("line %d: the rule pattern %r is not a plain URL path (host and scheme patterns "
                                   "are refused)" % (number, stripped))
            current = Rule(stripped, number)
            rules.append(current)
            continue
        if current is None:
            raise HeadersError("line %d: a header before any rule: %r" % (number, stripped))
        name, colon, value = stripped.partition(":")
        if not colon:
            raise HeadersError("line %d: expected `name: value`, got %r" % (number, stripped))
        name, value = name.strip(), value.strip()
        if not HEADER_NAME.match(name):
            raise HeadersError("line %d: %r is not a valid header name" % (number, name))
        if not value:
            raise HeadersError("line %d: header %s has an empty value" % (number, name))
        if name.lower() == CSP_NAME:
            if csp_line is not None:
                raise HeadersError("line %d: a second Content-Security-Policy (the first is on line %d); exactly one "
                                   "is allowed in the whole file" % (number, csp_line))
            csp_line = number
        current.headers.append((name, value, number))
    return rules


def parse_file(path):
    return parse(Path(path).read_text(encoding="utf-8"))


def pattern_regex(pattern):
    """A Cloudflare `_headers` URL pattern: `*` is a splat, `:name` a placeholder for one path segment."""
    out = []
    for part in re.split(r"(\*|:[A-Za-z][A-Za-z0-9_]*)", pattern):
        out.append(".*" if part == "*" else "[^/]+" if part.startswith(":") and len(part) > 1 else re.escape(part))
    return re.compile("^" + "".join(out) + "$")


def headers_for(text, path):
    """Every (name, value) of every rule whose pattern matches the served path, in file order."""
    return [(name, value) for rule in parse(text) if pattern_regex(rule.pattern).match(path)
            for name, value, _ in rule.headers]


def csp_values(text, path):
    """The raw Content-Security-Policy values (at most one, the file allows exactly one) that apply to the path."""
    return [value for name, value in headers_for(text, path) if name.lower() == CSP_NAME]


def csp_policies(text, path):
    """Each applicable CSP value split on commas into its policies (a header value may join several)."""
    return [p.strip() for v in csp_values(text, path) for p in v.split(",") if p.strip()]
