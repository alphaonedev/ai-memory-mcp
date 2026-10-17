"""Structural XSS guard for the cf-dashboard pages (#7587).

A small JavaScript lexer (strings, template literals with nested interpolations, regex literals, comments) used by
the page tests. It replaces a denylist of known-bad tokens with a rule over every page: no inline script or event
handler anywhere, no markup sink except the one typed helper, and every `${...}` of every template literal wrapped
in the escaping helper (`esc(`) or the numeric formatter (`nf(`).
"""
import re

WRAPPERS = ("esc", "nf")
REGEX_AFTER_PUNCT = set("(,=:[!&|?{};+-*%<>~^")
REGEX_AFTER_WORDS = {"return", "typeof", "case", "in", "of", "void", "delete", "throw", "else", "do"}
SINK_NAMES = ("innerHTML", "outerHTML", "insertAdjacentHTML", "srcdoc")
FORBIDDEN_CALLS = ("eval", "Function", "write", "writeln")
ID_START = re.compile(r"[A-Za-z_$]")
ID_BODY = re.compile(r"[A-Za-z0-9_$]*")
NUMBER = re.compile(r"[0-9][0-9A-Za-z_.]*")


class Token:
    __slots__ = ("kind", "value", "start", "end", "exprs")

    def __init__(self, kind, value, start, end, exprs=None):
        self.kind, self.value, self.start, self.end, self.exprs = kind, value, start, end, exprs or []

    def is_punct(self, ch):
        return self.kind == "p" and self.value == ch

    def is_id(self, name):
        return self.kind == "id" and self.value == name


def _regex_allowed(prev):
    if prev is None:
        return True
    if prev.kind == "p":
        return prev.value in REGEX_AFTER_PUNCT
    return prev.kind == "id" and prev.value in REGEX_AFTER_WORDS


def _skip_quoted(src, i):
    quote = src[i]
    j = i + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == quote:
            return j + 1
        j += 1
    raise ValueError("unterminated string at %d" % i)


def _skip_regex(src, i):
    j, in_class = i + 1, False
    while j < len(src):
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            j += 1
            while j < len(src) and src[j].isalpha():
                j += 1
            return j
        j += 1
    raise ValueError("unterminated regex at %d" % i)


def _template(src, i):
    """Lex a template literal starting at the backtick; return (token, index after it)."""
    j, exprs = i + 1, []
    while j < len(src):
        ch = src[j]
        if ch == "\\":
            j += 2
        elif ch == "`":
            return Token("tpl", src[i:j + 1], i, j + 1, exprs), j + 1
        elif ch == "$" and src[j + 1:j + 2] == "{":
            tokens, j = lex(src, j + 2, True)
            exprs.append(tokens)
        else:
            j += 1
    raise ValueError("unterminated template at %d" % i)


def lex(src, i=0, in_interpolation=False):
    """Return (tokens, index). Inside an interpolation stop after the closing brace."""
    tokens, depth = [], 0
    while i < len(src):
        ch = src[i]
        if ch.isspace():
            i += 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = len(src) if i < 0 else i
        elif src.startswith("/*", i):
            i = src.index("*/", i) + 2
        elif ch in "\"'":
            end = _skip_quoted(src, i)
            tokens.append(Token("str", src[i:end], i, end))
            i = end
        elif ch == "`":
            token, i = _template(src, i)
            tokens.append(token)
        elif ch == "/" and _regex_allowed(tokens[-1] if tokens else None):
            end = _skip_regex(src, i)
            tokens.append(Token("re", src[i:end], i, end))
            i = end
        elif ID_START.match(ch):
            end = i + 1 + len(ID_BODY.match(src, i + 1).group(0))
            tokens.append(Token("id", src[i:end], i, end))
            i = end
        elif ch.isdigit():
            end = NUMBER.match(src, i).end()
            tokens.append(Token("num", src[i:end], i, end))
            i = end
        else:
            if in_interpolation:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    if depth == 0:
                        return tokens, i + 1
                    depth -= 1
            tokens.append(Token("p", ch, i, i + 1))
            i += 1
    if in_interpolation:
        raise ValueError("unterminated interpolation")
    return tokens, i


def walk(tokens):
    """Every token, descending into template interpolations."""
    for token in tokens:
        yield token
        for expr in token.exprs:
            for inner in walk(expr):
                yield inner


def is_wrapped(expr):
    """True when the whole expression is one call of an approved wrapper."""
    if len(expr) < 3 or expr[0].kind != "id" or expr[0].value not in WRAPPERS or not expr[1].is_punct("("):
        return False
    depth = 0
    for index, token in enumerate(expr[1:], 1):
        if token.is_punct("("):
            depth += 1
        elif token.is_punct(")"):
            depth -= 1
            if depth == 0:
                return index == len(expr) - 1
    return False


def unwrapped_interpolations(src, tokens=None):
    """Source text of every `${...}` not wrapped in esc( or nf(."""
    tokens = lex(src)[0] if tokens is None else tokens
    bad = []
    for token in walk(tokens):
        for expr in token.exprs:
            if not expr or not is_wrapped(expr):
                bad.append(src[(expr[0].start if expr else token.start):(expr[-1].end if expr else token.end)])
    return bad


def sink_problems(src, allowed_sinks=0, allowed_new_html=0):
    """Markup sinks and dynamic-code calls outside the single typed helper."""
    tokens = lex(src)[0]
    flat = list(walk(tokens))
    problems = []
    sinks = [t for t in flat if t.kind == "id" and t.value in SINK_NAMES]
    if len(sinks) != allowed_sinks:
        problems.append("%d markup sink(s) (%s), allowed %d" % (len(sinks), ", ".join(t.value for t in sinks), allowed_sinks))
    for t in flat:
        if t.kind == "str" and any(name in t.value for name in SINK_NAMES):
            problems.append("a string names a markup sink: %s" % t.value)
        if t.kind == "str" and "javascript:" in t.value.lower():
            problems.append("javascript: URL in a string")
    for index, t in enumerate(flat):
        if t.kind == "id" and t.value in FORBIDDEN_CALLS:
            after = flat[index + 1] if index + 1 < len(flat) else None
            before = flat[index - 1] if index else None
            if after is not None and (after.is_punct("(") or t.value == "Function") and (
                    t.value in ("eval", "Function") or (before is not None and before.is_punct("."))):
                problems.append("dynamic code or document.write: %s" % t.value)
    made = [i for i, t in enumerate(flat) if t.is_id("new") and i + 1 < len(flat) and flat[i + 1].is_id("Html")]
    if len(made) != allowed_new_html:
        problems.append("%d `new Html(` sites, allowed %d" % (len(made), allowed_new_html))
    # markup( takes only literals joined by +: static text with wrapped interpolations
    for index, t in enumerate(flat):
        if t.is_id("markup") and index + 1 < len(flat) and flat[index + 1].is_punct("(") and not (
                index and flat[index - 1].is_id("const")):
            direct = _direct_args(tokens, t)
            if direct is not None and not all(u.kind in ("tpl", "str") or u.is_punct("+") for u in direct):
                problems.append("markup() takes only string literals at offset %d" % t.start)
    return problems


def _direct_args(tokens, call_id):
    """The tokens between the parentheses of `markup(...)` at the same nesting level as call_id, or None."""
    for token_list in _token_lists(tokens):
        for index, t in enumerate(token_list):
            if t is call_id and index + 1 < len(token_list) and token_list[index + 1].is_punct("("):
                depth, out = 0, []
                for u in token_list[index + 1:]:
                    if u.is_punct("("):
                        depth += 1
                        if depth == 1:
                            continue
                    elif u.is_punct(")"):
                        depth -= 1
                        if depth == 0:
                            return out
                    out.append(u)
    return None


def _token_lists(tokens):
    yield tokens
    for token in tokens:
        for expr in token.exprs:
            for lst in _token_lists(expr):
                yield lst


SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
EVENT_ATTR = re.compile(r"""[\s"'/]on[a-z]+\s*=""", re.IGNORECASE)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def html_problems(html):
    """Inline scripts, event-handler attributes and javascript: URLs in a static page."""
    text = HTML_COMMENT.sub("", html)
    problems = []
    for attrs, body in SCRIPT_TAG.findall(text):
        if "src=" not in attrs.lower():
            problems.append("inline <script> without src")
        elif body.strip():
            problems.append("<script src> with an inline body")
    if EVENT_ATTR.search(text):
        problems.append("event-handler attribute (on...=)")
    if re.search(r"javascript\s*:", text, re.IGNORECASE):
        problems.append("javascript: URL")
    return problems
