"""Static guard for the cf-dashboard scripts (#7587, #7634, #7635): an ALLOWLIST over a small JavaScript lexer.

A deny-list of known-bad names cannot be complete (`e['inner'+'HTML']`, `Range.createContextualFragment`,
`DOMParser`, `setHTMLUnsafe`, string `setTimeout` all reach the DOM without the name such a list would look for).
The browser enforces the real rule (Trusted Types, see public/_headers); this guard pins the SHAPE of the one place
that is allowed to talk to Trusted Types and refuses every deviation from it:

- the helper block `const { markup, cat, put } = (() => { ... })();` is the only code that names `createPolicy`,
  `createHTML`, `innerHTML` or the token internals (`trusted`, `mint`, `part`, `escText`, `WeakMap`, `Reflect`,
  `Html`), and the only code that may use `Object.create`, `.constructor`, `.prototype`, `__proto__` or
  `setPrototypeOf` (#7684: trust is a closure-private WeakMap brand, so no prototype game outside the block can
  matter, and none is accepted);
- inside the block the brand is a `new WeakMap` and nothing is a type: no `class`, no `instanceof`;
- inside it, `put` holds exactly one `createPolicy("dash", ...)` and exactly one `.createHTML(` call, and the
  policy's `createHTML` rule escapes (it names `escText`);
- every other `markup` token tags a template literal (`markup` followed by a template), never a call;
- a script that is not index.js names none of those tokens.

The lexer handles strings, template literals with nested interpolations, regex literals and comments, so a quote in
a regex or a name in a comment never moves a boundary.
"""
import re

REGEX_AFTER_PUNCT = set("(,=:[!&|?{};+-*%<>~^")
REGEX_AFTER_WORDS = {"return", "typeof", "case", "in", "of", "void", "delete", "throw", "else", "do"}
POLICY_NAME = "dash"
GUARDED_NAMES = ("Html", "createPolicy", "createHTML", "innerHTML", "trusted", "mint", "part", "escText", "WeakMap",
                 "Reflect", "setPrototypeOf", "__proto__", "constructor", "prototype")
# strings that name a prototype or constructor reach outside the block (`o["constructor"]`, `Object["create"]`)
GUARDED_STRINGS = frozenset(GUARDED_NAMES) | {"create"}
# inside the block: no type-based trust
HELPER_REFUSED = ("class", "instanceof", "Html", "constructor", "prototype", "setPrototypeOf", "__proto__", "Reflect")
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


def _match(tokens, i, open_ch, close_ch):
    """Index of the token that closes the bracket opened at tokens[i]."""
    depth = 0
    for j in range(i, len(tokens)):
        if tokens[j].is_punct(open_ch):
            depth += 1
        elif tokens[j].is_punct(close_ch):
            depth -= 1
            if depth == 0:
                return j
    raise ValueError("unbalanced %s at token %d" % (open_ch, i))


def _statement_end(tokens, i):
    """Index of the `;` that ends the top-level statement starting at tokens[i]."""
    depth = 0
    for j in range(i, len(tokens)):
        t = tokens[j]
        if t.kind == "p" and t.value in "({[":
            depth += 1
        elif t.kind == "p" and t.value in ")}]":
            depth -= 1
        elif t.is_punct(";") and depth == 0:
            return j
    raise ValueError("unterminated statement")


def _find(tokens, shape, start=0):
    """First index at or after start where the token values equal `shape` (a list of strings), else -1."""
    for i in range(start, len(tokens) - len(shape) + 1):
        if all(tokens[i + k].value == shape[k] for k in range(len(shape))):
            return i
    return -1


def _call_sites(flat, name):
    """Tokens of the identifier `name` used as a member call: `.name(`."""
    return [t for i, t in enumerate(flat) if t.is_id(name) and i and flat[i - 1].is_punct(".")
            and i + 1 < len(flat) and flat[i + 1].is_punct("(")]


def _token_lists(tokens):
    yield tokens
    for token in tokens:
        for expr in token.exprs:
            for lst in _token_lists(expr):
                yield lst


def js_problems(src, helper_allowed):
    """Allowlist violations of one script. `helper_allowed` is True only for the dashboard renderer (index.js)."""
    tokens = lex(src)[0]
    flat = list(walk(tokens))
    problems = []
    helper_lo = helper_hi = put_lo = put_hi = -1
    helper = _find(tokens, ["const", "{", "markup", ",", "cat", ",", "put", "}", "="])
    if helper >= 0:
        helper_lo, helper_hi = tokens[helper].start, tokens[_statement_end(tokens, helper)].end
        inner = [t for t in flat if helper_lo <= t.start < helper_hi]
        put_at = _find(inner, ["const", "put", "="])
        if put_at >= 0:
            put_lo, put_hi = inner[put_at].start, inner[_statement_end(inner, put_at)].end

    def inside(token, lo, hi):
        return lo <= token.start < hi

    if not helper_allowed and helper >= 0:
        problems.append("a helper block outside the dashboard renderer")
    if helper_allowed and helper < 0:
        problems.append("the helper block `const { markup, cat, put } = (() => {...})();` is missing")
    for name in GUARDED_NAMES:
        outside = [t for t in flat if t.is_id(name) and not inside(t, helper_lo, helper_hi)]
        if outside:
            problems.append("%s used outside the helper block (offset %d)" % (name, outside[0].start))
    for i, t in enumerate(flat):
        if inside(t, helper_lo, helper_hi):
            continue
        if t.is_id("create") and i >= 2 and flat[i - 1].is_punct(".") and flat[i - 2].is_id("Object"):
            problems.append("Object.create used outside the helper block (offset %d)" % t.start)
        text = t.value[1:-1] if t.kind == "str" or (t.kind == "tpl" and not t.exprs) else None
        if text in GUARDED_STRINGS:
            problems.append("the string %r names a prototype or constructor reach outside the helper block (offset %d)"
                            % (text, t.start))
    if helper_allowed and helper >= 0:
        inner_all = [t for t in flat if inside(t, helper_lo, helper_hi)]
        if not any(t.is_id("WeakMap") for t in inner_all):
            problems.append("the helper block must keep trust in a closure-private WeakMap")
        for name in HELPER_REFUSED:
            if any(t.is_id(name) for t in inner_all):
                problems.append("%s inside the helper block: trust is a WeakMap brand, not a type" % name)
    policies = [t for t in flat if t.is_id("createPolicy")]
    if helper_allowed:
        if len(policies) != 1 or not inside(policies[0], put_lo, put_hi):
            problems.append("expected exactly one createPolicy, inside put(); found %d" % len(policies))
        else:
            at = flat.index(policies[0])
            argument = flat[at + 2] if at + 2 < len(flat) else None
            if not (argument is not None and argument.kind == "str" and argument.value[1:-1] == POLICY_NAME):
                problems.append('the policy must be named "%s"' % POLICY_NAME)
        calls = _call_sites(flat, "createHTML")
        if len(calls) != 1 or not inside(calls[0], put_lo, put_hi):
            problems.append("expected exactly one .createHTML( call, inside put(); found %d" % len(calls))
        keys = [i for i, t in enumerate(flat) if t.is_id("createHTML") and i + 1 < len(flat) and flat[i + 1].is_punct(":")]
        if len(keys) != 1:
            problems.append("expected exactly one createHTML rule")
        else:
            body, depth = [], 0
            for t in flat[keys[0] + 2:]:
                if t.kind == "p" and t.value in "({[":
                    depth += 1
                elif t.kind == "p" and t.value in ")}]":
                    depth -= 1
                    if depth < 0:
                        break
                elif t.is_punct(",") and depth == 0:
                    break
                body.append(t.value)
            if "escText" not in body:
                problems.append("the createHTML rule must escape (it must name escText)")
        sinks = [t for t in flat if t.is_id("innerHTML")]
        if len(sinks) != 1 or not inside(sinks[0], put_lo, put_hi):
            problems.append("expected exactly one innerHTML, inside put(); found %d" % len(sinks))
    else:
        for name in ("createPolicy", "createHTML", "innerHTML"):
            if any(t.is_id(name) for t in flat):
                problems.append("%s in a script that is not the dashboard renderer" % name)
    for token_list in _token_lists(tokens):
        for i, t in enumerate(token_list):
            if not t.is_id("markup") or inside(t, helper_lo, helper_hi):
                continue
            after = token_list[i + 1] if i + 1 < len(token_list) else None
            if after is None or after.kind != "tpl":
                problems.append("markup at offset %d does not tag a template literal" % t.start)
    return problems
