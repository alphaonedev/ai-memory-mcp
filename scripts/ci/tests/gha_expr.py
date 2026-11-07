"""A minimal GitHub Actions expression evaluator for job-level `if:` probes (#8240).

Supports the subset ci.yml uses: string, boolean and null literals, dotted
context lookups (`needs.<job>.result`, `needs.<job>.outputs.<key>`,
`github.ref`), the operators `!`, `==`, `!=`, `&&`, `||`, parentheses, and the
functions `contains`, `format`, `startsWith` and the status functions
`success`, `failure`, `cancelled`, `always`.

GitHub prepends an implicit `success() &&` to a job `if:` that calls no status
function; `evaluate_job_if` reproduces that, because it is exactly the
behaviour that made a failed `select` job skip its dependants.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

TOKEN_RE = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<op>&&|\|\||==|!=|!|\(|\)|,)"
    r"|(?P<word>[A-Za-z_][A-Za-z0-9_.\-]*))")
STATUS_FUNCTIONS = ("success", "failure", "cancelled", "always")
RESULT_SUCCESS = "success"
RESULT_FAILURE = "failure"


class ExprError(ValueError):
    """The expression uses syntax outside the supported subset."""


def strip_wrapper(text: str) -> str:
    """Remove a surrounding `${{ ... }}` and whitespace."""
    text = text.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return text.strip()


def tokenize(text: str) -> List[Tuple[str, str]]:
    """Split `text` into (kind, value) tokens."""
    tokens: List[Tuple[str, str]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        match = TOKEN_RE.match(text, pos)
        if not match:
            raise ExprError("cannot tokenize at %r" % text[pos:pos + 20])
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "str":
            value = value[1:-1].replace("''", "'")
        tokens.append((kind, value))
        pos = match.end()
    return tokens


def truthy(value: Any) -> bool:
    """GitHub truthiness: false, 0, '' and null are falsy."""
    return value not in (False, 0, "", None)


def loose_equal(left: Any, right: Any) -> bool:
    """GitHub loose equality: strings compare case-insensitively, null is ''."""
    if isinstance(left, bool) or isinstance(right, bool):
        return truthy(left) == truthy(right) if isinstance(left, bool) and isinstance(right, bool) else False
    norm_left = "" if left is None else str(left).lower()
    norm_right = "" if right is None else str(right).lower()
    return norm_left == norm_right


class Evaluator:
    """Recursive-descent evaluator over a context dictionary."""

    def __init__(self, tokens: List[Tuple[str, str]], context: Dict[str, Any],
                 needs_results: List[str], cancelled: bool) -> None:
        self.tokens = tokens
        self.pos = 0
        self.context = context
        self.needs_results = needs_results
        self.cancelled = cancelled
        self.used_status = False

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, value: Optional[str] = None) -> Tuple[str, str]:
        token = self.peek()
        if token is None or (value is not None and token[1] != value):
            raise ExprError("expected %r, got %r" % (value, token))
        self.pos += 1
        return token

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.parse_and()
            left = left if truthy(left) else right
        return left

    def parse_and(self) -> Any:
        left = self.parse_eq()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.parse_eq()
            left = right if truthy(left) else left
        return left

    def parse_eq(self) -> Any:
        left = self.parse_unary()
        while self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            right = self.parse_unary()
            same = loose_equal(left, right)
            left = same if op == "==" else not same
        return left

    def parse_unary(self) -> Any:
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        token = self.take()
        kind, value = token
        if kind == "str":
            return value
        if value == "(":
            inner = self.parse_or()
            self.take(")")
            return inner
        if kind != "word":
            raise ExprError("unexpected token %r" % (token,))
        if self.peek() == ("op", "("):
            return self.call(value)
        return self.lookup(value)

    def call(self, name: str) -> Any:
        self.take("(")
        args: List[Any] = []
        if self.peek() != ("op", ")"):
            args.append(self.parse_or())
            while self.peek() == ("op", ","):
                self.take()
                args.append(self.parse_or())
        self.take(")")
        if name in STATUS_FUNCTIONS:
            self.used_status = True
            return self.status(name)
        if name == "contains":
            return str(args[1]).lower() in str(args[0] or "").lower()
        if name == "startsWith":
            return str(args[0] or "").lower().startswith(str(args[1]).lower())
        if name == "format":
            text = str(args[0])
            for index, arg in enumerate(args[1:]):
                text = text.replace("{%d}" % index, "" if arg is None else str(arg))
            return text
        raise ExprError("unsupported function %s" % name)

    def status(self, name: str) -> bool:
        if name == "always":
            return True
        if name == "cancelled":
            return self.cancelled
        if name == "failure":
            return not self.cancelled and any(r != RESULT_SUCCESS for r in self.needs_results)
        return not self.cancelled and all(r == RESULT_SUCCESS for r in self.needs_results)

    def lookup(self, dotted: str) -> Any:
        if dotted == "true":
            return True
        if dotted == "false":
            return False
        if dotted == "null":
            return None
        node: Any = self.context
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node


def evaluate_job_if(expression: str, context: Dict[str, Any],
                    cancelled: bool = False) -> bool:
    """Return True when a job with this `if:` and `context` would run.

    `context["needs"]` maps job id -> {"result", "outputs"}. The implicit
    `success() &&` is applied when the expression calls no status function.
    """
    text = strip_wrapper(expression)
    needs = context.get("needs", {})
    results = [(info or {}).get("result") for info in needs.values()]
    runner = Evaluator(tokenize(text), context, results, cancelled)
    value = runner.parse_or()
    if runner.pos != len(runner.tokens):
        raise ExprError("trailing tokens in %r" % text)
    if not runner.used_status and not runner.status("success"):
        return False
    return truthy(value)
