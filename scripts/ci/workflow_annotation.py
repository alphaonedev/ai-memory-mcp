"""The one place CI scripts build GitHub workflow-command lines and output-file lines (#9365, #9278, #8634).

A CI script that prints a path, name, label or exception text into ``::error::`` / ``::warning::`` /
``::notice::`` / ``::group::`` must never let a byte of that value start a new workflow command, end the
line or change the command's properties. Every script goes through this module:

* ``annotation(command, message, **properties)``: the whole line, exactly one line, at most
  ``MAX_ANNOTATION_CHARS`` long, message through ``safe_text``, property values through ``property_value``.
* ``safe_text(text)``: message text. Control characters, backslash, ``%``, surrogates and U+2028/9 become
  visible backslash escapes; in every run of colons each ``:`` followed by ``:`` becomes ``\\x3a``; a ``#``
  that is last or precedes ``#``/``[`` becomes ``\\x23`` and a ``[`` that follows ``#`` becomes ``\\x5b``. So
  the result holds no line break, no ``%`` (nothing the runner percent-decodes), no ``::`` and no ``##[``; no
  ``##[`` forms with a literal or escaped value after it, and before it only a literal ending in ``##`` could
  complete one (none exists in the scripts: the stream ratchet's literal cell).
* Runner rule (actions/runner ``src/Runner.Common/ActionCommand.cs``): the v2 form is a line that starts with
  ``::`` after leading whitespace (``TryParseV2``); the v1 form is ``##[`` ANYWHERE in the line (``TryParse``,
  ``IndexOf("##[")``, no trim). ``annotation``, ``render``, ``join`` and ``log_line`` also break every ``##[``
  of the finished line.
* ``property_value(text)``: ``safe_text`` plus ``,`` and ``:`` escaped, because the runner ends a property
  at ``,`` and the command at ``::`` (rule source: the GitHub Actions workflow-commands documentation and
  the runner's ``ActionCommand`` parser: message data escapes ``%``, CR, LF; property values also escape
  ``:`` and ``,``).
* ``log_line(text)``: a plain log line that carries untrusted text (a path in ``removed <path>``): line
  breaks become escapes, a leading ``::`` is neutralised and every ``##[`` becomes ``##\\x5b``; every other
  byte (ANSI colour included) is kept.
* ``env_file_value(value)``: a value for a ``KEY=value`` line of ``$GITHUB_OUTPUT`` / ``$GITHUB_ENV`` /
  ``$GITHUB_STEP_SUMMARY``; every line break becomes a space so the value can never add a second entry.

Standard library only; the syntax parses on old interpreters so a version refusal can still print.
Scripts import it by their own directory (``python3 -I`` drops ``sys.path[0]``).
"""

MAX_ANNOTATION_CHARS = 1000  # the whole annotation line, escapes included
ANNOTATION_CUT_MARK = "..."
ANNOTATION_COMMANDS = ("error", "warning", "notice", "debug", "group")
ANNOTATION_END_GROUP_LINE = "::endgroup::"
LEADING_COMMAND = "::"
NEUTRALISED_COMMAND = "\\x3a:"
LINE_BREAK_CHARS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
PROPERTY_ESCAPES = ((":", "\\x3a"), (",", "\\x2c"))
# v1 form: the runner reads ``##[`` ANYWHERE in a stdout/stderr line as a command (ActionCommand.TryParse:
# message.IndexOf("##["), no trim); v2 form: ``::`` at the start after TrimStart (TryParseV2).
V1_COMMAND_PREFIX = "##["
V1_NEUTRALISED_PREFIX = "##\\x5b"
V1_BREAK_AFTER_HASH = "#["
ESCAPED_COLON = "\\x3a"
ESCAPED_HASH = "\\x23"
ESCAPED_BRACKET = "\\x5b"


def safe_text(text):
    """Escape control characters, backslashes, ``%``, colon runs and ``##[`` pieces so a value cannot start a command.

    Each rule is decided on the raw characters, so it holds wherever the result is placed: a ``:`` followed by ``:``
    becomes ``\\x3a`` (no ``::`` is left in any run of colons); a ``#`` that is the last character or precedes ``#`` or
    ``[`` becomes ``\\x23``, and a ``[`` that follows ``#`` becomes ``\\x5b``. So no ``##[`` is left inside, none forms
    with a following literal or a following escaped value, and a leading ``[`` stays readable (``[Errno 13]``,
    ``[label]``): only a literal ending in ``##`` before the value could complete one, and the stream ratchet keeps
    every such literal out of the scripts. No escape contains ``#``, ``[`` or ``:``.
    """
    text = str(text)
    last = len(text) - 1
    pieces = []
    for index, char in enumerate(text):
        code = ord(char)
        if char == ":" and index < last and text[index + 1] == ":":
            pieces.append(ESCAPED_COLON)
        elif char == "#" and (index == last or text[index + 1] in V1_BREAK_AFTER_HASH):
            pieces.append(ESCAPED_HASH)
        elif char == "[" and index > 0 and text[index - 1] == "#":
            pieces.append(ESCAPED_BRACKET)
        elif char == "\\":
            pieces.append("\\\\")
        elif char == "%":
            pieces.append("\\x25")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            pieces.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            pieces.append("\\u%04x" % code)
        else:
            pieces.append(char)
    return "".join(pieces)


def _break_v1(line):
    """``line`` with every ``##[`` turned into ``##\\x5b``: one pass, the replacement adds no ``[``, so none is left."""
    return line.replace(V1_COMMAND_PREFIX, V1_NEUTRALISED_PREFIX)


def safe_value(text):
    """A value embedded in a script-chosen template: ``safe_text`` with EVERY ``:`` escaped (one pass, so no run survives)."""
    return safe_text(text).replace(":", ESCAPED_COLON)


class SafeText(str):
    """Text this module already escaped (built only by ``render`` and ``join``); ``annotation`` does not escape it again."""

    __slots__ = ()


def render(template, **values):
    """Fill the script-chosen ``template`` with ``values`` and return it as ``SafeText``.

    The template is a literal the script wrote (its own ``:`` stay). Every value goes through ``safe_value``
    unless it already is ``SafeText``. A plain ``str`` is never trusted.
    """
    filled = template.format(**{k: v if isinstance(v, SafeText) else safe_value(v) for k, v in values.items()})
    return SafeText(_break_v1(filled))


def join(separator, parts):
    """``separator`` (a script literal) between ``parts``; each part is ``SafeText`` or is escaped with ``safe_value``."""
    return SafeText(_break_v1(separator.join(p if isinstance(p, SafeText) else safe_value(p) for p in parts)))


def property_value(text):
    """A property value (``title=``, ``file=``): ``safe_text`` plus ``:`` and ``,`` escaped."""
    escaped = safe_text(text)
    for raw, replacement in PROPERTY_ESCAPES:
        escaped = escaped.replace(raw, replacement)
    return escaped


def annotation(command, message, max_chars=MAX_ANNOTATION_CHARS, **properties):
    """One workflow-command line: ``::command key=value,key=value::message``, bounded by ``max_chars``.

    ``command`` and the property keys are fixed names chosen by the script (a bad one raises ValueError);
    every value is escaped here, once. Never pass already escaped text.
    """
    if command not in ANNOTATION_COMMANDS:
        raise ValueError("unknown workflow command %r" % (command,))
    head = "::" + command
    keys = []
    for key, value in properties.items():
        if not key.isalpha() or not key.islower():
            raise ValueError("unknown workflow property %r" % (key,))
        keys.append("%s=%s" % (key, property_value(value)))
    if keys:
        head += " " + ",".join(keys)
    line = _break_v1(head + "::" + (message if isinstance(message, SafeText) else safe_text(message)))
    if len(line) > max_chars:
        line = line[: max_chars - len(ANNOTATION_CUT_MARK)] + ANNOTATION_CUT_MARK
    return line


def end_group_line():
    """The ``::endgroup::`` line (no variable field)."""
    return ANNOTATION_END_GROUP_LINE


def log_line(text):
    """A plain log line that may carry untrusted text: no line break inside, no leading ``::``, no ``##[`` anywhere."""
    pieces = []
    for char in str(text):
        if char in LINE_BREAK_CHARS:
            pieces.append("\\x%02x" % ord(char) if ord(char) < 0x100 else "\\u%04x" % ord(char))
        else:
            pieces.append(char)
    line = "".join(pieces)
    if line.lstrip().startswith(LEADING_COMMAND):
        start = line.index(LEADING_COMMAND)
        line = line[:start] + NEUTRALISED_COMMAND + line[start + len(LEADING_COMMAND):]
    return _break_v1(line)


def env_file_value(value):
    """``value`` for a ``KEY=value`` file line: every line break becomes a space (no second entry).

    A lone surrogate (a non-UTF-8 path read with surrogateescape) becomes a visible ``\\uXXXX`` so the file write
    cannot raise halfway through a multi-line append.
    """
    pieces = []
    for char in str(value):
        if char in LINE_BREAK_CHARS:
            pieces.append(" ")
        elif 0xD800 <= ord(char) <= 0xDFFF:
            pieces.append("\\u%04x" % ord(char))
        else:
            pieces.append(char)
    return "".join(pieces)
