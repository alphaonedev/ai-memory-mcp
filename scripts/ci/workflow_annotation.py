"""The one place CI scripts build GitHub workflow-command lines and output-file lines (#9365, #9278, #8634).

A CI script that prints a path, name, label or exception text into ``::error::`` / ``::warning::`` /
``::notice::`` / ``::group::`` must never let a byte of that value start a new workflow command, end the
line or change the command's properties. Every script goes through this module:

* ``annotation(command, message, **properties)``: the whole line, exactly one line, at most
  ``MAX_ANNOTATION_CHARS`` long, message through ``safe_text``, property values through ``property_value``.
* ``safe_text(text)``: message text. Control characters, backslash, ``%``, surrogates, U+2028/9 and ``::``
  become visible backslash escapes, so the value cannot carry a line break, a ``%0A`` the runner would
  decode, or a ``::``.
* ``property_value(text)``: ``safe_text`` plus ``,`` and ``:`` escaped, because the runner ends a property
  at ``,`` and the command at ``::`` (rule source: the GitHub Actions workflow-commands documentation and
  the runner's ``ActionCommand`` parser: message data escapes ``%``, CR, LF; property values also escape
  ``:`` and ``,``).
* ``log_line(text)``: a plain log line that carries untrusted text (a path in ``removed <path>``): line
  breaks become escapes and a leading ``::`` is neutralised; every other byte (ANSI colour included) is kept.
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


def safe_text(text):
    """Escape control characters, backslashes, ``%`` and ``::`` so a name cannot inject a log line or workflow command."""
    pieces = []
    for char in str(text):
        code = ord(char)
        if char == "\\":
            pieces.append("\\\\")
        elif char == "%":
            pieces.append("\\x25")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            pieces.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            pieces.append("\\u%04x" % code)
        else:
            pieces.append(char)
    return "".join(pieces).replace("::", "\\x3a:")


def safe_value(text):
    """A value embedded in a script-chosen template: ``safe_text`` with EVERY ``:`` escaped (one pass, so no run survives)."""
    return safe_text(text).replace(":", "\\x3a")


class SafeText(str):
    """Text this module already escaped (built only by ``render`` and ``join``); ``annotation`` does not escape it again."""

    __slots__ = ()


def render(template, **values):
    """Fill the script-chosen ``template`` with ``values`` and return it as ``SafeText``.

    The template is a literal the script wrote (its own ``:`` stay). Every value goes through ``safe_value``
    unless it already is ``SafeText``. A plain ``str`` is never trusted.
    """
    return SafeText(template.format(**{k: v if isinstance(v, SafeText) else safe_value(v) for k, v in values.items()}))


def join(separator, parts):
    """``separator`` (a script literal) between ``parts``; each part is ``SafeText`` or is escaped with ``safe_value``."""
    return SafeText(separator.join(p if isinstance(p, SafeText) else safe_value(p) for p in parts))


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
    line = head + "::" + (message if isinstance(message, SafeText) else safe_text(message))
    if len(line) > max_chars:
        line = line[: max_chars - len(ANNOTATION_CUT_MARK)] + ANNOTATION_CUT_MARK
    return line


def end_group_line():
    """The ``::endgroup::`` line (no variable field)."""
    return ANNOTATION_END_GROUP_LINE


def log_line(text):
    """A plain log line that may carry untrusted text: no line break inside, no leading ``::``."""
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
    return line


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
