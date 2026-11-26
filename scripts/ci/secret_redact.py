#!/usr/bin/env python3
"""The one redaction funnel for CI step output that can carry PostgreSQL connection data (#9750).

Class: a credential reaches a public job log or artifact in a form the URL pattern alone does not
cover. Invariant: every form below leaves no byte of the secret value in the output.

* URL form: ``scheme://user:secret@host/db``, bare (to the next blank) or quoted (to the closing
  quote, so a blank inside the quotes does not end it; an unclosed quote runs to the end of the line).
* Keyword form (libpq conninfo, options, YAML / JSON): ``password=secret``, ``password = 'a b'``,
  ``"password": "x"``, ``--password=x``.
* Environment form: ``PGPASSWORD=secret``, ``export PGPASSWORD="a b"``.
* SQL literal form (#9592 D3-L1): ``ALTER ROLE u [WITH ...] PASSWORD 'secret'`` and every word that
  holds a secret part, then blanks (none allowed), then a string literal: ``'..'`` with the doubled
  quote ``''`` escape, the E-string ``E'..'`` (any case) with backslash escapes, ``U&'..'`` and a
  dollar quote ``$tag$..``. The literal becomes REDACTED_VALUE, the keyword and blanks stay:
  ``PASSWORD <redacted>``. A backslash escapes the next character in every quoted literal and a
  dollar quote runs to the end of the line; both can only over-redact. The word ``password`` with no
  literal right after it (``password authentication failed``, ``PASSWORD NULL``) is left as it is.

A key is secret when its word contains one of SECRET_KEY_PARTS (any case), so ``PGPASSWORD``,
``db_password`` and ``passwd`` are all keys; a longer word that shares the part is over-redacted. The
value after ``=`` or ``:`` (blanks allowed around the separator, never a line break) is replaced by
REDACTED_VALUE: a quoted value to its closing quote (a backslash escapes the next character, as in
libpq), an unclosed quote to the end of the line, an unquoted value to the next blank. No form spans a
line break: a value is cut at the end of its line.

Cost: one left-to-right pass per pattern; no pattern backtracks more than a bounded distance, so the
time is linear in the input (pinned by a 100K-line test and 200K-character SQL literal lines). The SQL
literal pattern can start only at a word start (the lookbehind), and its literal body has alternatives
that begin with different characters and nothing after it that can fail, so a literal is read once per
start; a long literal is read again only from a later word start inside it that is followed by blanks
and a quote, and such a nested literal ends at the first single quote it meets. Standard library only.
"""
from __future__ import annotations

import re

REDACTED_URL = '<redacted-url>'
REDACTED_VALUE = '<redacted>'
SECRET_KEY_PARTS = ('password', 'passwd', 'passphrase')
SCHEME = r'[A-Za-z][A-Za-z0-9+.-]{0,30}://'
# A quote right before the scheme: the URL runs to the same quote (or the end of the line).
QUOTED_URL_RE = re.compile(r'([\'"])' + SCHEME + r'(?:(?!\1)[^\n])*\1?')
BARE_URL_RE = re.compile(SCHEME + r'\S*')
# A whole word, an optional closing quote of a quoted key, then `=` or `:` with blanks (not newlines).
KEY_SEP_RE = re.compile(r'(?<![A-Za-z0-9_])([A-Za-z0-9_]+)([\'"]?[ \t]*[=:][ \t]*)')
VALUE_RE = re.compile(r"'(?:[^'\\\n]|\\[^\n])*'?|\"(?:[^\"\\\n]|\\[^\n])*\"?|[^\s]+")
# SQL: a whole word, blanks (not newlines), then a string literal: optional E or U& prefix, a single
# quote, a body of plain characters, doubled quotes or backslash escapes, an optional closing quote; or
# the opening tag of a dollar quote (the redaction then runs to the end of the line, see below).
SQL_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z0-9_]+)([ \t]*)"
    r"((?:[Ee]|[Uu]&)?'(?:[^'\\\n]|''|\\[^\n])*'?|\$[A-Za-z0-9_]*\$)"
)
DOLLAR = '$'
NEWLINE = '\n'


def _is_secret_key(key: str) -> bool:
    low = key.lower()
    return any(part in low for part in SECRET_KEY_PARTS)


def _redact_urls(text: str, url_label: str) -> str:
    text = QUOTED_URL_RE.sub(lambda m: m.group(1) + url_label + m.group(1), text)
    return BARE_URL_RE.sub(url_label, text)


def _redact_sql_literals(text: str) -> str:
    out = []
    pos = 0
    scan = 0
    while (m := SQL_LITERAL_RE.search(text, scan)) is not None:
        if not _is_secret_key(m.group(1)):
            # Resume after the word, not after its literal, so a non-secret word's literal never
            # hides a later secret keyword.
            scan = m.end(1)
            continue
        end = m.end(3)
        if m.group(3).startswith(DOLLAR):
            # Read only for a secret word, so the cost stays one pass over the line.
            line_end = text.find(NEWLINE, end)
            end = len(text) if line_end < 0 else line_end
        out.append(text[pos:m.end(2)])
        out.append(REDACTED_VALUE)
        pos = scan = end
    out.append(text[pos:])
    return ''.join(out)


def _redact_values(text: str) -> str:
    out = []
    pos = 0
    for m in KEY_SEP_RE.finditer(text):
        if m.start() < pos or not _is_secret_key(m.group(1)):
            continue
        value = VALUE_RE.match(text, m.end())
        if value is None or value.end() == m.end():
            continue
        out.append(text[pos:m.end()])
        out.append(REDACTED_VALUE)
        pos = value.end()
    out.append(text[pos:])
    return ''.join(out)


def redact(text: str, url_label: str = REDACTED_URL) -> str:
    """``text`` with every URL, keyword, environment and SQL literal credential form replaced."""
    return _redact_values(_redact_sql_literals(_redact_urls(text, url_label)))
