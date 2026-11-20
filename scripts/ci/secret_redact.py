#!/usr/bin/env python3
"""The one redaction funnel for CI step output that can carry PostgreSQL connection data (#9750).

Class: a credential reaches a public job log or artifact in a form the URL pattern alone does not
cover. Invariant: every form below leaves no byte of the secret value in the output.

* URL form: ``scheme://user:secret@host/db``, bare (to the next blank) or quoted (to the closing
  quote, so a blank inside the quotes does not end it; an unclosed quote runs to the end of the line).
* Keyword form (libpq conninfo, options, YAML / JSON): ``password=secret``, ``password = 'a b'``,
  ``"password": "x"``, ``--password=x``.
* Environment form: ``PGPASSWORD=secret``, ``export PGPASSWORD="a b"``.

A key is secret when its word contains one of SECRET_KEY_PARTS (any case), so ``PGPASSWORD``,
``db_password`` and ``passwd`` are all keys; a longer word that shares the part is over-redacted. The
value after ``=`` or ``:`` (blanks allowed around the separator, never a line break) is replaced by
REDACTED_VALUE: a quoted value to its closing quote (a backslash escapes the next character, as in
libpq), an unclosed quote to the end of the line, an unquoted value to the next blank.

Cost: one left-to-right pass per pattern; no pattern backtracks more than a bounded distance, so the
time is linear in the input (pinned by a 100K-line test). Standard library only.
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


def _is_secret_key(key: str) -> bool:
    low = key.lower()
    return any(part in low for part in SECRET_KEY_PARTS)


def _redact_urls(text: str, url_label: str) -> str:
    text = QUOTED_URL_RE.sub(lambda m: m.group(1) + url_label + m.group(1), text)
    return BARE_URL_RE.sub(url_label, text)


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
    """``text`` with every URL, keyword and environment credential form replaced (see module doc)."""
    return _redact_values(_redact_urls(text, url_label))
