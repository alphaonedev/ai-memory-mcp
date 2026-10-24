#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when the enterprise-fed tier URL carries a password that is not a secret in practice (#6181).

Reads the tier URL from ``--url-file`` and refuses (exit 1, one ``::error::`` line on stdout) a password that

* is empty or absent,
* is shorter than 16 characters once percent-decoded, or
* is equal to, or contained in, the user, a host or the database name (from the URL or from the ``user=``,
  ``host=``, ``hostaddr=`` and ``dbname=`` query keys) or any other query value (#6640), or
* (for the two rules above and below) every entry of a comma-separated host list counts as a host, in the
  authority (``h1:5445,h2:5446``, IPv6 in brackets) and in ``host=`` / ``hostaddr=`` (#6872), or
* contains one of those components when it is at least 8 characters long (a shorter component can occur in a
  random password by chance).

Those components appear on psql argv and in process listings; a password that equals or hides in one of them
is exposed with them.  Messages name the rule and the component KIND, never a value: every message is a fixed
sentence, and a read error prints only an exception class name taken from a fixed list (#6899, #7971).  Exit 2
(also with an ``::error::`` line) when the file is missing, is group- or world-accessible (#6180, the mode rule
of ``tier_credential.py``) or does not hold one ``postgres://`` URL.  ci.yml runs it as ``python3 -I`` before
the URL is used.  Stdlib only.
"""

import argparse
import importlib.util
from pathlib import Path
import sys
from urllib.parse import SplitResult, unquote

EXIT_OK = 0
EXIT_WEAK = 1
EXIT_BAD_INPUT = 2
MIN_PASSWORD_LENGTH = 16
# A component of at least this many characters inside the password is refused; a shorter one can occur in a random
# password by chance.  Pinned at 8 by test_the_contained_component_boundary_is_8_characters_6645 (#6645).
MIN_CONTAINED_COMPONENT = 8
KINDS = ("user", "host", "database", "query")
URL_SCHEMES = ("postgres", "postgresql")
# libpq query keys that name a URL component; every other query value is checked under the kind "query" (#6640)
QUERY_KINDS = {"user": "user", "host": "host", "hostaddr": "host", "dbname": "database"}


class BadInput(Exception):
    pass


def components(url):
    """Return (password, {kind: [decoded values]}) for a postgres:// URL; raise BadInput otherwise."""
    if any(ch in url for ch in "\t\r\n\x00") or not url.startswith(tuple(f"{s}://" for s in URL_SCHEMES)):
        raise BadInput("the tier URL file does not hold one postgres:// URL")
    try:
        parts = split_url(url)
        netloc = parts.netloc
        userinfo, _, hostport = netloc.rpartition("@")
        user, _, raw_password = userinfo.partition(":")
        hosts = [unquote(host) for host in [hostport] + [netloc_host(entry) for entry in hostport.split(",")]]
        password = unquote(raw_password, errors="surrogateescape")
        named = {"user": [unquote(user)], "host": hosts,
                 "database": [unquote(parts.path[1:]) if parts.path.startswith("/") else ""], "query": []}
        for segment in parts.query.split("&"):
            key, _, value = segment.partition("=")
            key = unquote(key)
            if key == "password":
                password = unquote(value, errors="surrogateescape")
            else:
                named[QUERY_KINDS.get(key, "query")].append(unquote(value))
    except ValueError:
        raise BadInput("the tier URL file does not hold a valid postgres:// URL")
    # #6872: libpq takes a comma-separated host list in the authority and in host=/hostaddr=; each entry is a host.
    named["host"] += [entry for value in named["host"] for entry in value.split(",")]
    return password, named


def split_url(url):
    """Split a URL as RFC 3986 does, without urlsplit's host validation (#6872).

    Python 3.14's urlsplit refuses a bracketed IPv6 entry that is not the first entry of a libpq host list
    (``h1:5445,[::1]:5446``) while 3.9 accepts it; this split reads every supported Python the same way.
    Unbalanced brackets stay refused, as urlsplit refuses them.
    """
    scheme, _, rest = url.partition("://")
    ends = [index for index in (rest.find(mark) for mark in "/?#") if index >= 0]
    end = min(ends) if ends else len(rest)
    netloc, tail = rest[:end], rest[end:]
    if netloc.count("[") != netloc.count("]"):
        raise ValueError("unbalanced brackets in the URL authority")
    tail, _, fragment = tail.partition("#")
    path, _, query = tail.partition("?")
    return SplitResult(scheme, netloc, path, query, fragment)


def netloc_host(entry):
    """The host of one authority entry: ``h``, ``h:port``, ``[v6]`` or ``[v6]:port``."""
    return entry.split("]")[0].lstrip("[") if entry.startswith("[") else entry.rsplit(":", 1)[0]


def hides(password, values):
    """True when the password equals or is contained in a non-empty value (a boolean, it carries no text)."""
    return any(value and password in value for value in values)


def holds(password, values):
    """True when the password contains a value of MIN_CONTAINED_COMPONENT or more characters."""
    return any(len(value) >= MIN_CONTAINED_COMPONENT and value in password for value in values)


def problems(password, named):
    """The rule violations: fixed sentences picked by a boolean per component kind, never built from a value."""
    if not password:
        return ["the tier password is empty"]
    found = []
    if len(password) < MIN_PASSWORD_LENGTH:
        found.append(f"the tier password is shorter than {MIN_PASSWORD_LENGTH} characters")
    for kind in KINDS:
        if hides(password, named.get(kind, [])):
            found.append(f"the tier password equals or is contained in the {kind} component of the URL")
        elif holds(password, named.get(kind, [])):
            found.append(f"the tier password contains the {kind} component of the URL")
    return found


def credential_module():
    """``tier_credential.py`` next to this script: the one URL-file mode rule (#6180) and error-name list."""
    spec = importlib.util.spec_from_file_location("tier_credential", Path(__file__).with_name("tier_credential.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url-file", required=True, type=Path)
    args = parser.parse_args(argv)
    credential = credential_module()
    refusal = credential.mode_problem(args.url_file)
    if refusal is not None:
        print(f"::error::check-tier-password: {refusal}")
        return EXIT_BAD_INPUT
    try:
        url = args.url_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"::error::check-tier-password: cannot read the tier URL file ({credential.read_error_name(exc)})")
        return EXIT_BAD_INPUT
    url = url[:-1] if url.endswith("\n") else url
    try:
        password, named = components(url)
    except BadInput:
        print("::error::check-tier-password: the tier URL file does not hold one valid postgres:// URL")
        return EXIT_BAD_INPUT
    found = problems(password, named)
    if found:
        print("::error::check-tier-password: " + "; ".join(found)
              + " (#6181; rotate it to a random value of at least 32 bytes)")
        return EXIT_WEAK
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
