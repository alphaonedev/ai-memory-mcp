#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when the enterprise-fed tier URL carries a password that is not a secret in practice (#6181).

Reads the tier URL from ``--url-file`` and refuses (exit 1, one ``::error::`` line on stdout) a password that

* is empty or absent,
* is shorter than 16 characters once percent-decoded, or
* is equal to, or contained in, the user, a host (the URL host or a ``host=`` query value) or the database name, or
* contains one of those components when it is at least 8 characters long (a shorter component can occur in a
  random password by chance).

Those components appear on psql argv and in process listings; a password that equals or hides in one of them
is exposed with them.  Messages name the rule and the component KIND, never a value.  Exit 2 (also with an
``::error::`` line) when the file is missing or does not hold one ``postgres://`` URL.  ci.yml runs it as
``python3 -I`` before the URL is used.  Stdlib only.
"""

import argparse
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

EXIT_OK = 0
EXIT_WEAK = 1
EXIT_BAD_INPUT = 2
MIN_PASSWORD_LENGTH = 16
MIN_CONTAINED_COMPONENT = 8
URL_SCHEMES = ("postgres", "postgresql")


class BadInput(Exception):
    pass


def components(url):
    """Return (password, {kind: [decoded values]}) for a postgres:// URL; raise BadInput otherwise."""
    if any(ch in url for ch in "\t\r\n\x00") or not url.startswith(tuple(f"{s}://" for s in URL_SCHEMES)):
        raise BadInput("the tier URL file does not hold one postgres:// URL")
    try:
        parts = urlsplit(url)
        netloc = parts.netloc
        userinfo, _, hostport = netloc.rpartition("@")
        user, _, raw_password = userinfo.partition(":")
        host = hostport.rsplit(":", 1)[0] if not hostport.startswith("[") else hostport.split("]")[0].lstrip("[")
        password = unquote(raw_password, errors="surrogateescape")
        hosts = [unquote(host)]
        for segment in parts.query.split("&"):
            key, _, value = segment.partition("=")
            if unquote(key) == "password":
                password = unquote(value, errors="surrogateescape")
            elif unquote(key) == "host":
                hosts.append(unquote(value))
        database = unquote(parts.path[1:]) if parts.path.startswith("/") else ""
    except ValueError:
        raise BadInput("the tier URL file does not hold a valid postgres:// URL")
    return password, {"user": [unquote(user)], "host": hosts, "database": [database]}


def problems(password, named):
    """The rule violations (messages hold no values)."""
    found = []
    if not password:
        return ["the tier password is empty"]
    if len(password) < MIN_PASSWORD_LENGTH:
        found.append(f"the tier password is shorter than {MIN_PASSWORD_LENGTH} characters")
    for kind, values in named.items():
        if any(value and password in value for value in values):
            found.append(f"the tier password equals or is contained in the {kind} component of the URL")
        elif any(len(value) >= MIN_CONTAINED_COMPONENT and value in password for value in values):
            found.append(f"the tier password contains the {kind} component of the URL")
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        url = args.url_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"::error::check-tier-password: cannot read the tier URL file ({type(exc).__name__})")
        return EXIT_BAD_INPUT
    url = url[:-1] if url.endswith("\n") else url
    try:
        password, named = components(url)
    except BadInput as exc:
        print(f"::error::check-tier-password: {exc}")
        return EXIT_BAD_INPUT
    found = problems(password, named)
    if found:
        print("::error::check-tier-password: " + "; ".join(found)
              + " (#6181; rotate it to a random value of at least 32 bytes)")
        return EXIT_WEAK
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
