#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#4616 - cloud-init memory templates must start a daemon that can boot.

Two infra templates start ``ai-memory serve`` from a systemd unit rendered by
cloud-init (``infra/do-hive/cloud-init-memory.yaml.tpl`` and
``infra/aws-gpu-burst/cloud-init-memory.yaml.tpl``). A flag the binary does not
define (the old ``--bind``) makes the unit exit at start and loop on
``Restart=on-failure``; cloud-init discards a config containing a non-ASCII
byte (#1880). Neither failure shows up at provision time.

For every ``ExecStart=`` line that runs ``ai-memory serve`` in a tracked
``infra/*/cloud-init-memory*.tpl`` the gate fails when:

  * a ``--flag`` is not a field of ``ServeArgs`` in ``src/daemon_runtime.rs``
    (clap derives the long flag from the field name); or
  * ``--tls-cert`` / ``--tls-key`` are not both present (``tls_bind_guard``
    refuses every bind without in-process TLS); or
  * the template contains a non-ASCII byte.

Usage:
  scripts/check-cloud-init-serve-flags.py             exit 0 clean, 1 on a
                                                      hit, 2 on a scanner fault
  scripts/check-cloud-init-serve-flags.py --self-test prove the rule is red on
                                                      probes, green on a clean
                                                      line
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVE_SRC = ROOT / "src" / "daemon_runtime.rs"
TEMPLATE_GLOB = "infra/*/cloud-init-memory*.tpl"
REQUIRED_FLAGS = ("--tls-cert", "--tls-key")

STRUCT_RE = re.compile(r"pub struct ServeArgs \{(.*?)\n\}", re.S)
FIELD_RE = re.compile(r"^\s{4}pub (\w+):", re.M)
EXEC_RE = re.compile(r"^\s*ExecStart=\S*ai-memory serve(?P<rest>.*)$", re.M)
# Templates that still lack the sslmode floor, each with its tracker. The
# do-hive store URL dials PgBouncer on 127.0.0.1:6432 and its TLS shape has
# more than one viable form (#4635 do-hive leg, awaiting a vote). The list may
# only shrink: a listed template that passes the floor is itself a failure.
DSN_FLOOR_GAPS = {
    "infra/do-hive/cloud-init-memory.yaml.tpl": "#4635 do-hive pgbouncer leg",
}
DSN_RE = re.compile(r"^\s+(postgres(?:ql)?://\S+)\s*$", re.M)
FLAG_RE = re.compile(r"(?<![\w-])(--[A-Za-z][\w-]*)")


def serve_flags(source: str) -> set:
    """Long flags clap derives from the ServeArgs field names."""
    body = STRUCT_RE.search(source)
    if body is None:
        raise RuntimeError("pub struct ServeArgs not found in " + str(SERVE_SRC))
    names = FIELD_RE.findall(body.group(1))
    if not names:
        raise RuntimeError("ServeArgs has no fields")
    return {"--" + n.replace("_", "-") for n in names}


def scan_text(name: str, text: str, known: set) -> list:
    """Return one message per defect found in a template's text."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(ord(ch) > 127 for ch in line):
            hits.append("%s:%d: non-ASCII byte (cloud-init discards the config, #1880)" % (name, lineno))
    dsns = DSN_RE.findall(text)
    if not dsns:
        hits.append("%s: no postgres:// store URL line found (cannot check the sslmode floor)" % name)
    floor_ok = True
    for dsn in dsns:
        query = dsn.split("?", 1)[1] if "?" in dsn else ""
        modes = [p.split("=", 1)[1].strip().lower() for p in query.split("&") if p.lower().startswith("sslmode=")]
        if not modes or modes[-1] != "verify-full":
            floor_ok = False
            if name in DSN_FLOOR_GAPS:
                continue
            hits.append("%s: store URL has no sslmode=verify-full (serve refuses it at start, #3705 floor, src/transit_encryption.rs:436-446)" % name)
    if name in DSN_FLOOR_GAPS and floor_ok and dsns:
        hits.append("%s: store URL now passes the sslmode floor; remove it from DSN_FLOOR_GAPS" % name)
    for m in EXEC_RE.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        # Strip terraform directives so their words are not read as flags.
        rest = re.sub(r"%\{[^}]*\}", " ", m.group("rest"))
        rest = re.sub(r"\$\$?\{[^}]*\}", " ", rest)
        flags = FLAG_RE.findall(rest)
        for flag in flags:
            if flag not in known:
                hits.append("%s:%d: serve flag %s is not a ServeArgs field (unit would exit at start)" % (name, lineno, flag))
        for req in REQUIRED_FLAGS:
            if req not in flags:
                hits.append("%s:%d: serve has no %s (tls_bind_guard refuses a plaintext bind)" % (name, lineno, req))
    return hits


def self_test(known: set) -> int:
    good = "      postgres://u:p@localhost/db?sslmode=verify-full&sslrootcert=/c\nExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077 --tls-cert /a --tls-key /b\n"
    probes = {
        "bind flag": good.replace("--host 0.0.0.0", "--bind 0.0.0.0:9077"),
        "no tls": "ExecStart=/opt/ai-memory/bin/ai-memory serve --host 0.0.0.0 --port 9077\n",
        "tls key missing": good.replace(" --tls-key /b", ""),
        "no sslmode": good.replace("?sslmode=verify-full&sslrootcert=/c", ""),
        "weak sslmode": good.replace("verify-full", "require"),
        "non-ascii": "# em dash —\n" + good,
    }
    red = 0
    for label, text in probes.items():
        if scan_text(label, text, known):
            red += 1
        else:
            print("SELF-TEST FAIL: probe not flagged: " + label, file=sys.stderr)
    clean = scan_text("good", good, known) == [] and scan_text("directive", good.rstrip() + "%{ if x } --quorum-writes 2%{ endif }\n", known) == []
    if red != len(probes) or not clean:
        print("SELF-TEST FAIL: %d/%d probes flagged, clean=%s" % (red, len(probes), clean), file=sys.stderr)
        return 2
    print("self-test: %d red probes flagged, 2 green probes clean" % red)
    return 0


def main(argv: list) -> int:
    try:
        known = serve_flags(SERVE_SRC.read_text(encoding="utf-8"))
        if argv[1:] == ["--self-test"]:
            return self_test(known)
        templates = sorted(ROOT.glob(TEMPLATE_GLOB))
        if len(templates) < 2:
            print("FAULT: expected at least 2 templates, found %d" % len(templates), file=sys.stderr)
            return 2
        hits = []
        for path in templates:
            hits.extend(scan_text(str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"), known))
    except (OSError, RuntimeError, UnicodeDecodeError) as exc:
        print("FAULT: %s" % exc, file=sys.stderr)
        return 2
    if hits:
        print("\n".join(hits), file=sys.stderr)
        print("FAIL: %d cloud-init serve defect(s)" % len(hits), file=sys.stderr)
        return 1
    print("PASS: %d templates checked, %d serve flags known" % (len(templates), len(known)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
