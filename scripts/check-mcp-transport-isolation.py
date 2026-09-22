#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3829 — MCP transport-isolation gate.

Pins the CONDITION under which MCP-stdio is ruled OUT of the encryption/TLS
standard (SECURITY.md "MCP transport is stdio-only"): the MCP module
(``src/mcp/**``) serves ONLY over stdio. It binds NO server socket and
constructs NO network client for its own transport. That ruling is a claim
about the code; a claim with no gate decays silently — a future
``TcpListener::bind`` or a stray client dropped into an MCP tool would make MCP
a network-serving/​-connecting surface with nothing to notice, and the
"MCP is out of the encryption standard" line would quietly become false.

The ONE documented exception is the MCP→HTTP federation-forward bridge
``src/mcp/tools/store/transport.rs`` (#881/#318): an OUTBOUND client to the HTTP
daemon (whose TLS covers that hop) that lets MCP-stdio writes join the daemon's
federation fanout. It is a client, never a server, so it is allowlisted for the
network-CLIENT check and — like all of ``src/mcp/**`` — MUST still bind no
server socket.

Two checks over production Rust under ``src/mcp/``:

  1. SERVER SOCKET — no ``TcpListener``/``UnixListener`` bind, no ``axum::serve``
     / ``hyper::server``. MCP never listens on a network port; it owns stdin/
     stdout. (No allowlist: the correct count is zero.)
  2. NETWORK CLIENT — no ``reqwest``, ``TcpStream::connect`` or ``hyper``/
     ``hyper_util`` client construction, EXCEPT in the allowlisted forward
     bridge. Pins "MCP's own transport constructs no network client" while
     permitting the documented federation forward.

Production-vs-test heuristic mirrors ``scripts/check-vendor-literals.sh``: skip
``*test*.rs`` / ``tests.rs`` files, skip lines at/below the first ``mod tests {``
in a file, and skip comment lines (so the wiremock ``MockServer`` in a test mod
and every doc comment are out of scope). Bare ``.bind(`` is deliberately NOT a
pattern — rusqlite SQL parameter binds use it all over the MCP tools; only the
type-qualified socket constructors are matched.

Usage:
  scripts/check-mcp-transport-isolation.py            exit 0 clean, 1 on violation
  scripts/check-mcp-transport-isolation.py --self-test  plant a server socket and an
                                                      out-of-allowlist client, prove
                                                      the gate reds on each (rule m)
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = "src/mcp"

# The ONE allowlisted network-CLIENT file: the documented MCP→HTTP
# federation-forward bridge (#881/#318). A client to the HTTP daemon, never a
# server. Repo-root-relative.
CLIENT_ALLOWLIST = {
    "src/mcp/tools/store/transport.rs",
}

# Server-socket construction. Type-qualified only — NEVER bare `.bind(`, which
# is rusqlite SQL parameter binding throughout the MCP tools.
SERVER_SOCKET = re.compile(
    r"\b(?:TcpListener|UnixListener)\s*::\s*(?:bind|from_std)\b"
    r"|\baxum::serve\b"
    r"|\bhyper::server\b"
)

# Network-CLIENT construction. `reqwest::` covers the blocking + async clients;
# the connect / hyper-client forms cover a hand-rolled socket client.
NET_CLIENT = re.compile(
    r"\breqwest::"
    r"|\bTcpStream::connect\b"
    r"|\bhyper::client\b"
    r"|\bhyper_util::client\b"
)

REMEDY = (
    "MCP transport is stdio-only (SECURITY.md): move network I/O to the HTTP "
    "daemon under src/handlers/, or — for the store federation-forward only — "
    "keep it in the allowlisted src/mcp/tools/store/transport.rs. To add a new "
    "legitimate MCP→HTTP client file, add its repo-relative path to "
    "CLIENT_ALLOWLIST in scripts/check-mcp-transport-isolation.py and document "
    "the carve-out in SECURITY.md."
)


_MOD_DECL = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{?\s*$")


def _production_lines(text: str) -> list[tuple[int, str]]:
    """Return (1-based lineno, line) for production lines only.

    Drops everything at/below the first ``#[cfg(test)]``-attributed MODULE (of
    ANY name — MCP test mods are named ``tests`` but also
    ``coordination_forward_tests`` / ``credential_to_sink_3711_tests``, so
    matching only ``mod tests {`` would leak their test sockets), and single-
    line / doc / block-continuation comment lines. A bare ``#[cfg(test)]`` on a
    single item (fn/const), not a module, does NOT cut — that mirrors the
    check-vendor-literals rationale (cfg(test) guards top-of-file test helpers
    too, so only a test MODULE marks the test section).
    """
    lines = text.splitlines()
    cut = len(lines)
    for i, raw in enumerate(lines):
        if raw.lstrip().startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines):
                s = lines[j].lstrip()
                if s == "" or s.startswith("#["):
                    j += 1
                    continue
                if _MOD_DECL.match(s):
                    cut = i
                break
            if cut != len(lines):
                break
    out: list[tuple[int, str]] = []
    for i, raw in enumerate(lines[:cut], start=1):
        stripped = raw.lstrip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        out.append((i, raw))
    return out


def _is_test_file(rel: str) -> bool:
    name = Path(rel).name
    return "test" in name or name == "tests.rs"


def scan(root: Path) -> list[str]:
    violations: list[str] = []
    mcp = root / MCP_DIR
    if not mcp.is_dir():
        return [f"{MCP_DIR}/ not found under {root} — cannot verify MCP transport isolation"]
    for path in sorted(mcp.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if _is_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            violations.append(f"{rel}: unreadable ({exc})")
            continue
        for lineno, line in _production_lines(text):
            if SERVER_SOCKET.search(line):
                violations.append(
                    f"{rel}:{lineno}: MCP binds/serves a SOCKET — MCP serves stdio only.\n"
                    f"    {line.strip()}"
                )
            if NET_CLIENT.search(line) and rel not in CLIENT_ALLOWLIST:
                violations.append(
                    f"{rel}:{lineno}: MCP constructs a NETWORK CLIENT outside the allowlist.\n"
                    f"    {line.strip()}"
                )
    return violations


def report(violations: list[str]) -> int:
    if not violations:
        print(
            "MCP transport-isolation gate: PASS "
            "(src/mcp binds no socket; the only network client is the "
            "allowlisted federation-forward src/mcp/tools/store/transport.rs)"
        )
        return 0
    print("MCP transport-isolation gate: FAIL", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    print("", file=sys.stderr)
    print(REMEDY, file=sys.stderr)
    return 1


def main() -> int:
    return report(scan(ROOT))


# --------------------------------------------------------------------------
# --self-test (rule m): a gate that cannot fail gates nothing.
# --------------------------------------------------------------------------
def _run_in_copy(planted: dict[str, str]) -> list[str]:
    """Copy src/mcp into a scratch tree, apply `planted` edits, scan it."""
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs"), prefix="mcp-iso-selftest-") as td:
        sandbox = Path(td)
        import shutil

        dst_mcp = sandbox / MCP_DIR
        dst_mcp.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOT / MCP_DIR, dst_mcp)
        for rel_under_mcp, contents in planted.items():
            target = dst_mcp / rel_under_mcp
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")
        return scan(sandbox)


def self_test() -> int:
    (ROOT / ".local-runs").mkdir(exist_ok=True)
    legs: list[tuple[str, dict[str, str], str]] = [
        (
            "planted TcpListener::bind in an mcp file must RED",
            {"planted_socket.rs": "fn boom() {\n    let _l = TcpListener::bind(\"0.0.0.0:9077\").unwrap();\n}\n"},
            "binds/serves a SOCKET",
        ),
        (
            "planted axum::serve in an mcp file must RED",
            {"planted_serve.rs": "async fn boom() {\n    axum::serve(listener, app).await.unwrap();\n}\n"},
            "binds/serves a SOCKET",
        ),
        (
            "planted reqwest client OUTSIDE the allowlist must RED",
            {"planted_client.rs": "fn boom() {\n    let _c = reqwest::blocking::Client::new();\n}\n"},
            "NETWORK CLIENT outside the allowlist",
        ),
    ]
    failed = 0
    for label, planted, needle in legs:
        vio = _run_in_copy(planted)
        if any(needle in v for v in vio):
            print(f"  [ok] {label}")
        else:
            print(f"  [FAIL] {label} — gate did NOT catch it; violations={vio}", file=sys.stderr)
            failed += 1

    # Negative control: the allowlisted forward file may hold a reqwest client.
    ok_client = _run_in_copy(
        {"tools/store/transport.rs": "fn ok() {\n    let _c = reqwest::blocking::Client::new();\n}\n"}
    )
    if any("NETWORK CLIENT" in v for v in ok_client):
        print("  [FAIL] allowlisted transport.rs client must NOT red", file=sys.stderr)
        failed += 1
    else:
        print("  [ok] a reqwest client in the allowlisted transport.rs is permitted")

    # Negative control: a bare `.bind(` (SQL param) must NOT red.
    ok_sql = _run_in_copy(
        {"planted_sql.rs": "fn ok(stmt: &mut Statement) {\n    stmt.bind((1, \"x\")).unwrap();\n}\n"}
    )
    if ok_sql:
        print(f"  [FAIL] a bare .bind( (rusqlite SQL) must NOT red; got {ok_sql}", file=sys.stderr)
        failed += 1
    else:
        print("  [ok] a rusqlite .bind( SQL parameter is not a socket bind")

    if failed:
        print("MCP transport-isolation gate self-test: FAIL", file=sys.stderr)
        return 1
    print("MCP transport-isolation gate self-test: PASS (gate reds on each planted violation; near-misses pass)")
    return 0


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--self-test":
        raise SystemExit(self_test())
    if arg:
        print(f"usage: {sys.argv[0]} [--self-test]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
