#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed oracles for the five #3543 harness predicates.

Each function is the NEW (fail-closed) oracle. The matching ``legacy_*``
function is the pre-#3543 false-green oracle, kept only so a committed
negative fixture can prove: old predicate PASSes the defect, new predicate
FAILs it. Production producers call the new functions only.

Exit 0 from ``--self-test`` means every fixture in
``scripts/evidence/fixtures/neg-*.json`` is red under the legacy oracle
and green-as-FAIL under the new one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"

# curl(1) exit codes that prove the TLS layer never produced an HTTP status.
CURL_SSL_CONNECT_ERROR = 35
CURL_GOT_NOTHING = 52
CURL_RECV_ERROR = 56
PLAINTEXT_TLS_EXITS = frozenset(
    {CURL_SSL_CONNECT_ERROR, CURL_GOT_NOTHING, CURL_RECV_ERROR}
)

HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
ANON_REFUSED_STATUSES = frozenset({HTTP_UNAUTHORIZED, HTTP_FORBIDDEN})

STATUS_PENDING = "pending"
ATTEST_AGENT_ATTESTED = "agent_attested"


def payload_digest(title: str, content: str, namespace: str) -> str:
    """SHA-256 of the durable claim fields, NUL-separated (not JSON pretty-print)."""
    h = hashlib.sha256()
    h.update(title.encode("utf-8"))
    h.update(b"\x00")
    h.update(content.encode("utf-8"))
    h.update(b"\x00")
    h.update(namespace.encode("utf-8"))
    return h.hexdigest()


# --- 1. Big-10 plaintext listener ------------------------------------------

def plaintext_no_listener(*, curl_exit: int, http_status: int | None = None, **_kwargs: Any) -> bool:
    """PASS only on a TLS-layer refusal. A plaintext HTTP 401 is still a listener."""
    del http_status  # status is untrusted once curl produced an HTTP response
    return int(curl_exit) in PLAINTEXT_TLS_EXITS


def legacy_plaintext_no_listener(*, curl_exit: int, http_status: int | None = None) -> bool:
    """False-green: any status other than 200 counted as 'no listener'."""
    del curl_exit
    return http_status != 200


# --- 2. Big-10 anonymous write ---------------------------------------------

def anonymous_write_refused(*, status: int, error_code: str, delta: int, **_kwargs: Any) -> bool:
    """PASS only on 401/403 + a documented error code + zero memories delta."""
    return (
        int(status) in ANON_REFUSED_STATUSES
        and bool(str(error_code).strip())
        and int(delta) == 0
    )


def legacy_anonymous_write_refused(*, status: int, error_code: str = "", delta: int = 0) -> bool:
    """False-green: any status other than 201 counted as refused (500/202 pass)."""
    del error_code, delta
    return int(status) != 201


# --- 3. Continuity retained ------------------------------------------------

def continuity_retained(
    *,
    ready: bool,
    stored_digest: str,
    stored_version: Any,
    expected_digest: str,
    expected_version: Any,
    **_kwargs: Any,
) -> bool:
    """PASS only when recall-readiness held AND digest+version match the seed."""
    if not ready:
        return False
    if not stored_digest or not expected_digest:
        return False
    if stored_digest != expected_digest:
        return False
    if stored_version is None or expected_version is None:
        return False
    return stored_version == expected_version


def legacy_continuity_retained(*, get_status: int, **_kwargs: Any) -> bool:
    """False-green: GET-by-id HTTP 200 counted as retained, ignoring bytes/version."""
    return int(get_status) == 200


# --- 4. Attestation stored level -------------------------------------------

def attest_level_matches(*, stored: str, expected: str = ATTEST_AGENT_ATTESTED, **_kwargs: Any) -> bool:
    """PASS only when the stored row carries the expected attest_level."""
    return str(stored) == expected


def legacy_attest_level_matches(*, http_status: int, stored: str = "", **_kwargs: Any) -> bool:
    """False-green: 201 accept was 'the primary proof'; stored level was INFO."""
    del stored
    return int(http_status) == 201


# --- 5. Swarm coverage -----------------------------------------------------

def result_is_pending(result: Any) -> bool:
    if isinstance(result, dict):
        return str(result.get("status") or "").lower() == STATUS_PENDING
    return False


def result_memory_id(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    for key in ("id", "memory_id"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def swarm_covered(
    *,
    ok: bool = False,
    pending: bool = False,
    memory_id: str | None = None,
    expected_refusal: bool = False,
    result: Any = None,
    **_kwargs: Any,
) -> bool:
    """PASS only on a persisted memory_id or a documented EXPECTED_REFUSAL.

    A 200 ``{"status":"pending"}`` is never coverage. ``ok`` (handler returned
    without exception) is not enough on its own.
    """
    pending = bool(pending) or result_is_pending(result)
    if pending:
        return False
    if expected_refusal:
        return True
    mid = memory_id or result_memory_id(result)
    if mid:
        return True
    # Non-write / non-row payloads (health, list, 204 forget): ok and not pending.
    if ok and result_memory_id(result) is None and not result_is_pending(result):
        if isinstance(result, dict) and ("id" in result or "memory_id" in result):
            return False  # claimed a row id but it was empty
        return True
    return False


def legacy_swarm_covered(*, handler_returned: bool, **_kwargs: Any) -> bool:
    """False-green: handler returned without exception, including pending 200."""
    return bool(handler_returned)


PREDICATES: dict[str, tuple[Any, Any]] = {
    "plaintext_no_listener": (plaintext_no_listener, legacy_plaintext_no_listener),
    "anonymous_write_refused": (anonymous_write_refused, legacy_anonymous_write_refused),
    "continuity_retained": (continuity_retained, legacy_continuity_retained),
    "attest_level_matches": (attest_level_matches, legacy_attest_level_matches),
    "swarm_covered": (swarm_covered, legacy_swarm_covered),
}


def _load_fixtures() -> list[dict[str, Any]]:
    rows = []
    for path in sorted(FIXTURES.glob("neg-pred-*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["_path"] = str(path)
        rows.append(doc)
    return rows


def run_self_test() -> int:
    rows = _load_fixtures()
    if len(rows) < 5:
        print(
            f"FATAL: expected >=5 neg-pred-*.json fixtures, found {len(rows)}",
            file=sys.stderr,
        )
        return 2
    failed = 0
    for doc in rows:
        name = doc.get("predicate")
        args = doc.get("args") or {}
        pair = PREDICATES.get(name)
        if pair is None:
            print(f"FATAL: unknown predicate {name!r} in {doc['_path']}", file=sys.stderr)
            failed += 1
            continue
        new_fn, old_fn = pair
        old = bool(old_fn(**args))
        new = bool(new_fn(**args))
        want_old = bool(doc.get("old_pass"))
        want_new = bool(doc.get("new_pass"))
        if old != want_old or new != want_new:
            print(
                f"FAIL: {doc['_path']} predicate={name} "
                f"legacy={old} (want {want_old}) new={new} (want {want_new})",
                file=sys.stderr,
            )
            failed += 1
            continue
        if want_old and not want_new:
            print(f"PASS: {Path(doc['_path']).name} red-under-legacy green-as-FAIL-under-new")
        else:
            print(f"PASS: {Path(doc['_path']).name} legacy={old} new={new}")
    if failed:
        print(f"FATAL: {failed} predicate fixture(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(rows)} negative predicate fixtures")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
