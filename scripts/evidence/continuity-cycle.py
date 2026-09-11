#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""continuity-cycle.py — clock-1 continuity producer (#3547 / #3543).

Repo-relative: REPO is the git root containing this file, never a
hard-coded operator path. Readiness is a recall probe that returns a
seeded row, not the boot-time `embedder_ready` constant. Retention
compares payload digest + version (not GET-by-id HTTP 200). The
published clock is `clock_1_harness_restart_to_health_ok_ms` (health
200), never a sleep-inflated `resume_ms`.

The JSON record carries run_id + daemon_binary_sha256 + source_commit
so a dashboard stamp cannot outlive its source (#3547 binding).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

# Predicates live beside this file so the producer and --self-test share one SSOT.
sys.path.insert(0, str(HERE))
from predicates import continuity_retained, payload_digest  # noqa: E402


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO), *args], text=True).strip()


def sha256_of_pid(pid: int) -> str:
    script = HERE / "lib.sh"
    out = subprocess.check_output(
        ["bash", "-c", f"source {script} && evidence_sha256_of_pid {pid}"],
        text=True,
    ).strip()
    if len(out) != 64:
        raise SystemExit(f"could not hash pid {pid}: {out!r}")
    return out


def sha256_of_file(path: Path) -> str:
    out = subprocess.check_output(["shasum", "-a", "256", str(path)], text=True)
    return out.split()[0]


def http_json(url: str, method: str = "GET", body: bytes | None = None, timeout: float = 5.0):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode()) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload = json.loads(raw.decode()) if raw else {}
        except json.JSONDecodeError:
            payload = {"body": raw.decode("utf-8", "replace")}
        return e.code, payload


def wait_health(base: str, timeout_s: float) -> float:
    """Return milliseconds until GET /health returns 200. Fail closed on timeout."""
    deadline = time.monotonic() + timeout_s
    t0 = time.monotonic()
    while time.monotonic() < deadline:
        try:
            status, _ = http_json(f"{base}/health", timeout=1.0)
            if status == 200:
                return (time.monotonic() - t0) * 1000.0
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise SystemExit(f"health did not return 200 within {timeout_s}s")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", required=True, help="daemon origin, e.g. http://127.0.0.1:9077/api/v1")
    p.add_argument("--pid", type=int, help="live daemon pid (preferred binding)")
    p.add_argument("--binary", type=Path, help="daemon executable to hash when --pid is omitted")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed-title", default="continuity-seed")
    args = p.parse_args()

    if args.pid is None and args.binary is None:
        print("FATAL: --pid or --binary required (hash is computed, never typed)", file=sys.stderr)
        return 2

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    health_ok_ms = wait_health(args.base_url.rstrip("/"), timeout_s=30.0)

    seed_title = args.seed_title
    seed_content = "continuity-cycle seeded row for recall-readiness"
    seed_ns = "evidence/continuity"
    expected_digest = payload_digest(seed_title, seed_content, seed_ns)
    seed_body = json.dumps(
        {
            "title": seed_title,
            "content": seed_content,
            "namespace": seed_ns,
            "tier": "mid",
        }
    ).encode()
    status, created = http_json(
        f"{args.base_url.rstrip('/')}/memories", method="POST", body=seed_body
    )
    if status not in (200, 201) or "id" not in created:
        print(f"FATAL: seed write failed status={status} body={created}", file=sys.stderr)
        return 1
    seed_id = created["id"]
    expected_version = created.get("version")
    if expected_version is None:
        print("FATAL: seed write returned no version", file=sys.stderr)
        return 1

    # Readiness = recall returns the seeded row. Not embedder_ready.
    rec_status, rec = http_json(
        f"{args.base_url.rstrip('/')}/recall?q={args.seed_title}&limit=5"
    )
    hits = rec.get("memories") or rec.get("results") or rec.get("hits") or []
    ids = [h.get("id") for h in hits if isinstance(h, dict)]
    ready = rec_status == 200 and seed_id in ids
    if not ready:
        print(
            f"FATAL: recall readiness failed status={rec_status} seed={seed_id} ids={ids}",
            file=sys.stderr,
        )
        return 1

    # Retention oracle: payload digest + version, never GET-by-id 200.
    get_status, got = http_json(f"{args.base_url.rstrip('/')}/memories/{seed_id}")
    row = got.get("memory") if isinstance(got.get("memory"), dict) else got
    stored_digest = payload_digest(
        str(row.get("title") or ""),
        str(row.get("content") or ""),
        str(row.get("namespace") or ""),
    )
    stored_version = row.get("version")
    retained = continuity_retained(
        ready=ready,
        stored_digest=stored_digest,
        stored_version=stored_version,
        expected_digest=expected_digest,
        expected_version=expected_version,
        get_status=get_status,
    )
    if not retained:
        print(
            f"FATAL: retention failed ready={ready} get_status={get_status} "
            f"digest_match={stored_digest == expected_digest} "
            f"version stored={stored_version} expected={expected_version}",
            file=sys.stderr,
        )
        return 1

    addressed = sha256_of_pid(args.pid) if args.pid is not None else sha256_of_file(args.binary)
    run_id = os.environ.get("EVIDENCE_RUN_ID") or git("rev-parse", "HEAD")[:8] + "-" + str(int(time.time()))
    record = {
        "artifact_kind": "daemon",
        "producer_id": "continuity-cycle",
        "run_id": run_id,
        "supersedes_run_id": None,
        "started_at_utc": started,
        "finished_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_commit": git("rev-parse", "HEAD"),
        "source_tree_sha": git("rev-parse", "HEAD^{tree}"),
        "daemon_binary_sha256": addressed,
        "addressed_exe_sha256": addressed,
        "verdict": "PASS",
        "oracle_kind": "independent",
        "capacity": {"p99_method": "not-applicable"},
        "clock_1_harness_restart_to_health_ok_ms": round(health_ok_ms, 3),
        "readiness": "recall_seeded_row",
        "retained": True,
        "seed_id": seed_id,
        "payload_digest": expected_digest,
        "version": expected_version,
        "repo": str(REPO),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[continuity-cycle] wrote {args.out} clock_1={health_ok_ms:.1f}ms run_id={run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
