#!/usr/bin/env python3
"""Campaign P: bounded, isolated HTTP overload measurements (#7028).

Never targets an existing listener. Every tier checks host/CI admission, creates
a private directory and SQLite database, and owns all server/stressor children.
TLS verifies the fresh daemon's own local CA. Unsigned fixture writes are an
explicit loopback-only test posture, not a production deployment recommendation.
Unknown bounds and missing observations are INCOMPLETE, never a passing cell.
Postgres uses the same HTTP workload; its independently minted store URL belongs
in the owner-only --db file. Its integrity adapter is reserved for the PG lane.
"""

from __future__ import annotations

import argparse
import atexit
from collections import Counter
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / ".local-runs" / "overload"
REPOSITORY = "alphaonedev/ai-memory-mcp"
TIERS = (50, 200, 1000)
OPERATIONS = ("store", "recall", "subscribe")
ROUTES = dict(zip(OPERATIONS, ("/api/v1/memories", "/api/v1/recall",
                             "/api/v1/subscriptions")))
AGENT = "ai:campaign-p-7028"
NAMESPACE = "campaign-p-7028"
LOAD_START = 8
LOAD_STOP = 24
TIER_CAP = 300
STARTUP_SECONDS = 60
REQUEST_SECONDS = 65
DEFAULT_DURATION = 30
MAX_DURATION = 150
METRIC = "ai_memory_admission_shed_total"
EXIT_OK, EXIT_FINDING, EXIT_ERROR, EXIT_HOLD = 0, 1, 2, 75
# Targets, not measured claims: PERFORMANCE.md:65,69. Subscribe has no target.
P99_MS = {"store": 50, "recall": 150, "subscribe": None}
BOUND_SOURCES = {
    "store_p99_ms": "PERFORMANCE.md:69 (no embedding)",
    "recall_p99_ms": "PERFORMANCE.md:65 (hot depth=1)",
    "subscribe_p99_ms": "not documented; observation only",
    "timeout_seconds": "src/config.rs:5768; src/lib.rs:1249-1261 (504)",
    "body_bytes": "src/lib.rs:87,1695 (2 MiB, 413)",
    "admission": "docs/ADMIN_GUIDE.md:364; src/lib.rs:1788-1835 (503 OVERLOADED)",
    "fd_limit": "/proc/<owned-server-pid>/limits: Max open files",
    "rss_limit": "no campaign RSS ceiling documented; observation only",
}
GIB = 1024**3
MIN_DISK_BYTES = 100 * GIB
MIN_MEMORY_BYTES = 40 * GIB
BODY_LIMIT = 2 * 1024**2
STRESS_BLOCK_BYTES = 1024**2
TERM_GRACE_SECONDS = 10
KILL_GRACE_SECONDS = 5
WEBHOOK_URL = "https://example.com/campaign-p-unused"


def host_admission() -> dict:
    """Fail closed on unreadable host state or truncated in-progress CI lists."""
    commands = [
        ["uptime"],
        ["gh", "run", "list", "--repo", REPOSITORY, "--status", "in_progress",
         "--limit", "20", "--json", "databaseId,name,workflowName"],
        ["df", "-h", "/", str(ROOT)], ["free", "-g"],
    ]
    evidence = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                check=False)
        evidence.append({"command": command, "rc": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            return {"admitted": False, "reason": "host command error", "evidence": evidence}
    runs = json.loads(evidence[1]["stdout"])
    busy = [r for r in runs if r["name"] == "CI" or
            "coverage" in r["workflowName"].casefold() or r["workflowName"] == "CI"]
    available = int(next(line.split()[1] for line in Path("/proc/meminfo")
                         .read_text().splitlines() if line.startswith("MemAvailable:"))) * 1024
    disks = [os.statvfs(p) for p in (Path("/"), ROOT)]
    free_bytes = [d.f_bavail * d.f_frsize for d in disks]
    load = os.getloadavg()[0]
    admitted = (load < LOAD_START and not busy and len(runs) < 20
                and available > MIN_MEMORY_BYTES and min(free_bytes) > MIN_DISK_BYTES)
    return {"admitted": admitted, "load1": load, "busy": busy, "evidence": evidence,
            "memory_available_bytes": available, "disk_free_bytes": free_bytes}


def quantile(histogram: Counter, percentile: int) -> int | None:
    """Nearest rank over 1-ms upper-bound buckets; an empty sample is unknown."""
    count = sum(histogram.values())
    if not count:
        return None
    rank = math.ceil(count * percentile / 100)
    for upper, frequency in sorted(histogram.items()):
        rank -= frequency
        if rank <= 0:
            return upper
    raise ValueError("invalid histogram")


def summarize(samples: dict) -> dict:
    return {kind: {"count": sum(row["status"].values()),
                   "status": dict(row["status"]),
                   "latency_ms_upper": {f"p{p}": quantile(row["histogram"], p)
                                        for p in (50, 95, 99)},
                   "histogram_ms_upper": dict(sorted(row["histogram"].items()))}
            for kind, row in samples.items()}


def evaluate(report: dict) -> dict:
    """Evaluate measured facts; no success from zero traffic or unknown ceilings."""
    faults = []
    traffic = report["operations"]
    for kind in OPERATIONS:
        row = traffic[kind]
        if not row["count"]:
            faults.append(f"{kind}: no observations")
        if row["status"].get("other", 0):
            faults.append(f"{kind}: unexpected response or transport error")
        p99, bound = row["latency_ms_upper"]["p99"], P99_MS[kind]
        if bound is not None and p99 is not None and p99 >= bound:
            # Merely observing one shed does not excuse a silently queued tail.
            if report["late_successes"].get(kind, 0) or not report["shed_delta"]:
                faults.append(f"{kind}: latency target exceeded without bounded refusal")
    integrity = report["integrity"]
    if not integrity.get("ok", False):
        faults.append("store integrity or acknowledgement reconciliation incomplete")
    if (report["probe_status"] != 200 or not report["shed_stable"]
            or report["probe_ms"] >= 60_000):
        faults.append("post-tier permit recovery not observed")
    peak_fd, fd_limit = report["fd_peak"], report["fd_limit"]
    if peak_fd is None or fd_limit is None or peak_fd >= fd_limit:
        faults.append("fd bound missing or exceeded")
    if report["rss_peak_kib"] is None:
        faults.append("RSS samples missing")
    if not report.get("cleanup_ok", False):
        faults.append("child cleanup not proven")
    gaps = ["subscribe p99 target", "RSS ceiling", "direct in-flight gauge"]
    return {"verdict": "FINDING" if faults else "INCOMPLETE", "faults": faults,
            "gaps": gaps, "all_bounds_hold": False,
            "cells": {"P2a": "FINDING" if any(k in f for f in faults for k in OPERATIONS)
                      else "INCOMPLETE: subscribe target absent",
                      "P2c": "PASS" if integrity.get("ok") else "FINDING",
                      "P2e": "INDIRECT PASS" if report["probe_status"] == 200
                      and report["shed_stable"] and report["probe_ms"] < 60_000 else "FINDING",
                      "P2g": "FINDING" if peak_fd is None or fd_limit is None
                      or peak_fd >= fd_limit or report["rss_peak_kib"] is None
                      else "INCOMPLETE: RSS ceiling absent"}}


def markdown(report: dict) -> str:
    lines = ["# Campaign P overload report", "", f"Backend: {report['backend']}",
             f"Clients: {report['clients']}; duration: {report['duration_seconds']} s", "",
             "| Bound | Source |", "|---|---|"]
    lines += [f"| {key} | {value} |" for key, value in BOUND_SOURCES.items()]
    lines += ["", "| Operation | Count | Status counts | p50/p95/p99 ms (upper) |",
              "|---|---:|---|---|"]
    for kind, row in report.get("operations", {}).items():
        lines.append(f"| {kind} | {row['count']} | {row['status']} | {row['latency_ms_upper']} |")
    lines += ["", "```json", json.dumps({k: v for k, v in report.items()
                                      if k != "operations"}, indent=2), "```", ""]
    return "\n".join(lines)


class Children:
    """Record and reap only owned child processes; cleanup is idempotent."""

    def __init__(self):
        self.children = []
        self.handles = []
        self.forced = []
        atexit.register(self.close)

    def start(self, command: list[str], log: Path, env: dict) -> subprocess.Popen:
        handle = log.open("wb")
        self.handles.append(handle)
        child = subprocess.Popen(["nice", "-n", "19", "ionice", "-c", "3", *command],
                                 stdout=handle, stderr=subprocess.STDOUT, env=env,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        self.children.append(child)
        return child

    def stop_group(self, children: list[subprocess.Popen]) -> None:
        # Both waits have one shared deadline, independent of worker count.
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + TERM_GRACE_SECONDS
        survivors = []
        for child in children:
            try:
                child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                survivors.append(child)
                self.forced.append(child.pid)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        for child in survivors:
            child.wait(timeout=max(0, deadline - time.monotonic()))

    def close(self) -> None:
        self.stop_group(self.children)
        for handle in self.handles:
            handle.close()

    def proof(self) -> dict:
        pids = [child.pid for child in self.children]
        command = ["ps", "-o", "pid=,ppid=,stat=,comm=", "-p", ",".join(map(str, pids))]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return {"command": command, "rc": result.returncode, "stdout": result.stdout,
                "owned_pids": pids, "forced_kills": self.forced,
                "ok": result.returncode == 1 and not result.stdout.strip()}


def isolated_environment(directory: Path, backend: str, db: Path) -> dict:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AI_MEMORY_", "FED_", "PG"))}
    home = directory / "home"
    home.mkdir(mode=0o700)
    keys = directory / "keys"
    keys.mkdir(mode=0o700)
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               TMPDIR=str(directory), AI_MEMORY_NO_CONFIG="1", AI_MEMORY_KEY_DIR=str(keys),
               AI_MEMORY_REQUIRE_AGENT_ATTESTATION="0", AI_MEMORY_AGENT_ID=AGENT)
    if backend == "postgres":
        env["AI_MEMORY_STORE_URL_FILE"] = str(db)
    return env


class Http:
    def __init__(self, port: int, ca: Path):
        self.port = port
        self.context = ssl.create_default_context(cafile=str(ca))

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection("127.0.0.1", self.port,
                                                 context=self.context, timeout=REQUEST_SECONDS)
        try:
            payload = None if body is None else json.dumps(body).encode()
            connection.request(method, path, body=payload,
                               headers={"Content-Type": "application/json", "X-Agent-Id": AGENT})
            response = connection.getresponse()
            data = response.read(BODY_LIMIT + 1)
            if len(data) > BODY_LIMIT:
                raise ValueError("response exceeded body bound")
            return response.status, data
        finally:
            connection.close()

    def shed(self) -> int:
        status, data = self.call("GET", "/metrics")
        if status != 200:
            raise ValueError("metrics scrape refused")
        rows = [line.split()[1] for line in data.decode().splitlines()
                if line.startswith(METRIC + " ")]
        if len(rows) != 1:
            raise ValueError("shed metric missing or duplicated")
        return int(float(rows[0]))


def wait_server(child: subprocess.Popen, port: int, ca: Path) -> Http:
    deadline = time.monotonic() + STARTUP_SECONDS
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("private daemon exited during startup; see private server log")
        try:
            client = Http(port, ca)
            if client.call("GET", "/api/v1/health")[0] == 200:
                return client
        except (OSError, ssl.SSLError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise TimeoutError("private daemon readiness deadline")


def process_sample(pid: int) -> dict:
    proc = Path("/proc") / str(pid)
    status = proc.joinpath("status").read_text().splitlines()
    rss = int(next(line.split()[1] for line in status if line.startswith("VmRSS:")))
    fd = sum(1 for _ in proc.joinpath("fd").iterdir())
    limit = next(line.split()[3] for line in proc.joinpath("limits").read_text().splitlines()
                 if line.startswith("Max open files"))
    return {"at": time.monotonic(), "rss_kib": rss, "fd": fd,
            "fd_limit": int(limit) if limit != "unlimited" else None}


def stress(kind: str, directory: Path, seconds: float) -> int:
    """Bounded workers, launched behind nice and idle-I/O scheduling."""
    deadline = time.monotonic() + seconds
    if kind == "cpu":
        block = bytes(STRESS_BLOCK_BYTES)
        while time.monotonic() < deadline:
            hashlib.sha256(block).digest()
    else:
        with (directory / "fsync-stressor.bin").open("xb") as stream:
            block = bytes(STRESS_BLOCK_BYTES)
            while time.monotonic() < deadline:
                stream.seek(0)
                stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
    return EXIT_OK


def reconcile(db: Path, acknowledgements: Path, namespace: str) -> dict:
    """Read-only SQLite verification after server shutdown; never migrations."""
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        seen = set()
        mismatches = 0
        with acknowledgements.open() as stream:
            for line in stream:
                ack = json.loads(line)
                row = connection.execute(
                    "SELECT title, content FROM memories WHERE id=? AND namespace=?",
                    (ack["id"], namespace)).fetchone()
                if (ack["id"] in seen or row is None or row[0] != ack["title"]
                        or hashlib.sha256(row[1].encode()).hexdigest() != ack["sha256"]):
                    mismatches += 1
                seen.add(ack["id"])
        count = connection.execute("SELECT count(*) FROM memories WHERE namespace=?",
                                   (namespace,)).fetchone()[0]
    return {"ok": integrity == [("ok",)] and not foreign_keys and not mismatches
            and count == len(seen) and bool(seen), "integrity_check": integrity,
            "foreign_key_violations": len(foreign_keys), "acknowledged": len(seen),
            "row_count": count, "payload_mismatches": mismatches}


def workload(client: Http, clients: int, duration: int, mix: tuple[int, ...],
             directory: Path, pid: int, namespace: str) -> dict:
    samples = {kind: {"histogram": Counter(), "status": Counter()} for kind in OPERATIONS}
    late = Counter()
    lock = threading.Lock()
    start = threading.Event()
    stop = threading.Event()
    deadline = [0.0]
    secret = secrets.token_hex(32)
    resources = []
    thread_errors = []
    acknowledgements = (directory / "acknowledged.jsonl").open("x")

    def worker(index: int) -> None:
        start.wait()
        sequence = 0
        try:
            while time.monotonic() < deadline[0] and not stop.is_set():
                slot = (index + sequence) % sum(mix)
                kind = OPERATIONS[0 if slot < mix[0] else 1 if slot < sum(mix[:2]) else 2]
                title = f"p7028-{index}-{sequence}"
                body = {"store": {"namespace": namespace, "title": title,
                                   "content": f"campaign record {title}", "tier": "long"},
                        "recall": {"context": "campaign record", "namespace": namespace,
                                   "limit": 5},
                        "subscribe": {"url": WEBHOOK_URL, "events": "memory.deleted",
                                      "namespace_filter": namespace, "secret": secret}}[kind]
                begun = time.monotonic()
                status, data = 0, b""
                try:
                    status, data = client.call("POST", ROUTES[kind], body)
                    parsed = json.loads(data)
                    category = str(status)
                    if status == 503 and parsed.get("code") != "OVERLOADED":
                        category = "other"
                    elif status not in (200, 201, 503, 504):
                        category = "other"
                    elif status == 201 and kind not in ("store", "subscribe"):
                        category = "other"
                except (OSError, ValueError, http.client.HTTPException):
                    category, parsed = "other", {}
                milliseconds = math.ceil((time.monotonic() - begun) * 1000)
                with lock:
                    samples[kind]["histogram"][milliseconds] += 1
                    samples[kind]["status"][category] += 1
                    if status in (200, 201) and P99_MS[kind] is not None:
                        if milliseconds >= P99_MS[kind]:
                            late[kind] += 1
                    if kind == "store" and status in (200, 201):
                        if not isinstance(parsed.get("id"), str):
                            thread_errors.append("store receipt lacks id")
                        else:
                            digest = hashlib.sha256(body["content"].encode()).hexdigest()
                            acknowledgements.write(json.dumps({
                                "id": parsed["id"], "title": title, "sha256": digest}) + "\n")
                sequence += 1
        except Exception as error:  # Stop peers; retain class, never secret-bearing text.
            with lock:
                thread_errors.append(type(error).__name__)
            stop.set()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(clients)]
    try:
        for thread in threads:
            thread.start()
        deadline[0] = time.monotonic() + duration
        start.set()
        while time.monotonic() < deadline[0] and not stop.is_set():
            resources.append(process_sample(pid))
            time.sleep(min(1, max(0, deadline[0] - time.monotonic())))
    finally:
        stop.set()
        start.set()
        join_deadline = time.monotonic() + REQUEST_SECONDS + 1
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=max(0, join_deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            raise TimeoutError("client cleanup deadline")
        acknowledgements.close()
    if thread_errors:
        raise RuntimeError("client worker errors: " + ",".join(sorted(set(thread_errors))))
    if not resources:
        raise RuntimeError("no resource samples")
    return {"operations": summarize(samples), "late_successes": dict(late),
            "rss_peak_kib": max(r["rss_kib"] for r in resources),
            "fd_peak": max(r["fd"] for r in resources), "fd_limit": resources[0]["fd_limit"],
            "resource_samples": resources}


def run_tier(args: argparse.Namespace, directory: Path, admission: dict) -> dict:
    report = {"backend": args.backend, "clients": args.clients,
              "duration_seconds": args.duration, "admission": admission,
              "bounds": BOUND_SOURCES, "cap_override": args.max_inflight}
    children = Children()
    db = (args.db or directory / "campaign.db").resolve()
    if args.backend == "sqlite" and (db.exists() or not db.is_relative_to(directory)):
        raise ValueError("SQLite database must be fresh and inside this tier directory")
    env = isolated_environment(directory, args.backend, db)
    if args.max_inflight is not None:
        env["AI_MEMORY_MAX_INFLIGHT_REQUESTS"] = str(args.max_inflight)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [str(args.binary)]
    if args.backend == "sqlite":
        command += ["--db", str(db)]
    command += ["serve", "--host", "127.0.0.1", "--port", str(port)]
    try:
        server = children.start(command, directory / "server.log", env)
        client = wait_server(server, port, directory / "keys/tls/local-ca.pem")
        report["version"] = subprocess.run([str(args.binary), "--version"], env=env,
            capture_output=True, text=True, check=True, timeout=10).stdout.strip()
        with args.binary.open("rb") as binary:
            report["binary_sha256"] = hashlib.file_digest(binary, "sha256").hexdigest()
        before = client.shed()
        cpu_workers = max(0, len(os.sched_getaffinity(0)) - 1)
        stressors = []
        for index in range(cpu_workers + 1):
            kind = "cpu" if index < cpu_workers else "io"
            stressors.append(children.start([sys.executable, str(Path(__file__).resolve()), "--stressor", kind,
                            "--scratch", str(directory), "--duration", str(TIER_CAP)],
                           directory / f"stressor-{index}.log", env))
        namespace = NAMESPACE + "/" + directory.name
        report.update(workload(client, args.clients, args.duration, args.mix,
                               directory, server.pid, namespace))
        children.stop_group(stressors)
        after = client.shed()
        probe_start = time.monotonic()
        report["probe_status"] = client.call("POST", ROUTES["recall"],
            {"context": "campaign", "namespace": namespace, "limit": 1})[0]
        report["probe_ms"] = (time.monotonic() - probe_start) * 1000
        time.sleep(1)
        report["shed_stable"] = client.shed() == after
        report["shed_before"], report["shed_after"] = before, after
        report["shed_delta"] = after - before
        children.close()
        report["server_exit"] = server.returncode
        report["integrity"] = (reconcile(db, directory / "acknowledged.jsonl", namespace)
                               if args.backend == "sqlite" else
                               {"ok": False, "reason": "PG integrity adapter not executed"})
    finally:
        children.close()
        report["cleanup"] = children.proof()
        report["cleanup_ok"] = report["cleanup"]["ok"] and not children.forced
        (directory / "partial.json").write_text(json.dumps(report, indent=2) + "\n")
    report["evaluation"] = evaluate(report)
    return report


def parse_mix(value: str) -> tuple[int, ...]:
    parts = tuple(map(int, value.split("/")))
    if len(parts) != len(OPERATIONS) or any(n <= 0 for n in parts) or sum(parts) != 100:
        raise argparse.ArgumentTypeError("mix must be three positive percentages totaling 100")
    return parts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="own release binary (required for a tier)")
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--db", type=Path, help="fresh SQLite file or owner-only PG URL file")
    parser.add_argument("--clients", type=int, choices=TIERS, default=TIERS[0])
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--mix", type=parse_mix, default=parse_mix("60/30/10"))
    parser.add_argument("--max-inflight", type=int,
                        help="explicit cap; omitted uses daemon default")
    parser.add_argument("--stressor", choices=("cpu", "io"), help=argparse.SUPPRESS)
    parser.add_argument("--scratch", type=Path, default=SCRATCH, help=argparse.SUPPRESS)
    parser.add_argument("--admission-only", action="store_true")
    args = parser.parse_args()
    max_duration = TIER_CAP if args.stressor else MAX_DURATION
    if not 1 <= args.duration <= max_duration:
        parser.error(f"duration must be 1..{max_duration} seconds within the {TIER_CAP}s tier cap")
    if args.stressor:
        if not args.scratch.resolve().is_relative_to(SCRATCH.resolve()):
            parser.error("stressor scratch must be project-local")
        return stress(args.stressor, args.scratch, args.duration)
    SCRATCH.mkdir(parents=True, exist_ok=True, mode=0o700)
    admission = host_admission()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)
    directory = SCRATCH / stamp
    directory.mkdir(mode=0o700)
    (directory / "admission.json").write_text(json.dumps(admission, indent=2) + "\n")
    if args.admission_only or not admission["admitted"]:
        print(json.dumps({"admitted": admission["admitted"], "evidence": str(directory)}))
        return EXIT_OK if admission["admitted"] else EXIT_HOLD
    if args.binary is None or not args.binary.resolve().is_file():
        parser.error("--binary must name the lane's built release binary")
    args.binary = args.binary.resolve()
    if args.backend == "postgres" and args.db is None:
        parser.error("postgres requires a minted --db URL file")
    if args.max_inflight is not None and args.max_inflight <= 0:
        parser.error("max-inflight must be positive")
    old_umask = os.umask(0o077)

    def interrupted(signum, _frame):
        raise RuntimeError(f"tier interrupted by signal {signum}")

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(TIER_CAP - 20)  # Reserve cleanup time within the hard tier ceiling.
    try:
        report = run_tier(args, directory, admission)
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (directory / "report.md").write_text(markdown(report))
        print(json.dumps({"report": str(directory / "report.json"),
                          "evaluation": report["evaluation"]}))
        return EXIT_OK if report["evaluation"]["all_bounds_hold"] else EXIT_FINDING
    except Exception as error:
        # Do not print responses, keys or DSNs from exception strings.
        (directory / "error.json").write_text(json.dumps({"error_class": type(error).__name__}))
        print(f"campaign error class={type(error).__name__}; evidence={directory}")
        return EXIT_ERROR
    finally:
        signal.alarm(0)
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
