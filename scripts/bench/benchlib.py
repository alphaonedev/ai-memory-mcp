# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""benchlib -- shared measurement primitives for the #2921 capacity bench.

Stdlib only, deliberately. A capacity producer whose numbers depend on a
pip resolution is not reproducible on the host an operator actually has,
and `docs/enterprise-deployment.md` §11.1 exists because a number without
a runnable producer is not data.

Three things live here because both the single-node throughput producers
(`ops_producer.py`) and the mesh probe (`mesh_probe.py`) need them and
must compute them IDENTICALLY:

  * `HttpSession` -- a keep-alive HTTP client. This is load-bearing, not
    an optimisation. The prior op-mix instrument
    (`infra/pillar4-envelope/measure-envelope.sh`) forks one `curl` per
    operation; at a few hundred ops/s the fork+TCP-handshake cost is a
    large fraction of the measured wall time, so the number it produces
    is a floor on the instrument, not a ceiling on the substrate. Reusing
    one connection per worker removes the handshake; `--calibrate` (see
    `ops_producer.py`) bounds what is left.
  * `percentiles` -- the same nearest-rank reducer the prior harnesses
    use, so a number here is comparable to a number there.
  * `host_facts` -- CPU model / core count / RAM / storage, captured with
    every run. §11.1's rule is that a throughput figure without its host
    is not a figure.
"""

from __future__ import annotations

import http.client
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
import urllib.parse


class HttpSession:
    """One keep-alive HTTP/1.1 connection to one daemon.

    Not thread-safe by design: each load worker owns one session, which
    is what makes "offered concurrency = N" mean N real concurrent
    connections rather than N threads contending for one socket.

    Reconnects once on a dropped connection, then surfaces the error --
    a silent infinite retry would turn a daemon that stopped accepting
    into a throughput number that merely looks slow.
    """

    def __init__(self, base_url: str, api_key: str | None = None,
                 agent_id: str | None = None, timeout: float = 30.0):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme != "http":
            raise ValueError(
                f"HttpSession speaks plaintext http only (got {u.scheme!r}); "
                "the bench mesh runs on a private single-host bridge"
            )
        self.host = u.hostname
        self.port = u.port or 80
        self.api_key = api_key
        self.agent_id = agent_id
        self.timeout = timeout
        self._conn: http.client.HTTPConnection | None = None

    def _connect(self) -> http.client.HTTPConnection:
        if self._conn is None:
            self._conn = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"accept": "application/json"}
        if self.api_key:
            h["x-api-key"] = self.api_key
        if self.agent_id:
            h["x-agent-id"] = self.agent_id
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, path: str, body: dict | None = None,
                extra_headers: dict | None = None,
                raw: bytes | None = None) -> tuple[int, bytes, float]:
        """Return (status, body_bytes, elapsed_ms).

        `raw` posts pre-serialised bytes verbatim -- used for pre-signed
        attested bodies, whose signature covers fields that a re-encode
        through a dict could reorder or reformat. Never re-serialise a
        signed body.

        Status 0 means the request never produced an HTTP response (the
        connection failed twice). It is counted as an error, never folded
        into a latency percentile -- a failed request has no latency.
        """
        payload = None
        headers = self._headers(extra_headers)
        if raw is not None:
            payload = raw
            headers["content-type"] = "application/json"
        elif body is not None:
            payload = json.dumps(body).encode()
            headers["content-type"] = "application/json"
        for attempt in (0, 1):
            conn = self._connect()
            t0 = time.perf_counter()
            try:
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                return resp.status, data, (time.perf_counter() - t0) * 1000.0
            except (http.client.HTTPException, socket.error, OSError):
                self.close()
                if attempt == 1:
                    return 0, b"", (time.perf_counter() - t0) * 1000.0
        return 0, b"", 0.0  # unreachable; keeps type checkers honest


class BodyPool:
    """A pool of PRE-SIGNED, ready-to-POST request bodies.

    v1.0.0 refuses an unsigned `POST /api/v1/memories`
    (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`, fail-closed by compiled
    default) and its federation receive path refuses an unsigned
    third-party relayed write (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`,
    likewise fail-closed). Measuring the shipped posture therefore means
    every offered write must carry a valid Ed25519 attestation.

    Signing per request inside the load driver would make the
    measurement a benchmark of the DRIVER's signing loop. So bodies are
    signed AHEAD of the timed window by the in-tree
    `examples/attest_sign_batch` -- the same crate code the verifier runs
    -- and replayed here as raw bytes. What is then measured is the
    server-side cost: verification, storage, and (federated) relay. The
    client-side signing cost is deliberately excluded and is not part of
    any published figure.

    Consequences this class makes explicit rather than hiding:

      * Bodies are CONSUMED, never recycled. Each carries a unique
        `(title, namespace)`; replaying one would exercise the conflict
        path instead of an insert. When the pool runs dry the rung STOPS
        and reports `pool_exhausted`, so a short rung is visible as a
        short rung rather than as a lower throughput number.
      * Signatures commit to a `created_at` stamped at signing time and
        the server enforces a bounded freshness window, so a pool has a
        SHELF LIFE. `age_secs()` is recorded with every result.
    """

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.bodies = [ln for ln in fh.read().split(b"\n") if ln.strip()]
        self._i = 0
        self._lock = threading.Lock()
        self.created_at = time.time()
        self.exhausted = False

    def __len__(self) -> int:
        return len(self.bodies)

    def age_secs(self) -> float:
        return round(time.time() - self.created_at, 1)

    def take(self) -> bytes | None:
        with self._lock:
            if self._i >= len(self.bodies):
                self.exhausted = True
                return None
            b = self.bodies[self._i]
            self._i += 1
            return b

    def consumed(self) -> int:
        with self._lock:
            return self._i


def percentiles(samples: list[float], ps=(50, 95, 99)) -> dict:
    """Nearest-rank percentiles over a latency sample.

    Same index arithmetic as `measure-envelope.sh` /
    `measure-capacity-ramp.sh` so figures produced here are directly
    comparable to figures produced there.
    """
    if not samples:
        return {f"p{p}_ms": 0.0 for p in ps}
    s = sorted(samples)
    out = {}
    for p in ps:
        i = min(len(s) - 1, int(p / 100.0 * len(s)))
        out[f"p{p}_ms"] = round(s[i], 3)
    return out


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def host_facts() -> dict:
    """CPU / RAM / storage facts to publish alongside every number.

    Everything is read from `/proc` and `/sys` or from tools present on a
    stock Linux host. Fields that cannot be determined are reported as
    `null` rather than guessed -- an invented hardware fact is worse than
    an absent one for a document whose whole point is that unproduced
    numbers are not data.
    """
    cpuinfo = _read("/proc/cpuinfo")
    model = None
    m = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.M)
    if m:
        model = m.group(1).strip()
    cores = os.cpu_count()
    threads_per_core = None
    try:
        out = subprocess.run(["lscpu"], capture_output=True, text=True,
                             timeout=10)
        tm = re.search(r"^Thread\(s\) per core:\s*(\d+)", out.stdout, re.M)
        if tm:
            threads_per_core = int(tm.group(1))
    except (OSError, subprocess.SubprocessError):
        pass

    meminfo = _read("/proc/meminfo")
    mem_total_kb = None
    mm = re.search(r"^MemTotal:\s*(\d+) kB", meminfo, re.M)
    if mm:
        mem_total_kb = int(mm.group(1))

    storage = None
    try:
        out = subprocess.run(["df", "-h", "--output=source,fstype,size,avail",
                              os.getcwd()],
                             capture_output=True, text=True, timeout=10)
        rows = [r.split() for r in out.stdout.strip().splitlines()[1:]]
        if rows:
            src, fstype, size, avail = rows[0][:4]
            rotational = None
            base = re.sub(r"p?\d+$", "", os.path.basename(src))
            rot = _read(f"/sys/block/{base}/queue/rotational").strip()
            if rot in ("0", "1"):
                rotational = rot == "1"
            storage = {
                # Device NODE only (e.g. `nvme0n1p3`); never the mount
                # path, which on a developer host is a home directory.
                "device": os.path.basename(src),
                "fstype": fstype,
                "size": size,
                "avail": avail,
                "rotational": rotational,
            }
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    return {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os": _os_pretty_name(),
        "cpu_model": model,
        "cpu_logical_cores": cores,
        "threads_per_core": threads_per_core,
        "mem_total_kb": mem_total_kb,
        "mem_total_gib": (round(mem_total_kb / 1024 / 1024, 1)
                          if mem_total_kb else None),
        "storage": storage,
        "python": platform.python_version(),
    }


def _os_pretty_name() -> str | None:
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def utc_stamp() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
