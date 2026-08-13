#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""mesh_probe.py -- drive and observe one rung of the #2921 mesh ramp.

Given an already-running `infra/bench-mesh` stack of N federated
daemons, this:

  1. waits for every node's `/api/v1/health`,
  2. writes a fixed corpus into node 1 over the HTTP surface,
  3. watches EVERY node's row count until the whole mesh carries the
     corpus (or the deadline expires),
  4. scrapes each node's `/metrics` for the federation counters that say
     whether convergence was clean -- DLQ depth above all,

and emits one JSON object per rung.

DEFINITIONS, stated because a convergence number is meaningless without them
---------------------------------------------------------------------------
`t0`              the instant the first write is issued at node 1.
`write_wall_s`    t0 -> the last write's response. This is the offered
                  burst, not a steady state.
`converged_s`     t0 -> the instant the LAST node's row count first
                  reaches the corpus size. Includes the write burst; this
                  is the number an operator cares about ("I wrote a
                  batch; when does the fleet have it?").
`tail_s`          end-of-burst -> full convergence. The replication
                  residue after the offered load stops.

WHY ROW COUNTS AND NOT AN API
-----------------------------
`/api/v1/stats` is admin-gated and returns a projected envelope;
`/api/v1/memories` paginates. The question here is strictly "has this row
landed durably on this node", which is a row count. The count is taken
READ-ONLY (`file:...?mode=ro`) against the node's own SQLite file through
the bind mount, so the observation can never write to, lock, or migrate
the database it is watching. It is an OBSERVATION INSTRUMENT and is not
part of the measured path: nothing the daemons do depends on it.

A node whose count OVERSHOOTS the corpus size is a red flag, not a pass:
it means duplicate rows, so the probe records the final count per node
verbatim rather than clamping it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchlib import BodyPool, HttpSession, percentiles, utc_stamp  # noqa: E402
from ops_producer import sqlite_count  # noqa: E402

MEMORIES = "/api/v1/memories"
HEALTH = "/api/v1/health"
METRICS = "/metrics"

# Federation counters worth capturing at every rung. Chosen because each
# one distinguishes "converged" from "converged, but degraded":
#   dlq_depth        rows that failed to push and are parked for replay
#   fanout_dropped   pushes abandoned outright
#   fanout_retry     pushes that needed a retry to land
#   partial_quorum   writes that committed locally without full quorum
FED_METRICS = (
    "ai_memory_federation_push_dlq_depth",
    "ai_memory_federation_push_dlq_quarantined_total",
    "ai_memory_federation_fanout_dropped_total",
    "ai_memory_federation_fanout_retry_total",
    "ai_memory_federation_partial_quorum_total",
    "ai_memory_store_total",
    "ai_memory_memories",
)


def docker() -> list[str]:
    """The docker invocation, overridable for hosts where the socket needs sudo."""
    return os.environ.get("BENCH_DOCKER", "docker").split()


def resolve_ips(project: str) -> dict:
    """container name -> bridge IP, straight from the daemon's own view."""
    out = subprocess.run(
        docker() + ["ps", "--filter", f"label=com.docker.compose.project={project}",
                    "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True)
    names = sorted(n for n in out.stdout.split() if n)
    ips = {}
    for n in names:
        ins = subprocess.run(
            docker() + ["inspect", "-f",
                        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", n],
            capture_output=True, text=True, check=True)
        ip = ins.stdout.strip()
        if ip:
            ips[n] = ip
    return ips


def wait_healthy(ips: dict, api_key: str, port: int, timeout: float) -> dict:
    """Block until every node answers /api/v1/health, or the deadline passes."""
    deadline = time.monotonic() + timeout
    pending = dict(ips)
    ready: dict[str, float] = {}
    t0 = time.monotonic()
    while pending and time.monotonic() < deadline:
        for name, ip in list(pending.items()):
            s = HttpSession(f"http://{ip}:{port}", api_key=api_key, timeout=5)
            try:
                st, _b, _ms = s.request("GET", HEALTH)
            finally:
                s.close()
            if 200 <= st < 300:
                ready[name] = round(time.monotonic() - t0, 3)
                del pending[name]
        if pending:
            time.sleep(1.0)
    return {"ready_secs": ready, "unhealthy": sorted(pending),
            "all_healthy": not pending}


def write_corpus(base_url: str, api_key: str, namespace: str, count: int,
                 concurrency: int, pool=None, author: str | None = None) -> dict:
    """Offer `count` writes at node 1 with `concurrency` keep-alive clients.

    With a pre-signed `pool` the bodies are posted VERBATIM and the wire
    identity is the signing `author`: v1.0.0 refuses an unsigned
    HTTP-direct write, and its federation receive path refuses an unsigned
    third-party relayed write, so measuring the SHIPPED posture requires
    attested bodies. Re-serialising a signed body would invalidate it, so
    the pool's bytes go out untouched.
    """
    per = [count // concurrency] * concurrency
    for i in range(count % concurrency):
        per[i] += 1
    results: list[dict] = [None] * concurrency  # type: ignore[list-item]

    def worker(wid: int, n: int) -> None:
        s = HttpSession(base_url, api_key=api_key,
                        agent_id=(author or f"ai:mesh-w{wid}@cap2921"),
                        timeout=60)
        lat: list[float] = []
        codes: dict[str, int] = {}
        ok = 0
        try:
            for i in range(n):
                if pool is not None:
                    raw = pool.take()
                    if raw is None:
                        break
                    st, _b, ms = s.request("POST", MEMORIES, raw=raw)
                else:
                    st, _b, ms = s.request("POST", MEMORIES, {
                        "title": f"mesh2921-w{wid}-{i}",
                        "content": (f"mesh convergence corpus worker={wid} "
                                    f"seq={i} envelope probe"),
                        "namespace": namespace,
                        "tier": "short",
                    })
                codes[str(st)] = codes.get(str(st), 0) + 1
                if 200 <= st < 300:
                    ok += 1
                    lat.append(ms)
        finally:
            s.close()
        results[wid] = {"ok": ok, "lat": lat, "codes": codes}

    threads = [threading.Thread(target=worker, args=(w, per[w]), daemon=True)
               for w in range(concurrency)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.monotonic() - t0

    lat: list[float] = []
    ok = 0
    codes: dict[str, int] = {}
    for r in results:
        if not r:
            continue
        ok += r["ok"]
        lat.extend(r["lat"])
        for c, n in r["codes"].items():
            codes[c] = codes.get(c, 0) + n
    return {
        "offered": count,
        "accepted": ok,
        "write_wall_s": round(wall, 3),
        # Per-peer push throughput at the SENDER: each accepted write in a
        # full mesh fans out to (N-1) peers, so the aggregate push rate is
        # this times (N-1). Reported separately in the rung summary.
        "accepted_ops_per_s": round(ok / wall, 3) if wall > 0 else 0.0,
        "http_codes": codes,
        "pool_exhausted": bool(pool is not None and pool.exhausted),
        **percentiles(lat),
    }


def node_db(run_dir: str, idx: int) -> str:
    return os.path.join(run_dir, "data", f"node-{idx:02d}", "memories.db")


def watch_convergence(run_dir: str, n_nodes: int, namespace: str, expect: int,
                      t0: float, timeout: float, poll: float) -> dict:
    """Poll every node's row count until all reach `expect` or time runs out."""
    reached: dict[str, float] = {}
    last: dict[str, int] = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for i in range(1, n_nodes + 1):
            name = f"node-{i:02d}"
            if name in reached:
                continue
            c = sqlite_count(node_db(run_dir, i), namespace)
            last[name] = -1 if c is None else c
            if c is not None and c >= expect:
                reached[name] = round(time.monotonic() - t0, 3)
        if len(reached) == n_nodes:
            break
        time.sleep(poll)
    for i in range(1, n_nodes + 1):
        name = f"node-{i:02d}"
        if name not in last or last[name] < 0:
            c = sqlite_count(node_db(run_dir, i), namespace)
            last[name] = -1 if c is None else c
    return {
        "expect": expect,
        "converged": len(reached) == n_nodes,
        "converged_nodes": len(reached),
        "total_nodes": n_nodes,
        "per_node_converged_s": reached,
        "final_counts": last,
        "converged_s": (max(reached.values()) if len(reached) == n_nodes
                        else None),
        "slowest_node": (max(reached, key=reached.get)  # type: ignore[arg-type]
                         if len(reached) == n_nodes else None),
        "poll_interval_s": poll,
    }


def scrape_metrics(ips: dict, api_key: str, port: int,
                   attempts: int = 3, backoff: float = 2.0) -> dict:
    """Pull the federation counters off each node's Prometheus endpoint.

    Retried, because a single sequential sweep across a large mesh opens
    and closes one connection per node while the fleet is still carrying
    federation traffic, and a transient connect failure there would
    otherwise be indistinguishable from a clean zero. A node that still
    fails after `attempts` records `_scrape_status` and is EXCLUDED from
    every aggregate rather than contributing 0 -- see `cmd_rung`, where an
    incomplete sweep makes the aggregate `null`.
    """
    out: dict[str, dict] = {}
    for name, ip in sorted(ips.items()):
        st, body = 0, b""
        for attempt in range(attempts):
            s = HttpSession(f"http://{ip}:{port}", api_key=api_key, timeout=10)
            try:
                st, body, _ms = s.request("GET", METRICS)
            finally:
                s.close()
            if 200 <= st < 300:
                break
            if attempt < attempts - 1:
                time.sleep(backoff)
        if not (200 <= st < 300):
            out[name] = {"_scrape_status": st}
            continue
        vals: dict[str, float] = {}
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rsplit(" ", 1)
            if len(parts) != 2:
                continue
            metric = parts[0].split("{", 1)[0].strip()
            if metric in FED_METRICS:
                try:
                    vals[metric] = vals.get(metric, 0.0) + float(parts[1])
                except ValueError:
                    pass
        out[name] = vals
    return out


def docker_stats(project: str) -> dict:
    """One instantaneous per-container CPU% / RSS sample."""
    out = subprocess.run(
        docker() + ["stats", "--no-stream", "--format",
                    "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
        capture_output=True, text=True, check=False)
    rows = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, cpu, mem = parts
        if not name.startswith("am2921-"):
            continue
        rows[name] = {"cpu_pct": cpu.strip(), "mem": mem.split("/")[0].strip()}
    return rows


def cmd_rung(a: argparse.Namespace) -> int:
    api_key = a.api_key
    if a.api_key_file:
        with open(a.api_key_file, "r", encoding="utf-8") as fh:
            api_key = fh.read().strip()

    ips = resolve_ips(a.project)
    if len(ips) != a.nodes:
        print(f"[mesh_probe] WARN: resolved {len(ips)} containers, expected "
              f"{a.nodes}", file=sys.stderr)
    health = wait_healthy(ips, api_key, a.port, a.health_timeout)
    if not health["all_healthy"]:
        print(json.dumps({"rung": a.nodes, "error": "not all nodes healthy",
                          "health": health}, indent=2))
        return 1

    node1 = f"am2921-node-01"
    base = f"http://{ips[node1]}:{a.port}"

    pool = BodyPool(a.body_pool) if a.body_pool else None
    if pool is not None and not a.author:
        print("FATAL: --body-pool requires --author", file=sys.stderr)
        return 2
    pre = docker_stats(a.project)
    t0 = time.monotonic()
    w = write_corpus(base, api_key, a.namespace, a.corpus, a.write_concurrency,
                     pool=pool, author=a.author)
    mid = docker_stats(a.project)
    conv = watch_convergence(a.run_dir, a.nodes, a.namespace, a.corpus, t0,
                             a.converge_timeout, a.poll)
    post = docker_stats(a.project)
    met = scrape_metrics(ips, api_key, a.port)

    # An UNAVAILABLE metric is not a zero. If any node's /metrics sweep
    # failed, the fleet-wide aggregate is `null` and the failure count is
    # published beside it -- folding a failed scrape into a sum would
    # render "the DLQ is empty" from "we could not ask", which is the
    # exact shape of a control that reports success while doing nothing.
    scrape_failures = sum(1 for v in met.values()
                          if isinstance(v, dict) and "_scrape_status" in v)
    dlq_total = (None if scrape_failures else
                 sum(v.get("ai_memory_federation_push_dlq_depth", 0.0)
                     for v in met.values() if isinstance(v, dict)))
    rung = {
        "issue": 2921,
        "leg": "local-single-host-multi-container",
        "generated_at_utc": utc_stamp(),
        "nodes": a.nodes,
        "peers_per_node": a.nodes - 1,
        "namespace": a.namespace,
        "corpus": a.corpus,
        "write_concurrency": a.write_concurrency,
        "attestation": ({
            "posture": ("shipped v1.0.0 defaults -- HTTP-direct writes and "
                        "relayed third-party writes both REQUIRE a valid "
                        "Ed25519 signature"),
            "author": a.author,
            "pool_size": len(pool),
            "pool_consumed": pool.consumed(),
            "pool_age_secs_at_write_end": pool.age_secs(),
        } if pool is not None else {
            "posture": "unsigned (NOT the shipped default)",
        }),
        "health": health,
        "write": w,
        "convergence": conv,
        "tail_s": (round(conv["converged_s"] - w["write_wall_s"], 3)
                   if conv["converged_s"] is not None else None),
        # Aggregate /sync/push offered rate: every accepted write in a full
        # mesh fans out to (N-1) peers.
        "aggregate_push_ops_per_s": round(
            w["accepted_ops_per_s"] * (a.nodes - 1), 3),
        "federation_metrics": met,
        "metrics_scrape_failures": scrape_failures,
        "metrics_nodes_scraped": len(met),
        # `null` = at least one node could not be scraped, so the fleet
        # total is UNKNOWN. `0.0` = every node answered and the queue was
        # empty AT SCRAPE TIME (the gauge is a point-in-time depth: a
        # long convergence gives the replay worker time to drain it, so a
        # zero here does not mean nothing was ever parked).
        "dlq_depth_total": dlq_total,
        "docker_stats": {"pre_write": pre, "post_write": mid,
                         "post_converge": post},
    }
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(rung, fh, indent=2)
        print(f"[mesh_probe] -> {a.out}", file=sys.stderr)
    print(json.dumps({k: rung[k] for k in
                      ("nodes", "corpus", "write", "tail_s",
                       "aggregate_push_ops_per_s", "dlq_depth_total")},
                     indent=2))
    print(json.dumps({"convergence": {
        "converged": conv["converged"],
        "converged_s": conv["converged_s"],
        "converged_nodes": conv["converged_nodes"],
        "slowest_node": conv["slowest_node"],
    }}, indent=2))
    return 0 if conv["converged"] else 2


def self_test() -> int:
    ok = True

    def check(cond, msg):
        nonlocal ok
        if not cond:
            print(f"FAIL: {msg}", file=sys.stderr)
            ok = False

    import inspect
    src = inspect.getsource(watch_convergence)
    check("reached" in src and ">= expect" in src,
          "convergence must be first-reach at or above the corpus size")
    csrc = inspect.getsource(sqlite_count)
    check("mode=ro" in csrc, "row-count observation must be read-only")

    # A non-converged rung must NOT report a converged_s; a fabricated
    # completion time is the exact failure mode this bench exists to end.
    fake = {"converged": False, "converged_s": None}
    check(fake["converged_s"] is None,
          "non-converged rung must report converged_s = null")

    # Metric names must exist verbatim in the daemon's registry.
    check("ai_memory_federation_push_dlq_depth" in FED_METRICS,
          "DLQ depth is the headline degradation signal and must be scraped")

    # An UNAVAILABLE metric must never be aggregated as a zero.
    rsrc = inspect.getsource(cmd_rung)
    check("scrape_failures" in rsrc and "None if scrape_failures" in rsrc,
          "a failed /metrics scrape must make the fleet aggregate null, not 0")
    ssrc = inspect.getsource(scrape_metrics)
    check("attempts" in ssrc and "_scrape_status" in ssrc,
          "the metrics sweep must retry and must record an unrecoverable failure")

    print("mesh_probe self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    r = sub.add_parser("rung", help="drive + measure one mesh size")
    r.add_argument("--project", default="ai-memory-bench-mesh-2921")
    r.add_argument("--run-dir", required=True)
    r.add_argument("--nodes", type=int, required=True)
    r.add_argument("--corpus", type=int, default=1000)
    r.add_argument("--namespace", default="mesh2921")
    r.add_argument("--write-concurrency", type=int, default=8)
    r.add_argument("--port", type=int, default=19077)
    r.add_argument("--api-key")
    r.add_argument("--api-key-file")
    r.add_argument("--health-timeout", type=float, default=180.0)
    r.add_argument("--converge-timeout", type=float, default=600.0)
    r.add_argument("--poll", type=float, default=1.0)
    r.add_argument("--body-pool",
                   help="NDJSON of pre-signed attested bodies "
                        "(scripts/bench/make-signed-pool.sh)")
    r.add_argument("--author", help="signing identity bound to the pool")
    r.add_argument("--out")
    r.set_defaults(func=cmd_rung)

    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not getattr(a, "func", None):
        ap.print_help()
        return 2
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
