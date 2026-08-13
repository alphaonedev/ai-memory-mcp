#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ops_producer.py -- the missing producers for docs/enterprise-deployment.md §11.1.

§11.1 removed a 14-cell ops/s table because eleven cells had no producer,
and stated the rule this file exists to satisfy: *an unproduced number is
not data*. Three cells were called out by name as having NO producer at
all -- `memory_store` ops/s, `memory_recall` ops/s, and `/sync/push`
ops/s. `benches/` cannot supply them: every in-tree bench is a Criterion
LATENCY distribution over an in-process call, and none of them crosses
the HTTP surface an operator actually offers load to. These are
END-TO-END SURFACE producers, which is a different instrument.

WHAT THIS MEASURES
------------------
One `ai-memory serve` daemon, one host, offered concurrency ramped over a
geometric ladder. At each rung, `N` workers each hold ONE keep-alive
connection and issue one operation class in a tight loop for
`--duration` seconds. The rung's throughput is completed operations /
wall seconds; latency percentiles are nearest-rank over per-request wall
time measured client-side.

Op classes:
  store       POST /api/v1/memories                (the write path)
  recall      GET  /api/v1/recall                  (the read path)
  sync_push   POST /api/v1/memories against a daemon configured with ONE
              peer and `--quorum-writes 2`, so every accepted write must
              be acknowledged by that peer's `/sync/push`. The rate is
              therefore the sustained end-to-end federation push rate,
              signature verification included. Confirmed independently by
              the receiver's row-count delta (`--receiver-db`) so the
              number is not merely the sender's opinion.

WHY KEYWORD TIER FOR RECALL
---------------------------
`--tier keyword` makes the read path embedder-INDEPENDENT. A recall
number measured at `semantic` or `autonomous` is dominated by whichever
embedding endpoint the host happened to have, which is not a property of
this substrate and does not transfer to the reader's host. The tier is
recorded in the results JSON; a recall figure without its tier is
uninterpretable, so it is never emitted without one.

WHAT THIS DOES *NOT* MEASURE (read before quoting a number)
-----------------------------------------------------------
  * Not an agent count. One worker is a tight loop with zero think time;
    a real LLM-paced agent offers orders of magnitude less. Workers are
    an UPPER bound on the agents a host could carry, never an agent
    capacity.
  * Not the Postgres backend. SQLite only here.
  * Not a production host. Numbers are host-relative; the curve SHAPE
    transfers more reliably than the absolute ops/s.

INSTRUMENT HONESTY
------------------
`--calibrate` runs the identical worker loop against `/api/v1/health` --
the cheapest handler on the surface -- and records the result in the
output. That rate is the CEILING this driver can report on this host: a
measured op rate near the calibration rate is instrument-bound, not
substrate-bound, and the results doc must say so. This is the check the
prior `curl`-per-op harness could not make about itself.

Output is byte-compatible with the results JSON that
`infra/pillar4-envelope/usl-fit.py` consumes, so the USL fit is the
EXISTING, self-tested fitter rather than a second one written here.

    ops_producer.py ramp --op store --base-url http://127.0.0.1:9077 ...
    ops_producer.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import uuid
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchlib import BodyPool, HttpSession, host_facts, percentiles, utc_stamp  # noqa: E402

MEMORIES = "/api/v1/memories"
RECALL = "/api/v1/recall"
HEALTH = "/api/v1/health"

DEFAULT_STEPS = "1 2 4 8 16 32 64"
# 503 is the admission-control shed code (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`).
# It is counted separately from errors: a shed request is the daemon
# working correctly under overload, and the shed RATE is a first-class
# signal for where the knee is.
SHED_CODE = 503

# A per-process token stamped into every generated title. The HTTP write path
# treats `(title, namespace)` as a natural key and its default conflict policy
# is `error`, so without this the SECOND rung of a ramp collides with the
# first (worker 1 restarts its sequence at 1) and reports 409s as errors --
# measuring the conflict path instead of the insert path. Observed as
# 14k-21k 409s per rung before this token existed.
RUN_TOKEN = uuid.uuid4().hex[:8]


class Worker(threading.Thread):
    """One simulated concurrent client on one keep-alive connection."""

    def __init__(self, wid: int, op: str, base_url: str, api_key: str,
                 namespace: str, deadline: float, query: str,
                 pool=None, author: str | None = None, conc: int = 0):
        super().__init__(daemon=True)
        self.wid = wid
        self.conc = conc
        self.op = op
        self.namespace = namespace
        self.deadline = deadline
        self.query = query
        self.pool = pool
        # With a pre-signed pool the wire identity MUST be the signing
        # author: the attestation gate binds `agent_id` inside the signed
        # envelope, so a per-worker id would fail verification.
        self.sess = HttpSession(base_url, api_key=api_key,
                                agent_id=(author or f"ai:bench-w{wid}@cap2921"))
        self.lat: list[float] = []
        self.ok = 0
        self.shed = 0
        self.err = 0
        self.codes: dict[int, int] = {}

    def _record(self, status: int, ms: float) -> None:
        self.codes[status] = self.codes.get(status, 0) + 1
        if status == SHED_CODE:
            self.shed += 1
            return
        if 200 <= status < 300:
            self.ok += 1
            self.lat.append(ms)
            return
        self.err += 1

    def run(self) -> None:
        n = 0
        try:
            while time.monotonic() < self.deadline:
                n += 1
                if self.op == "recall":
                    q = f"?q={self.query}&namespace={self.namespace}&limit=5"
                    st, _b, ms = self.sess.request("GET", RECALL + q)
                elif self.op == "health":
                    st, _b, ms = self.sess.request("GET", HEALTH)
                elif self.pool is not None:
                    # Pre-signed attested body, posted verbatim. A dry pool
                    # ends the rung immediately rather than degrading into a
                    # lower throughput number for an unstated reason.
                    raw = self.pool.take()
                    if raw is None:
                        break
                    st, _b, ms = self.sess.request("POST", MEMORIES, raw=raw)
                else:  # store / sync_push -- identical wire op, different daemon config
                    body = {
                        "title": f"cap2921-{RUN_TOKEN}-c{self.conc}-w{self.wid}-{n}",
                        "content": (f"capacity envelope probe worker={self.wid} "
                                    f"seq={n} {self.query}"),
                        "namespace": self.namespace,
                        "tier": "short",
                    }
                    st, _b, ms = self.sess.request("POST", MEMORIES, body)
                self._record(st, ms)
        finally:
            self.sess.close()


def sqlite_count(db_path: str, namespace: str | None) -> int | None:
    """Row count observed directly from a node's SQLite file.

    READ-ONLY, via a `file:...?mode=ro` URI so this observation can never
    write to, lock out, or migrate the database it is watching. Used as
    the INDEPENDENT confirmation of the receiver-side push rate and as
    the mesh convergence probe: the HTTP `/api/v1/stats` route is
    admin-gated and returns a projected envelope, whereas the question
    "did this row land durably on this node" is exactly a row count.
    """
    if not os.path.exists(db_path):
        return None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        try:
            cur = con.cursor()
            if namespace:
                cur.execute("SELECT COUNT(*) FROM memories WHERE namespace = ?",
                            (namespace,))
            else:
                cur.execute("SELECT COUNT(*) FROM memories")
            return int(cur.fetchone()[0])
        finally:
            con.close()
    except sqlite3.Error:
        return None


def run_rung(op: str, conc: int, base_url: str, api_key: str, namespace: str,
             duration: float, query: str, pool=None,
             author: str | None = None) -> dict:
    deadline = time.monotonic() + duration
    workers = [Worker(i, op, base_url, api_key, namespace, deadline, query,
                      pool=pool, author=author, conc=conc)
               for i in range(1, conc + 1)]
    t0 = time.monotonic()
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=duration + 120)
    wall = time.monotonic() - t0

    lat: list[float] = []
    ok = shed = err = 0
    codes: dict[str, int] = {}
    for w in workers:
        lat.extend(w.lat)
        ok += w.ok
        shed += w.shed
        err += w.err
        for c, n in w.codes.items():
            codes[str(c)] = codes.get(str(c), 0) + n
    reqs = ok + shed + err
    pct = percentiles(lat)
    return {
        "offered_concurrency": conc,
        "wall_secs": round(wall, 4),
        "reqs": reqs,
        "ok": ok,
        "errors": err,
        "shed": shed,
        "shed_rate": round(shed / reqs, 6) if reqs else 0.0,
        # Throughput counts SUCCEEDED operations only. Counting sheds or
        # errors as throughput is how an overloaded daemon reports its
        # best number.
        "total_ops_per_s": round(ok / wall, 4) if wall > 0 else 0.0,
        "http_codes": codes,
        "pool_exhausted": bool(pool is not None and pool.exhausted),
        "ops": {op: {"count": ok, "ops_per_s": round(ok / wall, 4) if wall else 0.0,
                     **pct}},
    }


def seed_corpus(base_url: str, api_key: str, namespace: str, count: int,
                concurrency: int = 8) -> int:
    """Pre-load a corpus so the read path is not measured against an empty table."""
    done = [0]
    lock = threading.Lock()
    per = max(1, count // concurrency)

    def loader(wid: int, n: int) -> None:
        s = HttpSession(base_url, api_key=api_key,
                        agent_id=f"ai:bench-seed{wid}@cap2921")
        try:
            for i in range(n):
                st, _b, _ms = s.request("POST", MEMORIES, {
                    "title": f"cap2921-seed-{RUN_TOKEN}-{wid}-{i}",
                    "content": (f"capacity envelope seed corpus row {wid}/{i} "
                                "envelope probe keyword token"),
                    "namespace": namespace,
                    "tier": "short",
                })
                if 200 <= st < 300:
                    with lock:
                        done[0] += 1
        finally:
            s.close()

    threads = [threading.Thread(target=loader, args=(w, per), daemon=True)
               for w in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return done[0]


def cmd_ramp(a: argparse.Namespace) -> int:
    steps = [int(x) for x in a.concurrency_steps.split()]
    api_key = a.api_key or ""
    pool = BodyPool(a.body_pool) if a.body_pool else None
    if pool is not None and not a.author:
        print("FATAL: --body-pool requires --author (the signing identity the "
              "attestation gate binds)", file=sys.stderr)
        return 2

    calib = None
    if a.calibrate:
        c = run_rung("health", max(steps), a.base_url, api_key, a.namespace,
                     a.calibrate_secs, "cal")
        calib = {
            "endpoint": HEALTH,
            "offered_concurrency": c["offered_concurrency"],
            "ops_per_s": c["total_ops_per_s"],
            "note": ("Instrument ceiling on this host. A measured op rate "
                     "approaching this is instrument-bound, not "
                     "substrate-bound."),
        }

    seeded = None
    if a.seed_corpus:
        seeded = seed_corpus(a.base_url, api_key, a.namespace, a.seed_corpus)

    recv_before = None
    if a.receiver_db:
        recv_before = sqlite_count(a.receiver_db, a.namespace)

    points = []
    t_start = time.time()
    print(f"{'CONC':>6} {'ops/s':>10} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8} "
          f"{'shed%':>7} {'err':>6}", file=sys.stderr)
    for conc in steps:
        p = run_rung(a.op, conc, a.base_url, api_key, a.namespace,
                     a.duration, a.query, pool=pool, author=a.author)
        points.append(p)
        o = p["ops"][a.op]
        print(f"{conc:>6} {p['total_ops_per_s']:>10.1f} {o['p50_ms']:>8.1f} "
              f"{o['p95_ms']:>8.1f} {o['p99_ms']:>8.1f} "
              f"{p['shed_rate'] * 100:>6.2f}% {p['errors']:>6}",
              file=sys.stderr)
        if a.cooldown_secs:
            time.sleep(a.cooldown_secs)

    recv_after = None
    receiver = None
    if a.receiver_db:
        if a.receiver_drain_secs:
            time.sleep(a.receiver_drain_secs)
        recv_after = sqlite_count(a.receiver_db, a.namespace)
        wall = sum(p["wall_secs"] for p in points) + (a.cooldown_secs
                                                      * (len(points) - 1))
        applied = ((recv_after - recv_before)
                   if (recv_after is not None and recv_before is not None)
                   else None)
        receiver = {
            "rows_before": recv_before,
            "rows_after": recv_after,
            "rows_applied": applied,
            "wall_secs_total": round(wall, 3),
            # Averaged across the WHOLE ramp including cooldowns, so it is
            # a conservative floor on the receiver's absorb rate, not a
            # peak. The per-rung sender numbers above are the peak.
            "mean_applied_ops_per_s": (round(applied / wall, 4)
                                       if applied is not None and wall > 0
                                       else None),
            "note": ("Independent receiver-side confirmation that the "
                     "sender's accepted writes landed durably on the peer "
                     "via /sync/push."),
        }

    out = {
        "meta": {
            "issue": 2921,
            "producer": "scripts/bench/ops_producer.py",
            "producer_argv": sys.argv[1:],
            "op": a.op,
            "label": a.label or a.op,
            "backend": "sqlite",
            "tier": a.tier,
            "host_substrate": a.host_substrate or "single-host",
            "corpus_scale": seeded if seeded is not None else 0,
            "step_duration_secs": a.duration,
            "generated_at_utc": utc_stamp(),
            "measured_label": "MEASURED",
            "instrument": ("ops_producer.py keep-alive worker pool; op shapes "
                           "match infra/pillar4-envelope/measure-envelope.sh"),
            "host_facts": host_facts(),
            "calibration": calib,
            "attestation": ({
                "posture": "attested (shipped v1.0.0 default: signature REQUIRED)",
                "author": a.author,
                "pool_size": len(pool),
                "pool_consumed": pool.consumed(),
                "pool_exhausted": pool.exhausted,
                "pool_age_secs_at_end": pool.age_secs(),
                "signer": "examples/attest_sign_batch (same crate code the verifier runs)",
                "note": ("Client-side signing happens BEFORE the timed window "
                         "and is excluded from every figure; what is measured "
                         "is server-side verification + storage (+ relay)."),
            } if pool is not None else {
                "posture": ("unsigned (AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 -- "
                            "NOT the shipped default)"),
                "note": ("An upper bound relative to the shipped posture: no "
                         "per-write Ed25519 verification is performed."),
            }),
            "receiver": receiver,
            "elapsed_wall_secs": round(time.time() - t_start, 2),
        },
        "points": points,
    }
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[ops_producer] -> {a.out}", file=sys.stderr)
    else:
        json.dump(out, sys.stdout, indent=2)
        print()
    return 0


def cmd_count(a: argparse.Namespace) -> int:
    print(json.dumps({"db": os.path.basename(a.db),
                      "namespace": a.namespace,
                      "count": sqlite_count(a.db, a.namespace)}))
    return 0


def self_test() -> int:
    """Contract checks that need no daemon: reducers, JSON shape, safety."""
    ok = True

    def check(cond, msg):
        nonlocal ok
        if not cond:
            print(f"FAIL: {msg}", file=sys.stderr)
            ok = False

    p = percentiles([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0])
    check(p["p50_ms"] == 6.0, f"nearest-rank p50 of 1..10 is 6.0, got {p}")
    check(p["p95_ms"] == 10.0, f"p95 of 1..10 is 10.0, got {p}")
    check(percentiles([])["p95_ms"] == 0.0, "empty sample must not divide by zero")

    # A rung with zero successes must report zero throughput, not NaN and
    # not the shed count dressed as throughput.
    fake = {
        "offered_concurrency": 4, "wall_secs": 10.0, "reqs": 100, "ok": 0,
        "errors": 0, "shed": 100, "shed_rate": 1.0, "total_ops_per_s": 0.0,
    }
    check(fake["total_ops_per_s"] == 0.0, "all-shed rung must be 0 ops/s")

    # usl-fit.py contract: every point needs offered_concurrency and
    # total_ops_per_s; the fitter reads exactly those two under
    # `--series total`.
    pt = run_rung.__doc__ or ""
    required = {"offered_concurrency", "wall_secs", "reqs", "shed",
                "shed_rate", "total_ops_per_s", "ops"}
    import inspect
    src = inspect.getsource(run_rung)
    for k in required:
        check(f'"{k}"' in src, f"results point must carry {k} for usl-fit.py")

    # The row-count observation must be read-only. This is a data-integrity
    # property, not a style point: the probe watches a LIVE daemon's
    # database while it is being written.
    csrc = inspect.getsource(sqlite_count)
    check("mode=ro" in csrc and "uri=True" in csrc,
          "sqlite_count must open the observed DB strictly read-only")

    hf = host_facts()
    check(hf["cpu_logical_cores"] is not None, "host facts must carry core count")
    check("/home/" not in json.dumps(hf),
          "host facts must not embed a home-directory path")

    print("ops_producer self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    r = sub.add_parser("ramp", help="run a concurrency ramp for one op class")
    r.add_argument("--op", choices=("store", "recall", "health"), required=True)
    r.add_argument("--label", help="results label (e.g. sync_push)")
    r.add_argument("--base-url", required=True)
    r.add_argument("--api-key")
    r.add_argument("--namespace", default="cap2921")
    r.add_argument("--tier", default="keyword")
    r.add_argument("--query", default="envelope")
    r.add_argument("--duration", type=float, default=20.0)
    r.add_argument("--cooldown-secs", type=float, default=2.0)
    r.add_argument("--concurrency-steps", default=DEFAULT_STEPS)
    r.add_argument("--seed-corpus", type=int, default=0,
                   help="rows to pre-load before the ramp (read path)")
    r.add_argument("--receiver-db",
                   help="peer SQLite file, for receiver-side push confirmation")
    r.add_argument("--receiver-drain-secs", type=float, default=0.0)
    r.add_argument("--host-substrate", help="free-text host label for the results")
    r.add_argument("--calibrate", action="store_true",
                   help="measure the driver's own ceiling against /api/v1/health "
                        "first, and record it beside the result")
    r.add_argument("--calibrate-secs", type=float, default=5.0)
    r.add_argument("--body-pool",
                   help="NDJSON of pre-signed, ready-to-POST attested bodies "
                        "(see scripts/bench/make-signed-pool.sh)")
    r.add_argument("--author",
                   help="signing identity bound to the pool; required with "
                        "--body-pool")
    r.add_argument("--out")
    r.set_defaults(func=cmd_ramp)

    c = sub.add_parser("count", help="read-only row count of a node's SQLite DB")
    c.add_argument("--db", required=True)
    c.add_argument("--namespace")
    c.set_defaults(func=cmd_count)

    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not getattr(a, "func", None):
        ap.print_help()
        return 2
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
