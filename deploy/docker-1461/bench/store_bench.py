#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# EC-CPU "Ollama or no Ollama" store-path throughput anchor (EPIC #174, #182).
#
# Measures END-TO-END memory-store throughput against a running ai-memory
# daemon: POST /api/v1/memories, where the write path synchronously computes
# the embedding before the row lands. This is the number that actually bounds
# Enterprise ingest, because the embedder runs inline on the request thread.
#
# Point it at the "no-Ollama" arm (a daemon whose tier resolves to the
# in-process candle MiniLM-L6-v2, 384-dim, CPU-only) to anchor the simplest
# EC-CPU config; point it at an Ollama-backed daemon (nomic-embed-text, 768-dim)
# to anchor the Ollama EC-CPU arm. The two store-throughput numbers + the
# recall@k floor decide the EC-CPU embedder default.
#
# Verification: the create response does NOT surface embed status, so after
# the run we read embedding_dim straight from the SQLite db (--db) to prove
# every stored row carries a populated vector of the expected dim.
#
# Pure stdlib (urllib + sqlite3) — no third-party deps, fully reproducible.
# Concurrency via threads (network-bound on a local socket; GIL released during
# the blocking HTTP call, and the heavy embed work happens in the daemon).
#
# Usage:
#   python3 store_bench.py --url http://127.0.0.1:9097 --out-dir <dir> \
#       --arm minilm_local --expect-dim 384 --db <path/to.db> \
#       --iters 200 --concurrency 1 4 8 [--namespace contest]

import argparse
import json
import sqlite3
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

# Same representative ai-memory payloads as embed_bench.py: short title + a
# spread of body lengths so embedder cost (which scales with token count) is
# not cherry-picked to one length.
CORPUS = [
    ("operator directive", "ship v0.7.0 release gate"),
    ("federation quorum",
     "The federation quorum uses W=2-of-3 mTLS with /sync/* bypassing the "
     "api_key under client-cert auth, so peer health gates and quorum POSTs "
     "succeed without presenting the daemon HTTP api_key."),
    ("pgvector hnsw",
     "pgvector 0.8.2 HNSW index over the 768-dim nomic-embed-text vectors "
     "stored in PostgreSQL 18.4; the daemon connects over TLS verify-full and "
     "the ANN search honors hnsw.ef_search at query time."),
    ("provisioning reflection",
     "Reflection: across the do-1461 provisioning run the role.sql application "
     "site was switched from psql -f to a stdin redirect because -f names the "
     "file in its permission-denied error, which is how we diagnosed the "
     "stale-binary failure; the current 20_pg_age.sh already carries the fix "
     "and the green fleet validate confirmed it end to end."),
]


def store_once(base_url, namespace, title, content, timeout=120.0):
    body = json.dumps({
        "title": title,
        "content": content,
        "namespace": namespace,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/v1/memories",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read())
    dt = time.perf_counter() - t0
    return dt, payload.get("id")


def run_arm(base_url, namespace, warmup, iters, concurrency):
    for i in range(warmup):
        t, c = CORPUS[i % len(CORPUS)]
        store_once(base_url, namespace, f"warmup {uuid.uuid4().hex[:8]} {t}", c)

    latencies = []
    ids = []
    errors = []
    lock = threading.Lock()

    # Unique titles (default on_conflict=error rejects dup title+namespace).
    work = []
    for i in range(iters):
        t, c = CORPUS[i % len(CORPUS)]
        work.append((f"{t} {i:05d} {uuid.uuid4().hex[:8]}", c))

    def worker(slice_items):
        for title, content in slice_items:
            try:
                dt, mid = store_once(base_url, namespace, title, content)
                with lock:
                    latencies.append(dt)
                    if mid:
                        ids.append(mid)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                with lock:
                    errors.append(str(e))

    chunks = [work[i::concurrency] for i in range(concurrency)]
    threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]

    wall0 = time.perf_counter()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    wall = time.perf_counter() - wall0

    ok = len(latencies)
    lat_ms = sorted(x * 1000.0 for x in latencies)

    def pct(p):
        if not lat_ms:
            return None
        k = max(0, min(len(lat_ms) - 1,
                       int(round((p / 100.0) * (len(lat_ms) - 1)))))
        return round(lat_ms[k], 2)

    return {
        "concurrency": concurrency,
        "iters": iters,
        "ok": ok,
        "errors": len(errors),
        "error_sample": errors[:3],
        "wall_secs": round(wall, 4),
        "throughput_stores_per_sec": round(ok / wall, 2) if wall > 0 else None,
        "latency_ms_p50": pct(50),
        "latency_ms_p95": pct(95),
        "latency_ms_p99": pct(99),
        "latency_ms_mean": round(statistics.mean(lat_ms), 2) if lat_ms else None,
        "latency_ms_min": round(lat_ms[0], 2) if lat_ms else None,
        "latency_ms_max": round(lat_ms[-1], 2) if lat_ms else None,
    }, ids


def verify_db(db_path, expect_dim):
    # Prove every embedded row carries a populated vector of the expected dim.
    con = sqlite3.connect(db_path)
    try:
        total = con.execute("SELECT count(*) FROM memories").fetchone()[0]
        by_dim = dict(con.execute(
            "SELECT embedding_dim, count(*) FROM memories GROUP BY embedding_dim"
        ).fetchall())
        null_blob = con.execute(
            "SELECT count(*) FROM memories WHERE embedding IS NULL").fetchone()[0]
        sample = con.execute(
            "SELECT length(embedding) FROM memories "
            "WHERE embedding_dim = ? LIMIT 1", (expect_dim,)).fetchone()
    finally:
        con.close()
    return {
        "db": db_path,
        "rows_total": total,
        "rows_by_embedding_dim": {str(k): v for k, v in by_dim.items()},
        "rows_null_embedding": null_blob,
        "expect_dim": expect_dim,
        "expect_dim_blob_bytes": sample[0] if sample else None,
        "all_rows_embedded_at_expect_dim": (
            null_blob == 0 and by_dim.get(expect_dim, 0) == total),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--arm", required=True,
                    help="label, e.g. minilm_local or nomic_ollama_cpu")
    ap.add_argument("--expect-dim", type=int, required=True)
    ap.add_argument("--db", help="SQLite db path for embedding verification")
    ap.add_argument("--namespace", default="contest")
    ap.add_argument("--warmup", type=int, default=4)
    ap.add_argument("--iters", type=int, default=200)
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 8])
    args = ap.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = []
    for conc in args.concurrency:
        print(f"[{args.arm}] concurrency={conc} iters={args.iters} ...",
              file=sys.stderr, flush=True)
        r, _ids = run_arm(args.url, args.namespace, args.warmup,
                          args.iters, conc)
        r["arm"] = args.arm
        results.append(r)
        print(f"  -> {r['throughput_stores_per_sec']} stores/s  "
              f"p50={r['latency_ms_p50']}ms p99={r['latency_ms_p99']}ms  "
              f"errors={r['errors']}", file=sys.stderr, flush=True)

    verification = verify_db(args.db, args.expect_dim) if args.db else None
    if verification:
        print(f"[verify] rows={verification['rows_total']} "
              f"by_dim={verification['rows_by_embedding_dim']} "
              f"all_embedded={verification['all_rows_embedded_at_expect_dim']}",
              file=sys.stderr, flush=True)

    out = {
        "benchmark": "store_throughput",
        "arm": args.arm,
        "host": "m4-mac-mini-10core-32gb",
        "url": args.url,
        "expect_dim": args.expect_dim,
        "namespace": args.namespace,
        "utc": ts,
        "note": "End-to-end POST /api/v1/memories throughput; embedder runs "
                "inline on the write path. Absolute stores/s are M4-specific.",
        "verification": verification,
        "results": results,
    }

    json_path = f"{args.out_dir}/store-bench-{args.arm}-{ts}.json"
    tsv_path = f"{args.out_dir}/store-bench-{args.arm}-{ts}.tsv"
    with open(json_path, "w") as f:
        json.dump(out, f, indent=2)
    with open(tsv_path, "w") as f:
        f.write("arm\tconcurrency\titers\tok\terrors\tstores_per_sec\t"
                "p50_ms\tp95_ms\tp99_ms\tmean_ms\n")
        for r in results:
            f.write(f"{r['arm']}\t{r['concurrency']}\t{r['iters']}\t{r['ok']}\t"
                    f"{r['errors']}\t{r['throughput_stores_per_sec']}\t"
                    f"{r['latency_ms_p50']}\t{r['latency_ms_p95']}\t"
                    f"{r['latency_ms_p99']}\t{r['latency_ms_mean']}\n")

    print(f"wrote {json_path}", file=sys.stderr)
    print(f"wrote {tsv_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
