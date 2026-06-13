#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# GPU-vs-CPU embedder throughput anchor for the Enterprise-config matrix
# (EPIC #174). Measures embeds/sec + p50/p95/p99 latency for nomic-embed-text
# (768-dim) against two Ollama arms on THIS M4 Mac mini:
#
#   GPU arm  -> host-native Ollama on :11434 (Metal-accelerated; the only path
#               that reaches the M4 GPU — Docker on Apple Silicon cannot).
#   CPU arm  -> ollama/ollama container `ollama-cpu-bench` on :11435 (pure CPU).
#
# Both arms run the SAME model on the SAME host, so the ratio is a clean
# architecture-controlled GPU:CPU embedder-throughput anchor. This is one of
# the physically-MEASURED anchors that feeds the capacity-planning model; the
# absolute numbers are M4-specific and are NOT comparable to the DO amd64
# EC-CPU reference numbers (different ISA + no virtualization layer) — only the
# within-host GPU/CPU ratio transfers.
#
# Pure stdlib (urllib) — no third-party deps, fully reproducible. Concurrency
# via threads (the work is network-bound on a local socket; the GIL is released
# during the blocking HTTP call).
#
# Usage:
#   python3 embed_bench.py --out-dir <dir> [--warmup N] [--iters N]
#                          [--concurrency C [C ...]] [--model NAME]

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# Representative ai-memory store/recall payloads: short titles, mid memory
# bodies, long reflection content. Embedder cost scales with token count, so a
# spread keeps the anchor honest rather than cherry-picking one length.
CORPUS = [
    "operator directive: ship v0.7.0 release gate",
    "The federation quorum uses W=2-of-3 mTLS with /sync/* bypassing the api_key "
    "under client-cert auth, so peer health gates and quorum POSTs succeed without "
    "presenting the daemon HTTP api_key.",
    "pgvector 0.8.2 HNSW index over the 768-dim nomic-embed-text vectors stored in "
    "PostgreSQL 18.4; the daemon connects over TLS verify-full and the ANN search "
    "honors hnsw.ef_search at query time.",
    "Reflection: across the do-1461 provisioning run the role.sql application site "
    "was switched from psql -f to a stdin redirect because -f names the file in its "
    "permission-denied error, which is how we diagnosed the stale-binary failure; "
    "the current 20_pg_age.sh already carries the fix and the green 15:54 fleet "
    "validate confirmed it end to end across all four peer nodes and the pg node.",
]


def embed_once(base_url: str, model: str, text: str, timeout: float = 120.0):
    body = json.dumps({"model": model, "input": text}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/embed",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read())
    dt = time.perf_counter() - t0
    embs = payload.get("embeddings") or []
    dim = len(embs[0]) if embs and isinstance(embs[0], list) else 0
    return dt, dim


def run_arm(name: str, base_url: str, model: str, warmup: int, iters: int,
            concurrency: int):
    # Warm the model into the runner (first call pays load latency).
    for i in range(warmup):
        embed_once(base_url, model, CORPUS[i % len(CORPUS)])

    latencies = []
    dims = set()
    errors = []
    lock = threading.Lock()
    work = [CORPUS[i % len(CORPUS)] for i in range(iters)]

    def worker(slice_texts):
        for text in slice_texts:
            try:
                dt, dim = embed_once(base_url, model, text)
                with lock:
                    latencies.append(dt)
                    dims.add(dim)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                with lock:
                    errors.append(str(e))

    # Partition the work across `concurrency` threads.
    chunks = [work[i::concurrency] for i in range(concurrency)]
    threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]

    wall0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - wall0

    ok = len(latencies)
    lat_ms = sorted(x * 1000.0 for x in latencies)

    def pct(p):
        if not lat_ms:
            return None
        k = max(0, min(len(lat_ms) - 1, int(round((p / 100.0) * (len(lat_ms) - 1)))))
        return round(lat_ms[k], 2)

    return {
        "arm": name,
        "base_url": base_url,
        "model": model,
        "concurrency": concurrency,
        "iters": iters,
        "ok": ok,
        "errors": len(errors),
        "error_sample": errors[:3],
        "embed_dim": sorted(dims),
        "wall_secs": round(wall, 4),
        "throughput_embeds_per_sec": round(ok / wall, 2) if wall > 0 else None,
        "latency_ms_p50": pct(50),
        "latency_ms_p95": pct(95),
        "latency_ms_p99": pct(99),
        "latency_ms_mean": round(statistics.mean(lat_ms), 2) if lat_ms else None,
        "latency_ms_min": round(lat_ms[0], 2) if lat_ms else None,
        "latency_ms_max": round(lat_ms[-1], 2) if lat_ms else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--gpu-url", default="http://127.0.0.1:11434")
    ap.add_argument("--cpu-url", default="http://127.0.0.1:11435")
    ap.add_argument("--model", default="nomic-embed-text")
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--iters", type=int, default=120)
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 8])
    args = ap.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arms = [("gpu_metal", args.gpu_url), ("cpu_container", args.cpu_url)]
    results = []

    for conc in args.concurrency:
        for arm_name, url in arms:
            print(f"[{arm_name}] concurrency={conc} iters={args.iters} ...",
                  file=sys.stderr, flush=True)
            r = run_arm(arm_name, url, args.model, args.warmup, args.iters, conc)
            results.append(r)
            print(f"  -> {r['throughput_embeds_per_sec']} embeds/s  "
                  f"p50={r['latency_ms_p50']}ms p99={r['latency_ms_p99']}ms  "
                  f"dim={r['embed_dim']} errors={r['errors']}",
                  file=sys.stderr, flush=True)

    # GPU:CPU throughput ratio per concurrency level (the transferable anchor).
    ratios = {}
    for conc in args.concurrency:
        g = next((r for r in results if r["arm"] == "gpu_metal"
                  and r["concurrency"] == conc), None)
        c = next((r for r in results if r["arm"] == "cpu_container"
                  and r["concurrency"] == conc), None)
        if g and c and c["throughput_embeds_per_sec"]:
            ratios[str(conc)] = round(
                g["throughput_embeds_per_sec"] / c["throughput_embeds_per_sec"], 3)

    out = {
        "benchmark": "embed_gpu_vs_cpu",
        "host": "m4-mac-mini-10core-32gb",
        "model": args.model,
        "embed_dim_expected": 768,
        "utc": ts,
        "note": "Within-host GPU(Metal):CPU ratio is the transferable anchor; "
                "absolute embeds/s are M4-specific, NOT comparable to DO amd64.",
        "gpu_cpu_throughput_ratio_by_concurrency": ratios,
        "results": results,
    }

    json_path = f"{args.out_dir}/embed-bench-{ts}.json"
    tsv_path = f"{args.out_dir}/embed-bench-{ts}.tsv"
    with open(json_path, "w") as f:
        json.dump(out, f, indent=2)
    with open(tsv_path, "w") as f:
        f.write("arm\tconcurrency\titers\tok\terrors\tembeds_per_sec\t"
                "p50_ms\tp95_ms\tp99_ms\tmean_ms\tembed_dim\n")
        for r in results:
            f.write(f"{r['arm']}\t{r['concurrency']}\t{r['iters']}\t{r['ok']}\t"
                    f"{r['errors']}\t{r['throughput_embeds_per_sec']}\t"
                    f"{r['latency_ms_p50']}\t{r['latency_ms_p95']}\t"
                    f"{r['latency_ms_p99']}\t{r['latency_ms_mean']}\t"
                    f"{'/'.join(map(str, r['embed_dim']))}\n")

    print(f"\nGPU:CPU throughput ratio by concurrency: {ratios}", file=sys.stderr)
    print(f"wrote {json_path}", file=sys.stderr)
    print(f"wrote {tsv_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
