#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# EC-CPU "Ollama or no Ollama" recall@k FLOOR anchor (EPIC #174, #182).
#
# The store-throughput contest (store_bench.py) decisively favors the no-Ollama
# candle MiniLM-L6-v2 (384-dim) arm over Ollama nomic-embed-text-v1.5 (768-dim)
# on CPU. The ONLY thing that could override that verdict is a RECALL
# regression: a 384-dim embedder that retrieves materially worse than the
# 768-dim one would trade throughput for answer quality. This script measures
# whether MiniLM-384 clears the recall floor set by nomic-768.
#
# Method (controlled, daemon-agnostic):
#   1. Store a labeled IR set into a running ai-memory daemon. Each query is a
#      PARAPHRASE of exactly one target document, lexically divergent from it,
#      with same-topic distractor docs present — so a hit requires SEMANTIC
#      retrieval, not keyword overlap.
#   2. The daemon embeds every stored row with its configured embedder. We read
#      the embedding BLOBs straight back from SQLite (tag byte + little-endian
#      f32; vectors are L2-normalized, so cosine == dot product). This uses the
#      EXACT embedder under test for both docs and queries, with no separate
#      embed endpoint and no recall-path visibility gating.
#   3. Rank docs per query by dot product; report recall@{1,3,5,10} and MRR.
#
# Run once per arm (point --url/--db at each daemon), then compare. If MiniLM-384
# recall@5 / MRR is within a small epsilon of nomic-768 (or better), the EC-CPU
# default is no-Ollama. Pure stdlib.
#
# Usage:
#   python3 recall_floor.py --url http://127.0.0.1:9097 \
#       --db .../minilm.db --expect-dim 384 --arm minilm_local \
#       --out-dir <reports> [--namespace recall_floor]

import argparse
import json
import math
import sqlite3
import struct
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

# Labeled IR set: 8 topics from the ai-memory operational domain. Each topic
# has 3-4 documents (factual statements) and 2-3 queries. Every query targets
# ONE document (doc_id) and is phrased with different vocabulary than its
# target, while same-topic distractors compete. doc_id is globally unique.
TOPICS = [
    {
        "topic": "federation_quorum",
        "docs": {
            "fq1": "A write is acknowledged once two of the three federation "
                   "peers confirm it under mutual-TLS client certificates.",
            "fq2": "Sync endpoints skip the HTTP api_key check because the "
                   "client certificate already authenticates the calling peer.",
            "fq3": "Peer health probes run on a fixed cadence and mark a node "
                   "degraded after consecutive missed heartbeats.",
        },
        "queries": [
            ("How many nodes must agree before a write counts as durable?",
             "fq1"),
            ("Why don't peer-to-peer sync calls need the daemon API token?",
             "fq2"),
        ],
    },
    {
        "topic": "vector_index",
        "docs": {
            "vi1": "Approximate nearest-neighbor search is served by an HNSW "
                   "graph built over the stored embedding column.",
            "vi2": "The number of candidates explored during a search is "
                   "governed by a runtime tunable that trades latency for "
                   "recall.",
            "vi3": "Embeddings are persisted as a binary float array alongside "
                   "each memory row in the relational store.",
        },
        "queries": [
            ("What data structure powers the fast similarity lookup?", "vi1"),
            ("Which knob lets me dial search accuracy up at the cost of speed?",
             "vi2"),
        ],
    },
    {
        "topic": "transport_security",
        "docs": {
            "ts1": "Client and server present certificates to each other so "
                   "both ends of the connection are cryptographically verified.",
            "ts2": "The daemon refuses to talk to its database unless the TLS "
                   "certificate chain validates all the way to the root.",
            "ts3": "Audit records are signed with an Ed25519 key so any later "
                   "tampering with the log is detectable.",
        },
        "queries": [
            ("How does each side prove its identity on the wire?", "ts1"),
            ("What stops a forged or altered audit entry from going unnoticed?",
             "ts3"),
        ],
    },
    {
        "topic": "write_path",
        "docs": {
            "wp1": "Signing the audit chain happens off the request thread so "
                   "the hot path is not blocked by cryptographic work.",
            "wp2": "Bulk ingestion uses a copy-style batch path instead of one "
                   "round trip per row.",
            "wp3": "Prepared statements are reused so the planner does not "
                   "recompile the same query on every insert.",
        },
        "queries": [
            ("Why doesn't per-row signature computation slow down inserts?",
             "wp1"),
            ("How are large imports made faster than inserting one at a time?",
             "wp2"),
        ],
    },
    {
        "topic": "embedder_choice",
        "docs": {
            "ec1": "The in-process model produces 384-dimensional vectors and "
                   "needs no external service to run.",
            "ec2": "The larger model emits 768-dimensional vectors but requires "
                   "a separate inference server reachable over HTTP.",
            "ec3": "On a CPU-only host the external embedder serializes "
                   "requests, so adding concurrency does not raise throughput.",
        },
        "queries": [
            ("Which embedding option runs entirely inside the daemon with no "
             "sidecar?", "ec1"),
            ("Why does the standalone inference server stop scaling when many "
             "requests arrive at once on a processor-only box?", "ec3"),
        ],
    },
    {
        "topic": "scope_visibility",
        "docs": {
            "sv1": "A memory left at the default visibility is readable only by "
                   "the agent that created it.",
            "sv2": "Widening a record to the collective level lets every agent "
                   "in the namespace retrieve it.",
            "sv3": "Namespaces partition memories so unrelated tenants never "
                   "see each other's data.",
        },
        "queries": [
            ("Who can read an entry that was stored without changing its "
             "sharing setting?", "sv1"),
            ("How do I make a fact available to all agents in the same space?",
             "sv2"),
        ],
    },
    {
        "topic": "postgres_tuning",
        "docs": {
            "pt1": "A connection pooler sits between the daemon and the "
                   "database to cap the number of live backend sessions.",
            "pt2": "Statement timeouts abort runaway queries before they "
                   "exhaust server resources.",
            "pt3": "An index on the updated-at column keeps incremental sync "
                   "scans from degrading into full table reads.",
        },
        "queries": [
            ("What component limits how many simultaneous backend connections "
             "the server holds?", "pt1"),
            ("How are long-running queries prevented from monopolizing the "
             "database?", "pt2"),
        ],
    },
    {
        "topic": "identity_trust",
        "docs": {
            "it1": "New peers are enrolled automatically by issuing them a "
                   "signed credential from a first-party authority.",
            "it2": "Each credential carries an attestation level describing how "
                   "strongly the holder's identity was verified.",
            "it3": "Credentials expire and are rotated on a schedule so a "
                   "leaked key has a bounded useful lifetime.",
        },
        "queries": [
            ("How do brand-new nodes join trust without a human provisioning "
             "step?", "it1"),
            ("What bounds the damage if one node's signing key is stolen?",
             "it3"),
        ],
    },
]


def store_once(base_url, namespace, title, content, timeout=120.0):
    body = json.dumps({"title": title, "content": content,
                       "namespace": namespace}).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/api/v1/memories", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def decode_blob(blob, dim):
    # 1 leading tag byte, then `dim` little-endian f32. L2-normalized upstream.
    return struct.unpack("<%df" % dim, blob[1:1 + dim * 4])


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--expect-dim", type=int, required=True)
    ap.add_argument("--arm", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--namespace", default=None)
    args = ap.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ns = args.namespace or f"recall_floor_{args.arm}_{uuid.uuid4().hex[:6]}"
    run = uuid.uuid4().hex[:8]

    # title -> ("doc", doc_id) | ("query", query_idx, relevant_doc_id)
    title_of = {}
    docs = {}        # doc_id -> title
    queries = []     # (title, relevant_doc_id, query_text)

    print(f"[{args.arm}] storing labeled IR set into ns={ns} ...",
          file=sys.stderr, flush=True)
    for t in TOPICS:
        for doc_id, text in t["docs"].items():
            title = f"{run} doc {doc_id}"
            store_once(args.url, ns, title, text)
            title_of[title] = doc_id
            docs[doc_id] = title
        for qi, (qtext, rel) in enumerate(t["queries"]):
            title = f"{run} q {t['topic']} {qi}"
            store_once(args.url, ns, title, qtext)
            queries.append((title, rel, qtext))

    # Let the inline write-path embed settle (it is synchronous, but the row
    # commit + WAL flush can lag the HTTP 201 slightly).
    time.sleep(1.0)

    con = sqlite3.connect(args.db)
    rows = con.execute(
        "SELECT title, embedding, embedding_dim FROM memories "
        "WHERE namespace = ?", (ns,)).fetchall()
    con.close()

    emb = {}
    bad_dim = 0
    for title, blob, ed in rows:
        if ed != args.expect_dim or blob is None:
            bad_dim += 1
            continue
        emb[title] = decode_blob(blob, args.expect_dim)

    doc_ids = list(docs.keys())
    doc_titles = [docs[d] for d in doc_ids]
    missing = [t for t in doc_titles if t not in emb] + \
              [q[0] for q in queries if q[0] not in emb]
    if missing:
        print(f"[{args.arm}] WARNING: {len(missing)} rows missing embeddings",
              file=sys.stderr)

    ks = [1, 3, 5, 10]
    hits = {k: 0 for k in ks}
    rr_sum = 0.0
    n = 0
    per_query = []
    for title, rel, qtext in queries:
        if title not in emb or rel not in docs or docs[rel] not in emb:
            continue
        qv = emb[title]
        scored = sorted(
            ((dot(qv, emb[docs[d]]), d) for d in doc_ids if docs[d] in emb),
            reverse=True)
        ranked = [d for _, d in scored]
        rank = ranked.index(rel) + 1 if rel in ranked else None
        n += 1
        if rank:
            rr_sum += 1.0 / rank
            for k in ks:
                if rank <= k:
                    hits[k] += 1
        per_query.append({
            "query": qtext, "relevant": rel, "rank": rank,
            "top3": ranked[:3],
        })

    metrics = {
        "queries_scored": n,
        "docs": len(doc_ids),
        "recall_at_k": {str(k): round(hits[k] / n, 4) if n else None
                        for k in ks},
        "mrr": round(rr_sum / n, 4) if n else None,
    }

    out = {
        "benchmark": "recall_floor",
        "arm": args.arm,
        "host": "m4-mac-mini-10core-32gb",
        "url": args.url,
        "expect_dim": args.expect_dim,
        "namespace": ns,
        "utc": ts,
        "rows_missing_embedding": len(missing),
        "rows_bad_dim": bad_dim,
        "metrics": metrics,
        "per_query": per_query,
    }
    json_path = f"{args.out_dir}/recall-floor-{args.arm}-{ts}.json"
    with open(json_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"[{args.arm}] dim={args.expect_dim} docs={len(doc_ids)} "
          f"queries={n}", file=sys.stderr)
    print(f"  recall@1={metrics['recall_at_k']['1']} "
          f"@3={metrics['recall_at_k']['3']} "
          f"@5={metrics['recall_at_k']['5']} "
          f"@10={metrics['recall_at_k']['10']}  MRR={metrics['mrr']}",
          file=sys.stderr)
    print(f"wrote {json_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
