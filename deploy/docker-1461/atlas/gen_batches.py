#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Atlas Corpus batch generator for the docker-1461 ingest harness.
#
# Reads a JSONL corpus and emits batch-NNNN.json arrays of CreateMemory bodies
# under $BATCH_DIR, ready to POST to /api/v1/memories/bulk. Dedups by
# (title, namespace) keeping the LAST occurrence so a single multi-row INSERT
# never hits two identical ON CONFLICT (title, namespace) targets (postgres
# errors "cannot affect row a second time" otherwise). Remaps source ->
# $ATLAS_SOURCE (wire-valid) and preserves the original under
# metadata.atlas_source; pins on_conflict=merge for idempotent re-runs.
#
# Prints "<unique> <total> <dropped>" on stdout. Env inputs:
#   ATLAS_CORPUS  path to the JSONL corpus
#   ATLAS_NS      fallback namespace when a record omits one
#   BATCH_DIR     output dir for batch-*.json
#   BATCH_SIZE    max rows per batch (<= server max_page_size)
#   ATLAS_SOURCE  wire-valid source string to stamp on every row
import json
import os

corpus = os.environ["ATLAS_CORPUS"]
ns_force = os.environ["ATLAS_NS"]
batch_dir = os.environ["BATCH_DIR"]
batch_size = int(os.environ["BATCH_SIZE"])
src = os.environ["ATLAS_SOURCE"]

total = 0
dedup = {}  # (title, namespace) -> CreateMemory dict (last wins)
with open(corpus) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        total += 1
        r = json.loads(line)
        ns = r.get("namespace") or ns_force
        title = r["title"]
        meta = r.get("metadata") or {}
        if isinstance(meta, dict) and r.get("source"):
            meta = dict(meta)
            meta["atlas_source"] = r["source"]
        body = {
            "title": title,
            "content": r["content"],
            "namespace": ns,
            "scope": r.get("scope", "collective"),
            "tier": r.get("tier", "mid"),
            "tags": r.get("tags", []),
            "kind": r.get("kind"),
            "source": src,
            "metadata": meta,
            "on_conflict": "merge",
        }
        su = r.get("source_uri")
        if su:
            # The substrate's source_uri contract (validate_source_uri) requires
            # a scheme prefix: uri: (absolute URL), doc: (substrate doc id), or
            # file: (path). The corpus carries bare https:// video URLs, so wrap
            # any unschemed value as uri:<url>. Already-schemed values pass through.
            if not su.startswith(("uri:", "doc:", "file:")):
                su = "uri:" + su
            body["source_uri"] = su
        dedup[(title, ns)] = body

rows = list(dedup.values())
b = 0
for i in range(0, len(rows), batch_size):
    with open(os.path.join(batch_dir, "batch-%04d.json" % b), "w") as out:
        json.dump(rows[i:i + batch_size], out)
    b += 1
print("%d %d %d" % (len(rows), total, total - len(rows)))
