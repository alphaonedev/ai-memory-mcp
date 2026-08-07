#cloud-config
# Track E1 / #2438 -- load-generator droplet bootstrap. Templated by main.tf
# when var.agent_workload == "loadgen" (measurement.tfvars). This is the
# capacity-measurement sibling of cloud-init-agent.yaml.tpl: it installs
# curl + python3 ONLY -- NO IronClaw, NO XAI key, NO LLM inference bill --
# and drops the measure-envelope.sh op-mix worker loop as
# /opt/loadgen/worker.sh, pointed at the substrate at ${memory_private_ip}:9077.
#
# The offered concurrency (worker count) is a RUNTIME knob, not a provision-time
# one, because the #2438 capacity ramp sweeps it (8..512). The orchestrator's
# infra/pillar4-envelope/measure-capacity-ramp.sh drives run-workers.sh over SSH
# with LOADGEN_WORKERS=<n> per step. The systemd unit below is a DISABLED
# convenience for a single fixed-concurrency smoke; it mirrors the agent
# template's "not enabled by default" discipline and is never what the ramp uses.
#
# ASCII-ONLY (the #1880 check-cloud-init-ascii.sh gate covers infra/do-hive/*.tpl:
# a stray non-ASCII byte makes cloud-init silently discard the config and boot a
# BARE droplet). All embedded bash uses unbraced shell vars only (the same
# discipline cloud-init-memory.yaml.tpl provision.sh uses) so bash expansions
# never collide with Terraform interpolation and no escaping is needed. The only
# Terraform-interpolated tokens here are the substrate private IP and the agent
# index (rendered by main.tf's templatefile call).
package_update: true
packages:
  - curl
  - python3
write_files:
  - path: /opt/loadgen/worker.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # One worker == one simulated agent doing the canonical op mix
      # (store -> link(prev->cur) -> recall) against the substrate HTTP surface,
      # byte-for-byte the same loop as infra/pillar4-envelope/measure-envelope.sh
      # so the numbers are comparable to the already-populated envelope cells.
      # Args: WID OUT DEADLINE BASE  (BASE ends in /api/v1). Appends one
      # "op http_code wall_ms" line per request to OUT.
      set -u
      WID="$1"; OUT="$2"; DEADLINE="$3"; BASE="$4"
      BODYF="$OUT.body"
      now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
      n=0; prev_id=""
      while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        n=$((n+1))
        agent="env-w$WID"
        title="w$WID-m$n"
        # store (capture the created id so the link op has a real edge to write)
        t0=$(now_ms)
        code=$(curl -s -o "$BODYF" -w '%%{http_code}' -X POST "$BASE/memories" \
          -H 'content-type: application/json' -H "x-agent-id: $agent" \
          -d "{\"title\":\"$title\",\"content\":\"envelope load $title\",\"namespace\":\"envelope\",\"tier\":\"short\"}" 2>/dev/null || echo "000")
        t1=$(now_ms)
        echo "store $code $((t1-t0))" >> "$OUT"
        cur_id=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("id",""))
except Exception: print("")' "$BODYF" 2>/dev/null || echo "")
        # link prev->cur -- exercises the AGE graph write path (the real
        # per-module throughput bound; PgBouncer fixes fan-in, NOT AGE writes).
        if [ -n "$prev_id" ] && [ -n "$cur_id" ]; then
          t0=$(now_ms)
          code=$(curl -s -o /dev/null -w '%%{http_code}' -X POST "$BASE/links" \
            -H 'content-type: application/json' -H "x-agent-id: $agent" \
            -d "{\"source_id\":\"$prev_id\",\"target_id\":\"$cur_id\",\"relation\":\"related_to\"}" 2>/dev/null || echo "000")
          t1=$(now_ms)
          echo "link $code $((t1-t0))" >> "$OUT"
        fi
        [ -n "$cur_id" ] && prev_id="$cur_id"
        # recall (read path; FTS + reranker)
        t0=$(now_ms)
        code=$(curl -s -o /dev/null -w '%%{http_code}' "$BASE/recall?q=envelope&namespace=envelope&limit=5" \
          -H "x-agent-id: $agent" 2>/dev/null || echo "000")
        t1=$(now_ms)
        echo "recall $code $((t1-t0))" >> "$OUT"
      done
      rm -f "$BODYF"
  - path: /opt/loadgen/run-workers.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # Per-droplet load unit: spawn LOADGEN_WORKERS concurrent worker.sh loops
      # for STEP_DURATION_SECS against AI_MEMORY_HTTP, then aggregate and print
      # ONE JSON object to stdout (the measure-capacity-ramp.sh driver captures
      # it per droplet). The aggregation reducer is the SAME one as
      # measure-envelope.sh (p50/p95/p99 + 503 shed-rate), extended with a
      # per-op-class ops/s throughput column (count / wall) -- the #2438 add.
      # No `set -u`: env knobs may be unset and are defaulted brace-free (a bash
      # colon-dash default would use braces, which collide with Terraform
      # interpolation, so this file never uses brace expansions -- header note).
      HTTP="$AI_MEMORY_HTTP"; [ -z "$HTTP" ] && HTTP="http://127.0.0.1:9077"
      WORKERS="$LOADGEN_WORKERS"; [ -z "$WORKERS" ] && WORKERS="8"
      DUR="$STEP_DURATION_SECS"; [ -z "$DUR" ] && DUR="20"
      OUTDIR="$LOADGEN_OUT"; [ -z "$OUTDIR" ] && OUTDIR="/opt/loadgen/run-$$"
      BASE="$HTTP/api/v1"
      mkdir -p "$OUTDIR"
      start=$(date +%s)
      deadline=$((start + DUR))
      w=1
      while [ "$w" -le "$WORKERS" ]; do
        /opt/loadgen/worker.sh "$w" "$OUTDIR/w$w.txt" "$deadline" "$BASE" &
        w=$((w+1))
      done
      wait
      wall=$(( $(date +%s) - start ))
      [ "$wall" -lt 1 ] && wall=1
      cat "$OUTDIR"/w*.txt 2>/dev/null | AGG_WALL="$wall" AGG_WORKERS="$WORKERS" python3 -c '
import sys, os, json
wall = float(os.environ.get("AGG_WALL", "1")) or 1.0
workers = int(os.environ.get("AGG_WORKERS", "0"))
ops = {}
tot = 0; shed = 0
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 3:
        continue
    op, code, ms = parts
    tot += 1
    if code == "503":
        shed += 1
    d = ops.setdefault(op, {"lat": [], "count": 0})
    d["count"] += 1
    try:
        d["lat"].append(int(ms))
    except ValueError:
        pass
def pct(lat, p):
    if not lat:
        return 0
    s = sorted(lat)
    i = min(len(s) - 1, int(p / 100.0 * len(s)))
    return s[i]
out = {"workers": workers, "wall_secs": wall, "reqs": tot,
       "shed": shed, "shed_rate": round((shed / tot) if tot else 0.0, 6), "ops": {}}
for op, d in ops.items():
    out["ops"][op] = {
        "count": d["count"],
        "ops_per_s": round(d["count"] / wall, 4),
        "p50_ms": pct(d["lat"], 50),
        "p95_ms": pct(d["lat"], 95),
        "p99_ms": pct(d["lat"], 99),
    }
print(json.dumps(out))
'
      rm -rf "$OUTDIR"
  - path: /etc/systemd/system/loadgen.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ai-memory load generator #${agent_index} (#2438 capacity measurement)
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=oneshot
      User=loadgen
      Group=loadgen
      # Substrate HTTP surface (private VPC IP). No inference; no XAI key.
      Environment=AI_MEMORY_HTTP=http://${memory_private_ip}:9077
      # Default offered concurrency for a single fixed-concurrency smoke. The
      # #2438 ramp OVERRIDES this by invoking run-workers.sh over SSH per step.
      Environment=LOADGEN_WORKERS=8
      Environment=STEP_DURATION_SECS=20
      ExecStart=/opt/loadgen/run-workers.sh

      [Install]
      WantedBy=multi-user.target
runcmd:
  - useradd -m -d /opt/loadgen -s /bin/bash loadgen || true
  - mkdir -p /opt/loadgen
  - chown -R loadgen:loadgen /opt/loadgen
  - chmod 0755 /opt/loadgen/worker.sh /opt/loadgen/run-workers.sh
  - systemctl daemon-reload
  # Service is NOT enabled by default -- the orchestrator drives the ramp via
  # infra/pillar4-envelope/measure-capacity-ramp.sh over SSH (per-step
  # LOADGEN_WORKERS), NOT via this unit. Mirrors the agent template discipline.
