#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# host-facts.sh -- emit the hardware facts every published throughput number
# must carry (#2921).
#
# docs/enterprise-deployment.md §11.1: "If you need a committed throughput
# figure for a procurement gate, run the measurement and record the host."
# This is that record, in machine-readable form, captured by the same code
# path the producers embed in their own results JSON (`benchlib.host_facts`)
# so the standalone capture and the embedded capture can never drift.
#
# Emits ONLY device nodes and hardware identifiers -- never a filesystem path
# from the operator's home directory, because this output is committed as
# evidence.
#
#   scripts/bench/host-facts.sh            # JSON to stdout
#   scripts/bench/host-facts.sh --check    # non-zero if a required fact is absent
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--check" ]; then
  python3 - "$HERE" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from benchlib import host_facts
f = host_facts()
missing = [k for k in ("cpu_model", "cpu_logical_cores", "mem_total_gib") if not f.get(k)]
if missing:
    print("host-facts: MISSING " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
print("host-facts: OK")
PY
  exit $?
fi

python3 - "$HERE" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1])
from benchlib import host_facts, utc_stamp
print(json.dumps({"captured_at_utc": utc_stamp(), **host_facts()}, indent=2))
PY
