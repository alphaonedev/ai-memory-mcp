#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v0.7.x — pm-v3.1 const/variable NAME-literal lint-gate (operator
# directive 2026-06-10, #1579 remediation train: "make sure no literals
# hard coded in variable or constant names"). Companion to
# scripts/check-hardcoded-literals.sh (duplicated string VALUES) and
# scripts/check-vendor-literals.sh (vendor strings + SECS_PER_* numerics).
#
# WHAT IT BLOCKS: a `const`/`static`/`let` binding whose NAME embeds the
# numeric value it is assigned — e.g.:
#     const BATCH_64: usize = 64;            // -> DEFAULT_DRAIN_BATCH
#     const TIMEOUT_8000_MS: u64 = 8_000;    // -> DEFAULT_QUORUM_TIMEOUT_MS
#     let chunk_500 = 500;                   // -> gc_chunk_rows
# Such names re-hardcode the value in the identifier: when the value is
# tuned, the name silently lies (or every use-site churns). Names must be
# SEMANTIC; the value lives in exactly one place — the initializer.
#
# Deliberately NOT flagged (low-false-positive scope):
#   - values with fewer than 2 digits (V1/V2-style version markers and
#     tiny counts in names are domain terms, not tuned values);
#   - domain-number tokens where the number IS the term, not the value
#     (SHA256, ED25519, FTS5, BASE64, HTTP2, CL100K, ...) — allowlisted
#     in scripts/qc-allowlists/const-name-literals-allow.txt as regexes
#     matched against the IDENTIFIER;
#   - bindings whose initializer contains no numeric literal at all;
#   - comments / doc-comments / string contents (declaration lines only).
#
# RATCHET (same contract as check-hardcoded-literals.sh): pre-existing
# hits at gate-introduction are grandfathered in the baseline file as
# "relpath:identifier" entries scheduled for burn-down (#1579 merge-train
# closes them to EMPTY); any hit NOT in the baseline is a HARD-BLOCK.
# Removing entries never fails; the baseline only shrinks.
#
# Usage:
#   scripts/check-const-name-literals.sh                   # exit 0 clean / 1 hits
#   scripts/check-const-name-literals.sh --update-baseline # regenerate (operator-gated)
#   scripts/check-const-name-literals.sh --self-test       # inject violation,
#                                                          # verify HARD-BLOCK, clean up

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALLOWLIST="${ROOT}/scripts/qc-allowlists/const-name-literals-allow.txt"
BASELINE="${ROOT}/scripts/qc-allowlists/const-name-literals-baseline.txt"

scan () {
    # $1: "check" (apply baseline) or "emit" (print all hits, for baseline
    # regeneration). Python walks src/ + tests/ itself: the program arrives
    # on stdin via the heredoc, so it must NOT also be the data channel (a
    # grep pipe here would be silently swallowed by the heredoc redirection).
    python3 - "${1:-check}" "$ALLOWLIST" "$BASELINE" "$ROOT" "${ROOT}/src" "${ROOT}/tests" <<'PYEOF'
import os, re, sys

mode = sys.argv[1]
allow_path = sys.argv[2]
baseline_path = sys.argv[3]
repo_root = sys.argv[4]
scan_roots = sys.argv[5:]

baseline = set()
if mode == "check":
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw and not raw.startswith("#"):
                    baseline.add(raw)
    except FileNotFoundError:
        pass
allow = []
try:
    with open(allow_path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if raw and not raw.startswith("#"):
                allow.append(re.compile(raw))
except FileNotFoundError:
    pass

decl = re.compile(
    r'^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:const|static|let)(?:\s+mut)?\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*(.*)$'
)
# Numeric literals in the initializer: ints (with _ separators), hex, floats.
numlit = re.compile(r'\b(?:0x[0-9a-fA-F_]+|\d[\d_]*(?:\.\d[\d_]*)?)\b')

failures = 0
for root_dir in scan_roots:
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fname in sorted(filenames):
            if not fname.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for lineno, content in enumerate(lines, start=1):
                # Strip string contents and line comments so quoted or
                # commented digits don't count as initializer literals.
                code = re.sub(r'"(?:\\.|[^"\\])*"', '""', content.rstrip("\n"))
                code = code.split("//")[0]
                dm = decl.match(code)
                if not dm:
                    continue
                name, init = dm.groups()
                if any(rx.search(name) for rx in allow):
                    continue
                flat_name = name.replace("_", "")
                for lit in numlit.findall(init):
                    if lit.lower().startswith("0x"):
                        digits = lit[2:].replace("_", "")
                    else:
                        digits = lit.replace("_", "").split(".")[0]
                    if len(digits) < 2:
                        # single-digit values: V1/V2-style markers, not tuned values
                        continue
                    if digits in flat_name:
                        rel = os.path.relpath(path, repo_root)
                        key = f"{rel}:{name}"
                        if mode == "emit":
                            print(key)
                            break
                        if key in baseline:
                            break  # grandfathered — burn-down scheduled
                        print(
                            f"{path}:{lineno}: name `{name}` embeds its value "
                            f"`{lit}` — rename semantically; the value belongs "
                            f"only in the initializer"
                        )
                        failures += 1
                        break
sys.exit(1 if failures else 0)
PYEOF
}

if [[ "${1:-}" == "--update-baseline" ]]; then
    {
        echo "# const-name-literals grandfathered baseline — burn-down to EMPTY"
        echo "# scheduled in the #1579 merge-train. Entries: relpath:identifier."
        echo "# Regenerate ONLY via --update-baseline (operator-gated)."
        scan emit | sort -u
    } > "$BASELINE"
    echo "baseline regenerated: $(grep -cv '^#' "$BASELINE" || true) entries"
    exit 0
fi

if [[ "${1:-}" == "--self-test" ]]; then
    probe="${ROOT}/src/__name_literal_gate_selftest.rs"
    trap 'rm -f "$probe"' EXIT
    printf 'pub const SELFTEST_TIMEOUT_8000_MS: u64 = 8_000;\n' > "$probe"
    if scan >/dev/null 2>&1; then
        echo "SELF-TEST FAILED: injected value-encoding name was NOT blocked" >&2
        exit 1
    fi
    rm -f "$probe"
    trap - EXIT
    if ! scan >/dev/null; then
        echo "SELF-TEST FAILED: clean tree reported hits" >&2
        exit 1
    fi
    echo "self-test OK: gate is load-bearing"
    exit 0
fi

if scan; then
    echo "const-name-literals: clean"
    exit 0
else
    echo "const-name-literals: HARD-BLOCK — value-encoding identifier name(s) above" >&2
    exit 1
fi
