#!/usr/bin/env bash
# check-benchmark-claims.sh — HARD-BLOCK any operator-facing doc that
# publishes a KEYWORD-TIER BENCHMARK CELL contradicting the canonical
# binary-faithful LongMemEval source of truth.
#
# Why (CERT GATE — TRUTHFULNESS; #2879 / C-01, follows the #2869
# capacity-claim pattern and the CERT-GATE-2 published-claims set
# #2629/#2492): the final cert vote caught `ROADMAP.md` §9.5 still
# publishing the RETIRED Python-shadow-harness keyword figures — Recall@5
# = 97.0% (485/500) and 232 q/s — while `README.md` §Benchmark had already
# corrected them to the BINARY-FAITHFUL 96.4% (482/500) / 1.2 q/s ("232
# q/s is not a product number"). Gate 4 (docs-vs-SSOT) scans only Rust
# consts; gates 9/10/11 pin symbols / SDK paths / CI-job claims; #2869
# pins agent-count capacity claims — but NOTHING policed a published
# BENCHMARK NUMBER, so a retired-shadow keyword figure could sit in a
# shipped table with every claims gate GREEN. That is the #2444 "reports
# success while doing nothing" shape one axis over.
#
# CANONICAL SOURCE OF TRUTH: `benchmarks/longmemeval/results.md`, the
# `keyword-baseline` binary-faithful row (the `harness.py` shipped-binary
# path — R@1 / R@5 / R@10 / R@20). README §Benchmark cites this file as
# the full per-tier disclosure, so it is the SSOT and this gate parses it
# live rather than hard-coding the recall figures.
#
# WHAT IS CHECKED (aimed at the defect, not its neighbourhood):
#   * Only MARKDOWN TABLE ROWS (lines starting with `|`) — a "cell". A
#     re-worded prose sentence is out of scope; a benchmark CELL is a
#     table cell, and the C-01 defect lives in a table.
#   * Only PURE KEYWORD-TIER rows — the label side names `keyword` AND the
#     row does NOT also name an expansion tier (`expansion` /
#     `llm-expanded` / `smart` / `shadow` / `semantic` / `autonomous`), so
#     the higher LLM-expanded / semantic / autonomous figures are never
#     compared against the keyword canon. ("LLM-independent" is a keyword
#     descriptor and does NOT exclude the row.)
#   * RECALL: every `R@N` / `Recall@N` token (N in 5/10/20) in the row is
#     zipped, in order, with the row's `NN.N%` percentages and each must
#     equal the canonical binary-faithful keyword value for that N.
#   * THROUGHPUT: a keyword row citing `<x> q/s` must equal the
#     binary-faithful keyword throughput (BINARY_FAITHFUL_KEYWORD_QPS =
#     1.2, the `harness.py` shipped-binary row published in README
#     §Benchmark; the retired shadow figure 232 q/s is a 10-core parallel
#     Python FTS5 reimplementation, explicitly "not a product number").
#
# DELIBERATELY NOT FLAGGED:
#   * A RETIREMENT / HISTORICAL note that quotes the retired figure to
#     document its retirement (README's "If the image above shows 97.0%
#     R@5 or 232 q/s … stale render"; ROADMAP §9.5's retirement note) —
#     recognised by markers like "retired", "shadow", "stale render",
#     "not a product number", "#1975", "prior release", evaluated over a
#     +/-1 line window.
#   * Any non-table prose (the "cell" scope).
#   * The LLM-expanded / semantic / autonomous rows (a different canon).
#
# Scope: README.md + ROADMAP.md at the repo root (override the scan root
# with AI_MEMORY_BENCHMARK_DOCS_DIR for --self-test; the CANON is always
# the repo's real results.md). Exit 0 = clean, 1 = a contradicting cell
# (offender printed), 2 = usage / self-test failure, 3 = canon unparsable
# or empty scan (fail-closed).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANON="${AI_MEMORY_BENCHMARK_CANON:-${HERE}/benchmarks/longmemeval/results.md}"
DOCS_DIR="${AI_MEMORY_BENCHMARK_DOCS_DIR:-${HERE}}"

# The scanner. argv[1] = canon results.md, argv[2] = scan root.
# Emits "<relpath>:<lineno>: <reason>" per violation; exit 0 clean,
# 1 violations, 3 canon-unparsable / empty scan (fail-closed).
scan() {
  local canon="$1"
  local root="$2"
  python3 - "$canon" "$root" <<'PY'
import os, re, sys

# The binary-faithful keyword throughput published in README §Benchmark
# (the `harness.py` shipped-binary row: 414 s / 500 q = 1.2 q/s). The
# retired shadow figure 232 q/s never loads the Rust ranker.
BINARY_FAITHFUL_KEYWORD_QPS = 1.2

canon_path, root = sys.argv[1], sys.argv[2]

# Only these two operator-facing docs carry benchmark cells today; scan
# by name so a new doc is added deliberately, not silently.
SCAN_BASENAMES = ("README.md", "ROADMAP.md")

# ---- parse the canonical binary-faithful keyword row ----------------------
# `benchmarks/longmemeval/results.md` binary-faithful table:
#   | 1 | keyword-baseline | `keyword` | ... | 86.6% | 96.4% | 98.4% | 99.4% |
# The last four NN.N% tokens on the keyword-baseline line are R@1/5/10/20.
if not os.path.exists(canon_path):
    print(f"check-benchmark-claims: canon source not found: {canon_path}", file=sys.stderr)
    sys.exit(3)

canon = {}
pct_re = re.compile(r'(\d+\.\d+)%')
for line in open(canon_path, encoding='utf-8'):
    if 'keyword-baseline' in line:
        pcts = [float(x) for x in pct_re.findall(line)]
        if len(pcts) >= 4:
            canon = {1: pcts[-4], 5: pcts[-3], 10: pcts[-2], 20: pcts[-1]}
        break
if not canon:
    print("check-benchmark-claims: could not parse the binary-faithful "
          "keyword-baseline row from the canon results.md — failing CLOSED",
          file=sys.stderr)
    sys.exit(3)

# ---- collect scan files (root-level operator docs only) -------------------
# Deliberately NOT recursive: the benchmark cells live in the top-level
# README.md / ROADMAP.md, and a repo walk would sweep in every sdk/ + docs/
# README.md that carries no LongMemEval table.
files = [os.path.join(root, n) for n in SCAN_BASENAMES
         if os.path.isfile(os.path.join(root, n))]
files.sort()
if not files:
    print("check-benchmark-claims: no benchmark docs scanned (empty scan) — "
          "failing CLOSED", file=sys.stderr)
    sys.exit(3)

# ---- rules ----------------------------------------------------------------
HIST = re.compile(
    r'retired|retirement|shadow|stale render|not a product number'
    r'|previously|historical|python.?shadow|#1975|were retired'
    r'|prior release|at the v|used to (?:say|read|show)', re.I)

# an expansion-tier / non-keyword row uses a different canon
EXPANSION = re.compile(
    r'expansion|llm-expanded|\bsmart\b|shadow|semantic|autonomous', re.I)

K_RE   = re.compile(r'(?:Recall@|R@)(5|10|20)\b', re.I)
QPS_RE = re.compile(r'(\d+(?:\.\d+)?)\s*q/s', re.I)

def approx(a, b):
    return round(a, 1) == round(b, 1)

violations = []

for f in files:
    rel = os.path.relpath(f, root).replace(os.sep, '/')
    try:
        lines = open(f, encoding='utf-8').read().splitlines()
    except (UnicodeDecodeError, OSError):
        continue
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line.startswith('|'):
            continue  # cell = table row only
        window = "\n".join(lines[max(0, i - 1): i + 2])
        if HIST.search(window):
            continue  # retirement / historical note
        low = line.lower()
        if 'keyword' not in low:
            continue
        if EXPANSION.search(line):
            continue  # not a pure keyword row
        # RECALL cells
        ks = [int(m.group(1)) for m in K_RE.finditer(line)]
        if ks:
            pcts = [float(x) for x in pct_re.findall(line)]
            for k, pct in zip(ks, pcts):
                if k in canon and not approx(pct, canon[k]):
                    violations.append(
                        f"{rel}:{i + 1}: keyword R@{k} cell shows {pct:g}% but "
                        f"the binary-faithful canon is {canon[k]:g}% "
                        f"(benchmarks/longmemeval/results.md keyword-baseline)")
        # THROUGHPUT cells
        qm = QPS_RE.search(line)
        if qm:
            q = float(qm.group(1))
            if not approx(q, BINARY_FAITHFUL_KEYWORD_QPS):
                violations.append(
                    f"{rel}:{i + 1}: keyword throughput cell shows {q:g} q/s but "
                    f"the binary-faithful (harness.py) figure is "
                    f"{BINARY_FAITHFUL_KEYWORD_QPS:g} q/s "
                    f"(232 q/s is the retired shadow number — README §Benchmark)")

if violations:
    for v in violations:
        print(v)
    sys.exit(1)
sys.exit(0)
PY
}

# --------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
  tmp="${HERE}/.local-runs/benchmark-claims-selftest.$$"
  cleanup() { rm -rf "$tmp"; }
  trap cleanup EXIT
  mkdir -p "$tmp/bad" "$tmp/good" "$tmp/empty"

  # The self-test judges throwaway docs against the REAL canon results.md,
  # so the planted C-01 contradiction is measured against 96.4 / 98.4 /
  # 99.4 / 1.2 exactly as a live run would be.

  # 1) the exact C-01 contradiction — MUST be flagged (gate exits non-zero).
  #    Retired keyword R@5 97.0%, retired R@10 98.2%, and retired 232 q/s,
  #    planted as LIVE cells (no retirement markers in the window).
  cat > "$tmp/bad/ROADMAP.md" <<'EOF'
### 9.5 LongMemEval

| Metric | Result |
|---|---|
| Recall@5 (keyword, LLM-independent) | **97.0%** (485/500) |
| Recall@10 / Recall@20 (keyword) | 98.2% (491/500) / 99.4% (497/500) |
| Throughput (keyword) | 232 q/s |
EOF
  if scan "$CANON" "$tmp/bad" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate did not catch the C-01 keyword contradiction" >&2
    scan "$CANON" "$tmp/bad" >&2 || true
    exit 2
  fi

  # 2) the honest binary-faithful cells + legit near-misses — MUST all PASS:
  #    corrected keyword cells; the LLM-expanded anchor row (different canon,
  #    higher figures); a retirement note quoting the retired figures; the
  #    semantic-tier row; a keyword TABLE row with no R@ token (header-based).
  cat > "$tmp/good/ROADMAP.md" <<'EOF'
### 9.5 LongMemEval

| Metric | Result |
|---|---|
| Recall@5 (keyword, binary-faithful, LLM-independent) | **96.4%** (482/500) |
| Recall@5 (LLM-expanded anchor, shadow) | **97.2%** (Gemma 4, API venue) |
| Recall@10 / Recall@20 (keyword, binary-faithful) | 98.4% (492/500) / 99.4% (497/500) |
| Recall@10 / Recall@20 (LLM-expanded anchor, shadow) | 99.6% / 99.8% |
| Throughput (keyword, binary-faithful `harness.py`) | 1.2 q/s |
| Throughput (LLM-expanded, shadow `harness_99.py`) | 142 q/s |

Retirement note: the earlier keyword figures 97.0% R@5 (485/500) and 232 q/s
were Python-shadow-harness numbers and are retired.

| Tier | R@5 | Harness |
|---|---|---|
| **keyword** | **96.4%** | binary-faithful |
| **semantic** | **96.8%** | binary-faithful |
EOF
  if ! scan "$CANON" "$tmp/good" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate flagged an honest / anchor / retirement-note / semantic / header-based cell" >&2
    scan "$CANON" "$tmp/good" >&2 || true
    exit 2
  fi

  # 3) empty scan must FAIL CLOSED (rc 3 -> caller treats as failure).
  if scan "$CANON" "$tmp/empty" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate passed on an empty scan (must fail closed)" >&2
    exit 2
  fi

  echo "check-benchmark-claims self-test OK"
  exit 0
fi

rc=0
scan "$CANON" "$DOCS_DIR" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-benchmark-claims: OK (no published keyword benchmark cell contradicts the binary-faithful canon, #2879)"
  exit 0
elif [ "$rc" -eq 3 ]; then
  echo "" >&2
  echo "FAIL (#2879): canon results.md unparsable OR no docs scanned — the gate fails CLOSED rather than green a no-op." >&2
  exit 3
else
  echo "" >&2
  echo "FAIL (#2879): a doc publishes a KEYWORD benchmark cell that contradicts the" >&2
  echo "binary-faithful canonical source (benchmarks/longmemeval/results.md keyword-baseline" >&2
  echo "row + the README §Benchmark 1.2 q/s harness.py throughput). Reconcile the cell to the" >&2
  echo "binary-faithful figure (96.4% R@5 / 98.4% R@10 / 99.4% R@20 / 1.2 q/s), or, for a" >&2
  echo "retired-shadow figure quoted to document its retirement, add a retirement marker to the" >&2
  echo "line's window (\"retired\", \"shadow\", \"not a product number\", \"#1975\")." >&2
  exit 1
fi
