#!/usr/bin/env bash
# check-capacity-claims.sh — HARD-BLOCK any operator-facing doc that publishes
# an AGENT-COUNT / fleet-scale capacity claim above the operator-ratified
# certification ceiling.
#
# Why (CERT GATE — TRUTHFULNESS; #2869, follows the CERT-GATE-2 published-claims
# set #2629/#2492): the 3x7 claims register (`docs/audit/3x7-claims-register-
# 2026-08-01.md`, finding C-12) caught `docs/zero-touch-trust.html` still
# shipping "Scale a federated fleet from 1 to ~1,000,000 AI agents" in BOTH its
# `<meta name="description">` and its page tagline — the exact figure #2438
# RETIRED as three orders of magnitude beyond the documents' own topology
# envelope (T6 = 1000+ agents/mesh, a ~50-peer federation ceiling, and an
# explicit "the peer-to-peer mesh model is the wrong shape past ~50 peers").
# Gate 4 (docs-vs-SSOT) pins VALUES against Rust consts; gates 9/10/11 pin
# symbols / SDK paths / CI-job claims — but NOTHING policed agent-count /
# scale-capacity claims, so this whole class was invisible while every other
# claims gate was GREEN. That is the #2444 "reports success while doing nothing"
# shape one axis over, and the register's diagnosis governs it: "the drift
# direction is consistently toward MORE CLAIMED ENFORCEMENT THAN EXISTS."
#
# The ratified certification scope (#2438) is a **500-1000-agent cluster,
# composed modularly in 500-agent blocks** — scale past one cluster by adding
# independent clusters, never by growing one mesh. So the per-fleet AGENT
# ceiling this gate enforces is 1000 (`AGENT_FLEET_CEILING`). A doc may say
# "hundreds of agents", "500-agent blocks", "500-1000-agent clusters", or
# "compose independent clusters" freely; it may NOT publish a single-fleet
# agent number above the ceiling as a live capacity claim.
#
# WHAT IS DELIBERATELY NOT FLAGGED (aimed at the defect, not its neighbourhood):
#   * A row / record / corpus count. `docs/performance.html`'s "1M+ on
#     Postgres" is a CORPUS-ROW claim ("...on Postgres", no agent noun) and is
#     defensible; `MAX_ROWS = 1,000,000` (the migration row cap) is not an
#     agent count. A big number is a violation ONLY when it sits within 40
#     chars of an `agent(s)` / `AI agents` / `NHI agents` noun on the SAME line
#     AND the line's ±1 window is not a retirement/historical note.
#   * A RETIREMENT NOTE that quotes the retired figure to document its
#     retirement (`docs/federation.md`, `docs/federation-identity.md` both cite
#     #2438) — recognised by markers like "previous revision", "advertised",
#     "retired", "three orders of magnitude", "#2438".
#   * FROZEN doc trees that describe a tree AS IT WAS: `docs/v0.*/`,
#     `docs/audit/` (the register itself quotes the overclaim), `docs/rfc/`,
#     `docs/adr*`, `docs/internal/`, `docs/BASELINE-*`.
#   * A bare 4-digit year (1900-2099) — a date, not a capacity number.
#
# Allowlist for any genuinely-legitimate remaining use:
# `scripts/qc-allowlists/capacity-claims-allow.txt` (`<relpath> <substring>`;
# a MALFORMED entry HARD-FAILS, a STALE entry that no longer matches HARD-FAILS
# — the burn-down discipline, so the ledger cannot rot). Empty is the passing
# state.
#
# Scope: docs/**/*.md + docs/**/*.html (override with AI_MEMORY_CAPACITY_DOCS_DIR
# for --self-test). Exit 0 = clean, 1 = a claim above the ceiling (offender
# printed), 2 = usage / self-test / malformed-allowlist / empty-scan failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS_DIR="${AI_MEMORY_CAPACITY_DOCS_DIR:-${HERE}/docs}"
ALLOWLIST="${AI_MEMORY_CAPACITY_ALLOWLIST:-${HERE}/scripts/qc-allowlists/capacity-claims-allow.txt}"

# The scanner. Reads the allowlist path as argv[1], the scan root as argv[2].
# Emits "<relpath>:<lineno>: <line>" per violation; exit 0 clean, 1 violations,
# 2 malformed/stale allowlist, 3 empty scan (fail-closed).
scan() {
  local root="$1"
  local allow="${2:-$ALLOWLIST}"
  python3 - "$allow" "$root" <<'PY'
import os, re, sys

AGENT_FLEET_CEILING = 1000  # ratified #2438 per-cluster ceiling
allow_path, root = sys.argv[1], sys.argv[2]

FROZEN = ("docs/v0.", "docs/audit/", "docs/rfc/", "docs/adr",
          "docs/internal/", "docs/BASELINE-")

HIST = re.compile(
    r'previous revision|previously published|advertised|retired|no longer'
    r'|used to (?:say|advertise|claim|read)|three orders of magnitude|was three orders'
    r'|#2438|deprecated|formerly|claims correction|no .{0,12}scale certification', re.I)

# The overclaim shape is a magnitude token DIRECTLY quantifying agents:
# "1,000,000 AI agents", "1 to ~1,000,000 agents", "millions of agents",
# "hundreds of thousands to millions of agents". A big number elsewhere on a
# line that merely CONTAINS the word "agent" (a byte quota `104857600` beside
# "per-agent", a row count "1M rows", a context window "1M context") is NOT a
# claim about fleet size and must NOT match — so the magnitude token has to sit
# immediately before the `agents` noun, separated only by short connectors
# (whitespace, `+`, `~`, a dash, `or more`, `to`, `of`, `of the`).
# Each numeric alternative is \b-anchored so a digit-run INSIDE an identifier
# ("Ed25519 agent", "SHA256 agent") is not mistaken for an agent count — the
# only \b in "Ed25519" is at its ends, so `\b\d{4,}\b` cannot latch onto the
# interior "25519".
_MAG = (r'\b\d[\d,_]*\s*M\b'          # 1M / 10M
        r'|\b\d{1,3}(?:[,_]\d{3})+\b'  # 1,000,000
        r'|\b\d{4,}\b'                 # bare >= 1000
        r'|\bmillions?\b'              # word-magnitude
        r'|\bhundreds of thousands\b')
QUANT = re.compile(
    r'(?P<num>' + _MAG + r')'
    r'(?:\s*(?:\+|or more|to|through|[-–—~]|of|of the)\s*)*\s+'
    r'(?:AI |NHI )?agents?\b', re.I)

def magnitude(tok):
    t = tok.strip()
    low = t.lower()
    if low.startswith('million'):
        return 1_000_000, False
    if low.startswith('hundreds of thousands'):
        return 100_000, False
    if low.endswith('m') or low.endswith('M'):
        return int(re.sub(r'[^\d]', '', t)) * 1_000_000, False
    v = int(t.replace(',', '').replace('_', ''))
    is_year = re.fullmatch(r'\d{4}', t) is not None and 1900 <= v <= 2099
    return v, is_year

# ---- load files -----------------------------------------------------------
files = []
for dirpath, _dirs, names in os.walk(root):
    for n in names:
        if n.endswith(('.md', '.html')):
            files.append(os.path.join(dirpath, n))
files.sort()
if not files:
    print("check-capacity-claims: no docs scanned (empty scan) — failing CLOSED", file=sys.stderr)
    sys.exit(3)

# ---- load allowlist (path<space>substring) --------------------------------
allow = []  # (relpath, substring)
if os.path.exists(allow_path):
    for ln in open(allow_path, encoding='utf-8'):
        s = ln.rstrip('\n')
        if not s.strip() or s.lstrip().startswith('#'):
            continue
        parts = s.split(None, 1)
        if len(parts) != 2 or not parts[1].strip():
            print(f"MALFORMED allowlist entry (need '<relpath> <substring>'): {s!r}", file=sys.stderr)
            sys.exit(2)
        allow.append((parts[0], parts[1]))
allow_hit = [False] * len(allow)

violations = []

def relpath(p):
    r = os.path.relpath(p, root)
    # normalise so the FROZEN prefixes + allowlist match against docs/... form
    if not r.startswith('docs' + os.sep) and (os.sep + 'docs' + os.sep) in (os.sep + p):
        i = p.find(os.sep + 'docs' + os.sep)
        if i >= 0:
            r = p[i + 1:]
    return r.replace(os.sep, '/')

for f in files:
    rel = relpath(f)
    if any(rel.startswith(pre) for pre in FROZEN):
        continue
    try:
        lines = open(f, encoding='utf-8').read().splitlines()
    except (UnicodeDecodeError, OSError):
        continue
    for i, line in enumerate(lines):
        window = "\n".join(lines[max(0, i - 1): i + 2])
        if HIST.search(window):
            continue
        for m in QUANT.finditer(line):
            val, is_year = magnitude(m.group('num'))
            if val <= AGENT_FLEET_CEILING or is_year:
                continue
            # allowlist?
            covered = False
            for idx, (ap, asub) in enumerate(allow):
                if rel == ap and asub in line:
                    allow_hit[idx] = True
                    covered = True
                    break
            if covered:
                continue
            violations.append(f"{rel}:{i + 1}: {line.strip()}")
            break  # one report per line is enough

# ---- stale allowlist entries HARD-FAIL (burn-down discipline) --------------
stale = [f"{allow[i][0]} {allow[i][1]}" for i in range(len(allow)) if not allow_hit[i]]
if stale:
    print("STALE allowlist entry (no longer matches any flagged line — remove it):", file=sys.stderr)
    for s in stale:
        print(f"  {s}", file=sys.stderr)
    sys.exit(2)

if violations:
    for v in violations:
        print(v)
    sys.exit(1)
sys.exit(0)
PY
}

# --------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
  tmp="${HERE}/.local-runs/capacity-claims-selftest.$$"
  cleanup() { rm -rf "$tmp"; }
  trap cleanup EXIT
  mkdir -p "$tmp/docs"

  # scan() takes the allowlist as its 2nd arg; the self-test uses an empty one
  # (/dev/null) so the throwaway corpus is judged on the detection rules alone,
  # never against the production allowlist.
  mkdir -p "$tmp/bad" "$tmp/good" "$tmp/empty"

  # 1) the exact #2438 overclaim — MUST be flagged (gate exits non-zero).
  printf '%s\n' '<p class="tagline">Scale a federated fleet from 1 to ~1,000,000 AI agents.</p>' > "$tmp/bad/bad.html"
  if scan "$tmp/bad" /dev/null >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate did not catch the 1,000,000-agent overclaim" >&2
    exit 2
  fi

  # 2) the honest fixed claim + legit near-misses — MUST all PASS:
  #    honest envelope; corpus-row "1M+ on Postgres"; the MAX_ROWS row cap; a
  #    retirement note that quotes the retired figure; a bare year; and an
  #    identifier ("Ed25519 agent") whose interior digit-run must not be read
  #    as an agent count.
  cat > "$tmp/good/good.html" <<'EOF'
<p>Scale a federated fleet of hundreds of AI agents (certified: 500-1000-agent
clusters, composed modularly in 500-agent blocks) - see #2438.</p>
<p><strong>1M+ on Postgres</strong> - supported via SAL (a corpus-row count).</p>
<p>The migrator reads one page capped at 1,000,000 rows (MAX_ROWS).</p>
<p>A previous revision advertised "1 to ~1,000,000 AI agents" - three orders of
magnitude beyond the envelope; retired per #2438.</p>
<p>Released in 2026 for AI agents everywhere; enroll Ed25519 agent identities.</p>
EOF
  if ! scan "$tmp/good" /dev/null >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate flagged an honest / corpus-row / retirement-note / year / identifier line" >&2
    scan "$tmp/good" /dev/null >&2 || true
    exit 2
  fi

  # 3) the allowlist must EXEMPT a vetted line (gate PASSES), and a STALE entry
  #    that matches nothing must HARD-FAIL (rc 2) — the burn-down discipline.
  mkdir -p "$tmp/vision"
  printf '%s\n' '<p>The north star: hundreds of thousands to millions of agents.</p>' > "$tmp/vision/vision.html"
  printf '%s\n' 'vision.html millions of agents' > "$tmp/allow.txt"
  if ! scan "$tmp/vision" "$tmp/allow.txt" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: a matching allowlist entry did not exempt a vetted line" >&2
    exit 2
  fi
  printf '%s\n' 'vision.html this-substring-matches-nothing' > "$tmp/stale.txt"
  strc=0; scan "$tmp/vision" "$tmp/stale.txt" >/dev/null 2>&1 || strc=$?
  if [ "$strc" -ne 2 ]; then
    echo "SELF-TEST FAIL: a stale allowlist entry did not hard-fail (burn-down discipline)" >&2
    exit 2
  fi

  # 4) empty scan must FAIL CLOSED (rc 3 -> the caller treats it as failure).
  if scan "$tmp/empty" /dev/null >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: gate passed on an empty scan (must fail closed)" >&2
    exit 2
  fi

  echo "check-capacity-claims self-test OK"
  exit 0
fi

rc=0
scan "$DOCS_DIR" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-capacity-claims: OK (no agent-count capacity claim exceeds the ratified 500-1000-agent envelope, #2438)"
  exit 0
elif [ "$rc" -eq 3 ]; then
  echo "" >&2
  echo "FAIL (#2869): no docs were scanned — the gate fails CLOSED rather than green a no-op." >&2
  exit 2
elif [ "$rc" -eq 2 ]; then
  echo "" >&2
  echo "FAIL (#2869): malformed or stale entry in ${ALLOWLIST}." >&2
  exit 2
else
  echo "" >&2
  echo "FAIL (#2869): a doc publishes an AGENT-COUNT capacity claim above the ratified" >&2
  echo "500-1000-agent cluster ceiling (#2438). Replace the number with the honest" >&2
  echo "certified envelope (e.g. \"a fleet of hundreds of agents; certified 500-1000-agent" >&2
  echo "clusters composed in 500-agent blocks\"), or — for a genuine history/corpus-row use" >&2
  echo "the structural exemptions miss — add a line to ${ALLOWLIST}." >&2
  exit 1
fi
