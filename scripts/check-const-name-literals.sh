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
# MATCHING IS SEGMENT-AWARE (#3121): a value counts as embedded only when
# it equals a whole `_`-delimited name segment (or the whole identifier),
# or is the digit run of an otherwise alphabetic segment (`chunk500`) —
# never an arbitrary substring, which used to match the hex byte `0xad`
# inside the identifier `payload_hash` (its "paylo-AD" tail).
#
# Deliberately NOT flagged (low-false-positive scope):
#   - values with fewer than 2 digits (V1/V2-style version markers and
#     tiny counts in names are domain terms, not tuned values);
#   - hex literals of fewer than 3 hex digits: a byte value (0xde, 0xad)
#     is far too short to be a value-encoding name;
#   - hex values that span consecutive `_` segments (`MAGIC_DEAD_BEEF` =
#     `0xdeadbeef`) ARE flagged (concatenated whole segments); a substring
#     inside one word still is not;
#   - semantic width names (`zero32`, `buf64`, `key256`) live in the
#     allowlist as exact identifier regexes — not a fused `<alpha><width>`
#     matcher, which would also exempt `POOL_SIZE256 = 256` (#3122);
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
#   scripts/check-const-name-literals.sh --self-test       # inject violations
#                                                          # + known-good names,
#                                                          # verify HARD-BLOCK /
#                                                          # no-false-positive, clean up

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
# A `_`-delimited name segment split into optional alphabetic stem, digit
# run, optional alphabetic tail: `8000`, `chunk500`, `500ms`.
seg_split = re.compile(r'([A-Za-z]*)([0-9]+)([A-Za-z]*)')


def encodes_value(name, digits, is_hex):
    """Does the identifier `name` re-encode the literal value `digits`?

    SEGMENT-AWARE (#3121): the value must equal a whole `_`-delimited
    segment (or the whole identifier), or be the digit run of an otherwise
    alphabetic segment — never an arbitrary substring. The previous
    `digits in name.replace("_", "")` test matched the hex byte `0xad`
    inside `paylo{ad}_hash`.

    Hex (#3122 follow-up): also match a span of consecutive whole
    segments whose concatenation equals the digits (`MAGIC_DEAD_BEEF`
    vs `0xdeadbeef`). A substring inside one word still does not match.
    """
    want = digits.lower()
    segs = [s.lower() for s in name.split("_") if s]
    for i, seg in enumerate(segs):
        if seg == want:
            return True
        if is_hex:
            acc = seg
            for nxt in segs[i + 1 :]:
                acc += nxt
                if acc == want:
                    return True
                if len(acc) > len(want):
                    break
            continue
        m = seg_split.fullmatch(seg)
        if m is None or m.group(2) != want:
            continue
        return True
    return False

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
                for lit in numlit.findall(init):
                    is_hex = lit.lower().startswith("0x")
                    if is_hex:
                        digits = lit[2:].replace("_", "")
                    else:
                        digits = lit.replace("_", "").split(".")[0]
                    if len(digits) < 2:
                        # single-digit values: V1/V2-style markers, not tuned values
                        continue
                    if is_hex and len(digits) < 3:
                        # two-hex-digit byte values (0xde, 0xad) are far too
                        # short to be a value-encoding name (#3121)
                        continue
                    if encodes_value(name, digits, is_hex):
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
    # The probe is never compiled (no `mod` declares it); it exists only as
    # a line the scanner must read. Each case is probed on its own so one
    # shape can never mask another.
    probe="${ROOT}/src/__name_literal_gate_selftest.rs"
    trap 'rm -f "$probe"' EXIT
    st_rc=0

    # (a) TRUE POSITIVES — the gate must still HARD-BLOCK every one.
    while IFS= read -r probe_line; do
        [[ -z "$probe_line" ]] && continue
        printf '%s\n' "$probe_line" > "$probe"
        if scan >/dev/null 2>&1; then
            echo "SELF-TEST FAILED: value-encoding name NOT blocked: ${probe_line}" >&2
            st_rc=1
        fi
    done <<'SELFTEST_POSITIVE'
pub const SELFTEST_TIMEOUT_8000_MS: u64 = 8_000;
pub const SELFTEST_CHUNK500: usize = 500;
pub const SELFTEST_MAGIC_DEADBEEF: u32 = 0xdead_beef;
pub const SELFTEST_MAGIC_DEAD_BEEF: u32 = 0xdeadbeef;
pub const SELFTEST_POOL_SIZE256: usize = 256;
let selftest_chunk_500 = 500;
SELFTEST_POSITIVE

    # (b) FALSE POSITIVES from #3121 — the gate must NOT flag any of these.
    while IFS= read -r probe_line; do
        [[ -z "$probe_line" ]] && continue
        printf 'fn __selftest() {\n%s\n}\n' "$probe_line" > "$probe"
        if ! scan >/dev/null 2>&1; then
            echo "SELF-TEST FAILED: false positive on: ${probe_line}" >&2
            st_rc=1
        fi
    done <<'SELFTEST_NEGATIVE'
    let payload_hash = vec![0xde, 0xad, 0xbe, 0xef, 0x10, 0x46];
    let zero32 = [0u8; 32];
    let buf64 = [0u8; 64];
    let key256 = [0u8; 256];
SELFTEST_NEGATIVE

    rm -f "$probe"
    trap - EXIT
    if [[ "$st_rc" -ne 0 ]]; then
        exit 1
    fi
    if ! scan >/dev/null; then
        echo "SELF-TEST FAILED: clean tree reported hits" >&2
        exit 1
    fi
    echo "self-test OK: gate is load-bearing and free of the #3121 false positives"
    exit 0
fi

if scan; then
    echo "const-name-literals: clean"
    exit 0
else
    echo "const-name-literals: HARD-BLOCK — value-encoding identifier name(s) above" >&2
    exit 1
fi
