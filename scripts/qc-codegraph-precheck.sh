#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# C8 orchestrator safeguard (per CLAUDE.md §"Enforceable Orchestrator
# Safeguards", added under #923 + #953). HARD-BLOCK any new
# `CallerContext::for_agent("<literal>")` site outside the allowlist,
# and any new `CallerContext::for_admin("<literal>")` privacy-bypass
# site outside its allowlist.
#
# Usage:
#   scripts/qc-codegraph-precheck.sh            # check (exit 1 on violation)
#   scripts/qc-codegraph-precheck.sh --update   # regenerate allowlists from current state
#
# What it checks:
#   - Every line in src/ matching `CallerContext::for_agent("<lit>")`
#     OR `for_agent("<lit>")` where the literal is a static string
#     (not a variable reference). Test code is excluded — see
#     `is_production_site` below.
#   - Same scan for `for_admin("<lit>")`.
#   - Each surviving site must appear in the corresponding allowlist.
#
# What it deliberately does NOT do (out of scope for v0.7.0):
#   - Symbol removal / dangling-caller detection. Codegraph indexes
#     are per-developer and not available in CI; this script uses
#     `grep` as the load-bearing detector. The deeper codegraph
#     integration is tracked separately and can layer on top of the
#     allowlist contract this script enforces.
#
# Why grep (not codegraph): CodeGraph indexes live under .codegraph/
# (gitignored, per-developer; not in CI). For a CI-grade pre-PR gate
# we need a tool every checkout already has. `grep` is sufficient for
# the literal-site enumeration; the rest of the C8 contract (rationale
# for each site) lives in the allowlist files' comments.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "${ROOT}/scripts/lib/production-lines.sh"
ALLOW_DIR="${ROOT}/scripts/qc-codegraph-allowlists"
ALLOW_FOR_AGENT="${ALLOW_DIR}/caller-context-literals.txt"
ALLOW_FOR_ADMIN="${ALLOW_DIR}/for-admin-bypass.txt"

if [[ ! -d "${ALLOW_DIR}" ]]; then
    echo "ERROR: allowlist dir missing: ${ALLOW_DIR}" >&2
    exit 2
fi

UPDATE=0
if [[ "${1:-}" == "--update" ]]; then
    UPDATE=1
fi

# --self-test (#1651): prove the for_admin detector is load-bearing for
# the SENTINEL-CONST call form (the #1558 refactor moved every
# production site off string literals, which silently collapsed the
# literal-only detector's coverage to zero). Injects a transient
# production file containing a sentinel-form for_admin call, expects
# the main check to HARD-BLOCK, then cleans up.
if [[ "${1:-}" == "--self-test" ]]; then
    # The load-bearing DETECTOR probes (#1651 for_admin, #3943
    # for_admin_checked) run FIRST so a failure in the #3623 scenario harness
    # below cannot stop them from running. The harness runs LAST, so its status
    # is the self-test's exit while the detector probes stay reachable.
    PROBE="${ROOT}/src/c8_probe_1651.rs"
    trap 'rm -f "${PROBE}"' EXIT
    cat > "${PROBE}" <<'PROBE_EOF'
// C8 --self-test probe (transient; created + removed by qc-codegraph-precheck.sh --self-test)
pub fn probe() {
    let _ = CallerContext::for_admin(sentinels::C8_SELF_TEST_PROBE);
}
PROBE_EOF
    if "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL: sentinel-form for_admin injection was NOT detected" >&2
        exit 1
    fi
    echo "C8 SELF-TEST PASS: sentinel-form for_admin injection HARD-BLOCKed as expected"
    rm -f "${PROBE}"

    # #3943 — prove the literal-second-argument detector is load-bearing. One
    # known-POSITIVE (a production literal, the quarantine.rs:182 shape with
    # inner parens in arg 1) must HARD-BLOCK; three known-NEGATIVES must PASS —
    # they are the exact false-positive classes f2r measured in the pre-review:
    # the gate's own threaded shape, a #[cfg(test)] literal, and a comment.
    PROBE3943="${ROOT}/src/c8_probe_3943.rs"
    trap 'rm -f "${PROBE}" "${PROBE3943}"' EXIT

    # known-POSITIVE — must be DETECTED (bare "$0" must exit non-zero).
    cat > "${PROBE3943}" <<'PROBE3943_EOF'
// C8 #3943 self-test probe (transient; created + removed by --self-test)
pub fn probe() {
    let ctx = crate::store::CallerContext::for_admin_checked(caller.clone(), true);
    let _ = ctx;
}
PROBE3943_EOF
    if "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL (#3943): production for_admin_checked(.., true) was NOT detected" >&2
        exit 1
    fi

    # known-NEGATIVE 1 — the blessed swarm_rewind shape: the second argument is
    # the gate result, not a literal. Must PASS.
    cat > "${PROBE3943}" <<'PROBE3943_EOF'
// C8 #3943 self-test probe (transient)
pub fn probe() {
    let (caller, is_admin) = match require_admin() {
        Ok(c) => (c, true),
        Err(resp) => return resp,
    };
    let ctx = crate::store::CallerContext::for_admin_checked(caller, is_admin);
    let _ = ctx;
}
PROBE3943_EOF
    if ! "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL (#3943): threaded for_admin_checked(caller, is_admin) was flagged" >&2
        exit 1
    fi

    # known-NEGATIVE 2 — a literal inside #[cfg(test)] (production_lines blanks
    # it, mirroring store/mod.rs:7774, the #1062 constructor coverage test).
    cat > "${PROBE3943}" <<'PROBE3943_EOF'
// C8 #3943 self-test probe (transient)
#[cfg(test)]
mod tests {
    fn cov() {
        let _ = crate::store::CallerContext::for_admin_checked("ops:admin", true);
    }
}
PROBE3943_EOF
    if ! "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL (#3943): a #[cfg(test)] for_admin_checked(.., true) was flagged" >&2
        exit 1
    fi

    # known-NEGATIVE 3 — a COMMENT that spells the pattern (store/mod.rs:7772).
    cat > "${PROBE3943}" <<'PROBE3943_EOF'
// C8 #3943 self-test probe (transient)
// for_admin_checked(.., true) yields a bypass-visibility admin ctx; pins #1062.
pub fn probe() {}
PROBE3943_EOF
    if ! "$0" >/dev/null 2>&1; then
        echo "C8 SELF-TEST FAIL (#3943): a COMMENT spelling for_admin_checked(.., true) was flagged" >&2
        exit 1
    fi

    rm -f "${PROBE3943}"
    echo "C8 SELF-TEST PASS (#3943): production literal second-arg HARD-BLOCKed; threaded / #[cfg(test)] / comment forms accepted"

    # #3623 production-boundary scenario harness runs LAST (see the note at the
    # top of this block). Its exit status is the self-test's. Its #5884 cases
    # pin the GOVERNANCE_INTERNAL exemption (content, enclosing function,
    # exactly one site) with fixtures built from the constants above.
    set +e
    python3 "${ROOT}/scripts/tests/gate-production-3623.py" "$(basename "$0")"
    harness_rc=$?
    set -e
    exit "${harness_rc}"
fi

# #5884 — the one #3638-adjudicated for_admin(GOVERNANCE_INTERNAL) site is
# exempt by CONTENT: file, the exact source line, and the function that encloses
# it. No line number is pinned (a pin goes stale on every edit above it and then
# silently stops matching). Closed world: the exemption applies only when the
# file holds EXACTLY ONE copy of the line and that copy sits inside the anchor
# function. Zero copies (moved or reworded), two or more (duplicated), or a copy
# in another function is a HARD-BLOCK that names the file and the count; the
# site is then not exempt. scripts/tests/gate-production-3623.py reads these
# three constants from this file so the fixtures cannot drift from the gate.
C8_EXEMPT_FILE='src/store/postgres.rs'
C8_EXEMPT_FN='resolve_governance_policy'
C8_EXEMPT_LINE='            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);'
C8_EXEMPT_LINENO=""
C8_EXEMPT_ERR=""

exempt_precheck () {
    local f="${ROOT}/${C8_EXEMPT_FILE}"
    [[ -f "${f}" ]] || return 0
    local res count lineno fn
    res="$(production_lines "$f" | EXEMPT_LINE="${C8_EXEMPT_LINE}" "${AWK_BIN:-awk}" '
        /^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+[A-Za-z_]/ {
            t = $0
            sub(/^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+/, "", t)
            match(t, /^[A-Za-z0-9_]+/)
            cur = substr(t, 1, RLENGTH)
        }
        $0 == ENVIRON["EXEMPT_LINE"] { n++; ln = NR; fn = cur }
        END { printf "%d %d %s\n", n + 0, ln + 0, fn }')"
    read -r count lineno fn <<< "${res}"
    if [[ "${count}" != "1" ]]; then
        C8_EXEMPT_ERR="exemption for ${C8_EXEMPT_FILE} needs exactly 1 match of the pinned line, found ${count}"
    elif [[ "${fn}" != "${C8_EXEMPT_FN}" ]]; then
        C8_EXEMPT_ERR="exemption for ${C8_EXEMPT_FILE} needs exactly 1 match inside fn ${C8_EXEMPT_FN}, found ${count} (inside fn ${fn:-none})"
    else
        C8_EXEMPT_LINENO="${lineno}"
    fi
}
exempt_precheck

# Enumerate production sites through the shared #3623 item filter.
collect_sites () {
    local pattern="$1"
    local mode="${2:-literal}"
    local out=""
    # Find src files; production_lines applies the test exclusions.
    while IFS= read -r -d '' f; do
        local production
        production="$(production_lines "$f")"
        # Find matching lines with original source line numbers.
        # Pattern format: `for_agent("LIT")` or `for_admin("LIT")`.
        #
        # NOTE: the inner match list is captured into a variable and fed
        # to the loop via a here-string (`<<<`) rather than a second
        # process substitution. A process substitution nested inside the
        # outer `< <(find ...)` one reliably SIGTRAPs (exit 133) under
        # macOS system bash 3.2 on arm64; the here-string is behaviour-
        # identical and runs the loop in the current shell so `out`
        # still accumulates.
        local matches
        if [[ "${mode}" == "any-arg" ]]; then
            # #1651 — for_admin is a privacy-bypass CONSTRUCTION; the
            # bypass is the call itself, in ANY argument form. The
            # pre-#1651 literal-only grep went blind when #1558 moved
            # every site onto sentinel consts.
            matches="$(printf '%s\n' "$production" | grep -n "${pattern}(" || true)"
        else
            matches="$(printf '%s\n' "$production" | grep -n "${pattern}(\"" || true)"
        fi
        [[ -z "${matches}" ]] && continue
        while IFS=: read -r lineno content; do
            # Skip blank/no-match
            [[ -z "${lineno}" ]] && continue
            # Skip comment lines (//, ///, block-comment continuations) —
            # prose mentioning the call is not a call site (#1651).
            if printf '%s\n' "$content" | grep -qE '^[[:space:]]*(//|\*)'; then
                continue
            fi
            # Extract the literal between `${pattern}("` and `")`.
            local literal
            literal=$(printf '%s\n' "$content" | sed -nE "s/.*${pattern}\(\"([^\"]+)\"\).*/\1/p" | head -1)
            if [[ -z "${literal}" && "${mode}" == "any-arg" ]]; then
                # #1651 — non-literal argument: key on the argument
                # expression (identifier / sentinel path / variable),
                # normalized to its last `::` segment so the allowlist
                # stays stable across import-style refactors.
                literal=$(printf '%s\n' "$content" \
                    | sed -nE "s/.*${pattern}\(([^\")(,]+)[,)].*/\1/p" \
                    | head -1 | tr -d ' &')
                if [[ -z "${literal}" ]] \
                    && printf '%s\n' "$content" | grep -qE "${pattern}\($"; then
                    # Call split across lines (rustfmt reflow): take
                    # the first token of the next source line.
                    local nextline
                    nextline=$(sed -n "$((lineno + 1))p" "$f")
                    literal=$(printf '%s\n' "$nextline" | sed -nE 's/^[[:space:]]*"([^"]+)".*/\1/p')
                    [[ -z "${literal}" ]] && literal=$(printf '%s\n' "$nextline" \
                        | sed -nE 's/^[[:space:]]*([A-Za-z0-9_:&]+).*/\1/p' | tr -d '&')
                fi
                literal="${literal##*::}"
            fi
            if [[ -n "${literal}" ]]; then
                # Strip the absolute prefix so the allowlist is
                # repo-root-relative (and stable across checkouts).
                local rel="${f#"${ROOT}/"}"
                # #3623 Conductor ruling: this one tenant-reachable governance
                # read is adjudicated separately by #3638 (policy disclosure
                # redaction). It is NOT an approved system-internal bypass.
                # #5884: the exemption is identified by file + exact content
                # line + enclosing function, and exempt_precheck proved that
                # exactly ONE such site exists (no line-number pin).
                if [[ "$mode" == "any-arg" && "$rel" == "${C8_EXEMPT_FILE}" \
                    && -n "${C8_EXEMPT_LINENO}" && "$lineno" == "${C8_EXEMPT_LINENO}" \
                    && "$content" == "${C8_EXEMPT_LINE}" ]]; then
                    continue
                fi
                out+="${rel}:${lineno}:${literal}"$'\n'
            fi
        done <<< "${matches}"
    done < <(find "${ROOT}/src" -type f -name '*.rs' -print0)
    # Sort + dedup so the diff against the allowlist is order-stable.
    printf '%s' "$out" | LC_ALL=C sort -u
}

CURRENT_FOR_AGENT="$(collect_sites 'CallerContext::for_agent')"
CURRENT_FOR_ADMIN="$(collect_sites 'CallerContext::for_admin' any-arg)"

# Strip the line-number column from a "file:line:literal" stream so
# the allowlist contract is `file:literal` only — line numbers drift
# on every unrelated edit and would otherwise flood the diff.
# Literals can contain `:` (e.g. `ai:seed`, `ai:http-internal`), so
# we use sed with a regex that requires the second column to be
# digits — preserves the rest of the line verbatim.
strip_line () {
    sed -E 's/^([^:]+):[0-9]+:(.*)$/\1:\2/'
}

CURRENT_FOR_AGENT_NORM="$(printf '%s' "$CURRENT_FOR_AGENT" | strip_line | LC_ALL=C sort -u)"
CURRENT_FOR_ADMIN_NORM="$(printf '%s' "$CURRENT_FOR_ADMIN" | strip_line | LC_ALL=C sort -u)"

write_allowlist () {
    local out="$1"
    local payload="$2"
    local title="$3"
    {
        printf '# %s\n' "$title"
        printf '# Auto-generated by scripts/qc-codegraph-precheck.sh --update.\n'
        printf '# Format: <repo-root-relative-file>:<literal>\n'
        printf '# Edit deliberately — every entry should be a reviewed exception.\n'
        printf '# See CLAUDE.md §"Enforceable Orchestrator Safeguards" (C8).\n'
        printf '\n'
        printf '%s\n' "$payload"
    } > "$out"
}

if (( UPDATE )); then
    write_allowlist "$ALLOW_FOR_AGENT" "$CURRENT_FOR_AGENT_NORM" \
        "CallerContext::for_agent(\"<literal>\") allowlist (C8 safeguard)."
    write_allowlist "$ALLOW_FOR_ADMIN" "$CURRENT_FOR_ADMIN_NORM" \
        "CallerContext::for_admin(\"<literal>\") privacy-bypass allowlist (C8 safeguard)."
    echo "Allowlists regenerated:"
    echo "  ${ALLOW_FOR_AGENT}"
    echo "  ${ALLOW_FOR_ADMIN}"
    exit 0
fi

if [[ ! -f "$ALLOW_FOR_AGENT" || ! -f "$ALLOW_FOR_ADMIN" ]]; then
    echo "ERROR: allowlist file(s) missing. Run \`scripts/qc-codegraph-precheck.sh --update\` to seed." >&2
    exit 2
fi

# The allowlist files carry a comment header (lines starting with `#`)
# + a blank line; the payload is `<file>:<literal>` pairs. Strip
# comments + blanks before diffing.
strip_comments () {
    # `grep -v` returns 1 when its input is empty after filtering;
    # that triggers `set -e` + `pipefail` and aborts the script. The
    # `|| true` swallows the non-zero so an empty allowlist body
    # (e.g. the for_agent file post-#955) is treated as legitimate.
    { grep -v '^#' "$1" | grep -v '^$' | LC_ALL=C sort -u; } || true
}

ALLOW_FOR_AGENT_BODY="$(strip_comments "$ALLOW_FOR_AGENT")"
ALLOW_FOR_ADMIN_BODY="$(strip_comments "$ALLOW_FOR_ADMIN")"

violations=0

if [[ -n "${C8_EXEMPT_ERR}" ]]; then
    echo "C8 HARD-BLOCK (#5884): ${C8_EXEMPT_ERR}; the GOVERNANCE_INTERNAL site is not exempt." >&2
    violations=$(( violations + 1 ))
fi

check_diff () {
    local label="$1"
    local current="$2"
    local allow="$3"
    # New sites = lines in current not in allow.
    local new_sites
    new_sites="$(LC_ALL=C comm -23 \
        <(printf '%s\n' "$current") \
        <(printf '%s\n' "$allow") || true)"
    if [[ -n "${new_sites//[[:space:]]/}" ]]; then
        echo "C8 HARD-BLOCK: new ${label} site(s) not in allowlist:" >&2
        printf '  %s\n' "${new_sites}" >&2
        echo "" >&2
        echo "If these are deliberate exceptions, run:" >&2
        echo "  scripts/qc-codegraph-precheck.sh --update" >&2
        echo "and review the diff to ${ALLOW_DIR%/}/*.txt before committing." >&2
        violations=$(( violations + 1 ))
    fi
    # Stale entries = lines in allow not in current. Surface as a
    # WARN — not a hard block — so unrelated refactors that delete a
    # site don't fail unrelated PRs.
    local stale
    stale="$(LC_ALL=C comm -13 \
        <(printf '%s\n' "$current") \
        <(printf '%s\n' "$allow") || true)"
    if [[ -n "${stale//[[:space:]]/}" ]]; then
        echo "C8 WARN: stale ${label} allowlist entries (no longer present in source):" >&2
        printf '  %s\n' "${stale}" >&2
        echo "  → run \`scripts/qc-codegraph-precheck.sh --update\` to prune." >&2
    fi
}

check_diff "CallerContext::for_agent" "$CURRENT_FOR_AGENT_NORM" "$ALLOW_FOR_AGENT_BODY"
check_diff "CallerContext::for_admin" "$CURRENT_FOR_ADMIN_NORM" "$ALLOW_FOR_ADMIN_BODY"

# #3943 — a LITERAL bool in the SECOND argument of `for_admin_checked(` severs
# the type dependency on the admin gate: a free-standing `.., true` still
# compiles after the gate is removed, silently yielding an admin-bypass
# context. No allowlist — the second argument MUST be the gate's result
# (threaded from a `require_admin` Ok arm). Paren-aware + multi-line +
# comment/test-skipping; see scripts/tests/for-admin-checked-literal-3943.py.
checked_literal_hits=""
# Prefilter to the files that actually contain the call (a call always opens
# `for_admin_checked(` on one line, even when the ARGS wrap) so the paren-aware
# python parser runs on a handful of files, not one startup per src file.
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    hits="$(production_lines "$f" \
        | python3 "${ROOT}/scripts/tests/for-admin-checked-literal-3943.py" "${f#"${ROOT}/"}")"
    [[ -n "${hits}" ]] && checked_literal_hits+="${hits}"$'\n'
done < <(grep -rlF --include='*.rs' 'for_admin_checked(' "${ROOT}/src" 2>/dev/null || true)
checked_literal_hits="$(printf '%s' "${checked_literal_hits}" | grep -v '^$' || true)"
if [[ -n "${checked_literal_hits}" ]]; then
    echo "C8 HARD-BLOCK (#3943): for_admin_checked(.., <literal bool>) in production." >&2
    echo "  The second argument must be threaded from the admin gate (require_admin Ok" >&2
    echo "  arm), never a literal — a literal still compiles after the gate is removed." >&2
    printf '%s\n' "${checked_literal_hits}" | sed 's/^/    /' >&2
    violations=$(( violations + 1 ))
fi

# #5084 / #5241 — every SQLite write transaction must open BEGIN IMMEDIATE
# (WriteTxn::begin); a DEFERRED read-then-write upgrade fails with
# SQLITE_BUSY_SNAPSHOT (517) that busy_timeout never retries. Allowlist and
# rules live in the gate itself.
# The gate's allowlist names real sites in src/. The #3623 scenario harness runs
# this precheck in a fixture tree that copies scripts/ but has an empty src/, where
# every allowlist entry is "stale" and the gate would fail for reasons unrelated
# to the probe (#5877). A real checkout always has the WriteTxn home
# (src/storage/connection.rs); the gate runs whenever it exists and a tree
# without it has no SQLite write transaction to guard.
if [[ -f "${ROOT}/src/storage/connection.rs" ]] \
    && ! python3 "${ROOT}/scripts/check-sqlite-write-txn-immediate.py" >&2; then
    echo "C8 HARD-BLOCK (#5084): a SQLite transaction opened without BEGIN IMMEDIATE." >&2
    violations=$(( violations + 1 ))
fi

if (( violations > 0 )); then
    echo "" >&2
    echo "C8 precheck FAILED with ${violations} category/categories of violation." >&2
    exit 1
fi

echo "C8 precheck OK (for_agent: $(printf '%s\n' "$CURRENT_FOR_AGENT_NORM" | grep -c . || true) sites, for_admin: $(printf '%s\n' "$CURRENT_FOR_ADMIN_NORM" | grep -c . || true) sites)."
