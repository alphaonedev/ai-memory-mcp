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
#   - Every production CALL of `<path>::for_agent(..)` whose first argument
#     is a string literal, and every production `<path>::for_admin` token, call
#     or bare fn-item reference, whatever the path prefix (#4020: the site
#     finder is the scope lexer `scripts/tests/c8-enclosing-fn-3970.py`, not a
#     text match, so `Cc::for_admin(..)` after `use ..::CallerContext as Cc`
#     and `let mk = CallerContext::for_admin;` are sites; a bare reference,
#     including to `for_admin_checked`, is keyed `<unparsed>` and blocks).
#     Counted per call, not per line. Test code is excluded via
#     `production_lines`. A `CallerContext as <alias>` import is refused.
#   - Each surviving site must appear in the corresponding allowlist,
#     keyed `<file>:<literal>:<count>` (#3965). The count is the number of
#     production sites in that file using that literal. More sites than
#     the entry allows is a HARD-BLOCK, so an approved entry licenses a
#     KNOWN NUMBER of reviewed sites, never "any number in this file".
#     Line numbers stay out of the key (they drift on unrelated edits);
#     the count is what makes an ADDITIONAL site visible. Same shape as
#     the sibling `check-hardcoded-literals.sh` baseline
#     (`<site-count><TAB><literal>`), which trips on +1.
#     #3970: the key also names the ENCLOSING FUNCTION (`<file>:<fn>:
#     <literal>:<count>`), so moving an approved site into a DIFFERENT
#     function (the #3638 shape: a GOVERNANCE_INTERNAL read relocated into a
#     tenant-reachable handler) is a new key and HARD-BLOCKs. The remaining
#     granularity is the function: two sites of the same literal inside ONE
#     function are interchangeable, which the count still bounds.
#
# What it deliberately does NOT do (out of scope for v0.7.0):
#   - Symbol removal / dangling-caller detection. Codegraph indexes
#     are per-developer and not available in CI; this script uses
#     a token lexer (python3) as the load-bearing detector. The deeper codegraph
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
    # below cannot stop them from running. The harness runs LAST and its status
    # is the self-test's exit. (It was red on cases 19/20/22 until #3965 keyed
    # the allowlist by site count; CI runs this self-test since #3965.)
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
    # top of this block). Its exit status is the self-test's.
    set +e
    python3 "${ROOT}/scripts/tests/gate-production-3623.py" "$(basename "$0")"
    harness_rc=$?
    set -e
    exit "${harness_rc}"
fi

# Enumerate production sites through the shared #3623 item filter.
collect_sites () {
    # #4020 — the scope lexer is the site FINDER as well as the keyer. Before,
    # sites were found by the TEXT `CallerContext::for_admin(`, so a renaming
    # import (`use ..::CallerContext as Cc; Cc::for_admin(x)`) and a fn-item
    # reference (`let mk = CallerContext::for_admin; mk(x)`) both passed. The
    # lexer flags every code token `::<method>` whatever its path prefix, one
    # site per CALL; a bare reference is keyed `<unparsed>` (blocks). The
    # argument key is byte-identical to the #3965 normalisation, and the
    # enclosing-fn key is the #3970 scope key. A file that does not lex yields
    # an `<unparsed>` site (fail closed). `CallerContext as <alias>` imports
    # are reported as `RENAME:<file>:<line>` lines and refused below.
    local method="$1"
    local mode="${2:-literal}"
    local out=""
    while IFS= read -r -d '' f; do
        # Cheap prefilter: a file without the text cannot hold the token.
        grep -q -- "${method}" "$f" || continue
        local production
        production="$(production_lines "$f")"
        # (A test-only file yields an empty production text; the lexer then
        # reports no production site. No bash-side emptiness test: a pattern
        # substitution over a multi-megabyte file is quadratic.)
        local rel="${f#"${ROOT}/"}"
        local found
        found="$(printf '%s\n' "$production" \
            | python3 "${ROOT}/scripts/tests/c8-enclosing-fn-3970.py" "$f" "${method}" "${mode}")"
        [[ -z "${found}" ]] && continue
        local kind lineno encl literal
        while IFS=$'\t' read -r kind lineno encl literal; do
            case "${kind}" in
                site) out+="${rel}:${lineno}:${encl}:${literal}"$'\n' ;;
                rename) out+="RENAME:${rel}:${lineno}"$'\n' ;;
            esac
        done <<< "${found}"
    done < <(find "${ROOT}/src" -type f -name '*.rs' -print0)
    # Sorted for an order-stable diff; NOT deduplicated, because two calls on
    # one line are two sites (#4020).
    printf '%s' "$out" | LC_ALL=C sort
}

CURRENT_FOR_AGENT_RAW="$(collect_sites for_agent)"
CURRENT_FOR_ADMIN_RAW="$(collect_sites for_admin any-arg)"
# #4020 — renaming imports of CallerContext, from both passes.
CURRENT_RENAMES="$(printf '%s\n%s\n' "$CURRENT_FOR_AGENT_RAW" "$CURRENT_FOR_ADMIN_RAW" \
    | grep '^RENAME:' | LC_ALL=C sort -u || true)"
CURRENT_FOR_AGENT="$(printf '%s\n' "$CURRENT_FOR_AGENT_RAW" | grep -v '^RENAME:' || true)"
CURRENT_FOR_ADMIN="$(printf '%s\n' "$CURRENT_FOR_ADMIN_RAW" | grep -v '^RENAME:' || true)"

# Strip the line-number column from a "file:line:literal" stream so
# the key is `file:literal` — line numbers drift on every unrelated edit
# and would otherwise flood the diff. Literals can contain `:` (e.g.
# `ai:seed`, `ai:http-internal`), so the regex requires the second column
# to be digits and preserves the rest of the line verbatim.
strip_line () {
    sed -E 's/^([^:]+):[0-9]+:(.*)$/\1:\2/'
}

# #3965 — collapse the per-site stream to `file:literal:<count>`. Before
# #3965 the stream was `sort -u`'d to bare `file:literal`, which made one
# allowlist entry a licence for an UNLIMITED number of bypass sites of that
# literal in that file: a second identical `for_admin(DAEMON_PRINCIPAL)`
# added to an already-listed file was reported as nothing at all.
count_sites () {
    { strip_line | grep -v '^$' | LC_ALL=C sort | uniq -c \
        | sed -E 's/^ *([0-9]+) (.*)$/\2:\1/' | LC_ALL=C sort; } || true
}

CURRENT_FOR_AGENT_NORM="$(printf '%s' "$CURRENT_FOR_AGENT" | count_sites)"
CURRENT_FOR_ADMIN_NORM="$(printf '%s' "$CURRENT_FOR_ADMIN" | count_sites)"

ALLOW_FORMAT_LINE='# Format: <repo-root-relative-file>:<fn>:<literal>:<count>   (#3965/#3970: <count> = production sites of <literal> in <fn> of <file>)'

# --update rewrites ONLY the entry lines: every comment (each entry's review
# justification) is kept in place, an entry whose key is still present gets
# its current count, a key no longer present is dropped, and a NEW key is
# appended at the end for a reviewer to justify. Accepts the legacy
# count-less `file:literal` form so the #3965 migration is one --update.
update_allowlist () {
    local out="$1"
    local payload="$2"
    local title="$3"
    if [[ ! -f "$out" ]]; then
        {
            printf '# %s\n' "$title"
            printf '# Auto-generated by scripts/qc-codegraph-precheck.sh --update.\n'
            printf '%s\n' "$ALLOW_FORMAT_LINE"
            printf '# Edit deliberately — every entry should be a reviewed exception.\n'
            printf '# See CLAUDE.md §"Enforceable Orchestrator Safeguards" (C8).\n'
            printf '\n'
        } > "$out"
    fi
    local tmp="${out}.update.$$"
    printf '%s\n' "$payload" | awk -v fmt="$ALLOW_FORMAT_LINE" '
        FNR == NR {
            if ($0 == "") next
            m = match($0, /:[0-9]+$/)
            key = substr($0, 1, m - 1); cur[key] = substr($0, m + 1); order[++n] = key
            # #3970 migration: the pre-fn key of `file:fn:literal` is
            # `file:literal`. Remember every fn-keyed entry per legacy key so a
            # legacy line is REPLACED IN PLACE (its justification comment stays
            # above the entries it justified).
            i1 = index(key, ":"); rest = substr(key, i1 + 1); i2 = index(rest, ":")
            legacy = substr(key, 1, i1) substr(rest, i2 + 1)
            bylegacy[legacy] = bylegacy[legacy] SUBSEP key
            # The first #3970 cut keyed by the BARE fn name (`resolve_governance_policy`);
            # the scope key qualifies it (`PostgresStore.resolve_governance_policy`).
            # Map the bare form to the qualified one too, so that line is also
            # replaced in place. (The fn field never contains `:`.)
            fnq = substr(rest, 1, i2 - 1); nseg = split(fnq, seg, ".")
            if (nseg > 1) {
                bare = substr(key, 1, i1) seg[nseg] ":" substr(rest, i2 + 1)
                bylegacy[bare] = bylegacy[bare] SUBSEP key
            }
            # A trait impl is keyed `Type[Trait]`; an entry written before
            # that (`Type.method`) maps to its bracketed form in place too.
            unbr = fnq; gsub(/\[[^]]*\]/, "", unbr)
            if (unbr != fnq) {
                pre = substr(key, 1, i1) unbr ":" substr(rest, i2 + 1)
                bylegacy[pre] = bylegacy[pre] SUBSEP key
            }
            next
        }
        /^# Format:/ { print fmt; next }
        /^#/ || /^[[:space:]]*$/ { print; next }
        {
            key = $0
            if (match(key, /:[0-9]+$/)) key = substr(key, 1, RSTART - 1)
            if (key in cur) {
                if (!(key in done)) { print key ":" cur[key]; done[key] = 1 }
            } else if (key in bylegacy) {
                k = split(bylegacy[key], parts, SUBSEP)
                for (j = 2; j <= k; j++) if (!(parts[j] in done)) { print parts[j] ":" cur[parts[j]]; done[parts[j]] = 1 }
            }
        }
        END {
            for (i = 1; i <= n; i++) if (!(order[i] in done)) print order[i] ":" cur[order[i]]
        }
    ' - "$out" > "$tmp"
    mv "$tmp" "$out"
}

if (( UPDATE )); then
    update_allowlist "$ALLOW_FOR_AGENT" "$CURRENT_FOR_AGENT_NORM" \
        "CallerContext::for_agent(\"<literal>\") allowlist (C8 safeguard)."
    update_allowlist "$ALLOW_FOR_ADMIN" "$CURRENT_FOR_ADMIN_NORM" \
        "CallerContext::for_admin(\"<literal>\") privacy-bypass allowlist (C8 safeguard)."
    echo "Allowlists regenerated (entry comments preserved):"
    echo "  ${ALLOW_FOR_AGENT}"
    echo "  ${ALLOW_FOR_ADMIN}"
    exit 0
fi

if [[ ! -f "$ALLOW_FOR_AGENT" || ! -f "$ALLOW_FOR_ADMIN" ]]; then
    echo "ERROR: allowlist file(s) missing. Run \`scripts/qc-codegraph-precheck.sh --update\` to seed." >&2
    exit 2
fi

# The allowlist files carry a comment header (lines starting with `#`)
# + a blank line; the payload is `<file>:<literal>:<count>` entries. Strip
# comments + blanks before diffing.
strip_comments () {
    # `grep -v` returns 1 when its input is empty after filtering;
    # that triggers `set -e` + `pipefail` and aborts the script. The
    # `|| true` swallows the non-zero so an empty allowlist body
    # (e.g. the for_agent file post-#955) is treated as legitimate.
    { grep -v '^#' "$1" | grep -v '^[[:space:]]*$' | LC_ALL=C sort; } || true
}

# #3965 — an entry without a trailing `:<count>` is REFUSED, not read as
# "unlimited" (that reading IS the defect) nor silently as 1. Fail closed
# and name the line so the fix is one `--update`.
require_counted () {
    local file="$1"
    local body="$2"
    local bad
    bad="$(printf '%s\n' "$body" | grep -v '^$' | grep -vE ':[1-9][0-9]*$' || true)"
    if [[ -n "$bad" ]]; then
        echo "C8 ERROR (#3965): allowlist entries without a site count in ${file#"${ROOT}/"}:" >&2
        printf '  %s\n' "$bad" >&2
        echo "  Format is <file>:<literal>:<count>. Run \`scripts/qc-codegraph-precheck.sh --update\`" >&2
        echo "  and review the counts it writes before committing." >&2
        exit 2
    fi
}

ALLOW_FOR_AGENT_BODY="$(strip_comments "$ALLOW_FOR_AGENT")"
ALLOW_FOR_ADMIN_BODY="$(strip_comments "$ALLOW_FOR_ADMIN")"
require_counted "$ALLOW_FOR_AGENT" "$ALLOW_FOR_AGENT_BODY"
require_counted "$ALLOW_FOR_ADMIN" "$ALLOW_FOR_ADMIN_BODY"

violations=0

# Compare `key:count` streams. OVER = more sites than allowlisted (includes a
# key absent from the allowlist, allowed 0) → HARD-BLOCK. UNDER = fewer sites
# than allowlisted (including 0) → WARN only, so an unrelated refactor that
# deletes a site does not fail an unrelated PR; `--update` lowers the count.
compare_counts () {
    awk '
        function split_key(line) { m = match(line, /:[0-9]+$/); K = substr(line, 1, m - 1); C = substr(line, m + 1) + 0 }
        FNR == NR { if ($0 == "") next; split_key($0); allow[K] = C; next }
        { if ($0 == "") next; split_key($0); cur[K] = C
          a = (K in allow) ? allow[K] : 0
          if (C > a) printf "OVER\t%s\t%d\t%d\n", K, C, a }
        END { for (k in allow) { c = (k in cur) ? cur[k] : 0
                if (c < allow[k]) printf "UNDER\t%s\t%d\t%d\n", k, c, allow[k] } }
    ' <(printf '%s\n' "$2") <(printf '%s\n' "$1") | LC_ALL=C sort
}

check_diff () {
    local label="$1"
    local current="$2"
    local allow="$3"
    local result over under
    result="$(compare_counts "$current" "$allow")"
    over="$(printf '%s\n' "$result" | awk -F'\t' '$1 == "OVER" { printf "%s  (%d site(s) in source, %d allowlisted)\n", $2, $3, $4 }')"
    under="$(printf '%s\n' "$result" | awk -F'\t' '$1 == "UNDER" { printf "%s  (%d site(s) in source, %d allowlisted)\n", $2, $3, $4 }')"
    if [[ -n "${over//[[:space:]]/}" ]]; then
        echo "C8 HARD-BLOCK: new ${label} site(s) not in allowlist:" >&2
        printf '  %s\n' "${over}" >&2
        echo "" >&2
        echo "An allowlist entry licenses a COUNTED number of sites (#3965); an additional" >&2
        echo "site of an approved literal needs the same review as a new literal." >&2
        echo "If these are deliberate exceptions, run:" >&2
        echo "  scripts/qc-codegraph-precheck.sh --update" >&2
        echo "and review the diff to ${ALLOW_DIR%/}/*.txt before committing." >&2
        violations=$(( violations + 1 ))
    fi
    if [[ -n "${under//[[:space:]]/}" ]]; then
        echo "C8 WARN: stale ${label} allowlist entries (fewer sites in source than allowlisted):" >&2
        printf '  %s\n' "${under}" >&2
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

# #4020 — a renaming import of CallerContext is refused outright. Every
# `<alias>::for_admin(..)` is already found as a site above, whatever the
# prefix; this closes the shape at its source so an alias never needs review.
if [[ -n "${CURRENT_RENAMES}" ]]; then
    echo "C8 HARD-BLOCK (#4020): CallerContext renaming import(s) in production:" >&2
    printf '%s\n' "${CURRENT_RENAMES}" | sed 's/^RENAME:/    /' >&2
    echo "  Import CallerContext under its own name; an alias hides privacy-bypass" >&2
    echo "  constructors from review." >&2
    violations=$(( violations + 1 ))
fi

if (( violations > 0 )); then
    echo "" >&2
    echo "C8 precheck FAILED with ${violations} category/categories of violation." >&2
    exit 1
fi

# Sites = the sum of the per-key counts; keys = distinct file:literal pairs.
sum_sites () { printf '%s\n' "$1" | awk '/:[0-9]+$/ { m = match($0, /:[0-9]+$/); t += substr($0, m + 1) } END { print t + 0 }'; }
echo "C8 precheck OK (for_agent: $(sum_sites "$CURRENT_FOR_AGENT_NORM") sites, for_admin: $(sum_sites "$CURRENT_FOR_ADMIN_NORM") sites in $(printf '%s\n' "$CURRENT_FOR_ADMIN_NORM" | grep -c . || true) counted entries)."
