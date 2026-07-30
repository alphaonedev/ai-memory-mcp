#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 required-context SOUNDNESS gate (#2494 / #2496) — FAIL-CLOSED.
#
# THE DEFECT CLASS THIS CLOSES. A branch-protection required-status-check set
# reads as N gates and can FUNCTION as far fewer. Three independent ways, all
# observed live on `release/v1.0.0`:
#
#   (1) THE WEDGE (#2494). `ci.yml` job `mobile-cross-compile` was BOTH a
#       `strategy: matrix` job AND carried a job-level
#       `if: needs.classify.outputs.docs_only != 'true'`. GitHub evaluates a
#       job-level `if:` BEFORE matrix expansion, so a skipped matrix job emits
#       exactly ONE check-run bearing the UNEXPANDED template name. Probed on
#       docs-only commit 45ba8741:
#           skipped  Cross-compile (${{ matrix.target }})
#           Cross-compile (aarch64-apple-ios)      present: 0
#           Cross-compile (aarch64-linux-android)  present: 0
#       Both of those absent names ARE required contexts. An absent required
#       context is `pending` indefinitely and `enforce_admins: true` means no
#       admin merge clears it — the branch wedges for that PR shape. On the
#       SAME commit `Check (ubuntu/macos/windows-latest)` all EXPANDED and
#       reported `success`, because the `check` job carries NO job-level `if:`
#       and guards every STEP instead. That contrast is the whole rule: a
#       matrix job whose name carries a required context must never take a
#       job-level `if:`.
#
#   (2) THE SKIPPED-COUNTS-AS-SATISFIED FAIL-OPEN. A non-matrix required job
#       with a job-level `if:` reports `skipped`, which GitHub counts as
#       SATISFIED. Eight required contexts do this on a docs-only diff. That
#       is only safe while the classifier is correct — and it was not (#2496:
#       PR #2031 merged 22 non-docs files to `main` with zero compilation).
#       Rule (b2) is therefore a RATCHET, not a ban: the existing eight are
#       allowlisted with a dated justification and the list may only SHRINK.
#
#   (3) THE UNREPORTABLE CONTEXT. A required context whose carrying workflow
#       has a `paths:` / `paths-ignore:` filter on its `pull_request` trigger
#       simply never runs for an out-of-filter PR — the context is never
#       created and the branch wedges exactly as in (1), with no `if:` in
#       sight. Rule (c).
#
# DATA-INTEGRITY posture (North Star): a required-check set that reads as 22
# gates and functions as 9 is a control that reports success while doing
# nothing — the "defaults lie" class. This gate DEGRADES a drifting
# configuration to a loud non-zero exit rather than letting an unvalidated
# change merge behind green checks. Fail-closed, never fail-silent: anything
# this parser cannot resolve with confidence is a FAILURE, not a pass.
#
# WHY STATIC, AND WHY A COMMITTED MIRROR. The branch-protection API needs an
# admin-scoped token; the Actions `GITHUB_TOKEN` does not have it. So the gate
# runs STATICALLY at PR time against a hand-authored mirror of the required
# set at `scripts/qc-allowlists/required-contexts-release.txt`.
#
#   *** THE MIRROR IS HAND-AUTHORED FROM INTENT. NEVER GENERATE IT FROM LIVE
#   *** API STATE. One required context is currently
#   ***     L3-boundary perma-ban gate (§25.3 S5 / RQ-10
#   *** which is a YAML TRUNCATION ARTIFACT: `c8-precheck.yml:75` writes the
#   *** name UNQUOTED as `... / RQ-10 #1853)`, and in YAML a `#` PRECEDED BY
#   *** WHITESPACE opens a comment, so the parsed job name stops at `RQ-10`.
#   *** It MATCHES today and is deliberately left alone (see #2473). If the
#   *** mirror is ever regenerated from live state, that truncation is
#   *** laundered into the declaration and rule (a) becomes a tautology that
#   *** passes forever. That is the failure mode this warning exists for.
#
#   (Contrast: `(#1174 PR10)` / `(#2146)` / `(#1989)` names do NOT truncate,
#   because there the `#` is preceded by `(`, not whitespace. This parser
#   implements the real YAML rule, so it reproduces both outcomes.)
#
# RULES — any one => exit 1:
#   (a) every mirror context equals a parsed static job `name`, or an EXPANDED
#       matrix name, belonging to a workflow whose `pull_request.branches`
#       covers the protected branch the mirror scopes to.
#   (b1) HARD-FAIL, never allowlistable: a required context's job has BOTH
#       `strategy.matrix` AND a job-level `if:` — the exact #2494 wedge shape.
#   (b2) a required context's job has a job-level `if:` at all (the
#       skipped-counts-as-satisfied class) => fail unless the context is
#       listed in the burn-down ratchet
#       `scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt`
#       (`hardcoded-literals-baseline.txt` style: entries may only be
#       REMOVED; a STALE entry — one whose job no longer has a job-level
#       `if:`, or which is no longer a required context — also fails, so the
#       ratchet cannot silently rot).
#   (c) the carrying workflow's `pull_request` trigger exists and has NO
#       `paths:` / `paths-ignore:` filter.
#   (b3) in ANY job with `needs: classify` and NO job-level `if:`, EVERY step
#       carries a `docs_only` guard. One unguarded step silently runs the
#       heavy work on docs-only PRs (or, worse, half-runs it). The single
#       structural exemption is a bare `actions/checkout@*` step, which is
#       what the `check` job's proven pattern does.
#
# CLI:
#   scripts/check-required-contexts.sh              — run the gate (exit 0/1)
#   scripts/check-required-contexts.sh --self-test  — plant the historical
#       shapes in a throwaway copy UNDER the repo (never system /tmp) and
#       confirm the gate rejects EACH: the (b1) matrix+`if:` wedge, an (a)
#       mirror context matching no job, a (c) `paths:`-filtered carrier, and a
#       (b3) unguarded step in a `needs: classify` job — plus a clean control
#       that must PASS. Proves the gate is load-bearing, not decorative.
#   scripts/check-required-contexts.sh --dump       — print the raw parse
#       record stream (diagnostic; shows which job `name:` was resolved).
#
# Env overrides (so --self-test can point at planted fixtures):
#   RQC_WORKFLOW_DIR      (default <root>/.github/workflows)
#   RQC_MIRROR_FILE       (default <root>/scripts/qc-allowlists/required-contexts-release.txt)
#   RQC_ALLOW_FILE        (default <root>/scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt)
#   RQC_PROTECTED_BRANCH  (default release/v1.0.0)
#   RQC_CLASSIFY_JOB      (default classify)  — the job id rule (b3) keys on
#
# Mirrors the structure + `--self-test` convention of the sibling gates
# (`scripts/check-migration-ladder.sh`, `scripts/check-vendor-literals.sh`).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORKFLOW_DIR="${RQC_WORKFLOW_DIR:-$ROOT/.github/workflows}"
MIRROR_FILE="${RQC_MIRROR_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-release.txt}"
ALLOW_FILE="${RQC_ALLOW_FILE:-$ROOT/scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt}"
PROTECTED_BRANCH="${RQC_PROTECTED_BRANCH:-release/v1.0.0}"
CLASSIFY_JOB="${RQC_CLASSIFY_JOB:-classify}"

FAILURES=0

fail() {
    printf '%s\n' "❌ required-contexts: $*" >&2
    FAILURES=$((FAILURES + 1))
}

# --- The YAML subset parser -------------------------------------------------
#
# Deliberately a narrow, indentation-driven scanner over THIS repo's workflow
# style (2-space indent, no tabs, jobs at indent 2, job keys at 4, steps at 6,
# step keys at 8) rather than a general YAML implementation — the house idiom
# is bash + awk with no new dependencies. It is fail-closed by construction:
# it emits only what it positively recognised, and an unrecognised or
# unexpandable shape leaves a mirror context UNMATCHED, which rule (a) fails.
#
# It correctly implements the two YAML scalar rules this gate turns on:
#   * a `#` PRECEDED BY WHITESPACE in an unquoted scalar opens a comment
#     (the `RQ-10 #1853)` truncation), while `(#1174` does not;
#   * a quoted scalar is taken verbatim with no comment stripping.
# It skips block scalars (`|` / `>`) entirely so a `run:` body can never be
# misread as workflow structure.
#
# Record stream (TAB-delimited; workflow files in this repo contain no tabs):
#   WF   <file> <pr_trigger> <pr_paths> <branches-csv>
#   JOB  <file> <jobid> <name> <job_if> <has_matrix> <needs-csv>
#   MX   <file> <jobid> <key> <value>
#   STEP <file> <jobid> <idx> <has_if> <guarded> <uses> <name>
parse_workflows() {
    local f
    for f in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml; do
        [ -f "$f" ] || continue
        awk -v FNAME="$(basename "$f")" '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
        function indent(l,   n) { n = 0; while (substr(l, n + 1, 1) == " ") n++; return n }
        # YAML-faithful scalar extraction for a "key: value" tail.
        function scalar(v,   ch, q, out, i, c, p) {
            v = trim(v)
            if (v == "") return ""
            ch = substr(v, 1, 1)
            if (ch == "\"" || ch == "'"'"'") {
                q = ch; out = ""
                for (i = 2; i <= length(v); i++) {
                    c = substr(v, i, 1)
                    if (c == q) break
                    out = out c
                }
                return out
            }
            # unquoted: a "#" preceded by whitespace opens a comment
            for (i = 1; i <= length(v); i++) {
                if (substr(v, i, 1) != "#") continue
                if (i == 1) { v = ""; break }
                p = substr(v, i - 1, 1)
                if (p == " " || p == "\t") { v = substr(v, 1, i - 1); break }
            }
            return trim(v)
        }
        # Split a flow sequence "[a, b, \"c\"]" into scalars.
        function flowseq(v, out,   n, i, parts, item) {
            v = trim(v)
            if (substr(v, 1, 1) != "[") return 0
            sub(/^\[/, "", v); sub(/\][ \t]*$/, "", v)
            n = split(v, parts, ",")
            for (i = 1; i <= n; i++) {
                item = scalar(parts[i])
                if (item != "") out[++out[0]] = item
            }
            return out[0]
        }
        function flushstep() {
            if (cur_step > 0)
                printf "STEP\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", FNAME, job, cur_step, s_hasif, s_guard, s_uses, s_name
            cur_step = 0; s_hasif = 0; s_guard = 0; s_uses = ""; s_name = ""
        }
        function flushjob() {
            flushstep()
            if (job != "")
                printf "JOB\t%s\t%s\t%s\t%d\t%d\t%s\n", FNAME, job, j_name, j_if, j_matrix, j_needs
            job = ""; j_name = ""; j_if = 0; j_matrix = 0; j_needs = ""
            in_steps = 0; in_strategy = 0; in_matrix = 0; in_include = 0
        }
        BEGIN {
            blockind = -1; section = ""; on_key = ""
            pr_trigger = 0; pr_paths = 0; branches = ""
            job = ""; cur_step = 0
            seqkey = ""; seqind = -1
        }
        {
            line = $0
            ind = indent(line)
            # --- block scalar skip (a run: body must never be parsed) ---
            if (blockind >= 0) {
                if (trim(line) == "" || ind > blockind) next
                blockind = -1
            }
            if (trim(line) == "") next
            body = trim(line)
            if (substr(body, 1, 1) == "#") next

            # --- pending block-sequence continuation ("key:" then "- item") ---
            if (seqind >= 0) {
                if (ind == seqind && substr(body, 1, 2) == "- ") {
                    item = scalar(substr(body, 3))
                    if (seqkey == "branches") branches = (branches == "" ? item : branches "," item)
                    else if (seqkey == "needs") j_needs = (j_needs == "" ? item : j_needs "," item)
                    else if (seqkey ~ /^mx:/) {
                        k = substr(seqkey, 4)
                        printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, k, item
                    }
                    next
                }
                seqind = -1; seqkey = ""
            }

            # --- key: value split (structure lines only) ---
            key = ""; val = ""
            if (match(body, /^[-]? *[A-Za-z0-9_.:$-]+:/)) {
                kv = substr(body, RSTART, RLENGTH)
                val = substr(body, RSTART + RLENGTH)
                sub(/^- */, "", kv)
                sub(/:$/, "", kv)
                key = kv
            }
            rawval = trim(val)
            isblock = (rawval ~ /^[|>][0-9+-]*$/)

            # --- top level ---
            if (ind == 0) {
                flushjob()
                section = key
                on_key = ""
                if (isblock) blockind = ind
                next
            }

            if (section == "on") {
                if (ind == 2) {
                    on_key = key
                    if (key == "pull_request") pr_trigger = 1
                } else if (ind == 4 && on_key == "pull_request") {
                    if (key == "paths" || key == "paths-ignore") pr_paths = 1
                    else if (key == "branches") {
                        delete bs; bs[0] = 0
                        if (flowseq(rawval, bs) > 0) {
                            for (i = 1; i <= bs[0]; i++)
                                branches = (branches == "" ? bs[i] : branches "," bs[i])
                        } else if (rawval == "") { seqkey = "branches"; seqind = 6 }
                        else branches = (branches == "" ? scalar(rawval) : branches "," scalar(rawval))
                    }
                }
                if (isblock) blockind = ind
                next
            }

            if (section != "jobs") { if (isblock) blockind = ind; next }

            # --- jobs ---
            if (ind == 2) { flushjob(); job = key; next }
            if (job == "") { if (isblock) blockind = ind; next }

            if (ind == 4) {
                flushstep()
                in_steps = 0; in_strategy = 0; in_matrix = 0; in_include = 0
                if (key == "name") j_name = scalar(rawval)
                else if (key == "if") j_if = 1
                else if (key == "needs") {
                    delete ns; ns[0] = 0
                    if (flowseq(rawval, ns) > 0) {
                        for (i = 1; i <= ns[0]; i++) j_needs = (j_needs == "" ? ns[i] : j_needs "," ns[i])
                    } else if (rawval == "") { seqkey = "needs"; seqind = 6 }
                    else j_needs = scalar(rawval)
                }
                else if (key == "strategy") in_strategy = 1
                else if (key == "steps") in_steps = 1
                if (isblock) blockind = ind
                next
            }

            if (in_strategy && ind == 6) {
                if (key == "matrix") { j_matrix = 1; in_matrix = 1; in_include = 0 }
                else { in_matrix = 0; in_include = 0 }
                if (isblock) blockind = ind
                next
            }

            if (in_matrix && ind == 8) {
                in_include = 0
                if (key == "include") { in_include = 1 }
                else if (key != "" && key != "exclude") {
                    delete vs; vs[0] = 0
                    if (flowseq(rawval, vs) > 0) {
                        for (i = 1; i <= vs[0]; i++)
                            printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, vs[i]
                    } else if (rawval == "") { seqkey = "mx:" key; seqind = 10 }
                    else printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, scalar(rawval)
                }
                if (isblock) blockind = ind
                next
            }

            if (in_include && (ind == 10 || ind == 12)) {
                if (key != "")
                    printf "MX\t%s\t%s\t%s\t%s\n", FNAME, job, key, scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (in_steps && ind == 6 && substr(body, 1, 2) == "- ") {
                flushstep()
                cur_step = ++stepno[job]
                if (key == "if") { s_hasif = 1; if (rawval ~ /docs_only/) s_guard = 1 }
                else if (key == "uses") s_uses = scalar(rawval)
                else if (key == "name") s_name = scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (in_steps && ind == 8 && cur_step > 0) {
                if (key == "if") { s_hasif = 1; if (rawval ~ /docs_only/) s_guard = 1 }
                else if (key == "uses") s_uses = scalar(rawval)
                else if (key == "name") s_name = scalar(rawval)
                if (isblock) blockind = ind
                next
            }

            if (isblock) blockind = ind
        }
        END {
            flushjob()
            printf "WF\t%s\t%d\t%d\t%s\n", FNAME, pr_trigger, pr_paths, branches
        }
        ' "$f"
    done
}

# glob_match <pattern> <branch-ref>
# GitHub workflow `branches:` globbing: `**` spans `/`, `*` does not.
glob_match() {
    local pat="$1" ref="$2" rx="" i ch
    for ((i = 0; i < ${#pat}; i++)); do
        ch="${pat:i:1}"
        case "$ch" in
            '*')
                if [ "${pat:i:2}" = "**" ]; then rx+='.*'; i=$((i + 1)); else rx+='[^/]*'; fi
                ;;
            '?') rx+='[^/]' ;;
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\') rx+="\\$ch" ;;
            *) rx+="$ch" ;;
        esac
    done
    [[ "$ref" =~ ^${rx}$ ]]
}

read_list() {
    # Whole-line `#` comments and blanks only. Inline `#` is NOT a comment:
    # several required context names legitimately contain one, e.g.
    # `Vendor-monoculture + SECS_PER_* lint-gate (#1174 PR10)`.
    local file="$1" line
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')" in
            '' | '#'*) continue ;;
        esac
        printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
    done < "$file"
}

run_gate() {
    local records
    records="$(parse_workflows)"

    if [ -z "$records" ]; then
        fail "parsed ZERO records from $WORKFLOW_DIR — refusing to pass on an empty parse (fail-closed)"
        return 1
    fi
    if [ ! -f "$MIRROR_FILE" ]; then
        fail "mirror file missing: $MIRROR_FILE (fail-closed — the gate cannot verify an undeclared required set)"
        return 1
    fi

    local -a contexts=() allow=()
    mapfile -t contexts < <(read_list "$MIRROR_FILE")
    mapfile -t allow < <(read_list "$ALLOW_FILE")

    if [ "${#contexts[@]}" -eq 0 ]; then
        fail "mirror $MIRROR_FILE declares NO contexts — refusing to pass a vacuous mirror (fail-closed)"
        return 1
    fi

    # ---- index the parsed records -----------------------------------------
    declare -A JOB_NAME=() JOB_IF=() JOB_MATRIX=() JOB_NEEDS=() JOB_FILE=()
    declare -A WF_PR=() WF_PATHS=() WF_BRANCHES=()
    declare -A MXKEYS=()   # "file|job|key" -> space-joined values
    declare -a JOBKEYS=()

    local rec kind a b c d e f g
    while IFS=$'\t' read -r kind a b c d e f g; do
        case "$kind" in
            WF)
                WF_PR["$a"]="$b"; WF_PATHS["$a"]="$c"; WF_BRANCHES["$a"]="$d"
                ;;
            JOB)
                local jk="$a|$b"
                JOBKEYS+=("$jk")
                JOB_FILE["$jk"]="$a"; JOB_NAME["$jk"]="$c"
                JOB_IF["$jk"]="$d"; JOB_MATRIX["$jk"]="$e"; JOB_NEEDS["$jk"]="$f"
                ;;
            MX)
                local mk="$a|$b|$c"
                MXKEYS["$mk"]="${MXKEYS[$mk]:-} $d"
                ;;
        esac
    done <<< "$records"

    # ---- expand job names into the concrete context names they report -----
    declare -A CTX_JOB=()      # context name -> "file|job"
    declare -a UNEXPANDABLE=()
    local jk name mvar vals v expanded
    for jk in "${JOBKEYS[@]}"; do
        name="${JOB_NAME[$jk]}"
        [ -n "$name" ] || continue
        if [[ "$name" != *'${{'* ]]; then
            [ -n "${CTX_JOB[$name]:-}" ] || CTX_JOB["$name"]="$jk"
            continue
        fi
        # Exactly one `${{ matrix.<key> }}` is expandable; anything else is
        # reported as unexpandable and (if required) fails rule (a).
        if [[ "$name" =~ ^([^$]*)\$\{\{[[:space:]]*matrix\.([A-Za-z0-9_-]+)[[:space:]]*\}\}(.*)$ ]]; then
            local pre="${BASH_REMATCH[1]}" post="${BASH_REMATCH[3]}"
            mvar="${BASH_REMATCH[2]}"
            if [[ "$post" == *'${{'* ]]; then
                UNEXPANDABLE+=("$jk :: $name (more than one expression)")
                continue
            fi
            vals="${MXKEYS[${jk}|${mvar}]:-}"
            if [ -z "${vals// /}" ]; then
                UNEXPANDABLE+=("$jk :: $name (no matrix.$mvar values found)")
                continue
            fi
            for v in $vals; do
                expanded="${pre}${v}${post}"
                [ -n "${CTX_JOB[$expanded]:-}" ] || CTX_JOB["$expanded"]="$jk"
            done
        else
            UNEXPANDABLE+=("$jk :: $name")
        fi
    done

    # ---- rules (a) / (b1) / (b2) / (c), per required context --------------
    declare -A ALLOWED=()
    local ctx
    for ctx in "${allow[@]}"; do ALLOWED["$ctx"]=1; done
    declare -A ALLOW_USED=()

    local wf
    for ctx in "${contexts[@]}"; do
        jk="${CTX_JOB[$ctx]:-}"
        if [ -z "$jk" ]; then
            fail "RULE (a) — required context '$ctx' matches NO parsed job name (static or matrix-expanded) in $WORKFLOW_DIR."
            echo "     A required context that no job produces is never created, so it stays 'Expected — waiting' forever and the branch WEDGES (enforce_admins cannot clear it)." >&2
            echo "     FIX: correct the mirror to the name the workflow actually reports, or add/rename the job. Do NOT regenerate the mirror from live API state — see the header warning about the §25.3 truncation artifact." >&2
            if [ "${#UNEXPANDABLE[@]}" -gt 0 ]; then
                echo "     NOTE: these job names could not be expanded by the parser and may be the intended carrier:" >&2
                printf '       %s\n' "${UNEXPANDABLE[@]}" >&2
            fi
            continue
        fi
        wf="${JOB_FILE[$jk]}"

        # (b1) the wedge shape — never allowlistable.
        if [ "${JOB_MATRIX[$jk]}" = "1" ] && [ "${JOB_IF[$jk]}" = "1" ]; then
            fail "RULE (b1) HARD-FAIL — required context '$ctx' comes from $jk, which has BOTH 'strategy.matrix' AND a job-level 'if:' (the #2494 wedge)."
            echo "     GitHub evaluates a job-level 'if:' BEFORE matrix expansion, so when that 'if:' is false the job emits ONE check-run with the UNEXPANDED template name and '$ctx' is NEVER CREATED — pending forever, unmergeable." >&2
            echo "     FIX: delete the job-level 'if:', keep 'needs:', and move that condition onto EVERY step (the 'check' job in ci.yml is the proven pattern). NOT 'if: always()' — that reports success even when the dependency failed." >&2
            continue
        fi

        # (b2) skipped-counts-as-satisfied — ratcheted.
        if [ "${JOB_IF[$jk]}" = "1" ]; then
            if [ -n "${ALLOWED[$ctx]:-}" ]; then
                ALLOW_USED["$ctx"]=1
            else
                fail "RULE (b2) — required context '$ctx' comes from $jk, which carries a job-level 'if:'. It will report 'skipped', which branch protection COUNTS AS SATISFIED — the gate fails OPEN."
                echo "     FIX (preferred): move the condition onto every step so the job runs and reports real 'success'/'failure'." >&2
                echo "     OR, if the fail-open is a deliberate, dated, justified carry-over: add '$ctx' to $ALLOW_FILE. That file is a BURN-DOWN ratchet — entries may only be removed." >&2
                continue
            fi
        fi

        # (c) the carrying workflow must actually fire for this branch, unfiltered.
        if [ "${WF_PR[$wf]:-0}" != "1" ]; then
            fail "RULE (c) — required context '$ctx' is carried by $wf, which has NO 'pull_request' trigger. It can never report on a PR, so the context stays pending and the branch wedges."
            continue
        fi
        if [ "${WF_PATHS[$wf]:-0}" = "1" ]; then
            fail "RULE (c) — required context '$ctx' is carried by $wf, whose 'pull_request' trigger has a 'paths:'/'paths-ignore:' filter."
            echo "     An out-of-filter PR never triggers the workflow, so '$ctx' is never created — the same wedge as (b1) with no 'if:' in sight. FIX: drop the path filter, or gate inside the job with per-step guards." >&2
            continue
        fi
        local br matched=0
        IFS=',' read -r -a _brs <<< "${WF_BRANCHES[$wf]:-}"
        for br in "${_brs[@]}"; do
            [ -n "$br" ] || continue
            if glob_match "$br" "$PROTECTED_BRANCH"; then matched=1; break; fi
        done
        if [ "$matched" != "1" ]; then
            fail "RULE (a) — required context '$ctx' is carried by $wf, whose pull_request 'branches:' (${WF_BRANCHES[$wf]:-<none>}) does NOT cover the protected branch '$PROTECTED_BRANCH'."
            echo "     FIX: add a matching pattern (e.g. \"release/**\") to that trigger, or drop the context from the mirror + from branch protection." >&2
        fi
    done

    # ---- ratchet hygiene: no stale allowlist entries ----------------------
    for ctx in "${allow[@]}"; do
        if [ -z "${ALLOW_USED[$ctx]:-}" ]; then
            fail "RATCHET STALE — '$ctx' is listed in $ALLOW_FILE but is no longer a required context whose job carries a job-level 'if:'."
            echo "     The allowlist is a burn-down ledger, not a junk drawer: remove the entry (thresholds tighten, never loosen)." >&2
        fi
    done

    # ---- rule (b3): every step guarded in an unguarded needs:classify job -
    local needs step_recs
    for jk in "${JOBKEYS[@]}"; do
        needs=",${JOB_NEEDS[$jk]},"
        [[ "$needs" == *",${CLASSIFY_JOB},"* ]] || continue
        [ "${JOB_IF[$jk]}" = "0" ] || continue
        wf="${JOB_FILE[$jk]}"
        local jobid="${jk#*|}"
        step_recs="$(printf '%s\n' "$records" | awk -F'\t' -v w="$wf" -v j="$jobid" '$1=="STEP" && $2==w && $3==j')"
        if [ -z "$step_recs" ]; then
            fail "RULE (b3) — job $jk has 'needs: $CLASSIFY_JOB' and no job-level 'if:', but the parser found NO steps. Refusing to pass an unverifiable job (fail-closed)."
            continue
        fi
        local sidx shasif sguard suses sname
        while IFS=$'\t' read -r _ _ _ sidx shasif sguard suses sname; do
            [ -n "$sidx" ] || continue
            if [ "$sguard" = "1" ]; then continue; fi
            # Structural exemption: a bare checkout, exactly as the proven
            # `check` job does. Nothing else is exempt.
            if [ "$shasif" = "0" ] && [[ "$suses" == actions/checkout@* ]]; then continue; fi
            fail "RULE (b3) — job $jk (needs: $CLASSIFY_JOB, no job-level 'if:') has step #$sidx ['${sname:-${suses:-<unnamed>}}'] with NO '${CLASSIFY_JOB}.outputs.docs_only' guard."
            echo "     This job's contract is 'runs always, no-ops on docs-only'. An unguarded step silently executes the heavy work on every docs-only PR — burning runner time and, worse, half-running a job whose other steps skipped." >&2
            echo "     FIX: add 'if: needs.${CLASSIFY_JOB}.outputs.docs_only != '\''true'\''' (or the '== '\''true'\''' short-circuit notice form) to that step. Only a bare 'actions/checkout@*' step is exempt." >&2
        done <<< "$step_recs"
    done

    [ "$FAILURES" -eq 0 ]
}

# --- self-test --------------------------------------------------------------
selftest() {
    echo "required-contexts gate: self-test (clean control -> PASS; #2494 (b1) matrix+if wedge -> FAIL; (a) unmatched mirror context -> FAIL; (c) paths-filtered carrier -> FAIL; (b3) unguarded step -> FAIL)"

    local scratch
    scratch="$(mktemp -d "$ROOT/.required-contexts-selftest.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$scratch'" RETURN

    local wf="$scratch/wf" al="$scratch/allow.txt" mi="$scratch/mirror.txt"
    mkdir -p "$wf"
    : > "$al"

    # A minimal but structurally faithful fixture: one matrix job following
    # the proven per-step-guard pattern, plus a plain required job.
    write_clean() {
        cat > "$wf/ci.yml" <<'YAML'
name: CI
on:
  push:
    branches: [main, "release/**"]
  pull_request:
    branches: [main, develop, "release/**"]
jobs:
  classify:
    name: Classify changes
    runs-on: ubuntu-latest
    outputs:
      docs_only: ${{ steps.cls.outputs.docs_only }}
    steps:
      - uses: actions/checkout@v4
      - id: cls
        shell: bash
        run: |
          # a run: body that LOOKS like structure must never be parsed:
          #       - name: not a real step
          #         if: bogus
          echo "docs_only=false" >> "$GITHUB_OUTPUT"
  check:
    name: Check (${{ matrix.os }})
    needs: classify
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - name: docs-only short-circuit
        if: needs.classify.outputs.docs_only == 'true'
        run: echo noop
      - name: Run tests
        if: needs.classify.outputs.docs_only != 'true'
        run: echo test
  mobile:
    name: Cross-compile (${{ matrix.target }})
    needs: classify
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: aarch64-apple-ios
            os: macos-latest
          - target: aarch64-linux-android
            os: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: cargo check
        if: needs.classify.outputs.docs_only != 'true'
        run: echo build
  quoted:
    name: Truncating gate (§X / RQ-10 #1853)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: run
        run: echo ok
  parens:
    name: Paren gate (#1174 PR10)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: run
        run: echo ok
YAML
        cat > "$mi" <<'TXT'
# self-test mirror
Check (ubuntu-latest)
Check (windows-latest)
Cross-compile (aarch64-apple-ios)
Cross-compile (aarch64-linux-android)
Truncating gate (§X / RQ-10
Paren gate (#1174 PR10)
TXT
        : > "$al"
    }

    run_fixture() {
        (
            set +e
            RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
                RQC_PROTECTED_BRANCH="release/v1.0.0" \
                bash "${BASH_SOURCE[0]}" >/dev/null 2>&1
            echo $?
        )
    }

    local rc

    # ---- control: clean tree must PASS (and must exercise both YAML rules)
    write_clean
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [control] clean fixture REJECTED (exit $rc) — the gate is over-strict; a false positive is as bad as a miss" >&2
        RQC_WORKFLOW_DIR="$wf" RQC_MIRROR_FILE="$mi" RQC_ALLOW_FILE="$al" \
            RQC_PROTECTED_BRANCH="release/v1.0.0" bash "${BASH_SOURCE[0]}" >&2 || true
        return 2
    fi
    echo "  [control] clean fixture PASSES (incl. the ' #' truncation + the '(#' non-truncation YAML rules)"

    # ---- (b1) the #2494 wedge: add a job-level if: to the matrix job
    write_clean
    perl -0pi -e 's/(  mobile:\n    name: Cross-compile \(\$\{\{ matrix\.target \}\}\)\n    needs: classify\n)/$1    if: needs.classify.outputs.docs_only != \x27true\x27\n/' "$wf/ci.yml"
    grep -q "^    if: needs.classify.outputs.docs_only" "$wf/ci.yml" || {
        echo "  [b1] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b1] matrix + job-level 'if:' wedge: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [b1] #2494 matrix + job-level 'if:' wedge (the confirmed branch-wedge shape): CAUGHT"

    # ---- (a) a mirror context matching no job
    write_clean
    printf 'Gate That Does Not Exist\n' >> "$mi"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [a] mirror context matching no job: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [a] mirror context matching no parsed job name (the #2473 truncation class): CAUGHT"

    # ---- (c) a paths:-filtered carrier
    write_clean
    perl -0pi -e "s/(  pull_request:\n    branches: \[main, develop, \"release\/\*\*\"\]\n)/\$1    paths:\n      - 'src\/**'\n/" "$wf/ci.yml"
    grep -q "^    paths:" "$wf/ci.yml" || {
        echo "  [c] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [c] paths:-filtered workflow carrying a required context: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [c] paths:-filtered pull_request trigger on a required-context carrier: CAUGHT"

    # ---- (b3) an unguarded step in a needs: classify job
    write_clean
    perl -0pi -e 's/(      - name: cargo check\n)/      - name: unguarded leak\n        run: echo this runs on docs-only PRs\n$1/' "$wf/ci.yml"
    grep -q "unguarded leak" "$wf/ci.yml" || {
        echo "  [b3] fixture injection FAILED (self-test is broken, not the gate)" >&2; return 2; }
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b3] unguarded step in a 'needs: classify' job: NOT CAUGHT (gate passed) — FAIL" >&2
        return 2
    fi
    echo "  [b3] unguarded step in a 'needs: classify' job with no job-level 'if:': CAUGHT"

    # ---- (b2) ratchet: allowlisted passes, stale entry fails
    write_clean
    perl -0pi -e 's/(  parens:\n    name: Paren gate \(#1174 PR10\)\n)/$1    needs: classify\n    if: needs.classify.outputs.docs_only != \x27true\x27\n/' "$wf/ci.yml"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b2] un-allowlisted job-level 'if:' on a required context: NOT CAUGHT — FAIL" >&2
        return 2
    fi
    printf 'Paren gate (#1174 PR10)\n' > "$al"
    rc="$(run_fixture)"
    if [ "$rc" != "0" ]; then
        echo "  [b2] allowlisted job-level 'if:' still REJECTED (exit $rc) — the ratchet does not work" >&2
        return 2
    fi
    printf 'Paren gate (#1174 PR10)\nSome Retired Gate\n' > "$al"
    rc="$(run_fixture)"
    if [ "$rc" = "0" ]; then
        echo "  [b2] STALE ratchet entry: NOT CAUGHT — FAIL" >&2
        return 2
    fi
    echo "  [b2] job-level 'if:' fail-open ratchet (un-allowlisted FAILS, allowlisted PASSES, stale entry FAILS): CAUGHT"

    echo "required-contexts gate self-test: PASS (load-bearing — catches the #2494 (b1) wedge, the (a) unmatched-context class, the (c) path-filtered carrier, the (b3) unguarded step, and both directions of the (b2) ratchet; spares a clean tree)"
}

if [ "${1:-}" = "--self-test" ]; then
    selftest
    exit $?
fi

# --dump prints the raw parse record stream. Diagnostic only — use it to see
# exactly which job `name:` the parser resolved (e.g. to confirm the §25.3
# YAML truncation is being reproduced rather than accidentally matched).
if [ "${1:-}" = "--dump" ]; then
    parse_workflows
    exit 0
fi

if [ "${1:-}" != "" ]; then
    echo "usage: $0 [--self-test|--dump]" >&2
    exit 2
fi

if run_gate; then
    echo "check-required-contexts: OK (${PROTECTED_BRANCH}: every mirrored required context maps to a reporting job; no matrix+if wedge; no path-filtered carrier; every needs-${CLASSIFY_JOB} step guarded)"
    exit 0
fi

echo "" >&2
echo "FAIL (#2494/#2496): the required-status-check set is not sound — see the rule citations above." >&2
echo "Mirror:    $MIRROR_FILE  (HAND-AUTHORED from intent — never regenerate from live API state)" >&2
echo "Ratchet:   $ALLOW_FILE   (burn-down; entries may only be removed)" >&2
echo "Self-test: scripts/check-required-contexts.sh --self-test" >&2
exit 1
