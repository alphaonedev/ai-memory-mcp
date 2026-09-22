#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# check-cert-expiry.sh — CI gate for the enterprise-federation
# certification §7 expiry trigger (F7 / 2026-08-12 ratification caveat).
#
# THE DEFECT CLASS THIS CLOSES. docs/compliance/ENTERPRISE-FEDERATION-
# CERTIFICATION.md §7 states that the certification "expires on any
# change to the federation wire path (`src/federation/**`,
# `src/handlers/federation_receive.rs`,
# `src/handlers/federation_signing_check.rs`) or the `AI_MEMORY_FED_*`
# env surface" and that any such change "requires re-running §5.4(2)–(5)
# and re-issuing this document against the new SHA." Until this gate
# that sentence was prose-only: a federation-wire change could merge
# through green CI while the cert kept being cited. This is the #2444
# "reports success while doing nothing" shape applied to a certification
# expiry trigger.
#
# THE RULE (TASK C, verbatim — no extra escape hatches). The change
# under test is the standard PR diff
# (`merge-base(PR-base, HEAD)..HEAD`), NEVER a diff against the cert's
# pinned SHA (unrelated later PRs must not fail forever). The gate
# FAILS when that diff touches ANY of:
#
#   * src/federation/**  (the directory itself or any path under it)
#   * src/handlers/federation_receive.rs
#   * src/handlers/federation_signing_check.rs
#   * added / removed / renamed `AI_MEMORY_FED_[A-Z0-9_]+` identifiers
#     anywhere in src/  (set-diff of identifiers at merge-base vs HEAD)
#
# UNLESS the same change also modifies
# `docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md` (a re-issue
# or voiding record in the same change satisfies the gate).
#
# Failure message (required wording):
#   federation-wire surface changed → the enterprise-federation
#   certification expires per its §7 → re-issue or void the cert doc
#   in this same change.
#
# RANGE RESOLUTION.
#   pull_request     — PR_BASE_SHA + PR_HEAD_SHA (fail-closed if base
#                      is missing or merge-base is unresolvable after
#                      a shallow deepen).
#   push             — github.event.before .. GITHUB_SHA. An all-zero
#                      `before` (new branch / first push) is N/A-skip,
#                      never a false-fail.
#   workflow_dispatch / other / empty
#                    — CERT_EXPIRY_BASE[/HEAD] override if set; else
#                      (local convenience) merge-base with @{upstream}
#                      or origin/release/v1.0.0; else N/A-skip.
#   Shallow checkout — if merge-base fails and the repo is shallow,
#                      unshallow / deepen + fetch the missing tip,
#                      then retry. Still-unresolvable on a
#                      pull_request event is fail-closed.
#
# THE TWO PREDICATES #3556 ADDS (2026-09-21). The TASK-C rule above is a
# change-SHAPE test: "does the PR range touch the wire set without
# touching the doc". Two holes were measured on the v1.0.0 promotion tip:
#
#   * (B) the escape hatch accepted ANY edit of the cert doc. An
#     incidental prose edit in a range that also rewired federation
#     satisfied the gate while the doc's STATUS and Binds-to lines were
#     untouched — a re-issue that re-issued nothing. Now a cert-doc edit
#     satisfies the hatch ONLY if the STATUS line or the Binds-to line
#     changed between merge-base and HEAD (a re-issue rebinds; a voiding
#     record flips STATUS; prose does neither).
#   * (C) the gate never read the banner at all, so a doc that said
#     LIVE bound to a SHA twelve wire-file changes ago stayed green on
#     every later PR: the certification had expired by its own §7 and
#     its banner said otherwise. Now, at HEAD, a banner that says LIVE
#     bound to <sha> must have NO wire-surface drift between <sha> and
#     HEAD (paths and AI_MEMORY_FED_* identifiers, the same surface as
#     TASK C); otherwise the gate FAILS naming the drift. STATUS VOID or
#     EXPIRED makes no live claim and is never failed by (C). Drift is a
#     TREE comparison (`git diff <sha> HEAD`), so ancestry is not
#     required: a squash-merge whose watched surface equals the bound
#     tree passes on zero drift, and a bind to an unrelated commit reds
#     on the drift it carries; an unparseable banner or a bound SHA
#     absent from the repository is fail-closed. (C) is deliberately NOT "diff against
#     the pinned SHA as the PR range" (TASK C forbids that as a PR
#     gate): it asks whether the DOC'S OWN CLAIM is true at HEAD, and
#     the one-line remedy — record VOID/EXPIRED — is accepted by (B).
#
# Failure messages: (B) carries the TASK-C sentence plus "incidental
# edit"; (C) carries "claims LIVE bound to <sha> … while its banner
# still says LIVE".
#
# WHAT THIS DOES NOT CLAIM. A value-only edit of an *existing*
# AI_MEMORY_FED_* identifier in a file outside the three path watches
# does not trip the identifier check (TASK C is add/remove/rename of
# the identifier surface, not every behavioural tweak). Path watches
# still catch any edit under src/federation/** or the two handler
# files, values included. This gate does not re-run §5.4(2)–(5); it
# only forces the cert-doc to be touched so a human/re-issue cannot
# be skipped.
#
# Usage:
#   scripts/check-cert-expiry.sh              # against the resolved range
#   scripts/check-cert-expiry.sh --self-test  # plant-a-violation in a
#                                             # scratch clone (never a
#                                             # real branch)
#
# Exit codes: 0 clean / N/A-skip · 1 violation · 2 usage / self-test fail.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CERT_DOC="docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
FED_ID_PATTERN='AI_MEMORY_FED_[A-Z0-9_]+'

# ---------------------------------------------------------------------------
# Path / identifier classifiers
# ---------------------------------------------------------------------------

# is_watched_path PATH — 0 iff PATH is on the §7 federation-wire surface.
# Use [[ == ]] globs, not `case`. bash `case` `*` does not match `/`, so
# `src/federation/*` would miss nested paths (e.g. src/federation/identity/*.rs
# — 10 files at 580d8427). `[[ == ]]` `*` does match `/`.
is_watched_path() {
    [[ "$1" == src/federation || "$1" == src/federation/* ]] && return 0
    [[ "$1" == src/handlers/federation_receive.rs ]] && return 0
    [[ "$1" == src/handlers/federation_signing_check.rs ]] && return 0
    return 1
}

is_cert_doc_path() {
    [[ "$1" == "$CERT_DOC" ]]
}

# The cert doc's two banner lines (#3556). The document has carried them
# in this shape since the 2026-08-12 mint:
#   > ## STATUS — **LIVE as of 2026-09-21** (…)
#   **Binds to:** `f32c18dadf8a659567960747cc2802186bac9de9` (…)
# The patterns are TOLERANT of formatting (#3556 ruling, fix 3): optional
# blockquote, one to three `#`, flexible whitespace, em dash / en dash /
# hyphen, optional backticks, case-insensitive hex. A gate that reds the
# whole repository on a reformat while a one-line decoy walks past it is
# worse than no gate. They are anchored at line start and require the
# heading marker / the bold "Binds to", so the §7 history records that
# QUOTE these words in prose do not match.
STATUS_LINE_RE='^>?[[:space:]]*#{1,3}[[:space:]]*STATUS[[:space:]]*(—|–|-)[[:space:]]*\*\*[[:space:]]*(LIVE|VOID|EXPIRED)'
BINDS_LINE_RE='^>?[[:space:]]*\*\*[[:space:]]*Binds[[:space:]]+to[[:space:]]*:?[[:space:]]*\*\*[[:space:]]*:?[[:space:]]*`?[0-9a-fA-F]{40}`?'

# cert_banner REPO TREE — prints "<STATUS> <BINDS>" for the cert doc at
# TREE. STATUS ∈ LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no
# STATUS line) | DUPLICATE (two or more STATUS lines — #3556 ruling, fix
# 1: a decoy inserted above the real banner must not be read as the
# banner) | ABSENT (no doc at TREE). BINDS = the lowercase 40-hex bound
# SHA, "-" when no Binds-to line matches, "DUPLICATE" when two or more do.
cert_banner() {
    local repo="$1" tree="$2" doc status_lines binds_lines status binds
    if ! doc="$(git -C "$repo" show "${tree}:${CERT_DOC}" 2>/dev/null)"; then
        echo "ABSENT -"
        return 0
    fi
    status_lines="$(printf '%s\n' "$doc" | grep -iE "$STATUS_LINE_RE" || true)"
    binds_lines="$(printf '%s\n' "$doc" | grep -iE "$BINDS_LINE_RE" || true)"
    case "$(printf '%s\n' "$status_lines" | sed '/^$/d' | wc -l | tr -d ' ')" in
        0) status="UNPARSEABLE" ;;
        1) status="$(printf '%s\n' "$status_lines" | grep -oiE 'LIVE|VOID|EXPIRED' | head -1 | tr '[:lower:]' '[:upper:]')" ;;
        *) status="DUPLICATE" ;;
    esac
    case "$(printf '%s\n' "$binds_lines" | sed '/^$/d' | wc -l | tr -d ' ')" in
        0) binds="-" ;;
        1) binds="$(printf '%s\n' "$binds_lines" | grep -oiE '[0-9a-f]{40}' | head -1 | tr '[:upper:]' '[:lower:]')" ;;
        *) binds="DUPLICATE" ;;
    esac
    echo "${status} ${binds}"
}

# wire_drift REPO FROM TO — prints the §7 surface that differs between the
# two trees: watched paths (one per line) and AI_MEMORY_FED_* identifiers
# added (+ID) / removed (-ID). Empty output = no drift.
wire_drift() {
    local repo="$1" from="$2" to="$3" p
    while IFS= read -r -d '' p; do
        [[ -z "$p" ]] && continue
        if is_watched_path "$p"; then
            printf '%s\n' "$p"
        fi
    done < <(git -C "$repo" -c core.quotePath=false diff --name-only -z --no-renames "$from" "$to")
    local from_ids to_ids
    from_ids="$(extract_fed_ids "$repo" "$from")"
    to_ids="$(extract_fed_ids "$repo" "$to")"
    comm -13 <(printf '%s\n' "$from_ids" | sed '/^$/d') <(printf '%s\n' "$to_ids" | sed '/^$/d') | sed 's/^/+/'
    comm -23 <(printf '%s\n' "$from_ids" | sed '/^$/d') <(printf '%s\n' "$to_ids" | sed '/^$/d') | sed 's/^/-/'
}

# extract_fed_ids REPO TREE — unique AI_MEMORY_FED_* identifiers in src/
# at TREE. Empty (no src/, no matches) prints nothing and returns 0.
extract_fed_ids() {
    local repo="$1" tree="$2"
    local out
    out="$(git -C "$repo" grep -h -I -E "$FED_ID_PATTERN" "$tree" -- src 2>/dev/null || true)"
    if [[ -z "$out" ]]; then
        return 0
    fi
    printf '%s\n' "$out" | grep -oE "$FED_ID_PATTERN" | sort -u
}

# ---------------------------------------------------------------------------
# Range resolution + shallow recovery
# ---------------------------------------------------------------------------

ZERO_SHA_RE='^0+$'

# ensure_commit REPO SHA — fetch SHA if it is not yet a local commit.
ensure_commit() {
    local repo="$1" sha="$2"
    if git -C "$repo" rev-parse --verify --quiet "${sha}^{commit}" >/dev/null; then
        return 0
    fi
    git -C "$repo" fetch --no-tags --quiet origin "$sha" 2>/dev/null || true
    git -C "$repo" rev-parse --verify --quiet "${sha}^{commit}" >/dev/null
}

# resolve_merge_base REPO A B — print merge-base; deepen a shallow clone
# once if the first attempt fails. Returns 1 if still unresolvable.
resolve_merge_base() {
    local repo="$1" a="$2" b="$3"
    local mb
    if mb="$(git -C "$repo" merge-base "$a" "$b" 2>/dev/null)"; then
        printf '%s\n' "$mb"
        return 0
    fi
    if [[ "$(git -C "$repo" rev-parse --is-shallow-repository 2>/dev/null || true)" == "true" ]]; then
        git -C "$repo" fetch --unshallow --quiet 2>/dev/null \
            || git -C "$repo" fetch --deepen=2147483647 --quiet 2>/dev/null \
            || true
        ensure_commit "$repo" "$a" || true
        ensure_commit "$repo" "$b" || true
        if mb="$(git -C "$repo" merge-base "$a" "$b" 2>/dev/null)"; then
            printf '%s\n' "$mb"
            return 0
        fi
    fi
    return 1
}

# resolve_range REPO
# Prints "BASE HEAD" on stdout.
#   0 = have a range to check
#   3 = N/A skip (no range; not a failure)
#   1 = fail-closed (PR event with an unresolvable range)
resolve_range() {
    local repo="$1"
    local event="${GITHUB_EVENT_NAME:-}"

    if [[ -n "${CERT_EXPIRY_BASE:-}" ]]; then
        printf '%s %s\n' "$CERT_EXPIRY_BASE" "${CERT_EXPIRY_HEAD:-HEAD}"
        return 0
    fi

    case "$event" in
        pull_request)
            if [[ -z "${PR_BASE_SHA:-}" ]]; then
                echo "check-cert-expiry: ERROR — PR_BASE_SHA is unset on a pull_request event (fail-closed)" >&2
                return 1
            fi
            printf '%s %s\n' "$PR_BASE_SHA" "${PR_HEAD_SHA:-HEAD}"
            return 0
            ;;
        push)
            local before="${GITHUB_EVENT_BEFORE:-}"
            local after="${GITHUB_SHA:-HEAD}"
            if [[ -z "$before" || "$before" =~ $ZERO_SHA_RE ]]; then
                echo "check-cert-expiry: N/A — push has no previous tip (new branch / first push); skip" >&2
                return 3
            fi
            printf '%s %s\n' "$before" "$after"
            return 0
            ;;
        workflow_dispatch)
            echo "check-cert-expiry: N/A — workflow_dispatch has no PR/push range (set CERT_EXPIRY_BASE to force a check); skip" >&2
            return 3
            ;;
        "")
            # Local convenience: standard PR-shaped range vs the tracking
            # branch or origin/release/v1.0.0. Never invent a range against
            # the cert pinned SHA.
            local base_ref=""
            if git -C "$repo" rev-parse --verify --quiet '@{upstream}' >/dev/null 2>&1; then
                base_ref='@{upstream}'
            elif git -C "$repo" rev-parse --verify --quiet origin/release/v1.0.0 >/dev/null 2>&1; then
                base_ref='origin/release/v1.0.0'
            else
                echo "check-cert-expiry: N/A — no CERT_EXPIRY_BASE, no @{upstream}, no origin/release/v1.0.0; skip" >&2
                return 3
            fi
            local base_sha
            base_sha="$(git -C "$repo" rev-parse --verify "$base_ref")"
            printf '%s %s\n' "$base_sha" "HEAD"
            return 0
            ;;
        *)
            echo "check-cert-expiry: N/A — event '$event' has no PR/push range; skip" >&2
            return 3
            ;;
    esac
}

# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------

# check_change REPO BASE HEAD
# Returns 0 pass, 1 fail (violation OR unresolvable range).
# Prints the verdict (and, on fail, the required expiry sentence) to stdout
# so the caller can capture + re-emit.
check_change() {
    local repo="$1" base="$2" head="$3"

    if ! git -C "$repo" rev-parse --verify --quiet "${base}^{commit}" >/dev/null \
        || ! git -C "$repo" rev-parse --verify --quiet "${head}^{commit}" >/dev/null; then
        echo "check-cert-expiry: ERROR — cannot resolve range ${base}..${head} (fail-closed)"
        return 1
    fi

    local mb
    if ! mb="$(resolve_merge_base "$repo" "$base" "$head")"; then
        echo "check-cert-expiry: ERROR — no merge-base for ${base}..${head} (fail-closed; shallow checkout?)"
        return 1
    fi

    # --no-renames so a move of a watched file cannot hide as an unwatched
    # destination-only name (D of the old path still surfaces).
    # -c core.quotePath=false + -z: git C-quotes any path with a non-ASCII
    # byte (or " / \\ / control char) into `"src/federation/na\303\257ve.rs"`,
    # and the leading quote makes every [[ == ]] path glob MISS. -z emits
    # raw NUL-delimited paths, so a newline in a name cannot split a record
    # either.
    local watched=() cert_touched=0
    local p
    while IFS= read -r -d '' p; do
        [[ -z "$p" ]] && continue
        if is_cert_doc_path "$p"; then
            cert_touched=1
        fi
        if is_watched_path "$p"; then
            watched+=("$p")
        fi
    done < <(git -C "$repo" -c core.quotePath=false diff --name-only -z --no-renames "$mb" "$head")

    local base_ids head_ids added removed
    base_ids="$(extract_fed_ids "$repo" "$mb")"
    head_ids="$(extract_fed_ids "$repo" "$head")"
    added="$(comm -13 <(printf '%s\n' "$base_ids" | sed '/^$/d') <(printf '%s\n' "$head_ids" | sed '/^$/d') || true)"
    removed="$(comm -23 <(printf '%s\n' "$base_ids" | sed '/^$/d') <(printf '%s\n' "$head_ids" | sed '/^$/d') || true)"

    local id_changed=0
    [[ -n "$added" || -n "$removed" ]] && id_changed=1

    if ((${#watched[@]} == 0)) && ((id_changed == 0)); then
        echo "check-cert-expiry: PASS — federation-wire surface unchanged in ${mb}..${head}"
        check_banner_consistency "$repo" "$head"
        return
    fi

    # (B) #3556 — the hatch is a REAL re-issue/voiding only if the banner
    # (STATUS line or Binds-to line) differs between merge-base and HEAD.
    local incidental=0 deleted=0 malformed=0 banner_mb="" banner_head=""
    if ((cert_touched == 1)); then
        banner_mb="$(cert_banner "$repo" "$mb")"
        banner_head="$(cert_banner "$repo" "$head")"
        if [[ "$banner_mb" == "$banner_head" ]]; then
            incidental=1
        fi
        # #3556 ruling, fix 2: a DELETED cert doc is not a voiding record.
        # Deleting the certification while rewiring federation must fail
        # closed, not read as "the doc changed, hatch satisfied".
        if [[ "$banner_head" == "ABSENT -" ]]; then
            deleted=1
        fi
        # #3556 ruling, fix 1: a HEAD banner the gate cannot read as exactly
        # one STATUS line and at most one Binds-to line is not a re-issue
        # either (a decoy line above the real banner would otherwise count
        # as "the banner changed").
        case "$banner_head" in
            DUPLICATE\ * | UNPARSEABLE\ * | *\ DUPLICATE) malformed=1 ;;
        esac
    fi

    if ((cert_touched == 1)) && ((incidental == 0)) && ((deleted == 0)) && ((malformed == 0)); then
        echo "check-cert-expiry: PASS — federation-wire surface changed AND cert doc re-issued/voided in the same change (${mb}..${head}; banner ${banner_mb} → ${banner_head})"
        check_banner_consistency "$repo" "$head"
        return
    fi

    echo "federation-wire surface changed → the enterprise-federation certification expires per its §7 → re-issue or void the cert doc in this same change."
    if ((incidental == 1)); then
        echo "The cert doc WAS edited in this change, but neither its STATUS line nor its Binds-to line changed (banner ${banner_head} at both ends) — an incidental edit is not a re-issue and not a voiding record (#3556)."
    fi
    if ((deleted == 1)); then
        echo "The cert doc is ABSENT at HEAD (deleted in this change) while the federation-wire surface changed — deleting the certification is not a voiding record; record VOID/EXPIRED in the document instead (#3556)."
    fi
    if ((malformed == 1)); then
        echo "The cert doc at HEAD does not carry exactly one STATUS banner line and at most one Binds-to line (parsed: ${banner_head}) — the gate reads one banner and will not guess; a duplicated or unparseable banner is not a re-issue and not a voiding record (#3556)."
    fi
    echo ""
    echo "Range: ${mb}..${head}  (merge-base of ${base} and ${head})"
    if ((${#watched[@]} > 0)); then
        echo "Watched federation-wire paths touched:"
        local w
        for w in "${watched[@]}"; do
            echo "  $w"
        done
    fi
    if ((id_changed == 1)); then
        echo "AI_MEMORY_FED_* identifiers added/removed/renamed in src/:"
        if [[ -n "$added" ]]; then
            printf '%s\n' "$added" | sed 's/^/  + /'
        fi
        if [[ -n "$removed" ]]; then
            printf '%s\n' "$removed" | sed 's/^/  - /'
        fi
    fi
    echo ""
    echo "Remedy: modify ${CERT_DOC} in this same change (re-issue against the new SHA, or record the voiding)."
    return 1
}

# (C) #3556 — check_banner_consistency REPO HEAD
# The doc's own claim at HEAD must be true: STATUS LIVE bound to <sha>
# means no §7 wire-surface drift between <sha> and HEAD. Returns 0 (true,
# or no live claim, or drift unmeasurable on this history) / 1 (the claim
# is false, or the banner cannot be read — fail-closed).
check_banner_consistency() {
    local repo="$1" head="$2" banner status binds
    banner="$(cert_banner "$repo" "$head")"
    read -r status binds <<<"$banner"
    case "$status" in
        ABSENT)
            echo "check-cert-expiry: banner — ${CERT_DOC} absent at HEAD; no live claim to check"
            return 0
            ;;
        UNPARSEABLE)
            echo "check-cert-expiry: ERROR — ${CERT_DOC} at HEAD has no parseable STATUS line. Expected a line shaped like '> ## STATUS — **LIVE as of …**' (blockquote, heading level, dash style, spacing and hex case are tolerated). If this change reformatted the banner, restore that shape; if it removed the banner, the document must say LIVE, VOID or EXPIRED. Fail-closed, #3556."
            return 1
            ;;
        DUPLICATE)
            echo "check-cert-expiry: ERROR — ${CERT_DOC} at HEAD has two or more STATUS banner lines; the gate reads exactly one and will not guess which is the banner (a decoy line above the real banner is how a stale LIVE could be read as VOID). Remove the duplicate. Fail-closed, #3556."
            return 1
            ;;
        VOID | EXPIRED)
            echo "check-cert-expiry: banner STATUS=${status} — the doc makes no live claim; nothing to hold it to"
            return 0
            ;;
    esac
    # LIVE
    if [[ "$binds" == "-" ]]; then
        echo "check-cert-expiry: ERROR — ${CERT_DOC} at HEAD says STATUS LIVE but has no parseable Binds-to line. Expected a line shaped like '**Binds to:** \`<40-hex sha>\`' (spacing, backticks and hex case are tolerated). Fail-closed, #3556."
        return 1
    fi
    if [[ "$binds" == "DUPLICATE" ]]; then
        echo "check-cert-expiry: ERROR — ${CERT_DOC} at HEAD has two or more Binds-to lines; the gate reads exactly one and will not guess which SHA the LIVE claim binds to. Remove the duplicate. Fail-closed, #3556."
        return 1
    fi
    ensure_commit "$repo" "$binds" || true
    if ! git -C "$repo" rev-parse --verify --quiet "${binds}^{commit}" >/dev/null; then
        echo "check-cert-expiry: ERROR — banner is LIVE bound to ${binds} but that commit is not in this repository, so the claim cannot be checked (fail-closed, #3556)"
        return 1
    fi
    # Ancestry is deliberately NOT required: `git diff <binds> <head>` is a
    # tree-to-tree comparison, so a squash-merge whose watched surface
    # equals the bound tree passes on zero drift, and a bind pointed at
    # some unrelated commit (an evasion) reds on the drift it carries. An
    # ancestry-based N/A hatch was cut first and withdrawn — it was a
    # defeat: any existing side commit would have silenced (C).
    local drift
    drift="$(wire_drift "$repo" "$binds" "$head")"
    if [[ -z "$drift" ]]; then
        echo "check-cert-expiry: PASS — banner LIVE bound to ${binds}; federation-wire surface unchanged since the bind (#3556)"
        return 0
    fi
    local n
    n="$(printf '%s\n' "$drift" | sed '/^$/d' | wc -l | tr -d ' ')"
    echo "the enterprise-federation certification claims LIVE bound to ${binds} but ${n} federation-wire change(s) landed since → the certification expired per its §7 while its banner still says LIVE → re-issue it at HEAD or record VOID/EXPIRED in ${CERT_DOC}."
    echo ""
    echo "Bound: ${binds}  HEAD: ${head}"
    echo "Federation-wire drift since the bind (paths; +added / -removed AI_MEMORY_FED_* identifiers):"
    printf '%s\n' "$drift" | sed '/^$/d; s/^/  /'
    echo ""
    echo "Remedy: re-run §5.4(2)–(5) at HEAD and rebind ${CERT_DOC}, or set its STATUS line to VOID/EXPIRED (#3556)."
    return 1
}

run_gate() {
    local repo="${1:-$REPO_ROOT}"
    local pair rc
    set +e
    pair="$(resolve_range "$repo")"
    rc=$?
    set -e
    if ((rc == 3)); then
        return 0
    fi
    if ((rc != 0)); then
        return 1
    fi
    local base head
    read -r base head <<<"$pair"
    if ! out="$(check_change "$repo" "$base" "$head")"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
    printf '%s\n' "$out"
    return 0
}

# ---------------------------------------------------------------------------
# Plant-a-violation self-test (scratch clone; never a real branch)
# ---------------------------------------------------------------------------

self_test() {
    local tmp
    tmp="$REPO_ROOT/.local-runs/cert-expiry-selftest.$$"
    mkdir -p "$tmp"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    local repo="$tmp/repo"
    mkdir -p "$repo/src/federation" "$repo/src/handlers" "$repo/docs/compliance"
    git -C "$repo" init -q -b main
    git -C "$repo" config user.name "Cert Expiry Selftest"
    git -C "$repo" config user.email "selftest@invalid.example"
    git -C "$repo" config commit.gpgsign false

    printf 'fn federation_mod() {}\n' >"$repo/src/federation/mod.rs"
    printf 'fn receive() {}\n' >"$repo/src/handlers/federation_receive.rs"
    printf 'fn signing_check() {}\n' >"$repo/src/handlers/federation_signing_check.rs"
    printf 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\n' >"$repo/src/config.rs"
    printf 'fn other() {}\n' >"$repo/src/unrelated.rs"
    git -C "$repo" add .
    git -C "$repo" commit -q -m "genesis"
    local genesis_sha
    genesis_sha="$(git -C "$repo" rev-parse HEAD)"

    # write_banner STATUS BINDS [EXTRA] — the cert doc in its real shape
    # (#3556: the gate now READS the banner, so the fixture carries one).
    write_banner() {
        {
            printf '# Enterprise federation certification (fixture)\n\n'
            printf '**Binds to:** `%s` (fixture bind)\n\n' "$2"
            printf '> ## STATUS — **%s as of 2026-01-01** (fixture)\n\n' "$1"
            printf 'Body prose.\n%s' "${3:-}"
        } >"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    }
    # The base fixture is LIVE and bound to the genesis tree, so a range
    # from base_sha carries no wire drift since the bind ((C) is true).
    write_banner LIVE "$genesis_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "base: certification LIVE bound to genesis"
    local base_sha
    base_sha="$(git -C "$repo" rev-parse HEAD)"

    local failed=0 out

    # (a) RED — watched federation path, no cert-doc touch.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "violate: touch src/federation without cert doc"
    local viol_sha
    viol_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$viol_sha" 2>&1)"; then
        echo "self-test FAILED (a): watched-path violation was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'federation-wire surface changed → the enterprise-federation certification expires per its §7'; then
            echo "self-test FAILED (a): rejection did not carry the required §7 expiry sentence:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'src/federation/mod.rs'; then
            echo "self-test FAILED (a): rejection did not name the watched path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # (b) GREEN — same violation PLUS a REAL re-issue: the doc rebinds to
    #     the wire-change commit (the Binds-to line changes, (B) accepts;
    #     the bound SHA is an ancestor of HEAD with no drift after it, (C)
    #     holds).
    write_banner LIVE "$viol_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "satisfy: re-issue cert doc alongside wire change"
    local satisfied_sha
    satisfied_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$satisfied_sha")"; then
        echo "self-test FAILED (b): cert-doc-touching variant was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'cert doc re-issued/voided'; then
            echo "self-test FAILED (b): pass message did not name the cert-doc satisfy path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (c) RED — AI_MEMORY_FED_* identifier added in src/ OUTSIDE the
    #     three path watches (proves the identifier surface is independent).
    printf 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\npub const Y: &str = "AI_MEMORY_FED_NEW_KNOB";\n' \
        >"$repo/src/config.rs"
    git -C "$repo" add src/config.rs
    git -C "$repo" commit -q -m "violate: add AI_MEMORY_FED_* identifier"
    local id_sha
    id_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$id_sha" 2>&1)"; then
        echo "self-test FAILED (c): identifier-add violation was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'AI_MEMORY_FED_NEW_KNOB'; then
            echo "self-test FAILED (c): rejection did not name the added identifier:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'federation-wire surface changed → the enterprise-federation certification expires per its §7'; then
            echo "self-test FAILED (c): rejection did not carry the required §7 expiry sentence:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # (d) GREEN — identifier add + a real re-issue (rebind to the add).
    write_banner LIVE "$id_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "satisfy: re-issue cert doc alongside identifier add"
    local id_ok_sha
    id_ok_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$id_ok_sha")"; then
        echo "self-test FAILED (d): identifier-add + cert-doc variant was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (e) GREEN — unrelated src/ edit (no watched path, no identifier change).
    echo "// unrelated" >>"$repo/src/unrelated.rs"
    git -C "$repo" add src/unrelated.rs
    git -C "$repo" commit -q -m "clean: unrelated src edit"
    local clean_sha
    clean_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$clean_sha")"; then
        echo "self-test FAILED (e): unrelated src edit was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'federation-wire surface unchanged'; then
            echo "self-test FAILED (e): pass message did not say the surface was unchanged:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (f) GREEN — cert-doc-only change (the re-issue / docs-only shape).
    echo "// docs only" >>"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "clean: cert-doc only"
    local docs_sha
    docs_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$docs_sha")"; then
        echo "self-test FAILED (f): cert-doc-only change was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (g) RED — federation_receive.rs (the first named handler file).
    echo "// mutate receive" >>"$repo/src/handlers/federation_receive.rs"
    git -C "$repo" add src/handlers/federation_receive.rs
    git -C "$repo" commit -q -m "violate: touch federation_receive.rs"
    local recv_sha
    recv_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$recv_sha" 2>&1)"; then
        echo "self-test FAILED (g): federation_receive.rs violation was NOT rejected" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'src/handlers/federation_receive.rs'; then
            echo "self-test FAILED (g): rejection did not name federation_receive.rs:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (h) RED — federation_signing_check.rs (the second named handler file).
    echo "// mutate signing" >>"$repo/src/handlers/federation_signing_check.rs"
    git -C "$repo" add src/handlers/federation_signing_check.rs
    git -C "$repo" commit -q -m "violate: touch federation_signing_check.rs"
    local sign_sha
    sign_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$sign_sha" 2>&1)"; then
        echo "self-test FAILED (h): federation_signing_check.rs violation was NOT rejected" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'src/handlers/federation_signing_check.rs'; then
            echo "self-test FAILED (h): rejection did not name federation_signing_check.rs:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (h2) RED — nested path under src/federation/** (bash `case` `*` does
    #     not match `/`; this is the bypass that would have let
    #     src/federation/identity/*.rs through).
    mkdir -p "$repo/src/federation/identity"
    printf 'fn identity() {}\n' >"$repo/src/federation/identity/mod.rs"
    git -C "$repo" add src/federation/identity/mod.rs
    git -C "$repo" commit -q -m "violate: touch nested src/federation/identity"
    local nested_sha
    nested_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$nested_sha" 2>&1)"; then
        echo "self-test FAILED (h2): nested src/federation/identity/mod.rs was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'src/federation/identity/mod.rs'; then
            echo "self-test FAILED (h2): rejection did not name the nested watched path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (i) RED — rename of a watched file (D of the old path must still trip;
    #     --no-renames is the property under test).
    mkdir -p "$repo/src/elsewhere"
    git -C "$repo" mv src/federation/mod.rs src/elsewhere/mod.rs
    git -C "$repo" commit -q -m "violate: rename watched federation file away"
    local rename_sha
    rename_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$rename_sha" 2>&1)"; then
        echo "self-test FAILED (i): watched-file rename was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'src/federation/mod.rs'; then
            echo "self-test FAILED (i): rename rejection did not name the old watched path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (j) RED — identifier RENAME (remove one, add another).
    printf 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIGNATURE";\n' >"$repo/src/config.rs"
    git -C "$repo" add src/config.rs
    git -C "$repo" commit -q -m "violate: rename AI_MEMORY_FED_* identifier"
    local idren_sha
    idren_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$idren_sha" 2>&1)"; then
        echo "self-test FAILED (j): identifier-rename was NOT rejected" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'AI_MEMORY_FED_REQUIRE_SIGNATURE'; then
            echo "self-test FAILED (j): rejection did not name the added identifier:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'AI_MEMORY_FED_REQUIRE_SIG'; then
            echo "self-test FAILED (j): rejection did not name the removed identifier:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (p) RED — non-ASCII path under a watched dir. core.quotePath (default
    #     true) C-quotes such a path into `"src/federation/na\303\257ve…"`,
    #     and the leading `"` makes every [[ == ]] path glob MISS — the gate
    #     must read raw NUL-delimited paths (-z + core.quotePath=false) so
    #     the watch still trips. Pins the fix for that bypass.
    printf 'fn wire() {}\n' >"$repo/src/federation/naïve_wire.rs"
    git -C "$repo" add "src/federation/naïve_wire.rs"
    git -C "$repo" commit -q -m "violate: non-ASCII watched path"
    local quoted_sha
    quoted_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$quoted_sha" 2>&1)"; then
        echo "self-test FAILED (p): non-ASCII watched path was NOT rejected (core.quotePath bypass)" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'src/federation/naïve_wire.rs'; then
            echo "self-test FAILED (p): rejection did not name the raw (unquoted) non-ASCII path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # ---- #3556 predicates (B) and (C) ----------------------------------

    # (q) RED — wire change + an INCIDENTAL cert-doc edit (banner lines
    #     untouched). Pre-#3556 this satisfied the hatch — the hole the
    #     v1.0.0 promotion range went through.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    write_banner LIVE "$genesis_sha" "An incidental prose edit.\n"
    git -C "$repo" add src/federation/mod.rs "$CERT_DOC"
    git -C "$repo" commit -q -m "violate: wire change + incidental doc edit"
    local incidental_sha
    incidental_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$incidental_sha" 2>&1)"; then
        echo "self-test FAILED (q): wire change + incidental cert-doc edit was NOT rejected (#3556 hole open)" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'an incidental edit is not a re-issue and not a voiding record'; then
            echo "self-test FAILED (q): rejection did not name the incidental edit:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'federation-wire surface changed → the enterprise-federation certification expires per its §7'; then
            echo "self-test FAILED (q): rejection did not carry the required §7 expiry sentence:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (r) GREEN — wire change + the STATUS line flipped to VOID (a voiding
    #     record satisfies (B); a VOID banner makes no live claim for (C)).
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    write_banner VOID "$genesis_sha"
    git -C "$repo" add src/federation/mod.rs "$CERT_DOC"
    git -C "$repo" commit -q -m "satisfy: wire change + VOID record"
    local void_sha
    void_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$void_sha")"; then
        echo "self-test FAILED (r): wire change + VOID record was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'banner STATUS=VOID'; then
            echo "self-test FAILED (r): pass output did not report the VOID banner:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # (t) GREEN — an unrelated change ON TOP of the VOID record: drift since
    #     the bind exists, but a VOID banner claims nothing ((C) never
    #     fails a VOID/EXPIRED doc — TASK C's "no fail forever").
    echo "// unrelated" >>"$repo/src/unrelated.rs"
    git -C "$repo" add src/unrelated.rs
    git -C "$repo" commit -q -m "clean: unrelated edit over a VOID record"
    local over_void_sha
    over_void_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$void_sha" "$over_void_sha")"; then
        echo "self-test FAILED (t): unrelated change over a VOID banner was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (s) RED — LIVE banner + wire drift since the bind, on a range that
    #     touches NOTHING watched: the wire change landed EARLIER without
    #     a re-issue, the doc still says LIVE bound to genesis. Pre-#3556
    #     the gate never read the banner and passed this forever — the
    #     state the v1.0.0 promotion tip f32c18dad was in.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "earlier: wire change with no re-issue"
    local drifted_sha
    drifted_sha="$(git -C "$repo" rev-parse HEAD)"
    echo "// unrelated" >>"$repo/src/unrelated.rs"
    git -C "$repo" add src/unrelated.rs
    git -C "$repo" commit -q -m "later: unrelated edit over a stale LIVE banner"
    local stale_live_sha
    stale_live_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$drifted_sha" "$stale_live_sha" 2>&1)"; then
        echo "self-test FAILED (s): LIVE banner over wire drift was NOT rejected (#3556 hole open)" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q "claims LIVE bound to ${genesis_sha} but 1 federation-wire change(s) landed since"; then
            echo "self-test FAILED (s): rejection did not name the bound SHA and the drift count:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'while its banner still says LIVE'; then
            echo "self-test FAILED (s): rejection did not carry the banner-vs-drift sentence:" >&2
            echo "$out" >&2
            failed=1
        fi
        if ! printf '%s\n' "$out" | grep -q 'src/federation/mod.rs'; then
            echo "self-test FAILED (s): rejection did not list the drifted path:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # (u) GREEN — the same stale state HEALED by a one-line STATUS flip to
    #     EXPIRED in the range under test: (B) accepts the banner change,
    #     (C) has no live claim. The remedy the failure message names.
    write_banner EXPIRED "$genesis_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "heal: record EXPIRED"
    local healed_sha
    healed_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$stale_live_sha" "$healed_sha")"; then
        echo "self-test FAILED (u): recording EXPIRED over the stale LIVE banner was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (v1) GREEN — LIVE bound to a commit that is NOT an ancestor of HEAD
    #      but whose §7 watched tree equals HEAD's (the squash-merge shape):
    #      drift is a tree comparison, so this is measurable and clean.
    git -C "$repo" checkout -q -b side "$genesis_sha"
    echo "// side" >>"$repo/src/unrelated.rs"
    git -C "$repo" add src/unrelated.rs
    git -C "$repo" commit -q -m "side commit (unwatched)"
    local side_sha
    side_sha="$(git -C "$repo" rev-parse HEAD)"
    git -C "$repo" checkout -q main
    write_banner LIVE "$side_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "bind to a non-ancestor with an identical watched tree"
    local nonancestor_sha
    nonancestor_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$nonancestor_sha")"; then
        echo "self-test FAILED (v1): a bind to a non-ancestor with an identical watched tree was REJECTED:" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'federation-wire surface unchanged since the bind'; then
            echo "self-test FAILED (v1): pass output did not report zero drift since the bind:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (v2) RED — LIVE bound to a non-ancestor commit whose watched tree
    #      DIFFERS from HEAD's (a bind pointed somewhere convenient): the
    #      ancestry-N/A hatch would have silenced this; the tree diff reds it.
    git -C "$repo" checkout -q -b side2 "$genesis_sha"
    echo "// side wire" >>"$repo/src/federation/mod.rs"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "side commit (watched)"
    local side2_sha
    side2_sha="$(git -C "$repo" rev-parse HEAD)"
    git -C "$repo" checkout -q main
    write_banner LIVE "$side2_sha"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "bind to a non-ancestor whose watched tree differs"
    local evasive_sha
    evasive_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$evasive_sha" 2>&1)"; then
        echo "self-test FAILED (v2): a bind to a non-ancestor with a DIFFERENT watched tree was NOT rejected (evasion open)" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q "claims LIVE bound to ${side2_sha}"; then
            echo "self-test FAILED (v2): rejection did not name the evasive bound SHA:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (w) fail-closed — the doc exists but its STATUS line is unparseable:
    #     the gate must not read silence as a pass.
    printf '# cert\nno banner here\n' >"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "break: banner unparseable"
    local unparseable_sha
    unparseable_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$unparseable_sha" 2>&1)"; then
        echo "self-test FAILED (w): an unparseable STATUS line was NOT fail-closed" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'no parseable STATUS line'; then
            echo "self-test FAILED (w): fail-closed message did not name the missing STATUS line:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # ---- #3556 ruling: the three fixes, a cell each -----------------------

    # (x1) RED — DECOY: a second STATUS line (VOID) inserted ABOVE the real
    #      LIVE banner, with a wire change in the same range. A first-match
    #      reader would read VOID and pass; the gate reads exactly one.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    write_banner LIVE "$genesis_sha"
    sed -i '1i > ## STATUS — **VOID as of 2026-01-02** (decoy)' "$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add src/federation/mod.rs "$CERT_DOC"
    git -C "$repo" commit -q -m "violate: decoy STATUS line above the banner + wire change"
    local decoy_status_sha
    decoy_status_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$decoy_status_sha" 2>&1)"; then
        echo "self-test FAILED (x1): a decoy STATUS line above the real banner was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'not carry exactly one STATUS banner line'; then
            echo "self-test FAILED (x1): rejection did not name the duplicated banner:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (x2) RED — DECOY on the Binds-to line: a second Binds-to naming a
    #      drift-free SHA above the real one, with a wire change.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "wire change"
    local wire_sha
    wire_sha="$(git -C "$repo" rev-parse HEAD)"
    write_banner LIVE "$genesis_sha"
    sed -i "1i **Binds to:** \`${wire_sha}\` (decoy)" "$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "violate: decoy Binds-to line above the real one"
    local decoy_binds_sha
    decoy_binds_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$decoy_binds_sha" 2>&1)"; then
        echo "self-test FAILED (x2): a decoy Binds-to line above the real one was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'at most one Binds-to line'; then
            echo "self-test FAILED (x2): rejection did not name the duplicated Binds-to:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (y) RED — the cert doc DELETED in the same change as a wire change:
    #     ABSENT must fail closed, never read as "the doc changed".
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    git -C "$repo" rm -q "$CERT_DOC"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "violate: delete the certification + wire change"
    local deleted_sha
    deleted_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$deleted_sha" 2>&1)"; then
        echo "self-test FAILED (y): deleting the cert doc alongside a wire change was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'ABSENT at HEAD (deleted in this change)'; then
            echo "self-test FAILED (y): rejection did not name the deletion:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (z) GREEN — a PURE REFORMAT of the banner on a docs-only change: no
    #     blockquote, one hash, a hyphen for the dash, double spaces, an
    #     UPPERCASE SHA with no backticks. Must parse (LIVE, bound to
    #     genesis, zero drift) — a formatting change must never red the
    #     whole repository.
    {
        printf '# Enterprise federation certification (fixture)\n\n'
        printf '**Binds  to:**  %s  (reformatted)\n\n' "$(printf '%s' "$genesis_sha" | tr '[:lower:]' '[:upper:]')"
        printf '#  STATUS  -  **LIVE as of 2026-01-01**  (reformatted)\n\nBody prose.\n'
    } >"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add "$CERT_DOC"
    git -C "$repo" commit -q -m "docs: reformat the banner"
    local reformat_sha
    reformat_sha="$(git -C "$repo" rev-parse HEAD)"
    if ! out="$(check_change "$repo" "$base_sha" "$reformat_sha")"; then
        echo "self-test FAILED (z): a pure banner reformat was REJECTED (typographic landmine):" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q "banner LIVE bound to ${genesis_sha}; federation-wire surface unchanged since the bind"; then
            echo "self-test FAILED (z): the reformatted banner did not parse to LIVE bound to genesis:" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    # (z2) RED — the same reformat carried alongside a wire change is an
    #      INCIDENTAL edit (the extracted pair is unchanged), not UNPARSEABLE
    #      and not a re-issue.
    echo "// mutate" >>"$repo/src/federation/mod.rs"
    git -C "$repo" add src/federation/mod.rs
    git -C "$repo" commit -q -m "violate: wire change over the reformatted banner"
    local reformat_wire_sha
    reformat_wire_sha="$(git -C "$repo" rev-parse HEAD)"
    if out="$(check_change "$repo" "$base_sha" "$reformat_wire_sha" 2>&1)"; then
        echo "self-test FAILED (z2): reformat + wire change was NOT rejected" >&2
        echo "$out" >&2
        failed=1
    else
        if ! printf '%s\n' "$out" | grep -q 'an incidental edit is not a re-issue'; then
            echo "self-test FAILED (z2): rejection did not classify the reformat as incidental (pair unchanged):" >&2
            echo "$out" >&2
            failed=1
        fi
    fi

    git -C "$repo" reset -q --hard "$base_sha"

    # (k) fail-closed — pull_request with missing PR_BASE_SHA.
    if (
        unset CERT_EXPIRY_BASE CERT_EXPIRY_HEAD PR_BASE_SHA PR_HEAD_SHA GITHUB_EVENT_BEFORE
        export GITHUB_EVENT_NAME=pull_request
        run_gate "$repo"
    ) >/dev/null 2>&1; then
        echo "self-test FAILED (k): pull_request with unset PR_BASE_SHA did not fail closed" >&2
        failed=1
    fi

    # (l) N/A-skip — workflow_dispatch with no override (must not false-fail).
    if ! (
        unset CERT_EXPIRY_BASE CERT_EXPIRY_HEAD PR_BASE_SHA PR_HEAD_SHA GITHUB_EVENT_BEFORE
        export GITHUB_EVENT_NAME=workflow_dispatch
        run_gate "$repo"
    ) >/dev/null 2>&1; then
        echo "self-test FAILED (l): workflow_dispatch without CERT_EXPIRY_BASE did not skip" >&2
        failed=1
    fi

    # (m) N/A-skip — push with all-zero before (new branch / first push).
    if ! (
        unset CERT_EXPIRY_BASE CERT_EXPIRY_HEAD PR_BASE_SHA PR_HEAD_SHA
        export GITHUB_EVENT_NAME=push
        export GITHUB_EVENT_BEFORE=0000000000000000000000000000000000000000
        export GITHUB_SHA="$base_sha"
        run_gate "$repo"
    ) >/dev/null 2>&1; then
        echo "self-test FAILED (m): push with zero before-SHA did not skip" >&2
        failed=1
    fi

    # (n) fail-closed — unresolvable range.
    if check_change "$repo" "0000000000000000000000000000000000000000" "$base_sha" >/dev/null 2>&1; then
        echo "self-test FAILED (n): unresolvable base SHA did not fail closed" >&2
        failed=1
    fi

    # (o) GREEN — this PR itself (scripts / workflow / allowlist / CHANGELOG
    #     only; must not trip the gate). Runs against the REAL worktree so a
    #     future edit that accidentally touches the watched surface turns
    #     the self-test red before CI does.
    local own_base="" own_head
    own_head="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    if git -C "$REPO_ROOT" rev-parse --verify --quiet origin/release/v1.0.0 >/dev/null 2>&1; then
        own_base="$(git -C "$REPO_ROOT" rev-parse origin/release/v1.0.0)"
    elif git -C "$REPO_ROOT" rev-parse --verify --quiet '@{upstream}' >/dev/null 2>&1; then
        own_base="$(git -C "$REPO_ROOT" rev-parse '@{upstream}')"
    fi
    if [[ -n "$own_base" ]]; then
        if ! out="$(check_change "$REPO_ROOT" "$own_base" "$own_head")"; then
            echo "self-test FAILED (o): THIS change trips the cert-expiry gate without touching the cert doc:" >&2
            echo "$out" >&2
            failed=1
        fi
    else
        echo "self-test NOTE (o): skipped own-PR check (no origin/release/v1.0.0 and no @{upstream})" >&2
    fi

    if ((failed != 0)); then
        echo "check-cert-expiry self-test: FAIL" >&2
        exit 2
    fi
    echo "check-cert-expiry self-test OK: (a) watched-path violation RED with the §7 expiry sentence; (b) same change + cert-doc GREEN; (c) AI_MEMORY_FED_* identifier-add outside the path watches RED; (d) identifier-add + cert-doc GREEN; (e) unrelated src/ edit GREEN; (f) cert-doc-only GREEN; (g) federation_receive.rs RED; (h) federation_signing_check.rs RED; (h2) nested src/federation/identity/** RED; (i) watched-file rename RED (old path still named); (j) identifier-rename RED (both names listed); (k) pull_request missing PR_BASE_SHA fail-closed; (l) workflow_dispatch skip; (m) push with zero before-SHA skip; (n) unresolvable range fail-closed; (o) this checkout vs origin/release/v1.0.0 GREEN; (p) non-ASCII watched path RED (core.quotePath bypass closed); (q) wire change + incidental cert-doc edit RED (#3556 B); (r) wire change + VOID record GREEN; (s) unrelated change over a LIVE banner with wire drift since the bind RED (#3556 C, names the bound SHA and the drift); (t) unrelated change over a VOID banner GREEN; (u) stale LIVE healed by recording EXPIRED GREEN; (v1) LIVE bound to a non-ancestor with an identical watched tree GREEN (squash-merge shape, tree diff); (v2) LIVE bound to a non-ancestor whose watched tree differs RED (the ancestry hatch would have silenced it); (w) unparseable STATUS line fail-closed; (x1) decoy STATUS line above the banner RED (exactly-one rule); (x2) decoy Binds-to line RED; (y) cert doc deleted alongside a wire change RED (ABSENT fails closed); (z) pure banner reformat on a docs-only change GREEN (tolerant parse); (z2) reformat + wire change RED as incidental, not unparseable."
}

case "${1:-}" in
    --self-test)
        self_test
        ;;
    "")
        run_gate "$REPO_ROOT"
        ;;
    *)
        echo "usage: $(basename "$0") [--self-test]" >&2
        exit 2
        ;;
esac
