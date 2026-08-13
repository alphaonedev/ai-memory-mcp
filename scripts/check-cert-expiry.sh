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
is_watched_path() {
    case "$1" in
        src/federation | src/federation/*) return 0 ;;
        src/handlers/federation_receive.rs) return 0 ;;
        src/handlers/federation_signing_check.rs) return 0 ;;
        *) return 1 ;;
    esac
}

is_cert_doc_path() {
    [[ "$1" == "$CERT_DOC" ]]
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
    local paths
    paths="$(git -C "$repo" diff --name-only --no-renames "$mb" "$head")"

    local watched=() cert_touched=0
    local p
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        if is_cert_doc_path "$p"; then
            cert_touched=1
        fi
        if is_watched_path "$p"; then
            watched+=("$p")
        fi
    done <<<"$paths"

    local base_ids head_ids added removed
    base_ids="$(extract_fed_ids "$repo" "$mb")"
    head_ids="$(extract_fed_ids "$repo" "$head")"
    added="$(comm -13 <(printf '%s\n' "$base_ids" | sed '/^$/d') <(printf '%s\n' "$head_ids" | sed '/^$/d') || true)"
    removed="$(comm -23 <(printf '%s\n' "$base_ids" | sed '/^$/d') <(printf '%s\n' "$head_ids" | sed '/^$/d') || true)"

    local id_changed=0
    [[ -n "$added" || -n "$removed" ]] && id_changed=1

    if ((${#watched[@]} == 0)) && ((id_changed == 0)); then
        echo "check-cert-expiry: PASS — federation-wire surface unchanged in ${mb}..${head}"
        return 0
    fi

    if ((cert_touched == 1)); then
        echo "check-cert-expiry: PASS — federation-wire surface changed AND cert doc re-issued/voided in the same change (${mb}..${head})"
        return 0
    fi

    echo "federation-wire surface changed → the enterprise-federation certification expires per its §7 → re-issue or void the cert doc in this same change."
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
    printf '# cert\nbinds to e22bc93c\n' >"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
    git -C "$repo" add .
    git -C "$repo" commit -q -m "base"
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

    # (b) GREEN — same violation PLUS cert-doc touch.
    echo "// re-issue" >>"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
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

    # (d) GREEN — identifier add + cert-doc touch.
    echo "// re-issue" >>"$repo/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
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
    echo "check-cert-expiry self-test OK: (a) watched-path violation RED with the §7 expiry sentence; (b) same change + cert-doc GREEN; (c) AI_MEMORY_FED_* identifier-add outside the path watches RED; (d) identifier-add + cert-doc GREEN; (e) unrelated src/ edit GREEN; (f) cert-doc-only GREEN; (g) federation_receive.rs RED; (h) federation_signing_check.rs RED; (i) watched-file rename RED (old path still named); (j) identifier-rename RED (both names listed); (k) pull_request missing PR_BASE_SHA fail-closed; (l) workflow_dispatch skip; (m) push with zero before-SHA skip; (n) unresolvable range fail-closed; (o) this checkout vs origin/release/v1.0.0 GREEN."
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
