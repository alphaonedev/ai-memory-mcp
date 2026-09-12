# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
# Shared production-vs-test policy for the hard-block gates (#3623).
production_lines () {
    local f="$1" stem
    stem="$(basename "$f" .rs)"
    if [[ "$stem" =~ (^|_)tests?(_|$) ]]; then
        return 0
    fi
    "${AWK_BIN:-awk}" -f "${ROOT}/scripts/lib/production-lines.awk" "$f"
}
