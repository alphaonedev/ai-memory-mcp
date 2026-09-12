# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
# #3623: blank test items without changing source line numbers. rustfmt
# aligns an item's closing brace with its attribute. Do not truncate the
# rest of a file after an inline test module. Unknown cfg expressions stay
# visible: cfg(any(test, feature = ...)) can be production code.
{
    lines[NR] = $0
    if ($0 ~ /^[[:space:]]*#!\[cfg\(test\)\]/) whole_file = 1
    s = $0
    sub(/^[[:space:]]*/, "", s)
    indent = length($0) - length(s)
    if (!skipping && s ~ /^#\[cfg\(test\)\]/) {
        skipping = 1
        anchor = indent
    }
    # Separate expression avoids requiring a space after all(test,...).
    if (!skipping && s ~ /^#\[cfg\(all\(test[,)]/) {
        skipping = 1
        anchor = indent
    }
    if (skipping) {
        lines[NR] = ""
        sub(/^#\[cfg\(test\)\][[:space:]]*/, "", s)
        if (s ~ /^#/ || s ~ /^\/\// || s == "") next
        if (!opened && s ~ /\{/) opened = 1
        if ((!opened && s ~ /;[[:space:]]*(\/\/.*)?$/) ||
            (opened && indent == anchor && s ~ /^}[;]?[[:space:]]*(\/\/.*)?$/) ||
            (opened && indent == anchor && s ~ /\{.*}[;]?[[:space:]]*(\/\/.*)?$/)) {
            skipping = 0
            opened = 0
        }
    }
}
END {
    for (i = 1; i <= NR; i++) print whole_file ? "" : lines[i]
}
