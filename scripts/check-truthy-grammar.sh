#!/usr/bin/env bash
# #3200 — one house truthy/falsy grammar. The narrow 2-term forms
#   v == "1" || <id>.eq_ignore_ascii_case("true")   (drops yes/on, no trim)
#   v == "0" || <id>.eq_ignore_ascii_case("false")  (drops no/off)
# silently ignore half the house 1/true/yes/on convention (e.g. REQUIRE_TLS=yes
# was inert). Every truthy/falsy env check must route through the ONE grammar in
# security_profile::{is_truthy,is_falsy}. This gate DERIVES the offending site
# list by grep and HARD-BLOCKS any narrow form outside the documented
# deliberate-narrow allowlist. Toolchain-free (grep only).
set -euo pipefail

# --self-test (rule m): prove the gate still catches its target. Plant a narrow
# form at a production path in a throwaway copy UNDER .local-runs (never /tmp),
# assert the gate rejects it, then clean up.
if [ "${1:-}" = "--self-test" ]; then
  base="$(pwd)"; work="$base/.local-runs/truthy-gate-selftest.$$"
  rm -rf "$work"; mkdir -p "$work/src/handlers" "$work/scripts/qc-allowlists"
  cp "$base/scripts/check-truthy-grammar.sh" "$work/scripts/"
  cp "$base/scripts/qc-allowlists/truthy-grammar-narrow-allow.txt" "$work/scripts/qc-allowlists/"
  cat > "$work/src/handlers/plant.rs" <<'RS'
pub fn plant() -> bool {
    std::env::var("X").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}
RS
  if bash "$work/scripts/check-truthy-grammar.sh" "$work" >/dev/null 2>&1; then
    echo "check-truthy-grammar --self-test: FAIL (gate did NOT catch a planted narrow form)"; rm -rf "$work"; exit 1
  fi
  echo "check-truthy-grammar --self-test: OK (planted narrow form rejected)"; rm -rf "$work"; exit 0
fi

ROOT="${1:-.}"; cd "$ROOT"
ALLOW="scripts/qc-allowlists/truthy-grammar-narrow-allow.txt"
NARROW_T='== *"1" *\|\| *[A-Za-z_][A-Za-z0-9_]*\.eq_ignore_ascii_case\("true"\)'
NARROW_F='== *"0" *\|\| *[A-Za-z_][A-Za-z0-9_]*\.eq_ignore_ascii_case\("false"\)'

# Production-vs-test boundary mirrors check-vendor-literals.sh: skip *test*.rs
# and every line at/below the first `mod tests {` in each file.
prod_hits() {  # $1 = regex
  local re="$1" hits=""
  while IFS= read -r f; do
    case "$(basename "$f")" in *test*.rs|tests.rs) continue;; esac
    local cut; cut=$(grep -nE '^\s*(pub )?mod tests\b' "$f" | head -1 | cut -d: -f1 || true)
    local body; if [ -n "$cut" ]; then body=$(sed -n "1,$((cut-1))p" "$f"); else body=$(cat "$f"); fi
    while IFS= read -r m; do [ -n "$m" ] && hits+="$f:$m"$'\n'; done < <(printf '%s\n' "$body" | grep -nE "$re" || true)
  done < <(find src -name '*.rs' | sort)
  printf '%s' "$hits"
}
# The allowlist names deliberate-narrow SYMBOLS; a hit is exempt only if its
# enclosing fn is allowlisted. Simplest robust check: the ONLY sanctioned narrow
# site is governance_fail_open_value_enabled's body — exempt a hit iff the file's
# nearest preceding `fn <name>` is allowlisted for that file.
allowed_syms() { grep -vE '^\s*#|^\s*$' "$ALLOW" | awk '{print $1}'; }  # file::sym
rc=0
for kind in T F; do
  re="NARROW_$kind"; re="${!re}"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    f="${line%%:*}"; rest="${line#*:}"; lno="${rest%%:*}"
    # nearest preceding `fn <name>` at column 0..8
    sym=$(sed -n "1,${lno}p" "$f" | grep -oE 'fn [A-Za-z_][A-Za-z0-9_]*' | tail -1 | awk '{print $2}')
    key="$f::$sym"
    if allowed_syms | grep -qxF "$key"; then continue; fi
    echo "::error::#3200 narrow truthy/falsy grammar (drops yes/on|no/off) at $f:$lno — route through security_profile::{is_truthy,is_falsy}"
    rc=1
  done < <(prod_hits "$re")
done
[ "$rc" = 0 ] && echo "check-truthy-grammar: OK (no un-allowlisted narrow grammar)"
exit "$rc"
