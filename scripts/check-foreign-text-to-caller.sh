#!/usr/bin/env bash
# check-foreign-text-to-caller.sh — #3688 gate 7: FOREIGN TEXT CROSSING TO A CALLER.
#
# Thin wrapper over the python core beside it (the gate-8 `check-build-script-vetting.py`
# shape). The rule, the sink/source grammar and the allowlist grammar are documented at the
# top of scripts/check-foreign-text-to-caller.py.
#
# Usage:
#   scripts/check-foreign-text-to-caller.sh              # scan src/ — exit 1 on any FAIL
#   scripts/check-foreign-text-to-caller.sh --self-test  # fixtures under .local-runs/, never /tmp
#   scripts/check-foreign-text-to-caller.sh --json | --verbose | --only=<src/file.rs>
# Cargo-free, stdlib python3 only.
set -u
cd "$(dirname "$0")/.." || exit 2
exec python3 scripts/check-foreign-text-to-caller.py "$@"
