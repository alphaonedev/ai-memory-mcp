#!/usr/bin/env bash
# check-test-keydir-mode.sh — #3733 gate: a test that creates a directory it uses as a key dir must
# create it through tests/common/key_dir_sandbox.rs::mkdir_0700, never a bare std::fs::create_dir.
#
# Thin wrapper over the python core beside it (the check-foreign-text-to-caller.sh shape, and the
# standing standard: scripts are python). The invariant, the match grammar, the honest statement of
# what the match does and does not correlate, and the #4501 wrapped-call history are documented at
# the top of scripts/check-test-keydir-mode.py.
#
# Usage:
#   scripts/check-test-keydir-mode.sh              # scan tests/ — exit 1 on any violation
#   scripts/check-test-keydir-mode.sh --self-test  # fixtures under .local-runs/, never /tmp
#   scripts/check-test-keydir-mode.sh --only tests/foo.rs
# Cargo-free, stdlib python3 only.
set -u
cd "$(dirname "$0")/.." || exit 2
exec python3 scripts/check-test-keydir-mode.py "$@"
