#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin #8174: the two Postgres workflows run on EITHER fed node.

``postgres-ignored.yml`` and ``cert-postgres-age.yml`` used to pin their job to
``[self-hosted, linux-fed]`` while the macos-fed tier idled. The custom label
``fed`` is carried by every runner on both nodes, so ``[self-hosted, fed]``
lets whichever node is free take the job. Properties pinned (stdlib only,
Python 3.9+; workflows are read by line because PyYAML is not guaranteed on
every node):

  (a) the single job of each workflow has ``runs-on: [self-hosted, fed]``;
  (b) no ``run:`` block contains a GNU-only token (a macOS runner has BSD tools);
  (c) each workflow self-heals the hand-built macOS AGE install through
      ``scripts/ci/ensure-age-extension.py`` behind a ``$RUNNER_OS`` check, the
      same branch ci.yml takes for its macos-fed enterprise-fed leg. The whole "Point at the
      native enterprise-fed tier (per-job ephemeral db)" step is pinned byte for byte (3-agent
      vote 6def5ab6, 3-0): exactly one such step, only the keys ``name`` and ``run``, and the
      ``run: |`` lines, each stripped and blank lines dropped, equal ``EXPECTED_POINT_AT_RUN_CERT`` /
      ``EXPECTED_POINT_AT_RUN_IGNORED`` (tuples copied from the workflows, never built from them at
      test time). ``ensure-age-extension.py`` and ``RUNNER_OS`` occur nowhere outside that block
      (so the workflow-level ``env:`` block cannot carry ``RUNNER_OS``). The whole workflow SKELETON
      is pinned as a literal tuple per workflow (``EXPECTED_SKELETON_IGNORED`` / ``EXPECTED_SKELETON_CERT``):
      every non-blank, non-comment line at indent below 6 that is outside a block scalar, stripped of
      trailing whitespace, in file order. An added, removed, changed or reordered skeleton line is a
      named defect quoting the line and its 1-based file line number, so a ``defaults:``, ``env:`` or
      any other key is refused in every YAML spelling (quoted, escaped, tagged, anchored, explicit
      ``?`` key, alias, merge key, a commented ``jobs:`` line) without a YAML decoder. A skeleton line
      whose first non-blank character is ``?``, ``&``, ``!``, ``*`` or ``<``, or that carries a
      backslash inside quotes, is refused by form on top of that: those forms can spell any key and
      neither live workflow uses one (``grep -c`` of both live files: 0 each). A workflow with no
      exact ``jobs:`` line at indent 0 is refused. The workflow-level and job-level ``env`` key sets
      equal ``ENV_KEYS_BY_WORKFLOW`` (a new, removed or renamed key is a named defect), and the step has
      exactly one ``name`` key. Maintenance cost: an edit to the workflow header (triggers, permissions,
      concurrency, env, job keys) is made in the same PR as the matching edit to the skeleton tuples.
      The skeleton stops at indent 6, so two more pins cover what it cannot see. (1) Deep lines: any
      non-blank, non-comment line at indent 6 or deeper above the job's ``    steps:`` line and outside a
      block scalar is a named defect (a plain-scalar continuation there changes the value YAML reads while
      every skeleton line stays equal); neither live workflow has one (census: 0 per file). (2) Step list:
      every non-blank, non-comment line after ``    steps:`` to the end of the job, at every indent and
      outside block scalars, is pinned as a literal tuple (``EXPECTED_STEPS_IGNORED`` /
      ``EXPECTED_STEPS_CERT``), so an added, removed, reordered or changed step, ``uses:`` ref, ``with:`` or
      ``env:`` entry, and a deep continuation inside a step are named defects with line numbers. Block
      scalar content (the ``run:`` bodies) is outside both pins; the Point-at run text is pinned by the body
      check above. Maintenance cost: an edit to any step key line of either workflow is made in the same PR
      as the matching edit to the step-list tuple. U+0085, U+2028, U+2029 and a CR before the last character
      are refused anywhere in the file: PyYAML ends a line at each of them but a ``\n`` split does not, so a
      comment line carrying one can hide a key line from every line-based pin (membership test, not
      ``str.splitlines()``, so the reported line numbers stay the LF ones).
      No shell is lexed, so no bash text shape can be misread. A comment, a flag or a word
      changed inside the step is refused on purpose. Maintenance cost: the expected tuples are
      updated in the same PR as any edit to the step. The step's extent runs to the next non-blank
      non-comment line at or below the dash indent (a key after a comment is still a step key), the
      text is split on LF only and stripped of space, tab and CR only, and a non-ASCII or control
      character in a step line is a named defect unless the line is itself a pinned line (the live
      blocks print one em dash inside an echo string) or a comment that is not a line break.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_pg_workflows_fed_label_8174.py'
"""
import re
import unittest
from difflib import SequenceMatcher
from itertools import zip_longest
from pathlib import Path

try:  # the cross-check rows need PyYAML; the pin itself never does
    import yaml
except ImportError:  # pragma: no cover - a node without PyYAML skips the cross-check rows
    yaml = None

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = (
    REPO / ".github" / "workflows" / "postgres-ignored.yml",
    REPO / ".github" / "workflows" / "cert-postgres-age.yml",
)
EXPECTED_RUNS_ON = ["self-hosted", "fed"]
HEAL_SCRIPT = "scripts/ci/ensure-age-extension.py"
HEAL_GUARD = 'if [ "$RUNNER_OS" = "macOS" ]; then'
# GNU-only invocations (name, regex). Each is absent or different on macOS.
GNU_ONLY_TOKENS = (
    ("gtimeout", re.compile(r"\bgtimeout\b")),
    ("timeout", re.compile(r"(?<![-\w])timeout\s")),
    ("du -b", re.compile(r"\bdu\s+-\w*b")),
    ("stat -c", re.compile(r"\bstat\s+-c\b")),
    ("sed -i without suffix", re.compile(r"\bsed\s+(-\w*i\b|--in-place)")),
    ("readlink -f", re.compile(r"\breadlink\s+-f\b")),
    ("date -d", re.compile(r"\bdate\s+-d\b")),
    ("grep -P", re.compile(r"\bgrep\s+-\w*P")),
    ("xargs -r", re.compile(r"\bxargs\s+-\w*r\b")),
    ("sort -V", re.compile(r"\bsort\s+-\w*V")),
)

# Linux-only paths and tools a macOS runner lacks (code r1 F2, #8174).
LINUX_ONLY_TOKENS = (
    ("nproc", re.compile(r"\bnproc\b")),
    ("/proc/", re.compile(r"/proc/")),
    ("free", re.compile(r"(?<![\w./-])free\s+-")),
)
POSTGRES_LINUX_BIN = "/usr/lib/postgresql"
POSTGRES_MACOS_BIN = "/opt/homebrew/opt/postgresql@18/bin"

# Pinned text of the Point-at step's ``run: |`` block (stripped lines, blank lines dropped), copied from
# the workflows at cd57f84db. They are NOT built from the workflow at test time: an edit to the step
# is made in the same PR as the matching edit here.
EXPECTED_POINT_AT_RUN_CERT = (
    'set -euo pipefail',
    '# psql for the native tier lives under a versioned prefix. Prepend it',
    '# to GITHUB_PATH (for LATER steps + the always() cleanup) AND to THIS',
    "# step's own PATH (GITHUB_PATH does not affect the current step) so",
    '# the CREATE DATABASE below can find psql.',
    'for d in /usr/lib/postgresql/18/bin /opt/homebrew/opt/postgresql@18/bin; do',
    'if [ -d "$d" ]; then',
    'echo "$d" >> "$GITHUB_PATH"',
    'PATH="$d:$PATH"',
    'fi',
    'done',
    'export PATH',
    'url_file="$HOME/.ai-memory-ci-fed-url"',
    'if [ ! -f "$url_file" ]; then',
    'echo "::error::$RUNNER_NAME is missing $url_file — the native cert tier URL is not provisioned on this node"',
    'exit 1',
    'fi',
    'base_url="$(cat "$url_file")"',
    '# Unique db name: valid pg identifier (lowercase, [a-z0-9_], <=63',
    '# chars). run_id+attempt make it unique across concurrent runs; the',
    '# fixed `cert` suffix keeps it distinct from the ci.yml enterprise-fed',
    "# legs' ephemeral dbs on the same tier.",
    'CI_FED_DB="$(printf \'%s\' "ai_memory_test_ci_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_cert" | cut -c1-63)"',
    '# Compute-once, pass to the cleanup step via $GITHUB_ENV so create and',
    '# drop use the byte-identical name.',
    'echo "CI_FED_DB=$CI_FED_DB" >> "$GITHUB_ENV"',
    '# Create the ephemeral db on the base tier (connected to ai_memory_test).',
    'if ! psql "$base_url" -v ON_ERROR_STOP=1 -c "CREATE DATABASE \\"$CI_FED_DB\\";"; then',
    'echo "::error::$RUNNER_NAME failed to CREATE DATABASE $CI_FED_DB on the native cert tier"',
    'exit 1',
    'fi',
    "# Rewrite the base URL's db-name path segment (the last path segment,",
    "# before any '?') to the ephemeral db, preserving every query param",
    '# (sslmode/sslrootcert). The db name is [a-z0-9_] so needs no encoding.',
    'case "$base_url" in',
    '*\\?*) q="?${base_url#*\\?}"; head="${base_url%%\\?*}" ;;',
    '*)    q=""; head="$base_url" ;;',
    'esac',
    'new_url="${head%/*}/${CI_FED_DB}${q}"',
    '# #6161 - the macos-fed AGE install is hand-built; a Homebrew upgrade',
    '# relinks the postgresql@18 trees and drops its files. These two',
    '# workflows run on EITHER fed node (#8174), so mirror the ci.yml',
    '# `Configure enterprise-fed tier` branch: on macOS self-heal from the',
    '# node-local copy BEFORE CREATE EXTENSION (five sha256-pinned files;',
    '# one-line reason on stderr). Linux is unchanged.',
    '# python3 -I (#6339): the helper builds PGPASSWORD, so no sys.path[0] or PYTHONPATH.',
    'if [ "$RUNNER_OS" = "macOS" ]; then',
    'if ! python3 -I scripts/ci/ensure-age-extension.py --url-file "$url_file"; then',
    'echo "::error::$RUNNER_NAME: AGE self-heal failed (#6161), see the ensure-age-extension line above"',
    'exit 1',
    'fi',
    'fi',
    "# Provision the ephemeral db's extensions (the tier role is SUPERUSER).",
    'if ! psql "$new_url" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS age; CREATE EXTENSION IF NOT EXISTS vector;"; then',
    'echo "::error::$RUNNER_NAME failed to create age/vector extensions in $CI_FED_DB"',
    'exit 1',
    'fi',
    '# Both the pg and AGE test URLs are the same ephemeral db on the',
    '# native tier (a single PG 18.6 + AGE 1.8.0 + pgvector 0.8.7',
    '# instance). Setting AI_MEMORY_TEST_AGE_URL is what stops the',
    '# AGE-backed cells from self-skipping — the whole point of the in-PR',
    '# cert evidence (#2548).',
    '{',
    'echo "AI_MEMORY_TEST_POSTGRES_URL=$new_url"',
    'echo "AI_MEMORY_TEST_AGE_URL=$new_url"',
    '} >> "$GITHUB_ENV"',
    'echo "::notice::cert cells pointed at ephemeral db $CI_FED_DB on the native enterprise-fed tier ($RUNNER_NAME)"',
)
EXPECTED_POINT_AT_RUN_IGNORED = (
    'set -euo pipefail',
    'for d in /usr/lib/postgresql/18/bin /opt/homebrew/opt/postgresql@18/bin; do',
    'if [ -d "$d" ]; then',
    'echo "$d" >> "$GITHUB_PATH"',
    'PATH="$d:$PATH"',
    'fi',
    'done',
    'export PATH',
    'url_file="$HOME/.ai-memory-ci-fed-url"',
    'if [ ! -f "$url_file" ]; then',
    'echo "::error::$RUNNER_NAME is missing $url_file — the native cert tier URL is not provisioned on this node"',
    'exit 1',
    'fi',
    'base_url="$(cat "$url_file")"',
    'CI_FED_DB="$(printf \'%s\' "ai_memory_test_ci_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_ignored" | cut -c1-63)"',
    'echo "CI_FED_DB=$CI_FED_DB" >> "$GITHUB_ENV"',
    'if ! psql "$base_url" -v ON_ERROR_STOP=1 -c "CREATE DATABASE \\"$CI_FED_DB\\";"; then',
    'echo "::error::$RUNNER_NAME failed to CREATE DATABASE $CI_FED_DB on the native cert tier"',
    'exit 1',
    'fi',
    'case "$base_url" in',
    '*\\?*) q="?${base_url#*\\?}"; head="${base_url%%\\?*}" ;;',
    '*)    q=""; head="$base_url" ;;',
    'esac',
    'new_url="${head%/*}/${CI_FED_DB}${q}"',
    '# #6161 - the macos-fed AGE install is hand-built; a Homebrew upgrade',
    '# relinks the postgresql@18 trees and drops its files. These two',
    '# workflows run on EITHER fed node (#8174), so mirror the ci.yml',
    '# `Configure enterprise-fed tier` branch: on macOS self-heal from the',
    '# node-local copy BEFORE CREATE EXTENSION (five sha256-pinned files;',
    '# one-line reason on stderr). Linux is unchanged.',
    '# python3 -I (#6339): the helper builds PGPASSWORD, so no sys.path[0] or PYTHONPATH.',
    'if [ "$RUNNER_OS" = "macOS" ]; then',
    'if ! python3 -I scripts/ci/ensure-age-extension.py --url-file "$url_file"; then',
    'echo "::error::$RUNNER_NAME: AGE self-heal failed (#6161), see the ensure-age-extension line above"',
    'exit 1',
    'fi',
    'fi',
    'if ! psql "$new_url" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS age; CREATE EXTENSION IF NOT EXISTS vector;"; then',
    'echo "::error::$RUNNER_NAME failed to create age/vector extensions in $CI_FED_DB"',
    'exit 1',
    'fi',
    '{',
    'echo "AI_MEMORY_TEST_POSTGRES_URL=$new_url"',
    'echo "AI_MEMORY_TEST_AGE_URL=$new_url"',
    '} >> "$GITHUB_ENV"',
    'echo "::notice::[#3274] ignored pg tests pointed at ephemeral db $CI_FED_DB on $RUNNER_NAME"',
)


PIN_WS = " \t\r"  # the only characters the pin strips: the runner shell is not Unicode-aware


def split_lines(text):
    """Split on LF only: str.splitlines() also splits on U+2028, U+0085 and others the shell keeps."""
    parts = text.split("\n")
    return parts[:-1] if parts and parts[-1] == "" else parts


def lines_of(path):
    return split_lines(path.read_text(encoding="utf-8"))


def runs_on_lists(path):
    found = []
    for ln in lines_of(path):
        m = re.match(r"^    runs-on:\s*\[(.*)\]\s*$", ln)
        if m:
            found.append([x.strip() for x in m.group(1).split(",")])
    return found


def run_blocks(path):
    """Each ``run:`` body as a list of non-comment lines."""
    return run_blocks_of(lines_of(path))


def run_blocks_of(lines):
    """``run_blocks`` over already-split text (used for the in-memory mutation rows)."""
    blocks = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        body = []
        if rest and rest not in ("|", ">", "|-", ">-"):
            body.append(rest)
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            if lines[i].strip() and not lines[i].lstrip().startswith("#"):
                body.append(lines[i])
            i += 1
        blocks.append(body)
    return blocks


STEP_NAME = "Point at the native enterprise-fed tier (per-job ephemeral db)"
# A step is a list item at exactly 6 spaces; the same words as data deeper inside a run block are not one.
STEP_NAME_RX = re.compile(r"^      - name: *" + re.escape(STEP_NAME) + r"[ \t\r]*$")
KEY_RX = re.compile(r"^([A-Za-z_][\w-]*)\s*:")
# decision: pin the workflow-level and job-level env key sets to the live sets over a denylist of
# shell-affecting variable names because a denylist is never complete (BASH_ENV, ENV, SHELLOPTS,
# BASHOPTS, PS4, LD_PRELOAD, PATH, ...) and the pin already compares the step text byte for byte
# (fail-closed precedent PR 8252 cd57f84db; LOW with precedent, no vote).
ENV_KEYS_BY_WORKFLOW = {
    "postgres-ignored.yml": (
        (
            "CARGO_TERM_COLOR",
            "SELF_HOSTED_TARGET_CAP_BYTES",
            "CARGO_INCREMENTAL",
            "CARGO_PROFILE_DEV_DEBUG",
            "CARGO_PROFILE_TEST_DEBUG",
        ),
        (),
    ),
    "cert-postgres-age.yml": (
        (
            "CARGO_TERM_COLOR",
            "SELF_HOSTED_TARGET_CAP_BYTES",
            "CARGO_INCREMENTAL",
            "CARGO_PROFILE_DEV_DEBUG",
        ),
        (),
    ),
}
BODY_DIFFERS = "step body differs from the pinned text at line "
PINNED_OUTSIDE_TOKENS = ("ensure-age-extension.py", "RUNNER_OS")
EXPECTED_BY_WORKFLOW = {
    "cert-postgres-age.yml": EXPECTED_POINT_AT_RUN_CERT,
    "postgres-ignored.yml": EXPECTED_POINT_AT_RUN_IGNORED,
}
# decision: pin the whole workflow skeleton (every non-comment line at indent below 6 outside block
# scalars) as a literal tuple over adding more key-spelling regexes, because ten rounds of per-spelling
# pins each left another YAML spelling open and a literal skeleton refuses any added or changed line in
# any spelling without a decoder (fail-closed precedent PR 8252 cd57f84db; LOW with precedent, no vote).
# The tuples are copied from the workflows, never built from them at test time.
EXPECTED_SKELETON_IGNORED = (
    'name: Postgres ignored tests (#3274)',
    'on:',
    '  pull_request:',
    '    branches: ["release/**", "rehearsal/**", "chain/**"]',
    '  push:',
    '    branches: ["release/**"]',
    '  workflow_dispatch:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: pg-ignored-${{ github.event_name }}-${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}',
    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    'env:',
    '  CARGO_TERM_COLOR: always',
    '  SELF_HOSTED_TARGET_CAP_BYTES: 42949672960',
    '  CARGO_INCREMENTAL: "0"',
    '  CARGO_PROFILE_DEV_DEBUG: "0"',
    '  CARGO_PROFILE_TEST_DEBUG: "0"',
    'jobs:',
    '  postgres-ignored:',
    '    name: "Postgres ignored tests (sal-postgres --ignored)"',
    '    runs-on: [self-hosted, fed]',
    "    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository",
    '    timeout-minutes: 60',
    '    steps:',
)
EXPECTED_SKELETON_CERT = (
    'name: "Certified Postgres + AGE + pgvector tier (#2548)"',
    'on:',
    '  pull_request:',
    '    branches: ["release/**", "rehearsal/**", "chain/**"]',
    '  push:',
    '    branches: ["release/**"]',
    '  workflow_dispatch:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: cert-pg-age-${{ github.event_name }}-${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}',
    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    'env:',
    '  CARGO_TERM_COLOR: always',
    '  SELF_HOSTED_TARGET_CAP_BYTES: 42949672960',
    '  CARGO_INCREMENTAL: "0"',
    '  CARGO_PROFILE_DEV_DEBUG: "0"',
    'jobs:',
    '  cert-postgres-age:',
    '    name: "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)"',
    '    runs-on: [self-hosted, fed]',
    "    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository",
    '    timeout-minutes: 60',
    '    steps:',
)
# decision: pin the pinned job's complete step list as a literal tuple at every indent and refuse any deep
# line above steps: over adding per-step regexes for the earlier steps, because the r11 skeleton pin already
# proved a literal tuple refuses every added or changed line in any spelling and extending its reach to the
# step list and the deep lines closes both r11 findings with the same mechanism (precedent PR 8252 e1e4b84f7;
# LOW with precedent, no vote).
# The step-list tuples are copied from the workflows, never built from them at test time.
EXPECTED_STEPS_IGNORED = (
    '      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4',
    '        with:',
    '          persist-credentials: false',
    '      - name: Assert rustup is provisioned (self-hosted; fail-closed #3128)',
    "        if: runner.environment != 'github-hosted'",
    '        shell: bash',
    '        run: |',
    '      - name: Install Rust 1.98.0 (matches rust-toolchain.toml pin)',
    '        uses: dtolnay/rust-toolchain@f8be11a05b1d4f3fcebe6410cc16743212b999b0 # 1.98.0',
    '      - name: Point at the native enterprise-fed tier (per-job ephemeral db)',
    '        run: |',
    '      - name: cargo test --features sal-postgres -- --ignored',
    '        run: |',
    '      - name: Cleanup enterprise-fed ephemeral db',
    '        if: always()',
    '        run: |',
    '      - name: Sweep target/debug to the size cap (self-hosted)',
    "        if: always() && runner.environment == 'self-hosted'",
    '        run: python3 scripts/ci-sweep-target.py --target target --max-bytes ${{ env.SELF_HOSTED_TARGET_CAP_BYTES }}',
)
EXPECTED_STEPS_CERT = (
    '      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4',
    '        with:',
    '          persist-credentials: false',
    '      - name: Assert rustup is provisioned (self-hosted; fail-closed #3128)',
    "        if: runner.environment != 'github-hosted'",
    '        shell: bash',
    '        run: |',
    '      - name: Install Rust 1.98.0 (matches rust-toolchain.toml pin)',
    '        uses: dtolnay/rust-toolchain@f8be11a05b1d4f3fcebe6410cc16743212b999b0 # 1.98.0',
    '        with:',
    '          components: clippy',
    '      - name: Point at the native enterprise-fed tier (per-job ephemeral db)',
    '        run: |',
    '      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2',
    "        if: runner.environment == 'github-hosted'",
    '      - name: Resolve certified stack pins from deploy SSOT',
    '        run: |',
    '      - name: Wait for native tier readiness',
    '        run: |',
    '      - name: Ensure AGE + vector extensions present (best-effort — tier is pre-provisioned)',
    '        run: |',
    '      - name: Assert certified stack versions (cert evidence, hard-fail on drift)',
    '        run: |',
    '      - name: Run #[ignore]-gated pg + AGE cells against the certified stack',
    '        run: |',
    '      - name: Cluster-A cert-posture armability gate (#3061 #3016 #3067)',
    '        run: |',
    '      - name: Redact cert-bootstrap evidence on failure',
    '        if: failure()',
    '        run: |',
    '      - name: Upload cert-bootstrap evidence on failure',
    '        if: failure()',
    '        uses: actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4 # v5',
    '        with:',
    '          name: cert-bootstrap-evidence-${{ github.run_id }}-${{ github.run_attempt }}',
    '          path: .local-runs/cert-bootstrap-evidence-redacted/',
    '          if-no-files-found: ignore',
    '          retention-days: 7',
    '      - name: Cleanup enterprise-fed ephemeral db',
    '        if: always()',
    '        run: |',
    '      - name: Sweep target/debug to the size cap (self-hosted)',
    "        if: always() && runner.environment == 'self-hosted'",
    '        run: python3 scripts/ci-sweep-target.py --target target --max-bytes ${{ env.SELF_HOSTED_TARGET_CAP_BYTES }}',
)
STEPS_BY_WORKFLOW = {
    "postgres-ignored.yml": EXPECTED_STEPS_IGNORED,
    "cert-postgres-age.yml": EXPECTED_STEPS_CERT,
}
SKELETON_BY_WORKFLOW = {
    "postgres-ignored.yml": EXPECTED_SKELETON_IGNORED,
    "cert-postgres-age.yml": EXPECTED_SKELETON_CERT,
}
SKELETON_INDENT = 6  # a step item sits at indent 6; the skeleton is every line shallower than that
BLOCK_SCALAR_RX = re.compile(r"(?:^|[\s:\-])[|>][+-]?\d?[+-]?(?:[ \t]+#.*)?$")
# These leads (explicit key, anchor, tag, alias, merge key) and a backslash inside quotes can spell any
# key; neither live workflow uses one at indent below 6, so a skeleton line carrying one is refused.
SPELL_ANY_KEY_LEADS = "?&!*<"
QUOTED_BACKSLASH_RX = re.compile(r"[\"'][^\"']*\\")
NO_JOBS_DEFECT = "workflow has no exact jobs: line at indent 0"
NO_STEPS_DEFECT = "workflow has no exact steps: line at indent 4"
STEPS_LINE = "    steps:"
YAML_ONLY_BREAKS = ("\x85", "\u2028", "\u2029", "\r")


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def is_skipped(line):
    """Blank or comment line: YAML ignores its indentation, so it never ends a step."""
    text = line.strip(PIN_WS)
    return not text or text.startswith("#")


def as_lines(source):
    """``source`` is a workflow ``Path`` or already-split text (the in-memory mutation rows)."""
    return lines_of(source) if isinstance(source, Path) else list(source)


def key_column(text):
    """Column of the first mapping key on ``text``: the indent plus any ``- `` list-item prefixes."""
    column = indent_of(text)
    rest = text[column:]
    while rest.startswith("- "):
        trimmed = rest[2:].lstrip(" ")
        column += len(rest) - len(trimmed)
        rest = trimmed
    return column


def code_lines(lines):
    """``(1-based file line number, indent, text)`` of every non-blank, non-comment line outside a block
    scalar (``|`` or ``>`` and their chomping forms), trailing whitespace stripped, in file order."""
    block_above = None
    for number, line in enumerate(lines, 1):
        if is_skipped(line):
            continue
        indent = indent_of(line)
        if block_above is not None:
            if indent > block_above:
                continue
            block_above = None
        text = line.rstrip(PIN_WS)
        if BLOCK_SCALAR_RX.search(text):
            block_above = key_column(text)
        yield number, indent, text


def skeleton_of(lines):
    """``(1-based file line number, text)`` of every skeleton line: a ``code_lines`` line at indent below 6."""
    return [(number, text) for number, indent, text in code_lines(lines) if indent < SKELETON_INDENT]


def steps_line(lines):
    """1-based number of the first exact ``    steps:`` line, or ``None``."""
    return next((n for n, ln in enumerate(lines, 1) if ln.rstrip(PIN_WS) == STEPS_LINE), None)


def step_list_of(lines):
    """``(number, text)`` of every ``code_lines`` line, at any indent, after ``    steps:`` up to the first line
    at indent below 6 (the end of the job); block-scalar content is outside it (the run-text pin owns it)."""
    first = steps_line(lines)
    if first is None:
        return []
    found = []
    for number, indent, text in code_lines(lines):
        if number <= first:
            continue
        if indent < SKELETON_INDENT:
            break
        found.append((number, text))
    return found


def pin_defects(live, expected, label, total):
    """Named defects of every added, removed, changed or reordered line of ``live`` against ``expected``;
    ``label`` names the pin in each message and ``total`` is the file's line count."""
    matcher = SequenceMatcher(None, [text for _, text in live], list(expected), autojunk=False)
    added, changed, removed = [], [], []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        pair = min(i2 - i1, j2 - j1) if tag == "replace" else 0
        changed += [(live[i1 + k][0], live[i1 + k][1], expected[j1 + k]) for k in range(pair)]
        added += live[i1 + pair : i2]
        before = live[i1][0] if i1 < len(live) else total + 1
        removed += [(before, expected[k]) for k in range(j1 + pair, j2)]
    moved = {text for _, text in added} & {text for _, text in removed}
    found = [(n, "%s line %d %s: %s" % (label, n, "reordered" if t in moved else "added", t)) for n, t in added]
    found += [(n, "%s line %d changed: %s (expected: %s)" % (label, n, t, want)) for n, t, want in changed]
    found += [(n, "%s line removed before line %d: %s" % (label, n, t)) for n, t in removed if t not in moved]
    return [message for _, message in sorted(found, key=lambda item: item[0])]


def skeleton_defects(lines, workflow):
    """Named defects of every added, removed, changed or reordered skeleton line, in file order."""
    return pin_defects(skeleton_of(lines), SKELETON_BY_WORKFLOW[workflow], "skeleton", len(lines))


def step_list_defects(lines, workflow):
    """Named defects of every added, removed, changed or reordered line of the whole step list."""
    return pin_defects(step_list_of(lines), STEPS_BY_WORKFLOW[workflow], "step-list", len(lines))


def deep_line_defects(lines):
    """Every ``code_lines`` line at indent 6 or deeper above ``    steps:``: a plain-scalar continuation there
    changes the value YAML reads while every skeleton line stays equal. Comments are never code lines."""
    first = steps_line(lines)
    if first is None:
        return [NO_STEPS_DEFECT]
    return [
        "deep line %d above steps: (indent %d): %s" % (number, indent, text.strip())
        for number, indent, text in code_lines(lines)
        if number < first and indent >= SKELETON_INDENT
    ]


def line_break_defects(lines):
    """Every line carrying U+0085, U+2028, U+2029 or a CR before the last character. These end a line for
    PyYAML but not for the LF split, so a line-based pin sees one comment line where YAML reads a key
    (a membership test, not ``str.splitlines()``, so the file's own line numbers stay the LF ones)."""
    found = []
    for number, line in enumerate(lines, 1):
        body = line.rstrip("\r")
        for ch in YAML_ONLY_BREAKS:
            if ch in body:
                found.append(
                    "line %d carries U+%04X (a line break for YAML, not for the LF split): %s"
                    % (number, ord(ch), ascii(line.strip(PIN_WS)))
                )
    return found


def skeleton_form_defects(lines):
    """Skeleton lines whose form can spell any key: ``?``, ``&``, ``!``, ``*`` or ``<`` first, or a backslash in quotes."""
    found = []
    for number, text in skeleton_of(lines):
        content = text.lstrip(" \t")
        while content.startswith("- "):
            content = content[2:].lstrip(" \t")
        if (content and content[0] in SPELL_ANY_KEY_LEADS) or QUOTED_BACKSLASH_RX.search(text):
            found.append(
                "skeleton line %d can spell any key (explicit key, anchor, tag, alias, merge key or escape): %s"
                % (number, text)
            )
    return found


def env_keys(lines, key_indent):
    """Keys of every ``env:`` block whose ``env:`` line sits at ``key_indent - 2`` (a flow or inline ``env:`` is one key)."""
    found = []
    in_env = False
    head = key_indent - 2
    for ln in lines:
        text = ln.strip(PIN_WS)
        if not text or text.startswith("#"):
            continue
        ind = indent_of(ln)
        if ind == head:
            in_env = text == "env:"
            if text.startswith("env:") and not in_env:
                found.append(text)
        elif ind < head:
            in_env = False
        elif in_env and ind == key_indent:
            found.append(text.split(":", 1)[0].strip())
    return found


def env_defects(lines, workflow):
    """Named defects when the workflow-level or job-level ``env`` key set differs from the pinned set."""
    wf_expected, job_expected = ENV_KEYS_BY_WORKFLOW[workflow]
    # Workflow level: ``env:`` at indent 0, keys at indent 2. Job level: ``env:`` at indent 4 inside
    # ``jobs:``, keys at indent 6.
    levels = (
        ("workflow", wf_expected, env_keys(lines, 2)),
        ("job", job_expected, env_keys_in_jobs(lines)),
    )
    defects = []
    for level, expected, got in levels:
        for key in got:
            if got.count(key) > 1 and key in expected:
                defects.append("%s-level env key duplicated: %s" % (level, key))
            elif key not in expected:
                defects.append("%s-level env key added: %s" % (level, key))
        defects += ["%s-level env key removed: %s" % (level, k) for k in expected if k not in got]
    return list(dict.fromkeys(defects))


def env_keys_in_jobs(lines):
    """Keys of every job-level ``env:`` block (``env:`` at indent 4, keys at indent 6, under ``jobs:``)."""
    start = next((i for i, ln in enumerate(lines) if ln.rstrip(PIN_WS) == "jobs:"), None)
    if start is None:
        return []
    end = start + 1
    while end < len(lines) and (is_skipped(lines[end]) or indent_of(lines[end]) > 0):
        end += 1
    return env_keys(lines[start + 1 : end], 6)


def heal_defects(source, workflow="postgres-ignored.yml"):
    """Named defects of the pinned "Point at the native enterprise-fed tier" step; ``[]`` when clean.

    The step is pinned as a whole (decision: fixed-shape pin of the whole "Point at the native
    enterprise-fed tier (per-job ephemeral db)" run block over a sixth per-construct refusal round
    because five review rounds (r3-r7) each found a bash text shape the line scanner misreads, and
    a byte-for-byte pin has no shell lexing left to probe while changing nothing that runs in CI;
    3-agent vote (6def5ab6), 3-0, memory 8da30b8e; packet VOTE-8252-guard-shape.md.):
    exactly one such step; only the keys ``name`` and ``run``; the stripped, blank-dropped lines of
    ``run: |`` equal the pinned tuple for that workflow; ``ensure-age-extension.py`` and ``RUNNER_OS``
    occur nowhere outside that block (so the workflow-level ``env:`` block cannot carry ``RUNNER_OS``);
    exactly one ``name`` key; the workflow skeleton equals the pinned tuple (``skeleton_defects``), no
    skeleton line has a key-spelling form (``skeleton_form_defects``), an exact ``jobs:`` line exists, the
    whole step list equals the pinned tuple (``step_list_defects``), no code line at indent 6 or deeper
    sits above ``    steps:`` (``deep_line_defects``) and no line carries a YAML-only line break
    (``line_break_defects``).
    A ``Path`` selects the pinned tuple by file name; in-memory lines take ``workflow`` (default
    ``postgres-ignored.yml``).
    """
    lines = as_lines(source)
    expected = EXPECTED_BY_WORKFLOW[getattr(source, "name", workflow)]
    heads = [i for i, ln in enumerate(lines) if STEP_NAME_RX.match(ln)]
    if len(heads) != 1:
        return ["step named %r occurs %d times, expected exactly 1" % (STEP_NAME, len(heads))]
    at = heads[0]
    dash = indent_of(lines[at])
    # decision: the step's extent ends at the next non-blank non-comment line at or below the dash
    # indent and the key scan covers the whole extent, over stopping at the first comment, because
    # YAML ignores comment indentation and a key written after a comment is still a step key
    # (fail-closed precedent PR 8252 cd57f84db; LOW with precedent, no vote).
    end = at + 1
    while end < len(lines) and (is_skipped(lines[end]) or indent_of(lines[end]) > dash):
        end += 1
    defects = []
    # decision: ASCII-only step text with a "\n"-only split and " \t\r"-only strip over Unicode-aware
    # splitlines/strip because the runner shell reads bytes and the pin must compare what the shell
    # executes (byte-for-byte docstring at :18; LOW with precedent, no vote).
    # The two live run blocks print an em dash inside an echo string; a line is exempt only when its
    # stripped text IS a line of the pinned tuple (the body pin below then compares it byte for byte).
    # A comment line may carry printable non-ASCII (the live HOSTED ONLY block does) but never a control
    # character or a Unicode line break; a comment inside the run body is also compared by the body pin.
    for i in range(at, end):
        stripped = lines[i].strip(PIN_WS)
        if stripped in expected:
            continue
        comment = stripped.startswith("#")
        for ch in lines[i].rstrip("\r"):
            bad_control = (ord(ch) < 32 and ch != "\t") or ord(ch) in (127, 0x85, 0x2028, 0x2029)
            if bad_control or (ord(ch) > 126 and not comment):
                defects.append(
                    "step line %d carries U+%04X (non-ASCII or control character): %s"
                    % (i + 1, ord(ch), ascii(lines[i].strip(PIN_WS)))
                )
                break
    if defects:
        return defects
    keys = []
    for i in range(at + 1, end):
        text = lines[i].strip(PIN_WS)
        if text and not text.startswith("#") and indent_of(lines[i]) == dash + 2:
            hit = KEY_RX.match(text)
            keys.append((i, hit.group(1) if hit else text))
    defects += ["step has a key other than name and run: " + k for _, k in keys if k not in ("name", "run")]
    names = sum(1 for _, k in keys if k == "name") + 1  # the list item itself is the first name key
    if names > 1:
        defects.append("step has %d name keys, expected exactly 1" % names)
    runs = [i for i, k in keys if k == "run"]
    inside = range(0)
    if len(runs) != 1:
        defects.append("step has %d run keys, expected exactly 1" % len(runs))
    elif lines[runs[0]].strip(PIN_WS) != "run: |":
        defects.append("step run key is not a literal block: " + lines[runs[0]].strip(PIN_WS))
    else:
        # The run body ends at the first non-blank line at or below the key indent, comment or not.
        body_end = runs[0] + 1
        while body_end < len(lines) and (not lines[body_end].strip(PIN_WS) or indent_of(lines[body_end]) > dash + 2):
            body_end += 1
        inside = range(runs[0] + 1, body_end)
        got = [lines[i].strip(PIN_WS) for i in inside if lines[i].strip(PIN_WS)]
        for k, (g, w) in enumerate(zip_longest(got, expected), 1):
            if g != w:
                defects.append(
                    BODY_DIFFERS + "%d: %s != %s"
                    % (k, "(block ends)" if g is None else g, "(block ends)" if w is None else w)
                )
                break
    name = getattr(source, "name", workflow)
    defects += env_defects(lines, name)
    defects += skeleton_defects(lines, name)
    defects += skeleton_form_defects(lines)
    defects += step_list_defects(lines, name)
    defects += deep_line_defects(lines)
    defects += line_break_defects(lines)
    if not any(ln.rstrip(PIN_WS) == "jobs:" for ln in lines):
        defects.append(NO_JOBS_DEFECT)
    for i, ln in enumerate(lines):
        if i in inside:
            continue
        defects += [
            "%s outside the Point-at run block: %s" % (tok, ln.strip(PIN_WS))
            for tok in PINNED_OUTSIDE_TOKENS
            if tok in ln
        ]
    return defects


def linux_only_defects(source):
    """Linux-only tools or paths (nproc, /proc/, free) in any run block."""
    return [
        "linux-only " + name
        for body in run_blocks_of(as_lines(source))
        for ln in body
        for name, rx in LINUX_ONLY_TOKENS
        if rx.search(ln)
    ]


def twin_defects(source):
    """A /usr/lib/postgresql search path without the homebrew bin dir beside it."""
    return [
        "no homebrew twin"
        for body in run_blocks_of(as_lines(source))
        for ln in body
        if POSTGRES_LINUX_BIN in ln and POSTGRES_MACOS_BIN not in ln
    ]


# One named table of checks: the property tests and the mutation rows both read it.
MACOS_CHECKS = (heal_defects, linux_only_defects, twin_defects)


def macos_defects(source):
    """All defects of one workflow (a ``Path`` or split text), from every check in MACOS_CHECKS."""
    return [d for check in MACOS_CHECKS for d in check(source)]


HEAL_CALL = (
    '            if ! python3 -I scripts/ci/ensure-age-extension.py --url-file "$url_file"; then\n'
    '              echo "::error::$RUNNER_NAME: AGE self-heal failed (#6161), see the ensure-age-extension line above"\n'
    "              exit 1\n"
    "            fi\n"
)
GUARD_END = HEAL_CALL + "          fi\n"
GUARD_LINE = '          if [ "$RUNNER_OS" = "macOS" ]; then\n'
NEW_URL_LINE = "          new_url=\"${head%/*}/${CI_FED_DB}${q}\"\n"
STEP_HEAD = "      - name: Point at the native enterprise-fed tier (per-job ephemeral db)\n"
# Mutation table (code r1 F1/F2): name -> (old text, new text) applied to an in-memory copy of
# postgres-ignored.yml. Every row must make macos_defects report a defect.
MUTATIONS = {
    "M11 heal call moved after the guard fi": (
        GUARD_END,
        "          if true; then\n            :\n          fi\n" + HEAL_CALL.replace("            ", "          "),
    ),
    "M19 guard fi indented deeper, heal block after it at the guard indent": (
        GUARD_END,
        "            :\n            fi\n" + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True)),
    ),
    "M20 one-line if/fi in the guard, heal after the real fi, later mid-line if (sec r4 F1 = code r4 O1)": (
        GUARD_END,
        "            if true; then :; fi\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          x=1; if true; then\n            :\n          fi\n",
    ),
    "M21 heredoc body carries if x / fi, heal after the real fi (code r5 F1 = sec r5 F1, x1)": (
        GUARD_END,
        "            cat <<'EOF'\n            if x\n          EOF\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          cat <<'EOF'\n          fi\n          EOF\n",
    ),
    "M22 backslash-continued command whose next line is if x / fi (x2)": (
        GUARD_END,
        "            echo a \\\n            if x\n          fi\n"
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + "          echo b \\\n          fi\n",
    ),
    "M23 multi-line double-quoted string carries if x / fi (x3)": (
        GUARD_END,
        '            echo "a\n            if x\n            b"\n          fi\n'
        + "".join(x[2:] for x in HEAL_CALL.splitlines(keepends=True))
        + '          echo "a\n          fi\n          b"\n',
    ),
    "M24 mixed-quote multi-line string hides if x / fi, heal after the real fi (code r6 x9 = sec r6 y1)": (
        GUARD_END,
        "            echo \"'\" '\n            if x\n            x' \"'\"\n            fi\n"
        + HEAL_CALL
        + "            echo \"'\" '\n          fi\n          x' \"'\"\n",
    ),
    "M25 backslash inside single quotes hides if x / fi, heal after the real fi (code r6 x10 = sec r6 y2)": (
        GUARD_END,
        "            echo 'a\\'b'\n            if x\n            x\\'\n            fi\n"
        + HEAL_CALL
        + "            echo 'a\\'b'\n          fi\n          x\\'\n",
    ),
    "M26 heal call is data inside a mixed-quote string in the guard (code r6 x11)": (
        GUARD_END,
        "            echo \"'\" '\n" + HEAL_CALL + "            x' \"'\"\n          fi\n",
    ),
    "M27 multi-line (( )) names if / fi as variables, heal after the real fi (sec r6 y3)": (
        GUARD_END,
        "            (( a = 0 +\n            if +\n            1 ))\n            fi\n"
        + HEAL_CALL
        + "            (( a = 0 +\n          fi\n          + 1 ))\n",
    ),
    "M28 here-document opened before the guard swallows the guard line, heal runs on every OS (code r7 w1)": (
        GUARD_LINE,
        "          if true; then cat >/dev/null <<'" + GUARD_LINE.strip() + "'\n" + GUARD_LINE,
    ),
    "M29 RUNNER_OS=macOS assigned before the guard (sec r7 W1)": (
        GUARD_LINE,
        "          RUNNER_OS=macOS\n" + GUARD_LINE,
    ),
    "M30 the whole guard sits inside a single-quoted string opened before it (sec r7 W2)": (
        GUARD_LINE + GUARD_END,
        "          : '\n" + GUARD_LINE + GUARD_END + "          '\n",
    ),
    "M31 [ is shadowed by a function before the guard (sec r7 W3)": (
        GUARD_LINE,
        "          [() { return 1; }\n" + GUARD_LINE,
    ),
    "M32 step-level env key added to the step": (
        STEP_HEAD + "        run: |\n",
        STEP_HEAD + "        env:\n          RUNNER_OS: macOS\n        run: |\n",
    ),
    "M33 a second step with the same name": (
        STEP_HEAD,
        STEP_HEAD + "        run: |\n          echo decoy\n\n" + STEP_HEAD,
    ),
    "M34 shell key on the step": (
        STEP_HEAD + "        run: |\n",
        STEP_HEAD + "        shell: bash -e {0}\n        run: |\n",
    ),
    "M35 RUNNER_OS in the workflow-level env block": (
        "env:\n  CARGO_TERM_COLOR: always\n",
        "env:\n  CARGO_TERM_COLOR: always\n  RUNNER_OS: macOS\n",
    ),
    "M12 nproc added": (GUARD_END, GUARD_END + "          nproc\n"),
    "M13 /proc/meminfo added": (GUARD_END, GUARD_END + "          cat /proc/meminfo\n"),
    "M14 postgresql bin loop without homebrew twin": (
        GUARD_END,
        GUARD_END + "          for d in /usr/lib/postgresql/18/bin; do :; done\n",
    ),
}


# Round 9 rows (security r8 F1): a step key written after a comment line. Each row inserts lines into
# a copy of one workflow: (workflow index in WORKFLOWS, where, inserted lines, expected key).
# ``after_body`` = right after the last body line of the step; ``before_next`` = just above the next
# ``      - `` item, i.e. after the comment block that follows the step.
ROWS9 = {
    "M36 cert, continue-on-error after the indent-6 comment block (sec r8 H1)": (
        1, "before_next", ("        continue-on-error: true",), "continue-on-error"),
    "M37 cert, if after a column-0 comment (sec r8 H2)": (
        1, "after_body", ("# column zero note", "        if: runner.os == 'Linux'"), "if"),
    "M38 ign, continue-on-error after an indent-6 comment (sec r8 H3)": (
        0, "after_body", ("      # note", "        continue-on-error: true"), "continue-on-error"),
    "M39 cert, working-directory after an indent-4 comment (sec r8 H4)": (
        1, "after_body", ("    # note", "        working-directory: ."), "working-directory"),
    "M40 ign, shell after an indent-8 comment inside the step": (
        0, "after_body", ("        # note", "        shell: bash"), "shell"),
}


def insert_lines(idx, where, new):
    """The text of ``WORKFLOWS[idx]`` split into lines with ``new`` inserted after the Point-at step body."""
    lines = WORKFLOWS[idx].read_text(encoding="utf-8").splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.strip() == "- name: " + STEP_NAME)
    nxt = next(i for i in range(at + 1, len(lines)) if lines[i].startswith("      - "))
    if where == "before_next":
        pos = nxt
    else:
        pos = nxt
        while not lines[pos - 1].strip() or (lines[pos - 1].lstrip().startswith("#") and indent_of(lines[pos - 1]) <= 6):
            pos -= 1
    return lines[:pos] + list(new) + lines[pos:]


def yaml_step_keys(lines):
    """Keys of the Point-at step as PyYAML sees them (the live truth the line pin is compared with)."""
    doc = yaml.safe_load("\n".join(lines) + "\n")
    steps = [st for job in doc["jobs"].values() for st in job["steps"] if st.get("name") == STEP_NAME]
    assert len(steps) == 1, steps
    return list(steps[0])


class PgWorkflowsRunOnEitherFedNode(unittest.TestCase):
    def test_runs_on_is_the_shared_fed_label(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(runs_on_lists(path), [EXPECTED_RUNS_ON])

    def test_no_gnu_only_token_in_any_run_block(self):
        for path in WORKFLOWS:
            blocks = run_blocks(path)
            self.assertGreaterEqual(len(blocks), 4, path.name)
            for body in blocks:
                for ln in body:
                    for name, rx in GNU_ONLY_TOKENS:
                        with self.subTest(workflow=path.name, token=name):
                            self.assertIsNone(rx.search(ln), ln.strip())

    def test_macos_age_self_heal_is_behind_a_runner_os_check(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                text = "\n".join("\n".join(b) for b in run_blocks(path))
                create_anchor = "CREATE EXTENSION IF NOT EXISTS age"
                for anchor in (HEAL_GUARD, HEAL_SCRIPT, create_anchor):
                    # code r7 F2: the message names the anchor and the workflow only, never the
                    # run block (assertIn would append the whole container text).
                    self.assertTrue(
                        anchor in text,
                        "anchor absent from the run blocks of %s: %s" % (path.relative_to(REPO).as_posix(), anchor),
                    )
                guard_at = text.index(HEAL_GUARD)
                heal_at = text.index(HEAL_SCRIPT)
                create_at = text.index(create_anchor)
                self.assertLess(guard_at, heal_at)
                self.assertLess(heal_at, create_at)

    def _assert_check_clean(self, check):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name, check=check.__name__):
                self.assertEqual(check(path), [])

    def test_point_at_step_matches_the_pin_in_both_workflows(self):
        """The live truth row: both workflows are byte-for-byte the pinned step (stripped lines)."""
        self._assert_check_clean(heal_defects)

    def test_no_linux_only_tool_or_path_in_any_run_block(self):
        """code r1 F2: nproc and /proc are absent on macOS."""
        self._assert_check_clean(linux_only_defects)

    def test_every_linux_postgres_bin_path_has_its_homebrew_twin(self):
        """code r1 F2: a /usr/lib/postgresql search path needs the macOS bin dir beside it."""
        self._assert_check_clean(twin_defects)

    def test_unmutated_workflows_have_no_macos_defect(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(macos_defects(path), [])

    def test_pinned_tuples_are_the_guard_and_heal_text_of_each_workflow(self):
        """The tuples hold the guard line and the heal call once each, in order, and differ per workflow."""
        for const in (EXPECTED_POINT_AT_RUN_CERT, EXPECTED_POINT_AT_RUN_IGNORED):
            at = const.index(HEAL_GUARD)
            self.assertEqual(const[at + 1 : at + 5], tuple(x.strip() for x in HEAL_CALL.splitlines()))
            self.assertEqual(const[at + 5], "fi")
            self.assertEqual(sum(HEAL_SCRIPT in x for x in const), 1)
            self.assertEqual(sum("RUNNER_OS" in x for x in const if x.startswith("if [")), 1)
        self.assertNotEqual(EXPECTED_POINT_AT_RUN_CERT, EXPECTED_POINT_AT_RUN_IGNORED)

    def _defects(self, old, new, workflow=0):
        """heal_defects of one workflow text with ``old`` replaced by ``new`` (anchor must be unique)."""
        path = WORKFLOWS[workflow]
        base = path.read_text(encoding="utf-8")
        self.assertEqual(base.count(old), 1, "anchor drifted: " + old.strip())
        return heal_defects(base.replace(old, new, 1).splitlines(), path.name)

    def _added(self, idx, old, new, text):
        """The skeleton defect the pin names for the line ``text`` that ``new`` adds in place of ``old``."""
        lines = WORKFLOWS[idx].read_text(encoding="utf-8").replace(old, new, 1).split("\n")
        return "skeleton line %d added: %s" % (next(n for n, ln in enumerate(lines, 1) if ln.rstrip() == text), text)

    def _added_block(self, idx, head):
        """The three skeleton defects of ``head`` + ``  run:`` + ``    shell: bash`` inserted above ``jobs:``."""
        new = head + "\n  run:\n    shell: bash\njobs:\n"
        return [self._added(idx, "jobs:\n", new, t) for t in (head, "  run:", "    shell: bash")]

    def _row(self, prefix):
        name = next(n for n in MUTATIONS if n.startswith(prefix + " "))
        old, new = MUTATIONS[name]
        return self._defects(old, new)

    def _assert_body_differs(self, got):
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(BODY_DIFFERS), got)

    def test_every_mutation_row_is_detected(self):
        """Every MUTATIONS row (M11-M35) applied to an in-memory copy must be reported."""
        base = WORKFLOWS[0].read_text(encoding="utf-8")
        for name, (old, new) in MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(base.count(old), 1, "mutation anchor drifted")
                self.assertNotEqual(macos_defects(base.replace(old, new, 1).splitlines()), [])

    def test_m28_heredoc_before_the_guard_is_refused(self):
        """code r7 w1: the guard line is the delimiter of a here-document opened before it."""
        self._assert_body_differs(self._row("M28"))

    def test_m29_runner_os_assigned_before_the_guard_is_refused(self):
        """security r7 W1."""
        self._assert_body_differs(self._row("M29"))

    def test_m30_guard_inside_a_single_quoted_string_is_refused(self):
        """security r7 W2."""
        self._assert_body_differs(self._row("M30"))

    def test_m31_bracket_shadowed_by_a_function_is_refused(self):
        """security r7 W3."""
        self._assert_body_differs(self._row("M31"))

    def test_m32_step_level_env_key_is_refused(self):
        got = self._row("M32")
        self.assertIn("step has a key other than name and run: env", got)
        self.assertIn("RUNNER_OS outside the Point-at run block: RUNNER_OS: macOS", got)

    def test_m33_second_step_with_the_same_name_is_refused(self):
        got = self._row("M33")
        self.assertEqual(len(got), 1, got)
        self.assertIn("occurs 2 times, expected exactly 1", got[0])

    def _key_then_step_list(self, got, key):
        """The step-key defect first, then only step-list defects (the added key line is a step-list line)."""
        self.assertEqual(got[0], "step has a key other than name and run: " + key, got)
        self.assertTrue(len(got) == 2 and got[1].startswith("step-list line "), got)

    def test_m34_shell_key_on_the_step_is_refused(self):
        self._key_then_step_list(self._row("M34"), "shell")

    def test_m35_runner_os_in_the_workflow_level_env_block_is_refused(self):
        self.assertEqual(
            self._row("M35"),
            [
                "workflow-level env key added: RUNNER_OS",
                self._added(
                    0,
                    "env:\n  CARGO_TERM_COLOR: always\n",
                    "env:\n  CARGO_TERM_COLOR: always\n  RUNNER_OS: macOS\n",
                    "  RUNNER_OS: macOS",
                ),
                "RUNNER_OS outside the Point-at run block: RUNNER_OS: macOS",
            ],
        )

    def test_body_defect_names_the_first_differing_line(self):
        at = EXPECTED_POINT_AT_RUN_IGNORED.index(HEAL_GUARD) + 1
        got = self._defects(GUARD_LINE, GUARD_LINE + "            echo extra\n")
        self.assertEqual(
            got,
            [BODY_DIFFERS + "%d: echo extra != %s" % (at + 1, EXPECTED_POINT_AT_RUN_IGNORED[at])],
        )

    def test_body_defect_names_a_truncated_block(self):
        last = EXPECTED_POINT_AT_RUN_IGNORED[-1]
        got = self._defects("          " + last + "\n", "")
        self.assertEqual(
            got, [BODY_DIFFERS + "%d: (block ends) != %s" % (len(EXPECTED_POINT_AT_RUN_IGNORED), last)]
        )

    def _body_shifted(self, shift):
        """postgres-ignored.yml defects with every line of the Point-at run block indented by ``shift``."""
        lines = WORKFLOWS[0].read_text(encoding="utf-8").splitlines(keepends=True)
        at = next(i for i, ln in enumerate(lines) if ln.strip() == "- name: " + STEP_NAME)
        end = next(i for i in range(at + 1, len(lines)) if lines[i].startswith("      - "))
        out = lines[: at + 2] + [" " * shift + x if x.strip() else x for x in lines[at + 2 : end]] + lines[end:]
        return heal_defects("".join(out).splitlines(), "postgres-ignored.yml")

    def test_noop_run_block_reindent_is_accepted(self):
        """Pin control (b): the pin strips, so a uniform re-indent of the run block changes nothing."""
        self.assertEqual(self._body_shifted(2), [])

    def test_noop_blank_line_inside_the_run_block_is_accepted(self):
        """Pin control (c): blank lines are dropped."""
        self.assertEqual(self._defects(NEW_URL_LINE, NEW_URL_LINE + "\n"), [])

    def test_noop_trailing_whitespace_is_accepted(self):
        """Pin control (d)."""
        self.assertEqual(self._defects(NEW_URL_LINE, NEW_URL_LINE.rstrip("\n") + "   \n"), [])

    def test_noop_whole_guard_reindent_is_accepted(self):
        whole = GUARD_LINE + GUARD_END
        shifted = "".join("  " + x for x in whole.splitlines(keepends=True))
        self.assertEqual(self._defects(whole, shifted), [])

    def test_comment_inserted_inside_the_step_is_refused_by_design(self):
        """Pin control (a): a byte pin refuses every change inside the step, a comment included."""
        got = self._defects(NEW_URL_LINE, NEW_URL_LINE + "          # note\n")
        self._assert_body_differs(got)
        self.assertIn(": # note != ", got[0])

    def test_legitimate_comment_word_edit_is_refused_until_the_pin_is_updated(self):
        """Maintenance cost: the pinned text is updated in the same PR as any edit to the step."""
        old = "          # Create the ephemeral db on the base tier (connected to ai_memory_test).\n"
        got = self._defects(old, old.replace("Create", "Make"), workflow=1)
        self._assert_body_differs(got)
        self.assertIn("# Make the ephemeral db", got[0])

    def test_valid_elif_and_case_bodies_are_named_defects(self):
        """Shapes absent from the live guards are refused, not guessed at."""
        elif_body = (
            "            if a; then\n              :\n            elif b; then\n              :\n"
            "            else\n              :\n            fi\n"
        )
        case_body = '            case "$x" in\n              a) : ;;\n            esac\n'
        for label, body in (("elif", elif_body), ("case", case_body)):
            with self.subTest(shape=label):
                self._assert_body_differs(self._defects(GUARD_LINE, GUARD_LINE + body))

    def test_heal_script_named_outside_the_point_at_run_block_is_refused(self):
        got = self._defects(
            "env:\n  CARGO_TERM_COLOR: always\n",
            "env:\n  CARGO_TERM_COLOR: always\n  HEAL: scripts/ci/ensure-age-extension.py\n",
        )
        self.assertEqual(
            got,
            [
                "workflow-level env key added: HEAL",
                self._added(
                    0,
                    "env:\n  CARGO_TERM_COLOR: always\n",
                    "env:\n  CARGO_TERM_COLOR: always\n  HEAL: scripts/ci/ensure-age-extension.py\n",
                    "  HEAL: scripts/ci/ensure-age-extension.py",
                ),
                "ensure-age-extension.py outside the Point-at run block: HEAL: scripts/ci/ensure-age-extension.py",
            ],
        )

    def test_defaults_key_anywhere_in_the_workflow_is_refused(self):
        got = self._defects("jobs:\n", "defaults:\n  run:\n    shell: bash\njobs:\n")
        self.assertEqual(got, self._added_block(0, "defaults:"))

    def _r9_row(self, prefix):
        """One ROWS9 row: the pin names the key, and PyYAML (when present) agrees the key is a step key."""
        name = next(n for n in ROWS9 if n.startswith(prefix + " "))
        idx, where, new, key = ROWS9[name]
        lines = insert_lines(idx, where, new)
        if yaml is not None:
            self.assertEqual(yaml_step_keys(lines), ["name", "run", key])
        self._key_then_step_list(heal_defects(lines, WORKFLOWS[idx].name), key)

    def test_m36_key_after_the_indent_6_comment_block_is_refused(self):
        """sec r8 H1 (cert)."""
        self._r9_row("M36")

    def test_m37_key_after_a_column_0_comment_is_refused(self):
        """sec r8 H2 (cert)."""
        self._r9_row("M37")

    def test_m38_key_after_a_comment_is_refused_in_the_ignored_workflow(self):
        """sec r8 H3 (ign)."""
        self._r9_row("M38")

    def test_m39_working_directory_after_a_comment_is_refused(self):
        """sec r8 H4 (cert)."""
        self._r9_row("M39")

    def test_m40_key_after_an_indent_8_comment_is_refused_naming_only_the_key(self):
        """The comment sits inside the step; the body must end at it, so the key is the only defect."""
        self._r9_row("M40")

    @unittest.skipIf(yaml is None, "PyYAML absent on this node: the live cross-check is skipped")
    def test_r9_live_truth_yaml_and_the_pin_agree_on_the_step_keys(self):
        """Cross-check: PyYAML says name+run at head and the pin is clean, in both workflows."""
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8").splitlines()
                self.assertEqual(yaml_step_keys(text), ["name", "run"])
                self.assertEqual(heal_defects(path), [])

    def _text_defects(self, idx, old, new):
        """heal_defects of one workflow text with ``old`` replaced by ``new``, split on LF only."""
        base = WORKFLOWS[idx].read_text(encoding="utf-8")
        self.assertEqual(base.count(old), 1, "anchor drifted: " + old.strip())
        return heal_defects(base.replace(old, new, 1).split("\n"), WORKFLOWS[idx].name)

    def test_m41_u2028_inside_the_run_block_is_refused(self):
        """code r8 F1 (E3): U+2028 joins two lines for the shell but splitlines() still splits them."""
        old = "\n          " + HEAL_GUARD
        got = self._text_defects(1, old, "\u2028          " + HEAL_GUARD)
        self.assertEqual(len(got), 1, got)
        self.assertIn("U+2028", got[0])

    def test_m42_trailing_nbsp_on_the_env_redirect_line_is_refused(self):
        """code r8 F1 (E4): strip() removes a trailing U+00A0 the shell keeps in the redirect target."""
        old = '          } >> "$GITHUB_ENV"\n'
        got = self._text_defects(0, old, '          } >> "$GITHUB_ENV"\u00a0\n')
        self.assertEqual(len(got), 1, got)
        self.assertIn("U+00A0", got[0])

    def test_m43_zero_width_space_inside_a_shell_word_is_refused_by_code_point(self):
        """code r8 F1: the named defect quotes the code point, not just a body mismatch."""
        old = "      - name: " + STEP_NAME + "\n        run: |\n          set -euo pipefail"
        got = self._text_defects(1, old, old.replace("pipefail", "pipe\u200bfail"))
        self.assertEqual(len(got), 1, got)
        self.assertIn("U+200B", got[0])

    def test_m44_double_quoted_defaults_key_is_refused(self):
        """code r8 F2 (E5a): YAML maps "defaults" to the same key as defaults."""
        got = self._text_defects(1, "jobs:\n", '"defaults":\n  run:\n    shell: bash\njobs:\n')
        self.assertEqual(got, self._added_block(1, '"defaults":'))

    def test_m45_single_quoted_defaults_key_is_refused(self):
        """code r8 F2 (E5b)."""
        got = self._text_defects(1, "jobs:\n", "'defaults':\n  run:\n    shell: bash\njobs:\n")
        self.assertEqual(got, self._added_block(1, "'defaults':"))

    def test_m46_step_name_as_data_inside_another_run_block_is_not_a_step(self):
        """code r8 F3 observation: only a dash at exactly 6 spaces is a step; the data line is not."""
        decoy = "          - name: " + STEP_NAME + "\n"
        old = "      - name: cargo test --features sal-postgres -- --ignored\n        run: |\n"
        lines = self._text_defects_lines(0, old, old + decoy)
        if yaml is not None:
            self.assertEqual(yaml_step_keys(lines), ["name", "run"])
        self.assertEqual(heal_defects(lines, WORKFLOWS[0].name), [])

    def _text_defects_lines(self, idx, old, new):
        base = WORKFLOWS[idx].read_text(encoding="utf-8")
        self.assertEqual(base.count(old), 1, "anchor drifted: " + old.strip())
        return base.replace(old, new, 1).split("\n")

    def test_r9_comment_after_the_step_is_accepted(self):
        """Control: the live cert shape (indent-6 comment block after the step) and a trailing indent-8 comment."""
        for idx, comment in (
            (1, None),
            (0, ("      # trailing at indent 6",)),
            (0, ("        # trailing at indent 8",)),
        ):
            with self.subTest(comment=comment):
                lines = WORKFLOWS[idx].read_text(encoding="utf-8").splitlines()
                if comment:
                    lines = insert_lines(idx, "after_body", comment)
                self.assertEqual(heal_defects(lines, WORKFLOWS[idx].name), [])

    def _top_level_keys(self, lines):
        return list(yaml.safe_load("\n".join(lines))) if yaml is not None else None

    def _defaults_spelling(self, head, expected):
        """Both workflows: PyYAML reads ``head`` as a top-level defaults key, the pin names its skeleton line.

        ``expected`` is the text of the first inserted line; every defect is a skeleton defect.
        """
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(idx, "jobs:\n", head + "  run:\n    shell: bash\njobs:\n")
                keys = self._top_level_keys(lines)
                if keys is not None:
                    self.assertIn("defaults", keys)
                got = heal_defects(lines, WORKFLOWS[idx].name)
                at = next(n for n, ln in enumerate(lines, 1) if ln.rstrip() == expected)
                self.assertIn("skeleton line %d added: %s" % (at, expected), got)
                self.assertTrue(all(d.startswith("skeleton line ") for d in got), got)

    def test_m47_double_quoted_defaults_key_spelled_with_a_hex_escape_is_refused(self):
        """code r9 F1 (Q8): the escaped key is the key defaults for YAML; no decoder is needed to refuse it."""
        self._defaults_spelling('"\\x64efaults":\n', '"\\x64efaults":')

    def test_m48_explicit_key_form_of_the_defaults_key_is_refused(self):
        """code r9 F1 (Q10): ``? defaults`` on its own line, value on the next, is the key defaults."""
        self._defaults_spelling("? defaults\n:\n", "? defaults")

    def test_m49_double_quoted_key_spelled_with_a_unicode_escape_is_refused(self):
        """code r9 F1: a backslash escape spells any key, so a backslash in a double-quoted key is refused."""
        self._defaults_spelling('"\\u0064efaults":\n', '"\\u0064efaults":')

    def test_m50_control_a_comment_line_that_mentions_defaults_is_accepted(self):
        """Control: ``# defaults: tuned`` at indent 0 is a YAML comment, not a key."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(idx, "jobs:\n", "# defaults: tuned\njobs:\n")
                self.assertEqual(heal_defects(lines, WORKFLOWS[idx].name), [])
                if yaml is not None:
                    self.assertNotIn("defaults", self._top_level_keys(lines))

    def test_m55_tagged_defaults_key_is_refused(self):
        """security r9 F2: ``!!str defaults:`` is the key defaults."""
        self._defaults_spelling("!!str defaults:\n", "!!str defaults:")

    def test_m56_anchored_defaults_key_is_refused(self):
        """security r9 F2: ``&a defaults:`` is the key defaults."""
        self._defaults_spelling("&a defaults:\n", "&a defaults:")

    def _env_row(self, level, key, value):
        """Add one env entry at workflow or job level of both workflows; PyYAML sees it, the pin names it."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name, level=level):
                job = {0: "postgres-ignored", 1: "cert-postgres-age"}[idx]
                if level == "workflow":
                    old, new = "  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: always\n  %s: %s\n" % (key, value)
                else:
                    old = "\n  %s:\n" % job
                    new = old + "    env:\n      %s: %s\n" % (key, value)
                lines = self._text_defects_lines(idx, old, new)
                if yaml is not None:
                    doc = yaml.safe_load("\n".join(lines))
                    env = doc["env"] if level == "workflow" else doc["jobs"][job]["env"]
                    self.assertIn(key, env)
                skeleton_line = "  %s: %s" % (key, value) if level == "workflow" else "    env:"
                want = ["%s-level env key added: %s" % (level, key), self._added(idx, old, new, skeleton_line)]
                if level == "job":  # the env entry sits at indent 6 above steps: a deep line
                    at = next(n for n, ln in enumerate(lines, 1) if ln.rstrip() == "      %s: %s" % (key, value))
                    want.append("deep line %d above steps: (indent 6): %s: %s" % (at, key, value))
                self.assertEqual(heal_defects(lines, WORKFLOWS[idx].name), want)

    def test_m51_bash_env_at_workflow_level_is_refused(self):
        """security r9 F1: BASH_ENV changes what the pinned step executes."""
        self._env_row("workflow", "BASH_ENV", "./x")

    def test_m52_shellopts_at_job_level_is_refused(self):
        """security r9 F1: SHELLOPTS at job level."""
        self._env_row("job", "SHELLOPTS", "xtrace")

    def test_m53_an_innocuous_new_job_env_key_is_refused_too(self):
        """The pin is a set pin, not a denylist: any new key fails."""
        self._env_row("job", "FOO", "bar")

    def test_m54_control_the_live_env_sets_are_accepted(self):
        """Control: the unmutated workflows carry exactly the pinned env key sets."""
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(heal_defects(path), [])

    # Round 11 rows (security r10 F1-F3): the spellings the per-spelling regexes of rounds 8-10 passed.
    # Each bypass row changes PyYAML's reading of the workflow while the older pin returned [].
    JOB_BY_IDX = {0: "postgres-ignored", 1: "cert-postgres-age"}
    DV = "{run: {shell: bash}}"
    ANCHOR_INPUT = '    inputs:\n      note:\n        description: &d "def\\x61ults"\n'

    def _spelled(self, idx, level, snippet, anchor=False):
        """Lines of workflow ``idx`` with ``snippet`` (indent-0 text) at workflow or job level (indent +4)."""
        base = WORKFLOWS[idx].read_text(encoding="utf-8")
        if anchor:
            hook = "  workflow_dispatch:\n"
            self.assertEqual(base.count(hook), 1, "anchor drifted: " + hook.strip())
            base = base.replace(hook, hook + self.ANCHOR_INPUT, 1)
        if level == "workflow":
            old, new = "jobs:\n", snippet + "jobs:\n"
        else:
            old = "\n  %s:\n" % self.JOB_BY_IDX[idx]
            new = old + "".join("    " + x + "\n" for x in snippet.rstrip("\n").split("\n"))
        self.assertEqual(base.count(old), 1, "anchor drifted: " + old.strip())
        return base.replace(old, new, 1).split("\n")

    def _assert_skeleton_refused(self, lines, idx, quoted):
        """The pin names a skeleton line carrying ``quoted``; PyYAML is not consulted here."""
        got = heal_defects(lines, WORKFLOWS[idx].name)
        self.assertTrue(got, "the pin returned [] for a spelling PyYAML reads")
        self.assertTrue(
            any(d.startswith("skeleton line ") and quoted in d for d in got), "no skeleton defect names %r: %r" % (quoted, got)
        )

    def _defaults_row(self, snippet, quoted, levels=("workflow", "job"), anchor=False):
        for idx in (0, 1):
            for level in levels:
                with self.subTest(workflow=WORKFLOWS[idx].name, level=level):
                    lines = self._spelled(idx, level, snippet, anchor)
                    if yaml is not None:
                        doc = yaml.safe_load("\n".join(lines))
                        seen = doc if level == "workflow" else doc["jobs"][self.JOB_BY_IDX[idx]]
                        self.assertIn("defaults", seen)
                    self._assert_skeleton_refused(lines, idx, quoted)

    def test_m57_tagged_escaped_defaults_key_is_refused(self):
        """security r10 F1: a tag in front of the escaped quoted key."""
        self._defaults_row('!!str "\\x64efaults": ' + self.DV + "\n", '!!str "\\x64efaults"')

    def test_m58_anchored_escaped_defaults_key_is_refused(self):
        """security r10 F1: an anchor in front of the escaped quoted key."""
        self._defaults_row('&d "\\x64efaults": ' + self.DV + "\n", '&d "\\x64efaults"')

    def test_m59_explicit_key_below_indent_0_is_refused(self):
        """security r10 F1: ``?`` at job level (indent 4), value on the next line."""
        self._defaults_row('? "\\x64efaults"\n: ' + self.DV + "\n", '? "\\x64efaults"', levels=("job",))

    def test_m60_escaped_line_break_in_the_key_is_refused(self):
        """security r10 F1: a backslash-newline escape inside the quoted key."""
        self._defaults_row('? "def\\\n  aults"\n: ' + self.DV + "\n", '? "def\\', levels=("job",))

    def test_m61_alias_defaults_key_is_refused(self):
        """security r10 F1: ``*d :`` where the anchor ``&d "def\\x61ults"`` sits in a dispatch input."""
        self._defaults_row("*d : " + self.DV + "\n", "*d :", anchor=True)

    def test_m62_merge_key_carrying_defaults_is_refused(self):
        """security r10 F1: ``<<: {"\\x64efaults": ...}`` (PyYAML merge key)."""
        self._defaults_row('<<: {"\\x64efaults": ' + self.DV + "}\n", "<<:")

    def _env_spelling_row(self, spelling, quoted):
        """A job-level env block spelled ``spelling`` (PyYAML reads BASH_ENV) must be refused."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._spelled(idx, "job", spelling)
                if yaml is not None:
                    doc = yaml.safe_load("\n".join(lines))
                    self.assertIn("BASH_ENV", doc["jobs"][self.JOB_BY_IDX[idx]]["env"])
                self._assert_skeleton_refused(lines, idx, quoted)

    def test_m63_double_quoted_job_env_key_is_refused(self):
        """security r10 F2: ``"env":`` at job level."""
        self._env_spelling_row('"env":\n  BASH_ENV: ./x\n', '"env":')

    def test_m64_tagged_job_env_key_is_refused(self):
        """security r10 F2: ``!!str env:``."""
        self._env_spelling_row("!!str env:\n  BASH_ENV: ./x\n", "!!str env:")

    def test_m65_anchored_job_env_key_is_refused(self):
        """security r10 F2: ``&e env:``."""
        self._env_spelling_row("&e env:\n  BASH_ENV: ./x\n", "&e env:")

    def test_m66_explicit_key_job_env_is_refused(self):
        """security r10 F2: ``? env`` with the mapping on the next line."""
        self._env_spelling_row("? env\n: {BASH_ENV: ./x}\n", "? env")

    def test_m67_job_env_keys_indented_deeper_are_refused(self):
        """security r10 F2: env keys at +4 instead of +2 (the older pin only read +2)."""
        self._env_spelling_row("env:\n    BASH_ENV: ./x\n", "env:")

    def test_m68_jobs_line_with_a_trailing_comment_is_refused(self):
        """security r10 F2: ``jobs:  # note`` hid every job-level env from the older pin."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._spelled(idx, "job", "env:\n  BASH_ENV: ./x\n")
                at = lines.index("jobs:")
                lines[at] = "jobs:  # note"
                self._assert_skeleton_refused(lines, idx, "jobs:  # note")

    def test_m69_workflow_without_a_jobs_line_is_refused(self):
        """security r10 F2: no exact ``jobs:`` line at indent 0 was fail-open."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = WORKFLOWS[idx].read_text(encoding="utf-8").split("\n")
                lines.remove("jobs:")
                self.assertIn(
                    "workflow has no exact jobs: line at indent 0", heal_defects(lines, WORKFLOWS[idx].name)
                )

    def test_m70_second_name_key_in_the_pinned_step_is_refused(self):
        """security r10 F3 (= r9 O1): PyYAML renames the step to the last ``name``."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                head = "      - name: " + STEP_NAME + "\n"
                lines = self._text_defects_lines(idx, head, head + "        name: renamed\n")
                if yaml is not None:
                    self.assertNotIn(STEP_NAME, [s.get("name") for s in yaml.safe_load("\n".join(lines))["jobs"][self.JOB_BY_IDX[idx]]["steps"]])
                self.assertIn("step has 2 name keys, expected exactly 1", heal_defects(lines, WORKFLOWS[idx].name))

    def test_m71_control_a_comment_line_at_indent_0_is_accepted(self):
        """Control: comments are not skeleton lines."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._spelled(idx, "workflow", "# note: a comment line\n")
                self.assertEqual(heal_defects(lines, WORKFLOWS[idx].name), [])

    def test_m72_control_a_changed_run_block_line_is_caught_by_the_run_pin_not_the_skeleton(self):
        """Control: block-scalar lines are not skeleton lines; the run-text pin owns them."""
        got = self._defects(NEW_URL_LINE, NEW_URL_LINE.replace("new_url=", "new_url2="))
        self._assert_body_differs(got)
        self.assertFalse(any(d.startswith("skeleton line ") for d in got), got)

    def test_m73_skeleton_lines_that_can_spell_any_key_are_refused_by_form(self):
        """An explicit key, anchor, tag, alias or merge key, or a backslash inside quotes, is refused by form."""
        for lead in ("? x", "&a x: 1", "!!str x: 1", "*a : 1", "<<: {}", '"a\\x41": 1'):
            with self.subTest(line=lead):
                lines = self._spelled(0, "workflow", lead + "\n")
                got = heal_defects(lines, WORKFLOWS[0].name)
                self.assertTrue(any(d.startswith("skeleton line ") and "can spell" in d and lead in d for d in got), got)


    # Round 12 rows (code r11 F1 F2 F3, security r11 F1 F2): a deep continuation line above steps:, the whole
    # step list, and the Unicode line breaks YAML honours but the LF split keeps inside one line.
    ASSERT_HEAD = "      - name: Assert rustup is provisioned (self-hosted; fail-closed #3128)\n"
    INSTALL_HEAD = "      - name: Install Rust 1.98.0 (matches rust-toolchain.toml pin)\n"
    JOB_IF = (
        "    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name"
        " == github.repository\n"
    )

    def _r12_each(self, old, new, prefix, fragment, yaml_check=None):
        """Both workflows: ``new`` replaces ``old``; the pin names a ``prefix`` defect quoting ``fragment``."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(idx, old, new)
                if yaml is not None and yaml_check is not None:
                    yaml_check(yaml.safe_load("\n".join(lines)), self.JOB_BY_IDX[idx])
                got = heal_defects(lines, WORKFLOWS[idx].name)
                self.assertTrue(
                    any(d.startswith(prefix) and fragment in d for d in got),
                    "no %r defect quotes %r: %r" % (prefix, fragment, got),
                )

    def test_m74_continuation_line_under_the_job_if_guard_is_refused(self):
        """code r11 F1: a deep plain-scalar continuation turns the fork guard into ``... || true``."""
        self._r12_each(
            self.JOB_IF,
            self.JOB_IF + "      || true\n",
            "deep line ",
            "|| true",
            lambda doc, job: self.assertTrue(doc["jobs"][job]["if"].endswith("|| true")),
        )

    def test_m75_continuation_line_under_a_workflow_env_value_is_refused(self):
        """code r11 F1: ``CARGO_TERM_COLOR: always`` plus a continuation reads as ``always never``."""
        old = "  CARGO_TERM_COLOR: always\n"
        self._r12_each(
            old,
            old + "      never\n",
            "deep line ",
            "never",
            lambda doc, job: self.assertEqual(doc["env"]["CARGO_TERM_COLOR"], "always never"),
        )

    def test_m76_continuation_line_under_the_concurrency_group_is_refused(self):
        """code r11 F1: a continuation after the concurrency group value changes the group."""
        old = "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
        self._r12_each(
            old,
            "      tail\n" + old,
            "deep line ",
            "tail",
            lambda doc, job: self.assertTrue(doc["concurrency"]["group"].endswith(" tail")),
        )

    def test_m77_earlier_step_writing_github_env_is_refused(self):
        """code r11 F2 = security r11 F1: an added earlier step that writes BASH_ENV into $GITHUB_ENV."""
        self._r12_each(
            self.ASSERT_HEAD,
            "      - name: Early env\n        run: echo \"BASH_ENV=./x\" >> \"$GITHUB_ENV\"\n\n" + self.ASSERT_HEAD,
            "step-list line ",
            "GITHUB_ENV",
        )

    def test_m78_earlier_step_writing_github_path_is_refused(self):
        """code r11 F2 = security r11 F1: an added earlier step that prepends a directory to $GITHUB_PATH."""
        self._r12_each(
            self.ASSERT_HEAD,
            "      - name: Early path\n        run: echo \"$PWD/x\" >> \"$GITHUB_PATH\"\n\n" + self.ASSERT_HEAD,
            "step-list line ",
            "GITHUB_PATH",
        )

    def test_m79_added_uses_step_is_refused(self):
        """code r11 F2: an added ``uses:`` step."""
        self._r12_each(
            self.ASSERT_HEAD,
            "      - uses: actions/cache@v4\n\n" + self.ASSERT_HEAD,
            "step-list line ",
            "actions/cache@v4",
        )

    def _install_block(self, idx):
        """The text of the Install Rust step of workflow ``idx`` (its lines up to the next blank line)."""
        base = WORKFLOWS[idx].read_text(encoding="utf-8")
        start = base.index(self.INSTALL_HEAD)
        return base[start : base.index("\n\n", start) + 1]

    def test_m80_reordered_steps_are_refused(self):
        """code r11 F2: the Install Rust step moved above the Assert rustup step."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                block = self._install_block(idx)
                base = WORKFLOWS[idx].read_text(encoding="utf-8")
                text = base.replace(block, "", 1).replace(self.ASSERT_HEAD, block + self.ASSERT_HEAD, 1)
                got = heal_defects(text.split("\n"), WORKFLOWS[idx].name)
                self.assertTrue(
                    any(d.startswith("step-list line ") and "reordered" in d for d in got), got
                )

    def test_m81_removed_step_is_refused(self):
        """code r11 F2: the Install Rust step deleted."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                base = WORKFLOWS[idx].read_text(encoding="utf-8")
                got = heal_defects(base.replace(self._install_block(idx), "", 1).split("\n"), WORKFLOWS[idx].name)
                self.assertTrue(
                    any(d.startswith("step-list line removed") and "Install Rust 1.98.0" in d for d in got), got
                )

    def test_m82_changed_uses_ref_is_refused(self):
        """code r11 F2: the pinned toolchain action moved to another ref."""
        self._r12_each(
            "@f8be11a05b1d4f3fcebe6410cc16743212b999b0",
            "@0000000000000000000000000000000000000000",
            "step-list line ",
            "@0000000000000000000000000000000000000000",
        )

    def test_m83_changed_with_entry_of_an_earlier_step_is_refused(self):
        """code r11 F2: a ``with:`` entry of the Install Rust step (changed in cert, added in ignored)."""
        for idx, old, new in (
            (0, "# 1.98.0\n", "# 1.98.0\n        with:\n          components: rust-src\n"),
            (1, "          components: clippy\n", "          components: clippy, rust-src\n"),
        ):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                got = heal_defects(self._text_defects_lines(idx, old, new), WORKFLOWS[idx].name)
                self.assertTrue(any(d.startswith("step-list line ") and "rust-src" in d for d in got), got)

    def test_m84_deep_continuation_inside_an_earlier_step_is_refused(self):
        """code r11 F2: a continuation line under the Assert rustup step's ``if:`` value."""
        old = "        if: runner.environment != 'github-hosted'\n"
        self._r12_each(
            old,
            old + "          || true\n",
            "step-list line ",
            "|| true",
            lambda doc, job: self.assertTrue(
                any(str(s.get("if", "")).endswith("|| true") for s in doc["jobs"][job]["steps"])
            ),
        )

    def _break_row(self, ch):
        """A comment line carrying ``ch`` hides a ``defaults:`` key from the LF split; PyYAML reads the key."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._spelled(idx, "workflow", "# note%sdefaults:\n  run:\n    shell: bash\n" % ch)
                if yaml is not None:
                    self.assertIn("defaults", yaml.safe_load("\n".join(lines)))
                got = heal_defects(lines, WORKFLOWS[idx].name)
                code = "U+%04X" % ord(ch)
                self.assertTrue(any(d.startswith("line ") and code in d for d in got), got)

    def test_m85_u0085_inside_a_comment_line_is_refused(self):
        """security r11 F1: U+0085 (NEL) ends a line for PyYAML but not for the LF split."""
        self._break_row("\u0085")

    def test_m86_u2028_inside_a_comment_line_is_refused(self):
        """security r11 F1: U+2028 (line separator)."""
        self._break_row(" ")

    def test_m87_u2029_inside_a_comment_line_is_refused(self):
        """security r11 F1: U+2029 (paragraph separator)."""
        self._break_row(" ")

    def test_m91_a_lone_carriage_return_inside_a_comment_line_is_refused(self):
        """Same class as M85-M87: a CR in mid-line is a line break for PyYAML; only a trailing CR is CRLF."""
        self._break_row("\r")

    def test_m88_control_a_comment_at_indent_6_or_deeper_above_steps_is_accepted(self):
        """Control: comments are never deep lines, whatever their indent."""
        old = "    steps:\n"
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(idx, old, "      # note at 6\n          # note at 10\n" + old)
                self.assertEqual(heal_defects(lines, WORKFLOWS[idx].name), [])

    def test_m89_control_the_unchanged_live_files_have_no_defect(self):
        """Control: the live step list, skeleton, deep-line scan and line-break scan are clean."""
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(heal_defects(path), [])
                self.assertEqual(macos_defects(path), [])

    def test_m90_control_a_changed_run_line_is_caught_by_the_run_pin_not_the_step_list(self):
        """Control: block-scalar content is outside the skeleton and the step list; the run-text pin owns it."""
        got = self._defects(NEW_URL_LINE, NEW_URL_LINE.replace("new_url=", "new_url2="))
        self._assert_body_differs(got)
        self.assertFalse(any(d.startswith(("skeleton line ", "step-list line ", "deep line ")) for d in got), got)


    # Round 13 rows (code r12 F1 MAJOR = security r12 F1 MEDIUM): the step-list pin guards the chain's #8172
    # hardening, ``persist-credentials: false`` under the checkout step of both workflows.
    PERSIST_BLOCK = "        with:\n          persist-credentials: false\n"

    def test_m92_removing_persist_credentials_false_from_the_checkout_step_is_refused(self):
        """code r12 F1: dropping the #8172 hardening (``with:`` and ``persist-credentials: false``) names both lines."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(idx, self.PERSIST_BLOCK, "")
                got = heal_defects(lines, WORKFLOWS[idx].name)
                self.assertTrue(
                    any(d.startswith("step-list line removed") and "persist-credentials: false" in d for d in got), got
                )
                self.assertTrue(any(d.startswith("step-list line removed") and d.endswith("        with:") for d in got), got)

    def test_m93_persist_credentials_true_on_the_checkout_step_is_refused(self):
        """code r12 F1: ``persist-credentials: true`` is a changed line against the pinned ``false``."""
        for idx in (0, 1):
            with self.subTest(workflow=WORKFLOWS[idx].name):
                lines = self._text_defects_lines(
                    idx, self.PERSIST_BLOCK, "        with:\n          persist-credentials: true\n"
                )
                if yaml is not None:
                    steps = yaml.safe_load("\n".join(lines))["jobs"][self.JOB_BY_IDX[idx]]["steps"]
                    self.assertIs(steps[0]["with"]["persist-credentials"], True)
                got = heal_defects(lines, WORKFLOWS[idx].name)
                self.assertTrue(
                    any(
                        d.startswith("step-list line ")
                        and " changed: " in d
                        and "persist-credentials: true (expected:" in d
                        and d.endswith("persist-credentials: false)")
                        for d in got
                    ),
                    got,
                )


if __name__ == "__main__":
    unittest.main()
