"""Structural test of the tainted-job boundary for every workflow (umbrella #9452).

Invariant: after the first step of a job that runs pull-request code, no step of that job
holds (i) a secret, (ii) a write token, (iii) an output that feeds a gate decision, or
(iv) persistent state a trusted run later reads. A workflow or a job the classifier cannot
classify is a failure. Known violations need an allow row naming the open fix issue; the
row count is pinned and a stale row is a failure. The persistent-runner rule of (iv) is R2
(ruling abf38892 section 7): a job whose `runs-on` can resolve to a runner that is not
provably GitHub-hosted has no trusted trigger. It is read from the workflow files alone; no
environment variable, path form, cache-directory name or runner label clears it.

Every cell works on in-memory text: the real workflows are read once from the checkout and
synthetic workflows are named constants below. No file is written.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))
try:
    import taint_boundary as tb
except ImportError as _import_error:  # red at the base: every cell fails on its own
    tb = None
    IMPORT_ERROR = repr(_import_error)
else:
    IMPORT_ERROR = ""

try:
    import yaml as pyyaml  # parity oracle only; the classifier never imports it
except ImportError as _pyyaml_error:  # the skip reason of the parity cell names the import failure
    pyyaml = None
    PYYAML_IMPORT_ERROR = repr(_pyyaml_error)
else:
    PYYAML_IMPORT_ERROR = ""

# Three row kinds, three pins (FINAL efb2b9e8, correction 0773f6ce); each pin only goes down.
# Kind violation: the 13 rows before PR 9508, 4 class (iii) rows of #9553 and the 16 release.yml
# rows of #9570; stage 1 of #9455 removed the lifetime-tests R2 row (33 -> 32).
ALLOW_PIN_EXPECTED = 32
ALLOW_ROW_COUNT = 12
NEW_VIOLATION_ROW_COUNT = 4
RELEASE_ROW_COUNT = 16
OPEN_PIN_EXPECTED = 33
NOT_ANALYSED_PIN_EXPECTED = 3
JOB_COUNT_LARGE = 200
LARGE_SCAN_CEILING_S = 10.0
RUN_TEXT_BYTES_LARGE = 120_000
RUN_TEXT_CEILING_S = 5.0
FIX_ISSUES = frozenset({9454, 9455, 9456, 9471, 9553, 9570})
NEW_VIOLATION_ISSUE = 9553
RELEASE_ISSUE = 9570
RUNNER_ISSUE = 9455
SYNTH = "synthetic.yml"
# The step key of an R2 (iv) violation: the job's `runs-on`, not one of its steps.
R2_STEP = "runs-on"
R2_DETAIL = "job can run on a runner not provably GitHub-hosted and has a trusted trigger: {events}"
HOST_CREDENTIAL_DETAIL = "a credential resident on a self-hosted host read after pull-request code ran"
# A non-empty host-fact value of the old contract form; ruling 8b8cede8: no verdict reads it.
CLASS_IV = "iv"

# ---------------------------------------------------------------------------------------
# Synthetic corpus: one job per class and per clean form.
# ---------------------------------------------------------------------------------------

HEADER = """\
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
"""

JOB_CLASS_I = """\
  class-i:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
      - name: Use token
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh api repos/x/y
"""

JOB_CLASS_II = """\
  class-ii:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Test
        run: make test
"""

JOB_CLASS_III = """\
  class-iii:
    runs-on: ubuntu-24.04
    outputs:
      picked: ${{ steps.pick.outputs.value }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Pick
        id: pick
        run: scripts/pick.sh >> "$GITHUB_OUTPUT"
"""

JOB_CLASS_IV = """\
  class-iv:
    runs-on: [self-hosted, linux-fed]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo test --no-run
"""

JOB_CLEAN_SECRET_BEFORE = """\
  clean-secret-before:
    runs-on: ubuntu-24.04
    steps:
      - name: Query with token
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh api repos/x/y > list.txt
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
"""

JOB_CLEAN_OUTPUT_BEFORE = """\
  clean-output-before:
    runs-on: ubuntu-24.04
    outputs:
      files: ${{ steps.list.outputs.files }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 2
      - name: List
        id: list
        run: |
          files="$(git diff --name-only HEAD~1 | wc -l)"
          echo "files=$files" >> "$GITHUB_OUTPUT"
      - name: Build
        run: cargo build
"""

JOB_CLEAN_BASE_TREE = """\
  clean-base-tree:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Materialise the base tool
        env:
          BASE: ${{ github.event.pull_request.base.sha }}
        run: |
          base_dir="$RUNNER_TEMP/base"
          mkdir -p "$base_dir"
          git show "${BASE:?}:scripts/tool.py" > "$base_dir/tool.py"
          python3 -I "$base_dir/tool.py" --data .
"""

# 9566: trusted-only needs every run step read in full and running no tree code.
JOB_CLEAN_TRUSTED_ONLY = """\
  clean-trusted-only:
    if: github.event_name == 'push'
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Release
        env:
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
        run: echo release
"""

# 9566: cargo publish runs code from the checked-out tree; in a push job that code is no pull-request code.
JOB_PUSH_PUBLISH = """\
  push-publish:
    if: github.event_name == 'push'
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Release
        env:
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
        run: cargo publish
"""

# R2: a trusted-only job on a persistent runner is (iv) though it runs no pull-request code.
JOB_TRUSTED_ONLY_SELF_HOSTED = """\
  trusted-self-hosted:
    if: github.event_name == 'push'
    runs-on: [self-hosted, linux-fed]
    steps:
      - name: Publish
        run: echo publish
"""

# R2 needs a trusted trigger: a job narrowed to pull_request only has none.
JOB_PR_ONLY_SELF_HOSTED = """\
  pr-only-self-hosted:
    if: github.event_name == 'pull_request'
    runs-on: [self-hosted, linux-fed]
    steps:
      - name: Lint
        run: echo lint
"""

JOB_CLEAN_GITHUB_HOSTED = """\
  clean-hosted:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build --release
      - name: Path
        run: echo "$PWD/target/release" >> "$GITHUB_PATH"
"""

SYNTH_WORKFLOW = HEADER + "".join((
    JOB_CLASS_I, JOB_CLASS_II, JOB_CLASS_III, JOB_CLASS_IV, JOB_CLEAN_SECRET_BEFORE,
    JOB_CLEAN_OUTPUT_BEFORE, JOB_CLEAN_BASE_TREE, JOB_CLEAN_TRUSTED_ONLY, JOB_CLEAN_GITHUB_HOSTED,
    JOB_TRUSTED_ONLY_SELF_HOSTED, JOB_PR_ONLY_SELF_HOSTED, JOB_PUSH_PUBLISH,
))

SYNTH_VERDICTS = {
    "class-i": "i",
    "class-ii": "ii",
    "class-iii": "iii",
    "class-iv": "iv",
    # I-2: a token held before the taint point can persist into pull-request code.
    "clean-secret-before": "i",
    "clean-output-before": "clean",
    "clean-base-tree": "no-pr-code",
    "clean-trusted-only": "trusted-only",
    "push-publish": "no-pr-code",
    "clean-hosted": "clean",
    "trusted-self-hosted": "iv",
    "pr-only-self-hosted": "no-pr-code",
}

SYNTH_VIOLATIONS = {
    ("class-i", "Use token", "i"),
    ("class-ii", "Test", "ii"),
    ("class-iii", "Pick", "iii"),
    ("clean-secret-before", "Query with token", "i"),
    ("class-iv", R2_STEP, "iv"),
    ("trusted-self-hosted", R2_STEP, "iv"),
}

WF_LEAKY_CHECKOUT = HEADER + """\
  leaky:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build
        run: cargo build
"""

WF_LATE_CHECKOUT = HEADER + """\
  late:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
      - name: Second checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          path: other
"""

# Ruling 04701c74: a credential resident on a self-hosted host read after pull-request code
# is (i); the same read on a GitHub-hosted VM reaches no resident credential.
WF_HOST_CREDENTIAL = HEADER + """\
  host:
    runs-on: linux-fed
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Before
        run: test -r "$HOME/.netrc"
      - name: Build
        run: cargo build
      - name: Read url
        run: |
          url_file="$HOME/.ai-memory-ci-fed-url"
          test -r "$url_file"
      - name: Read pgpass
        run: test -r ~/.pgpass
      - name: Toolchain
        run: ls "$HOME/.cargo/bin"
  hosted:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
      - name: Read pgpass
        run: test -r ~/.pgpass
"""

# Text -> names a credential resident on a self-hosted host.
HOST_CREDENTIAL_CASES = (
    ('url_file="$HOME/.ai-memory-ci-fed-url"', True),
    ("test -r ${HOME}/.pgpass", True),
    ("test -r ~/.netrc", True),
    ("test -d \"$HOME/.ssh\"", True),
    ("test -r $HOME/.aws/credentials", True),
    ("test -r ~/.docker/config.json", True),
    ("test -r ~/.config/gh/hosts.yml", True),
    ("test -r $HOME/.git-credentials", True),
    ("test -r $HOME/.vault-token", True),
    ("test -r $HOME/.PGPASS", True),
    ("test -S /var/run/docker.sock", True),
    ("sudo -u postgres psql -c 'select 1'", True),
    ("psql -h 127.0.0.1 -U postgres -c 'select 1'", True),
    ('ls "$HOME/.cargo/bin"', False),
    ('mkdir -p "$HOME/.local/bin"', False),
    ("du -sh ~/.cache/huggingface", False),
    ("cat ./.pgpass-example", False),
    ("psql -U app -d proof", False),
)

# Ruling 04701c74: a write to GITHUB_ENV or GITHUB_PATH in a job holding a pull-request tree
# is the taint point, and every later step (actions and cleanup) is tainted.
WF_ENV_FILE = HEADER + """\
  envfile:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Set env
        run: echo "X=$(cat pr.txt)" >> "$GITHUB_ENV"
      - name: Comment
        uses: marocchino/sticky-pull-request-comment@v2
      - name: Cleanup
        if: always()
        env:
          T: ${{ secrets.T }}
        run: echo done
  pathfile:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Add path
        run: echo "$PWD/bin" >> "${GITHUB_PATH}"
      - name: Cleanup
        if: always()
        env:
          T: ${{ secrets.T }}
        run: echo done
"""

# Expression text -> names a secret or the job token.
SECRET_EXPR_CASES = (
    ("${{ secrets.TOKEN }}", True),
    ("${{ secrets['TOKEN'] }}", True),
    ("${{ toJSON(secrets) }}", True),
    ("${{ github.token }}", True),
    ("${{ github['token'] }}", True),
    ("${{ format('{0}', secrets.A) }}", True),
    ("${{ fromJSON('{\"a\": 1}').a && secrets.B }}", True),
    ("${{ Secrets.C }}", True),
    ("${{ secrets.A", True),
    ("${{ github.sha }} secrets.A", False),
    ("${{ github.event.pull_request.base.sha }}", False),
    ("${{ matrix.os }}", False),
)

WF_PR_TARGET_BASE = """\
on: pull_request_target
permissions:
  contents: read
jobs:
  compare:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          persist-credentials: false
      - name: Compare
        run: python3 -I scripts/compare.py
"""

WF_PR_TARGET_HEAD = """\
on: pull_request_target
permissions:
  contents: read
jobs:
  compare:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - name: Compare
        run: python3 scripts/compare.py
      - name: Comment
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: out.md
"""

WF_UNPARSABLE = HEADER + """\
  anchors:
    runs-on: &runner ubuntu-24.04
    steps:
      - run: echo hi
"""

WF_NO_RUNS_ON = HEADER + """\
  floating:
    steps:
      - run: echo hi
"""

WF_NO_PERMISSIONS = """\
on: pull_request
jobs:
  open:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: cargo build
"""

WF_UNKNOWN_ACTION = HEADER + """\
  mystery:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Mystery
        uses: someone/unknown-action@v1
"""

WF_UNKNOWN_EVENT = """\
on: issue_comment
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
"""

WF_COMPOSITE = HEADER + """\
  composite:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Local tool
        uses: ./.github/actions/tool
"""

ACTION_TOOL = """\
name: tool
runs:
  using: composite
  steps:
    - name: Inner
      shell: bash
      run: echo inner
    - name: Comment
      uses: marocchino/sticky-pull-request-comment@v2
      with:
        path: out.md
"""

ACTION_LOOP_A = """\
runs:
  using: composite
  steps:
    - uses: ./.github/actions/loop-b
"""

ACTION_LOOP_B = """\
runs:
  using: composite
  steps:
    - uses: ./.github/actions/loop-a
"""

WF_COMPOSITE_LOOP = HEADER + """\
  loop:
    runs-on: ubuntu-24.04
    steps:
      - uses: ./.github/actions/loop-a
"""

WF_CALLER = HEADER + """\
  call:
    uses: ./.github/workflows/inner.yml
"""

WF_INNER = """\
on: workflow_call
permissions:
  contents: read
jobs:
  inner-job:
    runs-on: [self-hosted, linux-fed]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Inner build
        run: cargo build
"""

WF_MATRIX = HEADER + """\
  matrix:
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
        include:
          - os: linux-fed
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
"""

# R2 table (ruling abf38892 section 7): `runs-on` form x trigger set. A form is the job text
# above `steps:`; its expectation is HOSTED, PERSISTENT or the needle of the unclassifiable
# reason. Anything not provably GitHub-hosted is persistent self-hosted.
HOSTED = "hosted"
PERSISTENT = "persistent"
R2_RUNS_ON_FORMS = {
    "hosted label": ("    runs-on: ubuntu-24.04\n", HOSTED),
    "hosted list": ("    runs-on: [ubuntu-24.04]\n", HOSTED),
    "hosted matrix": ("    strategy:\n      matrix:\n        os: [ubuntu-24.04, macos-15]\n"
                      "    runs-on: ${{ matrix.os }}\n", HOSTED),
    "self-hosted literal": ("    runs-on: self-hosted\n", PERSISTENT),
    "custom label": ("    runs-on: linux-fed\n", PERSISTENT),
    "list form": ("    runs-on: [self-hosted, linux-fed]\n", PERSISTENT),
    "hosted and self-hosted list": ("    runs-on: [ubuntu-24.04, self-hosted]\n", PERSISTENT),
    # A hosted name followed by a line break is not a hosted label: the match is whole-string.
    "hosted name with a trailing line break": ("    runs-on: \"ubuntu-24.04\\n\"\n", PERSISTENT),
    "hosted name in a literal block": ("    runs-on: |\n      ubuntu-24.04\n", PERSISTENT),
    "group mapping": ("    runs-on:\n      group: fleet\n", PERSISTENT),
    "labels mapping": ("    runs-on:\n      labels: [self-hosted, linux-fed]\n", PERSISTENT),
    "matrix leg": ("    strategy:\n      matrix:\n        os: [ubuntu-24.04]\n        include:\n"
                   "          - os: linux-fed\n    runs-on: ${{ matrix.os }}\n", PERSISTENT),
    "fromJSON matrix leg": ("    strategy:\n      matrix:\n        include:\n"
                            "          - runner: '[\"ubuntu-latest\"]'\n"
                            "          - runner: '[\"self-hosted\",\"macos-fed\"]'\n"
                            "    runs-on: ${{ fromJSON(matrix.runner) }}\n", PERSISTENT),
    "matrix value expression": ("    strategy:\n      matrix:\n        os: ['${{ inputs.os }}']\n"
                                "    runs-on: ${{ matrix.os }}\n", "matrix axis 'os' is an expression"),
    "expression": ("    runs-on: ${{ github.event.inputs.runner }}\n", PERSISTENT),
    "reusable-workflow input": ("    runs-on: ${{ inputs.runner }}\n", PERSISTENT),
    "expression in a list": ("    runs-on: [self-hosted, '${{ vars.POOL }}']\n", PERSISTENT),
    "missing": ("", "job without runs-on"),
    "number": ("    runs-on: 7\n", "outside the known forms"),
    "empty list": ("    runs-on: []\n", "outside the known forms"),
    "empty label": ("    runs-on: ''\n", "empty runs-on label"),
    "mapping without labels": ("    runs-on:\n      size: large\n", "outside the known forms"),
    "unterminated expression": ("    runs-on: '${{ inputs.runner'\n", "unterminated `${{` expression"),
    "matrix axis without values": ("    strategy:\n      matrix:\n        include:\n          - other: x\n"
                                   "    runs-on: ${{ matrix.os }}\n", "has no static values"),
}
# Trigger set -> (the `on:` block, the trusted triggers R2 names, the verdict of a hosted job
# that runs no pull-request code).
R2_TRIGGER_SETS = {
    "pull_request only": ("on:\n  pull_request:\n", (), "no-pr-code"),
    "pull_request_target only": ("on:\n  pull_request_target:\n", ("pull_request_target",), "no-pr-code"),
    "push": ("on:\n  push:\n    branches: [main]\n", ("push",), "trusted-only"),
    "merge_group": ("on:\n  merge_group:\n", ("merge_group",), "no-pr-code"),
    "schedule": ("on:\n  schedule:\n    - cron: '0 4 * * *'\n", ("schedule",), "trusted-only"),
    "workflow_dispatch": ("on:\n  workflow_dispatch:\n", ("workflow_dispatch",), "trusted-only"),
    "workflow_call": ("on: workflow_call\n", ("workflow_call",), "no-pr-code"),
    "mixed": ("on:\n  pull_request:\n  push:\n    branches: [main]\n  merge_group:\n",
              ("merge_group", "push"), "no-pr-code"),
}
R2_JOB_ID = "probe"
R2_STEPS = "    steps:\n      - name: Say\n        run: echo hi\n"


def r2_workflow(on_block: str, runs_on: str) -> str:
    return on_block + "permissions:\n  contents: read\njobs:\n  " + R2_JOB_ID + ":\n" + runs_on + R2_STEPS


# Hit 4-6 job (cert-postgres-age) with each split applied; none may clear R2.
# cert-postgres-age is unclassifiable through another step (REAL_UNCLASSIFIABLE); the
# postgres-ignored job shares its runs-on and classifies.
HIT_WORKFLOW = "postgres-ignored.yml"
HIT_JOB = "postgres-ignored"
HIT_RUNS_ON = "    runs-on: [self-hosted, linux-fed]\n"
HIT_SPLITS = {
    "path split": HIT_RUNS_ON + (
        "    env:\n"
        "      CARGO_HOME: ${{ runner.temp }}/pr-cargo\n"
        "      RUSTUP_HOME: ${{ runner.temp }}/pr-rustup\n"
        "      TMPDIR: ${{ runner.temp }}/pr-tmp\n"
        "      CARGO_TARGET_DIR: ${{ runner.temp }}/pr-target\n"
        "      PR_TIER_ISOLATED: 'true'\n"),
    "label split": "    runs-on: [self-hosted, linux-fed-pr, ephemeral]\n",
    "hosted label added": "    runs-on: [ubuntu-latest, self-hosted, linux-fed-pr]\n",
    "group split": "    runs-on:\n      group: pr-tier\n      labels: [self-hosted, ephemeral]\n",
    "group with a hosted label": "    runs-on:\n      group: pr-tier\n      labels: [ubuntu-latest]\n",
}

# The allow rows R2 keeps open under #9455 (ruling abf38892 section 7).
R2_ROWS = (
    ("ci.yml", "check"),
    ("cert-postgres-age.yml", "cert-postgres-age"),
    ("postgres-ignored.yml", "postgres-ignored"),
)
# Stage 1 of #9455: this job left the persistent runner; its R2 row is gone.
HOSTED_SESSION_BOOT = ("session-boot-lifetime.yml", "lifetime-tests")

# Shell text -> runs pull-request code, or the exact Unclassifiable reason (a str), in the
# reading of a job with a pull-request trigger (strict).
SHELL_CASES = (
    ("echo hi && grep -c x file | wc -l", False),
    ("git diff --name-only HEAD~1 > changed.txt", False),
    ("cargo build", True),
    ("scripts/ci-test-impact.sh a b", True),
    ("./run.sh", True),
    ("bash scripts/check.sh", True),
    ("bash -c 'echo hi'", False),
    ("bash -c 'make all'", True),
    ("source scripts/lib.sh", True),
    (". scripts/lib.sh", True),
    ("eval \"$cmd\"", True),
    ("$TOOL --flag", "command word '$TOOL' is not a literal word"),
    ("python3 scripts/x.py", True),
    ("python3 -I scripts/x.py", True),
    ("python3 -m pip install pytest", True),
    ("python3 -I -m json.tool f.json", False),
    ("python3 -c 'print(1)'", True),
    ("python3 -I -c 'print(1)'", False),
    ("python3 --version", False),
    ("node --version", False),
    ("npm ci", True),
    ("unknowncmd --x", "command word 'unknowncmd' is not on the closed command list"),
    ("x=$(cargo metadata)", True),
    ("echo \"$(make -s version)\"", True),
    ("echo `npm bin`", True),
    ("for f in a b; do echo \"$f\"; done", False),
    ("case \"$x\" in a|b) echo y ;; *) echo n ;; esac", False),
    ("case \"$x\" in a|b) make ;; esac", True),
    ("if [[ -n \"$x\" && -f y ]]; then echo ok; fi", False),
    ("(( n += 1 ))", False),
    ("f() { echo hi; }\nf", False),
    ("sudo -u nobody cargo build", True),
    ("timeout 30 cargo test", True),
    ("env A=1 make", True),
    ("find . -name '*.rs' -exec rustfmt {} \\;", True),
    ("find . -name '*.tmp' -exec rm {} \\;", False),
    ("awk -f scripts/x.awk file", True),
    ("docker build -t x .", True),
    # The image may be built from the pull-request tree: it runs pull-request code.
    ("docker run --rm img true", True),
    ("cat <<'EOF'\n$(cargo build)\nEOF", False),
    ("cat <<EOF\n$(cargo build)\nEOF", True),
    ("python3 - <<'PY'\nprint(1)\nPY", True),
    ("python3 -I - <<'PY'\nprint(1)\nPY", False),
    ("echo x 2>&1 | tee out.log", False),
    ("echo GHA_EXPR", False),
    ("GHA_EXPR --run", "command word 'GHA_EXPR' is not on the closed command list"),
    ("psql \"$U\" -v ON_ERROR_STOP=1 -tAc 'SELECT 1'", False),
    ("psql -tAf x.sql", True),
    ("psql -tAc 'COPY t FROM PROGRAM x'", "psql SQL text runs a program"),
    ("psql -tAY", "psql option '-tAY' is not on the closed option list"),
)

# Real forms at this checkout, every one the scan reaches to a fixpoint (FACTS of ruling
# f367b2f1, re-taken on the merge of chain tip 902faa04): (workflow, job, step label, exact
# reason). Kind unclassifiable: 33 forms (47 before the pre-scan of #9566), one open row each; these
# jobs are NOT shown to hold the boundary.
REAL_UNCLASSIFIABLE = (
    (
        'batman-mode-acceptance.yml', 'rust-integration', 'Assert binary refuses /tmp write under R001 end-to-end',
        "command word '$BIN' is not a literal word",
    ),
    (
        'cert-postgres-age.yml', 'cert-postgres-age',
        'Assert certified stack versions (cert evidence, hard-fail on drift)',
        "command word '$PSQL' is not a literal word",
    ),
    (
        'cert-postgres-age.yml', 'cert-postgres-age',
        'Ensure AGE + vector extensions present (best-effort — tier is pre-provisioned)',
        "command word '$PSQL' is not a literal word",
    ),
    (
        'ci.yml', 'check', 'Free disk before tests (hosted image only,',
        "command word 'fallocate' is not on the closed command list",
    ),
    (
        'ci.yml', 'check', 'Free disk before tests (hosted image only,',
        "command word 'mkswap' is not on the closed command list",
    ),
    (
        'ci.yml', 'check', 'Free disk before tests (hosted image only,',
        "command word 'swapon' is not on the closed command list",
    ),
    ('ci.yml', 'check', 'Run tests (impact-aware)', "command word '$TIMEOUT_BIN' is not a literal word"),
    # The forms the merge of chain tip 902faa04 brought into this step (baseline of the landing tree)
    # that the pre-scan of #9566 still reaches.
    ('ci.yml', 'check', 'Run tests (impact-aware)', "python module 'os' is not on the closed module list"),
    ('ci.yml', 'check', 'Run tests (impact-aware)', "python module 'stat' is not on the closed module list"),
    (
        'ci.yml', 'check', 'Run tests (impact-aware)',
        "python module 'workflow_annotation' is not on the closed module list",
    ),
    (
        'ci.yml', 'ci-gate', 'Fold job results (base gate)',
        "interpreter path '$RUNNER_TEMP/impact-base/impact/gate.py' is neither in the workspace nor bound to base content",
    ),
    ('ci.yml', 'ci-gate', 'Materialise the base gate (#8240)', 'python code uses a dunder name'),
    ('ci.yml', 'ci-gate', 'Materialise the base gate (#8240)', "python module 'os' is not on the closed module list"),
    (
        'ci.yml', 'ci-gate', 'Materialise the base gate (#8240)',
        "python module 'shutil' is not on the closed module list",
    ),
    (
        'ci.yml', 'ci-gate', 'Materialise the base gate (#8240)',
        "python module 'subprocess' is not on the closed module list",
    ),
    (
        'ci.yml', 'classify', 'id:cls',
        "interpreter path '$trust_impact/cargo_skip.py' is neither in the workspace nor bound to base content",
    ),
    (
        'ci.yml', 'select', 'Build impact index',
        "interpreter path '$RUNNER_TEMP/impact-base/impact/build_index.py' is neither in the workspace nor bound to base content",
    ),
    ('ci.yml', 'select', 'Materialise the base selector (#8240)', 'python code uses a dunder name'),
    (
        'ci.yml', 'select', 'Materialise the base selector (#8240)',
        "python module 'os' is not on the closed module list",
    ),
    (
        'ci.yml', 'select', 'Materialise the base selector (#8240)',
        "python module 'shutil' is not on the closed module list",
    ),
    (
        'ci.yml', 'select', 'Materialise the base selector (#8240)',
        "python module 'subprocess' is not on the closed module list",
    ),
    (
        'ci.yml', 'select', 'Select jobs',
        "interpreter path '$RUNNER_TEMP/impact-base/impact/select.py' is neither in the workspace nor bound to base content",
    ),
    (
        'ci.yml', 'select', 'Select the full matrix (base selector unavailable)',
        "python module 'os' is not on the closed module list",
    ),
    (
        'coverage.yml', 'classify', 'id:cls',
        "interpreter path '$trust_impact/cargo_skip.py' is neither in the workspace nor bound to base content",
    ),
    (
        'coverage.yml', 'per-module-thresholds', 'Free disk + add swap (#1148 belt-and-suspenders, aggressive)',
        "command word 'fallocate' is not on the closed command list",
    ),
    (
        'coverage.yml', 'per-module-thresholds', 'Free disk + add swap (#1148 belt-and-suspenders, aggressive)',
        "command word 'mkswap' is not on the closed command list",
    ),
    (
        'coverage.yml', 'per-module-thresholds', 'Free disk + add swap (#1148 belt-and-suspenders, aggressive)',
        "command word 'swapon' is not on the closed command list",
    ),
    (
        'coverage.yml', 'per-module-thresholds', 'Install mold linker (#1148, pinned+bounded',
        "command word 'mold' is not on the closed command list",
    ),
    (
        'mobile-runtime.yml', 'android-emulator', 'Boot Android emulator + run tests',
        "command word 'adb' is not on the closed command list",
    ),
    (
        'mobile-runtime.yml', 'android-emulator', 'Enable KVM',
        "command word 'udevadm' is not on the closed command list",
    ),
    (
        'mobile-runtime.yml', 'ios-simulator', 'Boot iOS Simulator (best-available iPhone)',
        "command word 'xcrun' is not on the closed command list",
    ),
    (
        'mobile-runtime.yml', 'ios-simulator', 'Run mobile_runtime tests on iOS Simulator',
        "command word 'xcrun' is not on the closed command list",
    ),
    (
        'mobile-runtime.yml', 'ios-simulator', 'Shut down simulator',
        "command word 'xcrun' is not on the closed command list",
    ),
)
# Kind not-analysed: (workflow, job, step label, exact reason, the line of what is not analysed).
REAL_NOT_ANALYSED = (
    (
        'ci.yml', 'check', 'Run tests (impact-aware)', 'arithmetic expansion holding a command substitution',
        'the command substitution inside the arithmetic expansion is not analysed',
    ),
    (
        'ci.yml', 'check', 'Run tests (impact-aware)', "timeout option '--version' is not on the closed option list",
        "command 'timeout': the rest of this command is not analysed after this form",
    ),
    (
        'coverage.yml', 'per-module-thresholds', 'Install jq + postgresql-client (bounded+retry',
        "psql option '--version' is not on the closed option list",
        "command 'psql': the rest of this command is not analysed after this form",
    ),
)
# The four violations reached once the covered forms no longer stop their jobs, without a row
# before PR 9508: (workflow, job, step label, class, detail); kind violation, #9553, gate step.
REAL_NEW_VIOLATIONS = (
    ('ci.yml', 'classify', 'id:cls', 'iii', 'job output set at or after pull-request code ran'),
    ('ci.yml', 'select', 'Select jobs', 'iii', 'job output set at or after pull-request code ran'),
    (
        'ci.yml', 'select', 'Select the full matrix (base selector unavailable)', 'iii',
        'job output set at or after pull-request code ran',
    ),
    ('coverage.yml', 'classify', 'id:cls', 'iii', 'job output set at or after pull-request code ran'),
)
# The violations of release.yml reached once the pre-scan of #9566 reads every run step of a
# job in full: (workflow, job, step label, class, detail); kind violation, #9570, no gate step.
REAL_RELEASE_VIOLATIONS = (
    ('release.yml', 'copr', 'Build source RPM', 'i', 'secret or token used after pull-request code ran'),
    ('release.yml', 'copr', 'Configure copr-cli', 'i', 'secret or token used after pull-request code ran'),
    (
        'release.yml', 'crates-io', 'Publish to crates.io (with retry)', 'i',
        'secret or token used after pull-request code ran',
    ),
    (
        'release.yml', 'homebrew', 'Checkout Homebrew tap', 'i',
        'checkout keeps the token in the workspace for later pull-request code',
    ),
    (
        'release.yml', 'homebrew', 'Checkout Homebrew tap', 'i',
        'secret held before pull-request code ran can persist into it',
    ),
    (
        'release.yml', 'homebrew', 'Download release assets, verify, and pin SHA256', 'i',
        'secret held before pull-request code ran can persist into it',
    ),
    (
        'release.yml', 'mobile-android', 'Attest build provenance (Android JNI bundle)', 'i',
        'secret or token used after pull-request code ran',
    ),
    (
        'release.yml', 'mobile-android', 'Attest build provenance (Android JNI bundle)', 'ii',
        'job token has a write scope',
    ),
    (
        'release.yml', 'mobile-android', 'Upload to GitHub Release', 'i',
        'secret or token used after pull-request code ran',
    ),
    (
        'release.yml', 'mobile-ios', 'Attest build provenance (iOS xcframework)', 'i',
        'secret or token used after pull-request code ran',
    ),
    ('release.yml', 'mobile-ios', 'Attest build provenance (iOS xcframework)', 'ii', 'job token has a write scope'),
    ('release.yml', 'mobile-ios', 'Upload to GitHub Release', 'i', 'secret or token used after pull-request code ran'),
    (
        'release.yml', 'preflight', 'Refuse when no tag ruleset protects v* tags', 'i',
        'secret or token used after pull-request code ran',
    ),
    (
        'release.yml', 'preflight', 'Verify the tag (annotated, SSH-signed by an enrolled release key)', 'iii',
        'job output set at or after pull-request code ran',
    ),
    ('release.yml', 'qualify', 'Qualify the tagged SHA', 'i', 'secret or token used after pull-request code ran'),
    (
        'release.yml', 'release', 'Attest build provenance (release binaries + packages)', 'i',
        'secret or token used after pull-request code ran',
    ),
    (
        'release.yml', 'release', 'Attest build provenance (release binaries + packages)', 'ii',
        'job token has a write scope',
    ),
    ('release.yml', 'release', 'Create GitHub Release', 'i', 'secret or token used after pull-request code ran'),
    (
        'release.yml', 'sbom', 'Attest build provenance (CycloneDX SBOM)', 'i',
        'secret or token used after pull-request code ran',
    ),
    ('release.yml', 'sbom', 'Attest build provenance (CycloneDX SBOM)', 'ii', 'job token has a write scope'),
    ('release.yml', 'sbom', 'Upload to GitHub Release', 'i', 'secret or token used after pull-request code ran'),
)
REAL_RELEASE_VERDICTS = {
    ('release.yml', 'copr'): 'i',
    ('release.yml', 'crates-io'): 'i',
    ('release.yml', 'homebrew'): 'i',
    ('release.yml', 'mobile-android'): 'i,ii',
    ('release.yml', 'mobile-ios'): 'i,ii',
    ('release.yml', 'preflight'): 'i,iii',
    ('release.yml', 'qualify'): 'i',
    ('release.yml', 'release'): 'i,ii',
    ('release.yml', 'sbom'): 'i,ii',
}
REAL_UNCLASSIFIABLE_JOBS = frozenset((wf, job) for wf, job, _, _ in REAL_UNCLASSIFIABLE)
REAL_FORM_JOB_COUNT = 10
PRUNE_STEP = "Prune stale runner TMPDIR (#8634)"
WORKFLOW_CALL_ONLY = "workflow_call-only workflow has no caller in this repository"


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"classifier module scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _scan(workflows: dict[str, str], actions: dict[str, str] | None = None,
          repo_files: frozenset[str] = frozenset()) -> "tb.ScanResult":
    return tb.scan_texts(workflows, actions or {}, repo_files)


_REAL: dict[str, object] = {}


def _real() -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    if "repo" not in _REAL:
        _REAL["repo"] = tb.load_repo(REPO_ROOT)
    return _REAL["repo"]  # type: ignore[return-value]


def _real_job(workflow: str, job: str) -> dict[str, object]:
    workflows, _, _ = _real()
    doc = tb.parse_yaml(workflows[workflow], workflow)
    return doc["jobs"][job]


def _real_step(workflow: str, job: str, label: str) -> dict[str, object]:
    steps = _real_job(workflow, job)["steps"]
    for pos, step in enumerate(steps):
        if tb._step_label(step, pos) == label:
            return step
    raise AssertionError(f"{workflow}/{job}: no step labelled {label!r}")


class SyntheticCorpusVerdicts(unittest.TestCase):
    """One job per class and per clean form gets its exact verdict and violation."""

    def test_9452_each_synthetic_job_gets_its_exact_verdict(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: SYNTH_WORKFLOW})
        self.assertEqual(result.unclassifiable, [])
        got = {job: verdict for (wf, job), verdict in result.verdicts.items() if wf == SYNTH}
        self.assertEqual(got, SYNTH_VERDICTS)

    def test_9452_each_synthetic_violation_names_job_step_and_class(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: SYNTH_WORKFLOW})
        got = {(v.job, v.step, v.klass) for v in result.violations}
        self.assertEqual(got, SYNTH_VIOLATIONS)

    def test_9452_checkout_keeping_the_token_before_pr_code_is_class_i(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_LEAKY_CHECKOUT})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Checkout", "i")})

    def test_9452_checkout_after_pr_code_is_class_i(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_LATE_CHECKOUT})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Second checkout", "i")})

    def test_9452_credential_resident_on_a_self_hosted_host_read_after_pr_code_is_class_i(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_HOST_CREDENTIAL})
        got = {(v.job, v.step, v.klass) for v in result.violations}
        self.assertEqual(got, {("host", R2_STEP, "iv"), ("host", "Read url", "i"), ("host", "Read pgpass", "i")})
        details = {v.detail for v in result.violations if v.klass == "i"}
        self.assertEqual(details, {HOST_CREDENTIAL_DETAIL})
        self.assertEqual(result.verdicts[(SYNTH, "hosted")], "clean")

    def test_9452_credential_resident_on_a_self_hosted_host_forms(self) -> None:
        _need_module(self)
        for text, expected in HOST_CREDENTIAL_CASES:
            with self.subTest(text=text):
                self.assertIs(tb._host_credential_in({"run": text}), expected)

    def test_9452_env_file_write_taints_every_later_step(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_ENV_FILE})
        self.assertEqual(result.unclassifiable, [])
        self.assertEqual(result.taint_steps[(SYNTH, "envfile")], "Set env")
        self.assertEqual(result.taint_steps[(SYNTH, "pathfile")], "Add path")
        got = {(v.job, v.step, v.klass) for v in result.violations}
        self.assertEqual(got, {("envfile", "Comment", "i"), ("envfile", "Cleanup", "i"), ("pathfile", "Cleanup", "i")})

    def test_9452_secret_reference_forms(self) -> None:
        _need_module(self)
        for text, expected in SECRET_EXPR_CASES:
            with self.subTest(text=text):
                self.assertIs(tb._has_secret_ref(text), expected)

    def test_9452_pull_request_target_base_checkout_runs_no_pr_code(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_PR_TARGET_BASE})
        self.assertEqual(result.verdicts[(SYNTH, "compare")], "no-pr-code")
        self.assertEqual(result.violations, [])

    def test_9452_pull_request_target_head_checkout_is_tainted(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_PR_TARGET_HEAD})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Comment", "i")})
        self.assertEqual(result.taint_steps[(SYNTH, "compare")], "Compare")

    def test_9452_matrix_leg_on_a_persistent_runner_is_class_iv(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_MATRIX})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {(R2_STEP, "iv")})


class FailClosed(unittest.TestCase):
    """An unparsable workflow, an unclassifiable job or an unknown action is a failure."""

    def assert_unclassifiable(self, text: str, needle: str) -> None:
        result = _scan({SYNTH: text})
        problems = tb.check(result, allow=(), pin=0)
        self.assertTrue(any(p.startswith("unclassifiable:") and needle in p for p in problems), problems)

    def test_9452_unparsable_workflow_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNPARSABLE, "outside the subset")

    def test_9452_job_without_runs_on_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_NO_RUNS_ON, "job without runs-on")

    def test_9452_job_without_permissions_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_NO_PERMISSIONS, "no `permissions:`")

    def test_9452_unknown_action_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNKNOWN_ACTION, "unknown action 'someone/unknown-action'")

    def test_9452_unknown_trigger_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNKNOWN_EVENT, "unknown trigger")

    def test_9452_missing_local_action_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_COMPOSITE, "local action ./.github/actions/tool not found")

    def test_9452_composite_action_cycle_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_COMPOSITE_LOOP},
                       {".github/actions/loop-a": ACTION_LOOP_A, ".github/actions/loop-b": ACTION_LOOP_B})
        self.assertTrue(any("composite action cycle" in m for m in result.unclassifiable), result.unclassifiable)

    def test_9452_yaml_subset_refuses_each_unsupported_form(self) -> None:
        _need_module(self)
        refused = {
            "anchor": "a: &x 1\n",
            "alias": "a: *x\n",
            "tag": "a: !!str 1\n",
            "merge key": "<<: {a: 1}\n",
            "complex key": "? a\n: b\n",
            "duplicate key": "a: 1\na: 2\n",
            "tab indent": "a:\n\tb: 1\n",
            "multi-line plain": "a: one\n  two\n",
            "multi-line quoted": "a: \"one\n  two\"\n",
            "nested flow": "a: [[1]]\n",
            "second document": "a: 1\n---\nb: 2\n",
            "inline mapping": "a: b: c\n",
        }
        for label, text in refused.items():
            with self.subTest(form=label):
                with self.assertRaises(tb.YamlError):
                    tb.parse_yaml(text, label)

    def test_9452_yaml_subset_parses_each_supported_form(self) -> None:
        _need_module(self)
        text = (
            "on: [push, pull_request]\n"
            "a: {x: 1, 'y': \"two\"}\n"
            "b: |\n  line1\n  line2\n"
            "c: >-\n  folded\n  text\n\n  para\n"
            "d: 'it''s' # comment\n"
            "e: \"tab\\there\"\n"
            "f: {}\n"
            "g:\n- k: 1\n  m: [a, b]\n- plain\n"
            "h: 010\n"
        )
        self.assertEqual(tb.parse_yaml(text, "forms"), {
            "on": ["push", "pull_request"],
            "a": {"x": 1, "y": "two"},
            "b": "line1\nline2\n",
            "c": "folded text\npara",
            "d": "it's",
            "e": "tab\there",
            "f": {},
            "g": [{"k": 1, "m": ["a", "b"]}, "plain"],
            "h": "010",
        })


class Indirection(unittest.TestCase):
    """Composite actions and reusable workflows under `uses: ./` are followed, not skipped."""

    def test_9452_composite_action_steps_are_followed(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_COMPOSITE}, {".github/actions/tool": ACTION_TOOL})
        self.assertEqual(result.taint_steps[(SYNTH, "composite")], "Local tool")
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Local tool > Comment", "i")})

    def test_9452_reusable_workflow_jobs_are_followed(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_CALLER, "inner.yml": WF_INNER})
        got = {(v.workflow, v.job, v.step, v.klass) for v in result.violations}
        self.assertIn((SYNTH, "call > inner-job", R2_STEP, "iv"), got)
        self.assertIn(("inner.yml", "inner-job", R2_STEP, "iv"), got)

    def test_9452_reusable_workflow_outside_the_repository_is_a_failure(self) -> None:
        _need_module(self)
        text = HEADER + "  call:\n    uses: other/repo/.github/workflows/x.yml@v1\n"
        result = _scan({SYNTH: text})
        self.assertTrue(any("not found in this repository" in m for m in result.unclassifiable))


class AllowTable(unittest.TestCase):
    """Rows need an open issue, a stale row fails, the count is pinned."""

    ROW = None

    def rows(self) -> tuple:
        return (tb.AllowRow(SYNTH, "class-iv", R2_STEP, ("iv",), RUNNER_ISSUE),)

    def test_9452_allowed_violation_passes_and_unallowed_fails(self) -> None:
        _need_module(self)
        text = HEADER + JOB_CLASS_IV
        result = _scan({SYNTH: text})
        self.assertEqual(tb.check(result, allow=self.rows(), pin=1), [])
        problems = tb.check(result, allow=(), pin=0)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith(f"violation class (iv) without an allow row: synthetic.yml/class-iv/{R2_STEP}: "))

    def test_9566_two_violations_of_one_class_on_one_step_print_in_one_order(self) -> None:
        """Two results of one class on one step differ only in detail: the lines come out in the
        same order whichever order the scan found them in."""
        _need_module(self)
        found = [tb.Violation(SYNTH, "class-iv", R2_STEP, "iv", detail) for detail in ("z detail", "a detail")]
        runs = [tb.check(tb.ScanResult(violations=list(order)), allow=(), pin=0) for order in (found, found[::-1])]
        expected = [f"violation class (iv) without an allow row: {SYNTH}/class-iv/{R2_STEP}: {detail}"
                    for detail in ("a detail", "z detail")]
        self.assertEqual(runs, [expected, expected])

    def test_9452_row_without_issue_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLASS_IV})
        rows = (tb.AllowRow(SYNTH, "class-iv", R2_STEP, ("iv",), None),)
        self.assertEqual(tb.check(result, allow=rows, pin=1),
                         [f"allow row without an open fix issue: synthetic.yml/class-iv/{R2_STEP}"])

    def test_9452_stale_row_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLEAN_GITHUB_HOSTED})
        rows = (tb.AllowRow(SYNTH, "clean-hosted", R2_STEP, ("iv",), RUNNER_ISSUE),)
        self.assertEqual(tb.check(result, allow=rows, pin=1),
                         [f"stale allow row (no longer violates class iv): synthetic.yml/clean-hosted/{R2_STEP}"])

    def test_9452_row_count_differs_from_pin_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLASS_IV})
        self.assertEqual(tb.check(result, allow=self.rows(), pin=2), ["allow table has 1 rows, pin is 2"])

    def test_9452_real_allow_table_is_pinned_and_names_fix_issues(self) -> None:
        _need_module(self)
        self.assertEqual(tb.TAINT_ALLOW_PIN, ALLOW_PIN_EXPECTED)
        self.assertEqual(len(tb.TAINT_ALLOW), ALLOW_ROW_COUNT + NEW_VIOLATION_ROW_COUNT + RELEASE_ROW_COUNT)
        self.assertEqual(len(tb.TAINT_ALLOW), ALLOW_PIN_EXPECTED)
        self.assertEqual((tb.OPEN_ROW_PIN, tb.NOT_ANALYSED_PIN), (OPEN_PIN_EXPECTED, NOT_ANALYSED_PIN_EXPECTED))
        self.assertEqual({row.issue for row in tb.TAINT_ALLOW}, FIX_ISSUES)
        new = [r for r in tb.TAINT_ALLOW if r.issue == NEW_VIOLATION_ISSUE]
        self.assertEqual(sorted((r.workflow, r.job, r.step, r.classes) for r in new),
                         sorted((wf, job, step, (klass,)) for wf, job, step, klass, _ in REAL_NEW_VIOLATIONS))
        release = [r for r in tb.TAINT_ALLOW if r.issue == RELEASE_ISSUE]
        self.assertEqual(len(release), RELEASE_ROW_COUNT)
        self.assertEqual({(r.workflow, r.job, r.step, k) for r in release for k in r.classes},
                         {(wf, job, step, klass) for wf, job, step, klass, _ in REAL_RELEASE_VIOLATIONS})
        # The mark follows the place: the rows in a gate job (ci.yml classify, select; coverage.yml
        # classify) are gate steps, the 9454 row in ci.yml classify among them; no other row is.
        gate_places = ({(wf, job, step) for wf, job, step, _, _ in REAL_NEW_VIOLATIONS}
                       | {("ci.yml", "classify", "id:impact")})
        self.assertEqual([r.gate_step for r in tb.TAINT_ALLOW],
                         [(r.workflow, r.job, r.step) in gate_places for r in tb.TAINT_ALLOW])
        self.assertEqual(sum(r.gate_step for r in tb.TAINT_ALLOW), 5)

    def test_9452_new_workflow_with_a_violating_job_and_no_row_fails(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        extended = dict(workflows, **{"new-workflow.yml": HEADER + JOB_CLASS_II})
        problems = [p for p in tb.check(tb.scan_texts(extended, actions, files)) if "new-workflow.yml" in p]
        self.assertEqual(problems, [
            "violation class (ii) without an allow row: new-workflow.yml/class-ii/Test: job token has a write scope",
        ])


class PersistentRunnerTrustedTrigger(unittest.TestCase):
    """R2: a job that can run on a persistent self-hosted runner has no trusted trigger."""

    def test_9452_r2_runs_on_form_by_trigger_set_table(self) -> None:
        _need_module(self)
        for form, (runs_on, expected) in R2_RUNS_ON_FORMS.items():
            for trigger, (on_block, trusted, hosted_verdict) in R2_TRIGGER_SETS.items():
                with self.subTest(form=form, trigger=trigger):
                    result = _scan({SYNTH: r2_workflow(on_block, runs_on)})
                    if trigger == "workflow_call":
                        self.assertEqual(result.unclassifiable, [f"{SYNTH}: {WORKFLOW_CALL_ONLY}"])
                        self.assertEqual(result.verdicts, {(SYNTH, "*"): "unclassifiable"})
                        continue
                    verdict = result.verdicts[(SYNTH, R2_JOB_ID)]
                    got = {(v.job, v.step, v.klass, v.detail) for v in result.violations}
                    if expected not in (HOSTED, PERSISTENT):
                        self.assertEqual(verdict, "unclassifiable")
                        self.assertEqual(len(result.unclassifiable), 1, result.unclassifiable)
                        self.assertIn(expected, result.unclassifiable[0])
                        self.assertEqual(got, set())
                    elif expected == PERSISTENT and trusted:
                        self.assertEqual(result.unclassifiable, [])
                        self.assertEqual(verdict, CLASS_IV)
                        self.assertEqual(got, {(R2_JOB_ID, R2_STEP, CLASS_IV,
                                                R2_DETAIL.format(events=", ".join(trusted)))})
                    else:
                        self.assertEqual(result.unclassifiable, [])
                        self.assertEqual(verdict, hosted_verdict)
                        self.assertEqual(got, set())

    def test_9452_r2_unknown_runs_on_form_is_a_problem_never_clean(self) -> None:
        _need_module(self)
        for form, (runs_on, expected) in R2_RUNS_ON_FORMS.items():
            if expected in (HOSTED, PERSISTENT):
                continue
            for trigger, (on_block, _, _) in R2_TRIGGER_SETS.items():
                with self.subTest(form=form, trigger=trigger):
                    problems = tb.check(_scan({SYNTH: r2_workflow(on_block, runs_on)}), allow=(), pin=0)
                    self.assertEqual(len(problems), 1, problems)
                    prefix = f"unclassifiable: {SYNTH}: " if trigger == "workflow_call" else \
                        f"unclassifiable: {SYNTH}/{R2_JOB_ID}: "
                    self.assertTrue(problems[0].startswith(prefix), problems)

    def test_9452_r2_split_of_a_hit_job_stays_class_iv(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        self.assertIn(HIT_RUNS_ON, workflows[HIT_WORKFLOW])
        for split, replacement in HIT_SPLITS.items():
            with self.subTest(split=split):
                text = workflows[HIT_WORKFLOW].replace(HIT_RUNS_ON, replacement, 1)
                self.assertNotEqual(text, workflows[HIT_WORKFLOW])
                result = tb.scan_texts(dict(workflows, **{HIT_WORKFLOW: text}), actions, files)
                self.assertEqual([u for u in result.unclassifiable if u.startswith(HIT_WORKFLOW)], [])
                self.assertIn(CLASS_IV, result.verdicts[(HIT_WORKFLOW, HIT_JOB)].split(","))
                got = {(v.step, v.klass, v.detail) for v in result.violations
                       if (v.workflow, v.job) == (HIT_WORKFLOW, HIT_JOB) and v.klass == CLASS_IV}
                self.assertEqual(got, {(R2_STEP, CLASS_IV,
                                        R2_DETAIL.format(events="push, workflow_dispatch"))})

    def test_9452_r2_host_fact_table_is_gone(self) -> None:
        _need_module(self)
        for name in ("RUNNER_BOUNDARY_FACTS", "BOUNDARY_REQUIRED_TRUE", "_boundary_holds", "_leg_persistent"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(tb, name), name)

    def test_9452_r2_real_rows_stay_open_under_the_runner_issue(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        rows = {(r.workflow, r.job): r for r in tb.TAINT_ALLOW if r.step == R2_STEP}
        self.assertEqual(set(rows), set(R2_ROWS))
        for key in R2_ROWS:
            with self.subTest(job=key):
                self.assertEqual(rows[key].classes, (CLASS_IV,))
                self.assertEqual(rows[key].issue, RUNNER_ISSUE)
                if key in REAL_UNCLASSIFIABLE_JOBS:
                    self.assertEqual(result.verdicts[key], "unclassifiable")
                else:
                    self.assertIn(CLASS_IV, result.verdicts[key].split(","))
        # Hosted on every leg: no R2 violation, and no row may cover it. Its suite step runs the
        # checked-out tree, so the pre-scan of #9566 sends it to the full analysis: no PR code.
        self.assertEqual(result.verdicts[HOSTED_SESSION_BOOT], "no-pr-code")
        self.assertNotIn(HOSTED_SESSION_BOOT, rows)

    def test_9452_r2_stale_row_for_a_gone_job_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLASS_IV})
        rows = (tb.AllowRow(SYNTH, "class-iv", R2_STEP, (CLASS_IV,), RUNNER_ISSUE),
                tb.AllowRow(SYNTH, "gone-job", R2_STEP, (CLASS_IV,), RUNNER_ISSUE))
        self.assertEqual(tb.check(result, allow=rows, pin=2),
                         [f"stale allow row (no longer violates class iv): {SYNTH}/gone-job/{R2_STEP}"])


class ShellClassifier(unittest.TestCase):
    """Run text -> runs pull-request code, fail closed on every unknown form."""

    def test_9452_shell_text_table(self) -> None:
        _need_module(self)
        for text, expected in SHELL_CASES:
            with self.subTest(text=text):
                if isinstance(expected, str):
                    with self.assertRaises(tb.Unclassifiable) as caught:
                        tb._shell_runs_pr_code(text, tb._ShellCtx(True))
                    self.assertEqual(str(caught.exception), expected)
                else:
                    self.assertIs(tb._shell_runs_pr_code(text, tb._ShellCtx(True)), expected)

    def test_9452_runner_temp_path_needs_isolation_and_a_base_copy(self) -> None:
        _need_module(self)
        unbound = 'root="$RUNNER_TEMP/base"\npython3 -I "$root/tool.py"'
        reason = "interpreter path '$root/tool.py' is neither in the workspace nor bound to base content"
        with self.assertRaises(tb.Unclassifiable) as caught:
            tb._shell_runs_pr_code(unbound, tb._ShellCtx(True))
        self.assertEqual(str(caught.exception), reason)
        # A job without a pull-request trigger looks only for a pull-request fetch.
        self.assertIs(tb._shell_runs_pr_code(unbound, tb._ShellCtx(False)), False)
        bound = 'root="$RUNNER_TEMP/base"\ngit show "$BASE:tool.py" > "$root/tool.py"\npython3 -I "$root/tool.py"'
        env = {"BASE": "${{ github.event.pull_request.base.sha }}"}
        result = _scan({SYNTH: "on: pull_request\npermissions:\n  contents: read\njobs:\n  j:\n"
                        "    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n"
                        "        with:\n          persist-credentials: false\n      - name: S\n"
                        "        env:\n          BASE: " + env["BASE"] + "\n        run: |\n"
                        + "".join("          " + line + "\n" for line in bound.splitlines())})
        self.assertEqual(result.unclassifiable, [])
        self.assertEqual(result.verdicts[(SYNTH, "j")], "no-pr-code")
        # Without -I the interpreter reads the workspace first: pull-request code.
        result = _scan({SYNTH: "on: pull_request\npermissions:\n  contents: read\njobs:\n  j:\n"
                        "    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n"
                        "        with:\n          persist-credentials: false\n      - name: S\n"
                        "        env:\n          BASE: " + env["BASE"] + "\n        run: |\n"
                        + "".join("          " + line.replace(" -I", "") + "\n" for line in bound.splitlines())})
        self.assertNotEqual(result.verdicts[(SYNTH, "j")], "no-pr-code")

    def test_9452_unterminated_forms_are_unclassifiable(self) -> None:
        _need_module(self)
        for text in ("echo 'open", "echo \"open", "x=$(echo", "cat <<EOF\nbody", "echo `x"):
            with self.subTest(text=text):
                with self.assertRaises(tb.Unclassifiable):
                    tb._shell_runs_pr_code(text, tb._ShellCtx(False))


class Bounds(unittest.TestCase):
    """Scanning time stays linear: 200 jobs and a 100K+ run text under a wall-clock ceiling."""

    def test_9452_two_hundred_job_workflow_under_ceiling(self) -> None:
        _need_module(self)
        jobs = "".join(JOB_CLASS_IV.replace("class-iv:", f"job-{n}:") for n in range(JOB_COUNT_LARGE))
        start = time.monotonic()
        result = _scan({SYNTH: HEADER + jobs})
        elapsed = time.monotonic() - start
        self.assertEqual(len(result.violations), JOB_COUNT_LARGE)
        self.assertLess(elapsed, LARGE_SCAN_CEILING_S)

    def test_9452_large_run_text_under_ceiling(self) -> None:
        _need_module(self)
        line = 'echo "$(printf %s abc)" | grep -c x >> out.txt # note\n'
        text = line * (RUN_TEXT_BYTES_LARGE // len(line) + 1)
        self.assertGreater(len(text), RUN_TEXT_BYTES_LARGE)
        start = time.monotonic()
        self.assertFalse(tb._shell_runs_pr_code(text, tb._ShellCtx(False)))
        self.assertLess(time.monotonic() - start, RUN_TEXT_CEILING_S)

    def test_9452_many_unterminated_expressions_under_ceiling(self) -> None:
        _need_module(self)
        text = "${{ a " * (RUN_TEXT_BYTES_LARGE // 6 + 1)
        start = time.monotonic()
        self.assertFalse(tb._has_secret_ref(text))
        with self.assertRaises(tb.Unclassifiable):
            tb._expr_free(text)
        self.assertLess(time.monotonic() - start, RUN_TEXT_CEILING_S)

    def test_9452_oversized_yaml_is_refused(self) -> None:
        _need_module(self)
        with self.assertRaises(tb.YamlError):
            tb.parse_yaml("a: " + "x" * (tb.MAX_YAML_BYTES + 1), "big")


class RealWorkflows(unittest.TestCase):
    """The invariant over every real workflow at the checkout, and the real step texts."""

    def test_9452_every_real_job_holds_the_boundary_or_has_a_row_of_each_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        self.assertEqual(tb.check_repo(tb.scan_texts(workflows, actions, files)), [])

    def test_9452_without_form_rows_every_real_form_is_a_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        problems = tb.check(tb.scan_texts(workflows, actions, files))
        self.assertEqual(sorted(p for p in problems if p.startswith("unclassifiable: ")),
                         sorted(f"unclassifiable: {wf}/{job}: step {step!r}: {reason}"
                                for wf, job, step, reason in REAL_UNCLASSIFIABLE))
        self.assertEqual(sorted(p for p in problems if p.startswith("not-analysed form without a row: ")),
                         sorted(f"not-analysed form without a row: {wf}/{job}: step {step!r}: {reason}: {note}"
                                for wf, job, step, reason, note in REAL_NOT_ANALYSED))
        self.assertEqual(len(problems), len(REAL_UNCLASSIFIABLE) + len(REAL_NOT_ANALYSED))

    def test_9452_without_the_new_violation_rows_each_is_a_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        old = tuple(r for r in tb.TAINT_ALLOW if r.issue != NEW_VIOLATION_ISSUE)
        problems = tb.check(result, old, len(old), tb.OPEN_ROWS, tb.OPEN_ROW_PIN, tb.NOT_ANALYSED_ROWS,
                            tb.NOT_ANALYSED_PIN)
        self.assertEqual(problems, sorted(f"violation class ({klass}) without an allow row: {wf}/{job}/{step}: {detail}"
                                          for wf, job, step, klass, detail in REAL_NEW_VIOLATIONS))

    def test_9566_without_the_release_rows_each_release_violation_is_a_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        old = tuple(r for r in tb.TAINT_ALLOW if r.issue != RELEASE_ISSUE)
        problems = tb.check(result, old, len(old), tb.OPEN_ROWS, tb.OPEN_ROW_PIN, tb.NOT_ANALYSED_ROWS,
                            tb.NOT_ANALYSED_PIN)
        # The check orders its lines by place, class and detail.
        self.assertEqual(problems, [f"violation class ({klass}) without an allow row: {wf}/{job}/{step}: {detail}"
                                    for wf, job, step, klass, detail in sorted(REAL_RELEASE_VIOLATIONS)])

    def test_9452_every_allow_row_names_a_real_step(self) -> None:
        _need_module(self)
        for row in tb.TAINT_ALLOW:
            with self.subTest(row=row):
                if row.step == R2_STEP:
                    self.assertIn("runs-on", _real_job(row.workflow, row.job))
                else:
                    self.assertIsInstance(_real_step(row.workflow, row.job, row.step), dict)

    def test_9452_real_trusted_classify_step_runs_no_pr_code(self) -> None:
        _need_module(self)
        for workflow, job, step_id in (("ci.yml", "classify", "id:cls"), ("coverage.yml", "classify", "id:cls")):
            with self.subTest(workflow=workflow):
                # Its base ref may come from the push `before` sha, which is not a proven base
                # ref: the copied path is unbound and the step is a finding (REAL_UNCLASSIFIABLE).
                step = _real_step(workflow, job, step_id)
                text = tb._expr_free(step["run"])
                reason = ("interpreter path '$trust_impact/cargo_skip.py' is neither in the workspace "
                          "nor bound to base content")
                with self.assertRaises(tb.Unclassifiable) as caught:
                    tb._shell_runs_pr_code(text, tb._ShellCtx(True))
                self.assertEqual(str(caught.exception), reason)

    def test_9452_real_impact_step_runs_pr_code(self) -> None:
        _need_module(self)
        step = _real_step("ci.yml", "classify", "id:impact")
        self.assertTrue(tb._shell_runs_pr_code(tb._expr_free(step["run"]), tb._ShellCtx(True)))

    def test_9452_real_select_job_runs_only_the_base_copy(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        # Its base copy imports a module off the closed list: a form of kind unclassifiable.
        self.assertEqual(result.verdicts[("ci.yml", "select")], "unclassifiable")
        self.assertIn("ci.yml/select: step 'Materialise the base selector (#8240)': "
                      "python module 'os' is not on the closed module list", [f.message() for f in result.forms])

    def test_9452_real_prune_step_is_the_taint_point_of_the_persistent_jobs(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        for key in (("ci.yml", "check"), ("cert-postgres-age.yml", "cert-postgres-age"),
                    ("postgres-ignored.yml", "postgres-ignored")):
            with self.subTest(job=key):
                # The prune step runs a workspace script through GITHUB_ACTION_PATH: listed, never
                # a finding of its own.
                self.assertEqual([u for u in result.unclassifiable + [f.message() for f in result.forms]
                                  if PRUNE_STEP in u], [])
                if key in REAL_UNCLASSIFIABLE_JOBS:
                    self.assertEqual(result.verdicts[key], "unclassifiable")
                    continue
                self.assertEqual(result.taint_steps[key], PRUNE_STEP)
                self.assertEqual(result.verdicts[key], "i,iv")

    def test_9452_real_hit_verdicts(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        hits = {key: v for key, v in result.verdicts.items() if v not in ("clean", "no-pr-code", "trusted-only")}
        self.assertEqual(hits, {
            ("c8-precheck.yml", "required-contexts-gate"): "i",
            ("postgres-ignored.yml", "postgres-ignored"): "i,iv",
        } | REAL_RELEASE_VERDICTS | {key: "unclassifiable" for key in REAL_UNCLASSIFIABLE_JOBS})

    def test_9452_real_unclassifiable_forms_are_exactly_the_listed_findings(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        self.assertEqual(result.unclassifiable, [])
        self.assertEqual(sorted(f.message() for f in result.forms if f.note is None),
                         sorted(f"{wf}/{job}: step {step!r}: {reason}" for wf, job, step, reason in REAL_UNCLASSIFIABLE))
        self.assertEqual(sorted((f.message(), f.note) for f in result.forms if f.note is not None),
                         sorted((f"{wf}/{job}: step {step!r}: {reason}", note)
                                for wf, job, step, reason, note in REAL_NOT_ANALYSED))
        self.assertEqual(len({(f.workflow, f.job) for f in result.forms}), REAL_FORM_JOB_COUNT)
        self.assertEqual(set(result.open_jobs), REAL_UNCLASSIFIABLE_JOBS)
        # A violation row never names a form: the steps they share are the four #9553 class (iii)
        # rows, a different kind with its own pin.
        rows = {(r.workflow, r.job, r.step) for r in tb.TAINT_ALLOW}
        self.assertEqual({(wf, job, step) for wf, job, step, _ in REAL_UNCLASSIFIABLE} & rows,
                         {("ci.yml", "classify", "id:cls"), ("coverage.yml", "classify", "id:cls"),
                          ("ci.yml", "select", "Select jobs"),
                          ("ci.yml", "select", "Select the full matrix (base selector unavailable)")})

    @unittest.skipUnless(pyyaml is not None, f"PyYAML not importable ({PYYAML_IMPORT_ERROR}): parity oracle skipped")
    def test_9452_subset_parser_matches_pyyaml_on_every_real_file(self) -> None:
        _need_module(self)
        workflows, actions, _ = _real()
        for name, text in list(workflows.items()) + list(actions.items()):
            with self.subTest(file=name):
                oracle = pyyaml.safe_load(text)
                if isinstance(oracle, dict) and True in oracle:
                    oracle["on"] = oracle.pop(True)
                self.assertEqual(tb.parse_yaml(text, name), oracle)


if __name__ == "__main__":
    unittest.main()
