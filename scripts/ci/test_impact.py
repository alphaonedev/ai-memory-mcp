#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""scripts/ci/test_impact.py

v0.7.0 Task #12 (#1399) - Test-impact selection without the codegraph
runtime dep in CI. Uses `git diff` + a static foundational-fallback
list + token-overlap matching against `tests/*.rs` binary names to
compute the minimum integration-test set that proves the diff.

Ported from the retired shell selector (#8077, fleet rule Python-not-shell).

The consumer (CI yaml) ALWAYS runs `cargo test --lib` regardless of
this script's output - that catches every inline `#[cfg(test)]` mod
tests under src/ in a single compile-once / link-once pass. This
script optimises only the slow `tests/*.rs` integration binaries
(each one compiles + links separately, ~5-15s setup per binary).

Output (writes to $GITHUB_OUTPUT and to stdout, ALL via key=value):
  test_impact=__SKIP__         # docs-only diff (caller short-circuits)
  test_impact=__ALL__          # foundational change OR fallback
  test_impact=<sp-sep names>   # impact-selected (e.g. "memories_query http_form4")
  test_impact_count=<N>        # number of impacted binaries
  test_impact_total=<N>        # total tests/*.rs binary count
  test_impact_reason=<string>  # human-readable explanation

CLI:
  test_impact.py <base-sha> [head-sha] [foundational-base-sha]
  The optional third base spans the whole PR: foundational changes there
  force __ALL__ even when the incremental diff only changes a gate allowlist.

Discipline (mandatory - do NOT relax without operator approval):
  1. PREFER false-positive (run too many tests) over false-negative
     (skip a test that would have caught a bug). Every ambiguous
     case defaults to __ALL__.
  2. Foundational files force __ALL__. The list is intentionally
     broad; trim ONLY when a concrete drift case justifies it.
  3. Parity-test invariants ALWAYS run (route_count_invariant,
     cli_subcommand_count_invariant, memory_link_relation_count_invariant,
     etc.) - they are mechanical, millisecond-fast, and exist
     specifically to catch cross-cutting drift the heuristic might miss.
  4. When the impact set would be empty for a non-docs / non-foundational
     diff, fall back to __ALL__ - empty almost certainly means the
     heuristic missed something.

Self-test:
  test_impact.py --self-test
    (exercises foundational predicates and token overlap)
  python3 scripts/test/test_ci_test_impact.py
    (exercises SKIP/ALL/IMPACT and the actual workflow classifier against
    committed fixture diffs, including incremental PR pushes)
"""

import fnmatch
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

KEY_IMPACT = "test_impact"
KEY_COUNT = "test_impact_count"
KEY_TOTAL = "test_impact_total"
KEY_REASON = "test_impact_reason"
VALUE_ALL = "__ALL__"
VALUE_SKIP = "__SKIP__"
COUNT_ALL = "ALL"
COUNT_NONE = "0"
DEFAULT_HEAD = "HEAD"
SELF_TEST_FLAG = "--self-test"
TESTS_DIR = "tests"
MIN_TOKEN_LEN = 3
TOKEN_SEPARATORS = "_./-"
PERCENT = 100
EXIT_OK = 0
EXIT_FAIL = 1
REPO_ROOT_DEPTH = 2
OWNED_GATE_REL = "scripts/ci/manifest_owned_paths.py"
OWNED_SCRATCH_DIR = ".local-runs"
OWNED_EXIT_OK = 0
OWNED_EXIT_MATCH = 1
OWNED_TIMEOUT_SECONDS = 120
OWNED_RUN_RE = re.compile(r"run: cargo test --test (\S+)")
OWNED_DEFECT_PREFIX = "manifest-owned-paths gate defect: "

DOCS_ONLY_PATTERNS = ("docs/*", "*.md")

# Patterns are shell globs (fnmatch `*` crosses `/`, as bash `case` does).
# Keep this list audited against the architecture surface; every entry is
# load-bearing.
FOUNDATIONAL_PATTERNS = (
    # Build / toolchain / dependency manifests
    "Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml",
    "build.rs", "deny.toml", "rustfmt.toml", "clippy.toml", ".cargo/*",
    # Library / dispatch root + cross-cutting validation
    "src/lib.rs", "src/main.rs", "src/validate.rs", "src/profile.rs",
    "src/errors.rs", "src/identity.rs", "src/identity/*",
    # Configuration + boot
    "src/config.rs", "src/config/*", "src/daemon_runtime.rs",
    "src/bootloader.rs",
    # Schema migrations + the sqlite substrate (every test touching the
    # DB depends on these). #1802 R-05: the storage/mod.rs monolith is
    # being split into src/storage/ submodules - the whole directory
    # stays foundational so the split never weakens the "storage changes
    # force the full suite" invariant.
    "src/storage/*", "migrations/*",
    # SAL trait AND all adapters/submodules touch store consumers. A
    # basename heuristic cannot track cross-backend security contracts.
    "src/store/*",
    # MCP dispatch surface (touches every MCP tool)
    "src/mcp/mod.rs", "src/mcp/registry.rs", "src/mcp/profile.rs",
    # Core data model (every test depends on Memory shape)
    "src/models/memory.rs", "src/models/link.rs", "src/models/mod.rs",
    # HTTP topology (every handler depends on transport)
    "src/handlers/transport.rs", "src/handlers/mod.rs",
    "src/handlers/http.rs",
    # #3503: binding, authorization and visibility changes must run every
    # acceptance/attestation/pubkey/federation suite, including explicitly
    # named Cargo.toml targets under tests/acceptance/.
    "src/handlers/admin.rs", "src/handlers/identity_binding.rs",
    "src/visibility.rs",
    # Federation RECEIVE authorization surface (#2488/#2491): the two
    # `/sync/push` funnels and the shared verdict they both route through.
    # A refused item is a counter bump inside an HTTP 200, so the token
    # heuristic cannot be trusted to select the federation binaries.
    "src/handlers/federation_receive.rs",
    "src/handlers/federation_signing_check.rs",
    # #3503 broadens the receive-auth pin to the entire federation tree.
    "src/federation/*",
    # CI + gate scripts (changes to CI itself need full validation)
    ".github/workflows/ci.yml", ".github/workflows/c8-precheck.yml",
    "scripts/check-vendor-literals.sh", "scripts/qc-codegraph-precheck.sh",
    "scripts/ci/test_impact.py",
    # Authorization bypass approvals need the same full-suite validation
    # as the gate that reads them.
    "scripts/qc-codegraph-allowlists/*",
    # Recall + governance + signed events (cross-cutting subsystems)
    "src/reranker.rs", "src/hnsw.rs", "src/embeddings.rs",
    "src/signed_events.rs", "src/governance/mod.rs",
    "src/governance/audit.rs", "src/governance/rules.rs",
)

# Cheap (millisecond runtime) tests that catch cross-cutting drift the
# heuristic might otherwise miss. Add a test here when it is (a) mechanical,
# (b) fast, (c) load-bearing for a substrate-wide invariant.
ALWAYS_RUN_PARITY_TESTS = (
    "route_count_invariant",
    "cli_subcommand_count_invariant",
    "memory_link_relation_count_invariant",
    "mcp_input_schema_no_false_strict_1052",
    "token_budget_guard",
    "config_precedence",
    # Wave-2 B3 - at-rest content-encryption E2E is a release gate (default
    # build RED when S1 refused ChaCha). Not millisecond-cheap; required.
    "encryption_at_rest",
)

STOPLIST = frozenset((
    "rs", "src", "lib", "mod", "tests", "test", "the", "and", "for", "use",
    "with", "core", "util", "utils", "main",
))


def emit(key, value):
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (key, value))
    sys.stdout.write("%s=%s\n" % (key, value))
    sys.stdout.flush()


def note(message):
    if os.environ.get("GITHUB_OUTPUT"):
        sys.stdout.write("::notice::%s\n" % message)
        sys.stdout.flush()
    else:
        sys.stderr.write("[note] %s\n" % message)


def emit_all(reason, total=COUNT_ALL):
    emit(KEY_IMPACT, VALUE_ALL)
    emit(KEY_COUNT, COUNT_ALL)
    emit(KEY_TOTAL, total)
    emit(KEY_REASON, reason)


def is_foundational(path):
    return any(fnmatch.fnmatchcase(path, pat) for pat in FOUNDATIONAL_PATTERNS)


def _strip_ext(text):
    index = text.rfind(".")
    return text[:index] if index >= 0 else text


def tokenise(path):
    """Tokens of 3+ chars from the basename and the full path (sorted, unique)."""
    stem = _strip_ext(path.rsplit("/", 1)[-1])
    full = _strip_ext(path.replace("/", "_"))
    tokens = set()
    for text in (stem, full):
        for char in TOKEN_SEPARATORS:
            text = text.replace(char, "\n")
        for fragment in text.split("\n"):
            if len(fragment) >= MIN_TOKEN_LEN and fragment not in STOPLIST:
                tokens.add(fragment.lower())
    return sorted(tokens)


def list_test_names(repo_root):
    tests = Path(repo_root) / TESTS_DIR
    try:
        entries = [p for p in tests.iterdir() if p.is_file() and p.name.endswith(".rs")]
    except OSError:
        return []
    return sorted(p.name for p in entries)


def compute_impact(repo_root, changed):
    tokens = set()
    direct = set()
    for path in changed:
        if fnmatch.fnmatchcase(path, "tests/*.rs"):
            direct.add(_strip_ext(path.rsplit("/", 1)[-1]))
        elif path.startswith("src/") or path.startswith("tests/"):
            tokens.update(tokenise(path))
    impacted = set()
    for name in [_strip_ext(n) for n in list_test_names(repo_root)]:
        if name in direct or tokens.intersection(tokenise(name + ".rs")):
            impacted.add(name)
    for name in ALWAYS_RUN_PARITY_TESTS:
        if (Path(repo_root) / TESTS_DIR / (name + ".rs")).is_file():
            impacted.add(name)
    return sorted(impacted)


def run_git(*args):
    return subprocess.run(
        ["git"] + list(args), check=False, capture_output=True, text=True)


def owned_paths_gate(repo_root, changed):
    """Run the manifest-owned paths gate (#8077).

    Returns (stems, defect): defect is None on exit 0/1, else the reason; any
    unexpected outcome fails closed (Discipline item 1).
    """
    gate = Path(repo_root) / OWNED_GATE_REL
    if not gate.is_file():
        return [], "script missing: %s" % OWNED_GATE_REL
    try:
        scratch = Path(repo_root) / OWNED_SCRATCH_DIR
        scratch.mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile(
                "w", dir=str(scratch), suffix=".diff", delete=False, encoding="utf-8") as handle:
            handle.write("\n".join(changed) + "\n")
            diff_file = Path(handle.name)
    except OSError as err:
        return [], "cannot write diff file: %s" % err
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(gate), "--root", str(repo_root), "--diff-file", str(diff_file)],
            check=False, capture_output=True, text=True, timeout=OWNED_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as err:
        return [], "gate did not run: %s" % err
    finally:
        try:
            diff_file.unlink()
        except OSError:
            pass
    if proc.returncode not in (OWNED_EXIT_OK, OWNED_EXIT_MATCH):
        first = (proc.stderr.strip().splitlines() or ["exit %d" % proc.returncode])[0]
        return [], first
    stems = []
    for line in proc.stdout.splitlines():
        found = OWNED_RUN_RE.search(line)
        if found and found.group(1) not in stems:
            stems.append(found.group(1))
    return stems, None


def run_self_test():
    repo_root = Path(__file__).resolve().parents[REPO_ROOT_DEPTH]
    counts = {"pass": 0, "fail": 0}

    def check(name, expected, got):
        if expected == got:
            print("  PASS  %s" % name)
            counts["pass"] += 1
        else:
            print("  FAIL  %s\n        expected: %s\n        got:      %s" % (name, expected, got))
            counts["fail"] += 1

    def yes_no(value):
        return "yes" if value else "no"

    check("Cargo.toml is foundational", "yes", yes_no(is_foundational("Cargo.toml")))
    check("src/lib.rs is foundational", "yes", yes_no(is_foundational("src/lib.rs")))
    check("src/validate.rs is foundational", "yes", yes_no(is_foundational("src/validate.rs")))
    check("migrations.rs is foundational", "yes", yes_no(is_foundational("src/storage/migrations.rs")))
    check("handlers/memories.rs is NOT foundational", "no", yes_no(is_foundational("src/handlers/memories.rs")))
    check("handlers/admin.rs IS foundational", "yes", yes_no(is_foundational("src/handlers/admin.rs")))
    check("tests/foo.rs is NOT foundational", "no", yes_no(is_foundational("tests/foo.rs")))
    check(".github/workflows/ci.yml IS foundational", "yes", yes_no(is_foundational(".github/workflows/ci.yml")))

    check("tokenise(memories_query) -> split + denoised", "handlers memories query",
          " ".join(tokenise("src/handlers/memories_query.rs")))
    check("tokenise(admin) -> denoised", "admin handlers",
          " ".join(tokenise("src/handlers/admin.rs")))

    if (repo_root / TESTS_DIR).is_dir():
        out = compute_impact(repo_root, ["src/handlers/admin.rs"])
        check("compute_impact(handlers/admin.rs) includes admin_*", "yes",
              "yes" if any("admin_" in n for n in out) else "no - got: %s" % " ".join(out))
        check("compute_impact always includes route_count_invariant", "yes",
              yes_no("route_count_invariant" in out))

    print("\n[self-test] %d passed / %d failed" % (counts["pass"], counts["fail"]))
    return EXIT_OK if counts["fail"] == 0 else EXIT_FAIL


def split_lines(text):
    return [line for line in text.split("\n") if line]


def main(argv):
    if argv and argv[0] == SELF_TEST_FLAG:
        return run_self_test()
    base = argv[0] if len(argv) > 0 else ""
    head = argv[1] if len(argv) > 1 and argv[1] else DEFAULT_HEAD
    foundational_base = argv[2] if len(argv) > 2 and argv[2] else base

    if not base:
        note("no base SHA supplied - running FULL suite")
        emit_all("no-base-sha")
        return EXIT_OK
    if run_git("rev-parse", base).returncode != 0:
        note("base SHA %s not in repo - running FULL suite" % base)
        emit_all("base-unreachable")
        return EXIT_OK

    # #1611 - a git FAILURE must fall back to the FULL suite, not masquerade
    # as an empty diff. Both paths of renames are shown (--no-renames) so a
    # security file moved into docs cannot hide behind the docs-only rule.
    diff = run_git("diff", "--no-renames", "--name-only", base, head)
    if diff.returncode != 0:
        note("git diff %s..%s FAILED - running FULL suite" % (base, head))
        emit_all("git-diff-failed")
        return EXIT_OK
    diff_out = diff.stdout.rstrip("\n")
    foundational_diff = diff_out
    if foundational_base != base:
        pr_diff = run_git("diff", "--no-renames", "--name-only", foundational_base, head)
        if pr_diff.returncode != 0:
            note("foundational diff failed - running FULL suite")
            emit_all("foundational-diff-failed")
            return EXIT_OK
        # Retain incremental paths too: reverting a security change still
        # needs full validation even if it vanishes from the net PR diff.
        foundational_diff = diff_out + "\n" + pr_diff.stdout.rstrip("\n")

    changed = split_lines(diff_out)
    if not changed:
        note("no diff vs base - treating as docs-only no-op")
        emit(KEY_IMPACT, VALUE_SKIP)
        emit(KEY_COUNT, COUNT_NONE)
        emit(KEY_TOTAL, COUNT_NONE)
        emit(KEY_REASON, "empty-diff")
        return EXIT_OK

    if all(any(fnmatch.fnmatchcase(p, pat) for pat in DOCS_ONLY_PATTERNS) for p in changed):
        emit(KEY_IMPACT, VALUE_SKIP)
        emit(KEY_COUNT, COUNT_NONE)
        emit(KEY_TOTAL, COUNT_NONE)
        emit(KEY_REASON, "docs-only")
        return EXIT_OK

    for path in foundational_diff.split("\n"):
        if is_foundational(path):
            note("foundational change detected (%s) - running FULL suite" % path)
            emit_all("foundational:%s" % path)
            return EXIT_OK

    top = run_git("rev-parse", "--show-toplevel")
    repo_root = top.stdout.strip() if top.returncode == 0 else "."
    impacted = compute_impact(repo_root, changed)
    total = len(list_test_names(repo_root))

    if not impacted:
        note("empty impact set for non-foundational diff - falling back to FULL suite")
        emit_all("empty-impact-fallback", total=str(total))
        return EXIT_OK

    owned, defect = owned_paths_gate(repo_root, changed)
    if defect is not None:
        note("manifest-owned-paths gate defect - running FULL suite: %s" % defect)
        emit_all(OWNED_DEFECT_PREFIX + defect, total=str(total))
        return EXIT_OK
    added = [stem for stem in owned if stem not in impacted]
    impacted = sorted(impacted + added)

    count = len(impacted)
    reduction = int((total - count) * PERCENT / max(total, 1))
    emit(KEY_IMPACT, " ".join(impacted))
    emit(KEY_COUNT, str(count))
    emit(KEY_TOTAL, str(total))
    reason = "impact-selected:%d/%d (%d%%-skip)" % (count, total, reduction)
    if added:
        reason += "; +%d manifest-owned" % len(added)
    emit(KEY_REASON, reason)
    note("test-impact: %d/%d integration binaries (%d%% skip)" % (count, total, reduction))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
