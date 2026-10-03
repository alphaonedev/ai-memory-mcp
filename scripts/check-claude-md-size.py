#!/usr/bin/env python3
"""check-claude-md-size.py - issue #4507: keep the tracked CLAUDE.md small and intact.

Claude Code loads the tracked CLAUDE.md in full into EVERY session and subagent
started in a checkout (measured: ~200k tokens on turn one at 448 KB, ~42k with a
slim copy). The Architecture and Code Style bodies therefore live in
docs/reference/ and CLAUDE.md keeps only rule sections plus pointers.

What this gate enforces (and nothing more):
  1. CLAUDE.md, ARCHITECTURE_REFERENCE.md and CODE_STYLE.md are each a regular
     file: a symlink or any other non-regular file is refused.
  2. CLAUDE.md is at most CLAUDE_MD_MAX_BYTES and at least CLAUDE_MD_MIN_BYTES.
  3. Every `## ` heading in CLAUDE_MD_REQUIRED_HEADINGS is present in CLAUDE.md
     (headings inside backtick or tilde code fences or inside HTML comments do
     not count), so deleting, renaming or hiding a rule section fails.
  4. Each reference file starts with its expected top heading and is at least
     its minimum size, so truncating or emptying it fails.
It does NOT verify the wording of any section body, and it does not prove that
moved text is unchanged; those need review. Heading, size and ceiling constants
are pinned: ceilings only fall, floors only rise, and a change to any of them is
an explicit decision.

Usage:
  scripts/check-claude-md-size.py [ROOT]
  scripts/check-claude-md-size.py --self-test
"""
import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

# Ceilings only fall (#4507 target: <= 80 KB). Keep CLAUDE.md short rather than raising this.
CLAUDE_MD_MAX_BYTES = 80_000
# Floors only rise. Measured at the #4507 split: 64,378 bytes plus the binding-rules index.
CLAUDE_MD_MIN_BYTES = 55_000

# Pinned `## ` headings of CLAUDE.md, identical to the pre-split file at 9f68ea41a (15 headings).
CLAUDE_MD_REQUIRED_HEADINGS = (
    "## Hard rule — `memory_store` FIRST on operator multi-step directives (L1 of #1389 layered-capture architecture)",
    "## Required Reading at Session Start (AI agents)",
    "## Build & Test Commands",
    "## Dogfooding release branches",
    "## Reproducing the v0.7.0 recursive-learning primitive",
    "## Architecture",
    "## Adding New Functionality",
    "## Code Style",
    "## Prime directive (operator-set, 2026-05-17)",
    "## Crossroads decision protocol — deterministic 5-agent adversarial vote (operator-set 2026-06-18)",
    "## v0.7.0 release gate (operator-set 2026-05-17 pm-v5)",
    "## Sole-authority operator + no-external-code-injection (operator-set 2026-05-25)",
    "## Commit & push policy (project override of global default)",
    "## Multi-agent worktree discipline (issue #856)",
    "## No agent-created files under /tmp, /var/tmp, /private/tmp, or any tmpfs (project hard rule)",
)

# (path, expected first line, minimum bytes). Floors only rise. Measured at the split:
# ARCHITECTURE_REFERENCE.md 333,930 bytes; CODE_STYLE.md 51,204 bytes.
REFERENCE_FILES = (
    ("docs/reference/ARCHITECTURE_REFERENCE.md", "# ai-memory Architecture Reference", 300_000),
    ("docs/reference/CODE_STYLE.md", "# ai-memory Code Style Reference", 45_000),
)
REFERENCE_PATHS = tuple(entry[0] for entry in REFERENCE_FILES)


def regular_size(path: Path, label: str, errors: list):
    """Return the size of a regular, non-symlink file, or None after recording why not."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        errors.append(f"FAIL: cannot stat {label}: {exc}")
        return None
    if stat.S_ISLNK(mode):
        errors.append(f"FAIL: {label} is a symlink; it must be a regular file (#4507)")
        return None
    if not stat.S_ISREG(mode):
        errors.append(f"FAIL: {label} is not a regular file (#4507)")
        return None
    return path.stat().st_size


FENCE_OPEN = re.compile(r"^\s*(`{3,}|~{3,})")


def split_lines(text: str) -> list:
    """Split on \\n only (as an editor or renderer does); Python's splitlines also splits on U+2028 and friends."""
    return text.replace("\r\n", "\n").split("\n")


def visible_lines(text: str) -> list:
    """Return the lines that render as prose: outside fenced code and outside HTML comments.

    Fences follow CommonMark: a run of 3+ backticks or tildes opens one, and only a bare run of the
    same character, at least as long, closes it. An unclosed fence hides the rest of the file.
    HTML comments (`<!--` to `-->`, on one line or many) are removed; text outside them is kept.
    """
    out = []
    fence = None
    in_comment = False
    for line in split_lines(text):
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if fence is not None:
            match = FENCE_OPEN.match(line)
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1] \
                    and not line.strip().strip(fence[0]):
                fence = None
            continue
        match = FENCE_OPEN.match(line)
        if match:
            fence = (match.group(1)[0], len(match.group(1)))
            continue
        kept = ""
        rest = line
        while True:
            start = rest.find("<!--")
            if start < 0:
                kept += rest
                break
            kept += rest[:start]
            end = rest.find("-->", start + 4)
            if end < 0:
                in_comment = True
                break
            rest = rest[end + 3:]
        if kept.strip() or not line.strip():
            out.append(kept)
    return out


def headings_outside_fences(text: str) -> list:
    """Return the `## ` heading lines of `text` that render (not fenced, not in an HTML comment)."""
    return [line.rstrip() for line in visible_lines(text) if line.startswith("## ")]


def check(root: Path) -> list:
    """Return a list of failure messages (empty means pass)."""
    errors = []
    claude = root / "CLAUDE.md"
    size = regular_size(claude, "CLAUDE.md", errors)
    if size is not None:
        if size > CLAUDE_MD_MAX_BYTES:
            errors.append(
                f"FAIL: CLAUDE.md is {size} bytes, over the {CLAUDE_MD_MAX_BYTES}-byte ceiling "
                "(CLAUDE_MD_MAX_BYTES). It loads eagerly into every agent session. Put "
                "reference material in " + " or ".join(REFERENCE_PATHS) +
                " instead, and keep CLAUDE.md to operator rule sections and pointers (#4507)."
            )
        if size < CLAUDE_MD_MIN_BYTES:
            errors.append(
                f"FAIL: CLAUDE.md is {size} bytes, under the {CLAUDE_MD_MIN_BYTES}-byte floor "
                "(CLAUDE_MD_MIN_BYTES); rule-section content appears to have been removed (#4507)."
            )
        try:
            text = claude.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read CLAUDE.md as UTF-8: {exc}")
            text = ""
        present = set(headings_outside_fences(text))
        for heading in CLAUDE_MD_REQUIRED_HEADINGS:
            if heading not in present:
                errors.append(f"FAIL: CLAUDE.md is missing the required heading: {heading}")
    for rel, top_heading, min_bytes in REFERENCE_FILES:
        path = root / rel
        ref_size = regular_size(path, rel, errors)
        if ref_size is None:
            continue
        if ref_size < min_bytes:
            errors.append(
                f"FAIL: {rel} is {ref_size} bytes, under its {min_bytes}-byte floor; "
                "the moved reference content appears to have been truncated (#4507)."
            )
        try:
            with path.open(encoding="utf-8") as handle:
                first = handle.readline().rstrip("\n")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read {rel} as UTF-8: {exc}")
            continue
        if first != top_heading:
            errors.append(f"FAIL: {rel} must start with the heading {top_heading!r}, found {first!r}")
    return errors


def build_fixture(root: Path) -> None:
    """Write a tree that passes check(): all pinned headings, files at their floors."""
    body = "\n".join(CLAUDE_MD_REQUIRED_HEADINGS) + "\n"
    pad = max(0, CLAUDE_MD_MIN_BYTES - len(body.encode("utf-8")))
    (root / "CLAUDE.md").write_text(body + "x" * pad, encoding="utf-8")
    for rel, top_heading, min_bytes in REFERENCE_FILES:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        head = top_heading + "\n"
        target.write_text(head + "x" * (min_bytes - len(head)), encoding="utf-8")


def expect(root: Path, label: str, want_fail: bool, needle: str = "") -> bool:
    errors = check(root)
    if want_fail and not any(needle in line for line in errors):
        print(f"FAIL: self-test - {label} was NOT rejected (wanted a message containing {needle!r})",
              file=sys.stderr)
        return False
    if not want_fail and errors:
        print(f"FAIL: self-test - {label} was rejected: {errors[0]}", file=sys.stderr)
        return False
    return True


def run_cases(base: Path) -> bool:
    """Each case builds a fresh tree under `base`, applies one defect and expects its refusal."""
    counter = [0]

    def fresh() -> Path:
        counter[0] += 1
        root = base / f"case{counter[0]}"
        root.mkdir()
        build_fixture(root)
        return root

    claude_md = "CLAUDE.md"
    arch, style = REFERENCE_PATHS
    ok = expect(fresh(), "a valid tree", False)

    root = fresh()
    (root / claude_md).write_text("x" * (CLAUDE_MD_MAX_BYTES + 1), encoding="utf-8")
    ok &= expect(root, "an oversized CLAUDE.md", True, "ceiling")

    root = fresh()
    (root / claude_md).write_text(
        "\n".join(CLAUDE_MD_REQUIRED_HEADINGS) + "\n" + "x" * (CLAUDE_MD_MAX_BYTES), encoding="utf-8")
    ok &= expect(root, "a CLAUDE.md just over the ceiling (inclusive bound)", True, "ceiling")

    root = fresh()
    text = "\n".join(CLAUDE_MD_REQUIRED_HEADINGS) + "\n"
    (root / claude_md).write_text(text + "x" * (CLAUDE_MD_MAX_BYTES - len(text.encode("utf-8"))), encoding="utf-8")
    ok &= expect(root, "a CLAUDE.md exactly at the ceiling", False)

    root = fresh()
    (root / claude_md).write_text("\n".join(CLAUDE_MD_REQUIRED_HEADINGS) + "\n", encoding="utf-8")
    ok &= expect(root, "a CLAUDE.md under the byte floor", True, "floor")

    root = fresh()
    (root / arch).unlink()
    ok &= expect(root, "a missing reference file", True, "cannot stat")

    root = fresh()
    real = root / "real.md"
    shutil.copy(root / claude_md, real)
    (root / claude_md).unlink()
    (root / claude_md).symlink_to(real)
    ok &= expect(root, "a symlinked CLAUDE.md", True, "symlink")

    root = fresh()
    real = root / "real-ref.md"
    shutil.copy(root / style, real)
    (root / style).unlink()
    (root / style).symlink_to(real)
    ok &= expect(root, "a symlinked reference file", True, "symlink")

    root = fresh()
    (root / claude_md).unlink()
    (root / claude_md).mkdir()
    ok &= expect(root, "a CLAUDE.md that is a directory", True, "not a regular file")

    root = fresh()
    (root / style).write_text("x\n", encoding="utf-8")
    ok &= expect(root, "a truncated reference file", True, "floor")

    root = fresh()
    path = root / arch
    path.write_text("# something else\n" + "x" * 300_000, encoding="utf-8")
    ok &= expect(root, "a reference file with the wrong top heading", True, "must start with the heading")

    for heading in CLAUDE_MD_REQUIRED_HEADINGS:
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", "", 1)
        (root / claude_md).write_text(text + "x" * len(heading), encoding="utf-8")
        ok &= expect(root, f"CLAUDE.md with the rule section {heading!r} deleted", True, "missing the required heading")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[0]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", "```\n" + heading + "\n```\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a required heading that exists only inside a code fence", True, "missing the required heading")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", "~~~\n" + heading + "\n~~~\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a required heading that exists only inside a tilde fence", True, "missing the required heading")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", "<!--\n" + heading + "\n-->\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a required heading that exists only inside an HTML comment", True, "missing the required heading")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", "<!-- " + heading + " -->\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a required heading wrapped in a one-line HTML comment", True, "missing the required heading")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", "````\n```\n" + heading + "\n````\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a heading after a shorter inner fence inside a four-backtick fence", True,
                 "missing the required heading")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8")
    text = "~~~\nfenced\n~~~\n<!-- a comment\nspanning lines -->\n<!-- one line -->\n" + text
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "headings after a closed tilde fence and closed HTML comments", False)

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", heading + " <!-- note -->\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a heading followed by a trailing HTML comment (still renders)", False)
    return ok


def self_test() -> int:
    # Scratch lives under <repo>/.local-runs/ (project no-/tmp hard rule), never system /tmp.
    scratch_base = Path(__file__).resolve().parent.parent / ".local-runs"
    scratch_base.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="claude-md-size-selftest-", dir=scratch_base)
    try:
        ok = run_cases(Path(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not ok:
        return 1
    print(
        "PASS: self-test #4507 - rejects oversize, undersize, missing or symlinked or non-regular files, "
        "truncated references, wrong top heading and every deleted pinned heading; accepts the ceiling exactly"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    errors = check(Path(args.root))
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        return 1
    print(
        f"PASS: CLAUDE.md is a regular file within {CLAUDE_MD_MIN_BYTES}..{CLAUDE_MD_MAX_BYTES} bytes with "
        f"all {len(CLAUDE_MD_REQUIRED_HEADINGS)} pinned headings; reference files are regular, "
        "start with their heading and meet their size floors"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
