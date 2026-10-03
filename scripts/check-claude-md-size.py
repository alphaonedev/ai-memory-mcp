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
  5. The `### Binding rules that live in the reference file` index is present in the
     Architecture and Code Style pointer sections with at least the pinned number of
     entries, and every quote in it is present verbatim at its cited lines of the
     reference file it names.
It does NOT verify the wording of any other section body, and it does not prove that
moved text is unchanged; those need review. Heading, size and ceiling constants
are pinned: ceilings only fall, floors only rise, and a change to any of them is
an explicit decision.

Usage:
  scripts/check-claude-md-size.py [ROOT]
  scripts/check-claude-md-size.py --self-test
"""
import argparse
import hashlib
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

# R3-8: minimum visible body bytes per pinned heading (about 90% of the size at the split, rounded down to
# 100). Without it a rule section could be emptied to its heading and CLAUDE.md would still clear the
# whole-file floor. One table, same order as CLAUDE_MD_REQUIRED_HEADINGS; floors only rise.
CLAUDE_MD_SECTION_MIN_BYTES = (
    1900,   # Hard rule - memory_store FIRST
    5700,   # Required Reading at Session Start
    1600,   # Build & Test Commands
    900,    # Dogfooding release branches
    700,    # Reproducing the v0.7.0 recursive-learning primitive
    1100,   # Architecture (pointer + binding-rules index)
    4300,   # Adding New Functionality
    1300,   # Code Style (pointer + binding-rules index)
    14600,  # Prime directive
    3100,   # Crossroads decision protocol
    1100,   # v0.7.0 release gate
    7100,   # Sole-authority operator + no-external-code-injection
    5700,   # Commit & push policy
    4100,   # Multi-agent worktree discipline
    2600,   # No agent-created files under /tmp
)

# (path, expected first line, minimum bytes). Floors only rise. Measured at the split:
# ARCHITECTURE_REFERENCE.md 333,930 bytes; CODE_STYLE.md 51,204 bytes.
REFERENCE_FILES = (
    ("docs/reference/ARCHITECTURE_REFERENCE.md", "# ai-memory Architecture Reference", 300_000),
    ("docs/reference/CODE_STYLE.md", "# ai-memory Code Style Reference", 45_000),
)
REFERENCE_PATHS = tuple(entry[0] for entry in REFERENCE_FILES)

# The binding-rules index (#4507 L1): agent-directed prohibitions that live only in a reference file are
# quoted verbatim in CLAUDE.md so they bind even if the reference file is never opened. Each pointer
# section must carry the index heading and at least the listed number of entries; every entry's quote
# must be present verbatim (line breaks joined by one space) at the cited lines of its reference file.
# Floors only rise: adding an index entry raises the count here, removing one is an explicit decision.
INDEX_HEADING = "### Binding rules that live in the reference file"
INDEX_MIN_QUOTE_CHARS = 20
# (CLAUDE.md `## ` section, reference basename without .md, minimum entry count)
INDEX_SECTIONS = (
    ("## Architecture", "ARCHITECTURE_REFERENCE", 5),
    ("## Code Style", "CODE_STYLE", 7),
)
INDEX_ENTRY = re.compile(r'^- `([A-Z_]+)\.md:(\d+)(?:-(\d+))?` "(.+)"$')


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


def sections_of(visible: list) -> dict:
    """Map each visible `## ` heading to the visible lines under it (first occurrence wins)."""
    sections = {}
    current = None
    for line in visible:
        if line.startswith("## "):
            current = line.rstrip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line.rstrip())
    return sections


def check_index(visible: list, ref_lines: dict, errors: list) -> None:
    """Fail unless each pointer section carries its binding-rules index and every quote is verbatim."""
    sections = sections_of(visible)
    for heading, name, minimum in INDEX_SECTIONS:
        lines = sections.get(heading)
        if lines is None:
            continue  # the missing pinned heading is already reported
        if INDEX_HEADING not in lines:
            errors.append(f"FAIL: CLAUDE.md section '{heading}' has no '{INDEX_HEADING}' block (#4507)")
            continue
        block = []
        for line in lines[lines.index(INDEX_HEADING) + 1:]:
            if line.startswith("#"):
                break
            if line.startswith("- "):
                block.append(line)
        verified = 0
        for line in block:
            match = INDEX_ENTRY.match(line)
            if not match or len(match.group(4)) < INDEX_MIN_QUOTE_CHARS:
                errors.append(f"FAIL: malformed binding-rules index entry under '{heading}': {line[:120]}")
                continue
            lo = int(match.group(2))
            hi = int(match.group(3) or match.group(2))
            where = f"{match.group(1)}.md:{lo}-{hi}"
            if match.group(1) != name:
                errors.append(f"FAIL: index entry under '{heading}' cites {where}, expected {name}.md")
                continue
            ref = ref_lines.get(name)
            if ref is None:
                continue  # the unreadable reference file is already reported
            if not 1 <= lo <= hi <= len(ref):
                errors.append(f"FAIL: index entry cites {where}, outside the {len(ref)}-line reference file")
                continue
            span = " ".join(part.strip() for part in ref[lo - 1:hi])
            if match.group(4) not in span:
                errors.append(f"FAIL: index quote is not verbatim at {where}: {match.group(4)[:100]}")
                continue
            verified += 1
        if verified < minimum:
            errors.append(
                f"FAIL: '{heading}' index has {verified} verified entries, under the pinned minimum "
                f"{minimum} (INDEX_SECTIONS); a binding rule was removed or altered (#4507)"
            )


def check(root: Path) -> list:
    """Return a list of failure messages (empty means pass)."""
    errors = []
    visible = []
    ref_lines = {}
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
        visible = visible_lines(text)
        present = {line.rstrip() for line in visible if line.startswith("## ")}
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
            ref_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read {rel} as UTF-8: {exc}")
            continue
        ref_lines[Path(rel).stem] = split_lines(ref_text)
        first = ref_lines[Path(rel).stem][0]
        if first != top_heading:
            errors.append(f"FAIL: {rel} must start with the heading {top_heading!r}, found {first!r}")
    if size is not None:
        sections = sections_of(visible)
        for heading, floor in zip(CLAUDE_MD_REQUIRED_HEADINGS, CLAUDE_MD_SECTION_MIN_BYTES):
            if heading not in sections:
                continue  # the missing heading is already reported
            body = len("\n".join(sections[heading]).encode("utf-8"))
            if body < floor:
                errors.append(
                    f"FAIL: CLAUDE.md section {heading!r} body is {body} bytes, under its {floor}-byte "
                    "floor (CLAUDE_MD_SECTION_MIN_BYTES); the rule section appears to have been emptied (#4507)"
                )
    check_index(visible, ref_lines, errors)
    return errors


def fixture_quote(name: str, number: int) -> str:
    return f"fixture binding rule {number} of {name} must never be dropped from the index"


def fixture_claude_text() -> str:
    """CLAUDE.md text that passes check() apart from the byte floor: pinned headings plus the index blocks."""
    counts = {heading: (name, minimum) for heading, name, minimum in INDEX_SECTIONS}
    lines = []
    for heading, floor in zip(CLAUDE_MD_REQUIRED_HEADINGS, CLAUDE_MD_SECTION_MIN_BYTES):
        lines.append(heading)
        lines.append("section body " + "x" * floor)
        if heading in counts:
            name, minimum = counts[heading]
            lines += ["", INDEX_HEADING, ""]
            lines += [f'- `{name}.md:{n + 1}` "{fixture_quote(name, n)}"' for n in range(1, minimum + 1)]
            lines.append("")
    return "\n".join(lines) + "\n"


def build_fixture(root: Path) -> None:
    """Write a tree that passes check(): all pinned headings and index blocks, files at their floors."""
    body = fixture_claude_text()
    pad = max(0, CLAUDE_MD_MIN_BYTES - len(body.encode("utf-8")))
    (root / "CLAUDE.md").write_text(body + "x" * pad, encoding="utf-8")
    minimums = {name: minimum for _heading, name, minimum in INDEX_SECTIONS}
    for rel, top_heading, min_bytes in REFERENCE_FILES:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        name = Path(rel).stem
        head = top_heading + "\n" + "".join(
            fixture_quote(name, n) + "\n" for n in range(1, minimums.get(name, 0) + 1))
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
    text = fixture_claude_text()
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
    for index, heading in enumerate(CLAUDE_MD_REQUIRED_HEADINGS):
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8")
        start = text.index(heading + "\n") + len(heading) + 1
        end = text.find("\n## ", start)
        end = len(text) if end < 0 else end + 1
        text = text[:start] + text[end:]
        (root / claude_md).write_text("x" * 30000 + "\n" + text, encoding="utf-8")  # pad above every section
        ok &= expect(root, f"the rule section {heading[:40]!r} emptied to its heading (floor #{index})", True,
                     "appears to have been emptied")

    root = fresh()
    ok &= expect(root, "every section exactly at its floor", False)
    arch_h, style_h = INDEX_SECTIONS[0][0], INDEX_SECTIONS[1][0]
    for label, sections in (("Architecture", (arch_h,)), ("Code Style", (style_h,)), ("both", (arch_h, style_h))):
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8")
        for heading in sections:
            start = text.index(heading + "\n")
            at = text.index(INDEX_HEADING, start)
            end = text.index("\n## ", at)
            text = text[:at] + text[end + 1:]
        (root / claude_md).write_text(text + "x" * 5000, encoding="utf-8")
        ok &= expect(root, f"CLAUDE.md with the binding-rules index deleted from {label}", True, "block (#4507)")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        INDEX_HEADING + "\n", "<!--\n" + INDEX_HEADING + "\n", 1)
    start = text.index("<!--\n" + INDEX_HEADING)
    end = text.index("\n## ", start)
    text = text[:end] + "\n-->" + text[end:]
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "an index hidden inside an HTML comment", True, "block (#4507)")

    quote = fixture_quote("CODE_STYLE", 1)
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(quote, quote.replace("must never", "may"), 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "an index quote altered in CLAUDE.md", True, "not verbatim")

    root = fresh()
    path = root / style
    text = path.read_text(encoding="utf-8").replace(quote, "y" * len(quote), 1)
    path.write_text(text, encoding="utf-8")
    ok &= expect(root, "a quoted line removed from the reference file", True, "not verbatim")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace("CODE_STYLE.md:2`", "CODE_STYLE.md:99999`", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "an index entry citing lines beyond the reference file", True, "outside the")

    root = fresh()
    lines = (root / claude_md).read_text(encoding="utf-8").split("\n")
    drop = next(i for i, line in enumerate(lines) if line.startswith("- `ARCHITECTURE_REFERENCE.md:"))
    del lines[drop]
    (root / claude_md).write_text("\n".join(lines) + "x" * 5000, encoding="utf-8")
    ok &= expect(root, "an index entry removed below the pinned minimum", True, "pinned minimum")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        '- `CODE_STYLE.md:2`', '- `ARCHITECTURE_REFERENCE.md:2`', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "an index entry citing the other section's reference file", True, "expected CODE_STYLE.md")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        '- `CODE_STYLE.md:3` "', '- CODE_STYLE.md:3 "', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a malformed index entry", True, "malformed binding-rules index entry")
    return ok


# R2-4: the limits above, restated as literals that do NOT derive from the constants. The cases in
# run_cases build their fixtures from the constants, so raising CLAUDE_MD_MAX_BYTES or lowering a
# floor would leave every case green; this table is the second, independent edit a deliberate change
# must make (and a reviewer must see). Ceilings only fall, floors only rise.
SELF_TEST_PINNED_LIMITS = {
    "CLAUDE_MD_MAX_BYTES": 80_000,
    "CLAUDE_MD_MIN_BYTES": 55_000,
    "CLAUDE_MD_REQUIRED_HEADINGS_COUNT": 15,
    # sha256 of the 15 pinned headings joined by newline: rewording or swapping one is a deliberate edit too.
    "CLAUDE_MD_REQUIRED_HEADINGS_SHA256": "a96178554adeea9c1a96dc35950a8f8d6987c88f6a196c0683a52c725c8f9db4",
    "CLAUDE_MD_SECTION_MIN_BYTES": (1900, 5700, 1600, 900, 700, 1100, 4300, 1300, 14600, 3100, 1100, 7100,
                                    5700, 4100, 2600),
    "REFERENCE_FLOOR ARCHITECTURE_REFERENCE": 300_000,
    "REFERENCE_FLOOR CODE_STYLE": 45_000,
    "INDEX_MIN_QUOTE_CHARS": 20,
    "INDEX_MIN_ENTRIES ARCHITECTURE_REFERENCE": 5,
    "INDEX_MIN_ENTRIES CODE_STYLE": 7,
}


def current_limits() -> dict:
    """The limits as the guard will actually enforce them, keyed like SELF_TEST_PINNED_LIMITS."""
    limits = {
        "CLAUDE_MD_MAX_BYTES": CLAUDE_MD_MAX_BYTES,
        "CLAUDE_MD_MIN_BYTES": CLAUDE_MD_MIN_BYTES,
        "CLAUDE_MD_REQUIRED_HEADINGS_COUNT": len(CLAUDE_MD_REQUIRED_HEADINGS),
        "CLAUDE_MD_REQUIRED_HEADINGS_SHA256": hashlib.sha256(
            "\n".join(CLAUDE_MD_REQUIRED_HEADINGS).encode("utf-8")).hexdigest(),
        "INDEX_MIN_QUOTE_CHARS": INDEX_MIN_QUOTE_CHARS,
        "CLAUDE_MD_SECTION_MIN_BYTES": tuple(CLAUDE_MD_SECTION_MIN_BYTES),
    }
    for rel, _top, floor in REFERENCE_FILES:
        limits[f"REFERENCE_FLOOR {Path(rel).stem}"] = floor
    for _heading, name, minimum in INDEX_SECTIONS:
        limits[f"INDEX_MIN_ENTRIES {name}"] = minimum
    return limits


def limit_drift(current: dict) -> list:
    """Return one message per limit that differs from SELF_TEST_PINNED_LIMITS (or is missing/extra)."""
    drift = []
    for key, pinned in SELF_TEST_PINNED_LIMITS.items():
        if current.get(key) != pinned:
            drift.append(f"FAIL: limit {key} is {current.get(key)!r} but the self-test pins {pinned!r}; "
                         "a deliberate change must edit SELF_TEST_PINNED_LIMITS as well (#4507)")
    for key in current:
        if key not in SELF_TEST_PINNED_LIMITS:
            drift.append(f"FAIL: limit {key} is not pinned in SELF_TEST_PINNED_LIMITS (#4507)")
    return drift


def run_limit_cases() -> bool:
    """The independent pins: the real limits match, and each deliberate mutation is refused."""
    ok = True
    real = limit_drift(current_limits())
    if real:
        print(real[0], file=sys.stderr)
        ok = False
    for key in SELF_TEST_PINNED_LIMITS:
        for delta, label in ((1, "raised"), (-1, "lowered")):
            mutated = dict(current_limits())
            if isinstance(mutated[key], str):
                mutated[key] = mutated[key][:-1] + ("0" if mutated[key][-1] != "0" else "1")
            elif isinstance(mutated[key], tuple):
                mutated[key] = (mutated[key][0] + delta,) + mutated[key][1:]
            else:
                mutated[key] += delta
            if not any(key in line for line in limit_drift(mutated)):
                print(f"FAIL: self-test - limit {key} {label} by one was NOT detected", file=sys.stderr)
                ok = False
    removed = {k: v for k, v in current_limits().items() if k != "INDEX_MIN_ENTRIES CODE_STYLE"}
    if not limit_drift(removed):
        print("FAIL: self-test - a removed limit was NOT detected", file=sys.stderr)
        ok = False
    return ok


def scratch_base_error(repo_root: Path):
    """Return a failure message when `<repo_root>/.local-runs` is a symlink (or not a directory), else None.

    The self-test writes and then deletes a fixture tree there; through a symlink that would write
    outside the checkout (possibly onto /tmp or a tmpfs, which the project forbids) and delete there.
    """
    base = repo_root / ".local-runs"
    try:
        mode = os.lstat(base).st_mode
    except FileNotFoundError:
        return None  # will be created as a real directory
    except OSError as exc:
        return f"FAIL: cannot stat {base}: {exc}"
    if stat.S_ISLNK(mode):
        return f"FAIL: {base} is a symlink; the self-test refuses to write its fixtures through it (#4507)"
    if not stat.S_ISDIR(mode):
        return f"FAIL: {base} is not a directory (#4507)"
    return None


def run_scratch_cases(scratch_base: Path) -> bool:
    """A symlinked or non-directory .local-runs is refused; a real or absent one is accepted."""
    ok = True
    probe = scratch_base / "scratch-probe"
    probe.mkdir()
    (probe / "elsewhere").mkdir()
    (probe / ".local-runs").symlink_to(probe / "elsewhere")
    if "symlink" not in (scratch_base_error(probe) or ""):
        print("FAIL: self-test - a symlinked .local-runs was NOT refused", file=sys.stderr)
        ok = False
    (probe / ".local-runs").unlink()
    (probe / ".local-runs").write_text("file", encoding="utf-8")
    if "not a directory" not in (scratch_base_error(probe) or ""):
        print("FAIL: self-test - a .local-runs that is a file was NOT refused", file=sys.stderr)
        ok = False
    (probe / ".local-runs").unlink()
    if scratch_base_error(probe) is not None:
        print("FAIL: self-test - an absent .local-runs was refused", file=sys.stderr)
        ok = False
    (probe / ".local-runs").mkdir()
    if scratch_base_error(probe) is not None:
        print("FAIL: self-test - a real .local-runs directory was refused", file=sys.stderr)
        ok = False
    return ok


def self_test() -> int:
    # Scratch lives under <repo>/.local-runs/ (project no-/tmp hard rule), never system /tmp.
    repo_root = Path(__file__).resolve().parent.parent
    refusal = scratch_base_error(repo_root)
    if refusal:
        print(refusal, file=sys.stderr)
        return 1
    scratch_base = repo_root / ".local-runs"
    scratch_base.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="claude-md-size-selftest-", dir=scratch_base)
    try:
        ok = run_cases(Path(tmp))
        ok &= run_limit_cases()
        ok &= run_scratch_cases(Path(tmp))
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
