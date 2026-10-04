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
     entries, every quote in it EQUALS the full text of its cited lines of the
     reference file it names, and the set of quotes equals INDEX_QUOTE_PINS.
  6. Every rule section of CLAUDE.md (the raw text under each `## ` heading, fenced code
     included, plus text before the first heading) hashes to its line in
     scripts/qc-allowlists/claude-md-rule-sections.sha256. A reworded or refilled
     section, a deleted section, an added unpinned section or a removed manifest line
     fails; a missing, unreadable or symlinked manifest fails. `--update` rewrites the
     manifest and prints the changed sections. This is tamper-evidence, not authority:
     an agent that edits a rule can also run --update, so the two reviews and the sole
     merger remain the enforcement.
  7. The pull_request_target workflow .github/workflows/claude-md-rule-compare.yml equals
     its pinned canonical form. That job runs the BASE guard and BASE manifest over the head
     (read from git objects, never executed) via scripts/claude-md-rule-compare.py, prints
     every changed, added or removed rule section with its diff ("RULE TEXT CHANGED", or
     "COUNT CHANGED" for digit-only edits) and fails a rule change unless a commit in the
     range carries a `Rule-Change-Approved-By: <who>` trailer. TAMPER-EVIDENCE, not
     authority: an agent can write the trailer; the two reviews and the sole merger enforce.
     Bootstrap: it runs only once the workflow is on the base branch, so PR #4508 itself is
     judged by review.
It does NOT prove that moved text is unchanged; that needs review. Heading, size and ceiling constants
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
import unicodedata
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
REFERENCE_DIR = "docs/reference"

# R3-9: the visible `## ` and `### ` subsection headings of each reference file at the split. A file with
# the right top heading and enough junk to clear its byte floor still fails if a subsection is gone.
# Headings inside code fences or HTML comments do not count. Keyed by file stem; removing an entry is an
# explicit decision.
REFERENCE_SUBSECTIONS = {
    "ARCHITECTURE_REFERENCE": (
        "### Key Modules",
        "### Data Model",
        "### Recall Pipeline",
        "### Upsert Behavior",
        "### Mobile target support (v0.7.0 Posture-1a, issue #1068)",
        "### Database",
        "### Environment Variables",
        "### Config schema v0.7.x (#1146) \u2014 sectioned `[llm]` / `[embeddings]` / `[reranker]` / `[storage]` / `[limits]`",
        "### Agent Identity (NHI) \u2014 `metadata.agent_id`",
    ),
    "CODE_STYLE": (
        "### Lint gates (issue #1174 PR10 \u2014 pm-v3.1 vendor-monoculture + SECS_PER_*)",
    ),
}

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
# R3-F2: the full set of index quotes, as (reference basename, sha256 of the quote text), sorted. A quote
# must equal the whitespace-normalised text of its cited lines AND be in this set, and every pinned quote
# must be present exactly once: reworded, re-pointed, dropped, duplicated or added entries all fail.
# code-R3-F3: sha256 of the exact index lines (both sections, in file order, joined by a newline), so the cited
# range and the quote text are pinned together. Also pinned in SELF_TEST_PINNED_LIMITS: a change is two edits.
INDEX_ENTRIES_SHA256 = "de11dd7af07f6e340e2c7d7a75b451f4e41c67cd66548d59165cf7c81c19b6f7"
INDEX_QUOTE_PINS = (
    ("ARCHITECTURE_REFERENCE",
     "123b8bbe696bb26fa77c2bf30545c3c5768b73904280534c126f74f88546ccd4"),
    ("ARCHITECTURE_REFERENCE",
     "19f3d0432d655574ba1f9c167e0dd88cb986fed84b7be8926c44ca87a8523e0a"),
    ("ARCHITECTURE_REFERENCE",
     "5e61b4d224673138fbe5172f055a5f00aebbef8bcfde90601a19a385c8587b22"),
    ("ARCHITECTURE_REFERENCE",
     "3aee9c961d4cf176c9e681ebf30becbfb21fef0b5c65a8371fe4db60fcfeb424"),
    ("ARCHITECTURE_REFERENCE",
     "f071617d60a2f0124c2d79b503ab8465534611d8f4415c0510612391ba971062"),
    ("CODE_STYLE",
     "415e325e496f24029d2a8f97b11c757bf212da9ed8929aea245fa324e31bef7b"),
    ("CODE_STYLE",
     "5de1252f50a6753845a571f6a9dac544c98af8ea8b3e636887fdfbb05fca4814"),
    ("CODE_STYLE",
     "7629fb7d9c366b91c6c560ca280353dfde4f1bb3650d4100f6f5ebd77248de1e"),
    ("CODE_STYLE",
     "a79930c2e5745a8f71e7aec6fc110575e370f35c400337d1b7ade39d044d77d1"),
    ("CODE_STYLE",
     "b40ec9dc3d99bd43d0a44dac5c7a898a934969eafad6228939f0ffcc5e2d3574"),
    ("CODE_STYLE",
     "c164ff0843f842e3e44486bf31b8a6e0d10b7b32b27e03050542ad74fee4619f"),
    ("CODE_STYLE",
     "f2810c0ffb9adaa8716498fc7f8cc21bafba24c19096565290e5adcaabef9db8"),
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


# R3-F5: CommonMark fences. An opener or closer has at most 3 SPACES of indent (a tab, a no-break space or 4+
# spaces make the line indented code or text, not a fence); a backtick opener's info string has no backtick;
# a closer is a bare run of the same character, at least as long, followed only by spaces or tabs.
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
FENCE_CLOSE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
ODD_INDENT_FENCE = re.compile(r"^[ \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]*[\t\u00a0\u1680\u2000-\u200a"
                              r"\u202f\u205f\u3000][ \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]*(`{3,}|~{3,})")


def split_lines(text: str) -> list:
    """Split on \\n only (as an editor or renderer does); Python's splitlines also splits on U+2028 and friends."""
    return text.replace("\r\n", "\n").split("\n")


def fence_scan(text: str) -> list:
    """Return (line, in_code) per line; in_code is True for fence delimiters and fenced content.

    An unclosed fence hides the rest of the file (CommonMark closes it at the end of the document, so
    nothing after it renders as prose).
    """
    out = []
    fence = None
    for line in split_lines(text):
        if fence is not None:
            out.append((line, True))
            match = FENCE_CLOSE.match(line)
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1]:
                fence = None
            continue
        match = FENCE_OPEN.match(line)
        if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
            fence = (match.group(1)[0], len(match.group(1)))
            out.append((line, True))
            continue
        out.append((line, False))
    return out


RAW_BLOCK_OPEN = re.compile(r"^ {0,3}<(pre|script|style|textarea)(?:[\s>]|$)", re.IGNORECASE)
COMMENT_BLOCK_OPEN = re.compile(r"^ {0,3}<!--")


def visible_lines(text: str) -> list:
    """Return the lines that render as prose: outside fenced code and outside HTML comments.

    HTML comments (`<!--` to `-->`, on one line or many) are removed from what counts as visible; they are
    also refused outright by html_errors, so this only keeps a hidden heading from satisfying a pin.
    """
    out = []
    in_comment = False
    raw_close = None
    for line, in_code in fence_scan(text):
        if in_code:
            continue
        if raw_close is not None:
            # CommonMark HTML block type 1 (pre, script, style, textarea) runs to its closing tag.
            if raw_close in line.lower():
                raw_close = None
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        block = RAW_BLOCK_OPEN.match(line)
        if block:
            if f"</{block.group(1).lower()}" not in line.lower():
                raw_close = f"</{block.group(1).lower()}"
            continue
        if COMMENT_BLOCK_OPEN.match(line):
            # A line that begins with `<!--` is one HTML block (type 2): all of it, up to and including the
            # line holding `-->`, is raw HTML, so text after the `-->` is never a heading.
            if "-->" not in line:
                in_comment = True
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


HTML_BLOCK_STARTS = (
    re.compile(r"^<(?:script|pre|style|textarea)(?:[\s>]|$)", re.IGNORECASE),
    re.compile(r"^<!--"),
    re.compile(r"^<\?"),
    re.compile(r"^<![A-Za-z]"),
    re.compile(r"^<!\[CDATA\["),
    re.compile(
        r"^</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|"
        r"dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|"
        r"html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|"
        r"section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[\s>]|/>|$)", re.IGNORECASE),
    re.compile(r"^(?:<[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*)?/?>|</[A-Za-z][A-Za-z0-9-]*\s*>)\s*$"),
)
CONTAINER_PREFIX = re.compile(r"^(?: {0,3}>[ ]?| {0,3}(?:[-+*]|\d{1,9}[.)])[ \t]+| +)")


def html_errors(text: str, label: str) -> list:
    """R3-F5: refuse raw HTML blocks, HTML comments and odd-indent fences outside code fences.

    A CommonMark HTML block (start conditions 1-7, also behind blockquote or list markers) or a comment
    renders nothing the way the source reads, so a rule heading or body can be hidden in one. Inline tags
    inside a sentence are not blocks and stay allowed.
    """
    errors = []
    for number, (line, in_code) in enumerate(fence_scan(text), 1):
        if in_code:
            continue
        if ODD_INDENT_FENCE.match(line):
            errors.append(
                f"FAIL: {label}:{number} a fence marker indented with a tab or a no-break space is not a "
                "CommonMark fence (#4507 R3-F5)")
        if "<!--" in line:
            errors.append(f"FAIL: {label}:{number} raw HTML comment outside a code fence (#4507 R3-F5)")
            continue
        rest = line
        while True:
            stripped = CONTAINER_PREFIX.sub("", rest, count=1)
            if stripped == rest:
                break
            rest = stripped
        if any(pattern.match(rest) for pattern in HTML_BLOCK_STARTS):
            errors.append(f"FAIL: {label}:{number} raw HTML block outside a code fence: {line.strip()[:60]} (#4507 R3-F5)")
    return errors


# R3-F6: characters that make the bytes an agent tokenises differ from what a reviewer sees. Everything in
# Unicode category Cf (bidi controls U+202A-U+202E and U+2066-U+2069, zero-width U+200B-U+200F, U+2060-U+2064,
# U+00AD, U+FEFF, tag characters, ...), controls other than tab and a CRLF/LF break, line and paragraph
# separators, private use and surrogates, plus the blank-looking letters and selectors below. The one
# allowed exception: U+FE0F directly after a symbol (the emoji presentation selector of a warning sign).
INVISIBLE_EXTRA = frozenset(
    [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0, 0xFFFC] + list(range(0x180B, 0x1810)) +
    list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0)))


def read_utf8(path: Path) -> str:
    """Read the file as UTF-8 WITHOUT newline translation, so a bare CR stays visible to char_errors."""
    return path.read_bytes().decode("utf-8")


def char_errors(text: str, label: str) -> list:
    """R3-F6: one message per distinct refused character (with its first line) and for a bare CR."""
    errors = []
    seen = {}
    previous = ""
    line = 1
    for index, char in enumerate(text):
        code = ord(char)
        category = unicodedata.category(char)
        bad = None
        if char == "\r":
            if text[index + 1:index + 2] != "\n":
                bad = "bare CR"
        elif char in "\n\t":
            bad = None
        elif code == 0xFE0F and unicodedata.category(previous) == "So":
            bad = None
        elif category in ("Cf", "Cc", "Zl", "Zp", "Co", "Cs") or code in INVISIBLE_EXTRA:
            bad = f"invisible or control character U+{code:04X}"
        if bad and bad not in seen:
            seen[bad] = line
            errors.append(f"FAIL: {label}:{line} {bad} (bidi, zero-width and control characters are refused, "
                          "#4507 R3-F6)")
        if char == "\n":
            line += 1
        previous = char
    return errors


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


def check_index(visible: list, ref_lines: dict, errors: list, index_pins=None) -> None:
    """Fail unless each pointer section carries its binding-rules index and every quote is verbatim."""
    sections = sections_of(visible)
    all_index_lines = []
    cited = set()
    complete = True
    for heading, name, minimum in INDEX_SECTIONS:
        lines = sections.get(heading)
        if lines is None:
            complete = False
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
        all_index_lines += block
        verified = 0
        found = []
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
            if (match.group(1), lo, hi) in cited:
                errors.append(f"FAIL: index entry {where} appears more than once; entries must be unique "
                              "(#4507 code-R3-F3)")
                continue
            cited.add((match.group(1), lo, hi))
            ref = ref_lines.get(name)
            if ref is None:
                continue  # the unreadable reference file is already reported
            if not 1 <= lo <= hi <= len(ref):
                errors.append(f"FAIL: index entry cites {where}, outside the {len(ref)}-line reference file")
                continue
            # What is compared (R3-11, tightened by R3-F2), exactly: the cited reference lines lo..hi
            # inclusive, each stripped of leading and trailing whitespace ONLY (no case folding, no
            # punctuation or markdown stripping, no Unicode normalisation), joined by ONE space; the
            # CLAUDE.md quote must EQUAL that text. A substring is not enough: a prefix, a suffix or a
            # clipped quote would drop the obligation while still citing the right lines.
            span = " ".join(part.strip() for part in ref[lo - 1:hi])
            if match.group(4) != span:
                errors.append(
                    f"FAIL: index quote is not verbatim (it must equal the full text of the cited lines) "
                    f"at {where}: {match.group(4)[:100]}")
                continue
            found.append((name, hashlib.sha256(match.group(4).encode("utf-8")).hexdigest()))
            verified += 1
        if verified < minimum:
            errors.append(
                f"FAIL: '{heading}' index has {verified} verified entries, under the pinned minimum "
                f"{minimum} (INDEX_SECTIONS); a binding rule was removed or altered (#4507)"
            )
        pinned = sorted(pin for pin in (INDEX_QUOTE_PINS if index_pins is None else index_pins) if pin[0] == name)
        if sorted(found) != pinned:
            lost = len(pinned) - len([pin for pin in pinned if pin in found])
            extra = len(found) - len([pin for pin in found if pin in pinned])
            errors.append(
                f"FAIL: '{heading}' index quote set differs from INDEX_QUOTE_PINS: {lost} pinned quote(s) "
                f"missing, {extra} unpinned or duplicated quote(s) present; a binding rule was reworded, "
                "re-pointed, dropped or added without updating the pins (#4507 R3-F2)"
            )
    if complete and index_pins is None:
        digest = hashlib.sha256("\n".join(all_index_lines).encode("utf-8")).hexdigest()
        if digest != INDEX_ENTRIES_SHA256:
            errors.append(
                f"FAIL: the binding-rules index lines hash to {digest[:16]}, not the pinned "
                f"{INDEX_ENTRIES_SHA256[:16]} (INDEX_ENTRIES_SHA256): an entry's text or cited range changed; a "
                "deliberate edit must update INDEX_ENTRIES_SHA256 and SELF_TEST_PINNED_LIMITS (#4507 code-R3-F3)")


def path_symlink_errors(root: Path, rel: str) -> list:
    """R3-F7: refuse a symlink (or a missing or non-directory parent) at EVERY level of `rel` below `root`.

    The leaf must be a regular file. Walking each component closes the docs -> elsewhere swap that a check of
    only the leaf and its parent directory would miss."""
    errors = []
    parts = Path(rel).parts
    current = root
    for index, part in enumerate(parts):
        current = current / part
        label = "/".join(parts[: index + 1])
        try:
            mode = os.lstat(current).st_mode
        except OSError as exc:
            errors.append(f"FAIL: cannot stat {label}: {exc}")
            return errors
        if stat.S_ISLNK(mode):
            errors.append(f"FAIL: {label} is a symlink; every level of {rel} must be real (#4507 R3-F7)")
            return errors
        last = index == len(parts) - 1
        if last and not stat.S_ISREG(mode):
            errors.append(f"FAIL: {label} is not a regular file (#4507)")
        if not last and not stat.S_ISDIR(mode):
            errors.append(f"FAIL: {label} is not a directory (#4507)")
            return errors
    return errors


def has_body_line(text: str) -> bool:
    """True when the text has at least one line that is neither blank nor a Markdown heading."""
    return any(line.strip() and not line.lstrip().startswith("#") for line in text.splitlines())


def refs_errors(root: Path) -> list:
    """R3-F7/F8: the checks the two doc gates share. Each reference file is reached without a symlink, is
    a regular readable valid-UTF-8 file, and has body content beyond its headings."""
    errors = []
    for rel in REFERENCE_PATHS:
        walk = path_symlink_errors(root, rel)
        if walk:
            errors += walk
            continue
        try:
            text = read_utf8(root / rel)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read {rel} as UTF-8: {exc}")
            continue
        if not text.strip():
            errors.append(f"FAIL: {rel} is empty (#4507 R3-F8)")
        elif not has_body_line(text):
            errors.append(f"FAIL: {rel} has only headings, no body content (#4507 R3-F8)")
    return errors


# R3-F9: live docs (docs/internal, docs/v1.0.0) must not cite a moved section as a CLAUDE.md section. The frozen
# per-release records (docs/v0.7.0 and older, CHANGELOG.md) quote history and are not scanned.
CITATION_DIRS = ("docs/internal", "docs/v1.0.0")
# R4 (#4507): also the possessive (`CLAUDE.md's "X"`), the word form (`CLAUDE.md section "X"`) and a heading
# anchor link (`CLAUDE.md#x-y`, matched against the GitHub slug of each moved heading below).
CLAUDE_CITATION = re.compile(
    r'CLAUDE\.md`?(?:\u2019s|\'s)?\s+(?:(?:section|heading|rule)\s+)?(?:\u00a7\s*)?[\u201c"]([^"\u201d]+)[\u201d"]',
    re.IGNORECASE)
CLAUDE_ANCHOR = re.compile(r'CLAUDE\.md#([a-z0-9_-]+)', re.IGNORECASE)


def github_slug(heading: str) -> str:
    """The GitHub anchor of a Markdown heading: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def stale_citation_errors(root: Path) -> list:
    """One message per cited `CLAUDE.md "<heading>"` whose heading now lives in a reference file."""
    moved = {sub.lstrip("#").strip() for subs in REFERENCE_SUBSECTIONS.values() for sub in subs}
    errors = []
    for directory in CITATION_DIRS:
        base = root / directory
        if not base.is_dir() or base.is_symlink():
            continue
        for path in sorted(base.rglob("*.md")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append(f"FAIL: cannot read {path.relative_to(root)}: {exc}")
                continue
            slugs = {github_slug(sub): sub for sub in moved}
            for match in CLAUDE_ANCHOR.finditer(text):
                if match.group(1).lower() in slugs:
                    line = text.count("\n", 0, match.start()) + 1
                    errors.append(
                        f"FAIL: {path.relative_to(root)}:{line} links CLAUDE.md#{match.group(1)}, which moved to a "
                        "docs/reference file; cite the reference file (#4507 R4)")
            for match in CLAUDE_CITATION.finditer(text):
                if match.group(1).strip() in moved:
                    line = text.count("\n", 0, match.start()) + 1
                    errors.append(
                        f"FAIL: {path.relative_to(root)}:{line} cites CLAUDE.md {match.group(1).strip()!r}, "
                        "which moved to a docs/reference file; cite the reference file (#4507 R3-F9)")
    return errors


# F1 (vote 4d3ea1c5, memory 0c41034e): the sha256 of every rule section is pinned in a SEPARATE tracked manifest,
# the design of scripts/check-declaration-hash.sh + scripts/qc-allowlists/declaration.sha256 (#3557). One line per
# section: `<sha256>  <heading>`. The hash covers the RAW section text (fenced code included, since a fenced
# block in a rule section is rule text), the lines between its heading and the next. Text before the first
# `## ` heading is pinned too, under PREAMBLE_KEY. A change needs `--update` AND a manifest line in the diff.
MANIFEST_PATH = "scripts/qc-allowlists/claude-md-rule-sections.sha256"
PREAMBLE_KEY = "(preamble before the first ## heading)"
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")
MANIFEST_HEADER = (
    "# #4507 F1 - sha256 of each CLAUDE.md rule section (raw text between a `## ` heading and the next).\n"
    "# Enforced by scripts/check-claude-md-size.py. Change it only with `scripts/check-claude-md-size.py --update`\n"
    "# in the same commit as the reviewed rule change. Format: <sha256>  <heading>\n"
)


def rule_section_hashes(text: str):
    """Return (ordered {key: sha256 hex}, [duplicate keys]) of the raw sections of CLAUDE.md text."""
    bodies = {PREAMBLE_KEY: []}
    duplicates = []
    current = PREAMBLE_KEY
    for line, in_code in fence_scan(text):
        if not in_code and line.startswith("## "):
            current = line.rstrip()
            if current in bodies:
                duplicates.append(current)
            else:
                bodies[current] = []
            continue
        bodies[current].append(line)
    hashes = {key: hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest() for key, lines in bodies.items()}
    return hashes, duplicates


def load_manifest(root: Path):
    """Return (errors, {key: sha256}) for the manifest; every failure is an error, never an empty pass."""
    walk = path_symlink_errors(root, MANIFEST_PATH)
    if walk:
        return walk, {}
    try:
        raw = read_utf8(root / MANIFEST_PATH)
    except (OSError, UnicodeDecodeError) as exc:
        return [f"FAIL: cannot read the rule-section manifest {MANIFEST_PATH}: {exc} (#4507 F1)"], {}
    errors = []
    pinned = {}
    for number, line in enumerate(raw.split("\n"), 1):
        if not line.strip() or line.startswith("# "):
            continue
        match = MANIFEST_LINE.match(line)
        if match is None:
            errors.append(f"FAIL: {MANIFEST_PATH}:{number} is not '<sha256>  <heading>' (#4507 F1)")
        elif match.group(2) in pinned:
            errors.append(f"FAIL: {MANIFEST_PATH}:{number} pins {match.group(2)!r} twice (#4507 F1)")
        else:
            pinned[match.group(2)] = match.group(1)
    if not pinned:
        errors.append(f"FAIL: {MANIFEST_PATH} pins no section (#4507 F1)")
    return errors, pinned


def manifest_errors(root: Path, text: str) -> list:
    """F1: every rule section hashes to its manifest line; no pinned section is missing, none is unpinned."""
    errors, pinned = load_manifest(root)
    if errors:
        return errors
    current, duplicates = rule_section_hashes(text)
    errors += [f"FAIL: CLAUDE.md has the heading {key!r} more than once (#4507 F1)" for key in duplicates]
    for key, digest in pinned.items():
        if key not in current:
            errors.append(f"FAIL: pinned rule section {key!r} is missing from CLAUDE.md (#4507 F1)")
        elif current[key] != digest:
            errors.append(
                f"FAIL: rule section {key!r} changed: sha256 {current[key][:16]} != pinned {digest[:16]}. "
                "A reviewed rule change must run `scripts/check-claude-md-size.py --update` and carry the "
                f"manifest line in the same commit (#4507 F1).")
    for key in current:
        if key not in pinned:
            errors.append(f"FAIL: rule section {key!r} is not pinned in {MANIFEST_PATH} (#4507 F1)")
    return errors


def update_manifest(root: Path) -> int:
    """--update: rewrite the manifest from CLAUDE.md and print which sections changed. 0 on success."""
    walk = path_symlink_errors(root, "CLAUDE.md")
    if walk:
        print("\n".join(walk), file=sys.stderr)
        return 1
    try:
        text = read_utf8(root / "CLAUDE.md")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"FAIL: cannot read CLAUDE.md as UTF-8: {exc}", file=sys.stderr)
        return 1
    target = root / MANIFEST_PATH
    try:
        mode = os.lstat(target).st_mode
    except FileNotFoundError:
        old = {}
    except OSError as exc:
        print(f"FAIL: cannot stat {MANIFEST_PATH}: {exc}", file=sys.stderr)
        return 1
    else:
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            print(f"FAIL: {MANIFEST_PATH} is a symlink or not a regular file; refusing to write (#4507 F1)",
                  file=sys.stderr)
            return 1
        load_errors, old = load_manifest(root)
        if load_errors:
            old = {}
    current, duplicates = rule_section_hashes(text)
    if duplicates:
        print(f"FAIL: CLAUDE.md repeats {duplicates[0]!r}; refusing to pin (#4507 F1)", file=sys.stderr)
        return 1
    if not target.parent.is_dir() or target.parent.is_symlink():
        print(f"FAIL: {target.parent} is not a real directory (#4507 F1)", file=sys.stderr)
        return 1
    body = MANIFEST_HEADER + "".join(f"{digest}  {key}\n" for key, digest in current.items())
    scratch = target.with_name(target.name + ".new")
    scratch.write_bytes(body.encode("utf-8"))
    os.replace(scratch, target)
    changed = [key for key in current if key in old and old[key] != current[key]]
    added = [key for key in current if key not in old]
    removed = [key for key in old if key not in current]
    for label, keys in (("changed", changed), ("added", added), ("removed", removed)):
        for key in keys:
            print(f"{label}: {key}")
    print(f"manifest written: {len(current)} sections, {len(changed)} changed, {len(added)} added, "
          f"{len(removed)} removed")
    return 0


def check(root: Path, index_pins=None) -> list:
    """Return a list of failure messages (empty means pass). `index_pins` is a self-test hook."""
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
            text = read_utf8(claude)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read CLAUDE.md as UTF-8: {exc}")
            text = ""
        errors += char_errors(text, "CLAUDE.md")
        errors += html_errors(text, "CLAUDE.md")
        errors += manifest_errors(root, text)
        visible = visible_lines(text)
        present = {line.rstrip() for line in visible if line.startswith("## ")}
        for heading in CLAUDE_MD_REQUIRED_HEADINGS:
            if heading not in present:
                errors.append(f"FAIL: CLAUDE.md is missing the required heading: {heading}")
    ref_dir_ok = True
    for rel in REFERENCE_PATHS:
        walk = path_symlink_errors(root, rel)
        if walk:
            errors += walk
            ref_dir_ok = False
    for rel, top_heading, min_bytes in REFERENCE_FILES:
        if not ref_dir_ok:
            break
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
            ref_text = read_utf8(path)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"FAIL: cannot read {rel} as UTF-8: {exc}")
            continue
        errors += char_errors(ref_text, rel)
        errors += html_errors(ref_text, rel)
        ref_lines[Path(rel).stem] = split_lines(ref_text)
        first = ref_lines[Path(rel).stem][0]
        if first != top_heading:
            errors.append(f"FAIL: {rel} must start with the heading {top_heading!r}, found {first!r}")
        present = {line.rstrip() for line in visible_lines(ref_text) if line.startswith(("## ", "### "))}
        for sub in REFERENCE_SUBSECTIONS[Path(rel).stem]:
            if sub not in present:
                errors.append(f"FAIL: {rel} is missing the pinned subsection heading {sub!r} (#4507)")
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
    check_index(visible, ref_lines, errors, index_pins)
    errors += stale_citation_errors(root)
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
    (root / MANIFEST_PATH).parent.mkdir(parents=True, exist_ok=True)
    update_manifest_quiet(root)
    minimums = {name: minimum for _heading, name, minimum in INDEX_SECTIONS}
    for rel, top_heading, min_bytes in REFERENCE_FILES:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        name = Path(rel).stem
        head = top_heading + "\n" + "".join(
            fixture_quote(name, n) + "\n" for n in range(1, minimums.get(name, 0) + 1))
        head += "".join(sub + "\n" for sub in REFERENCE_SUBSECTIONS[name])
        target.write_text(head + "x" * (min_bytes - len(head)), encoding="utf-8")


def update_manifest_quiet(root: Path) -> None:
    """Self-test helper: reseal the fixture manifest from the fixture CLAUDE.md without printing."""
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        update_manifest(root)


FIXTURE_PINS = [None]


def fixture_index_pins() -> list:
    """The pin list matching the fixture's index entries (see build_fixture)."""
    return sorted(
        (name, hashlib.sha256(fixture_quote(name, n).encode("utf-8")).hexdigest())
        for _heading, name, minimum in INDEX_SECTIONS for n in range(1, minimum + 1))


def expect(root: Path, label: str, want_fail: bool, needle: str = "", reseal: bool = True) -> bool:
    """Run check(); a case that wants a PASS reseals the manifest first, since it edits CLAUDE.md to test some
    other rule (the F1 cases call this with reseal=False, so the manifest is exercised unsealed)."""
    if not want_fail and reseal and (root / "CLAUDE.md").exists():
        update_manifest_quiet(root)
    errors = check(root, FIXTURE_PINS[0])
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
    FIXTURE_PINS[0] = fixture_index_pins()
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
    ok &= expect(root, "headings after a closed tilde fence and closed HTML comments", True, "raw HTML")

    root = fresh()
    heading = CLAUDE_MD_REQUIRED_HEADINGS[11]
    text = (root / claude_md).read_text(encoding="utf-8").replace(heading + "\n", heading + " <!-- note -->\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a heading followed by a trailing HTML comment (refused outright, R3-F5)", True, "raw HTML")
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

    root = fresh()
    path = root / arch
    path.write_text("# ai-memory Architecture Reference\n" + "junk body line\n" * 25000, encoding="utf-8")
    ok &= expect(root, "a reference file with the right top heading and junk padding to its floor", True,
                 "missing the pinned subsection heading")

    for name, rel in (("ARCHITECTURE_REFERENCE", arch), ("CODE_STYLE", style)):
        root = fresh()
        path = root / rel
        sub = REFERENCE_SUBSECTIONS[name][-1]
        path.write_text(path.read_text(encoding="utf-8").replace(sub + "\n", "x" * len(sub) + "\n", 1),
                        encoding="utf-8")
        ok &= expect(root, f"{name}.md with its last subsection heading removed", True,
                     "missing the pinned subsection heading")

    root = fresh()
    path = root / arch
    sub = REFERENCE_SUBSECTIONS["ARCHITECTURE_REFERENCE"][0]
    path.write_text(path.read_text(encoding="utf-8").replace(sub + "\n", "```\n" + sub + "\n```\n", 1),
                    encoding="utf-8")
    ok &= expect(root, "a pinned subsection heading that exists only inside a code fence", True,
                 "missing the pinned subsection heading")

    root = fresh()
    moved = root / "docs" / "reference-real"
    (root / REFERENCE_DIR).rename(moved)
    (root / REFERENCE_DIR).symlink_to(moved)
    ok &= expect(root, "a symlinked docs/reference directory", True, "every level of")

    root = fresh()
    shutil.rmtree(root / REFERENCE_DIR)
    ok &= expect(root, "a missing docs/reference directory", True, "cannot stat docs/reference")
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
    text = path.read_text(encoding="utf-8").replace("never be dropped", "never be droppe", 1)
    path.write_text(text, encoding="utf-8")
    ok &= expect(root, "an index quote whose reference text differs by one trailing letter", True, "not verbatim")

    root = fresh()
    path = root / style
    text = path.read_text(encoding="utf-8").replace(quote, quote.replace("fixture binding", "Fixture binding"), 1)
    path.write_text(text, encoding="utf-8")
    ok &= expect(root, "an index quote whose reference text differs only by case", True, "not verbatim")

    # Wrap the LAST CODE_STYLE entry so no later citation shifts by the extra line.
    last = INDEX_SECTIONS[1][2]
    quote_last = fixture_quote("CODE_STYLE", last)
    wrapped = quote_last.replace(f"rule {last} of", f"rule {last}\n    of", 1)
    root = fresh()
    path = root / style
    path.write_text(path.read_text(encoding="utf-8").replace(quote_last, wrapped, 1), encoding="utf-8")
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        f"CODE_STYLE.md:{last + 1}`", f"CODE_STYLE.md:{last + 1}-{last + 2}`", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a quote wrapped over two indented reference lines, cited as that range", False)

    root = fresh()
    path = root / style
    path.write_text(path.read_text(encoding="utf-8").replace(quote_last, wrapped, 1), encoding="utf-8")
    ok &= expect(root, "the same wrapped quote cited with only its first line", True, "not verbatim")

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

    # R3-F2: a quote must EQUAL the full cited span, and the set of quotes is pinned.
    quote_a = fixture_quote("CODE_STYLE", 2)
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        f'"{quote_a}"', f'"{quote_a[:-6]}"', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F2 an index quote truncated to a prefix of its cited line", True, "not verbatim")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        f'"{quote_a}"', '"' + quote_a.split(" ", 1)[1] + '"', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F2 an index quote with its leading word dropped", True, "not verbatim")

    root = fresh()
    altered = quote_a.replace("must never be dropped", "may be dropped")
    text = (root / claude_md).read_text(encoding="utf-8").replace(quote_a, altered, 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    path = root / style
    path.write_text(path.read_text(encoding="utf-8").replace(quote_a, altered, 1), encoding="utf-8")
    ok &= expect(root, "R3-F2 a quote and its reference line both reworded the same way", True,
                 "index quote set")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        f'`CODE_STYLE.md:3` "{quote_a}"', f'`CODE_STYLE.md:4` "{fixture_quote("CODE_STYLE", 3)}"', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F2 an entry re-pointed at a different complete line", True, "index quote set")

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8")
    extra = f'- `CODE_STYLE.md:3` "{quote_a}"\n'
    text = text.replace(f'- `CODE_STYLE.md:3` "{quote_a}"\n', f'- `CODE_STYLE.md:3` "{quote_a}"\n' + extra, 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F2 a duplicated index entry", True, "appears more than once")
    # code-R3-F3: the same file:range cited twice with a different (still verbatim) quote cannot slip through.
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8")
    extra = f'- `CODE_STYLE.md:3` "{fixture_quote("CODE_STYLE", 3)}" \n'
    text = text.replace(f'- `CODE_STYLE.md:3` "{quote_a}"\n', f'- `CODE_STYLE.md:3` "{quote_a}"\n' + extra, 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "code-R3-F3 the same file:range cited twice", True, "appears more than once")

    # R3-F5: CommonMark fences (at most 3 spaces of indent) and raw HTML blocks.
    heading = CLAUDE_MD_REQUIRED_HEADINGS[14]
    for label, closer in (("4 spaces", "    ```"), ("a no-break space", "\u00a0```"), ("a tab", "\t```")):
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8").replace(
            heading + "\n", "```\nhidden\n" + closer + "\n" + heading + "\n", 1)
        (root / claude_md).write_text(text, encoding="utf-8")
        ok &= expect(root, f"R3-F5 a fence 'closed' by a backtick line indented with {label}", True,
                     "missing the required heading")
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", "```\nfenced\n   ```\n" + heading + "\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F5 a fence legitimately closed by a 3-space-indented run", False)
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", "```\nhidden\n``` trailing\n" + heading + "\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F5 a fence 'closed' by a run followed by text", True, "missing the required heading")
    for label, lead in (("a tab", "\t"), ("a no-break space", "\u00a0")):
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8").replace(
            heading + "\n", lead + "```\n" + heading + "\n", 1)
        (root / claude_md).write_text(text, encoding="utf-8")
        ok &= expect(root, f"R3-F5 a fence opener indented with {label}", True, "fence")
    html_wraps = (
        ("pre block", "<pre>\n{h}\n</pre>\n"),
        ("div line above a heading", "<div>\n{h}\n"),
        ("details block", "<details>\n{h}\n</details>\n"),
        ("uppercase PRE", "<PRE>\n{h}\n</PRE>\n"),
        ("script block", "<script>\n{h}\n"),
        ("style block", "<style>\n{h}\n"),
        ("table block", "<table>\n{h}\n"),
        ("blockquote-nested div", "> <div>\n{h}\n"),
        ("list-nested div", "- <div>\n{h}\n"),
        ("closing tag only", "</div>\n{h}\n"),
        ("complete custom tag alone", "<span>\n{h}\n"),
        ("processing instruction", "<?php\n{h}\n"),
        ("declaration", "<!DOCTYPE html>\n{h}\n"),
        ("CDATA", "<![CDATA[\n{h}\n"),
        ("comment mid-line", "text <!-- x -->\n{h}\n"),
        ("comment opener only", "<!--\n{h}\n-->\n"),
        ("three-space-indented div", "   <div>\n{h}\n"),
    )
    html_wraps += (
        ("R3-code-F2(b) script wrap closed on its own line", "<script>\n{h}\n</script>\n"),
        ("R3-code-F2(c) comment glued to the heading", "<!-- x -->{h}\n"),
    )
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", "```\n    ```\n" + heading + "\n    ```\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-code-F2(a) a fence 'closed' only by a 4-space-indented decoy hides the section", True,
                 "missing the required heading")
    for label, wrap in html_wraps:
        root = fresh()
        text = (root / claude_md).read_text(encoding="utf-8").replace(
            heading + "\n", wrap.replace("{h}", heading), 1)
        (root / claude_md).write_text(text, encoding="utf-8")
        ok &= expect(root, f"R3-F5 raw HTML: {label}", True, "raw HTML")
    root = fresh()
    path = root / style
    path.write_text(path.read_text(encoding="utf-8") + "\n<div>\n", encoding="utf-8")
    ok &= expect(root, "R3-F5 raw HTML in a reference file", True, "raw HTML")
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", "```html\n<div>\n<!-- c -->\n```\n" + heading + "\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F5 HTML inside a closed code fence is plain text", False)
    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        heading + "\n", heading + "\nUse Vec<String> and <push-pattern> #<issue> here.\n", 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "R3-F5 inline angle brackets in prose are accepted", False)

    # R3-F6: bidi and invisible characters, bare CR.
    heading = CLAUDE_MD_REQUIRED_HEADINGS[12]
    invisible = (("U+202E bidi override", "\u202e"), ("U+202C pop directional", "\u202c"),
                 ("U+200B zero-width space", "\u200b"), ("U+200D zero-width joiner", "\u200d"),
                 ("U+200F right-to-left mark", "\u200f"), ("U+2060 word joiner", "\u2060"),
                 ("U+FEFF inside the text", "\ufeff"), ("U+2066 isolate", "\u2066"),
                 ("U+2069 pop isolate", "\u2069"), ("U+00AD soft hyphen", "\u00ad"),
                 ("U+E0041 tag character", "\U000e0041"), ("U+061C arabic letter mark", "\u061c"),
                 ("U+3164 hangul filler", "\u3164"), ("U+034F combining grapheme joiner", "\u034f"),
                 ("U+FE01 variation selector after a letter", "\ufe01"), ("U+FE0F after a letter", "\ufe0f"),
                 ("U+2028 line separator", "\u2028"), ("NUL", "\x00"), ("U+2800 braille blank", "\u2800"),
                 ("U+180E mongolian vowel separator", "\u180e"))
    for label, char in invisible:
        for where, target in (("CLAUDE.md", claude_md), ("CODE_STYLE.md", style), ("ARCHITECTURE_REFERENCE.md", arch)):
            if where != "CLAUDE.md" and char not in ("\u202e", "\ufeff", "\u200b"):
                continue
            root = fresh()
            path = root / target
            text = path.read_text(encoding="utf-8")
            anchor = heading if where == "CLAUDE.md" else REFERENCE_FILES[0 if where.startswith("ARCH") else 1][1]
            path.write_text(text.replace(anchor, anchor[:6] + char + anchor[6:], 1), encoding="utf-8")
            ok &= expect(root, f"R3-F6 {label} in {where}", True, "invisible")
    root = fresh()
    path = root / claude_md
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r", 1))
    ok &= expect(root, "R3-F6 a bare CR line break", True, "bare CR")
    root = fresh()
    path = root / claude_md
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    ok &= expect(root, "R3-F6 a leading byte-order mark", True, "invisible")
    root = fresh()
    path = root / claude_md
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    ok &= expect(root, "R3-F6 CRLF line endings are accepted", False)
    root = fresh()
    path = root / claude_md
    path.write_text(path.read_text(encoding="utf-8").replace(
        heading + "\n", heading + "\nA warning \u26a0\ufe0f sign.\n", 1), encoding="utf-8")
    ok &= expect(root, "R3-F6 an emoji presentation selector after a symbol is accepted", False)

    root = fresh()
    text = (root / claude_md).read_text(encoding="utf-8").replace(
        '- `CODE_STYLE.md:3` "', '- CODE_STYLE.md:3 "', 1)
    (root / claude_md).write_text(text, encoding="utf-8")
    ok &= expect(root, "a malformed index entry", True, "malformed binding-rules index entry")
    ok &= run_ref_cases(fresh, arch, style)
    ok &= run_citation_cases(fresh)
    ok &= run_manifest_cases(fresh)
    return ok


def run_citation_cases(fresh) -> bool:
    """R3-F9: a live doc citing a moved section as a CLAUDE.md section is refused."""
    ok = True
    heading = next(iter(REFERENCE_SUBSECTIONS["ARCHITECTURE_REFERENCE"])).lstrip("#").strip()
    for directory in CITATION_DIRS:
        for form in ('CLAUDE.md "{h}" 2', 'CLAUDE.md \u00a7"{h}"', 'CLAUDE.md` \u00a7\u201c{h}\u201d',
                     "CLAUDE.md's \"{h}\"", 'CLAUDE.md section "{h}"', "CLAUDE.md\u2019s heading \u201c{h}\u201d"):
            root = fresh()
            doc = root / directory / "nested" / "note.md"
            doc.parent.mkdir(parents=True)
            doc.write_text("See " + form.format(h=heading) + ".\n", encoding="utf-8")
            ok &= expect(root, f"R3-F9 stale citation in {directory} ({form[:14]})", True, "R3-F9")
        root = fresh()
        doc = root / directory / "anchor.md"
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(f"See [it](../../CLAUDE.md#{github_slug(heading)}).\n", encoding="utf-8")
        ok &= expect(root, f"R4 stale anchor link in {directory}", True, "R4")
    for label, form, want in (
            ("upper-case file name", 'See CLAUDE.MD section "{h}".', True),
            ("the word rule", 'See CLAUDE.md rule "{h}".', True),
            ("upper-case anchor", "See CLAUDE.md#" + github_slug(heading).upper() + ".", True),
            ("anchor of a heading that did not move", "See [rule](CLAUDE.md#hard-rule).", False),
            ("anchor that names no heading", "See CLAUDE.md#no-such-heading.", False),
            ("possessive of a section that stayed", 'See CLAUDE.md\'s "Hard rule".', False),
            ("section word with a section that stayed", 'See CLAUDE.md section "Build & Test Commands".', False)):
        root = fresh()
        doc = root / "docs" / "internal" / "form.md"
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(form.format(h=heading) + "\n", encoding="utf-8")
        ok &= expect(root, f"R5 citation form: {label}", want, "R4" if "anchor" in label else "R3-F9")
    root = fresh()
    doc = root / "docs" / "internal" / "note.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(f'See docs/reference/ARCHITECTURE_REFERENCE.md "{heading}"; CLAUDE.md "Hard rule".\n',
                   encoding="utf-8")
    ok &= expect(root, "R3-F9 a citation of the reference file is accepted", False)
    root = fresh()
    doc = root / "docs" / "v0.7.0" / "note.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(f'CLAUDE.md "{heading}" (frozen record)\n', encoding="utf-8")
    ok &= expect(root, "R3-F9 a frozen release record is not scanned", False)
    return ok


def run_manifest_cases(fresh) -> bool:
    """F1: the rule-section manifest. Every case runs check() UNSEALED (reseal=False) except where noted."""
    def raw(root: Path, label: str, want_fail: bool, needle: str = "") -> bool:
        return expect(root, label, want_fail, needle, reseal=False)

    def edit(root: Path, old: str, new: str, count: int = 1) -> None:
        path = root / "CLAUDE.md"
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"self-test fixture lacks {old!r}")
        path.write_text(text.replace(old, new, count), encoding="utf-8")

    heading = CLAUDE_MD_REQUIRED_HEADINGS[2]
    ok = raw(fresh(), "F1 a sealed tree", False)
    root = fresh()
    edit(root, "section body x", "section body y")
    ok &= raw(root, "F1 a same-size filler swap in a rule section", True, "changed")
    root = fresh()
    edit(root, "section body ", "section body must not ")
    ok &= raw(root, "F1 a reworded rule section", True, "changed")
    root = fresh()
    edit(root, f"{heading}\n", f"{heading}\nA new rule sentence.\n")
    ok &= raw(root, "F1 a rule sentence added", True, "changed")
    root = fresh()
    edit(root, f"{heading}\n", f"{heading}\n```\nfenced rule text\n```\n")
    ok &= raw(root, "F1 fenced text added to a rule section (the raw hash covers fences)", True, "changed")
    root = fresh()
    edit(root, "## ", "A preamble rule.\n\n## ")
    ok &= raw(root, "F1 text added before the first heading", True, "preamble")
    root = fresh()
    edit(root, "section body x", "<!-- section body x -->")
    ok &= raw(root, "F1 a rule moved into an HTML comment", True, "changed")
    root = fresh()
    edit(root, f"{heading}\n", "")
    ok &= raw(root, "F1 a section heading deleted", True, "is missing from CLAUDE.md")
    root = fresh()
    path = root / "CLAUDE.md"
    text = path.read_text(encoding="utf-8")
    start = text.index(heading)
    end = text.index("\n## ", start) + 1
    path.write_text(text[:start] + text[end:], encoding="utf-8")
    ok &= raw(root, "F1 a whole rule section deleted", True, "is missing from CLAUDE.md")
    root = fresh()
    path = root / "CLAUDE.md"
    path.write_text(path.read_text(encoding="utf-8") + "\n## An unpinned rule section\nNever do X.\n",
                    encoding="utf-8")
    ok &= raw(root, "F1 a rule section added", True, "is not pinned")
    root = fresh()
    edit(root, f"{heading}\n", f"{heading}\n\n{heading}\n")
    ok &= raw(root, "F1 a duplicated heading", True, "more than once")
    manifest = MANIFEST_PATH
    root = fresh()
    path = root / manifest
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text("".join(line for line in lines if heading not in line), encoding="utf-8")
    ok &= raw(root, "F1 a manifest line removed", True, "is not pinned")
    root = fresh()
    path = root / manifest
    text = path.read_text(encoding="utf-8")
    first = next(line for line in text.splitlines() if MANIFEST_LINE.match(line))
    path.write_text(text.replace(first, "0" * 64 + first[64:], 1), encoding="utf-8")
    ok &= raw(root, "F1 a manifest hash altered", True, "changed")
    root = fresh()
    path = root / manifest
    path.write_text(path.read_text(encoding="utf-8") + first + "\n", encoding="utf-8")
    ok &= raw(root, "F1 a manifest line duplicated", True, "twice")
    root = fresh()
    (root / manifest).write_text(MANIFEST_HEADER + "not a pin line\n", encoding="utf-8")
    ok &= raw(root, "F1 a malformed manifest line", True, "is not '<sha256>")
    root = fresh()
    (root / manifest).write_text(MANIFEST_HEADER, encoding="utf-8")
    ok &= raw(root, "F1 an empty manifest", True, "pins no section")
    root = fresh()
    (root / manifest).write_bytes(b"\xff\xfe\n")
    ok &= raw(root, "F1 a manifest that is not UTF-8", True, "cannot read")
    root = fresh()
    (root / manifest).unlink()
    ok &= raw(root, "F1 a missing manifest", True, "cannot stat")
    root = fresh()
    path = root / manifest
    moved = root / "manifest.aside"
    path.rename(moved)
    path.symlink_to(moved)
    ok &= raw(root, "F1 a symlinked manifest", True, "is a symlink")
    root = fresh()
    moved = root / "qc.aside"
    (root / "scripts" / "qc-allowlists").rename(moved)
    (root / "scripts" / "qc-allowlists").symlink_to(moved, target_is_directory=True)
    ok &= raw(root, "F1 a symlinked manifest directory", True, "is a symlink")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        root = fresh()
        os.chmod(root / manifest, 0)
        try:
            ok &= raw(root, "F1 an unreadable manifest", True, "cannot read")
        finally:
            os.chmod(root / manifest, 0o644)
    # --update: rewrites the manifest, reports the changed section, refuses a symlinked manifest.
    root = fresh()
    edit(root, "section body x", "section body y")
    import contextlib
    import io
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = update_manifest(root)
    if code != 0 or "1 changed" not in buffer.getvalue() or "changed: ## " not in buffer.getvalue():
        print(f"FAIL: self-test - F1 --update did not report one changed section: {buffer.getvalue()!r}",
              file=sys.stderr)
        ok = False
    ok &= raw(root, "F1 the tree after --update", False)
    root = fresh()
    path = root / manifest
    moved = root / "manifest.aside"
    path.rename(moved)
    path.symlink_to(moved)
    with contextlib.redirect_stderr(io.StringIO()):
        code = update_manifest(root)
    if code == 0:
        print("FAIL: self-test - F1 --update wrote through a symlinked manifest", file=sys.stderr)
        ok = False
    return ok


def refs_expect(root: Path, label: str, want_fail: bool, needle: str = "") -> bool:
    """Like expect(), for the shared reference checks the doc gates call (--refs-only)."""
    errors = refs_errors(root)
    if want_fail and not any(needle in line for line in errors):
        print(f"FAIL: self-test - {label} was NOT rejected by refs_errors (wanted {needle!r})", file=sys.stderr)
        return False
    if not want_fail and errors:
        print(f"FAIL: self-test - {label} was rejected by refs_errors: {errors[0]}", file=sys.stderr)
        return False
    return True


def run_ref_cases(fresh, arch: str, style: str) -> bool:
    """R3-F7 and R3-F8: a symlink at any level of a reference path; empty, heading-only, unreadable files."""
    ok = refs_expect(fresh(), "R3-F7 a valid reference pair", False)
    # F7: docs -> elsewhere (the link sits above docs/reference), through both the full check and refs_errors.
    root = fresh()
    moved = root / "elsewhere"
    (root / "docs").rename(moved)
    (root / "docs").symlink_to(moved, target_is_directory=True)
    ok &= expect(root, "R3-F7 docs is a symlink", True, "is a symlink")
    ok &= refs_expect(root, "R3-F7 docs is a symlink", True, "is a symlink")
    root = fresh()
    moved = root / "elsewhere"
    (root / "docs" / "reference").rename(moved)
    (root / "docs" / "reference").symlink_to(moved, target_is_directory=True)
    ok &= expect(root, "R3-F7 docs/reference is a symlink", True, "is a symlink")
    ok &= refs_expect(root, "R3-F7 docs/reference is a symlink", True, "is a symlink")
    for rel in (arch, style):
        root = fresh()
        target = root / rel
        moved = root / "leaf.md"
        target.rename(moved)
        target.symlink_to(moved)
        ok &= expect(root, f"R3-F7 {Path(rel).name} is a symlink", True, "is a symlink")
        ok &= refs_expect(root, f"R3-F7 {Path(rel).name} is a symlink", True, "is a symlink")
    # A dangling link at an intermediate level fails closed too.
    root = fresh()
    (root / "docs" / "reference").rename(root / "elsewhere")
    (root / "docs" / "reference").symlink_to(root / "nowhere", target_is_directory=True)
    ok &= refs_expect(root, "R3-F7 a dangling docs/reference link", True, "is a symlink")
    # F8: empty, heading-only, whitespace-only, invalid UTF-8, unreadable.
    for rel in (arch, style):
        name = Path(rel).name
        top = next(entry[1] for entry in REFERENCE_FILES if entry[0] == rel)
        for label, payload in (("empty", b""), ("whitespace-only", b"  \n\n"),
                               ("heading-only", (top + "\n\n## Sub\n").encode("utf-8")),
                               ("invalid UTF-8", b"# T\n\xff\xfe body\n")):
            root = fresh()
            (root / rel).write_bytes(payload)
            want = "cannot read" if label == "invalid UTF-8" else ("empty" if "empty" in label or "white" in label
                                                                    else "only headings")
            ok &= refs_expect(root, f"R3-F8 {name} {label}", True, want)
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            root = fresh()
            os.chmod(root / rel, 0)
            try:
                ok &= refs_expect(root, f"R3-F8 {name} unreadable (mode 000)", True, "cannot read")
            finally:
                os.chmod(root / rel, 0o644)
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
    # sha256 of the sorted "<file> <quote sha256>" index pin lines: any pinned quote change is a deliberate edit.
    "INDEX_ENTRIES_SHA256": "de11dd7af07f6e340e2c7d7a75b451f4e41c67cd66548d59165cf7c81c19b6f7",
    "INDEX_QUOTE_PINS_SHA256": "9d4c301ad7f479615115f9605e0ea6d1d86d0ea04b653c08bedb4ed72986eaeb",
    "REFERENCE_SUBSECTIONS ARCHITECTURE_REFERENCE": 9,
    "REFERENCE_SUBSECTIONS CODE_STYLE": 1,
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
        "INDEX_ENTRIES_SHA256": INDEX_ENTRIES_SHA256,
        "INDEX_QUOTE_PINS_SHA256": hashlib.sha256(
            "\n".join(f"{name} {digest}" for name, digest in INDEX_QUOTE_PINS).encode("utf-8")).hexdigest(),
    }
    for rel, _top, floor in REFERENCE_FILES:
        limits[f"REFERENCE_FLOOR {Path(rel).stem}"] = floor
    for _heading, name, minimum in INDEX_SECTIONS:
        limits[f"INDEX_MIN_ENTRIES {name}"] = minimum
    for name, subs in REFERENCE_SUBSECTIONS.items():
        limits[f"REFERENCE_SUBSECTIONS {name}"] = len(subs)
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


WORKFLOW_PATH = ".github/workflows/claude-md-guard.yml"


WORKFLOW_BASE_BRANCHES = ("main", "develop", "release/**", "rehearsal/**")
WORKFLOW_FORBIDDEN_KEYS = ("pull_request_target", "continue-on-error", "paths", "paths-ignore",
                           "branches-ignore", "tags", "tags-ignore", "if", "shell", "working-directory",
                           "defaults", "env", "container", "services", "strategy", "needs")
WORKFLOW_RUN_LINES = ("run: python3 scripts/check-claude-md-size.py",
                      "run: python3 scripts/check-claude-md-size.py --self-test")
WORKFLOW_PR_TYPES = ("opened", "synchronize", "reopened")
# R4 (#4507): the checkout action every CLAUDE.md workflow uses, pinned to ONE sha (the repo-wide pin), so a
# fork-network impostor commit of the same action cannot pass as "a 40-hex sha".
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
# R4 (#4507): the guard workflow is pinned to its canonical form WITH indentation (comments and blank lines
# dropped). The heuristic checks below name the class of a change; this pin refuses every change they miss
# (a pinned ref or repository on checkout, a third-party action, a label, a block-scalar run line).
WORKFLOW_CANONICAL_LINES = (
    'name: CLAUDE.md guard',
    'on:',
    '  push:',
    '    branches: [main, develop, "release/**", "rehearsal/**"]',
    '  pull_request:',
    '    branches: [main, develop, "release/**", "rehearsal/**"]',
    '  merge_group:',
    '    types: [checks_requested]',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: claude-md-guard-${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}',
    '  cancel-in-progress: true',
    'jobs:',
    '  guard:',
    '    name: CLAUDE.md rule-section guard',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 5',
    '    steps:',
    '      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
    '      - name: Guard the tracked CLAUDE.md and its reference files',
    '        run: python3 scripts/check-claude-md-size.py',
    '      - name: Guard self-test',
    '        run: python3 scripts/check-claude-md-size.py --self-test',
)


def workflow_blocks(lines: list) -> dict:
    """Map each indent-2 key under the top-level `on:` to the (indent, text) lines beneath it."""
    blocks = {}
    in_on = False
    current = None
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if indent == 0:
            in_on = text.rstrip(":") == "on" and text.endswith(":")
            current = None
        elif in_on and indent == 2 and text.endswith(":"):
            current = text[:-1]
            blocks[current] = []
        elif in_on and current is not None and indent > 2:
            blocks[current].append((indent, text))
    return blocks


def workflow_errors(path: Path, label: str = WORKFLOW_PATH) -> list:
    """R3-F4: the guard's own workflow must run on every base branch with least privilege and pinned actions.

    Text-level (the script is stdlib only): comments are dropped, then the trigger blocks, the permissions
    block, every `uses:` pin and the two run lines are checked. Narrowing a trigger, adding a path filter,
    widening permissions, unpinning an action, skipping a step or swallowing a failure all fail.
    """
    errors = []
    if regular_size(path, label, errors) is None:
        return errors
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"FAIL: cannot read {label} as UTF-8: {exc}"]
    lines = []
    for raw in split_lines(text):
        stripped = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if stripped.strip():
            lines.append(stripped)
    blocks = workflow_blocks(lines)
    for trigger in ("pull_request", "push"):
        body = blocks.get(trigger)
        if body is None:
            errors.append(f"FAIL: {label} has no `{trigger}` trigger; the guard must run on every base branch (#4507 R3-F4)")
            continue
        branches = [t for _i, t in body if t.startswith("branches:")]
        listed = set()
        if len(branches) == 1:
            listed = {item.strip().strip("\"'") for item in branches[0].split("[", 1)[-1].rstrip("]").split(",")}
        missing = [b for b in WORKFLOW_BASE_BRANCHES if b not in listed]
        if len(branches) != 1 or missing:
            errors.append(
                f"FAIL: {label} `{trigger}` branches must list {', '.join(WORKFLOW_BASE_BRANCHES)}; "
                f"missing {missing or 'a single branches: list'} (#4507 R3-F4)")
    types = [t for _i, t in blocks.get("pull_request", []) if t.startswith("types:")]
    if types and not all(kind in types[0] for kind in WORKFLOW_PR_TYPES):
        errors.append(f"FAIL: {label} pull_request types must include {', '.join(WORKFLOW_PR_TYPES)} (#4507 R3-F4)")
    for key in WORKFLOW_FORBIDDEN_KEYS:
        if any(re.match(rf"^\s*(- )?{re.escape(key)}:", line) for line in lines):
            errors.append(f"FAIL: {label} uses `{key}:`, which can skip or weaken the guard (#4507 R3-F4)")
    perm = [i for i, line in enumerate(lines) if re.match(r"^\s*permissions:", line)]
    ok_perm = (len(perm) == 1 and lines[perm[0]] == "permissions:" and perm[0] + 1 < len(lines)
               and lines[perm[0] + 1] == "  contents: read"
               and (perm[0] + 2 >= len(lines) or not lines[perm[0] + 2].startswith("  ")))
    if not ok_perm:
        errors.append(f"FAIL: {label} permissions must be exactly one top-level `contents: read` (#4507 R3-F4)")
    for line in lines:
        if "uses:" in line and not re.search(r"uses:\s*\S+@[0-9a-f]{40}$", line):
            errors.append(f"FAIL: {label} action is not pinned to a 40-hex commit sha: {line.strip()[:100]} (#4507 R3-F4)")
        if re.match(r"^\s*(- )?run:", line) and re.search(r"\|\||;|&", line):
            errors.append(f"FAIL: {label} run line could swallow a failure (|| ; &): {line.strip()[:100]} (#4507 R3-F4)")
    jobs_at = [i for i, line in enumerate(lines) if line == "jobs:"]
    job_names = [line for line in lines[jobs_at[0] + 1:] if re.match(r"^  \S", line)] if jobs_at else []
    step_count = len([line for line in lines if re.match(r"^      - ", line)])
    if len(job_names) != 1 or step_count != len(WORKFLOW_RUN_LINES) + 1:
        errors.append(
            f"FAIL: {label} must have exactly one job with exactly the checkout and the two guard steps; "
            f"found {len(job_names)} job(s) and {step_count} step(s) (#4507 R3-F4)")
    stripped_lines = [line.strip().removeprefix("- ") for line in lines]
    for required in WORKFLOW_RUN_LINES:
        if required not in stripped_lines:
            errors.append(f"FAIL: {label} is missing the step `{required}` (check-claude-md-size.py) (#4507 R3-F4)")
    if lines != list(WORKFLOW_CANONICAL_LINES):
        first = next((n for n, (got, want) in enumerate(zip(lines, WORKFLOW_CANONICAL_LINES), 1) if got != want),
                     min(len(lines), len(WORKFLOW_CANONICAL_LINES)) + 1)
        errors.append(f"FAIL: {label} differs from the pinned form (WORKFLOW_CANONICAL_LINES) at meaningful line "
                      f"{first}; indentation counts (#4507 R4)")
    return errors


COMPARE_WORKFLOW_PATH = ".github/workflows/claude-md-rule-compare.yml"
COMPARE_CHECKOUT = "uses: actions/checkout@"
# R3-F3: the pull_request_target workflow runs with the BASE checkout and treats the head as data. It is
# pinned to this canonical form (comments and blank lines dropped), so a changed trigger, a wider permission,
# a head checkout, an extra step or a `run:` that is not the comparison script fails the guard.
COMPARE_WORKFLOW_LINES = (
    "name: CLAUDE.md rule-change comparison",
    "on:",
    "pull_request_target:",
    'branches: [main, develop, "release/**", "rehearsal/**"]',
    "types: [opened, synchronize, reopened, edited]",
    "permissions:",
    "contents: read",
    "concurrency:",
    "group: claude-md-rule-compare-${{ github.event.pull_request.number }}",
    "cancel-in-progress: true",
    "jobs:",
    "compare:",
    "name: CLAUDE.md rule-change comparison",
    "runs-on: ubuntu-latest",
    "timeout-minutes: 10",
    "steps:",
    "- name: Check out the BASE commit only",
    COMPARE_CHECKOUT,
    "with:",
    "ref: ${{ github.event.pull_request.base.sha }}",
    "fetch-depth: 0",
    "persist-credentials: false",
    "- name: Fetch the pull request head as git objects (data, never checked out)",
    "env:",
    "PR_NUMBER: ${{ github.event.pull_request.number }}",
    'run: git fetch --no-tags origin "+refs/pull/${PR_NUMBER}/head:refs/remotes/pull/head"',
    "- name: Comparison self-test (base code)",
    "run: python3 scripts/claude-md-rule-compare.py --self-test",
    "- name: Compare the head rule sections with the base manifest",
    "env:",
    "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
    "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    'run: python3 scripts/claude-md-rule-compare.py --base-root . --repo . --base-sha "$BASE_SHA" '
    '--head-sha "$HEAD_SHA" --scratch "$RUNNER_TEMP/rule-compare" --summary "$GITHUB_STEP_SUMMARY"',
)
# R4 (#4507): the indentation of each meaningful line, so a key moved out of its block (for example
# `persist-credentials` lifted out of `with:`) is refused although its stripped text is unchanged.
COMPARE_WORKFLOW_INDENTS = (0, 0, 2, 4, 4, 0, 2, 0, 2, 2, 0, 2, 4, 4, 4, 4, 6, 8, 8, 10, 10, 10, 6, 8, 10, 8, 6, 8, 6, 8, 10, 10, 8)
COMPARE_DANGER = (
    ("if:", "a condition can skip the comparison"),
    ("paths:", "a paths filter can skip the comparison"),
    ("paths-ignore:", "a paths filter can skip the comparison"),
    ("continue-on-error:", "it can swallow a failure"),
    ("shell:", "it can swallow a failure"),
    ("head.ref", "the head branch name must never reach the job"),
    ("head.repo", "the head repository must never be checked out"),
    ("head_ref", "the head branch name must never reach the job"),
    ("/merge", "the merge ref contains head content"),
    ("secrets.", "no secret may be exposed to a pull_request_target job"),
)


def compare_workflow_errors(path: Path, label: str = COMPARE_WORKFLOW_PATH) -> list:
    """R3-F3: the pull_request_target comparison workflow must equal its pinned canonical form."""
    errors = []
    if regular_size(path, label, errors) is None:
        return errors
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"FAIL: cannot read {label} as UTF-8: {exc}"]
    lines = []
    indents = []
    for raw in split_lines(text):
        stripped = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if stripped.strip():
            lines.append(stripped.strip())
            indents.append(len(stripped) - len(stripped.lstrip(" ")))
    if tuple(indents) != COMPARE_WORKFLOW_INDENTS:
        errors.append(f"FAIL: {label} indentation differs from the pinned form (COMPARE_WORKFLOW_INDENTS) (#4507 R4)")
    for token, why in COMPARE_DANGER:
        if any(token in line for line in lines):
            errors.append(f"FAIL: {label} contains `{token}`: {why} (#4507 R3-F3)")
    for line in lines:
        if line.startswith(("- uses:", "uses:")) and not re.search(r"uses:\s*\S+@[0-9a-f]{40}$", line):
            errors.append(f"FAIL: {label} action is not pinned to a 40-hex commit sha: {line[:100]} (#4507 R3-F3)")
    expected = list(COMPARE_WORKFLOW_LINES)
    if len(lines) != len(expected):
        errors.append(f"FAIL: {label} has {len(lines)} meaningful lines, the pinned form has {len(expected)} (#4507 R3-F3)")
    for number, (got, want) in enumerate(zip(lines, expected), 1):
        if want == COMPARE_CHECKOUT:
            if got != f"uses: actions/checkout@{CHECKOUT_SHA}":
                errors.append(f"FAIL: {label} meaningful line {number} must be the pinned checkout action, got {got[:100]} (#4507 R3-F3)")
        elif got != want:
            errors.append(f"FAIL: {label} meaningful line {number} differs from the pinned form: {got[:100]} (#4507 R3-F3)")
            break
    return errors


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


def run_workflow_cases(repo_root: Path, base: Path) -> bool:
    """The guard's own workflow must exist and keep its triggers, permissions and pins (R3-F4)."""
    ok = True
    real = repo_root / WORKFLOW_PATH
    if workflow_errors(real):
        print(f"FAIL: self-test - the repository workflow was rejected: {workflow_errors(real)[0]}", file=sys.stderr)
        ok = False
    try:
        good = real.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"FAIL: self-test - cannot read {WORKFLOW_PATH}: {exc}", file=sys.stderr)
        return False
    wf = base / "wf"
    wf.mkdir()

    def case(label: str, text: str, needle: str) -> bool:
        target = wf / "w.yml"
        target.write_text(text, encoding="utf-8")
        if not any(needle in line for line in workflow_errors(target, label)):
            print(f"FAIL: self-test - workflow case {label!r} was NOT rejected (wanted {needle!r})", file=sys.stderr)
            return False
        return True

    ok &= case("R3-F4 rehearsal/** removed from pull_request", good.replace(
        '  pull_request:\n    branches: [main, develop, "release/**", "rehearsal/**"]',
        '  pull_request:\n    branches: [main, develop, "release/**"]', 1), "pull_request")
    ok &= case("R3-F4 rehearsal/** removed from push", good.replace(
        '  push:\n    branches: [main, develop, "release/**", "rehearsal/**"]',
        '  push:\n    branches: [main, develop, "release/**"]', 1), "push")
    ok &= case("R3-F4 pull_request branches filter removed", good.replace(
        '  pull_request:\n    branches: [main, develop, "release/**", "rehearsal/**"]',
        '  pull_request:', 1), "pull_request")
    ok &= case("R3-F4 paths filter added", good.replace(
        '  pull_request:\n', '  pull_request:\n    paths: ["src/**"]\n', 1), "paths")
    ok &= case("R3-F4 write permission", good.replace("  contents: read", "  contents: write", 1), "permissions")
    ok &= case("R3-F4 extra permission", good.replace(
        "  contents: read", "  contents: read\n  pull-requests: write", 1), "permissions")
    ok &= case("R3-F4 unpinned action", good.replace(
        "@11d5960a326750d5838078e36cf38b85af677262", "@v4", 1), "pinned")
    ok &= case("R3-F4 guard step removed", good.replace(
        "python3 scripts/check-claude-md-size.py\n", "true\n", 1), "check-claude-md-size.py")
    ok &= case("R3-F4 self-test step removed", good.replace(" --self-test", "", 1), "--self-test")
    ok &= case("R3-F4 continue-on-error", good.replace(
        "    timeout-minutes: 5", "    timeout-minutes: 5\n    continue-on-error: true", 1), "continue-on-error")
    ok &= case("R3-F4 pull_request_target", good.replace(
        "  merge_group:", "  pull_request_target:\n    branches: [main]\n  merge_group:", 1), "pull_request_target")
    ok &= case("R3-F4 failure swallowed with || true", good.replace(
        "run: python3 scripts/check-claude-md-size.py\n", "run: python3 scripts/check-claude-md-size.py || true\n", 1),
        "swallow")
    ok &= case("R3-F4 extra step added", good.replace(
        "      - name: Guard self-test", "      - run: git checkout -- CLAUDE.md\n      - name: Guard self-test", 1), "exactly one job")
    ok &= case("R3-F4 second job added", good + "  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n",
               "exactly one job")
    ok &= case("R3-F4 shell override", good.replace(
        "        run: python3 scripts/check-claude-md-size.py\n",
        "        shell: bash -c true {0}\n        run: python3 scripts/check-claude-md-size.py\n", 1), "shell")
    ok &= case("R3-F4 step condition", good.replace(
        "        run: python3 scripts/check-claude-md-size.py\n",
        "        if: false\n        run: python3 scripts/check-claude-md-size.py\n", 1), "if")
    ok &= case("R3-F4 env override", good.replace(
        "    timeout-minutes: 5", "    timeout-minutes: 5\n    env:\n      PYTHONPATH: /x", 1), "env")
    ok &= case("R4 checkout pinned to a fixed ref", good.replace(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n        with:\n          ref: 0000000000000000000000000000000000000000\n", 1),
        "pinned form")
    ok &= case("R4 run line swallowed in a block scalar", good.replace(
        "        run: python3 scripts/check-claude-md-size.py\n",
        "        run: |\n          python3 scripts/check-claude-md-size.py ||\n          true\n", 1), "pinned form")
    ok &= case("R4 runner label changed", good.replace("runs-on: ubuntu-latest", "runs-on: no-such-runner", 1),
               "pinned form")
    uses = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
    ok &= case("R5 checkout repository set", good.replace(
        uses, uses + "        with:\n          repository: someone/else\n", 1), "pinned form")
    ok &= case("R5 third-party checkout action pinned by sha", good.replace(
        "actions/checkout@", "someone-else/checkout@", 1), "pinned form")
    ok &= case("R5 guard run line moved into a step name", good.replace(
        "      - name: Guard the tracked CLAUDE.md and its reference files\n        run: python3 scripts/check-claude-md-size.py\n",
        "      - name: run: python3 scripts/check-claude-md-size.py\n        run: true\n", 1), "pinned form")
    ok &= case("R5 step indentation shifted", good.replace(
        "        run: python3 scripts/check-claude-md-size.py --self-test\n",
        "          run: python3 scripts/check-claude-md-size.py --self-test\n", 1), "pinned form")
    ok &= case("R5 timeout raised", good.replace("timeout-minutes: 5", "timeout-minutes: 500", 1), "pinned form")
    ok &= case("R5 concurrency cancel switched off", good.replace(
        "cancel-in-progress: true", "cancel-in-progress: false", 1), "pinned form")
    commented = good.replace("jobs:\n", "jobs:\n\n  # a comment and a blank line change nothing\n", 1)
    (wf / "w.yml").write_text(commented, encoding="utf-8")
    if workflow_errors(wf / "w.yml", "R5 comment-only edit"):
        print("FAIL: self-test - a comment-only edit of the guard workflow was refused", file=sys.stderr)
        ok = False
    ok &= case("R3-F4 pull_request types closed only", good.replace(
        '  pull_request:\n', '  pull_request:\n    types: [closed]\n', 1), "types")
    missing = wf / "absent.yml"
    if not any("cannot stat" in line for line in workflow_errors(missing, "absent")):
        print("FAIL: self-test - a missing workflow file was NOT rejected", file=sys.stderr)
        ok = False
    ok &= run_compare_workflow_cases(repo_root, base)
    return ok


def run_compare_workflow_cases(repo_root: Path, base: Path) -> bool:
    """R3-F3: the pull_request_target comparison workflow is pinned; each unsafe edit is refused."""
    ok = True
    real = repo_root / COMPARE_WORKFLOW_PATH
    if compare_workflow_errors(real):
        print(f"FAIL: self-test - the comparison workflow was rejected: {compare_workflow_errors(real)[0]}",
              file=sys.stderr)
        return False
    good = real.read_text(encoding="utf-8")
    wf = base / "cwf"
    wf.mkdir()

    def case(label: str, text: str, needle: str) -> bool:
        target = wf / "w.yml"
        target.write_text(text, encoding="utf-8")
        if not any(needle in line for line in compare_workflow_errors(target, label)):
            print(f"FAIL: self-test - compare workflow case {label!r} was NOT rejected (wanted {needle!r})",
                  file=sys.stderr)
            return False
        return True

    checkout = "        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n"
    ok &= case("R3-F3 head checked out", good.replace(
        "ref: ${{ github.event.pull_request.base.sha }}\n          fetch", "ref: ${{ github.event.pull_request.head.sha }}\n          fetch", 1),
        "differs from the pinned form")
    ok &= case("R3-F3 head repo checked out", good.replace(
        checkout, checkout + "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", 1), "head.repo")
    ok &= case("R3-F3 merge ref", good.replace("refs/pull/${PR_NUMBER}/head", "refs/pull/${PR_NUMBER}/merge", 1), "/merge")
    ok &= case("R3-F3 write permission", good.replace("  contents: read", "  contents: write", 1), "differs from the pinned form")
    ok &= case("R3-F3 extra permission", good.replace("  contents: read", "  contents: read\n  pull-requests: write", 1),
               "meaningful lines")
    ok &= case("R3-F3 job-level if", good.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    if: false", 1), "`if:`")
    ok &= case("R3-F3 paths filter", good.replace("    branches:", "    paths: [\"src/**\"]\n    branches:", 1), "`paths:`")
    ok &= case("R3-F3 branch removed", good.replace(', "rehearsal/**"]', "]", 1), "differs from the pinned form")
    ok &= case("R3-F3 unpinned action", good.replace("@11d5960a326750d5838078e36cf38b85af677262", "@v4", 1), "pinned")
    ok &= case("R3-F3 step removed", good.replace(
        "      - name: Comparison self-test (base code)\n        run: python3 scripts/claude-md-rule-compare.py --self-test\n", "", 1),
        "meaningful lines")
    ok &= case("R3-F3 extra step", good + "      - run: python3 CLAUDE.md\n", "meaningful lines")
    ok &= case("R3-F3 swallowed failure", good.replace(
        "--self-test\n", "--self-test\n        continue-on-error: true\n", 1), "continue-on-error")
    ok &= case("R3-F3 secret exposed", good.replace(
        "          PR_NUMBER:", "          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          PR_NUMBER:", 1), "secrets.")
    ok &= case("R5 edited type removed (a PR edit would not re-run the comparison)", good.replace(
        "types: [opened, synchronize, reopened, edited]", "types: [opened, synchronize, reopened]", 1),
        "differs from the pinned form")
    ok &= case("R5 types narrowed to synchronize only", good.replace(
        "types: [opened, synchronize, reopened, edited]", "types: [synchronize]", 1), "differs from the pinned form")
    ok &= case("R5 types line removed (default types skip edited)", good.replace(
        "    types: [opened, synchronize, reopened, edited]\n", "", 1), "meaningful lines")
    ok &= case("R4 checkout impostor sha", good.replace(
        "@11d5960a326750d5838078e36cf38b85af677262", "@" + "1" * 40, 1), "pinned checkout action")
    ok &= case("R4 persist-credentials moved out of with:", good.replace(
        "          persist-credentials: false", "        persist-credentials: false", 1), "indentation")
    ok &= case("R5 checkout re-pointed to another action pinned by sha", good.replace(
        "actions/checkout@", "someone-else/checkout@", 1), "pinned checkout action")
    ok &= case("R5 a step indented one level deeper", good.replace(
        "      - name: Comparison self-test (base code)", "        - name: Comparison self-test (base code)", 1),
        "indentation")
    ok &= case("R5 ref moved out of with:", good.replace(
        "          ref: ${{ github.event.pull_request.base.sha }}", "        ref: ${{ github.event.pull_request.base.sha }}", 1),
        "indentation")
    ok &= case("R5 tab-indented line", good.replace(
        "    runs-on: ubuntu-latest", "\truns-on: ubuntu-latest", 1), "indentation")
    ok &= case("R3-F3 pull_request trigger instead", good.replace("  pull_request_target:\n", "  pull_request:\n", 1),
               "differs from the pinned form")
    missing = wf / "absent.yml"
    if not any("cannot stat" in line for line in compare_workflow_errors(missing, "absent")):
        print("FAIL: self-test - a missing comparison workflow was NOT rejected", file=sys.stderr)
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
        ok &= run_workflow_cases(repo_root, Path(tmp))
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
    parser.add_argument("--update", action="store_true",
                        help="rewrite the rule-section manifest from CLAUDE.md and print the changed sections")
    parser.add_argument("--refs-only", action="store_true",
                        help="only the reference-file checks the doc gates call (symlink walk, readable, non-empty)")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.update:
        return update_manifest(Path(args.root))
    if args.refs_only:
        ref_errors = refs_errors(Path(args.root))
        for line in ref_errors:
            print(line, file=sys.stderr)
        return 1 if ref_errors else 0
    errors = check(Path(args.root))
    errors += workflow_errors(Path(args.root) / WORKFLOW_PATH)
    errors += compare_workflow_errors(Path(args.root) / COMPARE_WORKFLOW_PATH)
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
