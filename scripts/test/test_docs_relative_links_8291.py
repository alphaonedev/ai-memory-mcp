"""Guard for #8291: every relative markdown link in the public docs resolves.

Walks CHANGELOG.md, SECURITY.md, README.md, CLAUDE.md and the docs
subtrees in GUARDED_DOCS_SUBDIRS, skips fenced code blocks and inline code spans (so grammar examples are not
read as links), and asserts that each relative link target exists.

Python 3.9 compatible, standard library only.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT_FILES = ("CHANGELOG.md", "SECURITY.md", "README.md", "CLAUDE.md")
# Subtrees under docs/ that are clean and ratcheted here. Other docs subtrees
# still carry broken links that are tracked separately; add a subtree to this
# tuple once it is clean.
GUARDED_DOCS_SUBDIRS = ("docs/security",)
FENCE_RE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1")
LINK_RE = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "#", "tel:", "ftp://")


def markdown_files(root):
    """Yield every markdown file the guard covers under ``root``."""
    for name in ROOT_FILES:
        path = root / name
        if path.is_file():
            yield path
    for subdir in GUARDED_DOCS_SUBDIRS:
        base = root / subdir
        if base.is_dir():
            for path in sorted(base.rglob("*.md")):
                yield path


def relative_links(path):
    """Yield ``(line_number, target)`` for each relative link in ``path``."""
    in_fence = False
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = CODE_SPAN_RE.sub("", line)
        for match in LINK_RE.finditer(stripped):
            target = match.group(1).strip("<>")
            if target.startswith(EXTERNAL_PREFIXES):
                continue
            yield number, target


def broken_links(root):
    """Return a list of ``file:line target`` strings for unresolved links."""
    broken = []
    for path in markdown_files(root):
        for number, target in relative_links(path):
            target_path = target.split("#", 1)[0].split("?", 1)[0]
            if not target_path:
                continue
            if target_path.startswith("/"):
                resolved = root / target_path.lstrip("/")
            else:
                resolved = path.parent / target_path
            if resolved.suffix == ".html" and resolved.with_suffix(".md").exists():
                # The docs site renders each page as .html; a link to the
                # rendered form of an existing .md page is not broken.
                continue
            if not resolved.exists():
                broken.append("%s:%d %s" % (path.relative_to(root), number, target))
    return broken


class DocsRelativeLinksTest(unittest.TestCase):
    """#8291: no broken relative links in the public documentation."""

    def test_no_broken_relative_links(self):
        broken = broken_links(REPO_ROOT)
        self.assertEqual(broken, [], "broken relative links:\n" + "\n".join(broken))

    def test_hall_of_fame_stub_exists(self):
        self.assertTrue((REPO_ROOT / "docs" / "security" / "hall-of-fame.md").is_file())


if __name__ == "__main__":
    unittest.main()
