"""Guard for #8291: every relative markdown link in the public docs resolves.

Walks CHANGELOG.md, SECURITY.md, README.md, CLAUDE.md and the docs
subtrees in GUARDED_DOCS_SUBDIRS, skips fenced code blocks and inline code spans (so grammar examples are not
read as links), and asserts that each relative link target exists inside the
checkout. A target that resolves outside the repository root (a ``..`` climb or
a symlinked directory pointing out) is broken for every reader of the
repository, and a markdown file reached through a symlink is content outside
the checkout, so both are refused.

Lives under scripts/ci/tests so the CI discover root runs it.

Python 3.9 compatible, standard library only.
"""

import re
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_FILES = ("CHANGELOG.md", "SECURITY.md", "README.md", "CLAUDE.md")
# Subtrees under docs/ that are clean and ratcheted here. Other docs subtrees
# still carry broken links that are tracked separately; add a subtree to this
# tuple once it is clean.
GUARDED_DOCS_SUBDIRS = ("docs/security",)
FENCE_RE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1")
LINK_RE = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "#", "tel:", "ftp://")


def has_symlink_component(root, path):
    """True when ``path`` or any directory between ``root`` and it is a symlink."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def markdown_files(root):
    """Yield every non-symlinked markdown file the guard covers under ``root``."""
    for name in ROOT_FILES:
        path = root / name
        if path.is_file() and not has_symlink_component(root, path):
            yield path
    for subdir in GUARDED_DOCS_SUBDIRS:
        base = root / subdir
        if base.is_dir() and not has_symlink_component(root, base):
            for path in sorted(base.rglob("*.md")):
                if not has_symlink_component(root, path):
                    yield path


def exists_inside(root, candidate):
    """True when ``candidate`` resolves to an existing path inside ``root``."""
    try:
        real = candidate.resolve()
        real.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return real.exists()


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
            if resolved.suffix == ".html" and exists_inside(
                root, resolved.with_suffix(".md")
            ):
                # The docs site renders each page as .html; a link to the
                # rendered form of an existing .md page is not broken.
                continue
            if not exists_inside(root, resolved):
                broken.append("%s:%d %s" % (path.relative_to(root), number, target))
    return broken


class DocsRelativeLinksTest(unittest.TestCase):
    """#8291: no broken relative links in the public documentation."""

    def test_no_broken_relative_links(self):
        broken = broken_links(REPO_ROOT)
        self.assertEqual(broken, [], "broken relative links:\n" + "\n".join(broken))

    def test_hall_of_fame_stub_exists(self):
        self.assertTrue((REPO_ROOT / "docs" / "security" / "hall-of-fame.md").is_file())


class LinkContainmentTest(unittest.TestCase):
    """#8291: link targets are confined to the checkout; symlinks are not followed."""

    def setUp(self):
        scratch = REPO_ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix="links8291-", dir=str(scratch))).resolve()
        self.addCleanup(shutil.rmtree, str(self.base), True)
        self.root = self.base / "root"
        self.guarded = self.root / "docs" / "security"
        self.guarded.mkdir(parents=True)
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("x", encoding="utf-8")
        (self.outside / "page.md").write_text("# outside\n", encoding="utf-8")

    def write(self, name, text):
        path = self.guarded / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_parent_climb_out_of_root_is_broken(self):
        self.write("a.md", "[x](../../../outside/secret.txt)\n")
        self.assertEqual(
            broken_links(self.root),
            ["docs/security/a.md:1 ../../../outside/secret.txt"],
        )

    def test_symlinked_directory_out_of_root_is_broken(self):
        (self.guarded / "link").symlink_to(self.outside, target_is_directory=True)
        self.write("a.md", "[x](link/secret.txt)\n")
        self.assertEqual(broken_links(self.root), ["docs/security/a.md:1 link/secret.txt"])

    def test_symlinked_markdown_file_is_not_read(self):
        (self.guarded / "b.md").symlink_to(self.outside / "page.md")
        (self.outside / "page.md").write_text("[x](missing-target.md)\n", encoding="utf-8")
        self.assertEqual(list(markdown_files(self.root)), [])
        self.assertEqual(broken_links(self.root), [])

    def test_in_root_link_stays_resolved(self):
        (self.guarded / "real.md").write_text("# real\n", encoding="utf-8")
        self.write("a.md", "[x](real.md) [y](../security/real.md#top)\n")
        self.assertEqual(broken_links(self.root), [])

    def test_in_root_html_with_sibling_md_stays_resolved(self):
        (self.guarded / "page.md").write_text("# page\n", encoding="utf-8")
        self.write("a.md", "[x](page.html)\n")
        self.assertEqual(broken_links(self.root), [])


if __name__ == "__main__":
    unittest.main()
