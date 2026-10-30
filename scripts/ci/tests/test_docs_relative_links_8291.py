"""Guard for #8291: every relative markdown link in the public docs resolves.

Walks CHANGELOG.md, SECURITY.md, README.md, CLAUDE.md and the docs
subtrees in GUARDED_DOCS_SUBDIRS, skips fenced code blocks and inline code
spans (so grammar examples are not read as links), and asserts that each
relative link target exists inside the checkout.

Symlink behaviour: a markdown source that is itself a symlink is skipped.
Directory symlinks are followed for existence, and containment is decided by
``resolve()`` against the root, so a symlink that points outside the checkout
is broken, while a link to a symlinked markdown file that stays inside the
checkout resolves. A protocol-relative ``//host/x`` target is refused, and ``..`` is
normalised lexically (never through a directory symlink), so a climb out of
the root is refused on every host.

Lives under scripts/ci/tests so the CI discover root runs it.

Python 3.9 compatible, standard library only.
"""

import errno
import os
import re
import shutil
import stat
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
TRAILING_SLASH_REASON = "trailing slash on a file target"
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


def inside_state(root, candidate):
    """Return ``(state, detail)`` for ``candidate`` against ``root``.

    ``state`` is ``"file"`` or ``"dir"`` when the path exists and its real
    location is inside ``root``, ``"missing"`` when it does not exist (ENOENT,
    ENOTDIR) or leaves the root, and ``"unresolvable"`` (``detail`` = errno
    name, or ``OSError`` when the error carries none) when the operating
    system refuses the path, for example a segment longer than NAME_MAX or a
    symlink loop. ``os.stat`` is probed directly because ``Path.is_dir`` and
    ``Path.exists`` swallow those errors on Python 3.14.
    """
    try:
        real = candidate.resolve()
        real.relative_to(root.resolve())
        mode = os.stat(str(real)).st_mode
        return ("dir" if stat.S_ISDIR(mode) else "file"), ""
    except (FileNotFoundError, NotADirectoryError):
        pass
    except OSError as err:
        if err.errno is None:
            return "unresolvable", "OSError"
        return "unresolvable", errno.errorcode.get(err.errno, "OSError")
    except RuntimeError:
        # Python < 3.13 reports a symlink loop from resolve() as RuntimeError.
        return "unresolvable", "ELOOP"
    except ValueError:
        pass
    return "missing", ""


def exists_inside(root, candidate):
    """True when ``candidate`` resolves to an existing path inside ``root``."""
    return inside_state(root, candidate)[0] in ("file", "dir")


def is_protocol_relative(target_path):
    """True for a ``//`` target: a browser reads its first segment as a host."""
    return target_path.startswith("//")


def normalised_path(root, source, target_path):
    """Lexically normalised, root-relative form of ``target_path`` (no filesystem access).

    A single leading ``/`` joins the target to the repository root; any other
    target joins to ``source``'s directory. ``..`` is resolved by string
    normalisation only, because a browser never resolves it through a
    directory symlink.
    """
    if target_path.startswith("/"):
        joined = target_path.lstrip("/")
    else:
        joined = os.path.join(str(source.parent.relative_to(root)), target_path)
    return os.path.normpath(joined)


def climbs_out_of_root(root, source, target_path):
    """True when ``target_path``, joined lexically, leaves ``root``.

    A target with one leading ``/`` is joined to the repository root; any
    other target is joined to ``source``'s directory. A ``//`` target is not
    handled here: ``is_protocol_relative`` refuses it before this is called.
    Pure string normalisation with no filesystem access, so a climb that
    re-enters the checkout through its own directory name is still refused
    on every host.
    """
    normal = normalised_path(root, source, target_path)
    return normal == ".." or normal.startswith(".." + os.sep)


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


def is_directory_form(target_path):
    """True when the raw target ends in ``/``, ``/.`` or ``/..`` (it names a directory)."""
    return target_path.split("/")[-1] in ("", ".", "..")


def link_problem(root, path, target_path):
    """Return None when the link resolves, else the reason it is broken ("" = missing).

    The trailing-slash rule uses the directory form of the raw target and runs
    before the ``.html`` sibling check.
    """
    if is_protocol_relative(target_path):
        return "protocol-relative target"
    if climbs_out_of_root(root, path, target_path):
        return ""
    resolved = root / normalised_path(root, path, target_path)
    state, detail = inside_state(root, resolved)
    if state == "unresolvable":
        return "unresolvable target: " + detail
    directory_form = is_directory_form(target_path)
    if state == "file" and directory_form:
        return TRAILING_SLASH_REASON
    if state == "missing" and resolved.suffix == ".html":
        # The docs site renders each page as .html; a link to the
        # rendered form of an existing .md page is not broken.
        if exists_inside(root, resolved.with_suffix(".md")):
            return TRAILING_SLASH_REASON if directory_form else None
    if state == "missing":
        return ""
    return None


def broken_links(root):
    """Return a list of ``file:line target`` strings for unresolved links.

    A link broken for a named reason carries ``(reason)`` after the target.
    """
    broken = []
    for path in markdown_files(root):
        for number, target in relative_links(path):
            target_path = target.split("#", 1)[0].split("?", 1)[0]
            if not target_path:
                continue
            problem = link_problem(root, path, target_path)
            if problem is None:
                continue
            entry = "%s:%d %s" % (path.relative_to(root), number, target)
            if problem:
                entry += " (%s)" % problem
            broken.append(entry)
    return broken


class DocsRelativeLinksTest(unittest.TestCase):
    """#8291: no broken relative links in the public documentation."""

    def test_no_broken_relative_links(self):
        broken = broken_links(REPO_ROOT)
        self.assertEqual(broken, [], "broken relative links:\n" + "\n".join(broken))

    def test_hall_of_fame_stub_exists(self):
        self.assertTrue((REPO_ROOT / "docs" / "security" / "hall-of-fame.md").is_file())


class LinkContainmentTest(unittest.TestCase):
    """#8291: link targets are confined to the checkout by resolve(); a symlinked .md source is skipped."""

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

    def test_parent_climb_out_and_back_in_is_broken(self):
        (self.root / "README.md").write_text("# root\n", encoding="utf-8")
        target = "../../../root/README.md"
        self.write("a.md", "[x](%s)\n" % target)
        self.assertEqual(broken_links(self.root), ["docs/security/a.md:1 " + target])

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

    def test_protocol_relative_target_is_broken(self):
        (self.root / "README.md").write_text("# root\n", encoding="utf-8")
        self.write("a.md", "[a](//README.md)\n[b](///README.md)\n[c](/README.md)\n")
        self.assertEqual(
            broken_links(self.root),
            [
                "docs/security/a.md:1 //README.md (protocol-relative target)",
                "docs/security/a.md:2 ///README.md (protocol-relative target)",
            ],
        )

    def test_dotdot_after_directory_symlink_is_lexical(self):
        (self.root / "sub" / "deep").mkdir(parents=True)
        (self.root / "sub" / "x.md").write_text("# x\n", encoding="utf-8")
        (self.root / "README.md").write_text("# root\n", encoding="utf-8")
        (self.root / "inlink").symlink_to(self.root / "sub" / "deep", target_is_directory=True)
        self.write("a.md", "[a](../../inlink/../x.md)\n[b](../../inlink/../README.md)\n")
        self.assertEqual(
            broken_links(self.root), ["docs/security/a.md:1 ../../inlink/../x.md"]
        )

    def test_unresolvable_target_is_broken_by_name(self):
        target = "a" * 300 + ".md"
        self.write("a.md", "[a](%s)\n" % target)
        self.assertEqual(
            broken_links(self.root),
            ["docs/security/a.md:1 %s (unresolvable target: ENAMETOOLONG)" % target],
        )

    def test_trailing_slash_must_name_a_directory(self):
        (self.root / "README.md").write_text("# root\n", encoding="utf-8")
        self.write("a.md", "[a](../../docs/)\n[b](../../README.md/)\n")
        self.assertEqual(
            broken_links(self.root),
            ["docs/security/a.md:2 ../../README.md/ (trailing slash on a file target)"],
        )

    def test_symlink_loop_and_missing_errno_keep_their_reason_8291_r5(self):
        (self.guarded / "loop").symlink_to("loop")
        self.write("a.md", "[a](loop)\n[b](nope.md)\n[c](a.md/x)\n")
        self.assertEqual(
            broken_links(self.root),
            [
                "docs/security/a.md:1 loop (unresolvable target: ELOOP)",
                "docs/security/a.md:2 nope.md",
                "docs/security/a.md:3 a.md/x",
            ],
        )
        real_stat = os.stat

        def no_errno(path, *args, **kwargs):
            raise OSError("no errno")

        os.stat = no_errno
        try:
            state = inside_state(self.root, self.guarded / "a.md")
        finally:
            os.stat = real_stat
        self.assertEqual(state, ("unresolvable", "OSError"))

    def test_trailing_slash_rule_survives_dot_segments_and_html_siblings_8291_r5(self):
        (self.root / "README.md").write_text("# root\n", encoding="utf-8")
        (self.guarded / "page.md").write_text("# page\n", encoding="utf-8")
        targets = ["../../README.md/.", "../../README.md/x/..", "page.html/"]
        self.write("a.md", "".join("[l](%s)\n" % t for t in targets))
        self.assertEqual(
            broken_links(self.root),
            [
                "docs/security/a.md:%d %s (trailing slash on a file target)" % (n, t)
                for n, t in enumerate(targets, start=1)
            ],
        )


class DocstringStatesBehaviourTest(unittest.TestCase):
    """#8291: the module docstring names the real symlink and path behaviour."""

    def test_docstring_names_each_behaviour(self):
        doc = (__doc__ or "").lower()
        for word in ("symlink", "//", "..", "resolve"):
            self.assertIn(word, doc)


if __name__ == "__main__":
    unittest.main()
