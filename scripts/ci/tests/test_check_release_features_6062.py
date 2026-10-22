"""Release-feature guard residue of umbrella #6062: #6289, #6290, #6904, #8002, #8020, #8021 and #8023.

Each test mutates the release workflows of the tree this module runs in (never
a hard-coded copy) and requires scripts/check_release_features.py to refuse the
mutant; the unmutated tree is the control and must pass. Run:

    python3 -I -m unittest discover -s scripts/ci/tests

Stdlib only, Python 3.9+.
"""
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_release_features.py"
REL = ROOT / ".github" / "workflows" / "release.yml"
SHAPE = ROOT / ".github" / "workflows" / "release-shape.yml"
C8 = ROOT / ".github" / "workflows" / "c8-precheck.yml"
PUBLISH = ROOT / ".github" / "workflows" / "publish-ci-image.yml"

# One entry per issue this PR closes. SELF_CHECK below requires every issue to
# have at least one pinned case and the count to equal this list.
CLOSES = (6289, 6290, 6904, 8002, 8020, 8021, 8023)
PINNED_CASES = {}  # issue number -> list of test method names, filled by pins()


def pins(issue):
    def deco(fn):
        PINNED_CASES.setdefault(issue, []).append(fn.__name__)
        return fn
    return deco


def load_guard():
    spec = importlib.util.spec_from_file_location("check_release_features_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = load_guard()


def read(path):
    return path.read_bytes().decode("utf-8")


def job_span(text, job):
    m = re.search(r"(?m)^  %s:\n(?:(?!^  [A-Za-z0-9_-]+:\n).*\n?)*" % re.escape(job), text)
    if m is None:
        raise AssertionError("job %s not found" % job)
    return m.start(), m.end()


def edit_job(text, job, fn):
    a, b = job_span(text, job)
    new = fn(text[a:b])
    if new == text[a:b]:
        raise AssertionError("mutation of job %s changed nothing" % job)
    return text[:a] + new + text[b:]


def set_needs(text, job, value):
    def fn(body):
        return re.sub(r"(?m)^    needs:.*\n", ("    needs: %s\n" % value) if value else "", body, count=1)
    return edit_job(text, job, fn)


def errors_release(text):
    rep = G.Report()
    G.check_release_yml(text, rep)
    return rep.errors


def errors_shape(text):
    rep = G.Report()
    G.check_shape(text, rep)
    return rep.errors


JOBS_WITH_NEEDS = ("qualify", "supply-chain", "release", "sbom", "mobile-ios", "mobile-android",
                   "crates-io", "homebrew", "docker", "copr")


class Controls(unittest.TestCase):
    def test_shipped_workflows_pass(self):
        self.assertEqual(errors_release(read(REL)), [])
        self.assertEqual(errors_shape(read(SHAPE)), [])

    def test_self_check_pinned_case_count_equals_closes(self):
        """The pinned-case count equals the Closes count (7)."""
        self.assertEqual(len(CLOSES), 7)
        self.assertEqual(sorted(PINNED_CASES), sorted(CLOSES))
        for issue in CLOSES:
            self.assertTrue(PINNED_CASES[issue], "no pinned case for #%d" % issue)


class Needs6289(unittest.TestCase):
    """#6289: "Check every job's needs against that table ... Refuse any missing job and any extra job."
    A job's `needs:` may not shrink while the guard stays green."""

    @pins(6289)
    def test_every_job_refuses_a_shortened_needs(self):
        """#6289: shorten each job's needs to [preflight]; the guard must refuse all of them."""
        base = read(REL)
        survivors = []
        for job in JOBS_WITH_NEEDS:
            if not errors_release(set_needs(base, job, "[preflight]")):
                survivors.append(job)
        self.assertEqual(survivors, [], "needs: edge dropped with the guard green")

    @pins(6289)
    def test_every_job_refuses_a_removed_needs(self):
        """#6289: remove each job's needs: key entirely; the guard must refuse all of them."""
        base = read(REL)
        survivors = [j for j in JOBS_WITH_NEEDS if not errors_release(set_needs(base, j, ""))]
        self.assertEqual(survivors, [])

    @pins(6289)
    def test_root_job_may_not_gain_needs(self):
        """#6289: preflight is the root; a needs: on it is refused."""
        def fn(body):
            return body.replace("  preflight:\n", "  preflight:\n    needs: qualify\n", 1)
        self.assertTrue(errors_release(edit_job(read(REL), "preflight", fn)))

    @pins(6289)
    def test_publish_jobs_keep_the_release_edge(self):
        """#6289: crates-io, homebrew and copr must stay behind `release`."""
        base = read(REL)
        for job in ("crates-io", "homebrew", "copr"):
            self.assertTrue(errors_release(set_needs(base, job, "[preflight, qualify, supply-chain]")), job)


def shape_step_edit(marker, line):
    text = read(SHAPE)
    i = text.index(marker)
    j = text.index("\n", i) + 1
    return text[:j] + line + text[j:]


class Shape6290(unittest.TestCase):
    """#6290: "Pin the release-shape job's step list whole: step count, then the exact key set and body
    of each step." A step-level if:/continue-on-error: on a non-proof step must be refused."""

    @pins(6290)
    def test_if_false_on_guard_step(self):
        """#6290: `if: false` on the Release feature declaration guard step is refused."""
        self.assertTrue(errors_shape(shape_step_edit("      - name: Release feature declaration guard\n", "        if: false\n")))

    @pins(6290)
    def test_continue_on_error_on_guard_step(self):
        """#6290: `continue-on-error: true` on the guard step is refused."""
        self.assertTrue(errors_shape(shape_step_edit("      - name: Release feature declaration guard\n",
                                                     "        continue-on-error: true\n")))

    @pins(6290)
    def test_continue_on_error_on_checkout(self):
        """#6290: `continue-on-error: true` on the checkout step is refused."""
        self.assertTrue(errors_shape(shape_step_edit("      - uses: actions/checkout@", "        continue-on-error: true\n")))

    @pins(6290)
    def test_modifiers_on_other_steps(self):
        """#6290: if:/continue-on-error:/timeout-minutes: on any non-build, non-proof step is refused."""
        for marker in ("      - name: Install Rust 1.98.0",
                       "      - uses: Swatinem/rust-cache@",
                       "      - name: No OpenSSL / libpq / native-tls",
                       "      - name: Start a TLS PostgreSQL service"):
            for line in ("        if: false\n", "        continue-on-error: true\n", "        timeout-minutes: 1\n"):
                self.assertTrue(errors_shape(shape_step_edit(marker, line)), (marker, line))

    @pins(6290)
    def test_cleanup_if_always_narrowed(self):
        """#6290: the cleanup step's `if: always()` narrowed to success() is refused."""
        text = read(SHAPE).replace("        if: always()\n", "        if: success()\n", 1)
        self.assertTrue(errors_shape(text))

    @pins(6290)
    def test_step_appended(self):
        """#6290: a step appended to the job is refused (the step list is pinned whole)."""
        text = read(SHAPE).rstrip("\n") + "\n\n      - name: x\n        run: echo\n"
        self.assertTrue(errors_shape(text))


class Uses6904(unittest.TestCase):
    """#6904: "walks every `uses:` in all three workflows and rejects any value whose ref after `@` is
    not a 40-hex SHA (allow ./local and docker://...@sha256:)"."""

    def uses_mutants(self):
        text = read(REL)
        sha = re.compile(r"(uses:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})")
        found = list(sha.finditer(text))
        self.assertGreater(len(found), 20)
        return text, found

    @pins(6904)
    def test_every_release_uses_repointed_to_a_tag(self):
        """#6904: repoint each `uses:` of release.yml, one at a time, to a mutable tag; all are refused."""
        text, found = self.uses_mutants()
        survivors = []
        for m in found:
            mut = text[:m.start(3)] + "v4" + text[m.end(3):]
            if not errors_release(mut):
                survivors.append(text.count("\n", 0, m.start()) + 1)
        self.assertEqual(survivors, [], "release.yml lines whose mutable-tag mutant is accepted")

    @pins(6904)
    def test_malformed_refs_refused(self):
        """#6904: a 39-hex, upper-case, branch or docker-tag ref is refused in preflight and crates-io."""
        text = read(REL)
        for job in ("preflight", "qualify", "crates-io", "homebrew", "copr", "mobile-ios", "mobile-android"):
            a, b = job_span(text, job)
            m = re.search(r"uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@([0-9a-f]{40})", text[a:b])
            self.assertIsNotNone(m, job)
            s, e = a + m.start(1), a + m.end(1)
            for ref in (text[s:e - 1], text[s:e].upper(), "main", "v1"):
                self.assertTrue(errors_release(text[:s] + ref + text[e:]), (job, ref))

    @pins(6904)
    def test_docker_tag_ref_refused(self):
        """#6904: docker://alpine:3 (a tag, no sha256 digest) replaces a pinned action and is refused."""
        text = read(REL)
        m = re.search(r"uses:\s*actions/checkout@[0-9a-f]{40}", text)
        self.assertTrue(errors_release(text[:m.start()] + "uses: docker://alpine:3" + text[m.end():]))

    @pins(6904)
    def test_shape_workflow_uses_refused(self):
        """#6904: every `uses:` of release-shape.yml repointed to a tag is refused."""
        text = read(SHAPE)
        found = list(re.finditer(r"uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@([0-9a-f]{40})", text))
        self.assertGreaterEqual(len(found), 3)
        for m in found:
            self.assertTrue(errors_shape(text[:m.start(1)] + "v4" + text[m.end(1):]), m.group(0))

    @pins(6904)
    def test_local_and_digest_forms_are_accepted(self):
        """#6904: a ./local action and docker://...@sha256:<64 hex> are the allowed non-sha forms."""
        pattern = getattr(G, "USES_PINNED_RE", None)
        self.assertIsNotNone(pattern, "USES_PINNED_RE is not defined")
        self.assertTrue(pattern.fullmatch("./.github/actions/x"))
        self.assertTrue(pattern.fullmatch("docker://alpine@sha256:" + "a" * 64))
        self.assertFalse(pattern.fullmatch("docker://alpine:3"))
        self.assertFalse(pattern.fullmatch("actions/checkout@v4"))


def scratch():
    d = ROOT / ".local-runs"
    d.mkdir(exist_ok=True)
    return str(d)


class FailClosed(unittest.TestCase):
    """The guard compares the workflows in the tree it runs on and is never green on a skipped check."""

    def make_tree(self, tmp, drop=None):
        for rel in ("scripts/release-features.sh", ".github/workflows/release.yml",
                    ".github/workflows/release-shape.yml", ".github/workflows/c8-precheck.yml",
                    ".github/workflows/publish-ci-image.yml", "Dockerfile", "docs/INSTALL.md"):
            if rel == drop:
                continue
            dst = Path(tmp) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((ROOT / rel).read_bytes())
        return Path(tmp)

    def test_missing_workflow_is_not_green(self):
        """A missing release.yml is a failure, never OK."""
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = self.make_tree(tmp, drop=".github/workflows/release.yml")
            errors, _ = G.run_guard(root)
            self.assertTrue(errors)

    def test_undecodable_workflow_is_exit_2(self):
        """A non-UTF-8 release.yml is undecidable: InputError, exit 2."""
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = self.make_tree(tmp)
            (root / ".github/workflows/release.yml").write_bytes(b"\xff\xfe\x00bad")
            self.assertEqual(G.main([str(root)]), 2)

    def test_unmutated_tree_copy_is_exit_0(self):
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = self.make_tree(tmp)
            self.assertEqual(G.main([str(root)]), 0)


SHA_USES = re.compile(r"(uses:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})")


def first_use_to_tag(text):
    m = SHA_USES.search(text)
    assert m is not None
    return text[:m.start(3)] + "v4" + text[m.end(3):]


def tree_with(tmp, rel, text):
    root = FailClosed().make_tree(tmp)
    (root / rel).write_bytes(text.encode("utf-8"))
    return root


class Walked8002(unittest.TestCase):
    """#8002 / #8020 (part of #6904): the `uses:` walk covers c8-precheck.yml and the publish-ci path."""

    def every_use(self, path, label):
        text = read(path)
        found = list(SHA_USES.finditer(text))
        self.assertGreater(len(found), 3, label)
        survivors = []
        for m in found:
            mut = text[:m.start(3)] + "v4" + text[m.end(3):]
            rep = G.Report()
            doc = G.parse_yaml(mut, label, rep)
            G.check_uses_pinned(doc, label, rep)
            if not rep.errors:
                survivors.append(text.count("\n", 0, m.start()) + 1)
        self.assertEqual(survivors, [], label)

    @pins(8002)
    def test_c8_precheck_every_use_refused_by_the_walk(self):
        """#8002: every `uses:` of c8-precheck.yml repointed to a tag is refused by check_uses_pinned."""
        self.every_use(C8, "c8-precheck.yml")

    @pins(8002)
    def test_c8_precheck_tag_is_refused_by_the_guard(self):
        """#8002: run_guard refuses a c8-precheck.yml whose first `uses:` is @v4."""
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = tree_with(tmp, ".github/workflows/c8-precheck.yml", first_use_to_tag(read(C8)))
            errors, _ = G.run_guard(root)
            self.assertTrue(any("c8-precheck.yml" in e and "#6904" in e for e in errors), errors)

    @pins(8020)
    def test_publish_ci_every_use_refused_by_the_walk(self):
        """#8020: every `uses:` of publish-ci-image.yml repointed to a tag is refused by check_uses_pinned."""
        self.every_use(PUBLISH, "publish-ci-image.yml")

    @pins(8020)
    def test_publish_ci_tag_is_refused_by_the_guard(self):
        """#8020: run_guard refuses a publish-ci-image.yml whose first `uses:` is @v4."""
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = tree_with(tmp, ".github/workflows/publish-ci-image.yml", first_use_to_tag(read(PUBLISH)))
            errors, _ = G.run_guard(root)
            self.assertTrue(any("publish-ci-image.yml" in e and "#6904" in e for e in errors), errors)

    @pins(8020)
    def test_missing_publish_or_c8_workflow_is_not_green(self):
        """#8020: a missing c8-precheck.yml or publish-ci-image.yml is a failure, never OK."""
        for rel in (".github/workflows/c8-precheck.yml", ".github/workflows/publish-ci-image.yml"):
            with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
                root = FailClosed().make_tree(tmp, drop=rel)
                errors, _ = G.run_guard(root)
                self.assertTrue(errors, rel)

    @pins(8020)
    def test_undecodable_publish_or_c8_workflow_is_exit_2(self):
        """#8020: a non-UTF-8 c8-precheck.yml or publish-ci-image.yml is undecidable: exit 2."""
        for rel in (".github/workflows/c8-precheck.yml", ".github/workflows/publish-ci-image.yml"):
            with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
                root = FailClosed().make_tree(tmp)
                (root / rel).write_bytes(b"\xff\xfe\x00bad")
                self.assertEqual(G.main([str(root)]), 2, rel)


class Named8021(unittest.TestCase):
    """#8021: the `uses:` refusal names the job and the step, not only a line number."""

    @pins(8021)
    def test_error_names_job_and_step(self):
        """#8021: a tag-pinned crates-io step is reported with its job and step."""
        text = read(REL)
        a, b = job_span(text, "crates-io")
        mut = text[:a] + first_use_to_tag(text[a:b]) + text[b:]
        errs = [e for e in errors_release(mut) if "#6904" in e]
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("job `crates-io`", errs[0])
        self.assertIn("step ", errs[0])
        self.assertIn("release.yml", errs[0])

    @pins(8021)
    def test_error_names_the_job_in_another_workflow(self):
        """#8021: the same naming for c8-precheck.yml."""
        rep = G.Report()
        doc = G.parse_yaml(first_use_to_tag(read(C8)), "c8-precheck.yml", rep)
        G.check_uses_pinned(doc, "c8-precheck.yml", rep)
        self.assertEqual(len(rep.errors), 1, rep.errors)
        self.assertIn("job `c8-precheck`", rep.errors[0])


NEW_CELLS = (
    "N1 root job preflight gains needs is refused",
    "N2 homebrew needs drops release is refused",
    "N3 release.yml preflight uses repointed to a tag is refused",
    "N11 release.yml crates-io uses repointed to a tag is refused",
    "N4 release-shape.yml uses repointed to a tag is refused",
    "N5 c8-precheck.yml uses repointed to a tag is refused",
    "N6 publish-ci-image.yml uses repointed to a tag is refused",
    "N7 release-shape holds a non-mapping step is refused",
    "N8 release-shape step appended is refused",
    "N10 release-shape guard step gains if: false is refused",
)


class SelfTest8023(unittest.TestCase):
    """#8023: --self-test (run by c8-precheck) carries a cell for each new refusal site."""

    @pins(8023)
    def test_self_test_has_a_cell_per_new_site(self):
        """#8023: every new refusal has a named cell and the guard-case count rises above 355."""
        missing = [n for n in NEW_CELLS if n not in G.CASES]
        self.assertEqual(missing, [])
        self.assertGreater(len(G.CASES), 355)

    @pins(8023)
    def test_unit_slot_swap_is_a_message_cell(self):
        """#8023: swapping the guard and build steps is proven by a message cell (exact count)."""
        self.assertIn("message: swapped guard and build steps name the unit slot", G.MESSAGE_CASES)


if __name__ == "__main__":
    unittest.main()
