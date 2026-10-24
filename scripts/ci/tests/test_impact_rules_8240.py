"""Selector rule coverage for PR #8241 round 2 (umbrella #8240).

S2/F2  a change to the selector or its rules selects ALL.
F3     every src/tests file carrying a sal, sal-postgres or vectorlite cfg
       maps to the cells domain (postgres-feature and sal-feature).
S3     markdown compiled in by include_str!/include_bytes! selects rust.
F6     changed paths are read NUL-delimited (no quoted-path surprises).
S1     select emits an explicit 'true' per domain unless enforcement is on.
"""
import ast
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

import impact_fixture as fx
from impact import build_index, common

ImpactCase = fx.ImpactCase
SELECT_SCRIPT = fx.IMPACT_DIR / "select.py"
FEATURE_CFG_RE = re.compile(r'feature\s*=\s*"(sal|sal-postgres|vectorlite)"')
SCAN_TOPS = ("src", "tests", "benches")
ENTRY_SCRIPTS = ("select.py", "gate.py", "build_index.py")
DOMAINS = ("rust", "cells", "actionlint")


class SelectorChangesSelectAll(ImpactCase):
    def test_selector_files_and_rules_select_all(self):
        paths = [
            "scripts/ci/impact/select.py", "scripts/ci/impact/rules.json",
            "scripts/ci/impact/gate.py", "scripts/ci/impact/common.py",
            "scripts/ci/impact/build_index.py", "scripts/ci/tests/x.py",
            "scripts/ci/gha_anything.py", "scripts/check_foo.py",
            "scripts/check-foo.py", ".github/workflows/ci-full.yml",
        ]
        for path in paths:
            with self.subTest(path=path):
                out = self.select([path])
                self.assertTrue(out["all"], out["reasons"])
                self.assertIn("rust", out["jobs"])

    def test_every_local_import_of_the_entry_scripts_selects_all(self):
        modules = set()
        for script in ENTRY_SCRIPTS:
            tree = ast.parse((fx.IMPACT_DIR / script).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "impact":
                    modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("impact."):
                    modules.add(node.module.split(".", 1)[1])
        self.assertIn("common", modules)
        for module in sorted(modules):
            path = "scripts/ci/impact/%s.py" % module
            with self.subTest(path=path):
                self.assertTrue((fx.REPO_ROOT / path).is_file(), path)
                self.assertTrue(self.select([path])["all"])

    def test_rust_rule_is_kept(self):
        out = self.select(["src/x.rs"])
        self.assertFalse(out["all"])
        self.assertIn("rust", out["jobs"])


class CellsCoverage(unittest.TestCase):
    def test_every_feature_cfg_file_maps_to_cells(self):
        rules = json.loads(fx.RULES_JSON.read_text())
        globs = rules["cell_globs"]
        unmatched = []
        carrying = 0
        for top in SCAN_TOPS:
            for path in sorted((fx.REPO_ROOT / top).rglob("*.rs")):
                if FEATURE_CFG_RE.search(path.read_text(errors="replace")):
                    carrying += 1
                    rel = path.relative_to(fx.REPO_ROOT).as_posix()
                    if not any(common.match_glob(g, rel) for g in globs):
                        unmatched.append(rel)
        self.assertGreater(carrying, 400)
        self.assertEqual(unmatched, [], "feature-cfg files outside cell_globs")


class IncludedMarkdown(ImpactCase):
    def rebuild(self):
        build_index.build_index(self.repo, self.db, metadata=fx.make_metadata(self.repo),
                                rules_path=self.rules_path)

    def test_real_tree_scan_finds_performance_md(self):
        files, unresolved = build_index.scan_includes(fx.REPO_ROOT)
        self.assertIn("PERFORMANCE.md", files)
        self.assertEqual(unresolved, [])

    def test_included_markdown_selects_rust(self):
        fx.write_files(self.repo, {
            "src/posture.rs":
                'const SRC: &str = include_str!("../PERF.md");\n',
            "PERF.md": "x\n"})
        self.rebuild()
        out = self.select(["PERF.md"])
        self.assertIn("rust", out["jobs"])
        self.assertFalse(out["all"])
        self.assertEqual(self.select(["NOTES.md"])["jobs"].count("rust"), 0)

    def test_unresolved_include_makes_markdown_select_all(self):
        fx.write_files(self.repo, {
            "src/posture.rs":
                'const SRC: &str = include_str!(concat!(env!("D"), "/PERF.md"));\n'})
        self.rebuild()
        self.assertTrue(self.select(["NOTES.md"])["all"])

    def test_commented_include_is_ignored(self):
        fx.write_files(self.repo, {
            "src/posture.rs": '// include_str!("../missing.md")\n'})
        self.rebuild()
        _, unresolved = build_index.scan_includes(self.repo)
        self.assertEqual(unresolved, [])
        self.assertFalse(self.select(["NOTES.md"])["all"])

    def test_manifest_dir_concat_is_resolved(self):
        fx.write_files(self.repo, {
            "tests/wire.rs": 'let s = include_str!(concat!(\n    env!("CARGO_MANIFEST_DIR"),\n'
                             '    "/docs/WIRE.md"\n));\n',
            "docs/WIRE.md": "x\n"})
        files, unresolved = build_index.scan_includes(self.repo)
        self.assertIn("docs/WIRE.md", files)
        self.assertEqual(unresolved, [])

    def test_mention_inside_a_string_literal_is_ignored(self):
        fx.write_files(self.repo, {
            "tests/scan.rs": 'let a = t.find("include_str!(\\"");\n'})
        files, unresolved = build_index.scan_includes(self.repo)
        self.assertEqual(unresolved, [])

    def test_missing_target_is_unresolved(self):
        fx.write_files(self.repo, {
            "src/posture.rs": 'const A: &str = include_str!("../gone.md");\n'})
        _, unresolved = build_index.scan_includes(self.repo)
        self.assertEqual(len(unresolved), 1)


class NulDelimitedDiff(ImpactCase):
    def run_select(self, head):
        out = self.tmp / "out.json"
        cmd = [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
               "--repo", str(self.repo), "--base", self.base, "--head", head,
               "--out", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text())

    def test_filename_with_newline(self):
        name = "docs/a\nb.md"
        head = fx.commit_change(self.repo, {name: "x\n"})
        data = self.run_select(head)
        self.assertEqual(list(data["reasons"]), [name])
        self.assertFalse(data["all"])

    def test_non_ascii_filename(self):
        name = "docs/café.md"
        head = fx.commit_change(self.repo, {name: "x\n"})
        data = self.run_select(head)
        self.assertEqual(list(data["reasons"]), [name])
        self.assertFalse(data["all"])


class DomainOutputs(ImpactCase):
    def run_select(self, *extra):
        self.counter = getattr(self, "counter", 0) + 1
        head = fx.commit_change(self.repo, {"scripts/t.py": "x = %d\n" % self.counter})
        gh = self.tmp / ("gh%d.txt" % self.counter)
        cmd = [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
               "--repo", str(self.repo), "--base", self.base, "--head", head,
               "--github-output", str(gh)] + list(extra)
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        return dict(line.split("=", 1) for line in gh.read_text().splitlines())

    def test_enforce_off_emits_true_for_every_domain(self):
        for extra in ([], ["--enforce", ""], ["--enforce", "false"], ["--enforce", "TRUE?"]):
            with self.subTest(extra=extra):
                values = self.run_select(*extra)
                for domain in DOMAINS:
                    self.assertEqual(values[domain], "true")
                self.assertEqual(values["all"], "false")

    def test_enforce_on_emits_the_real_selection(self):
        values = self.run_select("--enforce", "true")
        self.assertEqual(values["rust"], "false")
        self.assertEqual(values["cells"], "false")
        self.assertEqual(values["actionlint"], "true")

    def test_enforce_on_with_all_selected_emits_true(self):
        head = fx.commit_change(self.repo, {"Cargo.lock": "x\n"})
        gh = self.tmp / "gh2.txt"
        cmd = [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
               "--repo", str(self.repo), "--base", self.base, "--head", head,
               "--enforce", "true", "--github-output", str(gh)]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        values = dict(line.split("=", 1) for line in gh.read_text().splitlines())
        for domain in DOMAINS:
            self.assertEqual(values[domain], "true")

    def test_fail_closed_diff_emits_true(self):
        gh = self.tmp / "gh3.txt"
        cmd = [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
               "--repo", str(self.repo), "--base", "0" * 40, "--head", self.base,
               "--enforce", "true", "--github-output", str(gh)]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        values = dict(line.split("=", 1) for line in gh.read_text().splitlines())
        for domain in DOMAINS:
            self.assertEqual(values[domain], "true")


if __name__ == "__main__":
    unittest.main()
