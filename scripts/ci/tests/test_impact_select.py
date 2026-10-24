"""Tests for scripts/ci/impact: index builder and test selector (umbrella #8240).

Every rule in rules.json, union over paths, blast-radius closure on a
three-crate fixture, unclassified => ALL, additive-only advice, history
ordering, the GitHub output format and the event/base-ref force-all arms.
"""
import json
import sqlite3
import subprocess
import sys
import textwrap
import unittest

import impact_fixture as fx
ImpactCase = fx.ImpactCase

EXIT_USAGE = 2
SELECT_SCRIPT = fx.IMPACT_DIR / "select.py"
BUILD_SCRIPT = fx.IMPACT_DIR / "build_index.py"
ALWAYS_ON = {"codeql", "signatures", "leakscan", "banned-phrases"}


class RuleTable(ImpactCase):
    """One assertion per shipped rule (first match by priority wins)."""

    def test_all_rules(self):
        all_paths = [
            ".github/workflows/ci.yml", "scripts/ci/isolation_x.py",
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs",
            "deny.toml", "weird/unknown.xyz",
        ]
        for path in all_paths:
            with self.subTest(path=path):
                out = self.select([path])
                self.assertTrue(out["all"], out)

    def test_rust_rules(self):
        for path in ["crates/core/src/lib.rs", "src/x.rs", "tests/a.rs",
                     "benches/b.rs"]:
            with self.subTest(path=path):
                out = self.select([path])
                self.assertFalse(out["all"], out)
                self.assertIn("rust", out["jobs"])

    def test_python_rule(self):
        out = self.select(["scripts/tool.py"])
        self.assertFalse(out["all"])
        self.assertLessEqual({"python", "actionlint", "isolation-smoke"},
                             set(out["jobs"]))
        self.assertNotIn("rust", out["jobs"])

    def test_docs_rule(self):
        for path in ["docs/a.txt", "README.md", "site/index.html",
                     "mkdocs.yml", "src/notes.md"]:
            with self.subTest(path=path):
                out = self.select([path])
                self.assertFalse(out["all"], out)
                self.assertIn("docs", out["jobs"])
                self.assertNotIn("rust", out["jobs"])

    def test_always_on_keys_present(self):
        out = self.select(["README.md"])
        self.assertLessEqual(ALWAYS_ON, set(out["jobs"]))

    def test_reasons_name_the_rule(self):
        out = self.select(["README.md", "crates/core/src/lib.rs"])
        self.assertEqual(set(out["reasons"]),
                         {"README.md", "crates/core/src/lib.rs"})

    def test_gate_scripts_force_all(self):
        out = self.select(["scripts/check-foo.sh"])
        self.assertTrue(out["all"])


class Union(ImpactCase):
    def test_union_of_python_and_docs(self):
        out = self.select(["scripts/tool.py", "docs/a.txt"])
        self.assertLessEqual({"python", "docs", "actionlint"}, set(out["jobs"]))
        self.assertFalse(out["all"])

    def test_one_all_path_makes_all(self):
        out = self.select(["docs/a.txt", "Cargo.lock"])
        self.assertTrue(out["all"])

    def test_empty_diff_fails_closed(self):
        out = self.select([])
        self.assertTrue(out["all"])
        self.assertIn("empty-diff", json.dumps(out["reasons"]))

    def test_force_all(self):
        out = self.select(["README.md"], force_all="event:push")
        self.assertTrue(out["all"])
        self.assertIn("event:push", json.dumps(out["reasons"]))


class BlastRadius(ImpactCase):
    cell_crates = ["store"]

    def test_core_change_reaches_dependants(self):
        out = self.select(["crates/core/src/lib.rs"])
        self.assertEqual(out["crates"], ["app", "core", "store"])

    def test_store_change_reaches_app_only(self):
        out = self.select(["crates/store/src/lib.rs"])
        self.assertEqual(out["crates"], ["app", "store"])

    def test_leaf_change_stays_local(self):
        out = self.select(["crates/app/src/lib.rs"])
        self.assertEqual(out["crates"], ["app"])

    def test_cells_added_when_closure_hits_cell_crate(self):
        self.assertIn("cells", self.select(["crates/core/src/lib.rs"])["jobs"])
        self.assertIn("cells", self.select(["crates/store/src/lib.rs"])["jobs"])
        self.assertNotIn("cells", self.select(["crates/app/src/lib.rs"])["jobs"])

    def test_tests_listed_for_closure_only(self):
        out = self.select(["crates/store/src/lib.rs"])
        self.assertEqual(sorted(out["tests"]), ["it_app", "it_store"])

    def test_all_lists_every_crate(self):
        out = self.select(["Cargo.lock"])
        self.assertEqual(out["crates"], ["app", "core", "store"])
        self.assertEqual(len(out["tests"]), 3)


class CellGlobs(ImpactCase):
    def test_store_path_adds_cells(self):
        out = self.select(["src/store/sqlite.rs"])
        self.assertIn("cells", out["jobs"])

    def test_cli_path_does_not_add_cells(self):
        out = self.select(["src/cli/args.rs"])
        self.assertNotIn("cells", out["jobs"])


class Advice(ImpactCase):
    def test_advice_adds_keys(self):
        out = self.select(["README.md"],
                          advice=[{"job_key": "rust", "reason": "doc embeds code"}])
        self.assertIn("rust", out["jobs"])
        self.assertEqual(out["advice"][0]["job_key"], "rust")

    def test_advice_cannot_remove(self):
        base = self.select(["scripts/tool.py"])
        advised = self.select(["scripts/tool.py"], advice=[
            {"job_key": "docs", "reason": "x"}])
        self.assertLessEqual(set(base["jobs"]), set(advised["jobs"]))

    def test_unknown_key_is_rejected(self):
        from impact import select
        with self.assertRaises(select.AdviceError):
            self.select(["README.md"], advice=[{"job_key": "nope", "reason": "x"}])

    def test_malformed_advice_is_rejected(self):
        from impact import select
        for bad in ({"job_key": "rust"}, "rust", {"reason": "x"}):
            with self.subTest(bad=bad), self.assertRaises(select.AdviceError):
                self.select(["README.md"], advice=[bad])

    def test_cli_unknown_key_exits_2_and_writes_nothing(self):
        advice = self.tmp / "advice.json"
        advice.write_text(json.dumps([{"job_key": "nope", "reason": "x"}]))
        out = self.tmp / "out.json"
        new = fx.commit_change(self.repo, {"README.md": "changed\n"})
        res = subprocess.run(
            [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
             "--repo", str(self.repo), "--base", self.base, "--head", new,
             "--advice", str(advice), "--out", str(out)],
            capture_output=True, text=True)
        self.assertEqual(res.returncode, EXIT_USAGE, res.stderr)
        self.assertFalse(out.exists())


class HistoryOrdering(ImpactCase):
    def test_failed_first_then_flaky_then_duration(self):
        con = sqlite3.connect(str(self.db))
        con.executemany(
            "insert or replace into history(target, duration_s, last_result,"
            " flaky_count, updated_at) values (?,?,?,?,?)",
            [("it_core", 9.0, "passed", 0, 1), ("it_store", 50.0, "passed", 3, 1),
             ("it_app", 1.0, "failed", 0, 1)])
        con.commit()
        con.close()
        out = self.select(["crates/core/src/lib.rs"])
        self.assertEqual(out["tests"], ["it_app", "it_store", "it_core"])

    def test_shorter_duration_first_when_equal(self):
        con = sqlite3.connect(str(self.db))
        con.executemany(
            "insert or replace into history(target, duration_s, last_result,"
            " flaky_count, updated_at) values (?,?,?,?,?)",
            [("it_core", 9.0, "passed", 0, 1), ("it_store", 2.0, "passed", 0, 1),
             ("it_app", 5.0, "passed", 0, 1)])
        con.commit()
        con.close()
        out = self.select(["crates/core/src/lib.rs"])
        self.assertEqual(out["tests"], ["it_store", "it_app", "it_core"])


class CommandLine(ImpactCase):
    def run_select(self, *extra, base=None, head=None):
        out = self.tmp / "out.json"
        gh = self.tmp / "gh.txt"
        cmd = [sys.executable, "-I", str(SELECT_SCRIPT), "--db", str(self.db),
               "--repo", str(self.repo), "--base", base or self.base,
               "--head", head, "--out", str(out), "--github-output", str(gh)]
        res = subprocess.run(cmd + list(extra), capture_output=True, text=True)
        return res, out, gh

    def test_github_output_format(self):
        head = fx.commit_change(self.repo, {"scripts/t.py": "x = 1\n"})
        res, out, gh = self.run_select(head=head)
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = gh.read_text().splitlines()
        keys = [ln.split("=", 1)[0] for ln in lines]
        self.assertEqual(keys, ["jobs", "all", "crates"])
        values = dict(ln.split("=", 1) for ln in lines)
        self.assertEqual(values["all"], "false")
        self.assertIn("python", values["jobs"].split(","))
        data = json.loads(out.read_text())
        self.assertEqual(values["jobs"], ",".join(data["jobs"]))

    def test_all_flag_in_github_output(self):
        head = fx.commit_change(self.repo, {"Cargo.lock": "x\n"})
        res, out, gh = self.run_select(head=head)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("all=true", gh.read_text().splitlines())

    def test_diff_comes_from_git(self):
        head = fx.commit_change(self.repo, {"crates/app/src/lib.rs": "// c\n"})
        res, out, gh = self.run_select(head=head)
        data = json.loads(out.read_text())
        self.assertEqual(data["crates"], ["app"])
        self.assertIn("crates/app/src/lib.rs", data["reasons"])

    def test_non_pr_event_forces_all(self):
        head = fx.commit_change(self.repo, {"README.md": "c\n"})
        res, out, gh = self.run_select("--event", "push", head=head)
        self.assertTrue(json.loads(out.read_text())["all"])

    def test_pull_request_event_does_not_force(self):
        head = fx.commit_change(self.repo, {"README.md": "c\n"})
        res, out, gh = self.run_select("--event", "pull_request",
                                       "--base-ref", "chain/x", head=head)
        self.assertFalse(json.loads(out.read_text())["all"])

    def test_release_base_ref_forces_all(self):
        head = fx.commit_change(self.repo, {"README.md": "c\n"})
        res, out, gh = self.run_select("--event", "pull_request",
                                       "--base-ref", "release/v1.0.0", head=head)
        self.assertTrue(json.loads(out.read_text())["all"])

    def test_bad_base_fails_closed(self):
        head = fx.commit_change(self.repo, {"README.md": "c\n"})
        res, out, gh = self.run_select(base="0" * 40, head=head)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(json.loads(out.read_text())["all"])

    def test_missing_db_fails_closed(self):
        head = fx.commit_change(self.repo, {"README.md": "c\n"})
        self.db.unlink()
        res, out, gh = self.run_select(head=head)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(json.loads(out.read_text())["all"])
        self.assertIn("all=true", gh.read_text().splitlines())


class BuildIndex(ImpactCase):
    def tables(self):
        con = sqlite3.connect(str(self.db))
        rows = con.execute("select name from sqlite_master where type='table'")
        names = {r[0] for r in rows}
        con.close()
        return names

    def test_schema_tables(self):
        self.assertLessEqual({"schema_version", "crates", "crate_deps",
                             "test_targets", "path_rules", "history",
                             "file_symbols", "symbol_edges"}, self.tables())

    def test_wal_mode(self):
        con = sqlite3.connect(str(self.db))
        self.assertEqual(con.execute("pragma journal_mode").fetchone()[0], "wal")
        con.close()

    def test_dep_edges_are_workspace_internal(self):
        con = sqlite3.connect(str(self.db))
        edges = set(con.execute("select crate, dep from crate_deps"))
        con.close()
        self.assertEqual(edges, {("app", "store"), ("store", "core")})

    def test_idempotent(self):
        from impact import build_index
        def snapshot():
            con = sqlite3.connect(str(self.db))
            data = {t: sorted(con.execute("select * from %s" % t))
                    for t in ("crates", "crate_deps", "test_targets", "path_rules")}
            con.close()
            return data
        first = snapshot()
        build_index.build_index(self.repo, self.db,
                                metadata=fx.make_metadata(self.repo),
                                rules_path=self.rules_path)
        self.assertEqual(first, snapshot())

    def test_junit_ingest(self):
        from impact import build_index
        junit = self.tmp / "junit.xml"
        junit.write_text(textwrap.dedent("""\
            <testsuites>
              <testsuite name="app::it_app" tests="2">
                <testcase classname="app::it_app" name="a" time="1.5"/>
                <testcase classname="app::it_app" name="b" time="0.5">
                  <failure message="boom"/>
                </testcase>
              </testsuite>
              <testsuite name="core::it_core" tests="1">
                <testcase classname="core::it_core" name="c" time="2.0">
                  <flakyFailure message="retry"/>
                </testcase>
              </testsuite>
            </testsuites>"""))
        build_index.build_index(self.repo, self.db,
                                metadata=fx.make_metadata(self.repo),
                                rules_path=self.rules_path, junit=junit)
        con = sqlite3.connect(str(self.db))
        rows = {r[0]: r[1:] for r in con.execute(
            "select target, duration_s, last_result, flaky_count from history")}
        con.close()
        self.assertEqual(rows["it_app"][:2], (2.0, "failed"))
        self.assertEqual(rows["it_core"][1:], ("passed", 1))

    def test_codegraph_schema_mismatch_is_skipped(self):
        from impact import build_index
        cg = self.tmp / ".codegraph"
        cg.mkdir()
        con = sqlite3.connect(str(cg / "codegraph.db"))
        con.execute("create table nodes (id text)")
        con.commit()
        con.close()
        summary = build_index.build_index(
            self.repo, self.db, metadata=fx.make_metadata(self.repo),
            rules_path=self.rules_path, codegraph=cg)
        self.assertEqual(summary["codegraph"], "skipped: schema differs")

    def test_codegraph_import(self):
        from impact import build_index
        cg = self.tmp / ".codegraph"
        cg.mkdir()
        con = sqlite3.connect(str(cg / "codegraph.db"))
        con.executescript("""
            create table nodes (id text primary key, kind text, name text,
              file_path text);
            create table edges (id integer primary key, source text,
              target text, kind text);
            insert into nodes values ('a','function','fa','src/a.rs');
            insert into nodes values ('b','function','fb','src/b.rs');
            insert into edges (source, target, kind) values ('a','b','calls');
        """)
        con.commit()
        con.close()
        summary = build_index.build_index(
            self.repo, self.db, metadata=fx.make_metadata(self.repo),
            rules_path=self.rules_path, codegraph=cg)
        self.assertEqual(summary["codegraph"], "imported")
        dbc = sqlite3.connect(str(self.db))
        self.assertEqual(dbc.execute(
            "select src_file, dst_file from symbol_edges").fetchall(),
            [("src/a.rs", "src/b.rs")])
        dbc.close()

    def test_cli_with_metadata_file(self):
        meta = self.tmp / "meta.json"
        meta.write_text(json.dumps(fx.make_metadata(self.repo)))
        db2 = self.tmp / "cli.db"
        res = subprocess.run(
            [sys.executable, "-I", str(BUILD_SCRIPT), "--repo", str(self.repo),
             "--db", str(db2), "--metadata-file", str(meta)],
            capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(db2.exists())


class RulesFile(unittest.TestCase):
    def test_rules_are_valid(self):
        rules = json.loads(fx.RULES_JSON.read_text())
        known = set(rules["known_jobs"])
        self.assertLessEqual(ALWAYS_ON, known)
        for rule in rules["rules"]:
            self.assertLessEqual(set(rule["jobs"]), known | {"ALL"}, rule)
        for key in rules["job_map"].values():
            self.assertIn(key, known)
        priorities = [r["priority"] for r in rules["rules"]]
        self.assertEqual(len(priorities), len(set(priorities)))


if __name__ == "__main__":
    unittest.main()
