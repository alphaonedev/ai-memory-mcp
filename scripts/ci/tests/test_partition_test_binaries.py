#!/usr/bin/env python3
"""Unit tests for scripts/ci/partition_test_binaries.py (#6344).

Run: python3 scripts/ci/tests/test_partition_test_binaries.py   (or python3 -m unittest scripts/ci/tests/test_partition_test_binaries.py)
Fixtures live in a scratch directory under the repository's .local-runs/ (never
the system temp directory).
"""
import json
import shutil
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import partition_test_binaries as pt  # noqa: E402

REPO = HERE.parents[2]
SCRATCH = REPO / '.local-runs' / 'partition-unittests'


def artifact(kind, name, src, executable=None, test=True):
    return json.dumps({
        'reason': 'compiler-artifact',
        'target': {'kind': kind, 'name': name, 'src_path': str(src)},
        'profile': {'test': test},
        'executable': executable or '/x/' + name,
    })


class Base(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        (SCRATCH / 'tests').mkdir(parents=True)
        (SCRATCH / 'src').mkdir()
        (SCRATCH / 'out').mkdir()

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def write_src(self, name, text):
        p = SCRATCH / 'tests' / (name + '.rs')
        p.write_text(text)
        return p


class ParseTests(Base):
    def test_only_test_profile_executables_and_dedup(self):
        p = self.write_src('foo', '')
        lines = [
            artifact(['test'], 'foo', p, '/x/foo'),
            artifact(['test'], 'foo', p, '/x/foo'),
            artifact(['lib'], 'dep', p, None, test=False),
            artifact(['test'], 'bar', p, '/x/bar', test=False),
            '{"reason":"build-finished","success":true}',
            'not json',
        ]
        exes = pt.parse_build_json(lines)
        self.assertEqual([e.key for e in exes], ['test:foo'])

    def test_lib_bin_example_selectors(self):
        p = self.write_src('foo', '')
        exes = pt.parse_build_json([
            artifact(['lib', 'staticlib', 'cdylib'], 'ai_memory', p, '/x/l'),
            artifact(['bin'], 'ai-memory', p, '/x/b'),
            artifact(['example'], 'fed_issue', p, '/x/e'),
        ])
        self.assertEqual(sorted(e.selector for e in exes),
                         ['--bin ai-memory', '--example fed_issue', '--lib'])

    def test_empty_build_is_an_error(self):
        with self.assertRaises(pt.PartitionError):
            pt.parse_build_json(['{"reason":"build-finished"}'])

    def test_unsafe_name_is_an_error(self):
        p = self.write_src('foo', '')
        with self.assertRaises(pt.PartitionError):
            pt.parse_build_json([artifact(['test'], 'a b;rm', p)])


class ClassifyTests(Base):
    def cls(self, name, text):
        p = self.write_src(name, text)
        e = pt.Exe('test', name, str(p), '/x/' + name)
        pt.classify(e)
        return e

    def test_plain_is_b(self):
        e = self.cls('plain', 'fn main() { let _ = 1; }')
        self.assertEqual((e.cls, e.shared), ('b', []))

    def test_postgres_tokens_are_a(self):
        for i, tok in enumerate(['AI_MEMORY_TEST_POSTGRES_URL', 'sqlx::query', 'PgPool',
                                 '#[cfg(feature = "sal-postgres")]', 'PostgresStore',
                                 'common::lane_db::x']):
            self.assertEqual(self.cls('pg%d' % i, 'use %s;' % tok if 'cfg' not in tok else tok).cls, 'a', tok)

    def test_serial_is_a(self):
        self.assertEqual(self.cls('ser', '#[serial]\nfn t() {}').cls, 'a')
        self.assertEqual(self.cls('ser2', 'use serial_test::serial;').cls, 'a')

    def test_federat_name_is_a(self):
        e = self.cls('federation_scale', 'fn x() {}')
        self.assertEqual(e.cls, 'a')
        self.assertIn('name:federat', e.reasons)

    def test_unknown_source_is_a(self):
        e = pt.Exe('test', 'ghost', str(SCRATCH / 'tests' / 'ghost.rs'), '/x/ghost')
        pt.classify(e)
        self.assertEqual((e.cls, e.reasons), ('a', ['unknown-source']))
        e2 = pt.Exe('test', 'nopath', '', '/x/nopath')
        pt.classify(e2)
        self.assertEqual(e2.cls, 'a')

    def test_module_directory_is_scanned(self):
        p = self.write_src('modded', 'mod helpers;')
        d = SCRATCH / 'tests' / 'modded'
        d.mkdir()
        (d / 'helpers.rs').write_text('use sqlx::PgPool;')
        e = pt.Exe('test', 'modded', str(p), '/x/m')
        pt.classify(e)
        self.assertEqual(e.cls, 'a')

    def test_main_rs_target_scans_its_directory(self):
        d = SCRATCH / 'tests' / 'dirtest'
        d.mkdir()
        (d / 'main.rs').write_text('mod a;')
        (d / 'a.rs').write_text('#[serial]')
        e = pt.Exe('test', 'dirtest', str(d / 'main.rs'), '/x/d')
        pt.classify(e)
        self.assertEqual(e.cls, 'a')

    def test_ports_and_shared_paths_mark_shared(self):
        self.assertEqual(self.cls('portly', 'let u = "http://127.0.0.1:11434/x";').shared, ['port'])
        self.assertEqual(self.cls('pathy', 'let p = "/tmp/shared.db";').shared, ['shared-path'])
        self.assertEqual(self.cls('ephemeral', 'bind("127.0.0.1:0")').shared, [])


class PartitionTests(Base):
    def build(self, specs, lib=True):
        lines = []
        if lib:
            lines.append(artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib'))
        for name, text in specs.items():
            lines.append(artifact(['test'], name, self.write_src(name, text), '/x/' + name))
        return pt.parse_build_json(lines)

    def weights(self, **kw):
        w = {'lib:pg': 5.0, 'lib:nonpg': 100.0}
        w.update({'test:' + k: v for k, v in kw.items()})
        return w

    def test_disjoint_and_complete(self):
        exes = self.build({'a1': 'PgPool', 'b1': '', 'b2': '', 'b3': '', 'federation_x': ''})
        serial, h1, h2, has_lib, totals, _ = pt.partition(
            exes, self.weights(a1=1, b1=40, b2=30, b3=20, federation_x=2), ['store::postgres'])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        pt.verify_written(SCRATCH / 'out', exes)
        self.assertEqual({e.name for e in serial}, {'a1', 'federation_x'})
        self.assertEqual({e.name for e in h1} | {e.name for e in h2}, {'b1', 'b2', 'b3'})
        self.assertTrue((SCRATCH / 'out' / 'serial.txt').read_text().startswith('--lib\n'))
        self.assertTrue((SCRATCH / 'out' / 'parallel_1.txt').read_text().startswith('--lib\n'))
        self.assertNotIn('--lib', (SCRATCH / 'out' / 'parallel_2.txt').read_text())

    def test_balance_prefers_the_lighter_half(self):
        exes = self.build({'b1': '', 'b2': '', 'b3': ''})
        _, h1, h2, _, totals, _ = pt.partition(exes, self.weights(b1=90, b2=60, b3=50), [])
        # half 1 starts with the lib (100): 90 and 60 go to half 2 (0, then 90 < 100), 50 to half 1.
        self.assertEqual(sorted(e.name for e in h2), ['b1', 'b2'])
        self.assertEqual([e.name for e in h1], ['b3'])
        self.assertAlmostEqual(totals['parallel_1'], 150.0)
        self.assertAlmostEqual(totals['parallel_2'], 150.0)

    def test_shared_binaries_share_one_half(self):
        exes = self.build({'p1': 'x = "127.0.0.1:9077"', 'p2': 'f = "/tmp/x"', 'p3': '"localhost:5555"',
                           'f1': '', 'f2': '', 'f3': ''})
        _, h1, h2, _, _, _ = pt.partition(
            exes, self.weights(p1=50, p2=50, p3=50, f1=40, f2=40, f3=40), [])
        halves = [{e.name for e in h1}, {e.name for e in h2}]
        homes = [i for i, h in enumerate(halves) if {'p1', 'p2', 'p3'} & h]
        self.assertEqual(len(homes), 1)
        self.assertTrue({'p1', 'p2', 'p3'} <= halves[homes[0]])

    def test_unmeasured_uses_class_mean(self):
        exes = self.build({'b1': '', 'new_b': '', 'a1': 'PgPool', 'new_a': '#[serial]'})
        _, _, _, _, totals, means = pt.partition(exes, self.weights(b1=10, a1=30), [])
        self.assertEqual(means, {'a': 30.0, 'b': 10.0})
        self.assertAlmostEqual(totals['serial'], 5.0 + 30.0 + 30.0)

    def test_verify_catches_overlap_and_missing(self):
        exes = self.build({'b1': '', 'b2': ''})
        serial, h1, h2, has_lib, _, _ = pt.partition(exes, self.weights(b1=1, b2=1), [])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        p1 = SCRATCH / 'out' / 'parallel_1.txt'
        p2 = SCRATCH / 'out' / 'parallel_2.txt'
        both = (p1.read_text() + p2.read_text()).replace('--lib\n', '')
        # overlap: duplicate a line into the other half
        line = [l for l in both.splitlines() if l][0]
        p2.write_text(p2.read_text() + line + '\n')
        p1.write_text(p1.read_text() + line + '\n')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)
        # missing: drop everything but --lib from both halves
        p1.write_text('--lib\n')
        p2.write_text('')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)

    def test_lib_misplacement_is_caught(self):
        exes = self.build({'b1': ''})
        serial, h1, h2, has_lib, _, _ = pt.partition(exes, self.weights(b1=1), [])
        pt.write_lists(SCRATCH / 'out', serial, h1, h2, has_lib)
        (SCRATCH / 'out' / 'parallel_2.txt').write_text('--lib\n')
        with self.assertRaises(pt.PartitionError):
            pt.verify_written(SCRATCH / 'out', exes)

    def test_deterministic(self):
        specs = {'b%d' % i: '' for i in range(12)}
        w = self.weights(**{'b%d' % i: float(i % 5 + 1) for i in range(12)})
        runs = []
        for _ in range(2):
            exes = self.build(specs)
            _, h1, h2, _, _, _ = pt.partition(exes, w, [])
            runs.append(([e.name for e in h1], [e.name for e in h2]))
        self.assertEqual(runs[0], runs[1])


class LibPrefixTests(Base):
    def test_covered_and_uncovered_modules(self):
        src = SCRATCH / 'src'
        (src / 'store').mkdir()
        (src / 'store' / 'postgres.rs').write_text('std::env::var("AI_MEMORY_TEST_POSTGRES_URL")')
        (src / 'store' / 'postgres').mkdir()
        (src / 'store' / 'postgres' / 'tx_retry.rs').write_text('env::var("AI_MEMORY_TEST_POSTGRES_URL")')
        (src / 'newmod.rs').write_text('std::env::var( "AI_MEMORY_TEST_POSTGRES_URL" )')
        (src / 'commentonly.rs').write_text('// reads `AI_MEMORY_TEST_POSTGRES_URL` in docs')
        self.assertEqual(pt.uncovered_lib_pg_modules(src, ['store::postgres']), ['newmod'])
        # r1 B2: a prefix naming one test inside newmod does not cover a
        # module-level read (a helper any test in newmod may call).
        self.assertEqual(pt.uncovered_lib_pg_modules(src, ['store::postgres', 'newmod::t']), ['newmod'])
        self.assertEqual(pt.uncovered_lib_pg_modules(src, ['store::postgres', 'newmod']), [])

    def test_module_path(self):
        root = Path('/r/src')
        self.assertEqual(pt.module_path_of(Path('/r/src/store/postgres.rs'), root), 'store::postgres')
        self.assertEqual(pt.module_path_of(Path('/r/src/cli/mod.rs'), root), 'cli')

    def test_real_tree_has_no_uncovered_lib_pg_module(self):
        prefixes = pt.load_prefixes(HERE.parent / 'lib_pg_prefixes.txt')
        self.assertTrue(prefixes)
        self.assertEqual(pt.uncovered_lib_pg_modules(REPO / 'src', prefixes), [])

    def test_run_fails_closed_without_prefixes(self):
        lines = [artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib')]
        (SCRATCH / 'b.jsonl').write_text('\n'.join(lines))
        (SCRATCH / 'empty.txt').write_text('# none\n')
        rc = pt.main(['--build-json', str(SCRATCH / 'b.jsonl'), '--out-dir', str(SCRATCH / 'out'),
                      '--repo-root', str(SCRATCH), '--lib-pg-prefixes', str(SCRATCH / 'empty.txt')])
        self.assertEqual(rc, 2)


def fx(rel, text):
    """Write a fixture file under SCRATCH (parents created) and return its path."""
    p = SCRATCH / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def exe_for(rel):
    name = Path(rel).stem if Path(rel).name != 'main.rs' else Path(rel).parent.name
    return pt.Exe('test', name, str(SCRATCH / rel), '/x/' + name)


PG_TEST = ('#[cfg(feature = "sal-postgres")]\n#[tokio::test]\nasync fn native_pg() {\n'
           '    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap();\n    let _ = url;\n}\n')


class ModGraphTests6344B1(Base):
    """r1 B1: classify on the union of every file the target compiles."""

    def test_path_mod_pulls_a_postgres_submodule_skill_promote_shape_6344(self):
        # Mirrors tests/skill_promote_test.rs:580 -> skill_promote_visibility_3551/
        # {mod.rs, http.rs}, whose http.rs holds a sal-postgres test.
        fx('tests/skill_promote_test.rs',
           'fn plain() {}\n#[path = "skill_promote_visibility_3551/mod.rs"]\nmod visibility_3551;\n')
        fx('tests/skill_promote_visibility_3551/mod.rs',
           '#[cfg(feature = "sal")]\nmod http;\n#[path = "../common/mcp_wait.rs"]\nmod mcp_wait;\n')
        fx('tests/skill_promote_visibility_3551/http.rs', PG_TEST)
        fx('tests/common/mcp_wait.rs', 'pub fn wait() {}\n')
        e = exe_for('tests/skill_promote_test.rs')
        pt.classify(e)
        self.assertEqual(e.cls, 'a', e.reasons)
        # The same through the partition (shared-helper index) path.
        exes = pt.parse_build_json([artifact(['test'], 'skill_promote_test', SCRATCH / 'tests/skill_promote_test.rs')])
        serial, h1, h2, _, _, _ = pt.partition(exes, {}, [])
        self.assertEqual(([x.name for x in serial], h1, h2), (['skill_promote_test'], [], []))

    def test_name_rs_and_name_mod_rs_and_nested_forms_6344(self):
        cases = {
            'flat': ('tests/flat.rs', 'mod a;', {'tests/flat/a.rs': PG_TEST}),
            'dirmod': ('tests/dirmod.rs', 'mod a;', {'tests/dirmod/a/mod.rs': 'mod b;',
                                                      'tests/dirmod/a/b.rs': PG_TEST}),
            'inline': ('tests/inline.rs', 'mod outer {\n    mod deep;\n}\n',
                       {'tests/inline/outer/deep.rs': PG_TEST}),
            'up': ('tests/up.rs', '#[path = "../shared_pg/x.rs"]\nmod x;\n', {'shared_pg/x.rs': PG_TEST}),
            'inc': ('tests/inc.rs', 'include!("frag/inc_body.rs");\n', {'tests/frag/inc_body.rs': PG_TEST}),
        }
        for name, (root, text, extra) in cases.items():
            fx(root, text)
            for rel, body in extra.items():
                fx(rel, body)
            e = exe_for(root)
            pt.classify(e)
            self.assertEqual(e.cls, 'a', '%s: %s' % (name, e.reasons))

    def test_unresolved_mod_fails_closed_6344(self):
        fx('tests/ghostly.rs', 'mod missing_helper;\nfn t() {}\n')
        e = exe_for('tests/ghostly.rs')
        pt.classify(e)
        self.assertEqual(e.cls, 'a')
        self.assertIn('unresolved-mod', e.reasons)

    def test_masked_mod_text_is_not_followed_6344(self):
        fx('tests/masked.rs', '// mod ghost_a;\n/* mod ghost_b; /* nested */ */\n'
           'const S: &str = "mod ghost_c;";\nconst R: &str = r#"mod ghost_d; "quoted""#;\n'
           "fn f<'a>(x: &'a str) -> char { let _ = x; '{' }\nfn g() {}\n")
        units, unresolved = pt.walk_crate(SCRATCH / 'tests/masked.rs')
        self.assertEqual(unresolved, [])
        self.assertEqual(len(units), 1)

    def test_mod_inside_fn_body_is_not_a_file_6344(self):
        fx('tests/fnbody.rs', 'fn t() {\n    mod local { pub fn x() {} }\n    local::x();\n}\n')
        self.assertEqual(pt.walk_crate(SCRATCH / 'tests/fnbody.rs')[1], [])


class SharedHelperTests6344B1(Base):
    """Files two binaries compile (tests/common) count per referenced item."""

    def setUp(self):
        super().setUp()
        fx('tests/common/mod.rs',
           'pub mod pgkit;\n'
           'pub fn plain_helper() -> u8 { 1 }\n'
           'pub fn pg_url() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n'
           'pub fn connect_like() -> String { pg_url() }\n'
           'pub use self::pgkit::Guard as PgGuard;\n')
        fx('tests/common/pgkit.rs',
           'pub struct Guard;\nimpl Guard { pub fn new() -> Self { let _ = sqlx::query("SELECT 1"); Guard } }\n'
           '#[test]\nfn url_predicate_is_pure() { assert!(is_pg("postgres://u@h/db")); }\n'
           'fn is_pg(u: &str) -> bool { u.starts_with("postgres") }\n')

    def run_part(self, bins):
        lines = [artifact(['test'], n, fx('tests/%s.rs' % n, body)) for n, body in bins.items()]
        exes = pt.parse_build_json(lines)
        pt.partition(exes, {}, [])
        return {e.name: e for e in exes}

    def test_binary_calling_a_postgres_helper_is_serial_6344(self):
        got = self.run_part({
            'uses_pg': 'mod common;\n#[test]\nfn t() { let _ = common::connect_like(); }\n',
            'uses_plain': 'mod common;\n#[test]\nfn t() { assert_eq!(common::plain_helper(), 1); }\n',
            'uses_alias': 'mod common;\n#[test]\nfn t() { let _g = common::PgGuard::new(); }\n',
        })
        self.assertEqual(got['uses_pg'].cls, 'a', got['uses_pg'].reasons)
        self.assertTrue(any(r.startswith('pg-helper:') for r in got['uses_pg'].reasons), got['uses_pg'].reasons)
        self.assertEqual(got['uses_alias'].cls, 'a', got['uses_alias'].reasons)
        self.assertEqual(got['uses_plain'].cls, 'b', got['uses_plain'].reasons)

    def test_postgres_test_declared_in_a_shared_file_moves_every_includer_6344(self):
        fx('tests/common/live.rs', '#[tokio::test]\nasync fn live_pg_roundtrip() { let _ = super::pg_url(); }\n')
        mod = (SCRATCH / 'tests/common/mod.rs').read_text()
        (SCRATCH / 'tests/common/mod.rs').write_text(mod + 'mod live;\n')
        got = self.run_part({'one': 'mod common;\nfn t() {}\n', 'two': 'mod common;\nfn t() {}\n'})
        self.assertEqual((got['one'].cls, got['two'].cls), ('a', 'a'), (got['one'].reasons, got['two'].reasons))

    def test_pure_shared_unit_test_naming_a_postgres_url_stays_parallel_6344(self):
        got = self.run_part({'one': 'mod common;\nfn t() {}\n', 'two': 'mod common;\nfn t() {}\n'})
        self.assertEqual((got['one'].cls, got['two'].cls), ('b', 'b'), (got['one'].reasons, got['two'].reasons))


class LibGateBypassTests6344B2(Base):
    """r1 B2: the three reviewer bypass cases of uncovered_lib_pg_modules."""

    def test_single_test_prefix_does_not_cover_its_whole_module_6344(self):
        fx('src/daemon_runtime.rs',
           'fn pg_helper() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n'
           '#[cfg(test)]\nmod cov {\n    #[test]\n    fn one_pg_test() {\n'
           '        let _ = std::env::var("AI_MEMORY_TEST_POSTGRES_URL");\n    }\n}\n')
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['daemon_runtime::cov::one_pg_test']),
                         ['daemon_runtime'])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['daemon_runtime']), [])

    def test_child_prefix_does_not_cover_the_parent_module_6344(self):
        fx('src/store/mod.rs', 'fn t() { let _ = std::env::var("AI_MEMORY_TEST_POSTGRES_URL"); }\n')
        fx('src/store/postgres.rs', 'fn t() { let _ = std::env::var("AI_MEMORY_TEST_POSTGRES_URL"); }\n')
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['store::postgres']), ['store'])

    def test_const_indirected_env_read_is_detected_6344(self):
        fx('src/atomicity_tests.rs',
           'const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";\n'
           '#[cfg(test)]\nmod pg {\n    #[test]\n    fn crash() { let _ = std::env::var(super::PG_URL_ENV); }\n}\n')
        fx('src/consts.rs', 'pub static PG_VAR: &str = "AI_MEMORY_TEST_POSTGRES_URL";\n')
        fx('src/user.rs', 'fn live() { let _ = std::env::var(crate::consts::PG_VAR); }\n')
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', []),
                         ['atomicity_tests', 'atomicity_tests::pg::crash', 'consts', 'user'])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['atomicity_tests', 'consts']), ['user'])

    def test_comments_do_not_count_and_test_fn_paths_are_exact_6344(self):
        fx('src/lib.rs', 'mod mcp;\n')
        fx('src/mcp/mod.rs', '#[path = "tools/store_tool.rs"]\nmod store_tool;\n')
        fx('src/mcp/tools/store_tool.rs',
           '// AI_MEMORY_TEST_POSTGRES_URL in a comment\n'
           '#[cfg(test)]\nmod tests {\n    #[tokio::test]\n    async fn live_store() {\n'
           '        let _ = std::env::var("AI_MEMORY_TEST_POSTGRES_URL");\n    }\n}\n')
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['mcp::tools::store_tool']),
                         ['mcp::store_tool::tests::live_store'])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['mcp::store_tool::tests::live_']), [])


class LibGateFollowUps6344R2(Base):
    """review r2 F2/F3/F4."""

    def test_cfg_test_helper_is_not_a_test_fn_6344_f3(self):
        for yes in ('#[test]', '#[tokio::test]', '#[tokio::test(flavor = "multi_thread")]', '#[sqlx::test]',
                    '#[rstest]', '#[test_log::test]', '#[test_case(1)]'):
            self.assertTrue(pt.TEST_ATTR_RE.search(yes), yes)
        for no in ('#[cfg(test)]', '#[cfg(all(test, unix))]', '#[cfg_attr(test, derive(Debug))]',
                   '#[derive(Debug)]', '#[serial]', '#[ignore]'):
            self.assertFalse(pt.TEST_ATTR_RE.search(no), no)
        fx('src/m.rs',
           '#[cfg(test)]\nfn pg_url() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n')
        # the helper is not a test fn: a prefix naming it must not "cover" it
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['m::pg_url']), ['m'])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['m']), [])

    def test_caller_of_a_cross_module_pg_helper_counts_as_postgres_6344_f2(self):
        fx('src/lib.rs', 'mod support;\nmod a;\n')
        fx('src/support.rs',
           'pub(crate) fn live_pg_url() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n')
        fx('src/a.rs',
           '#[cfg(test)]\nmod tests {\n    #[test]\n    fn talks_to_pg() { let _ = crate::support::live_pg_url(); }\n'
           '    #[test]\n    fn pure() { assert_eq!(1, 1); }\n}\n')
        got = pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['support'])
        self.assertEqual(got, ['a::tests::talks_to_pg'])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['support', 'a::tests::talks_to_pg']), [])
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['support', 'a']), [])

    def test_parallel_estimate_divides_by_min_tests_and_threads_6344_f4(self):
        specs = {'single': '#[test]\nfn one() {}\n',
                 'many': ''.join('#[test]\nfn t%d() {}\n' % i for i in range(6)),
                 'pair': '#[test]\nfn p1() {}\n#[test]\nfn p2() {}\n'}
        lines = [artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib')]
        for name, text in specs.items():
            lines.append(artifact(['test'], name, fx('tests/%s.rs' % name, text), '/x/' + name))
        w = {'lib:pg': 0.0, 'lib:nonpg': 300.0, 'test:single': 30.0, 'test:many': 30.0, 'test:pair': 30.0}
        exes = pt.parse_build_json(lines)
        totals = pt.partition(exes, w, [])[4]
        # all three binaries land in the half with the lib-free base (parallel_2)
        self.assertEqual(totals['parallel_2'], 90.0)
        self.assertEqual(totals['parallel_1'], 300.0)
        self.assertEqual(totals['parallel_2_est'], 30.0 + 10.0 + 15.0)
        self.assertEqual(totals['parallel_1_est'], 100.0)

    def test_unknown_test_count_falls_back_to_the_thread_count_6344_f4(self):
        exes = pt.parse_build_json([artifact(['test'], 'macro_gen', fx('tests/macro_gen.rs', 'gen_tests!();\n'))])
        totals = pt.partition(exes, {'test:macro_gen': 30.0}, [])[4]
        self.assertEqual(totals['parallel_1_est'] + totals['parallel_2_est'], 10.0)


class LibCallerResolution6412(Base):
    """#6412: callers of a Postgres helper are followed by resolved path, not bare name."""

    HELPER = 'pub(crate) fn live_pg_url() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() }\n'

    @staticmethod
    def in_tests(body):
        return '#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { %s }\n}\n' % body

    def gate(self, a_rs, prefixes=('support',)):
        fx('src/lib.rs', 'mod support;\nmod a;\n')
        fx('src/support.rs', self.HELPER)
        fx('src/a.rs', a_rs)
        return pt.uncovered_lib_pg_modules(SCRATCH / 'src', list(prefixes))

    def test_same_named_unrelated_fn_is_not_a_pg_site_6412(self):
        a = 'fn live_pg_url() -> &\'static str { "x" }\n' + self.in_tests('let _ = live_pg_url();')
        self.assertEqual(self.gate(a), [])

    def test_same_named_method_is_not_a_pg_site_6412(self):
        a = ('struct S;\nimpl S { fn live_pg_url(&self) -> u8 { 0 } }\n'
             + self.in_tests('let _ = S.live_pg_url();'))
        self.assertEqual(self.gate(a), [])

    def test_name_in_string_literal_or_comment_is_not_a_pg_site_6412(self):
        a = '// live_pg_url() in a comment\n' + self.in_tests('let _s = "live_pg_url()";')
        self.assertEqual(self.gate(a), [])

    def test_aliased_import_is_a_pg_site_6412(self):
        a = 'use crate::support::live_pg_url as u;\n' + self.in_tests('let _ = super::u();')
        self.assertEqual(self.gate(a), ['a::tests::t'])
        self.assertEqual(self.gate(a, ['support', 'a::tests::t']), [])

    def test_aliased_group_import_and_module_alias_are_pg_sites_6412(self):
        group = 'use crate::support::{live_pg_url as u};\n' + self.in_tests('let _ = super::u();')
        self.assertEqual(self.gate(group), ['a::tests::t'])
        modal = 'use crate::support as s;\n' + self.in_tests('let _ = super::s::live_pg_url();')
        self.assertEqual(self.gate(modal), ['a::tests::t'])

    def test_glob_and_plain_imports_are_pg_sites_6412(self):
        a = 'use crate::support::live_pg_url;\n' + self.in_tests('let _ = super::live_pg_url();')
        self.assertEqual(self.gate(a), ['a::tests::t'])
        b = 'use crate::support::*;\nfn wrap() -> String { live_pg_url() }\n'
        self.assertEqual(self.gate(b), ['a'])

    def test_function_passed_by_name_without_a_call_is_a_pg_site_6412(self):
        a = self.in_tests('let f = crate::support::live_pg_url; let _ = f;')
        self.assertEqual(self.gate(a), ['a::tests::t'])
        b = self.in_tests('run(crate::support::live_pg_url);')
        self.assertEqual(self.gate(b), ['a::tests::t'])

    def test_qualified_and_spaced_calls_still_resolve_6412(self):
        for call in ('crate::support::live_pg_url()', 'crate::support::live_pg_url ()',
                     'crate :: support :: live_pg_url::<>()'):
            self.assertEqual(self.gate(self.in_tests('let _ = %s;' % call)), ['a::tests::t'], call)

    def test_qualifier_that_resolves_elsewhere_is_not_a_pg_site_6412(self):
        a = self.in_tests('let _ = other::live_pg_url();')
        self.assertEqual(self.gate(a), [])

    def test_helper_defined_as_a_method_stays_fail_closed_6412(self):
        fx('src/lib.rs', 'mod support;\nmod a;\n')
        fx('src/support.rs', 'pub struct H;\nimpl H { pub fn url(&self) -> String '
           '{ std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() } }\n')
        fx('src/a.rs', self.in_tests('let _ = crate::support::H.url();'))
        self.assertEqual(pt.uncovered_lib_pg_modules(SCRATCH / 'src', ['support']), ['a::tests::t'])


class LibCallerTransitive6412(Base):
    """#6412 r2 (review HIGH-1): resolution follows `use`, globs and re-exports transitively and fails closed."""

    HELPER = LibCallerResolution6412.HELPER

    @staticmethod
    def with_tests(body, pre=''):
        return '#[cfg(test)]\nmod tests {\n    %s\n    #[test]\n    fn t() { %s }\n}\n' % (pre, body)

    def gate(self, files, prefixes=('support',)):
        mods = ['support'] + sorted({k.split('/')[0].split('.')[0] for k in files})
        fx('src/lib.rs', ''.join('mod %s;\n' % m for m in mods))
        fx('src/support.rs', self.HELPER
           + 'pub mod tests_support { pub fn pgurl() -> String { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").unwrap() } }\n')
        for k, v in files.items():
            fx('src/' + k, v)
        return pt.uncovered_lib_pg_modules(SCRATCH / 'src', list(prefixes))

    def test_c1_super_glob_reaches_parents_plain_import_6412(self):
        a = 'use crate::support::live_pg_url;\n' + self.with_tests('let _ = live_pg_url();', 'use super::*;')
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_c2_super_glob_reaches_parents_glob_import_6412(self):
        a = 'use crate::support::*;\n' + self.with_tests('let _ = live_pg_url();', 'use super::*;')
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_c3_super_glob_reaches_parents_alias_6412(self):
        a = 'use crate::support::live_pg_url as u;\n' + self.with_tests('let _ = u();', 'use super::*;')
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_r1_plain_use_of_a_reexport_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::re::live_pg_url;'),
                 're.rs': 'pub(crate) use crate::support::live_pg_url;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_r2_glob_use_of_a_reexport_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::re::*;'),
                 're.rs': 'pub use crate::support::live_pg_url;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_r3_plain_use_of_a_glob_reexport_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::re::live_pg_url;'),
                 're.rs': 'pub use crate::support::*;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_k1_use_super_super_helper_from_a_child_file_module_6412(self):
        files = {'a.rs': 'use crate::support::live_pg_url;\nmod b;\n',
                 'a/b.rs': self.with_tests('let _ = live_pg_url();', 'use super::super::live_pg_url;')}
        self.assertEqual(self.gate(files), ['a::b::tests::t'])

    def test_reexport_cycle_terminates_and_stays_clean_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::re::*;'),
                 're.rs': 'pub use crate::a::*;\n'}
        self.assertEqual(self.gate(files), [])

    def test_reexport_cycle_still_finds_the_helper_6412(self):
        files = {'a.rs': 'pub use crate::re::*;\n' + self.with_tests('let _ = live_pg_url();', 'use crate::re::*;'),
                 're.rs': 'pub use crate::a::*;\npub use crate::support::live_pg_url;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_unresolvable_in_crate_glob_is_fail_closed_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::Kind::*;')}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_external_glob_is_not_a_caller_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use some_extern_crate::*;')}
        self.assertEqual(self.gate(files), [])

    # probe cases from the review that must stay green
    def test_local_fn_shadows_a_glob_6412(self):
        a = 'use crate::support::*;\nfn live_pg_url() -> u8 { 0 }\n' + self.with_tests('let _ = super::live_pg_url();')
        self.assertEqual(self.gate({'a.rs': a}), [])

    def test_local_fn_shadows_through_super_glob_6412(self):
        a = ('use crate::support::*;\nfn live_pg_url() -> u8 { 0 }\n'
             + self.with_tests('let _ = live_pg_url();', 'use super::*;'))
        self.assertEqual(self.gate({'a.rs': a}), [])

    def test_path_expression_without_use_6412(self):
        a = self.with_tests('let _ = crate::support::live_pg_url();')
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_alias_inside_a_test_fn_6412(self):
        a = self.with_tests('use crate::support::live_pg_url as u; let _ = u();')
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_nested_group_with_self_6412(self):
        a = ('use crate::{support::{self, live_pg_url}};\n'
             + self.with_tests('let _ = super::support::live_pg_url(); let _ = super::live_pg_url();'))
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_renamed_reexport_through_a_qualified_path_6412(self):
        files = {'a.rs': self.with_tests('let _ = crate::re::pg();'),
                 're.rs': 'pub use crate::support::live_pg_url as pg;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_renamed_reexport_then_plain_use_6412(self):
        files = {'a.rs': self.with_tests('let _ = pg();', 'use crate::re::pg;'),
                 're.rs': 'pub use crate::support::live_pg_url as pg;\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_two_globs_one_offering_the_name_is_flagged_6412(self):
        files = {'a.rs': self.with_tests('let _ = live_pg_url();', 'use crate::support::*; use crate::other::*;'),
                 'other.rs': 'pub fn x() {}\n'}
        self.assertEqual(self.gate(files), ['a::tests::t'])

    def test_struct_literal_pass_by_name_6412(self):
        a = ('use crate::support::live_pg_url;\nstruct C { f: fn() -> String }\n'
             + self.with_tests('let _ = C { f: super::live_pg_url };'))
        self.assertEqual(self.gate({'a.rs': a}), ['a::tests::t'])

    def test_same_module_macro_flags_the_module_6412(self):
        a = ('macro_rules! m { () => { crate::support::live_pg_url() } }\n'
             + self.with_tests('let _ = m!();'))
        self.assertIn('a', self.gate({'a.rs': a}))

    def test_helper_defined_in_parent_module_is_flagged_6412(self):
        a = ('fn h() -> String { crate::support::live_pg_url() }\n'
             + self.with_tests('let _ = h();', 'use super::*;'))
        self.assertEqual(self.gate({'a.rs': a}), ['a'])


class LibMacroCaller6425(Base):
    """#6425 (review MEDIUM-1): a macro whose body reaches the Postgres URL records its invoking tests."""

    HELPER = LibCallerResolution6412.HELPER
    with_tests = staticmethod(LibCallerTransitive6412.with_tests)
    gate = LibCallerTransitive6412.gate
    EXPORTED = '#[macro_export]\nmacro_rules! mm { () => { $crate::support::live_pg_url() } }\n'

    def test_exported_macro_in_another_module_records_the_invoking_test_6425(self):
        files = {'a.rs': self.with_tests('let _ = crate::mm!();'), 're.rs': self.EXPORTED}
        self.assertEqual(self.gate(files), ['a::tests::t', 're'])
        self.assertEqual(self.gate(files, ['support', 'a::tests::t', 're']), [])

    def test_bare_macro_name_invocation_is_recorded_6425(self):
        files = {'a.rs': 'use crate::mm;\n' + self.with_tests('let _ = mm!();', 'use super::*;'), 're.rs': self.EXPORTED}
        self.assertEqual(self.gate(files), ['a::tests::t', 're'])

    def test_macro_that_names_the_url_directly_records_the_invoking_test_6425(self):
        files = {'a.rs': self.with_tests('let _ = crate::raw!();'),
                 're.rs': '#[macro_export]\nmacro_rules! raw { () => { std::env::var("AI_MEMORY_TEST_POSTGRES_URL") } }\n'}
        self.assertEqual(self.gate(files, ['support', 're']), ['a::tests::t'])

    def test_macro_calling_a_hot_macro_is_hot_6425(self):
        files = {'a.rs': self.with_tests('let _ = crate::outer!();'),
                 're.rs': self.EXPORTED + '#[macro_export]\nmacro_rules! outer { () => { $crate::mm!() } }\n'}
        self.assertEqual(self.gate(files, ['support', 're']), ['a::tests::t'])

    def test_macro_without_the_helper_records_nothing_6425(self):
        files = {'a.rs': self.with_tests('let _ = crate::cold!();'),
                 're.rs': '#[macro_export]\nmacro_rules! cold { () => { 1 } }\n'}
        self.assertEqual(self.gate(files), [])

    def test_macro_body_that_cannot_be_delimited_is_fail_closed_6425(self):
        files = {'a.rs': self.with_tests('let _ = crate::broken!();'),
                 're.rs': '#[macro_export]\nmacro_rules! broken { () => { 1 }\n'}
        self.assertIn('a::tests::t', self.gate(files))


class DocEstimateTests6344B6(Base):
    def test_doc_tests_are_in_the_serial_estimate_6344(self):
        exes = pt.parse_build_json([artifact(['lib'], 'ai_memory', SCRATCH / 'src' / 'lib.rs', '/x/lib'),
                                    artifact(['test'], 'a1', fx('tests/a1.rs', 'PgPool'))])
        w = {'lib:pg': 5.0, 'lib:nonpg': 10.0, 'doc:tests': 16.0, 'test:a1': 2.0}
        self.assertEqual(pt.partition(exes, w, ['x'], with_doc=True)[4]['serial'], 23.0)
        self.assertEqual(pt.partition(exes, w, ['x'], with_doc=False)[4]['serial'], 7.0)
        self.assertGreater(pt.load_weights(HERE.parent / 'test_binary_weights.json').get('doc:tests', 0), 0)


class WeightTableTests(unittest.TestCase):
    def test_vendored_table_is_well_formed(self):
        w = pt.load_weights(HERE.parent / 'test_binary_weights.json')
        self.assertIn('lib:pg', w)
        self.assertIn('lib:nonpg', w)
        self.assertTrue(all(v >= 0 for v in w.values()))


if __name__ == '__main__':
    unittest.main()
