#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_shared_test_db_refs.py (#7031 H4)."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / 'scripts' / 'ci' / 'check_shared_test_db_refs.py'
NAME = 'ai_memory' + '_test'  # built so this file never matches its own gate
SCRATCH = ROOT / '.local-runs'
GATE_LINE_SCAN_BUDGET_SECS = 5.0  # the gate must scan one adversarial line this fast (#7031 S1)
ADVERSARIAL_LINE_BYTES = 1 << 20  # one MiB on a single line
CONTINUATION_SCAN_BUDGET_SECS = 2.0  # one MiB of continuation lines must scan this fast (#7171)
EXIT_CLEAN, EXIT_VIOLATION, EXIT_USAGE = 0, 1, 2
COUPLED_PATH = 'scripts/ci/tests/test_pg_isolated_binary.py'
COUPLED_MARK = '[landing-order #7088]'
LANDING_ORDER_MARKERS_MAX = 0  # the landing-order exception is retired: no marked pin may exist (#7884)


def gate(root: Path, *extra: str, timeout: Optional[float] = None) -> 'subprocess.CompletedProcess[str]':
    return subprocess.run([sys.executable, str(GATE), '--root', str(root)] + list(extra),
                          capture_output=True, text=True, check=False, timeout=timeout)


class SharedTestDbRefs7031(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        (self.dir / 'allow.txt').write_text('', encoding='utf-8')

    def mutant(self, text: str, name: str = 'm.txt') -> 'subprocess.CompletedProcess[str]':
        (self.dir / name).write_text(text + '\n', encoding='utf-8')
        return gate(self.dir, '--paths', name, '--allowlist', str(self.dir / 'allow.txt'))

    def test_real_tree_passes_with_allowlist(self) -> None:
        done = gate(ROOT)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_r1_url_literal(self) -> None:
        done = self.mutant('url = "postgres://u:p@h:5445/%s"' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('::error file=m.txt,line=1::R1', done.stdout)

    def test_r2_postgres_db(self) -> None:
        done = self.mutant('  POSTGRES_DB: %s' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R2', done.stdout)

    def test_r3_db_flag(self) -> None:
        done = self.mutant('psql -U u -d %s -c x' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R3', done.stdout)

    def test_r4_pg_isready(self) -> None:
        done = self.mutant('pg_isready -U u -d %s' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn('R4', done.stdout)

    def test_prefixed_ephemeral_names_never_match(self) -> None:
        done = self.mutant('psql -d %s_ci_1_1_cov\nurl = "postgres://h/%s_p2_9"' % (NAME, NAME))
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_comment_only_lines_never_match(self) -> None:
        text = '\n'.join(['# psql -d %s' % NAME, '// "postgres://h/%s"' % NAME,
                          '  //! pg_isready -d %s' % NAME])
        done = self.mutant(text)
        self.assertEqual(done.returncode, 0, done.stdout)
        done = self.mutant('-- POSTGRES_DB=%s' % NAME, name='m.sql')
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_allowlist_whole_file_and_line(self) -> None:
        (self.dir / 'allow.txt').write_text('m.txt:1  # cited\n', encoding='utf-8')
        done = self.mutant('url = "postgres://h/%s"' % NAME)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_stale_allowlist_entry_exits_2(self) -> None:
        (self.dir / 'allow.txt').write_text('m.txt:1  # nothing matches\n', encoding='utf-8')
        done = self.mutant('clean line')
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('stale allowlist entry', done.stderr)

    def test_list_mode_exits_0(self) -> None:
        (self.dir / 'm.txt').write_text('POSTGRES_DB=%s\n' % NAME, encoding='utf-8')
        done = gate(self.dir, '--paths', 'm.txt', '--allowlist', str(self.dir / 'allow.txt'), '--list')
        self.assertEqual(done.returncode, 0)
        self.assertIn('m.txt:1 R2', done.stdout)

    # --- review findings F1-F10 (PR #7085) ---
    def test_f1_non_utf8_file_is_scanned(self) -> None:
        (self.dir / 'm.bin').write_bytes(b'# caf\xe9\npsql -d ' + NAME.encode() + b'\n')
        done = gate(self.dir, '--paths', 'm.bin', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('line=2::R3', done.stdout)

    def test_f1_unreadable_file_exits_2(self) -> None:
        target = self.dir / 'locked.txt'
        target.write_text('psql -d %s\n' % NAME, encoding='utf-8')
        target.chmod(0)
        self.addCleanup(target.chmod, 0o644)
        modes_ignored = True
        try:
            target.read_bytes()
        except OSError:
            modes_ignored = False  # the chmod-0 file is unreadable, which is what the probe needs
        if modes_ignored:
            self.skipTest('running as a user that ignores file modes')
        done = gate(self.dir, '--paths', 'locked.txt', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('::error file=locked.txt', done.stdout)

    def test_f2_allowlist_entry_for_missing_file_exits_2(self) -> None:
        (self.dir / 'allow.txt').write_text('gone.rs:5  # deleted\ngone2.rs:7  # deleted\n', encoding='utf-8')
        done = self.mutant('clean')
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('gone.rs:5', done.stderr)
        self.assertIn('gone2.rs:7', done.stderr)

    def test_f3_r5_forms(self) -> None:
        forms = ['x --db=%s', 'x --dbname %s', 'x --dbname=%s', 'export PGDATABASE=%s',
                 'dsn = "host=h dbname=%s user=u"', 'psql -d "%s"', "psql -d '%s'",
                 'PG_MAINT_DB="%s"', "MY_DB='%s'"]
        for form in forms:
            done = self.mutant(form % NAME)
            self.assertEqual(done.returncode, 1, form + done.stdout)

    def test_f3_password_variable_is_not_a_database_key(self) -> None:
        done = self.mutant('PG_PASS=%s\nPOSTGRES_PASSWORD=%s' % (NAME, NAME))
        self.assertEqual(done.returncode, 0, done.stdout)
        # a quoted password value is a quoted literal (R6), never a database key (R5)
        done = self.mutant('PG_PASS="%s"' % NAME)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertNotIn('R5', done.stdout)

    def test_f5_no_whole_file_entries_in_real_allowlist(self) -> None:
        text = (ROOT / 'scripts' / 'qc-allowlists' / 'shared-test-db-allow.txt').read_text(encoding='utf-8')
        for raw in text.splitlines():
            body = raw.split('#', 1)[0].strip()
            if body:
                self.assertRegex(body, r':\d+$', raw)

    def test_f6_nested_target_dir_is_scanned_but_root_target_is_not(self) -> None:
        (self.dir / 'scripts' / 'target').mkdir(parents=True)
        (self.dir / 'scripts' / 'target' / 'z.sh').write_text('psql -d %s\n' % NAME, encoding='utf-8')
        done = gate(self.dir, '--paths', 'scripts', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, 1, done.stdout)
        (self.dir / 'target').mkdir()
        (self.dir / 'target' / 'z.sh').write_text('psql -d %s\n' % NAME, encoding='utf-8')
        done = gate(self.dir, '--paths', 'target', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_f7_internal_errors_exit_2(self) -> None:
        (self.dir / 'allow.txt').write_bytes(b'\xff\xfe bad\n')
        done = self.mutant('clean')
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        (self.dir / 'allow.txt').write_text('', encoding='utf-8')
        done = gate(self.dir, '--paths', '/etc/hostname', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)

    def test_f8_one_annotation_per_line(self) -> None:
        done = self.mutant('pg_isready -U u -d %s' % NAME)
        self.assertEqual(done.stdout.count('::error'), 1, done.stdout)
        self.assertIn('::R3,R4', done.stdout)

    def test_f9_form_feed_keeps_git_line_numbers(self) -> None:
        done = self.mutant('a\x0cb\x0bc\npsql -d %s' % NAME)
        self.assertIn('line=2::R3', done.stdout)

    def test_f10_docs_are_scanned_by_default(self) -> None:
        self.make_default_tree()
        (self.dir / 'docs' / 'r.md').write_text('export U=postgres://h/%s\n' % NAME, encoding='utf-8')
        done = gate(self.dir)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('file=docs/r.md', done.stdout)

    # --- round 2: code r1 F1-F4, security r1 S1-S4 (#7149 #7150 #7151 #7154 #7155) ---
    def assert_flagged(self, form: str, name: str = 'm.txt') -> None:
        done = self.mutant(form, name=name)
        self.assertEqual(done.returncode, EXIT_VIOLATION, form + '\n' + done.stdout + done.stderr)

    def allow(self, text: str) -> None:
        (self.dir / 'allow.txt').write_text(text, encoding='utf-8')

    def make_default_tree(self) -> None:
        for rel in ['.github/workflows', 'tests', 'scripts/qc-allowlists', 'infra', 'src', 'packaging', 'docs',
                    'benches', 'clients', 'conformance', 'deploy', 'examples', 'hooks', 'loadtest', 'ops',
                    'plugins', 'sdk', 'tools']:
            (self.dir / rel).mkdir(parents=True, exist_ok=True)
        (self.dir / 'scripts' / 'qc-allowlists' / 'shared-test-db-allow.txt').write_text('', encoding='utf-8')

    def test_7031_f1_r1_url_terminators(self) -> None:
        for form in ['url: `postgres://u@h:5432/%s`', 'see (postgres://h/%s)', 'x=postgres://h/%s,y',
                     'echo postgres://h/%s>f', 'u=postgres://h/%s;', 'u=postgres://h/%s)', '<postgres://h/%s>']:
            self.assert_flagged(form % NAME)

    def test_7031_f1_database_key_and_positional_forms(self) -> None:
        for form in ['database=%s', '"database": "%s"', 'database: %s', 'psql -h h %s', 'createdb %s',
                     'dropdb %s', 'psql -h h -U u "%s"', 'pg_dump -h h %s > out.sql']:
            self.assert_flagged(form % NAME)

    def test_7031_f1_prefixed_names_stay_clean_for_new_forms(self) -> None:
        text = '\n'.join(['postgres://h/%s_x`' % NAME, 'database=%s_x' % NAME, 'createdb %s_x' % NAME,
                          'psql -h h %s_x' % NAME, '"%s_x"' % NAME, 'DROP DATABASE %s_x;' % NAME])
        done = self.mutant(text)
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout)

    def test_7031_s1_one_mib_line_scans_within_budget(self) -> None:
        pieces = {
            'db_runs': 'DB' * (ADVERSARIAL_LINE_BYTES // 2) + '=' + NAME,
            'pg_isready_runs': 'pg_isready ' * (ADVERSARIAL_LINE_BYTES // 11) + NAME,
            'word_run': 'A' * ADVERSARIAL_LINE_BYTES + ' ' + NAME,
            'space_run': ' ' * ADVERSARIAL_LINE_BYTES + NAME,
            'flag_runs': '-d ' * (ADVERSARIAL_LINE_BYTES // 3) + NAME,
            'name_runs': (NAME + ' ') * (ADVERSARIAL_LINE_BYTES // (len(NAME) + 1)),
            'psql_tokens': 'psql ' + 'x ' * (ADVERSARIAL_LINE_BYTES // 2) + NAME,
        }
        for label, text in pieces.items():
            (self.dir / 'big.txt').write_text(text + '\n', encoding='utf-8')
            started = time.monotonic()
            try:
                gate(self.dir, '--paths', 'big.txt', '--allowlist', str(self.dir / 'allow.txt'),
                     '--list', timeout=GATE_LINE_SCAN_BUDGET_SECS)
            except subprocess.TimeoutExpired:
                self.fail('%s: scan exceeded the %.1fs budget' % (label, GATE_LINE_SCAN_BUDGET_SECS))
            self.assertLess(time.monotonic() - started, GATE_LINE_SCAN_BUDGET_SECS, label)

    def test_7031_s2_whole_file_allowlist_entry_exits_2(self) -> None:
        self.allow('m.txt  # whole file\n')
        done = self.mutant('POSTGRES_DB=%s' % NAME)
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('allowlist line 1', done.stderr)

    def test_7031_s2_uncited_pin_exits_2(self) -> None:
        for body in ['m.txt:1\n', 'm.txt:1  #\n', 'm.txt:1  #   \n']:
            self.allow('# header\n' + body)
            done = self.mutant('POSTGRES_DB=%s' % NAME)
            self.assertEqual(done.returncode, EXIT_USAGE, body + done.stdout + done.stderr)
            self.assertIn('allowlist line 2', done.stderr)

    def test_7031_s2_duplicate_pin_exits_2(self) -> None:
        self.allow('m.txt:1  # cited\nm.txt:1  # cited again\n')
        done = self.mutant('POSTGRES_DB=%s' % NAME)
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('allowlist line 2', done.stderr)

    def test_7031_f2_unreadable_directory_exits_2(self) -> None:
        sub = self.dir / 'locked'
        sub.mkdir()
        (sub / 'z.sh').write_text('psql -d %s\n' % NAME, encoding='utf-8')
        sub.chmod(0)
        self.addCleanup(sub.chmod, 0o755)
        if os.access(str(sub), os.R_OK):
            self.skipTest('running as a user that ignores directory modes')
        done = gate(self.dir, '--paths', 'locked', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('file=locked', done.stdout)

    def test_7031_s3_missing_paths_entry_exits_2(self) -> None:
        done = gate(self.dir, '--paths', 'nope_7031', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('nope_7031', done.stderr)

    def test_7031_s3_renamed_default_directory_exits_2(self) -> None:
        self.make_default_tree()
        (self.dir / 'infra').rmdir()
        done = gate(self.dir)
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('infra', done.stderr)

    def test_7031_s3_executable_top_level_surfaces_are_scanned(self) -> None:
        for rel in ['deploy/up.sh', 'ops/run.sh', 'tools/x.py', 'loadtest/l.js', 'benches/b.rs', 'examples/e.rs',
                    'sdk/s.py', 'clients/c.py', 'conformance/c.sh', 'hooks/h.sh', 'plugins/p.sh',
                    'Dockerfile', 'Dockerfile.plan-c', 'entrypoint.plan-c.sh', 'install.sh']:
            self.make_default_tree()
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('psql -d %s\n' % NAME, encoding='utf-8')
            done = gate(self.dir)
            self.assertEqual(done.returncode, EXIT_VIOLATION, rel + done.stdout + done.stderr)
            self.assertIn('file=' + rel, done.stdout)
            target.unlink()

    def test_7031_s4_literal_forms(self) -> None:
        for form in ['let x = "%s";', "let x = '%s';", 'format!("{}", "%s")', 'db = "%s"',
                     'connect(database="%s")', 'DATABASE=%s', 'GRANT ALL ON DATABASE %s TO u;',
                     'DROP DATABASE %s;', 'drop database %s;', 'Db: %s',
                     'test_db=%s', 'db_name=%s', 'database_name: %s', 'psql -d%s']:
            self.assert_flagged(form % NAME)

    def test_7031_r3_compound_keys_and_glued_flag_keep_their_context(self) -> None:
        text = '\n'.join(['pg_db_password=%s' % NAME, 'x-d%s_y' % NAME])
        done = self.mutant(text)
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout)

    def test_7031_s4_sql_database_form_in_sql_file(self) -> None:
        self.assert_flagged('GRANT ALL PRIVILEGES ON DATABASE %s TO ai_memory;' % NAME, name='init.sql')

    def test_7031_s4_double_dash_continuation_is_not_a_comment_outside_sql(self) -> None:
        self.assert_flagged('-- --db %s' % NAME)
        self.assert_flagged('-- --db %s' % NAME, name='run.sh')
        done = self.mutant('-- --db %s' % NAME, name='q.sql')
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout)

    def coupled_file(self, lines: int, body: str = 'clean') -> None:
        target = self.dir / COUPLED_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('\n'.join([body] * lines) + '\n', encoding='utf-8')

    def run_coupled(self, allow: str, lines: int = 3, body: str = 'clean') -> 'subprocess.CompletedProcess[str]':
        self.coupled_file(lines, body)
        self.allow(allow)
        return gate(self.dir, '--paths', COUPLED_PATH, '--allowlist', str(self.dir / 'allow.txt'))

    def test_7031_landing_order_pin_may_be_absent_but_plain_pin_may_not(self) -> None:
        self.allow('m.txt:9  # plain pin\n')
        done = self.mutant('clean')
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)

    def test_7884_landing_order_marker_is_retired_and_exits_2(self) -> None:
        for allow in ['%s:717  # added by another PR %s\n' % (COUPLED_PATH, COUPLED_MARK),
                      'zz_never.sh:3  # x [landing-order #1]\n',
                      '%s:3  # x [landing-order #1]\n' % COUPLED_PATH,
                      'zz_never.sh:3  # x %s\n' % COUPLED_MARK]:
            done = self.run_coupled(allow)
            self.assertEqual(done.returncode, EXIT_USAGE, allow + done.stdout + done.stderr)
            self.assertIn('allowlist line 1', done.stderr)
            self.assertIn('retired', done.stderr)

    def test_7884_marker_cannot_preauthorise_a_hit(self) -> None:
        (self.dir / 'zz_pre.sh').write_text('POSTGRES_DB=%s\n' % NAME, encoding='utf-8')
        self.allow('zz_pre.sh:1  # x %s\n' % COUPLED_MARK)
        done = gate(self.dir, '--paths', 'zz_pre.sh', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)

    def test_7884_plain_pin_on_a_line_past_eof_is_stale(self) -> None:
        done = self.run_coupled('%s:717  # plain pin\n' % COUPLED_PATH)
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('stale allowlist entry', done.stderr)

    def test_7031_r3_landing_order_marker_count_only_shrinks(self) -> None:
        text = (ROOT / 'scripts' / 'qc-allowlists' / 'shared-test-db-allow.txt').read_text(encoding='utf-8')
        marked = [raw for raw in text.splitlines() if '[landing-order' in raw]
        self.assertEqual(len(marked), LANDING_ORDER_MARKERS_MAX, marked)

    # --- round 3: security r2 S6 (#7165), one cell per form ---
    def assert_clean(self, form: str, name: str = 'm.txt') -> None:
        done = self.mutant(form, name=name)
        self.assertEqual(done.returncode, EXIT_CLEAN, form + '\n' + done.stdout + done.stderr)

    def test_7031_r3_b7_b8_case_variants(self) -> None:
        self.assert_flagged('DROP DATABASE %s;' % NAME.upper(), name='m.sql')
        self.assert_flagged('u=postgres://h/%s' % NAME.upper())
        self.assert_flagged('GRANT ALL ON DATABASE %s TO u;' % NAME.title(), name='n.sql')

    def test_7031_r3_b1_b2_shell_line_continuation(self) -> None:
        for form in ['psql -h h -U u \\\n  %s', 'psql --dbname \\\n  %s', 'createdb \\\n%s']:
            done = self.mutant(form % NAME, name='m.sh')
            self.assertEqual(done.returncode, EXIT_VIOLATION, form + done.stdout + done.stderr)
            self.assertIn('line=1::', done.stdout)
        self.assert_clean('psql -h h -U u \\\n  %s_ci_1' % NAME, name='ok.sh')

    def test_7031_r3_b5_b6_psql_meta_commands(self) -> None:
        for form in ['\\c %s', '  \\connect %s', "\\c '%s'"]:
            self.assert_flagged(form % NAME, name='m.sh')
        self.assert_clean('\\c %s_ci_1' % NAME, name='ok.sh')

    def test_7031_r3_b10_b11_b18_comment_markers_are_suffix_aware(self) -> None:
        self.assert_flagged('#[sqlx(db = "%s")]' % NAME, name='m.rs')
        self.assert_flagged('#define DB_URL "postgres://h/%s"' % NAME, name='m.h')
        self.assert_flagged('//postgres://h/%s' % NAME, name='m.py')
        self.assert_flagged('//postgres://h/%s' % NAME, name='m.sh')
        self.assert_clean('// psql -d %s' % NAME, name='ok.rs')
        self.assert_clean('# psql -d %s' % NAME, name='ok.sh')
        self.assert_clean('# psql -d %s' % NAME, name='ok.py')

    def test_7031_r3_b9_utf16_file_fails_closed(self) -> None:
        (self.dir / 'u16.txt').write_bytes(('POSTGRES_DB: %s\n' % NAME).encode('utf-16'))
        done = gate(self.dir, '--paths', 'u16.txt', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('file=u16.txt', done.stdout)

    def test_7031_r3_b20_nul_inside_the_name_is_still_scanned(self) -> None:
        (self.dir / 'nul.txt').write_bytes(b'POSTGRES_DB: ai_memory\x00_test\n')
        done = gate(self.dir, '--paths', 'nul.txt', '--allowlist', str(self.dir / 'allow.txt'))
        self.assertEqual(done.returncode, EXIT_VIOLATION, done.stdout + done.stderr)
        self.assertIn('file=nul.txt', done.stdout)

    def test_7031_r3_b14_backtick_quoted_literal(self) -> None:
        self.assert_flagged('let x = `%s`;' % NAME)

    def test_7031_r3_b14_double_backtick_docstring_prose_is_not_a_literal(self) -> None:
        self.assert_clean('shared ``%s`` database' % NAME, name='m.py')
        self.assert_flagged('const x = `%s`;' % NAME, name='m.js')

    def test_7031_r3_b4_b17_lower_case_database_keys(self) -> None:
        self.assert_flagged('test_db: %s' % NAME, name='m.yml')
        self.assert_flagged('target_db = %s' % NAME, name='m.toml')

    def test_7031_r3_scope_is_a_deny_list_of_top_level_directories(self) -> None:
        for rel in ['.github/scripts/x.py', '.github/Dockerfile.ci', 'migrations/0001.sql', '.config/nextest.toml',
                    'coverage/check.sh', 'debian/postinst', 'fuzz/f.rs', 'benchmarks/b.py', 'zz_new_dir/x.sh']:
            self.make_default_tree()
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('psql -d %s\n' % NAME if not rel.endswith('.sql') else 'DROP DATABASE %s;\n' % NAME,
                              encoding='utf-8')
            done = gate(self.dir)
            self.assertEqual(done.returncode, EXIT_VIOLATION, rel + done.stdout + done.stderr)
            self.assertIn('file=' + rel, done.stdout)
            target.unlink()
        for rel in ['changelog.d/x.md', 'target/x.sh', 'vendor/x.sh']:
            self.make_default_tree()
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('psql -d %s\n' % NAME, encoding='utf-8')
            done = gate(self.dir)
            self.assertEqual(done.returncode, EXIT_CLEAN, rel + done.stdout + done.stderr)
            target.unlink()

    def test_7031_r3_allowlist_pin_paths_are_normalised(self) -> None:
        self.allow('./m.txt:1  # cited\n')
        done = self.mutant('POSTGRES_DB=%s' % NAME)
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout + done.stderr)
        done = self.mutant('clean')
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout + done.stderr)
        self.assertIn('stale allowlist entry', done.stderr)
        for bad in ['../m.txt:1  # c\n', '/etc/hosts:1  # c\n', 'a/../m.txt:1  # c\n']:
            self.allow(bad)
            done = self.mutant('clean')
            self.assertEqual(done.returncode, EXIT_USAGE, bad + done.stdout + done.stderr)
            self.assertIn('allowlist line 1', done.stderr)

    def test_7031_r3_docstring_states_the_not_scanned_indirection_forms(self) -> None:
        text = GATE.read_text(encoding='utf-8')
        for needle in ['env indirection', 'string concatenation', 'escape', 'percent-encoded']:
            self.assertIn(needle, text, needle)

    def test_7031_f4_changelog_fragment_states_the_gate(self) -> None:
        text = (ROOT / 'changelog.d' / '7031b.fixed.md').read_text(encoding='utf-8')
        for needle in ['R1', 'R5', 'docs/', 'exit 2', 'allowlist', 'unreadable', 'stale', 'ephemeral']:
            self.assertIn(needle, text, needle)


    # --- round 4: code r3 F1 (#7171) ---
    def test_7171_r4_one_mib_of_continuation_lines_scans_in_linear_time(self) -> None:
        pair = 'a \\\n# \\\n'
        forms = {
            'code_comment_alternating': pair * (ADVERSARIAL_LINE_BYTES // len(pair)) + 'x\n',
            'code_only_chain': 'a \\\n' * (ADVERSARIAL_LINE_BYTES // 4) + 'x\n',
            'comment_chain': '# \\\n' * (ADVERSARIAL_LINE_BYTES // 4) + 'x\n',
        }
        for label, text in forms.items():
            self.assertGreaterEqual(len(text), ADVERSARIAL_LINE_BYTES, label)
            (self.dir / 'm.sh').write_text(text, encoding='utf-8')
            started = time.monotonic()
            try:
                done = gate(self.dir, '--paths', 'm.sh', '--allowlist', str(self.dir / 'allow.txt'),
                            timeout=CONTINUATION_SCAN_BUDGET_SECS * 10)
            except subprocess.TimeoutExpired:
                self.fail('%s: scan exceeded %.0fs' % (label, CONTINUATION_SCAN_BUDGET_SECS * 10))
            elapsed = time.monotonic() - started
            self.assertEqual(done.returncode, EXIT_CLEAN, label + done.stdout + done.stderr)
            self.assertLess(elapsed, CONTINUATION_SCAN_BUDGET_SECS, '%s took %.2fs' % (label, elapsed))


    # --- round 4: code r3 F3 (#7173) ---
    def default_scope_run(self, allow: str) -> 'subprocess.CompletedProcess[str]':
        self.make_default_tree()
        (self.dir / 'src' / 'live.sh').write_text('POSTGRES_DB=%s\n' % NAME, encoding='utf-8')
        for rel in ('changelog.d/n.md', '.local-runs/probe.py', 'node_modules/dep.js', 'src/__pycache__/c.py'):
            target = self.dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('x = 1\n', encoding='utf-8')
        (self.dir / 'scripts' / 'qc-allowlists' / 'shared-test-db-allow.txt').write_text(allow, encoding='utf-8')
        return gate(self.dir)

    def test_7173_r4_default_scope_pin_on_an_unscanned_file_is_stale(self) -> None:
        live = 'src/live.sh:1  # live pin\n'
        done = self.default_scope_run(live)
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout + done.stderr)
        for dead in ('changelog.d/n.md', '.local-runs/probe.py', 'node_modules/dep.js', 'src/__pycache__/c.py'):
            done = self.default_scope_run(live + '%s:1  # dead pin\n' % dead)
            self.assertEqual(done.returncode, EXIT_USAGE, dead + done.stdout + done.stderr)
            self.assertIn('%s:1' % dead, done.stderr, dead)

    def test_7173_r4_narrowed_paths_still_skip_pins_outside_the_scan(self) -> None:
        (self.dir / 'other.sh').write_text('POSTGRES_DB=%s\n' % NAME, encoding='utf-8')
        self.allow('other.sh:1  # pin outside the narrowed scan\n')
        done = self.mutant('clean')
        self.assertEqual(done.returncode, EXIT_CLEAN, done.stdout + done.stderr)


if __name__ == '__main__':
    unittest.main()
