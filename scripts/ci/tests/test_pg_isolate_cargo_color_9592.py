#!/usr/bin/env python3
"""Cargo colour codes in per-binary logs (#9592 B(iii)).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolate_cargo_color_9592.py

Class: ci.yml sets CARGO_TERM_COLOR=always, so cargo writes its status word as
``ESC[1mESC[92m     RunningESC[0m tests/x.rs (.../deps/x-<16 hex>)``. A parser
that anchors on ``^\\s*Running`` misses every such line, and the serial
isolated step then reported about 700 binaries that ran green as
``no test binary path in the log: <name>`` (job 136822077211).

Invariant: a ``Running`` line is recognised with or without ANSI CSI / OSC
escape sequences around it, the binary path handed to ``--list --ignored``
carries no escape byte, and a log with no ``Running`` line for the binary
stays red with that binary's name. The scan is linear: a 120 000-line coloured
log and 100 000-byte unterminated escape runs stay under COLOR_SCAN_CEILING_SECS.
"""
import importlib.util
import io
import shutil
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PARITY = REPO / 'scripts' / 'ci' / 'pg_isolate_parity.py'
STEP = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_step.py'
FIXTURE = REPO / 'scripts' / 'ci' / 'tests' / 'fixtures' / 'pg-iso-colored-log-9592.log'
SCRATCH = REPO / '.local-runs' / 'test-pg-isolate-cargo-color-9592'

COLOR_SCAN_CEILING_SECS = 5.0
LARGE_LINES = 120_000
LONG_ESCAPE = 100_000

SECRET_URL = 'postgresql://ci_user:canarypw9592@pgfixture:5445/ai_memory_ci_fed_9592'
SHARED_DB = 'ai_memory_ci_fed_9592'
TEMPLATE = SHARED_DB + '_tpl'
TARGETS = ('alpha_9592', 'beta_9592', 'resid_9592')
RESIDUAL = ('resid_9592',)
JOB_T0 = 1_000_000
NOW = JOB_T0 + 600
HEX16 = '0123456789abcdef'

# The status-word forms a terminal colour writer can produce, written out by hand:
# (label, text before "Running", text after "Running").
ESC = '\x1b'
STATUS_FORMS = (
    ('plain', '     ', ''),
    ('cargo bold green (job 136822077211)', ESC + '[1m' + ESC + '[92m     ', ESC + '[0m'),
    ('one SGR with two params', ESC + '[0;32m     ', ESC + '[m'),
    ('params in the other order', ESC + '[32;1m     ', ESC + '[0m'),
    ('256-colour SGR', ESC + '[38;5;10m     ', ESC + '[39m'),
    ('truecolour SGR', ESC + '[38;2;0;255;0m     ', ESC + '[0m'),
    ('erase-line CSI before the word', ESC + '[2K' + ESC + '[1m     ', ESC + '[0m'),
    ('OSC 8 hyperlink with BEL', ESC + ']8;;https://example.invalid/x\x07     ', ESC + ']8;;\x07'),
    ('OSC 8 hyperlink with ST', ESC + ']8;;https://example.invalid/x' + ESC + '\\     ', ESC + ']8;;' + ESC + '\\'),
)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def running(name, before, after, path_prefix='target/debug/deps/'):
    return '%sRunning%s tests/%s.rs (%s%s-%s)' % (before, after, name, path_prefix, name, HEX16)


def colored_log(name, db, mode, before=STATUS_FORMS[1][1], after=STATUS_FORMS[1][2], tests=2):
    lines = ['# [pg_isolated_binary] current_database=%s mode=%s' % (db, mode),
             ESC + '[1m' + ESC + '[92m    Finished' + ESC + '[0m `test` profile [unoptimized] target(s) in 0.92s',
             running(name, before, after),
             '',
             'running %d tests' % tests]
    lines += ['test t%d ... ok' % i for i in range(tests)]
    lines += ['', 'test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; '
              'finished in 0.01s' % tests, '']
    return '\n'.join(lines) + '\n'


class FakeHost:
    """The serial step's host seam: records captures, writes the per-binary logs on the wrapper run."""

    def __init__(self, write_logs):
        self.write_logs = write_logs
        self.calls = []
        self.env_lines = []

    def now(self):
        return NOW

    def which(self, name):
        return '/usr/bin/' + name if name == 'timeout' else None

    def append_env(self, line):
        self.env_lines.append(line)

    def capture(self, argv, env):
        self.calls.append(('capture', list(argv), dict(env)))
        if '--list' in argv:
            return 0, ''
        run_id = argv[argv.index('--run-id') + 1]
        return 0, 'AI_MEMORY_TEST_PG_TEMPLATE=%s\nAI_MEMORY_TEST_PG_RUN_ID=%s\n' % (TEMPLATE, run_id)

    def run(self, argv, env):
        self.calls.append(('run', list(argv), dict(env)))
        if 'pg_isolated_binary.py' in ' '.join(argv) and 'run' in argv:
            log_dir = Path(argv[argv.index('--log-dir') + 1])
            self.write_logs(log_dir, argv[argv.index('--run-id') + 1])
        return 0

    def leftovers(self, env, db, run_id):
        return (0, 0)


class Parity(unittest.TestCase):
    def setUp(self):
        self.p = _load('pg_isolate_parity_color_9592', PARITY)

    def test_fixture_from_job_136822077211_is_one_segment(self):
        text = FIXTURE.read_text(encoding='utf-8')
        self.assertIn(ESC + '[92m     Running' + ESC + '[0m', text)
        segs = self.p.segments(text)
        self.assertEqual([s.name for s in segs], ['pg_health_probe_constant_cost_2617'])
        self.assertEqual(segs[0].totals, (1, 2, 0))
        self.assertEqual(segs[0].tests, {
            'a_pg_health_check_issues_no_corpus_count_2617': 'ok',
            'pg::b_pg_health_probe_touches_at_most_one_row_2617': 'FAILED',
            'pg::c_control_legacy_count_scanned_the_whole_corpus_2617': 'FAILED',
        })

    def test_every_status_form_is_one_segment(self):
        for label, before, after in STATUS_FORMS:
            with self.subTest(form=label):
                segs = self.p.segments(colored_log('alpha_9592', 'db', 'isolated', before, after))
                self.assertEqual([(s.name, s.totals) for s in segs], [('alpha_9592', (2, 0, 0))])

    def test_broken_escape_is_not_a_running_line(self):
        # A lone ESC or a cut-off sequence is not a colour code; the line is not cargo's and stays unread.
        for label, before in (('lone ESC', ESC + '     '), ('ESC [ with no final byte then a space', ESC + '[1;  '),
                              ('C1 CSI byte', '\x9b1m     '), ('word split by a code', '     Run' + ESC + '[0mx')):
            with self.subTest(form=label):
                self.assertEqual(self.p.segments(running('alpha_9592', before, '') + '\n'), [])

    def test_plain_helper_strips_only_escape_sequences(self):
        plain = getattr(self.p, 'plain', None)
        self.assertIsNotNone(plain, 'pg_isolate_parity.plain is missing')
        self.assertEqual(plain(ESC + '[1m' + ESC + '[92m     Running' + ESC + '[0m x'), '     Running x')
        self.assertEqual(plain('test a ... ok'), 'test a ... ok')
        self.assertEqual(plain(ESC + ']8;;u\x07a' + ESC + ']8;;' + ESC + '\\'), 'a')
        self.assertEqual(plain(ESC + 'x'), ESC + 'x')

    def test_coloured_serial_log_keeps_parity(self):
        names = ['alpha_9592', 'beta_9592']
        iso = {n + '.log': colored_log(n, 'db_' + n, 'isolated', '     ', '') for n in names}
        serial = ''.join(colored_log(n, SHARED_DB, 'residual') for n in names)
        reasons, summary = self.p.compare_logs(iso, serial, names)
        self.assertEqual(reasons, [])
        self.assertEqual(summary['ok'], 4)

    def test_large_coloured_log_is_linear(self):
        before, after = STATUS_FORMS[1][1], STATUS_FORMS[1][2]
        lines = []
        per = 200
        binaries = LARGE_LINES // (per + 2) + 1
        for b in range(binaries):
            lines.append(running('bin_%d' % b, before, after))
            lines += ['test t%d ... ok' % i for i in range(per)]
            lines.append('test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' % per)
        lines.append(ESC + '[' + '1;' * LONG_ESCAPE)
        lines.append((ESC + '[') * LONG_ESCAPE)
        lines.append(ESC + ']8;;' + 'u' * LONG_ESCAPE)
        text = '\n'.join(lines) + '\n'
        self.assertGreaterEqual(text.count('\n'), LARGE_LINES)
        t0 = time.monotonic()
        segs = self.p.segments(text)
        elapsed = time.monotonic() - t0
        self.assertEqual(len(segs), binaries)
        self.assertTrue(all(s.totals == (per, 0, 0) for s in segs))
        self.assertLess(elapsed, COLOR_SCAN_CEILING_SECS)


class SerialStep(unittest.TestCase):
    def setUp(self):
        self.e = _load('pg_isolate_serial_step_color_9592', STEP)
        self.root = SCRATCH / self.id().rsplit('.', 1)[-1]
        if self.root.exists():
            shutil.rmtree(self.root)
        shard = self.root / 'ci-shard'
        shard.mkdir(parents=True)
        (shard / 'iso_targets.txt').write_text(''.join('--test %s\n' % t for t in TARGETS))
        (shard / 'iso_residual.txt').write_text(''.join('%s\n' % t for t in RESIDUAL))
        (self.root / 'ci-iso-mode.txt').write_text('deferred\n')
        self.env = {'RUNNER_TEMP': str(self.root), 'AI_MEMORY_TEST_POSTGRES_URL': SECRET_URL,
                    'AI_MEMORY_TEST_PG_ISOLATE': '1', 'CI_FED_DB': SHARED_DB, 'JOB_TIMEOUT_MIN': '150',
                    'JOB_T0': str(JOB_T0), 'PATH': '/usr/bin', 'CI_PG_ISOLATE_OFF': ''}

    def step(self, host):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.e.run_step(host, dict(self.env))
        out = buf.getvalue()
        self.assertNotIn(SECRET_URL, out)
        return rc, out

    @staticmethod
    def writer(form, skip=()):
        _label, before, after = form

        def write(log_dir, run_id):
            log_dir.mkdir(parents=True, exist_ok=True)
            for i, name in enumerate(TARGETS):
                if name in RESIDUAL:
                    db, mode = SHARED_DB, 'residual'
                else:
                    db, mode = 'ai_memory_t_%s_1700000000_%08x' % (run_id, i), 'isolated'
                text = colored_log(name, db, mode, before, after)
                if name in skip:
                    text = '\n'.join(ln for ln in text.split('\n') if 'Running' not in ln)
                (log_dir / (name + '.log')).write_text(text)
        return write

    def test_coloured_logs_give_the_ok_line_for_every_form(self):
        for form in STATUS_FORMS:
            with self.subTest(form=form[0]):
                self.setUp()
                host = FakeHost(self.writer(form))
                rc, out = self.step(host)
                self.assertEqual(rc, 0, out)
                self.assertIn('[#9592] serial shard isolated binaries ok: binaries=3 isolated=2 residual=1', out)
                self.assertNotIn('no test binary path in the log', out)

    def test_listed_binary_path_carries_no_escape_byte(self):
        host = FakeHost(self.writer(STATUS_FORMS[1]))
        self.step(host)
        listed = [argv[0] for kind, argv, _ in host.calls if kind == 'capture' and '--list' in argv]
        self.assertEqual(listed, ['target/debug/deps/%s-%s' % (n, HEX16) for n in TARGETS])

    def test_binary_without_running_line_stays_red_with_its_name(self):
        host = FakeHost(self.writer(STATUS_FORMS[1], skip=('beta_9592',)))
        rc, out = self.step(host)
        self.assertEqual(rc, 1, out)
        self.assertIn('no test binary path in the log: beta_9592', out)
        self.assertNotIn('no test binary path in the log: alpha_9592', out)
        self.assertNotIn('no test binary path in the log: resid_9592', out)


if __name__ == '__main__':
    unittest.main()
