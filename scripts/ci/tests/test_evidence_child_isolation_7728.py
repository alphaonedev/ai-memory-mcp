#!/usr/bin/env python3
"""Behavioral child isolation checks, including the supported Python 3.9 runtime.

Run the harness with -I; the runner's own import boundary is tracked separately.
Fixtures and the positive control live only beneath the worktree's .local-runs.
"""
import argparse
import ast
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from unittest import mock

from test_evidence_generator_5040_5042 import ScratchCase, load

PROBE = (
    "import base64, json, os, sys; "
    "print(json.dumps({'isolated': sys.flags.isolated, "
    "'executable': sys.executable, 'module': base64.__file__, "
    "'cwd': os.getcwd(), 'entries': os.listdir('.')}))"
)
PLANT = "raise RuntimeError('PLANTED-MODULE-7728')\n"
ROOT = Path(__file__).resolve().parents[3]
SHELL_CHILDREN = (
    'check-cert-removal-proof.sh', 'check-docs-vs-ssot.sh', 'check-doc-symbol-anchors.sh',
    'check-ci-job-claims.sh', 'check-hardcoded-literals.sh', 'check-vendor-literals.sh',
    'qc-codegraph-precheck.sh', 'check-test-env-lock.sh', 'check-count-assertion-declared.sh',
    'check-foreign-text-to-caller.sh', 'check-bootstrap-cert-gate.sh',
    'recapture-cert-3607-posture.sh', 'check-migration-ladder.sh', 'lib/production-lines.sh',
)
PYTHON_CHILDREN = (
    'check-claude-md-size.py', 'check-foreign-text-to-caller.py', 'check-sqlite-write-txn-immediate.py',
    'cert_gate_evidence.py', 'tests/gate-production-3623.py', 'tests/for-admin-checked-literal-3943.py',
)


class ChildIsolation7728(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load('run_cert')
        self.wt = self.dir / 'checkout'
        self.wt.mkdir()
        self.runner = self.rc.Run(argparse.Namespace(
            tip='0' * 40, wt=str(self.wt), outd=str(self.dir / 'out'),
            leg='gates', targets=str(self.dir / 'targets'), tmpdir=str(self.dir / 'scratch')))
        self.out = self.dir / 'child.out'

    def run_probe(self, argv, extra=None, cwd=None):
        code = self.runner.run(argv, self.out, extra_env=extra, cwd=cwd, gate=False)
        text = self.out.read_text()
        self.assertEqual(code, 0, text)
        result = json.loads(text)
        self.assertEqual(result['isolated'], 1, text)
        self.assertEqual(Path(result['executable']).resolve(), Path(sys.executable).resolve())
        self.assertFalse(result['module'].startswith(str(self.wt)), text)
        self.assertEqual(list(self.runner.tmpdir.iterdir()), [], 'private launch resources cleaned')
        return result

    def test_direct_python_child_uses_isolated_mode_7728(self):
        result = self.run_probe([sys.executable, '-c', PROBE])
        self.assertEqual(result['entries'], [], 'child starts in an empty private cwd')
        self.assertFalse(Path(result['cwd']).exists())

    def test_nested_shell_python_ignores_checkout_modules_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        code = 'cd ' + shlex.quote(str(self.wt)) + '; python3 -c ' + shlex.quote(PROBE)
        self.run_probe(['bash', '-c', code])

    def test_nested_shell_python_ignores_script_siblings_7728(self):
        scripts = self.wt / 'scripts'
        scripts.mkdir()
        (scripts / 'base64.py').write_text(PLANT)
        probe = scripts / 'probe.py'
        probe.write_text(PROBE)
        self.run_probe(['bash', '-c', 'python3 ' + shlex.quote(str(probe))])

    def test_extra_environment_cannot_restore_python_import_paths_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        self.run_probe(['bash', '-c', 'python3 -c ' + shlex.quote(PROBE)],
                       {'PYTHONPATH': str(self.wt), 'PYTHONHOME': str(self.wt),
                        'PYTHONSAFEPATH': '0', 'PYTHONNOUSERSITE': '0'})

    def test_nested_bash_environment_cannot_replace_interpreter_7728(self):
        startup = self.dir / 'startup'
        startup.write_text("python3() { exit 86; }\n")
        self.run_probe(['bash', '-c', 'bash -c ' + shlex.quote('python3 -c ' + shlex.quote(PROBE))],
                       {'BASH_ENV': str(startup), 'BASH_FUNC_python3%%': '() { exit 87; }'})

    def test_path_python_cannot_switch_interpreter_or_recurse_7728(self):
        hostile = self.dir / 'hostile'
        hostile.mkdir()
        (hostile / 'python3').symlink_to('/bin/false')
        self.run_probe(['bash', '-c', 'python3 -c ' + shlex.quote(PROBE)],
                       {'PATH': str(hostile) + os.pathsep + os.environ['PATH']})

    def test_explicit_cargo_cwd_still_gets_nested_isolation_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        self.run_probe(['bash', '-c', 'python3 -c ' + shlex.quote(PROBE)], cwd=self.wt)

    def test_inline_shell_environment_cannot_restore_import_paths_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        command = ('PYTHONPATH=' + shlex.quote(str(self.wt)) + ' PYTHONHOME=' + shlex.quote(str(self.wt))
                   + ' python3 -c ' + shlex.quote(PROBE))
        self.run_probe(['bash', '-c', command])

    def test_launcher_is_private_and_does_not_live_in_child_cwd_7728(self):
        real_run = subprocess.run
        seen = []

        def inspect(argv, **kwargs):
            helper_dir = Path(kwargs['env']['PATH'].split(os.pathsep)[0])
            seen.append(helper_dir)
            self.assertEqual(helper_dir.stat().st_mode & 0o777, 0o700)
            self.assertNotEqual(helper_dir, Path(kwargs['cwd']))
            for helper in helper_dir.iterdir():
                self.assertEqual(helper.stat().st_mode & 0o777, 0o500)
                self.assertFalse(helper.is_symlink())
                self.assertTrue(helper.read_text().startswith('#!' + os.path.abspath(sys.executable) + ' -I\n'))
            return real_run(argv, **kwargs)

        with mock.patch.object(subprocess, 'run', side_effect=inspect):
            self.run_probe(['bash', '-c', 'python3 -c ' + shlex.quote(PROBE)])
        self.assertTrue(seen)
        self.assertTrue(all(not path.exists() for path in seen))

    def test_static_nested_gate_interpreter_inventory_7728(self):
        """Known shell entry points use the private PATH launcher; direct Python descendants carry -I.

        This is a drift guard for reviewed gate sources, not a general shell security parser. Runtime isolation
        and hostile-input tests above remain the behavioral proof. Alternate interpreter spellings or PATH resets
        require review before extending this inventory.
        """
        runner = (ROOT / 'scripts/evidence/run_cert.py').read_text()
        gates = set(re.findall(r'(?:self\.script\(|self\.low_priority\("\d+", )"(?:scripts/)?([^"/]+\.sh)"', runner))
        self.assertTrue(gates)
        self.assertLessEqual(gates, set(SHELL_CHILDREN))
        for name in SHELL_CHILDREN:
            source = (ROOT / 'scripts' / name).read_text()
            active = '\n'.join(line for line in source.splitlines() if not line.lstrip().startswith('#'))
            with self.subTest(script=name):
                # Recapture's env -i PATH values belong to Rust binary calls after its Python setup.
                self.assertIsNone(re.search(r'(?m)^(?:export )?(?:PATH|BASH_ENV)=', active), name)
                self.assertIsNone(re.search(r'\bpython(?:2|3\.\d+)?\s+-', active), name)
                self.assertIsNone(re.search(r'/python3\s+-', active), name)
        python_spawns = []
        for name in PYTHON_CHILDREN:
            tree = ast.parse((ROOT / 'scripts' / name).read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in ('run', 'Popen', 'call', 'check_call', 'check_output') or not node.args:
                    continue
                argv = node.args[0]
                if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts:
                    continue
                first = argv.elts[0]
                if isinstance(first, ast.Attribute) and first.attr == 'executable':
                    python_spawns.append((name, node.lineno))
                    self.assertGreater(len(argv.elts), 1)
                    self.assertEqual(getattr(argv.elts[1], 'value', None), '-I', (name, node.lineno))
        self.assertTrue(python_spawns)

    def test_positive_control_imports_the_planted_module_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        env = dict(os.environ)
        for name in ('PYTHONSAFEPATH', 'PYTHONPATH', 'PYTHONHOME'):
            env.pop(name, None)
        result = subprocess.run([sys.executable, '-c', 'import base64'], cwd=self.wt,
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PLANTED-MODULE-7728', result.stderr)
