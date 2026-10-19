#!/usr/bin/env python3
"""Behavioral child isolation checks, including the supported Python 3.9 runtime.

Run the harness with -I; the runner's own import boundary is tracked separately.
Fixtures and the positive control live only beneath the worktree's .local-runs.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from test_evidence_generator_5040_5042 import ScratchCase, load

PROBE = (
    "import base64, json, os, sys; "
    "print(json.dumps({'isolated': sys.flags.isolated, "
    "'executable': sys.executable, 'module': base64.__file__, "
    "'cwd': os.getcwd(), 'entries': os.listdir('.')}))"
)
PLANT = "raise RuntimeError('PLANTED-MODULE-7728')\n"


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

    def test_positive_control_imports_the_planted_module_7728(self):
        (self.wt / 'base64.py').write_text(PLANT)
        env = dict(os.environ)
        for name in ('PYTHONSAFEPATH', 'PYTHONPATH', 'PYTHONHOME'):
            env.pop(name, None)
        result = subprocess.run([sys.executable, '-c', 'import base64'], cwd=self.wt,
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PLANTED-MODULE-7728', result.stderr)
