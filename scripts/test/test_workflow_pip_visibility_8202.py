"""#8202: isolated workflow imports must see their pip installation target.

The import proof executes the workflow's Python code with system site packages
disabled and a local stub, so an installed host package cannot conceal drift.
No package download or model download occurs in these tests.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github/workflows'
COVERAGE_STEP = 'Pre-stage HF models with retry (#2019)'
TARGET_NAME = 'HF_PYTHON_TARGET'
TARGET_VALUE = '${{ github.workspace }}/.local-runs/coverage-hf-python'
MODEL = 'fixture/model-8202'
IMPORT_TIMEOUT_SECONDS = 30
SETUP_WORKFLOWS = ('clients-ci.yml', 'publish-sdk-shims.yml', 'publish-sdks.yml')
PIP_INSTALL = re.compile(r'\bpip3? install\b')


def coverage_step():
    """Read the named run step, bounded by the next step."""
    text = (WORKFLOWS / 'coverage.yml').read_text()
    tail = text.split('      - name: ' + COVERAGE_STEP + '\n', 1)[1]
    return tail.split('\n      - ', 1)[0]


def job_blocks(text):
    """Read the literal job IDs of these checked-in workflow files."""
    parts = re.split(r'(?m)^  ([\w-]+):\s*$', text.split('\njobs:\n', 1)[1])
    return zip(parts[1::2], parts[2::2])


class WorkflowPipVisibility8202(unittest.TestCase):
    def test_same_line_pip3_fallback_mutation_is_rejected(self):
        step = coverage_step()
        lines = step.splitlines(keepends=True)
        index = next(i for i, line in enumerate(lines) if '"huggingface_hub>=0.20"' in line)
        lines[index] = lines[index].rstrip('\n') + ' || pip3 install example\n'
        mutant = ''.join(lines)
        with mock.patch.object(sys.modules[__name__], 'coverage_step', return_value=mutant):
            with self.assertRaises(AssertionError):
                self.test_system_python_install_has_an_explicit_project_target()

    def test_system_python_install_has_an_explicit_project_target(self):
        step = coverage_step()
        self.assertIn(f'{TARGET_NAME}: {TARGET_VALUE}', step)
        self.assertNotRegex(step, r'\bpip3\b', 'no pip3 fallback anywhere in this step')
        self.assertNotIn('||', step, 'no fail-open install fallback')
        commands = step.replace('\\\n', ' ').splitlines()
        installs = [shlex.split(line.strip()) for line in commands if PIP_INSTALL.search(line)]
        self.assertEqual(len(installs), 1, 'use the same interpreter; no pip3 fallback')
        args = installs[0]
        self.assertEqual(args[:5], ['python3', '-I', '-m', 'pip', 'install'])
        self.assertIn('--target', args)
        self.assertEqual(args[args.index('--target') + 1], '$' + TARGET_NAME)
        self.assertIn('--upgrade', args)

    def test_isolated_import_loads_the_explicit_target_not_cwd_or_user_site(self):
        step = coverage_step()
        call = next(line.strip() for line in step.splitlines()
                    if line.strip().startswith('if python3 ') and 'snapshot_download' in line)
        args = shlex.split(call)
        self.assertEqual(args[:4], ['if', 'python3', '-I', '-c'])
        code = args[4]
        scratch = ROOT / '.local-runs'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            target = root / 'packages'
            target.mkdir()
            (target / 'json.py').write_text(
                'raise RuntimeError("pip target shadowed stdlib json")\n')
            (target / 'huggingface_hub.py').write_text(
                'import json\n'
                'def snapshot_download(model):\n'
                '    print("explicit-target:" + model)\n')
            (root / 'huggingface_hub.py').write_text(
                'raise RuntimeError("cwd or PYTHONPATH package loaded")\n')
            env = dict(os.environ, HF_PYTHON_TARGET=str(target), PYTHONPATH=str(root),
                       PYTHONUSERBASE=str(root / 'user-site'), TMPDIR=str(root))
            # -S makes the absence of a system installation deterministic; -I
            # and the import code are the actual workflow's isolation contract.
            result = subprocess.run([sys.executable, '-I', '-S', '-c', code, MODEL],
                                    cwd=root, env=env, capture_output=True, text=True,
                                    check=False, timeout=IMPORT_TIMEOUT_SECONDS)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'explicit-target:' + MODEL)

    def test_other_pip_installs_have_setup_python_earlier_in_the_same_job(self):
        for name in SETUP_WORKFLOWS:
            installs = 0
            for job, block in job_blocks((WORKFLOWS / name).read_text()):
                setup = False
                for line in block.splitlines():
                    if 'uses: actions/setup-python@' in line:
                        setup = True
                    if PIP_INSTALL.search(line):
                        installs += 1
                        with self.subTest(workflow=name, job=job, command=line.strip()):
                            self.assertTrue(setup, 'system Python needs an explicit target')
                            self.assertNotIn('--user', shlex.split(line.strip()))
            self.assertGreater(installs, 0, name)


if __name__ == '__main__':
    unittest.main()
