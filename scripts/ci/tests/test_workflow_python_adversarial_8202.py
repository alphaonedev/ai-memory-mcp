"""The 51 reviewed adversarial rows are separate CI tests, rooted in this checkout."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / 'scripts/ci/check_workflow_python_isolation.py'
CASES = (
    ('FLAG', '$PYTHON x.py'),
    ('FLAG', '$PYTHON -I x.py'),
    ('FLAG', '${PYTHON:-python3} x.py'),
    ('FLAG', '${{ steps.x.outputs.python-path }} x.py'),
    ('FLAG', '"$VENV"/bin/python x.py'),
    ('FLAG', '/opt/python3.12/bin/python3 x.py'),
    ('FLAG', 'env -i python3 x.py'),
    ('FLAG', 'python3 -E -s x.py'),
    ('FLAG', 'python3 \\\nx.py'),
    ('FLAG', 'true && python3 x.py'),
    ('FLAG', 'cat f | python3 x.py'),
    ('FLAG', 'true; python3 x.py'),
    ('FLAG', 'ls | xargs python3 x.py'),
    ('FLAG', 'sudo python3 x.py'),
    ('FLAG', 'nice python3 x.py'),
    ('FLAG', 'timeout 60 python3 x.py'),
    ('FLAG', '$TIMEOUT_BIN 60 python3 x.py'),
    ('FLAG', 'uv run python -I x.py'),
    ('FLAG', 'poetry run python x.py'),
    ('FLAG', 'pyenv exec python x.py'),
    ('FLAG', 'py -3 x.py'),
    ('FLAG', 'python3 - <<EOF\nprint(1)\nEOF\n'),
    ('FLAG', 'out=$(python3 x.py)'),
    ('FLAG', '& python3 x.py'),
    ('FLAG', '& $env:PYTHON x.py'),
    ('FLAG', 'python3 -W ignore x.py'),
    ('PASS', '/opt/python3.12/bin/python3 -I x.py'),
    ('PASS', 'PYTHONPATH=x python3 -I x.py'),
    ('PASS', 'python3 \\\n-I x.py'),
    ('PASS', 'true && python3 -I x.py'),
    ('PASS', 'timeout 60 python3 -I x.py'),
    ('PASS', '$BIN run x'),
    ('PASS', 'cat <<EOF\npython3 x.py\nEOF\n'),
    ('PASS', 'python3 -I - <<EOF\nprint(1)\nEOF\n'),
    ('PASS', "python3 -Ic 'pass'"),
    ('PASS', 'python3 -X dev -I x.py'),
    ('PASS', 'python3 -I -m pip install x'),
    ('PASS', 'python3 -I -m pipx install x'),
    ('PASS', 'python3 -I -m pytest'),
    ('PASS', 'python3 -I -m pipx ensurepath'),
    ('PASS', 'python3 -I -m pipx install copr-cli'),
    ('PASS', 'python3 -I -m pipx inject copr-cli rich'),
    ('WORKFLOW_FLAG', 'bash -e {0}\npython3 x.py'),
    ('WORKFLOW_PASS', 'bash -e {0}\npython3 -I x.py'),
    ('WORKFLOW_FLAG', 'pwsh\npython3 x.py'),
    ('WORKFLOW_PASS', 'pwsh\npython3 -I x.py'),
    ('EXEMPTION', '# isolation: exempt 8202'),
    ('EXEMPTION', '#isolation:exempt #8202'),
    ('EXEMPTION', '# isolation: exempt #'),
    ('EXEMPTION', '# isolation: exempt #8202 extra'),
    ('EXEMPTION', '# isolation:  exempt #8202'),
)


class ReviewedAdversarialRows8202(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('adversarial_8202', CHECKER)
        self.checker = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.checker
        spec.loader.exec_module(self.checker)

    def check_case(self, kind, text):
        if kind.startswith('WORKFLOW_'):
            scratch = ROOT / '.local-runs'
            scratch.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as directory:
                root = Path(directory)
                path = root / '.github/workflows/fixture.yml'
                path.parent.mkdir(parents=True)
                shell, command = text.split('\n')
                path.write_text('jobs:\n  test:\n    steps:\n      - shell: '
                                + shell + '\n        run: ' + command + '\n')
                found = [finding for _, finding in self.checker.scan_repository(root)]
            expected = kind == 'WORKFLOW_FLAG'
        elif kind == 'EXEMPTION':
            found, exempt = self.checker.scan_source('python3 x.py ' + text)
            self.assertEqual(exempt, [])
            self.assertEqual(self.checker.scan_source(
                'python3 x.py # isolation: exempt #8202'), ([], [(1, '8202')]))
            expected = True
        else:
            found = self.checker.scan_shell(text)
            expected = kind == 'FLAG'
        self.assertEqual(bool(found), expected, (kind, text, found))
        self.assertFalse(any(item.malformed for item in found), (kind, text, found))


def case_test(kind, text):
    def test(self):
        self.check_case(kind, text)
    test.__doc__ = f'{kind}: {text!r}'
    return test


for number, (kind, text) in enumerate(CASES, 1):
    setattr(ReviewedAdversarialRows8202, f'test_r3_{number:02d}_{kind.lower()}',
            case_test(kind, text))


if __name__ == '__main__':
    unittest.main()
