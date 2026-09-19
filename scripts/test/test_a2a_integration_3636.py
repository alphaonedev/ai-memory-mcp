#!/usr/bin/env python3
"""Issue #3636: keep the integration path and its Pages twin usable."""
import json
import os
import signal
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]

class CodeBlocks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.active = False
    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.active = True
            self.blocks.append('')
    def handle_endtag(self, tag):
        if tag == 'pre':
            self.active = False
    def handle_data(self, data):
        if self.active:
            self.blocks[-1] += data

class Integration3636(unittest.TestCase):
    def test_3636_complete_reader_path(self):
        guide = (ROOT / 'docs/a2a-integration.md').read_text()
        headings = re.findall(r'^## (.+)$', guide, re.M)
        self.assertEqual(headings, [
            '1. The model in one page', '2. Choose your receive pattern',
            '3. Enrolment, end to end', '4. Sending',
            '5. Drive an agent loop from wakes', '6. Multi-host',
            '7. Security model', '8. Degraded modes', '9. Troubleshooting'])
        for required in ['--daemon-producer', '--agent-type', '--include-agent',
                         'allowed_sender_agent_ids', 'peer_not_enrolled',
                         'deferred-audit spool ancestor permits untrusted rename',
                         'named_curve', '#3631', '#3635', '#3473',
                         'self-continuation', 'deduplicate', 'debounce', 'X-API-Key: $API_KEY']:
            self.assertIn(required, guide)

    def test_3636_pages_examples_match_markdown(self):
        guide = (ROOT / 'docs/a2a-integration.md').read_text()
        page = (ROOT / 'docs/a2a-integration.html').read_text()
        parser = CodeBlocks()
        parser.feed(page)
        blocks = re.findall(r'^```[^\n]*\n(.*?)^```', guide, re.M | re.S)
        self.assertGreater(len(blocks), 8)
        self.assertEqual([b.rstrip() for b in blocks], [b.rstrip() for b in parser.blocks])
        for shell in re.findall(r'^```bash\n(.*?)^```', guide, re.M | re.S):
            result = subprocess.run(['bash', '-n'], input=shell, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_3636_site_navigation(self):
        for path in (ROOT / 'docs').rglob('*.html'):
            page = path.read_text()
            for nav in re.findall(r'<nav\b.*?</nav>', page, re.S):
                if 'a2a-messaging.html' in nav:
                    self.assertIn('a2a-integration.html', nav, str(path))
        atlas = (ROOT / 'docs/a2a-messaging.html').read_text()
        self.assertIn('a2a-integration.html', atlas)
        self.assertIn('wake-hub.md', atlas)

class ShellGate3636(unittest.TestCase):
    def exercise(self, mode):
        guide = (ROOT / 'docs/a2a-integration.md').read_text()
        gate = next(b for b in re.findall(r'^```bash\n(.*?)^```', guide, re.M | re.S)
                    if b.startswith('#!/usr/bin/env bash'))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'gate.sh').write_text(gate)
            fake = base / 'ai-memory'
            fake.write_text("""#!/usr/bin/env python3
import json, os, time
from pathlib import Path
base = Path(os.environ['FAKE_ROOT'])
mode = os.environ['FAKE_MODE']
with (base / 'reads').open('a') as f: f.write('read\\n')
time.sleep(0.04)
rows = [] if mode == 'empty' else [{'id':'one'}, {'id':'two'}]
if mode == 'full': rows = [{'id':str(i)} for i in range(500)]
if mode == 'burst' and (base / 'calls').exists(): rows.append({'id':'three'})
print(json.dumps({'messages':rows}))
""")
            adapter = base / 'adapter'
            adapter.write_text("""#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
base = Path(os.environ['FAKE_ROOT'])
path = base / 'calls'
first = not path.exists()
rows = json.loads(Path(sys.argv[1]).read_text())
with path.open('a') as f: f.write(json.dumps(rows) + '\\n')
time.sleep(2)
if os.environ['FAKE_MODE'] == 'retry' and first: sys.exit(1)
""")
            fake.chmod(0o700)
            adapter.chmod(0o700)
            environment = dict(os.environ, PATH=str(base) + os.pathsep + os.environ['PATH'],
                               AGENT='ai:test', AGENT_PASS=str(adapter),
                               GATE_STATE=str(base / 'state'), FAKE_ROOT=str(base), FAKE_MODE=mode)
            process = subprocess.Popen(['bash', str(base / 'gate.sh')], env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       start_new_session=True, text=True)
            state = {}
            try:
                deadline = time.monotonic() + (3 if mode == 'empty' else 20)
                while time.monotonic() < deadline:
                    path = base / 'state/state.json'
                    if path.exists():
                        state = json.loads(path.read_text())
                    goal = 3 if mode == 'burst' else 2
                    if len(state.get('done', [])) == goal or process.poll() is not None:
                        break
                    time.sleep(0.03)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                _, errors = process.communicate(timeout=5)
            calls = [json.loads(line) for line in (base / 'calls').read_text().splitlines()] if (base / 'calls').exists() else []
            reads = (base / 'reads').read_text().splitlines()
            return state, calls, reads, errors

    def test_3636_burst_dedup_and_reads_during_pass(self):
        state, calls, reads, errors = self.exercise('burst')
        self.assertEqual(state['done'], ['one', 'three', 'two'], errors)
        self.assertEqual([[r['id'] for r in batch] for batch in calls], [['one', 'two'], ['three']])
        self.assertGreater(len(reads), 8, 'reader must keep running during the adapter')

    def test_3636_failed_pass_is_retried(self):
        state, calls, _, errors = self.exercise('retry')
        self.assertEqual(state['done'], ['one', 'two'], errors)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertIn('pending batch retained', errors)

    def test_3636_empty_timeouts_do_not_run_agent(self):
        state, calls, reads, _ = self.exercise('empty')
        self.assertEqual(calls, [])
        self.assertEqual(state['done'], [])
        self.assertGreater(len(reads), 1)

    def test_3636_full_page_refuses_false_completion(self):
        state, calls, _, errors = self.exercise('full')
        self.assertEqual(calls, [])
        self.assertEqual(state['done'], [])
        self.assertIn('reconcile older rows', errors)

if __name__ == '__main__':
    unittest.main()
