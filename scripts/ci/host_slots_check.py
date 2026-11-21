#!/usr/bin/env python3
"""Check the host-slot configuration against itself and the workflow files (#9231).

The slot configuration (scripts/ci/host_slots.json) names every host semaphore
gate, its slot count and the runners that serve a leg gated by it. Rule: the
number of serving runners never exceeds the slot count, so a job that holds a
runner always finds a slot and never idles in the semaphore wait.

Usage: python3 -I scripts/ci/host_slots_check.py
Exit 0 when the configuration holds, 1 with one line per violation.
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO / 'scripts' / 'ci' / 'host_slots.json'
WORKFLOW_DIR = REPO / '.github' / 'workflows'
CALL_RE = re.compile(r'host_semaphore\.py\s+--name\s+(\S+)')
EXIT_OK = 0
EXIT_VIOLATION = 1


def config_violations(cfg):
    """Return one line per gate whose serving runners exceed its slots or repeat a runner."""
    found = []
    for name, gate in sorted(cfg['gates'].items()):
        runners = gate['serving_runners']
        if len(set(runners)) != len(runners):
            found.append('%s: a serving runner is listed twice' % name)
        if len(runners) > gate['slots']:
            found.append('%s: %d serving runners for %d slots'
                         % (name, len(runners), gate['slots']))
    return found


def call_site_violations(cfg, workflow_texts):
    """Return one line per workflow call of an unconfigured gate and per gate never called."""
    called = set()
    found = []
    for wf, text in sorted(workflow_texts.items()):
        for name in CALL_RE.findall(text):
            called.add(name)
            if name not in cfg['gates']:
                found.append('%s: calls the unconfigured gate %s' % (wf, name))
    for name in sorted(set(cfg['gates']) - called):
        found.append('%s: configured but no workflow calls it' % name)
    return found


def main():
    cfg = json.loads(CONFIG_PATH.read_text())
    texts = {p.name: p.read_text() for p in sorted(WORKFLOW_DIR.glob('*.yml'))}
    problems = config_violations(cfg) + call_site_violations(cfg, texts)
    for line in problems:
        print('host_slots_check: %s' % line)
    return EXIT_VIOLATION if problems else EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
