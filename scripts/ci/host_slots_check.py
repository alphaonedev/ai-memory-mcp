#!/usr/bin/env python3
"""Check the host-slot configuration against itself and the workflow files (#9231).

The slot configuration (scripts/ci/host_slots.json) lists every registered self-hosted
runner, names every host semaphore gate, its slot count and the runners that serve a leg
gated by it. Rules:

* the configuration is well typed (one error line, never a traceback, on a malformed file);
* serving runners are registered runners, none listed twice, and never exceed the slot count,
  so a job that holds a runner always finds a slot and never idles in the semaphore wait;
* every `host_semaphore.py` call in a workflow or composite action under .github (`.yml` and
  `.yaml`) names a literal configured gate with `--name` in any position, gives `--max-wait-secs`
  exactly once before the ` -- ` of the wrapped command, and every configured gate is called;
* HOST_SEMAPHORE_MAX_WAIT_SECS has exactly one definition across the workflows and composite
  actions, parsed with the YAML subset parser of scripts/ci/taint_boundary.py, and is at most
  IDLE_SEAT_CEILING_SECS (scripts/ci/host_slot_limits.py, the value host_semaphore.py also refuses
  above at run time);
* in the run text of those files HOST_SEMAPHORE_MAX_WAIT_SECS appears only as its env mapping key or as
  a plain `$KEY` / `${KEY}` read: any other use (an assignment, export, declare, read, `${KEY:=v}`, an env
  prefix, an expression read) is refused, so the one parsed definition is the only value;
* the slot count of the gated leg in ci.yml equals the configured slots.

CI runs it inside the existing "Shard partition and wiring unit tests (#6344)" step: unittest discover
runs test_slot_wait_outcome_9231, which executes this script on the repository (a failing script is a red test).

Usage: python3 -I scripts/ci/host_slots_check.py
Exit 0 when everything holds, 1 with one line per violation, 2 on a malformed configuration.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import taint_boundary  # noqa: E402  (the repository's own YAML subset parser)
from host_slot_limits import IDLE_SEAT_CEILING_SECS  # noqa: E402  (the one ceiling, shared with host_semaphore.py)

REPO = HERE.parents[1]
CONFIG_PATH = HERE / 'host_slots.json'
GITHUB_DIR = REPO / '.github'
WAIT_KEY = 'HOST_SEMAPHORE_MAX_WAIT_SECS'
SLOTS_KEY = 'HOST_SEMAPHORE_SLOTS'
MAX_SLOTS = 64
GATE_NAME_RE = re.compile(r'^[A-Za-z0-9_-]+$')
CALL_RE = re.compile(r'python3?\s+(?:-\S+\s+)*\S*host_semaphore\.py\b')
NAME_FLAG_RE = re.compile(r'(?:^|\s)--name(?:=|\s+)(\S+)')
MAX_WAIT_FLAG_RE = re.compile(r'(?:^|\s)--max-wait-secs(?:=|\s|$)')
# decision: an allowlist of the env mapping key and a plain $ / ${} read over a list of forbidden assignment
# forms, because shell has open-ended ways to write a variable (export, declare, readonly, local, read,
# printf -v, ${:=}, eval, env X=) and an allowlist fails closed on each (#9231 R2-C).
WAIT_KEY_USE_RE = re.compile(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % WAIT_KEY)
WAIT_KEY_MAPPING_RE = re.compile(r'\s*%s\s*:' % WAIT_KEY)
SLOTS_EXPR_RE = re.compile(r"&& '(\d+)' \|\| '0'")
EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_MALFORMED = 2


class ConfigError(Exception):
    """The slot configuration is malformed; the message is the one error line."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _string_list(value, where):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError('%s must be a list of non-empty strings' % where)
    return value


def load_config(path=CONFIG_PATH):
    """The parsed, type and range checked configuration; ConfigError with one line otherwise."""
    try:
        cfg = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ConfigError('%s is unreadable or not JSON (%s)' % (Path(path).name, type(exc).__name__))
    if not isinstance(cfg, dict):
        raise ConfigError('top level must be an object')
    _string_list(cfg.get('registered_runners'), 'registered_runners')
    gates = cfg.get('gates')
    if not isinstance(gates, dict) or not gates:
        raise ConfigError('gates must be a non-empty object')
    for name, gate in gates.items():
        if not GATE_NAME_RE.match(name):
            raise ConfigError('gate name %r is not a plain name' % name)
        if not isinstance(gate, dict):
            raise ConfigError('gate %s must be an object' % name)
        if not _is_int(gate.get('slots')) or not 1 <= gate['slots'] <= MAX_SLOTS:
            raise ConfigError('gate %s: slots must be an integer from 1 to %d' % (name, MAX_SLOTS))
        if not isinstance(gate.get('label'), str) or not gate['label']:
            raise ConfigError('gate %s: label must be a non-empty string' % name)
        _string_list(gate.get('serving_runners'), 'gate %s: serving_runners' % name)
    return cfg


def config_violations(cfg):
    """One line per gate whose serving runners exceed its slots, repeat, or are not registered."""
    found = []
    registered = cfg['registered_runners']
    if len(set(registered)) != len(registered):
        found.append('registered_runners: a runner is listed twice')
    for name, gate in sorted(cfg['gates'].items()):
        runners = gate['serving_runners']
        if len(set(runners)) != len(runners):
            found.append('%s: a serving runner is listed twice' % name)
        for runner in runners:
            if runner not in registered:
                found.append('%s: serving runner %s is not a registered runner' % (name, runner))
        if len(runners) > gate['slots']:
            found.append('%s: %d serving runners for %d slots' % (name, len(runners), gate['slots']))
    return found


def _code_lines(text):
    """The text with comment-only lines blanked and shell line continuations joined."""
    lines = [('' if line.lstrip().startswith('#') else line) for line in text.splitlines()]
    return re.sub(r'\\\n', ' ', '\n'.join(lines)).splitlines()


def call_site_violations(cfg, workflow_texts):
    """One line per call with no literal gate name, of an unconfigured gate, and per gate never called."""
    called = set()
    found = []
    for wf, text in sorted(workflow_texts.items()):
        for line in _code_lines(text):
            if 'host_semaphore.py' not in line:
                continue
            call = CALL_RE.search(line)
            if call is None:
                found.append('%s: a host_semaphore.py reference that is not a python3 call' % wf)
                continue
            segment = re.split(r'\s--(?:\s|$)', line[call.end():], maxsplit=1)[0]
            names = NAME_FLAG_RE.findall(segment)
            if len(names) != 1 or not GATE_NAME_RE.match(names[0]):
                found.append('%s: a host_semaphore.py call without exactly one literal --name' % wf)
                continue
            called.add(names[0])
            if names[0] not in cfg['gates']:
                found.append('%s: calls the unconfigured gate %s' % (wf, names[0]))
            if len(MAX_WAIT_FLAG_RE.findall(segment)) != 1:
                found.append('%s: a host_semaphore.py call without exactly one --max-wait-secs' % wf)
    for name in sorted(set(cfg['gates']) - called):
        found.append('%s: configured but no workflow calls it' % name)
    return found


def _allowed_wait_key_use(line, start, end):
    """True when the key at LINE[START:END] is the env mapping key or a plain $KEY / ${KEY} read."""
    if start == len(line) - len(line.lstrip()) and WAIT_KEY_MAPPING_RE.match(line):
        return True
    if line[start - 1:start] == '$' and (start < 2 or line[start - 2] != '$'):
        return True
    return line[max(0, start - 2):start] == '${' and line[end:end + 1] == '}'


def wait_key_violations(texts):
    """One line per use of the wait key in run text that is neither its env mapping key nor a plain read."""
    found = []
    for rel, text in sorted(texts.items()):
        for line in _code_lines(text):
            for use in WAIT_KEY_USE_RE.finditer(line):
                if not _allowed_wait_key_use(line, use.start(), use.end()):
                    found.append('%s: %s is used other than as its env mapping key or a plain $ read; '
                                 'set it only in the one env mapping' % (rel, WAIT_KEY))
    return found


def _env_definitions(node, key, out):
    """Every value of KEY found in any `env` mapping of the parsed YAML document NODE."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == 'env' and isinstance(v, dict) and key in v:
                out.append(v[key])
            _env_definitions(v, key, out)
    elif isinstance(node, list):
        for item in node:
            _env_definitions(item, key, out)


def parsed_env_values(workflow_texts, key):
    """[(file, value)] of every definition of KEY in the workflows, parsed (comments and quoting ignored)."""
    found = []
    for wf, text in sorted(workflow_texts.items()):
        values = []
        _env_definitions(taint_boundary.parse_yaml(text, wf), key, values)
        found.extend((wf, value) for value in values)
    return found


def bound_violations(cfg, workflow_texts):
    """The wait bound is defined once, is an integer and is within the idle seat ceiling; slots match the config."""
    found = []
    waits = parsed_env_values(workflow_texts, WAIT_KEY)
    if len(waits) != 1:
        found.append('%s must be defined exactly once, found %d' % (WAIT_KEY, len(waits)))
    for wf, value in waits:
        if _is_int(value):  # a bare 3600 is an integer scalar for the parser; quoting must not matter
            value = str(value)
        if not isinstance(value, str) or not value.isdigit():
            found.append('%s: %s is not a plain integer (%r)' % (wf, WAIT_KEY, value))
        elif int(value) > IDLE_SEAT_CEILING_SECS:
            found.append('%s: %s %s is above the %d s idle seat ceiling'
                         % (wf, WAIT_KEY, value, IDLE_SEAT_CEILING_SECS))
    slots = parsed_env_values(workflow_texts, SLOTS_KEY)
    configured = {gate['slots'] for gate in cfg['gates'].values()}
    for wf, value in slots:
        match = SLOTS_EXPR_RE.search(value) if isinstance(value, str) else None
        if match is None or int(match.group(1)) not in configured:
            found.append('%s: %s %r matches no configured slot count %s'
                         % (wf, SLOTS_KEY, value, sorted(configured)))
    if not slots:
        found.append('%s is defined nowhere' % SLOTS_KEY)
    return found


def github_texts(github_dir=GITHUB_DIR):
    """{relative path: text} of every .yml and .yaml file under .github (workflows and composite actions)."""
    paths = sorted(p for pattern in ('*.yml', '*.yaml') for p in github_dir.rglob(pattern))
    return {str(p.relative_to(github_dir)): p.read_text(encoding='utf-8') for p in paths}


def main():
    try:
        cfg = load_config()
        texts = github_texts()
        # every .github text, composite actions included: a definition there counts and is bounded too
        problems = (config_violations(cfg) + call_site_violations(cfg, texts)
                    + bound_violations(cfg, texts) + wait_key_violations(texts))
    except (ConfigError, taint_boundary.YamlError) as exc:
        print('host_slots_check: malformed: %s' % exc)
        return EXIT_MALFORMED
    for line in problems:
        print('host_slots_check: %s' % line)
    return EXIT_VIOLATION if problems else EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
