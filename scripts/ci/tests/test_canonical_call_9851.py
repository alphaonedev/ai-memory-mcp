#!/usr/bin/env python3
"""The canonical-form allowlist of the host_semaphore call scan (#9851, round 1 of PR 9851).

decision: a canonical-form allowlist over a better bash and YAML emulation, because a checker that only admits text
it can read with no interpretation cannot disagree with bash. These tests pin that rule for all inputs:

* the charset invariant over EVERY ASCII character and three non-ASCII ones, against a set written out by hand;
* one row per reviewer repro (code M1 to M4, L1 R3/R4, security M1, M2), each with its exact reason;
* every YAML scalar style a `run` value can take;
* the 100K-call line and the 100K-line block, each with a wall-clock ceiling (security L1);
* one mutant per rule this module owns, each red.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_canonical_call_9851.py'
Standard library only.
"""
import collections
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_slot_wait_outcome_9231 import (  # noqa: E402
    CALL_HEAD, CI_DIR, S_DECODED, S_NEVER, S_NOT_CALL, S_NOT_YAML, S_OUTSIDE, S_POSITIONAL, S_TOKEN_AGAIN, SCAN_GOOD,
    SCAN_W, TokenScanFailsClosed, hsc, load_checker, need, run_block, s_char)

CFG = TokenScanFailsClosed.CFG
# Written out by hand (not taken from the checker): the characters a canonical call line may hold.
GOOD_PUNCTUATION = ' _./=:,-'
GOOD_HAND = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' + GOOD_PUNCTUATION)
# Written out by hand: every printable ASCII character outside the canonical set.
BAD_PRINTABLE_HAND = '!"#$%&\'()*+;<>?@[\\]^`{|}~'
# The ASCII controls (0 to 31 and 127); a newline ends the line, so it cannot sit inside one and is left out.
NEWLINE = 10
DELETE = 127
BAD_CONTROLS = tuple(chr(code) for code in range(32) if code != NEWLINE) + (chr(DELETE),)
# Three non-ASCII characters: a no-break space, a letter with an accent and a bidi override.
BAD_NON_ASCII = (' ', 'é', '‮')
ASCII_SIZE = 128
LABEL_CALL = CALL_HEAD + ' --name g --slots 1 --max-wait-secs 600 --label %s -- bash'
BIG = 100000
# The shortest canonical call: 100K of them stay under the 8 MiB cap of the YAML subset parser.
SHORT_CALL = 'python3 scripts/ci/host_semaphore.py --name g --slots 1 --max-wait-secs 1 -- b'
YAML_CAP_BYTES = 8 * 1024 * 1024
S_UNREADABLE = ('workflows/w.yml: the YAML subset parser cannot read this file, so its host_semaphore lines '
                'are not checked')
LINE_CEILING_SECS = 5.0
BLOCK_CEILING_SECS = 10.0
# #9847 r2 findings A and B: the reasons of the decoded-script scan, written out by hand.
S_JOINED = ('workflows/w.yml: a host_semaphore line joined from two or more lines by a backslash-newline '
            'continuation (the shell runs the joined line, which is never a canonical call)')
S_ESCAPED = ('workflows/w.yml: a parsed YAML key or value outside the run values holds host_semaphore where no raw '
             'line does (an escaped spelling)')
S_KEY_USE = ('workflows/w.yml: HOST_SEMAPHORE_MAX_WAIT_SECS is used other than as its env mapping key or a plain $ '
             'read; set it only in the one env mapping')
GOOD_TAIL = ' --name g --slots 1 --max-wait-secs 600 -- bash'
EVIL_TAIL = ' --name g --slots 1 --max-wait-secs 600 --root /evil -- bash x'


def positions(char):
    """The call lines with CHAR inside a value, between two words, at the end and inside the token."""
    return (
        ('in a value', SCAN_GOOD.replace('600', '6%s00' % char)),
        ('between words', SCAN_GOOD.replace(' --slots', ' %s --slots' % char)),
        ('at the end', SCAN_GOOD + char),
        ('in the token', SCAN_GOOD.replace('host_semaphore', 'host_sema%sphore' % char)),
    )


def label_block(value):
    """A `run: |` block holding the canonical call with the --label value VALUE."""
    return run_block(LABEL_CALL % value)


def scan(text, cfg=CFG):
    return hsc.call_site_violations(cfg, {SCAN_W: text})


class CharsetInvariant(unittest.TestCase):
    """Every character outside the canonical set is a finding naming its code point, wherever it sits."""

    def test_the_hand_written_sets_partition_ascii(self):
        bad = set(BAD_PRINTABLE_HAND) | set(BAD_CONTROLS) | {chr(NEWLINE)}
        self.assertEqual(len(BAD_PRINTABLE_HAND), len(set(BAD_PRINTABLE_HAND)))
        self.assertEqual(bad & GOOD_HAND, set())
        self.assertEqual(bad | GOOD_HAND, {chr(code) for code in range(ASCII_SIZE)})

    def test_the_checker_set_is_the_hand_written_set(self):
        self.assertEqual(hsc.CANONICAL_CHARS, GOOD_HAND)
        for code in range(ASCII_SIZE):
            with self.subTest(code=code):
                self.assertEqual(hsc.NON_CANONICAL_RE.fullmatch(chr(code)) is None, chr(code) in GOOD_HAND)

    def test_every_character_outside_the_set_is_a_finding_at_every_position(self):
        for char in tuple(BAD_PRINTABLE_HAND) + BAD_CONTROLS + BAD_NON_ASCII:
            for where, line in positions(char):
                with self.subTest(code='U+%04X' % ord(char), where=where):
                    self.assertEqual(scan(run_block(line)), [s_char('U+%04X' % ord(char)), S_NEVER])

    def test_every_canonical_character_is_admitted_in_a_label(self):
        for char in sorted(GOOD_HAND - {' ', '-'}):
            with self.subTest(char=char):
                self.assertEqual(scan(run_block(LABEL_CALL % ('a' + char + 'b'))), [])


class ReviewerRepros(unittest.TestCase):
    """One row per finding of REVIEW-9851-code-r1 and REVIEW-9851-security-r1, with its exact reason."""

    TABLE = [
        # code M1: a ), a backtick or an & inside a word ended the old segment
        ('code-M1 $(pwd)', run_block(LABEL_CALL.replace('--label %s', '--label=$(pwd) --root /x')),
         [s_char('U+0024'), S_NEVER]),
        ('code-M1 backtick', label_block('`pwd` --root /x'), [s_char('U+0060'), S_NEVER]),
        ('code-M1 $((1))', label_block('$((1)) --root /x'), [s_char('U+0024'), S_NEVER]),
        ('code-M1 >&', label_block('x>&2 --root /x'), [s_char('U+003E'), S_NEVER]),
        # code M3 and security M1: ANSI-C quoting
        ("code-M3 $'a\\''", label_block("$'a\\'' --root /x"), [s_char('U+0024'), S_NEVER]),
        ('security-M1 $"', label_block('$"a" --config /evil'), [s_char('U+0024'), S_NEVER]),
        # code M4: a label value in any form
        ('code-M4 $L', label_block('$L'), [s_char('U+0024'), S_NEVER]),
        ('code-M4 *', label_block('*'), [s_char('U+002A'), S_NEVER]),
        ('code-M4 ${{ }}', label_block('${{matrix.l}}'), [s_char('U+0024'), S_NEVER]),
        # code L1: the reviewer mutants R3 (a # mid-word) and R4 (a subshell call)
        ('code-L1 R3 a#b', label_block('a#b --root /x'), [s_char('U+0023'), S_NEVER]),
        ('code-L1 R4 subshell', run_block('( %s )' % SCAN_GOOD), [s_char('U+0028'), S_NEVER]),
        # code M2 and security M2: a run value whose lines are not the lines the shell runs
        ('code-M2 folded', 'run: >\n  %s\n  --root /x -- cargo\n' % CALL_HEAD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        # the YAML subset parser refuses a plain multi-line scalar: a finding, never clean
        ('code-M2 plain multi-line', 'run: %s\n  --root /x -- cargo\n' % CALL_HEAD,
         [S_OUTSIDE, S_UNREADABLE, S_NEVER]),
        ('security-M2 double-quoted escape', 'run: "%s"\n' % SCAN_GOOD.replace(' -- bash', '\\x20--config\\x20/e -- b'),
         [S_OUTSIDE, S_DECODED, S_NEVER]),
        # delta r2 finding D: the interpreter word is exactly python3, never a word that starts with it
        ('r2-D python3x', run_block('exec python3x -I scripts/ci/host_semaphore.py' + GOOD_TAIL),
         [S_NOT_CALL, S_NEVER]),
        ('r2-D python3.12', run_block('exec python3.12 -I scripts/ci/host_semaphore.py' + GOOD_TAIL),
         [S_NOT_CALL, S_NEVER]),
        ('r2-D python3-evil', run_block('exec python3-evil -I scripts/ci/host_semaphore.py' + GOOD_TAIL),
         [S_NOT_CALL, S_NEVER]),
    ]

    def test_each_repro_is_its_exact_finding(self):
        for row, text, expected in self.TABLE:
            with self.subTest(row):
                self.assertEqual(scan(text), expected)


class YamlStyles(unittest.TestCase):
    """The token is admitted only on a content line of a `run: |` literal block of a .yml or .yaml file."""

    TABLE = [
        ('literal |', run_block(SCAN_GOOD), []),
        ('literal |-', 'run: |-\n  %s\n' % SCAN_GOOD, []),
        ('literal |+ with a comment', 'run: |+ # keep\n  %s\n' % SCAN_GOOD, []),
        ('literal |2', 'run: |2\n  %s\n' % SCAN_GOOD, []),
        ('folded >', 'run: >\n  %s\n' % SCAN_GOOD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('folded >-', 'run: >-\n  %s\n' % SCAN_GOOD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('plain', 'run: %s\n' % SCAN_GOOD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('single-quoted', "run: '%s'\n" % SCAN_GOOD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('double-quoted', 'run: "%s"\n' % SCAN_GOOD, [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('a key', 'host_semaphore: 1\n' + run_block(SCAN_GOOD), [S_OUTSIDE]),
        ('a comment line', '# host_semaphore\n' + run_block(SCAN_GOOD), [S_OUTSIDE]),
        ('a literal block under another key', run_block(SCAN_GOOD, key='script'), [S_OUTSIDE, S_NEVER]),
    ]

    def test_each_style(self):
        for row, text, expected in self.TABLE:
            with self.subTest(row):
                self.assertEqual(scan(text), expected)

    def test_a_flow_mapping(self):
        text = 'steps: [{run: %s}]\n' % SCAN_GOOD
        self.assertEqual(scan(text)[0], S_OUTSIDE)
        self.assertEqual(scan(text)[-1], S_NEVER)

    def test_a_file_that_is_not_yaml(self):
        for name in ('workflows/w.json', 'workflows/w.yml.txt', 'scripts.sh'):
            with self.subTest(name):
                got = hsc.call_site_violations(CFG, {name: run_block(SCAN_GOOD), SCAN_W: run_block(SCAN_GOOD)})
                self.assertEqual(got, [S_NOT_YAML % name])


class LinearBounds(unittest.TestCase):
    """Security L1: no input up to a 100K-call line or a 100K-line block takes more than linear time."""

    def timed(self, text, ceiling):
        start = time.monotonic()
        got = scan(text)
        self.assertLess(time.monotonic() - start, ceiling)
        return got

    def test_a_100k_call_line(self):
        text = run_block(' '.join([SHORT_CALL] * BIG))
        self.assertGreater(len(text), 7000000)
        self.assertLess(len(text), YAML_CAP_BYTES)
        self.assertEqual(self.timed(text, LINE_CEILING_SECS), [S_TOKEN_AGAIN, S_NEVER])

    def test_a_100k_call_line_with_separators(self):
        text = run_block(';'.join([SHORT_CALL] * BIG))
        self.assertLess(len(text), YAML_CAP_BYTES)
        self.assertEqual(self.timed(text, LINE_CEILING_SECS), [s_char('U+003B'), S_NEVER])

    def test_a_100k_line_block(self):
        text = run_block(*[SHORT_CALL] * BIG)
        self.assertLess(len(text), YAML_CAP_BYTES)
        self.assertEqual(self.timed(text, BLOCK_CEILING_SECS), [])

    def test_a_100k_line_block_of_findings(self):
        text = run_block(*[SHORT_CALL + '$'] * BIG)
        self.assertLess(len(text), YAML_CAP_BYTES)
        got = self.timed(text, BLOCK_CEILING_SECS)
        self.assertEqual(collections.Counter(got), collections.Counter({s_char('U+0024'): BIG, S_NEVER: 1}))

    def test_a_file_over_the_parser_cap_is_a_finding(self):
        """Fail closed: a canonical block too large for the YAML cross-check is never clean."""
        text = run_block(*[SCAN_GOOD] * BIG)
        self.assertGreater(len(text), YAML_CAP_BYTES)
        self.assertEqual(self.timed(text, BLOCK_CEILING_SECS), [S_UNREADABLE])


class DecodedScriptInvariant(unittest.TestCase):
    """#9847, delta r2 findings A and B: the checker judges what the runner will execute.

    For every way YAML and the shell can spell a host semaphore call (backslash-newline continuation, the YAML
    escapes \\x5f, \\u005f and \\U0000005f of the underscore, folded and literal block scalars, quoting, line joins),
    the call is either found and checked against the canonical form or reported as a finding with a named reason.
    Zero findings is never the result of a spelling. Every expected row is written out by hand."""

    TABLE = [
        # finding A: a backslash-newline continuation, which the shell removes before it splits words
        ('continuation inside the token', run_block('exec python3 -I scripts/ci/host_\\', 'semaphore.py' + EVIL_TAIL),
         [S_JOINED, S_NEVER]),
        ('continuation inside the upper-case token', run_block('exec python3 -I scripts/ci/HOST_\\',
                                                               'SEMAPHORE.PY' + EVIL_TAIL), [S_JOINED, S_NEVER]),
        ('continuation inside the token of a canonical call',
         run_block('python3 scripts/ci/host_sema\\', 'phore.py' + GOOD_TAIL), [S_JOINED, S_NEVER]),
        ('continuation before a canonical call line', run_block('env X=1 \\', 'python3 scripts/ci/host_semaphore.py'
                                                                 + GOOD_TAIL), [S_JOINED]),
        ('continuation after a call line', run_block(SCAN_GOOD + ' \\', '--root /x'),
         [s_char('U+005C'), S_JOINED, S_NEVER]),
        ('continuation in a comment line (over-approximated: a finding)', run_block('# host_\\', 'semaphore'),
         [S_JOINED, S_NEVER]),
        ('CRLF line ends with the continuation inside the token',
         'run: |\r\n  exec python3 scripts/ci/host_\\\r\n  semaphore.py%s\r\n' % EVIL_TAIL, [S_JOINED, S_NEVER]),
        ('folded > with a blank line under the continuation',
         'run: >\n  exec python3 scripts/ci/host_\\\n\n  semaphore.py%s\n' % EVIL_TAIL, [S_JOINED, S_NEVER]),
        ('folded > joins with a space: bash runs no host_semaphore',
         'run: >\n  exec python3 scripts/ci/host_\\\n  semaphore.py%s\n' % EVIL_TAIL, [S_NEVER]),
        ('double-quoted \\n line join', 'run: "exec \\\\\\npython3 scripts/ci/host_semaphore.py%s"\n' % GOOD_TAIL,
         [S_OUTSIDE, S_DECODED, S_JOINED, S_NEVER]),
        # finding B: a YAML escape of the underscore, decoded before the runner sees the script
        ('double-quoted \\x5f', 'run: "exec python3 scripts/ci/host\\x5fsemaphore.py%s"\n' % EVIL_TAIL,
         [S_DECODED, S_NEVER]),
        ('double-quoted \\u005f', 'run: "exec python3 scripts/ci/host\\u005fsemaphore.py%s"\n' % EVIL_TAIL,
         [S_DECODED, S_NEVER]),
        ('double-quoted \\U0000005f', 'run: "exec python3 scripts/ci/host\\U0000005fsemaphore.py%s"\n' % EVIL_TAIL,
         [S_DECODED, S_NEVER]),
        ('\\x5f beside a canonical call', run_block(SCAN_GOOD) + 'env:\n  X: "host\\x5fsemaphore"\n', [S_ESCAPED]),
        ('\\u005f in a key beside a canonical call', '"host\\u005fsemaphore": 1\n' + run_block(SCAN_GOOD),
         [S_ESCAPED]),
        ('\\x5f in a run value beside a canonical call',
         'jobs:\n  a:\n    steps:\n      - run: |\n          %s\n      - run: "python3 scripts/ci/host\\x5fsemaphore.py'
         ' --root /e -- b"\n' % SCAN_GOOD, [S_DECODED]),
        # quoting the shell undoes: still the token, and a finding
        ('single-quoted with a doubled quote', "run: 'python3 scripts/ci/host_semaphore.py --label ''x''%s'\n"
         % GOOD_TAIL, [S_OUTSIDE, S_DECODED, S_NEVER]),
    ]

    def test_every_spelling_is_its_exact_finding(self):
        for row, text, expected in self.TABLE:
            with self.subTest(row):
                self.assertEqual(scan(text), expected)

    def test_a_continuation_in_a_file_that_is_not_yaml(self):
        texts = {'scripts.sh': 'python3 scripts/ci/host_\\\nsemaphore.py x\n', SCAN_W: run_block(SCAN_GOOD)}
        self.assertEqual(hsc.call_site_violations(CFG, texts), [S_NOT_YAML % 'scripts.sh'])

    def test_the_wait_key_sibling(self):
        """wait_key_violations scans the same decoded run text: a joined or escaped key use is refused."""
        rows = [
            ('continuation inside the key', 'run: |\n  export HOST_SEMAPHORE_MAX_\\\n  WAIT_SECS=3600\n', [S_KEY_USE]),
            ('\\x5f in the key', 'run: "export HOST\\x5fSEMAPHORE_MAX_WAIT_SECS=3600"\n', [S_KEY_USE]),
            ('a plain read stays admitted', 'run: |\n  echo "$HOST_SEMAPHORE_MAX_WAIT_SECS"\n', []),
        ]
        for row, text, expected in rows:
            with self.subTest(row):
                self.assertEqual(hsc.wait_key_violations({SCAN_W: text}), expected)

    def test_a_100k_block_with_a_continuation_is_linear(self):
        text = run_block(*['echo x'] * BIG + ['exec python3 -I scripts/ci/host_\\', 'semaphore.py' + EVIL_TAIL])
        self.assertGreater(len(text), BIG)
        start = time.monotonic()
        got = scan(text)
        self.assertLess(time.monotonic() - start, BLOCK_CEILING_SECS)
        self.assertEqual(got, [S_JOINED, S_NEVER])

    def test_a_100k_escaped_line_is_linear(self):
        text = 'run: "%s exec python3 scripts/ci/host\\x5fsemaphore.py%s"\n' % ('x ' * BIG, EVIL_TAIL)
        self.assertGreater(len(text), BIG)
        start = time.monotonic()
        got = scan(text)
        self.assertLess(time.monotonic() - start, LINE_CEILING_SECS)
        self.assertEqual(got, [S_DECODED, S_NEVER])


class RuleMutants(unittest.TestCase):
    """One mutant per rule of this module; each goes red on the named row."""

    SPLIT_PATH = run_block('python3 scripts/ci/host_"sema"phore.py --name g')
    # (mutant id, (old text, new text) in host_slots_check.py, workflow texts, expected findings)
    MUTANTS = [
        ('a comma dropped from the charset', ("r'[^A-Za-z0-9 _./=:,-]'", "r'[^A-Za-z0-9 _./=:-]'"),
         {SCAN_W: run_block(LABEL_CALL % 'a,b')}, []),
        ('a $ added to the charset', ("r'[^A-Za-z0-9 _./=:,-]'", "r'[^A-Za-z0-9 _./=:,$-]'"),
         {SCAN_W: run_block(LABEL_CALL % '$L')}, [s_char('U+0024'), S_NEVER]),
        ('the token searched in the raw line', ("    return NON_CANONICAL_RE.sub('', line)", '    return line'),
         {SCAN_W: SPLIT_PATH}, [s_char('U+0022'), S_NEVER]),
        ('a file that is not YAML admitted', ('        if not wf.endswith(YAML_SUFFIXES):', '        if False:'),
         {'CODEOWNERS': 'scripts/ci/host_semaphore.py @x\n', SCAN_W: run_block(SCAN_GOOD)},
         [S_NOT_YAML % 'CODEOWNERS']),
        ('the R3 shape: a # admitted', ("r'[^A-Za-z0-9 _./=:,-]'", "r'[^A-Za-z0-9 _./=:,#-]'"),
         {SCAN_W: run_block(LABEL_CALL % 'a#b --root /x')}, [s_char('U+0023'), S_NEVER]),
        ('the R4 shape: a ( admitted', ("r'[^A-Za-z0-9 _./=:,-]'", "r'[^A-Za-z0-9 _./=:,(-]'"),
         {SCAN_W: run_block('( %s )' % SCAN_GOOD)}, [s_char('U+0028'), S_NEVER]),
        ('a one-dash word taken as a value', ("not words[index].startswith('-')", 'True'),
         {SCAN_W: run_block(LABEL_CALL % '-x')}, [
             'workflows/w.yml: a host_semaphore.py call whose --label has no value', S_POSITIONAL]),
        # delta r2 finding D: the interpreter word matched by prefix
        ('python3 matched by prefix', ('words[index:index + 1] != [PYTHON_WORD]',
                                       'not words[index].startswith(PYTHON_WORD)'),
         {SCAN_W: run_block('exec python3x -I scripts/ci/host_semaphore.py' + GOOD_TAIL)}, [S_NOT_CALL, S_NEVER]),
        # #9847 continuation class: the join, its count, the parse gate, an empty join, a file that is not YAML
        ('no line continues', ('        if segment.endswith(CONTINUATION):', '        if False:'),
         {SCAN_W: run_block('exec python3 -I scripts/ci/host_\\', 'semaphore.py' + EVIL_TAIL)}, [S_JOINED, S_NEVER]),
        ('a joined line not counted', ('out.joined += sum(', 'out.joined += 0 * sum('),
         {SCAN_W: run_block('env X=1 \\', 'python3 scripts/ci/host_semaphore.py' + GOOD_TAIL)}, [S_JOINED]),
        ('the parse only for a raw token (CRLF)', ('if holds_token or CONTINUATION in text:', 'if holds_token:'),
         {SCAN_W: 'run: |\r\n  exec python3 scripts/ci/host_\\\r\n  semaphore.py%s\r\n' % EVIL_TAIL},
         [S_JOINED, S_NEVER]),
        ('a join before nothing counted',
         ('any(parts[1:])))\n            parts = []', 'True))\n            parts = []'),
         {SCAN_W: run_block(SCAN_GOOD + ' \\')}, [s_char('U+005C'), S_NEVER]),
        ('a continuation outside YAML not joined', ('for source in (text, joined)', 'for source in (text,)'),
         {'scripts.sh': 'python3 scripts/ci/host_\\\nsemaphore.py x\n', SCAN_W: run_block(SCAN_GOOD)},
         [S_NOT_YAML % 'scripts.sh']),
        # #9847 escape class: \x5f in a run value (the parse gate), \u005f in a run value, a key, a value
        ('the parse only for a raw token (\\x5f)', ('if holds_token or CONTINUATION in text:', 'if holds_token:'),
         {SCAN_W: 'run: "exec python3 scripts/ci/host\\x5fsemaphore.py%s"\n' % EVIL_TAIL}, [S_DECODED, S_NEVER]),
        ('the decoded run lines not compared',
         ('found = [] if sorted(decoded.call_lines) == sorted(block_lines) else [F_DECODED_DIFFERS % wf]',
          'found = []'),
         {SCAN_W: 'run: "exec python3 scripts/ci/host\\u005fsemaphore.py%s"\n' % EVIL_TAIL}, [S_DECODED, S_NEVER]),
        ('a key not scanned', ('out.other += sum(1 for line in key.split(',
                               'out.other += 0 * sum(1 for line in key.split('),
         {SCAN_W: '"host\\u005fsemaphore": 1\n' + run_block(SCAN_GOOD)}, [S_ESCAPED]),
        ('a value not scanned', ('out.other += sum(1 for line in node.split(',
                                 'out.other += 0 * sum(1 for line in node.split('),
         {SCAN_W: run_block(SCAN_GOOD) + 'env:\n  X: "host\\x5fsemaphore"\n'}, [S_ESCAPED]),
        # #9847 quoting and folding class: a single-quoted run value and a folded one, read decoded
        ('a quoted run value not compared',
         ('found = [] if sorted(decoded.call_lines) == sorted(block_lines) else [F_DECODED_DIFFERS % wf]',
          'found = []'),
         {SCAN_W: "run: 'python3 scripts/ci/host_semaphore.py --label ''x''%s'\n" % GOOD_TAIL},
         [S_OUTSIDE, S_DECODED, S_NEVER]),
        ('a folded run value not joined', ('        if segment.endswith(CONTINUATION):', '        if False:'),
         {SCAN_W: 'run: >\n  exec python3 scripts/ci/host_\\\n\n  semaphore.py%s\n' % EVIL_TAIL}, [S_JOINED, S_NEVER]),
    ]
    # (mutant id, (old text, new text), workflow text, expected wait-key findings) of the #9847 wait-key sibling
    WAIT_MUTANTS = [
        ('the wait key joined with a space', ("return '\\n'.join(lines).replace(CONTINUATION + '\\n', '')",
                                              "return '\\n'.join(lines).replace(CONTINUATION + '\\n', ' ')"),
         'run: |\n  export HOST_SEMAPHORE_MAX_\\\n  WAIT_SECS=3600\n', [S_KEY_USE]),
        ('the wait key not decoded', ('if CONTINUATION in text and rel.endswith(YAML_SUFFIXES):', 'if False:'),
         'run: "export HOST\\x5fSEMAPHORE_MAX_WAIT_SECS=3600"\n', [S_KEY_USE]),
    ]

    def test_each_mutant_goes_red(self):
        source = (CI_DIR / 'host_slots_check.py').read_text()
        for mutant, (old, new), texts, expected in self.MUTANTS:
            with self.subTest(mutant=mutant):
                self.assertEqual(source.count(old), 1, 'mutant anchor %r' % old)
                self.assertEqual(hsc.call_site_violations(CFG, texts), expected)
                got = load_checker(source.replace(old, new)).call_site_violations(CFG, texts)
                self.assertNotEqual(got, expected, 'mutant %s survived' % mutant)

    def test_each_wait_key_mutant_goes_red(self):
        source = (CI_DIR / 'host_slots_check.py').read_text()
        for mutant, (old, new), text, expected in self.WAIT_MUTANTS:
            with self.subTest(mutant=mutant):
                self.assertEqual(source.count(old), 1, 'mutant anchor %r' % old)
                self.assertEqual(hsc.wait_key_violations({SCAN_W: text}), expected)
                got = load_checker(source.replace(old, new)).wait_key_violations({SCAN_W: text})
                self.assertNotEqual(got, expected, 'mutant %s survived' % mutant)


# #9879 invariant B: every spelling of the wrapper path the runner or the shell resolves first is a finding. Written
# out by hand: the wrapper step for the gate g with 1 slot, and every reason below.
G_W = 'workflows/g.yml'
A_W = 'actions/x/action.yml'
EXEC_HEAD = '  exec python3 -I scripts/ci/host_semaphore.py'
EXEC_TAIL = (' --max-wait-secs 600 --label linux-fed/enterprise-fed -- bash --noprofile --norc -eo pipefail '
             '.local-runs/semaphore-step')
EXEC_LINE = EXEC_HEAD + ' --name g --slots 1' + EXEC_TAIL
PREFIX = (
    'set -euo pipefail',
    '# a comment line and a blank line are removed before the compare',
    'if [ "${HOST_SEMAPHORE_SLOTS:-0}" -gt 0 ] && [ -z "${HOST_SEMAPHORE_HELD:-}" ]; then',
    '  export HOST_SEMAPHORE_HELD=1',
    '  mkdir -p .local-runs',
    '  cp -- "$0" .local-runs/semaphore-step',
    EXEC_LINE,
    'fi',
    '',
    'cargo test',
)
STEP_ENV = (('HOST_SEMAPHORE_SLOTS', '"1"'), ('HOST_SEMAPHORE_MAX_WAIT_SECS', "'600'"))
STEP_INDENT = '      '
BODY_INDENT = STEP_INDENT + '  '


def exec_with(path):
    """PREFIX with the exec line calling PATH (the probed spellings of the wrapper path)."""
    line = '  exec python3 %s --name g --slots 9 --max-wait-secs 900 --config .local-runs/c.json -- bash x' % path
    return tuple(line if item == EXEC_LINE else item for item in PREFIX)


def step(lines=PREFIX, env=STEP_ENV, shell='bash', extra=''):
    """One step of job j: name, shell, env, extra keys, then the run block of LINES."""
    text = STEP_INDENT + '- name: t\n'
    if shell is not None:
        text += BODY_INDENT + 'shell: %s\n' % shell
    if env:
        text += BODY_INDENT + 'env:\n' + ''.join(BODY_INDENT + '  %s: %s\n' % pair for pair in env)
    text += extra
    return text + BODY_INDENT + 'run: |\n' + ''.join(
        (BODY_INDENT + '  ' + line).rstrip(' ') + '\n' for line in lines)


def gated(*steps, job='', top=''):
    """The workflow text of G_W: TOP, then job j with JOB keys and STEPS (default: the one canonical step)."""
    return top + 'jobs:\n  j:\n' + job + '    runs-on: x\n    steps:\n' + ''.join(steps or (step(),))


def action(*lines):
    """A composite action whose one step runs LINES (no workflow job holds it)."""
    return 'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n' + ''.join(
        '        %s\n' % line for line in lines)


S_G = 'workflows/g.yml: job j: '
S_B2 = (S_G + 'a run line of a gated job holds an expression ${{ (the runner substitutes it into the script before '
        'bash reads it)')
S_B1 = ('%s: a run line names ci/host and, with quotes removed, holds a character outside the canonical call '
        'characters')
S_B3 = '%s: a line names a wrapper fragment (host_sem, semaphore.py) with an expression, a glob character or a dollar-quote'
S_STEPS_UNREADABLE = '%s: the YAML subset parser cannot read this file, so its wrapper steps are not checked'
# The wrapper path taken wholly from a variable: no literal fragment, so no text rule reads it (the known limit of
# docs/ci/CARRIER-BRANCH-GATES.md; #9882 closes it at run time).
KNOWN_LIMIT_LINE = 'python3 -I "$WRAPPER" --name g --slots 9 --max-wait-secs 600 -- bash x'
# (row, path spelling, the B rules it trips in a composite action: B1 count, B3 count)
SPELLINGS = [
    # security finding 1
    ('expression inside the name', "scripts/ci/host_${{ 'semaphore' }}.py", 1, 0),
    ('format() of the path', "${{ format('scripts/ci/host_{0}.py', 'semaphore') }}", 1, 0),
    ('? glob', 'scripts/ci/host_sem?phore.py', 1, 1),
    ('* glob', 'scripts/ci/host_sema*.py', 1, 1),
    ("$'\\x5f' escape", "scripts/ci/host$'\\x5f'semaphore.py", 1, 1),
    ("$'\\137' escape", "scripts/ci/host$'\\137'semaphore.py", 1, 1),
    # code M-1
    ('empty expression in the token', "scripts/ci/host_${{ '' }}semaphore.py", 1, 1),
    ('expression for the _', "scripts/ci/host${{ '_' }}semaphore.py", 1, 1),
    ('format() with the _', "${{ format('scripts/ci/host{0}semaphore.py', '_') }}", 1, 1),
    # code L-1
    ('* glob over the token', 'scripts/ci/host_sem*.py', 1, 1),
    ('? glob inside the token', 'scripts/ci/host_sema?hore.py', 1, 1),
]


class GatedStepTemplate(unittest.TestCase):
    """#9879 invariant B (rules B1 to B3), each row with its reason by hand."""

    def gsv(self, texts, module=None, cfg=CFG):
        return need(self, module or hsc, 'gated_step_violations')(cfg, texts)

    # (row, text of G_W, expected findings)
    PROBES = [
        ('the canonical step', gated(), []),
        ('the call split by a continuation after the prefix',
         gated(step(PREFIX + ('exec python3 scripts/ci/host_\\', 'semaphore.py --name g',))), [S_B1 % G_W]),
        ('an expression in another step of the gated job',
         gated(step(('echo ${{ github.sha }}',), env=()), step()), [S_B2]),
        # review LOW (#9879 r2): B1 judges a line with its quote characters removed
        ('a quoted ci/host path in another line of the gated job', gated(step(PREFIX + ('echo "scripts/ci/host_slots.json"',))), []),
        # review L2 (#9905 r1): a step env that sets HOST_SEMAPHORE_SLOTS gates the job with no wrapper fragment
        ('a gated job by its env only', gated(step(('echo ${{ github.sha }}',))), [S_B2]),
    ]

    def test_each_probe_is_its_exact_finding(self):
        for row, text, expected in self.PROBES:
            with self.subTest(row):
                self.assertEqual(self.gsv({G_W: text}), expected)

    def test_the_canonical_step_passes_the_call_scan(self):
        self.assertEqual(hsc.call_site_violations(CFG, {G_W: gated()}), [])

    def test_each_spelling_in_a_gated_job_is_a_finding(self):
        for row, path, _, _ in SPELLINGS:
            with self.subTest(row):
                got = self.gsv({G_W: gated(step(exec_with(path)))})
                self.assertIn(S_B1 % G_W, got)
                if '${{' in path:
                    self.assertIn(S_B2, got)

    def test_each_spelling_outside_a_job_is_its_b_finding(self):
        for row, path, b1, b3 in SPELLINGS:
            line = 'exec python3 %s --name g --slots 9 --max-wait-secs 900 --config .local-runs/c.json -- bash x' % path
            with self.subTest(row):
                self.assertEqual(self.gsv({A_W: action(line)}),
                                 [S_B1 % A_W] * b1 + [S_B3 % A_W] * b3)

    def test_a_fragment_form_in_a_file_that_is_not_yaml(self):
        self.assertEqual(self.gsv({'CODEOWNERS': 'scripts/ci/host_sem* @x\n'}), [S_B3 % 'CODEOWNERS'])

    def test_an_unreadable_file_that_names_the_wrapper(self):
        text = 'a: &x 1\nrun: python3 scripts/ci/host_semaphore.py\n'
        self.assertEqual(self.gsv({SCAN_W: text}), [S_STEPS_UNREADABLE % SCAN_W])

    def test_the_known_limit_is_pinned(self):
        """A path taken wholly from a variable holds no literal fragment, so no text rule reads it (#9882)."""
        text = gated(step(PREFIX + (KNOWN_LIMIT_LINE,)))
        self.assertEqual(self.gsv({G_W: text}), [])
        self.assertEqual(hsc.call_site_violations(CFG, {G_W: text}), [])

    def test_a_100k_line_gated_step_is_linear(self):
        text = gated(step(PREFIX + ('echo x',) * BIG))
        self.assertGreater(len(text), BIG)
        start = time.monotonic()
        got = self.gsv({G_W: text})
        self.assertLess(time.monotonic() - start, BLOCK_CEILING_SECS)
        self.assertEqual(got, [])

    def test_a_100k_word_line_in_a_gated_step_is_linear(self):
        text = gated(step(PREFIX + ('echo ' + 'x ' * BIG + '${{ github.sha }}',)))
        start = time.monotonic()
        got = self.gsv({G_W: text})
        self.assertLess(time.monotonic() - start, LINE_CEILING_SECS)
        self.assertEqual(got, [S_B2])

    def test_the_real_tree_has_no_finding(self):
        self.assertEqual(self.gsv(hsc.github_all_texts(), cfg=hsc.load_config()), [])

    # (mutant id, (old text, new text) in host_slots_check.py, texts, expected findings)
    MUTANTS = [
        ('B1: a path character admitted',
         ('if PATH_FRAGMENT_RE.search(quoteless) and NON_CANONICAL_RE.search(quoteless):', 'if False:'),
         {A_W: action('exec python3 "scripts/ci/host"$S.py --name g')}, [S_B1 % A_W]),
        ('B1: the quote characters kept (review LOW)',
         ("quoteless = line.replace(QUOTES[0], '').replace(QUOTES[1], '')", 'quoteless = line'),
         {G_W: gated(step(PREFIX + ('echo "scripts/ci/host_slots.json"',)))}, []),
        ('B2: an expression in a gated job admitted', ('if EXPR_OPENER in line)', 'if False)'),
         {G_W: gated(step(PREFIX + ('echo ${{ github.sha }}',)))}, [S_B2]),
        ('B2: the HOST_SEMAPHORE_SLOTS env not a gating signal (review L2)',
         ('if not wrapper_steps and not any(SLOTS_KEY in env for env in slot_envs):', 'if not wrapper_steps:'),
         {G_W: gated(step(('echo ${{ github.sha }}',)))}, [S_B2]),
        ('B3: a glob beside a fragment admitted',
         ('    if not FRAGMENT_OPENER_RE.search(line):\n        return False',
          '    if True:\n        return False'),
         {A_W: action('x=host_sem*')}, [S_B3 % A_W]),
        ('an unreadable file admitted', ('                found.append(F_STEPS_UNREADABLE % wf)', '                pass'),
         {SCAN_W: 'a: &x 1\nrun: python3 scripts/ci/host_semaphore.py\n'}, [S_STEPS_UNREADABLE % SCAN_W]),
    ]

    def test_each_mutant_goes_red(self):
        source = (CI_DIR / 'host_slots_check.py').read_text()
        for mutant, (old, new), texts, expected in self.MUTANTS:
            with self.subTest(mutant=mutant):
                self.assertEqual(source.count(old), 1, 'mutant anchor %r' % old)
                self.assertEqual(self.gsv(texts), expected)
                got = self.gsv(texts, load_checker(source.replace(old, new)))
                self.assertNotEqual(got, expected, 'mutant %s survived' % mutant)


if __name__ == '__main__':
    unittest.main()
