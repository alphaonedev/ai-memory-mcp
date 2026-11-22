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
    CALL_HEAD, CI_DIR, S_DECODED, S_NEVER, S_NOT_YAML, S_OUTSIDE, S_POSITIONAL, S_TOKEN_AGAIN, SCAN_GOOD, SCAN_W,
    TokenScanFailsClosed, hsc, load_checker, run_block, s_char)

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
    ]

    def test_each_mutant_goes_red(self):
        source = (CI_DIR / 'host_slots_check.py').read_text()
        for mutant, (old, new), texts, expected in self.MUTANTS:
            with self.subTest(mutant=mutant):
                self.assertEqual(source.count(old), 1, 'mutant anchor %r' % old)
                self.assertEqual(hsc.call_site_violations(CFG, texts), expected)
                got = load_checker(source.replace(old, new)).call_site_violations(CFG, texts)
                self.assertNotEqual(got, expected, 'mutant %s survived' % mutant)


if __name__ == '__main__':
    unittest.main()
