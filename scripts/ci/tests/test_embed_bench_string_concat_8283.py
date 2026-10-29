# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#8283: benchmark list strings must use explicit concatenation."""

import io
import tokenize
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCH = ROOT / "deploy/docker-1461/bench/embed_bench.py"
TRIVIA = {tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT}


def implicit_list_string_runs(source):
    """Locate adjacent-STRING chains inside brackets, counting each chain once.

    This matches the list context of the CodeQL finding; joins in the report
    note and TSV header are outside that context.
    """
    hits = []
    previous = None
    in_run = False
    list_depth = 0
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in TRIVIA:
            continue
        if token.type == tokenize.OP:
            if token.string == "[":
                list_depth += 1
            elif token.string == "]":
                list_depth -= 1
        if list_depth and token.type == tokenize.STRING and previous is not None:
            if previous.type == tokenize.STRING and not in_run:
                hits.append(previous.start[0])
                in_run = True
        else:
            in_run = False
        previous = token
    return hits


class EmbedBenchStringConcat8283Tests(unittest.TestCase):
    def test_8283_benchmark_list_strings_have_no_implicit_concatenation(self):
        hits = implicit_list_string_runs(BENCH.read_text())
        self.assertEqual(hits, [], "implicit string concatenation starts on these lines")


if __name__ == "__main__":
    unittest.main()
