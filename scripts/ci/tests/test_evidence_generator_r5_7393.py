#!/usr/bin/env python3
"""PR #7393 round 5: gate fixtures for the delta r4 review findings (#7527-#7535) on the vendored certification
evidence generator.

  #7527  check_block refuses rows after EXIT, sections of unplanned legs and legs out of the runner's order
  #7528  the #7487 PLAN position tests fail when the position rule is removed (see test_evidence_generator_r4_7393.py)
  #7529  SANITIZATION.md records which legs.log rule judged the run
  #7530  an OSError from the expiry copy ends the gates leg with an EXIT row and a failure, no traceback
  #7531  the expiry copy sees the checkout as its repo root and leaves no nested scratch directory
  #7532  stale .expiry-* directories are swept; the open flags are pinned; creation goes through a directory fd
  #7533  sanitize_paths replaces a run path only at a real path-component boundary on both sides (#7491)
  #7534  the tmp-root guard is an AST walk over every evidence test file and catches every spelling
  #7535  --push-branch and --parent are refused on every leg but gates

Scratch lives under .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r5_7393.py
"""
import argparse
import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase, load
from test_evidence_generator_r2_7393 import GIT, make_repo
from test_evidence_generator_r3_7393 import CHAIN_LEGS, CONFIG, DONE, GREEN_CHAIN, SEC, block, leg_text

TESTS = Path(__file__).resolve().parent
EXIT_PG = "EXIT=0 leg=pg aggregate_failures=0 12:00Z\n"
CHAIN_DONE_ROW = "CHAIN_DONE aggregate_failures=0 10:55Z\n"


def chain_body(order, chain_done_at=None):
    """The body of a chain block with the legs in `order` (a list of leg names) and CHAIN_DONE after them, or at
    index `chain_done_at` of the leg list."""
    parts = [leg_text(l) for l in order]
    parts.insert(len(parts) if chain_done_at is None else chain_done_at, CHAIN_DONE_ROW)
    return "".join(parts)


class BlockOrderAndExit7527(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal) as cm:
            self.bb.check_run(self.legs(text))
        return str(cm.exception)

    def bad_shapes(self):
        pg_block = block("pg", ("pg",), leg_text("pg"))
        return {
            "unfinished removal section after a pg block's EXIT": GREEN_CHAIN + pg_block + SEC["removal"],
            "unfinished bootstrap section inside a pg block": GREEN_CHAIN + block("pg", ("pg",), leg_text("pg") + SEC["bootstrap"]),
            "unfinished CERT LEGS section inside a pg block": GREEN_CHAIN + block("pg", ("pg",), leg_text("pg") + SEC["battery"]),
            "PG_DONE after EXIT": GREEN_CHAIN + block("pg", ("pg",), SEC["pg"], exit_row=False) + EXIT_PG + DONE["pg"],
            "EXIT=0 before every leg": block("chain", CHAIN_LEGS, "EXIT=0 leg=chain aggregate_failures=0 12:00Z\n"
                                             + chain_body(CHAIN_LEGS[:-1]), exit_row=False),
            "chain legs out of runner order": block("chain", CHAIN_LEGS, chain_body(["battery", "pg", "removal", "bootstrap"])),
            "CHAIN_DONE before the bootstrap leg": block("chain", CHAIN_LEGS, chain_body(CHAIN_LEGS[:-1], chain_done_at=3)),
            "a junk row after EXIT": GREEN_CHAIN + "unrelated row\n",
            "a section of a leg the plan does not name": GREEN_CHAIN + block("pg", ("pg",), SEC["removal"] + leg_text("pg")),
            "a duplicated section": GREEN_CHAIN + block("pg", ("pg",), SEC["pg"] + leg_text("pg")),
        }

    def test_every_bad_shape_is_refused_7527(self):
        for name, text in self.bad_shapes().items():
            with self.subTest(shape=name):
                self.refused(text)

    def test_the_good_shapes_are_accepted_7527(self):
        self.bb.check_run(self.legs(GREEN_CHAIN))
        for leg in ("battery", "removal", "pg", "bootstrap"):
            self.bb.check_run(self.legs(GREEN_CHAIN + block(leg, (leg,), leg_text(leg))))
        self.bb.check_run(self.legs(GREEN_CHAIN + GREEN_CHAIN))
        self.bb.check_run(self.legs(GREEN_CHAIN + "\n"))  # a trailing blank line is not a row

    def test_the_failure_names_the_ordering_rule_7527(self):
        text = self.refused(block("chain", CHAIN_LEGS, chain_body(["battery", "pg", "removal", "bootstrap"])))
        self.assertIn("order", text)
        text = self.refused(GREEN_CHAIN + "unrelated row\n")
        self.assertIn("after its EXIT row", text)


if __name__ == "__main__":
    unittest.main()
