#!/usr/bin/env python3
"""Tests for scripts/ci/check_no_cn_ai_vendor.py (docs vendor-name gate).

Term fixtures are ROT13-encoded here too, so this file adds no literal name.
"""

import codecs
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "scripts/ci/check_no_cn_ai_vendor.py"
ALLOW = ROOT / "scripts/ci/cn_ai_vendor_allow.json"

# Plain-word terms (ROT13) the gate must flag in every spelling below.
PLAIN_TERMS_ROT13 = (
    "qrrcfrrx", "djra", "xvzv", "zvavznk", "muvch", "pungtyz", "onvpuhna",
    "qbhonb", "reavr", "uhalhna", "fgrcsha", "vagreayz", "qfu", "qnfufpbcr",
    "graprag", "grapragqo", "ibypratvar", "bcraivxvat", "ivxvatqo", "nyvonon",
    "rirezvaq",
)
# Exact-case terms and the dotted domain form (ROT13).
CASE_SENSITIVE_ROT13 = ("ZrzBF", "ZvZb")
DOTTED_ROT13 = "m.nv"
FLASH_FAMILY_ROT13 = "tyz"
SUFFIXED_ROT13 = "zbbafubg"
SPELLINGS = ("{t}", "{T}", "{C}", "use {t} here", "`{t}`", "{t}3", "{t}-max",
             "{T}_API_KEY", "x {C}/y")
SIZE_BOUND_BYTES = 1_000_000
TIME_CEILING_SECONDS = 20.0
NEAR_MISS = "kim qwe deepsee glam moon shot dashscop "


def rot(text):
    return codecs.decode(text, "rot13")


def load_gate():
    spec = importlib.util.spec_from_file_location("check_no_cn_ai_vendor", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE_MOD = load_gate()
ALLOW_DATA = json.loads(ALLOW.read_text(encoding="utf-8"))


def scan(rel, text):
    patterns = GATE_MOD.build_patterns()
    return list(GATE_MOD.scan_text(rel, text, patterns, ALLOW_DATA))


class PlainTermTests(unittest.TestCase):
    def test_every_spelling_of_every_term_is_a_hit(self):
        for stored in PLAIN_TERMS_ROT13:
            term = rot(stored)
            for form in SPELLINGS:
                line = form.format(t=term, T=term.upper(), C=term.capitalize())
                with self.subTest(line=line):
                    hits = scan("docs/x.md", line)
                    self.assertEqual([lab for _, lab in hits], [term])

    def test_exact_label_and_line_number(self):
        term = rot("djra")
        hits = scan("docs/x.md", "a\nb\nsee " + term + "\n")
        self.assertEqual(hits, [(3, term)])

    def test_near_misses_are_not_hits(self):
        self.assertEqual(scan("docs/x.md", NEAR_MISS), [])
        self.assertEqual(scan("docs/x.md", "the moonshot idea"), [])
        self.assertEqual(scan("docs/x.md", "Gemini, Mistral, Groq"), [])

    def test_letter_neighbours_do_not_match(self):
        term = rot("xvzv")
        self.assertEqual(scan("docs/x.md", "a" + term + "b"), [])


class ExtraNameTests(unittest.TestCase):
    def test_exact_case_names_are_hits_and_common_words_are_not(self):
        for stored in CASE_SENSITIVE_ROT13:
            name = rot(stored)
            for form in ("{n}", "use {n} here", "`{n}`", "{n}-2"):
                with self.subTest(name=name, form=form):
                    hits = scan("docs/x.md", form.format(n=name))
                    self.assertEqual([lab for _, lab in hits], [name])
        self.assertEqual(scan("docs/x.md", "meeting memos and a mimo of notes"), [])

    def test_dotted_name(self):
        name = rot(DOTTED_ROT13)
        for form in ("{n}", "{N}", "see {n} docs", "https://{n}/api"):
            with self.subTest(form=form):
                hits = scan("docs/x.md", form.format(n=name, N=name.upper()))
                self.assertEqual([lab for _, lab in hits], [name])
        self.assertEqual(scan("docs/x.md", "buz" + "." + "ai and x" + name), [])


class MoonshotTests(unittest.TestCase):
    def test_forms(self):
        moon = rot(SUFFIXED_ROT13)
        for line in (moon + " AI", moon.upper() + "_API_KEY", "api." + moon + ".cn",
                     moon + "-v1-8k"):
            with self.subTest(line=line):
                self.assertEqual([lab for _, lab in scan("docs/x.md", line)], [moon])


class FlashExceptionTests(unittest.TestCase):
    def test_swarm_path_is_allowed(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual(scan("sdk/python/swarm/agent.py", f"{family}-driven agent"), [])

    def test_flash_line_in_testing_docs_is_allowed(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual(scan("docs/testing/index.html", f"{family}-5.3-Flash NHIs"), [])

    def test_same_name_outside_testing_is_a_hit(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual([lab for _, lab in scan("README.md", f"{family}-5.3-Flash")], [family])
        self.assertEqual([lab for _, lab in scan("docs/x.md", f"use {family} here")], [family])

    def test_exception_does_not_cover_other_names(self):
        term = rot("djra")
        self.assertEqual([lab for _, lab in scan("sdk/python/swarm/a.py", term)], [term])


class RustCodeSiteTests(unittest.TestCase):
    def test_code_line_allowed_comment_line_flagged(self):
        term = rot("xvzv")
        self.assertEqual(scan("src/llm.rs", f'    "{term}" => 1,'), [])
        self.assertEqual([lab for _, lab in scan("src/llm.rs", f"/// {term}")], [term])
        self.assertEqual([lab for _, lab in scan("src/other.rs", f'"{term}"')], [term])


class SizeBoundTests(unittest.TestCase):
    def test_megabyte_input_scans_within_ceiling(self):
        text = (NEAR_MISS * (SIZE_BOUND_BYTES // len(NEAR_MISS) + 1)) + "\n"
        start = time.monotonic()
        hits = scan("docs/big.md", text)
        self.assertLess(time.monotonic() - start, TIME_CEILING_SECONDS)
        self.assertEqual(hits, [])
        planted = text + rot("djra") + "\n"
        self.assertEqual(len(scan("docs/big.md", planted)), 1)


class CliTests(unittest.TestCase):
    def test_exit_codes_on_scratch_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("clean text\n", encoding="utf-8")
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(ALLOW)]), 0)
            (root / "b.md").write_text("see " + rot("djra") + "\n", encoding="utf-8")
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(ALLOW)]), 1)
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(root / "no.json")]), 2)

    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.bin").write_bytes(b"\0" + rot("djra").encode())
            self.assertEqual(GATE_MOD.scan_root(Path(tmp), ALLOW_DATA), [])


class RepoTreeTests(unittest.TestCase):
    def test_repository_has_zero_hits(self):
        hits = GATE_MOD.scan_root(ROOT, ALLOW_DATA)
        sample = [f"{p}:{n}" for p, n, _ in hits[:10]]
        self.assertEqual(len(hits), 0, f"{len(hits)} hits, first: {sample}")


if __name__ == "__main__":
    unittest.main()
