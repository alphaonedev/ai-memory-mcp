#!/usr/bin/env python3
"""Tests for scripts/ci/check_no_cn_ai_vendor.py (docs vendor-name gate).

Term fixtures are ROT13-encoded here too, so this file adds no literal name.
"""

import codecs
import importlib.util
import json
import subprocess
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
    # Names that survived redaction in review records (F4).
    "olgrqnapr", "onvqh",
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
    def test_swarm_path_is_allowed_for_flash_token(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual(scan("sdk/python/swarm/agent.py", f"{family}-5.3-flash call"), [])

    def test_flash_line_in_testing_docs_is_allowed(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual(scan("docs/testing/index.html", f"{family}-5.3-Flash NHIs"), [])
        self.assertEqual(scan("docs/testing/index.html", f"slug z-ai/{family}-5.3-flash"), [])

    def test_same_name_outside_testing_is_a_hit(self):
        family = rot(FLASH_FAMILY_ROT13)
        self.assertEqual([lab for _, lab in scan("README.md", f"{family}-5.3-Flash")], [family])
        self.assertEqual([lab for _, lab in scan("docs/x.md", f"use {family} here")], [family])

    def test_exception_does_not_cover_other_names(self):
        term = rot("djra")
        self.assertEqual([lab for _, lab in scan("sdk/python/swarm/a.py", term)], [term])

    def test_non_flash_family_model_is_a_hit_in_every_allowed_prefix(self):
        family = rot(FLASH_FAMILY_ROT13)
        lines = (f"{family}-5.3-Pro", f"{family}-4.6", f"{family} NHI swarm hive cluster",
                 f"{family}-driven agent", f"{family}-5.3-Flash and {family}-5.3-Pro")
        for prefix in ALLOW_DATA["flash_testing"]["path_prefixes"]:
            rel = prefix + "x.md" if prefix.endswith("/") else prefix
            for line in lines:
                with self.subTest(prefix=prefix, line=line):
                    self.assertEqual([lab for _, lab in scan(rel, line)], [family])

    def test_flash_qualifier_must_be_on_the_token(self):
        family = rot(FLASH_FAMILY_ROT13)
        hits = scan("infra/do-hive/a.md", f"{family}-5.3 hive flash cluster swarm")
        self.assertEqual([lab for _, lab in hits], [family])

    def test_exception_is_data_not_a_context_regex(self):
        self.assertNotIn("line_context_regex", ALLOW_DATA["flash_testing"])


class RustCodeSiteTests(unittest.TestCase):
    def test_code_line_allowed_comment_line_flagged(self):
        term = rot("xvzv")
        self.assertEqual(scan("src/llm.rs", f'    "{term}" => 1,'), [])
        self.assertEqual([lab for _, lab in scan("src/llm.rs", f"/// {term}")], [term])
        self.assertEqual([lab for _, lab in scan("src/other.rs", f'"{term}"')], [term])


class RustTrailingCommentTests(unittest.TestCase):
    def test_trailing_line_comment_on_code_line_is_scanned(self):
        term = rot("xvzv")
        hits = scan("src/llm.rs", f"    let x = 1; // {term} alias")
        self.assertEqual([lab for _, lab in hits], [term])

    def test_slashes_inside_a_string_literal_are_not_a_comment(self):
        term = rot("xvzv")
        self.assertEqual(scan("src/llm.rs", f'    "https://x/{term}" => 1, // plain note'), [])

    def test_escaped_quote_does_not_end_the_string(self):
        term = rot("xvzv")
        line = '    "a \\" // ' + term + '" => 1,'
        self.assertEqual(scan("src/llm.rs", line), [])

    def test_trailing_comment_after_string_with_slashes_is_scanned(self):
        term = rot("xvzv")
        line = f'    "a//b" => 1, // {term}'
        self.assertEqual([lab for _, lab in scan("src/llm.rs", line)], [term])

    def test_char_literal_quote_does_not_hide_a_comment(self):
        term = rot("xvzv")
        line = "    '\"' => 1, // " + term
        self.assertEqual([lab for _, lab in scan("src/llm.rs", line)], [term])

    def test_trailing_block_comment_is_scanned(self):
        term = rot("xvzv")
        line = f"    let x = 1; /* {term} */"
        self.assertEqual([lab for _, lab in scan("src/llm.rs", line)], [term])


class UrlLabelTests(unittest.TestCase):
    LABELS = ("a cloud provider", "a vector database", "System X", "System Z")

    def test_url_containing_a_replacement_label_is_a_hit(self):
        for label in self.LABELS:
            for form in ("[a](https://www.{l}.com/jobs)", "see https://github.com/{l}-AI",
                         "(https://github.com/{l})", "src /srv/competitors/{l}"):
                with self.subTest(label=label, form=form):
                    hits = scan("docs/reviews/x.md", form.format(l=label))
                    self.assertEqual([lab for _, lab in hits], [GATE_MOD.URL_LABEL_HIT])

    def test_plain_label_text_and_clean_urls_are_not_hits(self):
        for line in ("a cloud provider and System X are neutral labels",
                     "see https://github.com/example-org/example-repo",
                     "docs/reviews/DOCS-VS-SYSTEM-X-3x3.md"):
            with self.subTest(line=line):
                self.assertEqual(scan("docs/x.md", line), [])


class AllowlistLivenessTests(unittest.TestCase):
    def run_tree(self, files, allow):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, body in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            return GATE_MOD.run_scan(root, allow)

    def allow(self, sites=(), prefixes=()):
        return {"flash_testing": {"path_prefixes": list(prefixes)},
                "functional_code_sites": [{"path": p, "reason": "t"} for p in sites]}

    def test_missing_code_site_path_is_stale(self):
        result = self.run_tree({"a.md": "ok\n"}, self.allow(sites=["src/gone.rs"]))
        self.assertEqual(result.stale, [
            "stale allowlist entry: functional_code_sites path `src/gone.rs` is not a tracked file"])

    def test_code_site_without_exempted_hit_is_stale(self):
        term = rot("xvzv")
        files = {"src/llm.rs": f"// {term} note in a comment only\n"}
        result = self.run_tree(files, self.allow(sites=["src/llm.rs"]))
        self.assertEqual(result.stale, [
            "stale allowlist entry: functional_code_sites path `src/llm.rs` "
            "exempts no hit on a non-comment line"])
        self.assertEqual(len(result.hits), 1)

    def test_live_code_site_is_not_stale(self):
        term = rot("xvzv")
        result = self.run_tree({"src/llm.rs": f'    "{term}" => 1,\n'},
                               self.allow(sites=["src/llm.rs"]))
        self.assertEqual((result.stale, result.hits), ([], []))

    def test_unmatched_flash_prefix_is_stale(self):
        result = self.run_tree({"a.md": "ok\n"}, self.allow(prefixes=["docs/no_such_dir/"]))
        self.assertEqual(result.stale, [
            "stale allowlist entry: flash_testing path_prefix `docs/no_such_dir/` "
            "matches no tracked file"])

    def test_matched_flash_prefix_is_not_stale(self):
        result = self.run_tree({"docs/testing/a.md": "ok\n"},
                               self.allow(prefixes=["docs/testing/"]))
        self.assertEqual(result.stale, [])

    def test_main_exits_nonzero_for_stale_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("ok\n", encoding="utf-8")
            allow = root / "allow.json"
            allow.write_text(json.dumps(self.allow(sites=["src/gone.rs"])), encoding="utf-8")
            code = GATE_MOD.main(["--root", tmp, "--allow-file", str(allow), "--count-only"])
            self.assertEqual(code, GATE_MOD.EXIT_STALE)

    def test_every_entry_in_the_shipped_allowlist_is_live(self):
        self.assertEqual(GATE_MOD.run_scan(ROOT, ALLOW_DATA).stale, [])


class SizeBoundTests(unittest.TestCase):
    def test_megabyte_input_scans_within_ceiling(self):
        text = (NEAR_MISS * (SIZE_BOUND_BYTES // len(NEAR_MISS) + 1)) + "\n"
        start = time.monotonic()
        hits = scan("docs/big.md", text)
        self.assertLess(time.monotonic() - start, TIME_CEILING_SECONDS)
        self.assertEqual(hits, [])
        planted = text + rot("djra") + "\n"
        self.assertEqual(len(scan("docs/big.md", planted)), 1)

    def test_long_url_like_line_is_linear(self):
        text = ("https://" + "a" * SIZE_BOUND_BYTES + "\n")
        start = time.monotonic()
        self.assertEqual(scan("docs/big.md", text), [])
        self.assertLess(time.monotonic() - start, TIME_CEILING_SECONDS)


class CliTests(unittest.TestCase):
    def test_exit_codes_on_scratch_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("clean text\n", encoding="utf-8")
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(ALLOW)]), 0)
            (root / "b.md").write_text("see " + rot("djra") + "\n", encoding="utf-8")
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(ALLOW)]), 1)
            self.assertEqual(GATE_MOD.main(["--root", tmp, "--allow-file", str(root / "no.json")]), 2)

    def test_binary_file_is_skipped_and_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.bin").write_bytes(b"\0" + rot("djra").encode())
            result = GATE_MOD.run_scan(Path(tmp), ALLOW_DATA)
            self.assertEqual((result.hits, result.skipped_binary), ([], 1))
            self.assertEqual(GATE_MOD.scan_root(Path(tmp), ALLOW_DATA), [])

    def test_skipped_binary_count_is_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.bin").write_bytes(b"\0\1\2")
            (Path(tmp) / "y.bin").write_bytes(b"\0\1\2")
            out = subprocess.run(
                ["python3", str(GATE), "--root", tmp, "--allow-file", str(ALLOW), "--count-only"],
                capture_output=True, text=True, check=False)
            self.assertEqual(out.returncode, 0)
            self.assertIn("skipped binary: 2", out.stdout)
            self.assertIn("hits: 0", out.stdout)

    def test_utf16_and_utf32_docs_with_a_barred_name_are_hits(self):
        term = rot("djra")
        body = "line one\nsee " + term + " here\n"
        encoded = {
            "utf-16": body.encode("utf-16"),
            "utf-16-le-bom": b"\xff\xfe" + body.encode("utf-16-le"),
            "utf-16-be-bom": b"\xfe\xff" + body.encode("utf-16-be"),
            "utf-32": body.encode("utf-32"),
            "utf-32-be-bom": b"\x00\x00\xfe\xff" + body.encode("utf-32-be"),
        }
        for name, raw in encoded.items():
            with self.subTest(codec=name), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "doc.md").write_bytes(raw)
                result = GATE_MOD.run_scan(Path(tmp), ALLOW_DATA)
                self.assertEqual(result.hits, [("doc.md", 2, term)])
                self.assertEqual(result.skipped_binary, 0)


class RepoTreeTests(unittest.TestCase):
    def test_repository_has_zero_hits(self):
        hits = GATE_MOD.scan_root(ROOT, ALLOW_DATA)
        sample = [f"{p}:{n}" for p, n, _ in hits[:10]]
        self.assertEqual(len(hits), 0, f"{len(hits)} hits, first: {sample}")


if __name__ == "__main__":
    unittest.main()
