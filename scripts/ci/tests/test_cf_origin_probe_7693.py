"""#7693: the review probes that found the origin-helper defects, kept as repository tests against the current API.

Two probes, both ported without weakening:
  * the oracle comparison: `cf_origin_7313.loaded_origins` over 137 URL shapes against the WHATWG URL parser of `node`
    (skipped where node is absent; the checked-in fixture test in test_cf_dashboard_7313.py covers the same table
    without node);
  * the revert-and-mutate probe: each defect the helper was written to fix is re-introduced as a text mutation of the
    helper source and the comparison must then find a mismatch, so a test that cannot fail cannot pass quietly.

The two ports the WHATWG parser rejects (65536 and 99999) are explicit refusal assertions: the oracle says PARSE-FAIL and
the helper must answer with an `unparsed:` origin, which the CSP checker refuses, never with a clean origin or nothing.

These are characterization tests of a helper that is already correct, not red-first tests; the mutation half is what
makes them fail when the helper regresses."""
import json
import shutil
import subprocess
import types
import unittest
from pathlib import Path

import cf_origin_7313 as origin_mod
import cf_pages_harness_7313 as harness

BASE_URL = "https://dash.example/page.html"
SAME_ORIGIN = "https://dash.example"
AT = chr(64)
REFUSED_PORTS = ("https://p.example:65536/x", "https://p.example:99999/x")
HELPER_SOURCE = Path(origin_mod.__file__)

CASES = [
    # C0 controls and space at each end
    *[(chr(i) + "https://c%02x.example/p" % i) for i in range(0x21)],
    *[("https://e%02x.example/p" % i + chr(i)) for i in range(0x21)],
    *[(chr(i) + "//r%02x.example/p" % i + chr(i)) for i in range(0x21)],
    # ports
    "https://p.example:443/x", "https://p.example:8443/x", "http://p.example:80/x", "http://p.example:8080/x",
    "http://p.example:443/x", "https://p.example:80/x",
    "https://p.example:0/x", "https://p.example:00443/x", "https://p.example:0080/x", "https://p.example:08443/x",
    "https://p.example:/x", "http://p.example:/x", *REFUSED_PORTS,
    "//p.example:8443/x", "//p.example:443/x",
    # IPv6 literals
    "https://[::1]/x", "https://[::1]:8443/x", "http://[2001:db8::1]:80/x", "//[::1]:9000/x",
    # IPv4
    "https://127.0.0.1:8443/x", "https://0x7f.1/x",
    # userinfo
    "https://u" + AT + "ui.example/x", "https://u:pw" + AT + "ui.example:9000/x",
    "https://u:p" + AT + "ss" + AT + "ui3.example/x", "https://a" + AT + "b" + AT + "ui4.example:8443/x",
    "https://u:" + AT + "ui5.example/x", "https://" + AT + "ui6.example/x",
    # case
    "HTTPS://UP.EXAMPLE/x", "HTTP://UP.EXAMPLE:8080/x", "HtTpS://Mx.Example:443/x",
    # other host shapes
    "https://%65xample.com/x", "https://a_b.example/x", "https://exämple.com/x", "https://host.example./x",
    "http:noslash.example/x", "https:noslash.example/x", "https:/one.example/x",
]

NODE = shutil.which("node")


def oracle(values):
    js = (
        "const vs=JSON.parse(require('fs').readFileSync(0,'utf8'));"
        "console.log(JSON.stringify(vs.map(v=>{try{const u=new URL(v,%s);"
        "return u.origin===%s?null:u.origin}catch(e){return 'PARSE-FAIL'}})));" % (
            json.dumps(BASE_URL), json.dumps(SAME_ORIGIN))
    )
    out = subprocess.run([NODE, "-e", js], input=json.dumps(values), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def img(value):
    return '<img src="%s">' % value.replace('"', "&quot;")


def mismatches(module, cases, want):
    """Cases where `module.loaded_origins` disagrees with the oracle. PARSE-FAIL is checked by the refusal test."""
    bad = []
    for value, expected in zip(cases, want):
        if expected == "PARSE-FAIL":
            continue
        got = sorted(module.loaded_origins(img(value)))
        if got != ([] if expected is None else [expected]):
            bad.append((value, got, expected))
    return bad


def mutated_helper(old, new):
    """The helper module re-executed from its own source with one text mutation; the replace must have applied."""
    source = HELPER_SOURCE.read_text(encoding="utf-8")
    assert source.count(old) >= 1, "the mutation target is gone from the helper: %r" % old
    mutated = source.replace(old, new)
    assert mutated != source, "the mutation changed nothing"
    return execute(mutated)


def execute(source):
    module = types.ModuleType("cf_origin_mutant_7693")
    module.__file__ = str(HELPER_SOURCE)
    exec(compile(source, str(HELPER_SOURCE), "exec"), module.__dict__)
    return module


@unittest.skipUnless(NODE, "node is not installed; the checked-in fixture test covers the same table")
class OracleComparison7693(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.want = oracle(CASES)

    def test_the_helper_agrees_with_the_whatwg_parser_on_every_case(self):
        self.assertEqual(mismatches(origin_mod, CASES, self.want), [])
        self.assertGreaterEqual(len(CASES), 137)

    def test_out_of_range_ports_are_an_explicit_refusal_not_a_clean_origin(self):
        for value in REFUSED_PORTS:
            self.assertEqual(self.want[CASES.index(value)], "PARSE-FAIL", value)
            got = origin_mod.loaded_origins(img(value))
            self.assertEqual(len(got), 1, (value, got))
            (origin,) = got
            self.assertTrue(origin.startswith(origin_mod.UNPARSED_PREFIX), (value, origin))
            self.assertIn(value, origin)

    def test_every_other_parse_failure_in_the_table_is_also_refused(self):
        for value, expected in zip(CASES, self.want):
            if expected == "PARSE-FAIL":
                got = origin_mod.loaded_origins(img(value))
                self.assertTrue(got and all(o.startswith(origin_mod.UNPARSED_PREFIX) for o in got), (value, got))

    def test_each_reintroduced_defect_is_caught_by_the_comparison(self):
        mutations = {
            "C0 controls and space not stripped": ("value = value.strip(C0_AND_SPACE)", "value = value.strip()"),
            "default ports kept in the origin": (
                'suffix = "" if not port or port == DEFAULT_PORTS[scheme] else ":" + port',
                'suffix = "" if not port else ":" + port'),
            "userinfo ends at the first at-sign": ("authority.rfind(chr(64))", "authority.find(chr(64))"),
            "default ports dropped for every scheme": (
                'suffix = "" if not port or port == DEFAULT_PORTS[scheme] else ":" + port',
                'suffix = "" if not port or port in DEFAULT_PORTS.values() else ":" + port'),
        }
        for label, (old, new) in mutations.items():
            with self.subTest(label):
                found = mismatches(mutated_helper(old, new), CASES, self.want)
                self.assertTrue(found, "the comparison did not notice: " + label)

    def test_a_mutation_that_applies_nothing_is_refused(self):
        with self.assertRaises(AssertionError):
            mutated_helper("this text is not in the helper", "x")

    def test_the_unmutated_helper_is_clean_so_the_mutations_prove_something(self):
        copy = execute(HELPER_SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(mismatches(copy, CASES, self.want), [])


class RealPageInjection7693(unittest.TestCase):
    """The plain-http injection probe: the real pages load only same-origin and the one allowed font origin, and a
    plain-http or mixed-case look-alike added to a real page is reported with its exact origin."""

    PAGES = ("datatier", "federation", "index", "mcp-tools", "northstar", "security", "swarm-tools")
    FONTS = "https://fonts.googleapis.com"

    def test_real_pages_load_only_the_allowed_origins(self):
        for name in self.PAGES:
            text = (harness.PUBLIC / (name + ".html")).read_text(encoding="utf-8")
            self.assertLessEqual(origin_mod.loaded_origins(text), {self.FONTS, "https://fonts.gstatic.com"}, name)

    def test_injected_loads_are_reported_with_their_exact_origin(self):
        page = (harness.PUBLIC / "index.html").read_text(encoding="utf-8")
        real = origin_mod.loaded_origins(page)
        cases = {
            '<img src="http://plain.example/a.png">': {"http://plain.example"},
            '<script src="http://plain.example:8080/a.js"></script>': {"http://plain.example:8080"},
            '<link rel="stylesheet" href="HTTP://FONTS.GOOGLEAPIS.COM/css">': {"http://fonts.googleapis.com"},
            '<link rel="stylesheet" href="http://fonts.googleapis.com/css">': {"http://fonts.googleapis.com"},
        }
        for injected, added in cases.items():
            got = origin_mod.loaded_origins(page.replace("</body>", injected + "</body>", 1))
            self.assertEqual(got - real, added, injected)
            self.assertNotIn(added.copy().pop(), real)


if __name__ == "__main__":
    unittest.main()
