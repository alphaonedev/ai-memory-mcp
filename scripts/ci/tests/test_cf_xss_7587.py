"""#7587 no untyped value reaches innerHTML and the CSP needs no 'unsafe-inline' for scripts; #7588 text is escaped
exactly once. A structural rule over every page replaces the old list of known-bad tokens, and a hostile state with
markup in every field is rendered in headless Chromium."""
import copy
import json
import re
import unittest
from pathlib import Path

import cf_pages_harness_7313 as harness
import cf_xss_guard_7587 as guard

PUBLIC = harness.PUBLIC
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "index_state_7587.json"
INDEX_JS = PUBLIC / "index.js"
PAYLOAD = '"><i class="pwn7587" onclick="window.__pwn=1">x</i><img src=x onerror="window.__pwn=2">'
INERT = ".pwn7587, [onerror], [onload], [onclick], img[src='x'], script:not([src])"


def page_scripts():
    return sorted(PUBLIC.glob("*.js"))


class GuardLexer7587(unittest.TestCase):
    """The guard itself: it must catch the shapes it exists to catch."""

    def bad(self, src):
        return guard.unwrapped_interpolations(src)

    def test_a_bare_interpolation_is_reported(self):
        self.assertEqual(self.bad("x = `<b>${a.b}</b>`"), ["a.b"])

    def test_an_escaped_or_formatted_interpolation_passes(self):
        self.assertEqual(self.bad("x = `<b>${esc(a.b)}${nf(c, 1)}</b>`"), [])

    def test_a_wrapper_followed_by_more_code_is_reported(self):
        self.assertEqual(self.bad("x = `${esc(a)+b}`"), ["esc(a)+b"])
        self.assertEqual(self.bad("x = `${esc(a),b}`"), ["esc(a),b"])

    def test_a_wrapper_named_like_one_but_a_method_is_reported(self):
        self.assertEqual(self.bad("x = `${o.esc(a)}`"), ["o.esc(a)"])

    def test_nested_templates_are_each_checked(self):
        self.assertEqual(self.bad("x = `${esc(c?`<i>${v}</i>`:'')}`"), ["v"])
        self.assertEqual(self.bad("x = `${esc(c?`<i>${esc(v)}</i>`:'')}`"), [])

    def test_regex_literals_and_comments_with_quotes_do_not_confuse_it(self):
        src = "a = s.replace(/\"/g,'&quot;').replace(/'/g,'&#39;'); // `${x}\n/* `${y}` */ b = `${z}`"
        self.assertEqual(self.bad(src), ["z"])

    def test_dollar_before_an_interpolation_is_a_literal_dollar(self):
        self.assertEqual(self.bad("x = `$${nf(a, 2)} of $${nf(b)}`"), [])
        self.assertEqual(self.bad("x = `$${a}`"), ["a"])

    def test_sinks_are_reported(self):
        self.assertTrue(guard.sink_problems("e.innerHTML = s"))
        self.assertTrue(guard.sink_problems("e.outerHTML = s"))
        self.assertTrue(guard.sink_problems("e.insertAdjacentHTML('beforeend', s)"))
        self.assertTrue(guard.sink_problems("e['innerHTML'] = s"))
        self.assertTrue(guard.sink_problems("document.write(s)"))
        self.assertTrue(guard.sink_problems("eval(s)"))
        self.assertTrue(guard.sink_problems("x = new Html(s)"))
        self.assertEqual(guard.sink_problems("host.innerHTML = h.s", 1), [])

    def test_markup_takes_only_literals(self):
        self.assertTrue(guard.sink_problems("m = markup(a + b)"))
        self.assertTrue(guard.sink_problems("m = markup(String(a))"))
        self.assertEqual(guard.sink_problems("m = markup(`<b>${esc(a)}</b>` + '<i></i>')"), [])
        self.assertEqual(guard.sink_problems("const markup = s => s"), [])

    def test_html_checks(self):
        self.assertTrue(guard.html_problems("<script>alert(1)</script>"))
        self.assertTrue(guard.html_problems('<button onclick="f()">x</button>'))
        self.assertTrue(guard.html_problems('<a href="javascript:f()">x</a>'))
        self.assertEqual(guard.html_problems('<script src="/a.js" defer></script><!-- <script>x</script> -->'), [])


class EveryPage7587(unittest.TestCase):
    def test_no_page_has_an_inline_script_a_handler_or_a_javascript_url(self):
        pages = sorted(PUBLIC.glob("*.html"))
        self.assertGreaterEqual(len(pages), 7)
        for page in pages:
            self.assertEqual(guard.html_problems(page.read_text(encoding="utf-8")), [], page.name)

    def test_every_interpolation_of_every_script_is_escaped_or_formatted(self):
        scripts = page_scripts()
        self.assertTrue(INDEX_JS in scripts)
        for path in scripts:
            src = path.read_text(encoding="utf-8")
            self.assertEqual(guard.unwrapped_interpolations(src), [], path.name)

    def test_the_only_markup_sink_is_the_typed_put_helper(self):
        for path in page_scripts():
            src = path.read_text(encoding="utf-8")
            if path == INDEX_JS:
                self.assertEqual(guard.sink_problems(src, allowed_sinks=1, allowed_new_html=2), [], path.name)
                self.assertRegex(src, r"function put\(host, h\)\{\s*if\(!\(h instanceof Html\)\) throw[^\n]*\s*host\.innerHTML = h\.s;")
            else:
                self.assertEqual(guard.sink_problems(src), [], path.name)

    def test_esc_escapes_all_five_entities_once(self):
        src = INDEX_JS.read_text(encoding="utf-8")
        m = re.search(r"function esc\(v\)\{(.*?)\n\}", src, re.DOTALL)
        self.assertIsNotNone(m)
        for ent in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            self.assertIn(ent, m.group(1))
        self.assertIn("instanceof Html", m.group(1))

    def test_script_src_has_no_unsafe_inline_in_any_policy_line(self):
        headers = (PUBLIC / "_headers").read_text(encoding="utf-8")
        policies = [line.split(":", 1)[1] for line in headers.splitlines() if line.strip().startswith("Content-Security-Policy")]
        self.assertTrue(policies)
        for policy in policies:
            for directive in policy.split(";"):
                parts = directive.split()
                if parts and parts[0] in ("script-src", "script-src-elem", "script-src-attr"):
                    self.assertNotIn("'unsafe-inline'", parts, directive)


def leaves(value, fn):
    """A copy of a JSON value with every string and number replaced by fn(leaf)."""
    if isinstance(value, dict):
        return {k: leaves(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [leaves(v, fn) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    return fn(value)


class IndexInChromium7587(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        harness.playwright_or_skip(cls, unittest)
        cls.state = json.loads(FIXTURE.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        harness.stop(cls)

    def render(self, state, with_csp=True):
        site = harness.Site(self._browser, with_csp=with_csp)
        self.addCleanup(site.close)
        site.answer["/state.json"] = (200, json.dumps(state))
        site.console = []
        site.page.on("console", lambda msg: site.console.append(msg.text) if "panel render error" in msg.text else None)
        site.goto("/")
        site.settle(900)
        return site

    def test_a_normal_state_renders_without_errors_or_violations_under_the_real_csp(self):
        site = self.render(self.state)
        self.assertEqual(site.errors, [])
        self.assertEqual(site.console, [], "a panel failed to render")
        self.assertEqual(site.violations(), [])
        self.assertFalse(site.page.inner_text("#livetext").startswith("offline"), site.page.inner_text("#livetext"))
        body = site.page.inner_text("body")
        for fragment in ("<div", "<span", "<svg", "&amp;", "&lt;", "&#39;", "undefined", "NaN"):
            self.assertNotIn(fragment, body)
        self.assertGreater(site.page.locator("#kpis .kpi").count(), 0)
        self.assertGreater(site.page.locator("#board .dim").count(), 0)
        self.assertGreater(site.page.locator("#swarm svg text").count(), 0)

    def test_markup_in_every_string_and_number_field_stays_inert_with_and_without_the_csp(self):
        hostile = leaves(self.state, lambda leaf: PAYLOAD + str(leaf))
        hostile["run_active"] = True
        for with_csp in (True, False):
            with self.subTest(with_csp=with_csp):
                site = self.render(hostile, with_csp=with_csp)
                self.assertEqual(site.page.evaluate("typeof window.__pwn"), "undefined")
                self.assertEqual(site.page.locator(INERT).count(), 0)
                self.assertEqual(site.page.evaluate("document.querySelectorAll('[class~=pwn7587]').length"), 0)
                # the payload text is displayed as text somewhere (the panels did render it)
                self.assertIn("pwn7587", site.page.inner_text("body"))

    def test_markup_in_numeric_fields_only_renders_the_placeholder_or_text(self):
        hostile = copy.deepcopy(self.state)
        hostile = leaves(hostile, lambda leaf: PAYLOAD if isinstance(leaf, (int, float)) else leaf)
        site = self.render(hostile)
        self.assertEqual(site.page.evaluate("typeof window.__pwn"), "undefined")
        self.assertEqual(site.page.locator(INERT).count(), 0)

    def test_text_with_an_ampersand_is_escaped_exactly_once_7588(self):
        state = copy.deepcopy(self.state)
        state["swarm"]["model"] = "R&D <GLM>"
        state["swarm"]["run"] = "run &amp; ship"
        state["swarm"]["asOf"] = "2026-10-17T00:00:00Z"
        site = self.render(state)
        svg_text = site.page.inner_text("#swarm") if site.page.locator("#swarm svg").count() else ""
        contents = site.page.evaluate("Array.from(document.querySelectorAll('#swarm svg text')).map(t => t.textContent)")
        self.assertTrue(any(t == "R&D <GLM> decide calls" for t in contents), contents)
        self.assertTrue(any("run &amp; ship" in t for t in contents), contents)
        self.assertFalse(any("&amp;amp;" in t or "&amp;lt;" in t for t in contents), contents)
        self.assertEqual(svg_text.count("&amp;amp;"), 0)
        self.assertEqual(site.page.evaluate("document.getElementById('swarmModelSec').textContent"), "R&D <GLM>")

    def test_a_kpi_label_with_ampersand_shows_once_escaped(self):
        state = copy.deepcopy(self.state)
        state["kpis"][0]["label"] = "A &amp; B"
        state["kpis"][0]["sub"] = "x & y"
        site = self.render(state)
        label = site.page.evaluate("document.querySelector('#kpis .kpi .lab').textContent")
        sub = site.page.evaluate("document.querySelector('#kpis .kpi .sub').textContent")
        self.assertEqual((label, sub), ("A &amp; B", "x & y"))


if __name__ == "__main__":
    unittest.main()
