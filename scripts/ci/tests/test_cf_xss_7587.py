"""#7587 no untyped value reaches innerHTML; #7588 text is escaped exactly once; #7634 #7645 the static guard is an
ALLOWLIST (one Trusted Types policy `dash`, one `.createHTML(` site, both inside `put()`; `markup` only as a template
tag; `Html` only in the helper block) with one red test per refused shape, and index.js must be among the scripts it
checks. The browser-enforced half is test_cf_browser_7634.py; a hostile state rendered in Playwright Chromium (skipped
where Playwright is absent) stays here."""
import copy
import json
import re
import unittest
from pathlib import Path

import cf_csp_allowlist_7313 as csp
import cf_pages_harness_7313 as harness
import cf_xss_guard_7587 as guard

PUBLIC = harness.PUBLIC
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "index_state_7587.json"
INDEX_JS = PUBLIC / "index.js"
PAYLOAD = '"><i class="pwn7587" onclick="window.__pwn=1">x</i><img src=x onerror="window.__pwn=2">'
INERT = ".pwn7587, [onerror], [onload], [onclick], img[src='x'], script:not([src])"


def page_scripts():
    return sorted(PUBLIC.glob("*.js"))


HELPER_END = "function num(v){"


def helper_source():
    src = INDEX_JS.read_text(encoding="utf-8")
    return src[:src.index(HELPER_END)]


def real_index():
    return INDEX_JS.read_text(encoding="utf-8")


class GuardAllowlist7634(unittest.TestCase):
    """#7634 #7635: the static guard is an allowlist of one helper shape. Every refused shape has its own test; each
    is the real index.js (or its helper block) with one deviation, so a refusal is a real deviation and not a typo."""

    def problems(self, src, helper_allowed=True):
        return guard.js_problems(src, helper_allowed)

    def mutated(self, old, new, count=1):
        src = real_index()
        self.assertEqual(src.count(old), count, old)
        return src.replace(old, new)

    def appended(self, extra):
        return real_index() + "\n" + extra + "\n"

    def refused(self, src, fragment, helper_allowed=True):
        found = self.problems(src, helper_allowed)
        self.assertTrue(any(fragment in p for p in found), (fragment, found))

    def test_the_real_renderer_and_the_other_scripts_are_accepted(self):
        self.assertEqual(self.problems(real_index()), [])
        for path in page_scripts():
            if path != INDEX_JS:
                self.assertEqual(self.problems(path.read_text(encoding="utf-8"), False), [], path.name)

    def test_a_second_createpolicy_is_refused(self):
        self.refused(self.appended('const second = window.trustedTypes.createPolicy("other", { createHTML: s => s });'),
                     "exactly one createPolicy")

    def test_a_createpolicy_outside_put_is_refused(self):
        src = self.mutated('const dash = window.trustedTypes ? window.trustedTypes.createPolicy("dash", rules) : rules;',
                           'const dash = rules;') + '\nconst p = window.trustedTypes.createPolicy("dash", {});\n'
        self.refused(src, "exactly one createPolicy")

    def test_a_policy_with_another_name_is_refused(self):
        self.refused(self.mutated('createPolicy("dash", rules)', 'createPolicy("everything", rules)'), 'must be named "dash"')

    def test_a_second_createhtml_call_is_refused(self):
        self.refused(self.appended('const trusted = dash.createHTML("", s);'), "exactly one .createHTML( call")

    def test_a_createhtml_call_outside_put_is_refused(self):
        src = self.mutated('host.innerHTML = dash.createHTML("", h);', 'host.innerHTML = h.s;')
        self.refused(src + '\nconst t = window.trustedTypes.defaultPolicy.createHTML(s);\n', "exactly one .createHTML( call")

    def test_a_pass_through_createhtml_rule_is_refused(self):
        self.refused(self.mutated("h instanceof Html ? h.s : escText(s)", "s"), "must escape")
        self.refused(self.mutated("h instanceof Html ? h.s : escText(s)", "h instanceof Html ? h.s : s"), "must escape")

    def test_an_innerhtml_outside_put_is_refused(self):
        self.refused(self.appended("el.innerHTML = s;"), "innerHTML used outside the helper block")
        self.refused("el.innerHTML = s;", "innerHTML", helper_allowed=False)

    def test_a_second_innerhtml_inside_put_is_refused(self):
        self.refused(self.mutated("host.innerHTML = dash.createHTML(\"\", h);",
                                  "host.innerHTML = dash.createHTML(\"\", h); host.innerHTML = h.s;"), "exactly one innerHTML")

    def test_markup_called_as_a_function_is_refused(self):
        self.refused(self.appended('const m = markup("<b>" + s + "</b>");'), "does not tag a template literal")
        self.refused(self.appended("const m = markup(`<b>x</b>`);"), "does not tag a template literal")

    def test_markup_passed_around_or_aliased_is_refused(self):
        self.refused(self.appended("const m = markup;"), "does not tag a template literal")
        self.refused(self.appended("const all = [markup];"), "does not tag a template literal")
        self.refused(self.appended("list.map(markup);"), "does not tag a template literal")

    def test_markup_inside_an_interpolation_is_checked_too(self):
        self.refused(self.appended("const m = markup`<i>${markup(s)}</i>`;"), "does not tag a template literal")
        self.assertEqual(self.problems(self.appended("const m = markup`<i>${markup`<b></b>`}</i>`;")), [])

    def test_html_named_outside_the_helper_block_is_refused(self):
        self.refused(self.appended("const h = new Html(s);"), "Html used outside the helper block")
        self.refused(self.appended("const ok = v instanceof Html;"), "Html used outside the helper block")

    def test_a_missing_helper_block_is_refused(self):
        src = real_index()
        self.refused(src.replace("const { markup, cat, put } =", "const helpers ="), "helper block")

    def test_a_script_that_is_not_the_renderer_names_none_of_it(self):
        for text in ("x.innerHTML = s;", 'trustedTypes.createPolicy("dash", {});', "p.createHTML(s);", "new Html(s);",
                     "markup(s);"):
            self.assertTrue(self.problems(text, False), text)
        self.refused("const { markup, cat, put } = (() => ({}))();", "outside the dashboard renderer", False)

    def test_names_in_comments_and_regex_literals_do_not_confuse_the_lexer(self):
        extra = '/* el.innerHTML = s; createPolicy markup( Html */ // innerHTML\nconst r = /"innerHTML`/g;\n'
        self.assertEqual(self.problems(self.appended(extra)), [])

    def test_the_old_deny_list_machinery_is_gone(self):
        for name in ("sink_problems", "unwrapped_interpolations", "is_wrapped", "_direct_args", "SINK_NAMES",
                     "FORBIDDEN_CALLS", "html_problems", "SCRIPT_TAG", "EVENT_ATTR"):
            self.assertFalse(hasattr(guard, name), name)
        self.assertTrue(hasattr(guard, "js_problems"))


def shipped_policy():
    headers = (PUBLIC / "_headers").read_text(encoding="utf-8")
    values = csp.header_csp_values(headers, "/index.html")
    assert len(values) == 1, values
    return values[0]


class EveryPage7587(unittest.TestCase):
    def test_no_page_has_an_inline_script_a_handler_or_a_javascript_url(self):
        pages = sorted(PUBLIC.glob("*.html"))
        self.assertGreaterEqual(len(pages), 7)
        policy = shipped_policy()
        for page in pages:
            self.assertEqual(csp.check_page(page.read_text(encoding="utf-8"), policy), [], page.name)

    def test_7645_index_js_is_among_the_scripts_and_each_passes_the_allowlist(self):
        scripts = page_scripts()
        self.assertIn(INDEX_JS, scripts)
        for path in scripts:
            self.assertEqual(guard.js_problems(path.read_text(encoding="utf-8"), path == INDEX_JS), [], path.name)

    def test_the_only_markup_sink_is_the_typed_put_helper(self):
        src = real_index()
        self.assertRegex(src, r'host\.innerHTML = dash\.createHTML\("", h\);')
        self.assertRegex(src, r'if\(!\(h instanceof Html\)\) throw new TypeError\("put\(\) takes markup, not a string"\);')
        self.assertEqual(src.count("innerHTML"), 2, "one assignment plus the header comment")

    def test_escText_escapes_all_five_entities_once_7588(self):
        src = real_index()
        m = re.search(r"const escText = v => (.*?);\n", src)
        self.assertIsNotNone(m)
        for ent in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            self.assertIn(ent, m.group(1))
        part = re.search(r"const part = v => (.*?);\n", src).group(1)
        self.assertIn("instanceof Html", part)
        self.assertIn("escText(v)", part)

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
