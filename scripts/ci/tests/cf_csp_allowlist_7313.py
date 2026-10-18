"""Fail-closed allowlist for the cf-dashboard Content-Security-Policy and page markup (#7313, #7636-#7638).

This replaces the earlier emulation of a browser's CSP matching (fallback chains, nonces, strict-dynamic,
host-source path rules). A checker that re-implements the browser can be wrong in the permissive direction; this
one has no semantics to get wrong. It holds ONE table of the directives and tokens the dashboard may ship, and it
REFUSES everything else:

- a directive not in ALLOWED_DIRECTIVES, a token not listed for its directive, a duplicate directive, a comma
  (several policies in one value), and anything but exactly one Content-Security-Policy value per served path;
- a missing REQUIRED_DIRECTIVES entry (the Trusted Types pair among them);
- 'unsafe-inline' anywhere (DOCUMENTED_EXCEPTIONS is empty: no exception remains, inline style is gone), and any page
  with a `<style>` block or a `style` attribute;
- a `_headers` file the shared reader (cf_headers_7313.py) cannot prove it understands: a `!` removal line, a host or
  scheme rule pattern, a non-ASCII byte, a second Content-Security-Policy; the refusal carries the line number;
- a page that loads from an origin not in LOAD_ALLOW, or from one its own directive does not list;
- inline script, event-handler attributes, `javascript:` in any spelling, `<base>`, `<meta http-equiv>`, `srcset`,
  a backslash in CSS, frames/objects, and an `<svg>` with content.

The checker may refuse something that is safe (a wildcard, an own-host source, an unusual but harmless tag). That is
intended: widen the table on purpose. Every refusal names the directive or token, the file to edit and the doc
section, so the person who hits one knows where to go.
"""
import html as html_lib
import re
from html.parser import HTMLParser

import cf_headers_7313 as headers_mod
import cf_origin_7313 as origin_mod

TABLE_FILE = "scripts/ci/tests/cf_csp_allowlist_7313.py (ALLOWED_DIRECTIVES, LOAD_ALLOW)"
DOC_SECTION = 'infra/cf-dashboard/README.md, section "Widening the CSP allowlist"'
GOOGLE_CSS = "https://fonts.googleapis.com"
GOOGLE_FONTS = "https://fonts.gstatic.com"
SELF = "'self'"
NONE = "'none'"
UNSAFE_INLINE = "'unsafe-inline'"

# directive -> the only tokens it may carry. Keywords are lower-case and quoted, hosts are scheme + host, no path.
ALLOWED_DIRECTIVES = {
    "default-src": frozenset((SELF,)),
    "script-src": frozenset((SELF,)),
    "style-src": frozenset((SELF, GOOGLE_CSS)),
    "font-src": frozenset((GOOGLE_FONTS,)),
    "img-src": frozenset((SELF, "data:")),
    "connect-src": frozenset((SELF,)),
    "base-uri": frozenset((NONE,)),
    "form-action": frozenset((NONE,)),
    "object-src": frozenset((NONE,)),
    "frame-ancestors": frozenset((NONE,)),
    "require-trusted-types-for": frozenset(("'script'",)),
    "trusted-types": frozenset(("dash",)),
}
REQUIRED_DIRECTIVES = ("default-src", "script-src", "object-src", "base-uri", "require-trusted-types-for",
                       "trusted-types")
# (directive, token) -> reason, for a token outside ALLOWED_DIRECTIVES that is allowed on purpose. EMPTY (#7689): the
# only entry was style-src 'unsafe-inline'; every style attribute and <style> block now lives in index.css / vv.css or
# is set through the CSSOM (style.setProperty), which style-src does not govern.
DOCUMENTED_EXCEPTIONS = {}
# kind of load -> origins a page may load it from (origin_mod normalises: SELF_ORIGIN is a page-relative load)
LOAD_ALLOW = {
    "script": frozenset((origin_mod.SELF_ORIGIN,)),
    "style": frozenset((origin_mod.SELF_ORIGIN, GOOGLE_CSS)),
    "font": frozenset((GOOGLE_FONTS,)),
    "img": frozenset((origin_mod.SELF_ORIGIN, origin_mod.DATA_ORIGIN)),
}
# (kind, origin) -> the (directive, token) of the policy that must list it
LOAD_NEEDS = {
    ("script", origin_mod.SELF_ORIGIN): ("script-src", SELF),
    ("style", origin_mod.SELF_ORIGIN): ("style-src", SELF),
    ("style", GOOGLE_CSS): ("style-src", GOOGLE_CSS),
    ("font", GOOGLE_FONTS): ("font-src", GOOGLE_FONTS),
    ("img", origin_mod.SELF_ORIGIN): ("img-src", SELF),
    ("img", origin_mod.DATA_ORIGIN): ("img-src", "data:"),
}
ALWAYS_REFUSED_LOADS = ("inline-script", "script-attr", "inline-style", "style-attr")
REFUSED_TAGS = frozenset(("base", "math", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "portal"))
URL_LIKE = re.compile(r"[\x00-\x20\x7f​-‏  ﻿]+")
BAD_SCHEMES = ("javascript:", "vbscript:")


def _where(directive_or_token):
    return "%s; edit %s; see %s" % (directive_or_token, TABLE_FILE, DOC_SECTION)


def check_policy(value):
    """Refusals for one Content-Security-Policy header value (an empty list means accepted)."""
    refusals = []
    if "," in value:
        return [_where("a comma (several policies in one value is refused)")]
    seen = {}
    for raw in value.split(";"):
        parts = headers_mod.csp_tokens(raw)  # ASCII whitespace only (#7686): a no-break space is not a separator
        if not parts:
            continue
        name, tokens = parts[0].lower(), parts[1:]
        if name in seen:
            refusals.append(_where("duplicate directive %s" % name))
            continue
        seen[name] = tokens
        if name not in ALLOWED_DIRECTIVES:
            refusals.append(_where("directive %s is not in the allowlist" % name))
            continue
        if not tokens:
            refusals.append(_where("directive %s has no tokens" % name))
        for token in tokens:
            norm = token.lower() if token.startswith("'") else token
            if norm not in ALLOWED_DIRECTIVES[name]:
                refusals.append(_where("%s token %s is not in the allowlist" % (name, token)))
            elif norm == UNSAFE_INLINE and (name, norm) not in DOCUMENTED_EXCEPTIONS:
                refusals.append(_where("%s %s has no documented exception" % (name, norm)))
    for name in REQUIRED_DIRECTIVES:
        if name not in seen:
            refusals.append(_where("required directive %s is missing" % name))
    return refusals


def policy_tokens(value):
    """directive -> set of tokens, for an accepted policy value."""
    out = {}
    for raw in value.split(";"):
        parts = headers_mod.csp_tokens(raw)
        if parts:
            out[parts[0].lower()] = {t.lower() if t.startswith("'") else t for t in parts[1:]}
    return out


def check_path(headers_text, path):
    """(refusals, policy value or None) for a served path: the file is read by the shared fail-closed reader (a refusal
    names the line), exactly one policy applies, and it must pass check_policy."""
    try:
        values = headers_mod.csp_values(headers_text, path)
    except headers_mod.HeadersError as exc:
        return [_where("%s: %s" % (path, exc))], None
    if len(values) != 1:
        return [_where("%s gets %d Content-Security-Policy values, exactly one is allowed" % (path, len(values)))], None
    return check_policy(values[0]), values[0]


def _normal(value):
    text = value
    for _ in range(4):  # entities can be stacked
        decoded = html_lib.unescape(text)
        if decoded == text:
            break
        text = decoded
    return URL_LIKE.sub("", text).lower()


class _PageChecker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refusals = []
        self._script = None  # [has_src, body parts] inside a <script>
        self._style = None
        self._svg_depth = 0

    def refuse(self, what):
        self.refusals.append(_where(what))

    def handle_data(self, data):
        if self._script is not None:
            self._script[1].append(data)
        if self._style is not None:
            self._style.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            has_src, parts = self._script
            if "".join(parts).strip():
                self.refuse("<script> with an inline body")
            self._script = None
        if tag == "style" and self._style is not None:
            if "\\" in "".join(self._style):
                self.refuse("a backslash in a <style> block (CSS escapes hide url() targets)")
            self._style = None
        if tag == "svg" and self._svg_depth:
            self._svg_depth -= 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_starttag(self, tag, attrs):
        names = [k for k, _ in attrs]
        if self._svg_depth and tag != "svg":
            self.refuse("an <svg> with content (<%s> inside svg)" % tag)
        if tag == "svg":
            self._svg_depth += 1
        if tag in REFUSED_TAGS:
            self.refuse("<%s>" % tag)
        if tag == "meta" and "http-equiv" in names:
            self.refuse("<meta http-equiv> (a body or head meta policy is refused, set headers in _headers)")
        if tag == "script":
            if "src" not in names:
                self.refuse("<script> without a src attribute (inline script)")
            self._script = ["src" in names, []]
        if tag == "style":
            self._style = []
        for key, raw in attrs:
            value = raw or ""
            if key.startswith("on"):
                self.refuse("event-handler attribute %s" % key)
            if key in ("srcset", "imagesrcset"):
                self.refuse("%s attribute" % key)
            if key == "style" and "\\" in value:
                self.refuse("a backslash in a style attribute")
            norm = _normal(value)
            for scheme in BAD_SCHEMES:
                if scheme in norm:
                    self.refuse("%s in attribute %s" % (scheme, key))


def check_page(html_text, policy_value):
    """Refusals for one page served under the accepted policy value."""
    parser = _PageChecker()
    parser.feed(html_text)
    parser.close()
    refusals = list(parser.refusals)
    tokens = policy_tokens(policy_value) if policy_value else {}
    for load in origin_mod.page_loads(html_text):
        if load.kind in ALWAYS_REFUSED_LOADS:
            refusals.append(_where("%s load" % load.kind))
        elif load.origin not in LOAD_ALLOW.get(load.kind, ()):
            refusals.append(_where("%s load from %s (%s) is not in LOAD_ALLOW" % (load.kind, load.origin, load.path)))
        else:
            directive, token = LOAD_NEEDS[(load.kind, load.origin)]
            if token not in tokens.get(directive, ()):
                refusals.append(_where("%s load from %s needs %s %s in the policy" % (load.kind, load.origin, directive, token)))
    return refusals


def check_stylesheet(css_text, policy_value):
    """Refusals for one local stylesheet served under the accepted policy value: it may fetch only what a page may."""
    refusals = []
    if "\\" in css_text:
        refusals.append(_where("a backslash in a stylesheet (CSS escapes hide url() targets)"))
    tokens = policy_tokens(policy_value) if policy_value else {}
    for kind, value in origin_mod.css_loads(css_text):
        try:
            resolved = origin_mod.resolve_load(value)
        except origin_mod.UnparsedURL:
            refusals.append(_where("stylesheet %s load of %r does not parse" % (kind, value)))
            continue
        if resolved is None:
            continue
        origin = resolved[0]
        if origin not in LOAD_ALLOW.get(kind, ()):
            refusals.append(_where("stylesheet %s load from %s is not in LOAD_ALLOW" % (kind, origin)))
        else:
            directive, token = LOAD_NEEDS[(kind, origin)]
            if token not in tokens.get(directive, ()):
                refusals.append(_where("stylesheet %s load from %s needs %s %s in the policy" % (kind, origin, directive, token)))
    return refusals


def check_site(public_dir):
    """(path, refusal) pairs for the headers and every page of a public directory; empty means the site is accepted."""
    headers_text = (public_dir / "_headers").read_text(encoding="utf-8")
    found = []
    for page in sorted(public_dir.glob("*.html")):
        text = page.read_text(encoding="utf-8")
        for path in origin_mod.served_paths(page.name):
            refusals, value = check_path(headers_text, path)
            found.extend((path, r) for r in refusals)
            if value is not None and not refusals:
                found.extend((path, r) for r in check_page(text, value))
                found.extend((path, r) for r in _local_stylesheets(public_dir, text, value))
    return found


class _StylesheetLinks(HTMLParser):
    """The href of every `<link rel=stylesheet>` of a page, as written."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "link" and "stylesheet" in (a.get("rel") or "").lower().split() and a.get("href") is not None:
            self.hrefs.append(a["href"])


def _local_stylesheets(public_dir, page_text, policy_value):
    """Refusals for the same-origin stylesheets a page links: moving a <style> block into a file must not hide it.
    The file must sit directly in the public directory (no subdirectory, no `..`)."""
    out = []
    parser = _StylesheetLinks()
    parser.feed(page_text)
    parser.close()
    for href in parser.hrefs:
        try:
            resolved = origin_mod.resolve_load(href)
        except origin_mod.UnparsedURL:
            continue  # check_page refuses an unparsable load itself
        if not resolved or resolved[0] != origin_mod.SELF_ORIGIN:
            continue
        name = href.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        target = public_dir / name
        if "/" in name or not name or not target.is_file():
            out.append(_where("the stylesheet %s is not a file directly in the public directory" % href))
        else:
            out.extend(check_stylesheet(target.read_text(encoding="utf-8"), policy_value))
    return out
