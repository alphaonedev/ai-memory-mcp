"""Loaded-origin helper for the cf-dashboard CSP guard (#7313); imported by test_cf_dashboard_7313.py."""
import re
from html.parser import HTMLParser

URL_ATTRS = ("src", "href", "data", "poster", "xlink:href")
NON_LOADING_RELS = frozenset(("preconnect", "dns-prefetch"))
ORIGIN_RE = re.compile(r"^(?:(https?):)?//(?:[^/@?#]*@)?([a-z0-9.-]+)(?::([0-9]+))?", re.IGNORECASE)
DEFAULT_PORTS = {"https": "443", "http": "80"}
C0_AND_SPACE = "".join(chr(i) for i in range(0x21))


def origin_of(scheme, host, port):
    """scheme://host[:port], lower-cased, the scheme's default port dropped."""
    scheme = (scheme or "https").lower()
    port = (port or "").lstrip("0")
    suffix = "" if not port or port == DEFAULT_PORTS[scheme] else ":" + port
    return "%s://%s%s" % (scheme, host.lower(), suffix)


class _OriginParser(HTMLParser):
    """Collect external https origins from resource-loading tags with a real HTML parser
    (tag and attribute names arrive lower-cased, attribute values are entity-unescaped)."""

    TAGS = frozenset(("link", "script", "img", "iframe", "source", "video", "audio", "embed", "object",
                      "track", "input", "image"))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = set()

    def handle_starttag(self, tag, attrs):
        if tag not in self.TAGS:
            return
        found = {}
        for k, v in attrs:
            found.setdefault(k, v or "")  # the HTML parser keeps the FIRST duplicate attribute
        attrs = found
        rels = set(attrs.get("rel", "").lower().split())
        if tag == "link" and rels and rels <= NON_LOADING_RELS:
            return
        values = [attrs[k] for k in URL_ATTRS if k in attrs]
        for key in ("srcset", "imagesrcset"):
            if key in attrs:
                values.extend(c.split()[0] for c in attrs[key].split(",") if c.split())
        for value in values:
            # WHATWG URL parsing: strip leading/trailing C0 controls and space, drop tab/LF/CR,
            # treat backslash as slash
            value = value.strip(C0_AND_SPACE)
            value = re.sub(r"[\t\n\r]", "", value).replace("\\", "/")
            m = ORIGIN_RE.match(value)
            if m:
                self.found.add(origin_of(m.group(1), m.group(2), m.group(3)))


def loaded_origins(html):
    """External https origins a page loads (protocol-relative //host counts as https)."""
    parser = _OriginParser()
    parser.feed(html)
    parser.close()
    return parser.found
