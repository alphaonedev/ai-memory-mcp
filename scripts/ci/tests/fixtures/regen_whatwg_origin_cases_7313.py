#!/usr/bin/env python3
"""Regenerate whatwg_origin_cases_7313.json from the WHATWG URL parser in node (#7512-#7515).

The fixture records what a browser-grade `new URL(value, base)` does with every URL shape the
cf-dashboard origin helper must agree with. node is needed ONLY to regenerate; the unit test reads the
committed JSON. Usage: python3 regen_whatwg_origin_cases_7313.py [--out PATH]

Each case records one of: an origin string (a network origin other than the page's own),
"none" (same origin as the page, or an opaque origin: nothing external is loaded), "PARSE-FAIL".
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

BASE_URL = "https://dash.example/page.html"
PAGE_ORIGIN = "https://dash.example"
AT = chr(64)  # built so no literal email-shaped string appears in the source
HERE = Path(__file__).resolve().parent

# The 137 cases of review r5 (REVIEW-7314-combined-r5), in the reviewer's order.
REVIEW_CASES = [
    *[(chr(i) + "https://c%02x.example/p" % i) for i in range(0x21)],
    *[("https://e%02x.example/p" % i + chr(i)) for i in range(0x21)],
    *[(chr(i) + "//r%02x.example/p" % i + chr(i)) for i in range(0x21)],
    "https://p.example:443/x", "https://p.example:8443/x", "http://p.example:80/x", "http://p.example:8080/x",
    "http://p.example:443/x", "https://p.example:80/x",
    "https://p.example:0/x", "https://p.example:00443/x", "https://p.example:0080/x", "https://p.example:08443/x",
    "https://p.example:/x", "http://p.example:/x", "https://p.example:65536/x", "https://p.example:99999/x",
    "//p.example:8443/x", "//p.example:443/x",
    "https://[::1]/x", "https://[::1]:8443/x", "http://[2001:db8::1]:80/x", "//[::1]:9000/x",
    "https://127.0.0.1:8443/x", "https://0x7f.1/x",
    "https://u" + AT + "ui.example/x", "https://u:pw" + AT + "ui.example:9000/x",
    "https://u:p" + AT + "ss" + AT + "ui3.example/x", "https://a" + AT + "b" + AT + "ui4.example:8443/x",
    "https://u:" + AT + "ui5.example/x", "https://" + AT + "ui6.example/x",
    "HTTPS://UP.EXAMPLE/x", "HTTP://UP.EXAMPLE:8080/x", "HtTpS://Mx.Example:443/x",
    "https://%65xample.com/x", "https://a_b.example/x", "https://exämple.com/x", "https://host.example./x",
    "http:noslash.example/x", "https:noslash.example/x", "https:/one.example/x",
]

# Extra shapes added in the r6 fix round (#7512): slash runs, backslashes, IPv6 and IPv4 corner cases, host
# characters, port syntax, authority terminators, relative forms and schemes that load nothing.
EXTRA_CASES = [
    "https:///triple.example/x", "http:///triple2.example/x", "///slashes.example/x", "http:\\\\bs.example/x",
    "https:\\/mixed.example/x", "\\/mixed2.example/x", "/path//x.example", "foo//x.example", "x.example/p",
    "https://[::1/x", "https://[::1]x/x", "https://[::FFFF:1.2.3.4]/x", "https://[1:0:0:2:0:0:0:3]/x",
    "https://[0:0:0:0:0:0:0:0]:81/x", "https://[::1%25eth0]/x", "https://[zz]/x", "https://[::1]:/x",
    "https://[::1]:99999/x", "https://[]/x", "https://[1:2:3:4:5:6:7:8]:443/x", "https://[1::2:3]:8080/x",
    "https://ho[st.example/x",
    "https://host.example:80a/x", "https://host.example:+80/x", "https://host.example:80:90/x",
    "https://:80/x", "https:///", "http://", "https://u" + AT + "/x", "https://u" + AT + ":80/x",
    "https://127.1/x", "https://0177.0.0.1/x", "https://1.2.3.4.5/x", "https://256.1.1.1/x", "https://1.2.3/x",
    "https://4294967295/x", "https://4294967296/x", "https://0x/x", "https://0xG/x", "https://1.2.3.4./x",
    "https://a.0x1/x", "https://09/x", "https://foo.09/x", "https://0X7F.0.0.1/x", "https://1.2.3.4:8443/x",
    "https://FOO.Example%2E/x", "https://exa%mple/x", "https://a b.example/x", "https://a<b.example/x",
    "https://xn--/x", "https://xn--exmple-cua.com/x", "https://EXÄMPLE.com/x",
    "https://ex%C3%A4mple.com/x", "https://exa。mple.com/x", "https://a%00b.example/x",
    "https://a.example:8443" + AT + "evil.example/x", "https://evil.example\\" + AT + "good.example/x",
    "https://good.example?" + AT + "evil.example/x", "https://good.example#" + AT + "evil.example/x",
    "https://good.example:443?x", "https://good.example#frag", "https://good.example",
    "http:good.example:8080/x", "https:good.example/x", "https:/good.example/x", "HTTPS:\\\\UP2.example/x",
    "  //lead.example/x", "//x.example:abc/x", "//x.example:65535/x", "//x.example:65536/x",
    "data:text/html,//x.example", "javascript:alert(1)", "mailto:a" + AT + "b.example", "about:blank",
    "", "   ", "#frag", "?q=1", "./x", "../x", "https://dash.example/x", "//dash.example/x",
    "https://dash.example:8443/x", "https://DASH.example:443/x",
    # #7546: a label that starts with a combining mark, punycode that decodes to a mark / an unassigned code
    # point / nothing valid, and control shapes the browser accepts (written as escapes: the marks are invisible)
    "https://\u0301.example/x", "https://\u0301abc.example/x", "https://a.\u0301b.example/x",
    "https://\u0903x.example/x", "https://\u20ddx.example/x", "https://a\u0301.example/x",
    "https://xn--lsa.example/x", "https://xn--a-wbb.example/x", "https://xn--0x-7tb/x", "https://a.xn--lsa/x",
    "https://xn--2560a.example/x", "https://xn--a.example/x", "https://xn--xn--256-sge/x",
    "https://\u0378.example/x", "https://a\u0378b.example/x",
    "https://XN--LSA.example/x", "https://b\u00fccher.example/x",
]

ALL_CASES = [("review", v) for v in REVIEW_CASES] + [("extra", v) for v in EXTRA_CASES]


def oracle(values):
    js = (
        "const vs=JSON.parse(require('fs').readFileSync(0,'utf8'));"
        "console.log(JSON.stringify(vs.map(v=>{try{const u=new URL(v,%s);"
        "return (u.origin===%s||u.origin==='null')?'none':u.origin}catch(e){return 'PARSE-FAIL'}})));" % (
            json.dumps(BASE_URL), json.dumps(PAGE_ORIGIN))
    )
    out = subprocess.run(["node", "-e", js], input=json.dumps(values), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=HERE / "whatwg_origin_cases_7313.json")
    args = ap.parse_args()
    values = [v for _, v in ALL_CASES]
    results = oracle(values)
    node_version = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    doc = {
        "base_url": BASE_URL,
        "page_origin": PAGE_ORIGIN,
        "oracle": "node %s new URL(input, base_url)" % node_version,
        "cases": [{"group": g, "input": v, "browser": r} for (g, v), r in zip(ALL_CASES, results)],
    }
    text = json.dumps(doc, indent=1, ensure_ascii=True)
    # the userinfo vectors are not addresses; escape the at-sign so no email-shaped text sits in the file
    text = text.replace(AT, "\\u0040")
    args.out.write_text(text + "\n", encoding="utf-8")
    print("wrote %s: %d review cases + %d extra cases" % (args.out, len(REVIEW_CASES), len(EXTRA_CASES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
