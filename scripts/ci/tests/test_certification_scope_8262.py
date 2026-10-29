#!/usr/bin/env python3
"""Doc-pin for the v1.0.0 GA certification scope statement (#8262).

The statement in docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md is the
single source of truth for what the GA candidate certifies. This guard pins:

* the heading and the four blocks in order (IN, in-scope-pending, not-yet-landed
  fail-closed controls, NOT claimed);
* each block's item list (keyword and issue number, exact item count);
* the load-bearing sentences verbatim: the canonical end-to-end content
  encryption paragraph (in scope for GA, delivered by #8278, certification only
  after landing), the mTLS transport-only sentence, the mTLS IN item and the
  Postgres-native TDE not-claimed sentence;
* that the IN block makes no end-to-end content encryption claim and no
  live/certified over-claim, and that the open fail-closed gaps sit only in
  the not-yet-landed block;
* that every other place that mentions end-to-end content encryption links the
  statement anchor or quotes the canonical paragraph verbatim, and that no
  stale "#1968 open" wording returns.
"""
import bisect
import pathlib
import re
import unicodedata
import unittest
from html import unescape

ROOT = pathlib.Path(__file__).resolve().parents[3]
CERT_REL = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
CERT = ROOT / CERT_REL
HEADING = "### Certification scope statement for the v1.0.0 GA candidate"
ANCHOR = "certification-scope-statement-for-the-v100-ga-candidate-8262"
POINTERS = ["docs/federation.md", "SECURITY.md", "docs/SECURITY.md", "README.md"]
# Files whose end-to-end content encryption mentions must defer to the statement.
SINGLE_SOURCE_FILES = [CERT_REL, "docs/federation.md", "SECURITY.md",
                       "docs/SECURITY.md", "README.md", "CHANGELOG.md",
                       "docs/encryption.html", "docs/compliance/honest-limitations.md",
                       "docs/compliance/nsa-csi-mcp-security-mapping.md",
                       "docs/enterprise-deployment.md", "docs/federation-identity.md",
                       "ROADMAP.md", "docs/production-deployment.md",
                       "docs/reference/ARCHITECTURE_REFERENCE.md"]
TRUST_FILES = ["docs/enterprise-deployment.md", "docs/federation-identity.md"]
TRUST_PARA = "> Peers are **authenticated but NOT trusted"
TRUST_SENTENCE = "Peers **ARE trusted for confidentiality**"
BLOB_PREFIX = ("https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/"
               "compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md#")
ISSUE_URL = "https://github.com/alphaonedev/ai-memory-mcp/issues/"

B_IN = ("**Claimed for the GA candidate (IN; certification re-issue under "
        "[#6063](" + ISSUE_URL + "6063)):**")
OLD_B_IN = "Certified for the GA candidate"
B_PENDING = ("**In scope for v1.0.0 GA, certification issued on landing "
             "(not certified today):**")
B_UNLANDED = "**Fail-closed controls required for GA that are NOT yet landed at the pinned SHA.**"
B_NOT = "**NOT claimed for v1.0.0"
BLOCK_MARKERS = [B_IN, B_PENDING, B_UNLANDED, B_NOT]

E2E_CANON = (
    "Federation end-to-end content encryption, variants A and B, is in scope "
    "for v1.0.0 GA and is delivered by [#8278](" + ISSUE_URL + "8278). "
    "The certification is issued only when #8278 has landed on "
    "release/v1.0.0 with its tests green."
)
MTLS_ONLY = (
    "Until #8278 lands, the shipped guarantee for federation content is the "
    "mTLS transport only: peers replicate and store plaintext content."
)
MTLS_IN = "Federation transport is mTLS, and outbound peer server-certificate verification is on by default"
TDE_NOT_CLAIMED = ("Postgres-native TDE as a machine-checked control is "
                   "deliberately NOT claimed for v1.0.0")
SUPERSEDED_FACT = "closed with the `deferred-v1.x` label and is superseded by"

# keyword -> issue numbers the item must cite.
IN_ITEMS = {
    "Federation transport is mTLS": (2448, 232),
    "`sync/since` is peer-scoped": (948,),
    "Every shape requires TLS": (),
    "At-rest AEAD envelope encryption": (),
    "rustls is at the audited version": (3821,),
    "Provenance links refuse a cycle-closing edge": (3041,),
    "Encryption in transit": (3824, 3830),
}
UNLANDED_ITEMS = {
    "Quarantine of unattributed inbound writes": 2967,
    "Cert-to-peer binding enforced": 8260,
    "Refusal of Claimed (header-asserted) identity": 8265,
}
NOT_ITEMS = {
    "Postgres-native TDE": 8284,
    "Curator namespace-scoped mode": 8264,
    "Batman Form 2": 8255,
    "Top-shelf encryption documentation": 3833,
    "Singleton and Team shapes": 3125,
}
# The one definition of the end-to-end term, spelled once. Separators between the words: ASCII
# hyphen, whitespace, U+2010 through U+2015 (hyphen, non-breaking hyphen, figure dash, en dash,
# em dash, horizontal bar), U+2212 (minus sign), U+FE63 (small hyphen-minus) and U+FF0D (fullwidth
# hyphen-minus); HTML entities are unescaped and U+00AD (soft hyphen) is stripped before any scan.
# U+2043 (hyphen bullet) is deliberately absent: it is a list marker, not a word joiner.
# The abbreviation is E2E or E2EE (every pattern that uses it is case-insensitive).
E2E_SEP = r"[-\s\u2010-\u2015\u2212\uFE63\uFF0D]"
E2E_ABBR = r"\bE2EE?\b"
E2E_TERM = "end" + E2E_SEP + "+to" + E2E_SEP + "+end|" + E2E_ABBR
E2E_TERM_RE = re.compile(E2E_TERM, re.IGNORECASE)
_STEM = r"(?:encrypt|seal|confiden|protect|secur)"
# One character of a live/certified or at-GA window (SCOPE_REFUSED, FUTURE_RE): anything but a
# period or semicolon; the period inside a version number (digit, dot, digit, as in v1.0.0) passes.
# The term-and-stem pair gate does NOT use this window: it splits the plain text with
# SENTENCE_SPLIT_RE and looks for both in one sentence.
_W = r"(?:[^.;]|(?<=\d)\.(?=\d))"
_T = "(?:" + E2E_TERM + ")"
_STEM_RE = re.compile(_STEM, re.IGNORECASE)
# A stem inside a path or file name token (01-secure-bootstrap.sh, docs/encryption.html) names a
# file, not a claim. A file name token is lower case, holds only word characters, dots, slashes and
# hyphens, and is one of: a token ending in a known extension; a bare known file name (Cargo.toml,
# README.md, CHANGELOG.md, ROADMAP.md, LICENSE); a token with a slash that starts with ./, ../, /, a
# repository top-level directory, a host name (first segment holds a dot), a directory (trailing
# slash) or a dotted segment (deploy/asi-hard.env, cert-1/posture.out). A slash token whose
# segments are all words of this scan (encrypted/sealed, encrypted/signed) is a prose alternation,
# never a file. "encrypted.It" (a missing space) and "encrypt-everything" are words, not files. A
# bare "secure" or "end-to-end-encrypted" in the same sentence is still a stem. Each token is
# classified once.
_FILE_EXTS = (".md", ".sh", ".py", ".rs", ".html", ".toml", ".yml", ".yaml", ".json", ".txt", ".lock")
_DOTTED_SEGMENT_RE = re.compile(r"[\w-]\.[a-z]")
_FILE_BARE = frozenset(["Cargo.toml", "Cargo.lock", "README.md", "CHANGELOG.md", "ROADMAP.md", "LICENSE"])
_FILE_ROOTS = ("./", "../", "/", "docs/", "src/", "scripts/", "tests/", "migrations/", "infra/",
               "benches/", "examples/", "cookbook/", "tools/", ".github/")
_SCAN_WORDS = frozenset(["encrypted", "sealed", "signed", "certified", "deferred", "scope", "live",
                         "landed"])
_FILE_CHARS_RE = re.compile(r"[\w./-]+")
_TOKEN_EDGE = "()[]{}<>\"',;:!?"


def _is_file_token(token):
    token = token.strip(_TOKEN_EDGE).rstrip(".").strip(_TOKEN_EDGE)
    if token in _FILE_BARE:
        return True
    if token != token.lower() or _FILE_CHARS_RE.fullmatch(token) is None:
        return False
    if token.endswith(_FILE_EXTS):
        return True
    if "/" not in token or all(seg in _SCAN_WORDS for seg in token.split("/")):
        return False
    return (token.startswith(_FILE_ROOTS) or token.endswith("/") or "." in token.split("/", 1)[0]
            or _DOTTED_SEGMENT_RE.search(token) is not None)


def _has_claim_stem(sent):
    """True when a whitespace-delimited token that is not a file name holds an encryption stem."""
    return any(_STEM_RE.search(tok) and not _is_file_token(tok) for tok in sent.split(" "))


def _strip_cf(text):
    """Drop every Unicode format character (category Cf: U+00AD, U+200B..U+200D, U+2060, U+FEFF)."""
    if text.isascii():
        return text
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


# Cyrillic and Greek look-alike letters are mapped to Latin once, with NFKC, before any scan
# ("sc" + Cyrillic o + "pe" is "scope"). Code points are written as integers so the source stays ASCII.
_CONFUSABLE_PAIRS = (
    (0x0430, "a"), (0x0435, "e"), (0x043E, "o"), (0x0440, "p"), (0x0441, "c"), (0x0445, "x"),
    (0x0443, "y"), (0x0456, "i"), (0x0458, "j"), (0x0501, "d"), (0x0475, "v"), (0x0455, "s"),
    (0x04BB, "h"), (0x051B, "q"), (0x051D, "w"), (0x04CF, "l"),
    (0x0410, "A"), (0x0412, "B"), (0x0415, "E"), (0x041A, "K"), (0x041C, "M"), (0x041D, "H"),
    (0x041E, "O"), (0x0420, "P"), (0x0421, "C"), (0x0422, "T"), (0x0425, "X"), (0x0405, "S"),
    (0x0406, "I"), (0x0408, "J"),
    (0x03BF, "o"), (0x03BD, "v"), (0x03C1, "p"), (0x03C4, "t"), (0x03C5, "u"), (0x03BA, "k"),
    (0x03B9, "i"), (0x03B1, "a"), (0x03B5, "e"),
    (0x0391, "A"), (0x0392, "B"), (0x0395, "E"), (0x0396, "Z"), (0x0397, "H"), (0x0399, "I"),
    (0x039A, "K"), (0x039C, "M"), (0x039D, "N"), (0x039F, "O"), (0x03A1, "P"), (0x03A4, "T"),
    (0x03A5, "Y"), (0x03A7, "X"),
)
_CONFUSABLES = dict(_CONFUSABLE_PAIRS)


def _normalise(text):
    """Format characters dropped, NFKC applied, Cyrillic and Greek look-alikes mapped to Latin."""
    if text.isascii():
        return text
    return unicodedata.normalize("NFKC", _strip_cf(text)).translate(_CONFUSABLES)


E2E_ABBR_RE = re.compile(E2E_ABBR)
E2E_SLUG_RE = re.compile(r"#1968|end-to-end-content", re.IGNORECASE)
SOFT_HYPHEN = "\u00ad"


class _E2EGate:
    """A unit is scanned when it names #1968 or the content slug, the uppercase E2E/E2EE
    abbreviation, or when one sentence of its plain text (split by SENTENCE_SPLIT_RE) holds the
    term and an encryption stem, in either order, at any distance. Format characters are
    stripped first; a stem inside a file name token does not count."""

    @staticmethod
    def search(unit):
        unit = _normalise(unit)
        if E2E_SLUG_RE.search(unit) or E2E_ABBR_RE.search(unit):
            return True
        for sent in SENTENCE_SPLIT_RE.split(_plain(unit)):
            if E2E_TERM_RE.search(sent) and _has_claim_stem(sent):
                return True
        return False


E2E_GATE = _E2EGate
STALE_RE = re.compile(r"1968[^.\n]{0,60}\b(?:open|unresolved|still\s+open)\b"
                      r"|\b(?:open|unresolved|still\s+open)\b[^.\n]{0,40}1968", re.IGNORECASE)
# The "Last updated: 2026-09-11 ... Previous: 2026-08-16 (... #1968 OPEN ...)" history line records
# what was true on that date. It is exempt from the stale and anchor scans ONLY; the over-claim
# scan (SCOPE_REFUSED, FUTURE_RE) still runs on it.
HISTORY_LINE_RE = re.compile(r"^Last updated:\s*\d{4}-\d{2}-\d{2}\b")
SECURITY_HISTORY_ENTRY = "federation-is-plaintext (#1968 OPEN) posture note added"
OVERCLAIM_RE = re.compile(r"\b(live|certified)\b", re.IGNORECASE)
E2E_WORD_RE = re.compile(E2E_TERM + r"|content encryption", re.IGNORECASE)
# Over-claim patterns refused in every end-to-end paragraph outside the statement.
E = "(?:" + E2E_TERM + ")"
NEG_RE = re.compile(r"\b(?:not|no)\b[^.;]{0,60}" + E + "|" + E + r"[^.;]{0,60}\bnot\b",
                    re.IGNORECASE)
SCOPE_REFUSED = [
    re.compile(r"\bout of (?:the |ga |v1\.0\.0 |\w+ ){0,3}scope\b", re.IGNORECASE),
    re.compile(r"\bnot in (?:the |ga |v1\.0\.0 |\w+ ){0,3}scope\b", re.IGNORECASE),
    re.compile(r"\bships? in v1\.0\.0", re.IGNORECASE),
    re.compile(r"\b(?:is|are)\s+(?!not\b)(?:\w+\s+){0,2}" + E, re.IGNORECASE),
    re.compile(E + _W + r"{0,60}\b(?:is|are)\s+(?:provided|supported|enabled|available|"
               r"shipped|implemented)", re.IGNORECASE),
    re.compile(r"\b(?:provides?|supports?|offers?)\s+(?:\w+\s+){0,2}" + E, re.IGNORECASE),
    re.compile(_STEM + r"\w*\s+(?:\w+\s+){0,2}" + E
               + _W + r"{0,50}(?<!not )\b(?:live|certified)\b", re.IGNORECASE),
    re.compile(r"(?<!not )\b(?:live|certified)\b" + _W + "{0,50}" + E + "|"
               + E + _W + r"{0,50}(?<!not )\b(?:live|certified)\b", re.IGNORECASE),
]
# Future-tense or at-GA wording is refused in any unit that lacks the landing condition.
FUTURE_RE = re.compile(r"\b(?:will|shall|to)\s+be\s+(?:\w+\s+){0,3}" + E
                       + r"|" + E + _W + r"{0,40}\bat\s+GA\b|\bencrypted\s+at\s+GA\b"
                       + r"|\bships?\s+(?:with|in|at)\s+GA\b|\bat\s+GA\b", re.IGNORECASE)
# Under-claim wording, ONE definition. A sentence about the term, #8278 or variant A/B
# (UNDER_SUBJECT_RE) is refused when it: uses a postponement predicate (_DEFER); uses a move or
# plan verb (_MOVE: slip, push, plan, schedule, target, slate, aim, due ...) followed by a later
# version, after GA or the next release; says "removed from ... scope"; names a GA scope exclusion
# (SCOPE_REFUSED[:2], _EXCLUDE); calls it a later-version item (_EXCLUDE). Postponement wording
# in a sentence that names #8278 or variant A/B is refused with no predicate needed (_NAMED_DEFER).
# The sentence bounds the scan, so the ROADMAP ruling paragraph that postpones other items to v1.x
# stays clean. Decision: no blanket "subject plus any later version" refusal (3 false positives on
# the docs: README.md 1, ROADMAP.md 2). Exempt: the one true ROADMAP supersession clause only.
# _LATER is any version other than v1.0.0, later, after GA, post GA, or a next/future release.
_LATER = (r"(?:\bv(?:1\.0\.[1-9]\d*|1\.[1-9x]\d*|1\d+|[2-9]\d*)(?:\.\d+)*"
          r"|\blater\b|\bafter\s+GA\b|\bpost[\s-]*GA\b"
          r"|\b(?:next|future)\s+(?:\w+\s+)?release\b)")
_PAST = r"(?:deferred|postponed|slipped)"
# Predicate use only (is/was/remains ... deferred, deferred until/post, defers/postpones it);
# an attributive "deferred graph projection" does not postpone the subject.
_DEFER = (r"\b(?:is|are|was|were|be|been|being|remains?|remained|gets?|got)\s+(?:\w+\s+){0,2}"
          + _PAST + r"\b|\b" + _PAST + r"\s+(?:to|until|till|past|beyond|after|post|for)\b"
          r"|\b(?:defers?|postpones?|punts?)\b|\bdeferred\s+set\b")
_MOVE = (r"\b(?:slip|push|mov|punt|defer|postpon|land|ship|come|arriv|plann|schedul|target|slat"
         r"|aim|due|retarget|re-target|expect)\w*\b")
_REMOVED = r"\bremoved\s+from\s+(?:the |ga |v1\.0\.0 |\w+ ){0,3}scope\b"
_NOT_GA = (r"\b(?:not|never|no\s+longer)\b(?:\W+\w+){0,3}?\W+"
          r"(?:part\s+of|in|included\s+in|ship\w*|land\w*)\b[^.;]{0,30}?\b(?:v1\.0\.0|GA)\b")
_NOT_GA_RE = re.compile(_NOT_GA, re.IGNORECASE)
_GA_WORD_RE = re.compile(r"\bGA\b|v1\.0\.0", re.IGNORECASE)
_EXCLUDE = (r"\bexclud\w*\s+from\b|\bdescoped\b"
            r"|\b(?:planned|scheduled|targeted|slated|tracked)\s+for\s+(?:\w+\s+){0,2}" + _LATER
            + r"|\b(?:an?\s+)?" + _LATER + r"\s+(?:item|feature|deliverable|milestone|target)s?\b"
            # Moved out of, dropped from, cut from GA or v1.0.0; missing or not making it; out of GA.
            + r"|\b(?:moved|pushed|dropped|cut|taken|pulled|removed|bumped)\s+(?:out\s+of|from|off)"
            r"\s+(?:\w+\s+){0,3}?(?:v1\.0\.0|GA)\b"
            + r"|\b(?:miss(?:es|ed)?|(?:will|does|did|do|would)\s+not\s+make|won't\s+make"
            r"|fail(?:s|ed)?\s+to\s+make)\s+(?:the\s+)?(?:v1\.0\.0\s+)?(?:GA|v1\.0\.0)\b"
            + r"|\b(?:out\s+of|outside)\s+(?:the\s+)?(?:v1\.0\.0\s+)?(?:GA|v1\.0\.0)\b")
UNDER_RE = re.compile(_DEFER + "|" + _REMOVED + "|" + _EXCLUDE, re.IGNORECASE)
# The move branch runs only on a sentence that holds a later-version token (cheap gate first).
MOVE_LATER_RE = re.compile(_MOVE + r"(?:\W+\w+){0,10}?\W+" + _LATER, re.IGNORECASE)
# Subjects: the end-to-end term, content encryption, #8278, and variant A or B (upper case letter).
UNDER_SUBJECT_RE = re.compile(E2E_TERM + r"|content\s+encryption|#8278|(?-i:\b[Vv]ariants?\s+[AB]\b)",
                              re.IGNORECASE)
NAMED_SUBJECT_RE = re.compile(r"#8278|(?-i:\b[Vv]ariants?\s+[AB]\b)", re.IGNORECASE)
_NAMED_DEFER = re.compile(r"\b(?:deferr(?:ed|al)|postponed|descoped?)\b(?!-)", re.IGNORECASE)
_LATER_RE = re.compile(_LATER, re.IGNORECASE)
# A scope sentence with a carve-out is a narrowing: except / save for / other than / apart from /
# excluding, "for variant A only", "but variant B is not", "until v1.1". Refused in every file.
SCOPE_WORD_RE = re.compile(r"\bscope\b|\bGA\b|v1\.0\.0", re.IGNORECASE)
CARVE_RE = re.compile(r"\b(?:except|save\s+for|other\s+than|apart\s+from|excluding)\b"
                      r"|\bbut\b[^.;]{0,60}?\b(?:is|are|was|were)\s+not\b"
                      r"|(?-i:\bvariants?\s+[AB]\s+only\b|\bonly\s+(?:for\s+|in\s+)?variants?\s+[AB]\b)"
                      r"|\buntil\s+" + _LATER, re.IGNORECASE)
# The dated supersession note, ROADMAP.md:986: "(Superseded by #8278 on 2026-10-28: federation
# content encryption was removed from this deferred set and is in v1.0.0 GA scope." Only this whole
# true sentence (ROADMAP_EXEMPT, exact after whitespace normalisation) is exempt, only in ROADMAP.md,
# and only after the negated form is refused; any text before or after it is scanned in full.
DEFERRED_CLAUSE = ("federation content encryption was removed from this deferred set "
                   "and is in v1.0.0 GA scope")
ROADMAP_REL = "ROADMAP.md"
NEG_REMOVED_RE = re.compile(r"\b(?:not|never)\b(?:\W+\w+){0,2}?\W+removed\s+from\s+this\s+deferred\s+set",
                            re.IGNORECASE)
# The one sentence splitter: a period or semicolon plus whitespace ends a sentence, except after
# "e.g", "i.e" and "etc" in any case. A period with no whitespace after it (v1.x, a URL) never splits.
SENTENCE_SPLIT_RE = re.compile(r"(?<!\b[eE]\.g)(?<!\b[iI]\.e)(?<!\b[eE][tT][cC])[.;]\s")


# The exempt ROADMAP sentence, whole: sentence boundary to sentence boundary after whitespace
# normalisation. Any leading or trailing text makes it a different sentence, which is scanned in full.
ROADMAP_EXEMPT = "(Superseded by #8278 on 2026-10-28: " + DEFERRED_CLAUSE


def _underclaims(sent, rel=None, strict=False):
    """True for a sentence about the term or #8278 that defers it or puts it out of GA scope.
    A table row, and any statement sentence (strict), also refuses a named subject plus a later
    version; a scope sentence with a carve-out is refused everywhere."""
    if "removed" in sent.lower() and NEG_REMOVED_RE.search(sent):
        return True
    if rel == ROADMAP_REL and _flat(sent).strip() == ROADMAP_EXEMPT:
        return False
    if not UNDER_SUBJECT_RE.search(sent):
        return False
    named_later = ((strict or sent.lstrip().startswith("|")) and NAMED_SUBJECT_RE.search(sent)
                   and _LATER_RE.search(sent))
    return bool(UNDER_RE.search(sent) or any(rx.search(sent) for rx in SCOPE_REFUSED[:2])
                or (_LATER_RE.search(sent) and MOVE_LATER_RE.search(sent))
                or (_GA_WORD_RE.search(sent) and _NOT_GA_RE.search(sent))
                or (NAMED_SUBJECT_RE.search(sent) and _NAMED_DEFER.search(sent))
                or (SCOPE_WORD_RE.search(sent) and CARVE_RE.search(sent)) or named_later)


# Over-claims keyed on the same subjects as the under-claims (#8278, variant A or B, content
# encryption): a landed, shipped, live, certified, enabled, available or encrypted predicate, or a
# plaintext or reader consequence, unless a condition or a negation stands in the 40 characters
# before it ("only when #8278 has landed", "is not live today").
OVERCLAIM_SUBJECT_RE = re.compile(r"#8278|(?-i:\b[Vv]ariants?\s+[AB]\b)|content\s+encryption",
                                  re.IGNORECASE)
OVERCLAIM_PRED_RE = re.compile(
    r"\b(?:landed|shipped|merged|certified|completed?|done|live|available|enabled|encrypts?|encrypted"
    r"|on\s+by\s+default|in\s+GA(?!\s+scope))\b"
    r"|\bno\s+longer\s+(?:store|see|hold)\w*\s+plaintext\b|\bpeers\s+cannot\s+read\b", re.IGNORECASE)
OVERCLAIM_HEDGE_RE = re.compile(r"\b(?:not|never|nor|until|unless|once|when|if|before|after|pending|yet"
                                r"|cannot)\b|\bno\b(?!\s+longer)", re.IGNORECASE)
HEDGE_WINDOW = 40
SUBJECT_REACH = 70


def _overclaims(sent):
    """True for a sentence that states #8278, variant A or B or content encryption as fact: a
    predicate within SUBJECT_REACH characters of a subject (either order) and not hedged."""
    spans = [(m.start(), m.end()) for m in OVERCLAIM_SUBJECT_RE.finditer(sent)]
    if not spans:
        return False
    firsts = [s for s, _ in spans]
    for m in OVERCLAIM_PRED_RE.finditer(sent):
        if OVERCLAIM_HEDGE_RE.search(sent[max(0, m.start() - HEDGE_WINDOW):m.start()]):
            continue
        k = bisect.bisect_right(firsts, m.start())
        before = m.start() - spans[k - 1][1] if k else SUBJECT_REACH + 1
        after = spans[k][0] - m.end() if k < len(spans) else SUBJECT_REACH + 1
        if min(before, after) <= SUBJECT_REACH:
            return True
    return False


def _sentence_problem(sent, rel=None, statement=False):
    """The one sentence check shared by the docs scan, the statement scan and the self-tests."""
    if _underclaims(sent, rel, strict=statement):
        return "under-claim"
    return "over-claim" if _overclaims(sent) else None


LANDING = "landed on release/v1.0.0"
# The one pointer sentence quoted in every file that mentions end-to-end content encryption.
# Only the link target differs per file; the anchor is pinned.
POINTER_HEAD = ("Federation content is not end-to-end encrypted today (mTLS transport only); "
                "the end-to-end content encryption status is stated only in the ")
POINTER_RE = re.compile(re.escape(POINTER_HEAD + "[certification scope statement](")
                        + r"[^)\s]*#" + re.escape(ANCHOR) + r"\)\.")
# Files whose in-scope text (outside the statement) must quote the pointer sentence.
POINTER_SENTENCE_FILES = ["SECURITY.md", "docs/SECURITY.md", "docs/federation.md",
                          "CHANGELOG.md", CERT_REL, "docs/encryption.html",
                          "docs/compliance/honest-limitations.md",
                          "docs/compliance/nsa-csi-mcp-security-mapping.md"]
SECURITY_E2E_SHAPE = (
    "End-to-end content encryption across federation (per-namespace scope keys, a per-record "
    "content key wrapped to each reader with X25519, envelope version 0x05, sealed on the wire, "
    "reader-scoped, with key rotation) is in scope for v1.0.0 GA and is delivered by "
    "[#8278](" + ISSUE_URL + "8278); it is not live today, and its certification is issued only "
    "when #8278 has landed on release/v1.0.0 with its tests green.")
OLD_E2E_LABEL = re.compile(r"blind-replica|ciphertext-only|reduced-capability", re.IGNORECASE)
SYNC_SINCE_PINS = [
    "`sync/since` is peer-scoped while the operator bypass `AI_MEMORY_FED_SYNC_TRUST_PEER=1` is unset",
    "so the empty-envelope and private-visibility claim does not hold under it",
    "`src/federation/peer_attestation.rs:390-392`",
    "consumed at `src/handlers/federation_sync_since.rs:289`",
    "The bypass is outside the asi-hard KNOBS set; only the enterprise posture doctor flags it",
    "`docs/compliance/evidence/cert-385da3a05/posture-*.out`",
]


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _subsection():
    text = CERT.read_text(encoding="utf-8")
    start = text.find(HEADING)
    if start < 0:
        raise AssertionError("scope statement heading missing: " + HEADING)
    end = text.find("\n---\n", start)
    return text[start:end if end > 0 else len(text)]


def _blocks():
    """Return {marker: body text after the marker line} in statement order."""
    sec = _subsection()
    positions = []
    for marker in BLOCK_MARKERS:
        if sec.count(marker) != 1:
            raise AssertionError("block marker must appear exactly once: " + marker)
        positions.append(sec.index(marker))
    if positions != sorted(positions):
        raise AssertionError("scope statement blocks are out of order")
    out = {}
    for i, marker in enumerate(BLOCK_MARKERS):
        stop = positions[i + 1] if i + 1 < len(positions) else len(sec)
        body = sec[positions[i]:stop]
        out[marker] = body.split("\n", 1)[1] if "\n" in body else ""
    return out


def _items(body):
    items, cur = [], None
    for ln in body.splitlines():
        if ln.startswith("- "):
            cur = [ln]
            items.append(cur)
        elif cur is not None and ln.startswith("  "):
            cur.append(ln)
    return [" ".join(part.strip() for part in i) for i in items]


def _plain(text):
    """Flatten and drop markdown emphasis, backticks and link targets before wording scans."""
    text = re.sub(r"\]\([^)]*\)", "]", text)
    return _flat(re.sub(r"[*`]", "", _normalise(text)))


# The statement is scanned like every other place, except for the two true sentences it exists to
# state: the pinned canonical paragraph, and the one fact that #1968 was closed with the label
# `deferred-v1.x` and is superseded by #8278. Only these exact strings are removed.
LABEL_FACT = "[#1968] was closed with the deferred-v1.x label and is superseded by #8278."


def _neutral_statement(plain):
    return plain.replace(_plain(E2E_CANON), "").replace(LABEL_FACT, "")


def _units(text):
    """Paragraphs further split at top-level list items and table rows, so each is one unit."""
    out = []
    for para in _paragraphs(text):
        out.extend(u for u in re.split(r"\n(?=[-*] |\|)", para) if u.strip())
    return out


def _html_text(html):
    """Plain text of an HTML page: links become markdown links, block ends become blank lines."""
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", "", html)
    html = re.sub(r'(?is)<a\s[^>]*href="([^"]*)"[^>]*>(.*?)</a>', r"[\2](\1)", html)
    html = re.sub(r"(?i)</(?:p|div|li|h\d|tr|section|pre)>", "\n\n", html)
    return unescape(re.sub(r"<[^>]+>", "", html))


def _flat(text):
    return re.sub(r"\s+", " ", text)


def _check_items(case, body, expected):
    items = _items(body)
    case.assertEqual(len(items), len(expected), "item count drifted: %d" % len(items))
    for key, nums in expected.items():
        hit = [i for i in items if key in i]
        case.assertEqual(len(hit), 1, "item missing or duplicated: " + key)
        for num in (nums if isinstance(nums, tuple) else (nums,)):
            case.assertRegex(hit[0], r"#%d\b" % num, key + " lost #%d" % num)
    return items


def _paragraphs(text):
    text = re.sub(r"^[ \t]*>+ ?", "", text, flags=re.MULTILINE)
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


def _unreleased(text):
    """The CHANGELOG entry this guard owns: the '### Docs (#8262' subsection."""
    start = text.find("### Docs (#8262")
    if start < 0:
        raise AssertionError("CHANGELOG #8262 entry missing")
    nxt = re.search(r"^### ", text[start + 5:], re.MULTILINE)
    return text[start:start + 5 + nxt.start()] if nxt else text[start:]


class CertificationScope8262(unittest.TestCase):
    def test_heading_present_and_blocks_in_order(self):
        self.assertIn(HEADING, CERT.read_text(encoding="utf-8"))
        self.assertEqual(len(_blocks()), len(BLOCK_MARKERS))

    def test_in_block_items_and_no_overclaim(self):
        body = _blocks()[B_IN]
        _check_items(self, body, IN_ITEMS)
        self.assertIn(MTLS_IN, _flat(body))
        self.assertIsNone(E2E_WORD_RE.search(body), "IN block makes an end-to-end claim")
        self.assertIsNone(OVERCLAIM_RE.search(body.replace("on by default", "")),
                          "IN block carries a live/certified over-claim")

    def test_e2e_canonical_paragraph_in_pending_block(self):
        body = _flat(_blocks()[B_PENDING])
        self.assertIn(E2E_CANON, body)
        self.assertIn(MTLS_ONLY, body)
        self.assertIn(SUPERSEDED_FACT, body)
        self.assertIn("#1968", body)
        self.assertEqual(body.count(E2E_CANON), 1)
        self.assertNotRegex(body.replace(E2E_CANON, ""), r"\b(is|are) (live|certified)\b")
        self.assertNotIn("1968) is open", body.lower())

    def test_unlanded_block_items(self):
        body = _blocks()[B_UNLANDED]
        _check_items(self, body, UNLANDED_ITEMS)
        self.assertIn("open", body)

    def test_open_gaps_only_in_unlanded_block(self):
        blocks = _blocks()
        for marker in (B_IN, B_PENDING, B_NOT):
            for num in UNLANDED_ITEMS.values():
                self.assertNotRegex(blocks[marker], r"#%d\b" % num,
                                    "open gap #%d sits outside the not-yet-landed block" % num)

    def test_not_claimed_block_items(self):
        body = _blocks()[B_NOT]
        items = _check_items(self, body, NOT_ITEMS)
        self.assertIn(TDE_NOT_CLAIMED, _flat(body))
        self.assertIsNone(E2E_WORD_RE.search(body), "NOT-claimed block names end-to-end encryption")
        self.assertTrue(any("deferred-v1.x" in i and not re.search(r"\bso\s+defer", i) for i in items))

    def test_pointers_present(self):
        for rel in POINTERS:
            self.assertIn(ANCHOR, _read(rel), rel + " lost the pointer")

    def test_readme_pointer_follows_current_release_paragraph(self):
        paras = _paragraphs(_read("README.md"))
        idx = [i for i, p in enumerate(paras) if ANCHOR in p]
        self.assertEqual(len(idx), 1)
        # U+2014 em dash, written as an escape: the README heading uses it.
        self.assertTrue(paras[idx[0] - 1].startswith("**v1.0.0 \u2014 current release.**"))

    def _scoped_text(self, rel):
        """The part of a file this guard scans: outside the statement, history lines removed."""
        return "\n".join(ln for ln in _normalise(self._text(rel)).splitlines()
                         if not HISTORY_LINE_RE.match(ln))

    def _history(self, rel):
        return [ln for ln in _normalise(self._text(rel)).splitlines() if HISTORY_LINE_RE.match(ln)]

    def _text(self, rel):
        text = _read(rel)
        if rel.endswith(".html"):
            text = _html_text(text)
        if rel == CERT_REL:
            text = text.replace(_subsection(), "")
        elif rel == "CHANGELOG.md":
            text = _unreleased(text)
        return text

    def test_single_source_for_e2e_scope(self):
        for rel in SINGLE_SOURCE_FILES:
            text = self._scoped_text(rel)
            self.assertIsNone(STALE_RE.search(text), rel + " carries a stale '#1968 open' claim")
            for unit in _units(text):
                for sent in SENTENCE_SPLIT_RE.split(_plain(unit)):
                    self.assertIsNone(_sentence_problem(sent, rel),
                                      "end-to-end scope under-claim or over-claim in "
                                      + rel + ": " + sent[:100])
                if not E2E_GATE.search(unit):
                    continue
                raw = _flat(unit)
                head = rel + ": " + raw[:100]
                self.assertTrue(ANCHOR in raw or E2E_CANON in raw,
                                "end-to-end paragraph without the statement anchor: " + head)
                plain = _plain(unit)
                self.assertRegex(plain, NEG_RE, "end-to-end paragraph lacks the not-E2E "
                                 "statement: " + head)
                self._refuse_overclaim(plain, head)
            for line in self._history(rel):
                self._refuse_overclaim(_plain(line), rel + " history: " + line[:80])

    def _refuse_overclaim(self, plain, head, landing_ok=True):
        for rx in SCOPE_REFUSED:
            self.assertIsNone(rx.search(plain), "end-to-end over-claim (%s) in %s"
                              % (rx.pattern[:40], head))
        if LANDING not in plain or not landing_ok:
            self.assertIsNone(FUTURE_RE.search(plain),
                              "future-tense end-to-end wording without the landing condition: " + head)

    def test_statement_is_scanned_for_over_and_under_claims(self):
        for unit in _units(_subsection()):
            plain = _neutral_statement(_plain(unit))
            for sent in SENTENCE_SPLIT_RE.split(plain):
                self.assertIsNone(_sentence_problem(sent, statement=True),
                                  "statement under-claim or over-claim: " + sent[:100])
            if E2E_GATE.search(plain):
                self._refuse_overclaim(plain, "statement: " + plain[:100], landing_ok=False)

    def test_pointer_sentence_quoted_in_every_pointer_file(self):
        for rel in POINTER_SENTENCE_FILES:
            flat = _flat(self._scoped_text(rel))
            self.assertIsNotNone(POINTER_RE.search(flat),
                                 rel + " lost the verbatim pointer sentence")

    def test_trust_boundary_sentence_is_pinned(self):
        for rel in TRUST_FILES:
            paras = [p for p in re.split(r"\n\s*\n", _read(rel)) if TRUST_PARA in p]
            self.assertEqual(len(paras), 1, rel + " lost the trust-boundary paragraph")
            self.assertEqual(paras[0].count(TRUST_SENTENCE), 1,
                             rel + " lost the peers-are-trusted-for-confidentiality sentence")

    def test_html_pointer_links_use_the_blob_url(self):
        text = _read("docs/encryption.html")
        hrefs = re.findall(r'href="([^"]*#' + re.escape(ANCHOR) + r')"', text)
        self.assertEqual(len(hrefs), 2)
        self.assertEqual(re.findall(r'href="(?!https?://)[^"]*\.md', text), [],
                         "docs/encryption.html carries a relative .md link")
        for href in hrefs:
            self.assertTrue(href.startswith(BLOB_PREFIX), "relative or wrong statement link: " + href)

    def test_security_md_e2e_bullet_states_8278_shape_and_condition(self):
        flat = _flat(_read("SECURITY.md"))
        self.assertEqual(flat.count(SECURITY_E2E_SHAPE), 1)
        self.assertIsNone(OLD_E2E_LABEL.search(flat), "SECURITY.md carries the #1968 design label")
        self.assertIn("**Federation is NOT end-to-end encrypted", _read("SECURITY.md"))

    def test_security_md_keeps_dated_history_entry(self):
        history = self._history("SECURITY.md")
        self.assertTrue(any(SECURITY_HISTORY_ENTRY in ln for ln in history),
                        "the dated 2026-08-16 history entry lost '(#1968 OPEN)'")

    def test_stale_claim_is_caught_outside_history(self):
        stale = "End-to-end encryption (#1968) is open today."
        self.assertIsNotNone(STALE_RE.search(stale))
        self.assertIsNone(HISTORY_LINE_RE.match(stale))
        self.assertIsNotNone(HISTORY_LINE_RE.match("Last updated: 2026-09-11 (x). Previous: 2026-08-16"))

    def test_overclaim_vocabulary_catches_reviewer_shapes(self):
        refused = ["E2E content encryption is live and certified for v1.0.0.",
                   "E2E is enabled by default.",
                   "Federation content is end-to-end encrypted and certified.",
                   "Federation content is end to end encrypted and certified for v1.0.0.",
                   "Federation is end\u2011to\u2011end encrypted and certified.",
                   unescape("Federation is end&#8209;to&#8209;end encrypted and certified."),
                   "Federation content is encrypted end-to-end and certified for v1.0.0.",
                   "Federation E2EE is live and certified",
                   "Federation is end\u2013to\u2013end encrypted and certified.",
                   "Federation is end\u2014to\u2014end encrypted and certified.",
                   "Federation content is secured end-to-end and certified.",
                   "Federation content is encrypted end to end and certified for v1.0.0.",
                   "e2e encryption is live and certified.",
                   "E2E content encryption in v1.0.0 is live and certified.",
                   "Certified and live for v1.0.0: federation content encrypted end-to-end.",
                   "E2E content encryption in GA is live and certified.",
                   "Federation is end\ufe63to\ufe63end encrypted and certified.",
                   "Federation is end\uff0dto\uff0dend encrypted and certified."]
        for s in refused:
            self.assertTrue(any(rx.search(s) for rx in SCOPE_REFUSED), s)
        gated = ["Federation content is encrypted end-to-end and certified.",
                 "| end-to-end | encrypted and certified |",
                 "Federation E2EE is live and certified", "e2e encryption is live",
                 "Federation is secured end\u2011to\u2011end and certified.",
                 "Federation is end\u2013to\u2013end encrypted.", "see #1968",
                 "Federation content is encrypted, end to end, and certified for v1.0.0.",
                 "Federation content is encrypted (end-to-end) and certified.",
                 "| 997 | encrypted, live and certified | end-to-end |",
                 "| 996 | live, certified, encrypted | end-to-end |",
                 "| 995 | encrypted | end-to-end |",
                 "Content is encrypted when the local node writes it and then travels end-to-end.",
                 "End-to-end delivery across the whole mesh of configured peers is protected by mTLS.",
                 "Federation is en\u00add-to-end encrypted.",
                 "Federation is end\ufe63to\ufe63end encrypted.",
                 "Federation is end\uff0dto\uff0dend encrypted.",
                 # A missing space is a typo, not a file name; so is a hyphenated word.
                 "Federation is end-to-end encrypted.It is certified.",
                 "Federation is end-to-end in encrypt-everything mode and certified.",
                 "Federation is end-to-end in Encrypt.MD mode.",
                 # One sentence is the plain text between sentence ends; e.g., i.e., etc. and the
                 # periods of v1.x or a URL do not end it.
                 "Federation content is end-to-end, e.g. across relays, encrypted and certified for v1.0.0.",
                 "Federation content is sealed, i.e. end-to-end, and certified for v1.0.0.",
                 "Federation content is end-to-end for rows, links, etc. and encrypted and certified.",
                 "End-to-end content for v1.x is encrypted and certified.",
                 "End-to-end (e.g. across relays) encrypted and certified.",
                 "Federation is end-to-end across relays, peers etc. and is encrypted and certified.",
                 "Federation is [end-to-end](docs/federation.md) encrypted and certified for v1.0.0.",
                 "Federation is end-to-end https://example.org/a.b/c encrypted and certified.",
                 # A bare word in the same sentence as a file name is still a stem.
                 "Run 01-secure-bootstrap.sh for the end-to-end demo, which is secure.",
                 # Format characters inside the term are invisible and stripped.
                 "Federation is end\u200b-to-end encrypted and certified.",
                 "Federation is end-to\u200d-end encrypted and certified.",
                 "Federation is end-\u2060to-end encrypted and certified."]
        for s in gated:
            self.assertTrue(E2E_GATE.search(s), s)
        # U+2043 is a list marker, not a word joiner: it is not a separator by decision. U+2E3A,
        # U+30FC and U+FF70 are not Latin word joiners and are not separators either.
        for s in ["Tested end-to-end in CI.", "The end-to-end suite passes.",
                  "Federation is end\u2043to\u2043end encrypted.",
                  "Federation is end\u2e3ato\u2e3aend encrypted.",
                  "Federation is end\u30fcto\u30fcend encrypted.",
                  "Federation is end\uff70to\uff70end encrypted.",
                  "Federation travels end-to-end. It is encrypted and certified.",
                  "Federation is encrypted (mTLS; end-to-end) and certified.",
                  "01-secure-bootstrap.sh is a runnable end-to-end demo.",
                  "Run scripts/secure-demo for the end-to-end demo.",
                  "See docs/encryption.html for the end-to-end demo."]:
            self.assertFalse(E2E_GATE.search(s), s)
        for s in ["End-to-end content encryption is deferred until v1.x.", "#8278 postponed to v1.x.",
                  "E2EE slipped to post-GA.", "#8278 is out of the GA scope.",
                  "#8278 is not in scope for v1.0.0.", "#8278 is deferred until v2.0.",
                  "#8278 is deferred until v1.2.", "#8278 is postponed until after GA.",
                  "#8278 is postponed until a later release.",
                  "#8278 is deferred post GA.", "#8278 is postponed to post GA.",
                  "#8278 is postponed to v10.0.", "#8278 is slipped to v1.0.1.",
                  "#8278 is postponed to the next release.", "#8278 is deferred.",
                  "Variant B is slipped to v1.1.", "Variants A and B were postponed.",
                  "#8278, E.g. variant B, slipped to v1.1.",
                  "#8278, I.E. variant B, slipped to v1.1.",
                  "#8278 was removed from the v1.0.0 GA scope.",
                  "#8278 is kept in this deferred set.", "#8278 moves to a future release.", "E2EE is pushed to v1.0.2."]:
            self.assertTrue(_underclaims(s), s)
        # Accepted boundaries: a pronoun subject, a postponement of something else, a deferred noun.
        for s in ["It is postponed to v1.1.", "Other items are postponed to v1.x.",
                  "A deferred graph projection ships beside end-to-end content encryption.",
                  "#8278 landed on release/v1.0.0 for GA."]:
            self.assertFalse(_underclaims(s), s)
        # The dated ROADMAP supersession note is a true statement, not an under-claim: exempt as the
        # whole clause, in ROADMAP.md only, and never in its negated or conjoined forms.
        note = ("(Superseded by #8278 on 2026-10-28: federation content encryption was removed "
                "from this deferred set and is in v1.0.0 GA scope. Next sentence.")
        self.assertFalse(any(_underclaims(s, ROADMAP_REL) for s in SENTENCE_SPLIT_RE.split(note)))
        self.assertTrue(_underclaims(note, "SECURITY.md"), "the exemption is ROADMAP.md only")
        for s in ["#8278 was not removed from this deferred set.",
                  "#8278 was never removed from this deferred set.",
                  "#8278 has not been removed from this deferred set.",
                  "#8278 is not removed from this deferred set.",
                  "federation content encryption was not removed from this deferred set",
                  "#8278 was removed from this deferred set and re-targeted to v1.1.",
                  "#8278 was removed from this deferred set and pushed to v1.1.",
                  "#8278 is in this deferred set.",
                  "federation content encryption was removed from this deferred set and is in "
                  "v1.0.0 GA scope, then re-targeted to v1.1.",
                  "federation content encryption was not removed from this deferred set and is "
                  "in v1.0.0 GA scope"]:
            self.assertTrue(_underclaims(s, ROADMAP_REL), s)
            self.assertTrue(_underclaims(s), s)
        # Non-predicate postponement of #8278 / variant A or B, and exclusions without "scope".
        for s in ["Status of #8278: deferred.", "| #8278 | federation content encryption | deferred |",
                  "Federation content encryption (#8278, deferred) follows GA.",
                  "The operator approved the defer" "ral of #8278.", "#8278 is not part of v1.0.0 GA.",
                  "#8278 does not ship in v1.0.0.", "#8278 is excluded from the v1.0.0 GA release.",
                  "#8278 is a v1.1 item.", "#8278 is planned for v1.1.",
                  "#8278 is no longer in the GA scope.", "#8278 is not in GA.",
                  "End-to-end content encryption is not part of v1.0.0 GA.",
                  "#8278 targets v1.1.", "#8278 is a v1.1 deliverable.",
                  "#8278 is scheduled for v1.1.", "Federation content encryption is deferred until v1.1.",
                  "Variant B is not part of v1.0.0 GA.", "#8278 is out of the GA scope.",
                  "Variants A and B are out of the GA scope.", "#8278 is deferred until v1.1."]:
            self.assertTrue(_underclaims(s), s)
        # README.md:121 style: an attributive deferred noun, no #8278 or variant, stays clean.
        self.assertFalse(_underclaims("A deferred Apache-AGE graph projection ships beside the "
                                      "end-to-end content encryption work."))
        self.assertFalse(_underclaims("The `deferred-v1.x` label was applied to #1968 in 2026."))
        for s in ["Federation content will be end-to-end encrypted at GA.",
                  "E2E at GA.", "Content is encrypted at GA.", "E2E ships with GA.",
                  "E2E ships in GA."]:
            self.assertIsNotNone(FUTURE_RE.search(s), s)
        self.assertIsNone(HISTORY_LINE_RE.match("2026-10-29: new dated line"))
        for s in ["#1968 is still unresolved.", "#1968 remains open.", "Open item #1968."]:
            self.assertIsNotNone(STALE_RE.search(s), s)

    def _statement_rows(self, sentence):
        """The sentence as a statement sentence, before the canon, after it and as a paragraph."""
        canon = _plain(E2E_CANON)
        for text in (sentence + " " + canon, canon + " " + sentence, canon + "\n\n" + sentence):
            plain = _neutral_statement(_plain(text))
            yield any(_sentence_problem(s, statement=True) for s in SENTENCE_SPLIT_RE.split(plain))

    def test_overclaims_are_keyed_on_the_scope_subjects(self):
        # Round 10 (security MEDIUM 1): #8278, variant A or B and content encryption are refused
        # with a landed, shipped, live, certified, enabled, available or encrypted predicate even
        # when no end-to-end term is present, in every file and in the statement.
        refused = ["#8278 has landed on release/v1.0.0 with its tests green.",
                   "Variants A and B are now live.",
                   "Content encryption for federation (#8278) is live.",
                   "#8278 shipped, so peers no longer store plaintext.",
                   "#8278 is merged.", "#8278 is certified.", "Variant A is complete.",
                   "Variant B is completed.", "Content encryption is done.",
                   "Content encryption is in GA.", "Content encryption is available.",
                   "Variant B is on by default.", "Content encryption is enabled by default.",
                   "Federation content encryption encrypts every row.",
                   "With #8278 peers cannot read content.", "Live: #8278.",
                   "Shipped in v1.0.0: variants A and B."]
        for s in refused:
            self.assertEqual(_sentence_problem(s), "over-claim", s)
            self.assertEqual(_sentence_problem(s, statement=True), "over-claim", s)
            self.assertTrue(all(self._statement_rows(s)), s)
        # A condition or a negation before the predicate is the true statement, not an over-claim.
        for s in ["Content encryption is not live today.", "#8278 is in v1.0.0 GA scope.",
                  "The certification is issued only when #8278 has landed on release/v1.0.0 "
                  "with its tests green.",
                  "Until #8278 lands, peers replicate and store plaintext content.",
                  "Peers are still plaintext; #8278 has not shipped."]:
            self.assertIsNone(_sentence_problem(s), s)
        # A predicate far from every subject is about something else (a measured table row).
        self.assertFalse(_overclaims("The content encryption status is stated only in the scope "
                                     "statement, which links the tracking issue and the rest of the "
                                     "audit trail, so the transport shipped plaintext."))

    def test_scope_carve_outs_are_refused_everywhere(self):
        # Round 10 (security LOW 1 = code LOW 3): a scope sentence with a carve-out is a narrowing.
        refused = ["#8278 is in v1.0.0 GA scope, except variant B.",
                   "#8278 is in v1.0.0 GA scope, but variant B is not.",
                   "Federation content encryption is in v1.0.0 GA scope for variant A only.",
                   "#8278 is in v1.0.0 GA scope, only for variant A.",
                   "#8278 is in v1.0.0 GA scope until v1.1.",
                   "#8278 is in GA scope save for variant B.",
                   "#8278 is in GA scope other than variant B.",
                   "#8278 is in GA scope apart from variant B."]
        for s in refused:
            for rel in (None, "SECURITY.md", ROADMAP_REL):
                self.assertTrue(_underclaims(s, rel), (rel, s))
            self.assertTrue(all(self._statement_rows(s)), s)
        # The ROADMAP exemption is the whole sentence: text before or after it, even a carve-out,
        # puts the sentence back into the scan.
        for tail in [", except variant B.", " for variant A only.", ", but variant B is not.",
                     " until v1.1.", ", save for variant B.", ", other than variant B."]:
            self.assertTrue(_underclaims(ROADMAP_EXEMPT + tail, ROADMAP_REL), tail)
        self.assertTrue(_underclaims("Note: " + ROADMAP_EXEMPT, ROADMAP_REL))
        self.assertFalse(_underclaims(ROADMAP_EXEMPT, ROADMAP_REL))
        self.assertFalse(_underclaims("  " + ROADMAP_EXEMPT.replace(" ", "  ") + " ", ROADMAP_REL))

    def test_underclaim_exclusion_and_scheduling_forms(self):
        # Round 10 (code LOW 2): exclusion, drop, miss and later-version wordings; a table row with
        # the subject and a later version; statement sentences with a named subject and a later one.
        refused = ["#8278 was moved out of GA.", "#8278 was dropped from GA.",
                   "#8278 was cut from v1.0.0.", "#8278 will not make GA.", "#8278 misses GA.",
                   "#8278 slips (per the operator ruling of 2026-10-28) to v1.1.",
                   "#8278 is planned, per the operator ruling, for v1.1.",
                   "| Federation end-to-end content encryption | v1.1 item |",
                   "#8278 is out of GA.", "| #8278 | v1.1 |", "| #8278 | after GA |",
                   "#8278 is expected in v1.1.", "#8278 is not expected before v1.1.",
                   "Variant B was dropped from v1.0.0.", "#8278 is pushed out of the GA release.",
                   "Variants A and B will not make v1.0.0."]
        for s in refused:
            self.assertTrue(_sentence_problem(s, statement=True), s)
        for s in refused:
            self.assertTrue(_sentence_problem(s), s)
        # Accepted: a pronoun, an unrelated later version, and the true landing sentence.
        for s in ["It will not make GA.", "Other items were dropped from v1.0.0.",
                  "#8278 landed on release/v1.0.0 for GA."]:
            self.assertFalse(_underclaims(s), s)

    def test_file_tokens_and_confusables(self):
        # Round 10 (code LOW 1): encrypted/sealed and encrypted/signed are prose alternations.
        for s in ["Federation content is end-to-end encrypted/sealed and certified for v1.0.0.",
                  "Federation content is end-to-end encrypted/signed today."]:
            self.assertTrue(E2E_GATE.search(s), s)
        for tok in ["encrypted/sealed", "encrypted/signed", "secure/ops", "sealed/signed",
                    "(encrypted/sealed)", "encrypted.It"]:
            self.assertFalse(_is_file_token(tok), tok)
        for tok in ["docs/encryption.html", "src/encryption/mod.rs", "scripts/secure-demo",
                    "src/encryption/", "01-secure-bootstrap.sh", "Cargo.toml", "README.md",
                    "(docs/encrypt.md).", "deploy/asi-hard.env", "cert-1/posture-x.out",
                    "github.com/alphaonedev/ai-memory-mcp/security", "./secure-demo",
                    "../docs/encryption.md", "/etc/secure", "tests/secure"]:
            self.assertTrue(_is_file_token(tok), tok)
        # Round 10 (security INFO): Cyrillic and Greek look-alikes are mapped to Latin once.
        cyr_o, cyr_e, grk_o = chr(0x043E), chr(0x0435), chr(0x03BF)
        for s in ["#8278 is out of the GA sc" + cyr_o + "pe.", "#8278 is d" + cyr_e + "ferred to v1.1.",
                  "Variants A and B are out of sc" + grk_o + "pe."]:
            self.assertTrue(_plain(s).isascii(), s)
            self.assertTrue(_underclaims(_plain(s)), s)
            self.assertTrue(all(self._statement_rows(s)), s)
        over = "Federation content is end-to-end encrypted and " + chr(0x0441) + "ertified."
        e2e = "Federation " + chr(0x0415) + "2" + chr(0x0415) + " is live and certified"
        for s in (over, e2e):
            self.assertTrue(E2E_GATE.search(s), s)
            self.assertTrue(any(rx.search(_plain(s)) for rx in SCOPE_REFUSED), s)
        self.assertTrue(E2E_GATE.search("Federation " + chr(0x0415) + "2" + chr(0x0415) + " is encrypted."))

    def test_term_is_spelled_once_and_covers_every_dash(self):
        src = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(src.count("end" + "[-"), 0, "a second spelling of the separator class")
        bs = "\\"
        self.assertEqual(src.count(bs + "u2010-" + bs + "u2015"), 1)
        # A narrower second class is caught too: the first dash code point is spelled once, no other
        # class opens with a hyphen and carries an escape, and the source stays ASCII.
        self.assertEqual(src.count(bs + "u2010"), 1, "a second class spells U+2010")
        self.assertEqual(len(re.findall(r"\[-[^\]]*" + bs + bs + "u[0-9A-Fa-f]{4}", src)), 1)
        self.assertTrue(src.isascii(), "a literal non-ASCII separator in the guard")
        # The stem alternation is spelled once (_STEM); a second narrower literal fails here.
        self.assertEqual(src.count("(?:encrypt" + "|"), 1, "a second stem alternation literal")
        self.assertEqual(src.count("encrypt" + "|"), 1, "a second stem alternation literal")
        self.assertEqual(src.count("|seal" + "|"), 1, "a second stem alternation literal")
        # The move and plan verbs are spelled once (_MOVE); a second narrower literal fails here.
        self.assertEqual(src.count("slip" + "|push"), 1, "a second move verb alternation literal")
        self.assertEqual(src.count("plann" + "|schedul"), 1, "a second plan verb alternation literal")
        self.assertEqual(src.count("part" + chr(92) + "s+of|in|included"), 1,
                         "a second exclusion alternation literal")
        for code in [0x2D, 0x20, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212,
                     0xFE63, 0xFF0D]:
            sep = chr(code)
            unit = "Content is end%sto%send encrypted." % (sep, sep)
            self.assertTrue(E2E_GATE.search(unit), repr(sep))
            self.assertTrue(any(rx.search(unit.replace("is end", "is certified end"))
                                for rx in SCOPE_REFUSED), repr(sep))
        self.assertTrue(E2E_GATE.search("Content is en" + SOFT_HYPHEN + "d-to-end encrypted."))

    def test_statement_neutraliser_removes_only_the_two_true_strings(self):
        canon = _plain(E2E_CANON)
        self.assertEqual(_neutral_statement("a " + canon + " b"), "a  b")
        self.assertIn(LABEL_FACT, _plain(_subsection()), "the true label sentence moved")
        self.assertEqual(_neutral_statement("x " + LABEL_FACT + " y"), "x  y")
        # A second sentence that names the label is NOT neutralised.
        second = "[#8278] carries the deferred-v1.x label and is deferred until v1.1."
        out = _neutral_statement(LABEL_FACT + " " + second)
        self.assertIn(second, out)
        self.assertTrue(any(_underclaims(s) for s in SENTENCE_SPLIT_RE.split(out)))
        # A reworded canonical paragraph is not removed either.
        self.assertIn("Variant B is deferred until v1.1.",
                      _neutral_statement(canon + " Variant B is deferred until v1.1."))
        over = "Federation content is end-to-end encrypted today."
        self.assertTrue(E2E_GATE.search(over))
        self.assertTrue(any(rx.search(over) for rx in SCOPE_REFUSED))

    def test_claim_stem_classification_is_linear(self):
        import time
        for sent in ["end-to-end " + "x/encrypt" * 22000 + ".md", "end-to-end " + "encrypt" * 30000,
                     "end-to-end " + "a.encrypt" * 22000, "encrypt " * 25000 + "end-to-end",
                     "end-to-end " * 18200]:
            t0 = time.perf_counter()
            E2E_GATE.search(sent)
            self.assertLess(time.perf_counter() - t0, 1.0, sent[:30])

    def test_underclaim_pattern_spares_the_roadmap_ruling_paragraph(self):
        units = [u for u in _units(self._scoped_text("ROADMAP.md")) if "postponed to v1.x" in u]
        self.assertTrue(units, "the ROADMAP ruling paragraph moved")
        for unit in units:
            for sent in SENTENCE_SPLIT_RE.split(_plain(unit)):
                self.assertFalse(_underclaims(sent, ROADMAP_REL), sent[:80])

    def test_in_heading_does_not_say_certified_and_cites_reissue(self):
        text = CERT.read_text(encoding="utf-8")
        self.assertNotIn(OLD_B_IN, text, "IN heading says Certified while the status is EXPIRED")
        self.assertEqual(text.count(B_IN), 1)
        self.assertIn("EXPIRED", text[:4000])

    def test_sync_since_item_names_the_operator_bypass(self):
        items = _items(_blocks()[B_IN])
        hit = [i for i in items if "`sync/since` is peer-scoped" in i]
        self.assertEqual(len(hit), 1)
        flat = _flat(hit[0])
        for pin in SYNC_SINCE_PINS:
            self.assertIn(pin, flat, "sync/since item lost: " + pin)
        self.assertLess(flat.index("AI_MEMORY_FED_SYNC_TRUST_PEER=1"), flat.index("empty envelope"),
                        "the bypass condition must precede the empty-envelope claim")


if __name__ == "__main__":
    unittest.main()
