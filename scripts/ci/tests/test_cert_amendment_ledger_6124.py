#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #6124: the rule (B) amendment ledger of scripts/check_cert_expiry.py.

THE INVARIANT (every range, every cert-doc byte content).
  1. While STATUS is EXPIRED/VOID at both ends and a section 7 watched path or an
     AI_MEMORY_FED_* identifier changed, the gate passes IFF the head doc holds one or more
     NEW dated amendment records (absent at the range start) whose names together are
     exactly the changed watched paths and identifiers. A missing name, an extra name, a
     record before the date floor or after the judged commit date, or an edited, reordered
     or removed earlier record fails with an exact reason line.
  2. The ledger is append-only: every record present at the range start is byte-identical
     at the head, in the same order (checked on every path that touches the doc).
  3. An amendment never discharges the certification: STATUS stays EXPIRED/VOID and LIVE
     behaviour is unchanged.
  4. While STATUS stays EXPIRED/VOID, setting or changing the bound SHA is refused;
     dropping it stays a voiding record (#6774 option B, narrowed).
  5. Anything the parser does not positively recognise in or around the ledger region is a
     refusal with a line number (fail closed), never a pass or a crash; an unreadable git
     object is a refusal.

Every case builds its own scratch repository under .local-runs/ (never /tmp). The
hostile table runs each construct through the whole gate (check_change) and asserts
rc 1 and the exact reason line.
"""
import datetime
import importlib.util
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[3]
GATE_PATH = HARNESS_ROOT / "scripts" / "check_cert_expiry.py"
SCRATCH_ROOT = HARNESS_ROOT / ".local-runs"
SCRATCH_PREFIX = "cert-amendment-6124."
CERT_REL = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
MARKER = "## Amendment ledger (rule B, append-only)"
GATE_PREFIX = "check-cert-expiry"
MOD_RS = "src/federation/mod.rs"
PEER_RS = "src/federation/peer.rs"
RECV_RS = "src/handlers/federation_receive.rs"
SIGN_RS = "src/handlers/federation_signing_check.rs"
CONFIG_RS = "src/config.rs"
UNRELATED_RS = "src/unrelated.rs"
LIVE_ID = "AI_MEMORY_FED_REQUIRE_SIG"
NEW_ID = "AI_MEMORY_FED_NEW_KNOB"
DAY = "2026-11-13"
LATER_DAY = "2026-11-14"
BEFORE_FLOOR_DAY = "2026-11-12"
FUTURE_DAY = "2099-01-01"
DOC_LIMIT_BYTES = 8 * 1024 * 1024
LINE_LIMIT_BYTES = 256
PARSE_BOUND_S = 5.0
BIG_LEDGER_LINES = 100_000
BIG_LINE_BYTES = 10 * 1024 * 1024
LONG_LINE_BYTES = 1024 * 1024
GENERATIVE_SEED = 6124
GENERATIVE_ROUNDS = 300
GIT_TIMEOUT_S = 60
# F6: every scratch commit carries this fixed date unless a case overrides it, and the
# gate's clock (cert.utc_today) is pinned to RUNNER_TODAY, so no row reads the wall clock.
FIXED_GIT_DATE = "2026-11-13T12:00:00+00:00"
RUNNER_TODAY = datetime.date(2026, 11, 13)
NAME_POOL = (f"- id: {LIVE_ID}", f"- id: {NEW_ID}", f"- path: {MOD_RS}", f"- path: {PEER_RS}",
             f"- path: {RECV_RS}", f"- path: {SIGN_RS}")
# Lines that are invalid in EVERY ledger parser state, so an injected one must be refused
# at exactly its own line number.
ALWAYS_BAD_LINES = (
    "garbage", "  ", "<!-- hidden -->", "[ref]: https://example.invalid", "```", "~~~",
    "> - path: src/federation/mod.rs", "#### Amendment 2026-11-13", "### amendment 2026-11-13",
    "- id: ai_memory_fed_lower", "- path: src/federation/mod.rs ", "- path: src/unrelated.rs",
    "### Amendment 2026-13-01", " ", "\x0c", "​", " ", "‮", "***",
    "- path:  src/federation/mod.rs", "    - path: src/federation/mod.rs", "===", "---",
)
# #6124 round 1 (NOTICE-FIX-9274-r1). Literal texts, never read from the gate, so a gate
# that lacks them fails on the assertion and not on an AttributeError.
ITEM_ORDER = "'- id:' lines before '- path:' lines, each group in ascending byte order, no duplicates"
PATH_RESTRICTION = ("A '- path:' item names one section 7 watched path spelled in printable ASCII "
                    "with no space; a watched path outside that form cannot be named and needs a "
                    "re-issue.")
STATUS_LINE_NO = 7
BIND_LINE_NO = 5
FROZEN_LINE = (
    f"{GATE_PREFIX}: ERROR — the STATUS line at {CERT_REL}:{STATUS_LINE_NO} is frozen while the "
    "certification is not LIVE: on an amendment pass it must be byte-identical to the range "
    "start (only the status word may change, between VOID and EXPIRED); put the reason for the "
    "change in the amendment ledger record (#6124, 3-agent vote 71472661) (fail-closed)")
DUPLICATE_3556 = ("has two or more STATUS banner lines; the gate reads exactly one and will not "
                  "guess which is the banner")
UNPARSEABLE_3556 = "has no parseable STATUS line"
BINDS_DUPLICATE_3556 = ("has two or more Binds-to lines; the gate reads exactly one and will not "
                        "guess which SHA the LIVE claim binds to")
MALFORMED_3556 = ("does not carry exactly one STATUS banner line and at most one Binds-to line "
                  "(parsed: {parsed})")
STRICT_STATUS_SECOND = "a second STATUS line under the strict grammar"
STRICT_BINDS_SECOND = "a second Binds-to line under the strict grammar"
LOOSE_STATUS = "a STATUS-like line the strict grammar does not read"
LOOSE_BINDS = "a Binds-like line the strict grammar does not read"
NO_STRICT_STATUS = "no STATUS line under the strict grammar"
PRE_LINE_LIMIT_BYTES = 4096
# B-3 / B-5: the five probed status strings, each refused as malformed (never read as VOID).
PROBED_STATUS = ("**VOIDED as of", "**VOID-LIVE as of", "**void as of", "**VOIDLIVE as of",
                 "**VOID (LIVE re-issued) as of")
HOMOGLYPH_E = "Ε"  # GREEK CAPITAL LETTER EPSILON, looks like E
HOMOGLYPH_O = "Ο"  # GREEK CAPITAL LETTER OMICRON, looks like O
ZERO_WIDTH = "​"
PRE_REGION_LINES = (10_000, 100_000, 1_000_000)
BIG_BINDS_BYTES = 100_000
BIG_EMPHASIS_LINES = 100_000
FAST_BOUND_S = 1.0
OVER_CAP_PAD = 9 * 1024 * 1024


def _load_gate():
    spec = importlib.util.spec_from_file_location("cert_expiry_gate_6124", str(GATE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["cert_expiry_gate_6124"] = module
    spec.loader.exec_module(module)
    return module


cert = _load_gate()


def head_doc(status="VOID", binds=None, status_suffix=""):
    """The cert doc in the real shape: SPDX comment on line 1, a quoted STATUS banner,
    a fenced block, prose quoting the word Amendment, and a closing GFM table."""
    bind_line = (f"**Binds to:** `{binds}` (fixture bind)" if binds
                 else "The certification is bound to no commit (voided).")
    lines = [
        "<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->",
        "",
        "# Enterprise federation certification (fixture)",
        "",
        bind_line,
        "",
        f"> ## STATUS — **{status} as of 2026-01-01**{status_suffix}",
        "> The certification makes no live claim; `<id>.pub` stays quoted.",
        "",
        "```rust",
        "example <code> block",
        "```",
        "",
        "> Amendment (2026-08-29, history). Quoted prose, not a record.",
        "",
        "| caveat | disposition |",
        "|---|---|",
        "| F1 | closed |",
        "",
    ]
    return "\n".join(lines) + "\n"


def record(date, *items):
    return f"\n### Amendment {date}\n\n" + "".join(f"{item}\n" for item in items)


def path_item(rel):
    return f"- path: {rel}"


def id_item(ident):
    return f"- id: {ident}"


def with_ledger(doc, *records, pre=""):
    return doc + pre + MARKER + "\n" + "".join(records)


def line_no(text, exact):
    for index, line in enumerate(text.split("\n"), 1):
        if line == exact:
            return index
    raise AssertionError(f"line {exact!r} not in the fixture")


def line_no_last(text, exact, before):
    """1-based number of the last line equal to EXACT above the line equal to BEFORE."""
    lines = text.split("\n")
    stop = lines.index(before)
    return max(i for i in range(stop) if lines[i] == exact) + 1


def ledger_error(text):
    """(reason, line) of the head-side LedgerError the parser raises, or None."""
    try:
        cert.parse_ledger(text.encode("utf-8") if isinstance(text, str) else text, "head")
    except cert.LedgerError as exc:
        return exc.reason, exc.line
    return None


def reason_line(reason, line=None, side="head"):
    where = f"at {CERT_REL}:{line}" if line else f"in {CERT_REL}"
    return f"{GATE_PREFIX}: ERROR — amendment ledger ({side}): {reason} {where} (fail-closed)"


def banner_line(reason, line=None, side="head"):
    """The first line of an I1 (clean-banner precondition) refusal."""
    where = f"at {CERT_REL}:{line}" if line else f"in {CERT_REL}"
    return f"{GATE_PREFIX}: ERROR — banner ({side}): {reason} {where} (fail-closed)"


def nth_line_no(text, exact, nth):
    """1-based number of the NTH (1-based) line equal to EXACT."""
    hits = [i for i, line in enumerate(text.split("\n"), 1) if line == exact]
    if len(hits) < nth:
        raise AssertionError(f"line {exact!r} occurs {len(hits)} times, wanted {nth}")
    return hits[nth - 1]


def status_line(status="VOID", suffix=""):
    return f"> ## STATUS — **{status} as of 2026-01-01**{suffix}"


def bind_line(sha):
    return f"**Binds to:** `{sha}` (fixture bind)"


NO_BIND_LINE = "The certification is bound to no commit (voided)."


def dup_status_doc(status="VOID", binds=None, second="VOID"):
    """head_doc with a second strict STATUS line appended after the table (DUPLICATE)."""
    return head_doc(status, binds) + "\n" + status_line(second) + "\n"


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["HOME"] = str(SCRATCH_ROOT)
    env["GIT_AUTHOR_DATE"] = FIXED_GIT_DATE
    env["GIT_COMMITTER_DATE"] = FIXED_GIT_DATE
    return env


class Scene:
    """A private repository: `genesis` (sources, one FED id), then `base` (the cert doc
    with the given STATUS and bind and no ledger)."""

    def __init__(self, root, status="VOID", bind_genesis=False, base_doc=None):
        self.repo = Path(tempfile.mkdtemp(prefix="repo.", dir=str(root)))
        self.g("init", "-q", "-b", "main")
        self.g("config", "user.name", "Cert Amendment Test")
        self.g("config", "user.email", "amendment-test@localhost")
        self.g("config", "commit.gpgsign", "false")
        self.genesis = self.commit({
            MOD_RS: "fn federation_mod() {}\n", PEER_RS: "fn peer() {}\n",
            RECV_RS: "fn receive() {}\n", SIGN_RS: "fn signing_check() {}\n",
            CONFIG_RS: f'pub const X: &str = "{LIVE_ID}";\n', UNRELATED_RS: "fn other() {}\n",
        }, "genesis")
        self.status = status
        self.binds = self.genesis if bind_genesis else None
        self.doc = head_doc(status, self.binds)
        if base_doc is not None:
            self.doc = base_doc(self) if callable(base_doc) else base_doc
        self.base = self.commit({CERT_REL: self.doc}, "base: certification banner")

    def g(self, *args, date=None):
        env = git_env()
        if date is not None:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
        proc = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True,
                              env=env, timeout=GIT_TIMEOUT_S, check=False)
        if proc.returncode != 0:
            raise AssertionError(f"git {args} failed: {proc.stderr.decode('utf-8', 'replace')}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def write(self, rel, content):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    def commit(self, files, msg, date=None):
        for rel, content in files.items():
            self.write(rel, content)
        self.g("add", "--", *files)
        self.g("commit", "-q", "-m", msg, date=date)
        return self.g("rev-parse", "HEAD")

    def touch_wire(self, rel=MOD_RS, note="wire change"):
        return {rel: (self.repo / rel).read_text(encoding="utf-8") + f"// {note}\n"}

    def judge(self, head, base=None):
        return cert.check_change(self.repo, base or self.base, head)


class LedgerCase(unittest.TestCase):
    def setUp(self):
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=str(SCRATCH_ROOT)))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        # F6: the gate's clock is pinned. Tolerant of a gate without utc_today (the base),
        # so a red row fails on its assertion, not on an AttributeError in setUp.
        if hasattr(cert, "utc_today"):
            clock = cert.utc_today
            self.addCleanup(setattr, cert, "utc_today", clock)
        else:
            self.addCleanup(lambda: hasattr(cert, "utc_today") and delattr(cert, "utc_today"))
        cert.utc_today = lambda: RUNNER_TODAY

    def scene(self, status="VOID", bind_genesis=False, base_doc=None):
        return Scene(self.tmp, status, bind_genesis, base_doc)

    def wire_and_doc(self, s, doc, *wire):
        files = {}
        for rel in wire or (MOD_RS,):
            files.update(s.touch_wire(rel))
        files[CERT_REL] = doc
        return s.commit(files, "change under test")

    def assert_banner_refused(self, ok, out, reason, line, side, text, parsed):
        """I1: the exact first line, the #3556 text for the side, then the malformed line."""
        self.assertFalse(ok, out)
        lines = out.split("\n")
        self.assertEqual(lines[0], banner_line(reason, line, side), out)
        where = "HEAD" if side == "head" else "the range start"
        self.assertIn(f"{CERT_REL} at {where} {text}", out)
        self.assertIn(f"The cert doc at {where} " + MALFORMED_3556.format(parsed=parsed), out)
        self.assertNotIn("a new amendment record names every change", out)

    def assert_pass(self, ok, out, *needles):
        self.assertTrue(ok, out)
        for needle in needles:
            self.assertIn(needle, out)

    def assert_refused(self, ok, out, exact_line):
        self.assertFalse(ok, out)
        self.assertIn(exact_line, out.split("\n"), out)


class HonestAmendment(LedgerCase):
    def test_void_to_void_honest_amendment_passes(self):
        s = self.scene("VOID")
        files = s.touch_wire()
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
        head = s.commit(files, "wire change + amendment")
        ok, out = s.judge(head)
        self.assert_pass(ok, out, "a new amendment record names every change",
                         "the certification stays VOID")
        self.assertEqual(cert.cert_banner(s.repo, head), ("VOID", "-"))

    def test_expired_to_expired_honest_amendment_passes(self):
        s = self.scene("EXPIRED", bind_genesis=True)
        files = s.touch_wire(RECV_RS)
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(RECV_RS)))
        head = s.commit(files, "wire change + amendment")
        ok, out = s.judge(head)
        self.assert_pass(ok, out, "the certification stays EXPIRED")
        self.assertEqual(cert.cert_banner(s.repo, head), ("EXPIRED", s.genesis))

    def test_identifier_add_and_rename_named_passes(self):
        s = self.scene("VOID")
        files = {CONFIG_RS: f'pub const X: &str = "{NEW_ID}";\n'}
        files[CERT_REL] = with_ledger(s.doc, record(DAY, id_item(NEW_ID), id_item(LIVE_ID)))
        ok, out = s.judge(s.commit(files, "rename an id + amendment"))
        self.assert_pass(ok, out, "a new amendment record names every change")

    def test_second_amendment_appends(self):
        s = self.scene("VOID")
        files = s.touch_wire()
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
        first = s.commit(files, "first amendment")
        files = s.touch_wire(PEER_RS)
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)),
                                      record(LATER_DAY, path_item(PEER_RS)))
        ok, out = s.judge(s.commit(files, "second amendment"), base=first)
        self.assert_pass(ok, out, "a new amendment record names every change")

    def test_two_new_records_may_name_the_same_path(self):
        # #6422: a promotion carries two honest records; the union is what must match.
        s = self.scene("VOID")
        files = s.touch_wire()
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)),
                                      record(DAY, path_item(MOD_RS), path_item(PEER_RS)))
        files.update(s.touch_wire(PEER_RS))
        ok, out = s.judge(s.commit(files, "two records"))
        self.assert_pass(ok, out, "a new amendment record names every change")

    def test_drop_bind_while_expired_is_refused(self):
        # I3 (#6124 round 1): while both ends are EXPIRED/VOID the bind never changes, a
        # drop to "-" included; the drop is no longer a voiding record.
        s = self.scene("EXPIRED", bind_genesis=True)
        files = s.touch_wire()
        files[CERT_REL] = head_doc("EXPIRED", None)
        ok, out = s.judge(s.commit(files, "drop the bind"))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n")[0], (
            f"{GATE_PREFIX}: ERROR — Binds-to dropped ({s.genesis} → -) while STATUS stays "
            "EXPIRED: an amendment never rebinds; re-issue as LIVE (#6774 option B narrowed) "
            "(fail-closed)"), out)

    def test_live_reissue_unchanged(self):
        s = self.scene("LIVE", bind_genesis=True)
        wire = s.commit(s.touch_wire(), "wire change")
        head = s.commit({CERT_REL: head_doc("LIVE", wire)}, "re-issue at the wire change")
        ok, out = s.judge(head)
        self.assert_pass(ok, out, "cert doc re-issued/voided", f"banner LIVE bound to {wire}")

    def test_committed_cert_doc_carries_a_valid_ledger(self):
        blob = (HARNESS_ROOT / CERT_REL).read_bytes()
        self.assertTrue(cert.ledger_present(blob))
        self.assertIsInstance(cert.parse_ledger(blob, "head"), list)


class RefusedAmendment(LedgerCase):
    def test_void_without_amendment_still_fails(self):
        s = self.scene("VOID")
        ok, out = s.judge(self.wire_and_doc(s, s.doc + "An incidental prose edit.\n"))
        self.assertFalse(ok, out)
        self.assertIn("an incidental edit is not a re-issue and not a voiding record", out)
        self.assertIn("No new dated amendment record names this change", out)

    def test_missing_name_fails(self):
        s = self.scene("VOID")
        head = self.wire_and_doc(s, with_ledger(s.doc, record(DAY, path_item(MOD_RS))),
                                 MOD_RS, RECV_RS)
        ok, out = s.judge(head)
        self.assert_refused(ok, out, reason_line(f"the new amendment records do not name changed {RECV_RS}"))

    def test_missing_identifier_fails(self):
        s = self.scene("VOID")
        files = {CONFIG_RS: f'pub const X: &str = "{LIVE_ID}";\npub const Y: &str = "{NEW_ID}";\n'}
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
        files.update(s.touch_wire())
        ok, out = s.judge(s.commit(files, "id add, unnamed"))
        self.assert_refused(ok, out, reason_line(f"the new amendment records do not name changed {NEW_ID}"))

    def test_extra_name_fails(self):
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS), path_item(RECV_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_refused(ok, out, reason_line(
            f"a new amendment record names {RECV_RS}, which this change did not touch"))

    def test_doc_only_new_record_fails(self):
        s = self.scene("VOID")
        head = s.commit({CERT_REL: with_ledger(s.doc, record(DAY, path_item(MOD_RS)))}, "doc only")
        ok, out = s.judge(head)
        self.assert_refused(ok, out, reason_line(
            f"a new amendment record names {MOD_RS}, which this change did not touch"))

    def first_record(self, s):
        files = s.touch_wire()
        files[CERT_REL] = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
        return s.commit(files, "first amendment")

    def test_edited_earlier_record_fails(self):
        s = self.scene("VOID")
        first = self.first_record(s)
        doc = with_ledger(s.doc, record(LATER_DAY, path_item(MOD_RS)),
                          record(LATER_DAY, path_item(PEER_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc, PEER_RS), base=first)
        self.assert_refused(ok, out, reason_line(
            f"record 1 of the base ledger (### Amendment {DAY}) is edited, reordered or removed",
            line_no(with_ledger(s.doc, record(DAY, path_item(MOD_RS))), f"### Amendment {DAY}")))

    def test_removed_earlier_record_fails(self):
        s = self.scene("VOID")
        first = self.first_record(s)
        doc = with_ledger(s.doc, record(LATER_DAY, path_item(PEER_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc, PEER_RS), base=first)
        self.assert_refused(ok, out, reason_line(
            f"record 1 of the base ledger (### Amendment {DAY}) is edited, reordered or removed",
            line_no(with_ledger(s.doc, record(DAY, path_item(MOD_RS))), f"### Amendment {DAY}")))

    def test_record_inserted_before_earlier_record_fails(self):
        s = self.scene("VOID")
        first = self.first_record(s)
        doc = with_ledger(s.doc, record(DAY, path_item(PEER_RS)), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc, PEER_RS), base=first)
        self.assert_refused(ok, out, reason_line(
            f"record 1 of the base ledger (### Amendment {DAY}) is edited, reordered or removed",
            line_no(with_ledger(s.doc, record(DAY, path_item(MOD_RS))), f"### Amendment {DAY}")))

    def test_ledger_removed_at_head_fails(self):
        s = self.scene("VOID")
        first = self.first_record(s)
        ok, out = s.judge(self.wire_and_doc(s, s.doc + "Ledger dropped.\n", PEER_RS), base=first)
        self.assert_refused(ok, out, reason_line("the ledger present at the range start is missing"))

    def test_doc_only_edit_of_earlier_record_fails(self):
        # #6423 / #6726: append-only holds on the doc-only path too.
        s = self.scene("VOID")
        first = self.first_record(s)
        head = s.commit({CERT_REL: with_ledger(s.doc, record(LATER_DAY, path_item(MOD_RS)))}, "edit")
        ok, out = s.judge(head, base=first)
        self.assert_refused(ok, out, reason_line(
            f"record 1 of the base ledger (### Amendment {DAY}) is edited, reordered or removed",
            line_no(with_ledger(s.doc, record(DAY, path_item(MOD_RS))), f"### Amendment {DAY}")))

    def test_future_dated_record_fails(self):
        # L-1: the ceiling is the runner's UTC date, never the author-set commit date.
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(FUTURE_DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_refused(ok, out, reason_line(
            f"record dated {FUTURE_DAY} is after the runner's UTC date {RUNNER_TODAY.isoformat()} "
            "plus 1 day", line_no(doc, f"### Amendment {FUTURE_DAY}")))

    def test_future_dated_record_with_future_commit_date_fails(self):
        # L-1: a 2099 record under a 2099 commit date is still refused by the runner clock.
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(FUTURE_DAY, path_item(MOD_RS)))
        files = s.touch_wire()
        files[CERT_REL] = doc
        head = s.commit(files, "future-dated commit", date=f"{FUTURE_DAY}T12:00:00+00:00")
        ok, out = s.judge(head)
        self.assert_refused(ok, out, reason_line(
            f"record dated {FUTURE_DAY} is after the runner's UTC date {RUNNER_TODAY.isoformat()} "
            "plus 1 day", line_no(doc, f"### Amendment {FUTURE_DAY}")))

    def test_record_dated_before_the_previous_record_fails(self):
        # L-1: record dates never decrease.
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(LATER_DAY, path_item(MOD_RS)), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_refused(ok, out, reason_line(
            f"record dated {DAY} is before the previous record dated {LATER_DAY}; record dates "
            "must not decrease", line_no(doc, f"### Amendment {DAY}")))

    def test_same_day_records_pass(self):
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), record(DAY, path_item(PEER_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc, MOD_RS, PEER_RS))
        self.assert_pass(ok, out, "a new amendment record names every change",
                         "the certification stays VOID")

    def test_before_floor_record_fails(self):
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(BEFORE_FLOOR_DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_refused(ok, out, reason_line(
            f"date {BEFORE_FLOOR_DAY} is before the ledger floor {DAY}",
            line_no(doc, f"### Amendment {BEFORE_FLOOR_DAY}")))

    def test_rebind_set_while_void_refused(self):
        s = self.scene("VOID")
        doc = with_ledger(head_doc("VOID", s.genesis), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n")[0], (
            f"{GATE_PREFIX}: ERROR — Binds-to set (- → {s.genesis}) while STATUS stays VOID: an "
            "amendment never rebinds; re-issue as LIVE (#6774 option B narrowed) (fail-closed)"), out)

    def test_rebind_change_while_expired_refused(self):
        s = self.scene("EXPIRED", bind_genesis=True)
        wire = s.commit(s.touch_wire(), "wire change")
        head = s.commit({CERT_REL: head_doc("EXPIRED", wire)}, "rebind while EXPIRED")
        ok, out = s.judge(head)
        self.assertFalse(ok, out)
        self.assertIn(f"{GATE_PREFIX}: ERROR — Binds-to changed ({s.genesis} → {wire}) while "
                      "STATUS stays EXPIRED", out)

    def test_doc_only_rebind_while_void_refused(self):
        s = self.scene("VOID")
        ok, out = s.judge(s.commit({CERT_REL: head_doc("VOID", s.genesis)}, "doc-only rebind"))
        self.assertFalse(ok, out)
        self.assertIn("while STATUS stays VOID", out)

    def test_revoiding_status_prose_with_exact_record_is_refused(self):
        # The #9176 shape under the v9274-status vote (B-1, B-4): the STATUS prose is
        # rewritten with the word kept; the line is frozen while not LIVE, so even an exact
        # amendment record is refused and the reason belongs in the record.
        s = self.scene("VOID")
        doc = with_ledger(head_doc("VOID", None, " (amended)"), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n"), [FROZEN_LINE], out)

    def test_revoiding_status_prose_without_record_fails(self):
        s = self.scene("VOID")
        ok, out = s.judge(self.wire_and_doc(s, head_doc("VOID", None, " (amended)")))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n"), [FROZEN_LINE], out)

    def test_status_change_with_inexact_record_fails(self):
        s = self.scene("LIVE", bind_genesis=True)
        doc = with_ledger(head_doc("VOID", None), record(DAY, path_item(PEER_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertIn(reason_line(f"the new amendment records do not name changed {MOD_RS}"),
                      out.split("\n"))

    def test_malformed_base_ledger_refused(self):
        s = self.scene("VOID")
        bad = with_ledger(s.doc, "\n### Amendment 2026-11-13\n- path: src/federation/mod.rs\n")
        broken = s.commit({CERT_REL: bad}, "malformed ledger lands on the base")
        files = s.touch_wire()
        files[CERT_REL] = bad + "\n### Amendment 2026-11-13\n\n- path: src/federation/mod.rs\n"
        ok, out = s.judge(s.commit(files, "append"), base=broken)
        self.assert_refused(ok, out, reason_line("expected a blank line",
                                                 line_no(bad, "- path: src/federation/mod.rs"),
                                                 side="base"))

    def test_unreadable_cert_blob_refused(self):
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
        head = self.wire_and_doc(s, doc)
        blob = s.g("rev-parse", f"{head}:{CERT_REL}")
        (s.repo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
        ok, out = s.judge(head)
        self.assertFalse(ok, out)
        self.assertIn("(fail-closed)", out)

    def test_unreadable_cert_tree_refused(self):
        # The doc's directory object is unreadable while the diff never needs it (same
        # tree at both ends): the banner read must refuse, never read the doc as absent.
        s = self.scene("VOID")
        head = s.commit({"README.md": "unrelated\n"}, "unrelated change")
        tree = s.g("rev-parse", f"{head}:docs/compliance")
        (s.repo / ".git" / "objects" / tree[:2] / tree[2:]).unlink()
        ok, out = s.judge(head)
        self.assertFalse(ok, out)
        self.assertIn(f"{GATE_PREFIX}: ERROR — git ls-tree", out)
        self.assertIn("(fail-closed)", out)

    def test_live_with_exact_record_still_expires(self):
        # LIVE behaviour is unchanged: an exact amendment never passes a LIVE banner.
        s = self.scene("LIVE", bind_genesis=True)
        ok, out = s.judge(self.wire_and_doc(s, with_ledger(s.doc, record(DAY, path_item(MOD_RS)))))
        self.assertFalse(ok, out)
        self.assertIn(cert.EXPIRY_SENTENCE, out)
        self.assertNotIn("a new amendment record names every change", out)

    def test_duplicate_binds_with_exact_record_refused(self):
        # A malformed banner (two Binds-to lines) is never an amendment pass.
        s = self.scene("VOID")
        bind = bind_line(s.genesis)
        assert NO_BIND_LINE in s.doc
        doc = with_ledger(s.doc.replace(NO_BIND_LINE, f"{bind}\n\n{bind}"),
                          record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_banner_refused(ok, out, STRICT_BINDS_SECOND, nth_line_no(doc, bind, 2),
                                   "head", BINDS_DUPLICATE_3556, "VOID DUPLICATE")


def hostile_rows():
    """(name, head doc text or bytes, exact reason, line or None). Every head adds an
    otherwise honest record for the MOD_RS wire change."""
    base = head_doc("VOID")
    honest = record(DAY, path_item(MOD_RS))
    rows = []

    def pre(name, block, reason, needle):
        doc = with_ledger(base, honest, pre=block)
        rows.append((name, doc, reason, line_no(doc, needle) if needle else None))

    pre("fence_open", "```text\nhidden\n\n", "a fence opened here is still open at the ledger marker", "```text")
    pre("tilde_fence_open", "~~~~\nhidden\n\n", "a fence opened here is still open at the ledger marker", "~~~~")
    pre("longer_closer_needed", "````\n```\n\n", "a fence opened here is still open at the ledger marker", "````")
    pre("other_char_closer", "```txt\n~~~\n\n", "a fence opened here is still open at the ledger marker", "```txt")
    pre("closer_with_info", "~~~~~\n~~~~~ x\n\n", "a fence opened here is still open at the ledger marker", "~~~~~")
    pre("list_item_fence", "- ```\n  hidden\n\n", "a fence-like line inside a container or indented is not supported", "- ```")
    pre("indented_fence", "   ```\n\n", "a fence-like line inside a container or indented is not supported", "   ```")
    pre("indented_code_fence", "    ```\n\n", "a fence-like line inside a container or indented is not supported", "    ```")
    pre("quoted_fence", "> ```\n\n", "a fence-like line inside a container or indented is not supported", "> ```")
    pre("nested_quote_list_fence", "> - > ~~~\n\n", "a fence-like line inside a container or indented is not supported", "> - > ~~~")
    pre("backtick_info_string", "```a`b\n\n", "a fence opener with a backtick in its info string is not supported", "```a`b")
    pre("html_comment_open", "<!-- open\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<!-- open")
    pre("html_details", "<details>\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<details>")
    pre("html_pre", "<pre>\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<pre>")
    pre("html_processing", "<?php\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<?php")
    pre("html_declaration", "<!DOCTYPE x\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<!DOCTYPE x")
    pre("html_cdata", "<![CDATA[\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "<![CDATA[")
    pre("html_close_tag", "</div>\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "</div>")
    pre("html_in_list_item", "- <details>\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "- <details>")
    pre("html_in_quote", "> <script>\n\n", "an HTML block start is not supported (only a one-line <!-- ... --> comment)", "> <script>")
    pre("lookalike_marker_case", "## amendment ledger (rule b, append-only)\n\n", "a heading-like line naming an amendment outside the ledger", "## amendment ledger (rule b, append-only)")
    pre("lookalike_record", "### Amendment 2026-11-13\n\n", "a heading-like line naming an amendment outside the ledger", "### Amendment 2026-11-13")
    pre("lookalike_nbsp_record", "### Amendment 2026-11-13\n\n", "a heading-like line naming an amendment outside the ledger", "### Amendment 2026-11-13")
    pre("lookalike_quoted_record", "> ### Amendment 2026-11-13\n\n", "a heading-like line naming an amendment outside the ledger", "> ### Amendment 2026-11-13")
    pre("lookalike_indented_record", "    ### Amendment 2026-11-13\n\n", "a heading-like line naming an amendment outside the ledger", "    ### Amendment 2026-11-13")

    def char(name, ch, cat):
        doc = with_ledger(base, honest, pre=f"prose {ch} here\n\n")
        rows.append((name, doc, f"forbidden character U+{ord(ch):04X} ({cat})", line_no(doc, f"prose {ch} here")))

    char("bare_cr", "\r", "Cc")
    char("nul", "\x00", "Cc")
    char("form_feed", "\x0c", "Cc")
    char("tab", "\t", "Cc")
    char("next_line", "\x85", "Cc")
    char("line_separator", " ", "Zl")
    char("paragraph_separator", " ", "Zp")
    char("zero_width_space", "​", "Cf")
    char("bidi_override", "‮", "Cf")
    char("bom", "﻿", "Cf")
    char("private_use", "", "Co")
    char("unassigned", "͸", "Cn")

    def region(name, ledger, reason, needle, offset=0):
        doc = with_ledger(base, ledger)
        if needle is None:
            # The last line of the document (a trailing blank), counted from the end.
            where = len(doc.split("\n")) - 1
        else:
            where = line_no(doc, needle) + offset
        rows.append((name, doc, reason, where))

    region("setext_under_heading", f"\n### Amendment {DAY}\n===\n", "expected a blank line", "===")
    region("link_reference_definition", f"\n### Amendment {DAY}\n\n[x]: https://example.invalid\n",
           "expected an item line '- id: AI_MEMORY_FED_*' or '- path: <watched path>'", "[x]: https://example.invalid")
    region("html_comment_in_region", "\n<!-- x -->\n", "expected '### Amendment YYYY-MM-DD'", "<!-- x -->")
    region("nbsp_in_region", f"\n### Amendment {DAY}\n\n- path: {MOD_RS}\n",
           "character outside printable ASCII in the ledger", f"- path: {MOD_RS}")
    region("quoted_record", f"\n> ### Amendment {DAY}\n", "expected '### Amendment YYYY-MM-DD'", f"> ### Amendment {DAY}")
    region("heading_trailing_text", f"\n### Amendment {DAY} closing #\n\n- path: {MOD_RS}\n",
           "expected '### Amendment YYYY-MM-DD'", f"### Amendment {DAY} closing #")
    region("no_blank_after_marker",f"### Amendment {DAY}\n\n- path: {MOD_RS}\n", "expected a blank line", f"### Amendment {DAY}")
    region("no_blank_after_heading", f"\n### Amendment {DAY}\n- path: {MOD_RS}\n", "expected a blank line", f"- path: {MOD_RS}")
    region("bad_calendar_date", f"\n### Amendment 2026-02-30\n\n- path: {MOD_RS}\n", "date 2026-02-30 is not a calendar date", "### Amendment 2026-02-30")
    region("unsorted_items", f"\n### Amendment {DAY}\n\n- path: {PEER_RS}\n- path: {MOD_RS}\n",
           f"item lines must be sorted and unique ({ITEM_ORDER}; this line is not after the previous one)", f"- path: {MOD_RS}")
    region("duplicate_items", f"\n### Amendment {DAY}\n\n- path: {MOD_RS}\n- path: {MOD_RS}\n",
           f"item lines must be sorted and unique ({ITEM_ORDER}; this line is not after the previous one)",
           f"- path: {MOD_RS}", offset=1)
    region("unwatched_path", f"\n### Amendment {DAY}\n\n- path: {UNRELATED_RS}\n",
           f"path {UNRELATED_RS} is not a section 7 watched path", f"- path: {UNRELATED_RS}")
    region("lowercase_id", f"\n### Amendment {DAY}\n\n- id: ai_memory_fed_x\n",
           "expected an item line '- id: AI_MEMORY_FED_*' or '- path: <watched path>'", "- id: ai_memory_fed_x")
    region("trailing_space", f"\n### Amendment {DAY}\n\n- path: {MOD_RS} \n",
           "expected an item line '- id: AI_MEMORY_FED_*' or '- path: <watched path>'", f"- path: {MOD_RS} ")
    region("trailing_blank_line", f"\n### Amendment {DAY}\n\n- path: {MOD_RS}\n\n",
           "trailing blank line at the end of the ledger", None)
    region("heading_without_items", f"\n### Amendment {DAY}\n\n", "the record is incomplete at the end of the file",
           f"### Amendment {DAY}")
    region("long_line", f"\n### Amendment {DAY}\n\n- path: src/federation/{'a' * LINE_LIMIT_BYTES}.rs\n",
           f"line longer than {LINE_LIMIT_BYTES} bytes", f"- path: src/federation/{'a' * LINE_LIMIT_BYTES}.rs")

    twice = with_ledger(base, honest) + "\n" + MARKER + "\n"
    rows.append(("marker_twice", twice, "the ledger marker line appears 2 times, expected exactly once", None))
    inside = base + "```\n\n" + MARKER + "\n\n```\n"
    rows.append(("marker_inside_fence", inside, "a fence opened here is still open at the ledger marker",
                 line_no_last(inside, "```", MARKER)))
    glued = base.rstrip("\n") + "\n" + MARKER + "\n" + honest
    rows.append(("marker_without_blank_above", glued, "the ledger marker must follow a blank line", line_no(glued, MARKER)))
    lookalike = with_ledger(base, honest).replace(MARKER, MARKER.replace("append-only", "append only"))
    rows.append(("marker_lookalike_over_records", lookalike,
                 "the ledger marker line appears 0 times, expected exactly once", None))
    front = "---\n" + with_ledger(base, honest)
    rows.append(("yaml_front_matter", front, "front matter on line 1 is not supported", 1))
    toml = "+++\n" + with_ledger(base, honest)
    rows.append(("toml_front_matter", toml, "front matter on line 1 is not supported", 1))
    no_status = with_ledger(base.replace("> ## STATUS — **VOID as of 2026-01-01**", "> Status prose."), honest)
    rows.append(("status_missing", no_status, "the STATUS banner must appear exactly once, above the ledger (found 0)", None))
    rows.append(("no_final_line_feed", with_ledger(base, honest).rstrip("\n"), "the document does not end with a line feed", None))
    bad_utf8 = with_ledger(base, honest).encode("utf-8").replace(b"Quoted prose", b"Quoted \xff prose")
    rows.append(("invalid_utf8", bad_utf8, f"not strict UTF-8 (invalid byte at offset {bad_utf8.index(b'\xff')})", None))
    return rows


# I1 (#6124 round 1): the banner precondition runs before the ledger parse, so a head with
# no strict STATUS line is refused by the banner reason at gate level; the parser row keeps
# its ledger reason.
GATE_FIRST_LINE = {"status_missing": banner_line(NO_STRICT_STATUS)}


class HostileTable(LedgerCase):
    def test_every_hostile_row_is_refused_with_its_exact_reason(self):
        s = self.scene("VOID")
        for name, doc, reason, line in hostile_rows():
            with self.subTest(row=name):
                files = s.touch_wire(note=name)
                files[CERT_REL] = doc
                head = s.commit(files, f"hostile row {name}")
                ok, out = s.judge(head)
                rc = 0 if ok else 1
                self.assertEqual(rc, 1, f"{name}: {out}")
                expected = GATE_FIRST_LINE.get(name, reason_line(reason, line))
                self.assertIn(expected, out.split("\n"), f"{name}: {out}")

    def test_parser_refuses_each_row_without_raising_anything_else(self):
        for name, doc, reason, line in hostile_rows():
            with self.subTest(row=name):
                self.assertEqual(ledger_error(doc), (reason, line))


class Generative(LedgerCase):
    def build(self, rng, records):
        # Record dates never decrease (#6124 L-1): draw the offsets, then sort them.
        out = []
        for offset in sorted(rng.randrange(30) for _ in range(records)):
            date = datetime.date(2026, 11, 13) + datetime.timedelta(days=offset)
            items = sorted(rng.sample(NAME_POOL, rng.randrange(1, len(NAME_POOL) + 1)))
            out.append(record(date.isoformat(), *items))
        return out

    def test_valid_ledgers_round_trip(self):
        rng = random.Random(GENERATIVE_SEED)
        for _ in range(GENERATIVE_ROUNDS):
            recs = self.build(rng, rng.randrange(0, 6))
            parsed = cert.parse_ledger(with_ledger(head_doc(), *recs).encode("utf-8"), "head")
            self.assertEqual(["".join(f"{ln}\n" for ln in r.lines) for r in parsed],
                             [r.replace("\n\n", "\n", 1).lstrip("\n") for r in recs])

    def test_injected_invalid_line_is_refused_at_its_line(self):
        rng = random.Random(GENERATIVE_SEED + 1)
        for _ in range(GENERATIVE_ROUNDS):
            doc = with_ledger(head_doc(), *self.build(rng, rng.randrange(1, 5)))
            lines = doc.split("\n")[:-1]
            marker_at = lines.index(MARKER)
            pos = rng.randrange(marker_at + 1, len(lines) + 1)
            bad = rng.choice(ALWAYS_BAD_LINES)
            lines.insert(pos, bad)
            got = ledger_error("\n".join(lines) + "\n")
            self.assertIsNotNone(got, bad)
            self.assertEqual(got[1], pos + 1, f"{bad!r} at line {pos + 1}: {got}")


class Bounds(LedgerCase):
    def timed(self, blob):
        start = time.monotonic()
        try:
            result = cert.parse_ledger(blob, "head")
        except cert.LedgerError as exc:
            result = (exc.reason, exc.line)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, PARSE_BOUND_S, f"parse took {elapsed:.2f}s")
        return result

    def test_100k_line_ledger_parses_in_linear_time(self):
        recs = [record(DAY, path_item(MOD_RS))] * (BIG_LEDGER_LINES // 4)
        blob = with_ledger(head_doc(), *recs).encode("utf-8")
        self.assertEqual(len(self.timed(blob)), BIG_LEDGER_LINES // 4)

    def test_10mb_single_line_is_refused_quickly(self):
        doc = with_ledger(head_doc(), record(DAY, "- path: src/federation/" + "a" * BIG_LINE_BYTES))
        blob = doc.encode("utf-8")
        self.assertEqual(self.timed(blob),
                         (f"the document is {len(blob)} bytes, over the {DOC_LIMIT_BYTES}-byte limit", None))

    def test_1mb_line_under_the_cap_is_refused_quickly(self):
        doc = with_ledger(head_doc(), record(DAY, "- path: src/federation/" + "a" * LONG_LINE_BYTES))
        lines = doc.split("\n")
        self.assertEqual(self.timed(doc.encode("utf-8")),
                         (f"line longer than {LINE_LIMIT_BYTES} bytes", len(lines) - 1))

    def test_10mb_prose_line_before_the_marker_is_refused_quickly(self):
        doc = with_ledger(head_doc(), pre="x" * BIG_LINE_BYTES + "\n\n")
        blob = doc.encode("utf-8")
        self.assertEqual(self.timed(blob),
                         (f"the document is {len(blob)} bytes, over the {DOC_LIMIT_BYTES}-byte limit", None))

    def test_1mb_prose_line_before_the_marker_is_refused_at_its_line(self):
        # The per-line cap runs before any pre-region regex (M-2).
        prose = "x" * LONG_LINE_BYTES
        doc = with_ledger(head_doc(), pre=prose + "\n\n")
        self.assertEqual(self.timed(doc.encode("utf-8")),
                         (f"line longer than {PRE_LINE_LIMIT_BYTES} bytes above the ledger",
                          line_no(doc, prose)))


    def test_pre_region_lines_parse_in_linear_time(self):
        # M-2: 10K, 100K and 1M plain pre-region lines; the bound grows linearly with N.
        honest = record(DAY, path_item(MOD_RS))
        for count in PRE_REGION_LINES:
            with self.subTest(lines=count):
                blob = with_ledger(head_doc(), honest, pre="p\n" * count + "\n").encode("utf-8")
                start = time.monotonic()
                parsed = cert.parse_ledger(blob, "head")
                elapsed = time.monotonic() - start
                bound = PARSE_BOUND_S + PRE_REGION_S_PER_LINE * count
                self.assertLess(elapsed, bound, f"{count} lines took {elapsed:.2f}s")
                self.assertEqual(len(parsed), 1)

    def test_100k_line_emphasis_paragraph_is_linear(self):
        # M-2: 100K unclosed '**' openers in one paragraph, then a line naming an amendment.
        doc = with_ledger(head_doc(), record(DAY, path_item(MOD_RS)),
                          pre="**x\n" * BIG_EMPHASIS_LINES + "**Amendment** x\n\n")
        self.assertEqual(self.timed(doc.encode("utf-8")),
                         ("emphasis naming an amendment or a status above the ledger",
                          line_no(doc, "**Amendment** x")))

    def test_100k_binds_line_is_refused_under_one_second(self):
        # M-3: a 100K-byte Binds line skips the strict regex (per-line cap first) and is
        # refused by the looser detector, end to end through the gate, within FAST_BOUND_S.
        s = self.scene("VOID")
        big = "**Binds to:** `" + "a" * BIG_BINDS_BYTES + "`"
        doc = with_ledger(s.doc + "\n" + big + "\n", record(DAY, path_item(MOD_RS)))
        head = self.wire_and_doc(s, doc)
        start = time.monotonic()
        ok, out = s.judge(head)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, FAST_BOUND_S, f"gate took {elapsed:.2f}s")
        self.assert_banner_refused(ok, out, LOOSE_BINDS, line_no(doc, big), "head",
                                   BINDS_DUPLICATE_3556, "VOID -")


PRE_REGION_S_PER_LINE = 25e-6


class BannerPrecondition(LedgerCase):
    """H-A / F1 (I1): one clean banner at both ends, judged before any ledger reason."""

    def test_doc_only_two_binds_while_void_refused(self):
        s = self.scene("VOID")
        bind = bind_line(s.genesis)
        doc = s.doc.replace(NO_BIND_LINE, f"{bind}\n\n{bind}")
        ok, out = s.judge(s.commit({CERT_REL: doc}, "doc-only: two binds"))
        self.assert_banner_refused(ok, out, STRICT_BINDS_SECOND, nth_line_no(doc, bind, 2),
                                   "head", BINDS_DUPLICATE_3556, "VOID DUPLICATE")

    def test_duplicate_both_ends_with_exact_record_refused(self):
        for status, bound in (("VOID", False), ("EXPIRED", True)):
            with self.subTest(status=status):
                s = self.scene(status, bind_genesis=bound, base_doc=lambda sc, st=status: dup_status_doc(
                    st, sc.binds, st))
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)))
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assert_banner_refused(
                    ok, out, STRICT_STATUS_SECOND, nth_line_no(s.doc, status_line(status), 2),
                    "base", DUPLICATE_3556, f"DUPLICATE {s.binds or '-'}")

    def test_duplicate_to_other_duplicate_refused(self):
        for wire in (True, False):
            with self.subTest(wire=wire):
                s = self.scene("VOID", base_doc=lambda sc: dup_status_doc("VOID"))
                doc = dup_status_doc("VOID", None, "EXPIRED")
                files = s.touch_wire() if wire else {}
                files[CERT_REL] = doc
                ok, out = s.judge(s.commit(files, "dup to other dup"))
                self.assert_banner_refused(
                    ok, out, STRICT_STATUS_SECOND, nth_line_no(s.doc, status_line("VOID"), 2),
                    "base", DUPLICATE_3556, "DUPLICATE -")

    def test_base_only_duplicate_refused(self):
        s = self.scene("VOID", base_doc=lambda sc: dup_status_doc("VOID"))
        doc = with_ledger(head_doc("VOID"), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_banner_refused(ok, out, STRICT_STATUS_SECOND,
                                   nth_line_no(s.doc, status_line("VOID"), 2), "base",
                                   DUPLICATE_3556, "DUPLICATE -")

    def test_base_only_unparseable_refused(self):
        s = self.scene("VOID", base_doc=lambda sc: head_doc("VOID").replace(
            status_line("VOID"), "> Status prose."))
        doc = with_ledger(head_doc("VOID"), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_banner_refused(ok, out, NO_STRICT_STATUS, None, "base", UNPARSEABLE_3556,
                                   "UNPARSEABLE -")

    def test_over_cap_head_refused_by_the_banner(self):
        # F4: the size cap applies before the split, at gate level.
        s = self.scene("VOID")
        doc = with_ledger(s.doc + ("y" * 80 + "\n") * (OVER_CAP_PAD // 81) + "\n",
                          record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        size = len(doc.encode("utf-8"))
        self.assert_banner_refused(
            ok, out, f"the document is {size} bytes, over the {DOC_LIMIT_BYTES}-byte limit", None,
            "head", UNPARSEABLE_3556, "UNPARSEABLE -")


class BaseLedgerTolerance(LedgerCase):
    """F5: the base is judged for grammar only (no watched-path check, no size cap)."""

    def test_base_record_naming_an_unwatched_path_is_accepted(self):
        s = self.scene("VOID", base_doc=lambda sc: with_ledger(
            head_doc("VOID"), record(DAY, path_item(UNRELATED_RS))))
        ok, out = s.judge(self.wire_and_doc(s, s.doc + record(DAY, path_item(MOD_RS))))
        self.assert_pass(ok, out, "a new amendment record names every change",
                         "the certification stays VOID")

    def test_base_over_the_cap_is_accepted(self):
        s = self.scene("VOID", base_doc=lambda sc: with_ledger(
            head_doc("VOID") + ("y" * 80 + "\n") * (OVER_CAP_PAD // 81) + "\n"))
        doc = with_ledger(head_doc("VOID"), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_pass(ok, out, "the certification stays VOID")


# H-B / M-2 (I4): pre-region constructs that hide or fake a record or a banner.
PRE_LEDGER_ROWS = (
    ("atx_in_fence", "```\n### Amendment 2026-11-13\n\n- path: src/federation/peer.rs\n```\n\n",
     "a fence body naming an amendment or a status above the ledger", "### Amendment 2026-11-13"),
    ("html_inline_open", "<!-- a --> <!--\n\nhidden text\n\n-->\n\n",
     "a second '<!--' on one line above the ledger", "<!-- a --> <!--"),
    ("setext_fake_ledger", "Amendment ledger (rule B, append-only)\n---\n\nAmendment 2026-11-14\n---\n\n"
     "- path: src/federation/peer.rs\n\n",
     "a setext heading naming an amendment or a status above the ledger",
     "Amendment ledger (rule B, append-only)"),
    ("bold_fake_record", "**Amendment 2026-11-14:** path src/federation/peer.rs\n\n",
     "emphasis naming an amendment or a status above the ledger",
     "**Amendment 2026-11-14:** path src/federation/peer.rs"),
    ("link_ref", "[amendment]: https://example.invalid/#amendment\n\n",
     "a link reference definition naming an amendment or a status above the ledger",
     "[amendment]: https://example.invalid/#amendment"),
)
PRE_BANNER_ROWS = (
    ("nested_quote", "> > ## STATUS — **LIVE as of 2026-11-13** bound to everything"),
    ("h4", "#### STATUS — **LIVE as of 2026-11-13**"),
)
ALWAYS_BAD_PRE_LINES = (
    ("x" * (PRE_LINE_LIMIT_BYTES + 1), f"line longer than {PRE_LINE_LIMIT_BYTES} bytes above the ledger"),
    ("<!-- a --> <!--", "a second '<!--' on one line above the ledger"),
)


class PreRegion(LedgerCase):
    def test_hiding_constructs_are_refused_at_their_line(self):
        s = self.scene("VOID")
        for name, block, reason, needle in PRE_LEDGER_ROWS:
            with self.subTest(row=name):
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), pre=block)
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assertFalse(ok, out)
                self.assertEqual(out.split("\n"), [reason_line(reason, line_no(doc, needle))], out)

    def test_banner_lookalikes_above_the_ledger_are_refused_by_the_banner(self):
        s = self.scene("VOID")
        for name, fake in PRE_BANNER_ROWS:
            with self.subTest(row=name):
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), pre=fake + "\n\n")
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assert_banner_refused(ok, out, LOOSE_STATUS, line_no(doc, fake), "head",
                                           DUPLICATE_3556, "DUPLICATE -")

    def test_hide_status_show_live_refused(self):
        s = self.scene("VOID")
        fake = "#### STATUS — **LIVE as of 2026-11-13**"
        doc = with_ledger(s.doc.replace(
            status_line("VOID"), f"{fake}\n\n<!-- x --> <!--\n{status_line('VOID')}\n-->"),
            record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_banner_refused(ok, out, LOOSE_STATUS, line_no(doc, fake), "head",
                                   DUPLICATE_3556, "DUPLICATE -")

    def test_hide_ledger_to_eof_refused(self):
        s = self.scene("VOID")
        doc = s.doc + "<!-- x --> <!--\n\n" + MARKER + "\n" + record(DAY, path_item(MOD_RS))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n"), [reason_line(
            "a second '<!--' on one line above the ledger", line_no(doc, "<!-- x --> <!--"))], out)

    def test_always_bad_pre_line_is_refused_at_every_position(self):
        base = with_ledger(head_doc("VOID"), record(DAY, path_item(MOD_RS)))
        lines = base.split("\n")
        marker_at = lines.index(MARKER)
        for bad, reason in ALWAYS_BAD_PRE_LINES:
            for pos in range(marker_at):
                with self.subTest(bad=bad[:16], line=pos + 1):
                    doc = "\n".join(lines[:pos] + [bad] + lines[pos:])
                    self.assertEqual(ledger_error(doc), (reason, pos + 1))


class Flip(LedgerCase):
    """H-C (I2): a VOID <-> EXPIRED change goes to the amendment branch."""

    def test_flip_without_record_refused(self):
        for old, new in (("VOID", "EXPIRED"), ("EXPIRED", "VOID")):
            with self.subTest(flip=f"{old}->{new}"):
                s = self.scene(old)
                ok, out = s.judge(self.wire_and_doc(s, head_doc(new)))
                self.assertFalse(ok, out)
                self.assertIn(cert.EXPIRY_SENTENCE, out)
                self.assertIn(f"The STATUS word changed {old} → {new}; a change between VOID and "
                              "EXPIRED is not a re-issue and not a voiding record (#6124).",
                              out.split("\n"))

    def test_flip_with_exact_record_passes(self):
        for old, new in (("VOID", "EXPIRED"), ("EXPIRED", "VOID")):
            with self.subTest(flip=f"{old}->{new}"):
                s = self.scene(old)
                ok, out = s.judge(self.wire_and_doc(
                    s, with_ledger(head_doc(new), record(DAY, path_item(MOD_RS)))))
                self.assert_pass(ok, out, "a new amendment record names every change",
                                 f"the certification goes {old} → {new}")

    def test_flip_with_missing_name_refused(self):
        s = self.scene("VOID")
        doc = with_ledger(head_doc("EXPIRED"), record(DAY, path_item(PEER_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n"), [
            reason_line(f"the new amendment records do not name changed {MOD_RS}")], out)


# v9274-status vote tally (3-agent vote 71472661), B-1 .. B-5.
B1_EDITS = (
    ("en_dash", lambda line: line.replace("—", "–")),
    ("lowercase_label", lambda line: line.replace("STATUS", "status")),
    ("heading_level", lambda line: line.replace("## ", "### ")),
    ("trailing_space", lambda line: line + " "),
    ("prose_kept_word", lambda line: line + " (amended)"),
)
B3_TOKENS = (
    *((probe, probe) for probe in PROBED_STATUS),
    ("synonym_reinstated", "**REINSTATED as of"),
    ("homoglyph_live", f"**LIV{HOMOGLYPH_E} as of"),
    ("homoglyph_void", f"**V{HOMOGLYPH_O}ID as of"),
    ("zero_width_split", f"**VO{ZERO_WIDTH}ID as of"),
)


class VoteTally(LedgerCase):
    def test_b1_status_line_bytes_frozen_on_amendment(self):
        # B-1 / B-4: every byte edit of the STATUS line (no normalisation) is refused with
        # the frozen reason, even with an exact record.
        for name, edit in B1_EDITS:
            with self.subTest(edit=name):
                s = self.scene("VOID")
                doc = with_ledger(s.doc.replace(status_line("VOID"), edit(status_line("VOID"))),
                                  record(DAY, path_item(MOD_RS)))
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assertFalse(ok, out)
                self.assertEqual(out.split("\n"), [FROZEN_LINE], out)

    def test_b2_flip_with_any_other_byte_changed_refused(self):
        s = self.scene("VOID")
        doc = with_ledger(head_doc("EXPIRED").replace("2026-01-01", DAY),
                          record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertFalse(ok, out)
        self.assertEqual(out.split("\n"), [FROZEN_LINE], out)

    def test_b2_token_only_flip_with_exact_record_passes(self):
        s = self.scene("VOID")
        ok, out = s.judge(self.wire_and_doc(
            s, with_ledger(head_doc("EXPIRED"), record(DAY, path_item(MOD_RS)))))
        self.assert_pass(ok, out, "the certification goes VOID → EXPIRED")

    def test_b3_b5_malformed_tokens_refused_as_malformed(self):
        # B-3 / B-5: never read as VOID; each is a STATUS-like line the strict grammar does
        # not read, so the banner is UNPARSEABLE, even with an exact record.
        for name, token in B3_TOKENS:
            with self.subTest(token=name):
                s = self.scene("VOID")
                doc = with_ledger(s.doc.replace("**VOID as of", token),
                                  record(DAY, path_item(MOD_RS)))
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assert_banner_refused(ok, out, LOOSE_STATUS, STATUS_LINE_NO, "head",
                                           UNPARSEABLE_3556, "UNPARSEABLE -")
                self.assertNotIn("stays VOID", out)


# #6124 round 1 mutation proof: one row per looser-detector arm, cap edge and pre-region
# reason, so a gate with any one arm or bound weakened fails on an exact-reason assertion
# and not only on a timing row. Every row carries an exact record.
NBSP = " "
LOOSE_STATUS_ARM_ROWS = (
    ("word_without_star", "#### STATUS: LIVE as of 2026-11-13"),
    ("unicode_space_separator", f"Status{NBSP}LIVE as of 2026-11-13"),
    ("format_char_in_label", f"STA{ZERO_WIDTH}TUS: LIVE as of 2026-11-13"),
)
LOOSE_BINDS_ARM_ROWS = (
    ("plural_then_colon", "Binds to: the commit named below"),
    ("singular_then_hex_run", "bind to deadbeefcafe0123 per the note"),
    ("hyphen_separator", "Bind-to: the commit named below"),
)
PRE_INLINE_ROWS = (
    ("inline_html_naming_amendment", "Prose <span>Amendment 2026-11-14</span> here.",
     "inline HTML naming an amendment or a status above the ledger"),
    ("comment_not_closed_on_its_line", "Prose <!-- open",
     "an HTML comment not closed on its line above the ledger"),
)
PAD_LINE = "y" * 80 + "\n"


def doc_of_size(doc, records, size):
    """with_ledger(DOC, *RECORDS) padded above the marker with prose to exactly SIZE bytes."""
    bare = len(with_ledger(doc, *records, pre="\n").encode("utf-8"))
    fill = size - bare
    whole, rest = divmod(fill, len(PAD_LINE))
    pad = PAD_LINE * whole + ("y" * (rest - 1) + "\n" if rest else "")
    out = with_ledger(doc, *records, pre=pad + "\n")
    if len(out.encode("utf-8")) != size:
        raise AssertionError(f"fixture is {len(out.encode('utf-8'))} bytes, wanted {size}")
    return out


class MutationKillRows(LedgerCase):
    def test_each_loose_status_arm_refuses_its_decoy(self):
        s = self.scene("VOID")
        for name, fake in LOOSE_STATUS_ARM_ROWS:
            with self.subTest(row=name):
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), pre=fake + "\n\n")
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assert_banner_refused(ok, out, LOOSE_STATUS, line_no(doc, fake), "head",
                                           DUPLICATE_3556, "DUPLICATE -")

    def test_each_loose_binds_arm_refuses_its_decoy(self):
        # Same refusal shape as the M-3 row (Bounds): the decoy's line, then the #3556
        # Binds text, then the parsed banner.
        s = self.scene("VOID")
        for name, fake in LOOSE_BINDS_ARM_ROWS:
            with self.subTest(row=name):
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), pre=fake + "\n\n")
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assert_banner_refused(ok, out, LOOSE_BINDS, line_no(doc, fake), "head",
                                           BINDS_DUPLICATE_3556, "VOID -")

    def test_two_binds_like_lines_still_name_the_duplicate(self):
        s = self.scene("VOID")
        fake = LOOSE_BINDS_ARM_ROWS[0][1]
        doc = with_ledger(s.doc.replace(NO_BIND_LINE, bind_line(s.genesis)),
                          record(DAY, path_item(MOD_RS)), pre=fake + "\n\n")
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assert_banner_refused(ok, out, LOOSE_BINDS, line_no(doc, fake), "head",
                                   BINDS_DUPLICATE_3556, "VOID DUPLICATE")

    def test_size_cap_edge_is_exact(self):
        s = self.scene("VOID")
        rec = record(DAY, path_item(MOD_RS))
        at_cap = doc_of_size(s.doc, (rec,), DOC_LIMIT_BYTES)
        ok, out = s.judge(self.wire_and_doc(s, at_cap))
        self.assert_pass(ok, out, "a new amendment record names every change")
        over = doc_of_size(s.doc, (rec,), DOC_LIMIT_BYTES + 1)
        ok, out = s.judge(self.wire_and_doc(s, over))
        self.assert_banner_refused(
            ok, out, f"the document is {DOC_LIMIT_BYTES + 1} bytes, over the {DOC_LIMIT_BYTES}-byte limit",
            None, "head", UNPARSEABLE_3556, "UNPARSEABLE -")

    def test_inline_html_rows_are_refused_at_their_line(self):
        s = self.scene("VOID")
        for name, fake, reason in PRE_INLINE_ROWS:
            with self.subTest(row=name):
                doc = with_ledger(s.doc, record(DAY, path_item(MOD_RS)), pre=fake + "\n\n")
                ok, out = s.judge(self.wire_and_doc(s, doc))
                self.assertFalse(ok, out)
                self.assertEqual(out.split("\n"), [reason_line(reason, line_no(doc, fake))], out)


class DocRecordForm(unittest.TestCase):
    """I5 / F3: the doc states the record form the parser reads."""

    DOC = (HARNESS_ROOT / CERT_REL)

    def doc_text(self):
        return " ".join(self.DOC.read_text(encoding="utf-8").split())

    def test_doc_example_record_parses(self):
        import re
        found = re.search(r"Example record: `(### Amendment \d{4}-\d{2}-\d{2})`, a blank line, "
                          r"`(- id: [A-Z_]+)`, `(- path: [^`]+)`\.", self.doc_text())
        self.assertIsNotNone(found, "the doc carries no example record")
        parsed = cert.parse_ledger(with_ledger(head_doc(), record(
            found.group(1).split(" ")[-1], found.group(2), found.group(3))).encode("utf-8"), "head")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].lines, (found.group(1), found.group(2), found.group(3)))

    def test_doc_names_the_item_order_and_path_restriction(self):
        text = self.doc_text()
        self.assertIn(ITEM_ORDER, text)
        self.assertIn(PATH_RESTRICTION, text)


if __name__ == "__main__":
    unittest.main()
