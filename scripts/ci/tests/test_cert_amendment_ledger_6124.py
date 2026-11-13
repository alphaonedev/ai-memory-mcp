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
    bind_line = f"**Binds to:** `{binds}` (fixture bind)" if binds else "**Binds to:** none (voided)"
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
        "> **Amendment (2026-08-29, history).** Quoted prose, not a record.",
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


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["HOME"] = str(SCRATCH_ROOT)
    return env


class Scene:
    """A private repository: `genesis` (sources, one FED id), then `base` (the cert doc
    with the given STATUS and bind and no ledger)."""

    def __init__(self, root, status="VOID", bind_genesis=False):
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
        self.base = self.commit({CERT_REL: self.doc}, "base: certification banner")

    def g(self, *args):
        proc = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True,
                              env=git_env(), timeout=GIT_TIMEOUT_S, check=False)
        if proc.returncode != 0:
            raise AssertionError(f"git {args} failed: {proc.stderr.decode('utf-8', 'replace')}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def write(self, rel, content):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    def commit(self, files, msg):
        for rel, content in files.items():
            self.write(rel, content)
        self.g("add", "--", *files)
        self.g("commit", "-q", "-m", msg)
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

    def scene(self, status="VOID", bind_genesis=False):
        return Scene(self.tmp, status, bind_genesis)

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

    def test_drop_bind_stays_a_voiding_record(self):
        s = self.scene("EXPIRED", bind_genesis=True)
        files = s.touch_wire()
        files[CERT_REL] = head_doc("EXPIRED", None)
        ok, out = s.judge(s.commit(files, "drop the bind"))
        self.assert_pass(ok, out, "cert doc re-issued/voided")

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
    def wire_and_doc(self, s, doc, *wire):
        files = {}
        for rel in wire or (MOD_RS,):
            files.update(s.touch_wire(rel))
        files[CERT_REL] = doc
        return s.commit(files, "change under test")

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
        self.assertFalse(ok, out)
        self.assertIn("record 1 of the base ledger", out)

    def test_record_inserted_before_earlier_record_fails(self):
        s = self.scene("VOID")
        first = self.first_record(s)
        doc = with_ledger(s.doc, record(DAY, path_item(PEER_RS)), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc, PEER_RS), base=first)
        self.assertFalse(ok, out)
        self.assertIn("record 1 of the base ledger", out)

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
        self.assertFalse(ok, out)
        self.assertIn("record 1 of the base ledger", out)

    def test_future_dated_record_fails(self):
        s = self.scene("VOID")
        doc = with_ledger(s.doc, record(FUTURE_DAY, path_item(MOD_RS)))
        head = self.wire_and_doc(s, doc)
        stamp = int(s.g("show", "-s", "--format=%ct", head))
        committed = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).date().isoformat()
        ok, out = s.judge(head)
        self.assert_refused(ok, out, reason_line(
            f"record dated {FUTURE_DAY} is after the judged commit date {committed} plus 1 day",
            line_no(doc, f"### Amendment {FUTURE_DAY}")))

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
        self.assertIn(f"{GATE_PREFIX}: ERROR — Binds-to set (- → {s.genesis}) while STATUS stays "
                      "VOID", out)

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

    def test_revoiding_status_prose_with_exact_record_passes(self):
        # The #9176 shape: the STATUS prose is rewritten as a re-voiding record and the word
        # stays VOID; with an exact amendment that is the honest pass, never a discharge.
        s = self.scene("VOID")
        doc = with_ledger(head_doc("VOID", None, " (amended)"), record(DAY, path_item(MOD_RS)))
        ok, out = s.judge(self.wire_and_doc(s, doc))
        self.assertTrue(ok, out)
        self.assertIn("the certification stays VOID", out)

    def test_revoiding_status_prose_without_record_fails(self):
        s = self.scene("VOID")
        ok, out = s.judge(self.wire_and_doc(s, head_doc("VOID", None, " (amended)")))
        self.assertFalse(ok, out)
        self.assertIn("No new dated amendment record names this change", out)

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
    region("no_blank_after_marker", f"### Amendment {DAY}\n\n- path: {MOD_RS}\n", "expected a blank line", f"### Amendment {DAY}")
    region("no_blank_after_heading", f"\n### Amendment {DAY}\n- path: {MOD_RS}\n", "expected a blank line", f"- path: {MOD_RS}")
    region("bad_calendar_date", f"\n### Amendment 2026-02-30\n\n- path: {MOD_RS}\n", "date 2026-02-30 is not a calendar date", "### Amendment 2026-02-30")
    region("unsorted_items", f"\n### Amendment {DAY}\n\n- path: {PEER_RS}\n- path: {MOD_RS}\n",
           "item lines must be sorted and unique (this line is not after the previous one)", f"- path: {MOD_RS}")
    region("duplicate_items", f"\n### Amendment {DAY}\n\n- path: {MOD_RS}\n- path: {MOD_RS}\n",
           "item lines must be sorted and unique (this line is not after the previous one)",
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
                self.assertIn(reason_line(reason, line), out.split("\n"), f"{name}: {out}")

    def test_parser_refuses_each_row_without_raising_anything_else(self):
        for name, doc, reason, line in hostile_rows():
            with self.subTest(row=name):
                self.assertEqual(ledger_error(doc), (reason, line))


class Generative(LedgerCase):
    def build(self, rng, records):
        out = []
        for _ in range(records):
            date = datetime.date(2026, 11, 13) + datetime.timedelta(days=rng.randrange(30))
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
        self.assertEqual(self.timed(blob)[1], None)


if __name__ == "__main__":
    unittest.main()
