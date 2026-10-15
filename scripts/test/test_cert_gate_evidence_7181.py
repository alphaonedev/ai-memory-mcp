#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the cert-bootstrap gate LEG B evidence behaviour (#7181).

#7181: the required check ``Certified pg+AGE cells`` failed in LEG B of
``scripts/check-bootstrap-cert-gate.sh`` and the gate's evidence
(``bring-up.out``) was lost with the runner workspace. The gate must

* print a bounded, redacted copy of the LEG B evidence into the job log when a
  LEG B row fails (helper ``scripts/cert_gate_evidence.py``),
* mint the witness and recorder keys inside the same hermetic sandbox as every
  other LEG B call (no bare ``"$BIN" identity generate``, output not silenced),
  with EVERY role key directory set explicitly and every inherited path
  variable cleared,
* remove every ``mktemp`` work directory on EXIT through ONE python invocation
  (no shell control flow), with ``TMPDIR`` pinned under the repo (no /tmp), and
* the workflow must upload only a REDACTED copy of the evidence on failure.

Stdlib only. Run: ``python3 -I scripts/test/test_cert_gate_evidence_7181.py``
"""
import importlib.util
import io
import random
import re
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "check-bootstrap-cert-gate.sh"
HELPER = ROOT / "scripts" / "cert_gate_evidence.py"
WORKFLOW = ROOT / ".github" / "workflows" / "cert-postgres-age.yml"
TAIL_LINES = 200
# Scratch dirs live under the repo's ignored .local-runs/ (never /tmp).
SCRATCH_ROOT = ROOT / ".local-runs" / "test-7181"
ROLE_KEY_DIR_ENVS = (
    "AI_MEMORY_KEY_DIR",
    "AI_MEMORY_WITNESS_KEY_DIR",
    "AI_MEMORY_RECORDER_KEY_DIR",
    "AI_MEMORY_JUDGE_KEY_DIR",
    "AI_MEMORY_STOPPER_KEY_DIR",
)
# Root cause of the #7181 LEG B conviction: the forensic audit sink is a SHARED
# per-user dir (under the state dir); earlier gate runs leave a watermark for
# the same genesis-derived db id, so a fresh bring-up is convicted of
# truncation. Every sandbox wrapper must pin its own sink dirs.
SINK_DIR_ENVS = ("AI_MEMORY_AUDIT_DIR", "AI_MEMORY_LOG_DIR")
# F5: every inherited AI_MEMORY_* path / credential variable the sandbox
# wrappers must clear (env::var literals in src/ ending DB, DIR, FILE, PATH,
# ROOT or URL, plus the passphrase pair).
CLEARED_ENVS = (
    "AI_MEMORY_DB",
    "AI_MEMORY_DB_PASSPHRASE",
    "AI_MEMORY_DB_PASSPHRASE_FILE",
    "AI_MEMORY_AGENT_API_KEY_FILE",
    "AI_MEMORY_CAPABILITY_FILE",
    "AI_MEMORY_ERASURE_DIR",
    "AI_MEMORY_FED_CRED_CHAIN_PATH",
    "AI_MEMORY_FED_CRED_PATH",
    "AI_MEMORY_FED_INVENTORY_PATH",
    "AI_MEMORY_FED_TRUST_BUNDLE_DIR",
    "AI_MEMORY_LOG_SYSLOG_TLS_CA_FILE",
    "AI_MEMORY_SKILLS_EXPORT_ROOT",
    "AI_MEMORY_SKILLS_IMPORT_ROOT",
    "AI_MEMORY_SYSTEM_PROMPT_DIR",
    "AI_MEMORY_EMBED_BASE_URL",
    "AI_MEMORY_LLM_BASE_URL",
)
PINNED_UPLOAD = re.compile(r"actions/upload-artifact@[0-9a-f]{40}\b")
REDACTED_DIR = ".local-runs/cert-bootstrap-evidence-redacted"


def _scratch() -> tempfile.TemporaryDirectory:
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(SCRATCH_ROOT))


def _load_helper():
    spec = importlib.util.spec_from_file_location("cert_gate_evidence", HELPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _leg_b_text() -> str:
    text = GATE.read_text(encoding="utf-8")
    start = text.index("== LEG B")
    return text[start:]


# Secrets are built at runtime so no credential-shaped literal is in the file.
HEX64 = "ab12" * 16
B64 = "Zm9v" * 11
PEM_LABEL = "ED25519 PRIVATE" + " KEY"
BEGIN = "-----BEGIN " + PEM_LABEL + "-----"
END = "-----END " + PEM_LABEL + "-----"
SPACED = "hunter2" + "value"
BEARER_TOK = "abc123" + "tokenvalue"


class HelperRedactsAndBounds(unittest.TestCase):
    def test_helper_exists(self):
        self.assertTrue(HELPER.is_file(), "scripts/cert_gate_evidence.py missing")

    def test_redacts_private_key_material_and_tokens(self):
        mod = _load_helper()
        sample = [
            "-----BEGIN " + "PRIVATE KEY-----",
            "private_key: " + "A" * 44,
            "api_" + "token=ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789",
            "db: ./ai-memory.db",
            "CERTIFIED-READY witness role_separation identity_lineage",
        ]
        out = [mod.redact_line(x) for x in sample]
        self.assertNotIn("A" * 16, "\n".join(out))
        self.assertNotIn("ghp" + "_abcdef", "\n".join(out))
        self.assertEqual(out[3], sample[3])
        self.assertEqual(out[4], sample[4])

    # F1: one test per leaked shape.
    def test_f1_hex_after_token_word_and_bare(self):
        mod = _load_helper()
        for ln in ("tok" + "en " + HEX64, "value is " + HEX64):
            self.assertNotIn(HEX64[:20], mod.redact_line(ln), ln)

    def test_f1_pem_digit_label_and_body(self):
        mod = _load_helper()
        lines = [BEGIN, "QUJD" + "REVG", B64[:30], END, "after: plain"]
        out = mod.redact_lines(lines)
        self.assertEqual(out[:4], [mod.REDACTED] * 4)
        self.assertEqual(out[4], "after: plain")

    def test_f1_secret_key_b64_whitespace_separator(self):
        mod = _load_helper()
        self.assertNotIn(B64[:8], mod.redact_line("secret" + "_key_b64 " + B64[:20]))

    def test_f1_json_quoted_key_and_value(self):
        mod = _load_helper()
        self.assertNotIn(B64[:8], mod.redact_line('"private' + '_key": "' + B64[:20] + '"'))

    def test_f1_spaced_secret_key_colon(self):
        mod = _load_helper()
        self.assertNotIn(SPACED, mod.redact_line("secret" + " key: " + SPACED))

    def test_f1_authorization_bearer(self):
        mod = _load_helper()
        self.assertNotIn(BEARER_TOK, mod.redact_line("Authori" + "zation: Bear" + "er " + BEARER_TOK))
        self.assertNotIn(BEARER_TOK, mod.redact_line("send Bear" + "er " + BEARER_TOK + " now"))

    def test_f1_long_runs_masked_but_public_key_line_allowlisted(self):
        mod = _load_helper()
        self.assertNotIn(B64, mod.redact_line("blob " + B64))
        pub = "pub_b" + "64: " + B64
        self.assertEqual(mod.redact_line(pub), pub)
        self.assertNotIn(HEX64, mod.redact_line("pub_b" + "64: x tok" + "en=" + HEX64))

    def test_f1_error_path_never_echoes_argument(self):
        marker = "ARGMARKER" + "9f3a"
        for argv in (["--evidence-dir", "/nonexistent/" + marker], ["--tail", marker, "--evidence-dir", "."]):
            proc = subprocess.run([sys.executable, str(HELPER)] + argv, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn(marker, proc.stdout + proc.stderr)

    def test_f2_redacted_copy_has_no_secrets(self):
        with _scratch() as td:
            ev = Path(td) / "ev"
            ev.mkdir()
            lines = [
                "tok" + "en " + HEX64,
                BEGIN,
                B64,
                END,
                '"private' + '_key": "' + B64 + '"',
                "secret" + " key: " + SPACED,
                "Authori" + "zation: Bear" + "er " + BEARER_TOK,
            ]
            (ev / "bring-up.out").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (ev / "pg-posture-1.out").write_text("dsn " + HEX64 + "\n", encoding="utf-8")
            out = Path(td) / "red"
            rc = subprocess.run(
                [sys.executable, str(HELPER), "--evidence-dir", str(ev), "--write-redacted", str(out)]
            ).returncode
            names = sorted(p.name for p in out.iterdir())
            blob = "".join(p.read_text(encoding="utf-8") for p in out.iterdir())
        self.assertEqual(rc, 0)
        self.assertEqual(names, ["bring-up.out"])
        for sec in (HEX64, B64, SPACED, BEARER_TOK):
            self.assertNotIn(sec, blob)

    def test_finalize_reports_leg_b_then_cleans(self):
        mod = _load_helper()
        with _scratch() as td:
            td = Path(td)
            ev, state, victim = td / "ev", td / "state", td / "victim"
            for d in (ev, state, victim):
                d.mkdir()
            (ev / "bring-up.out").write_text("hello\n", encoding="utf-8")
            (state / "fail-rows").write_text("A\tleg a row\nB\tleg b row\n", encoding="utf-8")
            (state / "cleanup-list").write_text("%s\n/\nrelative\n" % victim, encoding="utf-8")
            buf = io.StringIO()
            self.assertEqual(mod.finalize(state, ev, TAIL_LINES, buf), 0)
            self.assertIn("== LEG B evidence", buf.getvalue())
            self.assertIn("hello", buf.getvalue())
            self.assertFalse(victim.exists())
            self.assertFalse(state.exists())

    def test_finalize_silent_without_leg_b_failure(self):
        mod = _load_helper()
        with _scratch() as td:
            td = Path(td)
            ev, state = td / "ev", td / "state"
            ev.mkdir()
            state.mkdir()
            (state / "fail-rows").write_text("A\tleg a row\n", encoding="utf-8")
            buf = io.StringIO()
            mod.finalize(state, ev, TAIL_LINES, buf)
            self.assertEqual(buf.getvalue(), "")

    def test_tail_is_bounded_with_header(self):
        mod = _load_helper()
        with _scratch() as td:
            ev = Path(td)
            (ev / "bring-up.out").write_text(
                "".join("line %d\n" % i for i in range(1000)), encoding="utf-8"
            )
            buf = io.StringIO()
            mod.print_evidence(ev, ["bring-up.out", "absent.log"], TAIL_LINES, buf)
            text = buf.getvalue()
        self.assertIn("--- bring-up.out ---", text)
        self.assertIn("line 999", text)
        self.assertNotIn("line 799\n", text)
        self.assertIn("line 800", text)
        self.assertIn("absent.log", text)


class RedactorRound3(unittest.TestCase):
    """r3 (F1): one test per leak class (a)-(g); every secret is built at runtime."""

    PW = "Tr0ub" + "4dor" + "x9Qz"

    def test_a_passphrase_env_json_and_flag_forms(self):
        mod = _load_helper()
        forms = [
            "AI_MEMORY_DB_PASS" + "PHRASE=" + self.PW,
            '"db_pass' + 'phrase": "' + self.PW + '"',
            "--pass" + "phrase " + self.PW,
            "--pass" + "phrase=" + self.PW,
            "pass_" + "phrase: " + self.PW,
            "pw" + "d=" + self.PW,
            "pa" + "ss=" + self.PW,
            "cook" + "ie: " + self.PW,
            "session" + "id=" + self.PW,
            "sess" + "ion_id: " + self.PW,
            "cs" + "rf=" + self.PW,
            "au" + "th=" + self.PW,
            "creden" + "tials=" + self.PW,
            "creden" + "tial: " + self.PW,
        ]
        for ln in forms:
            self.assertNotIn(self.PW, mod.redact_line(ln), ln)

    def test_b_url_userinfo_with_raw_at_and_slash(self):
        mod = _load_helper()
        for pw in ("p@" + "ss" + "w0rd", "pa/" + "ss" + "w0rd", "a@b/" + "c@" + "dee"):
            ln = "dsn postgres://u:" + pw + "@h:5432/db"
            out = mod.redact_line(ln)
            self.assertNotIn(pw.split("@")[-1].split("/")[-1], out, ln)
            self.assertNotIn("ssw0rd", out, ln)
            self.assertIn("@h:5432/db", out)

    def test_c_escaped_quote_inside_quoted_value(self):
        mod = _load_helper()
        tail = "tail" + "Secret77"
        ln = '"val' + 'ue": "ab\\"cd' + tail + '"'
        self.assertNotIn(tail, mod.redact_line(ln.replace("val" + "ue", "pass" + "word")))
        ln2 = 'secret' + '="ab\\"cd' + tail + '" next'
        out = mod.redact_line(ln2)
        self.assertNotIn(tail, out)
        self.assertIn("next", out)

    def test_d_unicode_escaped_json_key(self):
        mod = _load_helper()
        for ln in ('{"\\u0070assword": "' + self.PW + '"}', '{"outer": {"pass\\u0077ord": "' + self.PW + '"}}',
                   'log "\\u0070assword": "' + self.PW + '"'):
            self.assertNotIn(self.PW, mod.redact_line(ln), ln)
        with _scratch() as td:
            doc = Path(td) / "doc.out"
            doc.write_text('{\n  "u": {\n    "\\u0070asswor\\u0064": "' + self.PW + '"\n  }\n}\n', encoding="utf-8")
            buf = io.StringIO()
            mod.print_evidence(Path(td), ["doc.out"], TAIL_LINES, buf)
        self.assertNotIn(self.PW, buf.getvalue())

    def test_e_base64_floor_is_32_and_hex_policy(self):
        mod = _load_helper()
        b32 = "Zm9v" * 8
        self.assertNotIn(b32, mod.redact_line("nonce " + b32))
        self.assertEqual(len(b32), 32)
        sha = "0123456789abcdef" * 2 + "01234567"
        self.assertEqual(len(sha), 40)
        self.assertEqual(mod.redact_line("commit " + sha), "commit " + sha)
        self.assertNotIn(HEX64, mod.redact_line("digest " + HEX64))
        self.assertEqual(mod.redact_line("31 chars " + "Zm9v" * 7 + "Zm9"), "31 chars " + "Zm9v" * 7 + "Zm9")

    def test_f_public_key_allowlist_is_value_span_only(self):
        mod = _load_helper()
        pk, sk = "AAAA" * 11, "Qm9i" * 11
        out = mod.redact_line("pub_b" + "64: " + pk + " sk: " + sk)
        self.assertIn(pk, out)
        self.assertNotIn(sk, out)
        out2 = mod.redact_line("pub" + "key: x " + HEX64)
        self.assertNotIn(HEX64, out2)

    def test_g_pem_state_survives_chunk_boundaries(self):
        mod = _load_helper()
        red = mod.Redactor()
        self.assertEqual(red.feed_line("before " + BEGIN), mod.REDACTED)
        self.assertEqual(red.feed_line("QUJDREVG"), mod.REDACTED)
        self.assertEqual(red.feed_line(END), mod.REDACTED)
        self.assertEqual(red.feed_line("after: plain"), "after: plain")
        red2 = mod.Redactor()
        got = red2.feed(BEGIN + "\nQUJDRE") + red2.feed("VG\nshort\n" + END + "\nok: 1\n") + red2.flush()
        self.assertEqual(got, [mod.REDACTED] * 4 + ["ok: 1"])

    def test_negative_git_sha_and_public_key_unchanged(self):
        mod = _load_helper()
        sha = "fedcba9876543210" * 2 + "fedcba98"
        ln = "pub_b" + "64: " + "AAAA" * 11 + " head " + sha
        self.assertEqual(mod.redact_line(ln), ln)
        self.assertEqual(mod.redact_line("path /srv/work/app/target/x"),
                         "path /srv/work/app/target/x")


class RedactorRound4(unittest.TestCase):
    """r4 (F1-r3): one test per leaked shape; every secret is built at runtime."""

    S = "Qx7Kp2" + "Lm9Zr4Tv8Wy3Bn6Hc1Dj5Fg0AaZ"
    BQ = "\\" + '"'
    # 16 chars: below the 32 LONG_B64 floor, so only the escaped-quote handling can mask it.
    SHORT = "".join(random.Random(7181).choice(string.ascii_letters + string.digits) for _ in range(16))

    def _red(self, line):
        return _load_helper().redact_line(line)

    def test_a_cookie_multi_pair_masked_to_end_of_line(self):
        s2 = "Uv3" + "Wx5Yz7Ab9Cd1Ef"
        out = self._red("Cookie: sid=%s; uid=%s; k=%s" % (self.S, s2, self.S))
        for sec in (self.S, s2):
            self.assertNotIn(sec, out)
        out = self._red("Set-Cookie: sid=%s; Path=/; k=%s" % (self.S, s2))
        self.assertNotIn(self.S, out)
        self.assertNotIn(s2, out)

    def test_c_rust_debug_nested_json_passphrase(self):
        b = self.BQ
        out = self._red('Error: "{%spassphrase%s: %s%s%s}"' % (b, b, b, self.SHORT, b))
        self.assertNotIn(self.SHORT, out)
        self.assertIn(_load_helper().REDACTED, out)

    def test_c_rust_debug_nested_json_db_password_no_space(self):
        b = self.BQ
        out = self._red('body="{%sdb_password%s:%s%s%s}"' % (b, b, b, self.SHORT, b))
        self.assertNotIn(self.SHORT, out)

    def test_c_unterminated_quoted_value_runs_to_end_of_line(self):
        tail = "Ta1l" + "Secret88"
        out = self._red('password: "%s %s' % (self.S, tail))
        self.assertNotIn(self.S, out)
        self.assertNotIn(tail, out)

    def test_a_flag_named_secret_in_list_render(self):
        flag = "--pass" + "phrase"
        short = "Tr0ub" + "4dor" + "x9Qz"
        for q in ('"', "'"):
            out = self._red("argv: [%s%s%s, %s%s%s]" % (q, flag, q, q, short, q))
            self.assertNotIn(short, out, q)
        out = self._red("args=[%s, %s]" % ('"' + flag + '"', '"' + short + '"'))
        self.assertNotIn(short, out)

    def test_e_lowercase_32_with_two_slashes_masked(self):
        run = "abcdefghij/klmnopqrst/uvwxyzabcd"
        self.assertEqual(len(run), 32)
        self.assertNotIn(run, self._red("x " + run))

    def test_e_48hex_token_inside_absolute_path_masked(self):
        tok = "ab12" * 12
        self.assertNotIn(tok, self._red("loaded /srv/hooks/" + tok))

    def test_e_32hex_token_inside_url_path_masked(self):
        tok = "cd34" * 8
        self.assertNotIn(tok, self._red("POST https://hooks.example.net/v1/hook/" + tok))

    def test_e_long_readable_key_dir_path_unchanged(self):
        ln = "key_dir: /home/runner/work/ai-memory-mcp/ai-memory-mcp/.local-runs/cert-bootstrap-evidence/witness/keys"
        self.assertEqual(self._red(ln), ln)

    def test_f2_mixed_case_std_base64_with_slash_under_root_masked_everywhere(self):
        mod = _load_helper()
        alpha = string.ascii_letters + string.digits
        rnd = random.Random(7182)
        left = "A" + "".join(rnd.choice(alpha) for _ in range(21))
        right = "".join(rnd.choice(alpha) for _ in range(20)) + "z"
        sec = left + "/" + right
        self.assertEqual(len(sec), 44)
        line = "key file /run/secrets/" + sec
        self.assertNotIn(sec, self._red(line))
        self.assertNotIn(left, self._red(line))
        with _scratch() as td:
            ev = Path(td) / "ev"
            ev.mkdir()
            (ev / "bring-up.out").write_text(line + "\n", encoding="utf-8")
            state = Path(td) / "state"
            state.mkdir()
            (state / "fail-rows").write_text("B\tprobe\n", encoding="utf-8")
            buf = io.StringIO()
            self.assertEqual(mod.finalize(state, ev, TAIL_LINES, buf), 0)
            self.assertNotIn(sec, buf.getvalue())
            out = Path(td) / "red"
            subprocess.run([sys.executable, str(HELPER), "--evidence-dir", str(ev),
                            "--write-redacted", str(out)], check=True, capture_output=True)
            blob = "".join(q.read_text(encoding="utf-8") for q in out.glob("*"))
            self.assertNotIn(sec, blob)
            self.assertNotIn(left, blob)

    def test_7207_key_equals_absolute_lowercase_path_unchanged(self):
        path = "/home/runner/work/ai-memory-mcp/ai-memory-mcp/.local-runs/cert-bootstrap-evidence/witness/keys"
        for key in ("key_dir", "AI_MEMORY_AUDIT_DIR"):
            ln = key + "=" + path
            self.assertEqual(self._red(ln), ln)

    def test_7207_key_equals_non_lowercase_path_value_still_masked(self):
        alpha = string.ascii_letters + string.digits
        sec = "Q" + "".join(random.Random(7207).choice(alpha) for _ in range(40))
        self.assertNotIn(sec, self._red("blob=" + sec))
        self.assertNotIn(sec, self._red("dir=/home/x/" + sec))
        self.assertNotIn(sec, self._red("dir=/run/" + sec[:20] + "/" + sec[20:]))

    def test_f_secret_joined_to_public_key_by_semicolon(self):
        pk = "AAAA" * 11
        out = self._red("pub_b" + "64=" + pk + ";signing_" + "key=" + self.S)
        self.assertIn(pk, out)
        self.assertNotIn(self.S, out)

    def test_f_secret_joined_to_public_key_by_comma(self):
        pk = "AAAA" * 11
        out = self._red("pub_b" + "64=" + pk + "," + self.S)
        self.assertIn(pk, out)
        self.assertNotIn(self.S, out)

    def test_finalize_path_masks_rust_debug_escaped_json(self):
        mod = _load_helper()
        b = self.BQ
        with _scratch() as td:
            ev = Path(td) / "ev"
            ev.mkdir()
            line = 'Error: "{%spassphrase%s: %s%s%s}"' % (b, b, b, self.SHORT, b)
            (ev / "bring-up.out").write_text(line + "\n", encoding="utf-8")
            state = Path(td) / "state"
            state.mkdir()
            (state / "fail-rows").write_text("B\tprobe\n", encoding="utf-8")
            buf = io.StringIO()
            self.assertEqual(mod.finalize(state, ev, TAIL_LINES, buf), 0)
        self.assertNotIn(self.SHORT, buf.getvalue())
        self.assertIn(mod.REDACTED, buf.getvalue())


class GateScriptPins(unittest.TestCase):
    def test_witness_recorder_generate_is_sandboxed_and_not_silenced(self):
        leg_b = _leg_b_text()
        for agent in ("audit-witness", "governance-recorder"):
            lines = [ln for ln in leg_b.splitlines() if "identity generate" in ln and agent in ln]
            self.assertEqual(len(lines), 1, agent)
            ln = lines[0]
            self.assertTrue(ln.lstrip().startswith("am_b "), "%s not run via am_b: %s" % (agent, ln))
            self.assertNotIn("/dev/null", ln, "%s output still silenced" % agent)
        for ln in leg_b.splitlines():
            if "identity generate" in ln:
                self.assertNotRegex(ln, r'^"\$BIN"', "bare unsandboxed identity generate: " + ln)

    def _wrapper(self, name):
        leg_b = _leg_b_text()
        m = re.search(r"^%s\(\) \{.*?\); \}$" % name, leg_b, re.S | re.M)
        self.assertIsNotNone(m, name)
        return m.group(0)

    def test_every_role_key_dir_is_explicit_in_each_sandbox_wrapper(self):
        for name in ("am_b", "am_d", "am_e"):
            body = self._wrapper(name)
            for env in ROLE_KEY_DIR_ENVS + SINK_DIR_ENVS:
                self.assertIn(env + "=", body, "%s lacks explicit %s" % (name, env))

    def test_f5_every_wrapper_unsets_full_env_list(self):
        for name in ("am_b", "am_d", "am_e"):
            body = self._wrapper(name) + " "
            for env in CLEARED_ENVS:
                self.assertIn("-u " + env + " ", body, "%s does not unset %s" % (name, env))

    def test_work_dirs_are_cleaned_by_exit_trap(self):
        text = GATE.read_text(encoding="utf-8")
        gate_body = text[text.rindex("EVIDENCE_DIR=") :]
        self.assertRegex(gate_body, r"trap\s+.*EXIT")
        self.assertIn("cert_gate_evidence.py", gate_body)

    def test_leg_b_failure_prints_evidence_via_python_finalize(self):
        text = GATE.read_text(encoding="utf-8")
        self.assertIn("--finalize", text)
        self.assertIn("--tail", text)

    def test_f3_tmpdir_pinned_under_repo_before_first_mktemp(self):
        text = GATE.read_text(encoding="utf-8")
        export = text.index("export TMPDIR=")
        self.assertIn(".local-runs/tmp", text[export : export + 160])
        self.assertLess(export, text.index("mktemp"))
        self.assertIn("chmod 700", text[export : export + 320])

    def test_f4_no_shell_control_flow_for_cleanup(self):
        text = GATE.read_text(encoding="utf-8")
        for name in ("CLEANUP_PATHS", "LEGB_FAILED", "IN_LEG_B", "cleanup_and_report"):
            self.assertNotIn(name, text)
        traps = [ln for ln in text.splitlines() if ln.lstrip().startswith("trap ") and "--finalize" in ln]
        self.assertEqual(len(traps), 1)
        self.assertEqual(traps[0].count("cert_gate_evidence.py"), 1)


class WorkflowUploadsEvidence(unittest.TestCase):
    def test_artifact_upload_on_failure_is_pinned_and_redacted_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, PINNED_UPLOAD)
        block = text[text.rindex("      - name:", 0, text.index("actions/upload-artifact")) :]
        block = block[: block.index("retention-days")]
        self.assertIn("if: failure()", block)
        self.assertIn(REDACTED_DIR, block)
        self.assertNotRegex(block, r"\.local-runs/cert-bootstrap-evidence(?!-redacted)")

    def test_redacted_copy_is_made_before_upload(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("--write-redacted " + REDACTED_DIR, text)
        self.assertLess(text.index("--write-redacted"), text.index("actions/upload-artifact"))


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
