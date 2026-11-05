"""Exercise the docs home-path guard and byte-preserving repair (#8493).

Every future review finding adds a grammar axis to the independent shape helper.
"""

import importlib.util
import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Resolve the sibling from this file, including isolated discovery and a tests-directory cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from docs_private_path_shapes_8493 import shapes

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts/ci/check_docs_private_paths.py"
SCRATCH = REPO / ".local-runs/redaction/tests"
DOC = "docs/nested/record.md"
PLACEHOLDER = b"<home>"


class DocsPrivatePaths(unittest.TestCase):
    """Run the real CLI against isolated documentation trees."""

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "docs private-path gate must exist")
        SCRATCH.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.doc = self.root / DOC
        self.doc.parent.mkdir(parents=True)
        self.exceptions = self.root / "exceptions.json"
        self.exceptions.write_text('{"exceptions": []}')

    def run_gate(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root),
             "--exceptions-file", str(self.exceptions), *args],
            capture_output=True, text=True, check=False,
        )

    def assert_repairs(self, rows):
        for before, after in rows:
            with self.subTest(before=before):
                self.doc.write_text(before)
                self.assertEqual(self.run_gate().returncode, 1)
                self.assertEqual(self.run_gate("--fix").returncode, 0)
                self.assertEqual(self.doc.read_bytes(), after.encode())
                self.assertEqual(self.run_gate().returncode, 0)

    def test_url_internal_punctuation_r6(self):
        for punctuation in "+:@;=!$&*?#":
            with self.subTest(punctuation=punctuation):
                text = "https://host/a" + punctuation + "b/home/private_account/x\n"
                self.doc.write_text(text)
                self.assertEqual(self.run_gate().returncode, 0)
                self.assertEqual(self.run_gate("--fix").returncode, 0)
                self.assertEqual(self.doc.read_text(), text)

    def test_switch_adjacent_relative_roots_r6(self):
        self.assert_repairs((
            ("gcc -Ihome/private_account/inc", "gcc -I<home>/inc"),
            ("ld -LUsers/private_account/lib", "ld -L<home>/lib"),
            ("gcc -Ivar/home/private_account/inc", "gcc -I<home>/inc"),
        ))

    def test_non_web_schemes_r6(self):
        self.assert_repairs(tuple(
            (scheme + "://host/home/private_account/x", scheme + "://host<home>/x")
            for name in ("ssh", "sftp", "rsync", "git+ssh", "scp", "smb", "nfs",
                         "git+http", "git+https")
            for scheme in (name, name.upper())
        ))

    def test_url_illegal_terminators_r7(self):
        terminators = "".join(map(chr, range(32))) + "\x7f\u200b\u200c\u200d\ufeff<>`|\\^{}"
        self.assert_repairs(tuple(
            ("https://host/a" + char + "/home/private_account/x",
             "https://host/a" + char + "<home>/x")
            for char in terminators
        ))

    def test_remote_authority_survives_r7(self):
        self.assert_repairs(tuple(
            ("ssh://" + authority + "/home/private_account/x",
             "ssh://" + authority + "<home>/x")
            for authority in ("host", "user@host", "host:22", "user@host:22", "")
        ))

    def test_generic_relative_switches_r7(self):
        self.assert_repairs(tuple(
            ("gcc " + switch + root + "private_account/i", "gcc " + switch + "<home>/i")
            for switch in ("-isystem", "-iquote", "-idirafter", "-F")
            for root in ("home/", "Users/", "./home/", "../home/", "var/home/", "mnt/c/Users/")
        ))

    def test_raw_home_pairs_survive_parent_segments_r5(self):
        self.assert_repairs((
            ("/home/private_account/..", "<home>/.."),
            ("x/../home/private_account/..", "<home>/.."),
            ("/Users/private_account/../..", "<home>/../.."),
        ))

    def test_url_adjacent_and_bare_domain_paths_r5(self):
        self.assert_repairs((
            ("https://example.test/a,/home/private_account/x",
             "https://example.test/a,<home>/x"),
            ("https://example.test/a]/Users/private_account/x",
             "https://example.test/a]<home>/x"),
            ("notes.md/home/private_account/x", "<home>/x"),
        ))

    def test_file_scheme_case_r5(self):
        self.assert_repairs((
            ("FILE:///home/private_account/x", "FILE://<home>/x"),
            ("File:///Users/private_account/x", "File://<home>/x"),
        ))

    def test_file_scheme_slash_count_r5(self):
        self.assert_repairs((
            ("file:/home/private_account/x", "file:<home>/x"),
            ("file:home/private_account/x", "file:<home>/x"),
        ))

    def test_compiler_option_prefix_survives_r5(self):
        self.assert_repairs((
            ("gcc -I/home/private_account/include", "gcc -I<home>/include"),
            ("ld -L/Users/private_account/lib", "ld -L<home>/lib"),
            ("gcc -I../home/private_account/include", "gcc -I<home>/include"),
            ("ld -Lname.ext/home/private_account/lib", "ld -L<home>/lib"),
        ))

    def test_generated_prefix_invariants_r5(self):
        spec = importlib.util.spec_from_file_location("private_path_gate_r5", SCRIPT)
        gate = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = gate
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(gate)
        allowed = gate.allowed_names(gate.DEFAULT_ALLOW_FILE)
        for case in shapes():
            with self.subTest(shape=case.label):
                matches, used = gate.findings(case.text, allowed)
                self.assertFalse(used)
                actual = tuple((item.start, item.end) for item in matches)
                self.assertEqual(actual, case.spans)
                repaired = gate.redact(case.text, matches)
                self.assertEqual(repaired.encode(), case.repaired().encode())
                self.assertEqual(gate.findings(repaired, allowed), ([], set()))

    def test_nested_normalized_home_roots_r4(self):
        roots = ("/var/home", "/usr/home", "/export/home", "/mnt/c/Users",
                 "/System/Volumes/Data/Users", "../home", "local/home",
                 "/var/./home", "/var/other/../home", "/home/./",
                 "/home/removed/../")
        for root in roots:
            with self.subTest(root=root):
                self.doc.write_text(root.rstrip("/") + "/private_account/file\n")
                self.assertEqual(self.run_gate().returncode, 1)
                self.assertEqual(self.run_gate("--fix").returncode, 0)
                self.assertEqual(self.doc.read_text(), "<home>/file\n")
                self.assertEqual(self.run_gate().returncode, 0)

    def test_diagnostics_never_echo_matched_account_r4(self):
        self.doc.write_text("/home/private_account/file\n~private_account\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("private_account", result.stdout + result.stderr)
        self.assertIn(DOC + ":1: private-home-prefix", result.stdout)
        self.assertIn(DOC + ":2: private-home-prefix", result.stdout)

    def test_nested_named_home_spans_merge_without_residue_r4(self):
        self.doc.write_text("~private_account/home/second_private/file\n")
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_text(), "<home>/file\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_escaped_and_invisible_account_is_fully_redacted_r4(self):
        names = (r"private\_account", "private\u200baccount", "private\u200caccount",
                 "private\u200daccount", "private\ufeffaccount", "private_account\u200b",
                 "private\\\u200b_account")
        for name in names:
            for root in ("/home/", "~", "/var/home/"):
                with self.subTest(root=root, name=name):
                    self.doc.write_text(root + name + "/file\n")
                    self.assertEqual(self.run_gate().returncode, 1)
                    self.assertEqual(self.run_gate("--fix").returncode, 0)
                    self.assertEqual(self.doc.read_text(), "<home>/file\n")
                    self.assertEqual(self.run_gate().returncode, 0)

    def test_shell_fence_languages_are_case_insensitive_r4(self):
        for language in ("Bash", "SH", "Console", "ZsH", "Shell"):
            with self.subTest(language=language):
                self.doc.write_text(f"```{language}\n~private_account\n```\n")
                self.assertEqual(self.run_gate().returncode, 1)

    def test_historical_install_owner_and_group_are_placeholders_r4(self):
        relative = ("docs/v0.7.0/test-campaign-2026-05-22-release-gate-final/"
                    "track-a-build-install-results.md")
        rows = [line.split() for line in (REPO / relative).read_text().splitlines()
                if line.startswith("lrwx")]
        self.assertTrue(rows, "the historical install listing must remain present")
        for fields in rows:
            self.assertEqual(fields[2:4], ["<user>", "<user>"])

    def test_linux_path_reports_file_line_and_class(self):
        self.doc.write_bytes(b"header\n/home/private_account/project/file\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(DOC + ":2: private-home-prefix", result.stdout)

    def test_macos_path_is_rejected(self):
        self.doc.write_bytes(b"`/Users/private_account/project`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_url_home_segment_is_preserved_r2(self):
        content = (b"https://example.com/news/home/20240716489550/en/story\n"
                   b"https://example.com/Users/private_account/story\n"
                   b"[source](https://example.com/news/home/2024/en/a)\n")
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_sentence_period_survives_prefix_replacement_r3(self):
        self.doc.write_bytes(b"in /home/private_account. and ~private_account.\n")
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), b"in <home>. and <home>.\n")

    def test_generic_names_before_period_are_preserved_r3(self):
        content = b"use /home/user. or /Users/aimem. or ~user.\n"
        self.doc.write_bytes(content)
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_prose_estimate_before_period_is_preserved_r3(self):
        content = b"takes ~seconds.\n"
        self.doc.write_bytes(content)
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_dotted_account_keeps_only_sentence_period_r3(self):
        self.doc.write_bytes(b"in /home/private.account. and ~private.account.\n")
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), b"in <home>. and <home>.\n")

    def test_colon_path_list_is_rejected_r3(self):
        self.doc.write_bytes(b"PATH=/bin:/home/private_account/bin\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_scp_home_is_rejected_r3(self):
        self.doc.write_bytes(b"scp node:/home/private_account/file destination\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_docker_mount_home_is_rejected_r3(self):
        self.doc.write_bytes(b"docker -v data:/home/private_account app\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_local_file_url_is_rejected_and_prefix_only_r3(self):
        self.doc.write_bytes(b"file:///home/private_account/file\n")
        self.assertEqual(self.run_gate().returncode, 1)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), b"file://<home>/file\n")

    def test_image_account_is_preserved_r2(self):
        content = (b"mountPath: /home/aimem/.config/ai-memory\n"
                   b"HOME=/home/aimem\n~aimem/.config/ai-memory\n")
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_illustrative_accounts_are_preserved_r2(self):
        content = (b"/home/u/record /home/op/record /Users/operator/record\n"
                   b"`~u` `~op` `~operator`\n")
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_sanitization_overlap_examples_are_preserved_r2(self):
        content = b"sensitive value (`/home/a` inside `/home/ab`)\n"
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_no_tail_absolute_home_in_prose_is_rejected_r2(self):
        self.doc.write_bytes(b"home /home/private_account and done\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("private-home-prefix", result.stdout)

    def test_no_tail_absolute_home_in_inline_code_is_rejected_r2(self):
        self.doc.write_bytes(b"home `/home/private_account`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_no_tail_macos_home_at_end_is_rejected_r2(self):
        self.doc.write_bytes(b"/Users/private_account")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_absolute_home_delimiters_preserved_r2(self):
        content = b"(/home/private_account), '/Users/private_account'; done\n"
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), b"(<home>), '<home>'; done\n")

    def test_bare_named_home_in_prose_is_rejected_r2(self):
        self.doc.write_bytes(b"home ~private_account and done\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_prose_approximation_has_no_code_exemption_r2(self):
        self.doc.write_bytes(b"home `~minutes`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_prose_approximation_has_no_path_exemption_r2(self):
        self.doc.write_bytes(b"home ~minutes/project\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_all_prose_approximations_require_code_and_path_checks_r2(self):
        names = (
            "Memory", "minutes", "seconds", "milliseconds", "tens", "LINEAR",
            "line", "all", "half-day", "loader-capped", "buildable", "CPU",
            "halved", "v78", "loader", "Peer",
        )
        for name in names:
            for content in (f"`~{name}`\n", f"```sh\n~{name}\n```\n",
                            f"~{name}/project\n"):
                with self.subTest(name=name, content=content):
                    self.doc.write_text(content)
                    self.assertEqual(self.run_gate().returncode, 1)

    def test_prose_approximation_matches_whole_token_r2(self):
        self.doc.write_bytes(b"home ~minutes_extra and done\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_named_tilde_home_is_rejected(self):
        self.doc.write_bytes(b"`~private_account/project`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_bare_named_home_in_inline_code_is_rejected(self):
        self.doc.write_bytes(b"home: `~private_account`\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_bare_named_home_in_shell_fences_is_rejected(self):
        for language in ("", "sh", "bash", "zsh", "shell", "console"):
            with self.subTest(language=language):
                self.doc.write_text(f"```{language}\n~private_account\n```\n")
                self.assertEqual(self.run_gate().returncode, 1)

    def test_non_shell_fences_are_not_inline_code(self):
        content = b"```python\n# `~private_account` is a string example\n```\n"
        self.doc.write_bytes(content)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_inline_delimiter_width_and_multiline_span(self):
        self.doc.write_bytes(b"``literal ` then\n~private_account``\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn(DOC + ":2: private-home-prefix", result.stdout)

    def test_tilde_fence_and_longer_fence(self):
        self.doc.write_bytes(b"~~~~bash\n~~~\n~private_account\n~~~~\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_numeric_and_prose_approximations_are_preserved(self):
        content = ("~Memory ~minutes ~seconds ~milliseconds ~tens ~LINEAR\n"
                   "~line ~all ~half-day ~loader-capped ~buildable ~CPU\n"
                   "~halved ~v78 ~loader ~Peer\n"
                   "~1400 ~4.0 ~0.5 ~10% ~135 ~30% ~4× ~5%→~40%\n"
                   "ratios ~52/90 ~1-2ms/request; `~20/second`\n"
                   "bare ~/ and generic ~alice/ remain\n").encode()
        self.doc.write_bytes(content)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_unicode_numeric_approximations_are_preserved_r2(self):
        content = "ratios ~⅓ ~½ ~Ⅳ; `~⅓` and `~½/second`\n".encode()
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_sixteen_historical_prose_lines_are_unchanged(self):
        fixture = Path(__file__).with_name("fixtures") / "docs-private-paths-prose-8493.json"
        rows = json.loads(fixture.read_text())
        content = "\n".join(row["text"] for row in rows).encode()
        self.doc.write_bytes(content)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), content)

    def diagram_fixture(self):
        lines = [
            "   tier 0 → tier 1: async logical repl, ~minutes lag, durable",
            "   tier 1 → tier 2: streaming repl, ~seconds lag",
            "   tier 2 → tier 3: federation push, ~milliseconds (intra-zone)",
        ]
        self.doc = self.root / "docs/reference-architectures.md"
        content = "\n" * 484 + "```\n" + "\n".join(lines) + "\n```\n"
        self.doc.write_text(content)
        entries = [{"path": "docs/reference-architectures.md", "line": number,
                    "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    "reason": "fixture: estimates not account names"}
                   for number, text in enumerate(lines, 486)]
        return content.encode(), entries

    def test_three_diagram_lines_pass_only_with_exception_file(self):
        content, entries = self.diagram_fixture()
        self.assertEqual(self.run_gate().returncode, 1)
        self.exceptions.write_text(json.dumps({"exceptions": entries}))
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exceptions_used=3 exceptions_unused=0", result.stdout)
        self.assertEqual(self.doc.read_bytes(), content)
        self.exceptions.unlink()
        self.assertEqual(self.run_gate().returncode, 2)

    def test_altered_diagram_line_fails_closed_without_fixing(self):
        content, entries = self.diagram_fixture()
        self.exceptions.write_text(json.dumps({"exceptions": entries}))
        altered = content.replace(b"~minutes lag", b"~minutes extra lag")
        self.doc.write_bytes(altered)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("exceptions_used=2 exceptions_unused=1", result.stdout)
        self.assertEqual(self.doc.read_bytes(), altered)

    def test_unused_exception_fails(self):
        _, entries = self.diagram_fixture()
        self.exceptions.write_text(json.dumps({"exceptions": entries}))
        self.doc.write_bytes(b"safe\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("exceptions_used=0 exceptions_unused=3", result.stdout)

    def test_exception_hash_mismatch_is_usage_error(self):
        _, entries = self.diagram_fixture()
        entries[0]["sha256"] = "0" * 64
        self.exceptions.write_text(json.dumps({"exceptions": entries}))
        self.assertEqual(self.run_gate().returncode, 2)

    def test_exception_cannot_allow_same_name_at_another_location(self):
        _, entries = self.diagram_fixture()
        self.exceptions.write_text(json.dumps({"exceptions": entries}))
        with self.doc.open("a") as stream:
            stream.write("\n`~minutes`\n~seconds/private\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("exceptions_used=3 exceptions_unused=0", result.stdout)

    def test_new_private_path_turns_clean_fixture_red(self):
        self.doc.write_bytes(b"safe <home>/project\n")
        self.assertEqual(self.run_gate().returncode, 0)
        with self.doc.open("ab") as stream:
            stream.write(b"~new_private_account/project\n")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_generic_placeholders_are_preserved(self):
        content = (b"/home/user/project /Users/alice/project ~bob/project "
                   b"<home>/project $HOME/project ~/project\n")
        self.doc.write_bytes(content)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), content)

    def test_fix_changes_only_prefix_bytes_and_is_idempotent(self):
        content = (b"# historical record\r\n\xff /home/private_account/a  \r\n"
                   b"/Users/private_account/b ~private_account/c\nlast byte")
        self.doc.write_bytes(content)
        expected = content.replace(b"/home/private_account", PLACEHOLDER)
        expected = expected.replace(b"/Users/private_account", PLACEHOLDER)
        expected = expected.replace(b"~private_account", PLACEHOLDER)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.doc.read_bytes(), expected)
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertEqual(self.run_gate("--fix").returncode, 0)
        self.assertEqual(self.doc.read_bytes(), expected)

    def test_allow_file_is_data_and_matches_whole_names(self):
        allow = self.root / "allow.json"
        allow.write_text(json.dumps({"allowed_names": ["fixture_account"]}))
        self.doc.write_bytes(b"/home/fixture_account/a\n/home/fixture_account_extra/b\n")
        result = self.run_gate("--allow-file", str(allow))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(DOC + ":1:", result.stdout)
        self.assertIn(DOC + ":2:", result.stdout)

    def test_bad_allow_file_refuses(self):
        allow = self.root / "allow.json"
        allow.write_text('{"allowed_names": "anything"}')
        self.doc.write_bytes(b"safe\n")
        result = self.run_gate("--allow-file", str(allow))
        self.assertEqual(result.returncode, 2)
        self.assertIn("allowed_names", result.stderr)

    def test_markdown_below_docs_only(self):
        self.doc.write_bytes(b"safe\n")
        (self.root / "outside.md").write_bytes(b"/home/private_account/a\n")
        (self.doc.parent / "data.txt").write_bytes(b"/home/private_account/b\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_symlink_is_refused_without_writing_target(self):
        target = self.root / "outside.md"
        content = b"/home/private_account/a\n"
        target.write_bytes(content)
        self.doc.symlink_to(target)
        result = self.run_gate("--fix")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(target.read_bytes(), content)

    def test_directory_symlink_is_refused(self):
        self.doc.write_bytes(b"safe\n")
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "docs/linked").symlink_to(outside, target_is_directory=True)
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
