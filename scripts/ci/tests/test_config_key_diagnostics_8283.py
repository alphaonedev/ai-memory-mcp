# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#8283: config permission-test assertions must not format key-derived values."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "src/config.rs"
LLM_TEST = "resolve_llm_1146_api_key_file_rejects_lax_perms"
EMBED_TEST = "resolve_embed_api_key_1598_api_key_file_rejects_lax_perms"
# A literal without format placeholders and without trailing format arguments.
CONSTANT_MESSAGE = r'"[^"{}\\]*"\s*,?\s*\);'


class ConfigKeyDiagnostics8283Tests(unittest.TestCase):
    def function_body(self, name):
        source = CONFIG.read_text()
        match = re.search(
            r"^    fn " + re.escape(name) + r"\(\) \{\n(.*?)^    \}",
            source, re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, "permission regression test must exist")
        return match.group(1)

    def test_8283_llm_permission_reason_is_not_formatted(self):
        body = self.function_body(LLM_TEST)
        pattern = (
            r'assert!\(\s*reason\.contains\("lax permissions"\)\s*&&\s*'
            r'reason\.contains\("0400"\)\s*,\s*' + CONSTANT_MESSAGE
        )
        self.assertTrue(bool(re.search(pattern, body)),
                        "LLM permission assertion must use a constant diagnostic")

    def test_8283_embeddings_permission_reason_is_not_formatted(self):
        body = self.function_body(EMBED_TEST)
        pattern = (
            r'assert!\(\s*reason\.contains\("\[embeddings\]\.api_key_file"\)\s*&&\s*'
            r'reason\.contains\("lax"\)\s*,\s*' + CONSTANT_MESSAGE
        )
        self.assertTrue(bool(re.search(pattern, body)),
                        "embeddings permission assertion must use a constant diagnostic")

    def test_8283_embeddings_key_absence_is_a_boolean_assertion(self):
        body = self.function_body(EMBED_TEST)
        pattern = (
            r'assert!\(\s*resolved\.api_key\(\)\.is_none\(\)\s*,\s*'
            + CONSTANT_MESSAGE
        )
        self.assertTrue(bool(re.search(pattern, body)),
                        "key absence assertion must not format the resolved key")


if __name__ == "__main__":
    unittest.main()
