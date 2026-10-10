#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Execute the LAN runner ownership/dual-pass regression corpus (#7031, #7086).

Run: python3 -I scripts/test/test_lan_parity_pass1_ephemeral_7031.py
The commands are inert stand-ins; native campaign evidence is recorded separately.
"""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEST_MODULE = ROOT / 'scripts' / 'ci' / 'tests' / 'test_lan_parity_runner_7086.py'
SPEC = importlib.util.spec_from_file_location('lan_parity_runner_controls', TEST_MODULE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('LAN runner regression module could not be loaded')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
LanParityRunner7086 = MODULE.LanParityRunner7086

if __name__ == '__main__':
    unittest.main()
