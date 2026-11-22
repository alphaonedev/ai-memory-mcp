# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The one source of the host-slot wait limit and of the wait value grammar (#9231).

scripts/ci/host_semaphore.py refuses, at run time, any wait above IDLE_SEAT_CEILING_SECS whatever its
source (the flag, a repeated flag, the HOST_SEMAPHORE_MAX_WAIT_SECS environment key), and
scripts/ci/host_slots_check.py refuses a workflow bound above it. Both read this value; no other file
holds it (the OneConstant test of #9231 pins that).

A waiting job holds a runner seat idle for the whole wait. A slot hold lasts about 2 h, so a wait only
bridges a slot handover or a non-CI holder; 15 minutes is the most idle seat time one wait may cost.

PLAIN_DECIMAL_PATTERN is the one grammar of a wait value, used with re.fullmatch by both scripts: ASCII
digits only (int() also takes " 9", "+9", "9_0" and non-ASCII digits such as Devanagari or Arabic-Indic),
no sign and no leading zero ("0900" and "007" are refused; "0" matches and is then refused as zero).

no_duplicate_keys is the one json object_pairs_hook of both readers of host_slots.json: a key given twice in
one object raises DuplicateKeyError (a ValueError), so a repeated gate or runner list is a refusal, never
"the last one wins" (#9851).
"""

IDLE_SEAT_CEILING_SECS = 900
PLAIN_DECIMAL_PATTERN = '0|[1-9][0-9]*'


class DuplicateKeyError(ValueError):
    """A JSON object of the slot configuration gives one key more than once."""


def no_duplicate_keys(pairs):
    """json object_pairs_hook: the dict of PAIRS, or DuplicateKeyError when a key repeats (the key is not shown)."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError('duplicate key')
        result[key] = value
    return result
