# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The one source of the host-slot wait limit (#9231).

scripts/ci/host_semaphore.py refuses, at run time, any wait above IDLE_SEAT_CEILING_SECS whatever its
source (the flag, a repeated flag, the HOST_SEMAPHORE_MAX_WAIT_SECS environment key), and
scripts/ci/host_slots_check.py refuses a workflow bound above it. Both read this value; no other file
holds it (scripts/ci/tests/test_slot_wait_outcome_9231.py OneConstant pins that).

A waiting job holds a runner seat idle for the whole wait. A slot hold lasts about 2 h, so a wait only
bridges a slot handover or a non-CI holder; 15 minutes is the most idle seat time one wait may cost.
"""

IDLE_SEAT_CEILING_SECS = 900
