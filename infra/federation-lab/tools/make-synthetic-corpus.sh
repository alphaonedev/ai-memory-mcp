#!/usr/bin/env bash
# =============================================================================
# tools/make-synthetic-corpus.sh — generate the COMMITTED synthetic fixture.
# =============================================================================
# `sample/lab-corpus.json` is the corpus the lab loads by default. Every row of
# it is SYNTHETIC: deterministically generated, obviously fictional prose about
# an invented freight cooperative on an invented coastline. Nothing in it is
# derived from, or paraphrased from, any real corpus, document or dataset.
#
# WHY SYNTHETIC, AND NOT A SLICE OF A REAL CORPUS. This repository is PUBLIC.
# Committing a verbatim slice of a real third-party corpus is redistribution of
# that corpus, whatever its size and whether or not the embedding vectors ride
# along — and it republishes someone else's text, attribution-free, under this
# project's name. It also drags whatever identifiers the source rows happened
# to carry (an internal `metadata.agent_id`, a `version_vector` keyed by the
# generating machine's hostname) into a public artifact. Synthetic fixtures are
# this repo's house standard for committed data for exactly these reasons; see
# PR #2926, which re-minted the golden/conformance vectors from synthetic
# identities. To exercise the lab against a REAL corpus, use
# `tools/make-local-slice.sh` + `run.sh --corpus-db`, which keeps that corpus
# on your machine and out of git.
#
# DETERMINISM. Every field is written here — ids are UUIDv5 over a fixed
# namespace and the row index, timestamps are a fixed constant, and the row
# vocabulary is drawn with a seeded PRNG. Re-running reproduces the committed
# file byte-for-byte, so a reviewer can regenerate and `diff` rather than trust
# the artifact. There is no hostname, no machine identity, no wall-clock
# anywhere in the output.
#
# The rows are stamped `tier = "long"` (permanent, no TTL) for the reason
# documented at length in tools/make-local-slice.sh: a fixture carrying a
# write-time TTL imports ALREADY EXPIRED once it is a couple of weeks old —
# present in `memories`, invisible to recall, archived by the next gc tick.
#
# USAGE
#   tools/make-synthetic-corpus.sh                  # regenerate the committed fixture
#   tools/make-synthetic-corpus.sh --rows 300 --out /tmp/elsewhere.json
#
# Requires: python3 and jq. A lab USER never runs this — the fixture is
# committed. It exists so the fixture is reproducible and reviewable, not
# because anyone needs to build it.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"

ROWS="${ROWS:-300}"
NAMESPACE="${NAMESPACE:-lab-corpus}"
OUT="${OUT:-$LAB/sample/lab-corpus.json}"

while [ $# -gt 0 ]; do
  case "$1" in
    --rows)      ROWS="$2";      shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --out)       OUT="$2";       shift 2 ;;
    -h|--help)   sed -n '2,45p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo "python3 is required to regenerate the fixture" >&2; exit 1; }
command -v jq      >/dev/null || { echo "jq is required" >&2; exit 1; }
case "$ROWS" in *[!0-9]* | "") echo "refusing non-numeric --rows: $ROWS" >&2; exit 2 ;; esac

mkdir -p "$(dirname "$OUT")"

ROWS="$ROWS" NAMESPACE="$NAMESPACE" python3 - > "$OUT" <<'PY'
"""Deterministic synthetic knowledge-atom corpus for the federation lab.

Emits the same envelope `ai-memory export` emits (memories + links + the
in-band scope markers), so `ai-memory import` consumes it unchanged.

Everything below is invented. The setting is a fictional freight cooperative
("the Kestrel Reach") on a fictional coastline. Any resemblance to a real
place, organisation or dataset would be a coincidence — the vocabulary was
chosen precisely so that it could not be mistaken for real-world commentary.
"""

import hashlib
import json
import os
import random
import uuid

ROWS = int(os.environ["ROWS"])
NAMESPACE = os.environ["NAMESPACE"]

# Fixed so the artifact is byte-reproducible. Not a real instant of anything;
# it is simply a constant, chosen to be unambiguous when read.
STAMP = "2020-01-01T00:00:00+00:00"
# Fixed UUIDv5 namespace: ids depend only on the row index, never on the clock.
ID_NS = uuid.UUID("6f0f5f2e-1c3a-5a7d-9b21-000000000001")

SETTLEMENTS = [
    "Ambervale", "Tessin Hollow", "Draymoor Flats", "Sable Crossing",
    "Norrin Shelf", "Quillhaven", "Marrow Bay", "Fenwick Verge",
    "Otterlin", "Pale Harbour", "Little Cassock", "Wrenmoor",
    "Halloway Sound", "Bittern Reach", "Coldkiln", "Saltmarch",
]

SUBJECTS = [
    ("ballast scheduling", "ballast"),
    ("kiln rotation", "kilns"),
    ("tide-lock windows", "tide-locks"),
    ("lattice courier routing", "couriers"),
    ("moss-silk harvest quotas", "moss-silk"),
    ("relay beacon upkeep", "beacons"),
    ("ferry draft limits", "ferries"),
    ("glasswork firing orders", "glasswork"),
    ("granary rotation", "granaries"),
    ("dock-crane pairing", "cranes"),
    ("cable-ferry tension", "cable-ferries"),
    ("pilot-boat rostering", "pilot-boats"),
    ("brine-pump maintenance", "brine-pumps"),
    ("lamp-oil rationing", "lamp-oil"),
    ("hull-scrape intervals", "hull-scrape"),
    ("weather-mast readings", "weather-masts"),
]

# Every entry must read grammatically when followed by one of OBJECTS, which
# are all noun phrases — so these are all verb phrases ending in a preposition
# or taking a direct object.
VERBS = [
    "should be staggered across", "must be renegotiated around",
    "collapses without", "is the binding constraint on",
    "quietly determines", "cannot be planned independently of",
    "reliably outperforms a fixed schedule during", "degrades gracefully under",
    "is routinely underestimated during", "sets the practical ceiling on",
]

OBJECTS = [
    "the shoulder season", "a two-crew rotation", "the spring freshet",
    "the winter embargo", "an understaffed night shift",
    "the shared crane pool", "a single-berth harbour",
    "the cooperative's ledger cycle", "the apprentice intake",
    "an unlit approach channel", "the quarterly audit",
    "a saturated relay chain",
]

CONSEQUENCES = [
    "Crews that ignore this discover it at the worst possible moment, when the "
    "only remaining option is to idle a full berth for a tide.",
    "The cost is invisible in the monthly totals and obvious in the weekly "
    "ones, which is why it survives so long unnoticed.",
    "Two neighbouring settlements solved this in opposite ways and both "
    "report success, which suggests the constraint is local rather than "
    "universal.",
    "The failure mode is not a shortage but a queue: nothing is missing, "
    "everything is simply late by the same margin.",
    "It is cheaper to over-provision here than to recover from a single "
    "missed window, and the cooperative's ledgers bear this out.",
    "Nobody writes this down, so every new harbourmaster rediscovers it in "
    "their first difficult season.",
    "The rule holds until the channel silts, after which the opposite rule "
    "holds just as firmly.",
    "Attempts to centralise the decision have all been abandoned within two "
    "seasons, for reasons the abandonment notices never record.",
]

IMPLICATIONS = [
    "plan the constraint first and let the schedule follow, rather than the "
    "reverse",
    "measure the queue, not the inventory, when deciding whether to intervene",
    "treat a neighbour's working practice as evidence about their harbour, "
    "not about yours",
    "budget for the recovery, not merely for the operation",
    "write the reasoning down where the next harbourmaster will find it",
    "prefer the reversible arrangement even when the irreversible one is "
    "cheaper this season",
    "re-derive the rule after any change to the channel, never carry it "
    "forward untested",
    "keep the decision with the crew that bears its consequences",
]

KINDS = ["principle", "tactic", "constraint", "observation"]

TITLE_LEAD = [
    "Stagger", "Re-cut", "Hold", "Rebalance", "Retire", "Pair", "Split",
    "Defer", "Front-load", "Cap", "Publish", "Devolve",
]

rng = random.Random(20260815)

memories = []
for i in range(ROWS):
    settlement = rng.choice(SETTLEMENTS)
    subject, tag = rng.choice(SUBJECTS)
    verb = rng.choice(VERBS)
    obj = rng.choice(OBJECTS)
    consequence = rng.choice(CONSEQUENCES)
    implication = rng.choice(IMPLICATIONS)
    kind = rng.choice(KINDS)
    lead = rng.choice(TITLE_LEAD)

    title = f"{lead} {subject} at {settlement}"
    # Disambiguate the (title, namespace) upsert key without making the title
    # look machine-generated to a reader skimming the fixture.
    title = f"{title} ({i + 1:03d})"

    content = (
        f"At {settlement}, {subject} {verb} {obj}. {consequence}\n\n"
        f"Why it matters: {implication}."
    )

    mid = str(uuid.uuid5(ID_NS, f"{NAMESPACE}/{i}"))
    # A content id in the substrate's `b3:<hex>` shape. The lab never verifies
    # it against a real BLAKE3 digest (CID_ENFORCE is warn-enforced), but a
    # deterministic well-formed value is better than a null.
    cid = "b3:" + hashlib.sha256(f"{mid}\n{content}".encode()).hexdigest()

    memories.append({
        "id": mid,
        "tier": "long",
        "namespace": NAMESPACE,
        "title": title,
        "content": content,
        "tags": ["lab-corpus", tag, f"kind:{kind}"],
        "priority": 5,
        "confidence": 1,
        "source": "api",
        "access_count": 0,
        "created_at": STAMP,
        "updated_at": STAMP,
        "metadata": {
            # Marked synthetic IN THE ARTIFACT, so a row that escapes into a
            # real corpus is still self-identifying.
            "synthetic": True,
            "fixture": "ai-memory federation-lab synthetic corpus",
            "generator": "infra/federation-lab/tools/make-synthetic-corpus.sh",
        },
        "reflection_depth": 0,
        "memory_kind": "observation",
        "citations": [],
        "confidence_source": "default",
        "cid": cid,
        "lifecycle_state": "open",
        "version": 1,
    })

envelope = {
    "memories": memories,
    "links": [],
    "count": len(memories),
    "exported_at": "1970-01-01T00:00:00+00:00",
    "export_scope": "memories+links",
    "portability_complete": False,
    "excludes": [
        "audit_chain", "revisions", "tombstones", "lineage", "attestations",
        "governance_rules", "trust_anchors",
    ],
    "withheld": {"total": 0},
}
print(json.dumps(envelope, indent=2, sort_keys=True))
PY

echo "== wrote $OUT" >&2
jq -r '"   memories: \(.count)   namespace: \(.memories[0].namespace)   synthetic: \(.memories[0].metadata.synthetic)"' "$OUT" >&2
echo "   sha256: $(sha256sum "$OUT" | awk '{print $1}')" >&2
