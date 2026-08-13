#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""gen-mesh.py -- render an N-node full-mesh ai-memory federation stack.

Part of the #2921 capacity bench. Emits, into a single run directory:

  <run>/keys/node-NN/    this node's Ed25519 federation keypair, its
                         `daemon` keypair, and EVERY peer's public key
                         (cross-enrolled at generation time)
  <run>/data/node-NN/    empty; becomes the node's SQLite DB + config
  <run>/docker-compose.yml

WHY KEYS ARE MINTED HERE AND NOT IN THE CONTAINERS
--------------------------------------------------
`infra/lan-parity-test/provision-peer-keys.sh` (#1803) cross-enrolls two
daemons AFTER boot, from a one-shot container that waits for both sides'
first-boot keygen. That is the right shape for a 2-node smoke test. It is
the wrong shape for a capacity ramp: a full mesh needs N*(N-1)
enrollments (2450 at N=50), and doing them after boot makes enrollment
latency part of whatever the ramp measures. Minting on the host means the
mesh is fully enrolled at t=0, so time-to-convergence is replication time
and nothing else.

The discipline that script establishes is preserved exactly: only PUBLIC
material is ever copied between nodes. A node's `.priv` is written once,
into that node's own directory, and never read again by this script.

WHY FULL MESH
-------------
`docs/federation.md` "Multi-peer scaling guidance" sizes meshes by peer
count with every node peered to every other; the ~50-peer ceiling it
states is a statement about that topology. Measuring a star or a chain
would measure a different topology than the one the ceiling describes.

Usage:
    gen-mesh.py --nodes 10 --run-dir <dir> --binary <path to ai-memory>
    gen-mesh.py --self-test          # no binary, no docker, no files kept
"""

import argparse
import base64
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

# The compose project + container-name prefix. Deliberately distinct from
# `ic-` (infra/plan-c) and `ic-parity-` (infra/lan-parity-test) so this
# stack can be brought up on a host already running either of those
# without a name collision -- the same co-existence discipline those two
# files document about each other.
PREFIX = "am2921"
PROJECT = "ai-memory-bench-mesh-2921"
NODE_PORT = 19077

# A /16 gives room for 50 containers plus the bridge gateway without
# tuning, and does not collide with 172.31.78.0/24 (plan-c) or
# 172.31.79.0/24 (lan-parity).
SUBNET = "172.30.0.0/16"

# See the comment at the compose render site: the shipped per-agent
# quotas (1000 writes/day, 100 MiB) would cap any single-author corpus
# above 1000 rows at `429`, so the ramp would measure the quota.
DEFAULT_QUOTA_WRITES = 10_000_000
DEFAULT_QUOTA_BYTES = 10_737_418_240

# Peer-count-dependent quorum width, straight off the sizing table in
# `docs/federation.md` "Multi-peer scaling guidance": W = 2 for a 2-3 peer
# mesh, W = ceil((N+1)/2) above that. Passing this rather than a constant
# means the ramp measures the CONFIGURATION THE DOCS PRESCRIBE at each
# mesh size, not an artificially cheap one.
def quorum_width(n_nodes: int) -> int:
    if n_nodes <= 3:
        return 2
    return (n_nodes + 1 + 1) // 2


def node_name(i: int) -> str:
    return f"{PREFIX}-node-{i:02d}"


def fed_identity(i: int) -> str:
    # `host:<hostname>` is the shape `resolve_federation_identity` falls
    # back to; pinning it explicitly (as lan-parity does for #1803)
    # removes container-hostname resolution timing from the picture.
    return f"host:{node_name(i)}"


def gen_keypair(binary: str, key_dir: str, agent_id: str) -> None:
    """Mint one Ed25519 keypair via the shipped CLI.

    Uses `ai-memory identity generate` rather than a Python Ed25519
    implementation so the on-disk format is by construction the format
    the daemon loads -- the #1803 failure mode was a key that existed,
    looked right, and did not match what the daemon signs with.

    The subprocess environment is HERMETIC on purpose. Left alone, the
    CLI resolves `--db` to `ai-memory.db` in the current directory and
    loads the invoking user's real `~/.config/ai-memory/config.toml`.
    Neither is wanted: a bench generator must not be able to open, create
    or migrate an operator's live store, and must not inherit whatever
    tier or store URL that operator happens to run.
    """
    env = dict(os.environ)
    env.update({
        "HOME": key_dir,
        "XDG_CONFIG_HOME": os.path.join(key_dir, ".config"),
        "XDG_DATA_HOME": os.path.join(key_dir, ".local", "share"),
        "AI_MEMORY_NO_CONFIG": "1",
        "AI_MEMORY_DB": os.path.join(key_dir, "keygen-scratch.db"),
        "AI_MEMORY_KEY_DIR": key_dir,
    })
    subprocess.run(
        [binary, "identity", "generate", "--key-dir", key_dir,
         "--agent-id", agent_id, "--json"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        env=env,
    )


# The single identity every corpus write is authored + SIGNED by. v1.0.0
# refuses an unsigned `POST /api/v1/memories` on the HTTP-direct surface AND
# refuses an unsigned third-party relayed write on `/sync/push` -- both
# fail-closed by compiled default. So a mesh measured in the CERTIFIED
# posture needs exactly one attested author whose key every node can verify.
BENCH_AUTHOR = "ai:bench-author@cap2921"
BENCH_AUTHOR_TYPE = "system"


def enroll_author(binary: str, run_dir: str, n_nodes: int) -> str:
    """Mint the corpus author's keypair and enroll it fleet-wide.

    TWO enrollment surfaces, because the two gates read DIFFERENT stores and
    getting only one of them is the #1803 failure shape one layer up:

      * the LOCAL store-path attestation gate resolves the author's bound key
        from the DATABASE agent registry, so the author is registered +
        bind-key'd into every node's SQLite file BEFORE the daemon starts;
      * the FEDERATION receive path resolves it from the registry OR the
        on-disk key store, so the author's PUBLIC key is also dropped into
        every node's key directory.

    Doing both means an attested write is accepted at the entry node AND
    verifiable at every relay hop. Only PUBLIC material is distributed: the
    author's private seed stays in `<run>/author/`.
    """
    author_dir = os.path.join(run_dir, "author")
    os.makedirs(author_dir, exist_ok=True)
    gen_keypair(binary, author_dir, BENCH_AUTHOR)
    pub_path = os.path.join(author_dir, f"{BENCH_AUTHOR}.pub")
    with open(pub_path, "rb") as fh:
        pub_b64 = base64.b64encode(fh.read()).decode()

    for i in range(1, n_nodes + 1):
        kd = os.path.join(run_dir, "keys", f"node-{i:02d}")
        shutil.copyfile(pub_path, os.path.join(kd, f"{BENCH_AUTHOR}.pub"))
        db = os.path.join(run_dir, "data", f"node-{i:02d}", "memories.db")
        env = dict(os.environ)
        env.update({"AI_MEMORY_NO_CONFIG": "1", "AI_MEMORY_DB": db,
                    "HOME": kd, "XDG_CONFIG_HOME": os.path.join(kd, ".config")})
        subprocess.run(
            [binary, "agents", "register", "--db", db,
             "--agent-id", BENCH_AUTHOR, "--agent-type", BENCH_AUTHOR_TYPE,
             "--json"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        subprocess.run(
            [binary, "agents", "bind-key", "--db", db,
             "--agent-id", BENCH_AUTHOR, "--pubkey", pub_b64, "--json"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    return pub_b64


def build_compose(n_nodes: int, run_dir: str, api_key: str,
                  catchup_secs: int, quorum_timeout_ms: int,
                  quorum_writes: int, image: str,
                  quota_writes: int = DEFAULT_QUOTA_WRITES,
                  quota_bytes: int = DEFAULT_QUOTA_BYTES) -> str:
    """Render the compose YAML by hand.

    Hand-rendered rather than templated through a YAML library so the
    output is diffable, comment-carrying, and readable as evidence: the
    rendered file is committed alongside the run logs, and a reviewer has
    to be able to see the exact knobs each node ran with.
    """
    net = ipaddress.ip_network(SUBNET)
    lines = [
        "# GENERATED by infra/bench-mesh/gen-mesh.py -- do not edit by hand.",
        "# Regenerate with the command recorded in run-manifest.json.",
        f"name: {PROJECT}",
        "",
        "services:",
    ]
    for i in range(1, n_nodes + 1):
        name = node_name(i)
        peers = ",".join(
            f"http://{node_name(j)}:{NODE_PORT}"
            for j in range(1, n_nodes + 1) if j != i
        )
        lines += [
            f"  {name}:",
            f"    image: {image}",
            f"    container_name: {name}",
            f"    hostname: {name}",
            "    restart: \"no\"",
            "    environment:",
            f"      AI_MEMORY_FED_IDENTITY: \"{fed_identity(i)}\"",
            # #1231 -- never the reserved `daemon` sentinel.
            f"      AI_MEMORY_AGENT_ID: \"ai:{name}@bench2921\"",
            "      AI_MEMORY_KEY_DIR: \"/keys\"",
            "      HOME: \"/data\"",
            "      BENCH_DATA_DIR: \"/data\"",
            f"      AI_MEMORY_API_KEY: \"{api_key}\"",
            f"      AI_MEMORY_LISTEN_PORT: \"{NODE_PORT}\"",
            f"      BENCH_QUORUM_WRITES: \"{quorum_writes}\"",
            f"      BENCH_QUORUM_TIMEOUT_MS: \"{quorum_timeout_ms}\"",
            f"      BENCH_CATCHUP_SECS: \"{catchup_secs}\"",
            # MEASUREMENT-ONLY quota lift, recorded in the manifest and in
            # the results doc as a deviation. The shipped per-agent defaults
            # are 1000 memory-writes/day and 100 MiB; the corpus is written
            # by ONE attested author by construction, so at the shipped
            # default any corpus above 1000 stops dead at `429` and the ramp
            # would be measuring the quota rather than the mesh. The quota
            # CHECK still runs on every write, so its per-write cost stays
            # inside the measured path.
            f"      AI_MEMORY_MAX_MEMORIES_PER_DAY: \"{quota_writes}\"",
            f"      AI_MEMORY_MAX_STORAGE_BYTES: \"{quota_bytes}\"",
            f"      BENCH_PEERS: \"{peers}\"",
            # #2477 -- a container bridge is NOT loopback, so the
            # peer-scheme guard refuses plaintext peers by default.
            # Acknowledged here because this bridge is private to one
            # host and exists only for measurement. Do NOT copy this line
            # into a deployment whose peers cross a real network.
            "      AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS: \"1\"",
            "      RUST_LOG: \"ai_memory=info\"",
            "    volumes:",
            f"      - ./keys/node-{i:02d}:/keys",
            f"      - ./data/node-{i:02d}:/data",
            "    networks:",
            "      - mesh",
            "    healthcheck:",
            "      test: [\"CMD-SHELL\", \"curl -f -sS --max-time 3 "
            f"-H 'X-API-Key: {api_key}' http://127.0.0.1:{NODE_PORT}/api/v1/health\"]",
            "      interval: 5s",
            "      timeout: 4s",
            "      retries: 12",
            "      start_period: 10s",
            "",
        ]
    lines += [
        "networks:",
        "  mesh:",
        "    driver: bridge",
        "    ipam:",
        "      driver: default",
        "      config:",
        f"        - subnet: {net.with_prefixlen}",
        "",
    ]
    return "\n".join(lines)


def generate(n_nodes: int, run_dir: str, binary: str, catchup_secs: int,
             quorum_timeout_ms: int, image: str,
             quorum_writes: int | None = None,
             quota_writes: int = DEFAULT_QUOTA_WRITES,
             quota_bytes: int = DEFAULT_QUOTA_BYTES) -> dict:
    os.makedirs(run_dir, exist_ok=True)
    api_key = secrets.token_hex(32)
    w = quorum_writes if quorum_writes is not None else quorum_width(n_nodes)

    # 1. Mint each node's own material.
    for i in range(1, n_nodes + 1):
        kd = os.path.join(run_dir, "keys", f"node-{i:02d}")
        os.makedirs(kd, exist_ok=True)
        os.makedirs(os.path.join(run_dir, "data", f"node-{i:02d}"), exist_ok=True)
        gen_keypair(binary, kd, fed_identity(i))
        # The fixed-label `daemon` keypair backs link/audit signing and is
        # a DIFFERENT file from the federation-identity one (#1803).
        gen_keypair(binary, kd, "daemon")

    # 2. Cross-enroll: every node learns every other node's PUBLIC key,
    #    under the exact `<sender_agent_id>.pub` name the receive path's
    #    `lookup_peer_public_key_in` searches for. `.priv` files are never
    #    read here -- only public material moves, per #1803's discipline.
    for i in range(1, n_nodes + 1):
        src = os.path.join(run_dir, "keys", f"node-{i:02d}",
                           f"{fed_identity(i)}.pub")
        for j in range(1, n_nodes + 1):
            if j == i:
                continue
            shutil.copyfile(
                src,
                os.path.join(run_dir, "keys", f"node-{j:02d}",
                             f"{fed_identity(i)}.pub"),
            )

    # 3. Mint + enroll the attested corpus author on every node (see
    #    `enroll_author` for why BOTH the DB registry and the on-disk key
    #    store are written).
    author_pub_b64 = enroll_author(binary, run_dir, n_nodes)

    compose_path = os.path.join(run_dir, "docker-compose.yml")
    with open(compose_path, "w", encoding="utf-8") as fh:
        fh.write(build_compose(n_nodes, run_dir, api_key, catchup_secs,
                               quorum_timeout_ms, w, image,
                               quota_writes, quota_bytes))

    manifest = {
        "nodes": n_nodes,
        "project": PROJECT,
        "quorum_writes": w,
        "quorum_timeout_ms": quorum_timeout_ms,
        "catchup_interval_secs": catchup_secs,
        "node_port": NODE_PORT,
        "subnet": SUBNET,
        "image": image,
        "tier": "keyword",
        "quota_max_memories_per_day": quota_writes,
        "quota_max_storage_bytes": quota_bytes,
        "author": BENCH_AUTHOR,
        "author_pubkey_b64": author_pub_b64,
        "attestation_posture": ("shipped v1.0.0 defaults: HTTP-direct writes "
                                "and relayed third-party writes both REQUIRE "
                                "a valid Ed25519 signature"),
        "topology": "full-mesh (every node peers every other node)",
        "api_key_len": len(api_key),
    }
    with open(os.path.join(run_dir, "mesh-manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    # The API key is a run secret: it goes to a mode-0600 sidecar the
    # ramp driver reads, NEVER into the manifest that lands in evidence.
    key_path = os.path.join(run_dir, "api-key")
    with open(key_path, "w", encoding="utf-8") as fh:
        fh.write(api_key)
    os.chmod(key_path, 0o600)
    return manifest


def self_test() -> int:
    """Contract check that needs no binary, no docker, and keeps no files."""
    ok = True

    def check(cond, msg):
        nonlocal ok
        if not cond:
            print(f"FAIL: {msg}", file=sys.stderr)
            ok = False

    # Quorum width follows the docs/federation.md sizing table.
    check(quorum_width(2) == 2, "W(2) should be 2")
    check(quorum_width(3) == 2, "W(3) should be 2")
    check(quorum_width(5) == 3, "W(5) should be ceil(6/2)=3")
    check(quorum_width(10) == 6, "W(10) should be ceil(11/2)=6")
    check(quorum_width(25) == 13, "W(25) should be ceil(26/2)=13")
    check(quorum_width(50) == 26, "W(50) should be ceil(51/2)=26")

    # Rendered compose: every node peers every other and nobody peers self.
    y = build_compose(4, "/tmp/unused", "K" * 64, 5, 2000, 3, "img:tag")
    for i in range(1, 5):
        line = [ln for ln in y.splitlines()
                if ln.strip().startswith("BENCH_PEERS:")][i - 1]
        peers = line.split('"')[1].split(",")
        check(len(peers) == 3, f"node {i} should have 3 peers, got {len(peers)}")
        check(node_name(i) not in line, f"node {i} must not peer itself")
    check(y.count("container_name:") == 4, "4 services expected")
    check(SUBNET in y, "subnet must be pinned")

    # Cross-enrollment moves only public material: assert the copy loop
    # never names a `.priv`. (Source-level assertion: the loop above
    # builds its source path from `.pub` only.)
    with open(__file__, "r", encoding="utf-8") as fh:
        src = fh.read()
    body = src.split("# 2. Cross-enroll", 1)[1].split("compose_path =", 1)[0]
    # Comment lines are prose ABOUT the discipline; the assertion is about
    # the executable statements, which must never name a private key.
    code = "\n".join(ln for ln in body.splitlines()
                     if not ln.lstrip().startswith("#"))
    check(".priv" not in code,
          "cross-enrollment code must never reference a .priv file")

    with tempfile.TemporaryDirectory() as td:
        check(os.path.isdir(td), "tempdir sanity")

    print("gen-mesh self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodes", type=int)
    ap.add_argument("--run-dir")
    ap.add_argument("--binary", help="path to a release `ai-memory`")
    ap.add_argument("--catchup-secs", type=int, default=5,
                    help="catch-up poll interval (default 5; the shipped "
                         "default is 30 -- see the results doc's "
                         "'what this changes' note)")
    ap.add_argument("--quorum-timeout-ms", type=int, default=2000)
    ap.add_argument("--quorum-writes", type=int, default=None,
                    help="override the docs/federation.md sizing table")
    ap.add_argument("--image", default="ai-memory-bench-mesh:2921")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if not (a.nodes and a.run_dir and a.binary):
        ap.error("--nodes, --run-dir and --binary are required")
    if a.nodes < 2:
        ap.error("--nodes must be >= 2 (a one-node 'mesh' measures nothing)")
    m = generate(a.nodes, a.run_dir, a.binary, a.catchup_secs,
                 a.quorum_timeout_ms, a.image, a.quorum_writes)
    print(json.dumps(m, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
